"""Isolated, deterministic, blinded A/B evaluation orchestration."""

from __future__ import annotations

import concurrent.futures
import datetime as dt
import difflib
import fcntl
import hashlib
import json
import math
import os
import re
import select
import shutil
import stat
import subprocess
import tempfile
import threading
import time
import uuid
from collections.abc import Iterator
from dataclasses import dataclass, replace
from pathlib import Path, PurePosixPath
from typing import Any

from .artifacts import (
    MAX_ARTIFACT_BYTES,
    ArtifactError,
    NormalizedArtifact,
    normalize_artifact,
)
from skivolve.comparator_runtime import (
    SANDBOX_ISOLATION_PROPERTIES,
    CalibrationError,
    ComparatorRuntime,
    SpendLedger,
    _safe_output_path as _private_output_path,
    _validate_private_file as _validate_private_journal_file,
    canonical_bytes,
    runtime_pair,
)

from .holdout_plan import (
    EMPTY_SOURCE_SHA256,
    HOLDOUT_PLAN_SCHEMA_VERSION,
    OPERATOR_DECLARED_ASSURANCE,
    SOURCE_FINGERPRINT_DOMAIN,
    HoldoutPlan,
    HoldoutPlanError,
    load_holdout_plan,
)
from .manifest import (
    CaseSpec,
    ComparisonSpec,
    ManifestError,
    ProviderConfig,
    SuiteSpec,
    VariantSpec,
)
from .providers import (
    AgentRequest,
    ClaudeCliProvider,
    ComparatorRequest,
    EvalProvider,
    FakeProvider,
    ProviderError,
    ProviderResult,
    execution_policy_for,
)
from .provider_capabilities import capabilities_for


MAX_FILE_BYTES = 64 * 1024 * 1024
MAX_TREE_BYTES = 256 * 1024 * 1024
MAX_TREE_ENTRIES = 16_384
MAX_TREE_DEPTH = 64
MAX_GIT_TREE_METADATA_BYTES = 128 * 1024 * 1024
MAX_WORKTREE_SCAN_ENTRIES = MAX_TREE_ENTRIES * 4
MAX_WORKTREE_SCAN_DEPTH = MAX_TREE_DEPTH * 4
MAX_EXECUTABLE_BYTES = 256 * 1024 * 1024
MAX_CODEX_EXECUTABLE_BYTES = 512 * 1024 * 1024
PRIVATE_DIRECTORY_MODE = 0o700
PRIVATE_FILE_MODE = 0o600
_GENERATED_CACHE_DIRECTORIES = frozenset(
    {"__pycache__", ".mypy_cache", ".pytest_cache", ".ruff_cache"}
)
_GENERATED_CACHE_SUFFIXES = frozenset({".pyc", ".pyo"})
_SANDBOX_TOOLING: tuple[str, str, str, str, str, str, str] | None = None
_SANDBOX_TOOLING_LOCK = threading.Lock()
_MIN_HOLDOUT_CASES_PER_SKILL = 8
_OBJECTIVE_ACCEPTANCE_POLICY = {
    "equal_rule": "tie",
    "policy_id": "verifier-pass-v1",
    "schema_version": 1,
    "winner_rule": "sole-passing-arm",
}
_OBJECTIVE_ACCEPTANCE_POLICY_SHA256 = hashlib.sha256(
    canonical_bytes(_OBJECTIVE_ACCEPTANCE_POLICY)
).hexdigest()
_CODEX_PROTOCOL_PROVENANCE_KEYS = frozenset(
    {
        "codex_cli_version",
        "executable_sha256",
        "lock_sha256",
        "runtime_bundle_sha256",
        "schema_sha256",
    }
)


def _comparator_profile_binding(
    runtime: ComparatorRuntime,
) -> tuple[str, str, str]:
    if (
        runtime.profile_id is None
        or runtime.profile_descriptor_sha256 is None
        or runtime.profile_authority_registry_sha256 is None
    ):
        raise RunnerError("comparator profile lacks reviewed authority")
    return (
        runtime.profile_id,
        runtime.profile_descriptor_sha256,
        runtime.profile_authority_registry_sha256,
    )


class RunnerError(RuntimeError):
    """Raised when the harness cannot produce trustworthy evaluation evidence."""


class _GeneratorDispatchJournalError(RunnerError):
    """Raised when generator dispatch accounting cannot remain trustworthy."""


_GENERATOR_DISPATCH_JOURNAL = "generator-dispatch.jsonl"
_GENERATOR_DISPATCH_LOCK = "generator-dispatch.lock"
_GENERATOR_DISPATCH_SCHEMA_VERSION = 1
_GENERATOR_DISPATCH_MAX_BYTES = 32 * 1024 * 1024
_GENERATOR_DISPATCH_MAX_RECORD_BYTES = 1024 * 1024
_GENERATOR_DIGEST_PATTERN = re.compile(r"^[0-9a-f]{64}$")
_GENERATOR_ATTEMPT_PATTERN = re.compile(r"^[0-9a-f]{32}$")
_GENERATOR_FAILURE_CATEGORIES = frozenset(
    {
        "local_io",
        "provider",
        "request_validation",
        "result_validation",
        "unexpected",
    }
)


def _generator_record_bytes(value: Any) -> bytes:
    try:
        return canonical_bytes(value)
    except (TypeError, ValueError, CalibrationError) as exc:
        raise _GeneratorDispatchJournalError(
            "generator dispatch value is not canonical JSON"
        ) from exc


def _generator_digest(value: Any) -> str:
    return hashlib.sha256(_generator_record_bytes(value)).hexdigest()


def _generator_identifier_digest(value: str, label: str) -> str:
    if not isinstance(value, str) or not value:
        raise _GeneratorDispatchJournalError(f"{label} must be non-empty")
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


def _generator_digest_field(value: Any, label: str) -> str:
    if not isinstance(value, str) or _GENERATOR_DIGEST_PATTERN.fullmatch(value) is None:
        raise _GeneratorDispatchJournalError(f"{label} is invalid")
    return value


class _GeneratorDispatchLedger:
    """Crash-durable, append-only accounting for generator dispatch attempts."""

    def __init__(
        self,
        *,
        result_root: Path,
        suite_id: str,
        manifest_sha256: str,
        provider_binding: dict[str, Any],
    ) -> None:
        root = Path(result_root)
        if not root.is_absolute() or root != Path(os.path.abspath(root)):
            raise _GeneratorDispatchJournalError(
                "generator dispatch result root must be canonical and absolute"
            )
        self.result_root = root
        self.journal_path = root / _GENERATOR_DISPATCH_JOURNAL
        self.lock_path = root / _GENERATOR_DISPATCH_LOCK
        self._root_identity: tuple[int, int] | None = None
        self._lock_descriptor = -1
        self._lock_identity: tuple[int, ...] | None = None
        self._journal_identity: tuple[int, ...] | None = None
        self._journal_size = 0
        self._journal_sha256 = hashlib.sha256(b"").hexdigest()
        self._lock = threading.Lock()
        self._attempts: dict[str, tuple[tuple[str, str, int, str], str, str]] = {}
        self._logical_attempts: dict[tuple[str, str, int, str], str] = {}
        self._record_count = 0
        self._check_root()
        if not isinstance(provider_binding, dict):
            raise _GeneratorDispatchJournalError(
                "generator dispatch provider binding must be an object"
            )
        self._header = {
            "event": "header",
            "manifest_sha256": _generator_digest_field(
                manifest_sha256, "generator dispatch manifest digest"
            ),
            "provider": json.loads(_generator_record_bytes(provider_binding)),
            "result_root": str(root),
            "schema_version": _GENERATOR_DISPATCH_SCHEMA_VERSION,
            "suite_id_sha256": _generator_identifier_digest(
                suite_id, "generator dispatch suite id"
            ),
        }
        try:
            self._acquire_lifetime_lock()
            try:
                self.journal_path.lstat()
            except FileNotFoundError:
                self._append(self._header, create=True)
            except OSError as exc:
                raise _GeneratorDispatchJournalError(
                    f"cannot inspect generator dispatch journal: {exc}"
                ) from exc
            else:
                self._attempts, self._logical_attempts, self._record_count = (
                    self._replay(self._read())
                )
        except BaseException:
            self._release_lifetime_lock()
            raise

    def close(self) -> None:
        with self._lock:
            if self._lock_descriptor < 0:
                return
            try:
                self._attest_lifetime_lock()
            finally:
                self._release_lifetime_lock()

    def __del__(self) -> None:
        try:
            self._release_lifetime_lock()
        except BaseException:
            pass

    def plan_attempt(
        self,
        *,
        comparison_id: str,
        case_id: str,
        repetition: int,
        role: str,
        variant_id: str,
        request_sha256: str,
    ) -> str:
        if (
            isinstance(repetition, bool)
            or not isinstance(repetition, int)
            or repetition < 0
        ):
            raise _GeneratorDispatchJournalError(
                "generator dispatch repetition is invalid"
            )
        logical_key = (
            _generator_identifier_digest(
                comparison_id, "generator dispatch comparison id"
            ),
            _generator_identifier_digest(case_id, "generator dispatch case id"),
            repetition,
            _generator_identifier_digest(role, "generator dispatch role"),
        )
        request_digest = _generator_digest_field(
            request_sha256, "generator dispatch request digest"
        )
        record = {
            "attempt_id": uuid.uuid4().hex,
            "case_id_sha256": logical_key[1],
            "comparison_id_sha256": logical_key[0],
            "event": "planned",
            "repetition": repetition,
            "request_sha256": request_digest,
            "role_sha256": logical_key[3],
            "variant_id_sha256": _generator_identifier_digest(
                variant_id, "generator dispatch variant id"
            ),
        }
        with self._lock:
            self._sync()
            if (
                logical_key in self._logical_attempts
                or record["attempt_id"] in self._attempts
            ):
                raise _GeneratorDispatchJournalError(
                    "generator dispatch logical arm already has an accounted attempt"
                )
            self._append(record)
            attempt_id = record["attempt_id"]
            self._attempts[attempt_id] = (logical_key, request_digest, "planned")
            self._logical_attempts[logical_key] = attempt_id
            return attempt_id

    def mark_dispatched(self, attempt_id: str) -> None:
        self._transition(
            attempt_id,
            expected="planned",
            updated="dispatched",
            record={"attempt_id": attempt_id, "event": "dispatched"},
        )

    def mark_completed(self, attempt_id: str, provider_result_sha256: str) -> None:
        self._transition(
            attempt_id,
            expected="dispatched",
            updated="completed",
            record={
                "attempt_id": attempt_id,
                "event": "completed",
                "provider_result_sha256": _generator_digest_field(
                    provider_result_sha256, "generator provider result digest"
                ),
            },
        )

    def mark_failed(
        self,
        attempt_id: str,
        *,
        dispatch_observed: bool,
        failure_category: str,
    ) -> None:
        if failure_category not in _GENERATOR_FAILURE_CATEGORIES:
            raise _GeneratorDispatchJournalError(
                "generator failure category is invalid"
            )
        dispatch_state = "observed" if dispatch_observed else "not_observed"
        self._transition(
            attempt_id,
            expected="dispatched" if dispatch_observed else "planned",
            updated="failed",
            record={
                "attempt_id": attempt_id,
                "dispatch_state": dispatch_state,
                "event": "failed",
                "failure_category": failure_category,
            },
        )

    def audit(self) -> dict[str, Any]:
        with self._lock:
            self._sync()
            unresolved = [
                {
                    "attempt_id": attempt_id,
                    "phase": state[2],
                    "request_sha256": state[1],
                }
                for attempt_id, state in sorted(self._attempts.items())
                if state[2] in {"planned", "dispatched"}
            ]
            states = {
                phase: sum(1 for state in self._attempts.values() if state[2] == phase)
                for phase in ("planned", "dispatched", "completed", "failed")
            }
            return {
                "attempts": len(self._attempts),
                "journal_sha256": self._journal_sha256,
                "records": self._record_count,
                "states": states,
                "unresolved_attempts": unresolved,
            }

    def _transition(
        self,
        attempt_id: str,
        *,
        expected: str,
        updated: str,
        record: dict[str, Any],
    ) -> None:
        with self._lock:
            self._sync()
            state = self._attempts.get(attempt_id)
            if (
                not isinstance(attempt_id, str)
                or _GENERATOR_ATTEMPT_PATTERN.fullmatch(attempt_id) is None
                or state is None
                or state[2] != expected
            ):
                raise _GeneratorDispatchJournalError(
                    "generator dispatch transition is out of order"
                )
            self._append(record)
            self._attempts[attempt_id] = (state[0], state[1], updated)

    def _sync(self) -> None:
        attempts, logical_attempts, record_count = self._replay(self._read())
        if (
            attempts != self._attempts
            or logical_attempts != self._logical_attempts
            or record_count != self._record_count
        ):
            raise _GeneratorDispatchJournalError(
                "generator dispatch journal state drifted in memory"
            )

    def _replay(
        self, raw: bytes
    ) -> tuple[
        dict[str, tuple[tuple[str, str, int, str], str, str]],
        dict[tuple[str, str, int, str], str],
        int,
    ]:
        if not raw or not raw.endswith(b"\n"):
            raise _GeneratorDispatchJournalError(
                "generator dispatch journal has a torn record"
            )
        lines = raw[:-1].split(b"\n")
        records: list[dict[str, Any]] = []
        for line in lines:
            if not line or len(line) > _GENERATOR_DISPATCH_MAX_RECORD_BYTES:
                raise _GeneratorDispatchJournalError(
                    "generator dispatch journal record has invalid size"
                )
            try:
                record = json.loads(line)
            except (UnicodeDecodeError, json.JSONDecodeError) as exc:
                raise _GeneratorDispatchJournalError(
                    "generator dispatch journal record is invalid"
                ) from exc
            if not isinstance(record, dict) or _generator_record_bytes(record) != line:
                raise _GeneratorDispatchJournalError(
                    "generator dispatch journal is not canonical JSONL"
                )
            records.append(record)
        if not records or records[0] != self._header:
            raise _GeneratorDispatchJournalError(
                "generator dispatch journal header binding is invalid"
            )
        attempts: dict[str, tuple[tuple[str, str, int, str], str, str]] = {}
        logical_attempts: dict[tuple[str, str, int, str], str] = {}
        for record in records[1:]:
            event = record.get("event")
            attempt_id = record.get("attempt_id")
            if (
                not isinstance(attempt_id, str)
                or _GENERATOR_ATTEMPT_PATTERN.fullmatch(attempt_id) is None
            ):
                raise _GeneratorDispatchJournalError(
                    "generator dispatch journal attempt id is invalid"
                )
            if event == "planned":
                expected_keys = {
                    "attempt_id",
                    "case_id_sha256",
                    "comparison_id_sha256",
                    "event",
                    "repetition",
                    "request_sha256",
                    "role_sha256",
                    "variant_id_sha256",
                }
                repetition = record.get("repetition")
                if (
                    set(record) != expected_keys
                    or attempt_id in attempts
                    or isinstance(repetition, bool)
                    or not isinstance(repetition, int)
                    or repetition < 0
                ):
                    raise _GeneratorDispatchJournalError(
                        "generator dispatch planned record is invalid"
                    )
                logical_key = (
                    _generator_digest_field(
                        record["comparison_id_sha256"], "generator comparison digest"
                    ),
                    _generator_digest_field(
                        record["case_id_sha256"], "generator case digest"
                    ),
                    repetition,
                    _generator_digest_field(
                        record["role_sha256"], "generator role digest"
                    ),
                )
                request_digest = _generator_digest_field(
                    record["request_sha256"], "generator request digest"
                )
                _generator_digest_field(
                    record["variant_id_sha256"], "generator variant digest"
                )
                if logical_key in logical_attempts:
                    raise _GeneratorDispatchJournalError(
                        "generator logical arm was planned more than once"
                    )
                attempts[attempt_id] = (logical_key, request_digest, "planned")
                logical_attempts[logical_key] = attempt_id
                continue
            state = attempts.get(attempt_id)
            if event == "dispatched" and set(record) == {"attempt_id", "event"}:
                expected_phase, updated = "planned", "dispatched"
            elif event == "completed" and set(record) == {
                "attempt_id",
                "event",
                "provider_result_sha256",
            }:
                _generator_digest_field(
                    record["provider_result_sha256"],
                    "generator provider result digest",
                )
                expected_phase, updated = "dispatched", "completed"
            elif event == "failed" and set(record) == {
                "attempt_id",
                "dispatch_state",
                "event",
                "failure_category",
            }:
                dispatch_state = record["dispatch_state"]
                if (
                    dispatch_state not in {"observed", "not_observed"}
                    or record["failure_category"] not in _GENERATOR_FAILURE_CATEGORIES
                ):
                    raise _GeneratorDispatchJournalError(
                        "generator dispatch failed record is invalid"
                    )
                expected_phase = (
                    "dispatched" if dispatch_state == "observed" else "planned"
                )
                updated = "failed"
            else:
                raise _GeneratorDispatchJournalError(
                    "generator dispatch journal event is invalid"
                )
            if state is None or state[2] != expected_phase:
                raise _GeneratorDispatchJournalError(
                    "generator dispatch journal transition is out of order"
                )
            attempts[attempt_id] = (state[0], state[1], updated)
        return attempts, logical_attempts, len(records)

    def _check_root(self) -> None:
        try:
            metadata = self.result_root.lstat()
            resolved = self.result_root.resolve(strict=True)
        except OSError as exc:
            raise _GeneratorDispatchJournalError(
                f"cannot validate generator dispatch result root: {exc}"
            ) from exc
        identity = (metadata.st_dev, metadata.st_ino)
        if (
            resolved != self.result_root
            or not stat.S_ISDIR(metadata.st_mode)
            or stat.S_ISLNK(metadata.st_mode)
            or metadata.st_uid != os.getuid()
            or stat.S_IMODE(metadata.st_mode) != PRIVATE_DIRECTORY_MODE
            or (self._root_identity is not None and identity != self._root_identity)
        ):
            raise _GeneratorDispatchJournalError(
                "generator dispatch result root is not a stable owner-only directory"
            )
        self._root_identity = identity

    def _acquire_lifetime_lock(self) -> None:
        self._check_root()
        target = _private_output_path(self.lock_path)
        flags = os.O_RDWR | os.O_CLOEXEC | getattr(os, "O_NOFOLLOW", 0)
        try:
            try:
                descriptor = os.open(
                    target,
                    flags | os.O_CREAT | os.O_EXCL,
                    PRIVATE_FILE_MODE,
                )
            except FileExistsError:
                descriptor = os.open(target, flags)
            try:
                identity = _validate_private_journal_file(
                    os.fstat(descriptor), str(target)
                )
                try:
                    fcntl.flock(descriptor, fcntl.LOCK_EX | fcntl.LOCK_NB)
                except BlockingIOError as exc:
                    raise _GeneratorDispatchJournalError(
                        "generator dispatch ledger is already active"
                    ) from exc
                self._attest_private_descriptor(target, descriptor, identity)
                os.fsync(descriptor)
                _fsync_directory(self.result_root)
            except BaseException:
                try:
                    fcntl.flock(descriptor, fcntl.LOCK_UN)
                except OSError:
                    pass
                os.close(descriptor)
                raise
        except _GeneratorDispatchJournalError:
            raise
        except (OSError, CalibrationError) as exc:
            raise _GeneratorDispatchJournalError(
                "cannot acquire generator dispatch lifetime lock"
            ) from exc
        self._lock_descriptor = descriptor
        self._lock_identity = identity
        self._check_root()

    def _attest_lifetime_lock(self) -> None:
        if self._lock_descriptor < 0 or self._lock_identity is None:
            raise _GeneratorDispatchJournalError(
                "generator dispatch lifetime lock is closed"
            )
        try:
            self._attest_private_descriptor(
                self.lock_path,
                self._lock_descriptor,
                self._lock_identity,
            )
        except (OSError, CalibrationError) as exc:
            raise _GeneratorDispatchJournalError(
                "generator dispatch lifetime lock lost integrity"
            ) from exc
        self._check_root()

    def _release_lifetime_lock(self) -> None:
        descriptor = getattr(self, "_lock_descriptor", -1)
        if descriptor < 0:
            return
        self._lock_descriptor = -1
        self._lock_identity = None
        try:
            try:
                fcntl.flock(descriptor, fcntl.LOCK_UN)
            except OSError as exc:
                raise _GeneratorDispatchJournalError(
                    "cannot release generator dispatch lifetime lock"
                ) from exc
        finally:
            os.close(descriptor)

    @staticmethod
    def _attest_private_descriptor(
        path: Path,
        descriptor: int,
        expected_identity: tuple[int, ...] | None = None,
    ) -> tuple[int, ...]:
        identity = _validate_private_journal_file(
            os.fstat(descriptor), str(path), expected_identity=expected_identity
        )
        _validate_private_journal_file(
            path.lstat(), str(path), expected_identity=identity
        )
        return identity

    @staticmethod
    def _read_descriptor(descriptor: int, size: int) -> bytes:
        if size > _GENERATOR_DISPATCH_MAX_BYTES:
            raise _GeneratorDispatchJournalError(
                "generator dispatch journal exceeds byte limit"
            )
        os.lseek(descriptor, 0, os.SEEK_SET)
        chunks: list[bytes] = []
        remaining = size
        while remaining:
            chunk = os.read(descriptor, min(1024 * 1024, remaining))
            if not chunk:
                raise _GeneratorDispatchJournalError(
                    "generator dispatch journal was truncated"
                )
            chunks.append(chunk)
            remaining -= len(chunk)
        if os.read(descriptor, 1):
            raise _GeneratorDispatchJournalError(
                "generator dispatch journal grew while reading"
            )
        return b"".join(chunks)

    def _read(self) -> bytes:
        self._attest_lifetime_lock()
        self._check_root()
        try:
            target = _private_output_path(self.journal_path)
            metadata = target.lstat()
            identity = _validate_private_journal_file(
                metadata,
                str(target),
                expected_identity=self._journal_identity,
            )
            flags = os.O_RDONLY | os.O_CLOEXEC | getattr(os, "O_NOFOLLOW", 0)
            descriptor = os.open(target, flags)
            try:
                _validate_private_journal_file(
                    os.fstat(descriptor), str(target), expected_identity=identity
                )
                raw = self._read_descriptor(descriptor, metadata.st_size)
                _validate_private_journal_file(
                    os.fstat(descriptor), str(target), expected_identity=identity
                )
            finally:
                os.close(descriptor)
        except (OSError, CalibrationError) as exc:
            raise _GeneratorDispatchJournalError(
                f"cannot read generator dispatch journal: {exc}"
            ) from exc
        digest = hashlib.sha256(raw).hexdigest()
        if self._journal_identity is not None and (
            metadata.st_size != self._journal_size or digest != self._journal_sha256
        ):
            raise _GeneratorDispatchJournalError(
                "generator dispatch journal prefix was modified"
            )
        self._journal_identity = identity
        self._journal_size = metadata.st_size
        self._journal_sha256 = digest
        self._attest_lifetime_lock()
        self._check_root()
        return raw

    def _append(self, record: dict[str, Any], *, create: bool = False) -> None:
        self._attest_lifetime_lock()
        encoded = _generator_record_bytes(record) + b"\n"
        if len(encoded) > _GENERATOR_DISPATCH_MAX_RECORD_BYTES:
            raise _GeneratorDispatchJournalError(
                "generator dispatch record exceeds byte limit"
            )
        self._check_root()
        try:
            target = _private_output_path(self.journal_path)
            flags = os.O_RDWR | os.O_APPEND | os.O_CLOEXEC
            flags |= getattr(os, "O_NOFOLLOW", 0)
            if create:
                flags |= os.O_CREAT | os.O_EXCL
            descriptor = os.open(target, flags, PRIVATE_FILE_MODE)
            try:
                if create:
                    os.fchmod(descriptor, PRIVATE_FILE_MODE)
                metadata = os.fstat(descriptor)
                identity = _validate_private_journal_file(
                    metadata,
                    str(target),
                    expected_identity=None if create else self._journal_identity,
                )
                prior = self._read_descriptor(descriptor, metadata.st_size)
                if create:
                    if prior:
                        raise _GeneratorDispatchJournalError(
                            "new generator dispatch journal is not empty"
                        )
                elif (
                    metadata.st_size != self._journal_size
                    or hashlib.sha256(prior).hexdigest() != self._journal_sha256
                ):
                    raise _GeneratorDispatchJournalError(
                        "generator dispatch journal prefix was modified"
                    )
                if len(prior) + len(encoded) > _GENERATOR_DISPATCH_MAX_BYTES:
                    raise _GeneratorDispatchJournalError(
                        "generator dispatch journal exceeds byte limit"
                    )
                view = memoryview(encoded)
                while view:
                    written = os.write(descriptor, view)
                    if written <= 0:
                        raise _GeneratorDispatchJournalError(
                            "generator dispatch journal append made no progress"
                        )
                    view = view[written:]
                os.fsync(descriptor)
                final = os.fstat(descriptor)
                final_identity = _validate_private_journal_file(final, str(target))
                observed = self._read_descriptor(descriptor, final.st_size)
                if final_identity[:2] != identity[:2] or observed != prior + encoded:
                    raise _GeneratorDispatchJournalError(
                        "generator dispatch journal append is inconsistent"
                    )
            finally:
                os.close(descriptor)
            _validate_private_journal_file(
                target.lstat(), str(target), expected_identity=final_identity
            )
            if create:
                _fsync_directory(self.result_root)
        except _GeneratorDispatchJournalError:
            raise
        except (OSError, CalibrationError) as exc:
            raise _GeneratorDispatchJournalError(
                f"cannot persist generator dispatch journal: {exc}"
            ) from exc
        self._journal_identity = final_identity
        self._journal_size = final.st_size
        self._journal_sha256 = hashlib.sha256(observed).hexdigest()
        self._record_count += 1
        self._attest_lifetime_lock()
        self._check_root()


def _generator_request_sha256(
    request: AgentRequest,
    *,
    comparison_id: str,
    repetition: int,
    role: str,
    skill_snapshot_sha256: str | None,
    context_sha256: str,
) -> str:
    """Bind every semantic AgentRequest field without persisting request content."""

    return _generator_digest(
        {
            "agent_request": {
                "case_id": request.case_id,
                "dispatch_callback_present": request.on_dispatched is not None,
                "model": request.model,
                "prompt": request.prompt,
                "required_tools": [list(item) for item in request.required_tools],
                "sandbox_pair_root": str(request.sandbox_pair_root),
                "sandbox_repository_root": str(request.sandbox_repository_root),
                "sandbox_suite_root": (
                    str(request.sandbox_suite_root)
                    if request.sandbox_suite_root is not None
                    else None
                ),
                "skill_snapshot": (
                    str(request.skill_snapshot)
                    if request.skill_snapshot is not None
                    else None
                ),
                "system_context": request.system_context,
                "timeout_seconds": request.timeout_seconds,
                "variant_id": request.variant_id,
                "workspace": str(request.workspace),
            },
            "logical_arm": {
                "comparison_id": comparison_id,
                "context_sha256": context_sha256,
                "repetition": repetition,
                "role": role,
                "skill_snapshot_sha256": skill_snapshot_sha256,
            },
        }
    )


def _generator_failure_category(exc: Exception, stage: str) -> str:
    if isinstance(exc, ProviderError):
        return "provider"
    if isinstance(exc, OSError):
        return "local_io"
    if isinstance(exc, RunnerError):
        return "request_validation" if stage != "agent" else "result_validation"
    return "unexpected"


@dataclass(frozen=True)
class RunSelection:
    split: str = "train"
    case_ids: tuple[str, ...] = ()
    comparison_ids: tuple[str, ...] = ()
    seed: int | None = None
    verifier_only: bool = False
    holdout_plan: Path | None = None


@dataclass(frozen=True)
class SourceMaterial:
    snapshot: Path | None
    snapshot_hash: str | None
    context_text: str
    context_hash: str
    source_commit: str | None
    source_dirty: bool | None


@dataclass(frozen=True)
class _TreeSnapshot:
    states: dict[str, "_FileState"]
    sha256: str


@dataclass(frozen=True)
class _ExecutableAttestation:
    logical_name: str
    source_path: Path
    sha256: str
    size: int
    mode: int
    device: int
    inode: int
    mtime_ns: int
    ctime_ns: int
    version: str
    go_root: Path | None = None
    gcc_exec_prefix: Path | None = None
    derived_executables: tuple["_ExecutableAttestation", ...] = ()

    def as_json(self) -> dict[str, Any]:
        return {
            "logical_name": self.logical_name,
            "source_path": str(self.source_path),
            "sha256": self.sha256,
            "stat": {
                "size": self.size,
                "mode": self.mode,
                "device": self.device,
                "inode": self.inode,
                "mtime_ns": self.mtime_ns,
                "ctime_ns": self.ctime_ns,
            },
            "version": self.version,
            "go_root": str(self.go_root) if self.go_root is not None else None,
            "gcc_exec_prefix": (
                str(self.gcc_exec_prefix) if self.gcc_exec_prefix is not None else None
            ),
            "derived_executables": [
                attestation.as_json() for attestation in self.derived_executables
            ],
        }


def _build_provider(config: ProviderConfig) -> EvalProvider:
    adapter_id = config.adapter_id
    if adapter_id == "claude-cli":
        return ClaudeCliProvider(config)
    if adapter_id == "codex-app-server":
        from .codex_app_server import CodexAppServerProvider

        return CodexAppServerProvider(config)
    if adapter_id == "deterministic-fake":
        return FakeProvider()
    raise RunnerError(f"unsupported provider adapter: {adapter_id}")


def _provider_execution_policy(provider: EvalProvider) -> dict[str, Any]:
    raw = getattr(provider, "execution_policy", None)
    if raw is None:
        raise RunnerError("generator provider omitted its execution policy")
    elif hasattr(raw, "as_json"):
        data = raw.as_json()
    elif isinstance(raw, dict):
        data = dict(raw)
    else:
        data = {
            "concurrency": getattr(raw, "concurrency", None),
            "release_authoritative": getattr(raw, "release_authoritative", None),
        }
    if not isinstance(data, dict):
        raise RunnerError("generator execution policy must serialize as an object")
    if set(data) != {"concurrency", "release_authoritative"}:
        raise RunnerError("generator execution policy fields are not exact")
    concurrency = data.get("concurrency")
    release_authoritative = data.get("release_authoritative")
    if concurrency not in {"concurrent", "serialized"}:
        raise RunnerError(
            "generator execution policy concurrency must be concurrent or serialized"
        )
    if type(release_authoritative) is not bool:
        raise RunnerError(
            "generator execution policy release_authoritative must be boolean"
        )
    return {
        "concurrency": concurrency,
        "release_authoritative": release_authoritative,
    }


def _optional_sha256(value: Any, label: str) -> str | None:
    if value is None:
        return None
    if (
        not isinstance(value, str)
        or len(value) != 64
        or any(character not in "0123456789abcdef" for character in value)
    ):
        raise RunnerError(f"{label} is invalid")
    return value


def _nonempty_provider_string(value: Any, label: str) -> str:
    if not isinstance(value, str) or not value:
        raise RunnerError(f"{label} must be a non-empty string")
    return value


def _json_object_copy(value: Any, label: str) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise RunnerError(f"{label} must be an object")
    try:
        encoded = json.dumps(
            value,
            allow_nan=False,
            ensure_ascii=True,
            separators=(",", ":"),
            sort_keys=True,
        )
        copied = json.loads(encoded)
    except (TypeError, ValueError, json.JSONDecodeError) as exc:
        raise RunnerError(f"{label} must be finite JSON: {exc}") from exc
    if not isinstance(copied, dict):
        raise RunnerError(f"{label} must remain an object")
    return copied


def _provider_protocol_provenance(provider: EvalProvider) -> dict[str, Any] | None:
    raw = getattr(provider, "protocol_provenance", None)
    if raw is None:
        return None
    return _json_object_copy(raw, "generator provider protocol provenance")


def _read_stable_binding_file(path: Path, label: str, maximum: int) -> bytes:
    logical = Path(os.path.abspath(path))
    try:
        before = logical.lstat()
    except OSError as exc:
        raise RunnerError(f"cannot inspect {label}: {exc}") from exc
    if stat.S_ISLNK(before.st_mode) or not stat.S_ISREG(before.st_mode):
        raise RunnerError(f"{label} must be a bounded regular non-symlink file")
    _assert_file_size_within_limit(before.st_size, maximum, label)
    flags = os.O_RDONLY | os.O_CLOEXEC | getattr(os, "O_NOFOLLOW", 0)
    try:
        descriptor = os.open(logical, flags)
    except OSError as exc:
        raise RunnerError(f"cannot open {label}: {exc}") from exc
    try:
        opened = os.fstat(descriptor)

        def identity(metadata: os.stat_result) -> tuple[int, ...]:
            return (
                metadata.st_dev,
                metadata.st_ino,
                metadata.st_size,
                metadata.st_mtime_ns,
                metadata.st_ctime_ns,
                metadata.st_uid,
                metadata.st_mode,
                metadata.st_nlink,
            )

        if identity(opened) != identity(before):
            raise RunnerError(f"{label} changed while it was opened")
        chunks: list[bytes] = []
        remaining = maximum + 1
        while remaining:
            chunk = os.read(descriptor, min(64 * 1024, remaining))
            if not chunk:
                break
            chunks.append(chunk)
            remaining -= len(chunk)
        raw = b"".join(chunks)
        if len(raw) > maximum:
            raise RunnerError(f"{label} exceeds its size limit")
        if identity(os.fstat(descriptor)) != identity(opened):
            raise RunnerError(f"{label} changed while it was read")
        return raw
    except OSError as exc:
        raise RunnerError(f"cannot read {label}: {exc}") from exc
    finally:
        os.close(descriptor)


def _configured_executable_sha256(value: str) -> str:
    candidate = Path(value)
    if candidate.parent == Path("."):
        located = shutil.which(value)
        if located is None:
            raise RunnerError("configured Codex executable is not on PATH")
        candidate = Path(located)
    try:
        resolved = candidate.expanduser().resolve(strict=True)
    except OSError as exc:
        raise RunnerError(f"cannot resolve configured Codex executable: {exc}") from exc
    if not os.access(resolved, os.X_OK):
        raise RunnerError("configured Codex executable is not executable")
    return _sha256(
        _read_stable_binding_file(
            resolved,
            "configured Codex executable",
            MAX_CODEX_EXECUTABLE_BYTES,
        )
    )


def _assert_file_size_within_limit(size: int, maximum: int, label: str) -> None:
    if size > maximum:
        raise RunnerError(f"{label} exceeds its size limit")


def _codex_provider_binding(
    config: ProviderConfig,
    provider: EvalProvider,
    provider_name: str,
    provider_version: str,
    provenance: dict[str, Any] | None,
    *,
    verify_executable: bool,
) -> dict[str, Any]:
    if (
        config.adapter_id != "codex-app-server"
        or config.billing_basis != "chatgpt_subscription"
        or config.max_budget_usd is not None
        or not isinstance(config.executable, str)
        or not config.executable
        or not isinstance(config.reasoning_effort, str)
        or not config.reasoning_effort
        or config.protocol_lock is None
    ):
        raise RunnerError("Codex generator configuration is incomplete")
    if provider_name != "codex-app-server":
        raise RunnerError("Codex generator provider name is not canonical")
    if provenance is None or set(provenance) != _CODEX_PROTOCOL_PROVENANCE_KEYS:
        raise RunnerError("Codex protocol provenance fields are not exact")
    cli_version = provenance["codex_cli_version"]
    if not isinstance(cli_version, str) or not cli_version:
        raise RunnerError("Codex protocol provenance version is invalid")
    digests: dict[str, str] = {}
    for field in (
        "executable_sha256",
        "lock_sha256",
        "runtime_bundle_sha256",
        "schema_sha256",
    ):
        digest = _optional_sha256(
            provenance[field], f"Codex protocol provenance {field}"
        )
        if digest is None:
            raise RunnerError(f"Codex protocol provenance {field} is missing")
        digests[field] = digest
    if cli_version != provider_version:
        raise RunnerError("Codex protocol provenance version differs from provider")
    exposed = {
        "executable_sha256": _optional_sha256(
            getattr(provider, "executable_sha256", None),
            "Codex provider executable digest",
        ),
        "lock_sha256": _optional_sha256(
            getattr(provider, "protocol_lock_sha256", None),
            "Codex provider protocol lock digest",
        ),
        "runtime_bundle_sha256": _optional_sha256(
            getattr(provider, "runtime_bundle_sha256", None),
            "Codex provider runtime bundle digest",
        ),
        "schema_sha256": _optional_sha256(
            getattr(provider, "protocol_schema_sha256", None),
            "Codex provider protocol schema digest",
        ),
    }
    if exposed != digests:
        raise RunnerError("Codex protocol provenance differs from provider digests")

    lock_bytes = _read_stable_binding_file(
        config.protocol_lock,
        "configured Codex protocol lock",
        MAX_FILE_BYTES,
    )
    if _sha256(lock_bytes) != digests["lock_sha256"]:
        raise RunnerError("Codex protocol provenance differs from configured lock")
    try:
        lock_text = lock_bytes.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise RunnerError("configured Codex protocol lock is not UTF-8") from exc
    lock = _load_strict_json(lock_text, "configured Codex protocol lock")
    if not isinstance(lock, dict):
        raise RunnerError("configured Codex protocol lock must be an object")
    protocol = lock.get("protocol")
    runtime_bundle = lock.get("runtime_bundle")
    models = lock.get("models")
    if (
        lock.get("schema_version") != 1
        or lock.get("codex_cli_version") != cli_version
        or lock.get("executable_sha256") != digests["executable_sha256"]
        or not isinstance(protocol, dict)
        or protocol.get("sha256") != digests["schema_sha256"]
        or not isinstance(runtime_bundle, dict)
        or runtime_bundle.get("sha256") != digests["runtime_bundle_sha256"]
        or not isinstance(models, dict)
    ):
        raise RunnerError("Codex protocol provenance differs from lock contents")
    model = models.get(config.model)
    efforts = model.get("reasoning_efforts") if isinstance(model, dict) else None
    if (
        not isinstance(efforts, list)
        or not all(isinstance(effort, str) and effort for effort in efforts)
        or config.reasoning_effort not in efforts
    ):
        raise RunnerError("Codex model configuration differs from protocol lock")
    if verify_executable and (
        _configured_executable_sha256(config.executable) != digests["executable_sha256"]
    ):
        raise RunnerError("Codex executable differs from protocol provenance")
    return {
        "config": {
            "billing_basis": config.billing_basis,
            "executable": config.executable,
            "model": config.model,
            "protocol_lock": str(config.protocol_lock),
            "reasoning_effort": config.reasoning_effort,
        },
        "name": provider_name,
        "provenance": dict(provenance),
        "version": provider_version,
    }


def _provider_authority_binding(
    config: ProviderConfig,
    provider: EvalProvider,
    *,
    role: str,
    provider_name: str,
    provider_version: str,
    protocol_provenance: dict[str, Any] | None,
) -> dict[str, Any]:
    capabilities = capabilities_for(config.adapter_id, role=role)
    protocol_lock_sha256 = (
        _sha256(
            _read_stable_binding_file(
                config.protocol_lock,
                "provider protocol lock",
                MAX_FILE_BYTES,
            )
        )
        if config.protocol_lock is not None
        else None
    )
    normalized_config = {
        "adapter_id": capabilities.adapter_id,
        "billing_basis": config.billing_basis,
        "executable": config.executable,
        "max_budget_usd": config.max_budget_usd,
        "model": config.model,
        "protocol_lock": str(config.protocol_lock) if config.protocol_lock else None,
        "protocol_lock_sha256": protocol_lock_sha256,
        "reasoning_effort": config.reasoning_effort,
        "timeout_seconds": config.timeout_seconds,
    }
    runtime_provenance = {
        "adapter_id": capabilities.adapter_id,
        "executable_sha256": getattr(provider, "executable_sha256", None),
        "name": provider_name,
        "protocol": protocol_provenance,
        "version": provider_version,
    }
    runtime_binding = getattr(provider, "authority_runtime_provenance", None)
    if callable(runtime_binding):
        try:
            runtime_provenance["sandbox_runtime"] = runtime_binding(role)
        except Exception as exc:
            raise RunnerError(
                "provider authority runtime provenance is unavailable"
            ) from exc
    binding = {
        "adapter_id": capabilities.adapter_id,
        "authority_scope": capabilities.authority_scope,
        "capability_sha256": capabilities.sha256,
        "config_sha256": _sha256(_canonical_json_bytes(normalized_config)),
        "contract_revision": capabilities.contract_revision,
        "role": role,
        "runtime_provenance_sha256": _sha256(_canonical_json_bytes(runtime_provenance)),
    }
    return {
        **binding,
        "binding_sha256": _sha256(_canonical_json_bytes(binding)),
    }


def _sandbox_tooling() -> tuple[str, str, str, str, str, str, str]:
    global _SANDBOX_TOOLING
    with _SANDBOX_TOOLING_LOCK:
        if _SANDBOX_TOOLING is not None:
            return _SANDBOX_TOOLING
        tools: list[str] = []
        for name in (
            "systemd-run",
            "systemctl",
            "env",
            "true",
            "unshare",
            "mount",
            "setpriv",
        ):
            resolved = shutil.which(name)
            if resolved is None:
                raise RunnerError(
                    f"required verifier sandbox tool is unavailable: {name}"
                )
            tools.append(resolved)
        (
            systemd_run,
            systemctl,
            env_tool,
            true_tool,
            unshare_tool,
            mount_tool,
            setpriv_tool,
        ) = tools
        unit_name = f"skill-verifier-probe-{uuid.uuid4().hex}"
        probe = [
            systemd_run,
            "--user",
            "--quiet",
            "--pipe",
            "--wait",
            "--collect",
            f"--unit={unit_name}",
        ]
        for probe_property in (
            *SANDBOX_ISOLATION_PROPERTIES,
            "PrivateNetwork=yes",
            "MemoryMax=256M",
            "TasksMax=32",
            "LimitNOFILE=256",
            "LimitFSIZE=16M",
        ):
            probe.extend(["-p", probe_property])
        probe.extend(
            [
                "--working-directory=/",
                "--",
                unshare_tool,
                "--user",
                "--map-current-user",
                "--pid",
                "--fork",
                "--mount-proc",
                "--kill-child",
                true_tool,
            ]
        )
        try:
            completed = subprocess.run(
                probe,
                capture_output=True,
                text=True,
                timeout=20,
                check=False,
                shell=False,
            )
            version = subprocess.run(
                [systemd_run, "--version"],
                capture_output=True,
                text=True,
                timeout=10,
                check=False,
                shell=False,
            )
        except (OSError, subprocess.TimeoutExpired) as exc:
            _stop_systemd_unit(systemctl, unit_name)
            raise RunnerError(f"verifier sandbox probe failed: {exc}") from exc
        if completed.returncode != 0:
            detail = (completed.stderr or completed.stdout).strip()
            raise RunnerError(f"verifier sandbox probe failed: {detail}")
        if version.returncode != 0 or not version.stdout.strip():
            raise RunnerError("cannot capture verifier sandbox version")
        _SANDBOX_TOOLING = (
            systemd_run,
            systemctl,
            env_tool,
            version.stdout.splitlines()[0],
            unshare_tool,
            mount_tool,
            setpriv_tool,
        )
        return _SANDBOX_TOOLING


def _runtime_root(prefix: str, parent: Path | None = None) -> Path:
    runtime_parent = (
        parent.resolve() if parent is not None else Path(f"/run/user/{os.getuid()}")
    )
    if not runtime_parent.is_dir():
        raise RunnerError(f"systemd runtime directory is missing: {runtime_parent}")
    root = runtime_parent / f"{prefix}-{uuid.uuid4().hex}"
    root.mkdir(mode=0o700)
    return root


def _new_external_plan_path(path: Path, suite_root: Path) -> Path:
    supplied = Path(path).expanduser()
    if not supplied.name:
        raise RunnerError("holdout plan output must name a file")
    try:
        parent = supplied.parent.resolve(strict=True)
    except OSError as exc:
        raise RunnerError(f"cannot resolve holdout plan output parent: {exc}") from exc
    if not parent.is_dir():
        raise RunnerError("holdout plan output parent must be a directory")
    output = parent / supplied.name
    if output.exists() or output.is_symlink():
        raise RunnerError("holdout plan output must not already exist")
    if output.is_relative_to(suite_root.resolve()):
        raise RunnerError(
            "holdout plan output must be external to the evaluation suite"
        )
    return output


def _pretty_json_bytes(payload: dict[str, Any]) -> bytes:
    try:
        text = json.dumps(
            payload,
            allow_nan=False,
            ensure_ascii=True,
            indent=2,
            sort_keys=True,
        )
    except (TypeError, ValueError) as exc:
        raise RunnerError(f"cannot encode holdout plan: {exc}") from exc
    return (text + "\n").encode("utf-8")


def _canonical_json_bytes(payload: dict[str, Any]) -> bytes:
    try:
        return (
            json.dumps(
                payload,
                allow_nan=False,
                ensure_ascii=True,
                separators=(",", ":"),
                sort_keys=True,
            )
            + "\n"
        ).encode("ascii")
    except (TypeError, ValueError) as exc:
        raise RunnerError(f"cannot encode holdout consumption record: {exc}") from exc


def _consumption_record_path_for_plan(plan_path: Path) -> Path:
    return plan_path.with_name(f"{plan_path.name}.consumption.json")


def _validate_consumption_record_target(
    path: Path,
    suite_root: Path,
    *,
    require_absent: bool,
) -> Path:
    target = Path(path)
    if not target.is_absolute() or target != Path(os.path.abspath(target)):
        raise RunnerError(
            "holdout consumption record path must be canonical and absolute"
        )
    try:
        resolved_parent = target.parent.resolve(strict=True)
        parent_metadata = target.parent.lstat()
    except OSError as exc:
        raise RunnerError(
            f"cannot validate holdout consumption registry: {exc}"
        ) from exc
    if (
        resolved_parent != target.parent
        or not stat.S_ISDIR(parent_metadata.st_mode)
        or stat.S_ISLNK(parent_metadata.st_mode)
        or parent_metadata.st_uid != os.getuid()
        or stat.S_IMODE(parent_metadata.st_mode) != PRIVATE_DIRECTORY_MODE
    ):
        raise RunnerError(
            "holdout consumption registry parent must be a current-uid mode-0700 "
            "non-symlink directory"
        )
    if target.is_relative_to(suite_root.resolve()):
        raise RunnerError("holdout consumption record must be external to the suite")
    try:
        target.lstat()
    except FileNotFoundError:
        pass
    except OSError as exc:
        raise RunnerError(f"cannot inspect holdout consumption record: {exc}") from exc
    else:
        if require_absent:
            raise RunnerError("holdout plan has already been consumed")
    return target


def _fsync_directory(path: Path) -> None:
    flags = os.O_RDONLY | os.O_CLOEXEC | getattr(os, "O_DIRECTORY", 0)
    flags |= getattr(os, "O_NOFOLLOW", 0)
    descriptor = os.open(path, flags)
    try:
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def _claim_holdout_consumption(
    plan: HoldoutPlan,
    suite: SuiteSpec,
    result_root: Path,
) -> None:
    target = _validate_consumption_record_target(
        plan.consumption_record_path,
        suite.root,
        require_absent=True,
    )
    payload = _canonical_json_bytes(
        {
            "manifest_sha256": plan.manifest_sha256,
            "plan_sha256": plan.sha256,
            "result_root": str(result_root),
            "schema_version": 1,
        }
    )
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_CLOEXEC | os.O_NOFOLLOW
    try:
        descriptor = os.open(target, flags, PRIVATE_FILE_MODE)
    except OSError as exc:
        raise RunnerError(f"cannot claim holdout plan consumption: {exc}") from exc
    try:
        os.fchmod(descriptor, PRIVATE_FILE_MODE)
        view = memoryview(payload)
        while view:
            written = os.write(descriptor, view)
            if written <= 0:
                raise RunnerError("holdout consumption claim made no progress")
            view = view[written:]
        metadata = os.fstat(descriptor)
        if (
            not stat.S_ISREG(metadata.st_mode)
            or metadata.st_uid != os.getuid()
            or metadata.st_nlink != 1
            or stat.S_IMODE(metadata.st_mode) != PRIVATE_FILE_MODE
        ):
            raise RunnerError("holdout consumption claim is not owner-only")
        os.fsync(descriptor)
    except OSError as exc:
        raise RunnerError(f"cannot persist holdout consumption claim: {exc}") from exc
    finally:
        os.close(descriptor)
    try:
        _fsync_directory(target.parent)
    except OSError as exc:
        raise RunnerError(
            f"cannot persist holdout consumption registry directory: {exc}"
        ) from exc


def _write_new_private_file(path: Path, payload: bytes) -> None:
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_CLOEXEC
    flags |= getattr(os, "O_NOFOLLOW", 0)
    try:
        descriptor = os.open(path, flags, PRIVATE_FILE_MODE)
    except OSError as exc:
        raise RunnerError(f"cannot create holdout plan output: {exc}") from exc
    succeeded = False
    try:
        os.fchmod(descriptor, PRIVATE_FILE_MODE)
        view = memoryview(payload)
        while view:
            written = os.write(descriptor, view)
            if written <= 0:
                raise RunnerError("holdout plan write made no progress")
            view = view[written:]
        os.fsync(descriptor)
        succeeded = True
    except OSError as exc:
        raise RunnerError(f"cannot write holdout plan output: {exc}") from exc
    finally:
        os.close(descriptor)
        if not succeeded:
            path.unlink(missing_ok=True)


def _runtime_mountpoint(name: str) -> Path:
    mountpoint = Path(f"/run/user/{os.getuid()}/{name}")
    mountpoint.mkdir(mode=0o700, exist_ok=True)
    if mountpoint.is_symlink() or not mountpoint.is_dir():
        raise RunnerError(f"unsafe runtime mountpoint: {mountpoint}")
    mountpoint.chmod(0o700)
    return mountpoint


def _stop_systemd_unit(systemctl: str, unit_name: str) -> None:
    try:
        subprocess.run(
            [systemctl, "--user", "stop", unit_name],
            capture_output=True,
            text=True,
            timeout=15,
            check=False,
            shell=False,
        )
    except (OSError, subprocess.TimeoutExpired):
        pass


class EvalRunner:
    """Execute suite comparisons and persist enough evidence to audit every gate."""

    def __init__(
        self,
        suite: SuiteSpec,
        provider: EvalProvider | None = None,
        comparator_provider: EvalProvider | None = None,
    ) -> None:
        self.suite = suite
        self._closed = False
        self._owned_providers: list[EvalProvider] = []
        self._comparator_runtime: ComparatorRuntime | None = None
        self._comparator_spend: dict[str, SpendLedger] = {}
        self._generator_dispatch_ledger: _GeneratorDispatchLedger | None = None
        self._holdout_plan: HoldoutPlan | None = None
        self._agent_provider_injected = provider is not None
        self._comparator_provider_injected = comparator_provider is not None
        if suite.evaluation_mode == "objective_only":
            if suite.comparator is not None or suite.comparator_profile is not None:
                raise RunnerError(
                    "objective-only suites must not configure a comparator"
                )
            if comparator_provider is not None:
                raise RunnerError(
                    "objective-only suites reject injected comparator providers"
                )
        elif suite.evaluation_mode == "judged":
            if suite.comparator is None or suite.comparator_profile is None:
                raise RunnerError(
                    "judged suites require a comparator and comparator profile"
                )
        else:
            raise RunnerError(f"unsupported evaluation mode: {suite.evaluation_mode}")
        try:
            if provider is None:
                self.agent_provider = _build_provider(suite.provider)
                self._owned_providers.append(self.agent_provider)
            else:
                self.agent_provider = provider
            self._agent_provider_instance = self.agent_provider
            if suite.evaluation_mode == "objective_only":
                self.comparator_provider: EvalProvider | None = None
            elif comparator_provider is None:
                assert suite.comparator is not None
                self.comparator_provider = _build_provider(suite.comparator)
                self._owned_providers.append(self.comparator_provider)
            else:
                self.comparator_provider = comparator_provider
            self._comparator_provider_instance = self.comparator_provider
            expected_policy = execution_policy_for(suite.provider.adapter_id).as_json()
            observed_policy = _provider_execution_policy(self.agent_provider)
            if observed_policy != expected_policy:
                raise RunnerError(
                    "generator execution policy differs from the manifest provider kind"
                )
            self._agent_execution_policy = expected_policy
            self._agent_provider_name = _nonempty_provider_string(
                self.agent_provider.name, "generator provider name"
            )
            self._agent_provider_version = _nonempty_provider_string(
                self.agent_provider.version, "generator provider version"
            )
            self._agent_protocol_provenance = _provider_protocol_provenance(
                self.agent_provider,
            )
            self._agent_authority_binding = _provider_authority_binding(
                self.suite.provider,
                self.agent_provider,
                role="generation",
                provider_name=self._agent_provider_name,
                provider_version=self._agent_provider_version,
                protocol_provenance=self._agent_protocol_provenance,
            )
            if self.comparator_provider is not None:
                assert self.suite.comparator is not None
                self._comparator_authority_binding = _provider_authority_binding(
                    self.suite.comparator,
                    self.comparator_provider,
                    role="comparison",
                    provider_name=_nonempty_provider_string(
                        self.comparator_provider.name, "comparator provider name"
                    ),
                    provider_version=_nonempty_provider_string(
                        self.comparator_provider.version,
                        "comparator provider version",
                    ),
                    protocol_provenance=_provider_protocol_provenance(
                        self.comparator_provider
                    ),
                )
            else:
                self._comparator_authority_binding = None
            self._agent_codex_binding = (
                _codex_provider_binding(
                    self.suite.provider,
                    self.agent_provider,
                    self._agent_provider_name,
                    self._agent_provider_version,
                    self._agent_protocol_provenance,
                    verify_executable=True,
                )
                if self.suite.provider.adapter_id == "codex-app-server"
                else None
            )
            (
                self._systemd_run,
                self._systemctl,
                self._env_tool,
                self._sandbox_version,
                self._unshare_tool,
                self._mount_tool,
                self._setpriv_tool,
            ) = _sandbox_tooling()
            self._git_commits: dict[str, str] = {}
            self._worktree_heads: dict[str, str] = {}
            self._worktree_source_commits: dict[str, str] = {}
            self._worktree_hashes: dict[tuple[str, str], str] = {}
            self._verifier_commands: dict[str, tuple[str, ...]] = {}
            self._verifier_tools: dict[str, tuple[tuple[str, str], ...]] = {}
            self._verifier_executables: dict[
                str, tuple[_ExecutableAttestation, tuple[_ExecutableAttestation, ...]]
            ] = {}
            self._case_snapshots: dict[str, _TreeSnapshot] = {}
            self._shared_snapshot: _TreeSnapshot | None = None
            self._case_hashes: dict[str, str] = {}
            self._manifest_bytes = _manifest_bytes(suite)
        except BaseException as initialization_error:
            try:
                self.close()
            except BaseException as cleanup_error:
                initialization_error.add_note(
                    "owned provider cleanup also failed with "
                    f"{type(cleanup_error).__name__}"
                )
            raise

    def __enter__(self) -> EvalRunner:
        self._ensure_open()
        return self

    def __exit__(
        self, _exc_type: object, _exc_value: object, _traceback: object
    ) -> None:
        self.close()

    def close(self) -> None:
        if self._closed:
            return
        self._closed = True
        providers = tuple(self._owned_providers)
        self._owned_providers.clear()
        closed: set[int] = set()
        cleanup_failure: BaseException | None = None
        runtime = self._comparator_runtime
        self._comparator_runtime = None
        if runtime is not None:
            try:
                runtime.close()
            except BaseException as exc:
                cleanup_failure = exc
        for owned_provider in reversed(providers):
            identity = id(owned_provider)
            if identity not in closed:
                try:
                    owned_provider.close()
                except BaseException as exc:
                    if cleanup_failure is None:
                        cleanup_failure = exc
                closed.add(identity)
        if cleanup_failure is not None:
            if isinstance(cleanup_failure, Exception):
                raise RunnerError(
                    "one or more owned providers failed to close"
                ) from cleanup_failure
            raise cleanup_failure

    def _ensure_open(self) -> None:
        if self._closed:
            raise RunnerError("evaluation runner is closed")

    def preflight(self, selection: RunSelection) -> dict[str, Any]:
        """Validate every selected source, fixture, verifier, and external tool."""

        self._ensure_open()
        return self._preflight(selection, allow_unsealed_holdout=False)

    def _effective_selection(self, selection: RunSelection) -> RunSelection:
        if (
            self.suite.evaluation_mode == "objective_only"
            and not selection.verifier_only
        ):
            return replace(selection, verifier_only=True)
        return selection

    def _execution_mode(self, selection: RunSelection) -> str:
        if self.suite.evaluation_mode == "objective_only":
            return "objective_only"
        return "verifier_only" if selection.verifier_only else "judged"

    def _preflight(
        self,
        selection: RunSelection,
        *,
        allow_unsealed_holdout: bool,
    ) -> dict[str, Any]:
        """Run the common preflight, with one internal holdout-preparation escape."""

        selection = self._effective_selection(selection)
        self._assert_manifest_integrity()
        self._assert_generator_execution_policy_integrity()
        self._assert_comparator_authority_binding_integrity()
        self._assert_codex_provider_binding_integrity(verify_executable=True)
        self._validate_holdout_selection_shape(
            selection, allow_unsealed_holdout=allow_unsealed_holdout
        )
        runtime = None
        if selection.split == "holdout":
            if self.suite.evaluation_mode == "judged":
                runtime = self._load_comparator_runtime()
                self._require_production_holdout_authority(runtime)
        cases, comparisons = self._selected(
            selection, allow_unsealed_holdout=allow_unsealed_holdout
        )
        self._assert_injected_fake_generator_admissible(selection, cases)
        if runtime is None and self.suite.evaluation_mode != "objective_only":
            runtime = self._load_comparator_runtime()
        generator_artifact_kinds = set(
            capabilities_for(
                self.suite.provider.adapter_id, role="generation"
            ).artifact_outputs
        )
        unsupported_generator_artifacts = sorted(
            {
                case.artifact_contract.kind
                for case in cases
                if case.artifact_contract.kind not in generator_artifact_kinds
            }
        )
        if unsupported_generator_artifacts:
            raise RunnerError(
                "generator adapter does not support selected artifact kinds: "
                + ", ".join(unsupported_generator_artifacts)
            )
        if runtime is not None:
            unsupported_profile_artifacts = sorted(
                {
                    case.artifact_contract.kind
                    for case in cases
                    if case.artifact_contract.kind
                    not in runtime.supported_artifact_kinds
                }
            )
            if unsupported_profile_artifacts:
                raise RunnerError(
                    "comparator profile does not support selected artifact kinds: "
                    + ", ".join(unsupported_profile_artifacts)
                )
        if selection.split == "holdout":
            self._assert_generator_release_authority(runtime)
        repository_commit = _git_commit(self.suite.repository_root)
        repository_dirty = _git_dirty(self.suite.repository_root)
        variants_by_id = self.suite.variants_by_id
        selected_variant_ids = {
            variant_id
            for comparison in comparisons
            for variant_id in (comparison.control, comparison.treatment)
        }
        source_records: dict[str, Any] = {}
        for variant_id in sorted(selected_variant_ids):
            variant = variants_by_id[variant_id]
            source_records[variant.id] = self._preflight_variant(variant, cases)
        if selection.split == "holdout":
            self._assert_generic_holdout_source_authority(
                comparisons, cases, source_records
            )
        release_context_commits = {
            role: (
                (
                    variants_by_id[role].root
                    if variants_by_id[role].kind == "worktree"
                    else self.suite.repository_root
                ),
                record["source_commit"],
            )
            for role, record in source_records.items()
            if isinstance(record.get("source_commit"), str)
        }
        shared_root = _effective_shared_verifier_dir(self.suite)
        self._shared_snapshot = (
            _snapshot_tree(shared_root, ignore_generated_caches=True)
            if shared_root is not None
            else None
        )
        case_records: list[dict[str, Any]] = []
        for case in cases:
            _scan_tree(case.fixture_dir, ignore_generated_caches=True)
            try:
                prompt = case.prompt_file.read_text(encoding="utf-8")
            except (OSError, UnicodeDecodeError) as exc:
                raise RunnerError(
                    f"cannot read UTF-8 prompt for case {case.id}: {exc}"
                ) from exc
            if not prompt.strip():
                raise RunnerError(f"case {case.id} prompt is empty")
            command = _resolve_verifier_command(self.suite.root, case, shared_root)
            self._verifier_commands[case.id] = command
            interpreter = _attest_executable(Path(command[0]), Path(command[0]).name)
            tool_attestations = tuple(
                _attest_executable(Path(_resolve_required_tool(case.id, name)), name)
                for name in case.verifier.required_tools
            )
            tools = tuple(
                (name, str(attestation.source_path))
                for name, attestation in zip(
                    case.verifier.required_tools, tool_attestations, strict=True
                )
            )
            self._verifier_tools[case.id] = tools
            self._verifier_executables[case.id] = (interpreter, tool_attestations)
            case_snapshot = _snapshot_tree(
                case.prompt_file.parent, ignore_generated_caches=True
            )
            self._case_snapshots[case.id] = case_snapshot
            case_hash = _combined_case_hash(case_snapshot, self._shared_snapshot)
            self._case_hashes[case.id] = case_hash
            prompt_sha256 = _sha256(prompt.encode("utf-8"))
            fixture_sha256 = _tree_hash(case.fixture_dir, ignore_generated_caches=True)
            shared_tree_sha256 = (
                self._shared_snapshot.sha256
                if self._shared_snapshot is not None
                else None
            )
            verifier_execution_sha256 = _verifier_execution_sha256(
                self.suite.root, case
            )
            context_content_sha256s = _release_context_content_hashes(
                self.suite.repository_root,
                case,
                release_context_commits,
            )
            case_records.append(
                {
                    "id": case.id,
                    "split": case.split,
                    "skill": case.skill,
                    "prompt_sha256": prompt_sha256,
                    "fixture_sha256": fixture_sha256,
                    "shared_tree_sha256": shared_tree_sha256,
                    "verifier_execution_sha256": verifier_execution_sha256,
                    "context_content_sha256s": context_content_sha256s,
                    "case_tree_sha256": case_snapshot.sha256,
                    "combined_case_shared_sha256": case_hash,
                    "release_case_fingerprint": _release_case_fingerprint(
                        case,
                        prompt_sha256=prompt_sha256,
                        fixture_sha256=fixture_sha256,
                        context_content_sha256s=context_content_sha256s,
                    ),
                    "verifier_argv": list(command),
                    "required_tools": {name: path for name, path in tools},
                    "verifier_interpreter_attestation": interpreter.as_json(),
                    "required_tool_attestations": {
                        name: attestation.as_json()
                        for name, attestation in zip(
                            case.verifier.required_tools,
                            tool_attestations,
                            strict=True,
                        )
                    },
                    "critical_expectations": list(case.critical_expectations),
                    "artifact_contract": {"kind": case.artifact_contract.kind},
                }
            )
        if selection.split == "holdout":
            _assert_release_task_content_uniqueness(case_records)
        if allow_unsealed_holdout:
            if runtime is not None:
                self._assert_production_holdout_runtime(runtime)
            self._holdout_plan = None
            holdout_plan = None
        else:
            holdout_plan = self._bind_holdout_plan(
                selection,
                cases,
                comparisons,
                source_records,
                case_records,
            )
        execution_plan = _execution_plan(
            cases,
            comparisons,
            runtime,
            agent_per_invocation_max_usd=self.suite.provider.max_budget_usd,
            agent_billing_basis=self.suite.provider.billing_basis,
        )
        if runtime is not None and not selection.verifier_only:
            _assert_comparator_plan_within_release_cap(execution_plan)
        execution_mode = self._execution_mode(selection)
        comparator_evidence: dict[str, Any] | None = None
        if runtime is not None:
            assert self.comparator_provider is not None
            assert self.suite.comparator is not None
            comparator_evidence = {
                "name": self.comparator_provider.name,
                "version": self.comparator_provider.version,
                "requested_model": self.suite.comparator.model,
                "release_sha256": runtime.release_summary["release_sha256"],
                "calibration_evidence_sha256": runtime.certification.evidence_sha256,
                "protocol_locks_valid": runtime.protocol_locks_valid,
                "live_calibration_valid": runtime.live_calibration_valid,
                "certification": runtime.certification.as_json(),
            }
            assert self.suite.comparator_profile is not None
            comparator_evidence.update(
                {
                    "profile_kind": self.suite.comparator_profile.kind,
                    "profile_id": runtime.profile_id,
                    "profile_descriptor_sha256": runtime.profile_descriptor_sha256,
                    "profile_authority_registry_sha256": (
                        runtime.profile_authority_registry_sha256
                    ),
                    "profile_locks_valid": runtime.profile_locks_valid,
                }
            )
        preflight_result = {
            "execution_mode": execution_mode,
            "suite_id": self.suite.suite_id,
            "manifest_sha256": self.suite.manifest_hash,
            "repository_commit": repository_commit,
            "repository_dirty": repository_dirty,
            "provider": self._generator_provider_binding(),
            "comparator": comparator_evidence,
            "selection": {
                "split": selection.split,
                "case_ids": [case.id for case in cases],
                "comparison_ids": [comparison.id for comparison in comparisons],
                "seed": self.suite.seed if selection.seed is None else selection.seed,
                "verifier_only": selection.verifier_only,
                "holdout_plan_sha256": (
                    holdout_plan["sha256"] if holdout_plan is not None else None
                ),
            },
            "plan": execution_plan,
            "holdout_plan": holdout_plan,
            "sources": source_records,
            "cases": case_records,
        }
        if self.suite.evaluation_mode == "objective_only":
            preflight_result["objective_acceptance"] = {
                **_OBJECTIVE_ACCEPTANCE_POLICY,
                "policy_sha256": _OBJECTIVE_ACCEPTANCE_POLICY_SHA256,
            }
        return preflight_result

    def run(
        self,
        selection: RunSelection,
        *,
        output_dir: Path | None,
        dry_run: bool = False,
    ) -> dict[str, Any]:
        """Run selected comparisons, or return a write-free validated plan."""

        self._ensure_open()
        selection = self._effective_selection(selection)
        preflight = self.preflight(selection)
        cases, comparisons = self._selected(selection)
        seed = self.suite.seed if selection.seed is None else selection.seed
        if dry_run:
            execution_mode = self._execution_mode(selection)
            comparator_evidence = preflight["comparator"]
            dry_run_result = {
                "schema_version": 1,
                "dry_run": True,
                "execution_mode": execution_mode,
                "preflight": preflight,
                "planned_pair_runs": sum(
                    comparison.repetitions * len(cases) for comparison in comparisons
                ),
                "protocol_locks_valid": (
                    comparator_evidence["protocol_locks_valid"]
                    if comparator_evidence is not None
                    else None
                ),
                "live_calibration_valid": (
                    comparator_evidence["live_calibration_valid"]
                    if comparator_evidence is not None
                    else None
                ),
            }
            dry_run_result["profile_locks_valid"] = (
                comparator_evidence["profile_locks_valid"]
                if comparator_evidence is not None
                else None
            )
            return dry_run_result
        runtime: ComparatorRuntime | None = None
        if self.suite.evaluation_mode == "judged":
            runtime = self._load_comparator_runtime()
        if runtime is not None and not selection.verifier_only:
            assert self.suite.comparator is not None
            if not (
                runtime.bundle.release["test_release"]
                and self.suite.comparator.adapter_id == "deterministic-fake"
            ):
                try:
                    if self.suite.comparator_profile.kind == "suite_local":
                        runtime.require_diagnostic_calibration()
                    else:
                        runtime.require_live_calibration()
                except CalibrationError as exc:
                    raise RunnerError(str(exc)) from exc
        if output_dir is None:
            raise RunnerError("output_dir is required outside dry-run mode")
        self._assert_manifest_integrity()
        self._assert_holdout_plan_integrity()
        output, output_created = _prepare_result_root(output_dir)
        if self._holdout_plan is not None:
            try:
                _claim_holdout_consumption(self._holdout_plan, self.suite, output)
            except Exception:
                if output_created:
                    try:
                        output.rmdir()
                    except OSError as cleanup_error:
                        raise RunnerError(
                            "holdout claim failed and its newly created empty result "
                            f"root could not be removed: {cleanup_error}"
                        ) from cleanup_error
                raise
        if runtime is None:
            self._comparator_spend = {}
        else:
            spend_root = output / "comparator-spend"
            _mkdir_private(spend_root, parents=False, exist_ok=False)
            run_cap = runtime.bundle.release["execution_limits"]["run_max_usd"]
            self._comparator_spend = {
                comparison.id: SpendLedger(
                    run_cap,
                    spend_root / f"{comparison.id}.jsonl",
                )
                for comparison in comparisons
            }
        _write_bytes(output / "manifest.snapshot.json", self._manifest_bytes)
        dispatch_ledger = _GeneratorDispatchLedger(
            result_root=output,
            suite_id=self.suite.suite_id,
            manifest_sha256=_sha256(self._manifest_bytes),
            provider_binding=self._generator_provider_binding(),
        )
        self._generator_dispatch_ledger = dispatch_ledger
        try:
            started_at = _utc_now()
            pair_results: list[dict[str, Any]] = []
            for comparison in comparisons:
                for case in cases:
                    for repetition in range(comparison.repetitions):
                        pair_results.append(
                            self._run_pair(
                                comparison,
                                case,
                                repetition,
                                seed=seed,
                                output_dir=output,
                                verifier_only=selection.verifier_only,
                            )
                        )
            self._assert_holdout_plan_integrity()
            self._assert_generator_execution_policy_integrity()
            self._assert_comparator_authority_binding_integrity()
            spend_records = {
                comparison_id: ledger.journal_records()
                for comparison_id, ledger in self._comparator_spend.items()
            }
            aggregate = _aggregate(
                pair_results,
                self.suite,
                comparisons,
                selection,
                holdout_plan=self._holdout_plan,
                release_authority_validated=(
                    (
                        runtime is not None
                        and runtime.production_authority_valid
                        and runtime.certification.valid
                        and runtime.certification.evidence_sha256 is not None
                    )
                    or (
                        self._holdout_plan is not None
                        and self._holdout_plan.evaluation_mode == "objective_only"
                        and self._holdout_plan.objective_acceptance_policy_sha256
                        == _OBJECTIVE_ACCEPTANCE_POLICY_SHA256
                    )
                ),
                generator_release_authoritative=(
                    self._production_generator_release_authoritative()
                ),
                comparator_spend_records=spend_records,
            )
            ledgers = {
                comparison_id: {
                    "charged_usd": ledger.spent_usd,
                    "maximum_usd": ledger.maximum_usd,
                    "journal_sha256": ledger.journal_sha256,
                    "records": len(spend_records[comparison_id]),
                }
                for comparison_id, ledger in self._comparator_spend.items()
            }
            aggregate["comparator_spend_ledgers"] = {
                "by_comparison": ledgers,
                "total_charged_usd": sum(
                    item["charged_usd"] for item in ledgers.values()
                ),
                "total_maximum_usd": sum(
                    item["maximum_usd"] for item in ledgers.values()
                ),
            }
            aggregate["execution_mode"] = self._execution_mode(selection)
            if self._generator_dispatch_ledger is None:
                raise RunnerError("generator dispatch ledger was not initialized")
            generator_dispatch_audit = self._generator_dispatch_ledger.audit()
            if generator_dispatch_audit["unresolved_attempts"]:
                raise RunnerError("generator dispatch ledger has unresolved attempts")
            aggregate["generator_dispatch_ledger"] = generator_dispatch_audit
            execution_mode = self._execution_mode(selection)
            result = {
                "schema_version": 1,
                "execution_mode": execution_mode,
                "suite_id": self.suite.suite_id,
                "started_at": started_at,
                "finished_at": _utc_now(),
                "dry_run": False,
                "preflight": preflight,
                "pairs": pair_results,
                "aggregate": aggregate,
                "passed": aggregate["passed"],
            }
            try:
                dispatch_ledger.close()
            finally:
                self._generator_dispatch_ledger = None
            _write_json(output / "run.json", result)
            return result
        finally:
            active_dispatch_ledger = self._generator_dispatch_ledger
            self._generator_dispatch_ledger = None
            if active_dispatch_ledger is not None:
                active_dispatch_ledger.close()

    def prepare_holdout_plan(
        self,
        *,
        output_path: Path,
        plan_id: str,
        reviewers: tuple[str, ...],
        freeze_record: str,
        seal_record: str,
    ) -> dict[str, Any]:
        """Prepare, write, and preflight one sealed production holdout plan."""

        self._ensure_open()
        output = _new_external_plan_path(output_path, self.suite.root)
        consumption_record_path = _consumption_record_path_for_plan(output)
        _validate_consumption_record_target(
            consumption_record_path,
            self.suite.root,
            require_absent=True,
        )
        release_comparison_ids = self.suite.holdout_comparison_ids
        selection = RunSelection(
            split="holdout",
            comparison_ids=release_comparison_ids,
        )
        draft = self._preflight(selection, allow_unsealed_holdout=True)
        comparisons_by_id = {
            comparison.id: comparison for comparison in self.suite.comparisons
        }
        payload = {
            "schema_version": HOLDOUT_PLAN_SCHEMA_VERSION,
            "plan_id": plan_id,
            "status": "sealed",
            "manifest_sha256": draft["manifest_sha256"],
            "evaluation_mode": self.suite.evaluation_mode,
            "generator_provider": draft["provider"],
            "source_bindings": [
                {
                    "variant_id": variant_id,
                    "kind": draft["sources"][variant_id]["kind"],
                    "source_commit": draft["sources"][variant_id]["source_commit"],
                    "source_sha256_by_case": {
                        case_id: digest
                        for case_id, digest in sorted(
                            draft["sources"][variant_id][
                                "source_sha256_by_case"
                            ].items()
                        )
                    },
                }
                for variant_id in sorted(draft["sources"])
            ],
            "consumption_record_path": str(consumption_record_path),
            "seed": draft["selection"]["seed"],
            "comparison_profile": [
                {
                    "id": comparison.id,
                    "control": comparison.control,
                    "treatment": comparison.treatment,
                    "repetitions": comparison.repetitions,
                    "comparator_order": comparison.comparator_order,
                }
                for comparison_id in release_comparison_ids
                for comparison in (comparisons_by_id[comparison_id],)
            ],
            "cases": [
                {
                    "id": case["id"],
                    "case_tree_sha256": case["case_tree_sha256"],
                    "shared_tree_sha256": case["shared_tree_sha256"],
                    "release_case_fingerprint": case["release_case_fingerprint"],
                    "skill": case["skill"],
                    "critical_expectations": case["critical_expectations"],
                }
                for case in draft["cases"]
            ],
            "provenance": {
                "assurance": OPERATOR_DECLARED_ASSURANCE,
                "privacy_claim": "not-a-cryptographic-privacy-proof",
                "frozen_before_candidate_evaluation": True,
                "sealed_after_independent_review": True,
                "reviewed_by": list(reviewers),
                "freeze_record": freeze_record,
                "seal_record": seal_record,
            },
        }
        payload["generator_adapter_binding"] = self._agent_authority_binding
        if self._comparator_authority_binding is not None:
            payload["comparator_adapter_binding"] = self._comparator_authority_binding
        if self.suite.evaluation_mode == "judged":
            comparator = draft["comparator"]
            assert comparator is not None
            runtime = self._load_comparator_runtime()
            profile_id, profile_descriptor, profile_registry = (
                _comparator_profile_binding(runtime)
            )
            payload.update(
                {
                    "comparator_release_sha256": comparator["release_sha256"],
                    "comparator_calibration_evidence_sha256": comparator[
                        "calibration_evidence_sha256"
                    ],
                    "comparator_profile_id": profile_id,
                    "comparator_profile_descriptor_sha256": profile_descriptor,
                    "comparator_profile_authority_registry_sha256": profile_registry,
                }
            )
        else:
            objective = draft["objective_acceptance"]
            payload.update(
                {
                    "objective_acceptance_policy_id": objective["policy_id"],
                    "objective_acceptance_policy_sha256": objective["policy_sha256"],
                }
            )
        encoded = _pretty_json_bytes(payload)
        expected_sha256 = hashlib.sha256(encoded).hexdigest()
        verified = False
        created = False
        try:
            _write_new_private_file(output, encoded)
            created = True
            try:
                loaded = load_holdout_plan(output)
            except HoldoutPlanError as exc:
                raise RunnerError(f"prepared holdout plan is invalid: {exc}") from exc
            if loaded.raw_bytes != encoded or loaded.sha256 != expected_sha256:
                raise RunnerError("prepared holdout plan bytes changed during write")
            proof = self.preflight(
                RunSelection(
                    split="holdout",
                    comparison_ids=release_comparison_ids,
                    holdout_plan=output,
                )
            )
            if proof["holdout_plan"]["sha256"] != expected_sha256:
                raise RunnerError(
                    "prepared holdout plan changed before normal preflight proof"
                )
            if stat.S_IMODE(output.stat().st_mode) != PRIVATE_FILE_MODE:
                raise RunnerError("prepared holdout plan mode changed from 0600")
            verified = True
        finally:
            if created and not verified:
                output.unlink(missing_ok=True)
        return {
            "plan_path": str(output),
            "plan_sha256": expected_sha256,
            "binding_verified": True,
            "file_mode": "0600",
            "case_count": len(draft["cases"]),
            "consumption_record_path": str(consumption_record_path),
            "execution_plan": draft["plan"],
            "preflight": proof,
        }

    def _generator_provider_binding(self) -> dict[str, Any]:
        self._assert_generator_execution_policy_integrity()
        executable_sha256 = _optional_sha256(
            getattr(self.agent_provider, "executable_sha256", None),
            "generator provider executable digest",
        )
        protocol_lock_sha256 = _optional_sha256(
            getattr(self.agent_provider, "protocol_lock_sha256", None),
            "generator provider protocol lock digest",
        )
        raw_protocol_lock = self.suite.provider.protocol_lock
        protocol_lock: str | None = None
        if raw_protocol_lock is not None:
            path = Path(raw_protocol_lock)
            resolved = (
                path.resolve()
                if path.is_absolute()
                else (self.suite.root / path).resolve()
            )
            try:
                protocol_lock = resolved.relative_to(
                    self.suite.root.resolve()
                ).as_posix()
            except ValueError as exc:
                raise RunnerError(
                    "generator provider protocol lock escapes the suite root"
                ) from exc
        return {
            "name": self._agent_provider_name,
            "version": self._agent_provider_version,
            "requested_model": self.suite.provider.model,
            "executable_sha256": executable_sha256,
            "reasoning_effort": self.suite.provider.reasoning_effort,
            "billing_basis": self.suite.provider.billing_basis,
            "protocol_lock": protocol_lock,
            "protocol_lock_sha256": protocol_lock_sha256,
            "execution_policy": dict(self._agent_execution_policy),
        }

    def _production_generator_release_authoritative(self) -> bool:
        capabilities = capabilities_for(self.suite.provider.adapter_id)
        if not (
            self._agent_execution_policy["release_authoritative"]
            and capabilities.authority_scope == "production"
            and self._agent_authority_binding["capability_sha256"]
            == capabilities.sha256
            and self.suite.provider.adapter_id == "claude-cli"
            and type(self.agent_provider) is ClaudeCliProvider
            and not self._agent_provider_injected
            and self.agent_provider is self._agent_provider_instance
            and getattr(self.agent_provider, "_config", None) == self.suite.provider
            and self._agent_provider_name == "claude-cli"
            and self._agent_protocol_provenance is None
        ):
            return False
        return (
            _optional_sha256(
                getattr(self.agent_provider, "executable_sha256", None),
                "generator provider executable digest",
            )
            is not None
        )

    def _assert_generator_release_authority(
        self, runtime: ComparatorRuntime | None
    ) -> None:
        if not self._agent_execution_policy["release_authoritative"]:
            raise RunnerError(
                "generator execution policy is not authoritative for holdout release"
            )
        if (
            runtime is None or not runtime.bundle.release["test_release"]
        ) and not self._production_generator_release_authoritative():
            raise RunnerError(
                "production holdout requires the exact built-in Claude CLI generator"
            )

    def _assert_generator_execution_policy_integrity(self) -> None:
        if self.agent_provider is not self._agent_provider_instance:
            raise RunnerError(
                "generator provider instance drifted after initialization"
            )
        expected = execution_policy_for(self.suite.provider.adapter_id).as_json()
        if expected != self._agent_execution_policy:
            raise RunnerError("manifest provider execution policy drifted")
        if _provider_execution_policy(self.agent_provider) != expected:
            raise RunnerError("generator execution policy drifted after initialization")
        if (
            self.agent_provider.name != self._agent_provider_name
            or self.agent_provider.version != self._agent_provider_version
        ):
            raise RunnerError(
                "generator provider identity drifted after initialization"
            )
        if (
            _provider_protocol_provenance(self.agent_provider)
            != self._agent_protocol_provenance
        ):
            raise RunnerError(
                "generator protocol provenance drifted after initialization"
            )
        observed_authority = _provider_authority_binding(
            self.suite.provider,
            self.agent_provider,
            role="generation",
            provider_name=self._agent_provider_name,
            provider_version=self._agent_provider_version,
            protocol_provenance=self._agent_protocol_provenance,
        )
        if observed_authority != self._agent_authority_binding:
            raise RunnerError("generator provider binding authority drifted")
        self._assert_codex_provider_binding_integrity(verify_executable=False)

    def _assert_codex_provider_binding_integrity(
        self, *, verify_executable: bool
    ) -> None:
        if self.suite.provider.adapter_id != "codex-app-server":
            if self._agent_codex_binding is not None:
                raise RunnerError("Codex provider binding persisted for another kind")
            return
        observed = _codex_provider_binding(
            self.suite.provider,
            self.agent_provider,
            self.agent_provider.name,
            self.agent_provider.version,
            _provider_protocol_provenance(self.agent_provider),
            verify_executable=verify_executable,
        )
        if observed != self._agent_codex_binding:
            raise RunnerError("Codex provider binding drifted after initialization")

    def _assert_comparator_authority_binding_integrity(self) -> None:
        if self.comparator_provider is None:
            if self._comparator_authority_binding is not None:
                raise RunnerError("comparator authority persisted without a provider")
            return
        if self.comparator_provider is not self._comparator_provider_instance:
            raise RunnerError(
                "comparator provider instance drifted after initialization"
            )
        if self.suite.comparator is None or self._comparator_authority_binding is None:
            raise RunnerError("comparator provider omitted its authority binding")
        observed = _provider_authority_binding(
            self.suite.comparator,
            self.comparator_provider,
            role="comparison",
            provider_name=_nonempty_provider_string(
                self.comparator_provider.name, "comparator provider name"
            ),
            provider_version=_nonempty_provider_string(
                self.comparator_provider.version, "comparator provider version"
            ),
            protocol_provenance=_provider_protocol_provenance(self.comparator_provider),
        )
        if observed != self._comparator_authority_binding:
            raise RunnerError("comparator provider authority binding drifted")

    def _production_comparator_release_authoritative(self) -> bool:
        if self.suite.comparator is None or self.comparator_provider is None:
            return False
        self._assert_comparator_authority_binding_integrity()
        capabilities = capabilities_for(
            self.suite.comparator.adapter_id, role="comparison"
        )
        if not (
            capabilities.authority_scope == "production"
            and self._comparator_authority_binding is not None
            and self._comparator_authority_binding["capability_sha256"]
            == capabilities.sha256
            and self.suite.comparator.adapter_id == "claude-cli"
            and type(self.comparator_provider) is ClaudeCliProvider
            and not self._comparator_provider_injected
            and self.comparator_provider is self._comparator_provider_instance
            and getattr(self.comparator_provider, "_config", None)
            == self.suite.comparator
            and self.comparator_provider.name == "claude-cli"
            and _provider_protocol_provenance(self.comparator_provider) is None
        ):
            return False
        return (
            _optional_sha256(
                getattr(self.comparator_provider, "executable_sha256", None),
                "comparator provider executable digest",
            )
            is not None
        )

    def _agent_result_json(
        self,
        result: ProviderResult,
        request: AgentRequest,
        *,
        verifier_only: bool = False,
    ) -> dict[str, Any]:
        self._assert_generator_execution_policy_integrity()
        if not isinstance(result, ProviderResult):
            raise RunnerError("agent provider returned an unsupported result type")
        try:
            payload = result.as_json()
        except ProviderError as exc:
            raise RunnerError(f"agent provider result is invalid: {exc}") from exc
        if payload["requested_model"] != request.model:
            raise RunnerError("agent result requested model differs from request")
        if tuple(payload["actual_models"]) != (request.model,):
            raise RunnerError("agent result did not use exactly the pinned model")
        if (
            payload["provider_name"] != self._agent_provider_name
            or payload["provider_version"] != self._agent_provider_version
        ):
            raise RunnerError("agent result provider identity differs from preflight")
        if payload["billing_basis"] != self.suite.provider.billing_basis:
            raise RunnerError("agent result billing basis differs from manifest")
        if payload["protocol_provenance"] != self._agent_protocol_provenance:
            raise RunnerError("agent result protocol provenance differs from preflight")
        sandbox = payload["sandbox"]
        expected_sandbox_kind = capabilities_for(
            self.suite.provider.adapter_id
        ).sandbox_kind
        injected_fake_admitted = (
            verifier_only
            and self._uses_exact_injected_fake_generator()
            and any(
                case.id == request.case_id and case.split != "holdout"
                for case in self.suite.cases
            )
        )
        if injected_fake_admitted:
            if sandbox != {"enforced": True, "kind": "fake"}:
                raise RunnerError(
                    "verifier-only fake agent result sandbox is not exact"
                )
        elif sandbox.get("kind") != expected_sandbox_kind:
            raise RunnerError("agent result sandbox kind differs from provider kind")
        if sandbox.get("enforced") is not True:
            raise RunnerError("agent result sandbox was not enforced")
        if self.suite.provider.adapter_id == "codex-app-server" and (
            sandbox.get("permission_profile") != "eval"
            or sandbox.get("cleanup_confirmed") is not True
        ):
            raise RunnerError(
                "Codex agent result lacks enforced eval-profile cleanup evidence"
            )
        return payload

    def _has_injected_fake_generator_identity(self) -> bool:
        return self.suite.provider.adapter_id == "claude-cli" and (
            isinstance(self.agent_provider, FakeProvider)
            or self._agent_provider_name == "deterministic-fake"
        )

    def _uses_exact_injected_fake_generator(self) -> bool:
        return (
            type(self.agent_provider) is FakeProvider
            and self.suite.provider.adapter_id == "claude-cli"
            and self._agent_provider_name == "deterministic-fake"
        )

    def _assert_injected_fake_generator_admissible(
        self,
        selection: RunSelection,
        cases: tuple[CaseSpec, ...],
    ) -> None:
        if not self._has_injected_fake_generator_identity():
            return
        if not (
            self._uses_exact_injected_fake_generator()
            and selection.verifier_only
            and all(case.split != "holdout" for case in cases)
        ):
            raise RunnerError(
                "an injected fake generator is allowed only for non-holdout "
                "verifier-only runs"
            )

    def _require_production_holdout_authority(self, runtime: ComparatorRuntime) -> None:
        try:
            runtime.require_production_authority()
        except CalibrationError as exc:
            raise RunnerError(str(exc)) from exc
        if (
            not runtime.bundle.release["test_release"]
            and not self._production_comparator_release_authoritative()
        ):
            raise RunnerError(
                "production holdout requires the exact built-in Claude CLI comparator"
            )

    @staticmethod
    def _assert_production_holdout_runtime(runtime: ComparatorRuntime) -> None:
        release_sha256 = hashlib.sha256(
            canonical_bytes(runtime.bundle.release)
        ).hexdigest()
        if release_sha256 != runtime.release_summary.get("release_sha256"):
            raise RunnerError("comparator release bytes drifted after load")
        try:
            runtime.require_live_calibration()
        except CalibrationError as exc:
            raise RunnerError(str(exc)) from exc
        if runtime.certification.evidence_sha256 is None:
            raise RunnerError(
                "production holdout requires live comparator calibration evidence"
            )

    @staticmethod
    def _assert_generic_holdout_source_authority(
        comparisons: tuple[ComparisonSpec, ...],
        cases: tuple[CaseSpec, ...],
        source_records: dict[str, Any],
    ) -> None:
        expected_cases = tuple(case.id for case in cases)
        for variant_id, record in source_records.items():
            hashes = record.get("source_sha256_by_case")
            if not isinstance(hashes, dict) or tuple(hashes) != expected_cases:
                raise RunnerError(
                    f"variant {variant_id} source fingerprints do not exactly match holdout cases"
                )
            if record.get("kind") == "without_skill":
                if record.get("source_commit") is not None or set(hashes.values()) != {
                    EMPTY_SOURCE_SHA256
                }:
                    raise RunnerError(
                        f"variant {variant_id} has invalid empty-source authority"
                    )
            elif not isinstance(record.get("source_commit"), str):
                raise RunnerError(
                    f"variant {variant_id} did not resolve to an exact source commit"
                )
        for comparison in comparisons:
            control = source_records[comparison.control]["source_sha256_by_case"]
            treatment = source_records[comparison.treatment]["source_sha256_by_case"]
            identical_cases = [
                case.id for case in cases if control[case.id] == treatment[case.id]
            ]
            if identical_cases:
                raise RunnerError(
                    f"holdout comparison {comparison.id} has identical evaluated sources "
                    f"for cases: {', '.join(identical_cases)}"
                )

    def _load_comparator_runtime(self) -> ComparatorRuntime:
        if self._comparator_runtime is None:
            comparator = self.suite.comparator
            profile = self.suite.comparator_profile
            if comparator is None or profile is None:
                raise RunnerError(
                    "objective-only suites do not have comparator runtimes"
                )
            test_release = comparator.adapter_id == "deterministic-fake"
            try:
                if profile.kind == "builtin":
                    certification_root, certification_name = (
                        self._profile_certification_location(profile.id)
                    )
                    self._comparator_runtime = ComparatorRuntime.load_builtin_profile(
                        profile.id,
                        external_suite_root=self.suite.root,
                        external_suite_manifest=self.suite.path,
                        certification_root=certification_root,
                        use_test_release=test_release,
                        certification_name=certification_name,
                    )
                elif profile.kind == "suite_local" and profile.resources is not None:
                    certification_root, certification_name = (
                        self._profile_certification_location(profile.id)
                    )
                    self._comparator_runtime = (
                        ComparatorRuntime.load_diagnostic_profile(
                            profile.resources,
                            use_test_release=test_release,
                            certification_root=certification_root,
                            certification_name=certification_name,
                        )
                    )
                else:
                    raise RunnerError("comparator profile binding is incomplete")
            except (CalibrationError, OSError, ValueError) as exc:
                raise RunnerError(
                    f"comparator protocol lock is invalid: {exc}"
                ) from exc
        return self._comparator_runtime

    def _profile_certification_location(self, profile_id: str) -> tuple[Path, str]:
        logical = self.suite.root / "comparator-evidence" / profile_id
        certification_name = "certification.json"
        current = self.suite.root
        for part in logical.relative_to(self.suite.root).parts:
            current = current / part
            if current.is_symlink():
                raise RunnerError("comparator certification root traverses a symlink")
        resolved = logical.resolve(strict=False)
        if not resolved.is_relative_to(self.suite.root):
            raise RunnerError("comparator certification root escapes the suite")
        if resolved.exists() and not resolved.is_dir():
            raise RunnerError("comparator certification root must be a directory")
        return resolved, certification_name

    def _assert_manifest_integrity(self) -> None:
        try:
            self.suite.assert_unchanged()
        except ManifestError as exc:
            raise RunnerError(f"suite manifest integrity check failed: {exc}") from exc

    def _selected(
        self,
        selection: RunSelection,
        *,
        allow_unsealed_holdout: bool = False,
    ) -> tuple[tuple[CaseSpec, ...], tuple[ComparisonSpec, ...]]:
        if selection.split not in {"train", "validation", "public", "holdout"}:
            raise RunnerError("split must be train, validation, public, or holdout")
        if allow_unsealed_holdout and selection.split != "holdout":
            raise RunnerError("unsealed preparation is only valid for holdout")
        if len(set(selection.case_ids)) != len(selection.case_ids):
            raise RunnerError("case selection must not contain duplicates")
        if len(set(selection.comparison_ids)) != len(selection.comparison_ids):
            raise RunnerError("comparison selection must not contain duplicates")
        self._validate_holdout_selection_shape(
            selection, allow_unsealed_holdout=allow_unsealed_holdout
        )
        if selection.split != "holdout":
            if selection.holdout_plan is not None:
                raise RunnerError("a holdout plan may only be used with split=holdout")
            if not selection.verifier_only and len(selection.comparison_ids) != 1:
                raise RunnerError(
                    "a judged diagnostic run requires exactly one explicit comparison id"
                )
        known_case_ids = {case.id for case in self.suite.cases}
        unknown_cases = set(selection.case_ids) - known_case_ids
        if unknown_cases:
            raise RunnerError(f"unknown case ids: {', '.join(sorted(unknown_cases))}")
        known_comparison_ids = {comparison.id for comparison in self.suite.comparisons}
        unknown_comparisons = set(selection.comparison_ids) - known_comparison_ids
        if unknown_comparisons:
            raise RunnerError(
                f"unknown comparison ids: {', '.join(sorted(unknown_comparisons))}"
            )
        case_filter = set(selection.case_ids)
        comparison_filter = set(selection.comparison_ids)
        cases = tuple(
            case
            for case in self.suite.cases
            if (
                (selection.split == "public" and case.split in {"train", "validation"})
                or case.split == selection.split
            )
            and (not case_filter or case.id in case_filter)
        )
        comparisons = tuple(
            comparison
            for comparison in self.suite.comparisons
            if not comparison_filter or comparison.id in comparison_filter
        )
        if not cases:
            raise RunnerError("selection matched no cases")
        if not comparisons:
            raise RunnerError("selection matched no comparisons")
        if selection.seed is not None and selection.seed < 0:
            raise RunnerError("seed override must be non-negative")
        if selection.split == "holdout":
            observed_profile = tuple(
                (
                    comparison.id,
                    comparison.control,
                    comparison.treatment,
                    comparison.repetitions,
                    comparison.comparator_order,
                )
                for comparison in comparisons
            )
            expected_profile = tuple(
                (
                    comparison.id,
                    comparison.control,
                    comparison.treatment,
                    3,
                    "ab_ba",
                )
                for comparison in comparisons
            )
            if observed_profile != expected_profile:
                raise RunnerError(
                    "holdout comparison semantics differ from the release profile"
                )
            skills = {case.skill for case in cases}
            counts = {
                skill: sum(case.skill == skill for case in cases) for skill in skills
            }
            if any(count < _MIN_HOLDOUT_CASES_PER_SKILL for count in counts.values()):
                raise RunnerError(
                    "holdout requires at least 8 cases for each selected skill"
                )
        return cases, comparisons

    def _validate_holdout_selection_shape(
        self,
        selection: RunSelection,
        *,
        allow_unsealed_holdout: bool,
    ) -> None:
        if selection.split != "holdout":
            return
        if allow_unsealed_holdout and selection.holdout_plan is not None:
            raise RunnerError("holdout preparation cannot consume an existing plan")
        if not allow_unsealed_holdout and selection.holdout_plan is None:
            raise RunnerError("holdout execution requires an explicit holdout plan")
        if selection.case_ids:
            raise RunnerError("holdout execution forbids case filters")
        if selection.seed is not None:
            raise RunnerError("holdout execution forbids seed overrides")
        release_comparison_ids = self.suite.holdout_comparison_ids
        if selection.comparison_ids != release_comparison_ids:
            raise RunnerError(
                "holdout execution requires exactly the explicit comparisons "
                + ", ".join(release_comparison_ids)
            )

    def _bind_holdout_plan(
        self,
        selection: RunSelection,
        cases: tuple[CaseSpec, ...],
        comparisons: tuple[ComparisonSpec, ...],
        source_records: dict[str, Any],
        case_records: list[dict[str, Any]],
    ) -> dict[str, Any] | None:
        if selection.split != "holdout":
            self._holdout_plan = None
            return None
        assert selection.holdout_plan is not None
        try:
            plan = load_holdout_plan(selection.holdout_plan)
        except HoldoutPlanError as exc:
            raise RunnerError(f"invalid holdout plan: {exc}") from exc
        if plan.path.is_relative_to(self.suite.root):
            raise RunnerError("holdout plan must be external to the evaluation suite")
        _validate_consumption_record_target(
            plan.consumption_record_path,
            self.suite.root,
            require_absent=True,
        )

        if plan.manifest_sha256 != self.suite.manifest_hash:
            raise RunnerError(
                "holdout plan manifest hash does not match exact suite bytes"
            )
        if plan.evaluation_mode != self.suite.evaluation_mode:
            raise RunnerError("holdout plan evaluation mode does not match the suite")
        runtime: ComparatorRuntime | None = None
        if plan.evaluation_mode == "judged":
            runtime = self._load_comparator_runtime()
            self._require_production_holdout_authority(runtime)
            self._assert_production_holdout_runtime(runtime)
            release_sha256 = runtime.release_summary["release_sha256"]
            if plan.comparator_release_sha256 != release_sha256:
                raise RunnerError(
                    "holdout plan comparator release hash does not match preflight"
                )
            evidence_sha256 = runtime.certification.evidence_sha256
            if not runtime.certification.valid or evidence_sha256 is None:
                raise RunnerError(
                    "production holdout requires valid live comparator certification evidence"
                )
            if plan.comparator_calibration_evidence_sha256 != evidence_sha256:
                raise RunnerError(
                    "holdout plan comparator calibration evidence hash does not match preflight"
                )
            expected_profile_binding = _comparator_profile_binding(runtime)
            observed_profile_binding = (
                plan.comparator_profile_id,
                plan.comparator_profile_descriptor_sha256,
                plan.comparator_profile_authority_registry_sha256,
            )
            if observed_profile_binding != expected_profile_binding:
                raise RunnerError(
                    "holdout plan comparator profile authority does not match preflight"
                )
        elif (
            plan.objective_acceptance_policy_id
            != _OBJECTIVE_ACCEPTANCE_POLICY["policy_id"]
            or plan.objective_acceptance_policy_sha256
            != _OBJECTIVE_ACCEPTANCE_POLICY_SHA256
        ):
            raise RunnerError(
                "holdout plan objective acceptance authority does not match preflight"
            )
        provider_binding = self._generator_provider_binding()
        if plan.generator_provider.as_json() != provider_binding:
            raise RunnerError(
                "holdout plan generator provider binding does not match preflight"
            )
        if plan.generator_adapter_binding.as_json() != self._agent_authority_binding:
            raise RunnerError(
                "holdout plan generator adapter authority does not match preflight"
            )
        observed_comparator_binding = (
            plan.comparator_adapter_binding.as_json()
            if plan.comparator_adapter_binding is not None
            else None
        )
        if observed_comparator_binding != self._comparator_authority_binding:
            raise RunnerError(
                "holdout plan comparator adapter authority does not match preflight"
            )
        if plan.seed != self.suite.seed:
            raise RunnerError("holdout plan seed does not match the suite seed")
        expected_profile = tuple(
            {
                "id": comparison.id,
                "control": comparison.control,
                "treatment": comparison.treatment,
                "repetitions": comparison.repetitions,
                "comparator_order": comparison.comparator_order,
            }
            for comparison in comparisons
        )
        observed_profile = tuple(item.as_json() for item in plan.comparison_profile)
        if observed_profile != expected_profile:
            raise RunnerError(
                "holdout plan comparison profile does not match the suite"
            )

        expected_bindings = tuple(
            {
                "variant_id": variant_id,
                "kind": source_records[variant_id]["kind"],
                "source_commit": source_records[variant_id]["source_commit"],
                "source_sha256_by_case": {
                    case_id: digest
                    for case_id, digest in sorted(
                        source_records[variant_id]["source_sha256_by_case"].items()
                    )
                },
            }
            for variant_id in sorted(source_records)
        )
        observed_bindings = tuple(binding.as_json() for binding in plan.source_bindings)
        if observed_bindings != expected_bindings:
            raise RunnerError(
                "holdout plan source bindings do not exactly match preflight"
            )
        self._assert_generic_holdout_source_authority(
            comparisons, cases, source_records
        )

        expected_cases = tuple(
            {
                "id": record["id"],
                "case_tree_sha256": record["case_tree_sha256"],
                "shared_tree_sha256": record["shared_tree_sha256"],
                "release_case_fingerprint": record["release_case_fingerprint"],
                "skill": record["skill"],
                "critical_expectations": record["critical_expectations"],
            }
            for record in case_records
        )
        observed_cases = tuple(item.as_json() for item in plan.cases)
        if observed_cases != expected_cases:
            raise RunnerError(
                "holdout plan cases do not exactly match ids, hashes, fingerprints, "
                "skills, and critical expectations"
            )
        if tuple(case.id for case in cases) != tuple(item.id for item in plan.cases):
            raise RunnerError("holdout plan case ordering does not match the suite")
        try:
            plan.assert_unchanged()
        except HoldoutPlanError as exc:
            raise RunnerError(f"invalid holdout plan: {exc}") from exc
        self._holdout_plan = plan
        evidence = plan.as_evidence()
        evidence["manifest_bound_models"] = {"generator": self.suite.provider.model}
        if plan.evaluation_mode == "judged":
            if self.suite.comparator is None or runtime is None:
                raise RunnerError(
                    "judged holdout plan requires a configured comparator"
                )
            evidence["manifest_bound_models"]["comparator"] = (
                self.suite.comparator.model
            )
            evidence["test_release_without_live_certification"] = bool(
                runtime.bundle.release["test_release"]
                and runtime.certification.evidence_sha256 is None
            )
            judgment_authority = bool(
                runtime.production_authority_valid
                and runtime.certification.valid
                and runtime.certification.evidence_sha256 is not None
            )
        else:
            judgment_authority = True
        evidence["production_release_authority_eligible"] = bool(
            judgment_authority and self._production_generator_release_authoritative()
        )
        return evidence

    def _assert_holdout_plan_integrity(self) -> None:
        if self._holdout_plan is None:
            return
        try:
            self._holdout_plan.assert_unchanged()
        except HoldoutPlanError as exc:
            raise RunnerError(f"invalid holdout plan: {exc}") from exc

    def _preflight_variant(
        self, variant: VariantSpec, cases: tuple[CaseSpec, ...]
    ) -> dict[str, Any]:
        if variant.kind == "without_skill":
            return {
                "kind": variant.kind,
                "source_commit": None,
                "source_dirty": None,
                "source_sha256_by_case": {
                    case.id: EMPTY_SOURCE_SHA256 for case in cases
                },
            }
        if variant.kind == "git_ref":
            if variant.git_ref is None:
                raise RunnerError(f"variant {variant.id} omitted git_ref")
            commit = _resolve_git_ref(self.suite.repository_root, variant.git_ref)
            self._git_commits[variant.id] = commit
            source_hashes: dict[str, str] = {}
            for case in cases:
                _git_bundle_entries(
                    self.suite.repository_root,
                    commit,
                    case.bundle_source,
                    ignore_generated_caches=True,
                )
                for context_file in case.context_files:
                    _git_blob(self.suite.repository_root, commit, context_file)
                source_hashes[case.id] = _git_source_fingerprint(
                    self.suite.repository_root,
                    commit,
                    case,
                    ignore_generated_caches=True,
                )
            return {
                "kind": variant.kind,
                "git_ref": variant.git_ref,
                "source_commit": commit,
                "source_dirty": False,
                "source_sha256_by_case": source_hashes,
            }
        if variant.kind == "worktree":
            if variant.root is None or variant.source_ref is None:
                raise RunnerError(
                    f"variant {variant.id} omitted worktree root or source_ref"
                )
            head_commit = _git_commit(variant.root)
            source_commit = _resolve_git_ref(variant.root, variant.source_ref)
            self._worktree_heads[variant.id] = head_commit
            self._worktree_source_commits[variant.id] = source_commit
            source_paths = _source_paths(cases)
            if _git_dirty(variant.root, source_paths):
                raise RunnerError(
                    f"variant {variant.id} bundle/context source is dirty; commit it before A/B evaluation"
                )
            for case in cases:
                bundle_root = _safe_repo_file(variant.root, case.bundle_source)
                if not bundle_root.is_dir() or bundle_root.is_symlink():
                    raise RunnerError(
                        f"variant {variant.id} has no regular bundle directory at {case.bundle_source}"
                    )
                _scan_tree(
                    bundle_root,
                    ignore_generated_caches=True,
                    ignore_empty_directories=True,
                )
                entrypoint = bundle_root / "SKILL.md"
                if not entrypoint.is_file() or entrypoint.is_symlink():
                    raise RunnerError(
                        f"variant {variant.id} bundle has no regular SKILL.md entrypoint at {case.bundle_source}"
                    )
                for context_file in case.context_files:
                    context_path = _safe_repo_file(variant.root, context_file)
                    if not context_path.is_file() or context_path.is_symlink():
                        raise RunnerError(
                            f"variant {variant.id} context file is missing: {context_file}"
                        )
                self._worktree_hashes[(variant.id, case.id)] = (
                    _worktree_source_fingerprint(
                        variant.root,
                        case,
                        ignore_empty_directories=True,
                    )
                )
                expected_hash = _git_source_fingerprint(
                    variant.root,
                    source_commit,
                    case,
                    ignore_generated_caches=True,
                )
                if self._worktree_hashes[(variant.id, case.id)] != expected_hash:
                    raise RunnerError(
                        f"variant {variant.id} skill/context bytes do not match "
                        f"source_ref {variant.source_ref} ({source_commit}) for case {case.id}"
                    )
            return {
                "kind": variant.kind,
                "root": str(variant.root),
                "source_ref": variant.source_ref,
                "expected_source_commit": source_commit,
                "worktree_head_commit": head_commit,
                "expected_source_sha256_by_case": {
                    case.id: self._worktree_hashes[(variant.id, case.id)]
                    for case in cases
                },
                "source_sha256_by_case": {
                    case.id: self._worktree_hashes[(variant.id, case.id)]
                    for case in cases
                },
                "source_commit": source_commit,
                "source_dirty": False,
            }
        raise RunnerError(f"unsupported variant kind: {variant.kind}")

    def _run_pair(
        self,
        comparison: ComparisonSpec,
        case: CaseSpec,
        repetition: int,
        *,
        seed: int,
        output_dir: Path,
        verifier_only: bool,
    ) -> dict[str, Any]:
        pair_id = f"{comparison.id}/{case.id}/{repetition:03d}"
        self._assert_generator_execution_policy_integrity()
        artifact_root = (
            output_dir / "pairs" / comparison.id / case.id / f"{repetition:03d}"
        )
        _mkdir_private(artifact_root, parents=True, exist_ok=False)
        self._assert_case_integrity(case)
        prompt = case.prompt_file.read_text(encoding="utf-8")
        base_files = _comparator_base_files(case.fixture_dir)
        variants = self.suite.variants_by_id
        cache_root = (
            Path(os.environ.get("XDG_CACHE_HOME", str(Path.home() / ".cache")))
            / "skill-evals"
        )
        cache_root.mkdir(parents=True, exist_ok=True, mode=0o700)
        with tempfile.TemporaryDirectory(
            prefix="skill-eval-pair-", dir=cache_root
        ) as temp_name:
            temp_root = Path(temp_name)
            roles = {
                "control": variants[comparison.control],
                "treatment": variants[comparison.treatment],
            }
            opaque_roots = {role: temp_root / uuid.uuid4().hex for role in roles}
            arm_execution_mode = self._agent_execution_policy["concurrency"]
            arm_execution_order: tuple[str, ...] | None = None
            if arm_execution_mode == "concurrent":
                start_barrier = threading.Barrier(2)
                with concurrent.futures.ThreadPoolExecutor(
                    max_workers=2, thread_name_prefix="skill-eval-arm"
                ) as executor:
                    futures = {
                        role: executor.submit(
                            self._run_arm,
                            pair_id,
                            comparison.id,
                            repetition,
                            role,
                            variant,
                            case,
                            prompt,
                            opaque_roots[role],
                            temp_root,
                            start_barrier,
                            artifact_root / role,
                            output_dir,
                            verifier_only,
                        )
                        for role, variant in roles.items()
                    }
                    arms = {role: future.result() for role, future in futures.items()}
            else:
                arm_execution_order = _serialized_arm_order(
                    seed,
                    comparison.id,
                    case.id,
                    repetition,
                )
                arms = {}
                for role in arm_execution_order:
                    arms[role] = self._run_arm(
                        pair_id,
                        comparison.id,
                        repetition,
                        role,
                        roles[role],
                        case,
                        prompt,
                        opaque_roots[role],
                        temp_root,
                        None,
                        artifact_root / role,
                        output_dir,
                        verifier_only,
                    )
        pair_errors: list[str] = []
        arms_started_concurrently: bool | None = None
        for role, arm in arms.items():
            if arm["status"] != "completed":
                pair_errors.append(f"{role}: {arm['error']}")
        if not pair_errors:
            control_provider = arms["control"]["provider"]
            treatment_provider = arms["treatment"]["provider"]
            if (
                control_provider["requested_model"]
                != treatment_provider["requested_model"]
            ):
                pair_errors.append("arms used different requested models")
            if control_provider["actual_models"] != treatment_provider["actual_models"]:
                pair_errors.append("arms used different actual models")
            if (
                arms["control"]["hashes"]["prompt_sha256"]
                != arms["treatment"]["hashes"]["prompt_sha256"]
            ):
                pair_errors.append("arms received different user prompts")
            if (
                arms["control"]["hashes"]["fixture_before_sha256"]
                != arms["treatment"]["hashes"]["fixture_before_sha256"]
            ):
                pair_errors.append("arms received different fixture snapshots")
            if arm_execution_mode == "concurrent":
                starts = [arm["provider_window"]["started"] for arm in arms.values()]
                finishes = [arm["provider_window"]["finished"] for arm in arms.values()]
                if all(value is not None for value in (*starts, *finishes)):
                    arms_started_concurrently = max(starts) <= min(finishes)
                if not arms_started_concurrently:
                    pair_errors.append(
                        "agent provider execution windows did not overlap"
                    )
        comparator_trials: list[dict[str, Any]] = []
        comparator_error: str | None = None
        consensus = "not_run"
        position_bias = False
        control_passed = arms["control"]["passed"]
        treatment_passed = arms["treatment"]["passed"]
        objective_only = self.suite.evaluation_mode == "objective_only"
        if pair_errors:
            final_winner = "inconclusive"
            winner_basis = "infrastructure_error"
        elif objective_only and control_passed == treatment_passed:
            final_winner = "tie"
            winner_basis = "verifier-pass-v1"
        elif treatment_passed and not control_passed:
            final_winner = "treatment"
            winner_basis = (
                "verifier-pass-v1" if objective_only else "objective_verifier"
            )
        elif control_passed and not treatment_passed:
            final_winner = "control"
            winner_basis = (
                "verifier-pass-v1" if objective_only else "objective_verifier"
            )
        elif not control_passed and not treatment_passed:
            final_winner = "unqualified"
            winner_basis = "objective_verifier"
        elif verifier_only:
            final_winner = "tie"
            winner_basis = "verifier_only"
        else:
            try:
                comparator_trials = self._compare_blind(
                    comparison,
                    case,
                    repetition,
                    arms,
                    prompt=prompt,
                    base_files=base_files,
                    seed=seed,
                    artifact_root=artifact_root,
                )
                normalized = [
                    trial["normalized_decision"] for trial in comparator_trials
                ]
                if len(normalized) != 2 or normalized[0] != normalized[1]:
                    position_bias = True
                    consensus = "inconclusive"
                    raise RunnerError("AB/BA full normalized decisions disagree")
                consensus = _map_outcome(normalized[0]["outcome"])
                final_winner = consensus
                winner_basis = "canonical_comparator"
            except (ProviderError, RunnerError, CalibrationError, OSError) as exc:
                comparator_error = str(exc)
                pair_errors.append(f"comparator: {exc}")
                final_winner = "inconclusive"
                winner_basis = "infrastructure_error"
        result = {
            "pair_id": pair_id,
            "comparison_id": comparison.id,
            "case_id": case.id,
            "skill": case.skill,
            "split": case.split,
            "repetition": repetition,
            "control_variant": comparison.control,
            "treatment_variant": comparison.treatment,
            "arm_execution_mode": arm_execution_mode,
            "arm_execution_order": (
                list(arm_execution_order) if arm_execution_order is not None else None
            ),
            "arms_started_concurrently": arms_started_concurrently,
            "arms": arms,
            "comparator_order": comparison.comparator_order,
            "comparator_trials": comparator_trials,
            "comparator_consensus": consensus,
            "comparator_error": comparator_error,
            "position_bias": position_bias,
            "final_winner": final_winner,
            "winner_basis": winner_basis,
            "infrastructure_errors": pair_errors,
            "completed": not pair_errors,
        }
        _write_json(artifact_root / "pair.json", result)
        return result

    def _run_arm(
        self,
        pair_id: str,
        comparison_id: str,
        repetition: int,
        role: str,
        variant: VariantSpec,
        case: CaseSpec,
        prompt: str,
        temp_root: Path,
        pair_root: Path,
        start_barrier: threading.Barrier | None,
        artifact_root: Path,
        result_root: Path,
        verifier_only: bool,
    ) -> dict[str, Any]:
        temp_root.mkdir(parents=True, mode=PRIVATE_DIRECTORY_MODE, exist_ok=False)
        _mkdir_private(artifact_root, parents=True, exist_ok=False)
        workspace = temp_root / "workspace"
        source: SourceMaterial | None = None
        provider_json: dict[str, Any] | None = None
        verifier_json: dict[str, Any] = {"ran": False, "valid": False}
        diff_text = ""
        hashes: dict[str, Any] = {"prompt_sha256": _sha256(prompt.encode("utf-8"))}
        provider_window: dict[str, float | None] = {"started": None, "finished": None}
        provider_dispatched = threading.Event()
        provider_attempt_id: str | None = None
        provider_journal_state: str | None = None
        provider_entered = False
        synchronization_complete = False
        normalized_artifact: NormalizedArtifact | None = None
        stage = "fixture_copy"
        try:
            self._assert_case_integrity(case)
            _copy_tree(case.fixture_dir, workspace, ignore_generated_caches=True)
            before = _read_tree(workspace, ignore_generated_caches=True)
            before_permissions = _read_tree_permissions(workspace)
            hashes["fixture_before_sha256"] = _states_hash(before)
            stage = "source_materialization"
            source = self._materialize_source(variant, case, temp_root / "source")
            hashes["skill_snapshot_sha256"] = source.snapshot_hash
            hashes["context_sha256"] = source.context_hash
            system_context = _system_context(case, source)

            def account_dispatch() -> None:
                if provider_attempt_id is None:
                    raise _GeneratorDispatchJournalError(
                        "generator dispatch callback preceded durable planning"
                    )
                ledger = self._generator_dispatch_ledger
                if ledger is None:
                    raise _GeneratorDispatchJournalError(
                        "generator dispatch ledger was not initialized"
                    )
                ledger.mark_dispatched(provider_attempt_id)
                provider_dispatched.set()

            request = AgentRequest(
                case_id=case.id,
                variant_id=variant.id,
                prompt=prompt,
                model=self.suite.provider.model,
                workspace=workspace,
                skill_snapshot=source.snapshot,
                sandbox_pair_root=pair_root,
                sandbox_repository_root=self.suite.repository_root,
                system_context=system_context,
                timeout_seconds=min(
                    case.timeout_seconds, self.suite.provider.timeout_seconds
                ),
                sandbox_suite_root=self.suite.root,
                required_tools=self._verifier_tools.get(case.id, ()),
                on_dispatched=account_dispatch,
            )
            ledger = self._generator_dispatch_ledger
            if ledger is None:
                raise _GeneratorDispatchJournalError(
                    "generator dispatch ledger was not initialized"
                )
            stage = "agent_accounting"
            provider_attempt_id = ledger.plan_attempt(
                comparison_id=comparison_id,
                case_id=case.id,
                repetition=repetition,
                role=role,
                variant_id=variant.id,
                request_sha256=_generator_request_sha256(
                    request,
                    comparison_id=comparison_id,
                    repetition=repetition,
                    role=role,
                    skill_snapshot_sha256=source.snapshot_hash,
                    context_sha256=source.context_hash,
                ),
            )
            provider_journal_state = "planned"
            stage = "agent_sync"
            if start_barrier is not None:
                start_barrier.wait(timeout=min(30, case.timeout_seconds))
                provider_window["started"] = time.monotonic()
                start_barrier.wait(timeout=min(30, case.timeout_seconds))
            else:
                provider_window["started"] = time.monotonic()
            synchronization_complete = True
            stage = "agent"
            try:
                provider_entered = True
                provider_result = self.agent_provider.run_agent(request)
                if not provider_dispatched.is_set():
                    account_dispatch()
                provider_journal_state = "dispatched"
                if case.artifact_contract.kind != "workspace_diff":
                    stage = "artifact_normalization"
                    normalized_artifact = normalize_artifact(
                        case.artifact_contract.kind,
                        provider_result.final_output,
                    )
                    stage = "agent_result"
                provider_json = self._agent_result_json(
                    provider_result,
                    request,
                    verifier_only=verifier_only,
                )
                if source.snapshot is not None:
                    observed_snapshot_hash = _tree_hash(source.snapshot)
                    if observed_snapshot_hash != source.snapshot_hash:
                        raise RunnerError("agent mutated the read-only skill snapshot")
                ledger.mark_completed(
                    provider_attempt_id,
                    _generator_digest(provider_json),
                )
                provider_journal_state = "completed"
            finally:
                provider_window["finished"] = time.monotonic()
                if source is not None and source.snapshot is not None:
                    _make_tree_writable(source.snapshot)
            hashes["agent_output_sha256"] = _sha256(
                provider_result.final_output.encode("utf-8")
            )
            _write_text(
                artifact_root / "final_output.txt", provider_result.final_output
            )
            stage = "agent_workspace_scan"
            after_agent = _read_tree(workspace, ignore_generated_caches=True)
            after_agent_mutation = _read_tree(workspace)
            after_agent_permissions = _read_tree_permissions(workspace)
            agent_workspace_mutated = (
                before != after_agent_mutation
                or before_permissions != after_agent_permissions
            )
            hashes["workspace_after_agent_sha256"] = _states_hash(after_agent)
            diff_text = _diff_states(before, after_agent)
            hashes["diff_sha256"] = _sha256(diff_text.encode("utf-8"))
            _write_text(artifact_root / "diff.patch", diff_text)
            if case.artifact_contract.kind == "workspace_diff":
                stage = "artifact_normalization"
                normalized_artifact = normalize_artifact("workspace_diff", diff_text)
            if normalized_artifact is None:
                raise RunnerError("case did not produce its declared artifact")
            artifact_evidence = normalized_artifact.as_evidence()
            hashes["artifact_sha256"] = normalized_artifact.sha256
            _write_bytes(
                artifact_root / normalized_artifact.filename,
                normalized_artifact.content,
            )
            stage = "verifier"
            self._assert_case_integrity(case)
            verifier_workspace = temp_root / "verifier-workspace"
            final_output_artifact = case.artifact_contract.kind != "workspace_diff"
            _copy_tree(
                case.fixture_dir if final_output_artifact else workspace,
                verifier_workspace,
                ignore_generated_caches=True,
            )
            verifier_before_hash = _tree_hash(verifier_workspace)
            verifier_json = self._run_verifier(
                case,
                verifier_workspace,
                normalized_artifact,
                result_root,
                workspace_read_only=final_output_artifact,
                agent_workspace_mutated=agent_workspace_mutated,
            )
            verifier_after_hash = _tree_hash(verifier_workspace)
            verifier_json["workspace_before_sha256"] = verifier_before_hash
            verifier_json["workspace_after_sha256"] = verifier_after_hash
            verifier_json["workspace_mutated"] = (
                verifier_before_hash != verifier_after_hash
            )
            if not verifier_json["valid"]:
                raise RunnerError(verifier_json["error"])
            critical = {
                assertion["id"]: assertion["passed"]
                for assertion in verifier_json["assertions"]
                if assertion["id"] in case.critical_expectations
            }
            passed = verifier_json["passed"] and all(critical.values())
            result = {
                "pair_id": pair_id,
                "role": role,
                "variant_id": variant.id,
                "variant_kind": variant.kind,
                "status": "completed",
                "error_stage": None,
                "error": None,
                "passed": passed,
                "source": _source_json(source),
                "provider": provider_json,
                "provider_accounting": {
                    "attempt_id": provider_attempt_id,
                    "billing_basis": self.suite.provider.billing_basis,
                    "dispatched": provider_dispatched.is_set(),
                    "journal_state": provider_journal_state,
                    "provider_entered": provider_entered,
                },
                "verifier": verifier_json,
                "artifact": artifact_evidence,
                "critical_results": critical,
                "hashes": hashes,
                "provider_window": provider_window,
                "diff": diff_text,
            }
        except (
            Exception
        ) as exc:  # The arm records all failures instead of losing pair evidence.
            if not synchronization_complete and start_barrier is not None:
                try:
                    start_barrier.abort()
                except threading.BrokenBarrierError:
                    pass
            if isinstance(exc, _GeneratorDispatchJournalError):
                raise
            if provider_attempt_id is not None and provider_journal_state not in {
                "completed",
                "failed",
            }:
                ledger = self._generator_dispatch_ledger
                if ledger is None:
                    raise _GeneratorDispatchJournalError(
                        "generator dispatch ledger was not initialized"
                    )
                ledger.mark_failed(
                    provider_attempt_id,
                    dispatch_observed=provider_dispatched.is_set(),
                    failure_category=_generator_failure_category(exc, stage),
                )
                provider_journal_state = "failed"
            result = {
                "pair_id": pair_id,
                "role": role,
                "variant_id": variant.id,
                "variant_kind": variant.kind,
                "status": "error",
                "error_stage": stage,
                "error": f"{type(exc).__name__}: {exc}",
                "passed": False,
                "source": _source_json(source),
                "provider": provider_json,
                "provider_accounting": {
                    "attempt_id": provider_attempt_id,
                    "billing_basis": self.suite.provider.billing_basis,
                    "dispatched": provider_dispatched.is_set(),
                    "journal_state": provider_journal_state,
                    "provider_entered": provider_entered,
                },
                "verifier": verifier_json,
                "artifact": (
                    normalized_artifact.as_evidence()
                    if normalized_artifact is not None
                    else None
                ),
                "critical_results": {},
                "hashes": hashes,
                "provider_window": provider_window,
                "diff": diff_text,
            }
        _write_json(artifact_root / "verifier.json", verifier_json)
        _write_json(artifact_root / "arm.json", result)
        return result

    def _materialize_source(
        self, variant: VariantSpec, case: CaseSpec, target_root: Path
    ) -> SourceMaterial:
        empty_hash = _sha256(b"")
        if variant.kind == "without_skill":
            return SourceMaterial(None, None, "", empty_hash, None, None)
        snapshot = target_root / "skill"
        context_parts: list[str] = []
        if variant.kind == "git_ref":
            commit = self._git_commits.get(variant.id)
            if commit is None:
                raise RunnerError(f"variant {variant.id} was not preflighted")
            _materialize_git_bundle(
                self.suite.repository_root,
                commit,
                case.bundle_source,
                snapshot,
                ignore_generated_caches=True,
            )
            for context_file in case.context_files:
                content = _git_blob(self.suite.repository_root, commit, context_file)
                context_parts.append(_decode_context(content, context_file))
            source_dirty: bool | None = False
        elif variant.kind == "worktree":
            if variant.root is None:
                raise RunnerError(f"variant {variant.id} omitted worktree root")
            expected_head = self._worktree_heads.get(variant.id)
            if expected_head is None or _git_commit(variant.root) != expected_head:
                raise RunnerError(
                    f"variant {variant.id} worktree HEAD changed after preflight"
                )
            commit = self._worktree_source_commits.get(variant.id)
            if commit is None:
                raise RunnerError(
                    f"variant {variant.id} source_ref was not preflighted"
                )
            expected_hash = self._worktree_hashes.get((variant.id, case.id))
            observed_hash = _worktree_source_fingerprint(
                variant.root,
                case,
                ignore_empty_directories=True,
            )
            if expected_hash is None or observed_hash != expected_hash:
                raise RunnerError(
                    f"variant {variant.id} skill/context source drifted after preflight"
                )
            bundle_source = _safe_repo_file(variant.root, case.bundle_source)
            _copy_tree(
                bundle_source,
                snapshot,
                ignore_generated_caches=True,
                ignore_empty_directories=True,
            )
            for context_file in case.context_files:
                context_path = _safe_repo_file(variant.root, context_file)
                try:
                    content = context_path.read_bytes()
                except OSError as exc:
                    raise RunnerError(
                        f"cannot read context file {context_file}: {exc}"
                    ) from exc
                context_parts.append(_decode_context(content, context_file))
            source_paths = _source_paths((case,))
            source_dirty = _git_dirty(variant.root, source_paths)
            if source_dirty:
                raise RunnerError(
                    f"variant {variant.id} skill/context source became dirty after preflight"
                )
        else:
            raise RunnerError(f"unsupported variant kind: {variant.kind}")
        snapshot_hash = _tree_hash(snapshot)
        _make_tree_readonly(snapshot)
        context_text = "\n\n".join(context_parts)
        return SourceMaterial(
            snapshot=snapshot,
            snapshot_hash=snapshot_hash,
            context_text=context_text,
            context_hash=_sha256(context_text.encode("utf-8")),
            source_commit=commit,
            source_dirty=source_dirty,
        )

    def _assert_case_integrity(self, case: CaseSpec) -> None:
        expected = self._case_hashes.get(case.id)
        if expected is None:
            raise RunnerError(f"case {case.id} was not preflighted")
        stored = self._case_snapshots.get(case.id)
        if stored is None:
            raise RunnerError(f"case {case.id} has no preflight source snapshot")
        shared_root = _effective_shared_verifier_dir(self.suite)
        observed = _combined_case_hash(
            _snapshot_tree(case.prompt_file.parent, ignore_generated_caches=True),
            _snapshot_tree(shared_root, ignore_generated_caches=True)
            if shared_root is not None
            else None,
        )
        if (
            observed != expected
            or _combined_case_hash(stored, self._shared_snapshot) != expected
        ):
            raise RunnerError(
                f"case {case.id} prompt/fixture/verifier source drifted after preflight"
            )

    def _run_verifier(
        self,
        case: CaseSpec,
        workspace: Path,
        artifact: NormalizedArtifact,
        result_root: Path,
        *,
        workspace_read_only: bool,
        agent_workspace_mutated: bool,
    ) -> dict[str, Any]:
        command = self._verifier_commands.get(case.id)
        if command is None:
            raise RunnerError(f"case {case.id} verifier was not preflighted")
        executable_bundle = self._verifier_executables.get(case.id)
        if executable_bundle is None:
            raise RunnerError(f"case {case.id} executable bundle was not preflighted")
        case_snapshot = self._case_snapshots.get(case.id)
        if case_snapshot is None:
            raise RunnerError(f"case {case.id} source snapshot was not preflighted")
        interpreter, tool_attestations = executable_bundle
        runtime_root = _runtime_root("skill-verifier")
        runtime_mount = _runtime_mountpoint("skill-eval-verifier-runtime")
        runtime_workspace = runtime_root / "work"
        runtime_case = runtime_root / "case"
        runtime_shared = runtime_root / "_shared"
        runtime_tool_bin = runtime_root / "tool-bin"
        runtime_artifact = runtime_root / "artifact" / artifact.filename
        mounted_workspace = runtime_mount / "work"
        mounted_case = runtime_mount / "case"
        mounted_shared = runtime_mount / "_shared"
        mounted_tool_bin = runtime_mount / "tool-bin"
        mounted_artifact = runtime_mount / "artifact" / artifact.filename
        shared_environment_enabled = self._shared_snapshot is not None
        shared_mount_enabled = self._shared_snapshot is not None
        _copy_tree(workspace, runtime_workspace)
        _write_bytes(runtime_artifact, artifact.content)
        artifact.assert_content(_read_private_artifact(runtime_artifact))
        _materialize_snapshot(case_snapshot, runtime_case)
        if self._shared_snapshot is not None:
            _materialize_snapshot(self._shared_snapshot, runtime_shared)
        executable_attestations = tuple(
            _flatten_executable_attestations((interpreter, *tool_attestations))
        )
        copied_executables = _materialize_executable_bundle(
            runtime_tool_bin, executable_attestations
        )
        for name, evidence in copied_executables.items():
            evidence["executed_path"] = str(mounted_tool_bin / name)
        case_root = case.prompt_file.parent
        shared_root = _effective_shared_verifier_dir(self.suite)
        translated: list[str] = []
        for index, argument in enumerate(command):
            if index == 0:
                translated.append(str(mounted_tool_bin / interpreter.logical_name))
                continue
            argument_path = Path(argument)
            if argument_path.is_absolute() and argument_path.is_relative_to(case_root):
                translated.append(
                    str(mounted_case / argument_path.relative_to(case_root))
                )
            elif (
                argument_path.is_absolute()
                and shared_root is not None
                and argument_path.is_relative_to(shared_root)
            ):
                translated.append(
                    str(mounted_shared / argument_path.relative_to(shared_root))
                )
            else:
                translated.append(argument)
        unit_name = f"skill-verifier-{uuid.uuid4().hex}"
        sensitive_roots = _sensitive_host_roots()
        resolved_tools = self._verifier_tools.get(case.id)
        if resolved_tools is None:
            raise RunnerError(f"case {case.id} required tools were not preflighted")
        go_roots = {
            attestation.go_root
            for attestation in executable_attestations
            if attestation.go_root is not None
        }
        if len(go_roots) > 1:
            raise RunnerError(f"case {case.id} resolved conflicting Go roots")
        go_root = next(iter(go_roots), None)
        gcc_prefixes = {
            attestation.gcc_exec_prefix
            for attestation in executable_attestations
            if attestation.gcc_exec_prefix is not None
        }
        if len(gcc_prefixes) > 1:
            raise RunnerError(f"case {case.id} resolved conflicting GCC roots")
        gcc_exec_prefix = next(iter(gcc_prefixes), None)
        properties = [
            *SANDBOX_ISOLATION_PROPERTIES,
            "PrivateNetwork=yes",
            "MemoryMax=3G",
            "TasksMax=256",
            "LimitNOFILE=2048",
            "LimitFSIZE=256M",
            f"RuntimeMaxSec={case.verifier.timeout_seconds}s",
            "KillMode=control-group",
            "UMask=0077",
            f"ReadWritePaths={runtime_mount}",
            f"InaccessiblePaths={self.suite.repository_root}",
            f"InaccessiblePaths={self.suite.root}",
            f"InaccessiblePaths={workspace.parents[1]}",
            f"InaccessiblePaths=-{result_root}",
            f"BindPaths={runtime_root}:{runtime_mount}",
            f"BindReadOnlyPaths={runtime_case}:{mounted_case}",
            f"BindReadOnlyPaths={runtime_tool_bin}:{mounted_tool_bin}",
            f"BindReadOnlyPaths={runtime_artifact}:{mounted_artifact}",
        ]
        if workspace_read_only:
            properties.append(
                f"BindReadOnlyPaths={runtime_workspace}:{mounted_workspace}"
            )
        properties.extend(f"InaccessiblePaths={root}" for root in sensitive_roots)
        if shared_mount_enabled:
            properties.append(f"BindReadOnlyPaths={runtime_shared}:{mounted_shared}")
        sandbox_command = [
            self._systemd_run,
            "--user",
            "--pipe",
            "--wait",
            "--collect",
            f"--unit={unit_name}",
        ]
        for property_value in properties:
            sandbox_command.extend(["-p", property_value])
        sandbox_command.extend(
            [
                f"--working-directory={mounted_workspace}",
                "--",
                self._env_tool,
                "-i",
                f"PATH={mounted_tool_bin}",
                "HOME=/nonexistent",
                "LANG=C.UTF-8",
                "LC_ALL=C.UTF-8",
                "GOCACHE=/tmp/go-cache",
                *([f"GOROOT={go_root}"] if go_root is not None else []),
                *(
                    [
                        f"GCC_EXEC_PREFIX={gcc_exec_prefix}/",
                        f"COMPILER_PATH={mounted_tool_bin}",
                        "CGO_ENABLED=1",
                    ]
                    if gcc_exec_prefix is not None
                    else []
                ),
                "NPM_CONFIG_CACHE=/tmp/npm-cache",
                "PYTHONDONTWRITEBYTECODE=1",
                "PYTHONPYCACHEPREFIX=/tmp/python-pycache",
                f"EVAL_WORKSPACE={mounted_workspace}",
                f"EVAL_ARTIFACT_PATH={mounted_artifact}",
                f"EVAL_ARTIFACT_KIND={artifact.kind}",
                f"EVAL_ARTIFACT_SHA256={artifact.sha256}",
                f"EVAL_AGENT_WORKSPACE_MUTATED={int(agent_workspace_mutated)}",
                f"EVAL_CASE_ROOT={mounted_case}",
                *(
                    [f"EVAL_SHARED_ROOT={mounted_shared}"]
                    if shared_environment_enabled
                    else []
                ),
                f"EVAL_TOOL_BIN={mounted_tool_bin}",
                f"EVAL_RESULT_ROOT={result_root}",
                f"EVAL_HOST_UID={os.getuid()}",
                f"EVAL_UNSHARE={self._unshare_tool}",
                f"EVAL_MOUNT={self._mount_tool}",
                f"EVAL_SETPRIV={self._setpriv_tool}",
                f"EVAL_ENV={self._env_tool}",
                *([f"EVAL_GO_ROOT={go_root}"] if go_root is not None else []),
                *(
                    [f"EVAL_GCC_EXEC_PREFIX={gcc_exec_prefix}"]
                    if gcc_exec_prefix is not None
                    else []
                ),
                self._unshare_tool,
                "--user",
                "--map-current-user",
                "--pid",
                "--fork",
                "--mount-proc",
                "--kill-child",
                *translated,
            ]
        )
        client_env = _systemd_client_environment()
        sandbox_evidence = {
            "kind": "systemd-run-user",
            "enforced": True,
            "version": self._sandbox_version,
            "properties": properties,
            "environment_mode": "env-i-allowlist",
            "process_namespace": "unshare-user-pid-private-proc",
            "candidate_process_namespace": (
                "nested-unshare-user-mount-pid-net-ipc-uts-private-proc"
            ),
            "result_root_masked": str(result_root),
            "verifier_interpreter": interpreter.as_json(),
            "required_tools": {
                name: attestation.as_json()
                for name, attestation in zip(
                    case.verifier.required_tools, tool_attestations, strict=True
                )
            },
            "copied_executables": copied_executables,
            "executed_interpreter": str(mounted_tool_bin / interpreter.logical_name),
            "artifact": {
                **artifact.as_evidence(),
                "mounted_path": str(mounted_artifact),
                "read_only": True,
            },
            "workspace_read_only": workspace_read_only,
            "agent_workspace_mutated": agent_workspace_mutated,
            "go_root": str(go_root) if go_root is not None else None,
            "gcc_exec_prefix": (
                str(gcc_exec_prefix) if gcc_exec_prefix is not None else None
            ),
        }
        started = time.monotonic()
        try:
            try:
                completed = subprocess.run(
                    sandbox_command,
                    cwd=runtime_root,
                    capture_output=True,
                    text=True,
                    timeout=case.verifier.timeout_seconds + 10,
                    check=False,
                    shell=False,
                    env=client_env,
                    start_new_session=True,
                )
            except subprocess.TimeoutExpired as exc:
                _stop_systemd_unit(self._systemctl, unit_name)
                return {
                    "ran": True,
                    "valid": False,
                    "error": f"verifier timed out after {case.verifier.timeout_seconds}s",
                    "argv": list(command),
                    "exit_code": None,
                    "duration_seconds": time.monotonic() - started,
                    "stdout": _timeout_text(exc.stdout),
                    "stderr": _timeout_text(exc.stderr),
                    "sandbox": sandbox_evidence,
                    "artifact": sandbox_evidence["artifact"],
                }
            except OSError as exc:
                return {
                    "ran": False,
                    "valid": False,
                    "error": f"verifier failed to execute: {exc}",
                    "argv": list(command),
                    "exit_code": None,
                    "duration_seconds": time.monotonic() - started,
                    "stdout": "",
                    "stderr": "",
                    "sandbox": sandbox_evidence,
                    "artifact": sandbox_evidence["artifact"],
                }
            _verify_executable_bundle(runtime_tool_bin, copied_executables)
            duration = time.monotonic() - started
            evidence: dict[str, Any] = {
                "ran": True,
                "valid": False,
                "argv": list(command),
                "executed_argv": translated,
                "exit_code": completed.returncode,
                "duration_seconds": duration,
                "stdout": completed.stdout,
                "stderr": completed.stderr,
                "stdout_sha256": _sha256(completed.stdout.encode("utf-8")),
                "sandbox": sandbox_evidence,
                "artifact": sandbox_evidence["artifact"],
            }
            if completed.returncode != 0:
                runtime_limit_hit = duration >= case.verifier.timeout_seconds * 0.8
                evidence["timed_out"] = runtime_limit_hit
                evidence["error"] = (
                    f"verifier timed out after {case.verifier.timeout_seconds}s"
                    if runtime_limit_hit
                    else f"verifier exited {completed.returncode}: {completed.stderr.strip()}"
                )
                return evidence
            try:
                payload, assertions, metrics = _validate_verifier_payload(
                    completed.stdout, case.critical_expectations
                )
            except RunnerError as exc:
                evidence["error"] = str(exc)
                return evidence
            evidence.update(
                {
                    "valid": True,
                    "passed": payload["passed"],
                    "assertions": assertions,
                    "metrics": metrics,
                }
            )
            return evidence
        finally:
            artifact_drift_error: RunnerError | None = None
            try:
                artifact.assert_content(_read_private_artifact(runtime_artifact))
            except (ArtifactError, OSError, RunnerError) as exc:
                artifact_drift_error = RunnerError(
                    f"normalized verifier artifact drifted: {exc}"
                )
            for path in (
                runtime_workspace,
                runtime_case,
                runtime_shared,
                runtime_tool_bin,
            ):
                _make_tree_writable(path)
            if workspace.exists():
                shutil.rmtree(workspace)
            shutil.copytree(runtime_workspace, workspace, symlinks=True)
            shutil.rmtree(runtime_root, ignore_errors=True)
            if artifact_drift_error is not None:
                raise artifact_drift_error

    def _compare_blind(
        self,
        comparison: ComparisonSpec,
        case: CaseSpec,
        repetition: int,
        arms: dict[str, dict[str, Any]],
        *,
        prompt: str,
        base_files: dict[str, str],
        seed: int,
        artifact_root: Path,
    ) -> list[dict[str, Any]]:
        cache_root = (
            Path(os.environ.get("XDG_CACHE_HOME", str(Path.home() / ".cache")))
            / "skill-evals"
        )
        cache_root.mkdir(parents=True, exist_ok=True, mode=0o700)
        isolation_root = Path(tempfile.mkdtemp(prefix="judge-runtime-", dir=cache_root))
        spend_ledger = self._comparator_spend.get(comparison.id)
        if spend_ledger is None:
            raise RunnerError(
                f"comparator spend ledger was not initialized for {comparison.id}"
            )
        runtime = self._load_comparator_runtime()
        if case.comparator_contract is None:
            raise RunnerError("judged case omitted its comparator contract")
        opaque_id = (
            "runtime-"
            + hashlib.sha256(
                (
                    f"{self.suite.manifest_hash}\0{comparison.id}\0{case.id}\0"
                    f"{repetition}\0{seed}"
                ).encode("utf-8")
            ).hexdigest()[:24]
        )
        pair = runtime_pair(
            opaque_id=opaque_id,
            task=prompt,
            contract=case.comparator_contract,
            base_files=base_files,
            diff_a=arms["control"]["diff"],
            diff_b=arms["treatment"]["diff"],
        )
        _assert_runtime_pair_representable(pair)
        orders = ("AB", "BA")

        def compare_one(index: int, order: str) -> dict[str, Any]:
            if self.suite.comparator is None or self.comparator_provider is None:
                raise RunnerError("judged comparison requires a comparator provider")
            self._assert_comparator_authority_binding_integrity()
            request_bytes = runtime.request_bytes(pair, repetition, order)
            request = ComparatorRequest(
                pair=pair,
                repetition=repetition,
                order=order,
                request_bytes=request_bytes,
                runtime=runtime,
                spend_ledger=spend_ledger,
                model=self.suite.comparator.model,
                timeout_seconds=self.suite.comparator.timeout_seconds,
                max_budget_usd=self.suite.comparator.max_budget_usd,
                sandbox_repository_root=self.suite.repository_root,
                sandbox_suite_root=self.suite.root,
                sandbox_isolation_root=isolation_root,
            )
            result = self.comparator_provider.run_comparator(request)
            result_json = result.as_json(request)
            self._assert_comparator_authority_binding_integrity()
            trial = {
                "index": index,
                "order": order,
                "invocation_id": runtime.invocation_id(opaque_id, repetition, order),
                "request_sha256": hashlib.sha256(request_bytes).hexdigest(),
                "normalized_decision": result_json["decision"],
                "response": result_json["response"],
                "transport": result_json["transport"],
                "provider": result_json["provider"],
            }
            _write_json(artifact_root / f"comparator-{index}.json", trial)
            return trial

        try:
            with concurrent.futures.ThreadPoolExecutor(
                max_workers=2, thread_name_prefix="skill-eval-comparator"
            ) as executor:
                futures = [
                    executor.submit(compare_one, index, order)
                    for index, order in enumerate(orders)
                ]
                return [future.result() for future in futures]
        finally:
            shutil.rmtree(isolation_root, ignore_errors=True)


def _system_context(case: CaseSpec, source: SourceMaterial) -> str:
    common = """This is an isolated agent-harness evaluation.
Work only inside the current fixture workspace. Do not inspect configuration, skills,
memory, or repositories outside the paths explicitly supplied by this evaluation.
Complete the user request in the fixture, run relevant local checks when applicable,
    and end with a concise factual summary of changes and executed verification. Never mention
    the evaluation harness or speculate about experimental roles."""
    if source.snapshot is None:
        return (
            common
            + "\nNo supplemental instruction bundle is supplied. Do not load external bundles."
        )
    context = f"""
    Supplemental instructions are materialized at this read-only directory:
{source.snapshot}
    Read SKILL.md first, then follow its reference routing from that directory. Apply the
    instructions operationally. Never edit the supplied directory."""
    if source.context_text:
        context += f"""

The following explicitly selected context files were loaded from the same variant source:
<explicit-context>
{source.context_text}
</explicit-context>"""
    return common + context


def _source_json(source: SourceMaterial | None) -> dict[str, Any] | None:
    if source is None:
        return None
    return {
        "skill_snapshot_present": source.snapshot is not None,
        "skill_snapshot_sha256": source.snapshot_hash,
        "context_sha256": source.context_hash,
        "source_commit": source.source_commit,
        "source_dirty": source.source_dirty,
    }


def _execution_plan(
    cases: tuple[CaseSpec, ...],
    comparisons: tuple[ComparisonSpec, ...],
    runtime: ComparatorRuntime | None,
    *,
    agent_per_invocation_max_usd: float | None,
    agent_billing_basis: str,
) -> dict[str, Any]:
    comparator_per_call = (
        runtime.bundle.release["execution_limits"]["per_invocation_max_usd"]
        if runtime is not None
        else 0.0
    )
    comparator_run_cap = (
        runtime.bundle.release["execution_limits"]["run_max_usd"]
        if runtime is not None
        else 0.0
    )
    if agent_billing_basis == "chatgpt_subscription":
        if agent_per_invocation_max_usd is not None:
            raise RunnerError(
                "subscription generator cannot declare a dollar invocation maximum"
            )
        agent_per_call = None
    elif agent_billing_basis == "metered_api":
        agent_per_call = (
            0.0
            if agent_per_invocation_max_usd is None
            else agent_per_invocation_max_usd
        )
    else:
        raise RunnerError(f"unsupported generator billing basis: {agent_billing_basis}")
    by_comparison: list[dict[str, Any]] = []
    for comparison in comparisons:
        pair_runs = comparison.repetitions * len(cases)
        agent_calls = pair_runs * 2
        comparator_calls = pair_runs * 2 if runtime is not None else 0
        agent_exposure = (
            None if agent_per_call is None else agent_calls * agent_per_call
        )
        comparator_exposure = comparator_calls * comparator_per_call
        by_comparison.append(
            {
                "comparison_id": comparison.id,
                "case_count": len(cases),
                "repetitions": comparison.repetitions,
                "pair_runs": pair_runs,
                "planned_agent_calls": agent_calls,
                "agent_billing_basis": agent_billing_basis,
                "maximum_agent_exposure_usd": agent_exposure,
                "maximum_comparator_calls": comparator_calls,
                "maximum_comparator_exposure_usd": comparator_exposure,
                "comparator_run_cap_usd": comparator_run_cap,
                "maximum_combined_exposure_usd": (
                    None
                    if agent_exposure is None
                    else agent_exposure + comparator_exposure
                ),
            }
        )
    pair_runs = sum(item["pair_runs"] for item in by_comparison)
    planned_agent_calls = sum(item["planned_agent_calls"] for item in by_comparison)
    maximum_comparator_calls = sum(
        item["maximum_comparator_calls"] for item in by_comparison
    )
    maximum_agent_exposure = (
        None
        if agent_per_call is None
        else sum(item["maximum_agent_exposure_usd"] for item in by_comparison)
    )
    maximum_comparator_exposure = sum(
        item["maximum_comparator_exposure_usd"] for item in by_comparison
    )
    return {
        "pair_runs": pair_runs,
        "planned_agent_calls": planned_agent_calls,
        "agent_billing_basis": agent_billing_basis,
        "maximum_agent_exposure_usd": maximum_agent_exposure,
        "maximum_comparator_calls": maximum_comparator_calls,
        "maximum_comparator_exposure_usd": maximum_comparator_exposure,
        "maximum_combined_exposure_usd": (
            None
            if maximum_agent_exposure is None
            else maximum_agent_exposure + maximum_comparator_exposure
        ),
        "comparator_run_cap_usd": comparator_run_cap,
        "total_comparator_run_cap_usd": comparator_run_cap * len(comparisons),
        "agent_per_invocation_max_usd": agent_per_call,
        "comparator_per_invocation_max_usd": comparator_per_call,
        "by_comparison": by_comparison,
        "calibration_expected_call_count_not_used": True,
    }


def _assert_comparator_plan_within_release_cap(plan: dict[str, Any]) -> None:
    over_cap = [
        item["comparison_id"]
        for item in plan["by_comparison"]
        if item["maximum_comparator_exposure_usd"] > item["comparator_run_cap_usd"]
    ]
    if over_cap:
        raise RunnerError(
            "planned comparator exposure exceeds the per-comparison release cap: "
            + ", ".join(over_cap)
        )


def _comparator_base_files(root: Path) -> dict[str, str]:
    states = _read_tree(root, ignore_generated_caches=True)
    if not states:
        raise RunnerError("comparator base fixture must contain at least one file")
    result: dict[str, str] = {}
    for path, state in sorted(states.items()):
        if state.executable:
            raise RunnerError("comparator base cannot represent executable file modes")
        try:
            result[path] = state.content.decode("utf-8")
        except UnicodeDecodeError as exc:
            raise RunnerError(
                f"comparator base fixture is not UTF-8 text: {path}"
            ) from exc
    return result


def _assert_runtime_pair_representable(pair: dict[str, Any]) -> None:
    for side in ("a", "b"):
        diff = pair[f"diff_{side}"]
        if not diff:
            raise RunnerError("comparator cannot judge a no-op candidate patch")
        if (
            "+++ /dev/null" in diff
            or "Binary files differ:" in diff
            or "File mode changed:" in diff
            or "rename from " in diff
            or "rename to " in diff
        ):
            raise RunnerError(
                "candidate patch uses an unsupported delete, binary, mode, or rename change"
            )


def _map_outcome(outcome: str) -> str:
    return {
        "A": "control",
        "B": "treatment",
        "tie": "tie",
        "tradeoff": "tradeoff",
        "unqualified": "unqualified",
    }.get(outcome, "inconclusive")


def _comparator_cost_accounting(
    records_by_comparison: dict[str, list[dict[str, Any]]],
    pairs: list[dict[str, Any]],
) -> tuple[float, int]:
    known_cost = 0.0
    unknown_invocations = 0
    terminal_by_attempt: dict[tuple[str, str], tuple[str, float, str, str]] = {}
    for comparison_id, records in records_by_comparison.items():
        if not isinstance(comparison_id, str) or not comparison_id:
            raise RunnerError("comparator spend comparison id is invalid")
        reserved: dict[str, tuple[float, str, str]] = {}
        for index, record in enumerate(records):
            if not isinstance(record, dict):
                raise RunnerError("comparator spend record must be an object")
            event = record.get("event")
            attempt_id = record.get("attempt_id")
            if (
                not isinstance(attempt_id, str)
                or re.fullmatch(r"[0-9a-f]{32}", attempt_id) is None
            ):
                raise RunnerError("comparator spend record omitted attempt_id")
            request_sha256 = _optional_sha256(
                record.get("request_sha256"),
                "comparator spend request digest",
            )
            invocation_id = _optional_sha256(
                record.get("invocation_id"),
                "comparator spend invocation id",
            )
            if request_sha256 is None or invocation_id is None:
                raise RunnerError("comparator spend binding is invalid")
            identity = (comparison_id, attempt_id)
            if event == "reserve":
                if set(record) != {
                    "event",
                    "attempt_id",
                    "invocation_id",
                    "request_sha256",
                    "reserved_usd",
                }:
                    raise RunnerError("comparator spend reservation fields are invalid")
                amount = record["reserved_usd"]
                if (
                    isinstance(amount, bool)
                    or not isinstance(amount, (int, float))
                    or not math.isfinite(amount)
                    or amount <= 0
                ):
                    raise RunnerError("comparator spend reservation is invalid")
                if attempt_id in reserved or identity in terminal_by_attempt:
                    raise RunnerError("comparator spend attempt was reserved twice")
                reserved[attempt_id] = (
                    float(amount),
                    request_sha256,
                    invocation_id,
                )
                continue
            if event == "historical":
                if set(record) != {
                    "event",
                    "attempt_id",
                    "charged_usd",
                    "invocation_id",
                    "request_sha256",
                }:
                    raise RunnerError("historical comparator spend fields are invalid")
                if attempt_id in reserved or identity in terminal_by_attempt:
                    raise RunnerError("historical comparator spend id was reused")
                cost = record.get("charged_usd")
                if (
                    isinstance(cost, bool)
                    or not isinstance(cost, (int, float))
                    or not math.isfinite(cost)
                    or cost < 0
                ):
                    raise RunnerError("historical comparator cost is invalid")
                terminal_by_attempt[identity] = (
                    "historical",
                    float(cost),
                    request_sha256,
                    invocation_id,
                )
                known_cost += float(cost)
                continue
            if event not in {"reconcile", "forfeit"}:
                raise RunnerError(
                    f"unsupported comparator spend event at record {index}"
                )
            if set(record) != {
                "event",
                "attempt_id",
                "charged_usd",
                "invocation_id",
                "request_sha256",
            }:
                raise RunnerError("comparator spend terminal fields are invalid")
            if attempt_id not in reserved or identity in terminal_by_attempt:
                raise RunnerError("comparator spend terminal record is unpaired")
            cost = record.get("charged_usd")
            if (
                isinstance(cost, bool)
                or not isinstance(cost, (int, float))
                or not math.isfinite(cost)
                or cost < 0
                or cost > reserved[attempt_id][0]
                or (event == "forfeit" and cost != reserved[attempt_id][0])
            ):
                raise RunnerError("terminal comparator cost is invalid")
            _, reserved_request, reserved_invocation = reserved[attempt_id]
            if (
                request_sha256 != reserved_request
                or invocation_id != reserved_invocation
            ):
                raise RunnerError(
                    "comparator spend terminal binding differs from reserve"
                )
            terminal_by_attempt[identity] = (
                event,
                float(cost),
                request_sha256,
                invocation_id,
            )
            if event == "forfeit":
                unknown_invocations += 1
                continue
            known_cost += float(cost)
        if set(reserved) != {
            attempt_id
            for record_comparison, attempt_id in terminal_by_attempt
            if record_comparison == comparison_id
            and terminal_by_attempt[(record_comparison, attempt_id)][0]
            in {"reconcile", "forfeit"}
        }:
            raise RunnerError("comparator spend journal has unterminated reservations")

    trial_attempts: set[tuple[str, str]] = set()
    for pair in pairs:
        comparison_id = pair.get("comparison_id")
        if not isinstance(comparison_id, str) or not comparison_id:
            raise RunnerError("comparator trial omitted comparison id")
        trials = pair.get("comparator_trials")
        if not isinstance(trials, list):
            raise RunnerError("comparator trials must be an array")
        for trial in trials:
            if not isinstance(trial, dict):
                raise RunnerError("comparator trial must be an object")
            transport = trial.get("transport")
            provider = trial.get("provider")
            if not isinstance(transport, dict) or not isinstance(provider, dict):
                raise RunnerError("comparator trial omitted transport cost evidence")
            attempt_id = transport.get("spend_attempt_id")
            if (
                not isinstance(attempt_id, str)
                or re.fullmatch(r"[0-9a-f]{32}", attempt_id) is None
            ):
                raise RunnerError("comparator trial omitted spend_attempt_id")
            identity = (comparison_id, attempt_id)
            if identity in trial_attempts:
                raise RunnerError("comparator spend attempt was reused by trials")
            trial_attempts.add(identity)
            terminal = terminal_by_attempt.get(identity)
            if terminal is None or terminal[0] != "reconcile":
                raise RunnerError(
                    "successful comparator trial lacks a reconciled spend record"
                )
            provider_cost = provider.get("cost_usd")
            transport_cost = transport.get("cost_usd")
            trial_request_sha256 = _optional_sha256(
                trial.get("request_sha256"),
                "comparator trial request digest",
            )
            trial_invocation_id = _optional_sha256(
                trial.get("invocation_id"),
                "comparator trial invocation id",
            )
            if any(
                isinstance(cost, bool)
                or not isinstance(cost, (int, float))
                or not math.isfinite(cost)
                or cost < 0
                for cost in (provider_cost, transport_cost)
            ):
                raise RunnerError("comparator trial cost evidence is invalid")
            if (
                trial_request_sha256 is None
                or trial_invocation_id is None
                or transport.get("request_sha256") != trial_request_sha256
                or terminal[2] != trial_request_sha256
                or terminal[3] != trial_invocation_id
            ):
                raise RunnerError("comparator trial binding differs from spend journal")
            if not (float(provider_cost) == float(transport_cost) == terminal[1]):
                raise RunnerError("comparator trial cost differs from spend journal")
    return known_cost, unknown_invocations


def _serialized_arm_order(
    seed: int,
    comparison_id: str,
    case_id: str,
    repetition: int,
) -> tuple[str, str]:
    identity = f"{seed}\0{comparison_id}\0{case_id}".encode("utf-8")
    control_first = hashlib.sha256(identity).digest()[0] % 2 == 0
    if repetition % 2 == 1:
        control_first = not control_first
    return ("control", "treatment") if control_first else ("treatment", "control")


def _aggregate(
    pairs: list[dict[str, Any]],
    suite: SuiteSpec,
    comparisons: tuple[ComparisonSpec, ...],
    selection: RunSelection,
    *,
    holdout_plan: HoldoutPlan | None = None,
    release_authority_validated: bool = False,
    generator_release_authoritative: bool = False,
    comparator_spend_records: dict[str, list[dict[str, Any]]] | None = None,
) -> dict[str, Any]:
    case_by_id = {case.id: case for case in suite.cases}
    release_fingerprint_by_case = (
        {case.id: case.release_case_fingerprint for case in holdout_plan.cases}
        if holdout_plan is not None
        else {case.id: case.id for case in suite.cases}
    )
    selected_case_specs = tuple(
        case
        for case in suite.cases
        if (
            (selection.split == "public" and case.split in {"train", "validation"})
            or case.split == selection.split
        )
        and (not selection.case_ids or case.id in set(selection.case_ids))
    )
    expected_pair_keys = {
        (comparison.id, case.id, repetition)
        for comparison in comparisons
        for case in selected_case_specs
        for repetition in range(comparison.repetitions)
    }
    observed_pair_keys = [
        (pair["comparison_id"], pair["case_id"], pair["repetition"]) for pair in pairs
    ]
    observed_pair_key_set = set(observed_pair_keys)
    duplicate_pair_keys = len(observed_pair_keys) != len(observed_pair_key_set)
    execution_matrix_exact = (
        not duplicate_pair_keys and observed_pair_key_set == expected_pair_keys
    )
    grouped: dict[tuple[str, str], list[dict[str, Any]]] = {}
    for pair in pairs:
        grouped.setdefault((pair["comparison_id"], pair["case_id"]), []).append(pair)
    cases: list[dict[str, Any]] = []
    for (comparison_id, case_id), repetitions in sorted(grouped.items()):
        repetitions.sort(key=lambda item: item["repetition"])
        expected_repetitions = next(
            item.repetitions for item in comparisons if item.id == comparison_id
        )
        complete = (
            len(repetitions) == expected_repetitions == 3
            and [item["repetition"] for item in repetitions] == [0, 1, 2]
            and all(item["completed"] for item in repetitions)
        )
        treatment_stable = complete and all(
            item["arms"]["treatment"]["status"] == "completed"
            and item["arms"]["treatment"]["passed"]
            for item in repetitions
        )
        critical_stable = treatment_stable and all(
            all(
                item["arms"]["treatment"]["critical_results"].get(assertion) is True
                for assertion in case_by_id[case_id].critical_expectations
            )
            for item in repetitions
        )
        winners = [item["final_winner"] for item in repetitions] if complete else []
        counts = {winner: winners.count(winner) for winner in set(winners)}
        majority = [winner for winner, count in counts.items() if count >= 2]
        winner = majority[0] if len(majority) == 1 else "inconclusive"
        cases.append(
            {
                "comparison_id": comparison_id,
                "case_id": case_id,
                "release_case_fingerprint": release_fingerprint_by_case.get(
                    case_id, ""
                ),
                "skill": case_by_id[case_id].skill,
                "split": case_by_id[case_id].split,
                "repetitions": len(repetitions),
                "infrastructure_complete": complete,
                "treatment_all_repetitions_passed": treatment_stable,
                "critical_all_repetitions_passed": critical_stable,
                "order_stable": complete
                and all(not item["position_bias"] for item in repetitions),
                "repetition_winners": winners,
                "winner": winner,
            }
        )

    agent_model_sets: set[tuple[str, ...]] = set()
    comparator_model_sets: set[tuple[str, ...]] = set()
    model_provenance_missing = False
    known_total_cost = 0.0
    unknown_cost_invocations = 0
    token_totals: dict[str, int] = {}
    for pair in pairs:
        providers = [
            arm.get("provider")
            for arm in pair["arms"].values()
            if arm.get("provider") is not None
        ]
        if len(providers) != 2:
            model_provenance_missing = True
        for provider in providers:
            agent_model_sets.add(tuple(provider["actual_models"]))
        comparator_providers = [
            trial["provider"] for trial in pair["comparator_trials"]
        ]
        for provider in comparator_providers:
            comparator_model_sets.add(tuple(provider["actual_models"]))
        for provider in providers:
            cost_usd = provider["cost_usd"]
            if cost_usd is None:
                unknown_cost_invocations += 1
            else:
                known_total_cost += cost_usd
            for key, value in provider["tokens"].items():
                token_totals[key] = token_totals.get(key, 0) + value
        for arm in pair["arms"].values():
            accounting = arm.get("provider_accounting")
            if (
                arm.get("provider") is None
                and isinstance(accounting, dict)
                and (
                    accounting.get("dispatched") is True
                    or accounting.get("provider_entered") is True
                )
            ):
                unknown_cost_invocations += 1
        for provider in comparator_providers:
            if comparator_spend_records is None:
                cost_usd = provider["cost_usd"]
                if cost_usd is None:
                    unknown_cost_invocations += 1
                else:
                    known_total_cost += cost_usd
            for key, value in provider["tokens"].items():
                token_totals[key] = token_totals.get(key, 0) + value

    if comparator_spend_records is not None:
        comparator_known, comparator_unknown = _comparator_cost_accounting(
            comparator_spend_records,
            pairs,
        )
        known_total_cost += comparator_known
        unknown_cost_invocations += comparator_unknown

    global_gates = {
        "execution_matrix_integrity": {
            "passed": execution_matrix_exact,
            "policy": "exact-comparison-case-cross-product-with-repetitions-0-1-2",
            "expected_pair_count": len(expected_pair_keys),
            "observed_pair_count": len(observed_pair_keys),
            "duplicate_pair_keys": duplicate_pair_keys,
            "missing_pair_keys": [
                list(item)
                for item in sorted(expected_pair_keys - observed_pair_key_set)
            ],
            "unexpected_pair_keys": [
                list(item)
                for item in sorted(observed_pair_key_set - expected_pair_keys)
            ],
        },
        "infrastructure_integrity": {
            "passed": bool(cases)
            and all(case["infrastructure_complete"] for case in cases),
            "failed_cases": [
                case["case_id"] for case in cases if not case["infrastructure_complete"]
            ],
        },
        "treatment_objective_stability": {
            "passed": bool(cases)
            and all(
                case["treatment_all_repetitions_passed"]
                and case["critical_all_repetitions_passed"]
                for case in cases
            ),
            "policy": "all-three-repetitions-and-every-critical-assertion",
        },
        "generator_model_stability": {
            "passed": not model_provenance_missing and len(agent_model_sets) == 1,
            "actual_model_sets": [list(value) for value in sorted(agent_model_sets)],
        },
        "comparator_model_stability": {
            "passed": selection.verifier_only or len(comparator_model_sets) <= 1,
            "actual_model_sets": [
                list(value) for value in sorted(comparator_model_sets)
            ],
        },
        "order_integrity": {
            "passed": selection.verifier_only
            or all(case["order_stable"] for case in cases),
            "failed_cases": [
                case["case_id"] for case in cases if not case["order_stable"]
            ],
        },
    }

    holdout_profile = tuple(
        (
            comparison.id,
            comparison.control,
            comparison.treatment,
            comparison.repetitions,
            comparison.comparator_order,
        )
        for comparison in comparisons
    )
    release_comparison_ids = suite.holdout_comparison_ids
    expected_holdout_profile = tuple(
        (
            comparison.id,
            comparison.control,
            comparison.treatment,
            3,
            "ab_ba",
        )
        for comparison in comparisons
    )
    selected_skills = frozenset(case.skill for case in selected_case_specs)
    holdout_skill_counts = {
        skill: len(
            {
                case.release_case_fingerprint
                for case in holdout_plan.cases
                if case.skill == skill
            }
        )
        if holdout_plan is not None
        else 0
        for skill in selected_skills
    }
    holdout_integrity_tree_uniqueness = bool(holdout_plan) and (
        len({case.case_tree_sha256 for case in holdout_plan.cases})
        == len(holdout_plan.cases)
    )
    holdout_task_content_uniqueness = bool(holdout_plan) and (
        len({case.release_case_fingerprint for case in holdout_plan.cases})
        == len(holdout_plan.cases)
    )
    suite_variants_by_id = suite.variants_by_id
    release_variant_ids = {
        variant_id
        for comparison in comparisons
        for variant_id in (comparison.control, comparison.treatment)
    }
    holdout_variant_kinds = {
        identifier: suite_variants_by_id.get(identifier).kind
        if suite_variants_by_id.get(identifier) is not None
        else None
        for identifier in sorted(release_variant_ids)
    }
    holdout_protocol_valid = selection.split != "holdout" or (
        holdout_plan is not None
        and release_authority_validated
        and generator_release_authoritative
        and selection.case_ids == ()
        and selection.seed is None
        and selection.comparison_ids == release_comparison_ids
        and holdout_profile == expected_holdout_profile
        and bool(selected_skills)
        and holdout_integrity_tree_uniqueness
        and holdout_task_content_uniqueness
        and all(
            count >= _MIN_HOLDOUT_CASES_PER_SKILL
            for count in holdout_skill_counts.values()
        )
        and execution_matrix_exact
    )
    holdout_release_gate = {
        "passed": holdout_protocol_valid,
        "applicable": selection.split == "holdout",
        "operator_declared_review_records_present": holdout_plan is not None,
        "generator_release_authoritative": generator_release_authoritative,
        "privacy_proof_claimed": False,
        "integrity_tree_uniqueness": holdout_integrity_tree_uniqueness,
        "exact_task_content_uniqueness": holdout_task_content_uniqueness,
        "skill_case_counts": holdout_skill_counts,
        "skill_unique_task_content_counts": holdout_skill_counts,
        "variant_kinds": holdout_variant_kinds,
        "comparison_profile": [list(item) for item in holdout_profile],
    }
    holdout_release_gate["production_judgment_authority_validated"] = (
        release_authority_validated
    )
    global_gates["holdout_release_protocol"] = holdout_release_gate

    by_comparison_skill: dict[str, dict[str, dict[str, Any]]] = {}
    for comparison in comparisons:
        cells: dict[str, dict[str, Any]] = {}
        for skill in sorted({case["skill"] for case in cases}):
            selected_records = [
                case
                for case in cases
                if case["comparison_id"] == comparison.id and case["skill"] == skill
            ]
            if not selected_records:
                continue
            selected_by_fingerprint: dict[str, dict[str, Any]] = {}
            duplicate_fingerprints: set[str] = set()
            for case in selected_records:
                fingerprint = case["release_case_fingerprint"]
                if fingerprint in selected_by_fingerprint:
                    duplicate_fingerprints.add(fingerprint)
                else:
                    selected_by_fingerprint[fingerprint] = case
            selected = list(selected_by_fingerprint.values())
            wins = sum(case["winner"] == "treatment" for case in selected)
            losses = sum(case["winner"] == "control" for case in selected)
            informative = wins + losses
            p_value = _one_sided_sign_test(wins, losses)
            integrity = not duplicate_fingerprints and all(
                case["infrastructure_complete"]
                and case["treatment_all_repetitions_passed"]
                and case["critical_all_repetitions_passed"]
                and (selection.verifier_only or case["order_stable"])
                for case in selected
            )
            candidate_comparison = comparison.id in release_comparison_ids
            developmental_signal = (
                candidate_comparison
                and informative >= 5
                and p_value is not None
                and p_value <= 0.05
            )
            holdout_authorized = (
                candidate_comparison
                and selection.split == "holdout"
                and informative >= 8
                and p_value is not None
                and p_value <= 0.05
                and integrity
            )
            cells[skill] = {
                "distinct_cases": len(selected),
                "distinct_release_case_fingerprints": len(selected),
                "statistical_unit": "exact_task_content_fingerprint",
                "duplicate_release_case_fingerprints": sorted(duplicate_fingerprints),
                "treatment_wins": wins,
                "control_wins": losses,
                "ties": sum(case["winner"] == "tie" for case in selected),
                "tradeoffs": sum(case["winner"] == "tradeoff" for case in selected),
                "unqualified": sum(
                    case["winner"] == "unqualified" for case in selected
                ),
                "inconclusive": sum(
                    case["winner"] == "inconclusive" for case in selected
                ),
                "informative_cases": informative,
                "one_sided_sign_test_p": p_value,
                "integrity_passed": integrity,
                "developmental_signal": developmental_signal,
                "holdout_authorized": holdout_authorized,
                "release_authority": (
                    "holdout"
                    if selection.split == "holdout" and candidate_comparison
                    else "diagnostic"
                ),
            }
        by_comparison_skill[comparison.id] = cells

    candidate_cells = [
        cell
        for comparison_id, cells_by_skill in by_comparison_skill.items()
        if comparison_id in release_comparison_ids
        for cell in cells_by_skill.values()
    ]
    candidate_cell_keys = {
        (comparison_id, skill)
        for comparison_id, cells_by_skill in by_comparison_skill.items()
        if comparison_id in release_comparison_ids
        for skill in cells_by_skill
    }
    expected_candidate_cell_keys = {
        (comparison_id, skill)
        for comparison_id in release_comparison_ids
        for skill in selected_skills
    }
    both_candidate_comparisons_present = {
        comparison.id
        for comparison in comparisons
        if comparison.id in release_comparison_ids
    } == set(release_comparison_ids)
    final_release_authorized = (
        selection.split == "holdout"
        and (not selection.verifier_only or suite.evaluation_mode == "objective_only")
        and generator_release_authoritative
        and both_candidate_comparisons_present
        and candidate_cell_keys == expected_candidate_cell_keys
        and len(candidate_cells) == len(expected_candidate_cell_keys)
        and all(cell["holdout_authorized"] for cell in candidate_cells)
        and all(gate["passed"] for gate in global_gates.values())
    )
    if selection.split == "holdout":
        passed = final_release_authorized
    elif selection.verifier_only:
        passed = all(
            global_gates[name]["passed"]
            for name in (
                "execution_matrix_integrity",
                "infrastructure_integrity",
                "treatment_objective_stability",
                "generator_model_stability",
            )
        )
    else:
        # Train and validation remain developmental/diagnostic and cannot release.
        passed = all(gate["passed"] for gate in global_gates.values())
    return {
        "execution_mode": "verifier_only" if selection.verifier_only else "judged",
        "pair_count": len(pairs),
        "distinct_case_count": len(
            {case["release_case_fingerprint"] for case in cases}
        ),
        "case_results": cases,
        "total_cost_usd": (None if unknown_cost_invocations else known_total_cost),
        "known_total_cost_usd": known_total_cost,
        "unknown_cost_invocations": unknown_cost_invocations,
        "tokens": token_totals,
        "by_comparison_skill": by_comparison_skill,
        "gates": global_gates,
        "analysis_role": (
            "informational"
            if all(
                comparison.id == "original-vs-no-skill" for comparison in comparisons
            )
            else "candidate-evaluation"
        ),
        "split_authority": (
            "release" if selection.split == "holdout" else "diagnostic"
        ),
        "final_release_authorized": final_release_authorized,
        "passed": passed,
    }


def _one_sided_sign_test(wins: int, losses: int) -> float | None:
    n = wins + losses
    if n == 0:
        return None
    return sum(math.comb(n, value) for value in range(wins, n + 1)) / (2**n)


def _resolve_verifier_command(
    suite_root: Path, case: CaseSpec, shared_root: Path | None
) -> tuple[str, ...]:
    def assert_mounted(path: Path, kind: str) -> None:
        if path.is_relative_to(case.prompt_file.parent) or (
            shared_root is not None and path.is_relative_to(shared_root)
        ):
            return
        raise RunnerError(
            f"case {case.id} verifier {kind} is outside case and shared verifier roots"
        )

    argv = list(case.verifier.argv)
    executable = Path(argv[0])
    if executable.parent != Path("."):
        if executable.is_absolute():
            raise RunnerError(
                f"case {case.id} verifier executable must be suite-relative"
            )
        resolved = (suite_root / executable).resolve()
        if not resolved.is_relative_to(suite_root):
            raise RunnerError(f"case {case.id} verifier executable escapes suite root")
        if not resolved.is_file() or not os.access(resolved, os.X_OK):
            raise RunnerError(
                f"case {case.id} verifier executable is missing or not executable"
            )
        assert_mounted(resolved, "executable")
        argv[0] = str(resolved)
    else:
        resolved_executable = shutil.which(argv[0])
        if resolved_executable is None:
            raise RunnerError(f"case {case.id} verifier tool is not on PATH: {argv[0]}")
        argv[0] = str(Path(resolved_executable).resolve())
    interpreter = Path(argv[0]).name
    if (
        interpreter.startswith("python") or interpreter in {"bash", "sh", "node"}
    ) and len(argv) >= 2:
        script = argv[1]
        if not script.startswith("-"):
            script_path = Path(script)
            if script_path.is_absolute():
                raise RunnerError(
                    f"case {case.id} verifier script must be suite-relative"
                )
            resolved_script = (suite_root / script_path).resolve()
            if (
                not resolved_script.is_relative_to(suite_root)
                or not resolved_script.is_file()
            ):
                raise RunnerError(
                    f"case {case.id} verifier script is missing: {script}"
                )
            assert_mounted(resolved_script, "script")
            argv[1] = str(resolved_script)
    return tuple(argv)


def _resolve_required_tool(case_id: str, name: str) -> str:
    resolved = shutil.which(name)
    if resolved is None:
        raise RunnerError(f"case {case_id} required tool is not on PATH: {name}")
    executable = Path(resolved).resolve()
    if not executable.is_file() or not os.access(executable, os.X_OK):
        raise RunnerError(
            f"case {case_id} required tool is not executable: {name}={executable}"
        )
    return str(executable)


def _attest_executable(
    path: Path,
    logical_name: str,
    *,
    derive_gcc_closure: bool = True,
    version_override: str | None = None,
) -> _ExecutableAttestation:
    if (
        not logical_name
        or logical_name != Path(logical_name).name
        or logical_name in {".", ".."}
    ):
        raise RunnerError(f"invalid executable logical name: {logical_name!r}")
    resolved = path.resolve(strict=True)
    flags = os.O_RDONLY | os.O_CLOEXEC
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    try:
        descriptor = os.open(resolved, flags)
    except OSError as exc:
        raise RunnerError(
            f"cannot open executable for attestation: {resolved}: {exc}"
        ) from exc
    try:
        metadata = os.fstat(descriptor)
        if not stat.S_ISREG(metadata.st_mode) or not metadata.st_mode & 0o111:
            raise RunnerError(f"attested tool is not a regular executable: {resolved}")
        if metadata.st_size > MAX_EXECUTABLE_BYTES:
            raise RunnerError(
                f"executable exceeds {MAX_EXECUTABLE_BYTES} bytes: {resolved}"
            )
        digest = _sha256_descriptor(descriptor, MAX_EXECUTABLE_BYTES)
        version = version_override or _executable_version(descriptor, resolved)
        go_root = (
            _go_runtime_root(descriptor, resolved) if logical_name == "go" else None
        )
        gcc_exec_prefix: Path | None = None
        derived_executables: tuple[_ExecutableAttestation, ...] = ()
        if logical_name == "gcc" and derive_gcc_closure:
            gcc_exec_prefix, derived_paths = _gcc_runtime_closure(descriptor, resolved)
            derived_executables = tuple(
                _attest_executable(
                    derived,
                    derived.name,
                    derive_gcc_closure=False,
                    version_override=(
                        f"{version} (derived GCC component {derived.name})"
                    ),
                )
                for derived in derived_paths
            )
        after = os.fstat(descriptor)
        if _stat_identity(metadata) != _stat_identity(after):
            raise RunnerError(f"executable drifted during preflight: {resolved}")
        return _ExecutableAttestation(
            logical_name=logical_name,
            source_path=resolved,
            sha256=digest,
            size=metadata.st_size,
            mode=stat.S_IMODE(metadata.st_mode),
            device=metadata.st_dev,
            inode=metadata.st_ino,
            mtime_ns=metadata.st_mtime_ns,
            ctime_ns=metadata.st_ctime_ns,
            version=version,
            go_root=go_root,
            gcc_exec_prefix=gcc_exec_prefix,
            derived_executables=derived_executables,
        )
    finally:
        os.close(descriptor)


def _executable_version(descriptor: int, path: Path) -> str:
    executable = f"/proc/self/fd/{descriptor}"
    failures: list[str] = []
    for arguments in (("--version",), ("version",)):
        try:
            completed = subprocess.run(
                [executable, *arguments],
                capture_output=True,
                text=True,
                timeout=10,
                check=False,
                shell=False,
                close_fds=True,
                pass_fds=(descriptor,),
                env={"LANG": "C.UTF-8", "LC_ALL": "C.UTF-8", "PATH": ""},
            )
        except (OSError, subprocess.TimeoutExpired) as exc:
            failures.append(str(exc))
            continue
        output = (completed.stdout or completed.stderr).strip()
        if completed.returncode == 0 and output:
            return output.splitlines()[0]
        failures.append(f"exit {completed.returncode}: {output[:160]}")
    raise RunnerError(
        f"cannot capture executable version for {path}: {'; '.join(failures)}"
    )


def _go_runtime_root(descriptor: int, path: Path) -> Path:
    executable = f"/proc/self/fd/{descriptor}"
    try:
        completed = subprocess.run(
            [executable, "env", "GOROOT"],
            capture_output=True,
            text=True,
            timeout=10,
            check=False,
            shell=False,
            close_fds=True,
            pass_fds=(descriptor,),
            env={
                "GOTOOLCHAIN": "local",
                "LANG": "C.UTF-8",
                "LC_ALL": "C.UTF-8",
                "PATH": "",
            },
        )
    except (OSError, subprocess.TimeoutExpired) as exc:
        raise RunnerError(f"cannot capture GOROOT for {path}: {exc}") from exc
    raw_root = completed.stdout.strip()
    if completed.returncode != 0 or not raw_root or "\n" in raw_root:
        detail = (completed.stderr or completed.stdout).strip()
        raise RunnerError(f"cannot capture GOROOT for {path}: {detail}")
    root = Path(raw_root)
    if not root.is_absolute():
        raise RunnerError(f"Go reported a non-absolute GOROOT for {path}: {raw_root}")
    try:
        resolved = root.resolve(strict=True)
    except OSError as exc:
        raise RunnerError(
            f"Go reported an inaccessible GOROOT for {path}: {exc}"
        ) from exc
    required = (resolved / "pkg" / "tool", resolved / "src")
    if not all(candidate.is_dir() for candidate in required):
        raise RunnerError(f"Go reported an incomplete GOROOT for {path}: {resolved}")
    return resolved


def _gcc_runtime_closure(descriptor: int, path: Path) -> tuple[Path, tuple[Path, ...]]:
    components: list[Path] = []
    for name in ("cc1", "collect2", "lto-wrapper"):
        raw_component = _gcc_query(descriptor, path, f"-print-prog-name={name}")
        component = Path(raw_component)
        if not component.is_absolute():
            raise RunnerError(
                f"GCC reported a non-absolute {name} component: {raw_component}"
            )
        resolved = component.resolve(strict=True)
        if resolved.name != name:
            raise RunnerError(f"GCC reported an unexpected {name} path: {resolved}")
        components.append(resolved)
    raw_libgcc = _gcc_query(descriptor, path, "-print-libgcc-file-name")
    libgcc = Path(raw_libgcc)
    if not libgcc.is_absolute():
        raise RunnerError(f"GCC reported a non-absolute libgcc path: {raw_libgcc}")
    resolved_libgcc = libgcc.resolve(strict=True)
    if not resolved_libgcc.is_file():
        raise RunnerError(f"GCC reported an invalid libgcc path: {resolved_libgcc}")
    machine = _gcc_query(descriptor, path, "-dumpmachine")
    major_version = _gcc_query(descriptor, path, "-dumpversion")
    install_root = resolved_libgcc.parent
    if install_root.parts[-2:] != (machine, major_version):
        raise RunnerError(
            "GCC libgcc path does not match its reported target and version: "
            f"{resolved_libgcc}"
        )
    exec_prefix = install_root.parent.parent
    if not exec_prefix.is_dir():
        raise RunnerError(f"GCC execution prefix is not a directory: {exec_prefix}")
    if len({component.name for component in components}) != len(components):
        raise RunnerError("GCC reported duplicate derived component names")
    return exec_prefix, tuple(components)


def _gcc_query(descriptor: int, path: Path, argument: str) -> str:
    executable = f"/proc/self/fd/{descriptor}"
    try:
        completed = subprocess.run(
            [executable, argument],
            capture_output=True,
            text=True,
            timeout=10,
            check=False,
            shell=False,
            close_fds=True,
            pass_fds=(descriptor,),
            env={"LANG": "C.UTF-8", "LC_ALL": "C.UTF-8", "PATH": ""},
        )
    except (OSError, subprocess.TimeoutExpired) as exc:
        raise RunnerError(f"cannot query GCC runtime for {path}: {exc}") from exc
    output = completed.stdout.strip()
    if completed.returncode != 0 or not output or "\n" in output:
        detail = (completed.stderr or completed.stdout).strip()
        raise RunnerError(f"cannot query GCC runtime for {path}: {detail}")
    return output


def _flatten_executable_attestations(
    attestations: tuple[_ExecutableAttestation, ...],
) -> list[_ExecutableAttestation]:
    flattened: list[_ExecutableAttestation] = []
    for attestation in attestations:
        flattened.append(attestation)
        flattened.extend(
            _flatten_executable_attestations(attestation.derived_executables)
        )
    return flattened


def _materialize_executable_bundle(
    destination: Path, attestations: tuple[_ExecutableAttestation, ...]
) -> dict[str, dict[str, Any]]:
    _mkdir_private(destination, parents=True, exist_ok=False)
    copied: dict[str, dict[str, Any]] = {}
    for attestation in attestations:
        if attestation.logical_name in copied:
            raise RunnerError(
                f"executable bundle contains duplicate name: {attestation.logical_name}"
            )
        target = destination / attestation.logical_name
        copied[attestation.logical_name] = _copy_attested_executable(
            attestation, target
        )
    destination.chmod(0o555)
    return copied


def _copy_attested_executable(
    attestation: _ExecutableAttestation, destination: Path
) -> dict[str, Any]:
    flags = os.O_RDONLY | os.O_CLOEXEC
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    try:
        source = os.open(attestation.source_path, flags)
    except OSError as exc:
        raise RunnerError(
            f"cannot reopen preflight executable {attestation.source_path}: {exc}"
        ) from exc
    try:
        metadata = os.fstat(source)
        expected_identity = (
            attestation.device,
            attestation.inode,
            attestation.mode,
            attestation.size,
            attestation.mtime_ns,
            attestation.ctime_ns,
        )
        if _stat_identity(metadata) != expected_identity:
            raise RunnerError(
                f"preflight executable metadata drifted: {attestation.source_path}"
            )
        if _sha256_descriptor(source, MAX_EXECUTABLE_BYTES) != attestation.sha256:
            raise RunnerError(
                f"preflight executable bytes drifted: {attestation.source_path}"
            )
        destination_flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_CLOEXEC
        target = os.open(destination, destination_flags, 0o500)
        try:
            offset = 0
            while offset < attestation.size:
                chunk = os.pread(
                    source, min(1024 * 1024, attestation.size - offset), offset
                )
                if not chunk:
                    raise RunnerError(
                        f"preflight executable was truncated: {attestation.source_path}"
                    )
                view = memoryview(chunk)
                while view:
                    written = os.write(target, view)
                    view = view[written:]
                offset += len(chunk)
            os.fchmod(target, 0o500)
            os.fsync(target)
        finally:
            os.close(target)
    finally:
        os.close(source)
    copied_metadata = destination.stat(follow_symlinks=False)
    copied_hash = _sha256(destination.read_bytes())
    if copied_hash != attestation.sha256 or copied_metadata.st_size != attestation.size:
        raise RunnerError(f"copied executable failed attestation: {destination}")
    return {
        "source": attestation.as_json(),
        "copied_path": str(destination),
        "sha256": copied_hash,
        "stat": {
            "size": copied_metadata.st_size,
            "mode": stat.S_IMODE(copied_metadata.st_mode),
            "device": copied_metadata.st_dev,
            "inode": copied_metadata.st_ino,
            "mtime_ns": copied_metadata.st_mtime_ns,
            "ctime_ns": copied_metadata.st_ctime_ns,
        },
        "matches_preflight": True,
    }


def _verify_executable_bundle(root: Path, copied: dict[str, dict[str, Any]]) -> None:
    observed: set[str] = set()
    for path in root.iterdir():
        metadata = path.lstat()
        if not stat.S_ISREG(metadata.st_mode) or stat.S_ISLNK(metadata.st_mode):
            raise RunnerError("private executable bundle contains a special entry")
        observed.add(path.name)
    if set(copied) != observed:
        raise RunnerError("private executable bundle changed during verifier execution")
    for name, evidence in copied.items():
        path = root / name
        metadata = path.stat(follow_symlinks=False)
        if (
            not stat.S_ISREG(metadata.st_mode)
            or stat.S_IMODE(metadata.st_mode) != 0o500
            or metadata.st_size != evidence["stat"]["size"]
            or _sha256(path.read_bytes()) != evidence["sha256"]
        ):
            raise RunnerError(f"executed executable bytes changed: {name}")


def _sha256_descriptor(descriptor: int, maximum: int) -> str:
    digest = hashlib.sha256()
    offset = 0
    while True:
        chunk = os.pread(descriptor, min(1024 * 1024, maximum + 1 - offset), offset)
        if not chunk:
            break
        digest.update(chunk)
        offset += len(chunk)
        if offset > maximum:
            raise RunnerError(f"descriptor content exceeds {maximum} bytes")
    return digest.hexdigest()


def _stat_identity(metadata: os.stat_result) -> tuple[int, int, int, int, int, int]:
    return (
        metadata.st_dev,
        metadata.st_ino,
        stat.S_IMODE(metadata.st_mode),
        metadata.st_size,
        metadata.st_mtime_ns,
        metadata.st_ctime_ns,
    )


def _sensitive_host_roots() -> tuple[Path, ...]:
    home = Path.home().resolve()
    candidates = [home]
    claude_root = Path(
        os.environ.get("CLAUDE_CONFIG_DIR", str(Path.home() / ".claude"))
    ).expanduser()
    if claude_root.exists():
        config_root = claude_root.resolve()
        candidates.append(config_root)
        if (
            config_root.name == ".claude"
            and not config_root.is_relative_to(home)
            and config_root.parent != config_root.parent.parent
        ):
            candidates.append(config_root.parent)
    configured = os.environ.get("XDG_CONFIG_HOME")
    if configured:
        xdg_root = Path(configured).expanduser()
        if xdg_root.exists():
            candidates.append(xdg_root.resolve())
    return tuple(dict.fromkeys(candidates))


def _systemd_client_environment() -> dict[str, str]:
    allowed = {
        "DBUS_SESSION_BUS_ADDRESS",
        "LANG",
        "LC_ALL",
        "PATH",
        "XDG_RUNTIME_DIR",
    }
    return {key: value for key, value in os.environ.items() if key in allowed}


def _safe_repo_file(root: Path, path: PurePosixPath) -> Path:
    candidate = (root / Path(*path.parts)).resolve()
    if not candidate.is_relative_to(root.resolve()):
        raise RunnerError(f"repository path escapes source root: {path}")
    current = root.resolve()
    for part in path.parts:
        current = current / part
        if current.is_symlink():
            raise RunnerError(f"repository path traverses symlink: {path}")
    return candidate


def _git_command(root: Path, arguments: list[str], *, timeout: int = 30) -> bytes:
    try:
        completed = subprocess.run(
            ["git", "-C", str(root), "--literal-pathspecs", *arguments],
            capture_output=True,
            timeout=timeout,
            check=False,
            shell=False,
        )
    except (OSError, subprocess.TimeoutExpired) as exc:
        raise RunnerError(f"git command failed: {exc}") from exc
    if completed.returncode != 0:
        detail = completed.stderr.decode("utf-8", errors="replace").strip()
        raise RunnerError(f"git {' '.join(arguments[:2])} failed: {detail}")
    return completed.stdout


def _git_nul_records(
    root: Path, arguments: list[str], *, timeout: int = 30
) -> Iterator[bytes]:
    command = ["git", "-C", str(root), "--literal-pathspecs", *arguments]
    deadline = time.monotonic() + timeout
    buffer = bytearray()
    total = 0
    with tempfile.TemporaryFile() as stderr:
        try:
            process = subprocess.Popen(
                command,
                stdout=subprocess.PIPE,
                stderr=stderr,
                shell=False,
            )
        except OSError as exc:
            raise RunnerError(f"git command failed: {exc}") from exc
        try:
            if process.stdout is None:
                raise RunnerError("git command did not expose stdout")
            descriptor = process.stdout.fileno()
            while True:
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    raise subprocess.TimeoutExpired(command, timeout)
                ready, _, _ = select.select([descriptor], [], [], remaining)
                if not ready:
                    raise subprocess.TimeoutExpired(command, timeout)
                chunk = os.read(descriptor, 64 * 1024)
                if not chunk:
                    break
                total += len(chunk)
                if total > MAX_GIT_TREE_METADATA_BYTES:
                    raise RunnerError(
                        f"git tree metadata exceeds {MAX_GIT_TREE_METADATA_BYTES} bytes"
                    )
                buffer.extend(chunk)
                while (separator := buffer.find(b"\0")) >= 0:
                    yield bytes(buffer[:separator])
                    del buffer[: separator + 1]
            if buffer:
                raise RunnerError("git returned an unterminated tree entry")
            remaining = max(0.0, deadline - time.monotonic())
            returncode = process.wait(timeout=remaining)
            if returncode != 0:
                stderr.seek(0)
                detail = stderr.read(8192).decode("utf-8", errors="replace").strip()
                raise RunnerError(f"git {' '.join(arguments[:2])} failed: {detail}")
            return
        except subprocess.TimeoutExpired as exc:
            raise RunnerError(f"git command failed: {exc}") from exc
        finally:
            if process.poll() is None:
                process.kill()
                process.wait()
            if process.stdout is not None:
                process.stdout.close()


def _git_commit(root: Path) -> str:
    output = _git_command(root, ["rev-parse", "--verify", "HEAD^{commit}"])
    commit = output.decode("ascii", errors="strict").strip()
    if not _valid_git_object_id(commit):
        raise RunnerError(f"git returned invalid commit id for {root}: {commit!r}")
    return commit


def _resolve_git_ref(root: Path, ref: str) -> str:
    output = _git_command(
        root, ["rev-parse", "--verify", "--end-of-options", f"{ref}^{{commit}}"]
    )
    commit = output.decode("ascii", errors="strict").strip()
    if not _valid_git_object_id(commit):
        raise RunnerError(f"git ref {ref!r} did not resolve to an exact commit")
    return commit


def _valid_git_object_id(value: str) -> bool:
    return len(value) in {40, 64} and all(
        character in "0123456789abcdef" for character in value
    )


def _git_dirty(root: Path, paths: tuple[PurePosixPath, ...] = ()) -> bool:
    arguments = ["status", "--porcelain=v1", "--untracked-files=all"]
    if paths:
        arguments.extend(["--", *(str(path) for path in paths)])
    return bool(_git_command(root, arguments))


def _source_paths(cases: tuple[CaseSpec, ...]) -> tuple[PurePosixPath, ...]:
    paths = {
        path for case in cases for path in (case.bundle_source, *case.context_files)
    }
    return tuple(sorted(paths, key=str))


def _worktree_source_fingerprint(
    root: Path,
    case: CaseSpec,
    *,
    ignore_empty_directories: bool = True,
) -> str:
    bundle_root = _safe_repo_file(root, case.bundle_source)
    context_states: dict[str, _FileState] = {}
    for context_file in case.context_files:
        path = _safe_repo_file(root, context_file)
        if not path.is_file() or path.is_symlink():
            raise RunnerError(f"worktree context file is missing: {context_file}")
        metadata = path.stat()
        context_states[context_file.as_posix()] = _FileState(
            path.read_bytes(), bool(metadata.st_mode & stat.S_IXUSR)
        )
    return _canonical_source_fingerprint(
        case.bundle_source,
        _read_tree(
            bundle_root,
            ignore_generated_caches=True,
            ignore_empty_directories=ignore_empty_directories,
        ),
        context_states,
    )


def _git_source_fingerprint(
    root: Path,
    commit: str,
    case: CaseSpec,
    *,
    ignore_generated_caches: bool = True,
) -> str:
    prefix = case.bundle_source
    bundle_states: dict[str, _FileState] = {}
    for entry in _git_bundle_entries(
        root,
        commit,
        case.bundle_source,
        ignore_generated_caches=ignore_generated_caches,
    ):
        relative = entry.path.relative_to(prefix).as_posix()
        bundle_states[relative] = _FileState(
            _git_blob(root, commit, entry.path), entry.mode == "100755"
        )
    return _canonical_source_fingerprint(
        case.bundle_source,
        bundle_states,
        {
            context_file.as_posix(): _git_file_state(root, commit, context_file)
            for context_file in case.context_files
        },
    )


def _canonical_source_fingerprint(
    bundle_source: PurePosixPath,
    bundle_states: dict[str, _FileState],
    context_states: dict[str, _FileState],
) -> str:
    digest = hashlib.sha256()
    digest.update(SOURCE_FINGERPRINT_DOMAIN)
    digest.update(
        _canonical_json_bytes(
            {
                "bundle_source": bundle_source.as_posix(),
                "schema_version": 1,
            }
        )
    )
    digest.update(b"\0")
    for role, states in (("bundle", bundle_states), ("context", context_states)):
        for path, state in sorted(states.items()):
            metadata = _canonical_json_bytes(
                {
                    "executable": state.executable,
                    "path": path,
                    "role": role,
                    "size": len(state.content),
                }
            )
            digest.update(str(len(metadata)).encode("ascii"))
            digest.update(b":")
            digest.update(metadata)
            digest.update(str(len(state.content)).encode("ascii"))
            digest.update(b":")
            digest.update(state.content)
    return digest.hexdigest()


def _effective_shared_verifier_dir(suite: SuiteSpec) -> Path | None:
    logical = suite.shared_verifier_dir
    if logical is None:
        return None
    try:
        relative = logical.relative_to(suite.root)
    except ValueError as exc:
        raise RunnerError("shared verifier directory escapes suite root") from exc
    current = suite.root
    for part in relative.parts:
        current /= part
        if current.is_symlink():
            raise RunnerError("shared verifier directory traverses a symlink")
    try:
        resolved = logical.resolve(strict=True)
    except OSError as exc:
        raise RunnerError(f"cannot resolve shared verifier directory: {exc}") from exc
    if (
        not resolved.is_relative_to(suite.root)
        or not resolved.is_dir()
        or resolved != logical
    ):
        raise RunnerError(
            "shared verifier directory must remain contained and unchanged"
        )
    return resolved


def _combined_case_hash(
    case_snapshot: _TreeSnapshot, shared_snapshot: _TreeSnapshot | None
) -> str:
    digest = hashlib.sha256()
    digest.update(b"case\0")
    digest.update(case_snapshot.sha256.encode("ascii"))
    if shared_snapshot is not None:
        digest.update(b"shared\0")
        digest.update(shared_snapshot.sha256.encode("ascii"))
    return digest.hexdigest()


def _release_case_fingerprint(
    case: CaseSpec,
    *,
    prompt_sha256: str,
    fixture_sha256: str,
    context_content_sha256s: dict[str, list[str]],
) -> str:
    """Hash canonical statistical task content, excluding evaluation mechanics."""

    contract = None
    if case.comparator_contract is not None:
        contract = {
            **case.comparator_contract,
            "requirements": sorted(
                case.comparator_contract["requirements"],
                key=lambda requirement: _canonical_json_bytes(requirement),
            ),
        }
    payload = {
        "artifact_contract": {"kind": case.artifact_contract.kind},
        "comparator_contract": contract,
        "context_content_sha256s": {
            role: sorted(hashes)
            for role, hashes in sorted(context_content_sha256s.items())
        },
        "critical_expectations": sorted(case.critical_expectations),
        "fixture_sha256": fixture_sha256,
        "prompt_sha256": prompt_sha256,
        "schema_version": 1,
        "skill": case.skill,
    }
    return _sha256(_canonical_json_bytes(payload))


def _verifier_execution_sha256(suite_root: Path, case: CaseSpec) -> str:
    normalized_argv: list[Any] = []
    execution_tree_hashes: set[str] = set()
    for index, argument in enumerate(case.verifier.argv):
        candidate = (suite_root / argument).resolve()
        if candidate.is_relative_to(suite_root) and candidate.is_file():
            normalized_argv.append(
                {"kind": "suite-file", "sha256": _sha256(candidate.read_bytes())}
            )
            execution_tree_hashes.add(
                _tree_hash(candidate.parent, ignore_generated_caches=True)
            )
        elif candidate.is_relative_to(suite_root) and candidate.is_dir():
            tree_sha256 = _tree_hash(candidate, ignore_generated_caches=True)
            normalized_argv.append({"kind": "suite-tree", "sha256": tree_sha256})
            execution_tree_hashes.add(tree_sha256)
        elif index == 0:
            normalized_argv.append({"kind": "tool", "name": Path(argument).name})
        else:
            normalized_argv.append({"kind": "literal", "value": argument})
    return _sha256(
        _canonical_json_bytes(
            {
                "argv": normalized_argv,
                "execution_tree_sha256s": sorted(execution_tree_hashes),
                "schema_version": 1,
            }
        )
    )


def _release_context_content_hashes(
    repository_root: Path,
    case: CaseSpec,
    commits: dict[str, str | tuple[Path | None, str]],
) -> dict[str, list[str]]:
    result: dict[str, list[str]] = {}
    for role, source in sorted(commits.items()):
        if isinstance(source, tuple):
            root, commit = source
            if root is None:
                raise RunnerError(f"source variant {role} omitted its Git root")
        else:
            root, commit = repository_root, source
        result[role] = [
            _sha256(_git_blob(root, commit, context_file))
            for context_file in case.context_files
        ]
    return result


def _assert_release_task_content_uniqueness(
    case_records: list[dict[str, Any]],
) -> None:
    tree_hashes = [record["case_tree_sha256"] for record in case_records]
    fingerprints = [record["release_case_fingerprint"] for record in case_records]
    if len(set(tree_hashes)) != len(tree_hashes):
        raise RunnerError(
            "holdout integrity case_tree_sha256 values must be globally unique"
        )
    if len(set(fingerprints)) != len(fingerprints):
        raise RunnerError(
            "holdout release case task-content fingerprints must be globally unique; "
            "evaluation-mechanic differences are pseudoreplication"
        )
    skills = {record["skill"] for record in case_records}
    unique_by_skill = {
        skill: {
            record["release_case_fingerprint"]
            for record in case_records
            if record["skill"] == skill
        }
        for skill in skills
    }
    if any(
        len(values) < _MIN_HOLDOUT_CASES_PER_SKILL
        for values in unique_by_skill.values()
    ):
        raise RunnerError(
            "holdout requires at least 8 unique task-content fingerprints for each "
            "selected skill"
        )


@dataclass(frozen=True)
class _GitBundleEntry:
    mode: str
    path: PurePosixPath
    size: int


def _is_generated_cache_path(path: PurePosixPath) -> bool:
    return path.suffix in _GENERATED_CACHE_SUFFIXES or any(
        part in _GENERATED_CACHE_DIRECTORIES for part in path.parts[:-1]
    )


def _git_bundle_entries(
    root: Path,
    commit: str,
    bundle_source: PurePosixPath,
    *,
    ignore_generated_caches: bool = False,
) -> list[_GitBundleEntry]:
    prefix = bundle_source.as_posix()
    entries: list[_GitBundleEntry] = []
    directories: set[PurePosixPath] = set()
    total = 0
    for raw_entry in _git_nul_records(
        root, ["ls-tree", "-r", "-z", "-l", "--full-tree", commit, "--", prefix]
    ):
        try:
            metadata, raw_path = raw_entry.split(b"\t", 1)
            mode, object_type, _object_id, size_text = metadata.decode("ascii").split()
            path = PurePosixPath(raw_path.decode("utf-8"))
            size = int(size_text)
        except (ValueError, UnicodeDecodeError) as exc:
            raise RunnerError(f"invalid git tree entry for {prefix}") from exc
        if object_type != "blob" or mode not in {"100644", "100755"}:
            raise RunnerError(
                f"bundle snapshot contains unsupported git entry: {mode} {path}"
            )
        if not path.is_relative_to(bundle_source) or ".." in path.parts:
            raise RunnerError(f"bundle snapshot path escapes prefix: {path}")
        entry = _GitBundleEntry(mode=mode, path=path, size=size)
        relative = path.relative_to(bundle_source)
        if ignore_generated_caches and _is_generated_cache_path(relative):
            continue
        if len(relative.parent.parts) > MAX_TREE_DEPTH:
            raise RunnerError(
                f"bundle snapshot exceeds maximum depth {MAX_TREE_DEPTH}: {prefix}"
            )
        if entry.size > MAX_FILE_BYTES:
            raise RunnerError(
                f"bundle snapshot file exceeds {MAX_FILE_BYTES} bytes: {entry.path}"
            )
        total += entry.size
        if total > MAX_TREE_BYTES:
            raise RunnerError(
                f"bundle snapshot exceeds {MAX_TREE_BYTES} bytes: {prefix}"
            )
        parent = relative.parent
        while parent != PurePosixPath("."):
            directories.add(parent)
            parent = parent.parent
        entries.append(entry)
        if len(entries) + len(directories) > MAX_TREE_ENTRIES:
            raise RunnerError(
                f"bundle snapshot exceeds maximum entries {MAX_TREE_ENTRIES}: {prefix}"
            )
    entrypoint = bundle_source / "SKILL.md"
    if not entries or entrypoint not in {entry.path for entry in entries}:
        raise RunnerError(
            f"commit {commit} has no complete bundle directory at {prefix}"
        )
    return entries


def _git_blob(root: Path, commit: str, path: PurePosixPath) -> bytes:
    return _git_command(
        root, ["show", "--no-ext-diff", "--no-textconv", f"{commit}:{path}"]
    )


def _git_file_state(root: Path, commit: str, path: PurePosixPath) -> _FileState:
    records = list(
        _git_nul_records(
            root,
            ["ls-tree", "-z", "-l", "--full-tree", commit, "--", path.as_posix()],
        )
    )
    if len(records) != 1:
        raise RunnerError(f"commit {commit} has no unique context file at {path}")
    try:
        metadata, raw_path = records[0].split(b"\t", 1)
        mode, object_type, _object_id, size_text = metadata.decode("ascii").split()
        observed_path = PurePosixPath(raw_path.decode("utf-8"))
        size = int(size_text)
    except (ValueError, UnicodeDecodeError) as exc:
        raise RunnerError(f"invalid git context entry for {path}") from exc
    if (
        object_type != "blob"
        or mode not in {"100644", "100755"}
        or observed_path != path
        or size > MAX_FILE_BYTES
    ):
        raise RunnerError(f"unsupported git context entry for {path}")
    content = _git_blob(root, commit, path)
    if len(content) != size:
        raise RunnerError(f"git context size changed while reading {path}")
    return _FileState(content, mode == "100755")


def _materialize_git_bundle(
    root: Path,
    commit: str,
    bundle_source: PurePosixPath,
    target: Path,
    *,
    ignore_generated_caches: bool = False,
) -> None:
    entries = _git_bundle_entries(
        root,
        commit,
        bundle_source,
        ignore_generated_caches=ignore_generated_caches,
    )
    prefix = bundle_source
    target.mkdir(parents=True, exist_ok=False)
    for entry in entries:
        relative = entry.path.relative_to(prefix)
        destination = target / Path(*relative.parts)
        destination.parent.mkdir(parents=True, exist_ok=True)
        content = _git_blob(root, commit, entry.path)
        if len(content) != entry.size:
            raise RunnerError(
                f"bundle snapshot size changed while reading {entry.path}"
            )
        destination.write_bytes(content)
        destination.chmod(0o755 if entry.mode == "100755" else 0o644)
    _scan_tree(target)


def _decode_context(content: bytes, path: PurePosixPath) -> str:
    if len(content) > MAX_FILE_BYTES:
        raise RunnerError(f"context file exceeds size limit: {path}")
    try:
        text = content.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise RunnerError(f"context file must be UTF-8 text: {path}") from exc
    return f'<context-file path="{path}">\n{text}\n</context-file>'


@dataclass(frozen=True)
class _FileState:
    content: bytes
    executable: bool


def _scan_normalized_worktree(
    root: Path, *, ignore_generated_caches: bool
) -> list[Path]:
    files: list[Path] = []
    total = 0
    traversed_entries = 0
    stack: list[tuple[Path, int]] = [(root, 0)]
    while stack:
        current, depth = stack.pop()
        try:
            with os.scandir(current) as scanner:
                for item in scanner:
                    traversed_entries += 1
                    if traversed_entries > MAX_WORKTREE_SCAN_ENTRIES:
                        raise RunnerError(
                            "worktree traversal exceeds maximum entries "
                            f"{MAX_WORKTREE_SCAN_ENTRIES}: {root}"
                        )
                    path = Path(item.path)
                    if item.is_symlink():
                        raise RunnerError(
                            f"tree contains symlink or special entry: {path}"
                        )
                    if item.is_dir(follow_symlinks=False):
                        if (
                            ignore_generated_caches
                            and item.name in _GENERATED_CACHE_DIRECTORIES
                        ):
                            continue
                        child_depth = depth + 1
                        if child_depth > MAX_WORKTREE_SCAN_DEPTH:
                            raise RunnerError(
                                "worktree traversal exceeds maximum depth "
                                f"{MAX_WORKTREE_SCAN_DEPTH}: {root}"
                            )
                        stack.append((path, child_depth))
                        continue
                    if not item.is_file(follow_symlinks=False):
                        raise RunnerError(f"tree contains special file: {path}")
                    if (
                        ignore_generated_caches
                        and path.suffix in _GENERATED_CACHE_SUFFIXES
                    ):
                        continue
                    size = item.stat(follow_symlinks=False).st_size
                    if size > MAX_FILE_BYTES:
                        raise RunnerError(
                            f"tree file exceeds {MAX_FILE_BYTES} bytes: {path}"
                        )
                    total += size
                    if total > MAX_TREE_BYTES:
                        raise RunnerError(
                            f"tree exceeds {MAX_TREE_BYTES} bytes: {root}"
                        )
                    files.append(path)
        except OSError as exc:
            raise RunnerError(f"cannot scan tree directory {current}: {exc}") from exc

    retained_directories = {
        parent
        for path in files
        for parent in path.relative_to(root).parents
        if parent != Path(".")
    }
    if any(len(path.parts) > MAX_TREE_DEPTH for path in retained_directories):
        raise RunnerError(f"tree exceeds maximum depth {MAX_TREE_DEPTH}: {root}")
    if len(files) + len(retained_directories) > MAX_TREE_ENTRIES:
        raise RunnerError(f"tree exceeds maximum entries {MAX_TREE_ENTRIES}: {root}")
    return sorted(files, key=lambda path: path.relative_to(root).as_posix())


def _scan_tree(
    root: Path,
    *,
    ignore_generated_caches: bool = False,
    ignore_empty_directories: bool = False,
    include_directories: bool = False,
) -> list[Path]:
    if not root.is_dir() or root.is_symlink():
        raise RunnerError(f"tree root must be a regular directory: {root}")
    if ignore_empty_directories:
        return _scan_normalized_worktree(
            root, ignore_generated_caches=ignore_generated_caches
        )
    paths: list[Path] = []
    total = 0
    entries = 0
    for current, directories, filenames in os.walk(root, followlinks=False):
        current_path = Path(current)
        relative_current = current_path.relative_to(root)
        if len(relative_current.parts) > MAX_TREE_DEPTH:
            raise RunnerError(f"tree exceeds maximum depth {MAX_TREE_DEPTH}: {root}")
        retained_directories: list[str] = []
        for name in directories:
            path = current_path / name
            if path.is_symlink() or not path.is_dir():
                raise RunnerError(f"tree contains symlink or special directory: {path}")
            if ignore_generated_caches and name in _GENERATED_CACHE_DIRECTORIES:
                continue
            entries += 1
            if entries > MAX_TREE_ENTRIES:
                raise RunnerError(
                    f"tree exceeds maximum entries {MAX_TREE_ENTRIES}: {root}"
                )
            retained_directories.append(name)
            if include_directories:
                paths.append(path)
        directories[:] = retained_directories
        for name in filenames:
            path = current_path / name
            mode = path.lstat().st_mode
            if stat.S_ISLNK(mode) or not stat.S_ISREG(mode):
                raise RunnerError(f"tree contains symlink or special file: {path}")
            if ignore_generated_caches and path.suffix in _GENERATED_CACHE_SUFFIXES:
                continue
            entries += 1
            if entries > MAX_TREE_ENTRIES:
                raise RunnerError(
                    f"tree exceeds maximum entries {MAX_TREE_ENTRIES}: {root}"
                )
            size = path.stat().st_size
            if size > MAX_FILE_BYTES:
                raise RunnerError(f"tree file exceeds {MAX_FILE_BYTES} bytes: {path}")
            total += size
            if total > MAX_TREE_BYTES:
                raise RunnerError(f"tree exceeds {MAX_TREE_BYTES} bytes: {root}")
            paths.append(path)
    return sorted(paths, key=lambda path: path.relative_to(root).as_posix())


def _read_tree(
    root: Path,
    *,
    ignore_generated_caches: bool = False,
    ignore_empty_directories: bool = False,
) -> dict[str, _FileState]:
    states: dict[str, _FileState] = {}
    for path in _scan_tree(
        root,
        ignore_generated_caches=ignore_generated_caches,
        ignore_empty_directories=ignore_empty_directories,
    ):
        relative = path.relative_to(root).as_posix()
        mode = path.stat().st_mode
        states[relative] = _FileState(path.read_bytes(), bool(mode & stat.S_IXUSR))
    return states


def _read_tree_permissions(
    root: Path,
    *,
    ignore_generated_caches: bool = False,
) -> dict[str, int]:
    permissions = {".": stat.S_IMODE(root.stat().st_mode)}
    for path in _scan_tree(
        root,
        ignore_generated_caches=ignore_generated_caches,
        include_directories=True,
    ):
        permissions[path.relative_to(root).as_posix()] = stat.S_IMODE(
            path.stat().st_mode
        )
    return permissions


def _copy_tree(
    source: Path,
    destination: Path,
    *,
    ignore_generated_caches: bool = False,
    ignore_empty_directories: bool = False,
) -> None:
    files = _scan_tree(
        source,
        ignore_generated_caches=ignore_generated_caches,
        ignore_empty_directories=ignore_empty_directories,
    )
    destination.mkdir(parents=True, exist_ok=False)
    directories = sorted(
        {
            parent
            for source_file in files
            for parent in source_file.relative_to(source).parents
            if parent != Path(".")
        },
        key=lambda path: (len(path.parts), path.as_posix()),
    )
    for directory in directories:
        (destination / directory).mkdir(parents=True, exist_ok=True)
    for source_file in files:
        relative = source_file.relative_to(source)
        target = destination / relative
        shutil.copy2(source_file, target, follow_symlinks=False)
        target.chmod(target.stat().st_mode | stat.S_IWUSR | stat.S_IRUSR)


def _states_hash(states: dict[str, _FileState]) -> str:
    digest = hashlib.sha256()
    for path, state in sorted(states.items()):
        digest.update(path.encode("utf-8"))
        digest.update(b"\0x\0" if state.executable else b"\0-\0")
        digest.update(str(len(state.content)).encode("ascii"))
        digest.update(b"\0")
        digest.update(state.content)
        digest.update(b"\0")
    return digest.hexdigest()


def _tree_hash(
    root: Path,
    *,
    ignore_generated_caches: bool = False,
    ignore_empty_directories: bool = False,
) -> str:
    return _states_hash(
        _read_tree(
            root,
            ignore_generated_caches=ignore_generated_caches,
            ignore_empty_directories=ignore_empty_directories,
        )
    )


def _snapshot_tree(root: Path, *, ignore_generated_caches: bool) -> _TreeSnapshot:
    states = _read_tree(root, ignore_generated_caches=ignore_generated_caches)
    return _TreeSnapshot(states=states, sha256=_states_hash(states))


def _materialize_snapshot(snapshot: _TreeSnapshot, destination: Path) -> None:
    _mkdir_private(destination, parents=True, exist_ok=False)
    directories = sorted(
        {
            Path(*PurePosixPath(relative).parent.parts)
            for relative in snapshot.states
            if PurePosixPath(relative).parent != PurePosixPath(".")
        },
        key=lambda path: (len(path.parts), path.as_posix()),
    )
    for directory in directories:
        _mkdir_private(destination / directory, parents=True, exist_ok=True)
    for relative, state in sorted(snapshot.states.items()):
        target = destination / Path(*PurePosixPath(relative).parts)
        _write_bytes(target, state.content)
        target.chmod(0o700 if state.executable else PRIVATE_FILE_MODE)
    if _states_hash(_read_tree(destination)) != snapshot.sha256:
        raise RunnerError(
            f"materialized source snapshot failed attestation: {destination}"
        )
    _make_tree_readonly(destination)


def _diff_states(before: dict[str, _FileState], after: dict[str, _FileState]) -> str:
    chunks: list[str] = []
    for path in sorted(before.keys() | after.keys()):
        old = before.get(path)
        new = after.get(path)
        if old == new:
            continue
        old_content = b"" if old is None else old.content
        new_content = b"" if new is None else new.content
        try:
            old_text = old_content.decode("utf-8").splitlines(keepends=True)
            new_text = new_content.decode("utf-8").splitlines(keepends=True)
        except UnicodeDecodeError:
            chunks.append(
                "Binary files differ: "
                f"{path} old={_sha256(old_content)} new={_sha256(new_content)}\n"
            )
            continue
        old_name = "/dev/null" if old is None else f"a/{path}"
        new_name = "/dev/null" if new is None else f"b/{path}"
        chunks.append(f"diff --git a/{path} b/{path}\n")
        if old is None:
            chunks.append("new file mode 100644\n")
            if new is not None and new.executable:
                chunks.append(f"File mode changed: {path} executable False -> True\n")
        elif new is None:
            chunks.append("deleted file mode 100644\n")
        chunks.extend(
            difflib.unified_diff(
                old_text,
                new_text,
                fromfile=old_name,
                tofile=new_name,
                lineterm="\n",
            )
        )
        if old is not None and new is not None and old.executable != new.executable:
            chunks.append(
                f"File mode changed: {path} executable {old.executable} -> {new.executable}\n"
            )
    result = "".join(chunks)
    return result if not result or result.endswith("\n") else result + "\n"


def _make_tree_readonly(root: Path) -> None:
    for path in _scan_tree(root):
        mode = path.stat().st_mode
        executable = bool(mode & stat.S_IXUSR)
        path.chmod(0o555 if executable else 0o444)
    directories = [Path(current) for current, _dirs, _files in os.walk(root)]
    for directory in sorted(
        directories, key=lambda path: len(path.parts), reverse=True
    ):
        directory.chmod(0o555)


def _make_tree_writable(root: Path) -> None:
    if not root.exists():
        return
    directories = [Path(current) for current, _dirs, _files in os.walk(root)]
    for directory in directories:
        try:
            directory.chmod(0o755)
        except OSError:
            pass
    for current, _directories, filenames in os.walk(root):
        for name in filenames:
            path = Path(current) / name
            try:
                if not path.is_symlink():
                    path.chmod(path.stat().st_mode | stat.S_IWUSR | stat.S_IRUSR)
            except OSError:
                pass


def _derived_seed(seed: int, *parts: str) -> int:
    digest = hashlib.sha256()
    digest.update(str(seed).encode("ascii"))
    for part in parts:
        digest.update(b"\0")
        digest.update(part.encode("utf-8"))
    return int.from_bytes(digest.digest()[:8], "big")


def _sha256(content: bytes) -> str:
    return hashlib.sha256(content).hexdigest()


def _load_strict_json(value: str, location: str) -> Any:
    def unique_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
        result: dict[str, Any] = {}
        for key, item in pairs:
            if key in result:
                raise RunnerError(f"{location} has duplicate key: {key}")
            result[key] = item
        return result

    def reject_constant(constant: str) -> None:
        raise RunnerError(f"{location} has non-finite number: {constant}")

    try:
        return json.loads(
            value,
            object_pairs_hook=unique_object,
            parse_constant=reject_constant,
        )
    except json.JSONDecodeError as exc:
        raise RunnerError(f"{location} is invalid JSON: {exc}") from exc


def _validate_verifier_payload(
    stdout: str, critical_expectations: tuple[str, ...]
) -> tuple[dict[str, Any], list[dict[str, Any]], dict[str, Any]]:
    payload = _load_strict_json(stdout, "verifier stdout")
    if not isinstance(payload, dict):
        raise RunnerError("verifier output must be a JSON object")
    unknown = set(payload) - {"passed", "assertions", "metrics"}
    if unknown:
        raise RunnerError(
            f"verifier output has unknown keys: {', '.join(sorted(unknown))}"
        )
    if not {"passed", "assertions"}.issubset(payload):
        raise RunnerError("verifier output requires passed and assertions")
    if not isinstance(payload["passed"], bool):
        raise RunnerError("verifier passed must be boolean")
    if not isinstance(payload["assertions"], list):
        raise RunnerError("verifier assertions must be an array")
    assertions: list[dict[str, Any]] = []
    assertion_ids: set[str] = set()
    for index, assertion in enumerate(payload["assertions"]):
        if not isinstance(assertion, dict) or set(assertion) != {
            "id",
            "passed",
            "evidence",
        }:
            raise RunnerError(
                f"verifier assertion {index} requires only id, passed, and evidence"
            )
        assertion_id = assertion["id"]
        if not isinstance(assertion_id, str) or not assertion_id:
            raise RunnerError(
                f"verifier assertion {index} id must be a non-empty string"
            )
        if assertion_id in assertion_ids:
            raise RunnerError(
                f"verifier returned duplicate assertion id: {assertion_id}"
            )
        if not isinstance(assertion["passed"], bool):
            raise RunnerError(
                f"verifier assertion {assertion_id} passed must be boolean"
            )
        if not isinstance(assertion["evidence"], str):
            raise RunnerError(
                f"verifier assertion {assertion_id} evidence must be a string"
            )
        assertion_ids.add(assertion_id)
        assertions.append(dict(assertion))
    missing = set(critical_expectations) - assertion_ids
    if missing:
        raise RunnerError(
            f"verifier omitted critical assertions: {', '.join(sorted(missing))}"
        )
    if payload["passed"] and any(not assertion["passed"] for assertion in assertions):
        raise RunnerError("verifier reported passed=true with failed assertions")
    metrics = payload.get("metrics", {})
    if not isinstance(metrics, dict):
        raise RunnerError("verifier metrics must be an object")
    return payload, assertions, metrics


def _timeout_text(value: bytes | str | None) -> str:
    if value is None:
        return ""
    if isinstance(value, bytes):
        return value.decode("utf-8", errors="replace")
    return value


def _manifest_bytes(suite: SuiteSpec) -> bytes:
    content = suite.raw_bytes
    observed = _sha256(content)
    if observed != suite.manifest_hash:
        raise RunnerError(
            "suite manifest bytes do not reproduce the loaded manifest hash"
        )
    return content


def _prepare_result_root(raw_path: Path) -> tuple[Path, bool]:
    requested = Path(os.path.abspath(Path(raw_path).expanduser()))
    if requested.is_symlink():
        raise RunnerError(f"result root must not be a symlink: {requested}")
    created = False
    if not requested.exists():
        missing_parents: list[Path] = []
        cursor = requested.parent
        while not cursor.exists():
            missing_parents.append(cursor)
            if cursor.parent == cursor:
                break
            cursor = cursor.parent
        for directory in reversed(missing_parents):
            try:
                directory.mkdir(mode=PRIVATE_DIRECTORY_MODE)
            except FileExistsError:
                continue
            directory.chmod(PRIVATE_DIRECTORY_MODE)
            _fsync_directory(directory.parent.resolve(strict=True))
        try:
            requested.mkdir(mode=PRIVATE_DIRECTORY_MODE)
            created = True
        except FileExistsError:
            pass
    try:
        resolved = requested.resolve(strict=True)
    except OSError as exc:
        raise RunnerError(f"cannot resolve result root {requested}: {exc}") from exc
    if requested.is_symlink() or not resolved.is_dir():
        raise RunnerError(f"result root must be a regular directory: {requested}")
    if created:
        resolved.chmod(PRIVATE_DIRECTORY_MODE)
    _validate_private_directory(resolved, "result root")
    if created:
        _fsync_directory(resolved.parent)
    try:
        nonempty = next(resolved.iterdir(), None)
    except OSError as exc:
        raise RunnerError(f"cannot inspect result root {resolved}: {exc}") from exc
    if nonempty is not None:
        raise RunnerError(f"result root must be empty: {resolved}")
    return resolved, created


def _validate_private_directory(path: Path, label: str) -> None:
    metadata = path.lstat()
    if (
        not stat.S_ISDIR(metadata.st_mode)
        or stat.S_ISLNK(metadata.st_mode)
        or metadata.st_uid != os.getuid()
        or stat.S_IMODE(metadata.st_mode) != PRIVATE_DIRECTORY_MODE
    ):
        raise RunnerError(
            f"{label} must be owned by uid {os.getuid()} with mode 0700: {path}"
        )


def _mkdir_private(path: Path, *, parents: bool, exist_ok: bool) -> None:
    target = Path(path)
    missing: list[Path] = []
    cursor = target
    while not cursor.exists():
        missing.append(cursor)
        if not parents:
            break
        if cursor.parent == cursor:
            break
        cursor = cursor.parent
    if not parents and len(missing) > 1:
        raise RunnerError(f"private directory parent is missing: {target.parent}")
    for directory in reversed(missing):
        try:
            directory.mkdir(mode=PRIVATE_DIRECTORY_MODE)
        except FileExistsError:
            pass
        directory.chmod(PRIVATE_DIRECTORY_MODE)
    if target.exists() and not missing and not exist_ok:
        raise FileExistsError(target)
    _validate_private_directory(target, "result artifact directory")


def _write_bytes(path: Path, value: bytes) -> None:
    _mkdir_private(path.parent, parents=True, exist_ok=True)
    temporary = path.with_name(f".{path.name}.tmp-{os.getpid()}-{time.monotonic_ns()}")
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_CLOEXEC
    descriptor = os.open(temporary, flags, PRIVATE_FILE_MODE)
    try:
        view = memoryview(value)
        while view:
            written = os.write(descriptor, view)
            view = view[written:]
        os.fchmod(descriptor, PRIVATE_FILE_MODE)
        os.fsync(descriptor)
    except Exception:
        try:
            temporary.unlink()
        except OSError:
            pass
        raise
    finally:
        os.close(descriptor)
    os.replace(temporary, path)
    metadata = path.lstat()
    if (
        not stat.S_ISREG(metadata.st_mode)
        or metadata.st_uid != os.getuid()
        or stat.S_IMODE(metadata.st_mode) != PRIVATE_FILE_MODE
    ):
        raise RunnerError(f"result artifact is not an owner-only regular file: {path}")


def _read_private_artifact(path: Path) -> bytes:
    flags = os.O_RDONLY | os.O_CLOEXEC | getattr(os, "O_NOFOLLOW", 0)
    descriptor = os.open(path, flags)
    try:
        metadata = os.fstat(descriptor)
        if (
            not stat.S_ISREG(metadata.st_mode)
            or metadata.st_uid != os.getuid()
            or stat.S_IMODE(metadata.st_mode) != PRIVATE_FILE_MODE
            or metadata.st_size > MAX_ARTIFACT_BYTES
        ):
            raise RunnerError("normalized artifact file metadata drifted")
        content = os.read(descriptor, MAX_ARTIFACT_BYTES + 1)
        if len(content) != metadata.st_size or os.read(descriptor, 1):
            raise RunnerError("normalized artifact file size drifted")
        return content
    finally:
        os.close(descriptor)


def _write_json(path: Path, value: Any) -> None:
    _write_bytes(
        path,
        (json.dumps(value, indent=2, sort_keys=True, ensure_ascii=True) + "\n").encode(
            "utf-8"
        ),
    )


def _write_text(path: Path, value: str) -> None:
    _write_bytes(path, value.encode("utf-8"))


def _utc_now() -> str:
    return dt.datetime.now(dt.timezone.utc).isoformat().replace("+00:00", "Z")
