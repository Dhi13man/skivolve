"""Shared, release-pinned comparator protocol and Claude transport."""

from __future__ import annotations

import contextlib
import hashlib
import json
import math
import os
import re
import shutil
import signal
import stat
import subprocess
import tempfile
import threading
import time
import uuid
from contextlib import ExitStack
from dataclasses import dataclass, field
from pathlib import Path, PurePosixPath
from typing import Any, Callable

from skivolve.comparator_calibration import calibration as _calibration
from skivolve.comparator_profiles import (
    ComparatorProfileResources,
    resolve_builtin_profile,
)


SUITE_ROOT = Path(__file__).resolve().parent
CALIBRATION_ROOT = SUITE_ROOT / "comparator_calibration"


CalibrationError = _calibration.CalibrationError
Bundle = _calibration.Bundle
EVIDENCE_TRIAL_KEYS = _calibration.EVIDENCE_TRIAL_KEYS
canonical_bytes = _calibration.canonical_bytes
canonical_sha256 = _calibration.canonical_sha256
exact_object = _calibration._exact
integer = _calibration._integer
text_value = _calibration._text
build_request_bytes = _calibration.build_request_bytes
evaluate_evidence = _calibration.evaluate_evidence
expected_transport_hashes = _calibration.expected_transport_hashes
invocation_id = _calibration.invocation_id
load_json = _calibration.load_json
parse_raw_provider_response = _calibration.parse_raw_provider_response
validate_manifest = _calibration.validate_manifest
validate_release = _calibration.validate_release
validate_profile_release = _calibration.validate_profile_release
validate_executor_evidence = _calibration.validate_executor_evidence
validate_response = _calibration.validate_response


RUNTIME_ADAPTER_ID = "shared-harness-claude-cli-v1"
CERTIFICATION_SCHEMA_VERSION = 1
MAX_REQUEST_BYTES = 4 * 1024 * 1024
MAX_BASE_BYTES = 2 * 1024 * 1024
MAX_DIFF_BYTES = 1024 * 1024
MAX_RESPONSE_BYTES = 4 * 1024 * 1024
MAX_STDERR_BYTES = 1024 * 1024
# ProtectKernelTunables and ProtectKernelLogs are deliberately absent: once a
# systemd user manager enforces their /proc over-mounts, the kernel rejects the
# nested candidate `unshare --mount-proc` these units depend on. PrivateUsers
# blocks tunable writes, PrivateDevices removes /dev/kmsg, and the filter
# denies syslog(2) with EPERM.
SANDBOX_ISOLATION_PROPERTIES = (
    "ProtectSystem=strict",
    "ProtectHome=read-only",
    "PrivateTmp=yes",
    "NoNewPrivileges=yes",
    "RestrictSUIDSGID=yes",
    "ProtectProc=invisible",
    "ProcSubset=pid",
    "PrivateUsers=yes",
    "PrivateDevices=yes",
    "ProtectKernelModules=yes",
    "ProtectControlGroups=yes",
    "LockPersonality=yes",
    "RestrictRealtime=yes",
    "SystemCallFilter=~syslog",
    "SystemCallErrorNumber=EPERM",
)
_SPEND_ATTEMPT_RE = re.compile(r"^[0-9a-f]{32}$")
_SPEND_BINDING_RE = re.compile(r"^[0-9a-f]{64}$")


class VerifiedExecutable:
    """Private executable copy made from one continuously held source descriptor."""

    def __init__(self, path: Path) -> None:
        self.path = Path(path).resolve(strict=True)
        self._owner_pid = os.getpid()
        self._source_descriptor = -1
        self._copy_descriptor = -1
        self._copy_root: Path | None = None
        self._copy_path: Path | None = None
        self._copy_identity: dict[str, int] | None = None
        try:
            (
                self._source_descriptor,
                self.identity,
                self.sha256,
            ) = _open_verified_executable(self.path)
            (
                self._copy_descriptor,
                self._copy_root,
                self._copy_path,
                self._copy_identity,
            ) = _private_executable_copy(
                self._source_descriptor,
                self.identity,
                self.sha256,
            )
        except BaseException:
            self.close()
            raise

    @property
    def descriptor_path(self) -> str:
        if self._copy_descriptor < 0 or os.getpid() != self._owner_pid:
            raise CalibrationError("verified executable descriptor is unavailable")
        return f"/proc/{self._owner_pid}/fd/{self._copy_descriptor}"

    @property
    def execution_path(self) -> Path:
        if self._copy_path is None:
            raise CalibrationError("verified executable copy is unavailable")
        return self._copy_path

    def ensure_source_unchanged(self) -> None:
        """Reject installed-source or private-copy drift before sandbox launch."""

        if self._source_descriptor < 0 or self._copy_descriptor < 0:
            raise CalibrationError("verified executable descriptor is closed")
        if os.getpid() != self._owner_pid:
            raise CalibrationError("verified executable cannot cross a process fork")
        if _file_identity(os.fstat(self._source_descriptor)) != self.identity:
            raise CalibrationError(
                "Claude executable changed after initial attestation"
            )
        descriptor = _open_regular_file(self.path)
        try:
            if _file_identity(os.fstat(descriptor)) != self.identity:
                raise CalibrationError(
                    "Claude executable path changed after initial attestation"
                )
        finally:
            os.close(descriptor)
        if (
            self._copy_path is None
            or self._copy_identity is None
            or _file_identity(os.fstat(self._copy_descriptor)) != self._copy_identity
        ):
            raise CalibrationError("private Claude executable descriptor changed")
        copy_descriptor = _open_regular_file(self._copy_path)
        try:
            if _file_identity(os.fstat(copy_descriptor)) != self._copy_identity:
                raise CalibrationError("private Claude executable path changed")
        finally:
            os.close(copy_descriptor)

    def close(self) -> None:
        for attribute in ("_copy_descriptor", "_source_descriptor"):
            descriptor = getattr(self, attribute, -1)
            if descriptor >= 0:
                try:
                    os.close(descriptor)
                except OSError:
                    pass
                setattr(self, attribute, -1)
        if self._copy_root is not None:
            try:
                self._copy_root.chmod(0o700)
                shutil.rmtree(self._copy_root)
            except OSError:
                pass
            self._copy_root = None
            self._copy_path = None
            self._copy_identity = None

    def __del__(self) -> None:
        self.close()


@dataclass(frozen=True)
class TransportExecution:
    """Exact process bytes and timing returned by an injected executor."""

    returncode: int
    stdout: bytes
    stderr: bytes
    duration_seconds: float
    executor: dict[str, Any]


class TransportOverflowError(CalibrationError):
    """A transport stream exceeded its hard byte ceiling."""

    def __init__(
        self,
        stream: str,
        captured: bytes,
        *,
        process_label: str = "Claude comparator",
    ) -> None:
        super().__init__(f"{process_label} {stream} exceeds byte limit")
        self.stream = stream
        self.captured = captured


def execute_bounded_transport(
    command: list[str],
    *,
    cwd: Path,
    stdin_bytes: bytes,
    timeout_seconds: int,
    stdout_limit: int,
    stderr_limit: int,
    terminate: Callable[[], None],
    evidence: dict[str, Any],
    process_label: str,
    on_started: Callable[[], None] | None = None,
) -> TransportExecution:
    """Run one process while retaining at most the declared stream limits."""

    if timeout_seconds <= 0 or stdout_limit <= 0 or stderr_limit <= 0:
        raise ValueError("transport limits must be positive")
    started = time.monotonic()
    try:
        process = subprocess.Popen(
            command,
            cwd=cwd,
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            shell=False,
            env=_systemd_client_environment(),
            start_new_session=True,
        )
    except OSError as exc:
        raise CalibrationError(f"{process_label} could not execute: {exc}") from exc
    assert process.stdin is not None
    assert process.stdout is not None
    assert process.stderr is not None

    def stop_process() -> None:
        with contextlib.suppress(BaseException):
            terminate()
        with contextlib.suppress(ProcessLookupError, PermissionError, OSError):
            os.killpg(process.pid, signal.SIGKILL)
        with contextlib.suppress(BaseException):
            process.kill()

    def close_pipes() -> None:
        for stream in (process.stdin, process.stdout, process.stderr):
            with contextlib.suppress(OSError):
                stream.close()

    try:
        if on_started is not None:
            on_started()
    except BaseException:
        stop_process()
        with contextlib.suppress(subprocess.TimeoutExpired):
            process.wait(timeout=5)
        close_pipes()
        raise

    buffers = {"stdout": bytearray(), "stderr": bytearray()}
    limits = {"stdout": stdout_limit, "stderr": stderr_limit}
    overflow = threading.Event()
    overflow_stream: list[str] = []
    reader_errors: list[BaseException] = []
    lock = threading.Lock()

    def read_stream(name: str, stream: Any) -> None:
        try:
            while chunk := stream.read(64 * 1024):
                with lock:
                    remaining = limits[name] - len(buffers[name])
                    if remaining > 0:
                        buffers[name].extend(chunk[:remaining])
                    if len(chunk) > remaining:
                        if not overflow_stream:
                            overflow_stream.append(name)
                        overflow.set()
                        return
        except BaseException as exc:  # surfaced as transport failure below
            reader_errors.append(exc)

    def write_stdin() -> None:
        try:
            process.stdin.write(stdin_bytes)
            process.stdin.close()
        except (BrokenPipeError, OSError):
            try:
                process.stdin.close()
            except OSError:
                pass

    readers = [
        threading.Thread(
            target=read_stream,
            args=("stdout", process.stdout),
            name="transport-stdout",
        ),
        threading.Thread(
            target=read_stream,
            args=("stderr", process.stderr),
            name="transport-stderr",
        ),
    ]
    writer = threading.Thread(target=write_stdin, name="transport-stdin")
    for thread in (*readers, writer):
        thread.start()
    deadline = started + timeout_seconds
    timed_out = False
    terminated = False
    while process.poll() is None:
        if overflow.is_set():
            break
        if time.monotonic() >= deadline:
            timed_out = True
            break
        time.sleep(0.01)
    if process.poll() is None:
        stop_process()
        terminated = True
    cleanup_deadline = time.monotonic() + 5

    def remaining_cleanup() -> float:
        return max(0.001, cleanup_deadline - time.monotonic())

    try:
        process.wait(timeout=remaining_cleanup())
    except subprocess.TimeoutExpired:
        stop_process()
        with contextlib.suppress(subprocess.TimeoutExpired):
            process.wait(timeout=remaining_cleanup())
    if process.poll() is None:
        close_pipes()
    for thread in (*readers, writer):
        thread.join(timeout=remaining_cleanup())
    close_pipes()
    cleanup_incomplete = process.poll() is None or any(
        thread.is_alive() for thread in (*readers, writer)
    )
    if cleanup_incomplete:
        reason = (
            f"{overflow_stream[0]} overflow"
            if overflow_stream
            else "timeout"
            if timed_out
            else "completion"
        )
        raise CalibrationError(f"{process_label} cleanup did not finish after {reason}")
    duration = time.monotonic() - started
    if overflow.is_set():
        if not terminated:
            try:
                terminate()
            except BaseException:
                pass
        name = overflow_stream[0]
        raise TransportOverflowError(
            name,
            bytes(buffers[name]),
            process_label=process_label,
        )
    if timed_out:
        raise CalibrationError(f"{process_label} timed out after {timeout_seconds}s")
    if reader_errors:
        raise CalibrationError(f"{process_label} stream capture failed")
    return TransportExecution(
        process.returncode,
        bytes(buffers["stdout"]),
        bytes(buffers["stderr"]),
        duration,
        evidence,
    )


@dataclass(frozen=True)
class TransportResult:
    """Validated provider evidence bound to one exact request."""

    response: dict[str, Any]
    decision: dict[str, Any]
    raw_response: str
    requested_model: str
    actual_models: tuple[str, ...]
    provider_name: str
    provider_version: str
    cost_usd: float
    duration_seconds: float
    request_sha256: str
    raw_response_sha256: str
    parsed_response_sha256: str
    command_sha256: str
    stdin_sha256: str
    spend_attempt_id: str
    executor: dict[str, Any]

    def as_json(self) -> dict[str, Any]:
        return {
            "response": self.response,
            "decision": self.decision,
            "raw_response": self.raw_response,
            "requested_model": self.requested_model,
            "actual_models": list(self.actual_models),
            "provider_name": self.provider_name,
            "provider_version": self.provider_version,
            "cost_usd": self.cost_usd,
            "duration_seconds": self.duration_seconds,
            "request_sha256": self.request_sha256,
            "raw_response_sha256": self.raw_response_sha256,
            "parsed_response_sha256": self.parsed_response_sha256,
            "command_sha256": self.command_sha256,
            "stdin_sha256": self.stdin_sha256,
            "spend_attempt_id": self.spend_attempt_id,
            "executor": self.executor,
        }


def _validate_spend_binding(request_sha256: str, invocation_id: str) -> tuple[str, str]:
    if (
        not isinstance(request_sha256, str)
        or _SPEND_BINDING_RE.fullmatch(request_sha256) is None
        or not isinstance(invocation_id, str)
        or _SPEND_BINDING_RE.fullmatch(invocation_id) is None
    ):
        raise CalibrationError("comparator spend request binding is invalid")
    return request_sha256, invocation_id


class SpendLedger:
    """Thread-safe run-level comparator spend ceiling with crash-safe journaling."""

    def __init__(self, maximum_usd: float, journal_path: Path | None = None) -> None:
        if not math.isfinite(maximum_usd) or maximum_usd <= 0:
            raise CalibrationError("comparator run spend limit must be positive")
        self.maximum_usd = maximum_usd
        self._spent_usd = 0.0
        self._reserved_usd = 0.0
        self._lock = threading.Lock()
        self.journal_path = (
            Path(os.path.abspath(journal_path)) if journal_path is not None else None
        )
        self._journal_identity: tuple[int, ...] | None = None
        self._journal_records = 0
        if self.journal_path is not None:
            self._restore_journal()

    @property
    def spent_usd(self) -> float:
        with self._lock:
            return self._spent_usd

    @property
    def has_journal_records(self) -> bool:
        with self._lock:
            return self._journal_records > 0

    @property
    def journal_sha256(self) -> str | None:
        with self._lock:
            raw = self._read_journal_bytes()
        if raw is None:
            return None
        return hashlib.sha256(raw).hexdigest()

    def journal_records(self) -> list[dict[str, Any]]:
        with self._lock:
            raw = self._read_journal_bytes()
        if raw is None:
            return []
        return [json.loads(line) for line in raw.splitlines()]

    def reserve(
        self,
        maximum_call_usd: float,
        *,
        request_sha256: str,
        invocation_id: str,
    ) -> "SpendReservation":
        request_sha256, invocation_id = _validate_spend_binding(
            request_sha256, invocation_id
        )
        if not math.isfinite(maximum_call_usd) or maximum_call_usd <= 0:
            raise CalibrationError("comparator reservation must be positive")
        with self._lock:
            committed = self._spent_usd + self._reserved_usd
            if committed + maximum_call_usd > self.maximum_usd:
                raise CalibrationError(
                    "comparator run lacks budget for another full invocation"
                )
            attempt_id = uuid.uuid4().hex
            self._append_journal(
                {
                    "event": "reserve",
                    "attempt_id": attempt_id,
                    "invocation_id": invocation_id,
                    "request_sha256": request_sha256,
                    "reserved_usd": maximum_call_usd,
                }
            )
            self._reserved_usd += maximum_call_usd
        return SpendReservation(
            self,
            attempt_id,
            maximum_call_usd,
            request_sha256,
            invocation_id,
        )

    def charge_historical(
        self,
        cost_usd: float,
        *,
        request_sha256: str,
        invocation_id: str,
    ) -> float:
        request_sha256, invocation_id = _validate_spend_binding(
            request_sha256, invocation_id
        )
        if not math.isfinite(cost_usd) or cost_usd < 0:
            raise CalibrationError("historical comparator cost is invalid")
        with self._lock:
            updated = self._spent_usd + cost_usd
            if updated + self._reserved_usd > self.maximum_usd:
                raise CalibrationError(
                    "historical comparator spend exceeds the run limit"
                )
            self._append_journal(
                {
                    "event": "historical",
                    "attempt_id": uuid.uuid4().hex,
                    "charged_usd": cost_usd,
                    "invocation_id": invocation_id,
                    "request_sha256": request_sha256,
                }
            )
            self._spent_usd = updated
            return updated

    def restore_reconciled(
        self,
        attempt_id: str,
        reserved_usd: float,
        cost_usd: float,
        *,
        request_sha256: str,
        invocation_id: str,
    ) -> float:
        request_sha256, invocation_id = _validate_spend_binding(
            request_sha256, invocation_id
        )
        cost = _finite_nonnegative(cost_usd, "historical comparator cost")
        reserved = _finite_nonnegative(reserved_usd, "historical reservation")
        if (
            not isinstance(attempt_id, str)
            or _SPEND_ATTEMPT_RE.fullmatch(attempt_id) is None
            or reserved <= 0
            or cost > reserved
        ):
            raise CalibrationError("historical comparator reservation is invalid")
        with self._lock:
            updated = self._spent_usd + cost
            if updated + self._reserved_usd > self.maximum_usd:
                raise CalibrationError(
                    "historical comparator spend exceeds the run limit"
                )
            self._append_journal(
                {
                    "event": "reserve",
                    "attempt_id": attempt_id,
                    "invocation_id": invocation_id,
                    "request_sha256": request_sha256,
                    "reserved_usd": reserved,
                }
            )
            self._append_journal(
                {
                    "event": "reconcile",
                    "attempt_id": attempt_id,
                    "charged_usd": cost,
                    "invocation_id": invocation_id,
                    "request_sha256": request_sha256,
                }
            )
            self._spent_usd = updated
            return updated

    def _finish(
        self,
        attempt_id: str,
        reserved: float,
        actual: float | None,
        request_sha256: str,
        invocation_id: str,
    ) -> None:
        request_sha256, invocation_id = _validate_spend_binding(
            request_sha256, invocation_id
        )
        if (
            not isinstance(attempt_id, str)
            or _SPEND_ATTEMPT_RE.fullmatch(attempt_id) is None
        ):
            raise CalibrationError("comparator spend attempt identity is invalid")
        with self._lock:
            charged = reserved if actual is None else actual
            if charged < 0 or charged > reserved:
                raise CalibrationError(
                    "comparator reservation reconciliation is invalid"
                )
            self._append_journal(
                {
                    "event": "forfeit" if actual is None else "reconcile",
                    "attempt_id": attempt_id,
                    "charged_usd": charged,
                    "invocation_id": invocation_id,
                    "request_sha256": request_sha256,
                }
            )
            self._reserved_usd -= reserved
            self._spent_usd += charged

    def _append_journal(self, record: dict[str, Any]) -> None:
        if self.journal_path is None:
            return
        target = _safe_output_path(self.journal_path)
        encoded = canonical_bytes(record) + b"\n"
        created = False
        try:
            metadata = target.lstat()
        except FileNotFoundError:
            created = True
            flags = os.O_WRONLY | os.O_APPEND | os.O_CREAT | os.O_EXCL | os.O_CLOEXEC
        except OSError as exc:
            raise CalibrationError(
                f"cannot inspect comparator spend journal: {exc}"
            ) from exc
        else:
            _validate_private_file(
                metadata,
                str(target),
                expected_identity=self._journal_identity,
            )
            flags = os.O_WRONLY | os.O_APPEND | os.O_CLOEXEC
        if hasattr(os, "O_NOFOLLOW"):
            flags |= os.O_NOFOLLOW
        try:
            descriptor = os.open(target, flags, 0o600)
        except OSError as exc:
            raise CalibrationError(
                f"cannot open comparator spend journal: {exc}"
            ) from exc
        try:
            if created:
                os.fchmod(descriptor, 0o600)
            identity = _validate_private_file(
                os.fstat(descriptor),
                str(target),
                expected_identity=self._journal_identity,
            )
            view = memoryview(encoded)
            while view:
                written = os.write(descriptor, view)
                if written <= 0:
                    raise CalibrationError("comparator spend journal made no progress")
                view = view[written:]
            os.fsync(descriptor)
            identity = _validate_private_file(os.fstat(descriptor), str(target))
        finally:
            os.close(descriptor)
        self._journal_identity = identity
        if created:
            _fsync_directory(target.parent)
        self._journal_records += 1

    def _restore_journal(self) -> None:
        assert self.journal_path is not None
        raw = self._read_journal_bytes()
        if raw is None:
            return
        lines = raw.splitlines()
        attempts: dict[str, tuple[float, float | None, str, str]] = {}
        seen_attempt_ids: set[str] = set()
        historical = 0.0
        for index, line in enumerate(lines):
            try:
                record = json.loads(line)
            except (UnicodeDecodeError, json.JSONDecodeError) as exc:
                raise CalibrationError(
                    f"comparator spend journal line {index + 1} is invalid"
                ) from exc
            if not isinstance(record, dict) or canonical_bytes(record) != line:
                raise CalibrationError(
                    "comparator spend journal is not canonical JSONL"
                )
            event = record.get("event")
            attempt_id = record.get("attempt_id")
            if (
                not isinstance(attempt_id, str)
                or _SPEND_ATTEMPT_RE.fullmatch(attempt_id) is None
            ):
                raise CalibrationError("comparator spend journal attempt id is invalid")
            request_sha256, invocation_id = _validate_spend_binding(
                record.get("request_sha256"), record.get("invocation_id")
            )
            if event == "reserve" and set(record) == {
                "event",
                "attempt_id",
                "invocation_id",
                "request_sha256",
                "reserved_usd",
            }:
                value = _finite_nonnegative(record["reserved_usd"], "reserved spend")
                if value <= 0 or attempt_id in seen_attempt_ids:
                    raise CalibrationError(
                        "comparator spend reservation journal is invalid"
                    )
                seen_attempt_ids.add(attempt_id)
                attempts[attempt_id] = (
                    value,
                    None,
                    request_sha256,
                    invocation_id,
                )
            elif event in {"reconcile", "forfeit"} and set(record) == {
                "event",
                "attempt_id",
                "charged_usd",
                "invocation_id",
                "request_sha256",
            }:
                charged = _finite_nonnegative(record["charged_usd"], "charged spend")
                if attempt_id not in attempts or attempts[attempt_id][1] is not None:
                    raise CalibrationError("comparator spend close journal is invalid")
                reserved, _, reserved_request, reserved_invocation = attempts[
                    attempt_id
                ]
                if (
                    request_sha256 != reserved_request
                    or invocation_id != reserved_invocation
                    or charged > reserved
                    or (event == "forfeit" and charged != reserved)
                ):
                    raise CalibrationError("comparator spend reconciliation is invalid")
                attempts[attempt_id] = (
                    reserved,
                    charged,
                    reserved_request,
                    reserved_invocation,
                )
            elif event == "historical" and set(record) == {
                "event",
                "attempt_id",
                "charged_usd",
                "invocation_id",
                "request_sha256",
            }:
                if attempt_id in seen_attempt_ids:
                    raise CalibrationError(
                        "historical comparator attempt is duplicated"
                    )
                seen_attempt_ids.add(attempt_id)
                historical += _finite_nonnegative(
                    record["charged_usd"], "historical spend"
                )
            else:
                raise CalibrationError("comparator spend journal event is invalid")
        # An unclosed reservation is conservatively charged at its full ceiling.
        restored = historical + sum(
            reserved if charged is None else charged
            for reserved, charged, _request, _invocation in attempts.values()
        )
        if restored > self.maximum_usd:
            raise CalibrationError("restored comparator spend exceeds the run limit")
        self._spent_usd = restored
        self._journal_records = len(lines)

    def _read_journal_bytes(self) -> bytes | None:
        if self.journal_path is None:
            return None
        target = _safe_output_path(self.journal_path)
        try:
            metadata = target.lstat()
        except FileNotFoundError:
            return None
        except OSError as exc:
            raise CalibrationError(
                f"cannot inspect comparator spend journal: {exc}"
            ) from exc
        expected_identity = self._journal_identity
        identity = _validate_private_file(
            metadata,
            str(target),
            expected_identity=expected_identity,
        )
        if metadata.st_size > 32 * 1024 * 1024:
            raise CalibrationError("comparator spend journal exceeds byte limit")
        flags = os.O_RDONLY | os.O_CLOEXEC
        if hasattr(os, "O_NOFOLLOW"):
            flags |= os.O_NOFOLLOW
        try:
            descriptor = os.open(target, flags)
        except OSError as exc:
            raise CalibrationError(
                f"cannot open comparator spend journal: {exc}"
            ) from exc
        try:
            opened = os.fstat(descriptor)
            _validate_private_file(
                opened,
                str(target),
                expected_identity=identity,
            )
            chunks: list[bytes] = []
            remaining = opened.st_size
            while remaining:
                chunk = os.read(descriptor, min(1024 * 1024, remaining))
                if not chunk:
                    raise CalibrationError("comparator spend journal was truncated")
                chunks.append(chunk)
                remaining -= len(chunk)
            if os.read(descriptor, 1):
                raise CalibrationError("comparator spend journal grew while reading")
            _validate_private_file(
                os.fstat(descriptor),
                str(target),
                expected_identity=identity,
            )
        finally:
            os.close(descriptor)
        self._journal_identity = identity
        return b"".join(chunks)


class SpendReservation:
    def __init__(
        self,
        ledger: SpendLedger,
        attempt_id: str,
        maximum_usd: float,
        request_sha256: str,
        invocation_id: str,
    ) -> None:
        self._ledger = ledger
        self._attempt_id = attempt_id
        self._maximum_usd = maximum_usd
        self._request_sha256 = request_sha256
        self._invocation_id = invocation_id
        self._finished = False
        self._lock = threading.Lock()

    @property
    def attempt_id(self) -> str:
        return self._attempt_id

    def reconcile(self, actual_usd: float) -> None:
        with self._lock:
            if self._finished:
                raise CalibrationError("comparator spend reservation is already closed")
            self._ledger._finish(
                self._attempt_id,
                self._maximum_usd,
                actual_usd,
                self._request_sha256,
                self._invocation_id,
            )
            self._finished = True

    def forfeit(self) -> None:
        with self._lock:
            if self._finished:
                return
            self._ledger._finish(
                self._attempt_id,
                self._maximum_usd,
                None,
                self._request_sha256,
                self._invocation_id,
            )
            self._finished = True


class SandboxedClaudeExecutor:
    """One sandboxed Claude executor shared by collection and production."""

    provider_name = "claude-cli"

    def __init__(
        self,
        *,
        executable: str,
        repository_root: Path,
        suite_root: Path,
        isolation_root: Path | None = None,
        verified_executable: VerifiedExecutable | None = None,
    ) -> None:
        self._executable = _resolve_executable(executable)
        if verified_executable is None:
            self._verified_executable = VerifiedExecutable(Path(self._executable))
        elif verified_executable.path != Path(self._executable):
            raise CalibrationError(
                "verified Claude executable path differs from request"
            )
        else:
            self._verified_executable = verified_executable
        self._systemd_run = _resolve_executable("systemd-run")
        self._systemctl = _resolve_executable("systemctl")
        self._env = _resolve_executable("env")
        self._unshare = _resolve_executable("unshare")
        self.repository_root = Path(repository_root).resolve(strict=True)
        self.suite_root = Path(suite_root).resolve(strict=True)
        self.isolation_root = (
            Path(isolation_root).resolve(strict=True)
            if isolation_root is not None
            else None
        )
        self.executable_identity = self._verified_executable.identity
        self.executable_sha256 = self._verified_executable.sha256
        self.provider_version = self._capture_version()
        self.systemd_version = self._capture_systemd_version()

    @property
    def command_executable(self) -> str:
        return f"/run/user/{os.getuid()}/skill-eval-comparator-runtime/bin/claude"

    def execute(
        self,
        command: tuple[str, ...],
        timeout_seconds: int,
        stdin_bytes: bytes,
    ) -> TransportExecution:
        if not command or command[0] != self.command_executable:
            raise CalibrationError("shared comparator command executable is invalid")
        if len(stdin_bytes) > MAX_REQUEST_BYTES:
            raise CalibrationError("comparator stdin exceeds the request byte limit")
        self._verified_executable.ensure_source_unchanged()
        runtime_parent = Path(f"/run/user/{os.getuid()}")
        if not runtime_parent.is_dir():
            raise CalibrationError("systemd user runtime directory is unavailable")
        runtime_root = Path(
            tempfile.mkdtemp(prefix="skill-comparator-", dir=runtime_parent)
        )
        runtime_root.chmod(0o700)
        runtime_mount = Path(f"/run/user/{os.getuid()}/skill-eval-comparator-runtime")
        runtime_mount.mkdir(mode=0o700, exist_ok=True)
        runtime_home = runtime_root / "home"
        runtime_config = runtime_home / ".claude"
        runtime_bin = runtime_root / "bin"
        runtime_work = runtime_root / "work"
        for directory in (runtime_home, runtime_config, runtime_bin, runtime_work):
            directory.mkdir(mode=0o700)
        credential = _credential_source()
        runtime_credential = runtime_config / ".credentials.json"
        _copy_private_file(credential, runtime_credential)
        runtime_executable = runtime_bin / "claude"
        runtime_executable.touch(mode=0o500)
        mounted_home = Path(self.command_executable).parents[1] / "home"
        mounted_bin = Path(self.command_executable).parent
        mounted_work = Path(self.command_executable).parents[1] / "work"
        unit_name = f"skill-eval-comparator-{uuid.uuid4().hex}"
        properties = [
            *SANDBOX_ISOLATION_PROPERTIES,
            "MemoryMax=4G",
            "TasksMax=512",
            "LimitNOFILE=4096",
            "LimitFSIZE=512M",
            f"RuntimeMaxSec={timeout_seconds}s",
            "KillMode=control-group",
            "UMask=0077",
            f"ReadWritePaths={Path(self.command_executable).parents[1]}",
            f"BindPaths={runtime_root}:{Path(self.command_executable).parents[1]}",
            "BindReadOnlyPaths="
            f"{self._verified_executable.execution_path}:{self.command_executable}",
        ]
        inaccessible = [
            self.repository_root,
            self.suite_root,
            *_sensitive_host_roots(),
        ]
        if self.isolation_root is not None:
            inaccessible.append(self.isolation_root)
        properties.extend(
            f"InaccessiblePaths={path}" for path in dict.fromkeys(inaccessible)
        )
        wrapped = [
            self._systemd_run,
            "--user",
            "--pipe",
            "--wait",
            "--collect",
            f"--unit={unit_name}",
        ]
        for value in properties:
            wrapped.extend(("-p", value))
        wrapped.extend(
            (
                f"--working-directory={mounted_work}",
                "--",
                self._env,
                "-i",
                f"HOME={mounted_home}",
                f"CLAUDE_CONFIG_DIR={mounted_home / '.claude'}",
                f"XDG_CONFIG_HOME={mounted_home / '.config'}",
                f"XDG_CACHE_HOME={mounted_home / '.cache'}",
                f"PATH={mounted_bin}:/usr/bin:/bin",
                "LANG=C.UTF-8",
                "LC_ALL=C.UTF-8",
                "USER=skill-eval",
                "LOGNAME=skill-eval",
                "SHELL=/bin/bash",
                "TERM=dumb",
                "CI=1",
                self._unshare,
                "--user",
                "--map-current-user",
                "--pid",
                "--fork",
                "--mount-proc",
                "--kill-child",
                *command,
            )
        )
        try:
            evidence = {
                "kind": "shared-systemd-claude-executor",
                "enforced": True,
                "provider_version": self.provider_version,
                "executable_path": self._executable,
                "executable_identity": self.executable_identity,
                "executable_sha256": self.executable_sha256,
                "execution_source": "descriptor-verified-private-copy",
                "execution_descriptor_path": (
                    self._verified_executable.descriptor_path
                ),
                "execution_copy_path": str(self._verified_executable.execution_path),
                "command_executable": self.command_executable,
                "systemd_version": self.systemd_version,
                "properties": properties,
                "environment_mode": "env-i-allowlist",
                "process_namespace": "unshare-user-pid-private-proc",
                "stdin_sha256": hashlib.sha256(stdin_bytes).hexdigest(),
                "remote_service_attestation": "not-cryptographically-attested",
            }
            return self._execute_bounded(
                wrapped,
                cwd=runtime_root,
                stdin_bytes=stdin_bytes,
                timeout_seconds=timeout_seconds,
                unit_name=unit_name,
                evidence=evidence,
            )
        finally:
            shutil.rmtree(runtime_root, ignore_errors=True)

    def _execute_bounded(
        self,
        command: list[str],
        *,
        cwd: Path,
        stdin_bytes: bytes,
        timeout_seconds: int,
        unit_name: str,
        evidence: dict[str, Any],
    ) -> TransportExecution:
        return execute_bounded_transport(
            command,
            cwd=cwd,
            stdin_bytes=stdin_bytes,
            timeout_seconds=timeout_seconds,
            stdout_limit=MAX_RESPONSE_BYTES,
            stderr_limit=MAX_STDERR_BYTES,
            terminate=lambda: self._terminate(unit_name),
            evidence=evidence,
            process_label="Claude comparator",
        )

    def _capture_version(self) -> str:
        completed = subprocess.run(
            [self._verified_executable.descriptor_path, "--version"],
            capture_output=True,
            text=True,
            timeout=15,
            check=False,
            shell=False,
        )
        version = completed.stdout.strip() or completed.stderr.strip()
        if completed.returncode != 0 or not version:
            raise CalibrationError("cannot capture Claude CLI version")
        return version.splitlines()[0]

    def _capture_systemd_version(self) -> str:
        completed = subprocess.run(
            [self._systemd_run, "--version"],
            capture_output=True,
            text=True,
            timeout=10,
            check=False,
            shell=False,
        )
        if completed.returncode != 0 or not completed.stdout.strip():
            raise CalibrationError("cannot capture systemd version")
        return completed.stdout.splitlines()[0]

    def _terminate(self, unit_name: str) -> None:
        try:
            subprocess.run(
                [self._systemctl, "--user", "stop", unit_name],
                capture_output=True,
                timeout=15,
                check=False,
                shell=False,
            )
        except (OSError, subprocess.TimeoutExpired):
            pass


@dataclass(frozen=True)
class RuntimeCertification:
    valid: bool
    evidence_path: Path | None
    evidence_sha256: str | None
    result_sha256: str | None
    actual_models: tuple[str, ...] | None
    executable_sha256: str | None
    systemd_version: str | None
    error: str | None

    def as_json(self) -> dict[str, Any]:
        return {
            "valid": self.valid,
            "evidence_path": (
                str(self.evidence_path) if self.evidence_path is not None else None
            ),
            "evidence_sha256": self.evidence_sha256,
            "result_sha256": self.result_sha256,
            "actual_models": (
                list(self.actual_models) if self.actual_models is not None else None
            ),
            "executable_sha256": self.executable_sha256,
            "systemd_version": self.systemd_version,
            "error": self.error,
        }


@dataclass(frozen=True)
class ComparatorRuntime:
    """Loaded protocol lock plus optional live calibration certification."""

    root: Path
    bundle: Bundle
    release_summary: dict[str, Any]
    certification: RuntimeCertification
    profile_id: str | None = None
    supported_artifact_kinds: tuple[str, ...] = ("workspace_diff",)
    profile_descriptor_sha256: str | None = None
    profile_authority_registry_sha256: str | None = None
    profile_authority_scope: str | None = None
    external_bindings_validated: bool = True
    _profile_context: Any = field(default=None, repr=False, compare=False)

    @classmethod
    def load(
        cls,
        root: Path = CALIBRATION_ROOT,
        *,
        release_name: str = "release.json",
        allow_test_release: bool = False,
        certification_name: str = "evidence/certification.json",
    ) -> "ComparatorRuntime":
        resolved = Path(root).resolve(strict=True)
        bundle = _calibration.load_bundle(
            resolved,
            release_name,
            allow_test_release=allow_test_release,
        )
        _calibration.validate_manifest(
            bundle.manifest, bundle.rubric, bundle.semantic_contract
        )
        summary = _calibration.validate_release(bundle)
        adapter = summary["runtime_adapter"]
        if adapter["id"] != RUNTIME_ADAPTER_ID:
            raise CalibrationError("release does not pin the shared runtime adapter")
        certification = _load_certification(
            bundle,
            resolved,
            certification_name,
            allow_missing=bundle.release["test_release"],
            profile_only=False,
            external_bindings_validated=True,
        )
        return cls(resolved, bundle, summary, certification)

    @classmethod
    def load_builtin_profile(
        cls,
        profile_id: str,
        *,
        external_suite_root: Path | None = None,
        external_suite_manifest: Path | None = None,
        certification_root: Path | None = None,
        use_test_release: bool = False,
        certification_name: str = "evidence/certification.json",
    ) -> "ComparatorRuntime":
        """Resolve and load one code-owned profile into a private snapshot."""

        profile = resolve_builtin_profile(profile_id)
        if profile.authority_binding is None:
            raise CalibrationError("built-in comparator profile omitted authority")
        if (
            not use_test_release
            and profile.authority_binding.authority_scope != "production"
        ):
            raise CalibrationError(
                "built-in comparator profile is not authorized for production"
            )
        return cls._load_profile_resources(
            profile,
            external_suite_root=external_suite_root,
            external_suite_manifest=external_suite_manifest,
            certification_root=certification_root,
            use_test_release=use_test_release,
            certification_name=certification_name,
        )

    @classmethod
    def load_diagnostic_profile(
        cls,
        profile: ComparatorProfileResources,
        *,
        use_test_release: bool = False,
        certification_root: Path | None = None,
        certification_name: str = "evidence/certification.json",
    ) -> "ComparatorRuntime":
        """Load unregistered data while keeping production authority unreachable."""

        if profile.authority_binding is not None:
            raise CalibrationError(
                "registered profiles must load through their code-owned id"
            )
        return cls._load_profile_resources(
            profile,
            external_suite_root=None,
            external_suite_manifest=None,
            certification_root=certification_root,
            use_test_release=use_test_release,
            certification_name=certification_name,
        )

    @classmethod
    def _load_profile_resources(
        cls,
        profile: ComparatorProfileResources,
        *,
        external_suite_root: Path | None,
        external_suite_manifest: Path | None,
        certification_root: Path | None,
        use_test_release: bool,
        certification_name: str,
    ) -> "ComparatorRuntime":
        profile_context = ExitStack()
        try:
            resolved = profile_context.enter_context(profile.materialize()).resolve(
                strict=True
            )
            release_resource = (
                "test_release" if use_test_release else "production_release"
            )
            parsed_resources = {
                name: _calibration.parse_json_object(
                    profile.read_bytes(name).decode("utf-8"),
                    f"profile {profile.descriptor.id} resource {name}",
                )
                for name in (
                    "manifest",
                    "manifest_schema",
                    "rubric",
                    "request_template",
                    "response_schema",
                    "evidence_schema",
                    "semantic_contract",
                    release_resource,
                )
            }
            bundle = Bundle(
                root=resolved,
                manifest=parsed_resources["manifest"],
                manifest_schema=parsed_resources["manifest_schema"],
                rubric=parsed_resources["rubric"],
                request_template=parsed_resources["request_template"],
                response_schema=parsed_resources["response_schema"],
                evidence_schema=parsed_resources["evidence_schema"],
                semantic_contract=parsed_resources["semantic_contract"],
                release=parsed_resources[release_resource],
            )
            if bundle.release.get("test_release") is True and not use_test_release:
                raise CalibrationError(
                    "test release requires explicit use_test_release=True"
                )
            _calibration.validate_manifest(
                bundle.manifest, bundle.rubric, bundle.semantic_contract
            )
            summary = _calibration.validate_profile_release(
                bundle,
                evaluator_root=Path(_calibration.__file__).resolve().parent,
            )
            external_bindings_validated = False
            if (external_suite_root is None) != (external_suite_manifest is None):
                raise CalibrationError(
                    "packaged external bindings require suite root and manifest"
                )
            if external_suite_root is not None:
                _calibration.validate_packaged_release_bindings(
                    bundle,
                    suite_manifest_path=external_suite_manifest,
                    runtime_source_root=Path(__file__).resolve().parent,
                )
                summary = {**summary, "external_bindings_validated": True}
                external_bindings_validated = True
            adapter = summary["runtime_adapter"]
            if adapter["id"] != RUNTIME_ADAPTER_ID:
                raise CalibrationError(
                    "release does not pin the shared runtime adapter"
                )
            certification_base = (
                resolved if certification_root is None else certification_root
            )
            certification = _load_certification(
                bundle,
                certification_base,
                certification_name,
                allow_missing=bundle.release["test_release"],
                profile_only=True,
                external_bindings_validated=external_bindings_validated,
            )
            return cls(
                resolved,
                bundle,
                summary,
                certification,
                profile_id=profile.descriptor.id,
                supported_artifact_kinds=profile.descriptor.supported_artifact_kinds,
                profile_descriptor_sha256=profile.descriptor.descriptor_sha256,
                profile_authority_registry_sha256=(
                    profile.authority_binding.registry_sha256
                    if profile.authority_binding is not None
                    else None
                ),
                profile_authority_scope=(
                    profile.authority_binding.authority_scope
                    if profile.authority_binding is not None
                    else None
                ),
                external_bindings_validated=external_bindings_validated,
                _profile_context=profile_context,
            )
        except BaseException:
            profile_context.close()
            raise

    def close(self) -> None:
        """Release any private profile snapshot owned by this runtime."""

        if self._profile_context is not None:
            self._profile_context.close()

    @property
    def protocol_locks_valid(self) -> bool:
        return self.external_bindings_validated

    @property
    def profile_locks_valid(self) -> bool:
        return True

    @property
    def live_calibration_valid(self) -> bool:
        return self.certification.valid

    @property
    def production_authority_valid(self) -> bool:
        if self.bundle.release["test_release"] or not self.external_bindings_validated:
            return False
        if self.profile_id is None:
            return True
        return (
            self.profile_authority_registry_sha256 is not None
            and self.profile_authority_scope == "production"
        )

    def require_production_authority(self) -> None:
        if (
            self.profile_id is not None
            and self.profile_authority_registry_sha256 is None
        ):
            raise CalibrationError(
                "production holdouts require an authority-bound comparator profile"
            )
        if self.profile_id is not None and self.profile_authority_scope != "production":
            raise CalibrationError(
                "comparator profile is not authorized for production holdouts"
            )
        if self.bundle.release["test_release"]:
            raise CalibrationError(
                "test comparator release cannot access production holdouts"
            )
        if not self.external_bindings_validated:
            raise CalibrationError(
                "comparator runtime external release bindings are not validated"
            )

    def require_live_calibration(self) -> None:
        self.require_production_authority()
        if not self.certification.valid:
            detail = self.certification.error or "certification is absent"
            raise CalibrationError(f"comparator live calibration is invalid: {detail}")

    def require_diagnostic_calibration(self) -> None:
        """Require calibrated comparison without granting release authority."""

        if self.bundle.release["test_release"]:
            raise CalibrationError(
                "test comparator release cannot run a real diagnostic comparator"
            )
        if not self.certification.valid:
            detail = self.certification.error or "certification is absent"
            raise CalibrationError(
                f"comparator diagnostic calibration is invalid: {detail}"
            )

    def invocation_id(self, opaque_context: str, repetition: int, order: str) -> str:
        return _calibration.invocation_id(
            self.bundle.release, opaque_context, repetition, order
        )

    def request_bytes(
        self,
        pair: dict[str, Any],
        repetition: int,
        order: str,
    ) -> bytes:
        for side in ("A", "B"):
            _calibration._validate_patch(pair, side)
        request = _calibration.build_request_bytes(self.bundle, pair, repetition, order)
        if len(request) > MAX_REQUEST_BYTES:
            raise CalibrationError("canonical comparator request exceeds byte limit")
        return request

    def run_transport(
        self,
        *,
        pair: dict[str, Any],
        repetition: int,
        order: str,
        request_bytes: bytes,
        requested_model: str,
        executor: Any,
        spend_ledger: SpendLedger,
    ) -> TransportResult:
        expected_request = self.request_bytes(pair, repetition, order)
        if request_bytes != expected_request:
            raise CalibrationError(
                "comparator request bytes differ from canonical bytes"
            )
        judge = self.bundle.release["judge"]
        if (
            executor.provider_name != judge["provider"]
            or executor.provider_version != judge["provider_version"]
            or requested_model != judge["requested_model"]
        ):
            raise CalibrationError(
                "comparator provider provenance differs from release"
            )
        certified_executable = self.certification.executable_sha256
        if (
            certified_executable is not None
            and getattr(executor, "executable_sha256", None) != certified_executable
        ):
            raise CalibrationError(
                "Claude executable bytes differ from live calibration"
            )
        certified_systemd = self.certification.systemd_version
        if (
            certified_systemd is not None
            and getattr(executor, "systemd_version", None) != certified_systemd
        ):
            raise CalibrationError("systemd version differs from live calibration")
        command = self.command(executor.command_executable, request_bytes)
        stdin_bytes = self.stdin_bytes(request_bytes)
        timeout = self.bundle.release["execution_limits"]["timeout_seconds"]
        per_call = self.bundle.release["execution_limits"]["per_invocation_max_usd"]
        request_sha256 = hashlib.sha256(request_bytes).hexdigest()
        request_invocation_id = self.invocation_id(pair["id"], repetition, order)
        reservation = spend_ledger.reserve(
            per_call,
            request_sha256=request_sha256,
            invocation_id=request_invocation_id,
        )
        reconciled = False
        try:
            execution = executor.execute(command, timeout, stdin_bytes)
            if execution.returncode != 0:
                detail = execution.stderr.decode("utf-8", errors="replace").strip()
                raise CalibrationError(
                    f"Claude comparator exited {execution.returncode}: {detail}"
                )
            try:
                raw_response = execution.stdout.decode("utf-8")
            except UnicodeDecodeError as exc:
                raise CalibrationError(
                    "Claude comparator returned non-UTF-8 response bytes"
                ) from exc
            response, actual_models, cost_usd = (
                _calibration.parse_raw_provider_response(raw_response)
            )
            self._validate_models(actual_models)
            if cost_usd > per_call:
                raise CalibrationError(
                    "comparator call exceeded the release-pinned per-call spend limit"
                )
            reservation.reconcile(cost_usd)
            reconciled = True
        finally:
            if not reconciled:
                reservation.forfeit()
        decision = _calibration.validate_response(self.bundle, pair, response, order)
        if decision["unsupported_performance"]:
            raise CalibrationError("unsupported performance winner is not admissible")
        if decision["unsupported_qualitative"]:
            raise CalibrationError("unsupported qualitative winner is not admissible")
        criteria = decision["criteria"]
        if criteria is not None:
            unsupported = [
                criterion
                for criterion, winner in criteria.items()
                if winner != "tie"
                and not self.bundle.release["criterion_support"][criterion][
                    "production_decisive"
                ]
            ]
            if unsupported:
                raise CalibrationError(
                    "uncalibrated criteria must remain tied: "
                    + ", ".join(sorted(unsupported))
                )
        return TransportResult(
            response=response,
            decision=decision,
            raw_response=raw_response,
            requested_model=requested_model,
            actual_models=tuple(actual_models),
            provider_name=executor.provider_name,
            provider_version=executor.provider_version,
            cost_usd=cost_usd,
            duration_seconds=execution.duration_seconds,
            request_sha256=request_sha256,
            raw_response_sha256=hashlib.sha256(execution.stdout).hexdigest(),
            parsed_response_sha256=canonical_sha256(response),
            command_sha256=canonical_sha256(list(command)),
            stdin_sha256=hashlib.sha256(stdin_bytes).hexdigest(),
            spend_attempt_id=reservation.attempt_id,
            executor=execution.executor,
        )

    def command(self, executable: str, request_bytes: bytes) -> tuple[str, ...]:
        try:
            envelope = json.loads(request_bytes)
        except (UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise CalibrationError("canonical comparator request is invalid") from exc
        if canonical_bytes(envelope) != request_bytes:
            raise CalibrationError("comparator request is not canonical JSON")
        expected_adapter = self.bundle.release["runtime_adapter"]["id"]
        if envelope.get("runtime_adapter") != expected_adapter:
            raise CalibrationError("comparator request runtime adapter is stale")
        schema_arg = canonical_bytes(self.bundle.response_schema).decode("ascii")
        return (
            executable,
            *self.bundle.release["sampling"]["cli_args"],
            "--system-prompt",
            envelope["system_prompt"],
            "--json-schema",
            schema_arg,
        )

    def stdin_bytes(self, request_bytes: bytes) -> bytes:
        envelope = json.loads(request_bytes)
        stdin = canonical_bytes(envelope["user_payload"])
        if len(stdin) > MAX_REQUEST_BYTES:
            raise CalibrationError("comparator stdin exceeds byte limit")
        return stdin

    def _validate_models(self, actual_models: list[str]) -> None:
        judge = self.bundle.release["judge"]
        primary = judge["required_primary_model_prefix"]
        auxiliaries = tuple(judge["allowed_auxiliary_model_prefixes"])
        if not any(model.startswith(primary) for model in actual_models):
            raise CalibrationError("comparator response omitted the required model")
        if any(
            not model.startswith((primary, *auxiliaries)) for model in actual_models
        ):
            raise CalibrationError("comparator response used an unapproved model")
        certified = self.certification.actual_models
        if certified is not None and tuple(actual_models) != certified:
            raise CalibrationError(
                "comparator actual model set differs from live calibration"
            )


def runtime_pair(
    *,
    opaque_id: str,
    task: str,
    contract: dict[str, Any],
    base_files: dict[str, str],
    diff_a: str,
    diff_b: str,
) -> dict[str, Any]:
    """Build the calibration-compatible pair used by production."""

    if not opaque_id or not task:
        raise CalibrationError("runtime comparator pair needs opaque id and task")
    normalized_files: dict[str, str] = {}
    base_bytes = 0
    for raw_path, content in sorted(base_files.items()):
        path = PurePosixPath(raw_path)
        if (
            path.is_absolute()
            or path == PurePosixPath(".")
            or ".." in path.parts
            or not isinstance(content, str)
        ):
            raise CalibrationError("runtime comparator base file is invalid")
        base_bytes += len(content.encode("utf-8"))
        if base_bytes > MAX_BASE_BYTES:
            raise CalibrationError("runtime comparator base files exceed byte limit")
        normalized_files[path.as_posix()] = content
    for side, diff in (("A", diff_a), ("B", diff_b)):
        if not isinstance(diff, str) or len(diff.encode("utf-8")) > MAX_DIFF_BYTES:
            raise CalibrationError(
                f"runtime comparator candidate {side} diff exceeds byte limit"
            )
    return {
        "id": opaque_id,
        "task": task,
        "contract": contract,
        "base_files": normalized_files,
        "diff_a": diff_a,
        "diff_b": diff_b,
    }


def write_certification(
    runtime: ComparatorRuntime,
    evidence_path: Path,
    destination: Path,
    *,
    persistence_root: Path | None = None,
) -> dict[str, Any]:
    """Validate live evidence and write a non-self-referential certification."""

    storage_root = (
        runtime.root
        if persistence_root is None
        else Path(os.path.abspath(persistence_root))
    )
    if storage_root.resolve(strict=True) != storage_root or not storage_root.is_dir():
        raise CalibrationError("certification persistence root is invalid")
    evidence_file = Path(os.path.abspath(evidence_path))
    if evidence_file.resolve(strict=True) != evidence_file:
        raise CalibrationError("certification evidence path traverses a symlink")
    if not evidence_file.is_relative_to(storage_root):
        raise CalibrationError(
            "certification evidence must remain inside its persistence root"
        )
    evidence, _evidence_bytes, evidence_sha256 = load_private_json_capture(
        evidence_file
    )
    result = _calibration.evaluate_evidence(
        runtime.bundle,
        evidence,
        profile_only=getattr(runtime, "profile_id", None) is not None,
        evaluator_root=Path(_calibration.__file__).resolve().parent,
        external_bindings_validated=getattr(
            runtime, "external_bindings_validated", True
        ),
    )
    if not result["passed"]:
        raise CalibrationError("comparator evidence did not pass every release gate")
    model_sets = result["actual_model_sets"]
    if len(model_sets) != 1:
        raise CalibrationError("calibration did not prove one stable model set")
    executable_hashes = result["executable_sha256s"]
    if len(executable_hashes) != 1:
        raise CalibrationError("calibration did not prove one stable executable")
    systemd_versions = result["systemd_versions"]
    if len(systemd_versions) != 1:
        raise CalibrationError("calibration did not prove one stable systemd version")
    payload = {
        "schema_version": CERTIFICATION_SCHEMA_VERSION,
        "release_sha256": runtime.release_summary["release_sha256"],
        "runtime_adapter_id": RUNTIME_ADAPTER_ID,
        "evidence_path": os.path.relpath(evidence_file, storage_root),
        "evidence_sha256": evidence_sha256,
        "result_sha256": canonical_sha256(result),
        "actual_models": model_sets[0],
        "executable_sha256": executable_hashes[0],
        "systemd_version": systemd_versions[0],
        "passed": True,
    }
    target = Path(os.path.abspath(destination))
    resolved_target_parent = target.parent.resolve(strict=False)
    if (
        not target.parent.is_relative_to(storage_root)
        or not resolved_target_parent.is_relative_to(storage_root)
        or resolved_target_parent != target.parent
    ):
        raise CalibrationError("comparator certification destination escapes its root")
    target.parent.mkdir(parents=True, mode=0o700, exist_ok=True)
    target_parent = target.parent.resolve(strict=True)
    if target_parent != target.parent or not target_parent.is_relative_to(storage_root):
        raise CalibrationError("comparator certification destination escapes its root")
    atomic_write_private_json(target, payload)
    return payload


def _load_certification(
    bundle: Bundle,
    root: Path,
    certification_name: str,
    *,
    allow_missing: bool,
    profile_only: bool = False,
    external_bindings_validated: bool = True,
) -> RuntimeCertification:
    logical_certification_path = Path(os.path.abspath(root / certification_name))
    certification_path = logical_certification_path.resolve()
    if not certification_path.is_relative_to(root):
        raise CalibrationError("comparator certification path escapes its root")
    if not certification_path.exists():
        if allow_missing:
            return RuntimeCertification(
                False, None, None, None, None, None, None, "not supplied"
            )
        return RuntimeCertification(
            False, None, None, None, None, None, None, "not supplied"
        )
    try:
        if logical_certification_path != certification_path:
            raise CalibrationError("comparator certification path traverses a symlink")
        certification, _certification_bytes, _certification_sha256 = (
            load_private_json_capture(certification_path)
        )
        expected_fields = {
            "schema_version",
            "release_sha256",
            "runtime_adapter_id",
            "evidence_path",
            "evidence_sha256",
            "result_sha256",
            "actual_models",
            "executable_sha256",
            "systemd_version",
            "passed",
        }
        if set(certification) != expected_fields:
            raise CalibrationError("comparator certification fields are invalid")
        if (
            certification["schema_version"] != CERTIFICATION_SCHEMA_VERSION
            or certification["passed"] is not True
            or certification["runtime_adapter_id"] != RUNTIME_ADAPTER_ID
            or certification["release_sha256"] != canonical_sha256(bundle.release)
        ):
            raise CalibrationError("comparator certification lock is stale")
        relative = PurePosixPath(certification["evidence_path"])
        if relative.is_absolute() or ".." in relative.parts:
            raise CalibrationError("comparator evidence path is invalid")
        logical_evidence_path = Path(os.path.abspath(root / relative))
        evidence_path = logical_evidence_path.resolve(strict=True)
        if not evidence_path.is_relative_to(root):
            raise CalibrationError("comparator evidence path escapes its root")
        if logical_evidence_path != evidence_path:
            raise CalibrationError("comparator evidence path traverses a symlink")
        evidence, _evidence_bytes, evidence_sha256 = load_private_json_capture(
            evidence_path
        )
        if evidence_sha256 != certification["evidence_sha256"]:
            raise CalibrationError("comparator evidence digest is stale")
        result = _calibration.evaluate_evidence(
            bundle,
            evidence,
            profile_only=profile_only,
            evaluator_root=Path(_calibration.__file__).resolve().parent,
            external_bindings_validated=external_bindings_validated,
        )
        result_sha256 = canonical_sha256(result)
        if not result["passed"] or result_sha256 != certification["result_sha256"]:
            raise CalibrationError("comparator certification result is invalid")
        model_sets = result["actual_model_sets"]
        if (
            len(model_sets) != 1
            or certification["actual_models"] != model_sets[0]
            or not all(
                isinstance(model, str) and model
                for model in certification["actual_models"]
            )
        ):
            raise CalibrationError("comparator certification model set is invalid")
        executable_hashes = result["executable_sha256s"]
        if (
            len(executable_hashes) != 1
            or certification["executable_sha256"] != executable_hashes[0]
            or not isinstance(certification["executable_sha256"], str)
            or len(certification["executable_sha256"]) != 64
        ):
            raise CalibrationError("comparator certification executable is invalid")
        systemd_versions = result["systemd_versions"]
        if (
            len(systemd_versions) != 1
            or certification["systemd_version"] != systemd_versions[0]
            or not isinstance(certification["systemd_version"], str)
            or not certification["systemd_version"]
        ):
            raise CalibrationError(
                "comparator certification systemd version is invalid"
            )
        return RuntimeCertification(
            True,
            evidence_path,
            evidence_sha256,
            result_sha256,
            tuple(model_sets[0]),
            certification["executable_sha256"],
            certification["systemd_version"],
            None,
        )
    except (OSError, TypeError, ValueError, CalibrationError) as exc:
        return RuntimeCertification(False, None, None, None, None, None, None, str(exc))


def _validate_private_file(
    metadata: os.stat_result,
    location: str,
    *,
    expected_identity: tuple[int, ...] | None = None,
) -> tuple[int, ...]:
    identity = (
        metadata.st_dev,
        metadata.st_ino,
        metadata.st_size,
        metadata.st_mtime_ns,
        metadata.st_ctime_ns,
        metadata.st_uid,
        stat.S_IMODE(metadata.st_mode),
        metadata.st_nlink,
    )
    if (
        not stat.S_ISREG(metadata.st_mode)
        or metadata.st_uid != os.getuid()
        or metadata.st_nlink != 1
        or stat.S_IMODE(metadata.st_mode) != 0o600
        or (expected_identity is not None and identity != expected_identity)
    ):
        raise CalibrationError(f"{location} is not a stable owner-only regular file")
    return identity


def _safe_output_path(path: Path) -> Path:
    target = Path(os.path.abspath(path))
    resolved_parent_before = target.parent.resolve(strict=False)
    if resolved_parent_before != target.parent:
        raise CalibrationError("private artifact parent must not traverse a symlink")
    target.parent.mkdir(parents=True, mode=0o700, exist_ok=True)
    try:
        resolved_parent = target.parent.resolve(strict=True)
        parent_metadata = target.parent.lstat()
    except OSError as exc:
        raise CalibrationError(f"private artifact parent is unsafe: {exc}") from exc
    if resolved_parent != target.parent or not stat.S_ISDIR(parent_metadata.st_mode):
        raise CalibrationError("private artifact parent must not traverse a symlink")
    return target


def _fsync_directory(path: Path) -> None:
    flags = os.O_RDONLY | os.O_CLOEXEC
    if hasattr(os, "O_DIRECTORY"):
        flags |= os.O_DIRECTORY
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    descriptor = os.open(path, flags)
    try:
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def atomic_write_private_json(path: Path, value: dict[str, Any]) -> None:
    """Atomically replace one owner-only JSON artifact without following links."""

    target = _safe_output_path(path)
    prior_identity: tuple[int, ...] | None = None
    try:
        prior = target.lstat()
    except FileNotFoundError:
        pass
    except OSError as exc:
        raise CalibrationError(
            f"cannot inspect private artifact target: {exc}"
        ) from exc
    else:
        prior_identity = _validate_private_file(prior, str(target))
    temporary = target.with_name(f".{target.name}.{uuid.uuid4().hex}.tmp")
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_CLOEXEC
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    descriptor = -1
    try:
        descriptor = os.open(temporary, flags, 0o600)
        try:
            encoded = (
                json.dumps(value, ensure_ascii=True, indent=2, sort_keys=True) + "\n"
            ).encode("ascii")
            view = memoryview(encoded)
            while view:
                written = os.write(descriptor, view)
                if written <= 0:
                    raise CalibrationError("private artifact write made no progress")
                view = view[written:]
            os.fchmod(descriptor, 0o600)
            os.fsync(descriptor)
            _validate_private_file(os.fstat(descriptor), str(temporary))
        finally:
            os.close(descriptor)
            descriptor = -1
        try:
            current = target.lstat()
        except FileNotFoundError:
            if prior_identity is not None:
                raise CalibrationError(
                    "private artifact target disappeared before replace"
                )
        else:
            if prior_identity is None:
                raise CalibrationError(
                    "private artifact target appeared before replace"
                )
            _validate_private_file(
                current,
                str(target),
                expected_identity=prior_identity,
            )
        os.replace(temporary, target)
        _validate_private_file(target.lstat(), str(target))
        _fsync_directory(target.parent)
    finally:
        if descriptor >= 0:
            os.close(descriptor)
        try:
            temporary.unlink()
        except FileNotFoundError:
            pass


def load_private_json(
    path: Path, *, maximum_bytes: int = 64 * 1024 * 1024
) -> dict[str, Any]:
    value, _raw, _sha256 = load_private_json_capture(path, maximum_bytes=maximum_bytes)
    return value


def load_private_json_capture(
    path: Path, *, maximum_bytes: int = 64 * 1024 * 1024
) -> tuple[dict[str, Any], bytes, str]:
    """Load one owner-only JSON artifact through a no-follow descriptor."""

    target = _safe_output_path(path)
    try:
        metadata = target.lstat()
    except OSError as exc:
        raise CalibrationError(f"cannot inspect private JSON artifact: {exc}") from exc
    identity = _validate_private_file(metadata, str(target))
    if metadata.st_size > maximum_bytes:
        raise CalibrationError("private JSON artifact exceeds byte limit")
    flags = os.O_RDONLY | os.O_CLOEXEC
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    descriptor = os.open(target, flags)
    try:
        opened = os.fstat(descriptor)
        _validate_private_file(opened, str(target), expected_identity=identity)
        chunks: list[bytes] = []
        first_digest = hashlib.sha256()
        remaining = opened.st_size
        while remaining:
            chunk = os.read(descriptor, min(1024 * 1024, remaining))
            if not chunk:
                raise CalibrationError("private JSON artifact was truncated")
            chunks.append(chunk)
            first_digest.update(chunk)
            remaining -= len(chunk)
        if os.read(descriptor, 1):
            raise CalibrationError("private JSON artifact grew while reading")
        _validate_private_file(
            os.fstat(descriptor), str(target), expected_identity=identity
        )
        os.lseek(descriptor, 0, os.SEEK_SET)
        second_digest = hashlib.sha256()
        remaining = opened.st_size
        while remaining:
            chunk = os.read(descriptor, min(1024 * 1024, remaining))
            if not chunk:
                raise CalibrationError("private JSON artifact changed while reading")
            second_digest.update(chunk)
            remaining -= len(chunk)
        if os.read(descriptor, 1) or second_digest.digest() != first_digest.digest():
            raise CalibrationError(f"{target} is not a stable owner-only regular file")
        _validate_private_file(
            os.fstat(descriptor), str(target), expected_identity=identity
        )
    finally:
        os.close(descriptor)
    raw_bytes = b"".join(chunks)
    try:
        raw = raw_bytes.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise CalibrationError("private JSON artifact is not UTF-8") from exc
    return (
        _calibration.parse_json_object(raw, str(target)),
        raw_bytes,
        first_digest.hexdigest(),
    )


def _finite_nonnegative(value: Any, location: str) -> float:
    if (
        isinstance(value, bool)
        or not isinstance(value, (int, float))
        or not math.isfinite(float(value))
        or float(value) < 0
    ):
        raise CalibrationError(f"{location} must be finite and non-negative")
    return float(value)


def _open_regular_file(path: Path) -> int:
    flags = os.O_RDONLY | os.O_CLOEXEC
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    try:
        descriptor = os.open(path, flags)
    except OSError as exc:
        raise CalibrationError(f"cannot attest executable {path}: {exc}") from exc
    metadata = os.fstat(descriptor)
    if not stat.S_ISREG(metadata.st_mode):
        os.close(descriptor)
        raise CalibrationError("Claude executable is not a regular file")
    return descriptor


def _file_identity(metadata: os.stat_result) -> dict[str, int]:
    return {
        "device": metadata.st_dev,
        "inode": metadata.st_ino,
        "size": metadata.st_size,
        "mode": metadata.st_mode,
        "mtime_ns": metadata.st_mtime_ns,
        "ctime_ns": metadata.st_ctime_ns,
    }


def _descriptor_sha256(descriptor: int, size: int) -> str:
    digest = hashlib.sha256()
    offset = 0
    while offset < size:
        chunk = os.pread(descriptor, min(1024 * 1024, size - offset), offset)
        if not chunk:
            raise CalibrationError("Claude executable changed or truncated during read")
        digest.update(chunk)
        offset += len(chunk)
    if os.pread(descriptor, 1, size):
        raise CalibrationError("Claude executable grew during read")
    return digest.hexdigest()


def _open_verified_executable(path: Path) -> tuple[int, dict[str, int], str]:
    descriptor = _open_regular_file(path)
    try:
        metadata = os.fstat(descriptor)
        if metadata.st_mode & 0o111 == 0:
            raise CalibrationError("Claude executable lacks execute permission")
        identity = _file_identity(metadata)
        digest = _descriptor_sha256(descriptor, metadata.st_size)
        if _file_identity(os.fstat(descriptor)) != identity:
            raise CalibrationError(
                "Claude executable changed during initial attestation"
            )
        return descriptor, identity, digest
    except BaseException:
        os.close(descriptor)
        raise


def _private_executable_copy(
    source_descriptor: int,
    source_identity: dict[str, int],
    source_sha256: str,
) -> tuple[int, Path, Path, dict[str, int]]:
    runtime_parent = Path(f"/run/user/{os.getuid()}")
    if not runtime_parent.is_dir():
        raise CalibrationError("systemd user runtime directory is unavailable")
    copy_root = Path(tempfile.mkdtemp(prefix="skill-executable-", dir=runtime_parent))
    copy_root.chmod(0o700)
    copy_path = copy_root / "claude"
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_CLOEXEC
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    writable = -1
    readonly = -1
    try:
        writable = os.open(copy_path, flags, 0o500)
        size = source_identity["size"]
        digest = hashlib.sha256()
        offset = 0
        while offset < size:
            chunk = os.pread(
                source_descriptor,
                min(1024 * 1024, size - offset),
                offset,
            )
            if not chunk:
                raise CalibrationError("Claude executable copy was truncated")
            digest.update(chunk)
            view = memoryview(chunk)
            write_offset = offset
            while view:
                written = os.pwrite(writable, view, write_offset)
                if written <= 0:
                    raise CalibrationError("Claude executable copy made no progress")
                view = view[written:]
                write_offset += written
            offset += len(chunk)
        if (
            digest.hexdigest() != source_sha256
            or _file_identity(os.fstat(source_descriptor)) != source_identity
        ):
            raise CalibrationError(
                "Claude executable changed while making private copy"
            )
        os.ftruncate(writable, size)
        os.fchmod(writable, 0o500)
        os.fsync(writable)
        os.close(writable)
        writable = -1
        readonly = _open_regular_file(copy_path)
        copy_identity = _file_identity(os.fstat(readonly))
        if (
            _descriptor_sha256(readonly, size) != source_sha256
            or copy_identity["size"] != size
            or copy_identity["mode"] & 0o777 != 0o500
        ):
            raise CalibrationError("private Claude executable copy failed verification")
        copy_root.chmod(0o500)
        return readonly, copy_root, copy_path, copy_identity
    except BaseException:
        if writable >= 0:
            os.close(writable)
        if readonly >= 0:
            os.close(readonly)
        copy_root.chmod(0o700)
        shutil.rmtree(copy_root, ignore_errors=True)
        raise


def _resolve_executable(value: str) -> str:
    candidate = Path(value)
    if candidate.parent == Path("."):
        resolved = shutil.which(value)
        if resolved is None:
            raise CalibrationError(f"required executable is unavailable: {value}")
        candidate = Path(resolved)
    resolved_path = candidate.expanduser().resolve(strict=True)
    if not resolved_path.is_file() or not os.access(resolved_path, os.X_OK):
        raise CalibrationError(f"required executable is not executable: {value}")
    return str(resolved_path)


def _credential_source() -> Path:
    configured = os.environ.get("CLAUDE_CONFIG_DIR")
    config_root = (
        Path(configured).expanduser().resolve(strict=True)
        if configured
        else (Path.home() / ".claude").resolve(strict=True)
    )
    logical = config_root / ".credentials.json"
    resolved = logical.resolve(strict=True)
    if (
        logical.is_symlink()
        or not resolved.is_file()
        or not resolved.is_relative_to(config_root)
        or resolved.stat().st_size > 1024 * 1024
    ):
        raise CalibrationError("Claude credential source is unsafe")
    return resolved


def _copy_private_file(source: Path, destination: Path) -> None:
    flags = os.O_RDONLY | os.O_CLOEXEC
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    descriptor = os.open(source, flags)
    try:
        metadata = os.fstat(descriptor)
        target = os.open(
            destination,
            os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_CLOEXEC,
            0o600,
        )
        try:
            offset = 0
            while offset < metadata.st_size:
                chunk = os.pread(
                    descriptor, min(1024 * 1024, metadata.st_size - offset), offset
                )
                if not chunk:
                    raise CalibrationError("credential copy was truncated")
                view = memoryview(chunk)
                while view:
                    written = os.write(target, view)
                    view = view[written:]
                offset += len(chunk)
            os.fchmod(target, 0o600)
            os.fsync(target)
        finally:
            os.close(target)
    finally:
        os.close(descriptor)


def _sensitive_host_roots() -> tuple[Path, ...]:
    home = Path.home().resolve()
    roots = [home]
    configured = os.environ.get("CLAUDE_CONFIG_DIR")
    if configured:
        root = Path(configured).expanduser().resolve(strict=True)
        roots.extend((root, root.parent))
    return tuple(dict.fromkeys(roots))


def _systemd_client_environment() -> dict[str, str]:
    allowed = {
        "DBUS_SESSION_BUS_ADDRESS",
        "LANG",
        "LC_ALL",
        "PATH",
        "XDG_RUNTIME_DIR",
    }
    return {key: value for key, value in os.environ.items() if key in allowed}
