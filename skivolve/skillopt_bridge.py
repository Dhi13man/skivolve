"""Strict contracts and Git helpers for the optional SkillOpt sidecar."""

from __future__ import annotations

import hashlib
import json
import os
import signal
import shutil
import stat
import subprocess
import threading
import time
from dataclasses import dataclass
from pathlib import Path, PurePosixPath
from typing import Any, Iterable

import rfc8785

from .manifest import CaseSpec, SuiteSpec, load_suite


SKILLOPT_REPOSITORY = "https://github.com/microsoft/SkillOpt.git"
SKILLOPT_COMMIT = "bdfdc30a8e17309c06cdbe8449f01bdecc120203"
PLAN_SCHEMA_VERSION = 1
MAX_CANDIDATE_BYTES = 64 * 1024
MAX_COMMAND_OUTPUT_BYTES = 4 * 1024 * 1024
MAX_COMMAND_INPUT_BYTES = 4 * 1024 * 1024
MAX_ENVIRONMENT_FILES = 250_000
MAX_ENVIRONMENT_BYTES = 2 * 1024 * 1024 * 1024
MAX_EVALUATION_INPUT_ENTRIES = 100_000
MAX_EVALUATION_INPUT_BYTES = 1024 * 1024 * 1024
MAX_TREE_DEPTH = 64
OPTIMIZER_ATTEMPTS_PER_CALL = 3
OPTIMIZER_CALL_TIMEOUT_SECONDS = 900
COMPARISON_ID = "skillopt-vs-seed"
FITNESS_COMPARISON_ID = "skillopt-fitness"
_CANDIDATE_COMMIT_DATE = "2000-01-01T00:00:00+00:00"
_GENERATED_CACHE_DIRECTORIES = frozenset(
    {"__pycache__", ".mypy_cache", ".pytest_cache", ".ruff_cache"}
)
_GENERATED_CACHE_SUFFIXES = frozenset({".pyc", ".pyo"})


class SkillOptBridgeError(RuntimeError):
    """Raised when the optimization boundary cannot be trusted."""


@dataclass(frozen=True)
class PilotPlan:
    """Fully resolved public-case optimization plan."""

    suite_path: Path
    repository_root: Path
    skill: str
    bundle_source: PurePosixPath
    skill_path: PurePosixPath
    baseline_commit: str
    train_case_ids: tuple[str, ...]
    selection_case_ids: tuple[str, ...]
    validation_case_ids: tuple[str, ...]
    seed: int
    optimizer_model: str
    optimizer_executable: Path
    optimizer_sandbox: Path
    output_dir: Path
    skillopt_source: Path
    skillopt_python: Path
    skillopt_environment: Path
    skivolve_python: Path
    timeout_seconds: int
    evaluation_inputs_sha256: str = "0" * 64
    skivolve_package_sha256: str = "0" * 64
    skillopt_python_sha256: str = "0" * 64
    skillopt_environment_sha256: str = "0" * 64
    skivolve_python_sha256: str = "0" * 64
    optimizer_executable_sha256: str = "0" * 64
    optimizer_sandbox_sha256: str = "0" * 64

    @property
    def planned_generator_calls(self) -> int:
        inner_case_evaluations = (
            len(self.selection_case_ids)
            + len(self.train_case_ids)
            + len(self.selection_case_ids)
        )
        final_case_evaluations = len(self.validation_case_ids)
        return 6 * (inner_case_evaluations + final_case_evaluations)

    @property
    def planned_optimizer_invocations(self) -> int:
        logical_calls = 1 if len(self.train_case_ids) == 1 else 4
        return OPTIMIZER_ATTEMPTS_PER_CALL * logical_calls

    @property
    def planned_generator_optimizer_invocation_ceiling(self) -> int:
        return self.planned_generator_calls + self.planned_optimizer_invocations

    def as_json(self) -> dict[str, Any]:
        return {
            "schema_version": PLAN_SCHEMA_VERSION,
            "suite_path": str(self.suite_path),
            "repository_root": str(self.repository_root),
            "skill": self.skill,
            "bundle_source": self.bundle_source.as_posix(),
            "skill_path": self.skill_path.as_posix(),
            "baseline_commit": self.baseline_commit,
            "train_case_ids": list(self.train_case_ids),
            "selection_case_ids": list(self.selection_case_ids),
            "validation_case_ids": list(self.validation_case_ids),
            "seed": self.seed,
            "optimizer": {
                "backend": "codex_exec",
                "model": self.optimizer_model,
                "executable": str(self.optimizer_executable),
                "sandbox_executable": str(self.optimizer_sandbox),
                "num_epochs": 1,
                "batch_size": len(self.train_case_ids),
                "accumulation": 1,
                "edit_budget": 2,
                "max_invocations": self.planned_optimizer_invocations,
                "per_invocation_timeout_seconds": OPTIMIZER_CALL_TIMEOUT_SECONDS,
                "use_gate": True,
                "gate_metric": "hard",
                "use_semantic_density": False,
                "use_slow_update": False,
                "use_meta_skill": False,
                "eval_test": False,
            },
            "output_dir": str(self.output_dir),
            "skillopt": {
                "repository": SKILLOPT_REPOSITORY,
                "commit": SKILLOPT_COMMIT,
                "source": str(self.skillopt_source),
                "python": str(self.skillopt_python),
                "environment": str(self.skillopt_environment),
            },
            "skivolve_python": str(self.skivolve_python),
            "timeout_seconds": self.timeout_seconds,
            "planned_generator_calls": self.planned_generator_calls,
            "planned_optimizer_invocations": self.planned_optimizer_invocations,
            "planned_generator_optimizer_invocation_ceiling": self.planned_generator_optimizer_invocation_ceiling,
            "bindings": {
                "evaluation_inputs_sha256": self.evaluation_inputs_sha256,
                "skivolve_package_sha256": self.skivolve_package_sha256,
                "skillopt_python_sha256": self.skillopt_python_sha256,
                "skillopt_environment_sha256": self.skillopt_environment_sha256,
                "skivolve_python_sha256": self.skivolve_python_sha256,
                "optimizer_executable_sha256": self.optimizer_executable_sha256,
                "optimizer_sandbox_sha256": self.optimizer_sandbox_sha256,
            },
            "holdout_used": False,
            "automatic_adoption": False,
        }


def canonical_bytes(value: Any) -> bytes:
    """Return RFC 8785 bytes for a provenance record."""

    try:
        return rfc8785.dumps(value)
    except (rfc8785.CanonicalizationError, RecursionError) as exc:
        raise SkillOptBridgeError(
            f"cannot canonicalize optimization evidence: {exc}"
        ) from exc


def sha256_bytes(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(64 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _skivolve_package_sha256() -> str:
    root = Path(__file__).resolve(strict=True).parent
    records: list[dict[str, Any]] = []
    for path in sorted(root.rglob("*"), key=lambda item: item.as_posix()):
        if "__pycache__" in path.parts or path.suffix in {".pyc", ".pyo"}:
            continue
        metadata = path.lstat()
        if stat.S_ISLNK(metadata.st_mode):
            raise SkillOptBridgeError(f"Skivolve package file is a symlink: {path}")
        if stat.S_ISREG(metadata.st_mode):
            records.append(
                {
                    "path": path.relative_to(root).as_posix(),
                    "sha256": sha256_file(path),
                    "bytes": metadata.st_size,
                    "executable": bool(metadata.st_mode & 0o111),
                }
            )
    return sha256_bytes(canonical_bytes(records))


def _environment_sha256(root: Path) -> str:
    """Bind an isolated Python environment without generated cache churn."""

    records: list[dict[str, Any]] = []
    total_bytes = 0
    pending = [(root, 0)]
    entry_count = 0
    while pending:
        directory, depth = pending.pop()
        if depth >= MAX_TREE_DEPTH:
            raise SkillOptBridgeError(
                f"SkillOpt environment exceeds {MAX_TREE_DEPTH} directory levels"
            )
        children: list[tuple[Path, os.stat_result]] = []
        try:
            with os.scandir(directory) as entries:
                for entry in entries:
                    entry_count += 1
                    if entry_count > MAX_ENVIRONMENT_FILES:
                        raise SkillOptBridgeError(
                            "SkillOpt environment exceeds "
                            f"{MAX_ENVIRONMENT_FILES} entries"
                        )
                    children.append(
                        (Path(entry.path), entry.stat(follow_symlinks=False))
                    )
        except OSError as exc:
            raise SkillOptBridgeError(
                f"cannot traverse SkillOpt environment: {exc}"
            ) from exc

        directories: list[Path] = []
        for path, metadata in sorted(children, key=lambda item: item[0].name):
            relative = path.relative_to(root)
            if stat.S_ISDIR(metadata.st_mode):
                if path.name not in _GENERATED_CACHE_DIRECTORIES:
                    directories.append(path)
                continue
            if (
                any(part in _GENERATED_CACHE_DIRECTORIES for part in relative.parts)
                or path.suffix in _GENERATED_CACHE_SUFFIXES
            ):
                continue
            if stat.S_ISLNK(metadata.st_mode):
                try:
                    target = path.resolve(strict=True)
                    target_metadata = target.stat()
                except OSError as exc:
                    raise SkillOptBridgeError(
                        f"cannot resolve SkillOpt environment symlink {path}: {exc}"
                    ) from exc
                target_inside_environment = target.is_relative_to(root)
                target_name = (
                    target.relative_to(root).as_posix()
                    if target_inside_environment
                    else str(target)
                )
                record: dict[str, Any] = {
                    "path": relative.as_posix(),
                    "symlink": os.readlink(path),
                    "target": target_name,
                    "target_scope": (
                        "environment" if target_inside_environment else "external"
                    ),
                }
                if stat.S_ISREG(target_metadata.st_mode):
                    total_bytes += target_metadata.st_size
                    if total_bytes > MAX_ENVIRONMENT_BYTES:
                        raise SkillOptBridgeError(
                            "SkillOpt environment exceeds "
                            f"{MAX_ENVIRONMENT_BYTES} bytes"
                        )
                    record.update(
                        {
                            "target_sha256": sha256_file(target),
                            "target_bytes": target_metadata.st_size,
                            "target_executable": bool(target_metadata.st_mode & 0o111),
                        }
                    )
                elif (
                    stat.S_ISDIR(target_metadata.st_mode) and target_inside_environment
                ):
                    record["target_type"] = "directory"
                else:
                    raise SkillOptBridgeError(
                        f"SkillOpt environment symlink has an unsafe target: {path}"
                    )
                records.append(record)
                continue
            if not stat.S_ISREG(metadata.st_mode):
                raise SkillOptBridgeError(
                    f"SkillOpt environment contains a special file: {path}"
                )
            total_bytes += metadata.st_size
            if total_bytes > MAX_ENVIRONMENT_BYTES:
                raise SkillOptBridgeError(
                    f"SkillOpt environment exceeds {MAX_ENVIRONMENT_BYTES} bytes"
                )
            records.append(
                {
                    "path": relative.as_posix(),
                    "sha256": sha256_file(path),
                    "bytes": metadata.st_size,
                    "executable": bool(metadata.st_mode & 0o111),
                }
            )
        pending.extend((path, depth + 1) for path in reversed(directories))
    records.sort(key=lambda record: str(record["path"]))
    return sha256_bytes(canonical_bytes(records))


def _skillopt_environment(python: Path) -> Path:
    completed = run_command(
        (
            python,
            "-I",
            "-c",
            "import json, sys; print(json.dumps(sys.prefix))",
        )
    )
    try:
        raw_prefix = json.loads(completed.stdout)
    except json.JSONDecodeError as exc:
        raise SkillOptBridgeError(
            "SkillOpt Python returned an invalid sys.prefix"
        ) from exc
    if not isinstance(raw_prefix, str) or not raw_prefix:
        raise SkillOptBridgeError("SkillOpt Python returned an invalid sys.prefix")
    supplied = Path(os.path.abspath(Path(raw_prefix).expanduser()))
    if supplied.is_symlink():
        raise SkillOptBridgeError("SkillOpt environment root must not be a symlink")
    try:
        environment = supplied.resolve(strict=True)
    except OSError as exc:
        raise SkillOptBridgeError(
            f"cannot resolve SkillOpt environment: {exc}"
        ) from exc
    if not environment.is_dir() or not Path(os.path.abspath(python)).is_relative_to(
        environment
    ):
        raise SkillOptBridgeError(
            "SkillOpt Python must be inside its isolated environment"
        )
    return environment


def private_write_json(path: Path, value: Any) -> None:
    """Create one private JSON artifact without following a final symlink."""

    data = json.dumps(value, indent=2, sort_keys=True, ensure_ascii=False) + "\n"
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0)
    descriptor = os.open(path, flags, 0o600)
    try:
        _write_all(descriptor, data.encode("utf-8"))
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def private_write_bytes(path: Path, value: bytes) -> None:
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0)
    descriptor = os.open(path, flags, 0o600)
    try:
        _write_all(descriptor, value)
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def _write_all(descriptor: int, value: bytes) -> None:
    remaining = memoryview(value)
    while remaining:
        written = os.write(descriptor, remaining)
        if written <= 0:
            raise SkillOptBridgeError("private artifact write made no progress")
        remaining = remaining[written:]


def load_strict_json(path: Path, *, maximum_bytes: int = 1024 * 1024) -> Any:
    """Read bounded JSON while rejecting duplicate keys and non-finite numbers."""

    metadata = path.lstat()
    if stat.S_ISLNK(metadata.st_mode) or not stat.S_ISREG(metadata.st_mode):
        raise SkillOptBridgeError(
            f"JSON input must be a regular non-symlink file: {path}"
        )
    if metadata.st_size > maximum_bytes:
        raise SkillOptBridgeError(f"JSON input exceeds {maximum_bytes} bytes: {path}")

    def unique(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
        result: dict[str, Any] = {}
        for key, value in pairs:
            if key in result:
                raise SkillOptBridgeError(f"duplicate JSON key: {key}")
            result[key] = value
        return result

    def reject_constant(value: str) -> None:
        raise SkillOptBridgeError(f"non-finite JSON number is not allowed: {value}")

    try:
        return json.loads(
            path.read_text(encoding="utf-8"),
            object_pairs_hook=unique,
            parse_constant=reject_constant,
        )
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise SkillOptBridgeError(f"invalid JSON input {path}: {exc}") from exc


def run_command(
    argv: Iterable[str | os.PathLike[str]],
    *,
    cwd: Path | None = None,
    timeout_seconds: int = 60,
    env: dict[str, str] | None = None,
    accepted_exit_codes: tuple[int, ...] = (0,),
    input_bytes: bytes | None = None,
) -> subprocess.CompletedProcess[str]:
    """Run an argument-vector command and preserve bounded diagnostic output."""

    command = [os.fspath(item) for item in argv]
    if input_bytes is not None and len(input_bytes) > MAX_COMMAND_INPUT_BYTES:
        raise SkillOptBridgeError(
            f"command input exceeded {MAX_COMMAND_INPUT_BYTES} bytes: {command[0]}"
        )
    process: subprocess.Popen[bytes] | None = None
    readers: list[threading.Thread] = []
    writer: threading.Thread | None = None
    try:
        process = subprocess.Popen(
            command,
            cwd=cwd,
            env=env,
            stdin=subprocess.PIPE if input_bytes is not None else subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            shell=False,
            start_new_session=os.name == "posix",
            creationflags=(
                subprocess.CREATE_NEW_PROCESS_GROUP if os.name == "nt" else 0
            ),
        )
        buffers = {"stdout": bytearray(), "stderr": bytearray()}
        overflow = threading.Event()

        def drain(label: str, stream: Any) -> None:
            try:
                while chunk := stream.read(64 * 1024):
                    remaining = MAX_COMMAND_OUTPUT_BYTES - len(buffers[label])
                    if len(chunk) > remaining:
                        buffers[label].extend(chunk[:remaining])
                        overflow.set()
                        return
                    buffers[label].extend(chunk)
            finally:
                stream.close()

        readers = [
            threading.Thread(
                target=drain, args=("stdout", process.stdout), daemon=True
            ),
            threading.Thread(
                target=drain, args=("stderr", process.stderr), daemon=True
            ),
        ]
        for reader in readers:
            reader.start()
        if input_bytes is not None:
            if process.stdin is None:
                raise SkillOptBridgeError("command input pipe was not created")

            def feed() -> None:
                try:
                    process.stdin.write(input_bytes)
                    process.stdin.flush()
                except (BrokenPipeError, OSError):
                    pass
                finally:
                    process.stdin.close()

            writer = threading.Thread(target=feed, daemon=True)
            writer.start()
        deadline = time.monotonic() + timeout_seconds
        while process.poll() is None and not overflow.is_set():
            if time.monotonic() >= deadline:
                _terminate_process_tree(process)
                raise subprocess.TimeoutExpired(command, timeout_seconds)
            time.sleep(0.02)
        if overflow.is_set():
            _terminate_process_tree(process)
        elif os.name == "posix":
            _terminate_process_tree(process)
        return_code = process.wait(timeout=5)
        for reader in readers:
            reader.join(timeout=5)
        if writer is not None:
            writer.join(timeout=5)
        if any(reader.is_alive() for reader in readers) or (
            writer is not None and writer.is_alive()
        ):
            raise SkillOptBridgeError(
                f"command I/O workers did not terminate: {command[0]}"
            )
        if overflow.is_set():
            label = next(
                name
                for name, buffer in buffers.items()
                if len(buffer) == MAX_COMMAND_OUTPUT_BYTES
            )
            raise SkillOptBridgeError(
                f"command {label} exceeded {MAX_COMMAND_OUTPUT_BYTES} bytes: {command[0]}"
            )
        completed = subprocess.CompletedProcess(
            command,
            return_code,
            stdout=buffers["stdout"].decode("utf-8", errors="replace"),
            stderr=buffers["stderr"].decode("utf-8", errors="replace"),
        )
    except KeyboardInterrupt:
        if process is not None:
            _terminate_process_tree(process)
        for reader in readers:
            reader.join(timeout=5)
        if writer is not None:
            writer.join(timeout=5)
        raise
    except SkillOptBridgeError:
        if process is not None:
            _terminate_process_tree(process)
        for reader in readers:
            reader.join(timeout=5)
        if writer is not None:
            writer.join(timeout=5)
        raise
    except (OSError, subprocess.TimeoutExpired) as exc:
        if process is not None:
            _terminate_process_tree(process)
        for reader in readers:
            reader.join(timeout=5)
        if writer is not None:
            writer.join(timeout=5)
        raise SkillOptBridgeError(
            f"command failed to execute: {command[0]}: {exc}"
        ) from exc
    if completed.returncode not in accepted_exit_codes:
        diagnostic = (completed.stderr or completed.stdout).strip()[-4000:]
        raise SkillOptBridgeError(
            f"command exited {completed.returncode}: {command[0]}: {diagnostic}"
        )
    return completed


def _terminate_process_tree(process: subprocess.Popen[bytes]) -> None:
    """Terminate the process group created for one owned command."""

    if os.name == "posix":
        try:
            os.killpg(process.pid, 0)
        except ProcessLookupError:
            return
        try:
            os.killpg(process.pid, signal.SIGTERM)
        except ProcessLookupError:
            return
        deadline = time.monotonic() + 5
        while time.monotonic() < deadline:
            process.poll()
            try:
                os.killpg(process.pid, 0)
            except ProcessLookupError:
                process.wait(timeout=1)
                return
            time.sleep(0.05)
        try:
            os.killpg(process.pid, signal.SIGKILL)
        except ProcessLookupError:
            pass
        process.wait(timeout=5)
        return

    if process.poll() is not None:
        return

    try:
        subprocess.run(
            ("taskkill", "/PID", str(process.pid), "/T", "/F"),
            stdin=subprocess.DEVNULL,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            timeout=5,
            check=False,
            shell=False,
        )
    except (OSError, subprocess.SubprocessError):
        process.kill()
    process.wait(timeout=5)


def git_output(repository: Path, *arguments: str) -> str:
    return run_command(
        (
            "git",
            "-c",
            "maintenance.auto=false",
            "-c",
            "gc.auto=0",
            "-C",
            repository,
            *arguments,
        )
    ).stdout.strip()


def git_blob_bytes(repository: Path, commit: str, path: PurePosixPath) -> bytes:
    """Read exact committed bytes and reject non-UTF-8/bounded-output drift."""

    path_text = path.as_posix()
    expected_blob = git_output(repository, "rev-parse", f"{commit}:{path_text}")
    completed = run_command(
        (
            "git",
            "-c",
            "maintenance.auto=false",
            "-c",
            "gc.auto=0",
            "-C",
            repository,
            "cat-file",
            "blob",
            expected_blob,
        )
    )
    value = completed.stdout.encode("utf-8")
    observed_blob = run_command(
        ("git", "hash-object", "--stdin"), input_bytes=value
    ).stdout.strip()
    if observed_blob != expected_blob:
        raise SkillOptBridgeError(
            f"baseline Git blob is not bounded UTF-8 text: {path_text}"
        )
    return value


def _accepted_skillopt_remote(value: str) -> bool:
    normalized = value.strip().removesuffix(".git").lower()
    return normalized in {
        "https://github.com/microsoft/skillopt",
        "ssh://git@github.com/microsoft/skillopt",
        "git@github.com:microsoft/skillopt",
    }


def validate_skillopt_checkout(source: Path) -> dict[str, str]:
    """Require the reviewed clean upstream commit, not a mutable package label."""

    supplied = source.expanduser()
    if supplied.is_symlink():
        raise SkillOptBridgeError("SkillOpt source must not be a symlink")
    try:
        resolved = supplied.resolve(strict=True)
    except OSError as exc:
        raise SkillOptBridgeError(f"cannot resolve SkillOpt source: {exc}") from exc
    if not resolved.is_dir():
        raise SkillOptBridgeError("SkillOpt source must be a directory")
    top = Path(git_output(resolved, "rev-parse", "--show-toplevel")).resolve(
        strict=True
    )
    if top != resolved:
        raise SkillOptBridgeError("SkillOpt source must be the checkout root")
    head = git_output(resolved, "rev-parse", "HEAD")
    if head != SKILLOPT_COMMIT:
        raise SkillOptBridgeError(
            f"SkillOpt source is {head}; expected reviewed commit {SKILLOPT_COMMIT}"
        )
    status = git_output(resolved, "status", "--porcelain=v1", "--untracked-files=all")
    if status:
        raise SkillOptBridgeError(
            "SkillOpt source must be clean, including untracked files"
        )
    remote = git_output(resolved, "remote", "get-url", "origin")
    if not _accepted_skillopt_remote(remote):
        raise SkillOptBridgeError(
            f"SkillOpt origin is not microsoft/SkillOpt: {remote}"
        )
    return {"source": str(resolved), "commit": head, "origin": remote}


def _resolve_executable(path: Path, label: str) -> Path:
    supplied = Path(os.path.abspath(path.expanduser()))
    try:
        supplied.lstat()
        target = supplied.resolve(strict=True)
    except OSError as exc:
        raise SkillOptBridgeError(f"cannot resolve {label}: {exc}") from exc
    if not target.is_file() or not os.access(supplied, os.X_OK):
        raise SkillOptBridgeError(f"{label} must resolve to an executable regular file")
    return supplied


def _resolve_commit(repository: Path, reference: str) -> str:
    commit = git_output(repository, "rev-parse", "--verify", f"{reference}^{{commit}}")
    if len(commit) != 40 or any(
        character not in "0123456789abcdef" for character in commit
    ):
        raise SkillOptBridgeError(
            f"baseline reference did not resolve to a commit: {reference}"
        )
    return commit


def _case_map(suite: SuiteSpec) -> dict[str, CaseSpec]:
    return {case.id: case for case in suite.cases}


def _select_cases(
    suite: SuiteSpec,
    ids: tuple[str, ...],
    *,
    skill: str,
    allowed_splits: set[str],
    label: str,
) -> tuple[CaseSpec, ...]:
    if not ids:
        raise SkillOptBridgeError(f"at least one {label} case is required")
    if len(set(ids)) != len(ids):
        raise SkillOptBridgeError(f"{label} cases must be unique")
    by_id = _case_map(suite)
    selected: list[CaseSpec] = []
    for case_id in ids:
        case = by_id.get(case_id)
        if case is None:
            raise SkillOptBridgeError(f"unknown {label} case: {case_id}")
        if case.skill != skill:
            raise SkillOptBridgeError(
                f"{label} case {case_id} belongs to skill {case.skill}"
            )
        if case.split not in allowed_splits:
            raise SkillOptBridgeError(
                f"{label} case {case_id} uses forbidden split {case.split}"
            )
        selected.append(case)
    return tuple(selected)


def _tracked_file_matches_commit(
    repository: Path, commit: str, path: PurePosixPath
) -> None:
    path_text = path.as_posix()
    mode_and_type = git_output(repository, "ls-tree", commit, "--", path_text).split()
    if len(mode_and_type) < 3 or mode_and_type[0] not in {"100644", "100755"}:
        raise SkillOptBridgeError(
            f"optimized skill must be a regular tracked file: {path_text}"
        )
    expected_blob = git_output(repository, "rev-parse", f"{commit}:{path_text}")
    observed_blob = git_output(repository, "hash-object", "--", path_text)
    if observed_blob != expected_blob:
        raise SkillOptBridgeError(
            f"working-tree bytes for {path_text} do not match baseline {commit}"
        )


def _evaluation_input_records(
    suite: SuiteSpec, cases: tuple[CaseSpec, ...]
) -> tuple[dict[str, Any], ...]:
    """Describe every selected public prompt, fixture, and verifier input."""

    files: dict[str, dict[str, Any]] = {}
    visited: set[Path] = set()
    entry_count = 0
    total_bytes = 0

    def add_path(path: Path, *, depth: int = 0, counted: bool = False) -> None:
        nonlocal entry_count, total_bytes
        absolute = Path(os.path.abspath(path))
        if absolute in visited:
            return
        visited.add(absolute)
        if not counted:
            entry_count += 1
            if entry_count > MAX_EVALUATION_INPUT_ENTRIES:
                raise SkillOptBridgeError(
                    f"evaluation inputs exceed {MAX_EVALUATION_INPUT_ENTRIES} entries"
                )
        if (
            any(part in _GENERATED_CACHE_DIRECTORIES for part in path.parts)
            or path.suffix in _GENERATED_CACHE_SUFFIXES
        ):
            return
        resolved = path.resolve(strict=True)
        if not resolved.is_relative_to(suite.root):
            raise SkillOptBridgeError(
                f"evaluation input escaped the suite root: {resolved}"
            )
        metadata = path.lstat()
        if stat.S_ISLNK(metadata.st_mode):
            raise SkillOptBridgeError(f"evaluation input must not be a symlink: {path}")
        if path.is_dir():
            if depth >= MAX_TREE_DEPTH:
                raise SkillOptBridgeError(
                    f"evaluation inputs exceed {MAX_TREE_DEPTH} directory levels"
                )
            children: list[tuple[Path, bool]] = []
            try:
                with os.scandir(path) as entries:
                    for entry in entries:
                        child = Path(entry.path)
                        child_absolute = Path(os.path.abspath(child))
                        newly_counted = child_absolute not in visited
                        if newly_counted:
                            entry_count += 1
                            if entry_count > MAX_EVALUATION_INPUT_ENTRIES:
                                raise SkillOptBridgeError(
                                    "evaluation inputs exceed "
                                    f"{MAX_EVALUATION_INPUT_ENTRIES} entries"
                                )
                        children.append((child, newly_counted))
            except OSError as exc:
                raise SkillOptBridgeError(
                    f"cannot traverse evaluation inputs: {exc}"
                ) from exc
            for child, newly_counted in sorted(children, key=lambda item: item[0].name):
                add_path(child, depth=depth + 1, counted=newly_counted)
            return
        if not stat.S_ISREG(metadata.st_mode):
            raise SkillOptBridgeError(
                f"evaluation input must be a regular file: {path}"
            )
        total_bytes += metadata.st_size
        if total_bytes > MAX_EVALUATION_INPUT_BYTES:
            raise SkillOptBridgeError(
                f"evaluation inputs exceed {MAX_EVALUATION_INPUT_BYTES} bytes"
            )
        relative = resolved.relative_to(suite.root).as_posix()
        files[relative] = {
            "path": relative,
            "sha256": sha256_file(resolved),
            "bytes": metadata.st_size,
            "executable": bool(metadata.st_mode & 0o111),
        }

    add_path(suite.path)
    if suite.shared_verifier_dir is not None:
        add_path(suite.shared_verifier_dir)
    for case in cases:
        add_path(case.prompt_file)
        add_path(case.fixture_dir)
        for argument in case.verifier.argv:
            candidate = suite.root / argument
            if candidate.exists() or candidate.is_symlink():
                add_path(candidate)
    return tuple(files[key] for key in sorted(files))


def _evaluation_inputs_sha256(suite: SuiteSpec, cases: tuple[CaseSpec, ...]) -> str:
    return sha256_bytes(canonical_bytes(_evaluation_input_records(suite, cases)))


def _evaluation_inputs_match_commit(
    repository: Path,
    commit: str,
    suite: SuiteSpec,
    cases: tuple[CaseSpec, ...],
) -> None:
    """Require reviewed input bytes to be the bytes the baseline clone will use."""

    for record in _evaluation_input_records(suite, cases):
        observed = (suite.root / record["path"]).resolve(strict=True)
        if not observed.is_relative_to(repository):
            raise SkillOptBridgeError(
                f"evaluation input is outside the baseline repository: {observed}"
            )
        relative = observed.relative_to(repository).as_posix()
        tree = git_output(repository, "ls-tree", commit, "--", relative).split()
        if len(tree) < 3 or tree[0] not in {"100644", "100755"}:
            raise SkillOptBridgeError(
                f"evaluation input must be a regular baseline file: {relative}"
            )
        expected_blob = tree[2]
        observed_blob = git_output(repository, "hash-object", "--", relative)
        if observed_blob != expected_blob:
            raise SkillOptBridgeError(
                f"working-tree evaluation input does not match baseline {commit}: {relative}"
            )
        if bool(observed.stat().st_mode & 0o111) != (tree[0] == "100755"):
            raise SkillOptBridgeError(
                f"evaluation input executable mode does not match baseline: {relative}"
            )


def _resolve_output_directory(target: Path) -> Path:
    supplied = target.expanduser()
    if supplied.exists() or supplied.is_symlink():
        raise SkillOptBridgeError("output directory must not already exist")
    supplied_parent = supplied.parent
    if supplied_parent.is_symlink():
        raise SkillOptBridgeError("output parent must not be a symlink")
    parent = supplied_parent.resolve(strict=True)
    resolved = parent / supplied.name
    if any(
        resolved.is_relative_to(ephemeral)
        for ephemeral in (Path("/tmp"), Path("/var/tmp"))
    ):
        raise SkillOptBridgeError(
            "output directory must not be under /tmp or /var/tmp because provider units use PrivateTmp"
        )
    return resolved


def build_plan(
    *,
    suite_path: Path,
    skill: str,
    baseline_ref: str,
    train_case_ids: tuple[str, ...],
    selection_case_ids: tuple[str, ...],
    validation_case_ids: tuple[str, ...],
    seed: int,
    optimizer_model: str,
    output_dir: Path,
    skillopt_source: Path,
    skillopt_python: Path,
    skivolve_python: Path,
    timeout_seconds: int,
) -> PilotPlan:
    """Resolve a bounded plan and reject holdout or attribution ambiguity."""

    if os.name != "posix":
        raise SkillOptBridgeError(
            "SkillOpt optimization is supported only on POSIX/Linux"
        )
    if timeout_seconds < 60 or timeout_seconds > 24 * 60 * 60:
        raise SkillOptBridgeError("timeout must be between 60 and 86400 seconds")
    suite = load_suite(suite_path)
    train_cases = _select_cases(
        suite, train_case_ids, skill=skill, allowed_splits={"train"}, label="training"
    )
    selection_cases = _select_cases(
        suite,
        selection_case_ids,
        skill=skill,
        allowed_splits={"train"},
        label="selection",
    )
    if len(selection_cases) != 1:
        raise SkillOptBridgeError(
            "v1 requires exactly one selection case so the aggregate gate cannot hide a task regression"
        )
    validation_cases = _select_cases(
        suite,
        validation_case_ids,
        skill=skill,
        allowed_splits={"validation"},
        label="validation",
    )
    overlap = set(train_case_ids) & set(selection_case_ids)
    if overlap:
        raise SkillOptBridgeError(
            f"training and selection cases must be disjoint: {', '.join(sorted(overlap))}"
        )
    all_cases = (*train_cases, *selection_cases, *validation_cases)
    bundle_sources = {case.bundle_source for case in all_cases}
    if len(bundle_sources) != 1:
        raise SkillOptBridgeError("all selected cases must use one bundle source")
    bundle_source = next(iter(bundle_sources))
    skill_path = bundle_source / "SKILL.md"
    if any(case.context_files != (skill_path,) for case in all_cases):
        raise SkillOptBridgeError(
            "v1 optimization requires every selected case to use only bundle SKILL.md"
        )
    repository = suite.repository_root.resolve(strict=True)
    baseline_commit = _resolve_commit(repository, baseline_ref)
    _tracked_file_matches_commit(repository, baseline_commit, skill_path)
    _evaluation_inputs_match_commit(repository, baseline_commit, suite, all_cases)
    skillopt = validate_skillopt_checkout(skillopt_source)
    resolved_skillopt_python = _resolve_executable(skillopt_python, "SkillOpt Python")
    skillopt_environment = _skillopt_environment(resolved_skillopt_python)
    resolved_skivolve_python = _resolve_executable(skivolve_python, "Skivolve Python")
    located_optimizer = shutil.which("codex")
    if located_optimizer is None:
        raise SkillOptBridgeError("Codex optimizer executable is not on PATH")
    resolved_optimizer = _resolve_executable(
        Path(located_optimizer), "Codex optimizer executable"
    )
    optimizer_target = resolved_optimizer.resolve(strict=True)
    bundled_sandbox = optimizer_target.parent.parent / "codex-resources" / "bwrap"
    resolved_sandbox = _resolve_executable(
        bundled_sandbox, "Codex bundled Bubblewrap optimizer sandbox"
    )
    evaluation_inputs_sha256 = _evaluation_inputs_sha256(suite, all_cases)
    resolved_output = _resolve_output_directory(output_dir)
    return PilotPlan(
        suite_path=suite.path,
        repository_root=repository,
        skill=skill,
        bundle_source=bundle_source,
        skill_path=skill_path,
        baseline_commit=baseline_commit,
        train_case_ids=train_case_ids,
        selection_case_ids=selection_case_ids,
        validation_case_ids=validation_case_ids,
        seed=seed,
        optimizer_model=optimizer_model,
        optimizer_executable=resolved_optimizer,
        optimizer_sandbox=resolved_sandbox,
        output_dir=resolved_output,
        skillopt_source=Path(skillopt["source"]),
        skillopt_python=resolved_skillopt_python,
        skillopt_environment=skillopt_environment,
        skivolve_python=resolved_skivolve_python,
        timeout_seconds=timeout_seconds,
        evaluation_inputs_sha256=evaluation_inputs_sha256,
        skillopt_python_sha256=sha256_file(resolved_skillopt_python),
        skillopt_environment_sha256=_environment_sha256(skillopt_environment),
        skivolve_python_sha256=sha256_file(resolved_skivolve_python),
        skivolve_package_sha256=_skivolve_package_sha256(),
        optimizer_executable_sha256=sha256_file(resolved_optimizer),
        optimizer_sandbox_sha256=sha256_file(resolved_sandbox),
    )


def plan_from_json(value: Any) -> PilotPlan:
    """Validate the immutable outer-process plan inside the sidecar."""

    if not isinstance(value, dict):
        raise SkillOptBridgeError("optimization plan must be a JSON object")
    required = {
        "schema_version",
        "suite_path",
        "repository_root",
        "skill",
        "bundle_source",
        "skill_path",
        "baseline_commit",
        "train_case_ids",
        "selection_case_ids",
        "validation_case_ids",
        "seed",
        "optimizer",
        "output_dir",
        "skillopt",
        "skivolve_python",
        "timeout_seconds",
        "planned_generator_calls",
        "planned_optimizer_invocations",
        "planned_generator_optimizer_invocation_ceiling",
        "bindings",
        "holdout_used",
        "automatic_adoption",
    }
    if set(value) != required:
        raise SkillOptBridgeError("optimization plan fields do not match schema v1")
    if value["schema_version"] != PLAN_SCHEMA_VERSION:
        raise SkillOptBridgeError("unsupported optimization plan schema")
    if value["holdout_used"] is not False or value["automatic_adoption"] is not False:
        raise SkillOptBridgeError("optimization plan violated holdout/adoption policy")
    bindings = value["bindings"]
    binding_fields = {
        "evaluation_inputs_sha256",
        "skivolve_package_sha256",
        "skillopt_python_sha256",
        "skillopt_environment_sha256",
        "skivolve_python_sha256",
        "optimizer_executable_sha256",
        "optimizer_sandbox_sha256",
    }
    if not isinstance(bindings, dict) or set(bindings) != binding_fields:
        raise SkillOptBridgeError("plan binding fields do not match schema v1")
    if any(
        not isinstance(bindings[field], str)
        or len(bindings[field]) != 64
        or any(character not in "0123456789abcdef" for character in bindings[field])
        for field in binding_fields
    ):
        raise SkillOptBridgeError("plan binding hashes are malformed")
    optimizer = value["optimizer"]
    expected_optimizer = {
        "backend",
        "model",
        "executable",
        "sandbox_executable",
        "num_epochs",
        "batch_size",
        "accumulation",
        "edit_budget",
        "max_invocations",
        "per_invocation_timeout_seconds",
        "use_gate",
        "gate_metric",
        "use_semantic_density",
        "use_slow_update",
        "use_meta_skill",
        "eval_test",
    }
    if not isinstance(optimizer, dict) or set(optimizer) != expected_optimizer:
        raise SkillOptBridgeError("optimizer policy fields do not match schema v1")
    fixed_optimizer = {
        "backend": "codex_exec",
        "num_epochs": 1,
        "accumulation": 1,
        "edit_budget": 2,
        "use_gate": True,
        "gate_metric": "hard",
        "use_semantic_density": False,
        "use_slow_update": False,
        "use_meta_skill": False,
        "eval_test": False,
    }
    for key, expected in fixed_optimizer.items():
        if optimizer.get(key) != expected:
            raise SkillOptBridgeError(f"optimizer policy changed forbidden field {key}")
    skillopt = value["skillopt"]
    if not isinstance(skillopt, dict) or set(skillopt) != {
        "repository",
        "commit",
        "source",
        "python",
        "environment",
    }:
        raise SkillOptBridgeError("SkillOpt binding fields do not match schema v1")
    if (
        skillopt["repository"] != SKILLOPT_REPOSITORY
        or skillopt["commit"] != SKILLOPT_COMMIT
    ):
        raise SkillOptBridgeError(
            "SkillOpt binding does not match the reviewed upstream"
        )

    def string(field: str) -> str:
        item = value[field]
        if not isinstance(item, str) or not item:
            raise SkillOptBridgeError(f"plan.{field} must be a non-empty string")
        return item

    def string_tuple(field: str) -> tuple[str, ...]:
        item = value[field]
        if (
            not isinstance(item, list)
            or not item
            or any(not isinstance(part, str) or not part for part in item)
            or len(set(item)) != len(item)
        ):
            raise SkillOptBridgeError(f"plan.{field} must contain unique strings")
        return tuple(item)

    bundle = PurePosixPath(string("bundle_source"))
    skill_path = PurePosixPath(string("skill_path"))
    if (
        bundle.is_absolute()
        or ".." in bundle.parts
        or skill_path != bundle / "SKILL.md"
    ):
        raise SkillOptBridgeError("plan skill path is not the bundle SKILL.md")
    baseline = string("baseline_commit")
    if len(baseline) != 40 or any(
        character not in "0123456789abcdef" for character in baseline
    ):
        raise SkillOptBridgeError("plan baseline commit is malformed")
    seed = value["seed"]
    timeout = value["timeout_seconds"]
    if isinstance(seed, bool) or not isinstance(seed, int):
        raise SkillOptBridgeError("plan seed must be an integer")
    if (
        isinstance(timeout, bool)
        or not isinstance(timeout, int)
        or not 60 <= timeout <= 86400
    ):
        raise SkillOptBridgeError("plan timeout is outside the allowed range")
    train = string_tuple("train_case_ids")
    selection = string_tuple("selection_case_ids")
    validation = string_tuple("validation_case_ids")
    if len(selection) != 1:
        raise SkillOptBridgeError("plan must bind exactly one selection case")
    if set(train) & set(selection):
        raise SkillOptBridgeError("plan training and selection cases overlap")
    if optimizer["batch_size"] != len(train):
        raise SkillOptBridgeError(
            "optimizer batch size does not bind the training cases"
        )
    model = optimizer["model"]
    if not isinstance(model, str) or not model:
        raise SkillOptBridgeError("optimizer model must be a non-empty string")
    optimizer_executable = optimizer["executable"]
    if not isinstance(optimizer_executable, str) or not optimizer_executable:
        raise SkillOptBridgeError("optimizer executable must be a non-empty string")
    optimizer_sandbox = optimizer["sandbox_executable"]
    if not isinstance(optimizer_sandbox, str) or not optimizer_sandbox:
        raise SkillOptBridgeError(
            "optimizer sandbox executable must be a non-empty string"
        )
    plan = PilotPlan(
        suite_path=Path(string("suite_path")).resolve(strict=True),
        repository_root=Path(string("repository_root")).resolve(strict=True),
        skill=string("skill"),
        bundle_source=bundle,
        skill_path=skill_path,
        baseline_commit=baseline,
        train_case_ids=train,
        selection_case_ids=selection,
        validation_case_ids=validation,
        seed=seed,
        optimizer_model=model,
        optimizer_executable=_resolve_executable(
            Path(optimizer_executable), "Codex optimizer executable"
        ),
        optimizer_sandbox=_resolve_executable(
            Path(optimizer_sandbox), "Bubblewrap optimizer sandbox"
        ),
        output_dir=Path(string("output_dir")).resolve(strict=True),
        skillopt_source=Path(skillopt["source"]).resolve(strict=True),
        skillopt_python=_resolve_executable(
            Path(skillopt["python"]), "SkillOpt Python"
        ),
        skillopt_environment=Path(skillopt["environment"]).resolve(strict=True),
        skivolve_python=_resolve_executable(
            Path(string("skivolve_python")), "Skivolve Python"
        ),
        timeout_seconds=timeout,
        evaluation_inputs_sha256=bindings["evaluation_inputs_sha256"],
        skivolve_package_sha256=bindings["skivolve_package_sha256"],
        skillopt_python_sha256=bindings["skillopt_python_sha256"],
        skillopt_environment_sha256=bindings["skillopt_environment_sha256"],
        skivolve_python_sha256=bindings["skivolve_python_sha256"],
        optimizer_executable_sha256=bindings["optimizer_executable_sha256"],
        optimizer_sandbox_sha256=bindings["optimizer_sandbox_sha256"],
    )
    if value["planned_generator_calls"] != plan.planned_generator_calls:
        raise SkillOptBridgeError("planned generator-call count is stale")
    if value["planned_optimizer_invocations"] != plan.planned_optimizer_invocations:
        raise SkillOptBridgeError("planned optimizer-invocation count is stale")
    if (
        optimizer["max_invocations"] != plan.planned_optimizer_invocations
        or optimizer["per_invocation_timeout_seconds"] != OPTIMIZER_CALL_TIMEOUT_SECONDS
    ):
        raise SkillOptBridgeError("optimizer invocation budget changed")
    if (
        value["planned_generator_optimizer_invocation_ceiling"]
        != plan.planned_generator_optimizer_invocation_ceiling
    ):
        raise SkillOptBridgeError(
            "planned generator/optimizer invocation ceiling is stale"
        )
    return plan


def revalidate_plan(plan: PilotPlan) -> tuple[SuiteSpec, bytes, dict[str, str]]:
    """Recheck source bindings at each process and certification boundary."""

    suite = load_suite(plan.suite_path)
    if suite.repository_root.resolve(strict=True) != plan.repository_root:
        raise SkillOptBridgeError("suite repository root drifted after planning")
    if (
        _resolve_commit(plan.repository_root, plan.baseline_commit)
        != plan.baseline_commit
    ):
        raise SkillOptBridgeError("baseline commit is no longer resolvable")
    train = _select_cases(
        suite,
        plan.train_case_ids,
        skill=plan.skill,
        allowed_splits={"train"},
        label="training",
    )
    selection = _select_cases(
        suite,
        plan.selection_case_ids,
        skill=plan.skill,
        allowed_splits={"train"},
        label="selection",
    )
    validation = _select_cases(
        suite,
        plan.validation_case_ids,
        skill=plan.skill,
        allowed_splits={"validation"},
        label="validation",
    )
    cases = (*train, *selection, *validation)
    if any(
        case.bundle_source != plan.bundle_source
        or case.context_files != (plan.skill_path,)
        for case in cases
    ):
        raise SkillOptBridgeError("selected case bundle/context binding drifted")
    if _evaluation_inputs_sha256(suite, cases) != plan.evaluation_inputs_sha256:
        raise SkillOptBridgeError("selected evaluation inputs drifted after planning")
    _evaluation_inputs_match_commit(
        plan.repository_root, plan.baseline_commit, suite, cases
    )
    if _skivolve_package_sha256() != plan.skivolve_package_sha256:
        raise SkillOptBridgeError("Skivolve package bytes drifted after planning")
    _tracked_file_matches_commit(
        plan.repository_root, plan.baseline_commit, plan.skill_path
    )
    baseline = git_blob_bytes(
        plan.repository_root, plan.baseline_commit, plan.skill_path
    )
    if len(baseline) > MAX_CANDIDATE_BYTES:
        raise SkillOptBridgeError("initial skill exceeds the candidate size ceiling")
    upstream = validate_skillopt_checkout(plan.skillopt_source)
    if (
        _resolve_executable(plan.skillopt_python, "SkillOpt Python")
        != plan.skillopt_python
        or sha256_file(plan.skillopt_python) != plan.skillopt_python_sha256
    ):
        raise SkillOptBridgeError("SkillOpt Python drifted after planning")
    if (
        _skillopt_environment(plan.skillopt_python) != plan.skillopt_environment
        or _environment_sha256(plan.skillopt_environment)
        != plan.skillopt_environment_sha256
    ):
        raise SkillOptBridgeError("SkillOpt environment drifted after planning")
    if (
        _resolve_executable(plan.skivolve_python, "Skivolve Python")
        != plan.skivolve_python
        or sha256_file(plan.skivolve_python) != plan.skivolve_python_sha256
    ):
        raise SkillOptBridgeError("Skivolve Python drifted after planning")
    if (
        _resolve_executable(plan.optimizer_executable, "Codex optimizer executable")
        != plan.optimizer_executable
        or sha256_file(plan.optimizer_executable) != plan.optimizer_executable_sha256
    ):
        raise SkillOptBridgeError("Codex optimizer executable drifted after planning")
    if (
        _resolve_executable(plan.optimizer_sandbox, "Bubblewrap optimizer sandbox")
        != plan.optimizer_sandbox
        or sha256_file(plan.optimizer_sandbox) != plan.optimizer_sandbox_sha256
        or plan.optimizer_sandbox.resolve(strict=True)
        != plan.optimizer_executable.resolve(strict=True).parent.parent
        / "codex-resources"
        / "bwrap"
    ):
        raise SkillOptBridgeError("optimizer sandbox drifted after planning")
    return suite, baseline, upstream


def frontmatter_bytes(value: bytes) -> bytes:
    """Return exact YAML frontmatter, including delimiters."""

    if not value.startswith(b"---\n"):
        return b""
    end = value.find(b"\n---\n", 4)
    if end < 0:
        raise SkillOptBridgeError("initial skill has unterminated YAML frontmatter")
    return value[: end + len(b"\n---\n")]


def validate_candidate(candidate: bytes, baseline: bytes) -> str:
    if not candidate or len(candidate) > MAX_CANDIDATE_BYTES:
        raise SkillOptBridgeError(
            f"candidate must contain 1..{MAX_CANDIDATE_BYTES} bytes"
        )
    try:
        text = candidate.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise SkillOptBridgeError("candidate must be valid UTF-8") from exc
    if "\x00" in text:
        raise SkillOptBridgeError("candidate must not contain NUL bytes")
    if frontmatter_bytes(candidate) != frontmatter_bytes(baseline):
        raise SkillOptBridgeError("candidate must preserve exact YAML frontmatter")
    return text


def clone_candidate(
    *,
    source_repository: Path,
    destination: Path,
    baseline_commit: str,
    skill_path: PurePosixPath,
    candidate: bytes,
) -> str:
    """Create a run-owned clone with exactly one committed candidate change."""

    if destination.exists() or destination.is_symlink():
        raise SkillOptBridgeError(
            f"candidate clone destination already exists: {destination}"
        )
    destination.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    commit_environment = {
        name: value for name, value in os.environ.items() if not name.startswith("GIT_")
    }
    commit_environment.update(
        {
            "GIT_AUTHOR_DATE": _CANDIDATE_COMMIT_DATE,
            "GIT_COMMITTER_DATE": _CANDIDATE_COMMIT_DATE,
        }
    )
    run_command(
        (
            "git",
            "clone",
            "--no-hardlinks",
            "--no-checkout",
            source_repository,
            destination,
        ),
        timeout_seconds=300,
    )
    git_output(destination, "checkout", "--detach", baseline_commit)
    target = destination.joinpath(*skill_path.parts)
    resolved_parent = target.parent.resolve(strict=True)
    if (
        not resolved_parent.is_relative_to(destination.resolve(strict=True))
        or target.is_symlink()
    ):
        raise SkillOptBridgeError("candidate skill path escaped the run-owned clone")
    baseline = target.read_bytes()
    validate_candidate(candidate, baseline)
    target.write_bytes(candidate)
    changed = tuple(
        line
        for line in git_output(destination, "diff", "--name-only", "--").splitlines()
        if line
    )
    if changed not in {(), (skill_path.as_posix(),)}:
        raise SkillOptBridgeError(f"candidate changed unexpected paths: {changed}")
    run_command(
        (
            "git",
            "-c",
            "user.name=Skivolve SkillOpt",
            "-c",
            "user.email=skillopt@invalid.local",
            "-c",
            "commit.gpgsign=false",
            "-C",
            destination,
            "commit",
            "--no-verify",
            "--allow-empty",
            "-m",
            "chore(skill): materialize SkillOpt candidate",
            "--",
            skill_path.as_posix(),
        ),
        timeout_seconds=60,
        env=commit_environment,
    )
    commit = git_output(destination, "rev-parse", "HEAD")
    if git_output(destination, "status", "--porcelain=v1", "--untracked-files=no"):
        raise SkillOptBridgeError("candidate clone remained dirty after commit")
    return commit


def candidate_snapshot_sha256(clone: Path, bundle_source: PurePosixPath) -> str:
    """Hash the exact bundle tree using Skivolve's source-snapshot contract."""

    from .runner import _tree_hash

    bundle = clone.joinpath(*bundle_source.parts)
    if not bundle.is_dir() or bundle.is_symlink():
        raise SkillOptBridgeError("candidate bundle is not a regular directory")
    return _tree_hash(
        bundle,
        ignore_generated_caches=True,
        ignore_empty_directories=True,
    )


def derived_suite_payload(
    *,
    suite: SuiteSpec,
    baseline_commit: str,
    candidate_commit: str,
    fitness: bool = False,
) -> dict[str, Any]:
    """Create an attributable comparison without changing case/oracle bytes."""

    payload = json.loads(json.dumps(suite.raw))
    payload["suite_id"] = f"{suite.suite_id}-skillopt"
    payload["repository_root"] = "."
    payload["evaluation_mode"] = "objective_only"
    payload.pop("comparator", None)
    payload.pop("comparator_profile", None)
    for case in payload.get("cases", []):
        if isinstance(case, dict):
            case.pop("comparator_contract", None)
    candidate = {
        "id": "candidate",
        "kind": "worktree",
        "root": ".",
        "source_ref": candidate_commit,
    }
    if fitness:
        payload["variants"] = [
            {"id": "no-skill", "kind": "without_skill"},
            candidate,
        ]
        comparison_id = FITNESS_COMPARISON_ID
        control = "no-skill"
    else:
        payload["variants"] = [
            {"id": "seed", "kind": "git_ref", "git_ref": baseline_commit},
            candidate,
        ]
        comparison_id = COMPARISON_ID
        control = "seed"
    payload["comparisons"] = [
        {
            "id": comparison_id,
            "control": control,
            "treatment": "candidate",
            "repetitions": 3,
            "comparator_order": "ab_ba",
        }
    ]
    payload["holdout"] = {"comparison_ids": [comparison_id]}
    return payload


def write_derived_suite(
    clone: Path,
    *,
    suite: SuiteSpec,
    baseline_commit: str,
    candidate_commit: str,
    fitness: bool = False,
) -> Path:
    path = clone / "suite.skillopt.generated.json"
    private_write_json(
        path,
        derived_suite_payload(
            suite=suite,
            baseline_commit=baseline_commit,
            candidate_commit=candidate_commit,
            fitness=fitness,
        ),
    )
    return path


def invoke_skivolve(
    *,
    python: Path,
    suite_path: Path,
    split: str,
    case_ids: tuple[str, ...],
    output_dir: Path | None,
    timeout_seconds: int,
    dry_run: bool = False,
    comparison_id: str = COMPARISON_ID,
) -> tuple[int, dict[str, Any]]:
    if split not in {"train", "validation"}:
        raise SkillOptBridgeError(f"optimizer cannot invoke split {split}")
    argv: list[str | os.PathLike[str]] = [
        python,
        "-I",
        "-m",
        "skivolve",
        "--suite",
        suite_path,
        "--split",
        split,
        "--comparison",
        comparison_id,
    ]
    for case_id in case_ids:
        argv.extend(("--case", case_id))
    if dry_run:
        argv.append("--dry-run")
    else:
        if output_dir is None:
            raise SkillOptBridgeError("Skivolve output directory is required")
        argv.extend(("--verifier-only", "--output-dir", output_dir))
    completed = run_command(
        argv,
        cwd=suite_path.parent,
        timeout_seconds=timeout_seconds,
        accepted_exit_codes=(0, 1),
    )
    try:
        summary = json.loads(completed.stdout)
    except json.JSONDecodeError as exc:
        raise SkillOptBridgeError("Skivolve emitted malformed JSON summary") from exc
    if not isinstance(summary, dict):
        raise SkillOptBridgeError("Skivolve summary must be a JSON object")
    return completed.returncode, summary
