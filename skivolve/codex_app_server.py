"""Pinned Codex app-server provider with bounded protocol and sandbox state."""

from __future__ import annotations

import errno
import fcntl
import hashlib
import json
import os
import re
import selectors
import shutil
import stat
import subprocess
import tempfile
import threading
import time
import uuid
from contextlib import contextmanager
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any, Callable, Iterator, Protocol

from skivolve.comparator_runtime import CalibrationError, VerifiedExecutable

from .manifest import ProviderConfig
from .providers import (
    AgentRequest,
    ComparatorRequest,
    ComparatorResult,
    ProviderError,
    ProviderResult,
    execution_policy_for,
)


class ProviderTimeoutError(ProviderError):
    """Raised when a Codex operation exceeds its configured deadline."""

    def __init__(self, message: str, *, cleanup_confirmed: bool = False) -> None:
        if type(cleanup_confirmed) is not bool:
            raise TypeError("cleanup_confirmed must be a bool")
        super().__init__(message)
        self.cleanup_confirmed = cleanup_confirmed


_MAX_FRAME_BYTES = 8 * 1024 * 1024
_MAX_MESSAGES = 20_000
_MAX_PAGES = 64
_MAX_PAGE_ITEMS = 4_096
_MAX_MODELS = 4_096
_MAX_SKILLS = 1_024
_MAX_COMPLETED_MESSAGES = 64
_MAX_COLLAB_THREADS = 32
_MAX_COLLAB_TURNS = 128
_MAX_RETAINED_TEXT_BYTES = 8 * 1024 * 1024
_MAX_RATE_LIMIT_BUCKETS = 32
_MAX_AUTH_BYTES = 1024 * 1024
_MAX_EXECUTABLE_BYTES = 512 * 1024 * 1024
_MAX_LOCK_BYTES = 64 * 1024
_MAX_POISON_BYTES = 64 * 1024
_PRIVATE_DIRECTORY_MODE = 0o700
_PRIVATE_FILE_MODE = 0o600
_TOOL_NAME_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._+-]*$")
_SHA256_RE = re.compile(r"^[0-9a-f]{64}$")
_CODEX_CLI_VERSION_RE = re.compile(
    r"\Acodex-cli (?P<thread_version>"
    r"(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)"
    r"(?:-(?:0|[1-9][0-9]*|[0-9]*[A-Za-z-][0-9A-Za-z-]*)"
    r"(?:\.(?:0|[1-9][0-9]*|[0-9]*[A-Za-z-][0-9A-Za-z-]*))*)?"
    r"(?:\+[0-9A-Za-z-]+(?:\.[0-9A-Za-z-]+)*)?"
    r")\Z"
)
_SYSTEMD_PATH_RE = re.compile(r"/[A-Za-z0-9/._@+=,-]*")
_SYSTEMD_UNIT_RE = re.compile(r"^skill-eval-codex-[A-Za-z0-9_.@-]{1,96}$")
_PROVIDER_LOCK_NAME = "skill-eval-codex-mount.lock"
_CLEANUP_POISON_NAME = "skill-eval-codex-mount.poison.json"
_CLEANUP_POISON_TEMP_RE = re.compile(
    rf"^\.{re.escape(_CLEANUP_POISON_NAME)}\.[0-9a-f]{{32}}\.tmp$"
)
_LAUNCH_GATE_TOKEN = b"GO\n"
_LAUNCH_GATE_SCRIPT = """set -eu
gate_fd=$1
shift
case "$gate_fd" in ''|*[!0-9]*) exit 124 ;; esac
IFS= read -r gate_token <&"$gate_fd" || exit 125
[ "$gate_token" = GO ] || exit 126
exec {gate_fd}<&-
exec "$@"
"""
_RUNTIME_BUNDLE_PATHS = (
    "bin/codex",
    "codex-path/rg",
    "codex-resources/bwrap",
    "codex-resources/zsh/bin/zsh",
)
_NO_PARAMS = object()

_IGNORED_NOTIFICATIONS = frozenset(
    {
        "item/agentMessage/delta",
        "item/commandExecution/outputDelta",
        "item/commandExecution/terminalInteraction",
        "item/fileChange/outputDelta",
        "item/fileChange/patchUpdated",
        "item/plan/delta",
        "item/reasoning/summaryPartAdded",
        "item/reasoning/summaryTextDelta",
        "item/reasoning/textDelta",
        "model/safetyBuffering/updated",
        "model/verification",
        "thread/status/changed",
        "turn/diff/updated",
        "turn/moderationMetadata",
        "turn/plan/updated",
    }
)
_PROHIBITED_NOTIFICATIONS = frozenset(
    {
        "configWarning",
        "deprecationNotice",
        "guardianWarning",
        "hook/completed",
        "hook/started",
        "item/autoApprovalReview/completed",
        "item/autoApprovalReview/started",
        "item/mcpToolCall/progress",
        "serverRequest/resolved",
        "thread/settings/updated",
        "warning",
        "windows/worldWritableWarning",
    }
)
_ALLOWED_ITEM_TYPES = frozenset(
    {
        "agentMessage",
        "collabAgentToolCall",
        "commandExecution",
        "contextCompaction",
        "fileChange",
        "imageView",
        "reasoning",
        "userMessage",
    }
)


class _Transport(Protocol):
    evidence: dict[str, Any]

    def send(self, payload: bytes, deadline: float) -> None: ...

    def receive(self, deadline: float) -> bytes: ...

    def close(self) -> None: ...


TransportFactory = Callable[[tuple[str, ...], Path, dict[str, str], str], _Transport]


@dataclass(frozen=True)
class _ProtocolLock:
    raw_bytes: bytes
    sha256: str
    cli_version: str
    thread_cli_version: str
    executable_sha256: str
    protocol_bundle: str
    protocol_canonical_bytes: int
    protocol_canonicalization: str
    protocol_generate_argv: tuple[str, ...]
    protocol_sha256: str
    runtime_bundle_files: dict[str, str]
    runtime_bundle_sha256: str
    model_efforts: dict[str, tuple[str, ...]]


@dataclass(frozen=True)
class _TurnOutcome:
    final_output: str
    tokens: dict[str, int]
    quota: dict[str, Any]
    raw_response: dict[str, Any]


@dataclass(frozen=True)
class _PoisonBinding:
    auth_device: int
    auth_inode: int
    protocol_lock_sha256: str
    provider_lock_device: int
    provider_lock_inode: int
    runtime_mount: str
    runtime_mount_device: int
    runtime_mount_inode: int

    def as_json(self) -> dict[str, int | str]:
        return asdict(self)


@dataclass(frozen=True)
class _WorkspaceRuntime:
    parent_descriptor: int
    directories: tuple[tuple[str, int], ...]


class _RecoveryProbe(Protocol):
    def confirm_unit_clean(
        self,
        unit_name: str,
        captured_control_group: str | None,
        deadline: float,
    ) -> str: ...

    def process_start_time(self, process_id: int) -> int | None: ...

    def matching_command_pids(self, command_sha256: str) -> tuple[int, ...]: ...

    def host_mount_present(self, path: Path) -> bool: ...


_UnitCleanupState = tuple[str, str, str, str]


def _reject_constant(value: str) -> None:
    raise ValueError(f"non-finite JSON number is not allowed: {value}")


def _unique_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("duplicate JSON key is not allowed")
        result[key] = value
    return result


def _decode_json(payload: bytes, label: str) -> dict[str, Any]:
    try:
        value = json.loads(
            payload,
            object_pairs_hook=_unique_object,
            parse_constant=_reject_constant,
        )
    except (
        UnicodeDecodeError,
        json.JSONDecodeError,
        ValueError,
        RecursionError,
    ) as exc:
        raise ProviderError(f"{label} is invalid JSON: {exc}") from exc
    if not isinstance(value, dict):
        raise ProviderError(f"{label} must be a JSON object")
    return value


def _encode_json(value: dict[str, Any], label: str) -> bytes:
    try:
        payload = json.dumps(
            value,
            allow_nan=False,
            ensure_ascii=True,
            separators=(",", ":"),
            sort_keys=True,
        ).encode("ascii")
    except (TypeError, ValueError) as exc:
        raise ProviderError(f"cannot encode {label}: {exc}") from exc
    if len(payload) > _MAX_FRAME_BYTES:
        raise ProviderError(f"{label} exceeds the protocol frame limit")
    return payload + b"\n"


def _command_sha256(command: tuple[str, ...]) -> str:
    payload = json.dumps(
        command,
        ensure_ascii=True,
        separators=(",", ":"),
    ).encode("ascii")
    return hashlib.sha256(payload).hexdigest()


def _systemctl_properties(payload: str, required: set[str]) -> dict[str, str] | None:
    values: dict[str, str] = {}
    for line in payload.splitlines():
        key, separator, value = line.partition("=")
        if separator != "=" or key not in required or key in values:
            return None
        values[key] = value
    if set(values) != required:
        return None
    return values


def _show_unit(
    systemctl: str, unit_name: str, properties: set[str], *, timeout: float = 5
) -> dict[str, str] | None:
    try:
        shown = subprocess.run(
            [
                systemctl,
                "--user",
                "show",
                unit_name,
                *(f"--property={name}" for name in sorted(properties)),
            ],
            capture_output=True,
            text=True,
            timeout=timeout,
            check=False,
            shell=False,
        )
    except (OSError, subprocess.TimeoutExpired) as exc:
        raise ProviderError("cannot query Codex unit state") from exc
    return (
        _systemctl_properties(shown.stdout, properties)
        if shown.returncode == 0
        else None
    )


def _plain_integer(
    value: Any, label: str, *, minimum: int = 0, maximum: int = 2**63 - 1
) -> int:
    if (
        not isinstance(value, int)
        or isinstance(value, bool)
        or not minimum <= value <= maximum
    ):
        raise ProviderError(f"{label} must be an integer in the permitted range")
    return value


def _linux_process_start_time(process_id: int) -> int | None:
    if process_id <= 0:
        raise ProviderError("process identity requires a positive PID")
    try:
        payload = (Path("/proc") / str(process_id) / "stat").read_bytes()
    except OSError as exc:
        if exc.errno in {errno.ENOENT, errno.ESRCH}:
            return None
        raise ProviderError(
            f"cannot inspect process identity for PID {process_id}"
        ) from exc
    if len(payload) > 16 * 1024:
        raise ProviderError(f"process identity for PID {process_id} is oversized")
    closing_parenthesis = payload.rfind(b")")
    if closing_parenthesis < 0:
        raise ProviderError(f"process identity for PID {process_id} is malformed")
    fields = payload[closing_parenthesis + 1 :].split()
    if len(fields) <= 19:
        raise ProviderError(f"process identity for PID {process_id} is incomplete")
    try:
        start_time = int(fields[19])
    except ValueError as exc:
        raise ProviderError(
            f"process identity for PID {process_id} has an invalid start time"
        ) from exc
    return _plain_integer(
        start_time, f"process identity for PID {process_id}", minimum=1
    )


def _mountinfo_path(value: str) -> str:
    replacements = {
        r"\040": " ",
        r"\011": "\t",
        r"\012": "\n",
        r"\134": "\\",
    }
    for escaped, decoded in replacements.items():
        value = value.replace(escaped, decoded)
    return value


def _host_mount_present(path: Path) -> bool:
    try:
        payload = Path("/proc/self/mountinfo").read_text(encoding="ascii")
    except (OSError, UnicodeError) as exc:
        raise ProviderError("cannot inspect host mount table during recovery") from exc
    if len(payload) > 16 * 1024 * 1024:
        raise ProviderError("host mount table exceeds the recovery bound")
    target = str(path)
    for line in payload.splitlines():
        fields = line.split()
        if len(fields) < 6 or "-" not in fields[6:]:
            raise ProviderError("host mount table is malformed")
        if _mountinfo_path(fields[4]) == target:
            return True
    return False


def _validate_control_group(value: Any, label: str, *, allow_empty: bool) -> str:
    if not isinstance(value, str) or len(value) > 4_096 or "\x00" in value:
        raise ProviderError(f"{label} is invalid")
    if not value:
        if allow_empty:
            return value
        raise ProviderError(f"{label} is empty")
    if not value.startswith("/") or any(
        part in {"", ".", ".."} for part in value.split("/")[1:]
    ):
        raise ProviderError(f"{label} is invalid")
    return value


def _canonical_json(value: dict[str, Any], label: str) -> bytes:
    try:
        return json.dumps(
            value,
            allow_nan=False,
            ensure_ascii=True,
            separators=(",", ":"),
            sort_keys=True,
        ).encode("ascii")
    except (TypeError, ValueError) as exc:
        raise ProviderError(f"cannot canonicalize {label}: {exc}") from exc


def _require_object(value: Any, label: str) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise ProviderError(f"{label} must be an object")
    return value


def _require_list(value: Any, label: str, *, maximum: int) -> list[Any]:
    if not isinstance(value, list):
        raise ProviderError(f"{label} must be an array")
    if len(value) > maximum:
        raise ProviderError(f"{label} exceeds the item limit")
    return value


def _require_string(value: Any, label: str) -> str:
    if not isinstance(value, str) or not value:
        raise ProviderError(f"{label} must be a non-empty string")
    return value


def _derive_thread_cli_version(cli_version: str) -> str:
    if len(cli_version) > 128:
        raise ProviderError("codex_cli_version is not an exact Codex SemVer banner")
    match = _CODEX_CLI_VERSION_RE.fullmatch(cli_version)
    if match is None:
        raise ProviderError("codex_cli_version is not an exact Codex SemVer banner")
    return match.group("thread_version")


def _validate_cli_version_output(
    completed: subprocess.CompletedProcess[str], expected: str
) -> None:
    if completed.returncode != 0:
        raise ProviderError("Codex CLI version command failed")
    if completed.stdout != f"{expected}\n" or completed.stderr != "":
        raise ProviderError("Codex CLI version differs from protocol lock")


def _require_protocol_id(value: Any, label: str) -> str:
    identifier = _require_string(value, label)
    if len(identifier) > 256 or re.fullmatch(r"[\x21-\x7e]+", identifier) is None:
        raise ProviderError(f"{label} is not a bounded printable identifier")
    return identifier


def _opaque_sha256(identifier: str) -> str:
    return hashlib.sha256(identifier.encode("ascii")).hexdigest()


def _require_jsonrpc_id(value: Any, label: str) -> int | str:
    if isinstance(value, bool):
        raise ProviderError(f"{label} is invalid")
    if isinstance(value, int):
        if -(2**31) <= value <= 2**31 - 1:
            return value
        raise ProviderError(f"{label} is outside the supported range")
    return _require_protocol_id(value, label)


def _require_exact_keys(
    value: dict[str, Any],
    label: str,
    *,
    required: set[str],
    optional: set[str] = frozenset(),
) -> None:
    missing = sorted(required - value.keys())
    if missing:
        raise ProviderError(f"{label} omitted keys: {', '.join(missing)}")
    unknown = sorted(value.keys() - required - optional)
    if unknown:
        raise ProviderError(f"{label} has unknown keys")


def _remaining(deadline: float, label: str) -> float:
    remaining = deadline - time.monotonic()
    if remaining <= 0:
        raise ProviderTimeoutError(f"{label} timed out")
    return remaining


def _sha256_file(path: Path, *, maximum: int, label: str) -> str:
    flags = os.O_RDONLY | os.O_CLOEXEC | getattr(os, "O_NOFOLLOW", 0)
    try:
        descriptor = os.open(path, flags)
    except OSError as exc:
        raise ProviderError(f"cannot open {label}: {exc}") from exc
    try:
        before = os.fstat(descriptor)
        if not stat.S_ISREG(before.st_mode) or before.st_size > maximum:
            raise ProviderError(f"{label} is not a bounded regular file")
        digest = hashlib.sha256()
        while chunk := os.read(descriptor, 1024 * 1024):
            digest.update(chunk)
        after = os.fstat(descriptor)
        if (
            before.st_dev,
            before.st_ino,
            before.st_size,
            before.st_mtime_ns,
            before.st_ctime_ns,
        ) != (
            after.st_dev,
            after.st_ino,
            after.st_size,
            after.st_mtime_ns,
            after.st_ctime_ns,
        ):
            raise ProviderError(f"{label} changed while it was hashed")
        return digest.hexdigest()
    except OSError as exc:
        raise ProviderError(f"cannot hash {label}: {exc}") from exc
    finally:
        os.close(descriptor)


def _read_bounded_descriptor(descriptor: int, maximum: int) -> bytes:
    chunks: list[bytes] = []
    remaining = maximum + 1
    while remaining:
        chunk = os.read(descriptor, min(1024 * 1024, remaining))
        if not chunk:
            break
        chunks.append(chunk)
        remaining -= len(chunk)
    return b"".join(chunks)


def _write_all(descriptor: int, payload: bytes, label: str) -> None:
    view = memoryview(payload)
    while view:
        written = os.write(descriptor, view)
        if written <= 0:
            raise ProviderError(f"{label} write made no progress")
        view = view[written:]


def _read_bounded_regular(path: Path, *, maximum: int, label: str) -> bytes:
    flags = os.O_RDONLY | os.O_CLOEXEC | getattr(os, "O_NOFOLLOW", 0)
    try:
        descriptor = os.open(path, flags)
    except OSError as exc:
        raise ProviderError(f"cannot open {label}: {exc}") from exc
    try:
        before = os.fstat(descriptor)
        if (
            not stat.S_ISREG(before.st_mode)
            or before.st_size <= 0
            or before.st_size > maximum
        ):
            raise ProviderError(f"{label} is not a bounded regular file")
        payload = _read_bounded_descriptor(descriptor, maximum)
        after = os.fstat(descriptor)
        if len(payload) > maximum:
            raise ProviderError(f"{label} exceeds the byte limit")
        if (
            before.st_dev,
            before.st_ino,
            before.st_size,
            before.st_mtime_ns,
            before.st_ctime_ns,
        ) != (
            after.st_dev,
            after.st_ino,
            after.st_size,
            after.st_mtime_ns,
            after.st_ctime_ns,
        ):
            raise ProviderError(f"{label} changed while it was read")
        return payload
    except OSError as exc:
        raise ProviderError(f"cannot read {label}: {exc}") from exc
    finally:
        os.close(descriptor)


def _resolve_executable(value: str) -> Path:
    resolved = shutil.which(value)
    if resolved is None:
        raise ProviderError(f"Codex executable is unavailable: {value}")
    path = Path(resolved).resolve(strict=True)
    metadata = path.stat()
    if not stat.S_ISREG(metadata.st_mode) or not os.access(path, os.X_OK):
        raise ProviderError("Codex executable must be an executable regular file")
    return path


def _resolve_system_tool(name: str) -> Path:
    for directory in (Path("/usr/bin"), Path("/bin")):
        candidate = directory / name
        try:
            metadata = candidate.lstat()
        except FileNotFoundError:
            continue
        except OSError as exc:
            raise ProviderError(
                f"cannot inspect required system tool {name}: {exc}"
            ) from exc
        if stat.S_ISLNK(metadata.st_mode):
            candidate = candidate.resolve(strict=True)
            metadata = candidate.lstat()
        if (
            not stat.S_ISREG(metadata.st_mode)
            or metadata.st_uid != 0
            or stat.S_IMODE(metadata.st_mode) & 0o022
            or not os.access(candidate, os.X_OK)
        ):
            raise ProviderError(f"required system tool {name} is not trusted")
        return candidate
    raise ProviderError(f"required system tool is unavailable: {name}")


def _resolve_gate_shell() -> tuple[Path, tuple[int, int]]:
    target = _resolve_system_tool("bash")
    try:
        metadata = target.lstat()
    except OSError as exc:
        raise ProviderError("cannot re-attest the Codex launch gate shell") from exc
    return target, (metadata.st_dev, metadata.st_ino)


def _attest_process_executable(
    process_id: int, expected_path: Path, expected_identity: tuple[int, int]
) -> None:
    executable = Path(f"/proc/{process_id}/exe")
    try:
        metadata = executable.stat()
        observed_path = Path(os.readlink(executable))
    except OSError as exc:
        raise ProviderError("cannot attest the Codex gate executable") from exc
    if (
        metadata.st_dev,
        metadata.st_ino,
    ) != expected_identity or observed_path != expected_path:
        raise ProviderError("Codex gate executable identity changed")


def _load_protocol_lock(path: Path) -> _ProtocolLock:
    raw = _read_bounded_regular(
        path, maximum=_MAX_LOCK_BYTES, label="Codex protocol lock"
    )
    data = _decode_json(raw, "Codex protocol lock")
    _require_exact_keys(
        data,
        "Codex protocol lock",
        required={
            "schema_version",
            "codex_cli_version",
            "executable_sha256",
            "protocol",
            "runtime_bundle",
            "models",
        },
    )
    if data["schema_version"] != 1:
        raise ProviderError("unsupported Codex protocol lock schema_version")
    cli_version = _require_string(data["codex_cli_version"], "codex_cli_version")
    thread_cli_version = _derive_thread_cli_version(cli_version)
    executable_sha256 = _require_string(data["executable_sha256"], "executable_sha256")
    if _SHA256_RE.fullmatch(executable_sha256) is None:
        raise ProviderError("Codex protocol lock executable_sha256 is invalid")
    protocol = _require_object(data["protocol"], "protocol")
    _require_exact_keys(
        protocol,
        "protocol",
        required={
            "bundle",
            "canonical_bytes",
            "canonicalization",
            "generate_argv",
            "sha256",
        },
    )
    bundle = _require_string(protocol["bundle"], "protocol.bundle")
    if bundle != "codex_app_server_protocol.v2.schemas.json":
        raise ProviderError("protocol.bundle differs from the pinned v2 bundle")
    argv_values = _require_list(
        protocol["generate_argv"], "protocol.generate_argv", maximum=16
    )
    if not argv_values or not all(
        isinstance(item, str) and item for item in argv_values
    ):
        raise ProviderError("protocol.generate_argv must contain non-empty strings")
    generate_argv = tuple(argv_values)
    if generate_argv != (
        "app-server",
        "generate-json-schema",
        "--experimental",
        "--out",
        "{output_dir}",
    ):
        raise ProviderError("protocol.generate_argv differs from the pinned command")
    canonicalization = _require_string(
        protocol["canonicalization"], "protocol.canonicalization"
    )
    if canonicalization != "json-sort-keys-compact-ascii-v1":
        raise ProviderError("unsupported protocol canonicalization")
    canonical_bytes = protocol["canonical_bytes"]
    if (
        isinstance(canonical_bytes, bool)
        or not isinstance(canonical_bytes, int)
        or canonical_bytes <= 0
        or canonical_bytes > _MAX_FRAME_BYTES * 8
    ):
        raise ProviderError("protocol.canonical_bytes is invalid")
    protocol_sha256 = _require_string(protocol["sha256"], "protocol.sha256")
    if _SHA256_RE.fullmatch(protocol_sha256) is None:
        raise ProviderError("Codex protocol lock protocol.sha256 is invalid")

    runtime_bundle = _require_object(data["runtime_bundle"], "runtime_bundle")
    _require_exact_keys(
        runtime_bundle,
        "runtime_bundle",
        required={"canonicalization", "files", "sha256"},
    )
    if runtime_bundle["canonicalization"] != "json-sort-keys-compact-ascii-v1":
        raise ProviderError("unsupported Codex runtime-bundle canonicalization")
    runtime_files = _require_object(runtime_bundle["files"], "runtime_bundle.files")
    if set(runtime_files) != set(_RUNTIME_BUNDLE_PATHS):
        raise ProviderError("Codex runtime bundle must pin the exact required files")
    for relative_path, digest in runtime_files.items():
        if not isinstance(digest, str) or _SHA256_RE.fullmatch(digest) is None:
            raise ProviderError(
                f"runtime_bundle.files.{relative_path} digest is invalid"
            )
    runtime_bundle_sha256 = _require_string(
        runtime_bundle["sha256"], "runtime_bundle.sha256"
    )
    if _SHA256_RE.fullmatch(runtime_bundle_sha256) is None:
        raise ProviderError("runtime_bundle.sha256 is invalid")
    observed_bundle_sha256 = hashlib.sha256(
        _canonical_json(runtime_files, "runtime_bundle.files")
    ).hexdigest()
    if observed_bundle_sha256 != runtime_bundle_sha256:
        raise ProviderError("runtime_bundle.sha256 differs from the pinned files")
    if runtime_files["bin/codex"] != executable_sha256:
        raise ProviderError(
            "runtime bundle Codex digest differs from executable_sha256"
        )

    models = _require_object(data["models"], "models")
    if set(models) != {"gpt-5.6-luna", "gpt-5.6-terra"}:
        raise ProviderError("Codex protocol lock must pin Luna and Terra exactly")
    model_efforts: dict[str, tuple[str, ...]] = {}
    for model, raw_model in models.items():
        model_data = _require_object(raw_model, f"models.{model}")
        _require_exact_keys(
            model_data,
            f"models.{model}",
            required={"reasoning_efforts"},
        )
        efforts = _require_list(
            model_data["reasoning_efforts"],
            f"models.{model}.reasoning_efforts",
            maximum=16,
        )
        if not efforts or not all(isinstance(item, str) and item for item in efforts):
            raise ProviderError(f"models.{model}.reasoning_efforts is invalid")
        if len(set(efforts)) != len(efforts):
            raise ProviderError(f"models.{model}.reasoning_efforts has duplicates")
        model_efforts[model] = tuple(efforts)
    return _ProtocolLock(
        raw_bytes=raw,
        sha256=hashlib.sha256(raw).hexdigest(),
        cli_version=cli_version,
        thread_cli_version=thread_cli_version,
        executable_sha256=executable_sha256,
        protocol_bundle=bundle,
        protocol_canonical_bytes=canonical_bytes,
        protocol_canonicalization=canonicalization,
        protocol_generate_argv=generate_argv,
        protocol_sha256=protocol_sha256,
        runtime_bundle_files=dict(runtime_files),
        runtime_bundle_sha256=runtime_bundle_sha256,
        model_efforts=model_efforts,
    )


def validate_codex_protocol_lock(
    executable: Path | VerifiedExecutable, lock: _ProtocolLock
) -> None:
    """Regenerate the installed protocol and validate binary/version provenance."""

    owned = not isinstance(executable, VerifiedExecutable)
    try:
        verified = VerifiedExecutable(Path(executable)) if owned else executable
    except (CalibrationError, OSError) as exc:
        raise ProviderError(f"cannot attest Codex executable: {exc}") from exc
    try:
        try:
            verified.ensure_source_unchanged()
        except (CalibrationError, OSError) as exc:
            raise ProviderError(f"Codex executable attestation failed: {exc}") from exc
        if verified.sha256 != lock.executable_sha256:
            raise ProviderError("Codex executable digest differs from protocol lock")
        release_root = verified.path.parent.parent
        for relative_path, expected_digest in lock.runtime_bundle_files.items():
            bundle_path = _resolve_bundle_executable(
                release_root / relative_path,
                f"Codex runtime bundle file {relative_path}",
            )
            observed_digest = _sha256_file(
                bundle_path,
                maximum=_MAX_EXECUTABLE_BYTES,
                label=f"Codex runtime bundle file {relative_path}",
            )
            if observed_digest != expected_digest:
                raise ProviderError(
                    f"Codex runtime bundle file {relative_path} differs from lock"
                )
        try:
            completed = subprocess.run(
                [verified.descriptor_path, "--version"],
                capture_output=True,
                text=True,
                timeout=15,
                check=False,
                shell=False,
            )
        except (OSError, subprocess.TimeoutExpired) as exc:
            raise ProviderError(f"cannot capture Codex CLI version: {exc}") from exc
        _validate_cli_version_output(completed, lock.cli_version)

        with tempfile.TemporaryDirectory(
            prefix="skill-eval-codex-protocol-"
        ) as temporary:
            root = Path(temporary)
            output = root / "schema"
            home = root / "codex-home"
            output.mkdir()
            home.mkdir(mode=_PRIVATE_DIRECTORY_MODE)
            argv = [
                verified.descriptor_path,
                *(
                    str(output) if item == "{output_dir}" else item
                    for item in lock.protocol_generate_argv
                ),
            ]
            try:
                generated = subprocess.run(
                    argv,
                    capture_output=True,
                    text=True,
                    timeout=60,
                    check=False,
                    shell=False,
                    env={
                        "CODEX_HOME": str(home),
                        "HOME": str(root),
                        "LANG": "C.UTF-8",
                        "PATH": "/usr/bin:/bin",
                    },
                )
            except (OSError, subprocess.TimeoutExpired) as exc:
                raise ProviderError(f"cannot regenerate Codex protocol: {exc}") from exc
            if generated.returncode != 0:
                raise ProviderError("Codex protocol regeneration failed")
            raw_bundle = _read_bounded_regular(
                output / lock.protocol_bundle,
                maximum=_MAX_FRAME_BYTES * 8,
                label="generated Codex protocol bundle",
            )
            canonical = _canonical_json(
                _decode_json(raw_bundle, "generated Codex protocol bundle"),
                "generated Codex protocol bundle",
            )
            if len(canonical) != lock.protocol_canonical_bytes:
                raise ProviderError(
                    "generated Codex protocol canonical length differs from lock"
                )
            observed_protocol = hashlib.sha256(canonical).hexdigest()
            if observed_protocol != lock.protocol_sha256:
                raise ProviderError(
                    "generated Codex protocol differs from protocol lock"
                )
    finally:
        if owned:
            verified.close()


class _JsonRpcSession:
    def __init__(self, transport: _Transport) -> None:
        self._transport = transport
        self._next_id = 1
        self._messages = 0
        self._closed = False

    def call(
        self,
        method: str,
        params: Any,
        deadline: float,
        notification_handler: Callable[[str, Any], None],
        on_sent: Callable[[], None] | None = None,
    ) -> Any:
        if self._closed:
            raise ProviderError("Codex protocol session is closed")
        request_id = self._next_id
        self._next_id += 1
        request: dict[str, Any] = {"id": request_id, "method": method}
        if params is not _NO_PARAMS:
            request["params"] = params
        self._transport.send(_encode_json(request, f"{method} request"), deadline)
        if on_sent is not None:
            try:
                on_sent()
            except Exception as exc:
                raise ProviderError(
                    "Codex dispatch accounting failed after request transmission"
                ) from exc
        while True:
            message = self._receive(deadline)
            if "method" in message:
                self._handle_server_message(message, deadline, notification_handler)
                continue
            _require_exact_keys(
                message,
                "JSON-RPC response",
                required={"id"},
                optional={"result", "error"},
            )
            response_id = _require_jsonrpc_id(message["id"], "JSON-RPC response id")
            if response_id != request_id:
                raise ProviderError("Codex returned an unknown JSON-RPC response id")
            if ("result" in message) == ("error" in message):
                raise ProviderError("Codex response must contain result or error")
            if "error" in message:
                error = _require_object(message["error"], "JSON-RPC error")
                code = error.get("code")
                if (
                    isinstance(code, bool)
                    or not isinstance(code, int)
                    or code < -(2**31)
                    or code > 2**31 - 1
                ):
                    raise ProviderError(f"Codex {method} returned a malformed error")
                raise ProviderError(f"Codex {method} failed with a JSON-RPC error")
            return message["result"]

    def notify(self, method: str, params: Any, deadline: float) -> None:
        notification: dict[str, Any] = {"method": method}
        if params is not _NO_PARAMS:
            notification["params"] = params
        self._transport.send(
            _encode_json(notification, f"{method} notification"), deadline
        )

    def receive_notification(
        self,
        deadline: float,
        notification_handler: Callable[[str, Any], None],
    ) -> None:
        message = self._receive(deadline)
        if "method" not in message:
            raise ProviderError("Codex sent a response with no pending request")
        self._handle_server_message(message, deadline, notification_handler)

    def _receive(self, deadline: float) -> dict[str, Any]:
        self._messages += 1
        if self._messages > _MAX_MESSAGES:
            raise ProviderError("Codex protocol message limit exceeded")
        return _decode_json(self._transport.receive(deadline), "Codex protocol frame")

    def _handle_server_message(
        self,
        message: dict[str, Any],
        deadline: float,
        notification_handler: Callable[[str, Any], None],
    ) -> None:
        if "id" in message:
            _require_exact_keys(
                message,
                "server request",
                required={"id", "method", "params"},
            )
            server_request_id = _require_jsonrpc_id(message["id"], "server request id")
            denial = {
                "error": {
                    "code": -32601,
                    "message": "server requests are denied by the evaluation harness",
                },
                "id": server_request_id,
            }
            self._transport.send(
                _encode_json(denial, "server-request denial"), deadline
            )
            raise ProviderError("Codex server request is not permitted")
        _require_exact_keys(
            message,
            "server notification",
            required={"method", "params"},
        )
        method = _require_string(message["method"], "notification method")
        notification_handler(method, message["params"])

    def close(self) -> None:
        if not self._closed:
            self._closed = True
            self._transport.close()


def _merge_sparse(current: Any, update: Any) -> Any:
    if update is None:
        return current
    if not isinstance(current, dict) or not isinstance(update, dict):
        return update
    result = {key: _json_copy(value) for key, value in current.items()}
    for key, value in update.items():
        result[key] = _merge_sparse(result.get(key), value)
    return result


def _json_copy(value: Any) -> Any:
    return json.loads(json.dumps(value, allow_nan=False, ensure_ascii=True))


def _optional_bounded_integer(
    value: Any, label: str, *, minimum: int = 0, maximum: int = 2**63 - 1
) -> int | None:
    if value is None:
        return None
    if (
        isinstance(value, bool)
        or not isinstance(value, int)
        or value < minimum
        or value > maximum
    ):
        raise ProviderError(f"{label} must be an integer in the supported range")
    return value


def _sanitize_rate_window(value: Any, label: str) -> dict[str, int | None] | None:
    if value is None:
        return None
    data = _require_object(value, label)
    _require_exact_keys(
        data,
        label,
        required={"usedPercent"},
        optional={"resetsAt", "windowDurationMins"},
    )
    used = _optional_bounded_integer(
        data["usedPercent"], f"{label}.usedPercent", maximum=100
    )
    assert used is not None
    return {
        "resetsAt": _optional_bounded_integer(
            data.get("resetsAt"), f"{label}.resetsAt"
        ),
        "usedPercent": used,
        "windowDurationMins": _optional_bounded_integer(
            data.get("windowDurationMins"), f"{label}.windowDurationMins"
        ),
    }


def _sanitize_rate_snapshot(value: Any, label: str) -> dict[str, Any]:
    data = _require_object(value, label)
    allowed = {
        "credits",
        "individualLimit",
        "limitId",
        "limitName",
        "planType",
        "primary",
        "rateLimitReachedType",
        "secondary",
    }
    _require_exact_keys(data, label, required=set(), optional=allowed)
    limit_id = data.get("limitId")
    if limit_id is not None:
        limit_id = _require_protocol_id(limit_id, f"{label}.limitId")
        if len(limit_id) > 64 or re.fullmatch(r"[A-Za-z0-9._-]+", limit_id) is None:
            raise ProviderError(f"{label}.limitId is invalid")
    plan_type = data.get("planType")
    allowed_plans = {
        "free",
        "go",
        "plus",
        "pro",
        "prolite",
        "team",
        "self_serve_business_usage_based",
        "business",
        "enterprise_cbp_usage_based",
        "enterprise",
        "edu",
        "unknown",
        None,
    }
    if plan_type not in allowed_plans:
        raise ProviderError(f"{label}.planType is invalid")
    reached = data.get("rateLimitReachedType")
    allowed_reached = {
        "rate_limit_reached",
        "workspace_owner_credits_depleted",
        "workspace_member_credits_depleted",
        "workspace_owner_usage_limit_reached",
        "workspace_member_usage_limit_reached",
        None,
    }
    if reached not in allowed_reached:
        raise ProviderError(f"{label}.rateLimitReachedType is invalid")
    sanitized: dict[str, Any] = {
        "limit_id_sha256": _opaque_sha256(limit_id) if limit_id is not None else None,
        "planType": plan_type,
        "primary": _sanitize_rate_window(data.get("primary"), f"{label}.primary"),
        "rateLimitReachedType": reached,
        "secondary": _sanitize_rate_window(data.get("secondary"), f"{label}.secondary"),
    }
    credits = data.get("credits")
    if credits is None:
        sanitized["credits"] = None
    else:
        credits_data = _require_object(credits, f"{label}.credits")
        _require_exact_keys(
            credits_data,
            f"{label}.credits",
            required={"hasCredits", "unlimited"},
            optional={"balance"},
        )
        if (
            type(credits_data["hasCredits"]) is not bool
            or type(credits_data["unlimited"]) is not bool
        ):
            raise ProviderError(f"{label}.credits flags must be booleans")
        sanitized["credits"] = {
            "hasCredits": credits_data["hasCredits"],
            "unlimited": credits_data["unlimited"],
        }
    individual = data.get("individualLimit")
    if individual is None:
        sanitized["individualLimit"] = None
    else:
        individual_data = _require_object(individual, f"{label}.individualLimit")
        _require_exact_keys(
            individual_data,
            f"{label}.individualLimit",
            required={"limit", "remainingPercent", "resetsAt", "used"},
        )
        remaining = _optional_bounded_integer(
            individual_data["remainingPercent"],
            f"{label}.individualLimit.remainingPercent",
            maximum=100,
        )
        resets = _optional_bounded_integer(
            individual_data["resetsAt"], f"{label}.individualLimit.resetsAt"
        )
        assert remaining is not None and resets is not None
        sanitized["individualLimit"] = {
            "remainingPercent": remaining,
            "resetsAt": resets,
        }
    return sanitized


def _sanitize_rate_limit_response(value: Any, label: str) -> dict[str, Any]:
    data = _require_object(value, label)
    _require_exact_keys(
        data,
        label,
        required={"rateLimits"},
        optional={"rateLimitsByLimitId", "rateLimitResetCredits"},
    )
    result: dict[str, Any] = {
        "rateLimits": _sanitize_rate_snapshot(data["rateLimits"], f"{label}.rateLimits")
    }
    by_id = data.get("rateLimitsByLimitId")
    if by_id is None:
        result["rateLimitsByLimitId"] = None
    else:
        buckets = _require_object(by_id, f"{label}.rateLimitsByLimitId")
        if len(buckets) > _MAX_RATE_LIMIT_BUCKETS:
            raise ProviderError("rate-limit bucket count exceeds the limit")
        sanitized_buckets: dict[str, Any] = {}
        for bucket_id, snapshot in buckets.items():
            if (
                not isinstance(bucket_id, str)
                or len(bucket_id) > 64
                or re.fullmatch(r"[A-Za-z0-9._-]+", bucket_id) is None
            ):
                raise ProviderError("rate-limit bucket id is invalid")
            sanitized_buckets[_opaque_sha256(bucket_id)] = _sanitize_rate_snapshot(
                snapshot, f"{label}.rateLimitsByLimitId.bucket"
            )
        result["rateLimitsByLimitId"] = sanitized_buckets
    credits = data.get("rateLimitResetCredits")
    if credits is None:
        result["rateLimitResetCredits"] = None
    else:
        credits_data = _require_object(credits, f"{label}.rateLimitResetCredits")
        _require_exact_keys(
            credits_data,
            f"{label}.rateLimitResetCredits",
            required={"availableCount"},
            optional={"credits"},
        )
        count = _optional_bounded_integer(
            credits_data["availableCount"],
            f"{label}.rateLimitResetCredits.availableCount",
            maximum=1_000_000,
        )
        assert count is not None
        result["rateLimitResetCredits"] = {"availableCount": count}
    return result


class _AppServerProtocol:
    def __init__(
        self,
        session: _JsonRpcSession,
        *,
        model: str,
        reasoning_effort: str,
        workspace: Path,
        system_context: str,
        locked_efforts: tuple[str, ...],
        locked_thread_cli_version: str,
        expected_codex_home: Path,
        on_dispatched: Callable[[], None] | None = None,
    ) -> None:
        self._session = session
        self._model = model
        self._reasoning_effort = reasoning_effort
        self._workspace = workspace
        self._system_context = system_context
        self._locked_efforts = locked_efforts
        self._locked_thread_cli_version = locked_thread_cli_version
        self._expected_codex_home = expected_codex_home
        self._on_dispatched = on_dispatched
        self._thread_id: str | None = None
        self._session_id: str | None = None
        self._announced_thread_id: str | None = None
        self._turn_id: str | None = None
        self._announced_turn_id: str | None = None
        self._turn_completed: dict[str, Any] | None = None
        self._completed_messages: list[dict[str, str | None]] = []
        self._collab_thread_ids: set[str] = set()
        self._validated_collab_thread_ids: set[str] = set()
        self._collab_parent_ids: dict[str, str] = {}
        self._collab_depths: dict[str, int] = {}
        self._collab_turn_ids: dict[str, set[str]] = {}
        self._active_collab_thread_ids: set[str] = set()
        self._seen_collab_turn_ids: set[tuple[str, str]] = set()
        self._collab_turn_usage: dict[tuple[str, str], dict[str, int]] = {}
        self._pending_spawn_items: dict[
            tuple[str, str], tuple[str | None, bytes | None]
        ] = {}
        self._terminal_collab_history: dict[
            tuple[str, str],
            tuple[
                str,
                str,
                tuple[str, ...],
                tuple[tuple[str, str], ...],
                str | None,
                bytes | None,
                str | None,
            ],
        ] = {}
        self._terminal_collab_item_ids: set[tuple[str, str]] = set()
        self._active_nonspawn_items: dict[
            tuple[str, str], tuple[str, tuple[str, ...]]
        ] = {}
        self._unbound_collab_thread_ids: set[str] = set()
        self._failed_collab_thread_ids: set[str] = set()
        self._retained_text_bytes = 0
        self._last_usage: dict[str, int] | None = None
        self._rate_limits: dict[str, Any] | None = None
        self._disabling_skills = False

    def run(self, prompt: str, deadline: float) -> _TurnOutcome:
        self._initialize(deadline)
        self._verify_model_catalog(deadline)
        self._verify_permission_profile(deadline)
        account = self._verify_account(deadline)
        before_limits = self._read_rate_limits(deadline)
        self._rate_limits = _json_copy(before_limits)
        self._disable_skills(deadline)
        self._start_thread(deadline)
        self._start_turn(prompt, deadline)
        while self._turn_completed is None:
            self._session.receive_notification(deadline, self._handle_notification)
        final_output, turn = self._finalize_turn()
        after_limits = self._read_rate_limits(deadline)
        if self._last_usage is None:
            raise ProviderError("Codex turn omitted last-turn token usage")
        total_usage = dict(self._last_usage)
        for child_usage in self._collab_turn_usage.values():
            for key, value in child_usage.items():
                total_usage[key] += value
        quota = {
            "before": before_limits,
            "rolling": self._rate_limits,
            "after": after_limits,
        }
        assert self._thread_id is not None and self._turn_id is not None
        raw = {
            "account": account,
            "model": self._model,
            "reasoning_effort": self._reasoning_effort,
            "thread_id_sha256": _opaque_sha256(self._thread_id),
            "turn": turn,
            "turn_id_sha256": _opaque_sha256(self._turn_id),
            "usage": dict(total_usage),
        }
        return _TurnOutcome(
            final_output=final_output,
            tokens=total_usage,
            quota=quota,
            raw_response=raw,
        )

    def _call(
        self,
        method: str,
        params: Any,
        deadline: float,
        *,
        on_sent: Callable[[], None] | None = None,
    ) -> Any:
        return self._session.call(
            method,
            params,
            deadline,
            self._handle_notification,
            on_sent=on_sent,
        )

    def _initialize(self, deadline: float) -> None:
        result = _require_object(
            self._call(
                "initialize",
                {
                    "capabilities": {
                        "experimentalApi": True,
                        "requestAttestation": False,
                    },
                    "clientInfo": {
                        "name": "skivolve",
                        "version": "1",
                    },
                },
                deadline,
            ),
            "initialize result",
        )
        for key in ("codexHome", "platformFamily", "platformOs", "userAgent"):
            _require_string(result.get(key), f"initialize result.{key}")
        if result["codexHome"] != str(self._expected_codex_home):
            raise ProviderError("Codex initialized with an unexpected CODEX_HOME")
        self._session.notify("initialized", _NO_PARAMS, deadline)

    def _paged(
        self,
        method: str,
        params: dict[str, Any],
        deadline: float,
        *,
        maximum: int,
    ) -> list[Any]:
        cursor: str | None = None
        seen: set[str] = set()
        values: list[Any] = []
        for _ in range(_MAX_PAGES):
            request = dict(params)
            if cursor is not None:
                request["cursor"] = cursor
            result = _require_object(self._call(method, request, deadline), method)
            _require_exact_keys(
                result,
                method,
                required={"data"},
                optional={"nextCursor"},
            )
            page = _require_list(
                result.get("data"), f"{method}.data", maximum=_MAX_PAGE_ITEMS
            )
            if len(values) + len(page) > maximum:
                raise ProviderError(f"{method} exceeds the total item limit")
            values.extend(page)
            next_cursor = result.get("nextCursor")
            if next_cursor is None:
                return values
            cursor = _require_protocol_id(next_cursor, f"{method}.nextCursor")
            if cursor in seen:
                raise ProviderError(f"{method} repeated a pagination cursor")
            seen.add(cursor)
        raise ProviderError(f"{method} exceeded the pagination limit")

    def _verify_model_catalog(self, deadline: float) -> None:
        models = self._paged(
            "model/list",
            {"includeHidden": True, "limit": 100},
            deadline,
            maximum=_MAX_MODELS,
        )
        matches = [
            _require_object(item, "model")
            for item in models
            if isinstance(item, dict) and item.get("model") == self._model
        ]
        if len(matches) != 1:
            raise ProviderError(
                "pinned model is missing or duplicated in model catalog"
            )
        efforts = _require_list(
            matches[0].get("supportedReasoningEfforts"),
            "supportedReasoningEfforts",
            maximum=32,
        )
        supported = {
            _require_string(
                _require_object(item, "reasoning effort").get("reasoningEffort"),
                "reasoningEffort",
            )
            for item in efforts
        }
        if len(supported) != len(efforts) or supported != set(self._locked_efforts):
            raise ProviderError(
                "model reasoning-effort catalog differs from protocol lock"
            )

    def _verify_permission_profile(self, deadline: float) -> None:
        profiles = self._paged(
            "permissionProfile/list",
            {"cwd": str(self._workspace), "limit": 100},
            deadline,
            maximum=_MAX_PAGE_ITEMS,
        )
        matches = [
            _require_object(item, "permission profile")
            for item in profiles
            if isinstance(item, dict) and item.get("id") == "eval"
        ]
        if len(matches) != 1 or matches[0].get("allowed") is not True:
            raise ProviderError("required eval permission profile is unavailable")

    def _verify_account(self, deadline: float) -> dict[str, Any]:
        result = _require_object(
            self._call("account/read", {"refreshToken": False}, deadline),
            "account/read",
        )
        account = _require_object(result.get("account"), "account/read.account")
        if account.get("type") != "chatgpt":
            raise ProviderError(
                "Codex evaluation requires ChatGPT account authentication"
            )
        plan_type = _require_string(account.get("planType"), "account.planType")
        if plan_type not in {
            "free",
            "go",
            "plus",
            "pro",
            "prolite",
            "team",
            "self_serve_business_usage_based",
            "business",
            "enterprise_cbp_usage_based",
            "enterprise",
            "edu",
            "unknown",
        }:
            raise ProviderError("Codex account returned an unsupported plan type")
        return {"plan_type": plan_type, "type": "chatgpt"}

    def _read_rate_limits(self, deadline: float) -> dict[str, Any]:
        result = self._call("account/rateLimits/read", _NO_PARAMS, deadline)
        return _sanitize_rate_limit_response(
            result,
            "account/rateLimits/read",
        )

    def _list_skills(self, deadline: float) -> list[dict[str, Any]]:
        result = _require_object(
            self._call(
                "skills/list",
                {"cwds": [str(self._workspace)], "forceReload": True},
                deadline,
            ),
            "skills/list",
        )
        entries = _require_list(result.get("data"), "skills/list.data", maximum=16)
        skills: list[dict[str, Any]] = []
        for index, raw_entry in enumerate(entries):
            entry = _require_object(raw_entry, f"skills/list.data[{index}]")
            errors = _require_list(
                entry.get("errors"), f"skills/list.data[{index}].errors", maximum=64
            )
            if errors:
                raise ProviderError("Codex skill discovery reported errors")
            for skill in _require_list(
                entry.get("skills"),
                f"skills/list.data[{index}].skills",
                maximum=_MAX_SKILLS,
            ):
                skills.append(_require_object(skill, "skill metadata"))
        if len(skills) > _MAX_SKILLS:
            raise ProviderError("Codex skill inventory exceeds the total item limit")
        return skills

    def _disable_skills(self, deadline: float) -> None:
        self._disabling_skills = True
        try:
            skills = self._list_skills(deadline)
            enabled_paths = {
                _require_string(skill.get("path"), "skill.path")
                for skill in skills
                if skill.get("enabled") is True
            }
            for path in sorted(enabled_paths):
                result = _require_object(
                    self._call(
                        "skills/config/write",
                        {"enabled": False, "path": path},
                        deadline,
                    ),
                    "skills/config/write",
                )
                if result.get("effectiveEnabled") is not False:
                    raise ProviderError("Codex refused to disable a bundled skill")
            remaining = self._list_skills(deadline)
            if any(skill.get("enabled") is not False for skill in remaining):
                raise ProviderError("Codex skill inventory was not fully disabled")
        finally:
            self._disabling_skills = False

    def _start_thread(self, deadline: float) -> None:
        result = _require_object(
            self._call(
                "thread/start",
                {
                    "allowProviderModelFallback": False,
                    "approvalPolicy": "never",
                    "config": {
                        "include_apps_instructions": False,
                        "include_collaboration_mode_instructions": False,
                        "model_reasoning_effort": self._reasoning_effort,
                    },
                    "cwd": str(self._workspace),
                    "developerInstructions": self._system_context,
                    "dynamicTools": [],
                    "ephemeral": True,
                    "historyMode": "paginated",
                    "model": self._model,
                    "permissions": "eval",
                    "runtimeWorkspaceRoots": [str(self._workspace)],
                    "threadSource": "skill-eval",
                },
                deadline,
            ),
            "thread/start",
        )
        if result.get("model") != self._model:
            raise ProviderError("Codex thread did not use the pinned model")
        if result.get("reasoningEffort") != self._reasoning_effort:
            raise ProviderError("Codex thread did not use the pinned reasoning effort")
        if result.get("approvalPolicy") != "never":
            raise ProviderError("Codex thread changed the approval policy")
        if result.get("approvalsReviewer") != "user":
            raise ProviderError("Codex thread changed the approvals reviewer")
        if result.get("multiAgentMode", "explicitRequestOnly") != "explicitRequestOnly":
            raise ProviderError("Codex thread enabled multi-agent mode")
        if result.get("cwd") != str(self._workspace):
            raise ProviderError("Codex thread changed the working directory")
        if result.get("instructionSources", []) != []:
            raise ProviderError("Codex thread loaded unexpected instruction sources")
        if result.get("runtimeWorkspaceRoots", []) != [str(self._workspace)]:
            raise ProviderError("Codex thread changed the runtime workspace roots")
        active = _require_object(
            result.get("activePermissionProfile"), "activePermissionProfile"
        )
        if active.get("id") != "eval" or active.get("extends") is not None:
            raise ProviderError("Codex thread did not activate the eval profile")
        sandbox = _require_object(result.get("sandbox"), "thread sandbox")
        if sandbox.get("type") != "workspaceWrite":
            raise ProviderError(
                "Codex thread did not activate workspace-write sandboxing"
            )
        thread = _require_object(result.get("thread"), "thread/start.thread")
        if (
            result.get("modelProvider") != "openai"
            or thread.get("modelProvider") != "openai"
        ):
            raise ProviderError("Codex thread used an unexpected model provider")
        if thread.get("cliVersion") != self._locked_thread_cli_version:
            raise ProviderError(
                "Codex thread CLI provenance differs from protocol lock"
            )
        created_at = _optional_bounded_integer(
            thread.get("createdAt"), "thread.createdAt"
        )
        updated_at = _optional_bounded_integer(
            thread.get("updatedAt"), "thread.updatedAt"
        )
        if created_at is None or updated_at is None or updated_at < created_at:
            raise ProviderError("Codex thread timestamps are missing or inconsistent")
        session_id = _require_protocol_id(thread.get("sessionId"), "thread.sessionId")
        status = _require_object(thread.get("status"), "thread.status")
        _require_exact_keys(status, "thread.status", required={"type"})
        if status != {"type": "idle"} or thread.get("preview") != "":
            raise ProviderError("Codex thread was not fresh and idle")
        if (
            thread.get("historyMode") != "paginated"
            or thread.get("path") is not None
            or any(
                thread.get(key) is not None
                for key in (
                    "agentNickname",
                    "agentRole",
                    "forkedFromId",
                    "parentThreadId",
                )
            )
        ):
            raise ProviderError(
                "Codex thread has parent, agent, or persisted history state"
            )
        if (
            thread.get("ephemeral") is not True
            or thread.get("cwd") != str(self._workspace)
            or thread.get("turns") != []
            or thread.get("source") != "vscode"
            or thread.get("threadSource") != "skill-eval"
        ):
            raise ProviderError(
                "Codex thread provenance differs from the isolated request"
            )
        thread_id = _require_protocol_id(thread.get("id"), "thread.id")
        if self._announced_thread_id not in {None, thread_id}:
            raise ProviderError("Codex thread announcement disagrees with thread/start")
        self._session_id = session_id
        self._thread_id = thread_id

    def _start_turn(self, prompt: str, deadline: float) -> None:
        assert self._thread_id is not None
        result = _require_object(
            self._call(
                "turn/start",
                {
                    "approvalPolicy": "never",
                    "cwd": str(self._workspace),
                    "effort": self._reasoning_effort,
                    "input": [{"text": prompt, "type": "text"}],
                    "model": self._model,
                    "permissions": "eval",
                    "runtimeWorkspaceRoots": [str(self._workspace)],
                    "threadId": self._thread_id,
                },
                deadline,
                on_sent=self._on_dispatched,
            ),
            "turn/start",
        )
        turn = _require_object(result.get("turn"), "turn/start.turn")
        turn_id = _require_protocol_id(turn.get("id"), "turn.id")
        if self._announced_turn_id not in {None, turn_id}:
            raise ProviderError("Codex turn announcement disagrees with turn/start")
        self._turn_id = turn_id
        if turn.get("status") != "inProgress":
            raise ProviderError("Codex turn did not enter inProgress state")

    def _handle_notification(self, method: str, raw_params: Any) -> None:
        params = _require_object(raw_params, "notification params")
        if self._turn_completed is not None and (
            method.startswith(("item/", "model/", "turn/"))
            or method
            in {
                "error",
                "thread/started",
                "thread/status/changed",
                "thread/tokenUsage/updated",
            }
        ):
            raise ProviderError("Codex emitted turn traffic after root completion")
        if method == "model/rerouted":
            raise ProviderError("Codex rerouted the pinned model")
        if method == "error":
            _require_exact_keys(
                params,
                "error notification",
                required={"error", "threadId", "turnId", "willRetry"},
            )
            error = _require_object(params.get("error"), "error notification.error")
            _require_exact_keys(
                error,
                "error notification.error",
                required={"message"},
                optional={"additionalDetails", "codexErrorInfo"},
            )
            _require_string(error.get("message"), "error notification.error.message")
            additional_details = error.get("additionalDetails")
            if additional_details is not None and not isinstance(
                additional_details, str
            ):
                raise ProviderError(
                    "error notification additionalDetails must be a string or null"
                )
            error_info = error.get("codexErrorInfo")
            if isinstance(error_info, str):
                if error_info not in {
                    "badRequest",
                    "contextWindowExceeded",
                    "cyberPolicy",
                    "internalServerError",
                    "other",
                    "sandboxError",
                    "serverOverloaded",
                    "sessionBudgetExceeded",
                    "threadRollbackFailed",
                    "unauthorized",
                    "usageLimitExceeded",
                }:
                    raise ProviderError(
                        "error notification has unknown Codex error info"
                    )
            elif error_info is not None:
                info = _require_object(error_info, "error notification.codexErrorInfo")
                if len(info) != 1:
                    raise ProviderError(
                        "error notification has invalid Codex error info"
                    )
                variant, raw_info = next(iter(info.items()))
                variant_info = _require_object(
                    raw_info, f"error notification.codexErrorInfo.{variant}"
                )
                if variant in {
                    "httpConnectionFailed",
                    "responseStreamConnectionFailed",
                    "responseStreamDisconnected",
                    "responseTooManyFailedAttempts",
                }:
                    _require_exact_keys(
                        variant_info,
                        f"error notification.codexErrorInfo.{variant}",
                        required=set(),
                        optional={"httpStatusCode"},
                    )
                    _optional_bounded_integer(
                        variant_info.get("httpStatusCode"),
                        "error notification HTTP status",
                        maximum=65535,
                    )
                elif variant == "activeTurnNotSteerable":
                    _require_exact_keys(
                        variant_info,
                        "error notification active-turn error info",
                        required={"turnKind"},
                    )
                    if variant_info.get("turnKind") not in {"review", "compact"}:
                        raise ProviderError(
                            "error notification has unknown active turn kind"
                        )
                else:
                    raise ProviderError(
                        "error notification has unknown Codex error info"
                    )
            main_turn = self._matches_turn(params)
            if not main_turn and not self._matches_collab_turn(params):
                raise ProviderError("Codex error notification changed turn scope")
            will_retry = params.get("willRetry")
            if type(will_retry) is not bool:
                raise ProviderError("Codex error notification has invalid retry state")
            if will_retry or not main_turn:
                return
            raise ProviderError("Codex reported a turn error")
        if method == "account/rateLimits/updated":
            update = _sanitize_rate_snapshot(
                params.get("rateLimits"), "rate limit update"
            )
            if self._rate_limits is not None:
                self._rate_limits["rateLimits"] = _merge_sparse(
                    self._rate_limits.get("rateLimits"), update
                )
                limit_id = update.get("limit_id_sha256")
                by_id = self._rate_limits.get("rateLimitsByLimitId")
                if isinstance(limit_id, str) and isinstance(by_id, dict):
                    if limit_id not in by_id and len(by_id) >= _MAX_RATE_LIMIT_BUCKETS:
                        raise ProviderError("rate-limit bucket count exceeds the limit")
                    by_id[limit_id] = _merge_sparse(by_id.get(limit_id), update)
            return
        if method == "skills/changed":
            if not self._disabling_skills:
                raise ProviderError("Codex skill configuration changed after isolation")
            return
        if method == "remoteControl/status/changed":
            _require_exact_keys(
                params,
                "remote-control status",
                required={"installationId", "serverName", "status"},
                optional={"environmentId"},
            )
            _require_protocol_id(
                params.get("installationId"), "remote-control installation id"
            )
            server_name = _require_string(
                params.get("serverName"), "remote-control server name"
            )
            if (
                len(server_name) > 256
                or not server_name.isprintable()
                or params.get("status") != "disabled"
                or params.get("environmentId") is not None
            ):
                raise ProviderError("Codex remote control is not disabled")
            return
        if method == "thread/started":
            thread = _require_object(params.get("thread"), "thread/started.thread")
            announced = _require_protocol_id(
                thread.get("id"), "thread/started.thread.id"
            )
            if self._thread_id is not None and announced != self._thread_id:
                _require_exact_keys(
                    thread,
                    "child thread",
                    required={
                        "cliVersion",
                        "createdAt",
                        "cwd",
                        "ephemeral",
                        "id",
                        "modelProvider",
                        "preview",
                        "sessionId",
                        "source",
                        "status",
                        "turns",
                        "updatedAt",
                    },
                    optional={
                        "agentNickname",
                        "agentRole",
                        "canAcceptDirectInput",
                        "extra",
                        "forkedFromId",
                        "gitInfo",
                        "historyMode",
                        "isPinned",
                        "name",
                        "parentThreadId",
                        "path",
                        "recencyAt",
                        "threadSource",
                    },
                )
                for field in ("agentNickname", "agentRole", "name"):
                    value = thread.get(field)
                    if value is not None and not isinstance(value, str):
                        raise ProviderError(
                            f"child thread.{field} must be a string or null"
                        )
                direct_input = thread.get("canAcceptDirectInput")
                if direct_input is not None and type(direct_input) is not bool:
                    raise ProviderError(
                        "child thread.canAcceptDirectInput must be a bool or null"
                    )
                if "isPinned" in thread and type(thread["isPinned"]) is not bool:
                    raise ProviderError("child thread.isPinned must be a bool")
                if thread.get("extra") is not None:
                    _require_object(thread["extra"], "child thread.extra")
                git_info = thread.get("gitInfo")
                if git_info is not None:
                    git_info = _require_object(git_info, "child thread.gitInfo")
                    _require_exact_keys(
                        git_info,
                        "child thread.gitInfo",
                        required=set(),
                        optional={"branch", "originUrl", "sha"},
                    )
                    for field in ("branch", "originUrl", "sha"):
                        value = git_info.get(field)
                        if value is not None and not isinstance(value, str):
                            raise ProviderError(
                                f"child thread.gitInfo.{field} must be a string or null"
                            )
                _optional_bounded_integer(
                    thread.get("recencyAt"), "child thread.recencyAt"
                )
                if announced in self._validated_collab_thread_ids:
                    raise ProviderError("Codex announced a child thread more than once")
                created_at = _optional_bounded_integer(
                    thread.get("createdAt"), "child thread.createdAt"
                )
                updated_at = _optional_bounded_integer(
                    thread.get("updatedAt"), "child thread.updatedAt"
                )
                session_id = _require_protocol_id(
                    thread.get("sessionId"), "child thread.sessionId"
                )
                parent_id = _require_protocol_id(
                    thread.get("parentThreadId"), "child thread.parentThreadId"
                )
                source = _require_object(thread.get("source"), "child thread.source")
                _require_exact_keys(
                    source, "child thread.source", required={"subAgent"}
                )
                subagent = _require_object(
                    source.get("subAgent"), "child thread.source.subAgent"
                )
                _require_exact_keys(
                    subagent,
                    "child thread.source.subAgent",
                    required={"thread_spawn"},
                )
                spawn = _require_object(
                    subagent.get("thread_spawn"),
                    "child thread.source.subAgent.thread_spawn",
                )
                _require_exact_keys(
                    spawn,
                    "child thread.source.subAgent.thread_spawn",
                    required={"depth", "parent_thread_id"},
                    optional={"agent_nickname", "agent_path", "agent_role"},
                )
                for field in ("agent_nickname", "agent_path", "agent_role"):
                    value = spawn.get(field)
                    if value is not None and not isinstance(value, str):
                        raise ProviderError(
                            f"child thread.source {field} must be a string or null"
                        )
                source_parent_id = _require_protocol_id(
                    spawn.get("parent_thread_id"),
                    "child thread.source parent thread id",
                )
                bound_parent_id = self._collab_parent_ids.get(announced)
                parent_depth = (
                    0
                    if parent_id == self._thread_id
                    else self._collab_depths.get(parent_id)
                )
                depth = _optional_bounded_integer(
                    spawn.get("depth"),
                    "child thread.source depth",
                    minimum=1,
                    maximum=_MAX_COLLAB_THREADS,
                )
                self._validate_thread_status(
                    _require_object(thread.get("status"), "child thread.status"),
                    "child thread.status",
                )
                preview = thread.get("preview")
                if not isinstance(preview, str):
                    raise ProviderError("child thread.preview must be a string")
                if len(preview.encode("utf-8")) > _MAX_RETAINED_TEXT_BYTES:
                    raise ProviderError("child thread.preview exceeds the byte limit")
                if (
                    created_at is None
                    or updated_at is None
                    or updated_at < created_at
                    or depth is None
                    or parent_depth is None
                    or depth != parent_depth + 1
                    or self._session_id is None
                    or session_id != self._session_id
                    or parent_id != source_parent_id
                    or (bound_parent_id is not None and bound_parent_id != parent_id)
                    or (
                        parent_id != self._thread_id
                        and parent_id not in self._validated_collab_thread_ids
                    )
                    or thread.get("modelProvider") != "openai"
                    or thread.get("cliVersion") != self._locked_thread_cli_version
                    or thread.get("cwd") != str(self._workspace)
                    or thread.get("ephemeral") is not True
                    or thread.get("historyMode") != "paginated"
                    or thread.get("path") is not None
                    or thread.get("forkedFromId") is not None
                    or thread.get("threadSource") != "skill-eval"
                    or thread.get("turns") != []
                ):
                    raise ProviderError(
                        "Codex child thread provenance differs from the root request"
                    )
                if not (
                    any(
                        sender == parent_id and pending[0] in {None, announced}
                        for (
                            sender,
                            _item_id,
                        ), pending in self._pending_spawn_items.items()
                    )
                    or any(
                        spawn_tool == "spawnAgent"
                        and sender == parent_id
                        and spawn_status == "completed"
                        and spawn_receivers == (announced,)
                        for (
                            sender,
                            _item_id,
                        ), (
                            spawn_tool,
                            spawn_status,
                            spawn_receivers,
                            _agent_statuses,
                            _model,
                            _prompt_digest,
                            _reasoning_effort,
                        ) in self._terminal_collab_history.items()
                    )
                ):
                    raise ProviderError(
                        "Codex child thread lacked parent-owned spawn history"
                    )
                if not self._claim_collab_thread_scope(announced):
                    raise ProviderError("Codex thread announcement changed scope")
                self._validated_collab_thread_ids.add(announced)
                self._collab_parent_ids[announced] = parent_id
                self._collab_depths[announced] = depth
                return
            if self._announced_thread_id is not None:
                raise ProviderError("Codex announced more than one thread")
            self._announced_thread_id = announced
            return
        if method == "turn/started":
            thread_id = _require_protocol_id(
                params.get("threadId"), "turn/started.threadId"
            )
            turn = _require_object(params.get("turn"), "turn/started.turn")
            announced = _require_protocol_id(turn.get("id"), "turn/started.turn.id")
            if self._thread_id is None:
                raise ProviderError("Codex turn announcement changed thread scope")
            if thread_id != self._thread_id:
                if thread_id not in self._validated_collab_thread_ids:
                    raise ProviderError(
                        "Codex child turn preceded its provenance announcement"
                    )
                turns = self._collab_turn_ids.setdefault(thread_id, set())
                turn_scope = (thread_id, announced)
                if turn_scope in self._seen_collab_turn_ids:
                    raise ProviderError("Codex announced a child turn more than once")
                if len(self._seen_collab_turn_ids) >= _MAX_COLLAB_TURNS:
                    raise ProviderError("collaboration turn count exceeds the limit")
                turns.add(announced)
                self._seen_collab_turn_ids.add(turn_scope)
                return
            if self._announced_turn_id is not None:
                raise ProviderError("Codex announced more than one turn")
            self._announced_turn_id = announced
            return
        if method == "thread/tokenUsage/updated":
            main_turn = self._matches_turn(params)
            if not main_turn and not self._matches_collab_turn(params):
                raise ProviderError("Codex token usage targeted an unknown turn")
            usage = _require_object(params.get("tokenUsage"), "tokenUsage")
            last = _require_object(usage.get("last"), "tokenUsage.last")
            validated = self._validate_usage(last)
            if main_turn:
                self._last_usage = validated
            else:
                thread_id = _require_protocol_id(
                    params.get("threadId"), "tokenUsage.threadId"
                )
                turn_id = _require_protocol_id(
                    params.get("turnId"), "tokenUsage.turnId"
                )
                self._collab_turn_usage[(thread_id, turn_id)] = validated
            return
        if method == "item/completed":
            main_turn = self._matches_turn(params)
            if not main_turn and not self._matches_collab_turn(params):
                raise ProviderError("Codex item completion targeted an unknown turn")
            if (
                _optional_bounded_integer(
                    params.get("completedAtMs"),
                    "item/completed.completedAtMs",
                    minimum=-(2**63),
                )
                is None
            ):
                raise ProviderError("item/completed.completedAtMs is required")
            item = _require_object(params.get("item"), "item/completed.item")
            self._validate_item(
                item,
                owner_thread_id=_require_protocol_id(
                    params.get("threadId"), "item/completed.threadId"
                ),
                lifecycle="completed",
            )
            if not main_turn:
                return
            if item.get("type") == "agentMessage":
                if len(self._completed_messages) >= _MAX_COMPLETED_MESSAGES:
                    raise ProviderError(
                        "completed agent-message count exceeds the limit"
                    )
                text = _require_string(item.get("text"), "agent message text")
                text_bytes = len(text.encode("utf-8"))
                if self._retained_text_bytes + text_bytes > _MAX_RETAINED_TEXT_BYTES:
                    raise ProviderError("retained agent-message text exceeds the limit")
                self._retained_text_bytes += text_bytes
                self._completed_messages.append(
                    {
                        "id": _require_protocol_id(item.get("id"), "agent message id"),
                        "phase": self._validate_message_phase(item.get("phase")),
                        "text": text,
                    }
                )
            return
        if method == "item/started":
            if not self._matches_turn(params) and not self._matches_collab_turn(params):
                raise ProviderError("Codex item start targeted an unknown turn")
            if (
                _optional_bounded_integer(
                    params.get("startedAtMs"),
                    "item/started.startedAtMs",
                    minimum=-(2**63),
                )
                is None
            ):
                raise ProviderError("item/started.startedAtMs is required")
            self._validate_item(
                _require_object(params.get("item"), "item/started.item"),
                owner_thread_id=_require_protocol_id(
                    params.get("threadId"), "item/started.threadId"
                ),
                lifecycle="started",
            )
            return
        if method == "turn/completed":
            completed_thread_id = _require_protocol_id(
                params.get("threadId"), "turn/completed.threadId"
            )
            turn = _require_object(params.get("turn"), "turn/completed.turn")
            completed_turn_id = _require_protocol_id(
                turn.get("id"), "turn/completed.turn.id"
            )
            encoded_size = len(_canonical_json(turn, "turn/completed.turn"))
            if encoded_size > _MAX_RETAINED_TEXT_BYTES:
                raise ProviderError("completed turn exceeds the retained-byte limit")
            if self._thread_id is None:
                raise ProviderError("Codex completed an unknown thread")
            if completed_thread_id != self._thread_id:
                if completed_turn_id not in self._collab_turn_ids.get(
                    completed_thread_id, set()
                ):
                    raise ProviderError("Codex completed an unknown child turn")
                self._validate_completed_turn(turn, completed_thread_id)
                if (
                    completed_thread_id,
                    completed_turn_id,
                ) not in self._collab_turn_usage:
                    raise ProviderError("Codex child turn omitted token usage")
                self._collab_turn_ids[completed_thread_id].remove(completed_turn_id)
                self._active_collab_thread_ids.discard(completed_thread_id)
                return
            if self._turn_id is None or completed_turn_id != self._turn_id:
                raise ProviderError("Codex completed an unknown turn")
            if self._turn_completed is not None:
                raise ProviderError("Codex completed the same turn more than once")
            self._validate_completed_turn(turn, completed_thread_id)
            children_with_turns = {
                thread_id for thread_id, _turn_id in self._seen_collab_turn_ids
            }
            if (
                self._pending_spawn_items
                or self._active_nonspawn_items
                or any(self._collab_turn_ids.values())
                or self._active_collab_thread_ids
                or not self._collab_thread_ids <= children_with_turns
            ):
                raise ProviderError(
                    "Codex completed root turn with outstanding child work"
                )
            self._turn_completed = turn
            return
        if method in _IGNORED_NOTIFICATIONS:
            self._validate_ignored_notification_scope(method, params)
            return
        if method in _PROHIBITED_NOTIFICATIONS:
            raise ProviderError(f"prohibited Codex notification: {method}")
        raise ProviderError("unexpected Codex notification")

    def _validate_item(
        self,
        item: dict[str, Any],
        *,
        owner_thread_id: str | None = None,
        lifecycle: str | None = None,
    ) -> None:
        item_type = _require_string(item.get("type"), "thread item type")
        if item_type not in _ALLOWED_ITEM_TYPES:
            raise ProviderError("prohibited or unknown Codex item type")
        if item_type == "collabAgentToolCall":
            self._validate_collab_item(
                item,
                owner_thread_id=owner_thread_id,
                lifecycle=lifecycle,
            )
        elif item_type == "agentMessage":
            _require_exact_keys(
                item,
                "agent message",
                required={"id", "text", "type"},
                optional={"memoryCitation", "phase"},
            )
            _require_protocol_id(item.get("id"), "agent message id")
            if not isinstance(item.get("text"), str):
                raise ProviderError("agent message text must be a string")
            self._validate_message_phase(item.get("phase"))

    def _validate_collab_item(
        self,
        item: dict[str, Any],
        *,
        owner_thread_id: str | None,
        lifecycle: str | None,
    ) -> None:
        _require_exact_keys(
            item,
            "collaboration item",
            required={
                "agentsStates",
                "id",
                "receiverThreadIds",
                "senderThreadId",
                "status",
                "tool",
                "type",
            },
            optional={"model", "prompt", "reasoningEffort"},
        )
        item_id = _require_protocol_id(item.get("id"), "collaboration item id")
        sender = _require_protocol_id(
            item.get("senderThreadId"), "collaboration sender thread id"
        )
        if self._thread_id is None or (
            sender != self._thread_id and sender not in self._collab_thread_ids
        ):
            raise ProviderError("collaboration item changed sender thread scope")
        if owner_thread_id is not None and sender != owner_thread_id:
            raise ProviderError("collaboration item sender disagrees with its envelope")
        tool = _require_string(item.get("tool"), "collaboration tool")
        if tool not in {"spawnAgent", "sendInput", "resumeAgent", "wait", "closeAgent"}:
            raise ProviderError("collaboration tool is unknown")
        raw_receivers = _require_list(
            item.get("receiverThreadIds"),
            "collaboration receiver thread ids",
            maximum=_MAX_COLLAB_THREADS,
        )
        receivers = [
            _require_protocol_id(value, "collaboration receiver thread id")
            for value in raw_receivers
        ]
        if len(receivers) != len(set(receivers)) or (
            self._thread_id in receivers
            and (sender == self._thread_id or tool == "spawnAgent")
        ):
            raise ProviderError("collaboration receiver thread ids are invalid")
        if any(receiver in self._failed_collab_thread_ids for receiver in receivers):
            raise ProviderError("failed spawn child thread ID was reused")
        status = _require_string(item.get("status"), "collaboration item status")
        if status not in {"inProgress", "completed", "failed"}:
            raise ProviderError("collaboration item status is unknown")
        if lifecycle == "started" and status != "inProgress":
            raise ProviderError("started collaboration item is not in progress")
        if lifecycle in {"completed", "snapshot"} and status == "inProgress":
            raise ProviderError("completed collaboration item is still in progress")
        item_scope = (sender, item_id)
        if lifecycle != "snapshot" and item_scope in self._terminal_collab_item_ids:
            raise ProviderError("collaboration item ID was reused after termination")
        model = item.get("model")
        prompt = item.get("prompt")
        reasoning_effort = item.get("reasoningEffort")
        for field, value in (
            ("model", model),
            ("prompt", prompt),
            ("reasoningEffort", reasoning_effort),
        ):
            if value is not None and not isinstance(value, str):
                raise ProviderError(f"collaboration {field} must be a string or null")
        prompt_digest = (
            hashlib.sha256(prompt.encode("utf-8")).digest()
            if prompt is not None
            else None
        )
        spawn_placeholder = tool == "spawnAgent" and (
            lifecycle == "started"
            or (
                lifecycle in {"completed", "snapshot"}
                and status == "failed"
                and not receivers
            )
        )
        if spawn_placeholder:
            if model != "" or reasoning_effort != "medium":
                raise ProviderError("spawnAgent placeholder metadata is invalid")
        elif tool == "spawnAgent" and lifecycle == "completed":
            if model != self._model or reasoning_effort != self._reasoning_effort:
                raise ProviderError("terminal spawnAgent metadata is invalid")
        elif reasoning_effort == "":
            raise ProviderError(
                "collaboration reasoningEffort must be a non-empty string or null"
            )
        elif model not in {None, self._model}:
            raise ProviderError("collaboration model differs from the pinned model")
        elif reasoning_effort not in {None, self._reasoning_effort}:
            raise ProviderError(
                "collaboration reasoningEffort differs from the pinned reasoning effort"
            )
        states = _require_object(item.get("agentsStates"), "collaboration agent states")
        if len(states) > _MAX_COLLAB_THREADS:
            raise ProviderError("collaboration agent-state count exceeds the limit")
        agent_statuses: dict[str, str] = {}
        for raw_thread_id, raw_state in states.items():
            thread_id = _require_protocol_id(
                raw_thread_id, "collaboration agent-state thread id"
            )
            if thread_id not in receivers:
                raise ProviderError("collaboration state targeted an unknown receiver")
            state = _require_object(raw_state, "collaboration agent state")
            _require_exact_keys(
                state,
                "collaboration agent state",
                required={"status"},
                optional={"message"},
            )
            agent_status = _require_string(
                state.get("status"), "collaboration agent status"
            )
            if agent_status not in {
                "pendingInit",
                "running",
                "interrupted",
                "completed",
                "errored",
                "shutdown",
                "notFound",
            }:
                raise ProviderError("collaboration agent status is unknown")
            agent_statuses[thread_id] = agent_status
            message = state.get("message")
            if message is not None:
                if (
                    len(
                        _require_string(message, "collaboration agent message").encode(
                            "utf-8"
                        )
                    )
                    > _MAX_RETAINED_TEXT_BYTES
                ):
                    raise ProviderError("collaboration agent message exceeds the limit")
        terminal_item = (
            tool,
            status,
            tuple(receivers),
            tuple(sorted(agent_statuses.items())),
            model,
            prompt_digest,
            reasoning_effort,
        )
        if (
            lifecycle == "snapshot"
            and self._terminal_collab_history.get(item_scope) != terminal_item
        ):
            raise ProviderError(
                "collaboration snapshot lacked matching live terminal history"
            )
        active_nonspawn_item = self._active_nonspawn_items.get(item_scope)
        if tool != "spawnAgent" and lifecycle == "started":
            if active_nonspawn_item is not None:
                raise ProviderError("collaboration item was already in progress")
        elif tool != "spawnAgent" and lifecycle == "completed":
            if active_nonspawn_item is None:
                raise ProviderError("collaboration item completed without a start")
            if active_nonspawn_item != (tool, tuple(receivers)):
                raise ProviderError(
                    "terminal collaboration item disagreed with its start"
                )
        if tool == "spawnAgent":
            if lifecycle == "started" and receivers:
                raise ProviderError("spawnAgent start must not have receivers")
            if status == "completed" and len(receivers) != 1:
                raise ProviderError(
                    "completed spawnAgent must have exactly one receiver"
                )
            if len(receivers) > 1:
                raise ProviderError("spawnAgent must have at most one receiver")
            pending_key = (sender, item_id)
            pending = pending_key in self._pending_spawn_items
            expected_receiver, expected_prompt_digest = self._pending_spawn_items.get(
                pending_key, (None, None)
            )
            if status == "inProgress" and pending:
                raise ProviderError("spawnAgent item was already in progress")
            if (
                lifecycle == "completed"
                and pending
                and prompt_digest != expected_prompt_digest
            ):
                raise ProviderError(
                    "terminal spawnAgent prompt disagreed with its start"
                )
            if expected_receiver is not None and receivers != [expected_receiver]:
                raise ProviderError(
                    "spawnAgent receiver did not match its pending child thread"
                )
            unbound_slots = sum(
                receiver is None
                for receiver, _prompt_digest in self._pending_spawn_items.values()
            )
            receiver = receivers[0] if receivers else None
            failed_reservation = None
            if (
                status == "failed"
                and receiver is None
                and expected_receiver is None
                and self._unbound_collab_thread_ids
            ):
                if unbound_slots != 1 or len(self._unbound_collab_thread_ids) != 1:
                    raise ProviderError(
                        "receiver-less spawn failure had ambiguous child scope"
                    )
                failed_reservation = next(iter(self._unbound_collab_thread_ids))
            if (
                lifecycle == "snapshot"
                and status == "completed"
                and receiver not in self._collab_thread_ids
            ):
                raise ProviderError(
                    "spawnAgent snapshot lacked matching live terminal history"
                )
            if lifecycle != "snapshot" and status != "failed":
                for claimed_receiver in receivers:
                    parent_id = self._collab_parent_ids.get(claimed_receiver)
                    if parent_id is not None and parent_id != sender:
                        raise ProviderError(
                            "spawnAgent receiver parent disagrees with its spawning sender"
                        )
            if (
                status == "failed"
                and receiver is not None
                and (
                    receiver in self._validated_collab_thread_ids
                    or receiver in self._active_collab_thread_ids
                    or self._collab_turn_ids.get(receiver)
                )
            ):
                raise ProviderError("failed spawn retained an active child")
            if (
                lifecycle != "snapshot"
                and status != "inProgress"
                and pending
                and expected_receiver is None
            ):
                if status == "failed" and receiver is None:
                    pass
                elif receiver in self._unbound_collab_thread_ids:
                    self._bind_unbound_collab_thread(receiver, sender)
                elif receiver is not None and receiver in self._collab_thread_ids:
                    raise ProviderError("spawnAgent receiver was already claimed")
                elif len(self._unbound_collab_thread_ids) >= unbound_slots:
                    raise ProviderError(
                        "spawnAgent receiver did not match a pending child thread"
                    )
            elif not pending and status != "inProgress" and lifecycle != "snapshot":
                raise ProviderError("spawnAgent completed without a pending child")
            new_receivers = set(receivers) - self._collab_thread_ids
            if len(self._collab_thread_ids) + len(new_receivers) > _MAX_COLLAB_THREADS:
                raise ProviderError("collaboration thread count exceeds the limit")
            if lifecycle == "snapshot":
                pass
            elif status == "inProgress":
                if any(receiver in self._collab_thread_ids for receiver in receivers):
                    raise ProviderError("spawnAgent receiver was already claimed")
                if len(self._pending_spawn_items) >= _MAX_COLLAB_THREADS:
                    raise ProviderError("pending spawn count exceeds the limit")
                self._pending_spawn_items[pending_key] = (receiver, prompt_digest)
            else:
                self._pending_spawn_items.pop(pending_key, None)
            if lifecycle == "snapshot":
                pass
            elif status == "failed":
                failed_receivers = set(receivers)
                if failed_reservation is not None:
                    failed_receivers.add(failed_reservation)
                for failed_receiver in failed_receivers:
                    self._failed_collab_thread_ids.add(failed_receiver)
                    self._unbound_collab_thread_ids.discard(failed_receiver)
                    self._collab_thread_ids.discard(failed_receiver)
                    self._active_collab_thread_ids.discard(failed_receiver)
                    self._collab_parent_ids.pop(failed_receiver, None)
            else:
                for claimed_receiver in receivers:
                    self._collab_parent_ids[claimed_receiver] = sender
                self._collab_thread_ids.update(receivers)
        elif any(
            receiver != self._thread_id and receiver not in self._collab_thread_ids
            for receiver in receivers
        ):
            raise ProviderError("collaboration item targeted an unknown child thread")
        if lifecycle != "snapshot":
            for thread_id, agent_status in agent_statuses.items():
                if (
                    thread_id == self._thread_id
                    or thread_id not in self._collab_thread_ids
                ):
                    continue
                if agent_status in {"pendingInit", "running"}:
                    child_has_completed_turn = any(
                        seen_thread_id == thread_id
                        for seen_thread_id, _turn_id in self._seen_collab_turn_ids
                    ) and not self._collab_turn_ids.get(thread_id)
                    if not (
                        tool == "spawnAgent"
                        and lifecycle == "completed"
                        and child_has_completed_turn
                    ):
                        self._active_collab_thread_ids.add(thread_id)
                else:
                    self._active_collab_thread_ids.discard(thread_id)
            if (
                lifecycle == "completed"
                and tool in {"sendInput", "resumeAgent"}
                and status == "completed"
            ):
                self._active_collab_thread_ids.update(
                    receiver
                    for receiver in receivers
                    if receiver != self._thread_id
                    and receiver in self._collab_thread_ids
                    and receiver not in agent_statuses
                )
        if lifecycle != "snapshot" and status in {"completed", "failed"}:
            if len(self._terminal_collab_item_ids) >= _MAX_MESSAGES:
                raise ProviderError(
                    "terminal collaboration item count exceeds the limit"
                )
            self._terminal_collab_item_ids.add(item_scope)
            self._terminal_collab_history[item_scope] = terminal_item
        if lifecycle == "started" and tool != "spawnAgent":
            if (
                item_scope not in self._active_nonspawn_items
                and len(self._active_nonspawn_items) >= _MAX_MESSAGES
            ):
                raise ProviderError("active collaboration item count exceeds the limit")
            self._active_nonspawn_items[item_scope] = (tool, tuple(receivers))
        elif lifecycle == "completed" and tool != "spawnAgent":
            self._active_nonspawn_items.pop(item_scope, None)

    def _validate_completed_turn(
        self, turn: dict[str, Any], owner_thread_id: str
    ) -> None:
        status = _require_string(turn.get("status"), "completed turn status")
        if status not in {"completed", "interrupted", "failed"}:
            raise ProviderError("completed turn has a non-terminal status")
        items = _require_list(
            turn.get("items"), "completed turn items", maximum=_MAX_MESSAGES
        )
        items_view = _require_string(turn.get("itemsView"), "completed turn itemsView")
        if items_view not in {"full", "notLoaded", "summary"}:
            raise ProviderError("completed turn returned an unsupported item view")
        if items_view == "notLoaded" and items:
            raise ProviderError("Codex not-loaded turn items must be empty")
        for index, raw_item in enumerate(items):
            self._validate_item(
                _require_object(raw_item, f"turn.items[{index}]"),
                owner_thread_id=owner_thread_id,
                lifecycle="snapshot",
            )

    @staticmethod
    def _validate_message_phase(value: Any) -> str | None:
        if value is None or value in {"commentary", "final_answer"}:
            return value
        raise ProviderError("agent message has an unknown phase")

    def _matches_turn(self, params: dict[str, Any]) -> bool:
        thread_id = _require_protocol_id(
            params.get("threadId"), "notification.threadId"
        )
        turn_id = _require_protocol_id(params.get("turnId"), "notification.turnId")
        return (
            self._thread_id is not None
            and self._turn_id is not None
            and thread_id == self._thread_id
            and turn_id == self._turn_id
        )

    def _claim_collab_thread_scope(self, thread_id: str) -> bool:
        if thread_id in self._failed_collab_thread_ids:
            raise ProviderError("failed spawn child thread ID was reused")
        if thread_id in self._collab_thread_ids:
            return True
        open_spawn_slots = sum(
            receiver is None
            for receiver, _prompt_digest in self._pending_spawn_items.values()
        )
        if len(self._unbound_collab_thread_ids) >= open_spawn_slots:
            return False
        if len(self._collab_thread_ids) >= _MAX_COLLAB_THREADS:
            raise ProviderError("collaboration thread count exceeds the limit")
        self._unbound_collab_thread_ids.add(thread_id)
        self._collab_thread_ids.add(thread_id)
        return True

    def _bind_unbound_collab_thread(self, thread_id: str, sender: str) -> None:
        parent_id = self._collab_parent_ids.get(thread_id)
        if parent_id is not None and parent_id != sender:
            raise ProviderError(
                "spawnAgent receiver parent disagrees with its spawning sender"
            )
        self._collab_parent_ids[thread_id] = sender
        self._unbound_collab_thread_ids.remove(thread_id)

    def _matches_collab_turn(self, params: dict[str, Any]) -> bool:
        thread_id = _require_protocol_id(
            params.get("threadId"), "collaboration notification.threadId"
        )
        turn_id = _require_protocol_id(
            params.get("turnId"), "collaboration notification.turnId"
        )
        return turn_id in self._collab_turn_ids.get(thread_id, set())

    def _validate_ignored_notification_scope(
        self, method: str, params: dict[str, Any]
    ) -> None:
        if method.startswith(("item/", "turn/", "model/")):
            if not self._matches_turn(params) and not self._matches_collab_turn(params):
                raise ProviderError(f"{method} omitted or changed turn scope")
            return
        if method == "thread/status/changed":
            _require_exact_keys(
                params,
                "thread/status/changed",
                required={"status", "threadId"},
            )
            thread_id = _require_protocol_id(
                params.get("threadId"), "thread/status/changed.threadId"
            )
            status_type = self._validate_thread_status(
                _require_object(params.get("status"), "thread/status/changed.status"),
                "thread/status/changed.status",
            )
            if self._thread_id is None:
                raise ProviderError("thread/status/changed changed thread scope")
            if (
                thread_id != self._thread_id
                and thread_id not in self._collab_thread_ids
            ):
                if not self._claim_collab_thread_scope(thread_id):
                    raise ProviderError("thread/status/changed changed thread scope")
            if thread_id != self._thread_id:
                if status_type == "active":
                    self._active_collab_thread_ids.add(thread_id)
                else:
                    self._active_collab_thread_ids.discard(thread_id)
            return
        thread_id = params.get("threadId")
        turn_id = params.get("turnId")
        if thread_id is not None and self._thread_id is not None:
            if _require_protocol_id(thread_id, f"{method}.threadId") != self._thread_id:
                raise ProviderError(f"{method} targeted an unknown thread")
        if turn_id is not None and self._turn_id is not None:
            if _require_protocol_id(turn_id, f"{method}.turnId") != self._turn_id:
                raise ProviderError(f"{method} targeted an unknown turn")

    @staticmethod
    def _validate_thread_status(status: dict[str, Any], label: str) -> str:
        status_type = _require_string(status.get("type"), f"{label}.type")
        if status_type == "active":
            _require_exact_keys(
                status,
                label,
                required={"activeFlags", "type"},
            )
            flags = _require_list(
                status.get("activeFlags"),
                f"{label}.activeFlags",
                maximum=2,
            )
            if any(
                _require_string(flag, "thread active flag")
                not in {"waitingOnApproval", "waitingOnUserInput"}
                for flag in flags
            ):
                raise ProviderError("thread status has an unknown active flag")
        elif status_type in {"notLoaded", "idle", "systemError"}:
            _require_exact_keys(status, label, required={"type"})
        else:
            raise ProviderError("thread status is unknown")
        return status_type

    @staticmethod
    def _validate_usage(raw: dict[str, Any]) -> dict[str, int]:
        mapping = {
            "cachedInputTokens": "cached_input_tokens",
            "inputTokens": "input_tokens",
            "outputTokens": "output_tokens",
            "reasoningOutputTokens": "reasoning_output_tokens",
            "totalTokens": "total_tokens",
        }
        if set(raw) != set(mapping):
            raise ProviderError("last-turn token usage has an unexpected shape")
        result: dict[str, int] = {}
        for source, target in mapping.items():
            value = raw[source]
            if isinstance(value, bool) or not isinstance(value, int) or value < 0:
                raise ProviderError(
                    "last-turn token usage must be non-negative integers"
                )
            result[target] = value
        if result["total_tokens"] < result["input_tokens"] + result["output_tokens"]:
            raise ProviderError("last-turn total token usage is inconsistent")
        return result

    def _finalize_turn(self) -> tuple[str, dict[str, Any]]:
        assert self._turn_completed is not None
        turn = self._turn_completed
        if turn.get("status") != "completed":
            raise ProviderError("Codex turn did not complete successfully")
        if turn.get("error") is not None:
            raise ProviderError("completed Codex turn included an error")
        items = _require_list(turn.get("items"), "turn.items", maximum=_MAX_MESSAGES)
        items_view = _require_string(turn.get("itemsView"), "turn.itemsView")
        messages: list[dict[str, str | None]]
        if items_view == "notLoaded":
            if items:
                raise ProviderError("Codex not-loaded turn items must be empty")
            messages = list(self._completed_messages)
        elif items_view in {"full", "summary"}:
            messages = []
            for index, raw_item in enumerate(items):
                item = _require_object(raw_item, f"turn.items[{index}]")
                self._validate_item(
                    item,
                    owner_thread_id=self._thread_id,
                    lifecycle="snapshot",
                )
                if item.get("type") == "agentMessage":
                    messages.append(
                        {
                            "id": _require_protocol_id(
                                item.get("id"), "agent message id"
                            ),
                            "phase": self._validate_message_phase(item.get("phase")),
                            "text": _require_string(
                                item.get("text"), "agent message text"
                            ),
                        }
                    )
            if items_view == "summary":
                if len(items) != 1 or len(messages) != 1:
                    raise ProviderError(
                        "Codex summary turn must contain one agent message"
                    )
                summary_index = next(
                    (
                        index
                        for index in range(len(self._completed_messages) - 1, -1, -1)
                        if str(self._completed_messages[index]["text"]).strip()
                    ),
                    None,
                )
                if summary_index is None:
                    summary_index = len(self._completed_messages) - 1
                if (
                    summary_index < 0
                    or messages[0] != self._completed_messages[summary_index]
                ):
                    raise ProviderError(
                        "Codex summary message disagrees with its completion event"
                    )
                messages = self._completed_messages[: summary_index + 1]
        else:
            raise ProviderError("Codex turn returned an unsupported item view")
        if not messages or not self._completed_messages:
            raise ProviderError("Codex turn omitted a completed final agent message")
        id_source = self._completed_messages if items_view == "summary" else messages
        message_ids = [message["id"] for message in id_source]
        if len(set(message_ids)) != len(message_ids):
            raise ProviderError("Codex turn repeated an agent-message id")
        if items_view == "full" and messages != self._completed_messages:
            raise ProviderError(
                "Codex agent-message sequence disagrees across completion events"
            )
        final_answers = [
            message for message in messages if message["phase"] == "final_answer"
        ]
        if len(final_answers) > 1:
            raise ProviderError("Codex turn emitted multiple final-answer messages")
        final_message = messages[-1]
        if final_message["phase"] == "commentary":
            raise ProviderError(
                "Codex turn ended with commentary instead of a final answer"
            )
        if final_answers and final_answers[0] is not final_message:
            raise ProviderError("Codex final-answer message was not terminal")
        if not str(final_message["text"]).strip():
            raise ProviderError("Codex final agent message was empty")
        duration_ms = _optional_bounded_integer(
            turn.get("durationMs"), "turn.durationMs", maximum=86_400_000
        )
        sanitized_turn = {
            "duration_ms": duration_ms,
            "final_message_id_sha256": _opaque_sha256(str(final_message["id"])),
            "final_message_phase": final_message["phase"],
            "items_view": items_view,
            "status": "completed",
        }
        return str(final_message["text"]), sanitized_turn


class _ProcessTransport:
    def __init__(
        self,
        command: tuple[str, ...],
        cwd: Path,
        environment: dict[str, str],
        unit_name: str,
        *,
        on_gate_ready: Callable[[dict[str, Any]], None] | None = None,
        on_started: Callable[[dict[str, Any]], None] | None = None,
        on_unit_active: Callable[[dict[str, Any]], None] | None = None,
    ) -> None:
        self._unit_name = unit_name
        self._systemctl = str(_resolve_system_tool("systemctl"))
        gate_shell, gate_shell_identity = _resolve_gate_shell()
        self._buffer = bytearray()
        self._stderr = bytearray()
        self._stderr_overflow = False
        self._closed = False
        self._control_group: str | None = None
        self._gate_write_fd: int | None = None
        self._stderr_thread: threading.Thread | None = None
        try:
            gate_read_fd, gate_write_fd = os.pipe2(os.O_CLOEXEC)
        except OSError as exc:
            raise ProviderError("cannot create the Codex launch gate") from exc
        self._gate_write_fd = gate_write_fd
        process_started = False
        try:
            gate_command = (
                str(gate_shell),
                "--noprofile",
                "--norc",
                "-c",
                _LAUNCH_GATE_SCRIPT,
                "codex-launch-gate",
                str(gate_read_fd),
                *command,
            )
            gate_executable = [str(gate_shell), *gate_shell_identity]
            self.evidence = {
                "command_sha256": _command_sha256(command),
                "enforced": True,
                "gate_command_sha256": _command_sha256(gate_command),
                "gate_executable": gate_executable,
                "kind": "systemd-run-user+codex-permission-profile",
                "permission_profile": "eval",
                "unit": unit_name,
            }
            if on_gate_ready is not None:
                on_gate_ready(dict(self.evidence))
            try:
                self._process = subprocess.Popen(
                    gate_command,
                    executable=str(gate_shell),
                    cwd=cwd,
                    env=environment,
                    stdin=subprocess.PIPE,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                    start_new_session=True,
                    shell=False,
                    pass_fds=(gate_read_fd,),
                )
                process_started = True
            except OSError as exc:
                raise ProviderError(
                    "cannot launch the gated Codex app-server sandbox"
                ) from exc
        finally:
            try:
                os.close(gate_read_fd)
            except OSError:
                pass
            if not process_started:
                self._close_gate_writer()
        try:
            self.evidence["launcher_pid"] = self._process.pid
            launcher_start_time = _linux_process_start_time(self._process.pid)
            if launcher_start_time is None:
                raise ProviderError("cannot attest the Codex gate launcher identity")
            self.evidence["launcher_start_time_ticks"] = launcher_start_time
            _attest_process_executable(
                self._process.pid, gate_shell, gate_shell_identity
            )
            if on_started is not None:
                on_started(dict(self.evidence))
            if (
                self._process.stdin is None
                or self._process.stdout is None
                or self._process.stderr is None
            ):
                raise ProviderError("Codex app-server pipes were not created")
            self._stdin_fd = self._process.stdin.fileno()
            self._stdout_fd = self._process.stdout.fileno()
            os.set_blocking(self._stdin_fd, False)
            os.set_blocking(self._stdout_fd, False)
            self._stderr_thread = threading.Thread(
                target=self._drain_stderr,
                name="codex-app-server-stderr",
                daemon=True,
            )
            self._stderr_thread.start()
            self._release_gate()
            self._confirm_active_unit()
            if on_unit_active is not None:
                on_unit_active(dict(self.evidence))
        except BaseException as startup_error:
            self._close_gate_writer()
            try:
                self.close()
            except BaseException as cleanup_error:
                startup_error.add_note(
                    f"Codex constructor rollback also failed: {cleanup_error}"
                )
            raise

    def _close_gate_writer(self) -> None:
        descriptor = getattr(self, "_gate_write_fd", None)
        self._gate_write_fd = None
        if descriptor is not None:
            try:
                os.close(descriptor)
            except OSError:
                pass

    def _release_gate(self) -> None:
        descriptor = self._gate_write_fd
        if descriptor is None:
            raise ProviderError("Codex launch gate is unavailable")
        try:
            _write_all(descriptor, _LAUNCH_GATE_TOKEN, "Codex launch gate")
        except OSError as exc:
            raise ProviderError("cannot release Codex launch gate") from exc
        finally:
            self._close_gate_writer()

    def _confirm_active_unit(self) -> None:
        deadline = time.monotonic() + 5
        last_state = "unavailable"
        properties = {"ActiveState", "ControlGroup", "KillMode", "LoadState", "Type"}
        while True:
            try:
                states = _show_unit(
                    self._systemctl, self._unit_name, properties, timeout=1
                )
            except ProviderError:
                states = None
            if states is not None:
                state = tuple(
                    states[key]
                    for key in ("LoadState", "ActiveState", "Type", "KillMode")
                )
                last_state = "/".join(state)
                if state == ("loaded", "active", "exec", "control-group"):
                    control_group = _validate_control_group(
                        states["ControlGroup"],
                        "Codex active unit control group",
                        allow_empty=False,
                    )
                    self._control_group = control_group
                    self.evidence.update(
                        control_group=control_group,
                        launch_confirmed=True,
                        unit_state_after_launch=last_state,
                    )
                    return
            if self._process.poll() is not None or time.monotonic() >= deadline:
                self.evidence["launch_confirmed"] = False
                self.evidence["unit_state_after_launch"] = last_state
                raise ProviderError("Codex app-server unit did not become active")
            time.sleep(0.05)

    def _drain_stderr(self) -> None:
        assert self._process.stderr is not None
        while True:
            try:
                chunk = os.read(self._process.stderr.fileno(), 16 * 1024)
            except OSError:
                return
            if not chunk:
                return
            remaining = 64 * 1024 - len(self._stderr)
            if remaining > 0:
                self._stderr.extend(chunk[:remaining])
            if len(chunk) > remaining:
                self._stderr_overflow = True

    def send(self, payload: bytes, deadline: float) -> None:
        view = memoryview(payload)
        with selectors.DefaultSelector() as selector:
            selector.register(self._stdin_fd, selectors.EVENT_WRITE)
            while view:
                events = selector.select(_remaining(deadline, "Codex protocol write"))
                if not events:
                    raise ProviderTimeoutError("Codex protocol write timed out")
                try:
                    written = os.write(self._stdin_fd, view)
                except BlockingIOError:
                    continue
                except (BrokenPipeError, OSError) as exc:
                    raise ProviderError("Codex app-server closed its input") from exc
                if written <= 0:
                    raise ProviderError("Codex protocol write made no progress")
                view = view[written:]

    def receive(self, deadline: float) -> bytes:
        with selectors.DefaultSelector() as selector:
            selector.register(self._stdout_fd, selectors.EVENT_READ)
            while True:
                newline = self._buffer.find(b"\n")
                if newline >= 0:
                    if newline > _MAX_FRAME_BYTES:
                        raise ProviderError(
                            "Codex protocol frame exceeds the byte limit"
                        )
                    frame = bytes(self._buffer[:newline])
                    del self._buffer[: newline + 1]
                    if not frame:
                        raise ProviderError("Codex protocol emitted an empty frame")
                    return frame
                if len(self._buffer) > _MAX_FRAME_BYTES:
                    raise ProviderError("Codex protocol frame exceeds the byte limit")
                events = selector.select(_remaining(deadline, "Codex protocol read"))
                if not events:
                    raise ProviderTimeoutError("Codex protocol read timed out")
                try:
                    chunk = os.read(self._stdout_fd, 64 * 1024)
                except BlockingIOError:
                    continue
                except OSError as exc:
                    raise ProviderError("cannot read Codex protocol output") from exc
                if not chunk:
                    code = self._process.poll()
                    digest = hashlib.sha256(self._stderr).hexdigest()
                    raise ProviderError(
                        "Codex app-server closed protocol output "
                        f"(exit={code}, stderr_sha256={digest})"
                    )
                self._buffer.extend(chunk)

    def close(self) -> None:
        if self._closed:
            return
        self._closed = True
        self._close_gate_writer()
        pipe_close_errors: list[str] = []
        try:
            if self._process.stdin is not None:
                self._process.stdin.close()
        except (OSError, ValueError) as exc:
            pipe_close_errors.append(f"stdin:{type(exc).__name__}")
        control_actions: list[dict[str, int | str | None]] = []

        def control(action: str, *arguments: str) -> int | None:
            try:
                completed = subprocess.run(
                    [self._systemctl, "--user", action, *arguments, self._unit_name],
                    capture_output=True,
                    text=True,
                    timeout=5,
                    check=False,
                    shell=False,
                )
            except (OSError, subprocess.TimeoutExpired) as exc:
                control_actions.append(
                    {"action": action, "error": type(exc).__name__, "returncode": None}
                )
                return None
            control_actions.append(
                {"action": action, "error": None, "returncode": completed.returncode}
            )
            return completed.returncode

        stop_returncode = control("stop")
        if stop_returncode != 0:
            control("kill", "--kill-whom=all", "--signal=KILL")
            control("stop")
        process_reaped = False
        try:
            self._process.wait(timeout=5)
            process_reaped = True
        except (OSError, subprocess.TimeoutExpired):
            control("kill", "--kill-whom=all", "--signal=KILL")
            control("stop")
            try:
                self._process.terminate()
            except OSError:
                pass
            try:
                self._process.wait(timeout=3)
                process_reaped = True
            except (OSError, subprocess.TimeoutExpired):
                try:
                    self._process.kill()
                except OSError:
                    pass
                try:
                    self._process.wait(timeout=3)
                    process_reaped = True
                except (OSError, subprocess.TimeoutExpired):
                    process_reaped = False
        unit_state = "unchecked"
        state_confirmed = False
        unit_probe = _SystemdRecoveryProbe(systemctl=self._systemctl)
        for wait_seconds in (1, 5):
            try:
                unit_state = unit_probe.confirm_unit_clean(
                    self._unit_name,
                    getattr(self, "_control_group", None),
                    time.monotonic() + wait_seconds,
                )
                state_confirmed = True
                break
            except ProviderError:
                if wait_seconds == 1:
                    control("kill", "--kill-whom=all", "--signal=KILL")
                    control("stop")
        if not state_confirmed:
            unit_state = "unconfirmed"
        stderr_reaped = True
        if self._stderr_thread is not None:
            self._stderr_thread.join(timeout=2)
            stderr_reaped = not self._stderr_thread.is_alive()
        for name, pipe in (
            ("stdout", self._process.stdout),
            ("stderr", self._process.stderr),
        ):
            try:
                if pipe is not None:
                    pipe.close()
            except (OSError, ValueError) as exc:
                pipe_close_errors.append(f"{name}:{type(exc).__name__}")
        cleanup_confirmed = (
            state_confirmed
            and process_reaped
            and stderr_reaped
            and not pipe_close_errors
        )
        self.evidence["stderr_sha256"] = hashlib.sha256(self._stderr).hexdigest()
        self.evidence["stderr_truncated"] = self._stderr_overflow
        self.evidence["returncode"] = self._process.returncode
        self.evidence["stop_returncode"] = stop_returncode
        self.evidence["control_actions"] = control_actions
        self.evidence["process_reaped"] = process_reaped
        self.evidence["stderr_reaped"] = stderr_reaped
        self.evidence["pipe_close_errors"] = pipe_close_errors
        self.evidence["unit_state_after_cleanup"] = unit_state
        self.evidence["cleanup_confirmed"] = cleanup_confirmed
        if not cleanup_confirmed:
            raise ProviderError("Codex app-server unit cleanup could not be confirmed")


def _validate_private_directory(path: Path, label: str) -> Path:
    try:
        metadata = path.lstat()
    except OSError as exc:
        raise ProviderError(f"cannot inspect {label}: {exc}") from exc
    if (
        not stat.S_ISDIR(metadata.st_mode)
        or stat.S_ISLNK(metadata.st_mode)
        or metadata.st_uid != os.getuid()
        or stat.S_IMODE(metadata.st_mode) != _PRIVATE_DIRECTORY_MODE
    ):
        raise ProviderError(
            f"{label} must be a current-uid mode-0700 non-symlink directory"
        )
    return path


def _resolve_nonsymlink_directory(path: Path, label: str) -> Path:
    logical = Path(path)
    try:
        metadata = logical.lstat()
    except OSError as exc:
        raise ProviderError(f"cannot inspect {label}: {exc}") from exc
    if not stat.S_ISDIR(metadata.st_mode) or stat.S_ISLNK(metadata.st_mode):
        raise ProviderError(f"{label} must be a non-symlink directory")
    try:
        return logical.resolve(strict=True)
    except OSError as exc:
        raise ProviderError(f"cannot resolve {label}: {exc}") from exc


def _resolve_nonsymlink_executable(path: Path, label: str) -> Path:
    logical = Path(path)
    try:
        metadata = logical.lstat()
    except OSError as exc:
        raise ProviderError(f"cannot inspect {label}: {exc}") from exc
    if (
        not stat.S_ISREG(metadata.st_mode)
        or stat.S_ISLNK(metadata.st_mode)
        or not os.access(logical, os.X_OK)
    ):
        raise ProviderError(f"{label} must be an executable non-symlink regular file")
    try:
        return logical.resolve(strict=True)
    except OSError as exc:
        raise ProviderError(f"cannot resolve {label}: {exc}") from exc


def _resolve_bundle_executable(path: Path, label: str) -> Path:
    logical = Path(path).absolute()
    try:
        resolved = logical.resolve(strict=True)
        metadata = logical.lstat()
    except OSError as exc:
        raise ProviderError(f"cannot inspect {label}: {exc}") from exc
    if (
        resolved != logical
        or stat.S_ISLNK(metadata.st_mode)
        or not stat.S_ISREG(metadata.st_mode)
        or metadata.st_uid not in {0, os.getuid()}
        or stat.S_IMODE(metadata.st_mode) & 0o022
        or not os.access(logical, os.X_OK)
    ):
        raise ProviderError(
            f"{label} must be a trusted non-symlink executable regular file"
        )
    return logical


def _systemd_property_path(path: Path, label: str) -> str:
    value = str(path)
    if not path.is_absolute() or _SYSTEMD_PATH_RE.fullmatch(value) is None:
        raise ProviderError(f"{label} cannot be encoded in a systemd path property")
    return value


def _protect_home_covers(path: Path) -> bool:
    return any(
        path == root or path.is_relative_to(root)
        for root in (Path("/home"), Path("/root"), Path("/run/user"))
    )


def _private_tmp_covers(path: Path) -> bool:
    return any(
        path == root or path.is_relative_to(root)
        for root in (Path("/tmp"), Path("/var/tmp"))
    )


def _runtime_root() -> Path:
    parent = _validate_private_directory(
        Path(f"/run/user/{os.getuid()}"), "user runtime directory"
    )
    root = parent / "skill-eval-codex"
    try:
        root.mkdir(mode=_PRIVATE_DIRECTORY_MODE, exist_ok=True)
    except OSError as exc:
        raise ProviderError(f"cannot create Codex runtime root: {exc}") from exc
    return _validate_private_directory(root, "Codex runtime root")


def _validate_auth_file(path: Path) -> Path:
    try:
        metadata = path.lstat()
    except OSError as exc:
        raise ProviderError(f"cannot inspect Codex auth.json: {exc}") from exc
    _validate_auth_metadata(metadata)
    _sha256_file(path, maximum=_MAX_AUTH_BYTES, label="Codex auth.json")
    return path


def _validate_auth_metadata(metadata: os.stat_result) -> None:
    if (
        not stat.S_ISREG(metadata.st_mode)
        or stat.S_ISLNK(metadata.st_mode)
        or metadata.st_uid != os.getuid()
        or metadata.st_nlink != 1
        or stat.S_IMODE(metadata.st_mode) != _PRIVATE_FILE_MODE
        or metadata.st_size > _MAX_AUTH_BYTES
    ):
        raise ProviderError(
            "Codex auth.json must be a current-uid mode-0600 single-link regular file"
        )


def _assert_auth_path_matches_descriptor(
    path: Path, descriptor: int
) -> tuple[int, int]:
    try:
        descriptor_metadata = os.fstat(descriptor)
        path_metadata = path.lstat()
    except OSError as exc:
        raise ProviderError(f"cannot attest Codex auth.json identity: {exc}") from exc
    _validate_auth_metadata(path_metadata)
    descriptor_identity = descriptor_metadata.st_dev, descriptor_metadata.st_ino
    path_identity = path_metadata.st_dev, path_metadata.st_ino
    if path_identity != descriptor_identity:
        raise ProviderError("Codex auth.json pathname changed during invocation")
    _validate_auth_metadata(descriptor_metadata)
    return descriptor_identity


def _open_auth_descriptor(path: Path) -> int:
    flags = os.O_RDWR | os.O_CLOEXEC | getattr(os, "O_NOFOLLOW", 0)
    try:
        descriptor = os.open(path, flags)
    except OSError as exc:
        raise ProviderError(
            f"cannot open Codex auth.json for invocation: {exc}"
        ) from exc
    try:
        _assert_auth_path_matches_descriptor(path, descriptor)
    except BaseException:
        os.close(descriptor)
        raise
    return descriptor


@contextmanager
def _held_auth_descriptor(path: Path) -> Iterator[int]:
    descriptor = _open_auth_descriptor(path)
    try:
        yield descriptor
    finally:
        os.close(descriptor)


@contextmanager
def _owner_lock(
    lock_path: Path, deadline: float, label: str
) -> Iterator[tuple[int, int]]:
    flags = os.O_RDWR | os.O_CREAT | os.O_CLOEXEC | getattr(os, "O_NOFOLLOW", 0)
    try:
        descriptor = os.open(lock_path, flags, _PRIVATE_FILE_MODE)
    except OSError as exc:
        raise ProviderError(f"cannot open {label}: {exc}") from exc
    body_error: BaseException | None = None
    serialization_timeout: ProviderTimeoutError | None = None
    try:
        identity = _validate_owner_file_descriptor(lock_path, descriptor, label)
        while True:
            try:
                fcntl.flock(descriptor, fcntl.LOCK_EX | fcntl.LOCK_NB)
                break
            except BlockingIOError:
                try:
                    _remaining(deadline, f"{label} serialization")
                except ProviderTimeoutError as exc:
                    serialization_timeout = exc
                    break
                time.sleep(min(0.05, max(0.0, deadline - time.monotonic())))
        if serialization_timeout is None:
            identity = _validate_owner_file_descriptor(lock_path, descriptor, label)
            try:
                yield identity
            except BaseException as exc:
                body_error = exc
                raise
            finally:
                try:
                    _validate_owner_file_descriptor(lock_path, descriptor, label)
                except BaseException as exc:
                    if body_error is not None:
                        body_error.add_note(f"{label} integrity also failed: {exc}")
                    else:
                        raise
    finally:
        try:
            fcntl.flock(descriptor, fcntl.LOCK_UN)
        finally:
            os.close(descriptor)
    if serialization_timeout is not None:
        raise ProviderTimeoutError(
            str(serialization_timeout), cleanup_confirmed=True
        ) from serialization_timeout


@contextmanager
def _auth_lock(auth_path: Path, deadline: float) -> Iterator[None]:
    lock_path = auth_path.with_name(f"{auth_path.name}.skill-eval.lock")
    with _owner_lock(lock_path, deadline, "Codex auth lock"):
        yield


def _validate_owner_file_metadata(
    metadata: os.stat_result, label: str, maximum: int | None = None
) -> tuple[int, int]:
    if (
        not stat.S_ISREG(metadata.st_mode)
        or stat.S_ISLNK(metadata.st_mode)
        or metadata.st_uid != os.getuid()
        or metadata.st_nlink != 1
        or stat.S_IMODE(metadata.st_mode) != _PRIVATE_FILE_MODE
        or (maximum is not None and metadata.st_size > maximum)
    ):
        raise ProviderError(
            f"{label} must be a current-uid mode-0600 single-link regular file"
        )
    return metadata.st_dev, metadata.st_ino


def _validate_owner_file_descriptor(
    path: Path, descriptor: int, label: str
) -> tuple[int, int]:
    try:
        descriptor_metadata = os.fstat(descriptor)
        path_metadata = path.lstat()
    except OSError as exc:
        raise ProviderError(f"cannot attest {label}: {exc}") from exc
    descriptor_identity = _validate_owner_file_metadata(descriptor_metadata, label)
    path_identity = _validate_owner_file_metadata(path_metadata, label)
    if descriptor_identity != path_identity:
        raise ProviderError(f"{label} pathname identity changed")
    return descriptor_identity


def _validate_poison_binding(value: Any) -> dict[str, int | str]:
    required = set(_PoisonBinding.__dataclass_fields__)
    if not isinstance(value, dict) or set(value) != required:
        raise ProviderError("Codex cleanup poison binding has an invalid schema")
    for key in required - {"protocol_lock_sha256", "runtime_mount"}:
        _plain_integer(value[key], f"cleanup poison binding.{key}")
    lock_sha256 = value["protocol_lock_sha256"]
    if not isinstance(lock_sha256, str) or _SHA256_RE.fullmatch(lock_sha256) is None:
        raise ProviderError("Codex cleanup poison protocol lock digest is invalid")
    runtime_mount = value["runtime_mount"]
    if (
        not isinstance(runtime_mount, str)
        or len(runtime_mount) > 4_096
        or not runtime_mount.startswith("/")
        or "\x00" in runtime_mount
    ):
        raise ProviderError("Codex cleanup poison runtime mount is invalid")
    return value


def _validate_cleanup_poison(value: dict[str, Any]) -> dict[str, Any]:
    required = {
        "binding",
        "command_sha256",
        "control_group",
        "gate_command_sha256",
        "gate_executable",
        "launcher_pid",
        "launcher_start_time_ticks",
        "schema_version",
        "unit_name",
    }
    if (
        not isinstance(value, dict)
        or set(value) != required
        or value.get("schema_version") != 1
    ):
        raise ProviderError("Codex cleanup poison has an invalid schema")
    _validate_poison_binding(value["binding"])
    command_sha256, gate_command_sha256 = (
        value["command_sha256"],
        value["gate_command_sha256"],
    )
    for digest, label in ((command_sha256, "command"), (gate_command_sha256, "gate")):
        if digest is not None and (
            not isinstance(digest, str) or _SHA256_RE.fullmatch(digest) is None
        ):
            raise ProviderError(f"Codex cleanup poison {label} digest is invalid")
    if command_sha256 is None:
        raise ProviderError("Codex cleanup poison command digest is invalid")
    gate_executable = value["gate_executable"]
    if (gate_command_sha256 is None) != (gate_executable is None):
        raise ProviderError("Codex cleanup poison gate identity is inconsistent")
    if gate_executable is not None:
        if not isinstance(gate_executable, list) or len(gate_executable) != 3:
            raise ProviderError("Codex cleanup poison gate executable is invalid")
        gate_path, gate_device, gate_inode = gate_executable
        if (
            not isinstance(gate_path, str)
            or not gate_path.startswith("/")
            or len(gate_path) > 4_096
            or "\x00" in gate_path
        ):
            raise ProviderError("Codex cleanup poison gate executable path is invalid")
        _plain_integer(gate_device, "cleanup poison gate executable device", minimum=0)
        _plain_integer(gate_inode, "cleanup poison gate executable inode", minimum=1)
    control_group = value["control_group"]
    if control_group is not None:
        control_group = _validate_control_group(
            control_group,
            "Codex cleanup poison control group",
            allow_empty=False,
        )
    unit_name = value["unit_name"]
    if not isinstance(unit_name, str) or _SYSTEMD_UNIT_RE.fullmatch(unit_name) is None:
        raise ProviderError("Codex cleanup poison unit name is invalid")
    launcher_pid, launcher_start_time = (
        value["launcher_pid"],
        value["launcher_start_time_ticks"],
    )
    for identity, label in (
        (launcher_pid, "PID"),
        (launcher_start_time, "start time"),
    ):
        if identity is not None:
            _plain_integer(identity, f"cleanup poison launcher {label}", minimum=1)
    if launcher_pid is None and launcher_start_time is not None:
        raise ProviderError("Codex cleanup poison launcher identity is inconsistent")
    if launcher_pid is not None and gate_command_sha256 is None:
        raise ProviderError("Codex cleanup poison launcher was not gate-bound")
    return value


class _SystemdRecoveryProbe:
    def __init__(
        self,
        *,
        systemctl: str | None = None,
        cgroup_root: Path = Path("/sys/fs/cgroup"),
    ) -> None:
        self._systemctl = systemctl or str(_resolve_system_tool("systemctl"))
        self._cgroup_root = cgroup_root

    def _cgroup_state(self, control_group: str) -> str:
        if not control_group:
            return "gone"
        relative = _validate_control_group(
            control_group, "Codex unit control group", allow_empty=False
        ).removeprefix("/")
        group = self._cgroup_root / relative
        try:
            metadata = group.lstat()
        except FileNotFoundError:
            return "gone"
        except OSError as exc:
            raise ProviderError("cannot inspect Codex unit cgroup") from exc
        if not stat.S_ISDIR(metadata.st_mode) or stat.S_ISLNK(metadata.st_mode):
            raise ProviderError("Codex unit cgroup is not a directory")

        def read_evidence(name: str) -> bytes:
            flags = os.O_RDONLY | os.O_CLOEXEC | getattr(os, "O_NOFOLLOW", 0)
            try:
                descriptor = os.open(group / name, flags)
                try:
                    payload = _read_bounded_descriptor(descriptor, 1024 * 1024)
                finally:
                    os.close(descriptor)
            except OSError as exc:
                raise ProviderError("cannot inspect Codex unit cgroup") from exc
            if len(payload) > 1024 * 1024:
                raise ProviderError("Codex unit cgroup evidence exceeds its bound")
            return payload

        process_payload = read_evidence("cgroup.procs")
        event_payload = read_evidence("cgroup.events")
        pairs = [line.split(maxsplit=1) for line in event_payload.splitlines()]
        if any(len(pair) != 2 for pair in pairs):
            raise ProviderError("Codex unit cgroup events are invalid")
        events = dict(pairs)
        if len(events) != len(pairs):
            raise ProviderError("Codex unit cgroup events are invalid")
        if events.get(b"populated") not in {b"0", b"1"}:
            raise ProviderError("Codex unit cgroup population state is invalid")
        return (
            "empty"
            if not process_payload.strip() and events[b"populated"] == b"0"
            else "populated"
        )

    def _observe(
        self, unit_name: str, captured_control_group: str | None
    ) -> _UnitCleanupState:
        properties = {"ActiveState", "ControlGroup", "KillMode", "LoadState"}
        values = _show_unit(self._systemctl, unit_name, properties)
        if values is None:
            raise ProviderError("Codex unit cleanup state is unavailable")
        current_group = _validate_control_group(
            values["ControlGroup"],
            "Codex unit control group",
            allow_empty=True,
        )
        groups = {
            group
            for group in (captured_control_group, current_group)
            if group is not None and group
        }
        group_states = {self._cgroup_state(group) for group in groups}
        cgroup_state = next(
            (state for state in ("populated", "empty") if state in group_states),
            "gone",
        )
        return (
            values["LoadState"],
            values["ActiveState"],
            values["KillMode"],
            cgroup_state,
        )

    @staticmethod
    def _clean(observation: _UnitCleanupState) -> bool:
        load_state, active_state, kill_mode, cgroup_state = observation
        unit_clean = (load_state, active_state, kill_mode) in {
            ("loaded", "failed", "control-group"),
            ("loaded", "inactive", "control-group"),
            ("not-found", "inactive", ""),
            ("not-found", "inactive", "control-group"),
        }
        return unit_clean and cgroup_state in {"empty", "gone"}

    def confirm_unit_clean(
        self,
        unit_name: str,
        captured_control_group: str | None,
        deadline: float,
    ) -> str:
        if captured_control_group is not None:
            _validate_control_group(
                captured_control_group,
                "captured Codex unit control group",
                allow_empty=False,
            )
        consecutive = 0
        last_state = "unavailable"
        while True:
            try:
                observation = self._observe(unit_name, captured_control_group)
            except ProviderError:
                consecutive = 0
                last_state = "unavailable"
            else:
                last_state = "/".join(value or "empty" for value in observation)
                consecutive = consecutive + 1 if self._clean(observation) else 0
                if consecutive >= 2:
                    return last_state
            if time.monotonic() >= deadline:
                raise ProviderError(f"Codex unit cleanup is not stable ({last_state})")
            time.sleep(0.05)

    def process_start_time(self, process_id: int) -> int | None:
        return _linux_process_start_time(process_id)

    def matching_command_pids(self, command_sha256: str) -> tuple[int, ...]:
        matches: list[int] = []
        inspected = 0
        try:
            entries = Path("/proc").iterdir()
            for entry in entries:
                if not entry.name.isdecimal():
                    continue
                inspected += 1
                if inspected > 65_536:
                    raise ProviderError("process-table recovery scan exceeds its bound")
                try:
                    metadata = entry.stat()
                    if metadata.st_uid != os.getuid():
                        continue
                    command_line = (entry / "cmdline").read_bytes()
                except OSError as exc:
                    if exc.errno in {errno.ENOENT, errno.ESRCH}:
                        continue
                    raise ProviderError(
                        "cannot scan local launchers during recovery"
                    ) from exc
                if not command_line:
                    continue
                if len(command_line) > 1024 * 1024:
                    raise ProviderError(
                        "local launcher command exceeds its recovery bound"
                    )
                arguments = tuple(
                    os.fsdecode(argument)
                    for argument in command_line.rstrip(b"\0").split(b"\0")
                )
                if _command_sha256(arguments) == command_sha256:
                    matches.append(int(entry.name))
        except OSError as exc:
            raise ProviderError(
                "cannot enumerate local launchers during recovery"
            ) from exc
        return tuple(matches)

    def host_mount_present(self, path: Path) -> bool:
        return _host_mount_present(path)


class _CleanupPoisonStore:
    # This state survives evaluator processes, not a reboot. A reboot also tears
    # down the per-user manager and its transient units.
    def __init__(self, root: Path) -> None:
        self._root = _validate_private_directory(root, "Codex coordination root")
        self.lock_path = self._root / _PROVIDER_LOCK_NAME
        self.marker_path = self._root / _CLEANUP_POISON_NAME

    @contextmanager
    def lock(self, deadline: float) -> Iterator[tuple[int, int]]:
        _validate_private_directory(self._root, "Codex coordination root")
        with _owner_lock(self.lock_path, deadline, "Codex provider lock") as identity:
            yield identity

    @staticmethod
    def _encode(poison: dict[str, Any]) -> bytes:
        encoded = (
            _canonical_json(_validate_cleanup_poison(poison), "Codex cleanup poison")
            + b"\n"
        )
        if len(encoded) > _MAX_POISON_BYTES:
            raise ProviderError("Codex cleanup poison exceeds its size limit")
        return encoded

    def _publish_new(self, payload: bytes) -> None:
        temporary = self._root / (f".{_CLEANUP_POISON_NAME}.{uuid.uuid4().hex}.tmp")
        flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_CLOEXEC
        flags |= getattr(os, "O_NOFOLLOW", 0)
        published = False
        try:
            descriptor = os.open(temporary, flags, _PRIVATE_FILE_MODE)
            try:
                os.fchmod(descriptor, _PRIVATE_FILE_MODE)
                _write_all(descriptor, payload, "cleanup poison")
                os.fsync(descriptor)
            finally:
                os.close(descriptor)
            os.link(temporary, self.marker_path, follow_symlinks=False)
            published = True
            try:
                os.unlink(temporary)
            except OSError as exc:
                try:
                    _fsync_private_directory(self._root)
                except OSError as sync_error:
                    exc.add_note(
                        f"directory sync also failed: {type(sync_error).__name__}"
                    )
                raise ProviderError(
                    "cannot finalize cleanup poison publication"
                ) from exc
            _fsync_private_directory(self._root)
        except OSError as exc:
            raise ProviderError("cannot publish Codex cleanup poison") from exc
        finally:
            if not published:
                try:
                    os.unlink(temporary)
                except FileNotFoundError:
                    pass
                except OSError:
                    pass

    def arm(self, binding: _PoisonBinding, unit_name: str, command_sha256: str) -> None:
        payload = self._encode(
            {
                "binding": binding.as_json(),
                "command_sha256": command_sha256,
                "control_group": None,
                "gate_command_sha256": None,
                "gate_executable": None,
                "launcher_pid": None,
                "launcher_start_time_ticks": None,
                "schema_version": 1,
                "unit_name": unit_name,
            }
        )
        self._publish_new(payload)

    def _identity(self) -> tuple[int, int]:
        try:
            metadata = self.marker_path.lstat()
        except OSError as exc:
            raise ProviderError("cannot re-attest Codex cleanup poison") from exc
        return _validate_owner_file_metadata(
            metadata, "Codex cleanup poison", _MAX_POISON_BYTES
        )

    def _replace(
        self, poison: dict[str, Any], marker_identity: tuple[int, int]
    ) -> None:
        if self._identity() != marker_identity:
            raise ProviderError("armed Codex cleanup poison identity changed")
        try:
            _write_private(
                self.marker_path,
                self._encode(poison),
                sync_parent=True,
            )
        except OSError as exc:
            raise ProviderError("cannot durably update cleanup poison") from exc
        observed = self._read()
        if observed is None or observed[0] != poison:
            raise ProviderError("armed Codex cleanup poison update is inconsistent")

    def _transition(
        self,
        evidence: dict[str, Any],
        *,
        require_gate: bool,
        updates: tuple[str, ...],
    ) -> None:
        loaded = self._read()
        if loaded is None:
            raise ProviderError("armed Codex cleanup poison disappeared")
        poison, marker_identity = loaded
        pairs = [("unit_name", "unit"), ("command_sha256", "command_sha256")]
        if require_gate:
            pairs.extend(
                (
                    ("gate_command_sha256", "gate_command_sha256"),
                    ("gate_executable", "gate_executable"),
                )
            )
        if any(poison[key] != evidence.get(source) for key, source in pairs):
            raise ProviderError("armed Codex cleanup poison launch identity changed")
        for key in updates:
            poison[key] = evidence.get(key)
        self._replace(poison, marker_identity)

    def bind_gate(self, evidence: dict[str, Any]) -> None:
        gate_digest = evidence.get("gate_command_sha256")
        if (
            not isinstance(gate_digest, str)
            or _SHA256_RE.fullmatch(gate_digest) is None
        ):
            raise ProviderError("Codex launch gate digest is invalid")
        self._transition(
            evidence,
            require_gate=False,
            updates=("gate_command_sha256", "gate_executable"),
        )

    def identify_launcher(self, evidence: dict[str, Any]) -> None:
        self._transition(
            evidence,
            require_gate=True,
            updates=("launcher_pid", "launcher_start_time_ticks"),
        )

    def identify_unit(self, evidence: dict[str, Any]) -> None:
        self._transition(evidence, require_gate=True, updates=("control_group",))

    def _heal_interrupted_publish(self, metadata: os.stat_result) -> None:
        if metadata.st_nlink == 1:
            return
        if metadata.st_nlink != 2:
            raise ProviderError(
                "cleanup poison has ambiguous links; manual remediation is required"
            )
        marker_identity = metadata.st_dev, metadata.st_ino
        matches: list[Path] = []
        try:
            for entry in self._root.iterdir():
                if _CLEANUP_POISON_TEMP_RE.fullmatch(entry.name) is None:
                    continue
                candidate = entry.lstat()
                if (candidate.st_dev, candidate.st_ino) == marker_identity:
                    matches.append(entry)
        except OSError as exc:
            raise ProviderError("cannot inspect interrupted cleanup poison") from exc
        if len(matches) != 1:
            raise ProviderError(
                "cleanup poison has ambiguous links; manual remediation is required"
            )
        try:
            candidate = matches[0].lstat()
        except OSError as exc:
            raise ProviderError("cannot re-attest interrupted cleanup poison") from exc
        if (candidate.st_dev, candidate.st_ino) != marker_identity or any(
            (
                not stat.S_ISREG(observed.st_mode)
                or observed.st_uid != os.getuid()
                or observed.st_nlink != 2
                or stat.S_IMODE(observed.st_mode) != _PRIVATE_FILE_MODE
                or observed.st_size > _MAX_POISON_BYTES
            )
            for observed in (metadata, candidate)
        ):
            raise ProviderError(
                "interrupted cleanup poison is unsafe; manual remediation is required"
            )
        try:
            os.unlink(matches[0])
            _fsync_private_directory(self._root)
        except OSError as exc:
            raise ProviderError("cannot heal interrupted cleanup poison") from exc

    def _read(self) -> tuple[dict[str, Any], tuple[int, int]] | None:
        try:
            before = self.marker_path.lstat()
        except FileNotFoundError:
            return None
        except OSError as exc:
            raise ProviderError("cannot inspect Codex cleanup poison") from exc
        self._heal_interrupted_publish(before)
        if before.st_nlink == 2:
            try:
                before = self.marker_path.lstat()
            except OSError as exc:
                raise ProviderError("cannot re-attest healed cleanup poison") from exc
        identity = _validate_owner_file_metadata(
            before, "Codex cleanup poison", _MAX_POISON_BYTES
        )
        raw = _read_bounded_regular(
            self.marker_path,
            maximum=_MAX_POISON_BYTES,
            label="Codex cleanup poison",
        )
        if self._identity() != identity:
            raise ProviderError("Codex cleanup poison pathname identity changed")
        return _validate_cleanup_poison(
            _decode_json(raw, "Codex cleanup poison")
        ), identity

    def _clear(self, marker_identity: tuple[int, int]) -> None:
        if self._identity() != marker_identity:
            raise ProviderError("Codex cleanup poison changed before removal")
        try:
            self.marker_path.unlink()
        except OSError as exc:
            raise ProviderError("cannot clear Codex cleanup poison") from exc
        try:
            _fsync_private_directory(self._root)
        except OSError as exc:
            raise ProviderError("cannot durably clear Codex cleanup poison") from exc

    def disarm(self, binding: _PoisonBinding, evidence: dict[str, Any]) -> None:
        loaded = self._read()
        if loaded is None:
            raise ProviderError("armed Codex cleanup poison disappeared")
        poison, marker_identity = loaded
        evidence_keys = (
            "command_sha256",
            "control_group",
            "gate_command_sha256",
            "gate_executable",
            "launcher_pid",
            "launcher_start_time_ticks",
        )
        if (
            poison["binding"] != binding.as_json()
            or poison["unit_name"] != evidence.get("unit")
            or any(poison[key] != evidence.get(key) for key in evidence_keys)
        ):
            raise ProviderError("armed Codex cleanup poison identity changed")
        self._clear(marker_identity)

    def recover(
        self,
        binding: _PoisonBinding,
        probe: _RecoveryProbe | None = None,
    ) -> bool:
        loaded = self._read()
        if loaded is None:
            return False
        poison, marker_identity = loaded
        if poison["binding"] != binding.as_json():
            raise ProviderError(
                "Codex cleanup poison belongs to a different auth, protocol lock, "
                "provider lock, or runtime mount; manual remediation is required"
            )
        probe = probe or _SystemdRecoveryProbe()
        for command_digest in (
            poison["gate_command_sha256"],
            poison["command_sha256"],
        ):
            if command_digest is not None and probe.matching_command_pids(
                command_digest
            ):
                raise ProviderError(
                    "Codex cleanup poison remains: a matching launcher process exists"
                )
        unit_state = probe.confirm_unit_clean(
            poison["unit_name"],
            poison["control_group"],
            time.monotonic() + 5,
        )
        launcher_pid = poison["launcher_pid"]
        recorded_start_time = poison["launcher_start_time_ticks"]
        if launcher_pid is None:
            if not unit_state.startswith("not-found/inactive/"):
                raise ProviderError(
                    "Codex cleanup poison remains: an un-attested launcher cannot be "
                    "excluded"
                )
        else:
            observed_start_time = probe.process_start_time(launcher_pid)
            if recorded_start_time is None:
                if observed_start_time is not None or not unit_state.startswith(
                    "not-found/inactive/"
                ):
                    raise ProviderError(
                        "Codex cleanup poison remains: launcher identity was incomplete"
                    )
            elif observed_start_time == recorded_start_time:
                raise ProviderError(
                    "Codex cleanup poison remains: the matching launcher process exists"
                )
        runtime_mount = Path(binding.runtime_mount)
        mount_metadata = _validate_private_directory(
            runtime_mount, "Codex poisoned runtime mountpoint"
        ).lstat()
        if (
            mount_metadata.st_dev,
            mount_metadata.st_ino,
        ) != (binding.runtime_mount_device, binding.runtime_mount_inode):
            raise ProviderError("Codex poisoned runtime mountpoint identity changed")
        if probe.host_mount_present(runtime_mount):
            raise ProviderError(
                "Codex cleanup poison remains: the fixed path is a host-visible mount"
            )
        # The host table cannot observe the unit's private mount namespace. The
        # stable systemd/cgroup probe is the proof that it ended.
        self._clear(marker_identity)
        return True


def _mkdir_private(path: Path) -> None:
    try:
        path.mkdir(mode=_PRIVATE_DIRECTORY_MODE, exist_ok=True)
        path.chmod(_PRIVATE_DIRECTORY_MODE)
    except OSError as exc:
        raise ProviderError(f"cannot prepare Codex runtime directory: {exc}") from exc
    _validate_private_directory(path, f"Codex runtime directory {path.name}")


def _clear_private_directory(path: Path, label: str) -> None:
    _validate_private_directory(path, label)
    for entry in path.iterdir():
        metadata = entry.lstat()
        if stat.S_ISLNK(metadata.st_mode):
            entry.unlink()
        elif stat.S_ISDIR(metadata.st_mode):
            shutil.rmtree(entry)
        elif stat.S_ISREG(metadata.st_mode):
            entry.unlink()
        else:
            raise ProviderError(f"{label} contains an unsupported filesystem entry")


def _new_invocation_root(parent: Path) -> Path:
    _validate_private_directory(parent, "Codex runtime root")
    try:
        path = Path(tempfile.mkdtemp(prefix="invocation-", dir=parent))
        path.chmod(_PRIVATE_DIRECTORY_MODE)
    except OSError as exc:
        raise ProviderError(f"cannot create Codex invocation root: {exc}") from exc
    return _validate_private_directory(path, "Codex invocation root")


def _remove_invocation_root(path: Path) -> None:
    _validate_private_directory(path, "Codex invocation root")
    try:
        shutil.rmtree(path)
    except OSError as exc:
        raise ProviderError(f"cannot remove Codex invocation root: {exc}") from exc


def _prepare_workspace_runtime(workspace: Path) -> _WorkspaceRuntime:
    paths = (
        workspace / ".skill-eval-tmp",
        workspace / ".skill-eval-cache",
        workspace / ".skill-eval-home",
    )
    created: list[Path] = []
    parent_descriptor: int | None = None
    directories: list[tuple[str, int]] = []
    try:
        for path in paths:
            if path.exists() or path.is_symlink():
                raise ProviderError(
                    f"workspace contains reserved evaluation runtime path: {path.name}"
                )
            path.mkdir(mode=_PRIVATE_DIRECTORY_MODE)
            created.append(path)
        flags = os.O_RDONLY | os.O_CLOEXEC | getattr(os, "O_DIRECTORY", 0)
        flags |= getattr(os, "O_NOFOLLOW", 0)
        parent_descriptor = os.open(workspace, flags)
        for path in paths:
            descriptor = os.open(path.name, flags, dir_fd=parent_descriptor)
            os.fchmod(descriptor, _PRIVATE_DIRECTORY_MODE)
            directories.append((path.name, descriptor))
    except BaseException:
        for _name, descriptor in reversed(directories):
            os.close(descriptor)
        if parent_descriptor is not None:
            os.close(parent_descriptor)
        for path in reversed(created):
            shutil.rmtree(path, ignore_errors=True)
        raise
    assert parent_descriptor is not None
    return _WorkspaceRuntime(parent_descriptor, tuple(directories))


def _open_workspace_runtime_directory(
    parent_descriptor: int,
    name: str,
    expected_identity: tuple[int, int],
) -> int:
    path_flag = getattr(os, "O_PATH", None)
    if path_flag is None:
        raise ProviderError("workspace runtime cleanup requires Linux O_PATH")
    path_descriptor = os.open(
        name,
        path_flag | os.O_CLOEXEC | os.O_DIRECTORY | os.O_NOFOLLOW,
        dir_fd=parent_descriptor,
    )
    try:
        metadata = os.fstat(path_descriptor)
        if (
            not stat.S_ISDIR(metadata.st_mode)
            or (
                metadata.st_dev,
                metadata.st_ino,
            )
            != expected_identity
        ):
            raise ProviderError("workspace runtime entry changed to an unsafe type")
        os.chmod(f"/proc/self/fd/{path_descriptor}", _PRIVATE_DIRECTORY_MODE)
        descriptor = os.open(
            ".",
            os.O_RDONLY | os.O_CLOEXEC | os.O_DIRECTORY | os.O_NOFOLLOW,
            dir_fd=path_descriptor,
        )
        opened = os.fstat(descriptor)
        if (opened.st_dev, opened.st_ino) != (metadata.st_dev, metadata.st_ino):
            os.close(descriptor)
            raise ProviderError("workspace runtime directory identity changed")
        return descriptor
    finally:
        os.close(path_descriptor)


def _clear_workspace_runtime_directory(descriptor: int) -> None:
    os.fchmod(descriptor, _PRIVATE_DIRECTORY_MODE)
    for name in os.listdir(descriptor):
        metadata = os.stat(name, dir_fd=descriptor, follow_symlinks=False)
        if stat.S_ISDIR(metadata.st_mode):
            child_descriptor = _open_workspace_runtime_directory(
                descriptor,
                name,
                (metadata.st_dev, metadata.st_ino),
            )
            try:
                child_identity = os.fstat(child_descriptor)
                _clear_workspace_runtime_directory(child_descriptor)
                current = os.stat(name, dir_fd=descriptor, follow_symlinks=False)
                if (current.st_dev, current.st_ino) != (
                    child_identity.st_dev,
                    child_identity.st_ino,
                ):
                    raise ProviderError("workspace runtime directory identity changed")
                os.rmdir(name, dir_fd=descriptor)
                if os.fstat(child_descriptor).st_nlink != 0:
                    raise ProviderError(
                        "workspace runtime directory removal was replaced"
                    )
            finally:
                os.close(child_descriptor)
        else:
            os.unlink(name, dir_fd=descriptor)


def _cleanup_workspace_runtime(runtime: _WorkspaceRuntime) -> None:
    try:
        for name, descriptor in runtime.directories:
            identity = os.fstat(descriptor)
            _clear_workspace_runtime_directory(descriptor)
            try:
                current = os.stat(
                    name,
                    dir_fd=runtime.parent_descriptor,
                    follow_symlinks=False,
                )
            except FileNotFoundError:
                if identity.st_nlink != 0:
                    raise ProviderError(
                        "workspace runtime directory was renamed"
                    ) from None
                continue
            if not stat.S_ISDIR(current.st_mode) or (
                current.st_dev,
                current.st_ino,
            ) != (identity.st_dev, identity.st_ino):
                raise ProviderError("workspace runtime directory identity changed")
            os.rmdir(name, dir_fd=runtime.parent_descriptor)
            if os.fstat(descriptor).st_nlink != 0:
                raise ProviderError("workspace runtime directory removal was replaced")
    except OSError as exc:
        raise ProviderError(f"cannot clean workspace runtime path: {exc}") from exc
    finally:
        for _name, descriptor in runtime.directories:
            os.close(descriptor)
        os.close(runtime.parent_descriptor)


def _fsync_private_directory(path: Path) -> None:
    _validate_private_directory(path, "private file parent")
    flags = os.O_RDONLY | os.O_CLOEXEC | getattr(os, "O_DIRECTORY", 0)
    flags |= getattr(os, "O_NOFOLLOW", 0)
    descriptor = os.open(path, flags)
    try:
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def _write_private(
    path: Path,
    payload: bytes,
    *,
    sync_parent: bool = False,
) -> None:
    target = path.with_name(f".{path.name}.{uuid.uuid4().hex}.tmp")
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_CLOEXEC
    flags |= getattr(os, "O_NOFOLLOW", 0)
    descriptor = os.open(target, flags, _PRIVATE_FILE_MODE)
    succeeded = False
    try:
        os.fchmod(descriptor, _PRIVATE_FILE_MODE)
        _write_all(descriptor, payload, "private file")
        os.fsync(descriptor)
        succeeded = True
    finally:
        os.close(descriptor)
        if not succeeded:
            target.unlink(missing_ok=True)
    os.replace(target, path)
    if sync_parent:
        _fsync_private_directory(path.parent)


def _toml_string(value: str) -> str:
    return json.dumps(value, ensure_ascii=True)


def _static_config(root: Path, model: str, reasoning_effort: str) -> bytes:
    work = root / "work"
    skill = root / "skill"
    tools = root / "tools"
    codex_home = root / "codex-home"
    temp_directory = work / ".skill-eval-tmp"
    cache_directory = work / ".skill-eval-cache"
    home_directory = work / ".skill-eval-home"
    lines = [
        f"model = {_toml_string(model)}",
        f"model_reasoning_effort = {_toml_string(reasoning_effort)}",
        'approval_policy = "never"',
        'default_permissions = "eval"',
        'forced_login_method = "chatgpt"',
        "allow_login_shell = false",
        'web_search = "disabled"',
        "include_apps_instructions = false",
        "include_collaboration_mode_instructions = false",
        "check_for_update_on_startup = false",
        "",
        "[tools.experimental_request_user_input]",
        "enabled = false",
        "",
        "[analytics]",
        "enabled = false",
        "",
        "[history]",
        'persistence = "none"',
        "",
        "[features]",
        "apps = false",
        "auth_elicitation = false",
        "browser_use = false",
        "browser_use_external = false",
        "browser_use_full_cdp_access = false",
        "code_mode_host = false",
        "computer_use = false",
        "goals = false",
        "guardian_approval = false",
        "hooks = false",
        "image_generation = false",
        "memories = false",
        "multi_agent = false",
        "plugin_sharing = false",
        "plugins = false",
        "remote_plugin = false",
        "skill_mcp_dependency_install = false",
        "tool_call_mcp_elicitation = false",
        "tool_suggest = false",
        "workspace_dependencies = false",
        "",
        "[shell_environment_policy]",
        'inherit = "none"',
        f'set = {{ PATH = {_toml_string(f"{tools}/bin:{tools}/codex-path:{tools}/codex-resources:{tools}/codex-resources/zsh/bin:{tools}/required:/usr/bin:/bin")}, HOME = {_toml_string(str(home_directory))}, LANG = "C.UTF-8", TMPDIR = {_toml_string(str(temp_directory))}, XDG_CACHE_HOME = {_toml_string(str(cache_directory))} }}',
        "",
        "[permissions.eval]",
        'description = "Isolated Skivolve execution"',
        "",
        "[permissions.eval.filesystem]",
        '":minimal" = "read"',
        '"/tmp" = "deny"',
        '"/var/tmp" = "deny"',
        f'{_toml_string(str(root))} = "read"',
        f'{_toml_string(str(codex_home))} = "read"',
        f'{_toml_string(str(codex_home / "auth.json"))} = "deny"',
        f'{_toml_string(str(codex_home / "config.toml"))} = "deny"',
        f'{_toml_string(str(work))} = "write"',
        f'{_toml_string(str(home_directory))} = "write"',
        f'{_toml_string(str(temp_directory))} = "write"',
        f'{_toml_string(str(cache_directory))} = "write"',
        f'{_toml_string(str(skill))} = "read"',
        f'{_toml_string(str(tools))} = "read"',
        "",
        "[permissions.eval.network]",
        "enabled = false",
        "",
    ]
    return "\n".join(lines).encode("ascii")


def _prepare_runtime(
    root: Path, mounted_root: Path, model: str, effort: str
) -> dict[str, Path]:
    paths = {name: root / name for name in ("work", "skill", "tools", "codex-home")}
    for path in paths.values():
        _mkdir_private(path)
    _clear_private_directory(paths["work"], "Codex work mount target")
    _clear_private_directory(paths["skill"], "Codex skill mount target")
    _clear_private_directory(paths["tools"], "Codex tools mount target")
    for entry in paths["codex-home"].iterdir():
        if entry.name in {"auth.json", "config.toml"}:
            continue
        if entry.is_symlink():
            entry.unlink()
        elif entry.is_dir():
            shutil.rmtree(entry)
        else:
            entry.unlink()
    auth_target = paths["codex-home"] / "auth.json"
    if auth_target.exists() or auth_target.is_symlink():
        metadata = auth_target.lstat()
        if not stat.S_ISREG(metadata.st_mode) or stat.S_ISLNK(metadata.st_mode):
            raise ProviderError("Codex runtime auth target is unsafe")
    else:
        _write_private(auth_target, b"")
    _write_private(
        paths["codex-home"] / "config.toml",
        _static_config(mounted_root, model, effort),
    )
    return paths


def _runtime_mountpoint() -> Path:
    parent = _validate_private_directory(
        Path(f"/run/user/{os.getuid()}"), "user runtime directory"
    )
    mountpoint = parent / "skill-eval-codex-mount"
    try:
        mountpoint.mkdir(mode=_PRIVATE_DIRECTORY_MODE, exist_ok=True)
    except OSError as exc:
        raise ProviderError(f"cannot prepare Codex runtime mountpoint: {exc}") from exc
    return _validate_private_directory(mountpoint, "Codex runtime mountpoint")


def _prepare_runtime_mountpoint(mountpoint: Path) -> None:
    _clear_private_directory(mountpoint, "Codex runtime mountpoint")
    for name in ("work", "skill", "tools", "codex-home"):
        (mountpoint / name).mkdir(mode=_PRIVATE_DIRECTORY_MODE)


def _systemd_environment() -> dict[str, str]:
    environment = {
        "LANG": "C.UTF-8",
        "PATH": "/usr/bin:/bin",
    }
    for name in ("DBUS_SESSION_BUS_ADDRESS", "XDG_RUNTIME_DIR"):
        value = os.environ.get(name)
        if value:
            environment[name] = value
    return environment


class CodexAppServerProvider:
    """Generator-only Codex provider pinned to ChatGPT subscription semantics."""

    def __init__(
        self,
        config: ProviderConfig,
        *,
        transport_factory: TransportFactory | None = None,
        auth_path: Path | None = None,
        runtime_root: Path | None = None,
        validate_lock: bool = True,
    ) -> None:
        if config.kind != "codex":
            raise ProviderError(f"Codex provider received config kind {config.kind!r}")
        if validate_lock != (transport_factory is None):
            raise ProviderError(
                "Codex transport injection requires validate_lock=False and "
                "production transport requires validate_lock=True"
            )
        if (
            config.executable is None
            or config.reasoning_effort is None
            or config.protocol_lock is None
            or config.billing_basis != "chatgpt_subscription"
            or config.max_budget_usd is not None
        ):
            raise ProviderError("Codex provider configuration is incomplete")
        self._config = config
        self._executable = _resolve_executable(config.executable)
        try:
            self._verified_executable = VerifiedExecutable(self._executable)
        except (CalibrationError, OSError) as exc:
            raise ProviderError(f"cannot attest Codex executable: {exc}") from exc
        self._runtime_bundle: dict[str, VerifiedExecutable] = {
            "bin/codex": self._verified_executable
        }
        self._closed = False
        try:
            self._lock = _load_protocol_lock(config.protocol_lock)
            efforts = self._lock.model_efforts.get(config.model)
            if efforts is None or config.reasoning_effort not in efforts:
                raise ProviderError(
                    "Codex model or reasoning effort is not protocol-locked"
                )
            if self._verified_executable.sha256 != self._lock.executable_sha256:
                raise ProviderError(
                    "Codex executable digest differs from protocol lock"
                )
            if validate_lock:
                validate_codex_protocol_lock(self._verified_executable, self._lock)
            release_root = self._executable.parent.parent
            for relative_path in _RUNTIME_BUNDLE_PATHS[1:]:
                source = _resolve_bundle_executable(
                    release_root / relative_path,
                    f"Codex runtime bundle file {relative_path}",
                )
                attestation = VerifiedExecutable(source)
                if attestation.sha256 != self._lock.runtime_bundle_files[relative_path]:
                    attestation.close()
                    raise ProviderError(
                        f"Codex runtime bundle file {relative_path} differs from lock"
                    )
                self._runtime_bundle[relative_path] = attestation
            self._runtime_root = (
                _validate_private_directory(runtime_root, "Codex runtime root")
                if runtime_root is not None
                else _runtime_root()
            )
            default_home = Path(
                os.environ.get("CODEX_HOME", str(Path.home() / ".codex"))
            )
            self._auth_path = _validate_auth_file(
                auth_path or default_home / "auth.json"
            )
            self._transport_is_injected = transport_factory is not None
            self._transport_factory = transport_factory or _ProcessTransport
        except BaseException:
            self.close()
            raise

    @property
    def name(self) -> str:
        return "codex-app-server"

    @property
    def version(self) -> str:
        return self._lock.cli_version

    @property
    def execution_policy(self) -> Any:
        return execution_policy_for("codex-app-server")

    @property
    def executable_sha256(self) -> str:
        return self._lock.executable_sha256

    @property
    def protocol_lock_sha256(self) -> str:
        return self._lock.sha256

    @property
    def protocol_schema_sha256(self) -> str:
        return self._lock.protocol_sha256

    @property
    def runtime_bundle_sha256(self) -> str:
        return self._lock.runtime_bundle_sha256

    @property
    def protocol_provenance(self) -> dict[str, Any]:
        return {
            "codex_cli_version": self._lock.cli_version,
            "executable_sha256": self._lock.executable_sha256,
            "lock_sha256": self._lock.sha256,
            "runtime_bundle_sha256": self._lock.runtime_bundle_sha256,
            "schema_sha256": self._lock.protocol_sha256,
        }

    def __enter__(self) -> CodexAppServerProvider:
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
        attestations = tuple(self._runtime_bundle.values())
        self._runtime_bundle.clear()
        closed: set[int] = set()
        for attestation in reversed(attestations):
            identity = id(attestation)
            if identity not in closed:
                attestation.close()
                closed.add(identity)

    def _ensure_open(self) -> None:
        if self._closed:
            raise ProviderError("Codex provider is closed")

    def run_agent(self, request: AgentRequest) -> ProviderResult:
        self._ensure_open()
        if request.model != self._config.model:
            raise ProviderError(
                "agent request model differs from configured Codex model"
            )
        if not (
            1 <= request.timeout_seconds <= min(self._config.timeout_seconds, 3_600)
        ):
            raise ProviderError("Codex request timeout exceeds the configured bound")
        workspace = _resolve_nonsymlink_directory(request.workspace, "Codex workspace")
        deadline = time.monotonic() + request.timeout_seconds
        started = time.monotonic()
        transport: _Transport | None = None
        outcome: _TurnOutcome | None = None
        timeout_error: ProviderTimeoutError | None = None
        sandbox: dict[str, Any] | None = None
        expected_command_sha256: str | None = None
        coordination_root = _validate_private_directory(
            Path(f"/run/user/{os.getuid()}"), "user runtime directory"
        )
        poison_store = _CleanupPoisonStore(coordination_root)
        poison_recovered = False
        with (
            poison_store.lock(deadline) as provider_lock_identity,
            _auth_lock(self._auth_path, deadline),
            _held_auth_descriptor(self._auth_path) as auth_descriptor,
        ):
            auth_identity = _assert_auth_path_matches_descriptor(
                self._auth_path, auth_descriptor
            )
            mounted_root = _runtime_mountpoint()
            mount_metadata = mounted_root.lstat()
            poison_binding = _PoisonBinding(
                auth_device=auth_identity[0],
                auth_inode=auth_identity[1],
                protocol_lock_sha256=self._lock.sha256,
                provider_lock_device=provider_lock_identity[0],
                provider_lock_inode=provider_lock_identity[1],
                runtime_mount=str(mounted_root),
                runtime_mount_device=mount_metadata.st_dev,
                runtime_mount_inode=mount_metadata.st_ino,
            )
            poison_recovered = poison_store.recover(poison_binding)
            _prepare_runtime_mountpoint(mounted_root)
            invocation_root = _new_invocation_root(self._runtime_root)
            workspace_runtime: _WorkspaceRuntime | None = None
            tool_attestations: list[VerifiedExecutable] = []
            try:
                try:
                    for attestation in self._runtime_bundle.values():
                        attestation.ensure_source_unchanged()
                except (CalibrationError, OSError) as exc:
                    raise ProviderError(f"Codex runtime bundle drifted: {exc}") from exc
                mounted_paths = {
                    name: mounted_root / name
                    for name in ("work", "skill", "tools", "codex-home")
                }
                paths = _prepare_runtime(
                    invocation_root,
                    mounted_root,
                    self._config.model,
                    self._config.reasoning_effort,
                )
                workspace_runtime = _prepare_workspace_runtime(workspace)
                command, unit_name = self._launch_command(
                    request, paths, mounted_paths, tool_attestations
                )
                expected_command_sha256 = _command_sha256(command)
                if self._transport_is_injected:
                    transport = self._transport_factory(
                        command,
                        mounted_paths["work"],
                        _systemd_environment(),
                        unit_name,
                    )
                else:
                    poison_store.arm(poison_binding, unit_name, expected_command_sha256)
                    transport = _ProcessTransport(
                        command,
                        mounted_paths["work"],
                        _systemd_environment(),
                        unit_name,
                        on_gate_ready=poison_store.bind_gate,
                        on_started=poison_store.identify_launcher,
                        on_unit_active=poison_store.identify_unit,
                    )
                session = _JsonRpcSession(transport)
                try:
                    if (
                        _assert_auth_path_matches_descriptor(
                            self._auth_path, auth_descriptor
                        )
                        != auth_identity
                    ):
                        raise ProviderError(
                            "Codex auth.json identity changed while the sandbox launched"
                        )
                    system_context = request.system_context
                    if request.skill_snapshot is not None:
                        logical_snapshot = str(request.skill_snapshot)
                        if system_context.count(logical_snapshot) != 1:
                            raise ProviderError(
                                "Codex system context must contain the mounted skill "
                                "snapshot path exactly once"
                            )
                        system_context = system_context.replace(
                            logical_snapshot, str(mounted_paths["skill"])
                        )
                        if logical_snapshot in system_context:
                            raise ProviderError(
                                "Codex system context retained the host skill path"
                            )
                    try:
                        outcome = _AppServerProtocol(
                            session,
                            model=self._config.model,
                            reasoning_effort=self._config.reasoning_effort,
                            workspace=mounted_paths["work"],
                            system_context=system_context,
                            locked_efforts=self._lock.model_efforts[self._config.model],
                            locked_thread_cli_version=self._lock.thread_cli_version,
                            expected_codex_home=mounted_paths["codex-home"],
                            on_dispatched=request.on_dispatched,
                        ).run(request.prompt, deadline)
                    except ProviderTimeoutError as exc:
                        timeout_error = exc
                finally:
                    session.close()
                    if not self._transport_is_injected:
                        if not isinstance(transport, _ProcessTransport):
                            raise ProviderError(
                                "Codex production transport type is invalid"
                            )
                        if (
                            transport.evidence.get("kind")
                            != "systemd-run-user+codex-permission-profile"
                            or transport.evidence.get("launch_confirmed") is not True
                            or transport.evidence.get("cleanup_confirmed") is not True
                            or transport.evidence.get("command_sha256")
                            != expected_command_sha256
                        ):
                            raise ProviderError(
                                "Codex production sandbox lifecycle evidence is "
                                "incomplete"
                            )
                        poison_store.disarm(poison_binding, transport.evidence)
                sandbox = dict(transport.evidence)
                sandbox.update(
                    {
                        "auth_serialization": "mount-global+auth-flock",
                        "cleanup_poison_recovered": poison_recovered,
                        "external_same_uid_clients": "not-coordinated",
                        "release_authoritative": False,
                        "runtime_bundle_sha256": self._lock.runtime_bundle_sha256,
                        "test_only_transport": self._transport_is_injected,
                    }
                )
                if self._transport_is_injected:
                    sandbox["enforced"] = False
                    raise ProviderError(
                        "injected Codex transports are test-only and cannot produce "
                        "ProviderResult"
                    )
            finally:
                try:
                    try:
                        for attestation in reversed(tool_attestations):
                            attestation.close()
                    finally:
                        if workspace_runtime is not None:
                            _cleanup_workspace_runtime(workspace_runtime)
                finally:
                    try:
                        post_identity = _assert_auth_path_matches_descriptor(
                            self._auth_path, auth_descriptor
                        )
                        if post_identity != auth_identity:
                            raise ProviderError(
                                "Codex auth.json identity changed during invocation"
                            )
                    finally:
                        _remove_invocation_root(invocation_root)
        if timeout_error is not None:
            raise ProviderTimeoutError(
                str(timeout_error), cleanup_confirmed=True
            ) from timeout_error
        assert outcome is not None and sandbox is not None
        return self._build_result(
            request,
            outcome,
            sandbox,
            duration_seconds=time.monotonic() - started,
        )

    def _build_result(
        self,
        request: AgentRequest,
        outcome: _TurnOutcome,
        sandbox: dict[str, Any],
        *,
        duration_seconds: float,
    ) -> ProviderResult:
        return ProviderResult(
            final_output=outcome.final_output,
            requested_model=request.model,
            actual_models=(request.model,),
            provider_name=self.name,
            provider_version=self.version,
            duration_seconds=duration_seconds,
            cost_usd=None,
            tokens=outcome.tokens,
            sandbox=sandbox,
            raw_response=outcome.raw_response,
            billing_basis="chatgpt_subscription",
            quota=outcome.quota,
            protocol_provenance=self.protocol_provenance,
        )

    def run_comparator(self, _request: ComparatorRequest) -> ComparatorResult:
        self._ensure_open()
        raise ProviderError(
            "Codex ChatGPT-subscription provider is generator-only and not "
            "release-authoritative for comparator execution"
        )

    def _launch_command(
        self,
        request: AgentRequest,
        paths: dict[str, Path],
        mounted_paths: dict[str, Path],
        tool_attestations: list[VerifiedExecutable],
    ) -> tuple[tuple[str, ...], str]:
        systemd_run = str(_resolve_system_tool("systemd-run"))
        env_tool = str(_resolve_system_tool("env"))
        _resolve_system_tool("systemctl")
        bundle_bindings: list[tuple[str, Path, Path]] = []
        for relative_path in _RUNTIME_BUNDLE_PATHS:
            placeholder = paths["tools"] / relative_path
            placeholder.parent.mkdir(
                mode=_PRIVATE_DIRECTORY_MODE, parents=True, exist_ok=True
            )
            _write_private(placeholder, b"")
            placeholder.chmod(0o700)
            bundle_bindings.append(
                (
                    "BindReadOnlyPaths",
                    self._runtime_bundle[relative_path].execution_path,
                    mounted_paths["tools"] / relative_path,
                )
            )
        executable_target = mounted_paths["tools"] / "bin" / "codex"
        pair_root = _resolve_nonsymlink_directory(
            request.sandbox_pair_root, "Codex pair root"
        )
        if not _protect_home_covers(pair_root):
            raise ProviderError(
                "Codex pair root must be covered by systemd ProtectHome"
            )
        workspace = _resolve_nonsymlink_directory(request.workspace, "Codex workspace")
        if workspace == pair_root or not workspace.is_relative_to(pair_root):
            raise ProviderError(
                "Codex workspace must be within the protected pair root"
            )
        bindings = [
            (
                "BindPaths",
                paths["work"].parent,
                mounted_paths["work"].parent,
            ),
            (
                "BindPaths",
                workspace,
                mounted_paths["work"],
            ),
            (
                "BindPaths",
                self._auth_path,
                mounted_paths["codex-home"] / "auth.json",
            ),
            *bundle_bindings,
        ]
        if request.skill_snapshot is not None:
            snapshot = _resolve_nonsymlink_directory(
                request.skill_snapshot, "Codex skill snapshot"
            )
            if snapshot == pair_root or not snapshot.is_relative_to(pair_root):
                raise ProviderError(
                    "Codex skill snapshot must be within the protected pair root"
                )
            bindings.append(("BindReadOnlyPaths", snapshot, mounted_paths["skill"]))
        seen_tools: set[str] = {"codex"}
        for name, raw_source in request.required_tools:
            if _TOOL_NAME_RE.fullmatch(name) is None or name in seen_tools:
                raise ProviderError(f"invalid or duplicate Codex tool name: {name!r}")
            source = _resolve_nonsymlink_executable(
                Path(raw_source), f"Codex tool {name}"
            )
            try:
                attestation = VerifiedExecutable(source)
            except (CalibrationError, OSError) as exc:
                raise ProviderError(f"cannot attest Codex tool {name}") from exc
            tool_attestations.append(attestation)
            placeholder = paths["tools"] / "required" / name
            placeholder.parent.mkdir(
                mode=_PRIVATE_DIRECTORY_MODE, parents=True, exist_ok=True
            )
            _write_private(placeholder, b"")
            placeholder.chmod(0o700)
            target = mounted_paths["tools"] / "required" / name
            bindings.append(("BindReadOnlyPaths", attestation.execution_path, target))
            seen_tools.add(name)
        unit_name = f"skill-eval-codex-{uuid.uuid4().hex}"
        runtime_mount = _systemd_property_path(
            mounted_paths["work"].parent, "Codex runtime mountpoint"
        )
        work_path = _systemd_property_path(
            mounted_paths["work"], "Codex work directory"
        )
        encoded_bindings = [
            (
                property_name,
                _systemd_property_path(source, f"{property_name} source"),
                _systemd_property_path(target, f"{property_name} target"),
            )
            for property_name, source, target in bindings
        ]
        command = [
            systemd_run,
            "--user",
            "--quiet",
            "--pipe",
            "--wait",
            "--collect",
            "--service-type=exec",
            f"--unit={unit_name}",
            "-p",
            "ProtectSystem=strict",
            "-p",
            "ProtectHome=tmpfs",
            "-p",
            "PrivateTmp=yes",
            "-p",
            "PrivateDevices=yes",
            "-p",
            "PrivateUsers=yes",
            "-p",
            "NoNewPrivileges=yes",
            "-p",
            "RestrictSUIDSGID=yes",
            "-p",
            "ProtectProc=invisible",
            "-p",
            "ProcSubset=pid",
            "-p",
            "ProtectKernelTunables=yes",
            "-p",
            "ProtectKernelModules=yes",
            "-p",
            "ProtectKernelLogs=yes",
            "-p",
            "ProtectControlGroups=yes",
            "-p",
            "LockPersonality=yes",
            "-p",
            "RestrictRealtime=yes",
            "-p",
            "RestrictAddressFamilies=AF_UNIX AF_INET AF_INET6 AF_NETLINK",
            "-p",
            "MemoryMax=4G",
            "-p",
            "TasksMax=128",
            "-p",
            "LimitNOFILE=512",
            "-p",
            "LimitFSIZE=512M",
            "-p",
            f"RuntimeMaxSec={request.timeout_seconds}s",
            "-p",
            "KillMode=control-group",
            "-p",
            "UMask=0077",
            "-p",
            f"ReadWritePaths={runtime_mount}",
        ]
        inaccessible_candidates = [
            Path.home().resolve(strict=True),
            _resolve_nonsymlink_directory(
                request.sandbox_repository_root, "Codex repository root"
            ),
            pair_root,
        ]
        if request.sandbox_suite_root is not None:
            inaccessible_candidates.append(
                _resolve_nonsymlink_directory(
                    request.sandbox_suite_root, "Codex suite root"
                )
            )
        inaccessible = [
            path
            for path in inaccessible_candidates
            if not _protect_home_covers(path) and not _private_tmp_covers(path)
        ]
        for _, source, _ in bindings:
            if _private_tmp_covers(source):
                raise ProviderError(
                    "Codex bind sources cannot be under systemd PrivateTmp roots"
                )
        encoded_inaccessible: list[str] = []
        for hidden in dict.fromkeys(inaccessible):
            invocation_root = paths["work"].parent
            if invocation_root.is_relative_to(hidden) or hidden.is_relative_to(
                invocation_root
            ):
                raise ProviderError("Codex hidden host root overlaps the runtime root")
            encoded_inaccessible.append(
                _systemd_property_path(hidden, "Codex inaccessible host root")
            )
        for hidden in encoded_inaccessible:
            command.extend(["-p", f"InaccessiblePaths={hidden}"])
        for property_name, source, target in encoded_bindings:
            command.extend(["-p", f"{property_name}={source}:{target}"])
        command.extend(
            [
                f"--working-directory={work_path}",
                "--",
                env_tool,
                "-i",
                f"CODEX_HOME={mounted_paths['codex-home']}",
                f"HOME={mounted_paths['work'] / '.skill-eval-home'}",
                "LANG=C.UTF-8",
                f"PATH={mounted_paths['tools'] / 'bin'}:{mounted_paths['tools'] / 'codex-path'}:{mounted_paths['tools'] / 'codex-resources'}:{mounted_paths['tools'] / 'codex-resources' / 'zsh' / 'bin'}:{mounted_paths['tools'] / 'required'}:/usr/bin:/bin",
                str(executable_target),
                "app-server",
                "--listen",
                "stdio://",
                "--strict-config",
            ]
        )
        return tuple(command), unit_name
