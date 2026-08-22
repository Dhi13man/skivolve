"""Owned invocation and timeout boundary for SkillOpt's Codex optimizer."""

from __future__ import annotations

import fcntl
import os
import signal
import stat
import sys
from pathlib import Path

from .skillopt_bridge import (
    MAX_COMMAND_INPUT_BYTES,
    SkillOptBridgeError,
    run_command,
    sha256_bytes,
    sha256_file,
)


_PREFIX = "SKIVOLVE_SKILLOPT_CODEX_"


def _required(name: str) -> str:
    value = os.environ.get(f"{_PREFIX}{name}")
    if not value:
        raise SkillOptBridgeError(f"missing Codex proxy binding {name}")
    return value


def _positive_integer(name: str) -> int:
    value = _required(name)
    if not value.isdigit() or int(value) <= 0:
        raise SkillOptBridgeError(f"invalid Codex proxy binding {name}")
    return int(value)


def _claim_invocation(path: Path, maximum: int) -> int:
    flags = os.O_RDWR | os.O_CREAT | getattr(os, "O_NOFOLLOW", 0)
    descriptor = os.open(path, flags, 0o600)
    try:
        metadata = os.fstat(descriptor)
        if not stat.S_ISREG(metadata.st_mode):
            raise SkillOptBridgeError("Codex invocation ledger is not a regular file")
        with os.fdopen(descriptor, "r+", encoding="ascii", closefd=False) as handle:
            fcntl.flock(handle, fcntl.LOCK_EX)
            raw = handle.read().strip()
            used = 0 if not raw else int(raw)
            claimed = used + 1
            if claimed > maximum:
                raise SkillOptBridgeError(
                    f"Codex optimizer invocation budget exhausted at {maximum}"
                )
            handle.seek(0)
            handle.truncate()
            handle.write(f"{claimed}\n")
            handle.flush()
            os.fsync(handle.fileno())
            return claimed
    except ValueError as exc:
        raise SkillOptBridgeError("Codex invocation ledger is malformed") from exc
    finally:
        os.close(descriptor)


def _interrupt(_signum: int, _frame: object) -> None:
    raise KeyboardInterrupt


def _codex_arguments(requested: list[str]) -> list[str]:
    if not requested or requested[0] != "exec":
        raise SkillOptBridgeError("Codex optimizer proxy permits only exec")
    filtered = ["exec", "--strict-config"]
    index = 1
    while index < len(requested):
        argument = requested[index]
        if argument in {"--sandbox", "-s"}:
            if index + 1 >= len(requested) or requested[index + 1] != "read-only":
                raise SkillOptBridgeError(
                    "Codex optimizer requested an unexpected sandbox"
                )
            index += 2
            continue
        if argument.startswith("--sandbox="):
            if argument != "--sandbox=read-only":
                raise SkillOptBridgeError(
                    "Codex optimizer requested an unexpected sandbox"
                )
            index += 1
            continue
        if argument in {
            "--dangerously-bypass-approvals-and-sandbox",
            "--ignore-user-config",
            "--profile",
            "-p",
        }:
            raise SkillOptBridgeError(
                "Codex optimizer attempted to override its permission profile"
            )
        filtered.append(argument)
        index += 1
    return filtered


def _directory_mounts(path: Path) -> list[str]:
    arguments: list[str] = []
    current = Path(path.anchor)
    for part in path.parts[1:-1]:
        current /= part
        if current in {
            Path("/usr"),
            Path("/etc"),
            Path("/home"),
            Path("/tmp"),
            Path("/opt"),
            Path("/proc"),
            Path("/dev"),
        }:
            continue
        arguments.extend(("--dir", str(current)))
    return arguments


def _sandbox_command(
    *,
    sandbox: Path,
    executable: Path,
    auth: Path,
    config: Path,
    workspace: Path,
    optimizer_tmp: Path,
    arguments: list[str],
) -> tuple[str, ...]:
    if workspace == Path("/") or any(
        workspace.is_relative_to(root)
        for root in (Path("/usr"), Path("/etc"), Path("/proc"), Path("/dev"))
    ):
        raise SkillOptBridgeError("optimizer workspace cannot mask a system mount")
    command = [
        str(sandbox),
        "--die-with-parent",
        "--new-session",
        "--unshare-user",
        "--unshare-pid",
        "--unshare-ipc",
        "--unshare-uts",
        "--unshare-cgroup-try",
        "--cap-drop",
        "ALL",
        "--ro-bind",
        "/usr",
        "/usr",
        "--symlink",
        "usr/bin",
        "/bin",
        "--symlink",
        "usr/lib",
        "/lib",
        "--symlink",
        "usr/lib64",
        "/lib64",
        "--dir",
        "/etc",
        "--dir",
        "/etc/ssl",
        "--ro-bind",
        "/etc/ssl/certs",
        "/etc/ssl/certs",
    ]
    for system_file in ("resolv.conf", "hosts", "nsswitch.conf"):
        source = Path("/etc") / system_file
        if source.is_file():
            command.extend(("--ro-bind", str(source), str(source)))
    command.extend(
        (
            "--proc",
            "/proc",
            "--dev",
            "/dev",
            "--tmpfs",
            "/tmp",
            "--tmpfs",
            "/home",
            "--dir",
            "/home/optimizer",
            "--dir",
            "/home/optimizer/.codex",
            "--ro-bind",
            str(auth),
            "/home/optimizer/.codex/auth.json",
            "--ro-bind",
            str(config),
            "/home/optimizer/.codex/config.toml",
            "--dir",
            "/opt",
            "--dir",
            "/opt/codex-resources",
            "--ro-bind",
            str(sandbox),
            "/opt/codex-resources/bwrap",
            "--ro-bind",
            str(executable),
            "/opt/skivolve-codex",
        )
    )
    command.extend(_directory_mounts(workspace))
    command.extend(
        (
            "--ro-bind",
            str(workspace),
            str(workspace),
            "--bind",
            str(optimizer_tmp),
            str(optimizer_tmp),
            "--chdir",
            str(workspace),
            "--clearenv",
            "--setenv",
            "HOME",
            "/home/optimizer",
            "--setenv",
            "CODEX_HOME",
            "/home/optimizer/.codex",
            "--setenv",
            "PATH",
            "/usr/bin:/bin",
            "--setenv",
            "LANG",
            "C.UTF-8",
            "--setenv",
            "TMPDIR",
            str(optimizer_tmp),
            "--setenv",
            "SSL_CERT_DIR",
            "/etc/ssl/certs",
            "--",
            "/opt/skivolve-codex",
            *arguments,
        )
    )
    return tuple(command)


def probe_optimizer_tool_boundary(
    *,
    sandbox: Path,
    executable: Path,
    auth: Path,
    config: Path,
    workspace: Path,
    optimizer_tmp: Path,
) -> dict[str, object]:
    """Prove that the optimizer cannot start any model-requested tool process."""

    version = run_command(
        _sandbox_command(
            sandbox=sandbox,
            executable=executable,
            auth=auth,
            config=config,
            workspace=workspace,
            optimizer_tmp=optimizer_tmp,
            arguments=["--version"],
        ),
        env={"LANG": "C.UTF-8", "PATH": "/usr/bin:/bin"},
        timeout_seconds=30,
    )
    strict_config = run_command(
        _sandbox_command(
            sandbox=sandbox,
            executable=executable,
            auth=auth,
            config=config,
            workspace=workspace,
            optimizer_tmp=optimizer_tmp,
            arguments=["exec", "--strict-config", "--help"],
        ),
        env={"LANG": "C.UTF-8", "PATH": "/usr/bin:/bin"},
        timeout_seconds=30,
    )
    denial = run_command(
        _sandbox_command(
            sandbox=sandbox,
            executable=executable,
            auth=auth,
            config=config,
            workspace=workspace,
            optimizer_tmp=optimizer_tmp,
            arguments=[
                "sandbox",
                "-P",
                "optimizer",
                "--",
                "/usr/bin/true",
            ],
        ),
        env={"LANG": "C.UTF-8", "PATH": "/usr/bin:/bin"},
        timeout_seconds=30,
        accepted_exit_codes=tuple(range(-255, 256)),
    )
    diagnostic = f"{denial.stderr}\n{denial.stdout}"
    if (
        "Usage: codex exec" not in strict_config.stdout
        or denial.returncode != 1
        or "/opt/skivolve-codex" not in diagnostic
        or "Permission denied" not in diagnostic
    ):
        raise SkillOptBridgeError(
            "optimizer permission profile did not deny tool-process startup: "
            + diagnostic.strip()[-2000:]
        )
    return {
        "codex_version": version.stdout.strip(),
        "codex_executable_sha256": sha256_file(executable),
        "sandbox_executable_sha256": sha256_file(sandbox),
        "optimizer_config_sha256": sha256_file(config),
        "strict_config_flag_accepted": "Usage: codex exec" in strict_config.stdout,
        "tool_process_start": "denied-before-exec",
        "tool_process_exit_code": denial.returncode,
        "tool_process_diagnostic_sha256": sha256_bytes(diagnostic.encode("utf-8")),
        "model_tool_secret_and_network_access": "unreachable-no-tool-process",
    }


def main(argv: list[str] | None = None) -> int:
    try:
        root = Path(_required("ROOT")).resolve(strict=True)
        executable = Path(_required("REAL")).resolve(strict=True)
        sandbox = Path(_required("SANDBOX")).resolve(strict=True)
        auth = Path(_required("AUTH_FILE"))
        config = Path(_required("CONFIG"))
        workspace = Path(_required("WORKSPACE")).resolve(strict=True)
        supplied_optimizer_tmp = Path(_required("TMP"))
        if supplied_optimizer_tmp.is_symlink():
            raise SkillOptBridgeError(
                "optimizer temporary directory must not be a symlink"
            )
        optimizer_tmp = supplied_optimizer_tmp.resolve(strict=True)
        proxy_bin = Path(_required("PROXY_BIN")).resolve(strict=True)
        ledger = Path(_required("LEDGER"))
        if not executable.is_file() or not os.access(executable, os.X_OK):
            raise SkillOptBridgeError("bound Codex executable is not executable")
        if sha256_file(executable) != _required("REAL_SHA256"):
            raise SkillOptBridgeError("bound Codex executable bytes drifted")
        if not sandbox.is_file() or not os.access(sandbox, os.X_OK):
            raise SkillOptBridgeError("bound optimizer sandbox is not executable")
        if sha256_file(sandbox) != _required("SANDBOX_SHA256"):
            raise SkillOptBridgeError("bound optimizer sandbox bytes drifted")
        auth_metadata = auth.lstat()
        if auth.is_symlink() or not stat.S_ISREG(auth_metadata.st_mode):
            raise SkillOptBridgeError("Codex auth input is not a regular file")
        auth = auth.resolve(strict=True)
        config_metadata = config.lstat()
        if config.is_symlink() or not stat.S_ISREG(config_metadata.st_mode):
            raise SkillOptBridgeError("Codex optimizer config is not a regular file")
        config = config.resolve(strict=True)
        if not config.is_relative_to(root) or sha256_file(config) != _required(
            "CONFIG_SHA256"
        ):
            raise SkillOptBridgeError("Codex optimizer config drifted")
        if workspace != root:
            raise SkillOptBridgeError("optimizer workspace differs from the run root")
        if optimizer_tmp != root / "optimizer-tmp":
            raise SkillOptBridgeError(
                "optimizer temporary directory escaped the run root"
            )
        if proxy_bin != root / "optimizer-bin":
            raise SkillOptBridgeError("optimizer proxy directory escaped the run root")
        if ledger.exists() or ledger.is_symlink():
            ledger_parent = ledger.parent.resolve(strict=True)
        else:
            ledger_parent = ledger.parent.resolve(strict=True)
        if ledger_parent != root or ledger.is_symlink():
            raise SkillOptBridgeError("Codex invocation ledger escaped the run root")
        maximum = _positive_integer("MAX_INVOCATIONS")
        timeout = _positive_integer("TIMEOUT_SECONDS")
        _claim_invocation(ledger, maximum)

        requested_arguments = argv if argv is not None else sys.argv[1:]
        codex_arguments = _codex_arguments(requested_arguments)
        prompt = sys.stdin.buffer.read(MAX_COMMAND_INPUT_BYTES + 1)
        if len(prompt) > MAX_COMMAND_INPUT_BYTES:
            raise SkillOptBridgeError("Codex optimizer prompt exceeded the input limit")

        signal.signal(signal.SIGTERM, _interrupt)
        signal.signal(signal.SIGINT, _interrupt)
        completed = run_command(
            _sandbox_command(
                sandbox=sandbox,
                executable=executable,
                auth=auth,
                config=config,
                workspace=workspace,
                optimizer_tmp=optimizer_tmp,
                arguments=codex_arguments,
            ),
            env={"LANG": "C.UTF-8", "PATH": "/usr/bin:/bin"},
            input_bytes=prompt,
            timeout_seconds=timeout,
            accepted_exit_codes=tuple(range(-255, 256)),
        )
        sys.stdout.write(completed.stdout)
        sys.stderr.write(completed.stderr)
        return completed.returncode
    except KeyboardInterrupt:
        return 130
    except (OSError, SkillOptBridgeError) as exc:
        print(f"Codex optimizer proxy error: {exc}", file=sys.stderr)
        return 124


if __name__ == "__main__":
    raise SystemExit(main())
