from __future__ import annotations

import concurrent.futures
import copy
import hashlib
import json
import os
import shutil
import stat
import sys
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import Mock, patch

from skivolve import comparator_runtime
from skivolve.comparator_runtime import (
    CalibrationError,
    SandboxedClaudeExecutor,
    SpendLedger,
    TransportExecution,
    TransportOverflowError,
    VerifiedExecutable,
    atomic_write_private_json,
    load_private_json,
    load_private_json_capture,
    write_certification,
)


HARNESS_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(HARNESS_ROOT))
_REQUEST_SHA256 = "a" * 64
_INVOCATION_ID = "b" * 64

from skivolve.manifest import ProviderConfig  # noqa: E402
from skivolve.providers import (  # noqa: E402
    AgentRequest,
    ClaudeCliProvider,
    ComparatorRequest,
    FakeProvider,
    ProviderError,
    _resolve_agent_bwrap_executable,
    _resolve_agent_seccomp_executable,
    _resolve_agent_socat_executable,
)

_REAL_SECCOMP_PROBE = ClaudeCliProvider._probe_agent_seccomp
_REAL_BWRAP_PROBE = ClaudeCliProvider._probe_agent_bwrap
_REAL_SOCAT_PROBE = ClaudeCliProvider._probe_agent_socat


class ClaudeCliProviderTests(unittest.TestCase):
    def setUp(self) -> None:
        runtime_parent = Path(f"/run/user/{os.getuid()}")
        self.credential_temporary = tempfile.TemporaryDirectory(dir=runtime_parent)
        self.addCleanup(self.credential_temporary.cleanup)
        self.external_user_home = (
            Path(self.credential_temporary.name) / "external-user-home"
        )
        config_root = self.external_user_home / ".claude"
        config_root.mkdir(parents=True)
        (config_root / ".credentials.json").write_text(
            '{"test_oauth_credential":true}\n', encoding="utf-8"
        )
        self.fake_seccomp = Path(self.credential_temporary.name) / "apply-seccomp"
        self.fake_seccomp.write_text("#!/bin/sh\nexit 0\n", encoding="utf-8")
        self.fake_seccomp.chmod(0o700)
        self.fake_bwrap = Path(self.credential_temporary.name) / "bwrap"
        self.fake_bwrap.write_text("#!/bin/sh\nexit 0\n", encoding="utf-8")
        self.fake_bwrap.chmod(0o700)
        self.fake_socat = Path(self.credential_temporary.name) / "socat"
        self.fake_socat.write_text("#!/bin/sh\nexit 0\n", encoding="utf-8")
        self.fake_socat.chmod(0o700)
        config_environment = patch.dict(
            os.environ,
            {
                "CLAUDE_CONFIG_DIR": str(config_root),
                "SKIVOLVE_CLAUDE_BWRAP_PATH": str(self.fake_bwrap),
                "SKIVOLVE_CLAUDE_SECCOMP_APPLY_PATH": str(self.fake_seccomp),
                "SKIVOLVE_CLAUDE_SOCAT_PATH": str(self.fake_socat),
            },
        )
        config_environment.start()
        self.addCleanup(config_environment.stop)
        version = patch.object(
            ClaudeCliProvider,
            "_capture_version",
            return_value="2.1.198 (Claude Code)",
        )
        sandbox = patch.object(
            ClaudeCliProvider,
            "_probe_sandbox",
            return_value="systemd 255",
        )
        version.start()
        sandbox.start()
        seccomp_canary = patch.object(
            ClaudeCliProvider,
            "_probe_agent_seccomp",
            return_value={"af_unix_socket_creation_denied": True},
        )
        seccomp_canary.start()
        bwrap_canary = patch.object(
            ClaudeCliProvider,
            "_probe_agent_bwrap",
            return_value={"version": "0.9.0"},
        )
        bwrap_canary.start()
        socat_canary = patch.object(
            ClaudeCliProvider,
            "_probe_agent_socat",
            return_value={"version": "1.8.0.0"},
        )
        socat_canary.start()
        self.addCleanup(version.stop)
        self.addCleanup(sandbox.stop)
        self.addCleanup(seccomp_canary.stop)
        self.addCleanup(bwrap_canary.stop)
        self.addCleanup(socat_canary.stop)

    def config(self) -> ProviderConfig:
        return ProviderConfig(
            adapter_id="claude-cli",
            kind="claude",
            executable=sys.executable,
            model="claude-test-20260710",
            max_budget_usd=1.25,
            timeout_seconds=30,
        )

    @staticmethod
    def transport(
        stdout: str,
        stderr: str = "",
        *,
        returncode: int = 0,
    ) -> TransportExecution:
        return TransportExecution(
            returncode=returncode,
            stdout=stdout.encode("utf-8"),
            stderr=stderr.encode("utf-8"),
            duration_seconds=0.01,
            executor={},
        )

    def private_copy_factory(self):
        roots: list[Path] = []

        def create(*, prefix: str, dir: str) -> str:
            self.assertEqual(prefix, "skill-executable-")
            self.assertEqual(Path(dir), Path(f"/run/user/{os.getuid()}"))
            root = Path(self.credential_temporary.name) / f"private-copy-{len(roots)}"
            root.mkdir(mode=0o700)
            roots.append(root)
            return str(root)

        return roots, create

    def test_provider_context_closes_private_copy_and_rejects_reuse(self) -> None:
        roots, create = self.private_copy_factory()
        with (
            patch("skivolve.comparator_runtime.tempfile.mkdtemp", side_effect=create),
            ClaudeCliProvider(self.config()) as provider,
        ):
            attestation = provider._verified_executable
            self.assertEqual(len(roots), 1)
            self.assertTrue(attestation.execution_path.is_file())

        self.assertFalse(roots[0].exists())
        provider.close()
        with self.assertRaisesRegex(ProviderError, "provider is closed"):
            provider.run_agent(None)

    def test_constructor_failure_closes_private_copy(self) -> None:
        roots, create = self.private_copy_factory()
        attestations: list[VerifiedExecutable] = []

        def capture(path: Path) -> VerifiedExecutable:
            attestation = VerifiedExecutable(path)
            attestations.append(attestation)
            return attestation

        with (
            patch("skivolve.comparator_runtime.tempfile.mkdtemp", side_effect=create),
            patch("skivolve.providers.VerifiedExecutable", side_effect=capture),
            patch.object(
                ClaudeCliProvider,
                "_capture_version",
                side_effect=ProviderError("version probe failed"),
            ),
            self.assertRaisesRegex(ProviderError, "version probe failed"),
        ):
            ClaudeCliProvider(self.config())

        self.assertEqual(len(roots), 1)
        self.assertEqual(len(attestations), 1)
        self.assertFalse(roots[0].exists())
        with self.assertRaisesRegex(CalibrationError, "unavailable"):
            _ = attestations[0].descriptor_path

    def comparator_request(self, runtime: Mock) -> ComparatorRequest:
        return ComparatorRequest(
            pair={"id": "opaque-pair"},
            repetition=0,
            order="AB",
            request_bytes=b"{}",
            runtime=runtime,
            spend_ledger=SpendLedger(2.0),
            model="claude-test-20260710",
            timeout_seconds=30,
            max_budget_usd=1.25,
            sandbox_repository_root=Path.cwd(),
        )

    def test_run_agent_when_live_sandbox_executes_hides_host_resources(
        self,
    ) -> None:
        # Arrange
        test_root = Path.home() / ".cache" / "skill-eval-tests"
        test_root.mkdir(parents=True, exist_ok=True)
        with tempfile.TemporaryDirectory(dir=test_root) as temporary:
            root = Path(temporary)
            executable = root / "bin/fake-claude"
            repository = root / "repository"
            pair = root / "pair"
            suite = Path(self.credential_temporary.name) / "private-suite"
            workspace_one = pair / "6f2acdb2" / "workspace"
            workspace_two = pair / "a1d957e4" / "workspace"
            for directory in (
                executable.parent,
                repository,
                suite,
                workspace_one,
                workspace_two,
            ):
                directory.mkdir(parents=True, exist_ok=True)
            secrets = {
                "home": root / "host-home-secret.txt",
                "repository": repository / "oracle-secret.txt",
                "pair": pair / "sibling-secret.txt",
                "suite": suite / "private-holdout-secret.txt",
                "external_home": self.external_user_home / "ssh-sibling-secret.txt",
                "config": self.external_user_home / ".claude" / "config-secret.txt",
            }
            for secret in secrets.values():
                secret.write_text("hidden", encoding="utf-8")
            executable.write_text(
                """#!/usr/bin/python3
import json
import os
import pathlib
import sys
import time

if "--version" in sys.argv:
    print("2.1.198 (Claude Code)")
    raise SystemExit(0)

context = sys.argv[sys.argv.index("--append-system-prompt") + 1]
probe = json.loads(context)
def hidden(path):
    try:
        return not pathlib.Path(path).exists()
    except OSError:
        return True
paths_hidden = all(hidden(path) for path in probe["secret_paths"])
host_pid = str(probe["host_pid"])
process_files_hidden = all(
    not pathlib.Path("/proc", host_pid, name).exists()
    for name in ("cmdline", "environ")
)
try:
    os.kill(int(host_pid), 0)
    host_signal_blocked = False
except (ProcessLookupError, PermissionError):
    host_signal_blocked = True
mountinfo = pathlib.Path("/proc/self/mountinfo").read_text(encoding="utf-8")
labels_hidden = not any(label in mountinfo for label in probe["forbidden_labels"])
private_pid_namespace = os.getpid() == 1
credential_present = pathlib.Path(
    os.environ["CLAUDE_CONFIG_DIR"], ".credentials.json"
).is_file()
settings = json.loads(sys.argv[sys.argv.index("--settings") + 1])
credential = pathlib.Path(
    os.environ["CLAUDE_CONFIG_DIR"], ".credentials.json"
)
security_settings_present = (
    settings["sandbox"]["enabled"] is True
    and settings["sandbox"]["failIfUnavailable"] is True
    and settings["sandbox"]["allowUnsandboxedCommands"] is False
    and settings["sandbox"]["network"]["deniedDomains"] == ["*"]
    and settings["sandbox"]["credentials"]["files"]
        == [{"mode": "deny", "path": str(credential)}]
    and settings["sandbox"]["filesystem"]["denyRead"] == [str(credential)]
    and settings["sandbox"]["filesystem"]["denyWrite"] == [str(credential)]
    and settings["sandbox"]["seccomp"]["applyPath"].endswith("/apply-seccomp")
    and pathlib.Path(settings["sandbox"]["seccomp"]["applyPath"]).is_file()
    and settings["permissions"]["deny"] == [
        f"Read(/{credential})",
        f"Edit(/{credential})",
    ]
)
pathlib.Path("value.txt").write_text("sandbox write")
time.sleep(0.4)
model = sys.argv[sys.argv.index("--model") + 1]
print(json.dumps({
    "result": json.dumps({
        "paths_hidden": paths_hidden,
        "process_files_hidden": process_files_hidden,
        "host_signal_blocked": host_signal_blocked,
        "labels_hidden": labels_hidden,
        "private_pid_namespace": private_pid_namespace,
        "controller_credential_present": credential_present,
        "security_settings_present": security_settings_present,
    }, sort_keys=True),
    "total_cost_usd": 0.01,
    "usage": {"input_tokens": 1, "output_tokens": 1},
    "modelUsage": {model: {}},
}))
""",
                encoding="utf-8",
            )
            executable.chmod(0o755)
            config = ProviderConfig(
                adapter_id="claude-cli",
                kind="claude",
                executable=str(executable),
                model="fake-model-exact",
                max_budget_usd=0.1,
                timeout_seconds=20,
            )
            with patch.object(
                ClaudeCliProvider,
                "_capture_version",
                return_value="2.1.198 (Claude Code)",
            ):
                provider = ClaudeCliProvider(config)
            requests = [
                AgentRequest(
                    case_id="sandbox",
                    variant_id=variant_id,
                    prompt="write value.txt",
                    model=config.model,
                    workspace=workspace,
                    skill_snapshot=None,
                    sandbox_pair_root=pair,
                    sandbox_repository_root=repository,
                    sandbox_suite_root=suite,
                    system_context=json.dumps(
                        {
                            "secret_paths": [
                                *(str(path) for path in secrets.values()),
                                str(sibling),
                            ],
                            "host_pid": os.getpid(),
                            "forbidden_labels": [
                                "control",
                                "treatment",
                                "no-skill",
                                "original",
                                "candidate",
                                "variant-one",
                                "variant-two",
                            ],
                        },
                        sort_keys=True,
                    ),
                    timeout_seconds=10,
                )
                for variant_id, workspace, sibling in (
                    ("variant-one", workspace_one, workspace_two),
                    ("variant-two", workspace_two, workspace_one),
                )
            ]
            # Act
            with concurrent.futures.ThreadPoolExecutor(max_workers=2) as executor:
                results = list(executor.map(provider.run_agent, requests))

            # Assert
            for result in results:
                evidence = json.loads(result.final_output)
                self.assertEqual(
                    evidence,
                    {
                        "controller_credential_present": True,
                        "host_signal_blocked": True,
                        "labels_hidden": True,
                        "paths_hidden": True,
                        "private_pid_namespace": True,
                        "process_files_hidden": True,
                        "security_settings_present": True,
                    },
                )
                self.assertEqual(
                    result.sandbox["kind"],
                    "systemd-run-user+claude-native-tool-sandbox",
                )
                self.assertEqual(
                    result.sandbox["credential_scope"],
                    "controller-auth-denied-to-model-tools",
                )
            self.assertEqual((workspace_one / "value.txt").read_text(), "sandbox write")
            self.assertEqual((workspace_two / "value.txt").read_text(), "sandbox write")

    @patch("skivolve.providers.execute_bounded_transport")
    def test_providers_when_roles_are_independent_use_distinct_models(
        self, run
    ) -> None:
        # Arrange
        generator_model = "claude-haiku-test-20260710"
        comparator_model = "claude-sonnet-test-20260710"
        run.side_effect = [
            self.transport(
                json.dumps(
                    {
                        "result": "agent result",
                        "total_cost_usd": 0.1,
                        "usage": {"input_tokens": 1},
                        "modelUsage": {generator_model: {}},
                    }
                ),
            ),
        ]
        generator = ClaudeCliProvider(
            ProviderConfig(
                adapter_id="claude-cli",
                kind="claude",
                executable=sys.executable,
                model=generator_model,
                max_budget_usd=0.5,
                timeout_seconds=20,
            )
        )
        comparator = ClaudeCliProvider(
            ProviderConfig(
                adapter_id="claude-cli",
                kind="claude",
                executable=sys.executable,
                model=comparator_model,
                max_budget_usd=1.0,
                timeout_seconds=30,
            )
        )
        repository_root = Path.cwd()
        invocation_id = "1" * 64
        request_bytes = json.dumps(
            {"user_payload": {"invocation_id": invocation_id}},
            separators=(",", ":"),
            sort_keys=True,
        ).encode("ascii")
        decision = {
            "criteria": None,
            "outcome": "A",
            "unsupported_performance": False,
            "unsupported_qualitative": [],
        }
        executor = {
            "command_executable": "/runtime/bin/claude",
            "enforced": True,
            "executable_sha256": "5" * 64,
            "kind": "shared-systemd-claude-executor",
            "properties": [f"InaccessiblePaths={repository_root}"],
        }
        hashes = {
            "command_sha256": "3" * 64,
            "request_sha256": hashlib.sha256(request_bytes).hexdigest(),
            "stdin_sha256": "2" * 64,
        }
        runtime = Mock()
        runtime.bundle.release = {
            "criterion_support": {},
            "execution_limits": {
                "timeout_seconds": 30,
                "per_invocation_max_usd": 1.0,
                "run_max_usd": 1.0,
            },
            "judge": {
                "provider": comparator.name,
                "provider_version": comparator.version,
                "requested_model": comparator_model,
            },
            "test_release": True,
        }
        runtime.invocation_id.return_value = invocation_id
        runtime.request_bytes.return_value = request_bytes
        raw = json.dumps(
            {
                "is_error": False,
                "structured_output": {},
                "total_cost_usd": 0.2,
                "usage": {"input_tokens": 2},
                "modelUsage": {comparator_model: {}},
            }
        )
        response = {}
        transport_payload = {
            "actual_models": [comparator_model],
            "command_sha256": hashes["command_sha256"],
            "cost_usd": 0.2,
            "decision": decision,
            "duration_seconds": 0.1,
            "executor": executor,
            "parsed_response_sha256": comparator_runtime.canonical_sha256(response),
            "provider_name": comparator.name,
            "provider_version": comparator.version,
            "raw_response": raw,
            "raw_response_sha256": hashlib.sha256(raw.encode()).hexdigest(),
            "request_sha256": hashes["request_sha256"],
            "requested_model": comparator_model,
            "response": response,
            "spend_attempt_id": "4" * 32,
            "stdin_sha256": hashes["stdin_sha256"],
        }
        transport = SimpleNamespace(
            raw_response=raw,
            actual_models=(comparator_model,),
            duration_seconds=0.1,
            cost_usd=0.2,
            executor=executor,
            decision=decision,
            response=response,
            as_json=lambda: transport_payload,
        )
        runtime.run_transport.return_value = transport

        # Act
        with tempfile.TemporaryDirectory() as temporary:
            generator.run_agent(
                AgentRequest(
                    case_id="case",
                    variant_id="variant",
                    prompt="prompt",
                    model=generator_model,
                    workspace=Path(temporary),
                    skill_snapshot=None,
                    sandbox_pair_root=Path(temporary),
                    sandbox_repository_root=Path(temporary),
                    system_context="context",
                    timeout_seconds=5,
                )
            )
        with (
            patch("skivolve.providers.SandboxedClaudeExecutor"),
            patch("skivolve.providers.validate_response", return_value=decision),
            patch("skivolve.providers.expected_transport_hashes", return_value=hashes),
            patch("skivolve.providers.validate_executor_evidence"),
        ):
            comparator.run_comparator(
                ComparatorRequest(
                    pair={"id": "opaque-pair"},
                    repetition=0,
                    order="AB",
                    request_bytes=request_bytes,
                    runtime=runtime,
                    spend_ledger=SpendLedger(1.0),
                    model=comparator_model,
                    timeout_seconds=30,
                    max_budget_usd=1.0,
                    sandbox_repository_root=repository_root,
                )
            )

        # Assert
        generator_command = run.call_args_list[0].args[0]
        self.assertEqual(
            generator_command[generator_command.index("--model") + 1], generator_model
        )
        self.assertEqual(
            runtime.run_transport.call_args.kwargs["requested_model"], comparator_model
        )
        self.assertNotEqual(generator_model, comparator_model)

    @patch("skivolve.providers.execute_bounded_transport")
    def test_agent_uses_safe_stateless_budgeted_command_and_captures_exact_usage(
        self, run
    ) -> None:
        run.side_effect = [
            self.transport(
                json.dumps(
                    {
                        "result": "implemented and tested",
                        "is_error": False,
                        "total_cost_usd": 0.42,
                        "usage": {"input_tokens": 5, "output_tokens": 7},
                        "modelUsage": {
                            "claude-test-20260710": {
                                "inputTokens": 5,
                                "outputTokens": 7,
                            }
                        },
                    }
                ),
            ),
        ]
        with tempfile.TemporaryDirectory() as temporary:
            workspace = Path(temporary) / "workspace"
            snapshot = Path(temporary) / "snapshot"
            workspace.mkdir()
            snapshot.mkdir()
            provider = ClaudeCliProvider(self.config())
            result = provider.run_agent(
                AgentRequest(
                    case_id="case",
                    variant_id="variant",
                    prompt="identical user prompt",
                    model="claude-test-20260710",
                    workspace=workspace,
                    skill_snapshot=snapshot,
                    sandbox_pair_root=Path(temporary),
                    sandbox_repository_root=Path(temporary),
                    system_context="explicit skill context",
                    timeout_seconds=12,
                )
            )

        self.assertEqual(result.provider_version, "2.1.198 (Claude Code)")
        self.assertEqual(result.requested_model, "claude-test-20260710")
        self.assertEqual(result.actual_models, ("claude-test-20260710",))
        self.assertEqual(result.cost_usd, 0.42)
        self.assertEqual(result.tokens, {"input_tokens": 5, "output_tokens": 7})
        self.assertEqual(
            result.sandbox["kind"],
            "systemd-run-user+claude-native-tool-sandbox",
        )
        self.assertTrue(result.sandbox["enforced"])
        self.assertRegex(result.sandbox["claude_executable_sha256"], r"^[0-9a-f]{64}$")
        self.assertEqual(
            result.sandbox["claude_execution_source"],
            "descriptor-verified-private-copy",
        )
        self.assertEqual(
            result.sandbox["credential_scope"],
            "controller-auth-denied-to-model-tools",
        )
        self.assertEqual(
            result.sandbox["agent_tool_sandbox"],
            {
                "bwrap_sha256": hashlib.sha256(
                    self.fake_bwrap.read_bytes()
                ).hexdigest(),
                "bwrap_canary": {"version": "0.9.0"},
                "credential_files_denied": True,
                "fail_if_unavailable": True,
                "network_domains_denied": True,
                "seccomp_apply_sha256": hashlib.sha256(
                    self.fake_seccomp.read_bytes()
                ).hexdigest(),
                "seccomp_canary": {"af_unix_socket_creation_denied": True},
                "socat_sha256": hashlib.sha256(
                    self.fake_socat.read_bytes()
                ).hexdigest(),
                "socat_canary": {"version": "1.8.0.0"},
                "unsandboxed_commands_allowed": False,
                "unix_socket_creation_denied": True,
            },
        )
        self.assertRegex(result.sandbox["agent_settings_sha256"], r"^[0-9a-f]{64}$")
        command = run.call_args_list[0].args[0]
        for flag in (
            "--print",
            "--safe-mode",
            "--setting-sources",
            "--no-session-persistence",
            "--disable-slash-commands",
            "--strict-mcp-config",
            "--max-budget-usd",
            "--model",
            "--add-dir",
            "--allowed-tools",
            "--settings",
        ):
            self.assertIn(flag, command)
        settings = json.loads(command[command.index("--settings") + 1])
        credential = Path(
            f"/run/user/{os.getuid()}/skill-eval-runtime/home/.claude/.credentials.json"
        )
        self.assertEqual(
            settings,
            {
                "permissions": {
                    "deny": [
                        f"Read(/{credential})",
                        f"Edit(/{credential})",
                    ]
                },
                "sandbox": {
                    "allowUnsandboxedCommands": False,
                    "bwrapPath": str(
                        Path(f"/run/user/{os.getuid()}/skill-eval-runtime/bin/bwrap")
                    ),
                    "credentials": {
                        "files": [{"mode": "deny", "path": str(credential)}]
                    },
                    "enabled": True,
                    "failIfUnavailable": True,
                    "filesystem": {
                        "denyRead": [str(credential)],
                        "denyWrite": [str(credential)],
                    },
                    "network": {
                        "allowAllUnixSockets": False,
                        "allowedDomains": [],
                        "deniedDomains": ["*"],
                    },
                    "seccomp": {
                        "applyPath": str(
                            Path(
                                f"/run/user/{os.getuid()}/skill-eval-runtime/bin/"
                                "apply-seccomp"
                            )
                        )
                    },
                    "socatPath": str(
                        Path(f"/run/user/{os.getuid()}/skill-eval-runtime/bin/socat")
                    ),
                },
            },
        )
        for sandbox_property in (
            "ProtectSystem=strict",
            "ProtectHome=read-only",
            "PrivateTmp=yes",
            "NoNewPrivileges=yes",
            "RestrictSUIDSGID=yes",
            "SystemCallFilter=~syslog",
            "SystemCallErrorNumber=EPERM",
        ):
            self.assertIn(sandbox_property, command)
        self.assertNotIn("ProtectKernelTunables=yes", command)
        self.assertNotIn("ProtectKernelLogs=yes", command)
        self.assertTrue(
            any(value.startswith("InaccessiblePaths=") for value in command)
        )
        self.assertTrue(any(value.startswith("BindPaths=") for value in command))
        self.assertTrue(
            any(value.startswith("BindReadOnlyPaths=") for value in command)
        )
        self.assertTrue(
            any(
                value.endswith("/skill-eval-runtime/bin/bwrap")
                for value in command
                if value.startswith("BindReadOnlyPaths=")
            )
        )
        self.assertTrue(
            any(
                value.endswith("/skill-eval-runtime/bin/socat")
                for value in command
                if value.startswith("BindReadOnlyPaths=")
            )
        )
        self.assertNotIn("--continue", command)
        self.assertNotIn("--resume", command)
        self.assertNotIn("--fallback-model", command)
        self.assertEqual(
            command[command.index("--setting-sources") + 1],
            "",
        )
        self.assertEqual(
            command[command.index("--tools") + 1],
            "Read,Edit,Write,Bash",
        )
        self.assertEqual(
            run.call_args_list[0].kwargs["stdin_bytes"], b"identical user prompt"
        )
        self.assertEqual(run.call_args_list[0].kwargs["timeout_seconds"], 12)
        inner = command[command.index("--") + 1 :]
        self.assertIn("CLAUDE_CODE_SUBPROCESS_ENV_SCRUB=1", inner)
        self.assertIn("PYTHONDONTWRITEBYTECODE=1", inner)

    def test_comparator_delegates_canonical_bytes_to_shared_runtime(self) -> None:
        provider = ClaudeCliProvider(self.config())
        repository_root = Path.cwd()
        isolation_root = repository_root / "isolation"
        invocation_id = "1" * 64
        request_bytes = json.dumps(
            {"user_payload": {"invocation_id": invocation_id}},
            separators=(",", ":"),
            sort_keys=True,
        ).encode("ascii")
        decision = {
            "checks": {},
            "criteria": None,
            "outcome": "B",
            "unsupported_performance": False,
            "unsupported_qualitative": [],
        }
        executor = {
            "command_executable": "/runtime/bin/claude",
            "enforced": True,
            "executable_sha256": "5" * 64,
            "kind": "shared-systemd-claude-executor",
            "properties": [
                f"InaccessiblePaths={repository_root}",
                f"InaccessiblePaths={isolation_root}",
            ],
        }
        hashes = {
            "command_sha256": "3" * 64,
            "request_sha256": hashlib.sha256(request_bytes).hexdigest(),
            "stdin_sha256": "2" * 64,
        }
        runtime = Mock()
        runtime.bundle.release = {
            "criterion_support": {},
            "execution_limits": {
                "timeout_seconds": 30,
                "per_invocation_max_usd": 1.25,
                "run_max_usd": 2.0,
            },
            "judge": {
                "provider": provider.name,
                "provider_version": provider.version,
                "requested_model": "claude-test-20260710",
            },
            "test_release": True,
        }
        runtime.invocation_id.return_value = invocation_id
        runtime.request_bytes.return_value = request_bytes
        raw = json.dumps(
            {
                "is_error": False,
                "structured_output": {"locked": True},
                "total_cost_usd": 0.08,
                "usage": {"input_tokens": 11, "output_tokens": 4},
                "modelUsage": {"claude-test-20260710": {}},
            }
        )
        response = {"locked": True}
        transport_payload = {
            "actual_models": ["claude-test-20260710"],
            "command_sha256": hashes["command_sha256"],
            "cost_usd": 0.08,
            "decision": decision,
            "duration_seconds": 0.2,
            "executor": executor,
            "parsed_response_sha256": comparator_runtime.canonical_sha256(response),
            "provider_name": provider.name,
            "provider_version": provider.version,
            "raw_response": raw,
            "raw_response_sha256": hashlib.sha256(raw.encode()).hexdigest(),
            "request_sha256": hashes["request_sha256"],
            "requested_model": "claude-test-20260710",
            "response": response,
            "spend_attempt_id": "4" * 32,
            "stdin_sha256": hashes["stdin_sha256"],
        }
        runtime.run_transport.return_value = SimpleNamespace(
            raw_response=raw,
            actual_models=("claude-test-20260710",),
            duration_seconds=0.2,
            cost_usd=0.08,
            executor=executor,
            decision=decision,
            response=response,
            as_json=lambda: transport_payload,
        )
        request = ComparatorRequest(
            pair={"id": "opaque-pair", "opaque": True},
            repetition=2,
            order="BA",
            request_bytes=request_bytes,
            runtime=runtime,
            spend_ledger=SpendLedger(2.0),
            model="claude-test-20260710",
            timeout_seconds=30,
            max_budget_usd=1.25,
            sandbox_repository_root=repository_root,
            sandbox_isolation_root=isolation_root,
        )
        with (
            patch("skivolve.providers.SandboxedClaudeExecutor") as executor_type,
            patch("skivolve.providers.validate_response", return_value=decision),
            patch("skivolve.providers.expected_transport_hashes", return_value=hashes),
            patch("skivolve.providers.validate_executor_evidence"),
        ):
            result = provider.run_comparator(request)

        self.assertEqual(result.outcome, "B")
        self.assertEqual(result.provider.actual_models, ("claude-test-20260710",))
        called = runtime.run_transport.call_args.kwargs
        self.assertEqual(called["request_bytes"], request_bytes)
        self.assertEqual(called["order"], "BA")
        self.assertIs(called["executor"], executor_type.return_value)

    def test_agent_requires_cli_version_with_credential_file_denial(self) -> None:
        provider = ClaudeCliProvider(self.config())
        for version in (
            "2.1.186 (Claude Code)",
            "unparseable",
            "wrapper 999.0.0 around Claude Code 2.1.0",
        ):
            with self.subTest(version=version):
                provider._version = version
                with self.assertRaisesRegex(
                    ProviderError,
                    "credential isolation",
                ):
                    provider._require_agent_sandbox_version()
        for version in ("2.1.187", "2.1.187 (Claude Code)", "2.1.211 (Claude Code)"):
            with self.subTest(version=version):
                provider._version = version
                provider._require_agent_sandbox_version()

    @patch("skivolve.providers.execute_bounded_transport")
    def test_agent_requires_attested_seccomp_before_dispatch(self, execute) -> None:
        provider = ClaudeCliProvider(self.config())
        provider._verified_agent_seccomp = None
        with (
            patch(
                "skivolve.providers._resolve_agent_seccomp_executable",
                side_effect=ProviderError("seccomp helper unavailable"),
            ),
            tempfile.TemporaryDirectory() as temporary,
            self.assertRaisesRegex(ProviderError, "seccomp helper unavailable"),
        ):
            provider.run_agent(
                AgentRequest(
                    case_id="case",
                    variant_id="variant",
                    prompt="prompt",
                    model="claude-test-20260710",
                    workspace=Path(temporary),
                    skill_snapshot=None,
                    sandbox_pair_root=Path(temporary),
                    sandbox_repository_root=Path(temporary),
                    system_context="context",
                    timeout_seconds=5,
                )
            )
        execute.assert_not_called()

    @patch("skivolve.providers.execute_bounded_transport")
    def test_agent_requires_attested_native_sandbox_tools_before_dispatch(
        self, execute
    ) -> None:
        provider = ClaudeCliProvider(self.config())
        provider._verified_agent_bwrap = None
        with (
            patch(
                "skivolve.providers._resolve_agent_bwrap_executable",
                side_effect=ProviderError("bwrap unavailable"),
            ),
            tempfile.TemporaryDirectory() as temporary,
            self.assertRaisesRegex(ProviderError, "bwrap unavailable"),
        ):
            provider.run_agent(
                AgentRequest(
                    case_id="case",
                    variant_id="variant",
                    prompt="prompt",
                    model="claude-test-20260710",
                    workspace=Path(temporary),
                    skill_snapshot=None,
                    sandbox_pair_root=Path(temporary),
                    sandbox_repository_root=Path(temporary),
                    system_context="context",
                    timeout_seconds=5,
                )
            )
        execute.assert_not_called()

        provider = ClaudeCliProvider(self.config())
        provider._verified_agent_socat = None
        with (
            patch(
                "skivolve.providers._resolve_agent_socat_executable",
                side_effect=ProviderError("socat unavailable"),
            ),
            tempfile.TemporaryDirectory() as temporary,
            self.assertRaisesRegex(ProviderError, "socat unavailable"),
        ):
            provider.run_agent(
                AgentRequest(
                    case_id="case",
                    variant_id="variant",
                    prompt="prompt",
                    model="claude-test-20260710",
                    workspace=Path(temporary),
                    skill_snapshot=None,
                    sandbox_pair_root=Path(temporary),
                    sandbox_repository_root=Path(temporary),
                    system_context="context",
                    timeout_seconds=5,
                )
            )
        execute.assert_not_called()

    def test_seccomp_canary_requires_observed_af_unix_denial(self) -> None:
        verified = Mock(descriptor_path="/verified/apply-seccomp")
        accepted = TransportExecution(
            returncode=0,
            stdout=b"af-unix-blocked\n",
            stderr=b"",
            duration_seconds=0.01,
            executor={},
        )
        rejected = TransportExecution(
            returncode=3,
            stdout=b"",
            stderr=b"",
            duration_seconds=0.01,
            executor={},
        )
        with patch(
            "skivolve.providers.execute_bounded_transport",
            side_effect=[accepted, rejected],
        ) as execute:
            evidence = _REAL_SECCOMP_PROBE(verified)
            self.assertTrue(evidence["af_unix_socket_creation_denied"])
            with self.assertRaisesRegex(ProviderError, "did not deny AF_UNIX"):
                _REAL_SECCOMP_PROBE(verified)
        self.assertEqual(execute.call_count, 2)

    def test_native_sandbox_tool_canaries_require_valid_versions(self) -> None:
        verified = Mock(descriptor_path="/verified/tool")
        bwrap = TransportExecution(
            returncode=0,
            stdout=b"bubblewrap 0.9.0\n",
            stderr=b"",
            duration_seconds=0.01,
            executor={},
        )
        socat = TransportExecution(
            returncode=0,
            stdout=b"socat version 1.8.0.0 on 03 Jul 2026\n",
            stderr=b"",
            duration_seconds=0.01,
            executor={},
        )
        invalid = TransportExecution(
            returncode=0,
            stdout=b"not-a-version\n",
            stderr=b"",
            duration_seconds=0.01,
            executor={},
        )
        with patch(
            "skivolve.providers.execute_bounded_transport",
            side_effect=[bwrap, socat, invalid, invalid],
        ):
            self.assertEqual(_REAL_BWRAP_PROBE(verified)["version"], "0.9.0")
            self.assertEqual(_REAL_SOCAT_PROBE(verified)["version"], "1.8.0.0")
            with self.assertRaisesRegex(ProviderError, "invalid version"):
                _REAL_BWRAP_PROBE(verified)
            with self.assertRaisesRegex(ProviderError, "invalid version"):
                _REAL_SOCAT_PROBE(verified)

    def test_native_sandbox_tools_resolve_from_explicit_paths(self) -> None:
        with patch.dict(
            os.environ,
            {
                "SKIVOLVE_TEST_BWRAP_PATH": str(self.fake_bwrap),
                "SKIVOLVE_TEST_SOCAT_PATH": str(self.fake_socat),
            },
            clear=True,
        ):
            self.assertEqual(
                _resolve_agent_bwrap_executable(
                    environment_variable="SKIVOLVE_TEST_BWRAP_PATH"
                ),
                self.fake_bwrap.resolve(),
            )
            self.assertEqual(
                _resolve_agent_socat_executable(
                    environment_variable="SKIVOLVE_TEST_SOCAT_PATH"
                ),
                self.fake_socat.resolve(),
            )

    def test_seccomp_helper_resolves_from_executable_npm_prefix(self) -> None:
        prefix = Path(self.credential_temporary.name) / "node-prefix"
        claude = prefix / "bin" / "claude"
        helper = (
            prefix
            / "lib/node_modules/@anthropic-ai/sandbox-runtime/vendor/seccomp/x64"
            / "apply-seccomp"
        )
        claude.parent.mkdir(parents=True)
        helper.parent.mkdir(parents=True)
        claude.write_text("#!/bin/sh\n", encoding="utf-8")
        helper.write_text("#!/bin/sh\n", encoding="utf-8")
        claude.chmod(0o700)
        helper.chmod(0o700)

        with (
            patch.dict(os.environ, {}, clear=True),
            patch("skivolve.providers.platform.machine", return_value="x86_64"),
        ):
            resolved = _resolve_agent_seccomp_executable(
                str(claude),
                environment_variable="SKIVOLVE_TEST_SECCOMP_PATH",
            )

        self.assertEqual(resolved, helper.resolve())

    def test_agent_stdout_limit_accepts_boundary_and_rejects_overflow(self) -> None:
        provider = ClaudeCliProvider(self.config())
        callback = Mock()
        exact = '{"x":"' + ("x" * 56) + '"}'
        self.assertEqual(len(exact.encode("ascii")), 64)
        with (
            tempfile.TemporaryDirectory() as temporary,
            patch("skivolve.providers.MAX_RESPONSE_BYTES", 64),
            patch.object(provider, "_terminate_unit") as terminate,
        ):
            payload, _duration = provider._execute(
                [sys.executable, "-c", f"import sys;sys.stdout.write({exact!r})"],
                prompt="",
                cwd=Path(temporary),
                timeout=5,
                unit_name="exact-boundary",
                on_dispatched=callback,
            )
            self.assertEqual(payload, {"x": "x" * 56})
            terminate.assert_not_called()

            with self.assertRaisesRegex(
                ProviderError, "stdout exceeds byte limit"
            ) as caught:
                provider._execute(
                    [
                        sys.executable,
                        "-c",
                        "import sys;sys.stdout.write('x'*10000)",
                    ],
                    prompt="",
                    cwd=Path(temporary),
                    timeout=5,
                    unit_name="overflow-boundary",
                    on_dispatched=callback,
                )
        self.assertIsInstance(caught.exception.__cause__, TransportOverflowError)
        self.assertEqual(len(caught.exception.__cause__.captured), 64)
        terminate.assert_called_once_with("overflow-boundary")
        self.assertEqual(callback.call_count, 2)

    @patch("skivolve.providers.execute_bounded_transport")
    def test_response_without_actual_model_fails_closed(self, run) -> None:
        run.side_effect = [
            self.transport(
                json.dumps({"result": "done", "total_cost_usd": 0.1}),
            ),
        ]
        provider = ClaudeCliProvider(self.config())
        with tempfile.TemporaryDirectory() as temporary:
            with self.assertRaisesRegex(ProviderError, "did not identify the model"):
                provider.run_agent(
                    AgentRequest(
                        case_id="case",
                        variant_id="variant",
                        prompt="prompt",
                        model="claude-test-20260710",
                        workspace=Path(temporary),
                        skill_snapshot=None,
                        sandbox_pair_root=Path(temporary),
                        sandbox_repository_root=Path(temporary),
                        system_context="context",
                        timeout_seconds=5,
                    )
                )

    @patch("skivolve.providers.execute_bounded_transport")
    def test_response_without_pinned_requested_model_fails_closed(self, run) -> None:
        run.side_effect = [
            self.transport(
                json.dumps(
                    {
                        "result": "done",
                        "total_cost_usd": 0.1,
                        "usage": {"input_tokens": 1},
                        "modelUsage": {"claude-fallback-20260710": {}},
                    }
                ),
            ),
        ]
        provider = ClaudeCliProvider(self.config())
        with tempfile.TemporaryDirectory() as temporary:
            with self.assertRaisesRegex(ProviderError, "pinned requested model"):
                provider.run_agent(
                    AgentRequest(
                        case_id="case",
                        variant_id="variant",
                        prompt="prompt",
                        model="claude-test-20260710",
                        workspace=Path(temporary),
                        skill_snapshot=None,
                        sandbox_pair_root=Path(temporary),
                        sandbox_repository_root=Path(temporary),
                        system_context="context",
                        timeout_seconds=5,
                    )
                )

    @patch("skivolve.providers.execute_bounded_transport")
    def test_missing_cost_or_negative_tokens_fail_closed(self, run) -> None:
        payloads = [
            {
                "result": "done",
                "usage": {"input_tokens": 1},
                "modelUsage": {"claude-test-20260710": {}},
            },
            {
                "result": "done",
                "total_cost_usd": 0.1,
                "usage": {"input_tokens": -1},
                "modelUsage": {"claude-test-20260710": {}},
            },
            {
                "result": "done",
                "total_cost_usd": 1.26,
                "usage": {"input_tokens": 1},
                "modelUsage": {"claude-test-20260710": {}},
            },
        ]
        run.side_effect = [self.transport(json.dumps(payload)) for payload in payloads]
        provider = ClaudeCliProvider(self.config())
        with tempfile.TemporaryDirectory() as temporary:
            request = AgentRequest(
                case_id="case",
                variant_id="variant",
                prompt="prompt",
                model="claude-test-20260710",
                workspace=Path(temporary),
                skill_snapshot=None,
                sandbox_pair_root=Path(temporary),
                sandbox_repository_root=Path(temporary),
                system_context="context",
                timeout_seconds=5,
            )
            with self.assertRaisesRegex(ProviderError, "omitted total_cost_usd"):
                provider.run_agent(request)
            with self.assertRaisesRegex(ProviderError, "must be non-negative"):
                provider.run_agent(request)
            with self.assertRaisesRegex(ProviderError, "above the configured"):
                provider.run_agent(request)

    def test_run_agent_when_executable_path_drifts_rejects_dispatch(
        self,
    ) -> None:
        # Arrange
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            executable = root / "claude"
            replacement = root / "replacement"
            executable.write_text("#!/bin/sh\nexit 0\n", encoding="utf-8")
            replacement.write_text("#!/bin/sh\nexit 1\n", encoding="utf-8")
            executable.chmod(0o700)
            replacement.chmod(0o700)
            provider = ClaudeCliProvider(
                ProviderConfig(
                    adapter_id="claude-cli",
                    kind="claude",
                    executable=str(executable),
                    model="claude-test-20260710",
                    max_budget_usd=1.0,
                    timeout_seconds=30,
                )
            )
            os.replace(replacement, executable)

            # Act + Assert
            with self.assertRaisesRegex(ProviderError, "executable drifted"):
                provider.run_agent(
                    AgentRequest(
                        case_id="case",
                        variant_id="variant",
                        prompt="prompt",
                        model="claude-test-20260710",
                        workspace=root,
                        skill_snapshot=None,
                        sandbox_pair_root=root,
                        sandbox_repository_root=root,
                        system_context="context",
                        timeout_seconds=5,
                    )
                )

    @patch("skivolve.providers.execute_bounded_transport")
    def test_agent_timeout_is_a_provider_failure(self, run) -> None:
        run.side_effect = CalibrationError("Claude CLI timed out after 2s")
        provider = ClaudeCliProvider(self.config())
        with tempfile.TemporaryDirectory() as temporary:
            with self.assertRaisesRegex(ProviderError, "timed out"):
                provider.run_agent(
                    AgentRequest(
                        case_id="case",
                        variant_id="variant",
                        prompt="prompt",
                        model="claude-test-20260710",
                        workspace=Path(temporary),
                        skill_snapshot=None,
                        sandbox_pair_root=Path(temporary),
                        sandbox_repository_root=Path(temporary),
                        system_context="context",
                        timeout_seconds=2,
                    )
                )

    def test_comparator_transport_and_sandbox_errors_are_redacted(self) -> None:
        sentinel = "SENTINEL_COMPARATOR_SECRET"
        provider = ClaudeCliProvider(self.config())
        runtime = Mock()
        runtime.bundle.release = {
            "execution_limits": {
                "timeout_seconds": 30,
                "per_invocation_max_usd": 1.25,
            }
        }
        request = self.comparator_request(runtime)

        transport_failure = RuntimeError(sentinel)
        runtime.run_transport.side_effect = transport_failure
        with self.assertRaises(ProviderError) as caught:
            provider._run_comparator_with_executor(request, Mock())
        self.assertEqual(str(caught.exception), "Claude comparator transport failed")
        self.assertIs(caught.exception.__cause__, transport_failure)
        self.assertNotIn(sentinel, str(caught.exception))

        sandbox_failure = OSError(sentinel)
        with (
            patch(
                "skivolve.providers.SandboxedClaudeExecutor",
                side_effect=sandbox_failure,
            ),
            self.assertRaises(ProviderError) as caught,
        ):
            provider.run_comparator(request)
        self.assertEqual(
            str(caught.exception), "Claude comparator sandbox initialization failed"
        )
        self.assertIs(caught.exception.__cause__, sandbox_failure)
        self.assertNotIn(sentinel, str(caught.exception))


class FakeProviderComparatorTests(unittest.TestCase):
    def test_comparator_transport_error_is_redacted(self) -> None:
        sentinel = "SENTINEL_COMPARATOR_SECRET"
        failure = RuntimeError(sentinel)
        runtime = Mock()
        runtime.run_transport.side_effect = failure
        request = ComparatorRequest(
            pair={"id": "opaque-pair"},
            repetition=0,
            order="AB",
            request_bytes=b"{}",
            runtime=runtime,
            spend_ledger=SpendLedger(1.0),
            model="fake-model",
            timeout_seconds=30,
            max_budget_usd=1.0,
            sandbox_repository_root=Path.cwd(),
        )
        provider = FakeProvider(
            comparator_handler=lambda _request: {"structured_output": {}}
        )

        with self.assertRaises(ProviderError) as caught:
            provider.run_comparator(request)

        self.assertEqual(str(caught.exception), "fake comparator transport failed")
        self.assertIs(caught.exception.__cause__, failure)
        self.assertNotIn(sentinel, str(caught.exception))


class SharedComparatorRuntimeTests(unittest.TestCase):
    def _executor_without_init(self) -> SandboxedClaudeExecutor:
        executor = object.__new__(SandboxedClaudeExecutor)
        executor._terminate = Mock()
        return executor

    def test_verified_executable_uses_a_private_copy_and_detects_path_drift(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / "claude"
            replacement = Path(temporary) / "replacement"
            original = b"#!/bin/sh\nprintf original\\n\n"
            path.write_bytes(original)
            replacement.write_bytes(b"#!/bin/sh\nprintf replacement\\n\n")
            path.chmod(0o700)
            replacement.chmod(0o700)
            verified = VerifiedExecutable(path)
            self.addCleanup(verified.close)

            os.replace(replacement, path)

            self.assertEqual(Path(verified.descriptor_path).read_bytes(), original)
            with self.assertRaisesRegex(CalibrationError, "changed"):
                verified.ensure_source_unchanged()

    def test_stdout_overflow_is_bounded_and_kills_the_unit(self) -> None:
        executor = self._executor_without_init()
        with (
            tempfile.TemporaryDirectory() as temporary,
            patch.object(comparator_runtime, "MAX_RESPONSE_BYTES", 64),
        ):
            with self.assertRaises(TransportOverflowError) as raised:
                executor._execute_bounded(
                    [sys.executable, "-c", "import sys;sys.stdout.write('x'*10000)"],
                    cwd=Path(temporary),
                    stdin_bytes=b"",
                    timeout_seconds=5,
                    unit_name="overflow-stdout",
                    evidence={"kind": "test"},
                )
        self.assertEqual(raised.exception.stream, "stdout")
        self.assertEqual(raised.exception.captured, b"x" * 64)
        executor._terminate.assert_called_once_with("overflow-stdout")

    def test_stderr_overflow_is_bounded_and_kills_the_unit(self) -> None:
        executor = self._executor_without_init()
        with (
            tempfile.TemporaryDirectory() as temporary,
            patch.object(comparator_runtime, "MAX_STDERR_BYTES", 48),
        ):
            with self.assertRaises(TransportOverflowError) as raised:
                executor._execute_bounded(
                    [sys.executable, "-c", "import sys;sys.stderr.write('e'*10000)"],
                    cwd=Path(temporary),
                    stdin_bytes=b"",
                    timeout_seconds=5,
                    unit_name="overflow-stderr",
                    evidence={"kind": "test"},
                )
        self.assertEqual(raised.exception.stream, "stderr")
        self.assertEqual(raised.exception.captured, b"e" * 48)
        executor._terminate.assert_called_once_with("overflow-stderr")

    def test_unclosed_reservation_is_fully_charged_after_resume(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            journal = Path(temporary) / "spend.jsonl"
            first = SpendLedger(2.0, journal)
            first.reserve(
                1.0,
                request_sha256=_REQUEST_SHA256,
                invocation_id=_INVOCATION_ID,
            )
            resumed = SpendLedger(2.0, journal)
            self.assertEqual(resumed.spent_usd, 1.0)
            reservation = resumed.reserve(
                1.0,
                request_sha256="c" * 64,
                invocation_id="d" * 64,
            )
            reservation.reconcile(0.25)
            self.assertEqual(resumed.spent_usd, 1.25)
            records = resumed.journal_records()
            self.assertEqual(
                {
                    (record["request_sha256"], record["invocation_id"])
                    for record in records
                },
                {
                    (_REQUEST_SHA256, _INVOCATION_ID),
                    ("c" * 64, "d" * 64),
                },
            )
            self.assertEqual(stat.S_IMODE(journal.stat().st_mode), 0o600)
            with self.assertRaisesRegex(CalibrationError, "lacks budget"):
                resumed.reserve(
                    1.0,
                    request_sha256="e" * 64,
                    invocation_id="f" * 64,
                )

    def test_spend_journal_rejects_unbound_and_cross_request_records(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            journal = Path(temporary) / "invalid-before-write.jsonl"
            ledger = SpendLedger(2.0, journal)
            with self.assertRaisesRegex(CalibrationError, "request binding"):
                ledger.reserve(
                    1.0,
                    request_sha256=_REQUEST_SHA256.upper(),
                    invocation_id=_INVOCATION_ID,
                )
            self.assertFalse(journal.exists())

        attempt_id = "1" * 32
        valid = [
            {
                "event": "reserve",
                "attempt_id": attempt_id,
                "invocation_id": _INVOCATION_ID,
                "request_sha256": _REQUEST_SHA256,
                "reserved_usd": 1.0,
            },
            {
                "event": "reconcile",
                "attempt_id": attempt_id,
                "charged_usd": 0.25,
                "invocation_id": _INVOCATION_ID,
                "request_sha256": _REQUEST_SHA256,
            },
        ]
        cases = {
            "legacy": lambda records: records[0].pop("request_sha256"),
            "uppercase": lambda records: records[0].__setitem__(
                "request_sha256", _REQUEST_SHA256.upper()
            ),
            "request drift": lambda records: records[1].__setitem__(
                "request_sha256", "c" * 64
            ),
            "invocation drift": lambda records: records[1].__setitem__(
                "invocation_id", "d" * 64
            ),
        }
        for label, mutate in cases.items():
            with self.subTest(label=label), tempfile.TemporaryDirectory() as temporary:
                records = copy.deepcopy(valid)
                mutate(records)
                journal = Path(temporary) / "spend.jsonl"
                journal.write_bytes(
                    b"".join(
                        comparator_runtime.canonical_bytes(record) + b"\n"
                        for record in records
                    )
                )
                journal.chmod(0o600)
                with self.assertRaises(CalibrationError):
                    SpendLedger(2.0, journal)

    def test_forfeit_repeats_the_exact_request_binding(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            ledger = SpendLedger(1.0, Path(temporary) / "spend.jsonl")
            reservation = ledger.reserve(
                1.0,
                request_sha256=_REQUEST_SHA256,
                invocation_id=_INVOCATION_ID,
            )
            reservation.forfeit()
            records = ledger.journal_records()
        self.assertEqual(
            [record["event"] for record in records], ["reserve", "forfeit"]
        )
        self.assertTrue(
            all(
                record["request_sha256"] == _REQUEST_SHA256
                and record["invocation_id"] == _INVOCATION_ID
                for record in records
            )
        )

    def test_first_spend_journal_creation_fsyncs_file_and_parent(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            real_fsync = os.fsync
            with patch(
                "skivolve.comparator_runtime.os.fsync", wraps=real_fsync
            ) as fsync:
                SpendLedger(2.0, Path(temporary) / "spend.jsonl").reserve(
                    1.0,
                    request_sha256=_REQUEST_SHA256,
                    invocation_id=_INVOCATION_ID,
                )
            self.assertGreaterEqual(fsync.call_count, 2)

    def test_private_json_writer_is_atomic_owner_only_and_rejects_links(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            target = root / "evidence.json"
            atomic_write_private_json(target, {"round": 1})
            self.assertEqual(stat.S_IMODE(target.stat().st_mode), 0o600)
            self.assertEqual(load_private_json(target), {"round": 1})

            atomic_write_private_json(target, {"round": 2})
            self.assertEqual(load_private_json(target), {"round": 2})
            self.assertFalse(any(path.name.endswith(".tmp") for path in root.iterdir()))

            victim = root / "victim.json"
            victim.write_text("{}", encoding="utf-8")
            victim.chmod(0o600)
            link = root / "linked.json"
            link.symlink_to(victim)
            with self.assertRaisesRegex(CalibrationError, "owner-only regular"):
                atomic_write_private_json(link, {"forged": True})

            external = root.parent / f"{root.name}-external"
            external.mkdir()
            self.addCleanup(shutil.rmtree, external, True)
            escape = root / "escape"
            escape.symlink_to(external, target_is_directory=True)
            escaped_target = escape / "created" / "evidence.json"
            with self.assertRaisesRegex(CalibrationError, "must not traverse"):
                atomic_write_private_json(escaped_target, {"forged": True})
            self.assertFalse((external / "created").exists())

    def test_private_json_capture_detects_same_inode_mutation_during_read(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            target = Path(temporary) / "evidence.json"
            atomic_write_private_json(target, {"value": "aaaa"})
            original_read = os.read
            mutated = False

            def mutating_read(descriptor: int, size: int) -> bytes:
                nonlocal mutated
                chunk = original_read(descriptor, size)
                if chunk and not mutated:
                    mutated = True
                    replacement = target.read_bytes().replace(b"aaaa", b"bbbb")
                    target.write_bytes(replacement)
                    target.chmod(0o600)
                return chunk

            with patch(
                "skivolve.comparator_runtime.os.read", side_effect=mutating_read
            ):
                with self.assertRaisesRegex(CalibrationError, "stable owner-only"):
                    load_private_json_capture(target)

    def test_spend_journal_rejects_links_unsafe_modes_and_inode_replacement(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            victim = root / "victim.jsonl"
            victim.write_bytes(b"")
            victim.chmod(0o600)
            linked = root / "linked.jsonl"
            linked.symlink_to(victim)
            with self.assertRaisesRegex(CalibrationError, "owner-only regular"):
                SpendLedger(2.0, linked)

            unsafe = root / "unsafe.jsonl"
            unsafe.write_bytes(b"")
            unsafe.chmod(0o644)
            with self.assertRaisesRegex(CalibrationError, "owner-only regular"):
                SpendLedger(2.0, unsafe)

            journal = root / "spend.jsonl"
            ledger = SpendLedger(4.0, journal)
            ledger.reserve(
                1.0,
                request_sha256=_REQUEST_SHA256,
                invocation_id=_INVOCATION_ID,
            )
            replacement = root / "replacement.jsonl"
            replacement.write_bytes(journal.read_bytes())
            replacement.chmod(0o600)
            os.replace(replacement, journal)
            with self.assertRaisesRegex(CalibrationError, "owner-only regular"):
                ledger.reserve(
                    1.0,
                    request_sha256="c" * 64,
                    invocation_id="d" * 64,
                )

    def test_write_certification_when_target_boundary_varies_enforces_private_file(
        self,
    ) -> None:
        # Arrange
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary).resolve()
            evidence = root / "evidence.json"
            atomic_write_private_json(evidence, {"schema_version": 1})
            runtime = SimpleNamespace(
                root=root,
                bundle=object(),
                release_summary={"release_sha256": "a" * 64},
            )
            result = {
                "passed": True,
                "actual_model_sets": [["claude-sonnet-5"]],
                "executable_sha256s": ["b" * 64],
                "systemd_versions": ["systemd 255"],
            }
            destination = root / "certification.json"

            # Act
            with patch.object(
                comparator_runtime._calibration,
                "evaluate_evidence",
                return_value=result,
            ):
                write_certification(runtime, evidence, destination)

            # Assert
            self.assertEqual(stat.S_IMODE(destination.stat().st_mode), 0o600)

            # Arrange
            victim = root / "victim.json"
            victim.write_text("{}", encoding="utf-8")
            victim.chmod(0o600)
            linked = root / "linked-certification.json"
            linked.symlink_to(victim)

            # Act + Assert
            with (
                patch.object(
                    comparator_runtime._calibration,
                    "evaluate_evidence",
                    return_value=result,
                ),
                self.assertRaisesRegex(CalibrationError, "owner-only regular"),
            ):
                write_certification(runtime, evidence, linked)

            # Arrange
            external = root.parent / f"{root.name}-external"
            external.mkdir()
            self.addCleanup(shutil.rmtree, external, True)
            escape = root / "escape"
            escape.symlink_to(external, target_is_directory=True)
            escaped_destination = escape / "created" / "certification.json"

            # Act + Assert
            with (
                patch.object(
                    comparator_runtime._calibration,
                    "evaluate_evidence",
                    return_value=result,
                ),
                self.assertRaisesRegex(CalibrationError, "escapes its root"),
            ):
                write_certification(runtime, evidence, escaped_destination)

            # Assert
            self.assertFalse((external / "created").exists())

    def test_load_certification_when_systemd_version_drifts_rejects_authority(
        self,
    ) -> None:
        # Arrange
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary).resolve()
            evidence = root / "evidence.json"
            atomic_write_private_json(evidence, {"schema_version": 1})
            bundle = SimpleNamespace(release={"locked": True})
            runtime = SimpleNamespace(
                root=root,
                bundle=bundle,
                release_summary={
                    "release_sha256": comparator_runtime.canonical_sha256(
                        bundle.release
                    )
                },
            )
            result = {
                "passed": True,
                "actual_model_sets": [["claude-sonnet-5"]],
                "executable_sha256s": ["b" * 64],
                "systemd_versions": ["systemd 255"],
            }
            destination = root / "certification.json"

            # Act
            with patch.object(
                comparator_runtime._calibration,
                "evaluate_evidence",
                return_value=result,
            ):
                write_certification(runtime, evidence, destination)
                certification = comparator_runtime._load_certification(
                    bundle,
                    root,
                    destination.name,
                    allow_missing=False,
                )

            # Assert
            self.assertTrue(certification.valid)
            self.assertEqual(certification.systemd_version, "systemd 255")

            # Arrange
            payload = load_private_json(destination)
            payload["systemd_version"] = "systemd 256"
            atomic_write_private_json(destination, payload)

            # Act
            with patch.object(
                comparator_runtime._calibration,
                "evaluate_evidence",
                return_value=result,
            ):
                certification = comparator_runtime._load_certification(
                    bundle,
                    root,
                    destination.name,
                    allow_missing=False,
                )

            # Assert
            self.assertFalse(certification.valid)
            self.assertIn("systemd version", certification.error)


if __name__ == "__main__":
    unittest.main()
