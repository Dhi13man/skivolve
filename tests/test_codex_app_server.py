from __future__ import annotations

import collections
import contextlib
import ctypes
import errno
import fcntl
import hashlib
import json
import os
import select
import signal
import shutil
import socket
import stat
import subprocess
import sys
import tempfile
import threading
import time
import tomllib
import unittest
from dataclasses import asdict, replace
from pathlib import Path
from typing import Any, Iterator
from unittest import mock


HARNESS_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(HARNESS_ROOT))

from skivolve.comparator_runtime import (  # noqa: E402
    CalibrationError,
    VerifiedExecutable as RuntimeVerifiedExecutable,
)
from skivolve.codex_app_server import (  # noqa: E402
    _ALLOWED_ITEM_TYPES,
    _AppServerProtocol,
    _CleanupPoisonStore,
    _JsonRpcSession,
    _LAUNCH_GATE_SCRIPT,
    _MAX_COLLAB_THREADS,
    _PoisonBinding,
    _ProcessTransport,
    _SystemdRecoveryProbe,
    _auth_lock,
    _cleanup_workspace_runtime,
    _command_sha256,
    _load_protocol_lock,
    _linux_process_start_time,
    _prepare_workspace_runtime,
    _remaining,
    _remove_invocation_root,
    _static_config,
    _resolve_gate_shell,
    _resolve_system_tool,
    validate_codex_protocol_lock,
    _validate_cli_version_output,
    CodexAppServerProvider,
    ProviderTimeoutError,
)
from skivolve.manifest import ProviderConfig  # noqa: E402
from skivolve.providers import AgentRequest, ProviderError  # noqa: E402


LOCK_PATH = HARNESS_ROOT / "codex-app-server-lock.json"
_REAL_CODEX_PREREQUISITE = (
    "real Codex tests require CODEX_EVAL_EXECUTABLE or codex on PATH"
)
_PR_SET_CHILD_SUBREAPER = 36
_PR_GET_CHILD_SUBREAPER = 37


@contextlib.contextmanager
def _linux_child_subreaper() -> Iterator[None]:
    libc = ctypes.CDLL(None, use_errno=True)
    prctl = libc.prctl
    prctl.argtypes = (
        ctypes.c_int,
        ctypes.c_ulong,
        ctypes.c_ulong,
        ctypes.c_ulong,
        ctypes.c_ulong,
    )
    prctl.restype = ctypes.c_int
    original = ctypes.c_int()
    original_pointer = ctypes.cast(ctypes.byref(original), ctypes.c_void_p).value
    if (
        original_pointer is None
        or prctl(_PR_GET_CHILD_SUBREAPER, original_pointer, 0, 0, 0) != 0
    ):
        error = ctypes.get_errno()
        raise OSError(error, "cannot read child-subreaper state")
    changed = original.value == 0
    if changed and prctl(_PR_SET_CHILD_SUBREAPER, 1, 0, 0, 0) != 0:
        error = ctypes.get_errno()
        raise OSError(error, "cannot enable child-subreaper state")
    try:
        yield
    finally:
        if changed and prctl(_PR_SET_CHILD_SUBREAPER, 0, 0, 0, 0) != 0:
            error = ctypes.get_errno()
            raise OSError(error, "cannot restore child-subreaper state")


def _discover_codex_executable() -> Path | None:
    explicit = os.environ.get("CODEX_EVAL_EXECUTABLE")
    if explicit is not None:
        raw_path = explicit
        source = "CODEX_EVAL_EXECUTABLE"
    else:
        located = shutil.which("codex")
        if located is None:
            return None
        raw_path = located
        source = "PATH codex"
    try:
        resolved = Path(raw_path).expanduser().resolve(strict=True)
    except OSError as exc:
        raise RuntimeError(f"{source} does not resolve to an executable file") from exc
    if not resolved.is_file() or not os.access(resolved, os.X_OK):
        raise RuntimeError(f"{source} does not resolve to an executable file")
    return resolved


try:
    REAL_CODEX_EXECUTABLE = _discover_codex_executable()
    REAL_CODEX_DISCOVERY_ERROR: str | None = None
except RuntimeError as discovery_error:
    REAL_CODEX_EXECUTABLE = None
    REAL_CODEX_DISCOVERY_ERROR = str(discovery_error)


def _require_real_codex(test: unittest.TestCase) -> Path:
    if REAL_CODEX_DISCOVERY_ERROR is not None:
        test.fail(REAL_CODEX_DISCOVERY_ERROR)
    if REAL_CODEX_EXECUTABLE is None:
        test.skipTest(_REAL_CODEX_PREREQUISITE)
    return REAL_CODEX_EXECUTABLE


def _line(value: dict[str, Any]) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":")).encode() + b"\n"


def _model(model: str, efforts: tuple[str, ...]) -> dict[str, Any]:
    return {
        "defaultReasoningEffort": "medium",
        "description": "test model",
        "displayName": model,
        "hidden": False,
        "id": model,
        "isDefault": False,
        "model": model,
        "supportedReasoningEfforts": [
            {"description": effort, "reasoningEffort": effort} for effort in efforts
        ],
    }


def _rate_limits(used: int, limit_id: str = "codex") -> dict[str, Any]:
    snapshot = {
        "limitId": limit_id,
        "limitName": "Codex",
        "planType": "pro",
        "primary": {
            "resetsAt": 2_000_000_000,
            "usedPercent": used,
            "windowDurationMins": 300,
        },
        "secondary": None,
    }
    return {
        "rateLimitResetCredits": None,
        "rateLimits": snapshot,
        "rateLimitsByLimitId": {limit_id: dict(snapshot)},
    }


class CodexExecutableDiscoveryTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)

    def executable(self, name: str) -> Path:
        path = self.root / name
        path.write_text("#!/bin/sh\nexit 0\n", encoding="ascii")
        path.chmod(0o755)
        return path.resolve(strict=True)

    def test_explicit_executable_takes_precedence_without_path_lookup(self) -> None:
        explicit = self.executable("explicit-codex")
        fallback = self.executable("path-codex")
        with (
            mock.patch.dict(
                os.environ, {"CODEX_EVAL_EXECUTABLE": str(explicit)}, clear=True
            ),
            mock.patch.object(shutil, "which", return_value=str(fallback)) as which,
        ):
            observed = _discover_codex_executable()

        self.assertEqual(observed, explicit)
        which.assert_not_called()

    def test_invalid_explicit_executable_fails_without_path_fallback(self) -> None:
        fallback = self.executable("path-codex")
        missing = self.root / "missing-codex"
        with (
            mock.patch.dict(
                os.environ, {"CODEX_EVAL_EXECUTABLE": str(missing)}, clear=True
            ),
            mock.patch.object(shutil, "which", return_value=str(fallback)) as which,
            self.assertRaisesRegex(RuntimeError, "CODEX_EVAL_EXECUTABLE"),
        ):
            _discover_codex_executable()

        which.assert_not_called()

    def test_path_lookup_is_used_when_explicit_override_is_absent(self) -> None:
        fallback = self.executable("path-codex")
        with (
            mock.patch.dict(os.environ, {}, clear=True),
            mock.patch.object(shutil, "which", return_value=str(fallback)) as which,
        ):
            observed = _discover_codex_executable()

        self.assertEqual(observed, fallback)
        which.assert_called_once_with("codex")

    def test_missing_explicit_and_path_executable_returns_none(self) -> None:
        with (
            mock.patch.dict(os.environ, {}, clear=True),
            mock.patch.object(shutil, "which", return_value=None) as which,
        ):
            observed = _discover_codex_executable()

        self.assertIsNone(observed)
        which.assert_called_once_with("codex")


class ScriptedTransport:
    def __init__(
        self,
        workspace: Path,
        *,
        additional_item_completed: dict[str, Any] | None = None,
        completed_text: str = "completed fixture",
        reroute: bool = False,
        omit_usage: bool = False,
        disagree_final_field: str | None = None,
        duplicate_item_completed: bool = False,
        final_phase: str = "final_answer",
        full_has_non_object_item: bool = False,
        identifier_sentinel: str | None = None,
        omit_item_completed: bool = False,
        not_loaded_has_items: bool = False,
        skill_disable_succeeds: bool = True,
        thread_cli_version: str = "0.144.3",
        turn_error: dict[str, Any] | None = None,
        turn_items_view: str | None = "notLoaded",
    ) -> None:
        self.workspace = workspace
        self.additional_item_completed = additional_item_completed
        self.completed_text = completed_text
        self.reroute = reroute
        self.omit_usage = omit_usage
        self.disagree_final_field = disagree_final_field
        self.duplicate_item_completed = duplicate_item_completed
        self.final_phase = final_phase
        self.full_has_non_object_item = full_has_non_object_item
        self.omit_item_completed = omit_item_completed
        self.not_loaded_has_items = not_loaded_has_items
        self.thread_id = (
            f"{identifier_sentinel}.thread" if identifier_sentinel else "thread-1"
        )
        self.turn_id = (
            f"{identifier_sentinel}.turn" if identifier_sentinel else "turn-1"
        )
        self.message_id = (
            f"{identifier_sentinel}.message" if identifier_sentinel else "message-1"
        )
        self.rate_limit_id = identifier_sentinel or "codex"
        self.skill_disable_succeeds = skill_disable_succeeds
        self.thread_cli_version = thread_cli_version
        self.turn_error = turn_error
        self.turn_items_view = turn_items_view
        self.incoming: collections.deque[bytes] = collections.deque()
        self.sent: list[dict[str, Any]] = []
        self.closed = False
        self.experimental_api = False
        self.skills_enabled = True
        self.rate_reads = 0
        self.evidence = {
            "cleanup_confirmed": True,
            "kind": "scripted",
            "enforced": True,
        }

    def send(self, payload: bytes, _deadline: float) -> None:
        message = json.loads(payload)
        self.sent.append(message)
        if "method" not in message or "id" not in message:
            return
        request_id = message["id"]
        method = message["method"]
        params = message.get("params")
        if method == "initialize":
            self.experimental_api = (
                params.get("capabilities", {}).get("experimentalApi") is True
            )
            result = {
                "codexHome": str(self.workspace.parent / "codex-home"),
                "platformFamily": "unix",
                "platformOs": "linux",
                "userAgent": "codex-cli-test",
            }
        elif method == "model/list":
            if params.get("cursor") is None:
                result = {
                    "data": [_model("irrelevant", ("low",))],
                    "nextCursor": "model-page-2",
                }
            else:
                result = {
                    "data": [
                        _model(
                            "gpt-5.6-luna",
                            ("low", "medium", "high", "xhigh", "max"),
                        )
                    ],
                    "nextCursor": None,
                }
        elif method == "permissionProfile/list":
            if params.get("cursor") is None:
                result = {
                    "data": [{"allowed": True, "id": ":read-only"}],
                    "nextCursor": "profile-page-2",
                }
            else:
                result = {
                    "data": [{"allowed": True, "id": "eval"}],
                    "nextCursor": None,
                }
        elif method == "account/read":
            result = {
                "account": {
                    "email": "must-not-survive@example.invalid",
                    "planType": "pro",
                    "type": "chatgpt",
                },
                "requiresOpenaiAuth": True,
            }
        elif method == "account/rateLimits/read":
            self.rate_reads += 1
            result = _rate_limits(
                10 if self.rate_reads == 1 else 45, self.rate_limit_id
            )
        elif method == "skills/list":
            result = {
                "data": [
                    {
                        "cwd": str(self.workspace),
                        "errors": [],
                        "skills": [
                            {
                                "description": "bundled",
                                "enabled": self.skills_enabled,
                                "name": "bundled-system-skill",
                                "path": "/isolated/system-skill",
                                "scope": "system",
                            }
                        ],
                    }
                ]
            }
        elif method == "skills/config/write":
            if self.skill_disable_succeeds:
                self.skills_enabled = False
            result = {"effectiveEnabled": not self.skill_disable_succeeds}
        elif method == "thread/start":
            if not self.experimental_api:
                self.incoming.append(
                    _line(
                        {
                            "id": request_id,
                            "error": {
                                "code": -32600,
                                "message": (
                                    "thread/start.runtimeWorkspaceRoots requires "
                                    "experimentalApi capability"
                                ),
                            },
                        }
                    )
                )
                return
            result = {
                "activePermissionProfile": {"extends": None, "id": "eval"},
                "approvalPolicy": "never",
                "approvalsReviewer": "user",
                "cwd": str(self.workspace),
                "instructionSources": [],
                "model": "gpt-5.6-luna",
                "modelProvider": "openai",
                "reasoningEffort": "low",
                "runtimeWorkspaceRoots": [str(self.workspace)],
                "sandbox": {"type": "workspaceWrite"},
                "thread": {"id": self.thread_id},
            }
            result["thread"].update(
                {
                    "cliVersion": self.thread_cli_version,
                    "createdAt": 1_700_000_000,
                    "cwd": str(self.workspace),
                    "ephemeral": True,
                    "historyMode": "paginated",
                    "modelProvider": "openai",
                    "path": None,
                    "preview": "",
                    "sessionId": "session-1",
                    "source": "vscode",
                    "status": {"type": "idle"},
                    "threadSource": "skill-eval",
                    "turns": [],
                    "updatedAt": 1_700_000_000,
                }
            )
        elif method == "turn/start":
            result = {"turn": {"id": self.turn_id, "items": [], "status": "inProgress"}}
        else:
            raise AssertionError(f"unexpected client method: {method}")
        self.incoming.append(_line({"id": request_id, "result": result}))
        if method == "turn/start":
            self._queue_turn_events()

    def _queue_turn_events(self) -> None:
        if self.reroute:
            self.incoming.append(
                _line(
                    {
                        "method": "model/rerouted",
                        "params": {
                            "fromModel": "gpt-5.6-luna",
                            "reason": "test",
                            "threadId": self.thread_id,
                            "toModel": "other",
                            "turnId": self.turn_id,
                        },
                    }
                )
            )
        self.incoming.append(
            _line(
                {
                    "method": "account/rateLimits/updated",
                    "params": {
                        "rateLimits": {
                            "limitId": self.rate_limit_id,
                            "planType": None,
                            "primary": {"usedPercent": 40},
                        }
                    },
                }
            )
        )
        if not self.omit_item_completed:
            primary_item = {
                "id": self.message_id,
                "phase": self.final_phase,
                "text": self.completed_text,
                "type": "agentMessage",
            }
            completed_items = [primary_item]
            if self.duplicate_item_completed:
                completed_items.append(primary_item)
            if self.additional_item_completed is not None:
                completed_items.append(self.additional_item_completed)
            for item in completed_items:
                self.incoming.append(
                    _line(
                        {
                            "method": "item/completed",
                            "params": {
                                "completedAtMs": 1,
                                "item": item,
                                "threadId": self.thread_id,
                                "turnId": self.turn_id,
                            },
                        },
                    )
                )
        if not self.omit_usage:
            self.incoming.append(
                _line(
                    {
                        "method": "thread/tokenUsage/updated",
                        "params": {
                            "threadId": self.thread_id,
                            "tokenUsage": {
                                "last": {
                                    "cachedInputTokens": 2,
                                    "inputTokens": 10,
                                    "outputTokens": 5,
                                    "reasoningOutputTokens": 1,
                                    "totalTokens": 15,
                                },
                                "modelContextWindow": 372000,
                                "total": {
                                    "cachedInputTokens": 2,
                                    "inputTokens": 10,
                                    "outputTokens": 5,
                                    "reasoningOutputTokens": 1,
                                    "totalTokens": 15,
                                },
                            },
                            "turnId": self.turn_id,
                        },
                    }
                )
            )
        full_items = [
            {
                "id": (
                    "different-message"
                    if self.disagree_final_field == "id"
                    else self.message_id
                ),
                "phase": (
                    None if self.disagree_final_field == "phase" else self.final_phase
                ),
                "text": (
                    "different"
                    if self.disagree_final_field == "text"
                    else self.completed_text
                ),
                "type": "agentMessage",
            }
        ]
        if self.additional_item_completed is not None:
            full_items.append(self.additional_item_completed)
        if self.full_has_non_object_item:
            full_items.append(None)
        turn_items = (
            full_items
            if self.turn_items_view in {None, "full"} or self.not_loaded_has_items
            else []
        )
        turn = {
            "durationMs": 25,
            "id": self.turn_id,
            "items": turn_items,
            "status": "completed",
        }
        if self.turn_error is not None:
            turn["error"] = self.turn_error
        if self.turn_items_view is not None:
            turn["itemsView"] = self.turn_items_view
        self.incoming.append(
            _line(
                {
                    "method": "turn/completed",
                    "params": {
                        "threadId": self.thread_id,
                        "turn": turn,
                    },
                }
            )
        )

    def receive(self, _deadline: float) -> bytes:
        if not self.incoming:
            raise AssertionError("scripted transport has no response")
        return self.incoming.popleft().removesuffix(b"\n")

    def close(self) -> None:
        self.closed = True


class QueueTransport:
    def __init__(self, frames: list[bytes]) -> None:
        self.frames = collections.deque(frames)
        self.sent: list[dict[str, Any]] = []
        self.closed = False
        self.evidence = {"kind": "queue"}

    def send(self, payload: bytes, _deadline: float) -> None:
        self.sent.append(json.loads(payload))

    def receive(self, _deadline: float) -> bytes:
        return self.frames.popleft()

    def close(self) -> None:
        self.closed = True


def _protocol(
    transport: ScriptedTransport | QueueTransport,
    *,
    on_dispatched: Any = None,
) -> _AppServerProtocol:
    return _AppServerProtocol(
        _JsonRpcSession(transport),
        model="gpt-5.6-luna",
        reasoning_effort="low",
        workspace=Path("/runtime/work"),
        system_context="isolated evaluation",
        locked_efforts=("low", "medium", "high", "xhigh", "max"),
        locked_thread_cli_version="0.144.3",
        expected_codex_home=Path("/runtime/codex-home"),
        on_dispatched=on_dispatched,
    )


class CodexProtocolTests(unittest.TestCase):
    def test_expired_deadline_raises_typed_timeout(self) -> None:
        with self.assertRaisesRegex(
            ProviderTimeoutError, "operation timed out"
        ) as caught:
            _remaining(time.monotonic() - 1, "operation")
        self.assertFalse(caught.exception.cleanup_confirmed)
        confirmed = ProviderTimeoutError("operation timed out", cleanup_confirmed=True)
        self.assertTrue(confirmed.cleanup_confirmed)
        self.assertIsInstance(confirmed, ProviderError)
        with self.assertRaisesRegex(TypeError, "cleanup_confirmed"):
            ProviderTimeoutError("operation timed out", cleanup_confirmed=1)  # type: ignore[arg-type]

    def test_happy_path_paginates_disables_skills_merges_quota_and_uses_last_usage(
        self,
    ) -> None:
        transport = ScriptedTransport(Path("/runtime/work"))
        session = _JsonRpcSession(transport)
        outcome = _AppServerProtocol(
            session,
            model="gpt-5.6-luna",
            reasoning_effort="low",
            workspace=Path("/runtime/work"),
            system_context="isolated evaluation",
            locked_efforts=("low", "medium", "high", "xhigh", "max"),
            locked_thread_cli_version="0.144.3",
            expected_codex_home=Path("/runtime/codex-home"),
        ).run("implement request", time.monotonic() + 5)

        self.assertEqual(outcome.final_output, "completed fixture")
        self.assertEqual(outcome.tokens["input_tokens"], 10)
        self.assertEqual(outcome.tokens["total_tokens"], 15)
        self.assertEqual(outcome.raw_response["turn"]["items_view"], "notLoaded")
        rolling = outcome.quota["rolling"]["rateLimits"]
        self.assertEqual(rolling["planType"], "pro")
        self.assertEqual(rolling["primary"]["usedPercent"], 40)
        self.assertNotIn("email", json.dumps(outcome.raw_response))
        calls = [message for message in transport.sent if "id" in message]
        model_calls = [call for call in calls if call["method"] == "model/list"]
        permission_calls = [
            call for call in calls if call["method"] == "permissionProfile/list"
        ]
        initialize = next(call for call in calls if call["method"] == "initialize")
        self.assertEqual(
            initialize["params"]["capabilities"],
            {"experimentalApi": True, "requestAttestation": False},
        )
        self.assertEqual(model_calls[1]["params"]["cursor"], "model-page-2")
        self.assertEqual(permission_calls[1]["params"]["cursor"], "profile-page-2")
        thread = next(call for call in calls if call["method"] == "thread/start")
        self.assertIs(thread["params"]["allowProviderModelFallback"], False)
        self.assertEqual(thread["params"]["permissions"], "eval")
        self.assertNotIn("environments", thread["params"])
        turn = next(call for call in calls if call["method"] == "turn/start")
        self.assertEqual(turn["params"]["effort"], "low")
        self.assertEqual(turn["params"]["model"], "gpt-5.6-luna")
        self.assertNotIn("environments", turn["params"])

    def test_thread_cli_version_mismatch_fails_before_turn_start(self) -> None:
        for version in ("codex-cli 0.144.1", "0.144.2"):
            with self.subTest(version=version):
                transport = ScriptedTransport(
                    Path("/runtime/work"), thread_cli_version=version
                )
                with self.assertRaisesRegex(ProviderError, "CLI provenance"):
                    _protocol(transport).run("request", time.monotonic() + 5)
                methods = [
                    message["method"] for message in transport.sent if "id" in message
                ]
                self.assertIn("thread/start", methods)
                self.assertNotIn("turn/start", methods)

    def test_reroute_fails_closed(self) -> None:
        transport = ScriptedTransport(Path("/runtime/work"), reroute=True)
        session = _JsonRpcSession(transport)
        with self.assertRaisesRegex(ProviderError, "rerouted"):
            _AppServerProtocol(
                session,
                model="gpt-5.6-luna",
                reasoning_effort="low",
                workspace=Path("/runtime/work"),
                system_context="test",
                locked_efforts=("low", "medium", "high", "xhigh", "max"),
                locked_thread_cli_version="0.144.3",
                expected_codex_home=Path("/runtime/codex-home"),
            ).run("request", time.monotonic() + 5)

    def test_missing_usage_rejects_completed_turn(self) -> None:
        transport = ScriptedTransport(Path("/runtime/work"), omit_usage=True)
        with self.assertRaisesRegex(ProviderError, "token usage"):
            _AppServerProtocol(
                _JsonRpcSession(transport),
                model="gpt-5.6-luna",
                reasoning_effort="low",
                workspace=Path("/runtime/work"),
                system_context="test",
                locked_efforts=("low", "medium", "high", "xhigh", "max"),
                locked_thread_cli_version="0.144.3",
                expected_codex_home=Path("/runtime/codex-home"),
            ).run("request", time.monotonic() + 5)

    def test_disagreeing_final_message_is_rejected(self) -> None:
        for field in ("id", "phase", "text"):
            with self.subTest(field=field):
                transport = ScriptedTransport(
                    Path("/runtime/work"),
                    disagree_final_field=field,
                    turn_items_view="full",
                )
                with self.assertRaisesRegex(ProviderError, "disagrees"):
                    _protocol(transport).run("request", time.monotonic() + 5)

    def test_full_turn_rejects_duplicate_matching_completion_events(self) -> None:
        transport = ScriptedTransport(
            Path("/runtime/work"),
            duplicate_item_completed=True,
            turn_items_view="full",
        )
        with self.assertRaisesRegex(ProviderError, "disagrees"):
            _protocol(transport).run("request", time.monotonic() + 5)

    def test_not_loaded_turn_rejects_duplicate_completion_events(self) -> None:
        transport = ScriptedTransport(
            Path("/runtime/work"), duplicate_item_completed=True
        )
        with self.assertRaisesRegex(ProviderError, "repeated an agent-message id"):
            _protocol(transport).run("request", time.monotonic() + 5)

    def test_not_loaded_turn_rejects_multiple_final_messages(self) -> None:
        transport = ScriptedTransport(
            Path("/runtime/work"),
            additional_item_completed={
                "id": "message-2",
                "phase": "final_answer",
                "text": "second final",
                "type": "agentMessage",
            },
        )
        with self.assertRaisesRegex(ProviderError, "multiple final-answer messages"):
            _protocol(transport).run("request", time.monotonic() + 5)

    def test_last_agent_message_must_be_terminal(self) -> None:
        cases = (
            ("commentary", "ended with commentary"),
            (None, "final-answer message was not terminal"),
        )
        for items_view in ("notLoaded", "full"):
            for phase, expected in cases:
                with self.subTest(items_view=items_view, phase=phase):
                    transport = ScriptedTransport(
                        Path("/runtime/work"),
                        additional_item_completed={
                            "id": "message-2",
                            "phase": phase,
                            "text": "trailing message",
                            "type": "agentMessage",
                        },
                        turn_items_view=items_view,
                    )
                    with self.assertRaisesRegex(ProviderError, expected):
                        _protocol(transport).run("request", time.monotonic() + 5)

    def test_terminal_agent_message_must_contain_non_whitespace_text(self) -> None:
        for items_view in ("notLoaded", "full"):
            with self.subTest(items_view=items_view):
                transport = ScriptedTransport(
                    Path("/runtime/work"),
                    completed_text=" \t\n",
                    turn_items_view=items_view,
                )
                with self.assertRaisesRegex(
                    ProviderError, "final agent message was empty"
                ):
                    _protocol(transport).run("request", time.monotonic() + 5)

    def test_completed_turn_cannot_include_an_error(self) -> None:
        sentinel = "SENTINEL_MUST_NOT_BE_DISCLOSED"
        transport = ScriptedTransport(
            Path("/runtime/work"), turn_error={"message": sentinel}
        )
        with self.assertRaisesRegex(ProviderError, "completed Codex turn") as raised:
            _protocol(transport).run("request", time.monotonic() + 5)
        self.assertNotIn(sentinel, str(raised.exception))

    def test_duplicate_agent_message_ids_are_rejected(self) -> None:
        transport = ScriptedTransport(
            Path("/runtime/work"),
            additional_item_completed={
                "id": "message-1",
                "phase": None,
                "text": "different legacy message",
                "type": "agentMessage",
            },
            final_phase=None,
        )
        with self.assertRaisesRegex(ProviderError, "repeated an agent-message id"):
            _protocol(transport).run("request", time.monotonic() + 5)

    def test_full_and_legacy_full_turn_items_remain_compatible(self) -> None:
        for items_view in ("full", None):
            with self.subTest(items_view=items_view):
                outcome = _protocol(
                    ScriptedTransport(Path("/runtime/work"), turn_items_view=items_view)
                ).run("request", time.monotonic() + 5)

                self.assertEqual(outcome.final_output, "completed fixture")
                self.assertEqual(outcome.raw_response["turn"]["items_view"], "full")

    def test_full_turn_rejects_non_object_items(self) -> None:
        transport = ScriptedTransport(
            Path("/runtime/work"),
            full_has_non_object_item=True,
            turn_items_view="full",
        )
        with self.assertRaisesRegex(
            ProviderError, r"turn\.items\[1\] must be an object"
        ):
            _protocol(transport).run("request", time.monotonic() + 5)

    def test_summary_and_unknown_turn_item_views_are_rejected(self) -> None:
        for items_view in ("summary", "future"):
            with self.subTest(items_view=items_view):
                with self.assertRaisesRegex(ProviderError, "unsupported item view"):
                    _protocol(
                        ScriptedTransport(
                            Path("/runtime/work"), turn_items_view=items_view
                        )
                    ).run("request", time.monotonic() + 5)

    def test_not_loaded_turn_items_must_be_empty(self) -> None:
        transport = ScriptedTransport(Path("/runtime/work"), not_loaded_has_items=True)
        with self.assertRaisesRegex(
            ProviderError, "not-loaded turn items must be empty"
        ):
            _protocol(transport).run("request", time.monotonic() + 5)

    def test_turn_requires_authoritative_completed_message(self) -> None:
        for items_view in ("notLoaded", "full"):
            with self.subTest(items_view=items_view):
                transport = ScriptedTransport(
                    Path("/runtime/work"),
                    omit_item_completed=True,
                    turn_items_view=items_view,
                )
                with self.assertRaisesRegex(
                    ProviderError, "completed final agent message"
                ):
                    _protocol(transport).run("request", time.monotonic() + 5)

    def test_skill_disable_refusal_is_rejected(self) -> None:
        transport = ScriptedTransport(
            Path("/runtime/work"), skill_disable_succeeds=False
        )
        with self.assertRaisesRegex(ProviderError, "refused"):
            _AppServerProtocol(
                _JsonRpcSession(transport),
                model="gpt-5.6-luna",
                reasoning_effort="low",
                workspace=Path("/runtime/work"),
                system_context="test",
                locked_efforts=("low", "medium", "high", "xhigh", "max"),
                locked_thread_cli_version="0.144.3",
                expected_codex_home=Path("/runtime/codex-home"),
            ).run("request", time.monotonic() + 5)

    def test_unexpected_server_request_is_denied_before_failure(self) -> None:
        transport = QueueTransport(
            [
                _line(
                    {
                        "id": "server-1",
                        "method": "execCommandApproval",
                        "params": {},
                    }
                ).removesuffix(b"\n")
            ]
        )
        session = _JsonRpcSession(transport)
        with self.assertRaisesRegex(ProviderError, "not permitted"):
            session.call("initialize", {}, time.monotonic() + 1, lambda *_: None)
        self.assertEqual(transport.sent[-1]["id"], "server-1")
        self.assertEqual(transport.sent[-1]["error"]["code"], -32601)

    def test_duplicate_json_key_is_rejected(self) -> None:
        transport = QueueTransport([b'{"id":1,"id":1,"result":{}}'])
        with self.assertRaisesRegex(ProviderError, "duplicate JSON key"):
            _JsonRpcSession(transport).call(
                "initialize", {}, time.monotonic() + 1, lambda *_: None
            )

    def test_unknown_response_id_is_rejected(self) -> None:
        transport = QueueTransport([b'{"id":2,"result":{}}'])
        with self.assertRaisesRegex(ProviderError, "unknown JSON-RPC response id"):
            _JsonRpcSession(transport).call(
                "initialize", {}, time.monotonic() + 1, lambda *_: None
            )

    def test_commentary_only_turn_is_not_accepted_as_final_output(self) -> None:
        transport = ScriptedTransport(Path("/runtime/work"), final_phase="commentary")
        with self.assertRaisesRegex(ProviderError, "commentary"):
            _protocol(transport).run("request", time.monotonic() + 5)

    def test_dispatch_callback_runs_once_after_turn_start_is_sent(self) -> None:
        transport = ScriptedTransport(Path("/runtime/work"))
        dispatched_after: list[str] = []

        def on_dispatched() -> None:
            dispatched_after.append(transport.sent[-1]["method"])

        outcome = _protocol(transport, on_dispatched=on_dispatched).run(
            "request", time.monotonic() + 5
        )

        self.assertEqual(outcome.final_output, "completed fixture")
        self.assertEqual(dispatched_after, ["turn/start"])

    def test_repeated_pagination_cursor_and_total_overflow_fail_closed(self) -> None:
        repeated = QueueTransport(
            [
                _line(
                    {"id": 1, "result": {"data": [], "nextCursor": "again"}}
                ).removesuffix(b"\n"),
                _line(
                    {"id": 2, "result": {"data": [], "nextCursor": "again"}}
                ).removesuffix(b"\n"),
            ]
        )
        with self.assertRaisesRegex(ProviderError, "repeated a pagination cursor"):
            _protocol(repeated)._paged(
                "model/list", {}, time.monotonic() + 1, maximum=10
            )

        overflow = QueueTransport(
            [
                _line(
                    {"id": 1, "result": {"data": [{}, {}], "nextCursor": None}}
                ).removesuffix(b"\n")
            ]
        )
        with self.assertRaisesRegex(ProviderError, "total item limit"):
            _protocol(overflow)._paged(
                "model/list", {}, time.monotonic() + 1, maximum=1
            )

    def test_untrusted_protocol_fields_are_not_echoed_in_errors(self) -> None:
        secret = "SENTINEL_DO_NOT_ECHO"
        frames = {
            "duplicate key": (
                f'{{"id":1,"result":{{}},"{secret}":1,"{secret}":2}}'.encode()
            ),
            "unknown response key": _line(
                {"id": 1, "result": {}, secret: True}
            ).removesuffix(b"\n"),
            "JSON-RPC message": _line(
                {"error": {"code": -1, "message": secret}, "id": 1}
            ).removesuffix(b"\n"),
            "server request method": _line(
                {"id": "server", "method": secret, "params": {}}
            ).removesuffix(b"\n"),
            "notification method": _line({"method": secret, "params": {}}).removesuffix(
                b"\n"
            ),
            "notification method with invalid params": _line(
                {"method": secret, "params": None}
            ).removesuffix(b"\n"),
            "error notification message": _line(
                {"method": "error", "params": {"error": {"message": secret}}}
            ).removesuffix(b"\n"),
        }
        notification_protocol = _protocol(QueueTransport([]))
        for label, frame in frames.items():
            with self.subTest(label=label):
                transport = QueueTransport([frame])
                session = _JsonRpcSession(transport)
                with self.assertRaises(ProviderError) as caught:
                    session.call(
                        "initialize",
                        {},
                        time.monotonic() + 1,
                        notification_protocol._handle_notification,
                    )
                self.assertNotIn(secret, str(caught.exception))

        notification_protocol._thread_id = "thread-1"
        notification_protocol._turn_id = "turn-1"
        with self.assertRaises(ProviderError) as caught:
            notification_protocol._handle_notification(
                "item/completed",
                {
                    "item": {"id": "item-1", "type": secret},
                    "threadId": "thread-1",
                    "turnId": "turn-1",
                },
            )
        self.assertNotIn(secret, str(caught.exception))

    def test_prohibited_notifications_and_post_isolation_skill_changes_fail(
        self,
    ) -> None:
        protocol = _protocol(QueueTransport([]))
        with self.assertRaisesRegex(ProviderError, "prohibited"):
            protocol._handle_notification("thread/settings/updated", {})
        with self.assertRaisesRegex(ProviderError, "changed after isolation"):
            protocol._handle_notification("skills/changed", {})
        protocol._handle_notification(
            "remoteControl/status/changed",
            {
                "environmentId": None,
                "installationId": "installation-secret",
                "serverName": "remote.example.invalid",
                "status": "disabled",
            },
        )
        with self.assertRaisesRegex(ProviderError, "not disabled"):
            protocol._handle_notification(
                "remoteControl/status/changed",
                {
                    "environmentId": None,
                    "installationId": "installation-secret",
                    "serverName": "remote.example.invalid",
                    "status": "connected",
                },
            )

        protocol._handle_notification("thread/started", {"thread": {"id": "thread-1"}})
        with self.assertRaisesRegex(ProviderError, "more than one thread"):
            protocol._handle_notification(
                "thread/started", {"thread": {"id": "thread-1"}}
            )

        protocol._thread_id = "thread-1"
        protocol._turn_id = "turn-1"
        scoped_notifications = (
            "thread/status/changed",
            "turn/diff/updated",
            "model/verification",
        )
        for method in scoped_notifications:
            with self.subTest(method=method, scope="empty"):
                with self.assertRaises(ProviderError):
                    protocol._handle_notification(method, {})
            with self.subTest(method=method, scope="wrong"):
                with self.assertRaises(ProviderError):
                    protocol._handle_notification(
                        method,
                        {"threadId": "other-thread", "turnId": "other-turn"},
                    )

    def test_item_type_allowlist_matches_isolated_local_tools(self) -> None:
        protocol = _protocol(QueueTransport([]))
        protocol._thread_id = "thread-1"
        protocol._turn_id = "turn-1"
        allowed = (
            "agentMessage",
            "collabAgentToolCall",
            "commandExecution",
            "contextCompaction",
            "fileChange",
            "imageView",
            "reasoning",
            "userMessage",
        )
        self.assertEqual(_ALLOWED_ITEM_TYPES, frozenset(allowed))
        for item_type in allowed:
            with self.subTest(item_type=item_type, disposition="allowed"):
                item = {"id": "item-1", "type": item_type}
                if item_type == "agentMessage":
                    item["text"] = "message"
                elif item_type == "collabAgentToolCall":
                    item.update(
                        {
                            "agentsStates": {},
                            "receiverThreadIds": ["child-1"],
                            "senderThreadId": "thread-1",
                            "status": "inProgress",
                            "tool": "spawnAgent",
                        }
                    )
                protocol._handle_notification(
                    "item/started",
                    {
                        "item": item,
                        "threadId": "thread-1",
                        "turnId": "turn-1",
                    },
                )

        protocol._handle_notification(
            "thread/status/changed",
            {
                "status": {"activeFlags": [], "type": "active"},
                "threadId": "child-1",
            },
        )
        with self.assertRaisesRegex(
            ProviderError, "thread/status/changed changed thread scope"
        ):
            protocol._handle_notification(
                "thread/status/changed",
                {"status": {"type": "idle"}, "threadId": "unknown-child"},
            )

        sentinel = "SENTINEL_MUST_NOT_BE_DISCLOSED"
        prohibited = (
            "dynamicToolCall",
            "enteredReviewMode",
            "exitedReviewMode",
            "hookPrompt",
            "imageGeneration",
            "mcpToolCall",
            "plan",
            "sleep",
            "subAgentActivity",
            "webSearch",
            sentinel,
        )
        for item_type in prohibited:
            with self.subTest(item_type=item_type, disposition="prohibited"):
                with self.assertRaisesRegex(
                    ProviderError, "prohibited or unknown Codex item type"
                ) as raised:
                    protocol._handle_notification(
                        "item/started",
                        {
                            "item": {"id": "item-1", "type": item_type},
                            "threadId": "thread-1",
                            "turnId": "turn-1",
                        },
                    )
                self.assertNotIn(sentinel, str(raised.exception))

    def test_spawn_agent_allows_schema_defined_empty_initial_receivers(self) -> None:
        protocol = _protocol(QueueTransport([]))
        protocol._thread_id = "thread-1"
        initial = {
            "agentsStates": {},
            "id": "item-1",
            "receiverThreadIds": [],
            "senderThreadId": "thread-1",
            "status": "inProgress",
            "tool": "spawnAgent",
            "type": "collabAgentToolCall",
        }
        protocol._validate_item(initial)
        self.assertEqual(protocol._collab_thread_ids, set())
        self.assertEqual(protocol._pending_spawn_items, {("thread-1", "item-1"): None})

        completed = {
            **initial,
            "agentsStates": {"child-1": {"status": "completed"}},
            "receiverThreadIds": ["child-1"],
            "status": "completed",
        }
        protocol._validate_item(completed)
        self.assertEqual(protocol._collab_thread_ids, {"child-1"})
        self.assertEqual(protocol._pending_spawn_items, {})

    def test_spawn_agent_bounds_total_child_thread_scope(self) -> None:
        protocol = _protocol(QueueTransport([]))
        protocol._thread_id = "thread-1"
        receivers = [f"child-{index}" for index in range(_MAX_COLLAB_THREADS)]
        base = {
            "agentsStates": {},
            "senderThreadId": "thread-1",
            "tool": "spawnAgent",
            "type": "collabAgentToolCall",
        }
        for index, receiver in enumerate(receivers):
            item = {
                **base,
                "id": f"item-{index}",
                "receiverThreadIds": [receiver],
            }
            protocol._validate_item({**item, "status": "inProgress"})
            protocol._validate_item({**item, "status": "completed"})

        with self.assertRaisesRegex(ProviderError, "thread count exceeds"):
            protocol._validate_item(
                {
                    **base,
                    "id": "overflow-item",
                    "receiverThreadIds": ["overflow-child"],
                    "status": "inProgress",
                }
            )

        protocol._validate_item(
            {
                **base,
                "id": "item-3",
                "receiverThreadIds": [],
                "status": "inProgress",
            }
        )
        with self.assertRaisesRegex(ProviderError, "thread count exceeds"):
            protocol._handle_notification(
                "thread/status/changed",
                {
                    "status": {"activeFlags": [], "type": "active"},
                    "threadId": "overflow-child",
                },
            )
        self.assertEqual(protocol._collab_thread_ids, set(receivers))
        self.assertEqual(protocol._pending_spawn_items, {("thread-1", "item-3"): None})

    def test_pending_spawn_bounds_early_child_status_scope(self) -> None:
        protocol = _protocol(QueueTransport([]))
        protocol._thread_id = "thread-1"
        initial = {
            "agentsStates": {},
            "id": "item-1",
            "receiverThreadIds": [],
            "senderThreadId": "thread-1",
            "status": "inProgress",
            "tool": "spawnAgent",
            "type": "collabAgentToolCall",
        }
        protocol._validate_item(initial)
        protocol._handle_notification(
            "thread/status/changed",
            {
                "status": {"activeFlags": [], "type": "active"},
                "threadId": "child-1",
            },
        )
        self.assertEqual(protocol._collab_thread_ids, {"child-1"})
        self.assertEqual(protocol._pending_spawn_items, {("thread-1", "item-1"): None})
        self.assertEqual(protocol._unbound_collab_thread_ids, {"child-1"})

        protocol._turn_id = "main-turn"
        protocol._handle_notification(
            "turn/started",
            {"threadId": "child-1", "turn": {"id": "child-turn"}},
        )
        protocol._handle_notification(
            "item/started",
            {
                "item": {"id": "reasoning-1", "type": "reasoning"},
                "threadId": "child-1",
                "turnId": "child-turn",
            },
        )
        protocol._handle_notification(
            "model/verification",
            {"threadId": "child-1", "turnId": "child-turn"},
        )
        protocol._handle_notification(
            "item/completed",
            {
                "item": {
                    "id": "message-1",
                    "phase": "final_answer",
                    "text": "child result",
                    "type": "agentMessage",
                },
                "threadId": "child-1",
                "turnId": "child-turn",
            },
        )
        protocol._handle_notification(
            "turn/completed",
            {
                "threadId": "child-1",
                "turn": {
                    "id": "child-turn",
                    "items": [],
                    "itemsView": "notLoaded",
                    "status": "completed",
                },
            },
        )
        self.assertIsNone(protocol._announced_turn_id)
        self.assertEqual(protocol._completed_messages, [])
        self.assertIsNone(protocol._turn_completed)

        with self.assertRaisesRegex(
            ProviderError, "thread/status/changed changed thread scope"
        ):
            protocol._handle_notification(
                "thread/status/changed",
                {"status": {"type": "idle"}, "threadId": "unknown-child"},
            )
        with self.assertRaisesRegex(ProviderError, "changed thread scope"):
            protocol._handle_notification(
                "turn/started",
                {"threadId": "unknown-child", "turn": {"id": "unknown-turn"}},
            )
        with self.assertRaisesRegex(ProviderError, "did not match"):
            protocol._validate_item(
                {
                    **initial,
                    "receiverThreadIds": ["different-child"],
                    "status": "completed",
                }
            )

        protocol._validate_item(
            {
                **initial,
                "agentsStates": {"child-1": {"status": "completed"}},
                "receiverThreadIds": ["child-1"],
                "status": "completed",
            }
        )
        self.assertEqual(protocol._pending_spawn_items, {})
        self.assertEqual(protocol._unbound_collab_thread_ids, set())

    def test_parallel_pending_spawns_accept_cross_ordered_child_announcements(
        self,
    ) -> None:
        protocol = _protocol(QueueTransport([]))
        protocol._thread_id = "thread-1"
        initial = {
            "agentsStates": {},
            "receiverThreadIds": [],
            "senderThreadId": "thread-1",
            "status": "inProgress",
            "tool": "spawnAgent",
            "type": "collabAgentToolCall",
        }
        protocol._validate_item({**initial, "id": "spawn-1"})
        protocol._validate_item({**initial, "id": "spawn-2"})

        for child in ("child-2", "child-1"):
            protocol._handle_notification(
                "thread/status/changed",
                {
                    "status": {"activeFlags": [], "type": "active"},
                    "threadId": child,
                },
            )

        for item_id, child in (("spawn-1", "child-1"), ("spawn-2", "child-2")):
            protocol._validate_item(
                {
                    **initial,
                    "agentsStates": {child: {"status": "running"}},
                    "id": item_id,
                    "receiverThreadIds": [child],
                    "status": "completed",
                }
            )

        self.assertEqual(protocol._pending_spawn_items, {})
        self.assertEqual(protocol._unbound_collab_thread_ids, set())
        self.assertEqual(protocol._collab_thread_ids, {"child-1", "child-2"})

    def test_pending_spawn_ids_are_scoped_to_the_sender_thread(self) -> None:
        protocol = _protocol(QueueTransport([]))
        protocol._thread_id = "main-thread"
        protocol._collab_thread_ids.add("child-a")
        base = {
            "agentsStates": {},
            "id": "same-id",
            "receiverThreadIds": [],
            "status": "inProgress",
            "tool": "spawnAgent",
            "type": "collabAgentToolCall",
        }
        protocol._validate_item({**base, "senderThreadId": "main-thread"})
        protocol._validate_item({**base, "senderThreadId": "child-a"})
        self.assertEqual(
            set(protocol._pending_spawn_items),
            {("main-thread", "same-id"), ("child-a", "same-id")},
        )

        protocol._validate_item(
            {
                **base,
                "agentsStates": {"child-b": {"status": "running"}},
                "receiverThreadIds": ["child-b"],
                "senderThreadId": "child-a",
                "status": "completed",
            }
        )
        self.assertEqual(
            protocol._pending_spawn_items, {("main-thread", "same-id"): None}
        )
        protocol._validate_item(
            {
                **base,
                "agentsStates": {"child-c": {"status": "running"}},
                "receiverThreadIds": ["child-c"],
                "senderThreadId": "main-thread",
                "status": "completed",
            }
        )
        self.assertEqual(protocol._pending_spawn_items, {})

    def test_one_child_cannot_complete_two_pending_spawns(self) -> None:
        protocol = _protocol(QueueTransport([]))
        protocol._thread_id = "main-thread"
        base = {
            "agentsStates": {},
            "receiverThreadIds": [],
            "senderThreadId": "main-thread",
            "status": "inProgress",
            "tool": "spawnAgent",
            "type": "collabAgentToolCall",
        }
        protocol._validate_item({**base, "id": "spawn-1"})
        protocol._validate_item({**base, "id": "spawn-2"})
        protocol._handle_notification(
            "thread/status/changed",
            {
                "status": {"activeFlags": [], "type": "active"},
                "threadId": "only-child",
            },
        )
        completed = {
            **base,
            "agentsStates": {"only-child": {"status": "running"}},
            "receiverThreadIds": ["only-child"],
            "status": "completed",
        }
        protocol._validate_item({**completed, "id": "spawn-1"})
        with self.assertRaisesRegex(ProviderError, "already claimed"):
            protocol._validate_item({**completed, "id": "spawn-2"})
        self.assertEqual(
            protocol._pending_spawn_items, {("main-thread", "spawn-2"): None}
        )

    def test_collaboration_optional_metadata_rejects_non_strings(self) -> None:
        base = {
            "agentsStates": {},
            "id": "item-1",
            "receiverThreadIds": [],
            "senderThreadId": "thread-1",
            "status": "inProgress",
            "tool": "spawnAgent",
            "type": "collabAgentToolCall",
        }
        for field in ("model", "prompt", "reasoningEffort"):
            protocol = _protocol(QueueTransport([]))
            protocol._thread_id = "thread-1"
            with (
                self.subTest(field=field),
                self.assertRaisesRegex(
                    ProviderError, f"collaboration {field} must be a string or null"
                ),
            ):
                protocol._validate_item({**base, field: {"malformed": True}})

        protocol = _protocol(QueueTransport([]))
        protocol._thread_id = "thread-1"
        with self.assertRaisesRegex(ProviderError, "non-empty string or null"):
            protocol._validate_item({**base, "reasoningEffort": ""})

    def test_collaboration_sender_and_lifecycle_match_event_envelope(self) -> None:
        protocol = _protocol(QueueTransport([]))
        protocol._thread_id = "main-thread"
        protocol._turn_id = "main-turn"
        protocol._collab_thread_ids.add("child-1")
        protocol._collab_turn_ids["child-1"] = {"child-turn"}
        item = {
            "agentsStates": {},
            "id": "spawn-1",
            "receiverThreadIds": [],
            "senderThreadId": "main-thread",
            "status": "inProgress",
            "tool": "spawnAgent",
            "type": "collabAgentToolCall",
        }

        with self.assertRaisesRegex(ProviderError, "disagrees with its envelope"):
            protocol._handle_notification(
                "item/started",
                {
                    "item": item,
                    "threadId": "child-1",
                    "turnId": "child-turn",
                },
            )
        self.assertEqual(protocol._pending_spawn_items, {})

        with self.assertRaisesRegex(ProviderError, "still in progress"):
            protocol._handle_notification(
                "item/completed",
                {
                    "item": item,
                    "threadId": "main-thread",
                    "turnId": "main-turn",
                },
            )
        self.assertEqual(protocol._pending_spawn_items, {})

    def test_child_payloads_are_validated_before_they_are_discarded(self) -> None:
        protocol = _protocol(QueueTransport([]))
        protocol._thread_id = "main-thread"
        protocol._turn_id = "main-turn"
        protocol._collab_thread_ids.add("child-1")
        protocol._collab_turn_ids["child-1"] = {"child-turn"}

        with self.assertRaisesRegex(ProviderError, "agent message omitted keys"):
            protocol._handle_notification(
                "item/completed",
                {
                    "item": {"type": "agentMessage"},
                    "threadId": "child-1",
                    "turnId": "child-turn",
                },
            )
        with self.assertRaisesRegex(ProviderError, "status must be a non-empty string"):
            protocol._handle_notification(
                "turn/completed",
                {
                    "threadId": "child-1",
                    "turn": {
                        "id": "child-turn",
                        "items": "not-an-array",
                        "status": 42,
                    },
                },
            )

    def test_child_turn_rejects_duplicate_completion_and_late_items(self) -> None:
        protocol = _protocol(QueueTransport([]))
        protocol._thread_id = "main-thread"
        protocol._turn_id = "main-turn"
        protocol._collab_thread_ids.add("child-1")
        protocol._collab_turn_ids["child-1"] = {"child-turn"}
        completed = {
            "threadId": "child-1",
            "turn": {
                "id": "child-turn",
                "items": [],
                "itemsView": "notLoaded",
                "status": "completed",
            },
        }
        protocol._handle_notification("turn/completed", completed)

        with self.assertRaisesRegex(ProviderError, "unknown child turn"):
            protocol._handle_notification("turn/completed", completed)
        with self.assertRaisesRegex(ProviderError, "unknown turn"):
            protocol._handle_notification(
                "item/completed",
                {
                    "item": {
                        "id": "message-1",
                        "text": "late",
                        "type": "agentMessage",
                    },
                    "threadId": "child-1",
                    "turnId": "child-turn",
                },
            )

    def test_thread_instruction_runtime_root_and_source_drift_fail_closed(self) -> None:
        class DriftingTransport(ScriptedTransport):
            def __init__(self, key: str, value: Any) -> None:
                super().__init__(Path("/runtime/work"))
                self.key = key
                self.value = value

            def send(self, payload: bytes, deadline: float) -> None:
                message = json.loads(payload)
                super().send(payload, deadline)
                if message.get("method") == "thread/start":
                    response = json.loads(self.incoming.pop())
                    if self.key.startswith("thread."):
                        response["result"]["thread"][
                            self.key.removeprefix("thread.")
                        ] = self.value
                    else:
                        response["result"][self.key] = self.value
                    self.incoming.append(_line(response))

        cases = {
            "instructionSources": ["/host/AGENTS.md"],
            "runtimeWorkspaceRoots": ["/host/workspace"],
            "thread.source": "appServer",
        }
        for key, value in cases.items():
            with self.subTest(key=key):
                with self.assertRaises(ProviderError):
                    _protocol(DriftingTransport(key, value)).run(
                        "request", time.monotonic() + 5
                    )


class CodexProcessTransportTests(unittest.TestCase):
    @staticmethod
    def _transport(process: Any) -> _ProcessTransport:
        transport = _ProcessTransport.__new__(_ProcessTransport)
        transport._unit_name = "skill-eval-codex-test"
        transport._systemctl = "/usr/bin/systemctl"
        transport._control_group = None
        transport._buffer = bytearray()
        transport._stderr = bytearray()
        transport._stderr_overflow = False
        transport._closed = False
        transport._stderr_thread = None
        transport._process = process
        transport.evidence = {
            "command_sha256": "a" * 64,
            "launcher_pid": 12345,
            "launcher_start_time_ticks": 67890,
            "unit": "skill-eval-codex-test",
        }
        return transport

    def test_cleanup_does_not_certify_not_found_active_and_uses_valid_kill_argv(
        self,
    ) -> None:
        process = mock.Mock()
        process.stdin = mock.Mock()
        process.stdout = mock.Mock()
        process.stderr = mock.Mock()
        process.returncode = 0
        process.pid = os.getpid()
        process.wait.return_value = 0
        calls: list[tuple[str, ...]] = []

        def run(command: list[str], **_kwargs: Any) -> subprocess.CompletedProcess[str]:
            calls.append(tuple(command))
            return subprocess.CompletedProcess(command, 0, stdout="", stderr="")

        with (
            mock.patch("skivolve.codex_app_server.subprocess.run", side_effect=run),
            mock.patch(
                "skivolve.codex_app_server._SystemdRecoveryProbe.confirm_unit_clean",
                side_effect=(
                    ProviderError("still active"),
                    "not-found/inactive/empty/gone",
                ),
            ),
        ):
            transport = self._transport(process)
            transport.close()

        kill = next(command for command in calls if "kill" in command)
        self.assertIn("--kill-whom=all", kill)
        self.assertIn("--signal=KILL", kill)
        self.assertTrue(transport.evidence["cleanup_confirmed"])
        process.stdout.close.assert_called_once_with()
        process.stderr.close.assert_called_once_with()

    def test_bash_gate_supports_high_descriptor_and_closes_it_before_exec(
        self,
    ) -> None:
        read_fd, write_fd = os.pipe2(os.O_CLOEXEC)
        high_fd = fcntl.fcntl(read_fd, fcntl.F_DUPFD_CLOEXEC, 20)
        os.close(read_fd)
        shell, _identity = _resolve_gate_shell()
        process = subprocess.Popen(
            (
                str(shell),
                "--noprofile",
                "--norc",
                "-c",
                _LAUNCH_GATE_SCRIPT,
                "codex-launch-gate",
                str(high_fd),
                "/bin/sh",
                "-c",
                f"test ! -e /proc/self/fd/{high_fd} && printf gate-ok",
            ),
            pass_fds=(high_fd,),
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )
        os.close(high_fd)
        os.write(write_fd, b"GO\n")
        os.close(write_fd)
        stdout, stderr = process.communicate(timeout=5)
        self.assertEqual((process.returncode, stdout, stderr), (0, b"gate-ok", b""))

    def test_constructor_failure_after_popen_reaps_process_and_closes_pipes(
        self,
    ) -> None:
        class Pipe:
            def __init__(self, descriptor: int) -> None:
                self.descriptor = descriptor
                self.closed = False

            def fileno(self) -> int:
                return self.descriptor

            def close(self) -> None:
                self.closed = True

        process = mock.Mock()
        process.stdin = Pipe(41)
        process.stdout = Pipe(42)
        process.stderr = Pipe(43)
        process.returncode = 0
        process.pid = os.getpid()
        process.wait.return_value = 0

        with (
            mock.patch(
                "skivolve.codex_app_server._resolve_system_tool",
                return_value=Path("/usr/bin/systemctl"),
            ),
            mock.patch(
                "skivolve.codex_app_server.subprocess.Popen", return_value=process
            ),
            mock.patch("skivolve.codex_app_server._attest_process_executable"),
            mock.patch(
                "skivolve.codex_app_server.os.set_blocking",
                side_effect=OSError("fixture failure"),
            ),
            mock.patch(
                "skivolve.codex_app_server.subprocess.run",
                return_value=subprocess.CompletedProcess([], 0, "", ""),
            ),
            mock.patch(
                "skivolve.codex_app_server._SystemdRecoveryProbe.confirm_unit_clean",
                return_value="not-found/inactive/empty/gone",
            ),
            self.assertRaises(OSError),
        ):
            _ProcessTransport(
                ("/bin/false",),
                Path("/"),
                {"PATH": "/usr/bin:/bin"},
                "skill-eval-codex-test",
            )

        process.wait.assert_called()
        self.assertTrue(process.stdin.closed)
        self.assertTrue(process.stdout.closed)
        self.assertTrue(process.stderr.closed)

    def test_cleanup_passes_captured_cgroup_to_shared_stability_probe(self) -> None:
        process = mock.Mock()
        process.stdin = mock.Mock()
        process.stdout = mock.Mock()
        process.stderr = mock.Mock()
        process.returncode = 0
        process.wait.return_value = 0
        transport = self._transport(process)
        transport._control_group = "/user.slice/test.service"
        with (
            mock.patch(
                "skivolve.codex_app_server.subprocess.run",
                return_value=subprocess.CompletedProcess([], 0, "", ""),
            ),
            mock.patch(
                "skivolve.codex_app_server._SystemdRecoveryProbe.confirm_unit_clean",
                return_value="loaded/inactive/control-group/empty",
            ) as confirm,
        ):
            transport.close()
        confirm.assert_called_once_with(
            "skill-eval-codex-test",
            "/user.slice/test.service",
            mock.ANY,
        )
        self.assertTrue(transport.evidence["cleanup_confirmed"])

    def test_process_identity_treats_only_gone_errnos_as_absent(self) -> None:
        for error_number in (errno.ENOENT, errno.ESRCH):
            with (
                self.subTest(error_number=error_number),
                mock.patch.object(
                    Path,
                    "read_bytes",
                    side_effect=OSError(error_number, "simulated process exit"),
                ),
            ):
                self.assertIsNone(_linux_process_start_time(12345))

        for error_number in (errno.EACCES, errno.EIO):
            with (
                self.subTest(error_number=error_number),
                mock.patch.object(
                    Path,
                    "read_bytes",
                    side_effect=OSError(error_number, "simulated inspection failure"),
                ),
                self.assertRaisesRegex(
                    ProviderError, "cannot inspect process identity"
                ),
            ):
                _linux_process_start_time(12345)


class CleanupPoisonStoreTests(unittest.TestCase):
    COMMAND_SHA256 = "a" * 64
    GATE_SHA256 = "d" * 64
    GATE_EXECUTABLE = ["/usr/bin/bash", 1, 2]
    UNIT_NAME = "skill-eval-codex-test"

    class Probe:
        def __init__(
            self,
            *,
            state: str = "not-found/inactive/empty/gone",
            start_time: int | None = None,
            host_mount: bool = False,
            matching_pids: tuple[int, ...] = (),
        ) -> None:
            self.state = state
            self.start_time = start_time
            self.host_mount = host_mount
            self.matching_pids = matching_pids

        def confirm_unit_clean(
            self,
            _unit_name: str,
            _captured_control_group: str | None,
            _deadline: float,
        ) -> str:
            return self.state

        def process_start_time(self, _process_id: int) -> int | None:
            return self.start_time

        def matching_command_pids(self, _command_sha256: str) -> tuple[int, ...]:
            return self.matching_pids

        def host_mount_present(self, _path: Path) -> bool:
            return self.host_mount

    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory(prefix="codex-poison-test-")
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        self.root.chmod(0o700)
        self.mount = self.root / "mount"
        self.mount.mkdir(mode=0o700)
        self.auth = self.root / "auth.json"
        self.auth.write_text('{"auth_mode":"chatgpt"}\n', encoding="ascii")
        self.auth.chmod(0o600)
        self.store = _CleanupPoisonStore(self.root)

    def binding(self, lock_identity: tuple[int, int]) -> _PoisonBinding:
        auth_metadata = self.auth.lstat()
        mount_metadata = self.mount.lstat()
        return _PoisonBinding(
            auth_device=auth_metadata.st_dev,
            auth_inode=auth_metadata.st_ino,
            protocol_lock_sha256="b" * 64,
            provider_lock_device=lock_identity[0],
            provider_lock_inode=lock_identity[1],
            runtime_mount=str(self.mount),
            runtime_mount_device=mount_metadata.st_dev,
            runtime_mount_inode=mount_metadata.st_ino,
        )

    def arm(self, binding: _PoisonBinding) -> None:
        self.store.arm(binding, self.UNIT_NAME, self.COMMAND_SHA256)

    def identify(self, *, start_time: int | None = 67890) -> None:
        self.store.bind_gate(
            {
                "command_sha256": self.COMMAND_SHA256,
                "gate_command_sha256": self.GATE_SHA256,
                "gate_executable": self.GATE_EXECUTABLE,
                "unit": self.UNIT_NAME,
            }
        )
        self.store.identify_launcher(
            {
                "command_sha256": self.COMMAND_SHA256,
                "gate_command_sha256": self.GATE_SHA256,
                "gate_executable": self.GATE_EXECUTABLE,
                "launcher_pid": 12345,
                "launcher_start_time_ticks": start_time,
                "unit": self.UNIT_NAME,
            }
        )

    @classmethod
    def launch_evidence(cls, *, start_time: int | None = 67890) -> dict[str, Any]:
        return {
            "command_sha256": cls.COMMAND_SHA256,
            "control_group": None,
            "gate_command_sha256": cls.GATE_SHA256,
            "gate_executable": cls.GATE_EXECUTABLE,
            "launcher_pid": 12345,
            "launcher_start_time_ticks": start_time,
            "unit": cls.UNIT_NAME,
        }

    @staticmethod
    def process() -> mock.Mock:
        process = mock.Mock()
        process.stdin = mock.Mock()
        process.stdin.close.side_effect = OSError("fixture close failure")
        process.stdout = mock.Mock()
        process.stderr = mock.Mock()
        process.pid = 12345
        process.returncode = 0
        process.wait.return_value = 0
        return process

    @staticmethod
    def inactive_systemctl(
        command: list[str], **_kwargs: Any
    ) -> subprocess.CompletedProcess[str]:
        if "show" in command:
            return subprocess.CompletedProcess(
                command,
                0,
                stdout=(
                    "LoadState=not-found\nActiveState=inactive\n"
                    "ControlGroup=\nKillMode=\n"
                ),
                stderr="",
            )
        return subprocess.CompletedProcess(command, 0, stdout="", stderr="")

    def test_cleanup_failure_leaves_owner_only_prearmed_poison(self) -> None:
        with self.store.lock(time.monotonic() + 1) as lock_identity:
            binding = self.binding(lock_identity)
            self.arm(binding)
            self.identify()
            transport = CodexProcessTransportTests._transport(self.process())
            with (
                mock.patch(
                    "skivolve.codex_app_server.subprocess.run",
                    side_effect=self.inactive_systemctl,
                ),
                mock.patch(
                    "skivolve.codex_app_server._SystemdRecoveryProbe.confirm_unit_clean",
                    return_value="not-found/inactive/empty/gone",
                ),
                self.assertRaisesRegex(ProviderError, "cleanup could not be confirmed"),
            ):
                transport.close()

            metadata = self.store.marker_path.lstat()
            self.assertTrue(stat.S_ISREG(metadata.st_mode))
            self.assertEqual(stat.S_IMODE(metadata.st_mode), 0o600)
            self.assertEqual(metadata.st_uid, os.getuid())
            self.assertEqual(metadata.st_nlink, 1)
            marker = json.loads(self.store.marker_path.read_text(encoding="ascii"))
            self.assertEqual(marker["binding"], binding.as_json())
            self.assertEqual(marker["launcher_start_time_ticks"], 67890)

    def test_constructor_failure_leaves_armed_marker_and_attaches_cleanup_failure(
        self,
    ) -> None:
        process = self.process()
        with self.store.lock(time.monotonic() + 1) as lock_identity:
            binding = self.binding(lock_identity)
            self.arm(binding)
            with (
                mock.patch(
                    "skivolve.codex_app_server._resolve_system_tool",
                    return_value=Path("/usr/bin/systemctl"),
                ),
                mock.patch(
                    "skivolve.codex_app_server.subprocess.Popen",
                    return_value=process,
                ),
                mock.patch("skivolve.codex_app_server._attest_process_executable"),
                mock.patch(
                    "skivolve.codex_app_server._linux_process_start_time",
                    return_value=67890,
                ),
                mock.patch(
                    "skivolve.codex_app_server._command_sha256",
                    return_value=self.COMMAND_SHA256,
                ),
                mock.patch(
                    "skivolve.codex_app_server.os.set_blocking",
                    side_effect=OSError("fixture setup failure"),
                ),
                mock.patch(
                    "skivolve.codex_app_server.subprocess.run",
                    side_effect=self.inactive_systemctl,
                ),
                self.assertRaisesRegex(OSError, "fixture setup failure") as raised,
            ):
                _ProcessTransport(
                    ("/bin/false",),
                    Path("/"),
                    {"PATH": "/usr/bin:/bin"},
                    "skill-eval-codex-test",
                    on_gate_ready=self.store.bind_gate,
                    on_started=self.store.identify_launcher,
                )

            self.assertTrue(self.store.marker_path.exists())
            self.assertTrue(
                any(
                    "constructor rollback also failed" in note
                    for note in getattr(raised.exception, "__notes__", ())
                )
            )

    def test_evaluator_death_leaves_armed_marker_for_restart_recovery(self) -> None:
        with self.store.lock(time.monotonic() + 1) as lock_identity:
            binding = self.binding(lock_identity)
            self.arm(binding)

        restarted_store = _CleanupPoisonStore(self.root)
        with restarted_store.lock(time.monotonic() + 1) as restarted_identity:
            restarted_binding = self.binding(restarted_identity)
            with self.assertRaisesRegex(ProviderError, "matching launcher"):
                restarted_store.recover(
                    restarted_binding, self.Probe(matching_pids=(54321,))
                )
            self.assertTrue(restarted_store.recover(restarted_binding, self.Probe()))

        self.assertFalse(restarted_store.marker_path.exists())

    def _assert_evaluator_death_before_gate_release(
        self, *, persist_launcher: bool
    ) -> bool:
        unit_name = f"skill-eval-codex-gap-{os.getpid()}-{time.monotonic_ns()}"
        systemd_run = str(_resolve_system_tool("systemd-run"))
        command = (
            systemd_run,
            "--user",
            "--quiet",
            "--wait",
            "--collect",
            "--service-type=exec",
            f"--unit={unit_name}",
            "--property=KillMode=control-group",
            "--",
            "/bin/sleep",
            "30",
        )
        with self.store.lock(time.monotonic() + 1) as lock_identity:
            binding = self.binding(lock_identity)
            self.store.arm(binding, unit_name, _command_sha256(command))

        status_read, status_write = os.pipe2(os.O_CLOEXEC)
        child_pid = os.fork()
        launcher_identity: tuple[int, int] | None = None
        child_reaped = False
        launcher_reaped = False
        try:
            if child_pid == 0:
                os.close(status_read)

                def persist_then_stop(evidence: dict[str, Any]) -> None:
                    if persist_launcher:
                        self.store.identify_launcher(evidence)
                    payload = (
                        json.dumps(
                            {
                                "pid": evidence["launcher_pid"],
                                "start": evidence["launcher_start_time_ticks"],
                            },
                            separators=(",", ":"),
                        ).encode("ascii")
                        + b"\n"
                    )
                    view = memoryview(payload)
                    while view:
                        view = view[os.write(status_write, view) :]
                    os.close(status_write)
                    while True:
                        signal.pause()

                try:
                    _ProcessTransport(
                        command,
                        Path("/"),
                        {"LANG": "C.UTF-8", "PATH": "/usr/bin:/bin"},
                        unit_name,
                        on_gate_ready=self.store.bind_gate,
                        on_started=persist_then_stop,
                    )
                except BaseException:
                    try:
                        os.write(status_write, b"ERROR\n")
                    except OSError:
                        pass
                os._exit(97)

            os.close(status_write)
            status_write = -1
            os.set_blocking(status_read, False)
            payload = bytearray()
            deadline = time.monotonic() + 5
            while b"\n" not in payload:
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    self.fail("forked evaluator did not reach the gate kill point")
                readable, _, _ = select.select([status_read], [], [], remaining)
                if not readable:
                    self.fail("forked evaluator did not reach the gate kill point")
                chunk = os.read(status_read, 4_096)
                if chunk:
                    payload.extend(chunk)
                else:
                    self.fail("forked evaluator exited before the gate kill point")

            if payload.startswith(b"ERROR"):
                self.fail("forked evaluator failed before the gate kill point")
            persisted = json.loads(bytes(payload).splitlines()[0])
            launcher_identity = persisted["pid"], persisted["start"]
            poison = self.store._read()
            assert poison is not None
            marker_launcher = (
                poison[0]["launcher_pid"],
                poison[0]["launcher_start_time_ticks"],
            )
            self.assertEqual(
                marker_launcher,
                launcher_identity if persist_launcher else (None, None),
            )

            launcher_pid, launcher_start = launcher_identity
            os.kill(child_pid, signal.SIGKILL)
            os.waitpid(child_pid, 0)
            child_reaped = True
            probe = _SystemdRecoveryProbe()
            wait_result: list[tuple[int, int]] = []
            wait_errors: list[BaseException] = []

            def reap_launcher() -> None:
                try:
                    wait_result.append(os.waitpid(launcher_pid, 0))
                except BaseException as exc:
                    wait_errors.append(exc)

            reaper = threading.Thread(target=reap_launcher, daemon=True)
            reaper.start()
            reaper.join(timeout=5)
            if reaper.is_alive():
                os.kill(launcher_pid, signal.SIGKILL)
                reaper.join(timeout=5)
                self.fail("blocked gate launcher survived evaluator death")
            self.assertEqual(wait_errors, [])
            self.assertEqual(wait_result[0][0], launcher_pid)
            launcher_reaped = True
            self.assertNotEqual(probe.process_start_time(launcher_pid), launcher_start)

            self.assertIn(
                probe.confirm_unit_clean(unit_name, None, time.monotonic() + 5),
                {
                    "not-found/inactive/control-group/gone",
                    "not-found/inactive/empty/gone",
                },
            )
            with self.store.lock(time.monotonic() + 1) as restarted_identity:
                self.assertTrue(
                    self.store.recover(self.binding(restarted_identity), probe)
                )
            self.assertIn(
                probe.confirm_unit_clean(unit_name, None, time.monotonic() + 5),
                {
                    "not-found/inactive/control-group/gone",
                    "not-found/inactive/empty/gone",
                },
            )
            return True
        finally:
            if status_read >= 0:
                os.close(status_read)
            if status_write >= 0:
                os.close(status_write)
            if child_pid != 0 and not child_reaped:
                try:
                    os.kill(child_pid, signal.SIGKILL)
                except ProcessLookupError:
                    pass
                try:
                    os.waitpid(child_pid, 0)
                except ChildProcessError:
                    pass
            if child_pid != 0 and launcher_identity is not None and not launcher_reaped:
                launcher_pid, launcher_start = launcher_identity
                probe = _SystemdRecoveryProbe()
                if probe.process_start_time(launcher_pid) == launcher_start:
                    try:
                        os.kill(launcher_pid, signal.SIGKILL)
                    except ProcessLookupError:
                        pass
                try:
                    os.waitpid(launcher_pid, 0)
                except ChildProcessError:
                    pass
            if child_pid != 0:
                systemctl = str(_resolve_system_tool("systemctl"))
                for action in ("kill", "stop"):
                    arguments = (
                        ["--kill-whom=all", "--signal=KILL"] if action == "kill" else []
                    )
                    subprocess.run(
                        [systemctl, "--user", action, *arguments, unit_name],
                        capture_output=True,
                        text=True,
                        timeout=5,
                        check=False,
                        shell=False,
                    )

    def test_evaluator_death_before_pid_fsync_never_executes_systemd_run(self) -> None:
        self.assertTrue(sys.platform.startswith("linux"), "requires Linux /proc")
        with _linux_child_subreaper():
            self.assertTrue(
                self._assert_evaluator_death_before_gate_release(persist_launcher=False)
            )

    def test_evaluator_death_after_pid_fsync_never_executes_systemd_run(self) -> None:
        self.assertTrue(sys.platform.startswith("linux"), "requires Linux /proc")
        with _linux_child_subreaper():
            self.assertTrue(
                self._assert_evaluator_death_before_gate_release(persist_launcher=True)
            )

    def test_identified_launcher_blocks_until_pid_reuse_and_mount_clear(self) -> None:
        with self.store.lock(time.monotonic() + 1) as lock_identity:
            binding = self.binding(lock_identity)
            self.arm(binding)
            self.identify()
            with self.assertRaisesRegex(ProviderError, "launcher process exists"):
                self.store.recover(binding, self.Probe(start_time=67890))
            reused_probe = self.Probe(start_time=99999, host_mount=True)
            with self.assertRaisesRegex(ProviderError, "host-visible mount"):
                self.store.recover(binding, reused_probe)
            reused_probe.host_mount = False
            self.assertTrue(self.store.recover(binding, reused_probe))

    def test_confirmed_cleanup_disarms_marker(self) -> None:
        with self.store.lock(time.monotonic() + 1) as lock_identity:
            binding = self.binding(lock_identity)
            self.arm(binding)
            self.identify()
            self.store.disarm(binding, self.launch_evidence())
        self.assertFalse(self.store.marker_path.exists())

    def test_atomic_marker_publication_survives_every_durable_crash_window(
        self,
    ) -> None:
        def assert_no_artifact() -> None:
            self.assertFalse(self.store.marker_path.exists())
            self.assertEqual(
                [path for path in self.root.iterdir() if path.name.endswith(".tmp")],
                [],
            )

        with self.store.lock(time.monotonic() + 1) as lock_identity:
            binding = self.binding(lock_identity)
            real_write = os.write
            wrote_partial = False

            def partial_then_fail(descriptor: int, payload: Any) -> int:
                nonlocal wrote_partial
                if not wrote_partial:
                    wrote_partial = True
                    real_write(descriptor, payload[: max(1, len(payload) // 2)])
                raise OSError("simulated write crash")

            with (
                mock.patch(
                    "skivolve.codex_app_server.os.write",
                    side_effect=partial_then_fail,
                ),
                self.assertRaisesRegex(ProviderError, "publish"),
            ):
                self.arm(binding)
            assert_no_artifact()

            with (
                mock.patch(
                    "skivolve.codex_app_server.os.fsync",
                    side_effect=OSError("simulated file fsync crash"),
                ),
                self.assertRaisesRegex(ProviderError, "publish"),
            ):
                self.arm(binding)
            assert_no_artifact()

            with (
                mock.patch(
                    "skivolve.codex_app_server.os.link",
                    side_effect=OSError("simulated link crash"),
                ),
                self.assertRaisesRegex(ProviderError, "publish"),
            ):
                self.arm(binding)
            assert_no_artifact()

            real_unlink = os.unlink
            unlink_failed = False

            def fail_first_temporary_unlink(
                path: Any, *args: Any, **kwargs: Any
            ) -> None:
                nonlocal unlink_failed
                if not unlink_failed and str(path).endswith(".tmp"):
                    unlink_failed = True
                    raise OSError("simulated unlink crash")
                real_unlink(path, *args, **kwargs)

            with (
                mock.patch(
                    "skivolve.codex_app_server.os.unlink",
                    side_effect=fail_first_temporary_unlink,
                ),
                self.assertRaisesRegex(ProviderError, "finalize"),
            ):
                self.arm(binding)
            self.assertEqual(self.store.marker_path.lstat().st_nlink, 2)
            self.assertTrue(self.store.recover(binding, self.Probe()))
            assert_no_artifact()

            with (
                mock.patch(
                    "skivolve.codex_app_server._fsync_private_directory",
                    side_effect=OSError("simulated directory fsync crash"),
                ),
                self.assertRaisesRegex(ProviderError, "publish"),
            ):
                self.arm(binding)
            self.assertEqual(self.store.marker_path.lstat().st_nlink, 1)
            self.assertTrue(self.store.recover(binding, self.Probe()))
            assert_no_artifact()

    def test_systemd_not_found_inactive_shape_is_accepted(self) -> None:
        stdout = "\n".join(
            (
                "ActiveState=inactive",
                "ControlGroup=",
                "KillMode=",
                "LoadState=not-found",
            )
        )
        with (
            mock.patch(
                "skivolve.codex_app_server._resolve_system_tool",
                return_value=Path("/usr/bin/systemctl"),
            ),
            mock.patch(
                "skivolve.codex_app_server.subprocess.run",
                return_value=subprocess.CompletedProcess([], 0, stdout, ""),
            ),
        ):
            state = _SystemdRecoveryProbe().confirm_unit_clean(
                self.UNIT_NAME, None, time.monotonic() + 1
            )
        self.assertEqual(state, "not-found/inactive/empty/gone")

    def test_cgroup_cleanup_requires_control_group_mode_and_empty_membership(
        self,
    ) -> None:
        cgroup_root = self.root / "cgroup"
        group = cgroup_root / "user.slice" / "test.service"
        group.mkdir(parents=True)
        (group / "cgroup.procs").write_text("", encoding="ascii")
        (group / "cgroup.events").write_text("populated 0\n", encoding="ascii")

        def shown(kill_mode: str) -> subprocess.CompletedProcess[str]:
            return subprocess.CompletedProcess(
                [],
                0,
                "\n".join(
                    (
                        "ActiveState=inactive",
                        "ControlGroup=/user.slice/test.service",
                        f"KillMode={kill_mode}",
                        "LoadState=loaded",
                    )
                ),
                "",
            )

        probe = _SystemdRecoveryProbe(
            systemctl="/usr/bin/systemctl", cgroup_root=cgroup_root
        )
        with mock.patch(
            "skivolve.codex_app_server.subprocess.run",
            return_value=shown("control-group"),
        ) as run:
            state = probe.confirm_unit_clean(
                self.UNIT_NAME,
                "/user.slice/test.service",
                time.monotonic() + 1,
            )
        self.assertEqual(state, "loaded/inactive/control-group/empty")
        self.assertEqual(run.call_count, 2)

        for kill_mode, processes, populated in (
            ("process", "", "0"),
            ("control-group", "12345\n", "1"),
        ):
            with self.subTest(kill_mode=kill_mode, populated=populated):
                (group / "cgroup.procs").write_text(processes, encoding="ascii")
                (group / "cgroup.events").write_text(
                    f"populated {populated}\n", encoding="ascii"
                )
                with (
                    mock.patch(
                        "skivolve.codex_app_server.subprocess.run",
                        return_value=shown(kill_mode),
                    ),
                    self.assertRaisesRegex(ProviderError, "not stable"),
                ):
                    probe.confirm_unit_clean(
                        self.UNIT_NAME,
                        "/user.slice/test.service",
                        time.monotonic() + 0.01,
                    )

    def test_two_clean_cgroup_observations_may_transition_from_empty_to_gone(
        self,
    ) -> None:
        cgroup_root = self.root / "cgroup-transition"
        group = cgroup_root / "user.slice" / "test.service"
        group.mkdir(parents=True)
        (group / "cgroup.procs").write_text("", encoding="ascii")
        (group / "cgroup.events").write_text("populated 0\n", encoding="ascii")
        calls = 0

        def run(
            _command: list[str], **_kwargs: Any
        ) -> subprocess.CompletedProcess[str]:
            nonlocal calls
            calls += 1
            if calls == 1:
                stdout = (
                    "ActiveState=inactive\n"
                    "ControlGroup=/user.slice/test.service\n"
                    "KillMode=control-group\n"
                    "LoadState=loaded\n"
                )
            else:
                shutil.rmtree(group)
                stdout = (
                    "ActiveState=inactive\nControlGroup=\nKillMode=\n"
                    "LoadState=not-found\n"
                )
            return subprocess.CompletedProcess([], 0, stdout, "")

        probe = _SystemdRecoveryProbe(
            systemctl="/usr/bin/systemctl", cgroup_root=cgroup_root
        )
        with mock.patch("skivolve.codex_app_server.subprocess.run", side_effect=run):
            state = probe.confirm_unit_clean(
                self.UNIT_NAME,
                "/user.slice/test.service",
                time.monotonic() + 1,
            )
        self.assertEqual(calls, 2)
        self.assertEqual(state, "not-found/inactive/empty/gone")

    def test_missing_cgroup_evidence_does_not_certify_an_existing_group(self) -> None:
        cgroup_root = self.root / "cgroup-incomplete"
        group = cgroup_root / "user.slice" / "test.service"
        group.mkdir(parents=True)
        stdout = (
            "ActiveState=inactive\n"
            "ControlGroup=/user.slice/test.service\n"
            "KillMode=control-group\n"
            "LoadState=loaded\n"
        )
        probe = _SystemdRecoveryProbe(
            systemctl="/usr/bin/systemctl", cgroup_root=cgroup_root
        )
        with (
            mock.patch(
                "skivolve.codex_app_server.subprocess.run",
                return_value=subprocess.CompletedProcess([], 0, stdout, ""),
            ),
            self.assertRaisesRegex(ProviderError, "not stable"),
        ):
            probe.confirm_unit_clean(
                self.UNIT_NAME,
                "/user.slice/test.service",
                time.monotonic() + 0.01,
            )

    def test_process_scan_finds_exact_current_command_identity(self) -> None:
        arguments = tuple(
            os.fsdecode(argument)
            for argument in Path("/proc/self/cmdline")
            .read_bytes()
            .rstrip(b"\0")
            .split(b"\0")
        )
        with mock.patch(
            "skivolve.codex_app_server._resolve_system_tool",
            return_value=Path("/usr/bin/systemctl"),
        ):
            matches = _SystemdRecoveryProbe().matching_command_pids(
                _command_sha256(arguments)
            )
        self.assertIn(os.getpid(), matches)

    def test_process_scan_ignores_only_volatile_gone_errnos(self) -> None:
        probe = _SystemdRecoveryProbe(systemctl="/usr/bin/systemctl")
        entry = Path("/proc/12345")
        metadata = mock.Mock(st_uid=os.getuid())

        def scan(operation: str, error_number: int) -> tuple[int, ...]:
            def fake_stat(_path: Path) -> Any:
                if operation == "stat":
                    raise OSError(error_number, "simulated proc race")
                return metadata

            def fake_read(_path: Path) -> bytes:
                if operation == "cmdline":
                    raise OSError(error_number, "simulated proc race")
                return b"/bin/true\0"

            with (
                mock.patch.object(Path, "iterdir", new=lambda _path: iter((entry,))),
                mock.patch.object(Path, "stat", new=fake_stat),
                mock.patch.object(Path, "read_bytes", new=fake_read),
            ):
                return probe.matching_command_pids("a" * 64)

        for operation in ("stat", "cmdline"):
            for error_number in (errno.ENOENT, errno.ESRCH):
                with self.subTest(operation=operation, error_number=error_number):
                    self.assertEqual(scan(operation, error_number), ())
            for error_number in (errno.EACCES, errno.EIO):
                with (
                    self.subTest(operation=operation, error_number=error_number),
                    self.assertRaisesRegex(
                        ProviderError, "cannot scan local launchers"
                    ),
                ):
                    scan(operation, error_number)

    def test_missing_start_identity_requires_stronger_unit_proof(self) -> None:
        with self.store.lock(time.monotonic() + 1) as lock_identity:
            binding = self.binding(lock_identity)
            self.arm(binding)
            self.identify(start_time=None)
            loaded_inactive = self.Probe(state="loaded/inactive/control-group/gone")
            with self.assertRaisesRegex(ProviderError, "identity was incomplete"):
                self.store.recover(binding, loaded_inactive)
            self.assertTrue(self.store.recover(binding, self.Probe()))

    def test_binding_and_runtime_mount_identity_mismatches_fail_closed(self) -> None:
        with self.store.lock(time.monotonic() + 1) as lock_identity:
            binding = self.binding(lock_identity)
            self.arm(binding)
            with self.assertRaisesRegex(ProviderError, "manual remediation"):
                self.store.recover(
                    replace(binding, auth_inode=binding.auth_inode + 1), self.Probe()
                )
            self.mount.rename(self.root / "old-mount")
            self.mount.mkdir(mode=0o700)
            with self.assertRaisesRegex(ProviderError, "mountpoint identity changed"):
                self.store.recover(binding, self.Probe())

    def test_marker_symlink_mode_and_schema_tamper_fail_closed(self) -> None:
        cases = (
            "symlink",
            "hardlink",
            "mode",
            "duplicate",
            "null",
            "list",
            "string",
        )
        for case in cases:
            with self.subTest(case=case):
                self.store.marker_path.unlink(missing_ok=True)
                with self.store.lock(time.monotonic() + 1) as lock_identity:
                    binding = self.binding(lock_identity)
                    self.arm(binding)
                    if case == "symlink":
                        target = self.root / "target"
                        target.write_text("{}\n", encoding="ascii")
                        target.chmod(0o600)
                        self.store.marker_path.unlink()
                        self.store.marker_path.symlink_to(target)
                        expected = "mode-0600"
                    elif case == "hardlink":
                        os.link(self.store.marker_path, self.root / "marker-link")
                        expected = "ambiguous links"
                    elif case == "mode":
                        self.store.marker_path.chmod(0o640)
                        expected = "mode-0600"
                    else:
                        malformed = {
                            "duplicate": '{"schema_version":1,"schema_version":1}\n',
                            "null": "null\n",
                            "list": "[]\n",
                            "string": '"poison"\n',
                        }[case]
                        self.store.marker_path.write_text(
                            malformed,
                            encoding="ascii",
                        )
                        self.store.marker_path.chmod(0o600)
                        expected = (
                            "duplicate JSON key"
                            if case == "duplicate"
                            else "must be a JSON object"
                        )
                    with self.assertRaisesRegex(ProviderError, expected):
                        self.store.recover(binding, self.Probe())

    def test_provider_lock_symlink_mode_and_inode_replacement_fail_closed(self) -> None:
        self.store.lock_path.write_text("", encoding="ascii")
        self.store.lock_path.chmod(0o640)
        with self.assertRaisesRegex(ProviderError, "mode-0600"):
            with self.store.lock(time.monotonic() + 1):
                self.fail("wrong-mode provider lock unexpectedly acquired")

        self.store.lock_path.unlink()
        self.store.lock_path.symlink_to(self.auth)
        with self.assertRaisesRegex(ProviderError, "cannot open"):
            with self.store.lock(time.monotonic() + 1):
                self.fail("symlink provider lock unexpectedly acquired")

        self.store.lock_path.unlink()
        self.store.lock_path.write_text("", encoding="ascii")
        self.store.lock_path.chmod(0o600)
        os.link(self.store.lock_path, self.root / "lock-link")
        with self.assertRaisesRegex(ProviderError, "single-link"):
            with self.store.lock(time.monotonic() + 1):
                self.fail("hard-linked provider lock unexpectedly acquired")

        (self.root / "lock-link").unlink()
        self.store.lock_path.unlink()
        with self.assertRaisesRegex(ProviderError, "provider lock"):
            with self.store.lock(time.monotonic() + 1):
                self.store.lock_path.unlink()
                self.store.lock_path.write_text("", encoding="ascii")
                self.store.lock_path.chmod(0o600)

    def test_provider_lock_serializes_independent_instances(self) -> None:
        entered = threading.Event()
        release = threading.Event()

        def holder() -> None:
            with self.store.lock(time.monotonic() + 2):
                entered.set()
                release.wait(2)

        thread = threading.Thread(target=holder)
        thread.start()
        self.assertTrue(entered.wait(1))
        try:
            other = _CleanupPoisonStore(self.root)
            with self.assertRaisesRegex(ProviderError, "serialization timed out"):
                with other.lock(time.monotonic() + 0.1):
                    self.fail("independent provider unexpectedly acquired the lock")
        finally:
            release.set()
            thread.join(2)
        self.assertFalse(thread.is_alive())


class CodexProviderTests(unittest.TestCase):
    def setUp(self) -> None:
        cache_root = Path.home() / ".cache"
        cache_root.mkdir(mode=0o700, exist_ok=True)
        self.temporary = tempfile.TemporaryDirectory(
            prefix="skill-eval-provider-test-", dir=cache_root
        )
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        self.runtime_temporary = tempfile.TemporaryDirectory(
            prefix="skill-eval-provider-runtime-", dir=f"/run/user/{os.getuid()}"
        )
        self.addCleanup(self.runtime_temporary.cleanup)
        self.runtime = Path(self.runtime_temporary.name)
        self.auth = self.root / "auth.json"
        self.auth.write_text('{"auth_mode":"chatgpt"}\n', encoding="ascii")
        self.auth.chmod(0o600)
        self.repository = self.root / "repository"
        self.repository.mkdir()
        self.pair = self.root / "pair"
        self.pair.mkdir()
        self.suite = self.root / "suite"
        self.suite.mkdir()
        self.workspace = self.pair / "workspace"
        self.workspace.mkdir()
        release = self.root / "codex-release"
        lock = json.loads(LOCK_PATH.read_text(encoding="ascii"))
        runtime_files: dict[str, str] = {}
        for index, relative_path in enumerate(sorted(lock["runtime_bundle"]["files"])):
            executable = release / relative_path
            executable.parent.mkdir(parents=True, exist_ok=True)
            executable.write_text(
                f"#!/bin/sh\n# fixture {index}\nexit 0\n", encoding="ascii"
            )
            executable.chmod(0o755)
            runtime_files[relative_path] = hashlib.sha256(
                executable.read_bytes()
            ).hexdigest()
        self.fake_executable = release / "bin" / "codex"
        lock["executable_sha256"] = runtime_files["bin/codex"]
        lock["runtime_bundle"]["files"] = runtime_files
        canonical_bundle = json.dumps(
            runtime_files,
            ensure_ascii=True,
            separators=(",", ":"),
            sort_keys=True,
        ).encode("ascii")
        lock["runtime_bundle"]["sha256"] = hashlib.sha256(canonical_bundle).hexdigest()
        self.fake_lock = self.root / "codex-app-server-fixture-lock.json"
        self.fake_lock.write_text(
            json.dumps(lock, ensure_ascii=True, indent=2, sort_keys=True) + "\n",
            encoding="ascii",
        )
        self.transport: ScriptedTransport | None = None
        self.launch: tuple[tuple[str, ...], Path, dict[str, str], str] | None = None

    def config(self) -> ProviderConfig:
        return ProviderConfig(
            adapter_id="codex-app-server",
            kind="codex",
            executable=str(self.fake_executable),
            model="gpt-5.6-luna",
            reasoning_effort="low",
            billing_basis="chatgpt_subscription",
            protocol_lock=self.fake_lock,
            timeout_seconds=30,
        )

    def real_config(self) -> ProviderConfig:
        executable = _require_real_codex(self)
        return replace(
            self.config(),
            executable=str(executable),
            protocol_lock=LOCK_PATH.resolve(),
        )

    def factory(
        self,
        command: tuple[str, ...],
        cwd: Path,
        environment: dict[str, str],
        unit_name: str,
    ) -> ScriptedTransport:
        self.launch = (command, cwd, environment, unit_name)
        self.transport = ScriptedTransport(cwd)
        return self.transport

    def request(self) -> AgentRequest:
        return AgentRequest(
            case_id="case",
            variant_id="candidate",
            prompt="implement request",
            model="gpt-5.6-luna",
            workspace=self.workspace,
            skill_snapshot=None,
            sandbox_pair_root=self.pair,
            sandbox_repository_root=self.repository,
            system_context="isolated system context",
            timeout_seconds=10,
            sandbox_suite_root=self.suite,
        )

    def private_copy_factory(self) -> tuple[list[Path], Any]:
        roots: list[Path] = []

        def create(*, prefix: str, dir: str) -> str:
            self.assertEqual(prefix, "skill-executable-")
            self.assertEqual(Path(dir), Path(f"/run/user/{os.getuid()}"))
            root = self.runtime / f"private-copy-{len(roots)}"
            root.mkdir(mode=0o700)
            roots.append(root)
            return str(root)

        return roots, create

    def test_provider_context_closes_runtime_bundle_and_rejects_reuse(self) -> None:
        roots, create = self.private_copy_factory()
        with (
            mock.patch(
                "skivolve.comparator_runtime.tempfile.mkdtemp", side_effect=create
            ),
            CodexAppServerProvider(
                self.config(),
                transport_factory=self.factory,
                auth_path=self.auth,
                runtime_root=self.runtime,
                validate_lock=False,
            ) as provider,
        ):
            attestations = tuple(provider._runtime_bundle.values())
            self.assertEqual(len(attestations), 4)
            self.assertEqual(len(roots), 4)
            self.assertTrue(all(root.is_dir() for root in roots))
            self.assertTrue(
                all(
                    attestation.execution_path.is_file() for attestation in attestations
                )
            )

        self.assertTrue(all(not root.exists() for root in roots))
        provider.close()
        with self.assertRaisesRegex(ProviderError, "provider is closed"):
            provider.run_comparator(None)
        for attestation in attestations:
            with self.assertRaisesRegex(CalibrationError, "unavailable"):
                _ = attestation.descriptor_path

    def test_injected_transport_cannot_produce_result_but_exercises_launch_contract(
        self,
    ) -> None:
        provider = CodexAppServerProvider(
            self.config(),
            transport_factory=self.factory,
            auth_path=self.auth,
            runtime_root=self.runtime,
            validate_lock=False,
        )
        with self.assertRaisesRegex(ProviderError, "injected.*test-only"):
            provider.run_agent(self.request())

        self.assertEqual(
            provider.protocol_provenance["schema_sha256"],
            "f5e8d20f3a8f9bb5e5b23ab0c5aa6bde7b12e7e0713606c5d0132651a4959d37",
        )
        self.assertEqual(provider.execution_policy.concurrency, "serialized")
        self.assertFalse(provider.execution_policy.release_authoritative)
        self.assertTrue(self.transport.closed)
        command = self.launch[0]
        joined = "\n".join(command)
        self.assertIn("ProtectHome=tmpfs", joined)
        self.assertNotIn("PrivateNetwork=yes", joined)
        self.assertIn("RuntimeMaxSec=10s", joined)
        self.assertIn("KillMode=control-group", joined)
        self.assertIn("--service-type=exec", command)
        self.assertIn(f"BindPaths={self.auth}", joined)
        self.assertNotIn(f"InaccessiblePaths={self.repository}", joined)
        self.assertNotIn(f"InaccessiblePaths={self.pair}", joined)
        self.assertIn(f"BindPaths={self.workspace}:", joined)
        self.assertNotIn(f"InaccessiblePaths={self.suite}", joined)
        app_server = command.index("app-server")
        self.assertEqual(
            command[app_server:],
            (
                "app-server",
                "--listen",
                "stdio://",
                "--strict-config",
            ),
        )
        self.assertEqual(self.launch[2]["PATH"], "/usr/bin:/bin")
        self.assertEqual(list(self.runtime.iterdir()), [])
        self.assertFalse((self.workspace / ".skill-eval-tmp").exists())
        self.assertFalse((self.workspace / ".skill-eval-cache").exists())

    def test_provider_closes_transport_when_protocol_fails(self) -> None:
        def factory(
            _command: tuple[str, ...],
            cwd: Path,
            _environment: dict[str, str],
            _unit_name: str,
        ) -> ScriptedTransport:
            self.transport = ScriptedTransport(cwd, reroute=True)
            return self.transport

        provider = CodexAppServerProvider(
            self.config(),
            transport_factory=factory,
            auth_path=self.auth,
            runtime_root=self.runtime,
            validate_lock=False,
        )
        with self.assertRaisesRegex(ProviderError, "rerouted"):
            provider.run_agent(self.request())
        self.assertTrue(self.transport.closed)

    def test_timeout_is_confirmed_only_after_cleanup_and_cleanup_failure_wins(
        self,
    ) -> None:
        def exercise(*, fail_workspace_cleanup: bool) -> tuple[list[str], Exception]:
            events: list[str] = []

            def assert_no_active_confirmed_timeout() -> None:
                active = sys.exception()
                if isinstance(active, ProviderTimeoutError):
                    self.assertFalse(active.cleanup_confirmed)

            @contextlib.contextmanager
            def record_exit(name: str, value: Any) -> Iterator[Any]:
                try:
                    yield value
                finally:
                    assert_no_active_confirmed_timeout()
                    events.append(name)

            class TimeoutTransport(ScriptedTransport):
                def __init__(
                    self,
                    command: tuple[str, ...],
                    cwd: Path,
                    _environment: dict[str, str],
                    _unit_name: str,
                    **_callbacks: Any,
                ) -> None:
                    super().__init__(cwd)
                    self.evidence.update(
                        cleanup_confirmed=False,
                        command_sha256=_command_sha256(command),
                        kind="systemd-run-user+codex-permission-profile",
                        launch_confirmed=True,
                    )

                def receive(self, _deadline: float) -> bytes:
                    events.append("protocol_timeout")
                    raise ProviderTimeoutError("Codex protocol read timed out")

                def close(self) -> None:
                    assert_no_active_confirmed_timeout()
                    super().close()
                    self.evidence["cleanup_confirmed"] = True
                    events.append("transport_close")

            poison_store = mock.Mock()
            poison_store.lock.side_effect = lambda _deadline: record_exit(
                "provider_lock_exit", (1, 2)
            )
            poison_store.recover.return_value = False
            poison_store.arm.side_effect = lambda *_args: events.append("poison_arm")

            def disarm_poison(
                _binding: _PoisonBinding, evidence: dict[str, Any]
            ) -> None:
                assert_no_active_confirmed_timeout()
                self.assertIs(evidence["cleanup_confirmed"], True)
                events.append("poison_disarm")

            poison_store.disarm.side_effect = disarm_poison

            auth_checks = 0

            def assert_auth_path_matches_descriptor(
                _path: Path, _descriptor: int
            ) -> tuple[int, int]:
                nonlocal auth_checks
                auth_checks += 1
                if auth_checks == 3:
                    assert_no_active_confirmed_timeout()
                    events.append("post_auth_identity")
                return (3, 4)

            def cleanup_workspace_runtime(runtime: Any) -> None:
                assert_no_active_confirmed_timeout()
                _cleanup_workspace_runtime(runtime)
                events.append("workspace_cleanup")
                if fail_workspace_cleanup:
                    raise ProviderError("injected workspace cleanup failure")

            def remove_invocation_root(path: Path) -> None:
                assert_no_active_confirmed_timeout()
                _remove_invocation_root(path)
                events.append("invocation_root_cleanup")

            provider = CodexAppServerProvider(
                self.config(),
                transport_factory=self.factory,
                auth_path=self.auth,
                runtime_root=self.runtime,
                validate_lock=False,
            )
            self.addCleanup(provider.close)
            provider._transport_is_injected = False
            with (
                mock.patch(
                    "skivolve.codex_app_server._ProcessTransport", TimeoutTransport
                ),
                mock.patch(
                    "skivolve.codex_app_server._CleanupPoisonStore",
                    return_value=poison_store,
                ),
                mock.patch(
                    "skivolve.codex_app_server._auth_lock",
                    side_effect=lambda *_args: record_exit("auth_lock_exit", None),
                ),
                mock.patch(
                    "skivolve.codex_app_server._held_auth_descriptor",
                    side_effect=lambda *_args: record_exit("auth_descriptor_exit", 1),
                ),
                mock.patch(
                    "skivolve.codex_app_server._assert_auth_path_matches_descriptor",
                    assert_auth_path_matches_descriptor,
                ),
                mock.patch(
                    "skivolve.codex_app_server._cleanup_workspace_runtime",
                    cleanup_workspace_runtime,
                ),
                mock.patch(
                    "skivolve.codex_app_server._remove_invocation_root",
                    remove_invocation_root,
                ),
            ):
                try:
                    provider.run_agent(self.request())
                except Exception as exc:
                    return events, exc
            self.fail("timeout transport unexpectedly returned a provider result")

        expected_order = (
            "poison_arm",
            "protocol_timeout",
            "transport_close",
            "poison_disarm",
            "workspace_cleanup",
            "post_auth_identity",
            "invocation_root_cleanup",
            "auth_descriptor_exit",
            "auth_lock_exit",
            "provider_lock_exit",
        )
        for fail_workspace_cleanup in (False, True):
            with self.subTest(fail_workspace_cleanup=fail_workspace_cleanup):
                events, error = exercise(fail_workspace_cleanup=fail_workspace_cleanup)
                positions = [events.index(event) for event in expected_order]
                self.assertEqual(positions, sorted(positions))
                if fail_workspace_cleanup:
                    self.assertIs(type(error), ProviderError)
                    self.assertEqual(str(error), "injected workspace cleanup failure")
                else:
                    self.assertIs(type(error), ProviderTimeoutError)
                    self.assertTrue(error.cleanup_confirmed)

    def test_workspace_runtime_cleanup_handles_unreadable_directories_safely(
        self,
    ) -> None:
        paths = tuple(
            self.workspace / name
            for name in (
                ".skill-eval-tmp",
                ".skill-eval-cache",
                ".skill-eval-home",
            )
        )
        runtime = _prepare_workspace_runtime(self.workspace)
        unreadable = paths[0] / "d"
        nested = unreadable / "nested"
        nested.mkdir(parents=True)
        (nested / "proof").write_text("temporary", encoding="ascii")
        outside = self.workspace / "outside-proof"
        outside.write_text("preserve", encoding="ascii")
        (paths[0] / "outside-link").symlink_to(outside)
        nested.chmod(0)
        unreadable.chmod(0)

        try:
            _cleanup_workspace_runtime(runtime)
        finally:
            for directory in (nested, unreadable):
                if directory.exists():
                    directory.chmod(0o700)

        self.assertTrue(all(not path.exists() for path in paths))
        self.assertEqual(outside.read_text(encoding="ascii"), "preserve")

    def test_workspace_runtime_cleanup_does_not_follow_replaced_root(self) -> None:
        runtime = _prepare_workspace_runtime(self.workspace)
        target = self.workspace / ".skill-eval-tmp"
        displaced = self.workspace / "displaced-runtime"
        outside = self.workspace / "outside-runtime"
        outside_nested = outside / "nested"
        outside_nested.mkdir(parents=True)
        outside.chmod(0o755)
        outside_nested.chmod(0o755)
        target.rename(displaced)
        target.symlink_to(outside, target_is_directory=True)

        try:
            with self.assertRaisesRegex(ProviderError, "identity changed"):
                _cleanup_workspace_runtime(runtime)
            self.assertEqual(stat.S_IMODE(outside.stat().st_mode), 0o755)
            self.assertEqual(stat.S_IMODE(outside_nested.stat().st_mode), 0o755)
        finally:
            if target.is_symlink():
                target.unlink()
            if displaced.exists():
                displaced.rmdir()
            for name in (".skill-eval-cache", ".skill-eval-home"):
                path = self.workspace / name
                if path.exists():
                    path.rmdir()

    def test_exact_systemd_app_server_launch_and_cleanup_without_protocol_turn(
        self,
    ) -> None:
        class ProbeComplete(RuntimeError):
            pass

        evidence: dict[str, Any] = {}

        def factory(
            command: tuple[str, ...],
            cwd: Path,
            environment: dict[str, str],
            unit_name: str,
        ) -> ScriptedTransport:
            transport = _ProcessTransport(command, cwd, environment, unit_name)
            evidence.update(transport.evidence)
            transport.close()
            evidence.update(transport.evidence)
            raise ProbeComplete

        provider = CodexAppServerProvider(
            self.real_config(),
            transport_factory=factory,
            auth_path=self.auth,
            runtime_root=self.runtime,
            validate_lock=False,
        )
        with self.assertRaises(ProbeComplete):
            provider.run_agent(self.request())

        self.assertTrue(evidence["launch_confirmed"])
        self.assertEqual(
            evidence["unit_state_after_launch"],
            "loaded/active/exec/control-group",
        )
        self.assertTrue(evidence["cleanup_confirmed"])
        self.assertIn(
            evidence["unit_state_after_cleanup"],
            {
                "loaded/failed/control-group/gone",
                "loaded/inactive/control-group/gone",
                "not-found/inactive/control-group/gone",
                "not-found/inactive/empty/gone",
            },
        )
        self.assertEqual(list(self.runtime.iterdir()), [])

    def test_exact_permission_profile_allows_work_but_denies_secrets_and_network(
        self,
    ) -> None:
        class ProbeComplete(RuntimeError):
            pass

        listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.addCleanup(listener.close)
        listener.bind(("127.0.0.1", 0))
        listener.listen(1)
        port = listener.getsockname()[1]
        completed: subprocess.CompletedProcess[str] | None = None

        def factory(
            command: tuple[str, ...],
            cwd: Path,
            environment: dict[str, str],
            _unit_name: str,
        ) -> ScriptedTransport:
            nonlocal completed
            codex = str(cwd.parent / "tools" / "bin" / "codex")
            codex_index = command.index(codex)
            mounted_home = cwd / ".skill-eval-home"
            mounted_temp = cwd / ".skill-eval-tmp"
            mounted_cache = cwd / ".skill-eval-cache"
            script = "\n".join(
                (
                    "set -eu",
                    f"! cat {cwd.parent / 'codex-home' / 'auth.json'} >/dev/null 2>&1",
                    f"! cat {cwd.parent / 'codex-home' / 'config.toml'} >/dev/null 2>&1",
                    f"! test -e {self.auth}",
                    f"! test -e {self.repository}",
                    f"! test -e {self.pair}",
                    f"! test -e {self.suite}",
                    f"test -d {mounted_home}",
                    f'test "$TMPDIR" = "{mounted_temp}"',
                    f'test "$XDG_CACHE_HOME" = "{mounted_cache}"',
                    'printf temp-ok > "$TMPDIR/temp-proof"',
                    'printf cache-ok > "$XDG_CACHE_HOME/cache-proof"',
                    'test "$(cat "$TMPDIR/temp-proof")" = temp-ok',
                    'test "$(cat "$XDG_CACHE_HOME/cache-proof")" = cache-ok',
                    "if printf forbidden > /tmp/skill-eval-forbidden 2>/dev/null; then exit 98; fi",
                    "if printf forbidden > /var/tmp/skill-eval-forbidden 2>/dev/null; then exit 99; fi",
                    (
                        "if /usr/bin/python3 -c 'import socket; "
                        's=socket.create_connection(("127.0.0.1", '
                        f"{port}), 0.25)' >/dev/null 2>&1; then exit 97; fi"
                    ),
                    f"printf profile-ok > {cwd / 'profile-proof'}",
                )
            )
            probe = (
                *command[: codex_index + 1],
                "sandbox",
                "-P",
                "eval",
                "-C",
                str(cwd),
                "--",
                "/bin/sh",
                "-c",
                script,
            )
            completed = subprocess.run(
                probe,
                cwd=cwd,
                env=environment,
                capture_output=True,
                text=True,
                timeout=20,
                check=False,
                shell=False,
            )
            raise ProbeComplete

        provider = CodexAppServerProvider(
            self.real_config(),
            transport_factory=factory,
            auth_path=self.auth,
            runtime_root=self.runtime,
            validate_lock=False,
        )
        with self.assertRaises(ProbeComplete):
            provider.run_agent(self.request())

        assert completed is not None
        self.assertEqual(
            completed.returncode,
            0,
            msg=f"stdout={completed.stdout!r} stderr={completed.stderr!r}",
        )
        self.assertEqual(
            (self.workspace / "profile-proof").read_text(encoding="ascii"),
            "profile-ok",
        )

    def test_result_mapping_recursively_omits_credentials_and_opaque_ids(self) -> None:
        sentinel = "SENTINEL_CREDENTIAL_123"
        transport = ScriptedTransport(
            Path("/runtime/work"), identifier_sentinel=sentinel
        )
        outcome = _protocol(transport).run("request", time.monotonic() + 5)
        provider = CodexAppServerProvider(
            self.config(),
            transport_factory=self.factory,
            auth_path=self.auth,
            runtime_root=self.runtime,
            validate_lock=False,
        )

        result = provider._build_result(
            self.request(),
            outcome,
            {"enforced": True, "kind": "unit-test-mapping"},
            duration_seconds=0.1,
        )
        serialized = json.dumps(asdict(result), sort_keys=True)

        self.assertNotIn(sentinel, serialized)
        self.assertNotIn("must-not-survive@example.invalid", serialized)
        self.assertIn("thread_id_sha256", result.raw_response)
        self.assertIn("turn_id_sha256", result.raw_response)
        self.assertIn("final_message_id_sha256", result.raw_response["turn"])
        self.assertNotIn("final_message_id", result.raw_response["turn"])

    def test_auth_path_replacement_fails_and_still_removes_runtime(self) -> None:
        auth = self.auth

        class ReplacingTransport(ScriptedTransport):
            def close(self) -> None:
                super().close()
                replacement = auth.with_name("auth-replacement.json")
                replacement.write_text('{"auth_mode":"chatgpt"}\n', encoding="ascii")
                replacement.chmod(0o600)
                replacement.replace(auth)

        def factory(
            _command: tuple[str, ...],
            cwd: Path,
            _environment: dict[str, str],
            _unit_name: str,
        ) -> ScriptedTransport:
            self.transport = ReplacingTransport(cwd)
            return self.transport

        provider = CodexAppServerProvider(
            self.config(),
            transport_factory=factory,
            auth_path=self.auth,
            runtime_root=self.runtime,
            validate_lock=False,
        )
        with self.assertRaisesRegex(ProviderError, "pathname changed"):
            provider.run_agent(self.request())

        self.assertTrue(self.transport.closed)
        self.assertEqual(list(self.runtime.iterdir()), [])
        self.assertFalse((self.workspace / ".skill-eval-tmp").exists())

    def test_same_inode_auth_refresh_is_allowed_until_test_transport_boundary(
        self,
    ) -> None:
        auth = self.auth

        class RefreshingTransport(ScriptedTransport):
            def close(self) -> None:
                super().close()
                auth.write_text(
                    '{"auth_mode":"chatgpt","refresh_token":"rotated"}\n',
                    encoding="ascii",
                )

        def factory(
            _command: tuple[str, ...],
            cwd: Path,
            _environment: dict[str, str],
            _unit_name: str,
        ) -> ScriptedTransport:
            self.transport = RefreshingTransport(cwd)
            return self.transport

        before = self.auth.stat()
        provider = CodexAppServerProvider(
            self.config(),
            transport_factory=factory,
            auth_path=self.auth,
            runtime_root=self.runtime,
            validate_lock=False,
        )
        with self.assertRaisesRegex(ProviderError, "injected.*test-only"):
            provider.run_agent(self.request())

        after = self.auth.stat()
        self.assertEqual((before.st_dev, before.st_ino), (after.st_dev, after.st_ino))
        self.assertIn("rotated", self.auth.read_text(encoding="ascii"))
        self.assertEqual(list(self.runtime.iterdir()), [])

    def test_systemd_property_paths_reject_colon_and_control_characters(self) -> None:
        provider = CodexAppServerProvider(
            self.config(),
            transport_factory=self.factory,
            auth_path=self.auth,
            runtime_root=self.runtime,
            validate_lock=False,
        )
        for component in ("bad:path", "bad\npath", "bad path", "bad%path", "bad\\path"):
            with self.subTest(component=repr(component)):
                workspace = self.pair / component
                workspace.mkdir()
                with self.assertRaisesRegex(ProviderError, "systemd path property"):
                    provider.run_agent(replace(self.request(), workspace=workspace))
                self.assertFalse((workspace / ".skill-eval-tmp").exists())
                self.assertEqual(list(self.runtime.iterdir()), [])

    def test_timeout_bounds_and_workspace_symlink_fail_before_dispatch(self) -> None:
        provider = CodexAppServerProvider(
            replace(self.config(), timeout_seconds=4_000),
            transport_factory=self.factory,
            auth_path=self.auth,
            runtime_root=self.runtime,
            validate_lock=False,
        )
        for timeout in (0, 3_601):
            with self.subTest(timeout=timeout):
                with self.assertRaisesRegex(ProviderError, "timeout exceeds"):
                    provider.run_agent(replace(self.request(), timeout_seconds=timeout))

        workspace_link = self.root / "workspace-link"
        workspace_link.symlink_to(self.workspace, target_is_directory=True)
        with self.assertRaisesRegex(ProviderError, "non-symlink"):
            provider.run_agent(replace(self.request(), workspace=workspace_link))
        self.assertIsNone(self.transport)

    def test_invocations_use_distinct_roots_and_rewrite_skill_context_once(
        self,
    ) -> None:
        launches: list[tuple[tuple[str, ...], Path, ScriptedTransport]] = []

        def factory(
            _command: tuple[str, ...],
            cwd: Path,
            _environment: dict[str, str],
            _unit_name: str,
        ) -> ScriptedTransport:
            transport = ScriptedTransport(cwd)
            launches.append((_command, cwd, transport))
            return transport

        snapshot = self.pair / "skill-snapshot"
        snapshot.mkdir()
        request = replace(
            self.request(),
            skill_snapshot=snapshot,
            system_context=f"Use the skill at {snapshot} exactly.",
        )
        provider = CodexAppServerProvider(
            self.config(),
            transport_factory=factory,
            auth_path=self.auth,
            runtime_root=self.runtime,
            validate_lock=False,
        )
        for _ in range(2):
            with self.assertRaisesRegex(ProviderError, "injected.*test-only"):
                provider.run_agent(request)

        mounted_root = launches[0][1].parent
        root_sources = []
        for command, cwd, transport in launches:
            root_binding = next(
                value
                for value in command
                if value.startswith("BindPaths=") and value.endswith(f":{mounted_root}")
            )
            root_sources.append(root_binding.removeprefix("BindPaths=").split(":")[0])
            thread_start = next(
                message
                for message in transport.sent
                if message.get("method") == "thread/start"
            )
            context = thread_start["params"]["developerInstructions"]
            self.assertNotIn(str(snapshot), context)
            self.assertEqual(context.count(str(cwd.parent / "skill")), 1)
        self.assertNotEqual(root_sources[0], root_sources[1])
        self.assertEqual(list(self.runtime.iterdir()), [])

    def test_comparator_is_explicitly_unsupported(self) -> None:
        provider = CodexAppServerProvider(
            self.config(),
            transport_factory=self.factory,
            auth_path=self.auth,
            runtime_root=self.runtime,
            validate_lock=False,
        )
        with self.assertRaisesRegex(ProviderError, "generator-only"):
            provider.run_comparator(None)

    def test_static_config_denies_credentials_and_command_network(self) -> None:
        text = _static_config(self.runtime, "gpt-5.6-luna", "low").decode()
        config = tomllib.loads(text)
        self.assertIn('default_permissions = "eval"', text)
        self.assertEqual(config["web_search"], "disabled")
        self.assertIn(f'"{self.runtime / "codex-home"}" = "read"', text)
        self.assertIn(f'"{self.runtime / "codex-home" / "auth.json"}" = "deny"', text)
        self.assertIn(f'"{self.runtime / "codex-home" / "config.toml"}" = "deny"', text)
        self.assertIn(f'HOME = "{self.runtime / "work" / ".skill-eval-home"}"', text)
        self.assertIn(f'"{self.runtime / "work"}" = "write"', text)
        self.assertIn(f'"{self.runtime / "work" / ".skill-eval-tmp"}" = "write"', text)
        self.assertIn(
            f'"{self.runtime / "work" / ".skill-eval-cache"}" = "write"', text
        )
        self.assertIn(f'"{self.runtime / "skill"}" = "read"', text)
        self.assertIn(f'"{self.runtime / "tools"}" = "read"', text)
        self.assertIn("[permissions.eval.network]\nenabled = false", text)
        self.assertIs(
            config["tools"]["experimental_request_user_input"]["enabled"], False
        )
        self.assertIn("plugins = false", text)
        self.assertIn("hooks = false", text)
        self.assertIn("apps = false", text)

    def test_auth_lock_serializes_with_deadline(self) -> None:
        entered = threading.Event()
        release = threading.Event()

        def holder() -> None:
            with _auth_lock(self.auth, time.monotonic() + 2):
                entered.set()
                release.wait(2)

        thread = threading.Thread(target=holder)
        thread.start()
        self.assertTrue(entered.wait(1))
        try:
            with self.assertRaisesRegex(ProviderError, "serialization timed out"):
                with _auth_lock(self.auth, time.monotonic() + 0.1):
                    self.fail("second auth lock unexpectedly acquired")
        finally:
            release.set()
            thread.join(2)
        self.assertFalse(thread.is_alive())

    def test_auth_file_with_group_permissions_is_rejected(self) -> None:
        self.auth.chmod(0o640)
        roots, create = self.private_copy_factory()
        attestations: list[RuntimeVerifiedExecutable] = []

        def capture(path: Path) -> RuntimeVerifiedExecutable:
            attestation = RuntimeVerifiedExecutable(path)
            attestations.append(attestation)
            return attestation

        with (
            mock.patch(
                "skivolve.codex_app_server.VerifiedExecutable", side_effect=capture
            ),
            mock.patch(
                "skivolve.comparator_runtime.tempfile.mkdtemp", side_effect=create
            ),
            self.assertRaisesRegex(ProviderError, "mode-0600"),
        ):
            CodexAppServerProvider(
                self.config(),
                transport_factory=self.factory,
                auth_path=self.auth,
                runtime_root=self.runtime,
                validate_lock=False,
            )
        self.assertEqual(len(roots), 4)
        self.assertEqual(len(attestations), 4)
        self.assertTrue(all(not root.exists() for root in roots))
        for attestation in attestations:
            with self.assertRaisesRegex(CalibrationError, "unavailable"):
                _ = attestation.descriptor_path


class CodexLockTests(unittest.TestCase):
    def test_cli_version_output_is_exact(self) -> None:
        banner = "codex-cli 0.144.3"
        valid = subprocess.CompletedProcess(
            args=("codex", "--version"),
            returncode=0,
            stdout=f"{banner}\n",
            stderr="",
        )
        _validate_cli_version_output(valid, banner)

        invalid = (
            ("leading whitespace", 0, f" {banner}\n", ""),
            ("trailing whitespace", 0, f"{banner} \n", ""),
            ("missing newline", 0, banner, ""),
            ("extra blank line", 0, f"{banner}\n\n", ""),
            ("extra output line", 0, f"{banner}\nother\n", ""),
            ("stderr output", 0, f"{banner}\n", "warning\n"),
            ("stderr fallback", 0, "", f"{banner}\n"),
            ("nonzero exit", 1, f"{banner}\n", ""),
        )
        for label, returncode, stdout, stderr in invalid:
            with self.subTest(label=label):
                completed = subprocess.CompletedProcess(
                    args=("codex", "--version"),
                    returncode=returncode,
                    stdout=stdout,
                    stderr=stderr,
                )
                expected = "command failed" if returncode else "differs"
                with self.assertRaisesRegex(ProviderError, expected):
                    _validate_cli_version_output(completed, banner)

    def test_lock_matches_installed_binary_and_regenerated_protocol_without_model_turn(
        self,
    ) -> None:
        executable = _require_real_codex(self)
        lock = _load_protocol_lock(LOCK_PATH)
        validate_codex_protocol_lock(executable, lock)
        self.assertEqual(lock.cli_version, "codex-cli 0.144.3")
        self.assertEqual(lock.thread_cli_version, "0.144.3")
        self.assertEqual(
            lock.protocol_sha256,
            "f5e8d20f3a8f9bb5e5b23ab0c5aa6bde7b12e7e0713606c5d0132651a4959d37",
        )
        self.assertEqual(lock.protocol_canonical_bytes, 308970)
        self.assertEqual(
            hashlib.sha256(LOCK_PATH.read_bytes()).hexdigest(), lock.sha256
        )

    def test_lock_requires_an_exact_semver_cli_banner(self) -> None:
        valid = "codex-cli 1.2.3-alpha.1+build.5"
        invalid = (
            "0.144.1",
            "codex 0.144.1",
            "codex-cli 0.144",
            "codex-cli 01.144.1",
            "codex-cli 0.144.1-01",
            "codex-cli 0.144.1 extra",
            "codex-cli 0.144.1\n",
            " codex-cli 0.144.1",
            "codex-cli \u0660.144.1",
        )
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / "lock.json"
            payload = json.loads(LOCK_PATH.read_text(encoding="ascii"))
            payload["codex_cli_version"] = valid
            path.write_text(json.dumps(payload), encoding="ascii")
            self.assertEqual(
                _load_protocol_lock(path).thread_cli_version,
                "1.2.3-alpha.1+build.5",
            )
            for cli_version in invalid:
                with self.subTest(cli_version=cli_version):
                    payload["codex_cli_version"] = cli_version
                    path.write_text(json.dumps(payload), encoding="ascii")
                    with self.assertRaisesRegex(
                        ProviderError, "exact Codex SemVer banner"
                    ):
                        _load_protocol_lock(path)

    def test_lock_rejects_duplicate_json_keys(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / "lock.json"
            path.write_text('{"schema_version":1,"schema_version":1}\n')
            with self.assertRaisesRegex(ProviderError, "duplicate JSON key"):
                _load_protocol_lock(path)

    def test_lock_rejects_symlink_path(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / "lock.json"
            path.symlink_to(LOCK_PATH)
            with self.assertRaisesRegex(ProviderError, "cannot open"):
                _load_protocol_lock(path)

    def test_lock_file_is_plain_json_and_contains_no_credentials(self) -> None:
        metadata = LOCK_PATH.lstat()
        self.assertTrue(stat.S_ISREG(metadata.st_mode))
        self.assertFalse(stat.S_ISLNK(metadata.st_mode))
        raw = LOCK_PATH.read_text(encoding="ascii")
        self.assertNotIn("token", raw.lower())
        self.assertNotIn("email", raw.lower())
        self.assertEqual(json.loads(raw)["schema_version"], 1)


if __name__ == "__main__":
    unittest.main()
