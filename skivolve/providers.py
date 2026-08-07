"""Agent and comparator providers for the evaluation harness."""

from __future__ import annotations

import copy
import hashlib
import json
import math
import os
import platform
import re
import secrets
import shutil
import subprocess
import sys
import threading
import time
import uuid
from dataclasses import InitVar, asdict, dataclass, field
from pathlib import Path
from typing import Any, Callable, Protocol

from skivolve.comparator_runtime import (
    CalibrationError,
    ComparatorRuntime,
    MAX_RESPONSE_BYTES,
    MAX_STDERR_BYTES,
    SANDBOX_ISOLATION_PROPERTIES,
    SandboxedClaudeExecutor,
    SpendLedger,
    TransportExecution,
    TransportOverflowError,
    VerifiedExecutable,
    canonical_sha256,
    execute_bounded_transport,
    expected_transport_hashes,
    parse_raw_provider_response,
    validate_executor_evidence,
    validate_response,
)

from .manifest import ProviderConfig
from .provider_capabilities import (
    ProviderCapabilityError,
    capabilities_for,
)


class ProviderError(RuntimeError):
    """Raised when a provider cannot return complete, attributable evidence."""


@dataclass(frozen=True)
class ProviderExecutionPolicy:
    """Scheduling and release-authority constraints for a provider kind."""

    concurrency: str
    release_authoritative: bool

    def __post_init__(self) -> None:
        if type(self.release_authoritative) is not bool or (
            self.concurrency,
            self.release_authoritative,
        ) not in {
            ("concurrent", True),
            ("serialized", False),
        }:
            raise ValueError("unsupported provider execution policy")

    def as_json(self) -> dict[str, Any]:
        return asdict(self)


CONCURRENT_AUTHORITATIVE = ProviderExecutionPolicy("concurrent", True)
SERIALIZED_DIAGNOSTIC = ProviderExecutionPolicy("serialized", False)


def execution_policy_for(adapter_id: str) -> ProviderExecutionPolicy:
    """Return the immutable execution policy for a reviewed adapter."""

    try:
        capabilities = capabilities_for(adapter_id)
    except ProviderCapabilityError as exc:
        raise ProviderError(str(exc)) from exc
    if capabilities.concurrency == "serialized":
        return SERIALIZED_DIAGNOSTIC
    return CONCURRENT_AUTHORITATIVE


@dataclass(frozen=True)
class AgentRequest:
    case_id: str
    variant_id: str
    prompt: str
    model: str
    workspace: Path
    skill_snapshot: Path | None
    sandbox_pair_root: Path
    sandbox_repository_root: Path
    system_context: str
    timeout_seconds: int
    sandbox_suite_root: Path | None = None
    required_tools: tuple[tuple[str, str], ...] = ()
    on_dispatched: Callable[[], None] | None = None


@dataclass(frozen=True)
class ComparatorRequest:
    pair: dict[str, Any]
    repetition: int
    order: str
    request_bytes: bytes
    runtime: ComparatorRuntime
    spend_ledger: SpendLedger
    model: str
    timeout_seconds: int
    max_budget_usd: float | None
    sandbox_repository_root: Path
    sandbox_suite_root: Path | None = None
    sandbox_isolation_root: Path | None = None

    def __post_init__(self) -> None:
        object.__setattr__(self, "_request_token_value", secrets.token_hex(32))

    @property
    def _request_token(self) -> str:
        return self._request_token_value  # type: ignore[attr-defined]

    def __copy__(self) -> ComparatorRequest:
        return type(self)(
            pair=self.pair,
            repetition=self.repetition,
            order=self.order,
            request_bytes=self.request_bytes,
            runtime=self.runtime,
            spend_ledger=self.spend_ledger,
            model=self.model,
            timeout_seconds=self.timeout_seconds,
            max_budget_usd=self.max_budget_usd,
            sandbox_repository_root=self.sandbox_repository_root,
            sandbox_suite_root=self.sandbox_suite_root,
            sandbox_isolation_root=self.sandbox_isolation_root,
        )

    def __deepcopy__(self, memo: dict[int, Any]) -> ComparatorRequest:
        duplicate = type(self)(
            pair=copy.deepcopy(self.pair, memo),
            repetition=self.repetition,
            order=self.order,
            request_bytes=self.request_bytes,
            runtime=self.runtime,
            spend_ledger=self.spend_ledger,
            model=self.model,
            timeout_seconds=self.timeout_seconds,
            max_budget_usd=self.max_budget_usd,
            sandbox_repository_root=self.sandbox_repository_root,
            sandbox_suite_root=self.sandbox_suite_root,
            sandbox_isolation_root=self.sandbox_isolation_root,
        )
        memo[id(self)] = duplicate
        return duplicate


@dataclass(frozen=True)
class ProviderResult:
    final_output: str
    requested_model: str
    actual_models: tuple[str, ...]
    provider_name: str
    provider_version: str
    duration_seconds: float
    cost_usd: float | None
    tokens: dict[str, int]
    sandbox: dict[str, Any]
    raw_response: dict[str, Any]
    billing_basis: str = "metered_api"
    quota: dict[str, Any] | None = None
    protocol_provenance: dict[str, Any] | None = None

    def __post_init__(self) -> None:
        if not isinstance(self.final_output, str):
            raise ProviderError("provider result final_output must be a string")
        for value, location in (
            (self.requested_model, "requested_model"),
            (self.provider_name, "provider_name"),
            (self.provider_version, "provider_version"),
        ):
            if not isinstance(value, str) or not value:
                raise ProviderError(
                    f"provider result {location} must be a non-empty string"
                )
        if (
            not isinstance(self.actual_models, tuple)
            or not self.actual_models
            or not all(isinstance(model, str) and model for model in self.actual_models)
            or len(set(self.actual_models)) != len(self.actual_models)
        ):
            raise ProviderError(
                "provider result actual_models must be unique non-empty strings"
            )
        if (
            isinstance(self.duration_seconds, bool)
            or not isinstance(self.duration_seconds, (int, float))
            or not math.isfinite(self.duration_seconds)
            or self.duration_seconds < 0
        ):
            raise ProviderError(
                "provider result duration_seconds must be finite and non-negative"
            )
        if not isinstance(self.billing_basis, str) or self.billing_basis not in {
            "metered_api",
            "chatgpt_subscription",
        }:
            raise ProviderError("provider result has unsupported billing_basis")
        if self.billing_basis == "metered_api":
            if self.cost_usd is None:
                raise ProviderError("metered provider result requires cost_usd")
            _validate_cost(self.cost_usd, "provider result cost_usd")
        elif self.cost_usd is not None:
            raise ProviderError(
                "ChatGPT subscription provider result must report cost_usd as null"
            )
        _validate_tokens(self.tokens, "provider result tokens")
        _validate_json_object(self.raw_response, "provider result raw_response")
        _validate_json_object(self.sandbox, "provider result sandbox")
        if self.sandbox.get("enforced") is not True:
            raise ProviderError("provider result sandbox must be enforced")
        if not isinstance(self.sandbox.get("kind"), str) or not self.sandbox["kind"]:
            raise ProviderError("provider result sandbox kind must be non-empty")
        if self.quota is not None:
            _validate_json_object(self.quota, "provider result quota")
        if self.protocol_provenance is not None:
            _validate_json_object(
                self.protocol_provenance,
                "provider result protocol_provenance",
            )
        if self.billing_basis == "chatgpt_subscription" and (
            not self.quota or not self.protocol_provenance
        ):
            raise ProviderError(
                "ChatGPT subscription result requires quota and protocol provenance"
            )

    def as_json(self) -> dict[str, Any]:
        self.__post_init__()
        return asdict(self)


@dataclass(frozen=True)
class _ComparatorResultBinding:
    request_token: str
    request_sha256: str
    invocation_id: str
    repetition: int
    order: str
    requested_model: str
    state_sha256: str


@dataclass(frozen=True)
class ComparatorResult:
    outcome: str
    decision: dict[str, Any]
    response: dict[str, Any]
    transport: dict[str, Any]
    provider: ProviderResult
    request: InitVar[ComparatorRequest] = field(kw_only=True)
    _binding: _ComparatorResultBinding = field(init=False, repr=False, compare=False)

    def __post_init__(self, request: ComparatorRequest) -> None:
        try:
            decision = _json_copy(self.decision, "decision")
            response = _json_copy(self.response, "response")
            transport = _json_copy(self.transport, "transport")
            provider = copy.deepcopy(self.provider)
        except ProviderError:
            raise
        except (AttributeError, RecursionError, TypeError, ValueError) as exc:
            raise ProviderError("comparator result cannot be copied safely") from exc
        object.__setattr__(self, "decision", decision)
        object.__setattr__(self, "response", response)
        object.__setattr__(self, "transport", transport)
        object.__setattr__(self, "provider", provider)
        binding = _validate_comparator_result(self, request)
        object.__setattr__(self, "_binding", binding)

    def as_json(self, request: ComparatorRequest) -> dict[str, Any]:
        if (
            not isinstance(request, ComparatorRequest)
            or request._request_token != self._binding.request_token
        ):
            raise ProviderError(
                "comparator result consumption request differs from its origin"
            )
        try:
            payload = {
                "outcome": self.outcome,
                "decision": _json_copy(self.decision, "decision"),
                "response": _json_copy(self.response, "response"),
                "transport": _json_copy(self.transport, "transport"),
                "provider": self.provider.as_json(),
            }
            observed_sha256 = _canonical_evidence_sha256(payload)
        except ProviderError:
            raise
        except (AttributeError, RecursionError, TypeError, ValueError) as exc:
            raise ProviderError(
                "comparator result cannot be serialized safely"
            ) from exc
        if observed_sha256 != self._binding.state_sha256:
            raise ProviderError("comparator result changed after validation")
        current_binding = _validate_comparator_result(self, request)
        if current_binding != self._binding:
            raise ProviderError(
                "comparator result or consumption request changed after validation"
            )
        return payload


_COMPARATOR_TRANSPORT_KEYS = frozenset(
    {
        "response",
        "decision",
        "raw_response",
        "requested_model",
        "actual_models",
        "provider_name",
        "provider_version",
        "cost_usd",
        "duration_seconds",
        "request_sha256",
        "raw_response_sha256",
        "parsed_response_sha256",
        "command_sha256",
        "stdin_sha256",
        "spend_attempt_id",
        "executor",
    }
)
_COMPARATOR_ATTEMPT_RE = re.compile(r"^[0-9a-f]{32}$")
_COMPARATOR_INVOCATION_RE = re.compile(r"^[0-9a-f]{64}$")


def _json_copy(value: Any, location: str) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise ProviderError(f"comparator {location} must be a JSON object")
    try:
        encoded = json.dumps(
            value,
            allow_nan=False,
            ensure_ascii=True,
            separators=(",", ":"),
            sort_keys=True,
        )
        decoded = json.loads(encoded)
    except (TypeError, ValueError, json.JSONDecodeError, RecursionError) as exc:
        raise ProviderError(f"comparator {location} is not canonical JSON") from exc
    if not isinstance(decoded, dict):
        raise ProviderError(f"comparator {location} must be a JSON object")
    return decoded


def _decode_json_object(raw: str, location: str) -> dict[str, Any]:
    try:
        value = json.loads(raw)
    except (TypeError, ValueError, json.JSONDecodeError, RecursionError) as exc:
        raise ProviderError(f"{location} is invalid JSON") from exc
    _validate_json_object(value, location)
    return value


def _canonical_evidence_sha256(value: Any) -> str:
    try:
        return canonical_sha256(value)
    except (
        AttributeError,
        CalibrationError,
        KeyError,
        RecursionError,
        TypeError,
        ValueError,
    ) as exc:
        raise ProviderError("comparator evidence is not canonical JSON") from exc


def _validate_comparator_result(
    result: ComparatorResult, request: ComparatorRequest
) -> _ComparatorResultBinding:
    if not isinstance(request, ComparatorRequest):
        raise ProviderError("comparator result requires its originating request")
    if (
        isinstance(request.repetition, bool)
        or not isinstance(request.repetition, int)
        or request.repetition < 0
        or request.order not in {"AB", "BA"}
        or not isinstance(request.request_bytes, bytes)
        or not request.request_bytes
        or not isinstance(request.model, str)
        or not request.model
        or _COMPARATOR_INVOCATION_RE.fullmatch(request._request_token) is None
        or not isinstance(request.pair, dict)
        or not isinstance(request.spend_ledger, SpendLedger)
        or not isinstance(request.sandbox_repository_root, Path)
        or not request.sandbox_repository_root.is_absolute()
        or (
            request.sandbox_suite_root is not None
            and (
                not isinstance(request.sandbox_suite_root, Path)
                or not request.sandbox_suite_root.is_absolute()
            )
        )
        or (
            request.sandbox_isolation_root is not None
            and (
                not isinstance(request.sandbox_isolation_root, Path)
                or not request.sandbox_isolation_root.is_absolute()
            )
        )
    ):
        raise ProviderError("comparator request provenance is malformed")
    pair_id = request.pair.get("id")
    if not isinstance(pair_id, str) or not pair_id:
        raise ProviderError("comparator request pair identity is malformed")
    try:
        expected_request = request.runtime.request_bytes(
            request.pair, request.repetition, request.order
        )
        invocation_id = request.runtime.invocation_id(
            pair_id, request.repetition, request.order
        )
        envelope = json.loads(expected_request)
        expected_decision = validate_response(
            request.runtime.bundle,
            request.pair,
            result.response,
            request.order,
        )
        expected_decision = _json_copy(expected_decision, "normalized decision")
        release = request.runtime.bundle.release
        judge = release["judge"]
        limits = release["execution_limits"]
    except (
        AttributeError,
        CalibrationError,
        KeyError,
        RecursionError,
        TypeError,
        UnicodeDecodeError,
        ValueError,
        json.JSONDecodeError,
    ) as exc:
        raise ProviderError("comparator request or response failed validation") from exc
    if not isinstance(expected_request, bytes) or not expected_request:
        raise ProviderError("comparator runtime returned malformed request bytes")
    if (
        not isinstance(invocation_id, str)
        or _COMPARATOR_INVOCATION_RE.fullmatch(invocation_id) is None
    ):
        raise ProviderError("comparator invocation identity is malformed")
    if request.request_bytes != expected_request:
        raise ProviderError("comparator request bytes are not canonical")
    user_payload = envelope.get("user_payload") if isinstance(envelope, dict) else None
    if (
        not isinstance(user_payload, dict)
        or user_payload.get("invocation_id") != invocation_id
    ):
        raise ProviderError("comparator invocation identity is inconsistent")
    try:
        timeout_seconds = limits["timeout_seconds"]
        per_call_usd = limits["per_invocation_max_usd"]
        run_max_usd = limits["run_max_usd"]
    except (AttributeError, KeyError, TypeError) as exc:
        raise ProviderError("comparator release limits are malformed") from exc
    if (
        type(request.timeout_seconds) is not int
        or request.timeout_seconds <= 0
        or request.timeout_seconds != timeout_seconds
        or isinstance(request.max_budget_usd, bool)
        or not isinstance(request.max_budget_usd, (int, float))
        or not math.isfinite(request.max_budget_usd)
        or request.max_budget_usd <= 0
        or request.max_budget_usd != per_call_usd
        or request.spend_ledger.maximum_usd != run_max_usd
    ):
        raise ProviderError("comparator request limits differ from release")
    if expected_decision.get(
        "unsupported_performance"
    ) is not False or expected_decision.get("unsupported_qualitative") not in ([], ()):
        raise ProviderError("comparator decision uses unsupported evidence")
    criteria = expected_decision.get("criteria")
    if criteria is not None and any(
        winner != "tie"
        and release["criterion_support"][criterion]["production_decisive"] is not True
        for criterion, winner in criteria.items()
    ):
        raise ProviderError("comparator decision uses an uncalibrated criterion")

    transport = result.transport
    if set(transport) != _COMPARATOR_TRANSPORT_KEYS:
        raise ProviderError("comparator transport evidence has an unexpected shape")
    raw_response = transport.get("raw_response")
    if not isinstance(raw_response, str):
        raise ProviderError("comparator raw response must be text")
    try:
        raw_payload = json.loads(raw_response)
        parsed_response, parsed_models, parsed_cost = parse_raw_provider_response(
            raw_response
        )
    except (CalibrationError, TypeError, ValueError, json.JSONDecodeError) as exc:
        raise ProviderError("comparator raw response failed validation") from exc
    provider = result.provider
    try:
        provider_payload = provider.as_json()
    except ProviderError:
        raise
    except (AttributeError, RecursionError, TypeError, ValueError) as exc:
        raise ProviderError("comparator provider evidence failed validation") from exc
    request_sha256 = hashlib.sha256(expected_request).hexdigest()
    expected = {
        "response": result.response,
        "decision": result.decision,
        "raw_response": provider.final_output,
        "requested_model": provider.requested_model,
        "actual_models": list(provider.actual_models),
        "provider_name": provider.provider_name,
        "provider_version": provider.provider_version,
        "cost_usd": provider.cost_usd,
        "duration_seconds": provider.duration_seconds,
        "request_sha256": request_sha256,
        "raw_response_sha256": hashlib.sha256(raw_response.encode("utf-8")).hexdigest(),
        "parsed_response_sha256": _canonical_evidence_sha256(result.response),
        "executor": provider.sandbox,
    }
    for key, value in expected.items():
        observed = transport.get(key)
        if _canonical_evidence_sha256(observed) != _canonical_evidence_sha256(value):
            raise ProviderError("comparator transport and provider evidence disagree")
    if (
        _canonical_evidence_sha256(parsed_response)
        != _canonical_evidence_sha256(result.response)
        or _canonical_evidence_sha256(expected_decision)
        != _canonical_evidence_sha256(result.decision)
        or _canonical_evidence_sha256(raw_payload)
        != _canonical_evidence_sha256(provider.raw_response)
        or result.outcome != result.decision.get("outcome")
        or parsed_models != list(provider.actual_models)
        or parsed_cost != provider.cost_usd
        or provider.tokens != _extract_tokens(raw_payload)
        or provider.billing_basis != "metered_api"
        or provider.quota is not None
        or provider.protocol_provenance is not None
        or provider.cost_usd is None
        or provider.cost_usd > request.max_budget_usd
        or request.model != provider.requested_model
        or judge.get("requested_model") != provider.requested_model
        or judge.get("provider") != provider.provider_name
        or judge.get("provider_version") != provider.provider_version
    ):
        raise ProviderError("comparator result is internally inconsistent")

    executor = transport.get("executor")
    if not isinstance(executor, dict):
        raise ProviderError("comparator executor evidence must be an object")
    try:
        if executor.get("kind") == "deterministic-fake":
            if (
                release.get("test_release") is not True
                or provider.provider_name != "deterministic-fake"
                or executor != {"enforced": True, "kind": "deterministic-fake"}
            ):
                raise ProviderError("comparator fake executor is not admissible")
            command_executable = "fake-claude"
        else:
            command_executable = executor["command_executable"]
            validate_executor_evidence(
                request.runtime.bundle,
                executor,
                executable_sha256=executor["executable_sha256"],
                stdin_sha256=transport["stdin_sha256"],
                location="comparator executor",
            )
            required_inaccessible = {
                f"InaccessiblePaths={request.sandbox_repository_root}",
                "InaccessiblePaths="
                f"{request.sandbox_suite_root or request.sandbox_repository_root}",
            }
            if request.sandbox_isolation_root is not None:
                required_inaccessible.add(
                    f"InaccessiblePaths={request.sandbox_isolation_root}"
                )
            properties = executor.get("properties")
            if not isinstance(properties, list) or not required_inaccessible.issubset(
                properties
            ):
                raise ProviderError(
                    "comparator executor is not bound to the requested sandbox roots"
                )
        hashes = expected_transport_hashes(
            request.runtime.bundle, expected_request, command_executable
        )
    except ProviderError:
        raise
    except (
        AttributeError,
        CalibrationError,
        KeyError,
        RecursionError,
        TypeError,
        ValueError,
    ) as exc:
        raise ProviderError(
            "comparator executor or transport hashes failed validation"
        ) from exc
    if any(transport.get(key) != value for key, value in hashes.items()):
        raise ProviderError(
            "comparator request, stdin, or command digest is inconsistent"
        )
    attempt_id = transport.get("spend_attempt_id")
    if (
        not isinstance(attempt_id, str)
        or _COMPARATOR_ATTEMPT_RE.fullmatch(attempt_id) is None
    ):
        raise ProviderError("comparator spend attempt identity is malformed")
    try:
        records = request.spend_ledger.journal_records()
        has_journal = request.spend_ledger.has_journal_records
    except (
        AttributeError,
        CalibrationError,
        OSError,
        RecursionError,
        ValueError,
    ) as exc:
        raise ProviderError("comparator spend provenance failed validation") from exc
    attempt_records = [
        record for record in records if record.get("attempt_id") == attempt_id
    ]
    expected_spend_records = [
        {
            "event": "reserve",
            "attempt_id": attempt_id,
            "invocation_id": invocation_id,
            "request_sha256": request_sha256,
            "reserved_usd": per_call_usd,
        },
        {
            "event": "reconcile",
            "attempt_id": attempt_id,
            "charged_usd": provider.cost_usd,
            "invocation_id": invocation_id,
            "request_sha256": request_sha256,
        },
    ]
    if (has_journal and attempt_records != expected_spend_records) or (
        not has_journal and release.get("test_release") is not True
    ):
        raise ProviderError("comparator spend attempt is not reconciled by the ledger")

    state = {
        "outcome": result.outcome,
        "decision": result.decision,
        "response": result.response,
        "transport": result.transport,
        "provider": provider_payload,
    }
    return _ComparatorResultBinding(
        request_token=request._request_token,
        request_sha256=request_sha256,
        invocation_id=invocation_id,
        repetition=request.repetition,
        order=request.order,
        requested_model=request.model,
        state_sha256=_canonical_evidence_sha256(state),
    )


class EvalProvider(Protocol):
    """Provider contract used by the runner and fake tests."""

    @property
    def name(self) -> str: ...

    @property
    def version(self) -> str: ...

    @property
    def execution_policy(self) -> ProviderExecutionPolicy: ...

    def close(self) -> None: ...

    def run_agent(self, request: AgentRequest) -> ProviderResult: ...

    def run_comparator(self, request: ComparatorRequest) -> ComparatorResult: ...


AgentHandler = Callable[[AgentRequest], str | dict[str, Any]]
ComparatorHandler = Callable[[ComparatorRequest], dict[str, Any]]


@dataclass
class _FakeTransportExecutor:
    provider_name: str
    provider_version: str
    raw_bytes: bytes
    returncode: int
    stderr: bytes
    started: float
    command_executable: str = "fake-claude"

    def execute(
        self,
        _command: tuple[str, ...],
        _timeout_seconds: int,
        _stdin_bytes: bytes,
    ) -> TransportExecution:
        return TransportExecution(
            self.returncode,
            self.raw_bytes,
            self.stderr,
            time.monotonic() - self.started,
            {"kind": "deterministic-fake", "enforced": True},
        )


def _missing_fake_comparator(_request: ComparatorRequest) -> dict[str, Any]:
    raise ProviderError("fake comparator handler is required for judged runs")


class FakeProvider:
    """Deterministic injectable provider for unit and local harness tests."""

    def __init__(
        self,
        *,
        agent_handler: AgentHandler | None = None,
        comparator_handler: ComparatorHandler | None = None,
        version: str = "1",
    ) -> None:
        self._agent_handler = agent_handler or (lambda request: "fake agent output")
        self._comparator_handler = comparator_handler or _missing_fake_comparator
        self._version = version
        self._lock = threading.Lock()
        self.agent_requests: list[AgentRequest] = []
        self.comparator_requests: list[ComparatorRequest] = []

    @property
    def name(self) -> str:
        return "deterministic-fake"

    @property
    def version(self) -> str:
        return self._version

    @property
    def execution_policy(self) -> ProviderExecutionPolicy:
        return CONCURRENT_AUTHORITATIVE

    def close(self) -> None:
        """Release provider resources; deterministic fakes own none."""

    def run_agent(self, request: AgentRequest) -> ProviderResult:
        started = time.monotonic()
        with self._lock:
            self.agent_requests.append(request)
        response = self._agent_handler(request)
        if isinstance(response, str):
            data: dict[str, Any] = {"final_output": response}
        elif isinstance(response, dict):
            data = response
        else:
            raise ProviderError("fake agent handler must return a string or object")
        final_output = data.get("final_output")
        if not isinstance(final_output, str):
            raise ProviderError("fake agent response requires string final_output")
        actual_models = data.get("actual_models", [request.model])
        if (
            not isinstance(actual_models, list)
            or not actual_models
            or not all(isinstance(model, str) and model for model in actual_models)
        ):
            raise ProviderError(
                "fake agent actual_models must be a non-empty string array"
            )
        tokens = _validate_tokens(data.get("tokens", {}), "fake agent tokens")
        cost = _validate_cost(data.get("cost_usd", 0.0), "fake agent cost_usd")
        raw = data.get("raw_response", {"fake": True})
        if not isinstance(raw, dict):
            raise ProviderError("fake agent raw_response must be an object")
        return ProviderResult(
            final_output=final_output,
            requested_model=request.model,
            actual_models=tuple(actual_models),
            provider_name=self.name,
            provider_version=self.version,
            duration_seconds=time.monotonic() - started,
            cost_usd=cost,
            tokens=tokens,
            sandbox={"kind": "fake", "enforced": True},
            raw_response=raw,
        )

    def run_comparator(self, request: ComparatorRequest) -> ComparatorResult:
        started = time.monotonic()
        with self._lock:
            self.comparator_requests.append(request)
        data = self._comparator_handler(request)
        if not isinstance(data, dict):
            raise ProviderError("fake comparator handler must return an object")
        response = data.get("structured_output", data.get("response"))
        if not isinstance(response, dict):
            raise ProviderError("fake comparator response requires structured_output")
        actual_models = data.get("actual_models", [request.model])
        if (
            not isinstance(actual_models, list)
            or not actual_models
            or not all(isinstance(model, str) and model for model in actual_models)
        ):
            raise ProviderError(
                "fake comparator actual_models must be a non-empty string array"
            )
        raw_payload = data.get(
            "raw_payload",
            {
                "is_error": data.get("is_error", False),
                "structured_output": response,
                "modelUsage": {model: {} for model in actual_models},
                "total_cost_usd": data.get("cost_usd", 0.0),
                "usage": data.get("tokens", {}),
            },
        )
        if not isinstance(raw_payload, dict):
            raise ProviderError("fake comparator raw_payload must be an object")
        raw_stdout = data.get("raw_stdout")
        if raw_stdout is None:
            raw_bytes = json.dumps(
                raw_payload,
                ensure_ascii=True,
                sort_keys=True,
                separators=(",", ":"),
            ).encode("ascii")
        elif isinstance(raw_stdout, str):
            raw_bytes = raw_stdout.encode("utf-8")
        elif isinstance(raw_stdout, bytes):
            raw_bytes = raw_stdout
        else:
            raise ProviderError("fake comparator raw_stdout must be bytes or text")

        executor = _FakeTransportExecutor(
            provider_name=self.name,
            provider_version=self.version,
            raw_bytes=raw_bytes,
            returncode=int(data.get("returncode", 0)),
            stderr=str(data.get("stderr", "")).encode("utf-8"),
            started=started,
        )

        try:
            transport = request.runtime.run_transport(
                pair=request.pair,
                repetition=request.repetition,
                order=request.order,
                request_bytes=request.request_bytes,
                requested_model=request.model,
                executor=executor,
                spend_ledger=request.spend_ledger,
            )
        except Exception as exc:
            raise ProviderError("fake comparator transport failed") from exc
        payload = _decode_json_object(transport.raw_response, "raw response")
        provider = ProviderResult(
            final_output=transport.raw_response,
            requested_model=request.model,
            actual_models=transport.actual_models,
            provider_name=self.name,
            provider_version=self.version,
            duration_seconds=transport.duration_seconds,
            cost_usd=transport.cost_usd,
            tokens=_extract_tokens(payload),
            sandbox=transport.executor,
            raw_response=payload,
        )
        return ComparatorResult(
            outcome=transport.decision["outcome"],
            decision=transport.decision,
            response=transport.response,
            transport=transport.as_json(),
            provider=provider,
            request=request,
        )


class ClaudeCliProvider:
    """Non-interactive Claude CLI provider with explicit isolation controls."""

    _TOOL_NAME_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._+-]*$")
    _SYSTEM_PATH = "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"
    _MAX_CREDENTIAL_BYTES = 1024 * 1024
    _MINIMUM_AGENT_SANDBOX_VERSION = (2, 1, 187)
    _SECCOMP_PATH_ENV = "SKIVOLVE_CLAUDE_SECCOMP_APPLY_PATH"

    def __init__(self, config: ProviderConfig) -> None:
        if config.kind != "claude":
            raise ProviderError(f"Claude provider received config kind {config.kind!r}")
        if config.executable is None or config.max_budget_usd is None:
            raise ProviderError("Claude provider requires executable and max budget")
        self._config = config
        self._executable = _resolve_executable(config.executable)
        self._closed = False
        self._agent_seccomp_lock = threading.Lock()
        self._verified_agent_seccomp: VerifiedExecutable | None = None
        self._agent_seccomp_canary: dict[str, Any] | None = None
        try:
            self._verified_executable = VerifiedExecutable(Path(self._executable))
        except (CalibrationError, OSError) as exc:
            raise ProviderError(f"cannot attest Claude CLI executable: {exc}") from exc
        try:
            self._systemd_run = _resolve_executable("systemd-run")
            self._systemctl = _resolve_executable("systemctl")
            self._env_tool = _resolve_executable("env")
            self._unshare = _resolve_executable("unshare")
            self._true = _resolve_executable("true")
            self._version = self._capture_version()
            self._sandbox_version = self._probe_sandbox()
        except BaseException:
            self.close()
            raise

    @property
    def name(self) -> str:
        return "claude-cli"

    @property
    def version(self) -> str:
        return self._version

    @property
    def execution_policy(self) -> ProviderExecutionPolicy:
        return CONCURRENT_AUTHORITATIVE

    @property
    def executable_sha256(self) -> str:
        return self._verified_executable.sha256

    def __enter__(self) -> ClaudeCliProvider:
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
        if self._verified_agent_seccomp is not None:
            self._verified_agent_seccomp.close()
            self._verified_agent_seccomp = None
            self._agent_seccomp_canary = None
        self._verified_executable.close()

    def _ensure_open(self) -> None:
        if self._closed:
            raise ProviderError("Claude provider is closed")

    def _capture_version(self) -> str:
        try:
            completed = subprocess.run(
                [self._verified_executable.descriptor_path, "--version"],
                capture_output=True,
                text=True,
                timeout=15,
                check=False,
                shell=False,
            )
        except (OSError, subprocess.TimeoutExpired) as exc:
            raise ProviderError(f"cannot capture Claude CLI version: {exc}") from exc
        version = completed.stdout.strip() or completed.stderr.strip()
        if completed.returncode != 0 or not version:
            raise ProviderError(
                f"cannot capture Claude CLI version (exit {completed.returncode}): {version}"
            )
        return version.splitlines()[0]

    def _probe_sandbox(self) -> str:
        unit_name = f"skill-eval-probe-{uuid.uuid4().hex}"
        runtime_root = self._runtime_root()
        runtime_mount = self._runtime_mountpoint()
        command = self._sandbox_prefix(
            repository_root=Path.cwd(),
            pair_root=None,
            suite_root=Path.cwd(),
            runtime_root=runtime_root,
            runtime_mount=runtime_mount,
            timeout_seconds=10,
            unit_name=unit_name,
        )
        command.extend(
            [
                f"--working-directory={runtime_mount}",
                "--",
                self._env_tool,
                "-i",
                "PATH=/usr/bin:/bin",
                "HOME=/nonexistent",
                self._unshare,
                "--user",
                "--map-current-user",
                "--pid",
                "--fork",
                "--mount-proc",
                "--kill-child",
                self._true,
            ]
        )
        try:
            completed = subprocess.run(
                command,
                cwd=runtime_root,
                capture_output=True,
                text=True,
                timeout=20,
                check=False,
                shell=False,
                env=_systemd_client_environment(),
            )
        except (OSError, subprocess.TimeoutExpired) as exc:
            raise ProviderError(f"systemd user sandbox probe failed: {exc}") from exc
        finally:
            shutil.rmtree(runtime_root, ignore_errors=True)
        if completed.returncode != 0:
            detail = (completed.stderr or completed.stdout).strip()
            raise ProviderError(f"systemd user sandbox probe failed: {detail}")
        try:
            version = subprocess.run(
                [self._systemd_run, "--version"],
                capture_output=True,
                text=True,
                timeout=10,
                check=False,
                shell=False,
            )
        except (OSError, subprocess.TimeoutExpired) as exc:
            raise ProviderError(
                f"cannot capture systemd sandbox version: {exc}"
            ) from exc
        if version.returncode != 0 or not version.stdout.strip():
            raise ProviderError("cannot capture systemd sandbox version")
        return version.stdout.splitlines()[0]

    def run_agent(self, request: AgentRequest) -> ProviderResult:
        self._ensure_open()
        runtime_root = self._runtime_root(request.sandbox_pair_root)
        try:
            return self._run_agent_in_runtime(request, runtime_root)
        finally:
            shutil.rmtree(runtime_root, ignore_errors=True)

    def _run_agent_in_runtime(
        self, request: AgentRequest, runtime_root: Path
    ) -> ProviderResult:
        if request.model != self._config.model:
            raise ProviderError("agent request model differs from configured model")
        self._require_agent_sandbox_version()
        seccomp = self._agent_seccomp()
        try:
            self._verified_executable.ensure_source_unchanged()
            seccomp.ensure_source_unchanged()
        except (CalibrationError, OSError) as exc:
            raise ProviderError(
                f"Claude agent runtime executable drifted: {exc}"
            ) from exc
        runtime_mount = self._runtime_mountpoint()
        _host_home, _host_bin, _host_executable = self._prepare_runtime(runtime_root)
        runtime_home = runtime_mount / "home"
        runtime_bin = runtime_mount / "bin"
        runtime_executable = runtime_bin / "claude"
        runtime_seccomp = runtime_bin / "apply-seccomp"
        command = self._base_command(
            executable=runtime_executable,
            model=request.model,
            budget=self._config.max_budget_usd,
            permission_mode="acceptEdits",
            tools="Read,Edit,Write,Bash",
        )
        agent_settings = self._agent_settings(runtime_home, runtime_seccomp)
        command.extend(
            [
                "--settings",
                json.dumps(
                    agent_settings,
                    ensure_ascii=True,
                    separators=(",", ":"),
                    sort_keys=True,
                ),
            ]
        )
        runtime_workspace = runtime_root / "work"
        runtime_workspace.mkdir()
        runtime_snapshot = runtime_root / "skill"
        mounted_workspace = runtime_mount / "work"
        mounted_snapshot = runtime_mount / "skill"
        system_context = request.system_context
        if request.skill_snapshot is not None:
            runtime_snapshot.mkdir()
            system_context = system_context.replace(
                str(request.skill_snapshot), str(mounted_snapshot)
            )
            command.extend(["--add-dir", str(mounted_snapshot)])
        command.extend(["--append-system-prompt", system_context])
        wrapped = self._sandbox_prefix(
            repository_root=request.sandbox_repository_root,
            pair_root=request.sandbox_pair_root,
            suite_root=request.sandbox_suite_root,
            runtime_root=runtime_root,
            runtime_mount=runtime_mount,
            timeout_seconds=request.timeout_seconds,
            unit_name=(unit_name := f"skill-eval-agent-{uuid.uuid4().hex}"),
        )
        wrapped.extend(
            [
                "-p",
                "BindReadOnlyPaths="
                f"{self._verified_executable.execution_path}:{runtime_executable}",
                "-p",
                f"BindReadOnlyPaths={seccomp.execution_path}:{runtime_seccomp}",
            ]
        )
        tool_properties, tool_dirs = self._runtime_tool_bindings(
            runtime_root, runtime_mount, request.required_tools
        )
        for property_value in tool_properties:
            wrapped.extend(["-p", property_value])
        wrapped.extend(
            [
                "-p",
                f"BindPaths={request.workspace}:{mounted_workspace}",
            ]
        )
        if request.skill_snapshot is not None:
            wrapped.extend(
                [
                    "-p",
                    f"BindReadOnlyPaths={request.skill_snapshot}:{mounted_snapshot}",
                ]
            )
        wrapped.extend(
            [
                f"--working-directory={mounted_workspace}",
                "--",
                *self._inner_prefix(runtime_home, runtime_bin, tool_dirs),
                *command,
            ]
        )
        sandbox = self._sandbox_evidence(wrapped, agent_settings)
        payload, duration = self._execute(
            wrapped,
            prompt=request.prompt,
            cwd=runtime_root,
            timeout=request.timeout_seconds,
            unit_name=unit_name,
            on_dispatched=request.on_dispatched,
        )
        final_output = payload.get("result")
        if not isinstance(final_output, str):
            raise ProviderError("Claude agent response omitted string result")
        return self._provider_result(
            payload, final_output, request.model, duration, sandbox=sandbox
        )

    def run_comparator(self, request: ComparatorRequest) -> ComparatorResult:
        self._ensure_open()
        try:
            executor = SandboxedClaudeExecutor(
                executable=self._executable,
                repository_root=request.sandbox_repository_root,
                suite_root=request.sandbox_suite_root
                or request.sandbox_repository_root,
                isolation_root=request.sandbox_isolation_root,
                verified_executable=self._verified_executable,
            )
        except Exception as exc:
            raise ProviderError(
                "Claude comparator sandbox initialization failed"
            ) from exc
        return self._run_comparator_with_executor(request, executor)

    def _run_comparator_with_executor(
        self, request: ComparatorRequest, executor: SandboxedClaudeExecutor
    ) -> ComparatorResult:
        if request.model != self._config.model:
            raise ProviderError(
                "comparator request model differs from configured model"
            )
        budget = request.max_budget_usd
        if budget is None:
            raise ProviderError("Claude comparator requires a positive max budget")
        limits = request.runtime.bundle.release["execution_limits"]
        if (
            request.timeout_seconds != limits["timeout_seconds"]
            or budget != limits["per_invocation_max_usd"]
        ):
            raise ProviderError(
                "comparator timeout or per-call budget differs from release"
            )
        try:
            transport = request.runtime.run_transport(
                pair=request.pair,
                repetition=request.repetition,
                order=request.order,
                request_bytes=request.request_bytes,
                requested_model=request.model,
                executor=executor,
                spend_ledger=request.spend_ledger,
            )
        except Exception as exc:
            raise ProviderError("Claude comparator transport failed") from exc
        payload = _decode_json_object(transport.raw_response, "raw response")
        tokens = _extract_tokens(payload)
        if not tokens:
            raise ProviderError("Claude comparator response omitted token usage")
        provider = ProviderResult(
            final_output=transport.raw_response,
            requested_model=request.model,
            actual_models=transport.actual_models,
            provider_name=self.name,
            provider_version=self.version,
            duration_seconds=transport.duration_seconds,
            cost_usd=transport.cost_usd,
            tokens=tokens,
            sandbox=transport.executor,
            raw_response=payload,
        )
        return ComparatorResult(
            outcome=transport.decision["outcome"],
            decision=transport.decision,
            response=transport.response,
            transport=transport.as_json(),
            provider=provider,
            request=request,
        )

    def _base_command(
        self,
        *,
        executable: Path,
        model: str,
        budget: float,
        permission_mode: str,
        tools: str,
    ) -> list[str]:
        command = [
            str(executable),
            "--print",
            "--output-format",
            "json",
            "--model",
            model,
            "--max-budget-usd",
            format(budget, ".12g"),
            "--no-session-persistence",
            "--safe-mode",
            "--setting-sources",
            "",
            "--disable-slash-commands",
            "--strict-mcp-config",
            "--permission-mode",
            permission_mode,
            "--tools",
            tools,
        ]
        if tools:
            command.extend(["--allowed-tools", tools])
        return command

    def _require_agent_sandbox_version(self) -> None:
        match = re.fullmatch(
            r"(\d+)\.(\d+)\.(\d+)(?: \(Claude Code\))?",
            self._version.strip(),
        )
        if match is None:
            raise ProviderError(
                "cannot verify Claude CLI support for agent credential isolation"
            )
        observed = tuple(int(part) for part in match.groups())
        if observed < self._MINIMUM_AGENT_SANDBOX_VERSION:
            required = ".".join(
                str(part) for part in self._MINIMUM_AGENT_SANDBOX_VERSION
            )
            raise ProviderError(
                f"Claude CLI {required} or newer is required for agent credential "
                "isolation"
            )

    def _agent_seccomp(self) -> VerifiedExecutable:
        with self._agent_seccomp_lock:
            if self._verified_agent_seccomp is not None:
                self._verified_agent_seccomp.ensure_source_unchanged()
                return self._verified_agent_seccomp
            path = _resolve_agent_seccomp_executable(
                self._executable,
                environment_variable=self._SECCOMP_PATH_ENV,
            )
            try:
                verified = VerifiedExecutable(path)
            except (CalibrationError, OSError) as exc:
                raise ProviderError(
                    f"cannot attest Claude Unix-socket seccomp helper: {exc}"
                ) from exc
            try:
                canary = self._probe_agent_seccomp(verified)
            except BaseException:
                verified.close()
                raise
            self._verified_agent_seccomp = verified
            self._agent_seccomp_canary = canary
            return self._verified_agent_seccomp

    @staticmethod
    def _probe_agent_seccomp(verified: VerifiedExecutable) -> dict[str, Any]:
        source = (
            "import errno,socket\n"
            "try:\n"
            " socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)\n"
            "except OSError as error:\n"
            " if error.errno != errno.EPERM: raise\n"
            " print('af-unix-blocked')\n"
            "else:\n"
            " raise SystemExit(3)\n"
        )
        try:
            result = execute_bounded_transport(
                [verified.descriptor_path, sys.executable, "-c", source],
                cwd=Path.cwd(),
                stdin_bytes=b"",
                timeout_seconds=10,
                stdout_limit=4096,
                stderr_limit=4096,
                terminate=lambda: None,
                evidence={"kind": "seccomp-canary"},
                process_label="Claude Unix-socket seccomp canary",
            )
        except (CalibrationError, OSError) as exc:
            raise ProviderError(f"Claude seccomp canary failed: {exc}") from exc
        if result.returncode != 0 or result.stdout.strip() != b"af-unix-blocked":
            raise ProviderError(
                "Claude seccomp canary did not deny AF_UNIX socket creation"
            )
        return {
            "af_unix_socket_creation_denied": True,
            "stdout_sha256": hashlib.sha256(result.stdout).hexdigest(),
        }

    def authority_runtime_provenance(self, role: str) -> dict[str, Any]:
        if role == "generation":
            seccomp = self._agent_seccomp()
            return {
                "agent_sandbox_minimum_version": ".".join(
                    str(part) for part in self._MINIMUM_AGENT_SANDBOX_VERSION
                ),
                "sandbox_kind": capabilities_for("claude-cli").sandbox_kind,
                "seccomp_apply_sha256": seccomp.sha256,
                "seccomp_canary": copy.deepcopy(self._agent_seccomp_canary),
                "systemd_version": self._sandbox_version,
                "unix_socket_policy": "deny-new-af-unix-sockets",
            }
        if role == "comparison":
            return {
                "sandbox_kind": "shared-systemd-claude-executor",
                "systemd_version": self._sandbox_version,
            }
        raise ProviderError(f"unsupported Claude provider role: {role}")

    @staticmethod
    def _agent_settings(runtime_home: Path, runtime_seccomp: Path) -> dict[str, Any]:
        credential = runtime_home / ".claude" / ".credentials.json"
        return {
            "permissions": {
                "deny": [
                    f"Read(/{credential})",
                    f"Edit(/{credential})",
                ],
            },
            "sandbox": {
                "allowUnsandboxedCommands": False,
                "credentials": {
                    "files": [
                        {
                            "mode": "deny",
                            "path": str(credential),
                        }
                    ]
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
                "seccomp": {"applyPath": str(runtime_seccomp)},
            },
        }

    def _runtime_root(self, parent: Path | None = None) -> Path:
        runtime_parent = (
            parent.resolve() if parent is not None else Path(f"/run/user/{os.getuid()}")
        )
        if not runtime_parent.is_dir():
            raise ProviderError(
                f"systemd runtime directory is missing: {runtime_parent}"
            )
        runtime_root = runtime_parent / f"runtime-{uuid.uuid4().hex}"
        runtime_root.mkdir(mode=0o700)
        return runtime_root

    def _runtime_mountpoint(self) -> Path:
        mountpoint = Path(f"/run/user/{os.getuid()}/skill-eval-runtime")
        mountpoint.mkdir(mode=0o700, exist_ok=True)
        if mountpoint.is_symlink() or not mountpoint.is_dir():
            raise ProviderError(f"unsafe runtime mountpoint: {mountpoint}")
        mountpoint.chmod(0o700)
        return mountpoint

    def _prepare_runtime(self, runtime_root: Path) -> tuple[Path, Path, Path]:
        runtime_home = runtime_root / "home"
        runtime_config = runtime_home / ".claude"
        runtime_bin = runtime_root / "bin"
        for directory in (runtime_home, runtime_config, runtime_bin):
            directory.mkdir(mode=0o700)
        credential = self._credential_source()
        if credential.stat().st_size > self._MAX_CREDENTIAL_BYTES:
            raise ProviderError("Claude OAuth credential exceeds the size limit")
        runtime_credential = runtime_config / ".credentials.json"
        shutil.copyfile(credential, runtime_credential, follow_symlinks=False)
        runtime_credential.chmod(0o600)
        runtime_executable = runtime_bin / "claude"
        runtime_executable.touch(mode=0o700)
        runtime_seccomp = runtime_bin / "apply-seccomp"
        runtime_seccomp.touch(mode=0o700)
        return runtime_home, runtime_bin, runtime_executable

    def _credential_source(self) -> Path:
        config_root = _claude_config_root()
        logical_credential = config_root / ".credentials.json"
        credential = logical_credential.resolve()
        if (
            logical_credential.is_symlink()
            or not credential.is_file()
            or not credential.is_relative_to(config_root)
        ):
            raise ProviderError(
                "Claude OAuth credential must be a regular .credentials.json file"
            )
        return credential

    def _runtime_tool_bindings(
        self,
        runtime_root: Path,
        runtime_mount: Path,
        tools: tuple[tuple[str, str], ...],
    ) -> tuple[list[str], tuple[str, ...]]:
        runtime_bin = runtime_root / "bin"
        properties: list[str] = []
        path_dirs: list[str] = []
        sensitive_roots = _sensitive_host_roots()
        seen: set[str] = set()
        for name, raw_path in tools:
            if self._TOOL_NAME_RE.fullmatch(name) is None or name in seen:
                raise ProviderError(
                    f"invalid or duplicate required tool name: {name!r}"
                )
            seen.add(name)
            executable = Path(raw_path).resolve()
            if not executable.is_file() or not os.access(executable, os.X_OK):
                raise ProviderError(
                    f"required tool is not executable: {name}={raw_path}"
                )
            if any(executable.is_relative_to(root) for root in sensitive_roots):
                target = runtime_bin / name
                target.touch(mode=0o700)
                mounted_target = runtime_mount / "bin" / name
                properties.append(f"BindReadOnlyPaths={executable}:{mounted_target}")
            else:
                path_dirs.append(str(executable.parent))
        return properties, tuple(dict.fromkeys(path_dirs))

    def _inner_prefix(
        self,
        runtime_home: Path,
        runtime_bin: Path,
        tool_dirs: tuple[str, ...],
    ) -> list[str]:
        path = ":".join((str(runtime_bin), *tool_dirs, self._SYSTEM_PATH))
        return [
            self._env_tool,
            "-i",
            f"HOME={runtime_home}",
            f"CLAUDE_CONFIG_DIR={runtime_home / '.claude'}",
            f"XDG_CONFIG_HOME={runtime_home / '.config'}",
            f"XDG_CACHE_HOME={runtime_home / '.cache'}",
            f"PATH={path}",
            "LANG=C.UTF-8",
            "LC_ALL=C.UTF-8",
            "USER=skill-eval",
            "LOGNAME=skill-eval",
            "SHELL=/bin/bash",
            "TERM=dumb",
            "CI=1",
            "PYTHONDONTWRITEBYTECODE=1",
            "CLAUDE_CODE_SUBPROCESS_ENV_SCRUB=1",
            self._unshare,
            "--user",
            "--map-current-user",
            "--pid",
            "--fork",
            "--mount-proc",
            "--kill-child",
        ]

    def _sandbox_prefix(
        self,
        *,
        repository_root: Path,
        pair_root: Path | None,
        suite_root: Path | None,
        runtime_root: Path,
        runtime_mount: Path,
        timeout_seconds: int,
        unit_name: str,
    ) -> list[str]:
        command = [
            self._systemd_run,
            "--user",
            "--pipe",
            "--wait",
            "--collect",
            f"--unit={unit_name}",
        ]
        for isolation_property in SANDBOX_ISOLATION_PROPERTIES:
            command.extend(["-p", isolation_property])
        for resource_property in (
            "MemoryMax=4G",
            "TasksMax=512",
            "LimitNOFILE=4096",
            "LimitFSIZE=512M",
            f"RuntimeMaxSec={timeout_seconds}s",
            "KillMode=control-group",
            "UMask=0077",
            f"ReadWritePaths={runtime_mount}",
        ):
            command.extend(["-p", resource_property])
        inaccessible = [
            repository_root.resolve(),
            *_sensitive_host_roots(),
        ]
        if pair_root is not None:
            inaccessible.append(pair_root.resolve())
        if suite_root is not None:
            inaccessible.append(suite_root.resolve())
        for path in dict.fromkeys(inaccessible):
            command.extend(["-p", f"InaccessiblePaths={path}"])
        command.extend(["-p", f"BindPaths={runtime_root}:{runtime_mount}"])
        return command

    def _sandbox_evidence(
        self, command: list[str], agent_settings: dict[str, Any]
    ) -> dict[str, Any]:
        properties = [
            value
            for index, value in enumerate(command)
            if index > 0 and command[index - 1] == "-p"
        ]
        return {
            "kind": capabilities_for("claude-cli").sandbox_kind,
            "enforced": True,
            "executable": self._systemd_run,
            "claude_executable_path": self._executable,
            "claude_executable_identity": self._verified_executable.identity,
            "claude_executable_sha256": self._verified_executable.sha256,
            "claude_execution_source": "descriptor-verified-private-copy",
            "version": self._sandbox_version,
            "properties": properties,
            "environment_mode": "env-i-allowlist",
            "process_namespace": "unshare-user-pid-private-proc",
            "credential_scope": "controller-auth-denied-to-model-tools",
            "agent_tool_sandbox": {
                "credential_files_denied": True,
                "fail_if_unavailable": True,
                "network_domains_denied": True,
                "seccomp_apply_sha256": self._agent_seccomp().sha256,
                "seccomp_canary": copy.deepcopy(self._agent_seccomp_canary),
                "unsandboxed_commands_allowed": False,
                "unix_socket_creation_denied": True,
            },
            "agent_settings_sha256": hashlib.sha256(
                json.dumps(
                    agent_settings,
                    ensure_ascii=True,
                    separators=(",", ":"),
                    sort_keys=True,
                ).encode("ascii")
            ).hexdigest(),
        }

    def _execute(
        self,
        command: list[str],
        *,
        prompt: str,
        cwd: Path,
        timeout: int,
        unit_name: str,
        on_dispatched: Callable[[], None] | None,
    ) -> tuple[dict[str, Any], float]:
        try:
            completed = execute_bounded_transport(
                command,
                cwd=cwd,
                stdin_bytes=prompt.encode("utf-8"),
                timeout_seconds=timeout,
                stdout_limit=MAX_RESPONSE_BYTES,
                stderr_limit=MAX_STDERR_BYTES,
                terminate=lambda: self._terminate_unit(unit_name),
                evidence={},
                process_label="Claude CLI",
                on_started=on_dispatched,
            )
        except TransportOverflowError as exc:
            raise ProviderError(str(exc)) from exc
        except CalibrationError as exc:
            raise ProviderError(str(exc)) from exc
        if completed.returncode != 0:
            detail = (
                (completed.stderr or completed.stdout)
                .decode("utf-8", errors="replace")
                .strip()
            )
            raise ProviderError(f"Claude CLI exited {completed.returncode}: {detail}")
        try:
            response = completed.stdout.decode("utf-8")
            payload = json.loads(response)
        except UnicodeDecodeError as exc:
            raise ProviderError("Claude CLI response is not valid UTF-8") from exc
        except json.JSONDecodeError as exc:
            raise ProviderError(f"Claude CLI returned invalid JSON: {exc}") from exc
        if not isinstance(payload, dict):
            raise ProviderError("Claude CLI JSON response must be an object")
        if payload.get("is_error") is True:
            raise ProviderError(
                f"Claude CLI reported an error: {payload.get('result', 'unknown')}"
            )
        return payload, completed.duration_seconds

    def _terminate_unit(self, unit_name: str) -> None:
        try:
            subprocess.run(
                [self._systemctl, "--user", "stop", unit_name],
                capture_output=True,
                text=True,
                timeout=15,
                check=False,
                shell=False,
            )
        except (OSError, subprocess.TimeoutExpired):
            pass

    def _provider_result(
        self,
        payload: dict[str, Any],
        final_output: str,
        requested_model: str,
        duration: float,
        *,
        sandbox: dict[str, Any],
    ) -> ProviderResult:
        actual_models = _extract_models(payload)
        if not actual_models:
            raise ProviderError("Claude CLI response did not identify the model used")
        if requested_model not in actual_models:
            raise ProviderError(
                "Claude CLI response did not include the pinned requested model: "
                f"requested {requested_model}, observed {', '.join(actual_models)}"
            )
        if "total_cost_usd" not in payload:
            raise ProviderError("Claude CLI response omitted total_cost_usd")
        cost = _validate_cost(payload["total_cost_usd"], "total_cost_usd")
        if cost > self._config.max_budget_usd:
            raise ProviderError(
                "Claude CLI reported cost above the configured per-call budget"
            )
        tokens = _extract_tokens(payload)
        if not tokens:
            raise ProviderError("Claude CLI response omitted token usage")
        return ProviderResult(
            final_output=final_output,
            requested_model=requested_model,
            actual_models=actual_models,
            provider_name=self.name,
            provider_version=self.version,
            duration_seconds=duration,
            cost_usd=cost,
            tokens=tokens,
            sandbox=sandbox,
            raw_response=payload,
        )


def _claude_config_root() -> Path:
    configured = os.environ.get("CLAUDE_CONFIG_DIR")
    candidate = Path(configured).expanduser() if configured else Path.home() / ".claude"
    try:
        return candidate.resolve(strict=True)
    except OSError as exc:
        raise ProviderError(f"Claude config directory is unavailable: {exc}") from exc


def _sensitive_host_roots() -> tuple[Path, ...]:
    home = Path.home().resolve()
    config_root = _claude_config_root()
    roots = [home, config_root]
    if (
        config_root.name == ".claude"
        and not config_root.is_relative_to(home)
        and config_root.parent != config_root.parent.parent
    ):
        roots.append(config_root.parent)
    configured = os.environ.get("XDG_CONFIG_HOME")
    if configured:
        candidate = Path(configured).expanduser()
        if candidate.exists():
            roots.append(candidate.resolve())
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


def _resolve_executable(value: str) -> str:
    candidate = Path(value)
    if candidate.parent != Path("."):
        resolved = candidate.expanduser().resolve()
        if not resolved.is_file() or not os.access(resolved, os.X_OK):
            raise ProviderError(
                f"provider executable is missing or not executable: {value}"
            )
        return str(resolved)
    resolved = shutil.which(value)
    if resolved is None:
        raise ProviderError(f"provider executable is not on PATH: {value}")
    return str(Path(resolved).resolve())


def _resolve_agent_seccomp_executable(
    claude_executable: str, *, environment_variable: str
) -> Path:
    explicit = os.environ.get(environment_variable)
    if explicit is not None:
        if not explicit or "\0" in explicit:
            raise ProviderError(f"{environment_variable} is invalid")
        candidates = (Path(explicit).expanduser(),)
    else:
        architecture = {
            "aarch64": "arm64",
            "arm64": "arm64",
            "x86_64": "x64",
            "x64": "x64",
        }.get(platform.machine().lower())
        if architecture is None:
            raise ProviderError(
                "Claude Unix-socket seccomp helper does not support this architecture"
            )
        package_suffix = (
            Path("@anthropic-ai/sandbox-runtime/vendor/seccomp")
            / architecture
            / "apply-seccomp"
        )
        home = Path.home()
        executable_prefix = Path(claude_executable).resolve().parent.parent
        candidates = (
            Path(claude_executable).resolve().with_name("apply-seccomp"),
            executable_prefix / "lib/node_modules" / package_suffix,
            Path("/usr/lib/node_modules") / package_suffix,
            Path("/usr/local/lib/node_modules") / package_suffix,
            Path("/opt/homebrew/lib/node_modules") / package_suffix,
            home / ".npm/lib/node_modules" / package_suffix,
            home / ".npm-global/lib/node_modules" / package_suffix,
        )
    for candidate in candidates:
        try:
            resolved = candidate.resolve(strict=True)
        except OSError:
            continue
        if resolved.is_file() and os.access(resolved, os.X_OK):
            return resolved
    raise ProviderError(
        "Claude generation requires the executable @anthropic-ai/sandbox-runtime "
        "apply-seccomp helper; install it globally or set "
        f"{environment_variable}"
    )


def _extract_models(payload: dict[str, Any]) -> tuple[str, ...]:
    models: set[str] = set()
    usage = payload.get("modelUsage")
    if isinstance(usage, dict):
        models.update(model for model in usage if isinstance(model, str) and model)
    model = payload.get("model")
    if isinstance(model, str) and model:
        models.add(model)
    return tuple(sorted(models))


def _extract_tokens(payload: dict[str, Any]) -> dict[str, int]:
    totals: dict[str, int] = {}
    usage = payload.get("usage")
    if isinstance(usage, dict):
        for key, value in usage.items():
            if isinstance(value, int) and not isinstance(value, bool) and value < 0:
                raise ProviderError(f"usage.{key} must be non-negative")
            if isinstance(value, int) and not isinstance(value, bool):
                totals[key] = value
    model_usage = payload.get("modelUsage")
    if isinstance(model_usage, dict):
        per_model_totals: dict[str, int] = {}
        for model_data in model_usage.values():
            if not isinstance(model_data, dict):
                continue
            for key, value in model_data.items():
                if (
                    not key.endswith("Tokens")
                    or not isinstance(value, int)
                    or isinstance(value, bool)
                ):
                    continue
                if value < 0:
                    raise ProviderError(f"modelUsage.{key} must be non-negative")
                normalized = _camel_to_snake(key)
                per_model_totals[normalized] = (
                    per_model_totals.get(normalized, 0) + value
                )
        for key, value in per_model_totals.items():
            totals.setdefault(key, value)
    return totals


def _camel_to_snake(value: str) -> str:
    result: list[str] = []
    for character in value:
        if character.isupper() and result:
            result.append("_")
        result.append(character.lower())
    return "".join(result)


def _validate_tokens(value: Any, location: str) -> dict[str, int]:
    if not isinstance(value, dict):
        raise ProviderError(f"{location} must be an object")
    result: dict[str, int] = {}
    for key, token_count in value.items():
        if (
            not isinstance(key, str)
            or isinstance(token_count, bool)
            or not isinstance(token_count, int)
            or token_count < 0
        ):
            raise ProviderError(f"{location} must map strings to non-negative integers")
        result[key] = token_count
    return result


def _validate_json_object(value: Any, location: str) -> None:
    if not isinstance(value, dict):
        raise ProviderError(f"{location} must be an object")

    def validate(item: Any, path: str) -> None:
        if item is None or isinstance(item, (str, bool)):
            return
        if isinstance(item, int):
            return
        if isinstance(item, float):
            if math.isfinite(item):
                return
            raise ProviderError(f"{path} must be finite")
        if isinstance(item, list):
            for index, child in enumerate(item):
                validate(child, f"{path}[{index}]")
            return
        if isinstance(item, dict):
            for key, child in item.items():
                if not isinstance(key, str):
                    raise ProviderError(f"{path} keys must be strings")
                validate(child, f"{path}.{key}")
            return
        raise ProviderError(f"{path} is not JSON-compatible")

    validate(value, location)


def _validate_cost(value: Any, location: str) -> float:
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        raise ProviderError(f"{location} must be a non-negative number")
    result = float(value)
    if result < 0 or result != result or result in {float("inf"), float("-inf")}:
        raise ProviderError(f"{location} must be a finite non-negative number")
    return result
