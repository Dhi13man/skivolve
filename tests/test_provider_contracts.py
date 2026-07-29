from __future__ import annotations

import copy
import hashlib
import json
import stat
import sys
import tempfile
import unittest
from dataclasses import FrozenInstanceError, replace
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

from jsonschema import Draft202012Validator

from skivolve.comparator_runtime import (
    CalibrationError,
    SpendLedger,
    canonical_sha256,
)


HARNESS_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(HARNESS_ROOT))

from skivolve.holdout_plan import HoldoutPlanError, load_holdout_plan  # noqa: E402
from skivolve.manifest import ManifestError, load_suite  # noqa: E402
from skivolve.provider_capabilities import (  # noqa: E402
    ProviderCapabilityError,
    capabilities_for,
    reviewed_capabilities,
)
from skivolve.providers import (  # noqa: E402
    ComparatorRequest,
    ComparatorResult,
    FakeProvider,
    ProviderError,
    ProviderExecutionPolicy,
    ProviderResult,
    execution_policy_for,
)


class ProviderResultContractTests(unittest.TestCase):
    def result(self, **changes: object) -> ProviderResult:
        values: dict[str, object] = {
            "final_output": "done",
            "requested_model": "model",
            "actual_models": ("model",),
            "provider_name": "provider",
            "provider_version": "1",
            "duration_seconds": 0.1,
            "cost_usd": 0.25,
            "tokens": {"input_tokens": 1},
            "sandbox": {"enforced": True, "kind": "fake"},
            "raw_response": {"result": "done"},
        }
        values.update(changes)
        return ProviderResult(**values)  # type: ignore[arg-type]

    def test_existing_metered_result_keeps_cost_and_adds_explicit_provenance(
        self,
    ) -> None:
        payload = self.result().as_json()

        self.assertEqual(payload["cost_usd"], 0.25)
        self.assertEqual(payload["billing_basis"], "metered_api")
        self.assertIsNone(payload["quota"])
        self.assertIsNone(payload["protocol_provenance"])

    def test_subscription_result_requires_unknown_dollar_cost(self) -> None:
        result = self.result(
            cost_usd=None,
            billing_basis="chatgpt_subscription",
            quota={"remaining_percent": 80},
            protocol_provenance={"lock_sha256": "a" * 64},
        )
        self.assertIsNone(result.as_json()["cost_usd"])

        with self.assertRaisesRegex(ProviderError, "must report cost_usd as null"):
            self.result(cost_usd=0.0, billing_basis="chatgpt_subscription")
        with self.assertRaisesRegex(ProviderError, "requires cost_usd"):
            self.result(cost_usd=None)
        with self.assertRaisesRegex(ProviderError, "requires quota"):
            self.result(cost_usd=None, billing_basis="chatgpt_subscription")

    def test_result_rejects_malformed_runtime_and_json_evidence(self) -> None:
        mutations: tuple[dict[str, object], ...] = (
            {"final_output": 1},
            {"requested_model": ""},
            {"actual_models": ()},
            {"actual_models": ("model", "model")},
            {"provider_name": ""},
            {"provider_version": ""},
            {"duration_seconds": True},
            {"duration_seconds": -0.1},
            {"duration_seconds": float("nan")},
            {"duration_seconds": float("inf")},
            {"billing_basis": []},
            {"tokens": {"input_tokens": -1}},
            {"tokens": {"input_tokens": True}},
            {"tokens": {1: 1}},
            {"sandbox": {"enforced": False, "kind": "fake"}},
            {"sandbox": {"enforced": True, "kind": ""}},
            {"sandbox": {"enforced": True, "kind": "fake", "bad": float("nan")}},
            {"raw_response": []},
            {"raw_response": {"bad": float("nan")}},
            {"quota": {"bad": object()}},
            {"protocol_provenance": {"bad": object()}},
        )
        for mutation in mutations:
            with self.subTest(mutation=mutation):
                with self.assertRaises(ProviderError):
                    self.result(**mutation)

    def test_result_allows_provider_resolved_model_alias(self) -> None:
        result = self.result(actual_models=("resolved-model-version",))

        self.assertEqual(result.actual_models, ("resolved-model-version",))

    def test_as_json_revalidates_mutable_nested_evidence(self) -> None:
        result = self.result()
        result.tokens["input_tokens"] = -1
        with self.assertRaisesRegex(ProviderError, "non-negative"):
            result.as_json()

    def test_execution_policy_when_adapter_is_reviewed_is_exact_immutable_and_visible(
        self,
    ) -> None:
        # Arrange
        concurrent = execution_policy_for("claude-cli")

        # Act
        fake_policy = execution_policy_for("deterministic-fake")
        codex_policy = execution_policy_for("codex-app-server")

        # Assert
        self.assertIs(concurrent, fake_policy)
        self.assertEqual(
            concurrent.as_json(),
            {"concurrency": "concurrent", "release_authoritative": True},
        )
        self.assertEqual(FakeProvider().execution_policy, concurrent)
        self.assertEqual(
            codex_policy.as_json(),
            {"concurrency": "serialized", "release_authoritative": False},
        )
        for legacy_kind in ("claude", "codex", "fake"):
            with self.subTest(legacy_kind=legacy_kind):
                with self.assertRaisesRegex(ProviderError, "unknown reviewed"):
                    execution_policy_for(legacy_kind)
        with self.assertRaises(FrozenInstanceError):
            concurrent.concurrency = "serialized"  # type: ignore[misc]
        with self.assertRaisesRegex(ValueError, "unsupported"):
            ProviderExecutionPolicy("concurrent", False)
        with self.assertRaisesRegex(ValueError, "unsupported"):
            ProviderExecutionPolicy("concurrent", 1)  # type: ignore[arg-type]

    def test_reviewed_capabilities_when_registry_is_loaded_are_canonical_and_role_closed(
        self,
    ) -> None:
        # Arrange
        registry = reviewed_capabilities()

        # Act
        capability_hashes = {capabilities.sha256 for capabilities in registry.values()}

        # Assert
        self.assertEqual(
            set(registry),
            {"claude-cli", "codex-app-server", "deterministic-fake"},
        )
        self.assertEqual(len(capability_hashes), 3)
        for adapter_id, capabilities in registry.items():
            with self.subTest(adapter_id=adapter_id):
                self.assertEqual(capabilities.adapter_id, adapter_id)
                self.assertEqual(
                    capabilities.as_json()["provider_kind"],
                    capabilities.provider_kind,
                )
                self.assertNotIn("legacy_kind", capabilities.as_json())
                self.assertEqual(
                    capabilities.sha256, canonical_sha256(capabilities.as_json())
                )
                self.assertEqual(
                    capabilities.artifact_outputs,
                    ("final_output_json", "final_output_text", "workspace_diff"),
                )
                self.assertEqual(capabilities.contract_revision, 1)
        self.assertEqual(
            capabilities_for("claude-cli", role="comparison").authority_scope,
            "production",
        )
        self.assertEqual(capabilities_for("deterministic-fake").authority_scope, "test")
        with self.assertRaisesRegex(ProviderCapabilityError, "comparison role"):
            capabilities_for("codex-app-server", role="comparison")
        with self.assertRaisesRegex(ProviderCapabilityError, "unknown reviewed"):
            capabilities_for("suite-claimed-production")
        with self.assertRaises(TypeError):
            registry["forged"] = registry["claude-cli"]  # type: ignore[index]


class ComparatorResultContractTests(unittest.TestCase):
    def fixture(self) -> dict[str, object]:
        repository_root = Path.cwd()
        suite_root = repository_root / "suite"
        isolation_root = repository_root / "isolation"
        invocation_id = "1" * 64
        request_bytes = json.dumps(
            {"user_payload": {"invocation_id": invocation_id}},
            ensure_ascii=True,
            separators=(",", ":"),
            sort_keys=True,
        ).encode("ascii")
        response = {"locked": True}
        decision = {
            "checks": {},
            "criteria": None,
            "eligibility": {"A": "eligible", "B": "eligible"},
            "outcome": "A",
            "unsupported_performance": False,
            "unsupported_qualitative": [],
            "violations": {"A": [], "B": []},
        }
        model = "fake-sonnet-v2"
        raw_payload = {
            "is_error": False,
            "modelUsage": {model: {}},
            "structured_output": response,
            "total_cost_usd": 0.25,
            "usage": {"input_tokens": 3},
        }
        raw_response = json.dumps(
            raw_payload,
            ensure_ascii=True,
            separators=(",", ":"),
            sort_keys=True,
        )
        executor = {
            "command_executable": "/runtime/bin/claude",
            "enforced": True,
            "executable_sha256": "5" * 64,
            "kind": "shared-systemd-claude-executor",
            "properties": [
                f"InaccessiblePaths={repository_root}",
                f"InaccessiblePaths={suite_root}",
                f"InaccessiblePaths={isolation_root}",
            ],
        }
        hashes = {
            "request_sha256": hashlib.sha256(request_bytes).hexdigest(),
            "stdin_sha256": "2" * 64,
            "command_sha256": "3" * 64,
        }
        runtime = SimpleNamespace(
            bundle=SimpleNamespace(
                release={
                    "criterion_support": {},
                    "execution_limits": {
                        "per_invocation_max_usd": 1.0,
                        "run_max_usd": 1.0,
                        "timeout_seconds": 30,
                    },
                    "judge": {
                        "provider": "claude-cli",
                        "provider_version": "1",
                        "requested_model": model,
                    },
                    "test_release": True,
                }
            ),
            invocation_id=lambda _pair_id, _repetition, _order: invocation_id,
            request_bytes=lambda _pair, _repetition, _order: request_bytes,
        )
        request = ComparatorRequest(
            pair={"id": "opaque-pair"},
            repetition=2,
            order="AB",
            request_bytes=request_bytes,
            runtime=runtime,
            spend_ledger=SpendLedger(1.0),
            model=model,
            timeout_seconds=30,
            max_budget_usd=1.0,
            sandbox_repository_root=repository_root,
            sandbox_suite_root=suite_root,
            sandbox_isolation_root=isolation_root,
        )
        provider = ProviderResult(
            final_output=raw_response,
            requested_model=model,
            actual_models=(model,),
            provider_name="claude-cli",
            provider_version="1",
            duration_seconds=0.1,
            cost_usd=0.25,
            tokens={"input_tokens": 3},
            sandbox=executor,
            raw_response=raw_payload,
        )
        transport = {
            "actual_models": [model],
            "command_sha256": hashes["command_sha256"],
            "cost_usd": 0.25,
            "decision": decision,
            "duration_seconds": 0.1,
            "executor": executor,
            "parsed_response_sha256": canonical_sha256(response),
            "provider_name": "claude-cli",
            "provider_version": "1",
            "raw_response": raw_response,
            "raw_response_sha256": hashlib.sha256(raw_response.encode()).hexdigest(),
            "request_sha256": hashes["request_sha256"],
            "requested_model": model,
            "response": response,
            "spend_attempt_id": "4" * 32,
            "stdin_sha256": hashes["stdin_sha256"],
        }
        return {
            "decision": decision,
            "expected_hashes": hashes,
            "outcome": "A",
            "provider": provider,
            "request": request,
            "response": response,
            "transport": transport,
        }

    def result(self, fixture: dict[str, object] | None = None) -> ComparatorResult:
        values = self.fixture() if fixture is None else fixture
        with (
            patch(
                "skivolve.providers.validate_response",
                return_value=copy.deepcopy(values["decision"]),
            ),
            patch(
                "skivolve.providers.expected_transport_hashes",
                return_value=copy.deepcopy(values["expected_hashes"]),
            ),
            patch("skivolve.providers.validate_executor_evidence"),
        ):
            return ComparatorResult(
                outcome=values["outcome"],  # type: ignore[arg-type]
                decision=values["decision"],  # type: ignore[arg-type]
                response=values["response"],  # type: ignore[arg-type]
                transport=values["transport"],  # type: ignore[arg-type]
                provider=values["provider"],  # type: ignore[arg-type]
                request=values["request"],  # type: ignore[arg-type]
            )

    def serialize(
        self, result: ComparatorResult, fixture: dict[str, object]
    ) -> dict[str, object]:
        with (
            patch(
                "skivolve.providers.validate_response",
                return_value=copy.deepcopy(result.decision),
            ),
            patch(
                "skivolve.providers.expected_transport_hashes",
                return_value={
                    key: result.transport[key]
                    for key in (
                        "command_sha256",
                        "request_sha256",
                        "stdin_sha256",
                    )
                },
            ),
            patch("skivolve.providers.validate_executor_evidence"),
        ):
            return result.as_json(fixture["request"])  # type: ignore[arg-type,return-value]

    def fake_fixture(self) -> dict[str, object]:
        fixture = self.fixture()
        executor = {"enforced": True, "kind": "deterministic-fake"}
        fixture["provider"] = replace(
            fixture["provider"],  # type: ignore[arg-type]
            provider_name="deterministic-fake",
            sandbox=executor,
        )
        request = fixture["request"]
        request.runtime.bundle.release["judge"]["provider"] = "deterministic-fake"  # type: ignore[union-attr]
        fixture["transport"]["provider_name"] = "deterministic-fake"  # type: ignore[index]
        fixture["transport"]["executor"] = executor  # type: ignore[index]
        return fixture

    def test_valid_evidence_is_deep_copied_revalidated_and_serializable(self) -> None:
        fixture = self.fixture()
        result = self.result(fixture)
        fixture["decision"]["outcome"] = "B"  # type: ignore[index]
        fixture["transport"]["request_sha256"] = "f" * 64  # type: ignore[index]
        fixture["provider"].tokens["input_tokens"] = 99  # type: ignore[union-attr]

        payload = self.serialize(result, fixture)

        self.assertEqual(payload["outcome"], "A")
        self.assertEqual(payload["decision"]["outcome"], "A")
        self.assertEqual(payload["provider"]["tokens"], {"input_tokens": 3})
        encoded = json.dumps(payload, allow_nan=False, sort_keys=True)
        self.assertEqual(
            json.loads(encoded)["provider"]["actual_models"], ["fake-sonnet-v2"]
        )
        payload["decision"]["outcome"] = "B"
        payload["provider"]["tokens"]["input_tokens"] = 99
        self.assertEqual(
            self.serialize(result, fixture)["decision"]["outcome"],  # type: ignore[index]
            "A",
        )
        self.assertEqual(
            self.serialize(result, fixture)["provider"]["tokens"],  # type: ignore[index]
            {"input_tokens": 3},
        )

    def test_single_field_mutations_fail_closed(self) -> None:
        def provider_change(fixture: dict[str, object], **changes: object) -> None:
            fixture["provider"] = replace(fixture["provider"], **changes)  # type: ignore[arg-type]

        mutations = {
            "outcome": lambda value: value.__setitem__("outcome", "B"),
            "decision": lambda value: value["decision"].__setitem__("outcome", "B"),
            "response": lambda value: value["response"].__setitem__("locked", False),
            "transport decision": lambda value: value["transport"][
                "decision"
            ].__setitem__("outcome", "B"),
            "transport response": lambda value: value["transport"][
                "response"
            ].__setitem__("locked", False),
            "transport request": lambda value: value["transport"].__setitem__(
                "request_sha256", "f" * 64
            ),
            "transport raw hash": lambda value: value["transport"].__setitem__(
                "raw_response_sha256", "f" * 64
            ),
            "transport parsed hash": lambda value: value["transport"].__setitem__(
                "parsed_response_sha256", "f" * 64
            ),
            "transport command": lambda value: value["transport"].__setitem__(
                "command_sha256", "f" * 64
            ),
            "transport stdin": lambda value: value["transport"].__setitem__(
                "stdin_sha256", "f" * 64
            ),
            "transport attempt": lambda value: value["transport"].__setitem__(
                "spend_attempt_id", "bad"
            ),
            "transport model": lambda value: value["transport"].__setitem__(
                "requested_model", "other"
            ),
            "transport actual models": lambda value: value["transport"].__setitem__(
                "actual_models", ["other"]
            ),
            "transport provider": lambda value: value["transport"].__setitem__(
                "provider_name", "other"
            ),
            "transport version": lambda value: value["transport"].__setitem__(
                "provider_version", "other"
            ),
            "transport cost": lambda value: value["transport"].__setitem__(
                "cost_usd", 0.5
            ),
            "transport duration": lambda value: value["transport"].__setitem__(
                "duration_seconds", 0.2
            ),
            "transport executor": lambda value: value["transport"].__setitem__(
                "executor", {"enforced": False, "kind": "deterministic-fake"}
            ),
            "transport missing": lambda value: value["transport"].pop("stdin_sha256"),
            "transport extra": lambda value: value["transport"].__setitem__(
                "extra", True
            ),
            "provider model": lambda value: provider_change(
                value, requested_model="other"
            ),
            "provider actual models": lambda value: provider_change(
                value, actual_models=("other",)
            ),
            "provider name": lambda value: provider_change(
                value, provider_name="other"
            ),
            "provider version": lambda value: provider_change(
                value, provider_version="other"
            ),
            "provider cost": lambda value: provider_change(value, cost_usd=0.5),
            "provider duration": lambda value: provider_change(
                value, duration_seconds=0.2
            ),
            "provider sandbox": lambda value: provider_change(
                value, sandbox={"enforced": True, "kind": "other"}
            ),
            "provider output": lambda value: provider_change(value, final_output="{}"),
            "provider raw": lambda value: provider_change(
                value, raw_response={"changed": True}
            ),
            "provider tokens": lambda value: value["provider"].tokens.__setitem__(
                "input_tokens", 99
            ),
            "provider billing": lambda value: provider_change(
                value,
                billing_basis="chatgpt_subscription",
                cost_usd=None,
                quota={"remaining": 1},
                protocol_provenance={"transport": "test"},
            ),
            "request bytes": lambda value: setattr(
                value["request"], "request_bytes", b"{}"
            ),
        }
        for label, mutate in mutations.items():
            with self.subTest(label=label):
                fixture = self.fixture()
                if label == "request bytes":
                    fixture["request"] = replace(
                        fixture["request"],
                        request_bytes=b"{}",  # type: ignore[arg-type]
                    )
                else:
                    mutate(fixture)
                with self.assertRaises(ProviderError):
                    self.result(fixture)

    def test_consumption_requires_the_exact_originating_request_instance(self) -> None:
        fixture = self.fixture()
        origin = fixture["request"]
        result = self.result(fixture)
        with self.assertRaises(TypeError):
            result.as_json()  # type: ignore[call-arg]

        other_runtime = self.fixture()["request"].runtime  # type: ignore[union-attr]
        substitutions = {
            "equivalent instance": replace(origin),  # type: ignore[arg-type]
            "pair": replace(origin, pair={"id": "other-pair"}),  # type: ignore[arg-type]
            "repetition": replace(origin, repetition=3),  # type: ignore[arg-type]
            "order": replace(origin, order="BA"),  # type: ignore[arg-type]
            "runtime": replace(origin, runtime=other_runtime),  # type: ignore[arg-type]
            "shallow copy": copy.copy(origin),
            "deep copy": copy.deepcopy(origin),
        }
        for label, request in substitutions.items():
            with self.subTest(label=label):
                with self.assertRaisesRegex(ProviderError, "differs from its origin"):
                    result.as_json(request)  # type: ignore[arg-type]

        self.assertNotIn(origin._request_token, repr(origin))  # type: ignore[union-attr]
        self.assertNotIn("_request_token_value", origin.__dataclass_fields__)  # type: ignore[union-attr]
        self.assertEqual(origin, substitutions["equivalent instance"])
        self.assertNotEqual(
            origin._request_token,  # type: ignore[union-attr]
            substitutions["deep copy"]._request_token,  # type: ignore[union-attr]
        )

        same_instance_fixture = self.fixture()
        same_instance_request = same_instance_fixture["request"]
        same_instance_result = self.result(same_instance_fixture)
        object.__setattr__(same_instance_request, "repetition", 3)
        with (
            patch(
                "skivolve.providers.validate_response",
                return_value=copy.deepcopy(same_instance_result.decision),
            ),
            patch(
                "skivolve.providers.expected_transport_hashes",
                return_value={
                    key: same_instance_result.transport[key]
                    for key in (
                        "command_sha256",
                        "request_sha256",
                        "stdin_sha256",
                    )
                },
            ),
            patch("skivolve.providers.validate_executor_evidence"),
            self.assertRaisesRegex(ProviderError, "consumption request changed"),
        ):
            same_instance_result.as_json(same_instance_request)  # type: ignore[arg-type]

    def test_each_fake_executor_admission_conjunct_fails_independently(self) -> None:
        valid = self.fake_fixture()
        self.assertEqual(self.result(valid).outcome, "A")

        for label in ("release", "provider", "executor"):
            with self.subTest(label=label):
                fixture = self.fake_fixture()
                if label == "release":
                    fixture["request"].runtime.bundle.release["test_release"] = False  # type: ignore[union-attr]
                elif label == "provider":
                    fixture["provider"] = replace(
                        fixture["provider"],  # type: ignore[arg-type]
                        provider_name="other-provider",
                    )
                    fixture["transport"]["provider_name"] = "other-provider"  # type: ignore[index]
                    fixture["request"].runtime.bundle.release["judge"][  # type: ignore[union-attr]
                        "provider"
                    ] = "other-provider"
                else:
                    fixture["transport"]["executor"]["extra"] = True  # type: ignore[index]
                with self.assertRaisesRegex(ProviderError, "fake executor"):
                    self.result(fixture)

    def test_post_construction_nested_mutations_fail_serialization(self) -> None:
        mutations = (
            lambda result: result.decision.__setitem__("outcome", "B"),
            lambda result: result.transport.__setitem__("request_sha256", "f" * 64),
            lambda result: result.provider.tokens.__setitem__("input_tokens", 99),
        )
        for mutate in mutations:
            with self.subTest(mutate=mutate):
                fixture = self.fixture()
                result = self.result(fixture)
                mutate(result)
                with self.assertRaisesRegex(ProviderError, "changed after validation"):
                    result.as_json(fixture["request"])  # type: ignore[arg-type]

    def test_request_limits_are_bound_to_release_and_ledger(self) -> None:
        changes = (
            {"timeout_seconds": 31},
            {"max_budget_usd": 0.5},
            {"spend_ledger": SpendLedger(2.0)},
        )
        for change in changes:
            with self.subTest(change=change):
                fixture = self.fixture()
                fixture["request"] = replace(
                    fixture["request"],  # type: ignore[arg-type]
                    **change,
                )
                with self.assertRaisesRegex(ProviderError, "limits differ"):
                    self.result(fixture)

    def test_shared_executor_is_bound_to_every_requested_sandbox_root(self) -> None:
        for index in range(3):
            with self.subTest(property_index=index):
                fixture = self.fixture()
                executor = fixture["transport"]["executor"]  # type: ignore[index]
                executor["properties"].pop(index)  # type: ignore[index]
                with self.assertRaisesRegex(ProviderError, "sandbox roots"):
                    self.result(fixture)

    def test_production_spend_attempt_requires_exact_ledger_reconciliation(
        self,
    ) -> None:
        fixture = self.fixture()
        fixture["request"].runtime.bundle.release["test_release"] = False  # type: ignore[union-attr]
        with self.assertRaisesRegex(ProviderError, "not reconciled"):
            self.result(fixture)

        fixture = self.fixture()
        fixture["request"].runtime.bundle.release["test_release"] = False  # type: ignore[union-attr]
        with tempfile.TemporaryDirectory() as temporary:
            ledger = SpendLedger(1.0, Path(temporary) / "spend.jsonl")
            ledger.restore_reconciled(
                "4" * 32,
                1.0,
                0.25,
                request_sha256=fixture["expected_hashes"]["request_sha256"],  # type: ignore[index]
                invocation_id="1" * 64,
            )
            fixture["request"] = replace(
                fixture["request"],  # type: ignore[arg-type]
                spend_ledger=ledger,
            )
            self.assertEqual(self.result(fixture).outcome, "A")

    def test_boundary_helper_failures_are_redacted_provider_errors(self) -> None:
        sentinel = "SENTINEL_COMPARATOR_SECRET"
        for failure in (
            CalibrationError(sentinel),
            RecursionError(sentinel),
            AttributeError(sentinel),
        ):
            with self.subTest(failure=type(failure).__name__):
                fixture = self.fixture()
                result = self.result(fixture)
                with (
                    patch("skivolve.providers.canonical_sha256", side_effect=failure),
                    self.assertRaises(ProviderError) as caught,
                ):
                    result.as_json(fixture["request"])  # type: ignore[arg-type]
                self.assertNotIn(sentinel, str(caught.exception))

        fixture = self.fixture()
        with (
            patch(
                "skivolve.providers.validate_response",
                return_value=copy.deepcopy(fixture["decision"]),
            ),
            patch(
                "skivolve.providers.expected_transport_hashes",
                side_effect=AttributeError(sentinel),
            ),
            patch("skivolve.providers.validate_executor_evidence"),
            self.assertRaises(ProviderError) as caught,
        ):
            ComparatorResult(
                outcome=fixture["outcome"],  # type: ignore[arg-type]
                decision=fixture["decision"],  # type: ignore[arg-type]
                response=fixture["response"],  # type: ignore[arg-type]
                transport=fixture["transport"],  # type: ignore[arg-type]
                provider=fixture["provider"],  # type: ignore[arg-type]
                request=fixture["request"],  # type: ignore[arg-type]
            )
        self.assertNotIn(sentinel, str(caught.exception))

    def test_errors_do_not_disclose_malformed_raw_evidence(self) -> None:
        sentinel = "SENTINEL_COMPARATOR_SECRET"
        fixture = self.fixture()
        fixture["transport"]["raw_response"] = sentinel  # type: ignore[index]

        with self.assertRaises(ProviderError) as caught:
            self.result(fixture)

        self.assertNotIn(sentinel, str(caught.exception))


class ManifestProviderContractTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        (self.root / "fixture").mkdir()
        (self.root / "prompt.md").write_text(
            "Implement the change.\n", encoding="utf-8"
        )
        (self.root / "verify.py").write_text("raise SystemExit(0)\n", encoding="utf-8")
        (self.root / "codex-protocol-lock.json").write_text(
            '{"schema_version":1}\n', encoding="utf-8"
        )
        self.manifest = {
            "schema_version": 1,
            "suite_id": "provider-contract",
            "seed": 1,
            "repository_root": ".",
            "evaluation_mode": "judged",
            "provider": self.codex_provider(),
            "comparator": {
                "adapter": "deterministic-fake",
                "model": "fake-comparator",
                "timeout_seconds": 30,
                "max_budget_usd": 1.0,
            },
            "comparator_profile": {
                "kind": "builtin",
                "id": "software-engineering-v1",
            },
            "shared_verifier_dir": None,
            "variants": [
                {"id": "without", "kind": "without_skill"},
                {
                    "id": "candidate",
                    "kind": "worktree",
                    "root": ".",
                    "source_ref": "candidate-ref",
                },
            ],
            "comparisons": [
                {
                    "id": "without-candidate",
                    "control": "without",
                    "treatment": "candidate",
                    "repetitions": 3,
                    "comparator_order": "ab_ba",
                }
            ],
            "holdout": {"comparison_ids": ["without-candidate"]},
            "cases": [
                {
                    "id": "case",
                    "skill": "engineering",
                    "bundle_source": "skills/engineering",
                    "artifact_contract": {"kind": "workspace_diff"},
                    "split": "validation",
                    "prompt_file": "prompt.md",
                    "fixture_dir": "fixture",
                    "verifier": {
                        "argv": ["python3", "verify.py"],
                        "timeout_seconds": 10,
                        "required_tools": [],
                    },
                    "context_files": [],
                    "timeout_seconds": 10,
                    "critical_expectations": ["correct"],
                    "comparator_contract": {
                        "requirements": [
                            {
                                "id": "correct",
                                "kind": "required_behavior",
                                "text": "The implementation preserves required behavior.",
                            }
                        ],
                        "performance_basis": None,
                        "qualitative_bases": {},
                    },
                }
            ],
        }
        self.suite_schema = json.loads(
            (HARNESS_ROOT / "suite.schema.json").read_text(encoding="utf-8")
        )

    @staticmethod
    def codex_provider() -> dict[str, object]:
        return {
            "adapter": "codex-app-server",
            "executable": "codex",
            "model": "gpt-5.6-luna",
            "reasoning_effort": "max",
            "billing_basis": "chatgpt_subscription",
            "protocol_lock": "codex-protocol-lock.json",
            "timeout_seconds": 300,
        }

    def save(self, payload: dict[str, object] | None = None) -> Path:
        path = self.root / "suite.json"
        path.write_text(
            json.dumps(self.manifest if payload is None else payload), encoding="utf-8"
        )
        return path

    def assert_schema_and_parser_reject(self, payload: dict[str, object]) -> None:
        errors = list(Draft202012Validator(self.suite_schema).iter_errors(payload))
        self.assertTrue(errors, "suite schema unexpectedly accepted mutation")
        with self.assertRaises(ManifestError):
            load_suite(self.save(payload))

    def test_load_suite_when_codex_model_is_supported_binds_effort_and_provenance(
        self,
    ) -> None:
        # Arrange
        path = self.save()

        # Act
        suite = load_suite(path)

        # Assert
        self.assertEqual(suite.provider.adapter_id, "codex-app-server")
        self.assertEqual(suite.provider.reasoning_effort, "max")
        self.assertEqual(suite.provider.billing_basis, "chatgpt_subscription")
        self.assertEqual(
            suite.provider.protocol_lock,
            (self.root / "codex-protocol-lock.json").resolve(),
        )
        self.assertIsNone(suite.provider.max_budget_usd)

        self.manifest["provider"] = {
            **self.codex_provider(),
            "model": "gpt-5.6-terra",
            "reasoning_effort": "ultra",
        }
        terra = load_suite(self.save())

        self.assertEqual(terra.provider.reasoning_effort, "ultra")

    def test_load_suite_when_existing_claude_manifest_is_loaded_defaults_to_metered_provenance(
        self,
    ) -> None:
        # Arrange
        path = HARNESS_ROOT / "suite.json"

        # Act
        suite = load_suite(path)

        # Assert
        self.assertEqual(suite.provider.adapter_id, "claude-cli")
        self.assertEqual(suite.provider.billing_basis, "metered_api")
        self.assertIsNone(suite.provider.reasoning_effort)
        self.assertIsNone(suite.provider.protocol_lock)

    def test_load_suite_when_codex_provider_fields_conflict_rejects_schema_and_parser(
        self,
    ) -> None:
        # Arrange
        mutations: list[dict[str, object]] = []
        for missing in (
            "executable",
            "reasoning_effort",
            "billing_basis",
            "protocol_lock",
        ):
            payload = copy.deepcopy(self.manifest)
            del payload["provider"][missing]  # type: ignore[index]
            mutations.append(payload)
        for changes in (
            {"model": "gpt-5.6-unknown"},
            {"reasoning_effort": "ultra"},
            {"billing_basis": "metered_api"},
            {"max_budget_usd": 1.0},
            {"protocol_lock": "../codex-protocol-lock.json"},
            {"protocol_lock": "./codex-protocol-lock.json"},
        ):
            payload = copy.deepcopy(self.manifest)
            payload["provider"].update(changes)  # type: ignore[union-attr]
            mutations.append(payload)

        # Act + Assert
        for payload in mutations:
            with self.subTest(provider=payload["provider"]):
                self.assert_schema_and_parser_reject(payload)

    def test_load_suite_when_codex_is_configured_as_comparator_rejects_manifest(
        self,
    ) -> None:
        # Arrange
        payload = copy.deepcopy(self.manifest)
        payload["comparator"] = self.codex_provider()

        # Act + Assert
        self.assert_schema_and_parser_reject(payload)

    def test_load_suite_when_fake_provider_sets_executable_rejects_schema_and_parser(
        self,
    ) -> None:
        # Arrange
        payload = copy.deepcopy(self.manifest)
        payload["comparator"]["executable"] = "fake"  # type: ignore[index]

        # Act + Assert
        self.assert_schema_and_parser_reject(payload)

    def test_load_suite_when_timeout_exceeds_limit_rejects_schema_and_parser(
        self,
    ) -> None:
        # Arrange
        mutations = (
            ("provider",),
            ("comparator",),
            ("cases", 0),
            ("cases", 0, "verifier"),
        )

        # Act + Assert
        for path in mutations:
            payload = copy.deepcopy(self.manifest)
            target: object = payload
            for segment in path:
                target = target[segment]  # type: ignore[index]
            target["timeout_seconds"] = 3601  # type: ignore[index]
            with self.subTest(path=path):
                self.assert_schema_and_parser_reject(payload)

    def test_load_suite_when_protocol_lock_is_symlink_rejects_manifest(self) -> None:
        # Arrange
        link = self.root / "linked-lock.json"
        link.symlink_to(self.root / "codex-protocol-lock.json")
        payload = copy.deepcopy(self.manifest)
        payload["provider"]["protocol_lock"] = link.name  # type: ignore[index]

        # Act + Assert
        with self.assertRaisesRegex(ManifestError, "non-symlink"):
            load_suite(self.save(payload))


class HoldoutProviderContractTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        self.path = self.root / "holdout.json"
        self.schema = json.loads(
            (HARNESS_ROOT / "holdout-plan.schema.json").read_text(encoding="utf-8")
        )
        case_ids = [f"case-{index}" for index in range(8)]
        generator_binding = self.adapter_binding(
            "generation", adapter_id="codex-app-server", authority_scope="diagnostic"
        )
        self.payload = {
            "schema_version": 1,
            "plan_id": "provider-holdout",
            "status": "sealed",
            "manifest_sha256": "a" * 64,
            "evaluation_mode": "judged",
            "comparator_release_sha256": "b" * 64,
            "comparator_calibration_evidence_sha256": "3" * 64,
            "comparator_profile_id": "software-engineering-v1",
            "comparator_profile_descriptor_sha256": "4" * 64,
            "comparator_profile_authority_registry_sha256": "5" * 64,
            "generator_provider": {
                "name": "codex-app-server",
                "version": "codex-cli 0.144.1",
                "requested_model": "gpt-5.6-terra",
                "executable_sha256": "c" * 64,
                "reasoning_effort": "ultra",
                "billing_basis": "chatgpt_subscription",
                "protocol_lock": "codex-protocol-lock.json",
                "protocol_lock_sha256": "d" * 64,
                "execution_policy": {
                    "concurrency": "serialized",
                    "release_authoritative": False,
                },
            },
            "generator_adapter_binding": generator_binding,
            "comparator_adapter_binding": self.adapter_binding(
                "comparison",
                adapter_id="deterministic-fake",
                authority_scope="test",
            ),
            "source_bindings": [
                {
                    "variant_id": "candidate",
                    "kind": "worktree",
                    "source_commit": "e" * 64,
                    "source_sha256_by_case": {
                        case_id: "1" * 64 for case_id in case_ids
                    },
                },
                {
                    "variant_id": "original",
                    "kind": "git_ref",
                    "source_commit": "f" * 40,
                    "source_sha256_by_case": {
                        case_id: "2" * 64 for case_id in case_ids
                    },
                },
            ],
            "consumption_record_path": str((self.root / "consumption.json").resolve()),
            "seed": 1,
            "comparison_profile": [
                {
                    "id": "original-candidate",
                    "control": "original",
                    "treatment": "candidate",
                    "repetitions": 3,
                    "comparator_order": "ab_ba",
                }
            ],
            "cases": [
                {
                    "id": case_id,
                    "case_tree_sha256": f"{index + 1:064x}",
                    "shared_tree_sha256": None,
                    "release_case_fingerprint": f"{index + 101:064x}",
                    "skill": "engineering",
                    "critical_expectations": ["correct"],
                }
                for index, case_id in enumerate(case_ids)
            ],
            "provenance": {
                "assurance": "operator-declared-review-records",
                "privacy_claim": "not-a-cryptographic-privacy-proof",
                "frozen_before_candidate_evaluation": True,
                "sealed_after_independent_review": True,
                "reviewed_by": ["reviewer"],
                "freeze_record": "review:freeze",
                "seal_record": "review:seal",
            },
        }

    @staticmethod
    def adapter_binding(
        role: str, *, adapter_id: str, authority_scope: str
    ) -> dict[str, object]:
        return {
            "adapter_id": adapter_id,
            "authority_scope": authority_scope,
            "binding_sha256": "7" * 64,
            "capability_sha256": "8" * 64,
            "config_sha256": "9" * 64,
            "contract_revision": 1,
            "role": role,
            "runtime_provenance_sha256": "a" * 64,
        }

    def save(self, payload: dict[str, object]) -> None:
        self.path.write_text(json.dumps(payload), encoding="utf-8")
        self.path.chmod(stat.S_IRUSR | stat.S_IWUSR)

    def assert_schema_and_parser_reject(self, payload: dict[str, object]) -> None:
        self.assertTrue(
            list(Draft202012Validator(self.schema).iter_errors(payload)),
            "holdout schema unexpectedly accepted mutation",
        )
        self.save(payload)
        with self.assertRaises(HoldoutPlanError):
            load_holdout_plan(self.path)

    def test_load_holdout_plan_when_subscription_binding_is_complete_round_trips_provenance(
        self,
    ) -> None:
        # Arrange
        self.save(self.payload)

        # Act
        plan = load_holdout_plan(self.path)

        # Assert
        self.assertEqual(
            plan.generator_provider.as_json(), self.payload["generator_provider"]
        )
        self.assertFalse(
            plan.generator_provider.execution_policy["release_authoritative"]
        )

    def test_load_holdout_plan_when_contract_is_current_round_trips_bindings(
        self,
    ) -> None:
        # Arrange
        payload = copy.deepcopy(self.payload)

        # Act
        schema_errors = list(Draft202012Validator(self.schema).iter_errors(payload))
        self.save(payload)
        plan = load_holdout_plan(self.path)

        # Assert
        self.assertFalse(schema_errors)
        self.assertEqual(plan.evaluation_mode, "judged")
        self.assertEqual(
            tuple(binding.variant_id for binding in plan.source_bindings),
            ("candidate", "original"),
        )
        self.assertEqual(
            plan.generator_adapter_binding.adapter_id,
            "codex-app-server",
        )
        self.assertEqual(plan.as_evidence()["schema_version"], 1)
        self.assertFalse(hasattr(plan, "schema_version"))

    def test_load_holdout_plan_when_shape_is_legacy_rejects_payload(self) -> None:
        # Arrange
        payload = copy.deepcopy(self.payload)
        legacy_mutations = {
            "suite-era commit fields": lambda value: value.__setitem__(
                "candidate_commit", "e" * 40
            ),
            "non-v1 wire version": lambda value: value.__setitem__("schema_version", 3),
            "legacy assurance": lambda value: value["provenance"].__setitem__(
                "assurance", "trusted-reviewed-attestation"
            ),
        }

        # Act + Assert
        for label, mutate in legacy_mutations.items():
            with self.subTest(label=label):
                invalid = copy.deepcopy(payload)
                mutate(invalid)
                self.assert_schema_and_parser_reject(invalid)

    def test_load_holdout_plan_when_source_bindings_are_noncanonical_rejects_plan(
        self,
    ) -> None:
        # Arrange
        payload = copy.deepcopy(self.payload)
        case_ids = sorted(case["id"] for case in payload["cases"])

        mutations = {
            "missing variant": lambda value: value["source_bindings"].pop(),
            "reordered variants": lambda value: value["source_bindings"].reverse(),
            "missing case": lambda value: value["source_bindings"][0][
                "source_sha256_by_case"
            ].pop(case_ids[0]),
            "null worktree commit": lambda value: value["source_bindings"][
                0
            ].__setitem__("source_commit", None),
        }

        # Act + Assert
        for label, mutate in mutations.items():
            with self.subTest(label=label):
                invalid = copy.deepcopy(payload)
                mutate(invalid)
                self.save(invalid)
                with self.assertRaises(HoldoutPlanError):
                    load_holdout_plan(self.path)

    def test_load_holdout_plan_when_mode_is_objective_rejects_comparator_authority(
        self,
    ) -> None:
        # Arrange
        payload = copy.deepcopy(self.payload)
        payload["evaluation_mode"] = "objective_only"
        for field in (
            "comparator_release_sha256",
            "comparator_calibration_evidence_sha256",
            "comparator_profile_id",
            "comparator_profile_descriptor_sha256",
            "comparator_profile_authority_registry_sha256",
            "comparator_adapter_binding",
        ):
            payload.pop(field)
        payload["objective_acceptance_policy_id"] = "verifier-pass-v1"
        payload["objective_acceptance_policy_sha256"] = "6" * 64

        # Act
        schema_errors = list(Draft202012Validator(self.schema).iter_errors(payload))
        self.save(payload)
        objective_plan = load_holdout_plan(self.path)

        # Assert
        self.assertFalse(schema_errors)
        self.assertEqual(objective_plan.evaluation_mode, "objective_only")
        self.assertIsNone(objective_plan.comparator_release_sha256)
        self.assertIsNone(objective_plan.comparator_adapter_binding)

        objective_with_comparator = copy.deepcopy(payload)
        objective_with_comparator["comparator_release_sha256"] = "7" * 64
        self.assert_schema_and_parser_reject(objective_with_comparator)
        judged_with_objective = copy.deepcopy(self.payload)
        judged_with_objective["objective_acceptance_policy_id"] = "verifier-pass-v1"
        self.assert_schema_and_parser_reject(judged_with_objective)
        objective_without_policy = copy.deepcopy(payload)
        objective_without_policy.pop("objective_acceptance_policy_sha256")
        self.assert_schema_and_parser_reject(objective_without_policy)

    def test_load_holdout_plan_when_adapter_roles_are_confused_rejects_plan(
        self,
    ) -> None:
        # Arrange
        wrong_role = copy.deepcopy(self.payload)
        wrong_role["generator_adapter_binding"]["role"] = "comparison"

        # Act + Assert
        self.assert_schema_and_parser_reject(wrong_role)

    def test_load_holdout_plan_when_billing_policy_is_invalid_rejects_schema_and_parser(
        self,
    ) -> None:
        # Arrange
        mutations: list[dict[str, object]] = []
        for changes in (
            {"reasoning_effort": None},
            {"protocol_lock": None},
            {"protocol_lock_sha256": None},
            {"protocol_lock": "../codex-protocol-lock.json"},
            {"protocol_lock": "./codex-protocol-lock.json"},
            {"requested_model": "gpt-5.6-unknown"},
            {"requested_model": "gpt-5.6-luna", "reasoning_effort": "ultra"},
            {"executable_sha256": None},
            {
                "execution_policy": {
                    "concurrency": "concurrent",
                    "release_authoritative": True,
                }
            },
            {
                "execution_policy": {
                    "concurrency": "concurrent",
                    "release_authoritative": 1,
                }
            },
        ):
            payload = copy.deepcopy(self.payload)
            payload["generator_provider"].update(changes)  # type: ignore[union-attr]
            mutations.append(payload)

        metered = copy.deepcopy(self.payload)
        metered["generator_provider"]["billing_basis"] = "metered_api"  # type: ignore[index]
        mutations.append(metered)

        # Act + Assert
        for payload in mutations:
            with self.subTest(provider=payload["generator_provider"]):
                self.assert_schema_and_parser_reject(payload)


if __name__ == "__main__":
    unittest.main()
