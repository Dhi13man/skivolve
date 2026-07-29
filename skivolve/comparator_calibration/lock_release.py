"""Regenerate reviewable production and explicit-test release locks."""

from __future__ import annotations

import hashlib
import json
from pathlib import Path
from typing import Any

from calibration import (
    EVALUATOR_VERSION,
    PRODUCTION_CLI_ARGS,
    PRODUCTION_PER_INVOCATION_BUDGET_USD,
    PRODUCTION_RUN_BUDGET_USD,
    PRODUCTION_TIMEOUT_SECONDS,
    SHARED_RUNTIME_ADAPTER_ID,
    canonical_sha256,
    criterion_support,
    file_sha256,
    load_json,
    require_baseline_authority,
    review_artifact_hashes,
)


ROOT = Path(__file__).resolve().parent
PROJECT_ROOT = ROOT.parents[1]
TRUST_NOTE = (
    "This release lock detects accidental artifact, frozen-baseline, prompt, schema, "
    "provider, and evaluator drift only when these release bytes and the executing "
    "code are trusted; it is not a signature and cannot prevent an attacker from "
    "forging JSON and recomputing every untrusted hash."
)


def _artifacts() -> dict[str, str]:
    manifest = load_json(ROOT / "manifest.json")
    manifest_schema = load_json(ROOT / "manifest.schema.json")
    rubric = load_json(ROOT / "rubric.json")
    request_template = load_json(ROOT / "request-template.json")
    response_schema = load_json(ROOT / "response.schema.json")
    evidence_schema = load_json(ROOT / "evidence.schema.json")
    semantic_contract = load_json(ROOT / "semantic-contract.json")
    holdout_plan_schema_path = PROJECT_ROOT / "holdout-plan.schema.json"
    holdout_plan_schema = load_json(holdout_plan_schema_path)
    reviews = review_artifact_hashes(manifest)
    return {
        "profile_descriptor_sha256": file_sha256(ROOT / "profile.json"),
        "corpus_sha256": canonical_sha256(manifest),
        "manifest_schema_sha256": canonical_sha256(manifest_schema),
        "rubric_sha256": canonical_sha256(rubric),
        "request_template_sha256": canonical_sha256(request_template),
        "system_prompt_sha256": hashlib.sha256(
            request_template["system_prompt"].encode("utf-8")
        ).hexdigest(),
        "response_schema_sha256": canonical_sha256(response_schema),
        "evidence_schema_sha256": canonical_sha256(evidence_schema),
        "semantic_contract_sha256": canonical_sha256(semantic_contract),
        "holdout_plan_schema_sha256": canonical_sha256(holdout_plan_schema),
        "holdout_plan_schema_bytes_sha256": file_sha256(holdout_plan_schema_path),
        "reviewer_a_sha256": reviews["reviewer_a"],
        "reviewer_b_sha256": reviews["reviewer_b"],
        "re_review_sha256": reviews["re_review"],
        "resolution_sha256": reviews["resolution"],
        "scoring_gold_sha256": reviews["scoring_gold"],
    }


def _acceptance() -> dict[str, Any]:
    return {
        "minimum_outcome_balanced_accuracy": 0.8,
        "minimum_outcome_cohen_kappa": 0.8,
        "minimum_eligibility_accuracy": 0.9,
        "minimum_requirement_status_accuracy": 0.95,
        "minimum_violation_set_accuracy": 0.95,
        "minimum_per_criterion_balanced_accuracy": 0.8,
        "require_zero_order_disagreements": True,
        "require_zero_sentinel_instability": True,
        "require_zero_critical_hard_outcome_failures": True,
        "require_zero_critical_hard_admissibility_errors": True,
        "require_zero_length_bias_failures": True,
        "require_zero_unsupported_performance": True,
        "require_zero_unsupported_qualitative": True,
        "require_zero_spend_limit_failures": True,
        "require_stable_model_set": True,
        "require_stable_executable": True,
    }


def _release(*, test: bool) -> dict[str, Any]:
    authority_path = PROJECT_ROOT / "baseline-authority.json"
    frozen_original = require_baseline_authority(
        PROJECT_ROOT / "suite.json",
        authority_path,
    )
    return {
        "schema_version": 1,
        "release_id": (
            "software-engineering-comparator-test-v1"
            if test
            else "software-engineering-comparator-reference-cli-v1"
        ),
        "test_release": test,
        "artifacts": _artifacts(),
        "evaluator": {
            "version": EVALUATOR_VERSION,
            "source_sha256": file_sha256(ROOT / "calibration.py"),
            "collector_source_sha256": file_sha256(ROOT / "collect.py"),
            "certifier_source_sha256": file_sha256(ROOT / "certify.py"),
        },
        "judge": (
            {
                "provider": "deterministic-fake",
                "provider_version": "1",
                "requested_model": "fake-sonnet-v2",
                "required_primary_model_prefix": "fake-sonnet-v2",
                "allowed_auxiliary_model_prefixes": ["fake-haiku"],
            }
            if test
            else {
                "provider": "claude-cli",
                "provider_version": "2.1.198 (Claude Code)",
                "requested_model": "claude-sonnet-5",
                "required_primary_model_prefix": "claude-sonnet-5",
                "allowed_auxiliary_model_prefixes": ["claude-haiku"],
            }
        ),
        "sampling": {
            "sentinel_repetitions": 3,
            "ordinary_repetitions": 1,
            "cli_args": [] if test else list(PRODUCTION_CLI_ARGS),
        },
        "execution_limits": {
            "timeout_seconds": PRODUCTION_TIMEOUT_SECONDS,
            "per_invocation_max_usd": PRODUCTION_PER_INVOCATION_BUDGET_USD,
            "run_max_usd": PRODUCTION_RUN_BUDGET_USD,
            "expected_call_count": sum(
                pair["repetitions"] * 2
                for pair in load_json(ROOT / "manifest.json")["pairs"]
            ),
        },
        "criterion_support": criterion_support(
            load_json(ROOT / "manifest.json"),
            load_json(ROOT / "semantic-contract.json"),
        ),
        "invocation_namespace_sha256": hashlib.sha256(
            (
                "software-engineering-comparator-test-namespace-v1"
                if test
                else "software-engineering-comparator-reference-namespace-v1"
            ).encode("ascii")
        ).hexdigest(),
        "acceptance": _acceptance(),
        "runtime_adapter": {
            "id": SHARED_RUNTIME_ADAPTER_ID,
            "source_sha256": file_sha256(
                PROJECT_ROOT / "skivolve" / "comparator_runtime.py"
            ),
            "harness_runner_source_sha256": file_sha256(
                PROJECT_ROOT / "skivolve" / "runner.py"
            ),
            "artifact_normalizer_source_sha256": file_sha256(
                PROJECT_ROOT / "skivolve" / "artifacts.py"
            ),
            "provider_source_sha256": file_sha256(
                PROJECT_ROOT / "skivolve" / "providers.py"
            ),
            "profile_registry_source_sha256": file_sha256(
                PROJECT_ROOT / "skivolve" / "comparator_profiles.py"
            ),
            "provider_capability_registry_source_sha256": file_sha256(
                PROJECT_ROOT / "skivolve" / "provider_capabilities.py"
            ),
            "harness_manifest_source_sha256": file_sha256(
                PROJECT_ROOT / "skivolve" / "manifest.py"
            ),
            "harness_package_source_sha256": file_sha256(
                PROJECT_ROOT / "skivolve" / "__init__.py"
            ),
            "run_evals_source_sha256": file_sha256(
                PROJECT_ROOT / "skivolve" / "cli.py"
            ),
            "holdout_plan_source_sha256": file_sha256(
                PROJECT_ROOT / "skivolve" / "holdout_plan.py"
            ),
            "prepare_holdout_plan_source_sha256": file_sha256(
                PROJECT_ROOT / "skivolve" / "holdout_cli.py"
            ),
            "baseline_authority_source_sha256": file_sha256(authority_path),
            "frozen_original_commit": frozen_original,
        },
        "trust_boundary_note": TRUST_NOTE,
    }


def _encoded(value: dict[str, Any]) -> bytes:
    return (json.dumps(value, ensure_ascii=True, indent=2) + "\n").encode("ascii")


def _write(path: Path, raw_bytes: bytes) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(raw_bytes)


def _authority_entry(
    profile_root: Path,
    profile_id: str,
    authority_scope: str,
    production_release: bytes,
    test_release: bytes,
) -> dict[str, Any]:
    return {
        "id": profile_id,
        "descriptor_sha256": file_sha256(profile_root / "profile.json"),
        "production_release_sha256": hashlib.sha256(production_release).hexdigest(),
        "test_release_sha256": hashlib.sha256(test_release).hexdigest(),
        "certification_contract_sha256": file_sha256(
            profile_root / "evidence.schema.json"
        ),
        "requires_live_certification": True,
        "authority_scope": authority_scope,
    }


def main() -> None:
    production_release = _encoded(_release(test=False))
    test_release = _encoded(_release(test=True))
    authority_path = PROJECT_ROOT / "skivolve/comparator-profile-authority.json"
    plain_root = PROJECT_ROOT / "skivolve/plain_language_calibration"
    profiles = [
        _authority_entry(
            ROOT,
            "software-engineering-v1",
            "production",
            production_release,
            test_release,
        ),
        _authority_entry(
            plain_root,
            "plain-language-revision-v1",
            "test",
            (plain_root / "release.json").read_bytes(),
            (plain_root / "tests/test-release.json").read_bytes(),
        ),
    ]
    authority = _encoded(
        {"schema_version": 1, "profiles": sorted(profiles, key=lambda item: item["id"])}
    )
    _write(ROOT / "release.json", production_release)
    _write(ROOT / "tests" / "test-release.json", test_release)
    _write(authority_path, authority)


if __name__ == "__main__":
    main()
