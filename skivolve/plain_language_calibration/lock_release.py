"""Regenerate plain-language profile releases and its authority entry."""

from __future__ import annotations

import copy
import hashlib
import json
from pathlib import Path
from typing import Any

from skivolve.comparator_calibration.calibration import (
    canonical_sha256,
    criterion_support,
    file_sha256,
    load_json,
    review_artifact_hashes,
)


ROOT = Path(__file__).resolve().parent
PROJECT_ROOT = ROOT.parents[1]
SHARED = PROJECT_ROOT / "skivolve/comparator_calibration"
AUTHORITY = PROJECT_ROOT / "skivolve/comparator-profile-authority.json"
PROFILE_ID = "plain-language-revision-v1"


def _encoded(value: dict[str, Any]) -> bytes:
    return (json.dumps(value, ensure_ascii=True, indent=2) + "\n").encode("ascii")


def _release(*, test: bool) -> dict[str, Any]:
    template = load_json(
        SHARED / ("tests/test-release.json" if test else "release.json")
    )
    release = copy.deepcopy(template)
    manifest = load_json(ROOT / "manifest.json")
    rubric = load_json(ROOT / "rubric.json")
    request = load_json(ROOT / "request-template.json")
    semantic = load_json(ROOT / "semantic-contract.json")
    reviews = review_artifact_hashes(manifest)
    release["release_id"] = (
        "plain-language-revision-test-v1" if test else "plain-language-revision-v1"
    )
    release["artifacts"].update(
        {
            "profile_descriptor_sha256": file_sha256(ROOT / "profile.json"),
            "corpus_sha256": canonical_sha256(manifest),
            "manifest_schema_sha256": canonical_sha256(
                load_json(ROOT / "manifest.schema.json")
            ),
            "rubric_sha256": canonical_sha256(rubric),
            "request_template_sha256": canonical_sha256(request),
            "system_prompt_sha256": hashlib.sha256(
                request["system_prompt"].encode("utf-8")
            ).hexdigest(),
            "response_schema_sha256": canonical_sha256(
                load_json(ROOT / "response.schema.json")
            ),
            "evidence_schema_sha256": canonical_sha256(
                load_json(ROOT / "evidence.schema.json")
            ),
            "semantic_contract_sha256": canonical_sha256(semantic),
            **{f"{name}_sha256": digest for name, digest in reviews.items()},
        }
    )
    release["evaluator"] = {
        "version": "1.0.0",
        "source_sha256": file_sha256(SHARED / "calibration.py"),
        "collector_source_sha256": file_sha256(SHARED / "collect.py"),
        "certifier_source_sha256": file_sha256(SHARED / "certify.py"),
    }
    release["execution_limits"]["expected_call_count"] = sum(
        pair["repetitions"] * 2 for pair in manifest["pairs"]
    )
    release["criterion_support"] = criterion_support(manifest, semantic)
    release["invocation_namespace_sha256"] = hashlib.sha256(
        b"skivolve:plain-language-revision-v1:invocations:v1"
    ).hexdigest()
    runtime_sources = {
        "source_sha256": PROJECT_ROOT / "skivolve/comparator_runtime.py",
        "harness_runner_source_sha256": PROJECT_ROOT / "skivolve/runner.py",
        "artifact_normalizer_source_sha256": PROJECT_ROOT / "skivolve/artifacts.py",
        "provider_source_sha256": PROJECT_ROOT / "skivolve/providers.py",
        "profile_registry_source_sha256": PROJECT_ROOT
        / "skivolve/comparator_profiles.py",
        "provider_capability_registry_source_sha256": PROJECT_ROOT
        / "skivolve/provider_capabilities.py",
        "harness_manifest_source_sha256": PROJECT_ROOT / "skivolve/manifest.py",
        "harness_package_source_sha256": PROJECT_ROOT / "skivolve/__init__.py",
        "run_evals_source_sha256": PROJECT_ROOT / "skivolve/cli.py",
        "holdout_plan_source_sha256": PROJECT_ROOT / "skivolve/holdout_plan.py",
        "prepare_holdout_plan_source_sha256": PROJECT_ROOT / "skivolve/holdout_cli.py",
        "baseline_authority_source_sha256": PROJECT_ROOT / "baseline-authority.json",
    }
    release["runtime_adapter"].update(
        {name: file_sha256(path) for name, path in runtime_sources.items()}
    )
    release["trust_boundary_note"] = (
        "This test-authority profile binds author-authored editorial fixture data to "
        "the shared comparator engine; it makes no independent-review claim and cannot "
        "authorize production or replace source, provider, spend, isolation, or holdout "
        "authority."
    )
    return release


def _authority_entry(
    profile_root: Path,
    profile_id: str,
    authority_scope: str,
    production: bytes,
    test: bytes,
) -> dict[str, Any]:
    return {
        "id": profile_id,
        "descriptor_sha256": file_sha256(profile_root / "profile.json"),
        "production_release_sha256": hashlib.sha256(production).hexdigest(),
        "test_release_sha256": hashlib.sha256(test).hexdigest(),
        "certification_contract_sha256": file_sha256(
            profile_root / "evidence.schema.json"
        ),
        "requires_live_certification": True,
        "authority_scope": authority_scope,
    }


def main() -> None:
    production = _encoded(_release(test=False))
    test = _encoded(_release(test=True))
    software_root = PROJECT_ROOT / "skivolve/comparator_calibration"
    profiles = [
        _authority_entry(
            software_root,
            "software-engineering-v1",
            "production",
            (software_root / "release.json").read_bytes(),
            (software_root / "tests/test-release.json").read_bytes(),
        ),
        _authority_entry(ROOT, PROFILE_ID, "test", production, test),
    ]
    authority = _encoded(
        {"schema_version": 1, "profiles": sorted(profiles, key=lambda item: item["id"])}
    )
    (ROOT / "release.json").write_bytes(production)
    (ROOT / "tests").mkdir(parents=True, exist_ok=True)
    (ROOT / "tests/test-release.json").write_bytes(test)
    AUTHORITY.write_bytes(authority)


if __name__ == "__main__":
    main()
