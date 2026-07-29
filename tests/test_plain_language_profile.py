from __future__ import annotations

import json
import unittest
from pathlib import Path

from jsonschema import Draft202012Validator

from skivolve.comparator_calibration.calibration import validate_manifest
from skivolve.comparator_profiles import (
    BUILTIN_PLAIN_LANGUAGE_PROFILE_ID,
    ComparatorProfileError,
    resolve_builtin_profile,
    resolve_profile_directory,
)
from skivolve.comparator_runtime import CalibrationError, ComparatorRuntime


class PlainLanguageProfileTests(unittest.TestCase):
    def test_corpus_is_balanced_non_engineering_and_schema_valid(self) -> None:
        runtime = ComparatorRuntime.load_builtin_profile(
            BUILTIN_PLAIN_LANGUAGE_PROFILE_ID, use_test_release=True
        )
        try:
            summary = validate_manifest(
                runtime.bundle.manifest,
                runtime.bundle.rubric,
                runtime.bundle.semantic_contract,
            )
            Draft202012Validator(runtime.bundle.manifest_schema).validate(
                runtime.bundle.manifest
            )
            self.assertEqual(summary["pair_count"], 10)
            self.assertEqual(summary["raw_trial_count"], 40)
            self.assertEqual(
                summary["resolved_outcomes"],
                {"A": 2, "B": 2, "tie": 2, "tradeoff": 2, "unqualified": 2},
            )
            self.assertEqual(summary["languages"], {"text": 10})
            self.assertTrue(summary["adjudication_complete"])
            self.assertEqual(
                {
                    criterion
                    for criterion, support in summary["criterion_support"].items()
                    if support["production_decisive"]
                },
                {"reader_clarity", "concision"},
            )
            for criterion in ("reader_clarity", "concision"):
                self.assertGreaterEqual(
                    summary["criterion_support"][criterion]["canonical_counts"]["A"],
                    2,
                )
                self.assertGreaterEqual(
                    summary["criterion_support"][criterion]["canonical_counts"]["B"],
                    2,
                )
            probes = [pair["probes"] for pair in runtime.bundle.manifest["pairs"]]
            self.assertEqual(sum(probe["injection"] is not None for probe in probes), 2)
            self.assertEqual(
                {
                    probe["length_bias"]["kind"]
                    for probe in probes
                    if probe["length_bias"] is not None
                },
                {"necessary", "harmful"},
            )
            serialized = json.dumps(
                {
                    "manifest": runtime.bundle.manifest,
                    "rubric": runtime.bundle.rubric,
                    "semantic_contract": runtime.bundle.semantic_contract,
                }
            )
            self.assertNotIn("independently reviewed", serialized)
            self.assertTrue(
                all(
                    pair["provenance"]["reference"].startswith("Author-authored")
                    for pair in runtime.bundle.manifest["pairs"]
                )
            )
            for software_criterion in (
                "functional_correctness",
                "security_reliability",
                "maintainability_extensibility",
                "performance_efficiency",
                "simplicity_scope_discipline",
            ):
                self.assertNotIn(software_criterion, serialized)
        finally:
            runtime.close()

    def test_resolve_profile_directory_when_semantic_contract_comes_from_another_profile_rejects_release_lock(
        self,
    ) -> None:
        # Arrange
        built_in = resolve_builtin_profile(BUILTIN_PLAIN_LANGUAGE_PROFILE_ID)
        software = resolve_builtin_profile("software-engineering-v1")
        with built_in.materialize() as root:
            (Path(root) / "semantic-contract.json").write_bytes(
                software.read_bytes("semantic_contract")
            )

            # Act + Assert
            with self.assertRaisesRegex(
                ComparatorProfileError, "artifact lock is stale"
            ):
                resolve_profile_directory(root)

    def test_test_authority_cannot_select_production_release(self) -> None:
        with self.assertRaisesRegex(CalibrationError, "not authorized for production"):
            ComparatorRuntime.load_builtin_profile(BUILTIN_PLAIN_LANGUAGE_PROFILE_ID)


if __name__ == "__main__":
    unittest.main()
