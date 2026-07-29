from __future__ import annotations

import hashlib
import json
import shutil
import tempfile
import unittest
import zipfile
from importlib import resources as importlib_resources
from pathlib import Path
from unittest.mock import patch

import skivolve as harness_package
from skivolve import comparator_calibration, comparator_profiles
from skivolve.comparator_profiles import (
    BUILTIN_PLAIN_LANGUAGE_PROFILE_ID,
    BUILTIN_PROFILE_IDS,
    BUILTIN_SOFTWARE_PROFILE_ID,
    MAX_PROFILE_DESCRIPTOR_BYTES,
    ComparatorProfileError,
    parse_profile_descriptor,
    resolve_builtin_profile,
)
from skivolve.comparator_runtime import CalibrationError, ComparatorRuntime


class ComparatorProfileTests(unittest.TestCase):
    def descriptor_payload(self) -> dict[str, object]:
        return json.loads(
            resolve_builtin_profile(BUILTIN_SOFTWARE_PROFILE_ID).descriptor_bytes
        )

    def encode(self, payload: dict[str, object]) -> bytes:
        return (json.dumps(payload, ensure_ascii=True) + "\n").encode("ascii")

    def copied_profile_root(self, parent: Path) -> Path:
        source = Path(comparator_calibration.__file__).parent
        destination = parent / "profile"
        shutil.copytree(source, destination)
        return destination

    def profile_files_patch(self, profile_root: object):
        original_files = importlib_resources.files

        def files(package: object) -> object:
            if package is comparator_calibration:
                return profile_root
            return original_files(package)

        return patch("skivolve.comparator_profiles.resources.files", side_effect=files)

    def test_resolve_builtin_profile_when_software_profile_is_current_snapshots_every_release_bound_resource(
        self,
    ) -> None:
        # Arrange
        profile_id = BUILTIN_SOFTWARE_PROFILE_ID

        # Act
        profile = resolve_builtin_profile(profile_id)

        # Assert
        self.assertEqual(profile.descriptor.schema_version, 1)
        self.assertEqual(profile.descriptor.id, BUILTIN_SOFTWARE_PROFILE_ID)
        self.assertEqual(profile.descriptor.version, "1.0.0")
        self.assertEqual(
            profile.descriptor.supported_artifact_kinds, ("workspace_diff",)
        )
        self.assertEqual(
            profile.descriptor.descriptor_sha256,
            hashlib.sha256(profile.descriptor_bytes).hexdigest(),
        )
        self.assertTrue(profile.authority_binding.requires_live_certification)
        self.assertEqual(
            profile.authority_binding.descriptor_sha256,
            profile.descriptor.descriptor_sha256,
        )
        self.assertEqual(
            profile.authority_binding.certification_contract_sha256,
            hashlib.sha256(profile.read_bytes("evidence_schema")).hexdigest(),
        )
        for resource_name in profile.descriptor.resources_by_name:
            self.assertTrue(profile.read_bytes(resource_name))
        for release_name, expected_digest in (
            (
                "production_release",
                profile.authority_binding.production_release_sha256,
            ),
            ("test_release", profile.authority_binding.test_release_sha256),
        ):
            self.assertEqual(
                hashlib.sha256(profile.read_bytes(release_name)).hexdigest(),
                expected_digest,
            )

    def test_plain_language_profile_has_test_authority_only(self) -> None:
        self.assertEqual(
            BUILTIN_PROFILE_IDS,
            {BUILTIN_SOFTWARE_PROFILE_ID, BUILTIN_PLAIN_LANGUAGE_PROFILE_ID},
        )
        profile = resolve_builtin_profile(BUILTIN_PLAIN_LANGUAGE_PROFILE_ID)
        self.assertEqual(profile.authority_binding.authority_scope, "test")
        self.assertNotIn("calibration_engine", profile.descriptor.resources_by_name)
        runtime = ComparatorRuntime.load_builtin_profile(
            BUILTIN_PLAIN_LANGUAGE_PROFILE_ID, use_test_release=True
        )
        try:
            self.assertEqual(
                tuple(runtime.bundle.semantic_contract["criterion_ids"]),
                (
                    "factual_fidelity",
                    "reader_clarity",
                    "audience_fit",
                    "concision",
                ),
            )
            self.assertEqual(
                runtime.release_summary["execution_limits"]["expected_call_count"],
                40,
            )
        finally:
            runtime.close()
        with self.assertRaisesRegex(CalibrationError, "not authorized for production"):
            ComparatorRuntime.load_builtin_profile(BUILTIN_PLAIN_LANGUAGE_PROFILE_ID)

    def test_materialized_profile_contains_only_snapshotted_resources(self) -> None:
        profile = resolve_builtin_profile(BUILTIN_SOFTWARE_PROFILE_ID)

        with profile.materialize() as root:
            materialized = {
                path.relative_to(root).as_posix()
                for path in root.rglob("*")
                if path.is_file()
            }
            self.assertEqual(
                materialized,
                {"profile.json", *profile.descriptor.resources_by_name.values()},
            )
            self.assertEqual(
                (root / "manifest.json").read_bytes(), profile.read_bytes("manifest")
            )
            materialized_root = root

        self.assertFalse(materialized_root.exists())

    def test_materialized_test_profile_loads_without_checkout_bindings(self) -> None:
        runtime = ComparatorRuntime.load_builtin_profile(
            BUILTIN_SOFTWARE_PROFILE_ID, use_test_release=True
        )
        root = runtime.root

        self.assertEqual(runtime.profile_id, BUILTIN_SOFTWARE_PROFILE_ID)
        self.assertTrue(root.is_dir())
        self.assertTrue(runtime.profile_locks_valid)
        self.assertFalse(runtime.protocol_locks_valid)
        self.assertFalse(runtime.external_bindings_validated)
        self.assertFalse(runtime.live_calibration_valid)
        self.assertEqual(
            runtime.release_summary["artifacts"], runtime.bundle.release["artifacts"]
        )
        runtime.close()
        runtime.close()
        self.assertFalse(root.exists())

    def test_packaged_runtime_cannot_satisfy_production_calibration_gate(self) -> None:
        runtime = ComparatorRuntime.load_builtin_profile(BUILTIN_SOFTWARE_PROFILE_ID)
        try:
            with self.assertRaisesRegex(CalibrationError, "external release bindings"):
                runtime.require_live_calibration()
        finally:
            runtime.close()

    def test_packaged_profile_matches_compatibility_runtime_bindings(self) -> None:
        project_root = Path(harness_package.__file__).resolve().parent.parent
        packaged = ComparatorRuntime.load_builtin_profile(
            BUILTIN_SOFTWARE_PROFILE_ID,
            external_suite_root=project_root,
            external_suite_manifest=project_root / "suite.json",
            certification_root=(
                project_root / "comparator-evidence" / BUILTIN_SOFTWARE_PROFILE_ID
            ),
            certification_name="certification.json",
        )
        compatibility = ComparatorRuntime.load(
            project_root / "skivolve/comparator_calibration"
        )
        try:
            self.assertTrue(packaged.protocol_locks_valid)
            self.assertTrue(compatibility.protocol_locks_valid)
            self.assertEqual(packaged.release_summary, compatibility.release_summary)
            self.assertEqual(
                packaged.certification.as_json(), compatibility.certification.as_json()
            )
        finally:
            packaged.close()
            compatibility.close()

    def test_load_builtin_profile_when_external_assets_are_minimal_loads_without_checkout_only_files(
        self,
    ) -> None:
        # Arrange
        project_root = Path(harness_package.__file__).resolve().parent.parent
        with tempfile.TemporaryDirectory() as temporary:
            suite_root = Path(temporary)
            suite_manifest = suite_root / "external-suite.json"
            shutil.copy2(project_root / "suite.json", suite_manifest)

            # Act
            runtime = ComparatorRuntime.load_builtin_profile(
                BUILTIN_SOFTWARE_PROFILE_ID,
                external_suite_root=suite_root,
                external_suite_manifest=suite_manifest,
                use_test_release=True,
            )
            try:
                # Assert
                self.assertTrue(runtime.protocol_locks_valid)
                self.assertFalse((suite_root / "baseline-authority.json").exists())
                self.assertFalse((suite_root / "holdout-plan.schema.json").exists())
            finally:
                runtime.close()

    def test_resolution_snapshot_is_stable_after_package_drift(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = self.copied_profile_root(Path(temporary))
            with self.profile_files_patch(root):
                profile = resolve_builtin_profile(BUILTIN_SOFTWARE_PROFILE_ID)
            original = profile.read_bytes("manifest")
            (root / "manifest.json").write_bytes(b"changed after resolution")

            self.assertEqual(profile.read_bytes("manifest"), original)
            with profile.materialize() as materialized:
                self.assertEqual(
                    (materialized / "manifest.json").read_bytes(), original
                )

    def test_unknown_profile_fails_closed(self) -> None:
        with self.assertRaisesRegex(
            ComparatorProfileError, "unknown built-in comparator profile"
        ):
            resolve_builtin_profile("unknown-v1")

    def test_authority_scope_rejects_non_string_values_cleanly(self) -> None:
        registry = json.loads(
            (
                Path(harness_package.__file__).parent
                / "comparator-profile-authority.json"
            ).read_text(encoding="utf-8")
        )
        for malformed in ({}, []):
            with self.subTest(malformed=malformed):
                payload = json.loads(json.dumps(registry))
                payload["profiles"][0]["authority_scope"] = malformed
                with (
                    patch(
                        "skivolve.comparator_profiles._read_resource_bytes",
                        return_value=self.encode(payload),
                    ),
                    self.assertRaisesRegex(
                        ComparatorProfileError, "authority binding fields"
                    ),
                ):
                    comparator_profiles._authority_binding(payload["profiles"][0]["id"])

    def test_descriptor_and_each_declared_resource_are_drift_sensitive(self) -> None:
        profile = resolve_builtin_profile(BUILTIN_SOFTWARE_PROFILE_ID)
        with tempfile.TemporaryDirectory() as temporary:
            root = self.copied_profile_root(Path(temporary))
            (root / "profile.json").write_bytes(profile.descriptor_bytes + b" ")
            with (
                self.profile_files_patch(root),
                self.assertRaisesRegex(ComparatorProfileError, "authority registry"),
            ):
                resolve_builtin_profile(BUILTIN_SOFTWARE_PROFILE_ID)

        for name, relative in profile.descriptor.resources:
            with (
                self.subTest(resource=name),
                tempfile.TemporaryDirectory() as temporary,
            ):
                root = self.copied_profile_root(Path(temporary))
                target = root.joinpath(*Path(relative).parts)
                if target.suffix == ".json" and name not in {
                    "production_release",
                    "test_release",
                }:
                    payload = json.loads(target.read_bytes())
                    payload["_drift"] = True
                    target.write_text(json.dumps(payload), encoding="utf-8")
                else:
                    target.write_bytes(target.read_bytes() + b"\n")
                with (
                    self.profile_files_patch(root),
                    self.assertRaises(ComparatorProfileError),
                ):
                    resolve_builtin_profile(BUILTIN_SOFTWARE_PROFILE_ID)

    def test_swapped_semantic_resources_fail_release_validation(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = self.copied_profile_root(Path(temporary))
            rubric = root / "rubric.json"
            response = root / "response.schema.json"
            rubric_bytes = rubric.read_bytes()
            rubric.write_bytes(response.read_bytes())
            response.write_bytes(rubric_bytes)

            with (
                self.profile_files_patch(root),
                self.assertRaisesRegex(ComparatorProfileError, "lock is stale"),
            ):
                resolve_builtin_profile(BUILTIN_SOFTWARE_PROFILE_ID)

    def test_descriptor_and_semantic_contract_must_agree(self) -> None:
        for field, value in (
            ("engine_strategy", "unknown-strategy-v1"),
            ("artifact_kinds", ["final_output_text"]),
        ):
            with self.subTest(field=field), tempfile.TemporaryDirectory() as temporary:
                root = self.copied_profile_root(Path(temporary))
                contract_path = root / "semantic-contract.json"
                contract = json.loads(contract_path.read_bytes())
                contract[field] = value
                contract_path.write_text(json.dumps(contract), encoding="utf-8")

                with (
                    self.profile_files_patch(root),
                    self.assertRaisesRegex(
                        ComparatorProfileError, "semantic engine contract"
                    ),
                ):
                    resolve_builtin_profile(BUILTIN_SOFTWARE_PROFILE_ID)

    def test_symlinked_resource_fails_during_bounded_snapshot(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = self.copied_profile_root(Path(temporary))
            manifest = root / "manifest.json"
            target = root / "manifest-target.json"
            manifest.rename(target)
            manifest.symlink_to(target.name)

            with (
                self.profile_files_patch(root),
                self.assertRaisesRegex(ComparatorProfileError, "cannot read"),
            ):
                resolve_builtin_profile(BUILTIN_SOFTWARE_PROFILE_ID)

    def test_zip_backed_traversable_resolves_and_materializes(self) -> None:
        profile_root = Path(comparator_calibration.__file__).parent
        authority_path = (
            Path(harness_package.__file__).parent / "comparator-profile-authority.json"
        )
        with tempfile.TemporaryDirectory() as temporary:
            archive_path = Path(temporary) / "resources.zip"
            with zipfile.ZipFile(archive_path, "w") as archive:
                archive.write(
                    authority_path,
                    "skivolve/comparator-profile-authority.json",
                )
                for path in profile_root.rglob("*"):
                    if path.is_file():
                        archive.write(
                            path,
                            "skivolve/comparator_calibration/"
                            + path.relative_to(profile_root).as_posix(),
                        )
            with zipfile.ZipFile(archive_path) as archive:
                comparator_root = zipfile.Path(
                    archive, "skivolve/comparator_calibration/"
                )
                harness_root = zipfile.Path(archive, "skivolve/")
                original_files = importlib_resources.files

                def files(package: object) -> object:
                    if package is comparator_calibration:
                        return comparator_root
                    if package is harness_package:
                        return harness_root
                    return original_files(package)

                with patch(
                    "skivolve.comparator_profiles.resources.files",
                    side_effect=files,
                ):
                    resolved = resolve_builtin_profile(BUILTIN_SOFTWARE_PROFILE_ID)
                    with resolved.materialize() as materialized:
                        self.assertEqual(
                            (materialized / "profile.json").read_bytes(),
                            resolved.descriptor_bytes,
                        )

    def test_descriptor_rejects_unknown_duplicate_and_nonfinite_fields(self) -> None:
        payload = self.descriptor_payload()
        payload["unknown"] = True
        with self.assertRaisesRegex(ComparatorProfileError, "fields are invalid"):
            parse_profile_descriptor(self.encode(payload))

        with self.assertRaisesRegex(ComparatorProfileError, "duplicate JSON key"):
            parse_profile_descriptor(b'{"schema_version":1,"schema_version":1}')

        with self.assertRaisesRegex(ComparatorProfileError, "non-finite"):
            parse_profile_descriptor(b'{"schema_version":NaN}')

    def test_descriptor_rejects_size_and_field_length_overflow(self) -> None:
        with self.assertRaisesRegex(ComparatorProfileError, "byte limit"):
            parse_profile_descriptor(b" " * (MAX_PROFILE_DESCRIPTOR_BYTES + 1))

        identifier = self.descriptor_payload()
        identifier["id"] = "a" * 129
        with self.assertRaisesRegex(ComparatorProfileError, "id is invalid"):
            parse_profile_descriptor(self.encode(identifier))

        path = self.descriptor_payload()
        path["resources"]["manifest"] = "a" * 256  # type: ignore[index]
        with self.assertRaisesRegex(ComparatorProfileError, "path byte limit"):
            parse_profile_descriptor(self.encode(path))

    def test_descriptor_rejects_traversal_and_path_collisions(self) -> None:
        traversal = self.descriptor_payload()
        traversal["resources"]["manifest"] = "../manifest.json"  # type: ignore[index]
        with self.assertRaisesRegex(ComparatorProfileError, "canonical relative"):
            parse_profile_descriptor(self.encode(traversal))

        reserved = self.descriptor_payload()
        reserved["resources"]["manifest"] = "profile.json"  # type: ignore[index]
        with self.assertRaisesRegex(ComparatorProfileError, "non-overlapping"):
            parse_profile_descriptor(self.encode(reserved))

        ancestor = self.descriptor_payload()
        ancestor["resources"]["production_release"] = "tests"  # type: ignore[index]
        with self.assertRaisesRegex(ComparatorProfileError, "non-overlapping"):
            parse_profile_descriptor(self.encode(ancestor))

    def test_descriptor_rejects_artifact_contract_drift(self) -> None:
        artifacts = self.descriptor_payload()
        artifacts["supported_artifact_kinds"] = ["final_output_text"]
        with self.assertRaisesRegex(ComparatorProfileError, "supported artifact kinds"):
            parse_profile_descriptor(self.encode(artifacts))


if __name__ == "__main__":
    unittest.main()
