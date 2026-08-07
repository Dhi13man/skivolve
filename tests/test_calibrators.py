from __future__ import annotations

import ast
import importlib.util
import hashlib
import json
import os
import shutil
import stat
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch
from pathlib import Path
from types import ModuleType


SUITE_ROOT = Path(__file__).resolve().parents[1]


def load_module(name: str, relative_path: str) -> ModuleType:
    spec = importlib.util.spec_from_file_location(name, SUITE_ROOT / relative_path)
    if spec is None or spec.loader is None:
        raise AssertionError(f"cannot load calibration module: {relative_path}")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


SOFTWARE = load_module("software_calibrate", "cases/software/calibrate.py")
TESTING = load_module("testing_calibrate", "cases/testing/calibrate.py")


def completed(payload: object) -> subprocess.CompletedProcess[str]:
    return subprocess.CompletedProcess(
        ["verify"], 0, stdout=json.dumps(payload), stderr=""
    )


class CalibratorVerdictContractTests(unittest.TestCase):
    def valid_payload(self) -> dict[str, object]:
        return {
            "passed": True,
            "assertions": [
                {"id": "behavior", "passed": True, "evidence": "observed output"}
            ],
            "metrics": {"runs": 1},
        }

    def test_both_calibrators_accept_the_exact_contract(self) -> None:
        for module in (SOFTWARE, TESTING):
            with self.subTest(module=module.__name__):
                self.assertEqual(
                    module.parse_verdict(completed(self.valid_payload()), "case"),
                    self.valid_payload(),
                )

    def test_both_calibrators_reject_ambiguous_payloads(self) -> None:
        invalid_payloads = [
            {
                "passed": True,
                "assertions": [
                    {"id": "behavior", "passed": True, "evidence": "first"},
                    {"id": "behavior", "passed": True, "evidence": "duplicate"},
                ],
            },
            {
                "passed": True,
                "assertions": [{"id": "behavior", "passed": True, "evidence": ""}],
            },
            {
                "passed": False,
                "assertions": [
                    {"id": "behavior", "passed": True, "evidence": "contradiction"}
                ],
            },
            {
                "passed": True,
                "assertions": [
                    {"id": "behavior", "passed": True, "evidence": "observed"}
                ],
                "unexpected": True,
            },
            {
                "passed": True,
                "assertions": [
                    {"id": "behavior", "passed": True, "evidence": "observed"}
                ],
                "metrics": [],
            },
        ]
        for module in (SOFTWARE, TESTING):
            for payload in invalid_payloads:
                with self.subTest(module=module.__name__, payload=payload):
                    with self.assertRaises(AssertionError):
                        module.parse_verdict(completed(payload), "case")


class SoftwareCalibrationExpectationTests(unittest.TestCase):
    def verdict(self, *, behavior: bool, architecture: bool) -> dict[str, object]:
        return {
            "passed": behavior and architecture,
            "assertions": [
                {"id": "behavior", "passed": behavior, "evidence": "behavior"},
                {
                    "id": "architecture",
                    "passed": architecture,
                    "evidence": "architecture",
                },
            ],
        }

    def test_expectation_binds_target_and_unrelated_assertions(self) -> None:
        expectation = {
            "must_pass": ("behavior",),
            "must_fail": ("architecture",),
        }
        SOFTWARE.assert_expectation(
            "case",
            "adversarial/extra-layer",
            self.verdict(behavior=True, architecture=False),
            expectation,
        )
        with self.assertRaisesRegex(AssertionError, "expectation mismatch"):
            SOFTWARE.assert_expectation(
                "case",
                "adversarial/extra-layer",
                self.verdict(behavior=False, architecture=False),
                expectation,
            )

    def test_expectation_rejects_unknown_assertion(self) -> None:
        with self.assertRaisesRegex(AssertionError, "unknown assertions"):
            SOFTWARE.assert_expectation(
                "case",
                "variant",
                self.verdict(behavior=True, architecture=False),
                {"must_pass": (), "must_fail": ("missing",)},
            )

    def test_expectation_must_partition_every_assertion(self) -> None:
        with self.assertRaisesRegex(AssertionError, "omits assertions"):
            SOFTWARE.assert_expectation(
                "case",
                "variant",
                self.verdict(behavior=True, architecture=False),
                {"must_pass": ("behavior",), "must_fail": ()},
            )

    def test_expectation_file_is_strict(self) -> None:
        valid = {
            "schema_version": 1,
            "must_pass": ["behavior"],
            "must_fail": ["architecture"],
        }
        invalid = [
            {**valid, "unknown": True},
            {**valid, "schema_version": 2},
            {**valid, "schema_version": True},
            {**valid, "schema_version": 1.0},
            {**valid, "must_pass": ["behavior", "behavior"]},
            {**valid, "must_fail": ["behavior"]},
            {**valid, "must_pass": [], "must_fail": []},
        ]
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / "expect.json"
            path.write_text(json.dumps(valid), encoding="utf-8")
            self.assertEqual(
                SOFTWARE.load_expectation(path),
                {
                    "must_pass": ("behavior",),
                    "must_fail": ("architecture",),
                },
            )
            for payload in invalid:
                with self.subTest(payload=payload):
                    path.write_text(json.dumps(payload), encoding="utf-8")
                    with self.assertRaises(AssertionError):
                        SOFTWARE.load_expectation(path)
            path.write_text(
                '{"schema_version":1,"schema_version":1,"must_pass":[],"must_fail":["behavior"]}',
                encoding="utf-8",
            )
            with self.assertRaises(AssertionError):
                SOFTWARE.load_expectation(path)

    def test_good_variant_discovery_requires_executable_fixtures(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            for name in ("adversarial", "bad", "good", "good-private-helpers"):
                root.joinpath(name).mkdir()
            for name in ("good", "good-private-helpers"):
                root.joinpath(name, "apply.py").write_text("", encoding="utf-8")
            self.assertEqual(
                SOFTWARE.discover_good_variants(root),
                ("good", "good-private-helpers"),
            )
            root.joinpath("good-private-helpers", "apply.py").unlink()
            with self.assertRaisesRegex(AssertionError, "lack apply.py"):
                SOFTWARE.discover_good_variants(root)

    def test_final_output_variant_discovery_requires_artifacts(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            for name in ("adversarial/verbose", "bad", "good", "good-shaped"):
                root.joinpath(name).mkdir(parents=True)
                root.joinpath(name, "artifact.json").write_text("{}", encoding="utf-8")
            self.assertEqual(
                SOFTWARE.discover_good_variants(root, "final_output_json"),
                ("good", "good-shaped"),
            )
            self.assertEqual(
                SOFTWARE.discover_variants(root, "final_output_json"),
                ("adversarial/verbose", "bad", "good", "good-shaped"),
            )
            root.joinpath("good-shaped", "artifact.json").unlink()
            with self.assertRaisesRegex(AssertionError, "lack artifact.json"):
                SOFTWARE.discover_good_variants(root, "final_output_json")

    def test_workspace_fingerprint_detects_mode_and_content_changes(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            workspace = Path(temporary)
            target = workspace / "value.txt"
            target.write_text("first\n", encoding="utf-8")
            initial = SOFTWARE.workspace_fingerprint(workspace)
            workspace.chmod(workspace.stat().st_mode | stat.S_IWGRP)
            after_root_mode = SOFTWARE.workspace_fingerprint(workspace)
            target.chmod(target.stat().st_mode | stat.S_IXUSR)
            after_mode = SOFTWARE.workspace_fingerprint(workspace)
            target.write_text("second\n", encoding="utf-8")
            after_content = SOFTWARE.workspace_fingerprint(workspace)
        self.assertNotEqual(initial, after_root_mode)
        self.assertNotEqual(after_root_mode, after_mode)
        self.assertNotEqual(after_mode, after_content)

    def test_workspace_fingerprint_frames_tree_entries(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            left = root / "left"
            right = root / "right"
            left.mkdir()
            right.mkdir()
            left_file = left / "a"
            right_file = right / "a"
            appended_file = right / "b"
            right_file.write_bytes(b"")
            appended_file.write_bytes(b"")
            left_file.write_bytes(
                b"b" + appended_file.lstat().st_mode.to_bytes(4, "big") + b"file\0"
            )

            self.assertNotEqual(
                SOFTWARE.workspace_fingerprint(left),
                SOFTWARE.workspace_fingerprint(right),
            )

    def test_expectation_opt_in_requires_every_variant(self) -> None:
        variants = ("good", "bad", "adversarial/reflection")
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            SOFTWARE.require_complete_expectations(root, variants)
            root.joinpath("good").mkdir()
            root.joinpath("good", "expect.json").write_text("{}", encoding="utf-8")
            with self.assertRaisesRegex(AssertionError, "reflection.*bad"):
                SOFTWARE.require_complete_expectations(root, variants)
            for variant in variants[1:]:
                path = root / variant / "expect.json"
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_text("{}", encoding="utf-8")
            SOFTWARE.require_complete_expectations(root, variants)

    def test_checked_in_expectation_corpora_are_complete(self) -> None:
        manifest = json.loads((SUITE_ROOT / "suite.json").read_text(encoding="utf-8"))
        opted_in: set[str] = set()
        for case in manifest["cases"]:
            if case["skill"] != "engineering":
                continue
            calibration_root = (SUITE_ROOT / case["prompt_file"]).parent / "calibration"
            variants = SOFTWARE.discover_variants(
                calibration_root, case["artifact_contract"]["kind"]
            )
            if any(
                calibration_root.joinpath(variant, "expect.json").is_file()
                for variant in variants
            ):
                opted_in.add(case["id"])
            SOFTWARE.require_complete_expectations(calibration_root, variants)
        self.assertEqual(
            opted_in,
            {
                "software-behavioral-subtyping",
                "software-domain-simplicity",
                "software-evidence-gap",
                "software-knowledge-boundary",
                "software-compatibility-decision",
                "software-root-cause-diagnosis",
                "software-secure-archive-restore",
                "software-surgical-plan",
            },
        )

    def test_final_output_corpora_have_shape_and_mutation_sensitivity(self) -> None:
        manifest = json.loads((SUITE_ROOT / "suite.json").read_text(encoding="utf-8"))
        cases = {
            case["id"]: case
            for case in manifest["cases"]
            if case["skill"] == "engineering"
            and case["artifact_contract"]["kind"] == "final_output_json"
        }
        self.assertEqual(
            set(cases),
            {
                "software-compatibility-decision",
                "software-evidence-gap",
                "software-root-cause-diagnosis",
                "software-surgical-plan",
            },
        )
        for case_id, case in cases.items():
            with self.subTest(case_id=case_id):
                calibration_root = (
                    SUITE_ROOT / case["prompt_file"]
                ).parent / "calibration"
                self.assertEqual(
                    len(
                        SOFTWARE.discover_good_variants(
                            calibration_root, "final_output_json"
                        )
                    ),
                    7,
                )
                isolated_failures = set()
                for variant in SOFTWARE.discover_variants(
                    calibration_root, "final_output_json"
                ):
                    expectation = SOFTWARE.load_expectation(
                        calibration_root / variant / "expect.json"
                    )
                    self.assertIsNotNone(expectation, variant)
                    assert expectation is not None
                    if len(expectation["must_fail"]) == 1:
                        isolated_failures.update(expectation["must_fail"])
                self.assertEqual(isolated_failures, set(case["critical_expectations"]))
                mutation = calibration_root / "adversarial/workspace-edit"
                self.assertTrue(mutation.joinpath("apply.py").is_file())

    def test_secure_archive_expectations_cover_every_critical_assertion(self) -> None:
        manifest = json.loads((SUITE_ROOT / "suite.json").read_text(encoding="utf-8"))
        case = next(
            item
            for item in manifest["cases"]
            if item["id"] == "software-secure-archive-restore"
        )
        critical = set(case["critical_expectations"])
        calibration_root = (
            SUITE_ROOT / "cases/software/secure-archive-restore/calibration"
        )
        expected_failures = {
            "adversarial/absolute-home-residue": ("path-containment",),
            "adversarial/aggregate-limit-slack": ("declared-resource-limits",),
            "adversarial/clobber-publication-race": ("publication-failure-atomicity",),
            "adversarial/delayed-256-entry-rejection": ("bounded-entry-consumption",),
            "adversarial/delayed-entry-rejection": ("bounded-entry-consumption",),
            "adversarial/destructive-existing-destination": (
                "existing-destination-preserved",
            ),
            "adversarial/duplicate-and-unbounded": (
                "duplicate-member-defense",
                "declared-resource-limits",
                "bounded-entry-consumption",
            ),
            "adversarial/external-dependency-manifest": ("standard-library-only",),
            "adversarial/import-time-destination-mutation": (
                "existing-destination-preserved",
            ),
            "adversarial/late-resource-rejection": ("declared-resource-limits",),
            "adversarial/one-way-shape-conflict": ("duplicate-member-defense",),
            "adversarial/partial-single-content-read": ("declared-resource-limits",),
            "adversarial/partial-total-content-read": ("declared-resource-limits",),
            "adversarial/publication-residue": ("publication-failure-atomicity",),
            "adversarial/raw-name-dedup": ("duplicate-member-defense",),
            "adversarial/unbounded-member-scan": ("bounded-entry-consumption",),
            "adversarial/unsupported-link": ("unsupported-member-types",),
            "adversarial/variadic-public-signature": ("public-call-contract",),
            "adversarial/write-residue": ("invalid-archive-atomicity",),
            "adversarial/wrong-return-order": ("valid-archive-behavior",),
            "bad": (
                "path-containment",
                "unsupported-member-types",
                "duplicate-member-defense",
                "declared-resource-limits",
                "bounded-entry-consumption",
                "invalid-archive-atomicity",
                "existing-destination-preserved",
                "publication-failure-atomicity",
            ),
            "good": (),
            "good-lazy-imports": (),
            "good-two-pass-custom-errors": (),
        }
        good_variants = SOFTWARE.discover_good_variants(calibration_root)
        self.assertEqual(
            good_variants,
            ("good", "good-lazy-imports", "good-two-pass-custom-errors"),
        )
        observed_failures: dict[str, tuple[str, ...]] = {}
        for apply_script in sorted(calibration_root.rglob("apply.py")):
            variant = apply_script.parent.relative_to(calibration_root).as_posix()
            expectation = SOFTWARE.load_expectation(
                apply_script.with_name("expect.json")
            )
            self.assertIsNotNone(expectation, variant)
            assert expectation is not None
            self.assertEqual(
                set(expectation["must_pass"]) | set(expectation["must_fail"]),
                critical,
                variant,
            )
            observed_failures[variant] = expectation["must_fail"]
        self.assertEqual(observed_failures, expected_failures)
        self.assertEqual(
            {item for failures in observed_failures.values() for item in failures},
            critical,
        )


class SoftwareOracleTimeoutBudgetTests(unittest.TestCase):
    def test_behavioral_outer_budget_covers_every_bounded_child(self) -> None:
        suite = json.loads((SUITE_ROOT / "suite.json").read_text(encoding="utf-8"))
        outer = next(
            case["verifier"]["timeout_seconds"]
            for case in suite["cases"]
            if case["id"] == "software-behavioral-subtyping"
        )
        tree = ast.parse(
            (
                SUITE_ROOT / "cases/software/behavioral-subtyping/oracle/verify.py"
            ).read_text(encoding="utf-8")
        )
        child_timeout = next(
            node.value.value
            for node in tree.body
            if isinstance(node, ast.Assign)
            and len(node.targets) == 1
            and isinstance(node.targets[0], ast.Name)
            and node.targets[0].id == "CHILD_TIMEOUT_SECONDS"
            and isinstance(node.value, ast.Constant)
            and type(node.value.value) is int
        )
        child_calls = [
            node
            for node in ast.walk(tree)
            if isinstance(node, ast.Call)
            and isinstance(node.func, ast.Name)
            and node.func.id == "execute_order"
        ]
        untrusted_calls = [
            node
            for node in ast.walk(tree)
            if isinstance(node, ast.Call)
            and isinstance(node.func, ast.Name)
            and node.func.id == "run_untrusted"
        ]
        self.assertEqual(len(child_calls), 3)
        self.assertEqual(len(untrusted_calls), 1)
        self.assertIsInstance(untrusted_calls[0].args[2], ast.Name)
        self.assertEqual(
            untrusted_calls[0].args[2].id,
            "CHILD_TIMEOUT_SECONDS",
        )
        self.assertEqual(outer, len(child_calls) * child_timeout + 16)

    def test_multi_scenario_outer_budgets_cover_bounded_children(self) -> None:
        suite = json.loads((SUITE_ROOT / "suite.json").read_text(encoding="utf-8"))
        outer = {
            case["id"]: case["verifier"]["timeout_seconds"]
            for case in suite["cases"]
            if case["id"]
            in {
                "software-secure-archive-restore",
                "software-transactional-event-intent",
            }
        }
        agent = {
            case["id"]: case["timeout_seconds"]
            for case in suite["cases"]
            if case["id"] in outer
        }

        secure_tree = ast.parse(
            (
                SUITE_ROOT / "cases/software/secure-archive-restore/oracle/verify.py"
            ).read_text(encoding="utf-8")
        )
        transaction_tree = ast.parse(
            (
                SUITE_ROOT
                / "cases/software/transactional-event-intent/oracle/verify.py"
            ).read_text(encoding="utf-8")
        )

        def integer_assignment(tree: ast.Module, name: str) -> int:
            values = [
                node.value.value
                for node in tree.body
                if isinstance(node, ast.Assign)
                and len(node.targets) == 1
                and isinstance(node.targets[0], ast.Name)
                and node.targets[0].id == name
                and isinstance(node.value, ast.Constant)
                and isinstance(node.value.value, int)
            ]
            self.assertEqual(len(values), 1)
            return values[0]

        def assert_child_constant(tree: ast.Module) -> None:
            child_arguments = [
                node.args[2].id
                for node in ast.walk(tree)
                if isinstance(node, ast.Call)
                and isinstance(node.func, ast.Name)
                and node.func.id == "run_untrusted"
                and len(node.args) >= 3
                and isinstance(node.args[2], ast.Name)
            ]
            self.assertEqual(child_arguments, ["CHILD_TIMEOUT_SECONDS"])

        secure_child = integer_assignment(secure_tree, "CHILD_TIMEOUT_SECONDS")
        transaction_child = integer_assignment(
            transaction_tree, "CHILD_TIMEOUT_SECONDS"
        )
        assert_child_constant(secure_tree)
        assert_child_constant(transaction_tree)

        secure_attack_counts = {
            node.target.id: len(node.value.elts)
            for node in secure_tree.body
            if isinstance(node, ast.AnnAssign)
            and isinstance(node.target, ast.Name)
            and node.target.id.endswith("_ATTACKS")
            and isinstance(node.value, ast.List)
        }
        self.assertEqual(
            secure_attack_counts,
            {
                "DUPLICATE_ATTACKS": 4,
                "PATH_ATTACKS": 2,
                "RESOURCE_ATTACKS": 3,
                "UNSUPPORTED_ATTACKS": 4,
            },
        )
        secure_direct_scenarios = sum(
            isinstance(node, (ast.Assign, ast.AnnAssign))
            and isinstance(node.value, ast.Call)
            and isinstance(node.value.func, ast.Name)
            and node.value.func.id == "exercise_restore"
            for node in secure_tree.body
        )
        self.assertEqual(secure_direct_scenarios, 10)
        secure_overhead = integer_assignment(
            secure_tree, "VERIFIER_TIMEOUT_OVERHEAD_SECONDS"
        )
        entry_probe_members = integer_assignment(secure_tree, "ENTRY_PROBE_MEMBERS")
        entry_probe_read_chars = integer_assignment(
            secure_tree, "MAX_ENTRY_PROBE_READ_CHARS"
        )
        entry_probe_read_delta = integer_assignment(
            secure_tree, "MAX_ENTRY_PROBE_READ_DELTA"
        )
        oversize_probe_read_chars = integer_assignment(
            secure_tree, "MAX_OVERSIZE_PROBE_READ_CHARS"
        )
        total_probe_read_chars = integer_assignment(
            secure_tree, "MAX_TOTAL_PROBE_READ_CHARS"
        )
        self.assertEqual(entry_probe_members, 8_192)
        self.assertEqual(entry_probe_read_chars, 131_072)
        self.assertEqual(entry_probe_read_delta, 16_384)
        self.assertEqual(oversize_probe_read_chars, 65_536)
        self.assertEqual(total_probe_read_chars, 4_259_840)
        self.assertGreaterEqual(entry_probe_members * 512, entry_probe_read_chars * 16)
        transaction_scenarios = sum(
            isinstance(node, ast.Assign)
            and isinstance(node.value, ast.Call)
            and isinstance(node.value.func, ast.Name)
            and node.value.func.id == "run_scenario"
            for node in transaction_tree.body
        )
        self.assertEqual(
            outer,
            {
                "software-secure-archive-restore": (
                    sum(secure_attack_counts.values()) + secure_direct_scenarios
                )
                * secure_child
                + secure_overhead,
                "software-transactional-event-intent": transaction_scenarios
                * transaction_child
                + 10,
            },
        )
        self.assertEqual(
            agent,
            {
                "software-secure-archive-restore": 300,
                "software-transactional-event-intent": 300,
            },
        )
        self.assertGreater(
            outer["software-secure-archive-restore"],
            agent["software-secure-archive-restore"],
        )


class CalibratorToolBundleTests(unittest.TestCase):
    def test_verifier_environments_exclude_ambient_state(self) -> None:
        with SOFTWARE.private_tool_environment() as tool_environment:
            with patch.dict(
                os.environ,
                {
                    "CALIBRATION_SENTINEL_SECRET": "must-not-leak",
                    "EVAL_AMBIENT_SENTINEL": "must-not-leak",
                    "GOFLAGS": "-mod=vendor",
                },
                clear=False,
            ):
                environments = (
                    module.verifier_environment(
                        Path("/tmp/calibration-workspace"),
                        Path("/tmp/calibration-case"),
                        tool_environment,
                    )
                    for module in (SOFTWARE, TESTING)
                )
                for environment in environments:
                    self.assertNotIn("CALIBRATION_SENTINEL_SECRET", environment)
                    self.assertNotIn("EVAL_AMBIENT_SENTINEL", environment)
                    self.assertNotIn("GOFLAGS", environment)
                    self.assertEqual(environment["GOTOOLCHAIN"], "local")
                    self.assertEqual(environment["LANG"], "C.UTF-8")
                    self.assertEqual(environment["LC_ALL"], "C.UTF-8")
                    self.assertEqual(environment["TZ"], "UTC")
                    for variable in (
                        "EVAL_ENV",
                        "EVAL_MOUNT",
                        "EVAL_SETPRIV",
                        "EVAL_UNSHARE",
                    ):
                        self.assertTrue(Path(environment[variable]).is_absolute())

    def test_private_bundle_contains_the_closed_declared_toolchain(self) -> None:
        expected_sources = {
            "as": shutil.which("as"),
            "gcc": shutil.which("gcc"),
            "go": shutil.which("go"),
            "ld": shutil.which("ld"),
            "node": shutil.which("node"),
            "python3": sys.executable,
        }
        if any(path is None for path in expected_sources.values()):
            self.skipTest("complete calibration toolchain is unavailable")

        with SOFTWARE.private_tool_environment() as environment:
            tool_bin = Path(environment["EVAL_TOOL_BIN"])
            bundle_root = tool_bin.parent
            self.assertEqual(environment["PATH"], str(tool_bin))
            self.assertEqual(environment["GOROOT"], environment["EVAL_GO_ROOT"])
            self.assertEqual(
                environment["GCC_EXEC_PREFIX"],
                environment["EVAL_GCC_EXEC_PREFIX"],
            )
            self.assertEqual(environment["COMPILER_PATH"], str(tool_bin))
            self.assertEqual(
                {path.name for path in tool_bin.iterdir()},
                {
                    "as",
                    "cc1",
                    "collect2",
                    "gcc",
                    "go",
                    "ld",
                    "lto-wrapper",
                    "node",
                    "python3",
                },
            )
            for variable in ("GOCACHE", "GOMODCACHE", "TMPDIR"):
                private_directory = Path(environment[variable])
                self.assertTrue(private_directory.is_relative_to(bundle_root))
                metadata = private_directory.lstat()
                self.assertTrue(stat.S_ISDIR(metadata.st_mode))
                self.assertEqual(stat.S_IMODE(metadata.st_mode), 0o700)
            for name, raw_source in expected_sources.items():
                source = Path(str(raw_source)).resolve(strict=True)
                bundled = tool_bin / name
                metadata = bundled.lstat()
                self.assertTrue(stat.S_ISREG(metadata.st_mode))
                self.assertEqual(stat.S_IMODE(metadata.st_mode), 0o500)
                with bundled.open("rb") as bundled_file:
                    bundled_digest = hashlib.file_digest(
                        bundled_file, "sha256"
                    ).digest()
                with source.open("rb") as source_file:
                    source_digest = hashlib.file_digest(source_file, "sha256").digest()
                self.assertEqual(
                    bundled_digest,
                    source_digest,
                )
            for command in (
                [str(tool_bin / "python3"), "--version"],
                [str(tool_bin / "node"), "--version"],
                [str(tool_bin / "go"), "version"],
                [str(tool_bin / "gcc"), "--version"],
            ):
                completed_process = subprocess.run(
                    command,
                    capture_output=True,
                    text=True,
                    timeout=10,
                    check=False,
                    shell=False,
                    env=environment,
                )
                self.assertEqual(
                    completed_process.returncode,
                    0,
                    completed_process.stdout + completed_process.stderr,
                )
            go_environment = subprocess.run(
                [str(tool_bin / "go"), "env", "GOCACHE", "GOMODCACHE"],
                capture_output=True,
                text=True,
                timeout=10,
                check=False,
                shell=False,
                env=environment,
            )
            self.assertEqual(
                go_environment.returncode,
                0,
                go_environment.stdout + go_environment.stderr,
            )
            self.assertEqual(
                go_environment.stdout.splitlines(),
                [environment["GOCACHE"], environment["GOMODCACHE"]],
            )
            python_temporary = subprocess.run(
                [
                    str(tool_bin / "python3"),
                    "-c",
                    "import tempfile; print(tempfile.gettempdir())",
                ],
                capture_output=True,
                text=True,
                timeout=10,
                check=False,
                shell=False,
                env=environment,
            )
            self.assertEqual(
                python_temporary.returncode,
                0,
                python_temporary.stdout + python_temporary.stderr,
            )
            self.assertEqual(python_temporary.stdout.strip(), environment["TMPDIR"])
        self.assertFalse(bundle_root.exists())


if __name__ == "__main__":
    unittest.main()
