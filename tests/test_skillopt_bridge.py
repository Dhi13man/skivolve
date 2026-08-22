from __future__ import annotations

import copy
import json
import os
import shutil
import subprocess
import sys
import tempfile
import time
import unittest
from dataclasses import replace
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

from skivolve import optimize_cli
from skivolve import skillopt_codex_proxy
from skivolve import skillopt_sidecar
from skivolve.skillopt_bridge import (
    COMPARISON_ID,
    FITNESS_COMPARISON_ID,
    MAX_CANDIDATE_BYTES,
    MAX_COMMAND_INPUT_BYTES,
    MAX_COMMAND_OUTPUT_BYTES,
    SKILLOPT_COMMIT,
    PilotPlan,
    SkillOptBridgeError,
    _environment_sha256,
    _evaluation_inputs_sha256,
    _resolve_output_directory,
    candidate_snapshot_sha256,
    clone_candidate,
    derived_suite_payload,
    frontmatter_bytes,
    git_blob_bytes,
    invoke_skivolve,
    plan_from_json,
    private_write_bytes,
    private_write_json,
    run_command,
    sha256_bytes,
    sha256_file,
    validate_candidate,
    validate_skillopt_checkout,
)


_BASE_SKILL = b"---\nname: testing\ndescription: stable\n---\n\n# Testing\n\nSeed.\n"


class SkillOptBridgeContractTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name)
        self.suite = self.root / "suite.json"
        self.suite.write_text("{}\n", encoding="utf-8")
        self.repository = self.root / "repository"
        self.repository.mkdir()
        self.skillopt = self.root / "SkillOpt"
        self.skillopt.mkdir()
        self.python = Path(sys.executable).resolve()
        self.output = self.root / "output"
        self.plan = PilotPlan(
            suite_path=self.suite.resolve(),
            repository_root=self.repository.resolve(),
            skill="testing",
            bundle_source=Path("skills/testing"),
            skill_path=Path("skills/testing/SKILL.md"),
            baseline_commit="a" * 40,
            train_case_ids=("train-a",),
            selection_case_ids=("selection-a",),
            validation_case_ids=("validation-a",),
            seed=42,
            optimizer_model="gpt-5.6",
            optimizer_executable=self.python,
            optimizer_sandbox=self.python,
            output_dir=self.output,
            skillopt_source=self.skillopt.resolve(),
            skillopt_python=self.python,
            skillopt_environment=self.python.parent,
            skivolve_python=self.python,
            timeout_seconds=3600,
        )

    def tearDown(self) -> None:
        self.temporary.cleanup()

    def test_plan_round_trip_binds_fixed_policy_and_call_count(self) -> None:
        self.output.mkdir()
        value = self.plan.as_json()

        parsed = plan_from_json(value)

        self.assertEqual(parsed.baseline_commit, "a" * 40)
        self.assertEqual(parsed.selection_case_ids, ("selection-a",))
        self.assertEqual(value["planned_generator_calls"], 24)
        self.assertFalse(value["holdout_used"])
        self.assertFalse(value["automatic_adoption"])

    def test_plan_rejects_multi_case_selection_gate(self) -> None:
        self.output.mkdir()
        value = copy.deepcopy(self.plan.as_json())
        value["selection_case_ids"] = ["selection-a", "selection-b"]
        value["planned_generator_calls"] = 30

        with self.assertRaisesRegex(SkillOptBridgeError, "exactly one selection"):
            plan_from_json(value)

    def test_plan_rejects_unknown_and_changed_policy_fields(self) -> None:
        self.output.mkdir()
        unknown = copy.deepcopy(self.plan.as_json())
        unknown["surprise"] = True
        changed = copy.deepcopy(self.plan.as_json())
        changed["optimizer"]["use_semantic_density"] = True

        with self.assertRaisesRegex(SkillOptBridgeError, "fields do not match"):
            plan_from_json(unknown)
        with self.assertRaisesRegex(SkillOptBridgeError, "forbidden field"):
            plan_from_json(changed)

    @unittest.skipUnless(os.name == "posix", "PrivateTmp paths are POSIX-only")
    def test_output_rejects_private_tmp_roots_before_execution(self) -> None:
        with self.assertRaisesRegex(SkillOptBridgeError, "PrivateTmp"):
            _resolve_output_directory(
                Path(f"/tmp/skivolve-skillopt-test-output-{os.getpid()}")
            )

    def test_candidate_preserves_exact_frontmatter_and_bounds(self) -> None:
        accepted = _BASE_SKILL.replace(b"Seed.", b"Candidate guidance.")
        changed_frontmatter = _BASE_SKILL.replace(b"name: testing", b"name: other")

        self.assertEqual(validate_candidate(accepted, _BASE_SKILL), accepted.decode())
        self.assertTrue(frontmatter_bytes(accepted).endswith(b"---\n"))
        with self.assertRaisesRegex(SkillOptBridgeError, "frontmatter"):
            validate_candidate(changed_frontmatter, _BASE_SKILL)
        with self.assertRaisesRegex(SkillOptBridgeError, "1.."):
            validate_candidate(b"x" * (MAX_CANDIDATE_BYTES + 1), _BASE_SKILL)

    def test_run_artifact_semantics_bind_exact_candidate(self) -> None:
        candidate_commit = "b" * 40
        candidate_sha256 = "c" * 64
        run = {
            "dry_run": False,
            "passed": True,
            "pairs": [
                {
                    "comparison_id": COMPARISON_ID,
                    "case_id": "validation-a",
                    "repetition": repetition,
                    "arms": {
                        "treatment": {
                            "source": {
                                "source_commit": candidate_commit,
                                "skill_snapshot_sha256": candidate_sha256,
                            }
                        }
                    },
                }
                for repetition in range(3)
            ],
        }

        pairs = optimize_cli._validate_run_artifact(
            run=run,
            exit_code=0,
            expected_cases=("validation-a",),
            comparison_id=COMPARISON_ID,
            candidate_commit=candidate_commit,
            candidate_snapshot_sha256=candidate_sha256,
            label="candidate certification",
        )
        self.assertEqual(len(pairs["validation-a"]), 3)

        run["pairs"][0]["arms"]["treatment"]["source"]["source_commit"] = "d" * 40
        with self.assertRaisesRegex(SkillOptBridgeError, "provenance drifted"):
            optimize_cli._validate_run_artifact(
                run=run,
                exit_code=0,
                expected_cases=("validation-a",),
                comparison_id=COMPARISON_ID,
                candidate_commit=candidate_commit,
                candidate_snapshot_sha256=candidate_sha256,
                label="candidate certification",
            )

    def test_skillopt_checkout_requires_exact_clean_official_source(self) -> None:
        answers = {
            ("rev-parse", "--show-toplevel"): str(self.skillopt.resolve()),
            ("rev-parse", "HEAD"): SKILLOPT_COMMIT,
            ("status", "--porcelain=v1", "--untracked-files=all"): "",
            ("remote", "get-url", "origin"): "git@github.com:microsoft/SkillOpt.git",
        }

        with patch(
            "skivolve.skillopt_bridge.git_output",
            side_effect=lambda _repository, *arguments: answers[arguments],
        ):
            binding = validate_skillopt_checkout(self.skillopt)

        self.assertEqual(binding["commit"], SKILLOPT_COMMIT)

    def test_live_cli_requires_explicit_quota_acknowledgement(self) -> None:
        with patch("skivolve.optimize_cli.build_plan") as build:
            exit_code = optimize_cli.main(
                [
                    "--skill",
                    "testing",
                    "--skillopt-source",
                    str(self.skillopt),
                    "--skillopt-python",
                    str(self.python),
                    "--output-dir",
                    str(self.output),
                ]
            )

        self.assertEqual(exit_code, 2)
        build.assert_not_called()

    def _inner_record(
        self,
        *,
        ordinal: int,
        phase: str,
        candidate_sha256: str,
        case_ids: tuple[str, ...],
        passed: bool = False,
    ) -> dict[str, object]:
        candidate_commit = candidate_sha256[:40]
        run_path = self.output / f"run-{ordinal}.json"
        pairs = [
            {
                "comparison_id": FITNESS_COMPARISON_ID,
                "case_id": case_id,
                "repetition": repetition,
                "completed": True,
                "arms": {
                    "treatment": {
                        "status": "completed",
                        "passed": passed,
                        "critical_results": {"a": passed},
                        "source": {
                            "source_commit": candidate_commit,
                            "skill_snapshot_sha256": candidate_sha256,
                        },
                    }
                },
            }
            for case_id in case_ids
            for repetition in range(3)
        ]
        run_path.write_text(
            json.dumps({"dry_run": False, "passed": passed, "pairs": pairs}),
            encoding="utf-8",
        )
        return {
            "ordinal": ordinal,
            "phase": phase,
            "candidate_sha256": candidate_sha256,
            "candidate_skill": f"candidate-{ordinal}.skill.md",
            "candidate_snapshot_sha256": candidate_sha256,
            "candidate_commit": candidate_commit,
            "case_ids": list(case_ids),
            "split": "train",
            "skivolve_exit_code": 0 if passed else 1,
            "run_json": str(run_path.relative_to(self.output)),
            "run_json_sha256": sha256_file(run_path),
            "scores": [
                {"id": case_id, "hard": int(passed), "soft": float(passed)}
                for case_id in case_ids
            ],
        }

    @staticmethod
    def _candidate_bindings(
        records: list[dict[str, object]],
    ) -> dict[str, tuple[str, str]]:
        return {
            str(record["candidate_sha256"]): (
                str(record["candidate_commit"]),
                str(record["candidate_snapshot_sha256"]),
            )
            for record in records
        }

    @staticmethod
    def _trainer_summary(*, changed: bool) -> dict[str, object]:
        return {
            "config": {"num_epochs": 1, "eval_test": False},
            "baseline_selection_hard": 0.0,
            "best_selection_hard": 1.0 if changed else 0.0,
            "best_step": 1 if changed else 0,
            "total_steps": 1,
            "total_accepts": int(changed),
            "baseline_test_hard": None,
            "test_hard": None,
            "final_test_hard": None,
        }

    def test_inner_provenance_accepts_exact_two_run_no_change(self) -> None:
        self.output.mkdir()
        initial = sha256_bytes(_BASE_SKILL)
        records = [
            self._inner_record(
                ordinal=0,
                phase="baseline_selection",
                candidate_sha256=initial,
                case_ids=self.plan.selection_case_ids,
            ),
            self._inner_record(
                ordinal=1,
                phase="training",
                candidate_sha256=initial,
                case_ids=self.plan.train_case_ids,
            ),
        ]

        optimize_cli._validate_inner_runs(
            plan=self.plan,
            value=records,
            initial_sha256=initial,
            best_sha256=initial,
            trainer_summary=self._trainer_summary(changed=False),
            critical_expectations={"selection-a": ("a",), "train-a": ("a",)},
            candidate_bindings=self._candidate_bindings(records),
        )

    def test_inner_provenance_binds_changed_best_to_selection(self) -> None:
        self.output.mkdir()
        initial = sha256_bytes(_BASE_SKILL)
        changed = sha256_bytes(_BASE_SKILL.replace(b"Seed.", b"Changed."))
        records = [
            self._inner_record(
                ordinal=0,
                phase="baseline_selection",
                candidate_sha256=initial,
                case_ids=self.plan.selection_case_ids,
            ),
            self._inner_record(
                ordinal=1,
                phase="training",
                candidate_sha256=initial,
                case_ids=self.plan.train_case_ids,
            ),
        ]
        with self.assertRaisesRegex(SkillOptBridgeError, "omitted candidate"):
            optimize_cli._validate_inner_runs(
                plan=self.plan,
                value=records,
                initial_sha256=initial,
                best_sha256=changed,
                trainer_summary=self._trainer_summary(changed=True),
                critical_expectations={
                    "selection-a": ("a",),
                    "train-a": ("a",),
                },
                candidate_bindings=self._candidate_bindings(records),
            )

        records.append(
            self._inner_record(
                ordinal=2,
                phase="candidate_selection",
                candidate_sha256=changed,
                case_ids=self.plan.selection_case_ids,
                passed=True,
            )
        )
        optimize_cli._validate_inner_runs(
            plan=self.plan,
            value=records,
            initial_sha256=initial,
            best_sha256=changed,
            trainer_summary=self._trainer_summary(changed=True),
            critical_expectations={"selection-a": ("a",), "train-a": ("a",)},
            candidate_bindings=self._candidate_bindings(records),
        )

    def test_inner_provenance_rejects_artifact_hash_drift(self) -> None:
        self.output.mkdir()
        initial = sha256_bytes(_BASE_SKILL)
        records = [
            self._inner_record(
                ordinal=0,
                phase="baseline_selection",
                candidate_sha256=initial,
                case_ids=self.plan.selection_case_ids,
            ),
            self._inner_record(
                ordinal=1,
                phase="training",
                candidate_sha256=initial,
                case_ids=self.plan.train_case_ids,
            ),
        ]
        records[1]["run_json_sha256"] = "0" * 64

        with self.assertRaisesRegex(SkillOptBridgeError, "hash"):
            optimize_cli._validate_inner_runs(
                plan=self.plan,
                value=records,
                initial_sha256=initial,
                best_sha256=initial,
                trainer_summary=self._trainer_summary(changed=False),
                critical_expectations={
                    "selection-a": ("a",),
                    "train-a": ("a",),
                },
                candidate_bindings=self._candidate_bindings(records),
            )

    def test_inner_provenance_rejects_forged_objective_score(self) -> None:
        self.output.mkdir()
        initial = sha256_bytes(_BASE_SKILL)
        records = [
            self._inner_record(
                ordinal=0,
                phase="baseline_selection",
                candidate_sha256=initial,
                case_ids=self.plan.selection_case_ids,
            ),
            self._inner_record(
                ordinal=1,
                phase="training",
                candidate_sha256=initial,
                case_ids=self.plan.train_case_ids,
            ),
        ]
        records[0]["scores"] = [{"id": "selection-a", "hard": 1, "soft": 1.0}]

        with self.assertRaisesRegex(SkillOptBridgeError, "objective run evidence"):
            optimize_cli._validate_inner_runs(
                plan=self.plan,
                value=records,
                initial_sha256=initial,
                best_sha256=initial,
                trainer_summary=self._trainer_summary(changed=False),
                critical_expectations={
                    "selection-a": ("a",),
                    "train-a": ("a",),
                },
                candidate_bindings=self._candidate_bindings(records),
            )

    def test_inner_provenance_accepts_a_rejected_candidate(self) -> None:
        self.output.mkdir()
        initial = sha256_bytes(_BASE_SKILL)
        rejected = sha256_bytes(_BASE_SKILL.replace(b"Seed.", b"Rejected."))
        records = [
            self._inner_record(
                ordinal=0,
                phase="baseline_selection",
                candidate_sha256=initial,
                case_ids=self.plan.selection_case_ids,
            ),
            self._inner_record(
                ordinal=1,
                phase="training",
                candidate_sha256=initial,
                case_ids=self.plan.train_case_ids,
            ),
            self._inner_record(
                ordinal=2,
                phase="candidate_selection",
                candidate_sha256=rejected,
                case_ids=self.plan.selection_case_ids,
            ),
        ]

        optimize_cli._validate_inner_runs(
            plan=self.plan,
            value=records,
            initial_sha256=initial,
            best_sha256=initial,
            trainer_summary=self._trainer_summary(changed=False),
            critical_expectations={"selection-a": ("a",), "train-a": ("a",)},
            candidate_bindings=self._candidate_bindings(records),
        )

    def test_sidecar_environment_does_not_forward_pythonpath(self) -> None:
        with patch.dict(os.environ, {"PYTHONPATH": "sentinel", "HOME": "kept"}):
            environment = optimize_cli._sidecar_environment(self.root)

        self.assertNotIn("PYTHONPATH", environment)
        self.assertEqual(environment["HOME"], "kept")

    @unittest.skipUnless(os.name == "posix", "symlink semantics are POSIX-only")
    def test_environment_binding_tracks_external_symlink_target_bytes(self) -> None:
        environment = self.root / "environment"
        environment.mkdir()
        target = self.root / "python"
        target.write_bytes(b"first")
        (environment / "python").symlink_to(target)

        first = _environment_sha256(environment)
        target.write_bytes(b"second")

        self.assertNotEqual(first, _environment_sha256(environment))

    def test_environment_binding_bounds_empty_directory_traversal(self) -> None:
        environment = self.root / "environment"
        environment.mkdir()
        for name in ("a", "b", "c"):
            (environment / name).mkdir()

        with (
            patch("skivolve.skillopt_bridge.MAX_ENVIRONMENT_FILES", 2),
            self.assertRaisesRegex(SkillOptBridgeError, "exceeds 2 entries"),
        ):
            _environment_sha256(environment)

    def test_evaluation_input_binding_bounds_empty_directories(self) -> None:
        fixture = self.root / "fixture"
        fixture.mkdir()
        for name in ("a", "b", "c"):
            (fixture / name).mkdir()
        suite = SimpleNamespace(
            root=self.root,
            path=self.suite,
            shared_verifier_dir=None,
        )
        case = SimpleNamespace(
            prompt_file=self.suite,
            fixture_dir=fixture,
            verifier=SimpleNamespace(argv=()),
        )

        with (
            patch("skivolve.skillopt_bridge.MAX_EVALUATION_INPUT_ENTRIES", 3),
            self.assertRaisesRegex(SkillOptBridgeError, "exceed 3 entries"),
        ):
            _evaluation_inputs_sha256(suite, (case,))

    def test_evaluation_input_binding_bounds_total_bytes(self) -> None:
        fixture = self.root / "fixture"
        fixture.mkdir()
        suite = SimpleNamespace(
            root=self.root,
            path=self.suite,
            shared_verifier_dir=None,
        )
        case = SimpleNamespace(
            prompt_file=self.suite,
            fixture_dir=fixture,
            verifier=SimpleNamespace(argv=()),
        )

        with (
            patch("skivolve.skillopt_bridge.MAX_EVALUATION_INPUT_BYTES", 2),
            self.assertRaisesRegex(SkillOptBridgeError, "exceed 2 bytes"),
        ):
            _evaluation_inputs_sha256(suite, (case,))

    def test_private_artifact_writers_complete_short_writes(self) -> None:
        real_write = os.write

        def short_write(descriptor: int, value: bytes) -> int:
            return real_write(descriptor, value[:3])

        bytes_path = self.root / "bytes.bin"
        json_path = self.root / "value.json"
        with patch("skivolve.skillopt_bridge.os.write", side_effect=short_write):
            private_write_bytes(bytes_path, b"abcdefghij")
            private_write_json(json_path, {"value": "abcdefghij"})

        self.assertEqual(bytes_path.read_bytes(), b"abcdefghij")
        self.assertEqual(
            json.loads(json_path.read_text(encoding="utf-8")),
            {"value": "abcdefghij"},
        )

    def test_private_artifact_writer_rejects_zero_progress(self) -> None:
        with (
            patch("skivolve.skillopt_bridge.os.write", return_value=0),
            self.assertRaisesRegex(SkillOptBridgeError, "made no progress"),
        ):
            private_write_bytes(self.root / "partial.bin", b"payload")

    def test_skivolve_invocation_cannot_import_from_candidate_checkout(self) -> None:
        completed = subprocess.CompletedProcess(
            args=[],
            returncode=0,
            stdout='{"dry_run":true}',
            stderr="",
        )
        with patch(
            "skivolve.skillopt_bridge.run_command", return_value=completed
        ) as execute:
            exit_code, summary = invoke_skivolve(
                python=self.python,
                suite_path=self.suite,
                split="train",
                case_ids=("case-a",),
                output_dir=None,
                timeout_seconds=30,
                dry_run=True,
            )

        argv = execute.call_args.args[0]
        self.assertEqual(tuple(argv[:4]), (self.python, "-I", "-m", "skivolve"))
        self.assertEqual(execute.call_args.kwargs["cwd"], self.suite.parent)
        self.assertEqual(exit_code, 0)
        self.assertTrue(summary["dry_run"])

    def test_generated_manifest_preflight_fails_closed_on_nonzero_result(self) -> None:
        suite = SimpleNamespace()
        with (
            patch(
                "skivolve.optimize_cli.revalidate_plan",
                return_value=(suite, _BASE_SKILL, {}),
            ),
            patch("skivolve.optimize_cli.clone_candidate", return_value="b" * 40),
            patch("skivolve.optimize_cli.write_derived_suite", return_value=self.suite),
            patch(
                "skivolve.optimize_cli.invoke_skivolve",
                return_value=(
                    1,
                    {
                        "dry_run": True,
                        "preflight": {"plan": {"pair_runs": 3}},
                    },
                ),
            ),
        ):
            with self.assertRaisesRegex(SkillOptBridgeError, "failed closed"):
                optimize_cli._preflight_skivolve(self.plan)

    def test_evaluation_input_binding_is_prompt_and_fixture_sensitive(self) -> None:
        prompt = self.root / "prompt.md"
        fixture = self.root / "fixture"
        verifier = self.root / "verify.py"
        prompt.write_text("first\n", encoding="utf-8")
        fixture.mkdir()
        (fixture / "input.txt").write_text("fixture\n", encoding="utf-8")
        verifier.write_text("raise SystemExit(0)\n", encoding="utf-8")
        suite = SimpleNamespace(
            root=self.root,
            path=self.suite,
            shared_verifier_dir=None,
        )
        case = SimpleNamespace(
            prompt_file=prompt,
            fixture_dir=fixture,
            verifier=SimpleNamespace(argv=("python3", "verify.py")),
        )
        original = optimize_cli.sha256_bytes(
            optimize_cli.canonical_bytes(self.plan.as_json())
        )
        first = _evaluation_inputs_sha256(suite, (case,))

        prompt.write_text("second\n", encoding="utf-8")
        second = _evaluation_inputs_sha256(suite, (case,))
        changed_plan = copy.deepcopy(self.plan.as_json())
        changed_plan["bindings"]["evaluation_inputs_sha256"] = second

        self.assertNotEqual(first, second)
        self.assertNotEqual(
            original,
            optimize_cli.sha256_bytes(optimize_cli.canonical_bytes(changed_plan)),
        )

    @unittest.skipUnless(os.name == "posix", "Codex proxy is POSIX-only")
    def test_codex_proxy_invocation_ledger_fails_closed_at_budget(self) -> None:
        ledger = self.root / "codex-invocations.txt"
        self.assertEqual(skillopt_codex_proxy._claim_invocation(ledger, 1), 1)
        with self.assertRaisesRegex(SkillOptBridgeError, "budget exhausted"):
            skillopt_codex_proxy._claim_invocation(ledger, 1)
        self.assertEqual(ledger.read_text(encoding="ascii"), "1\n")

    @unittest.skipUnless(
        os.name == "posix" and shutil.which("bwrap"),
        "Bubblewrap integration is unavailable",
    )
    def test_codex_proxy_forwards_prompt_and_run_owned_temp_only(self) -> None:
        self.output.mkdir()
        proxy_bin = self.output / "optimizer-bin"
        proxy_bin.mkdir()
        optimizer_tmp = self.output / "optimizer-tmp"
        optimizer_tmp.mkdir()
        schema = optimizer_tmp / "schema.json"
        schema.write_text('{"type":"object"}\n', encoding="utf-8")
        last_message = optimizer_tmp / "last-message.json"
        auth = self.root / "auth.json"
        auth.write_text('{"tokens":{}}\n', encoding="utf-8")
        config = self.output / "optimizer-config.toml"
        config.write_text('model = "fixture"\n', encoding="utf-8")
        secret = self.root / "must-not-be-mounted"
        secret.write_text("secret\n", encoding="utf-8")
        fake_codex = self.root / "fake-codex"
        fake_codex.write_text(
            "#!/usr/bin/python3\n"
            "import json, sys\n"
            "from pathlib import Path\n"
            "args = sys.argv[1:]\n"
            "schema = Path(args[args.index('--output-schema') + 1])\n"
            "json.loads(schema.read_text())\n"
            "last = Path(args[args.index('--output-last-message') + 1])\n"
            f"secret_visible = Path({str(secret)!r}).exists()\n"
            "last.write_text(json.dumps({'prompt': sys.stdin.read(), "
            "'secret_visible': secret_visible}))\n",
            encoding="utf-8",
        )
        fake_codex.chmod(0o700)
        sandbox = Path(shutil.which("bwrap") or "").resolve(strict=True)
        ledger = self.output / "codex-invocations.txt"
        prefix = "SKIVOLVE_SKILLOPT_CODEX_"
        environment = {
            **os.environ,
            f"{prefix}ROOT": str(self.output),
            f"{prefix}REAL": str(fake_codex),
            f"{prefix}REAL_SHA256": sha256_file(fake_codex),
            f"{prefix}SANDBOX": str(sandbox),
            f"{prefix}SANDBOX_SHA256": sha256_file(sandbox),
            f"{prefix}AUTH_FILE": str(auth),
            f"{prefix}CONFIG": str(config),
            f"{prefix}CONFIG_SHA256": sha256_file(config),
            f"{prefix}WORKSPACE": str(self.output),
            f"{prefix}TMP": str(optimizer_tmp),
            f"{prefix}PROXY_BIN": str(proxy_bin),
            f"{prefix}LEDGER": str(ledger),
            f"{prefix}MAX_INVOCATIONS": "1",
            f"{prefix}TIMEOUT_SECONDS": "10",
        }
        completed = subprocess.run(
            [
                sys.executable,
                "-m",
                "skivolve.skillopt_codex_proxy",
                "exec",
                "--output-schema",
                str(schema),
                "--output-last-message",
                str(last_message),
                "-",
            ],
            input="exact optimizer prompt",
            capture_output=True,
            text=True,
            check=False,
            env=environment,
        )

        self.assertEqual(completed.returncode, 0, completed.stderr)
        captured = json.loads(last_message.read_text(encoding="utf-8"))
        self.assertEqual(captured["prompt"], "exact optimizer prompt")
        self.assertFalse(captured["secret_visible"])

    @unittest.skipUnless(
        os.name == "posix" and os.environ.get("SKIVOLVE_TEST_REAL_CODEX"),
        "real Codex optimizer probe is unavailable",
    )
    def test_real_codex_optimizer_accepts_strict_isolated_config(self) -> None:
        real = Path(os.environ["SKIVOLVE_TEST_REAL_CODEX"]).resolve(strict=True)
        sandbox = (real.parent.parent / "codex-resources" / "bwrap").resolve(
            strict=True
        )
        self.output.mkdir()
        plan = replace(
            self.plan,
            skillopt_python=Path(sys.executable).absolute(),
            optimizer_executable=real,
            optimizer_sandbox=sandbox,
            optimizer_executable_sha256=sha256_file(real),
            optimizer_sandbox_sha256=sha256_file(sandbox),
        )
        original_tempdir = tempfile.tempdir
        try:
            with patch.dict(os.environ, {}, clear=False):
                launcher, binding = skillopt_sidecar._prepare_codex_proxy(plan)
                completed = subprocess.run(
                    [str(launcher), "exec", "--help"],
                    input="",
                    capture_output=True,
                    text=True,
                    check=False,
                    env=os.environ.copy(),
                    timeout=30,
                )
        finally:
            tempfile.tempdir = original_tempdir

        self.assertEqual(completed.returncode, 0, completed.stderr)
        self.assertIn("Usage: codex exec", completed.stdout)
        self.assertEqual(
            binding["permission_preflight"]["tool_process_start"],
            "denied-before-exec",
        )
        self.assertEqual(
            binding["permission_preflight"]["model_tool_secret_and_network_access"],
            "unreachable-no-tool-process",
        )

    def test_proxy_removes_legacy_sandbox_override(self) -> None:
        arguments = skillopt_codex_proxy._codex_arguments(
            ["exec", "--json", "--sandbox", "read-only", "-"]
        )

        self.assertEqual(arguments[:2], ["exec", "--strict-config"])
        self.assertNotIn("--sandbox", arguments)

    def test_zero_optimizer_calls_finalize_as_a_valid_no_change_budget(self) -> None:
        self.output.mkdir()
        ledger = self.output / "codex-invocations.txt"
        ledger.write_text("0\n", encoding="ascii")

        observed = skillopt_sidecar._finalize_optimizer_budget(
            self.plan, {"ledger": ledger.name}
        )

        self.assertEqual(observed["used_invocations"], 0)

    @unittest.skipUnless(os.name == "posix", "process-group semantics are POSIX-only")
    def test_run_command_kills_grandchildren_on_timeout(self) -> None:
        marker = self.root / "escaped"
        child = (
            "import time; from pathlib import Path; time.sleep(2); "
            f"Path({str(marker)!r}).write_text('escaped')"
        )
        parent = (
            "import subprocess, sys, time; "
            f"subprocess.Popen([sys.executable, '-c', {child!r}]); time.sleep(30)"
        )

        with self.assertRaisesRegex(SkillOptBridgeError, "failed to execute"):
            run_command((sys.executable, "-c", parent), timeout_seconds=1)
        time.sleep(2)
        self.assertFalse(marker.exists())

    def test_run_command_rejects_output_flood_without_buffering_it(self) -> None:
        code = f"import sys; sys.stdout.write('x' * {MAX_COMMAND_OUTPUT_BYTES + 1})"
        with self.assertRaisesRegex(SkillOptBridgeError, "stdout exceeded"):
            run_command((sys.executable, "-c", code), timeout_seconds=10)

    def test_run_command_forwards_exact_bounded_stdin(self) -> None:
        completed = run_command(
            (
                sys.executable,
                "-c",
                "import sys; sys.stdout.buffer.write(sys.stdin.buffer.read())",
            ),
            input_bytes=b"optimizer prompt\n",
        )
        self.assertEqual(completed.stdout, "optimizer prompt\n")
        with self.assertRaisesRegex(SkillOptBridgeError, "input exceeded"):
            run_command(
                (sys.executable, "-c", "pass"),
                input_bytes=b"x" * (MAX_COMMAND_INPUT_BYTES + 1),
            )

    @unittest.skipUnless(os.name == "posix", "process-group semantics are POSIX-only")
    def test_run_command_kills_grandchildren_after_normal_leader_exit(self) -> None:
        marker = self.root / "normal-exit-escaped"
        child = (
            "import time; from pathlib import Path; time.sleep(1); "
            f"Path({str(marker)!r}).write_text('escaped')"
        )
        parent = (
            "import subprocess, sys; "
            f"subprocess.Popen([sys.executable, '-c', {child!r}])"
        )

        run_command((sys.executable, "-c", parent), timeout_seconds=10)
        time.sleep(1.5)
        self.assertFalse(marker.exists())

    @unittest.skipUnless(os.name == "posix", "process-group semantics are POSIX-only")
    def test_run_command_kills_grandchildren_when_caller_is_interrupted(self) -> None:
        import signal
        import threading

        marker = self.root / "interrupt-escaped"
        child = (
            "import time; from pathlib import Path; time.sleep(2); "
            f"Path({str(marker)!r}).write_text('escaped')"
        )
        parent = (
            "import subprocess, sys, time; "
            f"subprocess.Popen([sys.executable, '-c', {child!r}]); time.sleep(30)"
        )
        timer = threading.Timer(0.25, os.kill, args=(os.getpid(), signal.SIGINT))
        timer.start()
        try:
            with self.assertRaises(KeyboardInterrupt):
                run_command((sys.executable, "-c", parent), timeout_seconds=10)
        finally:
            timer.cancel()
        time.sleep(2)
        self.assertFalse(marker.exists())

    @unittest.skipUnless(
        os.environ.get("SKIVOLVE_TEST_SKILLOPT_SOURCE"),
        "exact SkillOpt source not supplied",
    )
    def test_exact_pinned_skillopt_trainer_constructs_with_adapter(self) -> None:
        source = Path(os.environ["SKIVOLVE_TEST_SKILLOPT_SOURCE"])
        validate_skillopt_checkout(source)
        base_loader, batch_spec, env_adapter, trainer = skillopt_sidecar._load_skillopt(
            source
        )
        self.output.mkdir()
        baseline_path = self.output / "initial.skill.md"
        baseline_path.write_bytes(_BASE_SKILL)
        prompt = self.repository / "prompt.md"
        prompt.write_text("exact public prompt\n", encoding="utf-8")
        cases = [
            SimpleNamespace(
                id="train-a",
                split="train",
                skill="testing",
                prompt_file=prompt,
                critical_expectations=("a",),
            ),
            SimpleNamespace(
                id="selection-a",
                split="train",
                skill="testing",
                prompt_file=prompt,
                critical_expectations=("a",),
            ),
        ]
        run_records: list[dict[str, object]] = []
        with patch(
            "skivolve.skillopt_sidecar.git_blob_bytes",
            return_value=prompt.read_bytes(),
        ):
            _loader, adapter = skillopt_sidecar._build_runtime_classes(
                base_dataloader=base_loader,
                batch_spec=batch_spec,
                env_adapter=env_adapter,
                suite=SimpleNamespace(cases=cases),
                plan=self.plan,
                baseline_skill=_BASE_SKILL,
                run_records=run_records,
            )
        adapter.reflect = lambda self, *_args, **_kwargs: []
        config = skillopt_sidecar._trainer_config(
            self.plan, baseline_path, Path("/bin/true")
        )

        constructed = trainer(config, adapter())

        def invoke(**kwargs: object) -> tuple[int, dict[str, object]]:
            output_dir = Path(kwargs["output_dir"])
            case_ids = tuple(kwargs["case_ids"])
            output_dir.mkdir(parents=True)
            pairs = [
                {
                    "comparison_id": FITNESS_COMPARISON_ID,
                    "case_id": case_id,
                    "repetition": repetition,
                    "completed": True,
                    "arms": {
                        "treatment": {
                            "status": "completed",
                            "passed": True,
                            "critical_results": {"a": True},
                            "source": {
                                "source_commit": "b" * 40,
                                "skill_snapshot_sha256": sha256_bytes(_BASE_SKILL),
                            },
                        }
                    },
                }
                for case_id in case_ids
                for repetition in range(3)
            ]
            gates = {
                name: {"passed": True}
                for name in (
                    "execution_matrix_integrity",
                    "infrastructure_integrity",
                    "generator_model_stability",
                )
            }
            (output_dir / "run.json").write_text(
                json.dumps(
                    {
                        "dry_run": False,
                        "passed": True,
                        "pairs": pairs,
                        "aggregate": {"gates": gates},
                    }
                ),
                encoding="utf-8",
            )
            return 0, {}

        with (
            patch("skivolve.skillopt_sidecar.clone_candidate", return_value="b" * 40),
            patch(
                "skivolve.skillopt_sidecar.candidate_snapshot_sha256",
                return_value=sha256_bytes(_BASE_SKILL),
            ),
            patch(
                "skivolve.skillopt_sidecar.write_derived_suite",
                return_value=self.suite,
            ),
            patch("skivolve.skillopt_sidecar.invoke_skivolve", side_effect=invoke),
        ):
            summary = constructed.train()

        self.assertEqual(constructed.cfg["num_epochs"], 1)
        self.assertEqual(
            [record["phase"] for record in run_records],
            [
                "baseline_selection",
                "training",
            ],
        )
        self.assertEqual(summary["best_step"], 0)
        self.assertEqual(
            (self.output / "skillopt/best_skill.md").read_bytes(), _BASE_SKILL
        )


class SkillOptCandidateGitTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name)
        self.repository = self.root / "source"
        self.repository.mkdir()
        self._git("init")
        self._git("config", "user.name", "Fixture")
        self._git("config", "user.email", "fixture@example.invalid")
        skill = self.repository / "skills/testing/SKILL.md"
        skill.parent.mkdir(parents=True)
        skill.write_bytes(_BASE_SKILL)
        self._git("add", "skills/testing/SKILL.md")
        self._git("commit", "-m", "seed")
        self.baseline = self._git("rev-parse", "HEAD").stdout.strip()

    def tearDown(self) -> None:
        self.temporary.cleanup()

    def _git(self, *arguments: str) -> subprocess.CompletedProcess[str]:
        completed = subprocess.run(
            ["git", "-C", str(self.repository), *arguments],
            capture_output=True,
            text=True,
            check=False,
        )
        if completed.returncode != 0:
            raise AssertionError(completed.stderr)
        return completed

    def test_candidate_clone_commits_only_skill_change(self) -> None:
        destination = self.root / "changed"
        candidate = _BASE_SKILL.replace(b"Seed.", b"Candidate.")

        commit = clone_candidate(
            source_repository=self.repository,
            destination=destination,
            baseline_commit=self.baseline,
            skill_path=Path("skills/testing/SKILL.md"),
            candidate=candidate,
        )

        changed = subprocess.run(
            [
                "git",
                "-C",
                str(destination),
                "diff",
                "--name-only",
                self.baseline,
                commit,
            ],
            capture_output=True,
            text=True,
            check=True,
        ).stdout.splitlines()
        self.assertEqual(changed, ["skills/testing/SKILL.md"])

    def test_candidate_commit_and_snapshot_are_reproducible(self) -> None:
        candidate = _BASE_SKILL.replace(b"Seed.", b"Candidate.")
        destinations = (self.root / "first", self.root / "second")

        commits = [
            clone_candidate(
                source_repository=self.repository,
                destination=destination,
                baseline_commit=self.baseline,
                skill_path=Path("skills/testing/SKILL.md"),
                candidate=candidate,
            )
            for destination in destinations
        ]
        snapshots = [
            candidate_snapshot_sha256(destination, Path("skills/testing"))
            for destination in destinations
        ]

        self.assertEqual(commits[0], commits[1])
        self.assertEqual(snapshots[0], snapshots[1])

    def test_reconstructs_rejected_candidate_from_bounded_artifact(self) -> None:
        output = self.root / "output"
        output.mkdir()
        candidate = _BASE_SKILL.replace(b"Seed.", b"Rejected.")
        artifact = output / "rejected.skill.md"
        artifact.write_bytes(candidate)
        digest = sha256_bytes(candidate)
        plan = SimpleNamespace(
            output_dir=output,
            repository_root=self.repository,
            baseline_commit=self.baseline,
            skill_path=Path("skills/testing/SKILL.md"),
            bundle_source=Path("skills/testing"),
        )

        bindings = optimize_cli._reconstruct_candidate_bindings(
            plan=plan,
            initial=_BASE_SKILL,
            records=[
                {
                    "candidate_skill": artifact.name,
                    "candidate_sha256": digest,
                }
            ],
        )

        commit, snapshot = bindings[digest]
        self.assertEqual(len(commit), 40)
        self.assertEqual(len(snapshot), 64)

    def test_git_blob_read_is_immutable_after_working_tree_drift(self) -> None:
        prompt = self.repository / "cases/prompt.md"
        prompt.parent.mkdir(parents=True)
        prompt.write_text("reviewed prompt\n", encoding="utf-8")
        self._git("add", "cases/prompt.md")
        self._git("commit", "-m", "add prompt")
        commit = self._git("rev-parse", "HEAD").stdout.strip()
        prompt.write_text("unreviewed prompt\n", encoding="utf-8")

        observed = git_blob_bytes(self.repository, commit, Path("cases/prompt.md"))

        self.assertEqual(observed, b"reviewed prompt\n")

    def test_candidate_clone_allows_seed_for_baseline_fitness(self) -> None:
        destination = self.root / "unchanged"

        commit = clone_candidate(
            source_repository=self.repository,
            destination=destination,
            baseline_commit=self.baseline,
            skill_path=Path("skills/testing/SKILL.md"),
            candidate=_BASE_SKILL,
        )

        self.assertNotEqual(commit, self.baseline)
        changed = subprocess.run(
            [
                "git",
                "-C",
                str(destination),
                "diff",
                "--name-only",
                self.baseline,
                commit,
            ],
            capture_output=True,
            text=True,
            check=True,
        ).stdout.strip()
        self.assertEqual(changed, "")

    def test_derived_suites_separate_fitness_from_attribution(self) -> None:
        class Suite:
            suite_id = "fixture"
            raw = {
                "suite_id": "fixture",
                "repository_root": ".",
                "evaluation_mode": "judged",
                "comparator": {"adapter": "fake"},
                "comparator_profile": {"kind": "fake"},
                "variants": [],
                "comparisons": [],
                "cases": [{"id": "case-a", "comparator_contract": {}}],
                "holdout": {"comparison_ids": []},
            }

        fitness = derived_suite_payload(
            suite=Suite(),
            baseline_commit=self.baseline,
            candidate_commit="b" * 40,
            fitness=True,
        )
        attribution = derived_suite_payload(
            suite=Suite(),
            baseline_commit=self.baseline,
            candidate_commit="b" * 40,
        )

        self.assertEqual(fitness["comparisons"][0]["id"], FITNESS_COMPARISON_ID)
        self.assertEqual(fitness["comparisons"][0]["control"], "no-skill")
        self.assertEqual(attribution["comparisons"][0]["id"], COMPARISON_ID)
        self.assertEqual(attribution["comparisons"][0]["control"], "seed")
        self.assertEqual(attribution["evaluation_mode"], "objective_only")
        self.assertNotIn("comparator", attribution)
        self.assertNotIn("comparator_profile", attribution)
        self.assertNotIn("comparator_contract", attribution["cases"][0])
        json.dumps(fitness)


class SkillOptScoreMappingTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name)

    def tearDown(self) -> None:
        self.temporary.cleanup()

    def test_score_requires_every_repetition_and_critical_assertion(self) -> None:
        pairs = []
        for repetition in range(3):
            critical = {"a": True, "b": repetition != 1}
            pairs.append(
                {
                    "comparison_id": FITNESS_COMPARISON_ID,
                    "case_id": "case-a",
                    "repetition": repetition,
                    "completed": True,
                    "arms": {
                        "treatment": {
                            "status": "completed",
                            "passed": repetition != 1,
                            "critical_results": critical,
                            "error_stage": None,
                            "error": None,
                            "diff": f"diff-{repetition}",
                        }
                    },
                }
            )
        item = {
            "id": "case-a",
            "task_description": "write sensitive tests",
            "task_type": "skivolve-testing",
            "critical_expectations": ["a", "b"],
        }
        prediction_root = self.root / "predictions"
        prediction_root.mkdir()

        result = skillopt_sidecar._score_case(
            run={"pairs": pairs}, item=item, prediction_root=prediction_root
        )

        self.assertEqual(result["hard"], 0)
        self.assertEqual(result["soft"], 7 / 9)
        self.assertIn("b", result["fail_reason"])
        self.assertIn("overall-failed", result["fail_reason"])
        self.assertNotIn("incomplete", result["fail_reason"])
        conversation = json.loads(
            (prediction_root / "case-a/conversation.json").read_text(encoding="utf-8")
        )
        self.assertEqual(conversation[0]["role"], "user")
        self.assertEqual(conversation[-1]["role"], "system")

    def test_infrastructure_gate_cannot_be_scored_as_candidate_failure(self) -> None:
        complete = {
            "aggregate": {
                "gates": {
                    name: {"passed": True}
                    for name in (
                        "execution_matrix_integrity",
                        "infrastructure_integrity",
                        "generator_model_stability",
                    )
                }
            }
        }
        incomplete = copy.deepcopy(complete)
        incomplete["aggregate"]["gates"]["infrastructure_integrity"]["passed"] = False

        self.assertTrue(skillopt_sidecar._infrastructure_passed(complete))
        self.assertFalse(skillopt_sidecar._infrastructure_passed(incomplete))


if __name__ == "__main__":
    unittest.main()
