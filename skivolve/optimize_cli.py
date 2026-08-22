"""Generate one SkillOpt candidate and qualify it with public Skivolve cases."""

from __future__ import annotations

import argparse
import json
import math
import os
import stat
import subprocess
import sys
import tempfile
from pathlib import Path
from typing import Any

from .skillopt_bridge import (
    SkillOptBridgeError,
    FITNESS_COMPARISON_ID,
    COMPARISON_ID,
    MAX_CANDIDATE_BYTES,
    OPTIMIZER_CALL_TIMEOUT_SECONDS,
    build_plan,
    canonical_bytes,
    candidate_snapshot_sha256,
    clone_candidate,
    invoke_skivolve,
    load_strict_json,
    private_write_bytes,
    private_write_json,
    revalidate_plan,
    run_command,
    sha256_bytes,
    sha256_file,
    validate_candidate,
    validate_skillopt_checkout,
    write_derived_suite,
)


_ENV_ALLOWLIST = frozenset(
    {
        "ANTHROPIC_CLAUDE_CODE_SANDBOX_RUNTIME_BIN",
        "CLAUDE_CONFIG_DIR",
        "CODEX_EXEC_PATH",
        "CODEX_HOME",
        "DBUS_SESSION_BUS_ADDRESS",
        "HOME",
        "LANG",
        "LC_ALL",
        "LOGNAME",
        "PATH",
        "SHELL",
        "SKIVOLVE_CLAUDE_SECCOMP_APPLY_PATH",
        "SKIVOLVE_CLAUDE_BWRAP_PATH",
        "SKIVOLVE_CLAUDE_SOCAT_PATH",
        "SSL_CERT_DIR",
        "SSL_CERT_FILE",
        "TEMP",
        "TMP",
        "TMPDIR",
        "USER",
        "XDG_CACHE_HOME",
        "XDG_CONFIG_HOME",
        "XDG_DATA_HOME",
        "XDG_RUNTIME_DIR",
    }
)


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--suite", type=Path, default=Path("suite.json"))
    parser.add_argument("--skill", required=True)
    parser.add_argument("--baseline-ref", default="HEAD")
    parser.add_argument("--train-case", action="append", default=[])
    parser.add_argument("--selection-case", action="append", default=[])
    parser.add_argument("--validation-case", action="append", default=[])
    parser.add_argument("--seed", type=int, default=42)
    parser.add_argument("--optimizer-model", default="gpt-5.6")
    parser.add_argument("--skillopt-source", type=Path, required=True)
    parser.add_argument("--skillopt-python", type=Path, required=True)
    parser.add_argument("--skivolve-python", type=Path, default=Path(sys.executable))
    parser.add_argument("--output-dir", type=Path, required=True)
    parser.add_argument("--timeout-seconds", type=int, default=21600)
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="validate the exact plan without creating files or invoking models",
    )
    parser.add_argument(
        "--confirm-live",
        action="store_true",
        help="acknowledge that a non-dry run consumes provider quota or metered spend",
    )
    parser.add_argument(
        "--expected-plan-sha256",
        help="bind live spending to the canonical plan hash emitted by --dry-run",
    )
    return parser


def _sidecar_environment(_package_root: Path) -> dict[str, str]:
    environment = {
        name: value for name, value in os.environ.items() if name in _ENV_ALLOWLIST
    }
    environment["PYTHONDONTWRITEBYTECODE"] = "1"
    return environment


def _probe_skillopt(plan: Any, package_root: Path) -> dict[str, str]:
    code = (
        "from pathlib import Path; import json, sys; "
        f"sys.path.insert(0, {str(plan.skillopt_source)!r}); "
        "import skillopt; from skillopt.engine.trainer import ReflACTTrainer; "
        "import skivolve; print(json.dumps({"
        "'skillopt': str(Path(skillopt.__file__).resolve()), "
        "'skivolve': str(Path(skivolve.__file__).resolve())}))"
    )
    completed = run_command(
        (plan.skillopt_python, "-I", "-c", code),
        env=_sidecar_environment(package_root),
        timeout_seconds=60,
    )
    try:
        imports = json.loads(completed.stdout)
        imported = Path(imports["skillopt"]).resolve(strict=True)
        imported_skivolve = Path(imports["skivolve"]).resolve(strict=True)
    except (json.JSONDecodeError, KeyError, OSError, TypeError) as exc:
        raise SkillOptBridgeError("SkillOpt interpreter probe was malformed") from exc
    if not imported.is_relative_to(plan.skillopt_source):
        raise SkillOptBridgeError(
            "SkillOpt interpreter imported an unreviewed checkout"
        )
    if not imported_skivolve.is_relative_to(package_root):
        raise SkillOptBridgeError(
            "SkillOpt interpreter imported a different Skivolve installation"
        )
    return {
        "python": str(plan.skillopt_python),
        "python_sha256": sha256_file(plan.skillopt_python),
        "imported_from": str(imported),
        "skivolve_imported_from": str(imported_skivolve),
    }


def _preflight_skivolve(plan: Any) -> list[dict[str, Any]]:
    suite, baseline, _upstream = revalidate_plan(plan)
    records: list[dict[str, Any]] = []
    with tempfile.TemporaryDirectory(
        prefix=".skivolve-skillopt-preflight-", dir=plan.output_dir.parent
    ) as temp:
        root = Path(temp)
        fitness_clone = root / "fitness"
        fitness_commit = clone_candidate(
            source_repository=plan.repository_root,
            destination=fitness_clone,
            baseline_commit=plan.baseline_commit,
            skill_path=plan.skill_path,
            candidate=baseline,
        )
        fitness_manifest = write_derived_suite(
            fitness_clone,
            suite=suite,
            baseline_commit=plan.baseline_commit,
            candidate_commit=fitness_commit,
            fitness=True,
        )
        attribution_clone = root / "attribution"
        attribution_commit = clone_candidate(
            source_repository=plan.repository_root,
            destination=attribution_clone,
            baseline_commit=plan.baseline_commit,
            skill_path=plan.skill_path,
            candidate=baseline,
        )
        attribution_manifest = write_derived_suite(
            attribution_clone,
            suite=suite,
            baseline_commit=plan.baseline_commit,
            candidate_commit=attribution_commit,
        )
        selections = (
            (fitness_manifest, FITNESS_COMPARISON_ID, "train", plan.train_case_ids),
            (
                fitness_manifest,
                FITNESS_COMPARISON_ID,
                "train",
                plan.selection_case_ids,
            ),
            (
                attribution_manifest,
                COMPARISON_ID,
                "validation",
                plan.validation_case_ids,
            ),
        )
        for manifest, comparison_id, split, case_ids in selections:
            exit_code, summary = invoke_skivolve(
                python=plan.skivolve_python,
                suite_path=manifest,
                split=split,
                case_ids=case_ids,
                output_dir=None,
                timeout_seconds=300,
                dry_run=True,
                comparison_id=comparison_id,
            )
            planned_pair_runs = (
                summary.get("preflight", {}).get("plan", {}).get("pair_runs")
            )
            if (
                exit_code != 0
                or summary.get("dry_run") is not True
                or planned_pair_runs != 3 * len(case_ids)
            ):
                raise SkillOptBridgeError(
                    "generated Skivolve manifest preflight failed closed"
                )
            records.append(
                {
                    "comparison_id": comparison_id,
                    "split": split,
                    "case_ids": list(case_ids),
                    "exit_code": exit_code,
                    "dry_run": summary.get("dry_run"),
                    "planned_pair_runs": planned_pair_runs,
                }
            )
    return records


def _preflight_optimizer(plan: Any) -> dict[str, object]:
    from .skillopt_sidecar import preflight_optimizer_boundary

    with tempfile.TemporaryDirectory(
        prefix=".skivolve-optimizer-preflight-", dir=plan.output_dir.parent
    ) as temp:
        return preflight_optimizer_boundary(plan, Path(temp))


def _reconstruct_candidate_bindings(
    *, plan: Any, initial: bytes, records: Any
) -> dict[str, tuple[str, str]]:
    """Rebuild every rollout candidate outside the SkillOpt process."""

    if not isinstance(records, list):
        raise SkillOptBridgeError("sidecar rollout lifecycle must be a list")
    candidates = {sha256_bytes(initial): initial}
    for record in records:
        if not isinstance(record, dict):
            raise SkillOptBridgeError("sidecar rollout record must be an object")
        relative = record.get("candidate_skill")
        if not isinstance(relative, str):
            raise SkillOptBridgeError("sidecar rollout candidate path must be a string")
        supplied = plan.output_dir / relative
        if supplied.is_symlink():
            raise SkillOptBridgeError(
                "sidecar rollout candidate path must not be a symlink"
            )
        candidate_path = supplied.resolve(strict=True)
        if not candidate_path.is_relative_to(plan.output_dir):
            raise SkillOptBridgeError(
                "sidecar rollout candidate path escaped the run root"
            )
        metadata = candidate_path.lstat()
        if not stat.S_ISREG(metadata.st_mode) or metadata.st_size > MAX_CANDIDATE_BYTES:
            raise SkillOptBridgeError(
                "sidecar rollout candidate must be a bounded regular file"
            )
        candidate = candidate_path.read_bytes()
        validate_candidate(candidate, initial)
        digest = sha256_bytes(candidate)
        if record.get("candidate_sha256") != digest:
            raise SkillOptBridgeError(
                "sidecar rollout candidate hash does not match its artifact"
            )
        candidates[digest] = candidate
    bindings: dict[str, tuple[str, str]] = {}
    with tempfile.TemporaryDirectory(
        prefix=".skivolve-candidate-binding-", dir=plan.output_dir.parent
    ) as temporary:
        root = Path(temporary)
        for ordinal, (digest, candidate) in enumerate(sorted(candidates.items())):
            clone = root / f"candidate-{ordinal}"
            commit = clone_candidate(
                source_repository=plan.repository_root,
                destination=clone,
                baseline_commit=plan.baseline_commit,
                skill_path=plan.skill_path,
                candidate=candidate,
            )
            bindings[digest] = (
                commit,
                candidate_snapshot_sha256(clone, plan.bundle_source),
            )
    return bindings


def _validate_sidecar_result(
    *,
    plan: Any,
    plan_sha256: str,
    baseline: bytes,
    suite: Any,
) -> tuple[dict[str, Any], bytes, Path]:
    result_path = plan.output_dir / "sidecar-result.json"
    result = load_strict_json(result_path, maximum_bytes=16 * 1024 * 1024)
    required = {
        "schema_version",
        "status",
        "plan_sha256",
        "skillopt",
        "best_skill",
        "best_skill_sha256",
        "best_skill_bytes",
        "initial_skill_sha256",
        "inner_runs",
        "trainer_summary",
        "optimizer_budget",
        "holdout_used",
        "automatic_adoption",
    }
    if not isinstance(result, dict) or set(result) != required:
        raise SkillOptBridgeError("sidecar result fields do not match schema v1")
    if (
        result["schema_version"] != 1
        or result["status"] != "completed"
        or result["plan_sha256"] != plan_sha256
        or result["holdout_used"] is not False
        or result["automatic_adoption"] is not False
    ):
        raise SkillOptBridgeError("sidecar result violated its immutable bindings")
    if result["skillopt"] != validate_skillopt_checkout(plan.skillopt_source):
        raise SkillOptBridgeError("sidecar SkillOpt provenance does not match the plan")
    relative = result["best_skill"]
    if not isinstance(relative, str):
        raise SkillOptBridgeError("sidecar best-skill path must be a string")
    supplied_candidate = plan.output_dir / relative
    if supplied_candidate.is_symlink():
        raise SkillOptBridgeError("sidecar best-skill path must not be a symlink")
    candidate_path = supplied_candidate.resolve(strict=True)
    if not candidate_path.is_relative_to(plan.output_dir):
        raise SkillOptBridgeError("sidecar best-skill path escaped the run root")
    candidate = candidate_path.read_bytes()
    validate_candidate(candidate, baseline)
    if (
        result["best_skill_sha256"] != sha256_bytes(candidate)
        or result["best_skill_bytes"] != len(candidate)
        or result["initial_skill_sha256"] != sha256_bytes(baseline)
    ):
        raise SkillOptBridgeError(
            "sidecar skill hashes or sizes do not match artifacts"
        )
    _validate_inner_runs(
        plan=plan,
        value=result["inner_runs"],
        initial_sha256=sha256_bytes(baseline),
        best_sha256=sha256_bytes(candidate),
        trainer_summary=result["trainer_summary"],
        critical_expectations={
            case.id: tuple(case.critical_expectations) for case in suite.cases
        },
        candidate_bindings=_reconstruct_candidate_bindings(
            plan=plan,
            initial=baseline,
            records=result["inner_runs"],
        ),
    )
    _validate_optimizer_budget(plan=plan, value=result["optimizer_budget"])
    return result, candidate, candidate_path


def _validate_run_artifact(
    *,
    run: Any,
    exit_code: int,
    expected_cases: tuple[str, ...],
    comparison_id: str,
    candidate_commit: str,
    candidate_snapshot_sha256: str,
    label: str,
) -> dict[str, list[dict[str, Any]]]:
    """Bind a Skivolve run's semantics to one exact candidate and matrix."""

    if not isinstance(run, dict) or run.get("dry_run") is not False:
        raise SkillOptBridgeError(f"{label} artifact is malformed")
    if type(exit_code) is not int or exit_code not in {0, 1}:
        raise SkillOptBridgeError(f"{label} exit code is invalid")
    if (exit_code == 0) != (run.get("passed") is True):
        raise SkillOptBridgeError(f"{label} exit code contradicts run evidence")
    expected_pairs = {
        (case_id, repetition) for case_id in expected_cases for repetition in range(3)
    }
    observed_pairs: set[tuple[str, int]] = set()
    pairs_by_case: dict[str, list[dict[str, Any]]] = {
        case_id: [] for case_id in expected_cases
    }
    pairs = run.get("pairs")
    if not isinstance(pairs, list) or len(pairs) != len(expected_pairs):
        raise SkillOptBridgeError(f"{label} pair matrix is incomplete")
    for pair in pairs:
        if not isinstance(pair, dict) or pair.get("comparison_id") != comparison_id:
            raise SkillOptBridgeError(f"{label} comparison binding drifted")
        key = (pair.get("case_id"), pair.get("repetition"))
        if key not in expected_pairs or key in observed_pairs:
            raise SkillOptBridgeError(f"{label} pair identity is invalid")
        observed_pairs.add(key)
        pairs_by_case[key[0]].append(pair)
        treatment = pair.get("arms", {}).get("treatment")
        source = treatment.get("source") if isinstance(treatment, dict) else None
        if (
            not isinstance(source, dict)
            or source.get("source_commit") != candidate_commit
            or source.get("skill_snapshot_sha256") != candidate_snapshot_sha256
        ):
            raise SkillOptBridgeError(f"{label} treatment provenance drifted")
    return pairs_by_case


def _validate_inner_runs(
    *,
    plan: Any,
    value: Any,
    initial_sha256: str,
    best_sha256: str,
    trainer_summary: Any,
    critical_expectations: dict[str, tuple[str, ...]],
    candidate_bindings: dict[str, tuple[str, str]],
) -> None:
    phases = ["baseline_selection", "training"]
    if not isinstance(value, list) or len(value) not in {2, 3}:
        raise SkillOptBridgeError("sidecar rollout lifecycle must contain 2 or 3 runs")
    if len(value) == 3:
        phases.append("candidate_selection")
    expected_fields = {
        "ordinal",
        "phase",
        "candidate_sha256",
        "candidate_skill",
        "candidate_snapshot_sha256",
        "candidate_commit",
        "case_ids",
        "split",
        "skivolve_exit_code",
        "run_json",
        "run_json_sha256",
        "scores",
    }
    selection_score: float | None = None
    candidate_score: float | None = None
    for ordinal, (record, phase) in enumerate(zip(value, phases, strict=True)):
        if not isinstance(record, dict) or set(record) != expected_fields:
            raise SkillOptBridgeError(
                "sidecar rollout record fields do not match schema v1"
            )
        if record["ordinal"] != ordinal or record["phase"] != phase:
            raise SkillOptBridgeError("sidecar rollout phase order is invalid")
        expected_cases = (
            plan.train_case_ids if phase == "training" else plan.selection_case_ids
        )
        case_ids = record["case_ids"]
        if (
            not isinstance(case_ids, list)
            or len(case_ids) != len(expected_cases)
            or set(case_ids) != set(expected_cases)
            or record["split"] != "train"
        ):
            raise SkillOptBridgeError("sidecar rollout cases or split drifted")
        candidate_sha256 = record["candidate_sha256"]
        candidate_snapshot_hash = record["candidate_snapshot_sha256"]
        candidate_commit = record["candidate_commit"]
        if (
            not isinstance(candidate_sha256, str)
            or len(candidate_sha256) != 64
            or any(
                character not in "0123456789abcdef" for character in candidate_sha256
            )
            or not isinstance(candidate_commit, str)
            or len(candidate_commit) != 40
            or any(
                character not in "0123456789abcdef" for character in candidate_commit
            )
            or not isinstance(candidate_snapshot_hash, str)
            or len(candidate_snapshot_hash) != 64
            or any(
                character not in "0123456789abcdef"
                for character in candidate_snapshot_hash
            )
        ):
            raise SkillOptBridgeError("sidecar rollout candidate binding is malformed")
        if candidate_bindings.get(candidate_sha256) != (
            candidate_commit,
            candidate_snapshot_hash,
        ):
            raise SkillOptBridgeError(
                "sidecar rollout candidate commit or snapshot binding drifted"
            )
        if ordinal < 2 and candidate_sha256 != initial_sha256:
            raise SkillOptBridgeError(
                "baseline or training rollout did not use the seed skill"
            )
        if phase == "candidate_selection" and candidate_sha256 == initial_sha256:
            raise SkillOptBridgeError(
                "redundant candidate selection should have used the cache"
            )
        exit_code = record["skivolve_exit_code"]
        if type(exit_code) is not int or exit_code not in {0, 1}:
            raise SkillOptBridgeError("sidecar rollout exit code is invalid")
        relative = record["run_json"]
        if not isinstance(relative, str):
            raise SkillOptBridgeError("sidecar rollout path must be a string")
        supplied = plan.output_dir / relative
        if supplied.is_symlink():
            raise SkillOptBridgeError("sidecar rollout path must not be a symlink")
        run_path = supplied.resolve(strict=True)
        if not run_path.is_relative_to(plan.output_dir):
            raise SkillOptBridgeError("sidecar rollout path escaped the run root")
        if record["run_json_sha256"] != sha256_file(run_path):
            raise SkillOptBridgeError(
                "sidecar rollout hash does not match its artifact"
            )
        run = load_strict_json(run_path, maximum_bytes=64 * 1024 * 1024)
        pairs_by_case = _validate_run_artifact(
            run=run,
            exit_code=exit_code,
            expected_cases=expected_cases,
            comparison_id=FITNESS_COMPARISON_ID,
            candidate_commit=candidate_commit,
            candidate_snapshot_sha256=candidate_snapshot_hash,
            label="sidecar rollout",
        )
        recomputed_scores: dict[str, tuple[int, float]] = {}
        for case_id in expected_cases:
            expectations = critical_expectations.get(case_id)
            if expectations is None:
                raise SkillOptBridgeError(
                    f"sidecar rollout case has no bound expectations: {case_id}"
                )
            numerator = 0
            hard_score = True
            for pair in pairs_by_case[case_id]:
                treatment = pair.get("arms", {}).get("treatment")
                if not isinstance(treatment, dict):
                    raise SkillOptBridgeError(
                        "sidecar rollout treatment arm is malformed"
                    )
                executed = (
                    pair.get("completed") is True
                    and treatment.get("status") == "completed"
                )
                overall_passed = treatment.get("passed") is True
                scored_completion = executed and overall_passed
                critical = treatment.get("critical_results")
                if not isinstance(critical, dict):
                    critical = {}
                exact = tuple(
                    critical.get(expectation) is True for expectation in expectations
                )
                numerator += int(scored_completion) + sum(exact)
                hard_score = hard_score and scored_completion and all(exact)
            denominator = 3 * (len(expectations) + 1)
            recomputed_scores[case_id] = (
                int(hard_score),
                numerator / denominator,
            )
        scores = record["scores"]
        if not isinstance(scores, list) or len(scores) != len(expected_cases):
            raise SkillOptBridgeError("sidecar rollout score vector is incomplete")
        score_ids: set[str] = set()
        for score in scores:
            if not isinstance(score, dict) or set(score) != {"id", "hard", "soft"}:
                raise SkillOptBridgeError("sidecar rollout score fields are invalid")
            hard = score["hard"]
            soft = score["soft"]
            if (
                score["id"] not in expected_cases
                or score["id"] in score_ids
                or type(hard) is not int
                or hard not in {0, 1}
                or isinstance(soft, bool)
                or not isinstance(soft, (int, float))
                or not math.isfinite(soft)
                or not 0 <= soft <= 1
            ):
                raise SkillOptBridgeError("sidecar rollout score value is invalid")
            expected_hard, expected_soft = recomputed_scores[score["id"]]
            if hard != expected_hard or soft != expected_soft:
                raise SkillOptBridgeError(
                    "sidecar rollout score contradicts objective run evidence"
                )
            score_ids.add(score["id"])
        if phase == "baseline_selection":
            selection_score = float(recomputed_scores[plan.selection_case_ids[0]][0])
        elif phase == "candidate_selection":
            candidate_score = float(recomputed_scores[plan.selection_case_ids[0]][0])

    if len(value) == 2 and best_sha256 != initial_sha256:
        raise SkillOptBridgeError(
            "changed best skill omitted candidate selection evidence"
        )
    if len(value) == 3 and best_sha256 not in {
        initial_sha256,
        value[2]["candidate_sha256"],
    }:
        raise SkillOptBridgeError("best skill is not represented by selection evidence")
    if not isinstance(trainer_summary, dict):
        raise SkillOptBridgeError("SkillOpt trainer summary must be an object")
    required_summary = {
        "baseline_selection_hard",
        "best_selection_hard",
        "best_step",
        "total_steps",
        "total_accepts",
        "baseline_test_hard",
        "test_hard",
        "final_test_hard",
        "config",
    }
    if not required_summary.issubset(trainer_summary):
        raise SkillOptBridgeError("SkillOpt trainer summary omitted lifecycle fields")
    config = trainer_summary["config"]
    if (
        trainer_summary["total_steps"] != 1
        or not isinstance(config, dict)
        or config.get("num_epochs") != 1
        or config.get("eval_test") is not False
        or any(
            trainer_summary[field] is not None
            for field in ("baseline_test_hard", "test_hard", "final_test_hard")
        )
        or trainer_summary["baseline_selection_hard"] != selection_score
    ):
        raise SkillOptBridgeError("SkillOpt trainer summary violated the bounded plan")
    if best_sha256 == initial_sha256:
        if (
            trainer_summary["best_step"] != 0
            or trainer_summary["total_accepts"] != 0
            or trainer_summary["best_selection_hard"] != selection_score
        ):
            raise SkillOptBridgeError(
                "unchanged best skill contradicts trainer summary"
            )
    elif (
        trainer_summary["best_step"] != 1
        or trainer_summary["total_accepts"] != 1
        or trainer_summary["best_selection_hard"] != candidate_score
    ):
        raise SkillOptBridgeError("changed best skill contradicts trainer summary")


def _validate_optimizer_budget(*, plan: Any, value: Any) -> None:
    fields = {
        "max_invocations",
        "per_invocation_timeout_seconds",
        "codex_executable",
        "codex_executable_sha256",
        "sandbox_executable",
        "sandbox_executable_sha256",
        "filesystem_isolation",
        "optimizer_config",
        "optimizer_config_sha256",
        "permission_preflight",
        "optimizer_tmp",
        "ledger",
        "used_invocations",
    }
    if not isinstance(value, dict) or set(value) != fields:
        raise SkillOptBridgeError("optimizer budget fields do not match schema v1")
    if (
        value["max_invocations"] != plan.planned_optimizer_invocations
        or value["per_invocation_timeout_seconds"] != OPTIMIZER_CALL_TIMEOUT_SECONDS
        or type(value["used_invocations"]) is not int
        or not 0 <= value["used_invocations"] <= plan.planned_optimizer_invocations
    ):
        raise SkillOptBridgeError("optimizer invocation budget was violated")
    if not isinstance(value["codex_executable"], str):
        raise SkillOptBridgeError("optimizer executable path must be a string")
    executable = Path(value["codex_executable"]).resolve(strict=True)
    if (
        executable != plan.optimizer_executable.resolve(strict=True)
        or value["codex_executable_sha256"] != plan.optimizer_executable_sha256
        or value["codex_executable_sha256"] != sha256_file(executable)
    ):
        raise SkillOptBridgeError("optimizer executable hash drifted")
    if not isinstance(value["sandbox_executable"], str):
        raise SkillOptBridgeError("optimizer sandbox path must be a string")
    sandbox = Path(value["sandbox_executable"]).resolve(strict=True)
    if (
        sandbox != plan.optimizer_sandbox.resolve(strict=True)
        or value["sandbox_executable_sha256"] != plan.optimizer_sandbox_sha256
        or value["sandbox_executable_sha256"] != sha256_file(sandbox)
        or value["filesystem_isolation"] != "bubblewrap-minimal-read-set-v1"
    ):
        raise SkillOptBridgeError("optimizer filesystem isolation drifted")
    config_relative = value["optimizer_config"]
    if not isinstance(config_relative, str):
        raise SkillOptBridgeError("optimizer config path must be a string")
    supplied_config = plan.output_dir / config_relative
    if supplied_config.is_symlink():
        raise SkillOptBridgeError("optimizer config must not be a symlink")
    config_path = supplied_config.resolve(strict=True)
    if config_path != plan.output_dir / "optimizer-config.toml" or value[
        "optimizer_config_sha256"
    ] != sha256_file(config_path):
        raise SkillOptBridgeError("optimizer config provenance drifted")
    permission = value["permission_preflight"]
    permission_fields = {
        "codex_version",
        "codex_executable_sha256",
        "sandbox_executable_sha256",
        "optimizer_config_sha256",
        "strict_config_flag_accepted",
        "tool_process_start",
        "tool_process_exit_code",
        "tool_process_diagnostic_sha256",
        "model_tool_secret_and_network_access",
    }
    if not isinstance(permission, dict) or set(permission) != permission_fields:
        raise SkillOptBridgeError(
            "optimizer permission preflight fields do not match schema v1"
        )
    if (
        not isinstance(permission["codex_version"], str)
        or not permission["codex_version"]
        or permission["codex_executable_sha256"] != plan.optimizer_executable_sha256
        or permission["sandbox_executable_sha256"] != plan.optimizer_sandbox_sha256
        or permission["optimizer_config_sha256"] != value["optimizer_config_sha256"]
        or permission["strict_config_flag_accepted"] is not True
        or permission["tool_process_start"] != "denied-before-exec"
        or permission["tool_process_exit_code"] != 1
        or permission["model_tool_secret_and_network_access"]
        != "unreachable-no-tool-process"
        or not isinstance(permission["tool_process_diagnostic_sha256"], str)
        or len(permission["tool_process_diagnostic_sha256"]) != 64
        or any(
            character not in "0123456789abcdef"
            for character in permission["tool_process_diagnostic_sha256"]
        )
    ):
        raise SkillOptBridgeError("optimizer permission preflight drifted")
    temporary_relative = value["optimizer_tmp"]
    if not isinstance(temporary_relative, str):
        raise SkillOptBridgeError("optimizer temporary path must be a string")
    supplied_temporary = plan.output_dir / temporary_relative
    if supplied_temporary.is_symlink():
        raise SkillOptBridgeError("optimizer temporary directory must not be a symlink")
    temporary = supplied_temporary.resolve(strict=True)
    if temporary != plan.output_dir / "optimizer-tmp":
        raise SkillOptBridgeError("optimizer temporary directory provenance drifted")
    relative = value["ledger"]
    if not isinstance(relative, str):
        raise SkillOptBridgeError("optimizer ledger path must be a string")
    supplied = plan.output_dir / relative
    if supplied.is_symlink():
        raise SkillOptBridgeError("optimizer ledger must not be a symlink")
    ledger = supplied.resolve(strict=True)
    if not ledger.is_relative_to(plan.output_dir):
        raise SkillOptBridgeError("optimizer ledger escaped the run root")
    if ledger.read_text(encoding="ascii").strip() != str(value["used_invocations"]):
        raise SkillOptBridgeError("optimizer ledger count drifted")


def _launch_sidecar(plan: Any, plan_path: Path, plan_sha256: str) -> None:
    package_root = Path(__file__).resolve(strict=True).parents[1]
    completed = run_command(
        (
            plan.skillopt_python,
            "-I",
            "-m",
            "skivolve.skillopt_sidecar",
            "--plan",
            plan_path,
            "--plan-sha256",
            plan_sha256,
        ),
        cwd=plan.output_dir,
        timeout_seconds=plan.timeout_seconds,
        env=_sidecar_environment(package_root),
        accepted_exit_codes=(0, 2),
    )
    private_write_bytes(
        plan.output_dir / "sidecar.stdout.log", completed.stdout.encode("utf-8")
    )
    private_write_bytes(
        plan.output_dir / "sidecar.stderr.log", completed.stderr.encode("utf-8")
    )
    if completed.returncode != 0:
        diagnostic = completed.stderr.strip()[-4000:]
        raise SkillOptBridgeError(f"SkillOpt sidecar failed: {diagnostic}")


def _certify_candidate(*, plan: Any, suite: Any, candidate: bytes) -> dict[str, Any]:
    certification_root = plan.output_dir / "certification"
    certification_root.mkdir(mode=0o700, exist_ok=False)
    clone = certification_root / "repository"
    candidate_commit = clone_candidate(
        source_repository=plan.repository_root,
        destination=clone,
        baseline_commit=plan.baseline_commit,
        skill_path=plan.skill_path,
        candidate=candidate,
    )
    manifest = write_derived_suite(
        clone,
        suite=suite,
        baseline_commit=plan.baseline_commit,
        candidate_commit=candidate_commit,
    )
    dry_exit, dry_summary = invoke_skivolve(
        python=plan.skivolve_python,
        suite_path=manifest,
        split="validation",
        case_ids=plan.validation_case_ids,
        output_dir=None,
        timeout_seconds=300,
        dry_run=True,
    )
    if dry_exit != 0 or dry_summary.get("dry_run") is not True:
        raise SkillOptBridgeError("fresh candidate certification dry-run failed")
    run_dir = certification_root / "skivolve-run"
    exit_code, _summary = invoke_skivolve(
        python=plan.skivolve_python,
        suite_path=manifest,
        split="validation",
        case_ids=plan.validation_case_ids,
        output_dir=run_dir,
        timeout_seconds=plan.timeout_seconds,
    )
    run_path = run_dir / "run.json"
    run = load_strict_json(run_path, maximum_bytes=64 * 1024 * 1024)
    candidate_sha256 = sha256_bytes(candidate)
    candidate_snapshot_hash = candidate_snapshot_sha256(clone, plan.bundle_source)
    pairs_by_case = _validate_run_artifact(
        run=run,
        exit_code=exit_code,
        expected_cases=plan.validation_case_ids,
        comparison_id=COMPARISON_ID,
        candidate_commit=candidate_commit,
        candidate_snapshot_sha256=candidate_snapshot_hash,
        label="candidate certification",
    )
    aggregate = run.get("aggregate")
    if not isinstance(aggregate, dict):
        raise SkillOptBridgeError("certification run omitted aggregate evidence")
    gates = aggregate.get("gates")
    if not isinstance(gates, dict):
        raise SkillOptBridgeError("certification run omitted gate evidence")
    infrastructure = all(
        isinstance(gates.get(name), dict) and gates[name].get("passed") is True
        for name in (
            "execution_matrix_integrity",
            "infrastructure_integrity",
            "generator_model_stability",
        )
    )
    if not infrastructure:
        raise SkillOptBridgeError(
            "candidate certification infrastructure was incomplete"
        )
    qualified = exit_code == 0 and run.get("passed") is True
    return {
        "candidate_commit": candidate_commit,
        "candidate_skill_sha256": candidate_sha256,
        "candidate_snapshot_sha256": candidate_snapshot_hash,
        "validated_case_ids": list(plan.validation_case_ids),
        "validated_pair_count": sum(len(pairs) for pairs in pairs_by_case.values()),
        "comparison_id": COMPARISON_ID,
        "derived_suite_sha256": sha256_file(manifest),
        "dry_run": dry_summary,
        "skivolve_exit_code": exit_code,
        "run_json": str(run_path.relative_to(plan.output_dir)),
        "run_json_sha256": sha256_file(run_path),
        "aggregate": aggregate,
        "qualified": qualified,
        "claim_authority": "public-objective-diagnostic",
    }


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    old_umask = os.umask(0o077)
    try:
        if not args.dry_run and not args.confirm_live:
            raise SkillOptBridgeError(
                "non-dry optimization requires --confirm-live because it consumes provider quota or spend"
            )
        plan = build_plan(
            suite_path=args.suite,
            skill=args.skill,
            baseline_ref=args.baseline_ref,
            train_case_ids=tuple(args.train_case),
            selection_case_ids=tuple(args.selection_case),
            validation_case_ids=tuple(args.validation_case),
            seed=args.seed,
            optimizer_model=args.optimizer_model,
            output_dir=args.output_dir,
            skillopt_source=args.skillopt_source,
            skillopt_python=args.skillopt_python,
            skivolve_python=args.skivolve_python,
            timeout_seconds=args.timeout_seconds,
        )
        package_root = Path(__file__).resolve(strict=True).parents[1]
        interpreter = _probe_skillopt(plan, package_root)
        preflights = _preflight_skivolve(plan)
        optimizer_preflight = _preflight_optimizer(plan)
        expected_plan_sha256 = sha256_bytes(canonical_bytes(plan.as_json()))
        dry_summary = {
            "dry_run": True,
            "plan": plan.as_json(),
            "skillopt_interpreter": interpreter,
            "skivolve_preflights": preflights,
            "optimizer_permission_preflight": optimizer_preflight,
            "expected_plan_sha256": expected_plan_sha256,
            "claim_limit": "public objective diagnostic; no private holdout or superiority claim",
        }
        if args.dry_run:
            print(json.dumps(dry_summary, indent=2, sort_keys=True))
            return 0
        if args.expected_plan_sha256 != expected_plan_sha256:
            raise SkillOptBridgeError(
                "live plan does not match --expected-plan-sha256 from the reviewed dry-run"
            )

        os.mkdir(plan.output_dir, mode=0o700)
        plan_path = plan.output_dir / "plan.json"
        private_write_json(plan_path, plan.as_json())
        plan_sha256 = sha256_file(plan_path)
        _launch_sidecar(plan, plan_path, plan_sha256)
        suite, baseline, _upstream = revalidate_plan(plan)
        sidecar_result, candidate, _candidate_path = _validate_sidecar_result(
            plan=plan,
            plan_sha256=plan_sha256,
            baseline=baseline,
            suite=suite,
        )
        candidate_copy = plan.output_dir / "candidate.skill.md"
        private_write_bytes(candidate_copy, candidate)
        changed = candidate != baseline
        certification = (
            _certify_candidate(plan=plan, suite=suite, candidate=candidate)
            if changed
            else None
        )
        revalidate_plan(plan)
        qualified = bool(certification and certification["qualified"])
        result = {
            "schema_version": 1,
            "status": "qualified"
            if qualified
            else ("no_change" if not changed else "rejected"),
            "plan_sha256": plan_sha256,
            "baseline_commit": plan.baseline_commit,
            "initial_skill_sha256": sha256_bytes(baseline),
            "candidate_skill": str(candidate_copy.relative_to(plan.output_dir)),
            "candidate_skill_sha256": sha256_bytes(candidate),
            "candidate_skill_bytes": len(candidate),
            "candidate_changed": changed,
            "sidecar_result_sha256": sha256_file(
                plan.output_dir / "sidecar-result.json"
            ),
            "inner_runs": sidecar_result["inner_runs"],
            "optimizer_budget": sidecar_result["optimizer_budget"],
            "certification": certification,
            "qualified": qualified,
            "holdout_used": False,
            "automatic_adoption": False,
            "source_revalidated_after_run": True,
            "claim_authority": "public-objective-diagnostic",
            "environment_names_forwarded": sorted(
                name for name in _ENV_ALLOWLIST if name in os.environ
            ),
        }
        result_path = plan.output_dir / "optimization.json"
        private_write_json(result_path, result)
        print(
            json.dumps(
                {**result, "output_dir": str(plan.output_dir)}, indent=2, sort_keys=True
            )
        )
        return 0 if qualified else 1
    except (
        SkillOptBridgeError,
        OSError,
        ValueError,
        ImportError,
        subprocess.SubprocessError,
    ) as exc:
        print(f"optimization error: {exc}", file=sys.stderr)
        return 2
    finally:
        os.umask(old_umask)


if __name__ == "__main__":
    raise SystemExit(main())
