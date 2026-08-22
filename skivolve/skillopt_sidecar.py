"""Pinned SkillOpt process that delegates objective rollouts to Skivolve."""

from __future__ import annotations

import argparse
import json
import os
import random
import shlex
import sys
import tempfile
from pathlib import Path, PurePosixPath
from typing import Any

from .skillopt_bridge import (
    FITNESS_COMPARISON_ID,
    OPTIMIZER_CALL_TIMEOUT_SECONDS,
    SkillOptBridgeError,
    candidate_snapshot_sha256,
    clone_candidate,
    git_blob_bytes,
    invoke_skivolve,
    load_strict_json,
    plan_from_json,
    private_write_bytes,
    private_write_json,
    revalidate_plan,
    sha256_bytes,
    sha256_file,
    validate_candidate,
    write_derived_suite,
)


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--plan", type=Path, required=True)
    parser.add_argument("--plan-sha256", required=True)
    return parser


def _load_skillopt(
    source: Path,
) -> tuple[type[Any], type[Any], type[Any], type[Any]]:
    source_text = str(source)
    if source_text in sys.path:
        sys.path.remove(source_text)
    sys.path.insert(0, source_text)
    from skillopt.datasets.base import BaseDataLoader, BatchSpec
    from skillopt.engine.trainer import ReflACTTrainer
    from skillopt.envs.base import EnvAdapter

    import skillopt

    imported = Path(skillopt.__file__).resolve(strict=True)
    if not imported.is_relative_to(source):
        raise SkillOptBridgeError(
            f"SkillOpt imported from {imported}, outside reviewed source {source}"
        )
    return BaseDataLoader, BatchSpec, EnvAdapter, ReflACTTrainer


def _case_items(
    suite: Any, plan: Any, case_ids: tuple[str, ...]
) -> list[dict[str, Any]]:
    by_id = {case.id: case for case in suite.cases}
    items: list[dict[str, Any]] = []
    for case_id in case_ids:
        case = by_id[case_id]
        prompt_path = case.prompt_file.resolve(strict=True)
        if not prompt_path.is_relative_to(plan.repository_root):
            raise SkillOptBridgeError(
                f"optimizer prompt escaped the baseline repository: {prompt_path}"
            )
        relative = PurePosixPath(
            prompt_path.relative_to(plan.repository_root).as_posix()
        )
        items.append(
            {
                "id": case.id,
                "skivolve_split": case.split,
                "task_type": f"skivolve-{case.skill}",
                "task_description": git_blob_bytes(
                    plan.repository_root, plan.baseline_commit, relative
                ).decode("utf-8"),
                "critical_expectations": list(case.critical_expectations),
            }
        )
    return items


def _infrastructure_passed(run: dict[str, Any]) -> bool:
    aggregate = run.get("aggregate")
    if not isinstance(aggregate, dict):
        return False
    gates = aggregate.get("gates")
    if not isinstance(gates, dict):
        return False
    required = (
        "execution_matrix_integrity",
        "infrastructure_integrity",
        "generator_model_stability",
    )
    return all(
        isinstance(gates.get(name), dict) and gates[name].get("passed") is True
        for name in required
    )


def _score_case(
    *,
    run: dict[str, Any],
    item: dict[str, Any],
    prediction_root: Path,
) -> dict[str, Any]:
    case_id = item["id"]
    expectations = tuple(item["critical_expectations"])
    pairs = [
        pair
        for pair in run.get("pairs", [])
        if isinstance(pair, dict)
        and pair.get("comparison_id") == FITNESS_COMPARISON_ID
        and pair.get("case_id") == case_id
    ]
    pairs.sort(key=lambda pair: pair.get("repetition", -1))
    if len(pairs) != 3 or [pair.get("repetition") for pair in pairs] != [0, 1, 2]:
        raise SkillOptBridgeError(f"Skivolve omitted repetitions for {case_id}")

    numerator = 0
    denominator = 3 * (len(expectations) + 1)
    hard = True
    observations: list[dict[str, Any]] = []
    conversation: list[dict[str, str]] = [
        {"role": "user", "content": item["task_description"]}
    ]
    for pair in pairs:
        treatment = pair.get("arms", {}).get("treatment", {})
        if not isinstance(treatment, dict):
            raise SkillOptBridgeError(
                f"Skivolve treatment arm is malformed for {case_id}"
            )
        executed = (
            pair.get("completed") is True and treatment.get("status") == "completed"
        )
        overall_passed = treatment.get("passed") is True
        scored_completion = executed and overall_passed
        critical = treatment.get("critical_results")
        if not isinstance(critical, dict):
            critical = {}
        exact_critical = {
            expectation: critical.get(expectation) is True
            for expectation in expectations
        }
        numerator += int(scored_completion) + sum(exact_critical.values())
        hard = hard and scored_completion and all(exact_critical.values())
        observations.append(
            {
                "repetition": pair["repetition"],
                "completed": executed,
                "overall_passed": overall_passed,
                "scored_completion": scored_completion,
                "critical_results": exact_critical,
                "error_stage": treatment.get("error_stage"),
                "error": treatment.get("error"),
            }
        )
        diff = treatment.get("diff")
        if isinstance(diff, str) and diff:
            conversation.append(
                {
                    "role": "assistant",
                    "content": (
                        f"Repetition {pair['repetition']} produced this workspace diff:\n{diff}"
                    ),
                }
            )
    verification = json.dumps(
        {"case_id": case_id, "objective_verification": observations},
        indent=2,
        sort_keys=True,
    )
    conversation.append({"role": "system", "content": verification})
    prediction_dir = prediction_root / case_id
    prediction_dir.mkdir(parents=True, mode=0o700, exist_ok=False)
    private_write_json(prediction_dir / "conversation.json", conversation)
    (prediction_dir / "target_user_prompt.txt").write_text(
        item["task_description"], encoding="utf-8"
    )
    os.chmod(prediction_dir / "target_user_prompt.txt", 0o600)
    failed = [
        expectation
        for observation in observations
        for expectation, passed in observation["critical_results"].items()
        if not passed
    ]
    failed.extend(
        f"repetition-{observation['repetition']}-incomplete"
        for observation in observations
        if not observation["completed"]
    )
    failed.extend(
        f"repetition-{observation['repetition']}-overall-failed"
        for observation in observations
        if observation["completed"] and not observation["overall_passed"]
    )
    return {
        "id": case_id,
        "hard": int(hard),
        "soft": numerator / denominator,
        "task_type": item["task_type"],
        "task_description": item["task_description"],
        "target_user_prompt": item["task_description"],
        "fail_reason": (
            "" if hard else "objective failures: " + ", ".join(sorted(set(failed)))
        ),
        "critical_expectations": list(expectations),
        "objective_verification": observations,
    }


def _build_runtime_classes(
    *,
    base_dataloader: type[Any],
    batch_spec: type[Any],
    env_adapter: type[Any],
    suite: Any,
    plan: Any,
    baseline_skill: bytes,
    run_records: list[dict[str, Any]],
) -> tuple[type[Any], type[Any]]:
    train_items = _case_items(suite, plan, plan.train_case_ids)
    selection_items = _case_items(suite, plan, plan.selection_case_ids)

    class SkivolveDataLoader(base_dataloader):
        def get_train_size(self) -> int:
            return len(train_items)

        def build_train_batch(self, batch_size: int, seed: int, **_kwargs: Any) -> Any:
            if batch_size > len(train_items):
                raise SkillOptBridgeError("training batch exceeds the frozen case pool")
            sampled = list(train_items)
            random.Random(seed).shuffle(sampled)
            sampled = sampled[:batch_size]
            return batch_spec(
                phase="train",
                split="train",
                seed=seed,
                batch_size=len(sampled),
                payload=sampled,
            )

        def build_eval_batch(
            self, env_num: int, split: str, seed: int, **_kwargs: Any
        ) -> Any:
            if split not in {"valid_seen", "selection", "val"}:
                raise SkillOptBridgeError(
                    f"SkillOpt requested forbidden eval split {split}"
                )
            if env_num not in {0, len(selection_items)}:
                raise SkillOptBridgeError("selection batch size drifted")
            return batch_spec(
                phase="eval",
                split="valid_seen",
                seed=seed,
                batch_size=len(selection_items),
                payload=list(selection_items),
            )

    class SkivolveAdapter(env_adapter):
        def __init__(self) -> None:
            self.dataloader = SkivolveDataLoader()
            self.analyst_workers = 1
            self.failure_only = False
            self.minibatch_size = max(1, len(train_items))
            self.edit_budget = 2

        def setup(self, cfg: dict[str, Any]) -> None:
            super().setup(cfg)
            self.dataloader.setup(cfg)

        def get_dataloader(self) -> Any:
            return self.dataloader

        def build_env_from_batch(
            self, batch: Any, **_kwargs: Any
        ) -> list[dict[str, Any]]:
            return list(batch.payload or [])

        def build_train_env(
            self, batch_size: int, seed: int, **kwargs: Any
        ) -> list[dict[str, Any]]:
            batch = self.dataloader.build_train_batch(batch_size, seed, **kwargs)
            return self.build_env_from_batch(batch)

        def build_eval_env(
            self, env_num: int, split: str, seed: int, **kwargs: Any
        ) -> list[dict[str, Any]]:
            batch = self.dataloader.build_eval_batch(env_num, split, seed, **kwargs)
            return self.build_env_from_batch(batch)

        def get_task_types(self) -> list[str]:
            return [f"skivolve-{plan.skill}"]

        def rollout(
            self,
            env_manager: list[dict[str, Any]],
            skill_content: str,
            out_dir: str,
            **_kwargs: Any,
        ) -> list[dict[str, Any]]:
            output = Path(out_dir).resolve()
            output.mkdir(parents=True, mode=0o700, exist_ok=True)
            candidate_bytes = skill_content.encode("utf-8")
            validate_candidate(candidate_bytes, baseline_skill)
            candidate_hash = sha256_bytes(candidate_bytes)
            candidate_path = output / "candidate.skill.md"
            private_write_bytes(candidate_path, candidate_bytes)
            clone = output / "candidate-repository"
            candidate_commit = clone_candidate(
                source_repository=plan.repository_root,
                destination=clone,
                baseline_commit=plan.baseline_commit,
                skill_path=plan.skill_path,
                candidate=candidate_bytes,
            )
            candidate_snapshot_hash = candidate_snapshot_sha256(
                clone, plan.bundle_source
            )
            manifest = write_derived_suite(
                clone,
                suite=suite,
                baseline_commit=plan.baseline_commit,
                candidate_commit=candidate_commit,
                fitness=True,
            )
            case_ids = tuple(item["id"] for item in env_manager)
            splits = {item["skivolve_split"] for item in env_manager}
            if len(splits) != 1 or not case_ids:
                raise SkillOptBridgeError(
                    "rollout must contain cases from one public split"
                )
            phases = [record["phase"] for record in run_records]
            if set(case_ids) == set(plan.selection_case_ids) and len(case_ids) == len(
                plan.selection_case_ids
            ):
                phase = "baseline_selection" if not phases else "candidate_selection"
            elif set(case_ids) == set(plan.train_case_ids) and len(case_ids) == len(
                plan.train_case_ids
            ):
                phase = "training"
            else:
                raise SkillOptBridgeError("SkillOpt requested an unbound case batch")
            allowed_transitions = {
                (): "baseline_selection",
                ("baseline_selection",): "training",
                ("baseline_selection", "training"): "candidate_selection",
            }
            if allowed_transitions.get(tuple(phases)) != phase:
                raise SkillOptBridgeError("SkillOpt rollout phase order drifted")
            run_dir = output / "skivolve-run"
            exit_code, _summary = invoke_skivolve(
                python=plan.skivolve_python,
                suite_path=manifest,
                split=next(iter(splits)),
                case_ids=case_ids,
                output_dir=run_dir,
                timeout_seconds=plan.timeout_seconds,
                comparison_id=FITNESS_COMPARISON_ID,
            )
            run_path = run_dir / "run.json"
            run = load_strict_json(run_path, maximum_bytes=64 * 1024 * 1024)
            if not isinstance(run, dict) or not _infrastructure_passed(run):
                raise SkillOptBridgeError(
                    "Skivolve rollout had incomplete infrastructure; it is not a candidate score"
                )
            prediction_root = output / "predictions"
            prediction_root.mkdir(mode=0o700, exist_ok=False)
            results = [
                _score_case(run=run, item=item, prediction_root=prediction_root)
                for item in env_manager
            ]
            record = {
                "ordinal": len(run_records),
                "phase": phase,
                "candidate_sha256": candidate_hash,
                "candidate_skill": str(candidate_path.relative_to(plan.output_dir)),
                "candidate_snapshot_sha256": candidate_snapshot_hash,
                "candidate_commit": candidate_commit,
                "case_ids": list(case_ids),
                "split": next(iter(splits)),
                "skivolve_exit_code": exit_code,
                "run_json": str(run_path.relative_to(plan.output_dir)),
                "run_json_sha256": sha256_file(run_path),
                "scores": [
                    {"id": result["id"], "hard": result["hard"], "soft": result["soft"]}
                    for result in results
                ],
            }
            run_records.append(record)
            return results

    return SkivolveDataLoader, SkivolveAdapter


def _trainer_config(
    plan: Any, baseline_path: Path, codex_executable: Path
) -> dict[str, Any]:
    return {
        "out_root": str(plan.output_dir / "skillopt"),
        "skill_init": str(baseline_path),
        "model_backend": "codex_exec",
        "optimizer_backend": "codex_exec",
        "target_backend": "codex_exec",
        "optimizer_model": plan.optimizer_model,
        "target_model": plan.optimizer_model,
        "reasoning_effort": "high",
        "codex_exec_path": str(codex_executable),
        "codex_exec_sandbox": "read-only",
        "codex_exec_approval_policy": "never",
        "codex_exec_use_sdk": False,
        "codex_exec_network_access": False,
        "codex_exec_web_search": False,
        "codex_trace_to_optimizer": False,
        "num_epochs": 1,
        "train_size": len(plan.train_case_ids),
        "batch_size": len(plan.train_case_ids),
        "accumulation": 1,
        "seed": plan.seed,
        "minibatch_size": max(1, len(plan.train_case_ids)),
        "merge_batch_size": 2,
        "analyst_workers": 1,
        "failure_only": False,
        "edit_budget": 2,
        "min_edit_budget": 1,
        "lr_scheduler": "constant",
        "lr_control_mode": "fixed",
        "skill_update_mode": "patch",
        "use_slow_update": False,
        "slow_update_gate_with_selection": True,
        "use_meta_skill": False,
        "use_skill_aware_reflection": False,
        "longitudinal_pair_policy": "mixed",
        "use_gate": True,
        "gate_metric": "hard",
        "use_semantic_density": False,
        "sel_env_num": len(plan.selection_case_ids),
        "test_env_num": 0,
        "eval_test": False,
        "exec_timeout": plan.timeout_seconds,
    }


def _optimizer_config_bytes(
    plan: Any, *, workspace: Path, optimizer_tmp: Path
) -> bytes:
    return (
        "\n".join(
            (
                f"model = {json.dumps(plan.optimizer_model)}",
                'model_reasoning_effort = "high"',
                'approval_policy = "never"',
                'default_permissions = "optimizer"',
                'forced_login_method = "chatgpt"',
                "allow_login_shell = false",
                'web_search = "disabled"',
                "include_apps_instructions = false",
                "include_collaboration_mode_instructions = false",
                "check_for_update_on_startup = false",
                "",
                "[tools.experimental_request_user_input]",
                "enabled = false",
                "",
                "[analytics]",
                "enabled = false",
                "",
                "[history]",
                'persistence = "none"',
                "",
                "[features]",
                "apps = false",
                "auth_elicitation = false",
                "browser_use = false",
                "browser_use_external = false",
                "browser_use_full_cdp_access = false",
                "code_mode_host = false",
                "computer_use = false",
                "goals = false",
                "guardian_approval = false",
                "hooks = false",
                "image_generation = false",
                "memories = false",
                "multi_agent = false",
                "plugin_sharing = false",
                "plugins = false",
                "remote_plugin = false",
                "skill_mcp_dependency_install = false",
                "tool_call_mcp_elicitation = false",
                "tool_suggest = false",
                "workspace_dependencies = false",
                "",
                "[shell_environment_policy]",
                'inherit = "none"',
                (
                    'set = { PATH = "/usr/bin:/bin", HOME = "/home/optimizer", '
                    f'LANG = "C.UTF-8", TMPDIR = {json.dumps(str(optimizer_tmp))} }}'
                ),
                "",
                "[permissions.optimizer]",
                'description = "Isolated SkillOpt optimizer"',
                "",
                "[permissions.optimizer.filesystem]",
                '":minimal" = "read"',
                '"/proc" = "deny"',
                f'{json.dumps(str(workspace))} = "read"',
                f'{json.dumps(str(optimizer_tmp))} = "write"',
                '"/home/optimizer" = "write"',
                '"/home/optimizer/.codex" = "read"',
                '"/home/optimizer/.codex/auth.json" = "deny"',
                '"/home/optimizer/.codex/config.toml" = "deny"',
                '"/opt/skivolve-codex" = "deny"',
                '"/opt/codex-resources/bwrap" = "deny"',
                "",
                "[permissions.optimizer.network]",
                "enabled = false",
                "",
            )
        )
    ).encode("utf-8")


def preflight_optimizer_boundary(plan: Any, workspace: Path) -> dict[str, object]:
    """Materialize and prove the no-tool optimizer boundary without a model call."""

    from .skillopt_codex_proxy import probe_optimizer_tool_boundary

    real = plan.optimizer_executable.resolve(strict=True)
    sandbox = plan.optimizer_sandbox.resolve(strict=True)
    if not real.is_file() or not os.access(real, os.X_OK):
        raise SkillOptBridgeError("Codex optimizer executable is not executable")
    if sha256_file(real) != plan.optimizer_executable_sha256:
        raise SkillOptBridgeError("Codex optimizer executable drifted from the plan")
    if not sandbox.is_file() or not os.access(sandbox, os.X_OK):
        raise SkillOptBridgeError("optimizer sandbox is not executable")
    if sha256_file(sandbox) != plan.optimizer_sandbox_sha256:
        raise SkillOptBridgeError("optimizer sandbox drifted from the plan")
    codex_home = Path(os.environ.get("CODEX_HOME", Path.home() / ".codex"))
    auth = codex_home / "auth.json"
    auth_metadata = auth.lstat()
    if auth.is_symlink() or not auth.is_file() or auth_metadata.st_size == 0:
        raise SkillOptBridgeError(
            "Codex optimizer requires a non-empty, regular auth.json"
        )
    optimizer_tmp = workspace / "optimizer-tmp"
    optimizer_tmp.mkdir(mode=0o700, exist_ok=False)
    config = workspace / "optimizer-config.toml"
    private_write_bytes(
        config,
        _optimizer_config_bytes(plan, workspace=workspace, optimizer_tmp=optimizer_tmp),
    )
    return probe_optimizer_tool_boundary(
        sandbox=sandbox,
        executable=real,
        auth=auth.resolve(strict=True),
        config=config,
        workspace=workspace,
        optimizer_tmp=optimizer_tmp,
    )


def _prepare_codex_proxy(plan: Any) -> tuple[Path, dict[str, Any]]:
    permission_preflight = preflight_optimizer_boundary(plan, plan.output_dir)
    real = plan.optimizer_executable.resolve(strict=True)
    sandbox = plan.optimizer_sandbox.resolve(strict=True)
    codex_home = Path(os.environ.get("CODEX_HOME", Path.home() / ".codex"))
    auth = (codex_home / "auth.json").resolve(strict=True)
    launcher_dir = plan.output_dir / "optimizer-bin"
    launcher_dir.mkdir(mode=0o700, exist_ok=False)
    launcher = launcher_dir / "codex"
    script = (
        "#!/bin/sh\nexec "
        f"{shlex.quote(str(plan.skillopt_python))} -I "
        '-m skivolve.skillopt_codex_proxy "$@"\n'
    ).encode("utf-8")
    private_write_bytes(launcher, script)
    os.chmod(launcher, 0o700)
    optimizer_tmp = plan.output_dir / "optimizer-tmp"
    os.environ["TMPDIR"] = str(optimizer_tmp)
    tempfile.tempdir = str(optimizer_tmp)
    config = plan.output_dir / "optimizer-config.toml"
    ledger = plan.output_dir / "codex-invocations.txt"
    private_write_bytes(ledger, b"0\n")
    bindings = {
        "max_invocations": plan.planned_optimizer_invocations,
        "per_invocation_timeout_seconds": OPTIMIZER_CALL_TIMEOUT_SECONDS,
        "codex_executable": str(real),
        "codex_executable_sha256": sha256_file(real),
        "sandbox_executable": str(sandbox),
        "sandbox_executable_sha256": sha256_file(sandbox),
        "filesystem_isolation": "bubblewrap-minimal-read-set-v1",
        "optimizer_config": str(config.relative_to(plan.output_dir)),
        "optimizer_config_sha256": sha256_file(config),
        "permission_preflight": permission_preflight,
        "optimizer_tmp": str(optimizer_tmp.relative_to(plan.output_dir)),
        "ledger": str(ledger.relative_to(plan.output_dir)),
    }
    os.environ.update(
        {
            "SKIVOLVE_SKILLOPT_CODEX_ROOT": str(plan.output_dir),
            "SKIVOLVE_SKILLOPT_CODEX_REAL": str(real),
            "SKIVOLVE_SKILLOPT_CODEX_REAL_SHA256": bindings["codex_executable_sha256"],
            "SKIVOLVE_SKILLOPT_CODEX_SANDBOX": str(sandbox),
            "SKIVOLVE_SKILLOPT_CODEX_SANDBOX_SHA256": bindings[
                "sandbox_executable_sha256"
            ],
            "SKIVOLVE_SKILLOPT_CODEX_AUTH_FILE": str(auth),
            "SKIVOLVE_SKILLOPT_CODEX_CONFIG": str(config),
            "SKIVOLVE_SKILLOPT_CODEX_CONFIG_SHA256": bindings[
                "optimizer_config_sha256"
            ],
            "SKIVOLVE_SKILLOPT_CODEX_TMP": str(optimizer_tmp),
            "SKIVOLVE_SKILLOPT_CODEX_WORKSPACE": str(plan.output_dir),
            "SKIVOLVE_SKILLOPT_CODEX_PROXY_BIN": str(launcher_dir),
            "SKIVOLVE_SKILLOPT_CODEX_LEDGER": str(ledger),
            "SKIVOLVE_SKILLOPT_CODEX_MAX_INVOCATIONS": str(
                plan.planned_optimizer_invocations
            ),
            "SKIVOLVE_SKILLOPT_CODEX_TIMEOUT_SECONDS": str(
                OPTIMIZER_CALL_TIMEOUT_SECONDS
            ),
        }
    )
    return launcher, bindings


def _finalize_optimizer_budget(plan: Any, binding: dict[str, Any]) -> dict[str, Any]:
    ledger = plan.output_dir / binding["ledger"]
    if not ledger.is_file() or ledger.is_symlink():
        raise SkillOptBridgeError(
            "Codex optimizer did not create its invocation ledger"
        )
    raw = ledger.read_text(encoding="ascii").strip()
    if not raw.isdigit():
        raise SkillOptBridgeError("Codex invocation ledger is malformed")
    used = int(raw)
    if not 0 <= used <= plan.planned_optimizer_invocations:
        raise SkillOptBridgeError("Codex optimizer invocation budget was violated")
    return {**binding, "used_invocations": used}


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    try:
        observed_plan_hash = sha256_file(args.plan)
        if observed_plan_hash != args.plan_sha256:
            raise SkillOptBridgeError(
                "optimization plan hash does not match launcher binding"
            )
        plan = plan_from_json(load_strict_json(args.plan))
        if not args.plan.resolve(strict=True).is_relative_to(plan.output_dir):
            raise SkillOptBridgeError(
                "optimization plan must reside inside its run root"
            )
        suite, baseline_skill, upstream = revalidate_plan(plan)
        baseline_path = plan.output_dir / "initial.skill.md"
        private_write_bytes(baseline_path, baseline_skill)
        loaded = _load_skillopt(plan.skillopt_source)
        base_dataloader, batch_spec, env_adapter, trainer_class = loaded
        run_records: list[dict[str, Any]] = []
        _loader, adapter_class = _build_runtime_classes(
            base_dataloader=base_dataloader,
            batch_spec=batch_spec,
            env_adapter=env_adapter,
            suite=suite,
            plan=plan,
            baseline_skill=baseline_skill,
            run_records=run_records,
        )
        codex_launcher, optimizer_budget = _prepare_codex_proxy(plan)
        config = _trainer_config(plan, baseline_path, codex_launcher)
        trainer = trainer_class(config, adapter_class())
        trainer_summary = trainer.train()
        optimizer_budget = _finalize_optimizer_budget(plan, optimizer_budget)
        best_path = plan.output_dir / "skillopt" / "best_skill.md"
        candidate = best_path.read_bytes()
        validate_candidate(candidate, baseline_skill)
        result = {
            "schema_version": 1,
            "status": "completed",
            "plan_sha256": observed_plan_hash,
            "skillopt": upstream,
            "best_skill": str(best_path.relative_to(plan.output_dir)),
            "best_skill_sha256": sha256_bytes(candidate),
            "best_skill_bytes": len(candidate),
            "initial_skill_sha256": sha256_bytes(baseline_skill),
            "inner_runs": run_records,
            "trainer_summary": trainer_summary,
            "optimizer_budget": optimizer_budget,
            "holdout_used": False,
            "automatic_adoption": False,
        }
        result_path = plan.output_dir / "sidecar-result.json"
        private_write_json(result_path, result)
        print(json.dumps({"status": "completed", "result": str(result_path)}))
        return 0
    except (SkillOptBridgeError, OSError, ValueError, ImportError) as exc:
        print(f"SkillOpt sidecar error: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
