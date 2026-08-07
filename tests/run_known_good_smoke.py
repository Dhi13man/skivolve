#!/usr/bin/env python3
"""Run all checked-in known-good calibrations through the production verifier path."""

from __future__ import annotations

import argparse
import json
from pathlib import Path
import shutil
import subprocess
import sys


SUITE_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(SUITE_ROOT))

from skivolve import EvalRunner, FakeProvider, RunSelection, load_suite  # noqa: E402


TEST_TARGETS = {
    "testing-oracle-sensitivity": "test_discounts.py",
    "testing-parser-boundaries": "frame_test.go",
    "testing-state-machine-sequences": "subscription.test.js",
    "testing-real-boundary-fidelity": "test_registry.py",
    "testing-concurrency-flake": "squares_test.go",
    "testing-legacy-characterization": "test_legacy_billing.py",
    "testing-event-idempotency": "ledger.test.js",
}


def _apply_known_good(case_id: str, workspace: Path) -> str:
    if case_id.startswith("software-"):
        case_directory = (
            SUITE_ROOT / "cases" / "software" / case_id.removeprefix("software-")
        )
        artifact = case_directory / "calibration" / "good" / "artifact.json"
        if artifact.is_file():
            return artifact.read_text(encoding="utf-8")
        apply_script = case_directory / "calibration" / "good" / "apply.py"
        completed = subprocess.run(
            [sys.executable, str(apply_script), str(workspace)],
            cwd=case_directory,
            capture_output=True,
            text=True,
            timeout=60,
            check=False,
            shell=False,
        )
        if completed.returncode != 0:
            raise RuntimeError(
                f"{case_id} known-good patch failed: {completed.stderr.strip()}"
            )
        return "Applied the checked-in known-good calibration."
    case_directory = SUITE_ROOT / "cases" / "testing" / case_id.removeprefix("testing-")
    target = TEST_TARGETS[case_id]
    shutil.copyfile(
        case_directory / "calibration" / "good" / target,
        workspace / target,
    )
    return "Applied the checked-in known-good calibration."


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--output-dir",
        required=True,
        type=Path,
        help="new or empty directory for the complete production-run evidence",
    )
    arguments = parser.parse_args()
    suite = load_suite(SUITE_ROOT / "suite.json")

    def agent(request):
        final_output = _apply_known_good(request.case_id, request.workspace)
        return {
            "final_output": final_output,
            "actual_models": [request.model],
            "cost_usd": 0.0,
            "tokens": {"input_tokens": 0, "output_tokens": 0},
        }

    provider = FakeProvider(
        agent_handler=agent,
        comparator_handler=lambda _request: {
            "winner": "tie",
            "rationale": "Known-good smoke intentionally supplies equivalent arms.",
            "assertions": [],
            "actual_models": [suite.comparator.model],
            "cost_usd": 0.0,
            "tokens": {"input_tokens": 0, "output_tokens": 0},
        },
    )
    result = EvalRunner(suite, provider, provider).run(
        RunSelection(
            split="public",
            comparison_ids=("original-vs-no-skill",),
            verifier_only=True,
        ),
        output_dir=arguments.output_dir,
    )

    pairs = result["pairs"]
    arms = [arm for pair in pairs for arm in pair["arms"].values()]
    comparison = next(
        item for item in suite.comparisons if item.id == "original-vs-no-skill"
    )
    public_case_count = sum(
        case.split in {"train", "validation"} for case in suite.cases
    )
    expected_pairs = public_case_count * comparison.repetitions
    expected_arms = expected_pairs * 2
    failures = [
        f"{arm['pair_id']}:{arm['role']}:{arm['error']}"
        for arm in arms
        if arm["status"] != "completed"
        or not arm["passed"]
        or not arm["verifier"].get("valid")
        or not arm["verifier"].get("passed")
    ]
    if len(pairs) != expected_pairs or len(arms) != expected_arms:
        failures.append(
            f"expected {expected_pairs} pairs/{expected_arms} arms, "
            f"got {len(pairs)}/{len(arms)}"
        )
    aggregate = result["aggregate"]
    if result.get("execution_mode") != "verifier_only":
        failures.append("run report did not identify verifier-only execution mode")
    if aggregate.get("execution_mode") != "verifier_only":
        failures.append("aggregate did not identify verifier-only execution mode")
    if aggregate["final_release_authorized"]:
        failures.append("verifier-only mode authorized a final release")
    if not aggregate["gates"]["infrastructure_integrity"]["passed"]:
        failures.append("known-good verifier-only run had infrastructure errors")
    if not aggregate["gates"]["treatment_objective_stability"]["passed"]:
        failures.append("known-good treatment was not stable across all repetitions")
    if not result["passed"]:
        failures.append("known-good verifier-only objective gates did not pass")

    summary = {
        "pairs": len(pairs),
        "arms": len(arms),
        "completed_arms": sum(arm["status"] == "completed" for arm in arms),
        "passed_arms": sum(bool(arm["passed"]) for arm in arms),
        "objective_stability": aggregate["gates"]["treatment_objective_stability"][
            "passed"
        ],
        "evidence": str(arguments.output_dir.resolve() / "run.json"),
        "failures": failures,
    }
    print(json.dumps(summary, indent=2, sort_keys=True))
    return 1 if failures else 0


if __name__ == "__main__":
    raise SystemExit(main())
