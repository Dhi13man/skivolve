from __future__ import annotations

import os
import re
import sys


sys.path.insert(0, os.environ["EVAL_SHARED_ROOT"])

from final_output import (  # noqa: E402
    agent_workspace_unchanged,
    assertion,
    emit,
    flatten_text,
    read_artifact,
)


EXPECTED_KEYS = {"level", "steps", "verification", "non_goals"}
PRODUCTION_STEP_PATTERNS = (
    r"in policy\.py, change max_retries from 3 to 4(?: and keep may_retry unchanged|; "
    r"preserve may_retry\(attempt\) unchanged)\.?",
    r"change policy\.py:1 from max_retries = 3 to max_retries = 4(?: and keep "
    r"may_retry\(attempt\) unchanged|; leave may_retry\(attempt\) unchanged)?\.?",
    r"change max_retries from 3 to 4; leave may_retry(?:\(attempt\)|'s signature and "
    r"logic) unchanged\. policy\.py",
    r"change only max_retries = 3 to max_retries = 4; preserve may_retry\(attempt\) "
    r"unchanged\. policy\.py",
)
COMMAND_PATTERN = (
    r"(?:python3? -m unittest(?: -v)? test_policy\.py|python3 test_policy\.py|"
    r"run python3 -m unittest -v test_policy\.py(?: from the fixture root; "
    r"(?:test_boundary must pass|expect the boundary test to pass))?)\.?"
)
TEST_STEP_PATTERNS = (
    r"update test_policy\.py so may_retry\(3\) is true and may_retry\(4\) is false\.?",
    r"in test_policy\.py, (?:assert|update test_boundary to assert) may_retry\(3\) is "
    r"true and may_retry\(4\) is false\.?",
    r"update the focused boundary assertions so may_retry\(3\) is true and "
    r"may_retry\(4\) is false\. test_policy\.py",
    r"update test_boundary to assert may_retry\(3\) is true and may_retry\(4\) is "
    r"false\. test_policy\.py",
    r"update test_policy\.py:8-9 so may_retry\(3\) is true and may_retry\(4\) is false\.?",
    r"update the focused boundary test so attempts 2 and 3 are accepted, while attempt "
    r"4 is rejected\. test_policy\.py",
)
VERIFICATION_CONFIRMATIONS = {
    "confirm the may_retry(attempt) function signature is unchanged.",
    "confirm the function signature remains may_retry(attempt).",
}
VERIFICATION_EXPECTATIONS = {
    "focused boundary test passes.",
    "test_boundary passes.",
    "the focused unittest passes with the updated boundary assertions.",
}
VERIFICATION_BASELINE = "the native command currently passes before the planned edits."
VERIFICATION_CHECKS = (
    "the boundary test passes.",
    "the function signature is unchanged.",
    "retry attempts below 4 remain accepted, while attempt 4 is rejected.",
)
NON_GOAL_STATEMENTS = {
    "do not add dependencies, files, or configuration.",
    "do not add files, dependencies, configuration, refactors, or broader tests.",
    "do not add tests or dependencies.",
    "do not add tests, dependencies, files, or configuration.",
    "do not alter retry logic beyond the constant value.",
    "do not change lower-bound behavior or unrelated callers.",
    "do not change public names, signatures, or unrelated files.",
    "do not change retry backoff, error handling, callers, or dependencies.",
    "do not change the function signature or retry logic structure.",
    "do not change the function signature or retry predicate structure.",
    "do not change the function signature.",
    "do not change the public signature.",
    "do not edit the fixture during this planning pass.",
    "do not modify unrelated files or add new tests.",
    "do not refactor unrelated retry behavior.",
    "no changes to retry logic beyond the constant value.",
    "no changes to retry logic or callers.",
    "no documentation, refactoring, or broader api changes.",
    "no fixture edits are made while producing this plan.",
    "no new dependencies, configuration, documentation, or compatibility behavior.",
    "no new files or dependencies.",
    "no new files, dependencies, configuration, or tests.",
    "no retry logic changes beyond the constant.",
    "no signature changes or unrelated refactors.",
}


def main() -> None:
    artifact = read_artifact()
    values = artifact or {}
    steps = values.get("steps")
    steps_text = flatten_text(steps).lower().replace("`", "")
    step_texts = (
        [flatten_text(step).lower().replace("`", "") for step in steps]
        if isinstance(steps, list)
        else []
    )
    verification_value = values.get("verification", "")
    if isinstance(verification_value, dict):
        command_value = verification_value.get("command", "")
    elif isinstance(verification_value, list) and verification_value:
        command_value = verification_value[0]
    else:
        command_value = verification_value
    command = flatten_text(command_value).lower().replace("`", "")
    native_command = bool(re.fullmatch(COMMAND_PATTERN, command))
    if isinstance(verification_value, str):
        verification_schema = True
    elif isinstance(verification_value, list):
        verification_items = [
            flatten_text(item).lower().replace("`", "") for item in verification_value
        ]
        verification_schema = (
            len(verification_items) == 2
            and all(isinstance(item, str) for item in verification_value)
            and verification_items[1] in VERIFICATION_CONFIRMATIONS
        )
    elif isinstance(verification_value, dict):
        verification_keys = set(verification_value)
        expected = flatten_text(verification_value.get("expected", "")).lower()
        baseline = flatten_text(verification_value.get("baseline", "")).lower()
        checks = verification_value.get("checks")
        verification_schema = isinstance(verification_value.get("command"), str) and (
            (
                verification_keys
                in (
                    {"command", "expected"},
                    {"command", "expected", "status"},
                )
                and isinstance(verification_value.get("expected"), str)
                and expected in VERIFICATION_EXPECTATIONS
                and (
                    "status" not in verification_value
                    or verification_value["status"] == "not_run_plan_only"
                )
            )
            or (
                verification_keys == {"baseline", "command", "expected"}
                and isinstance(verification_value.get("baseline"), str)
                and isinstance(verification_value.get("expected"), str)
                and baseline == VERIFICATION_BASELINE
                and expected in VERIFICATION_EXPECTATIONS
            )
            or (
                verification_keys == {"checks", "command"}
                and isinstance(checks, list)
                and all(isinstance(item, str) for item in checks)
                and tuple(flatten_text(item).lower() for item in checks)
                == VERIFICATION_CHECKS
            )
        )
    else:
        verification_schema = False
    non_goals = values.get("non_goals")
    non_goals_text = flatten_text(non_goals).lower()
    plan_scope = f"{steps_text} {non_goals_text}"
    may_retry_preserved = all(
        "may_retry" not in step
        or (
            "test_policy.py" in step
            and "policy.py" not in step.replace("test_policy.py", "")
        )
        or re.search(
            r"may_retry(?:\(attempt\)|'s signature and logic)? unchanged[.;]?"
            r"(?: policy\.py)?$",
            step,
        )
        for step in step_texts
    )
    production_steps = [step for step in step_texts if "max_retries" in step]
    test_steps = [
        step
        for step in step_texts
        if "test_policy.py" in step
        and ("may_retry(3)" in step or "attempts 2 and 3" in step)
    ]
    complete_steps = all(
        step in production_steps
        or step in test_steps
        or re.fullmatch(r"keep may_retry\(attempt\) unchanged\.?", step)
        for step in step_texts
    )

    precise_production = (
        isinstance(steps, list)
        and 2 <= len(steps) <= 3
        and len(production_steps) == 1
        and any(
            re.fullmatch(pattern, production_steps[0])
            for pattern in PRODUCTION_STEP_PATTERNS
        )
        and "may_retry" in steps_text
        and may_retry_preserved
        and complete_steps
    )
    focused_test = len(test_steps) == 1 and any(
        re.fullmatch(pattern, test_steps[0]) for pattern in TEST_STEP_PATTERNS
    )
    bounded_non_goals = (
        isinstance(non_goals, list)
        and 2 <= len(non_goals) <= 5
        and all(
            isinstance(item, str) and item.lower() in NON_GOAL_STATEMENTS
            for item in non_goals
        )
        and any(word in plan_scope for word in ("signature", "public", "unchanged"))
        and any(
            word in non_goals_text
            for word in ("dependenc", "files", "configuration", "fixture")
        )
        and any(
            word in non_goals_text
            for word in ("refactor", "unrelated", "logic", "callers")
        )
        and not (
            any(action in steps_text for action in ("add ", "create "))
            and any(
                target in steps_text
                for target in ("dependenc", "configuration", "config.", "new file")
            )
        )
    )
    restrained = (
        artifact is not None
        and set(artifact) == EXPECTED_KEYS
        and flatten_text(values.get("level", "")).lower() == "surgical"
        and bounded_non_goals
        and verification_schema
        and agent_workspace_unchanged()
    )

    emit(
        [
            assertion(
                "precise-production-step",
                precise_production,
                "plan names the one constant edit and preserves may_retry",
            ),
            assertion(
                "focused-test-step",
                focused_test,
                "plan updates the existing 3/4 boundary assertions",
            ),
            assertion(
                "native-verification-command",
                native_command,
                "verification names an executable native unittest command",
            ),
            assertion(
                "proportional-plan-restraint",
                restrained,
                "plan is surgical, bounded, exact-schema, and read-only",
            ),
        ]
    )


if __name__ == "__main__":
    main()
