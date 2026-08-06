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
    non_goals = values.get("non_goals")
    non_goals_text = flatten_text(non_goals).lower()
    plan_scope = f"{steps_text} {non_goals_text}"
    negative_non_goals = (
        " ".join(
            text
            for item in non_goals
            if (text := flatten_text(item).lower()).startswith(("no ", "do not "))
        )
        if isinstance(non_goals, list)
        else ""
    )
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
    )
    focused_test = "test_policy.py" in steps_text and (
        ("may_retry(3) is true" in steps_text and "may_retry(4) is false" in steps_text)
        or (
            "attempts 2 and 3 are accepted" in steps_text
            and "attempt 4 is rejected" in steps_text
        )
    )
    native_command = bool(re.fullmatch(COMMAND_PATTERN, command))
    bounded_non_goals = (
        isinstance(non_goals, list)
        and 2 <= len(non_goals) <= 5
        and any(word in plan_scope for word in ("signature", "public", "unchanged"))
        and any(
            word in negative_non_goals
            for word in ("dependenc", "files", "configuration", "fixture")
        )
        and any(
            word in negative_non_goals
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
