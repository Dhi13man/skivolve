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
    command_value = (
        verification_value.get("command", "")
        if isinstance(verification_value, dict)
        else verification_value
    )
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
        or "test_policy.py" in step
        or re.search(
            r"may_retry(?:\(attempt\)|'s signature and logic)? unchanged[.;]?"
            r"(?: policy\.py)?$",
            step,
        )
        for step in step_texts
    )

    precise_production = (
        isinstance(steps, list)
        and 2 <= len(steps) <= 3
        and "policy.py" in steps_text
        and "max_retries" in steps_text
        and any(
            transition in steps_text
            for transition in (
                "max_retries from 3 to 4",
                "max_retries = 3 to max_retries = 4",
            )
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
    native_command = (
        command.startswith(
            (
                "python ",
                "python3 ",
                "run python ",
                "run python3 ",
                "execute python ",
                "execute python3 ",
            )
        )
        and "test_policy.py" in command
        and ("unittest" in command or "python3 test_policy.py" in command)
        and not any(
            phrase in command
            for phrase in ("do not", "don't", "not run", "unnecessary", "skip ")
        )
    )
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
