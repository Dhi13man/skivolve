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
    string_steps = (
        steps
        if isinstance(steps, list)
        and 2 <= len(steps) <= 3
        and all(isinstance(step, str) for step in steps)
        else None
    )
    object_steps = (
        steps
        if isinstance(steps, list)
        and 2 <= len(steps) <= 3
        and all(
            isinstance(step, dict)
            and set(step) == {"file", "edit"}
            and all(isinstance(step.get(field), str) for field in ("file", "edit"))
            for step in steps
        )
        else None
    )
    if string_steps is not None:
        step_texts = [step.lower().replace("`", "") for step in string_steps]
    elif object_steps is not None:
        step_texts = [
            f"{step['edit']} {step['file']}".lower().replace("`", "")
            for step in object_steps
        ]
    else:
        step_texts = []
    steps_text = " ".join(step_texts)
    verification_value = values.get("verification", "")
    if isinstance(verification_value, dict):
        command_value = verification_value.get("command", "")
    elif isinstance(verification_value, list) and verification_value:
        command_value = verification_value[0]
    else:
        command_value = ""
    command = flatten_text(command_value).lower().replace("`", "")
    native_command = bool(
        re.search(
            r"\bpython3?\s+(?:-m\s+unittest(?:\s+-v)?\s+"
            r"test_policy(?:\.py)?(?:\s+-v)?|test_policy\.py)\b",
            command,
        )
        and not re.search(
            r"\b(?:do not|don't|never|unnecessary|skip|print|echo)\b|\s-c\s",
            command,
        )
    )
    if isinstance(verification_value, list):
        verification_items = [
            flatten_text(item).lower().replace("`", "") for item in verification_value
        ]
        confirmation = verification_items[1] if len(verification_items) == 2 else ""
        verification_schema = (
            len(verification_items) == 2
            and all(isinstance(item, str) for item in verification_value)
            and "confirm" in confirmation
            and "signature" in confirmation
            and re.search(r"\b(?:unchanged|remains?)\b", confirmation)
        )
    elif isinstance(verification_value, dict):
        verification_keys = set(verification_value)
        expected = flatten_text(verification_value.get("expected", "")).lower()
        baseline = flatten_text(verification_value.get("baseline", "")).lower()
        checks = verification_value.get("checks")
        expected_pass = bool(
            re.search(r"\b(?:test|boundary|unittest|test_boundary)\b", expected)
            and re.search(r"\bpass(?:es|ed)?\b", expected)
        )
        verification_schema = isinstance(verification_value.get("command"), str) and (
            (
                verification_keys
                in (
                    {"command", "expected"},
                    {"command", "expected", "status"},
                )
                and isinstance(verification_value.get("expected"), str)
                and expected_pass
                and (
                    "status" not in verification_value
                    or verification_value["status"] == "not_run_plan_only"
                )
            )
            or (
                verification_keys == {"baseline", "command", "expected"}
                and isinstance(verification_value.get("baseline"), str)
                and isinstance(verification_value.get("expected"), str)
                and re.search(r"\b(?:native|command)\b", baseline)
                and re.search(r"\bpass(?:es|ed)?\b", baseline)
                and re.search(r"\b(?:before|currently)\b", baseline)
                and expected_pass
            )
            or (
                verification_keys == {"checks", "command"}
                and isinstance(checks, list)
                and all(isinstance(item, str) for item in checks)
                and len(checks) == 3
                and "boundary" in flatten_text(checks).lower()
                and "passes" in flatten_text(checks).lower()
                and "signature" in flatten_text(checks).lower()
                and "unchanged" in flatten_text(checks).lower()
                and "4" in flatten_text(checks)
                and re.search(r"\b(?:rejected|false)\b", flatten_text(checks).lower())
            )
        )
    else:
        verification_schema = False
    non_goals = values.get("non_goals")
    non_goals_text = flatten_text(non_goals).lower()
    non_goals_schema = (
        isinstance(non_goals, list)
        and 2 <= len(non_goals) <= 5
        and all(isinstance(item, str) for item in non_goals)
    )
    exact_schema = (
        artifact is not None
        and set(artifact) == EXPECTED_KEYS
        and isinstance(artifact.get("level"), str)
        and (string_steps is not None or object_steps is not None)
        and verification_schema
        and non_goals_schema
    )
    plan_scope = f"{steps_text} {non_goals_text}"
    prohibited_step = re.search(
        r"\b(?:alter|edit|rewrite)\s+may_retry\b|"
        r"\bmay_retry\b[^.;]{0,100}\b(?:always|every attempt)\b|"
        r"\bmax_retries\b[^.;]{0,30}\b4\s+to\s+(?:3|100)\b|"
        r"\b(?:add|create|delete|replace)\b[^.;]{0,40}"
        r"\b(?:dependency|config|policy\.py|service)\b",
        steps_text,
    )
    production_steps = [step for step in step_texts if "max_retries" in step]
    test_steps = [
        step
        for step in step_texts
        if "test_policy.py" in step
        and ("may_retry(3)" in step or "attempts 2 and 3" in step)
    ]
    preservation_steps = [
        step
        for step in step_texts
        if "may_retry" in step
        and re.search(r"\b(?:unchanged|preserve|leave|keep)\b", step)
    ]
    complete_steps = all(
        step in production_steps or step in test_steps or step in preservation_steps
        for step in step_texts
    )

    precise_production = (
        bool(step_texts)
        and len(production_steps) == 1
        and "policy.py" in production_steps[0].replace("test_policy.py", "")
        and re.search(
            r"\bmax_retries\b[^.;]{0,35}\b(?:from\s+)?(?:=\s*)?3\b"
            r"[^.;]{0,35}\b(?:to\s+)?(?:max_retries\s*=\s*)?4\b",
            production_steps[0],
        )
        and preservation_steps
        and prohibited_step is None
        and complete_steps
    )
    focused_test = len(test_steps) == 1 and bool(
        not re.search(
            r"\bincorrect\b|may_retry\(3\)[^.;]{0,25}\bfalse\b|"
            r"may_retry\(4\)[^.;]{0,25}\btrue\b",
            test_steps[0],
        )
        and (
            (
                re.search(
                    r"may_retry\(3\)[^.;]{0,35}\b(?:true|accepted)\b",
                    test_steps[0],
                )
                and re.search(
                    r"may_retry\(4\)[^.;]{0,35}\b(?:false|rejected)\b",
                    test_steps[0],
                )
            )
            or (
                re.search(
                    r"attempts?\s+2\s+and\s+3[^.;]{0,25}\baccepted\b",
                    test_steps[0],
                )
                and re.search(r"attempt\s+4[^.;]{0,25}\brejected\b", test_steps[0])
            )
        )
    )
    bounded_non_goals = (
        non_goals_schema
        and all(
            isinstance(item, str)
            and re.match(r"^(?:no|do not)\b", item.lower())
            and not re.search(
                r"\b(?:but|then|however)\b[^.;]{0,40}"
                r"\b(?:add|create|change|edit|rewrite)\b",
                item.lower(),
            )
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
        exact_schema
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
