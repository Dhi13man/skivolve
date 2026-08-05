#!/usr/bin/env python3
"""Prove every software case accepts its good patch and rejects its bad patch."""

from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile


SUITE_MANIFEST = Path(__file__).resolve().parents[2] / "suite.json"
SUITE_ROOT = SUITE_MANIFEST.parent
sys.path.insert(0, str(SUITE_ROOT / "cases"))

from _calibration_tools import (  # noqa: E402
    private_tool_environment,
    sandbox_tool_paths,
)


def verifier_environment(
    workspace: Path, case_root: Path, tool_environment: dict[str, str]
) -> dict[str, str]:
    environment = dict(tool_environment)
    resolved = sandbox_tool_paths()
    environment.update(
        {
            "EVAL_WORKSPACE": str(workspace),
            "EVAL_SUITE_ROOT": str(SUITE_ROOT),
            "EVAL_CASE_ROOT": str(case_root),
            "EVAL_SHARED_ROOT": str(SUITE_ROOT / "cases" / "testing" / "_shared"),
            "EVAL_HOST_UID": str(os.getuid()),
            "EVAL_UNSHARE": str(resolved["unshare"]),
            "EVAL_MOUNT": str(resolved["mount"]),
            "EVAL_SETPRIV": str(resolved["setpriv"]),
            "EVAL_ENV": str(resolved["env"]),
            "LANG": "C.UTF-8",
            "LC_ALL": "C.UTF-8",
            "TZ": "UTC",
        }
    )
    return environment


def run(
    argv: list[str],
    *,
    cwd: Path,
    timeout_seconds: int,
    env: dict[str, str] | None = None,
) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        argv,
        cwd=cwd,
        env=env,
        text=True,
        capture_output=True,
        timeout=timeout_seconds,
        check=False,
    )


def parse_verdict(
    result: subprocess.CompletedProcess[str], case_id: str
) -> dict[str, object]:
    if result.returncode != 0:
        raise AssertionError(
            f"{case_id}: verifier exited {result.returncode}: {result.stderr.strip()}"
        )
    try:
        verdict = json.loads(result.stdout)
    except json.JSONDecodeError as error:
        raise AssertionError(
            f"{case_id}: verifier emitted invalid JSON: {result.stdout!r}"
        ) from error

    allowed = {"passed", "assertions", "metrics"}
    if set(verdict) - allowed or not {"passed", "assertions"}.issubset(verdict):
        raise AssertionError(
            f"{case_id}: verifier keys violate contract: {sorted(verdict)}"
        )
    if not isinstance(verdict["passed"], bool) or not isinstance(
        verdict["assertions"], list
    ):
        raise AssertionError(f"{case_id}: verifier types violate contract")
    if "metrics" in verdict and not isinstance(verdict["metrics"], dict):
        raise AssertionError(f"{case_id}: verifier metrics must be an object")

    assertion_ids: list[str] = []
    for index, assertion in enumerate(verdict["assertions"]):
        if not isinstance(assertion, dict) or set(assertion) != {
            "id",
            "passed",
            "evidence",
        }:
            raise AssertionError(
                f"{case_id}: assertion {index} violates the object contract"
            )
        if (
            not isinstance(assertion["id"], str)
            or not isinstance(assertion["passed"], bool)
            or not isinstance(assertion["evidence"], str)
            or not assertion["id"]
            or not assertion["evidence"]
        ):
            raise AssertionError(
                f"{case_id}: assertion {index} has invalid field types"
            )
        assertion_ids.append(assertion["id"])
    if len(assertion_ids) != len(set(assertion_ids)):
        raise AssertionError(f"{case_id}: verifier emitted duplicate assertion IDs")
    aggregate = all(assertion["passed"] for assertion in verdict["assertions"])
    if verdict["passed"] is not aggregate:
        raise AssertionError(
            f"{case_id}: top-level passed disagrees with its assertions"
        )
    return verdict


def _unique_json_object(pairs: list[tuple[str, object]]) -> dict[str, object]:
    result: dict[str, object] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError(f"duplicate JSON key: {key}")
        result[key] = value
    return result


def load_expectation(path: Path) -> dict[str, tuple[str, ...]] | None:
    if not path.exists():
        return None
    try:
        payload = json.loads(
            path.read_text(encoding="utf-8"), object_pairs_hook=_unique_json_object
        )
    except (OSError, UnicodeError, ValueError) as error:
        raise AssertionError(
            f"invalid calibration expectation {path}: {error}"
        ) from error
    if not isinstance(payload, dict) or set(payload) != {
        "schema_version",
        "must_pass",
        "must_fail",
    }:
        raise AssertionError(f"calibration expectation {path} has invalid keys")
    if type(payload["schema_version"]) is not int or payload["schema_version"] != 1:
        raise AssertionError(f"calibration expectation {path} has invalid version")

    groups: dict[str, tuple[str, ...]] = {}
    for key in ("must_pass", "must_fail"):
        raw = payload[key]
        if (
            not isinstance(raw, list)
            or not all(isinstance(item, str) and item for item in raw)
            or len(raw) != len(set(raw))
        ):
            raise AssertionError(f"calibration expectation {path} has invalid {key}")
        groups[key] = tuple(raw)
    overlap = set(groups["must_pass"]) & set(groups["must_fail"])
    if overlap or not any(groups.values()):
        raise AssertionError(
            f"calibration expectation {path} is empty or contradictory"
        )
    return groups


def assert_expectation(
    case_id: str,
    variant: str,
    verdict: dict[str, object],
    expectation: dict[str, tuple[str, ...]] | None,
) -> None:
    if expectation is None:
        return
    assertions = {
        str(item["id"]): bool(item["passed"])
        for item in verdict["assertions"]  # type: ignore[union-attr]
        if isinstance(item, dict)
    }
    declared = set(expectation["must_pass"]) | set(expectation["must_fail"])
    unknown = declared - assertions.keys()
    if unknown:
        raise AssertionError(
            f"{case_id}/{variant}: expectation names unknown assertions {sorted(unknown)}"
        )
    undeclared = assertions.keys() - declared
    if undeclared:
        raise AssertionError(
            f"{case_id}/{variant}: expectation omits assertions {sorted(undeclared)}"
        )
    mismatches = [
        *(
            identifier
            for identifier in expectation["must_pass"]
            if not assertions[identifier]
        ),
        *(
            identifier
            for identifier in expectation["must_fail"]
            if assertions[identifier]
        ),
    ]
    if mismatches:
        raise AssertionError(
            f"{case_id}/{variant}: assertion expectation mismatch {sorted(mismatches)}"
        )


def _material_name(artifact_kind: str) -> str:
    if artifact_kind == "workspace_diff":
        return "apply.py"
    if artifact_kind == "final_output_json":
        return "artifact.json"
    raise AssertionError(f"unsupported calibration artifact kind: {artifact_kind}")


def discover_variants(calibration_root: Path, artifact_kind: str) -> tuple[str, ...]:
    material_name = _material_name(artifact_kind)
    return tuple(
        sorted(
            path.parent.relative_to(calibration_root).as_posix()
            for path in calibration_root.rglob(material_name)
        )
    )


def discover_good_variants(
    calibration_root: Path, artifact_kind: str = "workspace_diff"
) -> tuple[str, ...]:
    candidates = sorted(
        path
        for path in calibration_root.iterdir()
        if path.is_dir() and (path.name == "good" or path.name.startswith("good-"))
    )
    material_name = _material_name(artifact_kind)
    missing = [
        path.name for path in candidates if not path.joinpath(material_name).is_file()
    ]
    if missing:
        raise AssertionError(
            f"known-good calibration directories lack {material_name}: {missing}"
        )
    variants = tuple(path.name for path in candidates)
    if "good" not in variants:
        raise AssertionError("canonical good calibration is missing")
    return variants


def workspace_fingerprint(workspace: Path) -> str:
    digest = hashlib.sha256()
    for path in sorted(workspace.rglob("*")):
        relative = path.relative_to(workspace).as_posix()
        digest.update(relative.encode("utf-8"))
        digest.update(path.lstat().st_mode.to_bytes(4, "big"))
        if path.is_symlink():
            digest.update(b"symlink\0")
            digest.update(os.readlink(path).encode("utf-8"))
        elif path.is_file():
            digest.update(b"file\0")
            digest.update(path.read_bytes())
        elif path.is_dir():
            digest.update(b"directory\0")
    return digest.hexdigest()


def require_complete_expectations(
    calibration_root: Path, variants: tuple[str, ...]
) -> None:
    expectation_paths = {
        variant: calibration_root / variant / "expect.json" for variant in variants
    }
    if not any(path.is_file() for path in expectation_paths.values()):
        return
    missing = sorted(
        variant for variant, path in expectation_paths.items() if not path.is_file()
    )
    if missing:
        raise AssertionError(
            f"calibration expectation coverage is incomplete for variants {missing}"
        )


def calibrate(
    case: dict[str, object],
    variant: str,
    tool_environment: dict[str, str],
) -> dict[str, object]:
    case_id = str(case["id"])
    fixture = SUITE_ROOT / str(case["fixture_dir"])
    prompt = SUITE_ROOT / str(case["prompt_file"])
    verifier_argv = [str(part) for part in case["verifier"]["argv"]]  # type: ignore[index]
    artifact_kind = str(case["artifact_contract"]["kind"])  # type: ignore[index]
    case_dir = prompt.parent
    calibration_dir = case_dir / "calibration" / variant
    apply_script = calibration_dir / "apply.py"
    artifact_path = calibration_dir / "artifact.json"

    safe_variant = variant.replace("/", "__")
    with tempfile.TemporaryDirectory(prefix=f"{case_id}-{safe_variant}-") as temp:
        workspace = Path(temp) / "workspace"
        shutil.copytree(fixture, workspace)
        before = workspace_fingerprint(workspace)

        if apply_script.is_file():
            applied = run(
                [sys.executable, str(apply_script), str(workspace)],
                cwd=case_dir,
                timeout_seconds=60,
            )
            if applied.returncode != 0:
                raise AssertionError(
                    f"{case_id}/{variant}: calibration patch failed: "
                    f"{applied.stderr.strip()}"
                )
        elif artifact_kind == "workspace_diff":
            raise AssertionError(f"{case_id}/{variant}: calibration lacks apply.py")

        env = verifier_environment(workspace, case_dir, tool_environment)
        if artifact_kind == "final_output_json":
            if not artifact_path.is_file():
                raise AssertionError(
                    f"{case_id}/{variant}: calibration lacks artifact.json"
                )
            content = artifact_path.read_bytes()
            env.update(
                {
                    "EVAL_ARTIFACT_PATH": str(artifact_path),
                    "EVAL_ARTIFACT_KIND": artifact_kind,
                    "EVAL_ARTIFACT_SHA256": hashlib.sha256(content).hexdigest(),
                    "EVAL_AGENT_WORKSPACE_MUTATED": str(
                        int(before != workspace_fingerprint(workspace))
                    ),
                }
            )
        verifier_timeout = int(case["verifier"]["timeout_seconds"])  # type: ignore[index]
        verdict = parse_verdict(
            run(
                verifier_argv,
                cwd=SUITE_ROOT,
                env=env,
                timeout_seconds=verifier_timeout,
            ),
            case_id,
        )

    expected_list = [str(identifier) for identifier in case["critical_expectations"]]  # type: ignore[index]
    if len(expected_list) != len(set(expected_list)):
        raise AssertionError(
            f"{case_id}: manifest contains duplicate critical expectation IDs"
        )
    expected_ids = set(expected_list)
    actual_ids = {
        assertion.get("id")
        for assertion in verdict["assertions"]  # type: ignore[union-attr]
        if isinstance(assertion, dict)
    }
    if actual_ids != expected_ids:
        raise AssertionError(
            f"{case_id}: assertion IDs {sorted(actual_ids)} != {sorted(expected_ids)}"
        )
    expectation = load_expectation(calibration_dir / "expect.json")
    assert_expectation(case_id, variant, verdict, expectation)
    return verdict


def main() -> int:
    manifest = json.loads(SUITE_MANIFEST.read_text(encoding="utf-8"))
    cases = [case for case in manifest["cases"] if case["skill"] == "engineering"]
    failures: list[str] = []

    with private_tool_environment() as tool_environment:
        for case in cases:
            case_id = case["id"]
            try:
                prompt = SUITE_ROOT / case["prompt_file"]
                calibration_root = prompt.parent / "calibration"
                artifact_kind = str(case["artifact_contract"]["kind"])
                good_variants = discover_good_variants(calibration_root, artifact_kind)
                adversarial_variants = tuple(
                    variant
                    for variant in discover_variants(calibration_root, artifact_kind)
                    if variant.startswith("adversarial/")
                )
                require_complete_expectations(
                    calibration_root,
                    (*good_variants, "bad", *adversarial_variants),
                )
                for variant in good_variants:
                    good = calibrate(case, variant, tool_environment)
                    if good["passed"] is not True:
                        raise AssertionError(f"known-good patch {variant} was rejected")
                bad = calibrate(case, "bad", tool_environment)
                if bad["passed"] is not False:
                    raise AssertionError("known-bad patch was accepted")
                for variant in adversarial_variants:
                    verdict = calibrate(case, variant, tool_environment)
                    if verdict["passed"] is not False:
                        raise AssertionError(f"known exploit {variant} was accepted")
                print(
                    f"PASS {case_id}: {len(good_variants)} good variant(s) accepted; bad and "
                    f"{len(adversarial_variants)} exploit(s) rejected"
                )
            except (AssertionError, OSError, subprocess.TimeoutExpired) as error:
                failures.append(f"{case_id}: {error}")
                print(f"FAIL {case_id}: {error}", file=sys.stderr)

    if failures:
        print(f"\n{len(failures)} calibration failure(s)", file=sys.stderr)
        return 1
    print(f"\nCalibrated {len(cases)} software cases")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
