#!/usr/bin/env python3
"""Prove built distributions work without checkout-relative package resources."""

from __future__ import annotations

import argparse
import ast
import hashlib
import importlib.util
import json
import os
import stat
import subprocess
import tarfile
import tempfile
import zipfile
from dataclasses import dataclass
from email import policy
from email.parser import BytesParser
from pathlib import Path, PurePosixPath


AUTHORITY_PATH = "skivolve/comparator-profile-authority.json"
SOURCE_FINGERPRINT_DOMAIN = b"skivolve-source-fingerprint-v1\0"
LEGACY_PACKAGE_PATH = "harness_evals/"
LEGACY_COMMANDS = ("harness-evals", "harness-evals-prepare-holdout")
PROFILE_LAYOUTS = {
    "skivolve/comparator_calibration/profile.json": {
        "skivolve/comparator_calibration/README.md"
    },
    "skivolve/plain_language_calibration/profile.json": set(),
}


@dataclass(frozen=True)
class ExternalSuite:
    manifest: Path
    bundle_commit: str
    bundle_source_sha256: str
    shared_tree_sha256: str
    verifier: Path


def _tree_sha256(root: Path) -> str:
    digest = hashlib.sha256()
    for path in sorted(
        (path for path in root.rglob("*") if path.is_file()),
        key=lambda path: path.relative_to(root).as_posix(),
    ):
        relative = path.relative_to(root).as_posix()
        content = path.read_bytes()
        executable = bool(path.stat().st_mode & stat.S_IXUSR)
        digest.update(relative.encode("utf-8"))
        digest.update(b"\0x\0" if executable else b"\0-\0")
        digest.update(str(len(content)).encode("ascii"))
        digest.update(b"\0")
        digest.update(content)
        digest.update(b"\0")
    return digest.hexdigest()


def _source_fingerprint(bundle_source: str, root: Path) -> str:
    digest = hashlib.sha256()
    digest.update(SOURCE_FINGERPRINT_DOMAIN)
    header = (
        json.dumps(
            {"bundle_source": bundle_source, "schema_version": 1},
            ensure_ascii=True,
            separators=(",", ":"),
            sort_keys=True,
        ).encode("ascii")
        + b"\n"
    )
    digest.update(header)
    digest.update(b"\0")
    for path in sorted(
        (path for path in root.rglob("*") if path.is_file()),
        key=lambda path: path.relative_to(root).as_posix(),
    ):
        relative = path.relative_to(root).as_posix()
        content = path.read_bytes()
        metadata = (
            json.dumps(
                {
                    "executable": bool(path.stat().st_mode & stat.S_IXUSR),
                    "path": relative,
                    "role": "bundle",
                    "size": len(content),
                },
                ensure_ascii=True,
                separators=(",", ":"),
                sort_keys=True,
            ).encode("ascii")
            + b"\n"
        )
        digest.update(str(len(metadata)).encode("ascii"))
        digest.update(b":")
        digest.update(metadata)
        digest.update(str(len(content)).encode("ascii"))
        digest.update(b":")
        digest.update(content)
    return digest.hexdigest()


def _run(*argv: str, cwd: Path) -> subprocess.CompletedProcess[str]:
    completed = subprocess.run(
        argv,
        cwd=cwd,
        capture_output=True,
        text=True,
        check=False,
        shell=False,
        env={key: value for key, value in os.environ.items() if key != "PYTHONPATH"},
    )
    if completed.returncode != 0:
        raise RuntimeError(
            f"command failed ({completed.returncode}): {' '.join(argv)}\n"
            f"stdout:\n{completed.stdout}\nstderr:\n{completed.stderr}"
        )
    return completed


def _declared_package_resources(profile_path: str, profile_bytes: bytes) -> set[str]:
    descriptor = json.loads(profile_bytes)
    resources = descriptor.get("resources")
    if not isinstance(resources, dict) or not resources:
        raise RuntimeError("packaged profile descriptor has no resource map")
    declared = {profile_path, AUTHORITY_PATH}
    base = PurePosixPath(profile_path).parent
    for name, raw_path in resources.items():
        path = PurePosixPath(raw_path) if isinstance(raw_path, str) else None
        if (
            path is None
            or path.is_absolute()
            or ".." in path.parts
            or path == PurePosixPath(".")
        ):
            raise RuntimeError(f"packaged profile resource is unsafe: {name}")
        declared.add((base / path).as_posix())
    return declared


def _metadata_version(raw: bytes, label: str) -> str:
    version = BytesParser(policy=policy.default).parsebytes(raw).get("Version")
    if not isinstance(version, str) or not version:
        raise RuntimeError(f"{label} has no package version")
    return version


def _module_version(raw: bytes, label: str) -> str:
    module = ast.parse(raw.decode("utf-8"), filename=label)
    versions = [
        node.value.value
        for node in module.body
        if isinstance(node, ast.Assign)
        and any(
            isinstance(target, ast.Name) and target.id == "__version__"
            for target in node.targets
        )
        and isinstance(node.value, ast.Constant)
        and isinstance(node.value.value, str)
    ]
    if len(versions) != 1:
        raise RuntimeError(f"{label} must declare exactly one string __version__")
    return versions[0]


def _inspect_distributions(wheel: Path, sdist: Path) -> None:
    with zipfile.ZipFile(wheel) as archive:
        wheel_files = set(archive.namelist())
        legacy_wheel_paths = sorted(
            path for path in wheel_files if path.startswith(LEGACY_PACKAGE_PATH)
        )
        if legacy_wheel_paths:
            raise RuntimeError(
                f"wheel retained legacy package paths: {legacy_wheel_paths}"
            )
        wheel_metadata = [
            path for path in wheel_files if path.endswith(".dist-info/METADATA")
        ]
        if len(wheel_metadata) != 1:
            raise RuntimeError("wheel must contain exactly one METADATA file")
        wheel_version = _metadata_version(
            archive.read(wheel_metadata[0]), "wheel METADATA"
        )
        wheel_module_version = _module_version(
            archive.read("skivolve/__init__.py"), "wheel skivolve/__init__.py"
        )
        wheel_required = set().union(
            *(
                _declared_package_resources(path, archive.read(path))
                for path in PROFILE_LAYOUTS
            )
        )
        wheel_resource_bytes = {
            path: archive.read(path) for path in wheel_required if path in wheel_files
        }
        entry_point_files = [
            path for path in wheel_files if path.endswith(".dist-info/entry_points.txt")
        ]
        if len(entry_point_files) != 1:
            raise RuntimeError("wheel must contain exactly one entry_points.txt file")
        entry_points = archive.read(entry_point_files[0]).decode("utf-8")
        retained_commands = [
            command for command in LEGACY_COMMANDS if f"{command} =" in entry_points
        ]
        if retained_commands:
            raise RuntimeError(
                f"wheel retained legacy console commands: {retained_commands}"
            )
    missing_wheel = wheel_required - wheel_files
    if missing_wheel:
        raise RuntimeError(f"wheel omitted package resources: {sorted(missing_wheel)}")

    with tarfile.open(sdist, "r:gz") as archive:
        normalized_sdist_files = {
            "/".join(PurePosixPath(member.name).parts[1:]): member
            for member in archive.getmembers()
            if member.isfile() and "/" in member.name
        }
        legacy_sdist_paths = sorted(
            path
            for path in normalized_sdist_files
            if path.startswith(LEGACY_PACKAGE_PATH)
        )
        if legacy_sdist_paths:
            raise RuntimeError(
                f"sdist retained legacy package paths: {legacy_sdist_paths}"
            )
        metadata_member = normalized_sdist_files.get("PKG-INFO")
        module_member = normalized_sdist_files.get("skivolve/__init__.py")
        if metadata_member is None or module_member is None:
            raise RuntimeError("sdist omitted package version sources")
        metadata_reader = archive.extractfile(metadata_member)
        module_reader = archive.extractfile(module_member)
        if metadata_reader is None or module_reader is None:
            raise RuntimeError("sdist package version sources are not regular files")
        sdist_version = _metadata_version(metadata_reader.read(), "sdist PKG-INFO")
        sdist_module_version = _module_version(
            module_reader.read(), "sdist skivolve/__init__.py"
        )
        sdist_required: set[str] = {AUTHORITY_PATH}
        for profile_path in PROFILE_LAYOUTS:
            profile_member = normalized_sdist_files.get(profile_path)
            if profile_member is None:
                raise RuntimeError(f"sdist omitted profile descriptor: {profile_path}")
            reader = archive.extractfile(profile_member)
            if reader is None:
                raise RuntimeError(
                    f"sdist profile descriptor is not a regular file: {profile_path}"
                )
            sdist_required.update(
                _declared_package_resources(profile_path, reader.read())
            )
        sdist_resource_bytes = {}
        for path in sdist_required:
            member = normalized_sdist_files.get(path)
            if member is None:
                continue
            resource_reader = archive.extractfile(member)
            if resource_reader is None:
                raise RuntimeError(f"sdist resource is not a regular file: {path}")
            sdist_resource_bytes[path] = resource_reader.read()
    missing_sdist = sdist_required - set(normalized_sdist_files)
    if missing_sdist:
        raise RuntimeError(f"sdist omitted package resources: {sorted(missing_sdist)}")
    if wheel_required != sdist_required:
        raise RuntimeError("wheel and sdist declare different profile resources")
    if wheel_resource_bytes != sdist_resource_bytes:
        raise RuntimeError("wheel and sdist profile resource bytes differ")
    if (
        len({wheel_version, wheel_module_version, sdist_version, sdist_module_version})
        != 1
    ):
        raise RuntimeError("wheel and sdist package versions differ")

    for label, files, required in (
        ("wheel", wheel_files, wheel_required),
        ("sdist", set(normalized_sdist_files), sdist_required),
    ):
        unexpected = set()
        for profile_path, allowed_support in PROFILE_LAYOUTS.items():
            profile_root = PurePosixPath(profile_path).parent.as_posix() + "/"
            unexpected.update(
                path
                for path in files
                if path.startswith(profile_root)
                and not path.endswith("/")
                and path not in required
                and path not in allowed_support
                and PurePosixPath(path).suffix not in {".py", ".pyi"}
            )
        if unexpected:
            raise RuntimeError(
                f"{label} contains unexpected non-code profile files: "
                f"{sorted(unexpected)}"
            )


def _write_external_suite(root: Path) -> ExternalSuite:
    from skivolve.comparator_profiles import (
        BUILTIN_SOFTWARE_PROFILE_ID,
        resolve_builtin_profile,
    )

    _run("git", "init", "-q", cwd=root)
    _run("git", "config", "user.email", "package-smoke@example.invalid", cwd=root)
    _run("git", "config", "user.name", "Package Smoke", cwd=root)
    bundle = root / "instruction-bundles" / "demo"
    bundle.mkdir(parents=True)
    (bundle / "SKILL.md").write_text(
        "# Installed package smoke bundle\n", encoding="utf-8"
    )
    _run("git", "add", "instruction-bundles", cwd=root)
    _run("git", "commit", "-q", "-m", "configured bundle", cwd=root)
    bundle_commit = _run("git", "rev-parse", "HEAD", cwd=root).stdout.strip()

    profile = resolve_builtin_profile(BUILTIN_SOFTWARE_PROFILE_ID)
    test_release = json.loads(profile.read_bytes("test_release"))
    frozen_original = test_release["runtime_adapter"]["frozen_original_commit"]
    authority = {
        "schema_version": 1,
        "original_commit": frozen_original,
    }
    (root / "baseline-authority.json").write_text(
        json.dumps(authority, indent=2) + "\n",
        encoding="utf-8",
    )
    case_root = root / "cases" / "basic"
    case_root.mkdir(parents=True)
    (case_root / "prompt.md").write_text("Create answer.txt.\n", encoding="utf-8")
    fixture = case_root / "fixture"
    fixture.mkdir()
    (fixture / "input.txt").write_text("input\n", encoding="utf-8")
    shared = root / "oracle-resources" / "common"
    shared.mkdir(parents=True)
    (shared / "helper.txt").write_text("shared oracle\n", encoding="utf-8")
    (shared / "verifier.py").write_text(
        "import json\nprint(json.dumps({'passed': True, 'assertions': "
        "[{'id': 'answer-present', 'passed': True, 'evidence': 'smoke'}], "
        "'metrics': {}}))\n",
        encoding="utf-8",
    )
    suite = {
        "schema_version": 1,
        "suite_id": "installed-package-smoke",
        "seed": 7123,
        "evaluation_mode": "judged",
        "repository_root": ".",
        "provider": {
            "adapter": "deterministic-fake",
            "model": "fake-model-v1",
            "timeout_seconds": 10,
        },
        "comparator": {
            "adapter": "deterministic-fake",
            "model": "fake-sonnet-v2",
            "timeout_seconds": 300,
            "max_budget_usd": 1.0,
        },
        "comparator_profile": {
            "kind": "builtin",
            "id": BUILTIN_SOFTWARE_PROFILE_ID,
        },
        "shared_verifier_dir": "oracle-resources/common",
        "variants": [
            {"id": "without", "kind": "without_skill"},
            {
                "id": "current",
                "kind": "worktree",
                "root": ".",
                "source_ref": bundle_commit,
            },
            {"id": "original", "kind": "git_ref", "git_ref": frozen_original},
        ],
        "comparisons": [
            {
                "id": "package-smoke",
                "control": "without",
                "treatment": "current",
                "repetitions": 3,
                "comparator_order": "ab_ba",
            }
        ],
        "holdout": {"comparison_ids": ["package-smoke"]},
        "cases": [
            {
                "id": "basic",
                "skill": "demo",
                "bundle_source": "instruction-bundles/demo",
                "artifact_contract": {"kind": "workspace_diff"},
                "split": "train",
                "prompt_file": "cases/basic/prompt.md",
                "fixture_dir": "cases/basic/fixture",
                "verifier": {
                    "argv": ["python3", "oracle-resources/common/verifier.py"],
                    "timeout_seconds": 5,
                    "required_tools": [],
                },
                "context_files": [],
                "timeout_seconds": 5,
                "critical_expectations": ["answer-present"],
                "comparator_contract": {
                    "requirements": [
                        {
                            "id": "answer-present",
                            "kind": "required_behavior",
                            "text": "The implementation must create a non-empty answer file.",
                        }
                    ],
                    "performance_basis": None,
                    "qualitative_bases": {},
                },
            }
        ],
    }
    manifest = root / "external-suite.json"
    manifest.write_text(json.dumps(suite, indent=2) + "\n", encoding="utf-8")
    return ExternalSuite(
        manifest=manifest,
        bundle_commit=bundle_commit,
        bundle_source_sha256=_source_fingerprint("instruction-bundles/demo", bundle),
        shared_tree_sha256=_tree_sha256(shared),
        verifier=(shared / "verifier.py").resolve(),
    )


def _run_external_smoke(cli: Path, forbidden_root: Path) -> None:
    if importlib.util.find_spec("harness_evals") is not None:
        raise RuntimeError("installed environment retained the legacy package import")
    retained_commands = [
        command for command in LEGACY_COMMANDS if (cli.parent / command).exists()
    ]
    if retained_commands:
        raise RuntimeError(
            f"installed environment retained legacy console commands: {retained_commands}"
        )

    import skivolve
    from skivolve.comparator_profiles import (
        BUILTIN_PLAIN_LANGUAGE_PROFILE_ID,
        BUILTIN_SOFTWARE_PROFILE_ID,
        resolve_builtin_profile,
    )
    from skivolve.comparator_runtime import CalibrationError, ComparatorRuntime

    package_path = Path(skivolve.__file__).resolve()
    if package_path.is_relative_to(forbidden_root.resolve()):
        raise RuntimeError(f"smoke imported checkout package: {package_path}")
    plain_language = resolve_builtin_profile(BUILTIN_PLAIN_LANGUAGE_PROFILE_ID)
    if plain_language.authority_binding.authority_scope != "test":
        raise RuntimeError("installed plain-language profile has invalid authority")
    runtime = ComparatorRuntime.load_builtin_profile(
        BUILTIN_PLAIN_LANGUAGE_PROFILE_ID, use_test_release=True
    )
    try:
        if runtime.profile_authority_scope != "test":
            raise RuntimeError("installed plain-language runtime lost test authority")
        if tuple(runtime.bundle.semantic_contract["criterion_ids"]) != (
            "factual_fidelity",
            "reader_clarity",
            "audience_fit",
            "concision",
        ):
            raise RuntimeError("installed plain-language runtime has wrong criteria")
    finally:
        runtime.close()
    try:
        ComparatorRuntime.load_builtin_profile(BUILTIN_PLAIN_LANGUAGE_PROFILE_ID)
    except CalibrationError:
        pass
    else:
        raise RuntimeError("installed test-authority profile loaded for production")
    with tempfile.TemporaryDirectory(prefix="skivolve-installed-") as temporary:
        root = Path(temporary).resolve()
        external = _write_external_suite(root)
        completed = _run(
            str(cli),
            "--suite",
            str(external.manifest),
            "--comparison",
            "package-smoke",
            "--dry-run",
            cwd=root,
        )
        summary = json.loads(completed.stdout)
        comparator = summary["preflight"]["comparator"]
        if comparator["profile_kind"] != "builtin":
            raise RuntimeError("installed CLI did not select a built-in profile")
        if comparator["profile_id"] != BUILTIN_SOFTWARE_PROFILE_ID:
            raise RuntimeError("installed CLI selected the wrong profile id")
        if comparator["profile_locks_valid"] is not True:
            raise RuntimeError("installed CLI did not validate profile locks")
        if comparator["protocol_locks_valid"] is not True:
            raise RuntimeError("installed CLI did not validate protocol locks")
        current = summary["preflight"]["sources"]["current"]
        if current["kind"] != "worktree":
            raise RuntimeError("installed CLI did not preflight the external worktree")
        if current["expected_source_commit"] != external.bundle_commit:
            raise RuntimeError("installed CLI resolved the wrong bundle source commit")
        if current["worktree_head_commit"] != external.bundle_commit:
            raise RuntimeError("installed CLI observed the wrong worktree commit")
        if current["source_dirty"] is not False:
            raise RuntimeError("installed CLI reported the configured bundle as dirty")
        if (
            current["expected_source_sha256_by_case"]["basic"]
            != external.bundle_source_sha256
        ):
            raise RuntimeError("installed CLI hashed the wrong configured bundle bytes")
        case = summary["preflight"]["cases"][0]
        if case["shared_tree_sha256"] != external.shared_tree_sha256:
            raise RuntimeError("installed CLI hashed the wrong shared snapshot bytes")
        if Path(case["verifier_argv"][1]).resolve() != external.verifier:
            raise RuntimeError("installed CLI did not resolve the external verifier")


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--wheel", type=Path)
    parser.add_argument("--sdist", type=Path)
    parser.add_argument("--cli", type=Path)
    parser.add_argument("--forbid-root", type=Path)
    args = parser.parse_args()
    if args.wheel is not None or args.sdist is not None:
        if args.wheel is None or args.sdist is None:
            parser.error("--wheel and --sdist must be supplied together")
        _inspect_distributions(args.wheel, args.sdist)
    if args.cli is not None or args.forbid_root is not None:
        if args.cli is None or args.forbid_root is None:
            parser.error("--cli and --forbid-root must be supplied together")
        _run_external_smoke(args.cli, args.forbid_root)
    if args.wheel is None and args.cli is None:
        parser.error("select distribution inspection, installed smoke, or both")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
