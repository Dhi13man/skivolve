# Contributing To Skivolve

Skivolve accepts focused changes that improve evaluator correctness, portability, security, calibration quality, or documented usability. Because evaluation defects can create false confidence, changes to cases, oracles, providers, schemas, statistics, or release authority require stronger evidence than ordinary tooling changes.

## Before Opening Work

Search existing issues and discussions. Open a proposal before changing a public schema, provider authority, holdout policy, statistical decision rule, corpus contract, or compatibility surface. Security findings must follow [SECURITY.md](SECURITY.md), not the public tracker.

## Development Setup

```bash
git clone https://github.com/Dhi13man/skivolve.git
cd skivolve
python3 -m venv .venv
. .venv/bin/activate
python -m pip install --upgrade pip
python -m pip install -e ".[test]"
python -m pip install --require-hashes -r requirements/build.txt
python -m pip install --require-hashes -r requirements/quality.txt
```

Runtime code must remain compatible with Python 3.11 and use only the standard library unless a dependency proposal establishes necessity, security posture, maintenance ownership, and a migration path.

## Required Local Checks

```bash
ruff check .
ruff format --check .
python -m compileall -q skivolve cases tests
python -m unittest discover -s tests -v
python -m unittest discover -s skivolve/comparator_calibration/tests -v
python -m unittest discover -s cases/testing/tests -v
python cases/software/calibrate.py
python cases/testing/calibrate.py
python -m build
```

Run `tests/run_known_good_smoke.py` when changing case execution, fixture materialization, isolation, verifiers, or known-good calibration variants. Provider-backed checks must be declared explicitly because they may require credentials or consume money or subscription quota; CI never makes paid calls.

## Case Contributions

Every case contribution must include:

- One narrowly specified user task with explicit compatibility and failure semantics.
- A minimal fixture that contains only the state needed to expose the targeted risks.
- An objective verifier that emits stable assertions, applies explicit time and resource bounds, and never trusts candidate-controlled tests as its sole oracle.
- Known-good and known-bad calibration implementations.
- Adversarial implementations for plausible bypasses, hard-coded evaluator detection, weakened boundaries, and partial compliance.
- Exact `expect.json` assertion partitions for focused variants when not every assertion should fail.
- Manifest requirements and critical expectations that match the executable oracle.
- Calibration output demonstrating that all good variants pass and every bad or adversarial variant fails its intended gate without unrelated failures.

Do not tune a public oracle against private holdout content. Do not introduce sleeps as concurrency proof, warmed-cache-only performance claims, self-referential expected values, broad snapshots without semantic assertions, or test doubles that erase the production boundary under evaluation.

## Core And Provider Contributions

Preserve strict parsing, duplicate-key rejection, path containment, symlink and TOCTOU defenses, tree and request hashing, dispatch journaling, crash-safe spend accounting, blinded ordering, cleanup poison, credential isolation, and fail-closed release authority. A new provider must include deterministic contract tests and must identify whether it is release-authoritative or diagnostic.

Public API, CLI, manifest, schema, corpus, comparator, or release-lock changes require a version decision and an entry in [CHANGELOG.md](CHANGELOG.md). Never rewrite a cryptographic release identity in place.

## Pull Requests

- Keep one coherent concern per pull request.
- Explain the failure mode or capability being changed, why the chosen layer owns it, and which alternatives were rejected.
- List exact commands and named scenarios used as evidence.
- Add or update tests before claiming a bug is fixed.
- Keep Markdown prose unwrapped; line length is intentionally not enforced.
- Ensure generated caches, credentials, diagnostics, results, and private evidence are absent from the diff.
- Accept the repository's MIT license for submitted work and confirm that fixtures and examples are original or compatibly licensed.

Maintainers may request independent oracle review, adversarial variants, repeated runs, or a fresh comparator certification when the blast radius warrants it.

## Commits

Use imperative, scoped commit subjects that explain intent, such as `fix(runner): bind worktree bytes before dispatch`. Keep generated artifacts and their source change in the same commit when they must remain cryptographically synchronized.

## Release Process

Releases are cut from a clean protected `main` commit after CI, package build and install smoke, schema and release-lock reproduction, corpus calibration, secret scanning, and changelog review pass. The maintainer creates a protected annotated `vMAJOR.MINOR.PATCH` tag. The release workflow verifies that the tag is reachable from `main` and matches package metadata, rebuilds and inspects the distributions from hash-locked dependencies, generates checksums and signed provenance, and publishes the matching changelog section with the GitHub release. The maintainer then verifies the published assets, attestations, and repository community profile.
