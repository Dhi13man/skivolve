# Changelog

All notable changes to Skivolve are documented in this file. The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and package releases follow [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added

- Added calibrated final-output cases for compatibility decisions, read-only diagnoses, surgical plans, and evidence-gap research, including verifier evidence when an agent mutates a final-output workspace.

### Changed

- Refreshed the Codex app-server runtime lock from 0.144.3 to 0.146.0, including the executable, bundled tools, and generated protocol schema.

### Fixed

- Accepted bounded Codex collaboration lifecycles, required each completed spawn to bind exactly one child, kept child-agent traffic from mutating the main result, and cleaned unreadable evaluator runtime directories without following symlinks.

## [0.5.0] - 2026-07-29

### Changed

- Made suite schema v1 and holdout-plan schema v1 the only accepted wire contracts and established `software-engineering-v1` as the production comparator profile.
- Required every suite to declare its evaluation mode, adapter identities, verifier-resource boundary, release comparisons, bundle sources, and artifact contracts explicitly.
- Reworked the README and website around installation, one runnable comparison, the current suite contract, and the project's claim limits.
- Reclassified holdout reviewer labels and record locators as operator-declared provenance rather than authenticated review evidence.
- Bound the revision-1 Claude provider capability, sandbox runtime, seccomp helper, and enforcement canary into provider authority.
- Bounded generator and comparator subprocess output, timeout cleanup, and process-group termination.
- Replaced `ProtectKernelTunables` and `ProtectKernelLogs` in the verifier, Claude agent, and comparator units with a `syslog(2)` seccomp denial, because systemd 256-or-newer user managers enforce those `/proc` over-mounts and the kernel then rejects the nested candidate namespace. Tunable writes stay blocked by the unprivileged user namespace and `/dev/kmsg` stays absent under `PrivateDevices`. The verifier preflight probe now exercises the exact shared isolation property set instead of a weaker copy.

### Removed

- Removed the earlier multi-version suite and holdout-plan contracts, implicit bundle and shared-resource discovery, legacy provider names, and compatibility-only source-authority paths.

### Migration

- Rewrite suites as schema v1 with `evaluation_mode`, adapter-based providers, `shared_verifier_dir`, `holdout`, per-case `bundle_source`, and per-case `artifact_contract` fields.
- Re-prepare unconsumed holdout plans with Skivolve 0.5.0. Version 0.5.0 does not read earlier suite or plan formats; use the release that created a historical artifact to inspect it, and never rewrite reviewed or consumed evidence.

### Security

- Fail Claude preflight unless code-owned sandbox settings and a digest-attested seccomp helper demonstrably block Unix sockets, while also denying credential paths and outbound network access.
- Hide the evaluation suite and oracle sources from candidate processes, detect stable-file read races, and reject oversized or invalid UTF-8 provider output before parsing.

## [0.4.0] - 2026-07-17

### Added

- Added a static, accessible GitHub Pages site with crawlable guides, canonical metadata, social previews, structured data, a sitemap, and robots policy.
- Added a least-privilege, commit-pinned Pages deployment workflow with deterministic site validation before deployment.

### Changed

- Renamed the repository, Python distribution, import package, module entry point, console commands, suite identity, release assets, schemas, documentation, and active protocol namespaces to Skivolve.
- Moved the project homepage to `https://dhi13man.github.io/skivolve/` and expanded repository metadata for agent skill and instruction evaluation discovery.
- Bumped the package to `0.4.0` because the public import and command surfaces changed.

### Migration

- Replace the former `harness-evals` distribution and `harness_evals` import with `skivolve`.
- Replace the former `harness-evals` command with `skivolve`, and `harness-evals-prepare-holdout` with `skivolve-prepare-holdout`.
- Re-prepare unconsumed holdout plans and do not compare pre-rename artifact evidence as if it used the new canonicalization or source-fingerprint namespaces.

### Security

- Advanced source-fingerprint and text/workspace canonicalization namespaces so renamed evidence cannot be confused with pre-rename bytes.
- Kept Pages deployment permissions isolated to the deployment job and pinned every external action to an immutable commit.

## [0.3.0] - 2026-07-13

### Added

- Added schema v3 with explicit judged and objective-only evaluation modes plus registered or suite-local comparator profile selection.
- Added package-backed comparator profiles, a test-authority plain-language profile, and shared profile-owned semantic contracts for domain-specific judgment without hard-coding evaluator criteria.
- Added schema v4 with explicit per-case bundle source paths and optional contained shared verifier resources.
- Added installed-wheel coverage for external suites whose bundles, cases, and verifier resources use independent layouts.
- Added schema v5 with suite-owned ordered release comparisons and holdout-plan schema v3 with generic per-variant source bindings.
- Added production objective-only holdouts that seal the canonical verifier acceptance policy without constructing a comparator.
- Added schema v6 with reviewed provider adapter IDs, immutable capability declarations, and canonical capability digests.
- Added holdout-plan schema v4 with role-specific generator and comparator authority bindings.
- Added schema v7 with explicit workspace-diff, final-text, and final-JSON artifact contracts.
- Added bounded LF text and RFC 8785 JSON normalization with canonical artifact evidence.
- Added read-only verifier artifact mounts and pristine read-only fixture workspaces for final-output cases.
- Added hash-locked runtime, test, quality, build, and fuzz dependency sets for reproducible CI installs.
- Added bounded pull-request fuzzing and a weekly extended Atheris campaign for final-JSON normalization.
- Added a protected-tag release workflow that rebuilds and inspects distributions, publishes SHA-256 checksums, and records GitHub/Sigstore build provenance.

### Changed

- Separated source authority from comparator judgment authority. Judged plans bind profile, release, and certification evidence; objective plans bind verifier-policy evidence.
- Limited holdout-plan schema v2 to the legacy schema-v2 through schema-v4 candidate/original adapter without rewriting historical plan bytes.
- Routed provider construction, scheduling, sandbox selection, billing evidence, and provenance through reviewed adapter capabilities while preserving schema-v2 through schema-v5 compatibility.
- Advanced reviewed provider capabilities to revision 2 for declared final-output capture; unconsumed schema-v4 authority plans from revision 1 must be re-prepared.
- Refreshed the supported Codex app-server runtime contract from `0.144.1` to `0.144.3` without changing the canonical protocol schema.
- Required wheel and sdist package metadata to agree with their packaged `harness_evals.__version__` declaration.

### Migration

- To adopt explicit evaluation semantics, migrate to schema v3, select `evaluation_mode`, and either configure a judged `comparator_profile` with case contracts or remove comparator fields for objective-only diagnostics.
- To adopt independent layouts, migrate to schema v4, declare every case's canonical `bundle_source`, and set `shared_verifier_dir` to a contained resource directory or `null`.
- To adopt generic source authority, migrate an unconsumed suite to schema v5, add `holdout.comparison_ids` in manifest order, validate the suite, and prepare a new holdout plan.
- To adopt reviewed provider authority, migrate to schema v6, replace legacy provider kinds with registered adapter IDs, validate the suite, and prepare a new schema-v4 holdout plan.
- To adopt declared output artifacts, migrate to schema v7 and add exactly one `artifact_contract` to every case. Existing schema-v2 through schema-v6 cases retain the workspace-diff compatibility default.
- Re-prepare every unconsumed schema-v4 plan created against provider capability revision 1. Never rewrite a reviewed or consumed plan.

### Security

- Added literal Git path handling, bounded source enumeration, Git/worktree snapshot parity, runtime shared-path revalidation, verifier-only source separation, and read-only configured shared mounts.
- Added domain-separated source fingerprints over bundle locators, paths, bytes, executable modes, and context files; equal evaluated arms, source drift, mode confusion, and authority substitution fail before dispatch.
- Bound production provider authority to reviewed capability, configuration, runtime provenance, executable identity, and non-injected provider instances; drift and instance substitution fail before dispatch or release.
- Reject malformed or non-idempotent canonical output before verification or judgment, reject uncalibrated judged artifact kinds before dispatch, and isolate final-output verification from candidate workspace mutations.
- Pin every Python CI dependency by cryptographic hash, validate all release distributions with Twine, and attach signed build provenance to release artifacts.

## [0.2.0] - 2026-07-12

### Changed

- Repositioned the project around A/B evaluation of user-defined skills and instruction bundles through agent harnesses; engineering and testing remain the first reference corpus rather than the evaluator boundary.
- Derived holdout skill cells and minimum-case gates from each selected suite instead of requiring the built-in `engineering` and `testing` identifiers.
- Generalized the isolated task context so non-engineering skill suites are not instructed as software-engineering evaluations.

## [0.1.0] - 2026-07-12

### Added

- Standalone MIT-licensed `harness-evals` Python package and console commands.
- Seventeen calibrated software engineering and testing cases with objective verifiers and adversarial oracle calibration.
- Strict suite manifests, Git-bound instruction variants, isolated Claude and diagnostic Codex providers, blinded AB/BA comparison, crash-safe spend accounting, and review-sealed holdout plans.
- Repository-local `engineering` and `testing` reference bundles for exercising Git-bound comparison variants.
- CI, CodeQL, OpenSSF Scorecard, Dependabot, issue forms, contribution policy, security reporting, governance, support, and release documentation.

[Unreleased]: https://github.com/Dhi13man/skivolve/compare/v0.5.0...HEAD
[0.5.0]: https://github.com/Dhi13man/skivolve/compare/v0.4.0...v0.5.0
[0.4.0]: https://github.com/Dhi13man/skivolve/compare/v0.3.0...v0.4.0
[0.3.0]: https://github.com/Dhi13man/skivolve/compare/v0.2.0...v0.3.0
[0.2.0]: https://github.com/Dhi13man/skivolve/compare/v0.1.0...v0.2.0
[0.1.0]: https://github.com/Dhi13man/skivolve/releases/tag/v0.1.0
