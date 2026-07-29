# Skivolve Comparator Calibration

This directory contains the production-authority `software-engineering-v1` profile for a pairwise comparator that is blinded to gold labels and canonical candidate identities before it is trusted to score software engineering and testing evaluations. It is a closed, offline-verifiable release bundle. Live collection is explicit and is not part of the unit tests.

## Profile Boundary

The shared evaluator is implemented by `calibration.py` and `../comparator_runtime.py`; the software domain is not encoded as an unavoidable runner contract. `semantic-contract.json` binds this profile's closed engine strategy, adapters, criterion and basis vocabularies, corpus identity, calibration rules, and support thresholds. The release binds that contract together with the descriptor, rubric, schemas, corpus, evaluator sources, external suite authority, and runtime sources.

`../plain_language_calibration/` is a data-only test-authority profile that uses the same engine with four editorial criteria. Its author-authored fixture corpus proves profile-owned semantics, suite-local execution, installed-package loading, and authority containment. It is not independent production calibration and cannot access a production holdout or authorize a release.

Data profiles cannot provide executable comparison code. New engine strategies or adapters require a reviewed package change and an explicit allowlist entry; arbitrary imports and profile-defined expression languages are rejected.

## Decision Protocol

The comparator evaluates admissibility before quality:

1. Check every controlled contract requirement for both candidates and report its exact `satisfied`, `violated`, or `unknown` status.
2. Mark a candidate ineligible when any required behavior or hard constraint is violated. Correctness, security, containment, atomicity, concurrency, API compatibility, and dependency violations are never quality tradeoffs.
3. Report an admissibility decision and exact violation IDs consistent with the per-requirement statuses. Set `criteria` to `null` unless both candidates are eligible.
4. When both qualify, compare the five locked criteria and mechanically derive `A`, `B`, `tie`, or `tradeoff` by Pareto dominance.
5. Assign a performance winner only from a typed `workload`, `asymptotic`, or `measurement` basis in the controlled contract.
6. Keep functional correctness and security/reliability tied in production; the v1 corpus does not calibrate decisive use of those axes. Typed bases remain structural evidence but do not override this release policy.

The model never authors an overall outcome. The evaluator derives it from eligibility and, only where applicable, the criterion vector.

## Corpus

`manifest.json` contains 30 distinct Python, JavaScript, TypeScript, and Go pairs. Resolved outcomes are balanced at six cases each for `A`, `B`, `tie`, `tradeoff`, and `unqualified`. The corpus includes multi-file, concurrency, API, dependency, testing, injection, identifier/path preservation, and length-bias cases.

Ten balanced sentinels run three times in both AB and BA order. The other 20 pairs run once in both orders, producing 100 raw calls. Repetitions stabilize a single pair decision; they never increase the metric sample size. Outcome and eligibility metrics use 30 distinct pairs. Criterion metrics use only the 13 pairs where both candidates qualify.

Canonical criterion support is intentionally not fabricated to look balanced. AB/BA ordering already presents every canonical non-tie once as model-visible A and once as B. The release separately records semantic support:

- Maintainability/extensibility and performance/efficiency have bidirectional canonical winners and calibrate bidirectional discrimination.
- Functional correctness is one-sided with only one decisive example and is production tie-only. Simplicity/scope has seven one-sided decisive examples, balanced by AB/BA presentation, and is production-decisive on that support.
- Security/reliability is tie-only and calibrates tie discipline, not winner discrimination.

The neutral length-bias probe distinguishes extra bytes that are `necessary` from extra bytes that are `harmful`. It rejects comparators that blindly prefer either longer or shorter patches.

## Adjudication

Each pair preserves five records:

- `reviewer_a`: the original author review under rubric 2.0.
- `reviewer_b`: a separately executed comparison review under rubric 2.0.
- `re_review`: a separately executed comparison review under rubric 2.1.
- `resolution`: the preserved root resolution under rubric 2.1.
- `scoring_gold`: the v1 exact per-requirement status expansion used for scoring.

The original records remain intact even where the v2.1 applicability rule makes their secondary criterion vectors obsolete. Semantic case IDs were visible to the comparison reviewers, so the release does not call these records blinded or claim cryptographic independence. It pins each preserved review stream's hash. The v2.1 re-review and root resolution disagree only on maintainability for `javascript-hot-regex-tradeoff`; the root rationale is recorded rather than disguising that disagreement as consensus.

`scoring_gold` may expand root-resolved requirements to exact statuses but is mechanically forbidden from changing decisions, violation IDs, criterion vectors, or outcomes. The only nontrivial expansions are the explicitly unverifiable undeclared-package behavior in pairs 5 and 30.

`migrate_adjudication_v21.py` is retained as a reproducible provenance asset. It materializes the recorded review sets, root resolutions, neutral length-bias metadata, and current v1 scoring labels. One execution must reproduce the checked-in manifest byte for byte; the focused migration regression enforces that stronger invariant. It is not imported by the evaluator or collector.

## Locked Artifacts

| File | Role |
| --- | --- |
| `manifest.json` | Corpus, contracts, patches, probes, and adjudication |
| `manifest.schema.json` | Versioned corpus schema |
| `profile.json` | Versioned profile descriptor and resource map |
| `semantic-contract.json` | Closed engine, adapter, vocabulary, calibration, and support contract |
| `rubric.json` | Eligibility, criterion, evidence, and outcome rules |
| `request-template.json` | Exact system prompt and payload field order |
| `response.schema.json` | Model output contract; no overall verdict field |
| `evidence.schema.json` | Offline invocation evidence contract |
| `../../holdout-plan.schema.json` | External release-plan evidence contract |
| `../../baseline-authority.json` | Independent frozen-original authority |
| `calibration.py` | Patch validation, request hashing, and scoring |
| `collect.py` | Release-pinned reference Claude CLI collector |
| `certify.py` | Evidence validation and production certification writer |
| `../comparator_runtime.py` | Shared protocol and transport runtime |
| `../holdout_plan.py` | Strict external plan loader |
| `../holdout_cli.py` | Non-live sealed-plan preparation CLI |
| `release.json` | Trusted reference-CLI release metadata |
| `tests/test-release.json` | Explicit fake-provider release for offline tests |

The reference release pins canonical hashes for the corpus, schemas, rubric, request template, and system prompt; byte hashes for the evaluator, collector, certifier, shared runtime, provider, runner, manifest loader, package exports, normal CLI, holdout loader, and preparation CLI; every preserved review stream; the full Claude CLI configuration; provider version; requested model; required primary-model prefix; allowed auxiliary-model prefixes; opaque invocation namespace; criterion support; execution limits; the exact frozen-original git commit jointly authorized by `baseline-authority.json` and `suite.json`; the authority artifact's byte hash; and holdout-plan schema.

Model-visible invocation IDs are 64-character HMAC-SHA-256 digests. Pair ID, order, repetition, outcome, skill, role, and release ID remain only in trusted evidence metadata and are absent from the request. The exact user payload contains the complete locked rubric, so any rubric mutation changes request bytes and hashes.

## Trust Boundary

The hashes detect accidental drift only when `release.json` and the executing code are trusted. They are not signatures. An attacker who can replace the release and code can forge JSON and recompute every hash. `lock_release.py` is therefore a review aid, not an authenticity mechanism: regenerate locks only after reviewing the artifact diff.

Reference evidence must request `claude-sonnet-5`, include a Sonnet 5 actual model ID, contain only allowed Sonnet/Haiku model IDs, and preserve the same full actual-model set across all calls. The explicit deterministic fake release is accepted only with `--allow-test-release` or `allow_test_release=True`.

Every trial retains the exact UTF-8 provider response, its raw byte hash, and a separate canonical parsed-response hash. Evaluation reparses the raw envelope and requires its `structured_output` and complete `modelUsage` set to match the parsed response and recorded actual models. `is_error` must be present and exactly `false`; `total_cost_usd` must be finite, non-negative, and match the trial record.

Evidence uses one-based inclusive source ranges. Candidate evidence paths refer to reconstructed post-patch files, including unchanged supplied files. Contract paths are exactly `contract/task`, `contract/requirements/<id>`, `contract/performance_basis`, or `contract/qualitative_bases/<criterion>` when present. `line_start` and `line_end` must exist in those bytes. `quote` must occur exactly within every cited line range and be repeated exactly in the explanatory observation. Requirement and criterion evidence also carries an exact typed `semantic_anchor`, repeated verbatim in the observation. The validator derives the only accepted anchor from the response field being justified.

## Shared Runtime And Certification

Collection and production both call the same `ComparatorRuntime` and `SandboxedClaudeExecutor`; there is no direct collector-only subprocess path. The canonical core reconstructs patches, validates bounded evidence, derives eligibility and violations, enforces typed criterion support, and mechanically derives outcomes for both paths.

The built-in runtime resolves descriptor and release bytes from installed package resources, binds them to the exact suite manifest, baseline authority, and installed runtime sources, and loads live evidence from the suite-owned `comparator-evidence/software-engineering-v1/certification.json`. The recorded evidence path is relative to that profile directory.

`write_certification(runtime, evidence_path, destination, persistence_root=root)` is the shared writer for a persistent external root. `root` must already be an existing non-symlink directory and should be mode `0700`; directory permissions remain the caller's responsibility. The evidence and certification are enforced as mode `0600`. The loader re-evaluates the complete evidence against immutable profile bytes and the separately validated suite/runtime bindings before accepting the certification.

The model receives the canonical user payload on stdin, not argv. Raw stdout is captured as exact bytes with independent hard stdout/stderr limits; timeout or overflow stops the complete systemd unit. Every invocation records its sandbox properties, request/stdin/command/response hashes, exact model set, local Claude regular-file identity and SHA-256, systemd version, provider version, duration, and cost. The executable used for the bind is a random private copy made from one continuously held and revalidated source descriptor, so an ordinary CLI path replacement cannot change executed bytes. The remote model service is outside cryptographic attestation.

Spend is reserved at the full per-call ceiling before launch. An append-only, fsynced JSONL journal records the reservation before execution, then exact reconciliation or a full-ceiling forfeit. Unclosed reservations restore as full charges after interruption. Calibration evidence embeds and hashes this ledger. Journals, checkpoints, and certifications must be owner-only regular files; writes are mode `0600`, atomic where replacement is required, and fsynced with their parent directory. Reads bind bytes, hashes, and file fingerprints to one descriptor capture.

No v1 live evidence or certification is checked in. This is intentional: protocol validation and dry runs report valid locks, while production judged runs fail closed with `live_calibration_valid: false`. A certification is valid only when complete fresh evidence passes every gate with one stable actual-model set, one stable local Claude executable digest, and one stable systemd version. Production rejects executable or systemd drift before a comparator call and model-set drift before accepting its result.

The private copy prevents normal package or symlink updates from racing the attested CLI. It does not defend against a hostile process already running as the same host UID; that process is outside this evaluator's isolation boundary.

## Verification

Run the complete offline suite:

```bash
cd skivolve/comparator_calibration
python3 -m unittest discover -s tests -v
ruff check calibration.py collect.py certify.py lock_release.py \
  migrate_adjudication_v21.py tests/test_calibration.py
python3 -m py_compile calibration.py collect.py certify.py lock_release.py \
  migrate_adjudication_v21.py tests/test_calibration.py
python3 calibration.py
python3 calibration.py --release tests/test-release.json --allow-test-release
```

Format first, then regenerate and review release locks after an intentional artifact change. The migration must remain byte-identical, and the lock generator must be the last source-affecting step before verification:

```bash
python3 migrate_adjudication_v21.py
python3 lock_release.py
git diff -- manifest.json release.json tests/test-release.json
```

Collect shared-runtime evidence. The calibration corpus has 100 billable calls with a locked 300-second timeout, `$1.00` per-call ceiling, and `$100.00` run ceiling. `expected_call_count` describes only this corpus and is never used for production planning. Output must be a direct child of the private mode-`0700` `evidence/` directory. Resume restores both successful charges and forfeited or interrupted reservations:

```bash
python3 collect.py --output evidence/claude-sonnet-5-v1.json
python3 calibration.py --evidence evidence/claude-sonnet-5-v1.json
python3 certify.py --evidence evidence/claude-sonnet-5-v1.json
```

Git does not preserve `0600` versus `0644`. After a fresh checkout of committed evidence, restore the enforced local modes before validation:

```bash
chmod 700 evidence
chmod 600 evidence/*.json
```

No live collection is required to validate protocol locks. Do not create a certification from synthetic evidence or copy a historical v2.2 result into the v1 profile; v1 needs fresh execution through the shared runtime.
