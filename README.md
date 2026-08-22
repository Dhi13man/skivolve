# Skivolve

[![CI](https://github.com/Dhi13man/skivolve/actions/workflows/ci.yml/badge.svg)](https://github.com/Dhi13man/skivolve/actions/workflows/ci.yml) [![CodeQL](https://github.com/Dhi13man/skivolve/actions/workflows/codeql.yml/badge.svg)](https://github.com/Dhi13man/skivolve/actions/workflows/codeql.yml) [![OpenSSF Scorecard](https://api.scorecard.dev/projects/github.com/Dhi13man/skivolve/badge)](https://scorecard.dev/viewer/?uri=github.com/Dhi13man/skivolve) [![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)

[Website](https://dhi13man.github.io/skivolve/) · [Documentation](https://dhi13man.github.io/skivolve/docs/) · [Corpus](https://dhi13man.github.io/skivolve/corpus/) · [Security model](https://dhi13man.github.io/skivolve/security/)

Skivolve runs reproducible A/B evaluations of agent skills and instruction bundles through isolated harnesses, objective case verifiers, and calibrated blinded comparison.

Version `0.7.0` is an alpha release for expert evaluation work on Linux. The public repository contains train and validation cases, not a private holdout, and ships no live comparator certification. It does not claim that one harness or bundle is superior. The production `software-engineering-v1` comparator profile is calibrated for software changes; the bundled plain-language profile has test authority and author-authored labels, not independent production calibration.

## What Skivolve Provides

- Git-bound control and treatment sources with drift detection.
- Twenty-one engineering and testing cases with objective, adversarially calibrated verifiers.
- Isolated Claude CLI generation and comparison, diagnostic Codex generation, and deterministic offline test providers.
- Bounded spend accounting, blinded AB/BA comparison, canonical output contracts, and single-attempt holdout plans.

## Requirements

- Linux with a working `systemd --user` manager.
- util-linux `unshare`, `mount`, and `setpriv`, with unprivileged user and mount namespaces enabled.
- Python 3.11 or newer.
- Git, Go, and Node.js for the included fixtures.
- GitHub CLI with `gh attestation` for release verification.
- For Claude runs: Claude Code 2.1.187 or newer, `bubblewrap`, `socat`, and the executable `@anthropic-ai/sandbox-runtime` seccomp helper. For nonstandard locations, set `SKIVOLVE_CLAUDE_BWRAP_PATH`, `SKIVOLVE_CLAUDE_SOCAT_PATH`, or `SKIVOLVE_CLAUDE_SECCOMP_APPLY_PATH`; Skivolve attests and privately mounts all three helpers.
- The authenticated provider executable configured by the suite. A dry run validates it and its local prerequisites without invoking a model.

The runtime package has one exact third-party dependency, `rfc8785==0.1.4`, for RFC 8785 JSON canonicalization.

## Install The Verified Release

Clone the tagged source so the reference suite, cases, and pinned Git baseline are available:

```bash
git clone --branch v0.7.0 https://github.com/Dhi13man/skivolve.git
cd skivolve
python3 -m venv .venv
. .venv/bin/activate
```

Download, verify, and install the release wheel:

```bash
mkdir -p /tmp/skivolve-0.7.0
gh release download v0.7.0 --repo Dhi13man/skivolve \
  --pattern "skivolve-0.7.0*" --pattern SHA256SUMS \
  --dir /tmp/skivolve-0.7.0
(cd /tmp/skivolve-0.7.0 && sha256sum --check SHA256SUMS)
gh attestation verify \
  /tmp/skivolve-0.7.0/skivolve-0.7.0-py3-none-any.whl \
  --repo Dhi13man/skivolve
python -m pip install \
  /tmp/skivolve-0.7.0/skivolve-0.7.0-py3-none-any.whl
```

## Run A Comparison

Preflight the checked-in candidate against the pinned original without dispatching a model or writing results:

```bash
skivolve \
  --suite suite.json \
  --comparison candidate-vs-original \
  --dry-run
```

Successful output contains `"dry_run": true` and the resolved preflight evidence.

Run generation and objective verifiers without comparator judgment:

```bash
skivolve \
  --suite suite.json \
  --comparison candidate-vs-original \
  --verifier-only \
  --output-dir /tmp/skivolve-verifier
```

This non-dry run invokes the configured generation provider and may consume metered API spend or subscription quota. Preflight reports the configured per-call and run ceilings; an unknown exact charge is accounted at its ceiling.

## Generate A Candidate With SkillOpt

SkillOpt is an optional candidate generator, not a replacement evaluator or a Skivolve runtime dependency. Skivolve accepts only a clean checkout of the reviewed upstream commit, sends explicitly selected public training and selection cases through SkillOpt, then evaluates the frozen output in a fresh Git clone. Candidate evaluation uses isolated Python module resolution so that clone cannot replace Skivolve's evaluator code, and outer validation independently reconstructs each deterministic candidate commit and whole-bundle snapshot. The command never reads a holdout or modifies, commits, or adopts the source skill. Linux and an authenticated standalone Codex CLI with its bundled Bubblewrap executable are required for the optimizer boundary.

Prepare a separate environment from the reviewed source:

```bash
git clone https://github.com/microsoft/SkillOpt.git /opt/skillopt-src
git -C /opt/skillopt-src checkout bdfdc30a8e17309c06cdbe8449f01bdecc120203
python3 -m venv /opt/skillopt-venv
/opt/skillopt-venv/bin/python -m pip install /opt/skillopt-src
/opt/skillopt-venv/bin/python -m pip install -e /path/to/skivolve
/opt/skillopt-venv/bin/python -m pip freeze --all > /opt/skillopt-venv.resolved.txt
```

Upstream declares dependency ranges rather than a lock. Review and retain the resolved environment record; Skivolve hashes the bounded isolated-environment tree and resolved file targets of its symlinks, excluding generated Python caches, and rejects any environment drift between plan approval and execution.

Preflight a one-step testing-skill pilot without creating persistent artifacts or invoking a model. The command uses private temporary clones to validate the exact generated fitness and attribution manifests and proves that the exact Codex permission profile denies every model-requested tool process before execution, then prints `expected_plan_sha256`:

```bash
skivolve-optimize \
  --suite suite.json \
  --skill testing \
  --baseline-ref HEAD \
  --train-case testing-real-boundary-fidelity \
  --selection-case testing-oracle-sensitivity \
  --validation-case testing-legacy-characterization \
  --skillopt-source /opt/skillopt-src \
  --skillopt-python /opt/skillopt-venv/bin/python \
  --output-dir /home/operator/skivolve-skillopt-testing \
  --dry-run
```

Run the same command without `--dry-run`, adding both `--confirm-live` and the reviewed hash as `--expected-plan-sha256 HASH`. Use an output parent outside `/tmp` and `/var/tmp`, because provider units use systemd `PrivateTmp`; the planner rejects those ephemeral roots before any model call. Live execution fails before creating its run directory or invoking a model if any selected suite, prompt, fixture, verifier, interpreter, isolated SkillOpt environment, upstream checkout, source commit, optimizer executable, bundled Bubblewrap executable, or plan binding changed. Prompts and the seed skill are read from the approved Git commit after the working-tree equality gate, eliminating a mutable-path read between approval and execution.

This recipe permits at most 24 Skivolve target-generator launches: baseline selection, one training rollout, candidate selection, and fresh validation, with two arms and three repetitions per case. Its separate SkillOpt optimizer budget permits at most three Codex CLI starts of 900 seconds each, for a combined generator/optimizer invocation ceiling of 27. That figure excludes verifier, Git, and orchestration processes; it is not a total process ceiling. Generated optimizer suites force `objective_only`, so no comparator is invoked. Process groups, bounded input and output, per-optimizer, sidecar, preflight, and certification timeouts, and optimizer start count are enforced; the run fails closed at those boundaries. A Codex CLI process may perform multiple provider turns, so these are not token, provider-call, or monetary ceilings. Set a separate provider or account quota before live execution. Skivolve continues to use the suite's configured target provider and objective verifiers.

The optimizer runs in a minimal Bubblewrap filesystem with a private home, a read-only run tree, a writable run-owned temporary directory, and a strict Codex permission profile that prevents model-generated tools from starting at all. The dry-run and live sidecar both probe this denial with the exact plan-bound Codex and bundled Bubblewrap before any optimizer model call. Provider-side apps, browser, image, plugin, elicitation, collaboration, memory, and related tool surfaces are disabled. Treat this as defense in depth for reviewed public inputs, not as permission to optimize secrets or adversarial prompt content: the trusted Codex parent process still needs authentication and network access, and provider-side spend authority remains external to Skivolve.

The final `optimization.json` reports `qualified`, `rejected`, or `no_change`, binds every candidate, optimizer invocation ledger, and Skivolve run by SHA-256, and labels its authority `public-objective-diagnostic`. A qualified public result is not a superiority or release claim. Adoption remains a separate human-reviewed Git change.

## Suite Contract

Skivolve accepts suite schema v1. The checked-in [suite.json](suite.json) is the runnable reference; [suite.schema.json](suite.schema.json) is the editor and interoperability contract, and the parser in [skivolve/manifest.py](skivolve/manifest.py) is authoritative. The schema and parser must remain behaviorally identical.

| Component | Purpose |
| --- | --- |
| `evaluation_mode` | Selects `judged` or `objective_only` evaluation. |
| `provider` | Selects a reviewed generation adapter and its bounded configuration. |
| `comparator` and `comparator_profile` | Select the judgment adapter and calibrated contract for judged runs. |
| `variants` and `comparisons` | Bind source arms, control and treatment roles, repetitions, and AB/BA order. |
| `shared_verifier_dir` | Selects one contained read-only resource directory or explicitly disables it with `null`. |
| `holdout` | Selects the ordered comparisons authorized for release evaluation. |
| `cases` | Bind task inputs, fixtures, bundle sources, verifiers, limits, expectations, and one artifact contract. |

Every case declares one of three canonical artifacts: `workspace_diff`, `final_output_text`, or `final_output_json`. Judged text or JSON requires a comparator profile calibrated for that artifact kind; the bundled production profile currently supports workspace diffs only. See the [getting-started guide](https://dhi13man.github.io/skivolve/docs/) for suite setup and [CONTRIBUTING.md](CONTRIBUTING.md) for case acceptance rules.

Verifiers receive canonical output through read-only `EVAL_ARTIFACT_PATH`, with `EVAL_ARTIFACT_KIND` and `EVAL_ARTIFACT_SHA256`; `EVAL_SHARED_ROOT` exists only when `shared_verifier_dir` is configured. Final-output verification uses a pristine fixture workspace, so candidate files cannot replace the declared output, while `EVAL_AGENT_WORKSPACE_MUTATED` reports generation-time writes even when the final bytes are restored.

The reviewed adapter IDs are `claude-cli`, `codex-app-server`, and `deterministic-fake`. Adapter names and provider output cannot grant authority beyond the code-owned capability registry.

## Evidence And Claim Limits

Public validation is not a private holdout. A release claim requires a separately stored suite frozen before candidate evaluation, independent review outside Skivolve, an external mode-`0600` sealed plan, and one consumed execution record. Skivolve records operator-supplied reviewer labels and record locations; it does not authenticate those people or records. Plan consumption reduces accidental reruns but is not an append-only or cryptographic defense against a hostile same-UID process.

Generated code, prompts, fixtures, provider output, and comparator responses are untrusted. Skivolve binds and rechecks declared sources and runs providers in bounded Linux isolation, but it does not defend against a compromised provider binary, kernel, root account, or host. Read [SECURITY.md](SECURITY.md) before using proprietary fixtures, private holdouts, or valuable credentials. The [calibration documentation](skivolve/comparator_calibration/README.md) defines the comparator's evidence and authority limits.

## Development And Support

Development setup, required checks, case design, and release policy are in [CONTRIBUTING.md](CONTRIBUTING.md). See [CHANGELOG.md](CHANGELOG.md) before upgrading. Use [GitHub Discussions](https://github.com/Dhi13man/skivolve/discussions) for evaluation design and setup questions, [SUPPORT.md](SUPPORT.md) for issue guidance, and private vulnerability reporting for security findings.

## License

Skivolve is released under the [MIT License](LICENSE).
