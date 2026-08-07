# Skivolve

[![CI](https://github.com/Dhi13man/skivolve/actions/workflows/ci.yml/badge.svg)](https://github.com/Dhi13man/skivolve/actions/workflows/ci.yml) [![CodeQL](https://github.com/Dhi13man/skivolve/actions/workflows/codeql.yml/badge.svg)](https://github.com/Dhi13man/skivolve/actions/workflows/codeql.yml) [![OpenSSF Scorecard](https://api.scorecard.dev/projects/github.com/Dhi13man/skivolve/badge)](https://scorecard.dev/viewer/?uri=github.com/Dhi13man/skivolve) [![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)

[Website](https://dhi13man.github.io/skivolve/) · [Documentation](https://dhi13man.github.io/skivolve/docs/) · [Corpus](https://dhi13man.github.io/skivolve/corpus/) · [Security model](https://dhi13man.github.io/skivolve/security/)

Skivolve runs reproducible A/B evaluations of agent skills and instruction bundles through isolated harnesses, objective case verifiers, and calibrated blinded comparison.

Version `0.5.0` is an alpha release for expert evaluation work on Linux. The public repository contains train and validation cases, not a private holdout, and ships no live comparator certification. It does not claim that one harness or bundle is superior. The production `software-engineering-v1` comparator profile is calibrated for software changes; the bundled plain-language profile has test authority and author-authored labels, not independent production calibration.

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
- For Claude runs: Claude Code 2.1.187 or newer, `bubblewrap`, `socat`, and the executable `@anthropic-ai/sandbox-runtime` seccomp helper. Set `SKIVOLVE_CLAUDE_SECCOMP_APPLY_PATH` for a nonstandard helper location.
- The authenticated provider executable configured by the suite. A dry run validates it and its local prerequisites without invoking a model.

The runtime package has one exact third-party dependency, `rfc8785==0.1.4`, for RFC 8785 JSON canonicalization.

## Install The Verified Release

Clone the tagged source so the reference suite, cases, and pinned Git baseline are available:

```bash
git clone --branch v0.5.0 https://github.com/Dhi13man/skivolve.git
cd skivolve
python3 -m venv .venv
. .venv/bin/activate
```

Download, verify, and install the release wheel:

```bash
mkdir -p /tmp/skivolve-0.5.0
gh release download v0.5.0 --repo Dhi13man/skivolve \
  --pattern "skivolve-0.5.0*" --pattern SHA256SUMS \
  --dir /tmp/skivolve-0.5.0
(cd /tmp/skivolve-0.5.0 && sha256sum --check SHA256SUMS)
gh attestation verify \
  /tmp/skivolve-0.5.0/skivolve-0.5.0-py3-none-any.whl \
  --repo Dhi13man/skivolve
python -m pip install \
  /tmp/skivolve-0.5.0/skivolve-0.5.0-py3-none-any.whl
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
