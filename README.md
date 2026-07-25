# harmony-ci

Public, shared **CI gate library** for the Harmony platform and its consumers
(Harmony, FireRisk, …). It exists so repos under **different GitHub owners** can
call the *same* gate definitions — GitHub can't share a private reusable workflow
across owners, so this thin orchestration lives in the open.

## What's here (and what isn't)

- **Here (public):** the reusable workflow that *invokes* the gates. Nothing else.
- **NOT here (private):** the gate **tools** and the Semgrep **ruleset** — they
  are baked into the private `harmony-arc-runner` image, the real trust root.
  This workflow only runs tools already on the runner's PATH.

## Gates

Env-independent scanners, all **blocking** on a greened repo (fail only on *new*
regressions):

| Gate | What | Config source |
|------|------|---------------|
| gitleaks | secret scan (full tree) | — |
| semgrep | SAST | baked ruleset `/opt/semgrep/harmony-baseline.yaml` |
| ruff | Python lint + format (auto-detected) | caller's `pyproject.toml` |
| osv-scanner | dependency CVEs (offline baked DB) | caller's lockfiles + `osv-scanner.toml` baseline |
| tflint | Terraform lint (auto-detected) | caller's `.tflint.hcl` |
| hadolint | Dockerfile lint (auto-detected) | caller's `.hadolint.yaml` |

**Type-checking is deliberately not here** — it needs the resolved dependency
graph, so it belongs in each consumer's own env-aware CI (e.g. `uv run mypy` /
`uv run basedpyright`, `tsc --noEmit`).

## Two ways to consume

Each gate is both a **composite action** (`actions/<gate>/`) and a step in the
batteries-included **reusable workflow** (`.github/workflows/gates.yml`):

- **Standard floor** — call the workflow (below): one line, all gates, stable
  check names (`gates / <gate>`) ideal for branch-protection required checks.
- **A single gate in your own job** — use the action directly, so you control the
  runner, ordering, and can interleave with your own steps:

  ```yaml
  jobs:
    build:
      runs-on: fire-risk-ci
      steps:
        - uses: actions/checkout@<sha>
        - uses: ductiletoaster/harmony-ci/actions/semgrep@<sha>   # just SAST, here
        - run: ./build.sh
  ```

Actions assume the repo is already checked out (they don't checkout). `gitleaks`
wants `fetch-depth: 0`. All actions require a `harmony-arc-runner` (baked tools).

## Requirements

Runners built from **`harmony-arc-runner`** (baked tools + rulesets + offline OSV
DB). Pass your runner label via the `runner` input.

## How to consume — pin to a commit SHA

This repo is a **supply-chain root**: its jobs run in your CI on runners that hold
write-capable tokens. **Never** consume it at `@main` or a floating tag — pin to a
full commit SHA so a `main` push or a moved tag can't hijack your pipeline. Let
Renovate bump the SHA through a reviewed PR.

```yaml
# .github/workflows/ci-gates.yml
name: CI Gates
on:
  push: { branches: [main] }
  pull_request:
jobs:
  gates:
    uses: ductiletoaster/harmony-ci/.github/workflows/gates.yml@<40-char-commit-sha>
    with:
      runner: fire-risk-ci   # your ARC pool label (default: harmony-cluster)
```

## Security model

- **Thin by construction** — no secrets, tools, or infra specifics in this repo.
- **Branch protection** — PR + CODEOWNERS review required, admins included, no
  force-push, signed/linear history. Every change is reviewed.
- **Immutable consumption** — consumers pin by SHA; version tags are protected.
- **Self-linting CI** — this repo lints its own workflows (yamllint + actionlint)
  and pins the actions it uses to commit SHAs.
