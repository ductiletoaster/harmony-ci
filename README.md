# harmony-ci

Public **CI action library** for the Harmony platform and its consumers
(Harmony, FireRisk, …). A set of **composite actions** — one per gate — that you
compose into **your own** workflow. There is deliberately **no shared reusable
workflow**: each project owns its CI workflow, so it controls which gates run,
their order, and any project-specific steps, and the whole pipeline is visible in
that project's own repo.

Repos under different GitHub owners can use these (GitHub can't share a *private*
reusable workflow across owners, and composable public actions are the clearer
mechanism anyway).

## What's here (and what isn't)

- **Here (public):** thin composite actions that *invoke* the gates. Nothing else.
- **NOT here (private):** the gate **tools** and the Semgrep **ruleset** — baked
  into the private `harmony-arc-runner` image, the real trust root. These actions
  only run tools already on the runner's PATH.

## Actions

Env-independent scanners; each is **blocking** on a greened repo (fails only on
*new* regressions):

| Action | What | Config source |
|--------|------|---------------|
| `actions/gitleaks` | secret scan (full tree; caller checks out `fetch-depth: 0`) | — |
| `actions/semgrep` | SAST | baked ruleset `/opt/semgrep/harmony-baseline.yaml` |
| `actions/ruff` | Python lint + format (auto-detected) | caller's `pyproject.toml` |
| `actions/osv-scanner` | dependency CVEs (offline baked DB) | caller's lockfiles + `osv-scanner.toml` |
| `actions/tflint` | Terraform lint (auto-detected) | caller's `.tflint.hcl` |
| `actions/hadolint` | Dockerfile lint (auto-detected) | caller's `.hadolint.yaml` |

**Type-checking is deliberately not here** — it needs the resolved dependency
graph, so it belongs in each consumer's own env-aware CI (e.g. `uv run mypy` /
`uv run basedpyright`, `tsc --noEmit`).

## Requirements

Runners built from **`harmony-arc-runner`** (baked tools + rulesets + offline OSV
DB). The actions assume the repo is already checked out (they don't checkout).

## How to consume — your own workflow, pinned by SHA

These actions run in your CI on runners that hold write-capable tokens, so they're
a **supply-chain surface**: pin every `uses:` to a full commit **SHA**, never
`@main` or a floating tag. Let Renovate bump the SHAs through reviewed PRs.

```yaml
# .github/workflows/ci-gates.yml — a workflow YOU own and can tailor
name: CI Gates
on:
  push: { branches: [main] }
  pull_request:
permissions:
  contents: read
jobs:
  gitleaks:
    name: gitleaks (secret scan)
    runs-on: fire-risk-ci            # your ARC pool label
    steps:
      - uses: actions/checkout@<sha>
        with: { fetch-depth: 0 }
      - uses: ductiletoaster/harmony-ci/actions/gitleaks@<sha>
  semgrep:
    name: semgrep (SAST)
    runs-on: fire-risk-ci
    steps:
      - uses: actions/checkout@<sha>
      - uses: ductiletoaster/harmony-ci/actions/semgrep@<sha>
  # …add ruff / osv-scanner / tflint / hadolint the same way; drop any you don't want.
```

You choose the runner, which gates to include, and their names — so your branch
protection required-checks are yours to define.

## Security model

- **Thin by construction** — no secrets, tools, or infra specifics in this repo.
- **Branch protection** — PR + CODEOWNERS review, admins included, no force-push,
  linear history. Every change is reviewed.
- **Immutable consumption** — consumers pin by SHA.
- **Self-linting CI** — this repo lints its own workflow + actions (yamllint) and
  pins the actions it uses to commit SHAs.
