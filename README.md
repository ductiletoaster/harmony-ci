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

## Guidance & convenient templates

On top of the raw actions there's **guidance** (recommended patterns + the
reasoning) and **copy-and-adapt workflows** to make reuse easy. All optional —
take what fits, delete the rest:

- **[GUIDANCE.md](GUIDANCE.md)** — recommended patterns, with rationale: a way to
  think about CI checks (the code-quality / security-floor / security-depth
  tiers), sensible defaults and why, a getting-started walkthrough, runner notes,
  optional branch protection, and prek coexistence. Nothing in it is required.
- **[templates/](templates/)** — ready-to-copy workflows (a cookbook, not a form):
  - `ci-arc.yml` — inline CI on a harmony-arc-runner (baked, tokenless floor).
  - `ci-github-hosted.yml` — the same floor on `ubuntu-latest`, no baked image
    (for repos without ARC access).
  - `security-scan.yml` — a weekly, non-blocking security sweep that files a
    tracking issue on findings.

Copy the template that matches your runner, keep the jobs you want, drop the
rest. The composite actions below are always there for bespoke pipelines — the
guidance is a recommended starting point, not a mandate.

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

The scanners above are **env-independent** — they run baked tools on the runner
and never need your dependencies installed.

## Language-pack actions (uv-based, env-dependent)

Code-quality checks that DO need the resolved dependency graph — type-checkers,
tests — can't run as baked scanners, so these run **your own pinned tools** via
`uv run`, matching your local dev exactly (no baked-vs-pinned skew). Granular by
design: adopt each independently — drop the type-check, or swap its checker,
without touching lint or test. Auto-detected (skip cleanly with no
`pyproject.toml`). Require **uv on PATH** — baked into `harmony-arc-runner`; on
github-hosted, run `astral-sh/setup-uv` first. They run the tools from your
**default** dependency group (`[dependency-groups] dev`), which `uv run` installs
via its implicit sync; a repo that isolates them in a non-default group must
promote it (`[tool.uv] default-groups`) or `uv run` won't find them.

| Action | What | Runs |
|--------|------|------|
| `actions/python-lint` | lint + format | `uv run ruff check .` + `uv run ruff format --check .` |
| `actions/python-typecheck` | type-check | `uv run <type-checker>` — input `type-checker`, default **mypy** (the fleet standard); override for basedpyright / pyrefly |
| `actions/python-test` | tests | `uv run pytest` (+ optional `args`) |

(`actions/ruff` above is the **baked, env-independent** lint variant for repos
without uv; `python-lint` uses your uv-pinned ruff for version-consistency with
the other `uv run` steps. Use whichever fits.)

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
