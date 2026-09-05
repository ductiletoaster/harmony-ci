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
| `actions/gitleaks` | secret scan over git history; **asserts history depth** — see below | — |
| `actions/semgrep` | SAST | baked ruleset `/opt/semgrep/harmony-baseline.yaml` |
| `actions/ruff` | Python lint + format (auto-detected) | caller's `pyproject.toml` |
| `actions/osv-scanner` | dependency CVEs (offline baked DB); **asserts coverage** — see below | caller's lockfiles + `osv-scanner.toml` |
| `actions/tflint` | Terraform lint (auto-detected) | caller's `.tflint.hcl` |
| `actions/hadolint` | Dockerfile lint (auto-detected) | caller's `.hadolint.yaml` |
| `actions/skill-layout` | agent skills sit where their harness reads them — flat files, dangling symlinks, name/dir mismatch (auto-detected) | rule pinned from `pixeloven/crew` |

The scanners above are **env-independent** — they run baked tools on the runner
and never need your dependencies installed.

### gitleaks: the checkout depth is asserted, not assumed

gitleaks scans **commits**, not the working tree, so the checkout's history
depth *is* this gate's coverage. `actions/checkout` defaults to
**`fetch-depth: 1`**, which means a caller who forgets the `with:` block gets a
secret scan of the tip commit and a green check. Measured on a repo with a
`ghp_…` token in an older commit and a clean tip:

| Checkout | Commits scanned | gitleaks alone |
|---|---:|---|
| `fetch-depth: 0` | 5 | `leaks found: 1`, exit **1** |
| default (depth 1) | 1 | `no leaks found`, exit **0** |

`actions/gitleaks` refuses to report success from a clone whose history it did
not see. It checks `git rev-parse --is-shallow-repository` before scanning, and
prints the number of commits actually scanned to the job summary on **every**
run, pass or fail. Two degenerate cases fail the same way: a non-git directory
and a HEAD with zero commits — gitleaks reports both as `no leaks found`, exit 0.

| Input | Default | What it does |
|---|---|---|
| `on-shallow` | `fail` | Stop on a shallow checkout, naming the one-line fix. Fail-closed. |
| | `deepen` | Run `git fetch --unshallow` here, then **re-assert** — a fetch that did not actually deepen still fails the gate. |
| | `allow` | Scan the shallow clone anyway and say loudly, in the log and the summary, how few commits that covered. An explicit, reviewable statement that this gate is not scanning history in this repo. |

`fail` is the default rather than `deepen` because the misconfiguration belongs
in the caller's workflow, where one line fixes it once for every job, rather
than being re-paid as a full-history fetch on every run of this action.

The scan runs with `--exit-code 2`, so "leaks found" and "gitleaks itself died"
(a bad config or an unreadable source — both exit **1** by default) can no
longer be reported as the same thing.

### osv-scanner: coverage is asserted, not assumed

A dependency-CVE gate that examines **zero packages** reports the same green
check as one that examined everything and found nothing. `actions/osv-scanner`
refuses to do that: it scans with `--all-packages`, counts what was actually
examined, prints that count to the job summary on **every** run, and **fails** if
it comes to zero.

The concrete trap this closes: osv-scanner's directory walk **honours
`.gitignore`**, so a repo that gitignores `uv.lock` scans nothing at all —
`0 Extract calls`, "No package sources found". Worse, if such a repo also has any
*other* extractable file, the run exits **0 with real vulnerabilities
unexamined**, and nothing anywhere says so. Generating the lockfile in CI first
does not help; it is skipped for being gitignored, not for being absent.

| Input | Default | What it does |
|---|---|---|
| `include-git-ignored` | `true` | Scan lockfiles `.gitignore` excludes. Turning this off opts back in to the blindness above. |
| `lockfiles` | — | Name lockfiles explicitly (`-L`), for a lockfile the walk can't find. Runs as a separate scan and is merged in. |
| `paths` | `.` | Directories to walk. |
| `allow-empty` | `false` | Let a zero-package scan pass. Only for a repo with genuinely no dependency manifest — an explicit, reviewable statement that this gate covers nothing here. |

The action never passes osv-scanner's `--allow-no-lockfiles`, which prints
"No package sources found / No issues found" and exits **0** — the silent pass in
its purest form.

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

## Versioning — exact semver, and what a bump means

This repo cuts a **semver release per change**. `VERSION` at the repo root is the
source of truth; merging a bump to `main` tags `vX.Y.Z` and publishes a GitHub
Release (`.github/workflows/release.yml`). There is no artifact to build — for a
consumed action library, the tag *is* the release.

What the numbers mean for a gate library, where the interface is the action
inputs **and the verdict**:

| Bump | Means |
|------|-------|
| **major** | a gate can now fail a build that previously passed — a required input, a removed action, or **widened detection** |
| **minor** | new action, new optional input, strictly-additive capability |
| **patch** | fix with no change to what passes |

Widened detection is a **major** on purpose. A consumer bumping a minor should
never have to budget for a newly-red pipeline.

There are deliberately **no moving `v1` / `v1.2` alias tags**. A moving tag is a
floating pin wearing a version number, so this repo does not publish one.

## How to consume — your own workflow, pinned to an exact version

These actions run in your CI on runners that hold write-capable tokens, so
they're a **supply-chain surface**. Pin every `uses:` to an **exact semver tag**
— `@v2.0.0`. Never `@main`, never a bare major (`@v1`), never a commit SHA.

Why exact semver rather than a SHA: a SHA is immutable but opaque — it carries no
signal about *what changed*, so every bump is an unreviewable 40-character diff
and there is nothing to read before taking it. An exact version tag is equally
pinned in practice (this repo never moves a published tag) while telling you
whether you are taking a patch or a behaviour change, and it points at release
notes. Let Renovate bump the version through reviewed PRs.

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
      - uses: actions/checkout@v4
        with: { fetch-depth: 0 }
      - uses: ductiletoaster/harmony-ci/actions/gitleaks@v2.0.0
  semgrep:
    name: semgrep (SAST)
    runs-on: fire-risk-ci
    steps:
      - uses: actions/checkout@v4
      - uses: ductiletoaster/harmony-ci/actions/semgrep@v2.0.0
  # …add ruff / osv-scanner / tflint / hadolint the same way; drop any you don't want.
```

You choose the runner, which gates to include, and their names — so your branch
protection required-checks are yours to define.

## Security model

- **Thin by construction** — no secrets, tools, or infra specifics in this repo.
- **Branch protection** — PR + CODEOWNERS review, admins included, no force-push,
  linear history. Every change is reviewed.
- **Immutable consumption** — consumers pin an exact semver tag, and this repo
  never moves a published tag or publishes a moving major alias.
- **Self-linting CI** — this repo lints its own workflow + actions (yamllint +
  actionlint) and validates that `VERSION` is strict semver on every PR.
