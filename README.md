# harmony-ci

Public **CI action library** — a set of **composite actions**, one per gate, that
you compose into **your own** workflow. It runs on `ubuntu-latest` like anything
else; a self-hosted runner pool is an optimization here, not a requirement.

Two audiences, deliberately: the private Harmony fleet this was built for and is
dogfooded by, and any public repo that wants the same gates without a cluster
behind it. Where those diverge — a tool that has to be baked, a ruleset that is
private — each action's **Runner needs** column says so, rather than the README
claiming one runner for all of them.

There is deliberately **no shared reusable workflow**: each project owns its CI
workflow, so it controls which gates run, their order, and any project-specific
steps, and the whole pipeline is visible in that project's own repo. Repos under
different GitHub owners can use these (GitHub can't share a *private* reusable
workflow across owners, and composable public actions are the clearer mechanism
anyway).

## Guidance & convenient templates

On top of the raw actions there's **guidance** (recommended patterns + the
reasoning) and **copy-and-adapt workflows** to make reuse easy. All optional —
take what fits, delete the rest:

- **[GUIDANCE.md](GUIDANCE.md)** — recommended patterns, with rationale: a way to
  think about CI checks (the code-quality / security-floor / security-depth
  tiers), sensible defaults and why, a getting-started walkthrough, runner notes,
  optional branch protection, and prek coexistence. Nothing in it is required.
- **[templates/](templates/)** — ready-to-copy workflows (a cookbook, not a form):
  - `ci-github-hosted.yml` — the floor on `ubuntu-latest`, no baked image. The
    default starting point, and the one that needs nothing you don't already
    have. It sources its gates from **public marketplace actions**, so it gives
    you the same *tools* as the library — and none of the coverage assertions
    below, which live in `actions/*`. Swap any job for the matching action once
    you have put its tool on PATH.
  - `ci-arc.yml` — the same tools on a self-hosted ARC pool, wired through this
    library's `actions/*` (so the assertions apply), with the tools and an
    offline OSV DB baked into the image.
  - `security-scan.yml` — a weekly, non-blocking security sweep that files a
    tracking issue on findings.

Copy the template that matches your runner, keep the jobs you want, drop the
rest. The composite actions below are always there for bespoke pipelines — the
guidance is a recommended starting point, not a mandate.

## What's here (and what isn't)

- **Here (public):** thin composite actions that *invoke* the gates. Nothing
  else — no secrets, no tools, no infra specifics.
- **Not here:** the gate **tools** themselves. An action runs what is already on
  the runner's PATH, so where that comes from is yours to choose: public
  marketplace actions and one-line installs on `ubuntu-latest`, or an image you
  bake. Harmony bakes them into the private `harmony-arc-runner`, which is that
  fleet's trust root — not a dependency of this library.

## Actions

Env-independent scanners; each is **blocking** on a greened repo (fails only on
*new* regressions). **Runner needs** is what has to exist before the action can
run — the one claim this library makes about your infrastructure:

| Action | What | Runner needs | Config source |
|--------|------|--------------|---------------|
| `actions/gitleaks` | secret scan over git history; **asserts depth and scope** — see below | `gitleaks` on PATH | — |
| `actions/semgrep` | SAST; **refuses a login-gated ruleset** — see below | `semgrep` on PATH + a ruleset | `config` input, default baked `/opt/semgrep/harmony-baseline.yaml` |
| `actions/ruff` | Python lint + format (auto-detected) | `ruff` on PATH | caller's `pyproject.toml` |
| `actions/osv-scanner` | dependency CVEs (offline baked DB); **asserts coverage and freshness** — see below | `osv-scanner` on PATH **and an offline DB** (`db-dir`, default `/opt/osv-scanner-db`) — in practice a baked image | caller's lockfiles + `osv-scanner.toml` |
| `actions/tflint` | Terraform lint (auto-detected) | `tflint` on PATH | caller's `.tflint.hcl` |
| `actions/hadolint` | Dockerfile lint (auto-detected) | `hadolint` on PATH | caller's `.hadolint.yaml` |
| `actions/skill-layout` | agent skills sit where their harness reads them — flat files, dangling symlinks, name/dir mismatch (auto-detected) | nothing baked, but **egress at job time**: it `npm install -g`s two CLIs, installs skilllint from PyPI and `curl`s the rule | rule pinned from `pixeloven/crew` |

The scanners above are **env-independent** — they run a tool that is already on
the runner and never need *your* dependencies installed. That is a separate
question from where the tool itself comes from, which is the **Runner needs**
column: `skill-layout` fetches what it needs at job time, and the rest need
their binary provided, whether by a baked image or an install step in your
workflow. `osv-scanner` is the one an install step does **not** satisfy: it
scans `--offline`, so it needs the vulnerability *database* on disk as well as
the binary — `db-dir`, defaulting to `/opt/osv-scanner-db` — which in practice
means a baked image.

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
prints **which scope ran and how many commits that covered** to the job summary
on **every** run, pass or fail. Two degenerate cases fail the same way: a
non-git directory and a HEAD with zero commits — gitleaks reports both as
`no leaks found`, exit 0.

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

`on-shallow` applies under **every** scope, `branch` included. A depth-1
checkout truncates what `HEAD` reaches too, so exempting `branch` would let the
commit count pass while coverage silently shrank to the tip.

### gitleaks: which commits, not just how many

Depth is one half of coverage; **which refs** is the other. With no `--log-opts`
gitleaks walks `git log --all`, and `actions/checkout` with `fetch-depth: 0`
always fetches `+refs/heads/*:refs/remotes/origin/*` regardless of its `ref:`
input. So on a pull request the default scope also scans every **other**
unmerged branch in the repo — observed consequence: a PR blocked by two findings
on a branch its author had never touched.

| Input | Default | What it does |
|---|---|---|
| `scope` | `history` | Every commit in the clone, across all refs — gitleaks' own default walk. Unchanged from v2.0.0. |
| | `branch` | Only the commits reachable from `HEAD`: the branch under review, back through its full history. |

`history` stays the default because narrowing a security gate should be a
decision someone makes, not something an upgrade does to them. Choose `branch`
for a per-PR merge gate, where a finding must be about the change under review;
keep a repo-wide sweep, but on a schedule (`templates/security-scan.yml`) where
it can't block an unrelated merge.

One non-obvious mechanic, recorded because it is expensive to re-derive:
gitleaks drops its own `--full-history`, `--all` **and** `--diff-filter=tuxdb`
the moment `--log-opts` is non-empty. `branch` therefore re-states
`--full-history` and `--diff-filter=tuxdb` explicitly — otherwise changing which
*refs* are walked would silently change which *diff types* are scanned as a side
effect. A selftest step asserts both directions of this against the real binary
on every run: that `branch` still reaches back past the tip commit, and that it
still stops at the branch.

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

### osv-scanner: freshness is asserted too, because a stale DB looks clean

Coverage answers *what was scanned*. It does not answer *what it was scanned
against*. The baked database is offline by design — that is what makes this gate
egress-free — but it therefore cannot see any advisory published after the
runner image was built, and a scan against it still exits **0**.

Measured: the same `uv.lock` got opposite verdicts from two gates in the same
PR. The baked gate passed; a github-hosted job querying osv.dev failed on two
`anyio` 4.13.0 advisories — one **critical**, a TLS certificate-verification
bypass — published the day before. The hosted job was right. Nothing in the
baked gate's output distinguished "no advisories" from "no advisories as of
whenever that image was built".

So the database's age is measured, printed to the job summary on **every** run,
and past a threshold the gate **fails**:

| Input | Default | What it does |
|---|---|---|
| `db-dir` | `/opt/osv-scanner-db` | The offline database this gate scans against, and the one whose age it measures. An image that bakes the DB elsewhere points this at it — otherwise the age reads as *unknown*, which now fails. |
| `max-db-age` | `30` | Days. Past this the gate fails, naming the build date and the fix. |
| | `0` | Turns the freshness check off **entirely**, including an age that cannot be determined at all. The age is still measured and still reported wherever it can be — opting out of the gate is not opting out of knowing. |
| `allow-stale-db` | `false` | Pass an over-age — or undateable — database as a warning. An explicit, reviewable statement that this gate's CVE freshness is not guaranteed here. |

`allow-stale-db` and `allow-empty` say different things and neither stands in
for the other: one is about *how current* the answer is, the other about
*whether anything was examined*. Neither can mask a real finding, and a selftest
case asserts each of those directions — including the one that caught a real bug
where `allow-stale-db` short-circuited past the empty-coverage check.

**How the database is dated.** In order:

1. **`<db-dir>/BAKED_AT`** — RFC3339, or a bare `YYYY-MM-DD`. Authoritative,
   and the contract a runner image should implement: it survives anything that
   rewrites file mtimes, and it states the date rather than letting the gate
   infer it.
2. Otherwise the **oldest baked `all.zip` mtime**, which is what an image build
   leaves behind today. The *oldest*, not the newest: the image seeds one
   database per ecosystem (PyPI/npm/Go/Cargo), and layer caching is exactly the
   mechanism that lets a rebuild refresh some and not others. A gate needs the
   **lower** bound — otherwise one re-seeded ecosystem vouches for three that
   rotted. The count and, where they disagree, the span are reported too, so a
   divergent image is visible rather than merely averaged away.
3. Otherwise **unknown** — which counts as stale. A cutoff nobody can name is
   not a cutoff, and "no advisories as of an unknown date" is not a result.

A build date more than **24 hours in the future** also counts as unknown. NTP
bounds real clock skew to seconds, so anything beyond a day is a marker
describing a date that has not happened — and a date that has not happened is
not a vintage. Clamping it to "0 days old" would let a `BAKED_AT` of
`2099-01-01` report *built 2099-01-01, 0 days old*, pass, and keep passing
forever past any threshold. Within the 24 hours it is still clamped to 0, so
ordinary skew cannot turn a working gate red.

An unparseable marker falls back to the mtime rather than collapsing to
unknown, so a malformed `BAKED_AT` cannot turn a working gate red on its own.

### semgrep: the ruleset is yours to choose, and it cannot be a registry name

A SAST gate is only as real as the rules it loads. Semgrep's registry configs
(`auto`, `p/*`, `r/*`) are **login-gated**: without `SEMGREP_APP_TOKEN` they
resolve to **zero rules**, find nothing, and exit **0**. That green is
indistinguishable from a clean scan of a real ruleset — the same silent-pass
shape as a shallow secret scan or a zero-package CVE scan.

So `actions/semgrep` takes the ruleset as an input and **refuses** a registry
name outright rather than passing it through:

| Input | Default | What it does |
|---|---|---|
| `config` | `/opt/semgrep/harmony-baseline.yaml` | The tokenless ruleset baked into `harmony-arc-runner`. Behaviour on that image is unchanged. |
| | a path in your repo | e.g. `.semgrep/rules.yml`. A file or a directory; it must be readable **and load at least one rule**. This is what makes the gate usable with no baked image. |
| | `auto`, `p/…`, `r/…` | **Refused**, with the reason above. Use `semgrep ci` directly if you want registry rules and have a token. |

The preflight asserts three things separately — `semgrep` on PATH, the ruleset
readable, and the ruleset **not empty** — so a failure says *which* one is
missing and how to fix it, rather than surfacing as `semgrep: command not
found` or a usage error that both read like the gate itself broke.

Readable is not the same as populated, and that gap is the same silent pass
arriving by a different door: `rules: []`, an empty directory, or a directory
of files semgrep cannot load each resolve to **zero rules**, match nothing and
exit **0**. So the preflight runs `semgrep --validate` and reads the rule count
out of it, failing at zero. What that cannot tell you offline is whether any of
those rules *apply* to your code — a ruleset whose `languages:` never match
still counts as rules and still finds nothing. It is the strongest claim
available without running a scan; it is not a claim about coverage.

```yaml
# off a baked image: install semgrep, vendor the rules
- uses: actions/checkout@v4
- run: uv tool install semgrep
- uses: ductiletoaster/harmony-ci/actions/semgrep@v3.0.0
  with: { config: .semgrep/rules.yml }
```

## Language-pack actions (uv-based, env-dependent)

Code-quality checks that DO need the resolved dependency graph — type-checkers,
tests — can't run as baked scanners, so these run **your own pinned tools** via
`uv run`, matching your local dev exactly (no baked-vs-pinned skew). Granular by
design: adopt each independently — drop the type-check, or swap its checker,
without touching lint or test. Auto-detected (skip cleanly with no
`pyproject.toml`). Require **uv on PATH** — on `ubuntu-latest` run
`astral-sh/setup-uv` first; a baked image may already have it (Harmony's does).
They run the tools from your
**default** dependency group (`[dependency-groups] dev`), which `uv run` installs
via its implicit sync; a repo that isolates them in a non-default group must
promote it (`[tool.uv] default-groups`) or `uv run` won't find them.

| Action | What | Runner needs | Runs |
|--------|------|--------------|------|
| `actions/python-lint` | lint + format | `uv` on PATH | `uv run ruff check .` + `uv run ruff format --check .` |
| `actions/python-typecheck` | type-check | `uv` on PATH | `uv run <type-checker>` — input `type-checker`, default **mypy**; override for basedpyright / pyrefly |
| `actions/python-test` | tests | `uv` on PATH | `uv run pytest` (+ optional `args`) |

(`actions/ruff` above is the **baked, env-independent** lint variant for repos
without uv; `python-lint` uses your uv-pinned ruff for version-consistency with
the other `uv run` steps. Use whichever fits.)

## Requirements

Only two things are true of every action here: the repo is **already checked
out** (no action runs `actions/checkout` for you), and the tool it drives is
already on **PATH**. What that second one costs you per action is the **Runner
needs** column above.

On `ubuntu-latest`, `skill-layout` works as-is, the uv-based language packs need
one `astral-sh/setup-uv` step first, and the rest need their binary installed by
a step in your workflow. `osv-scanner` is the exception: it scans `--offline`,
so a binary alone is not enough — it also needs a vulnerability database on disk
at `db-dir` (default `/opt/osv-scanner-db`), which in practice means a baked
image.

On a self-hosted image that bakes the tools — Harmony uses `harmony-arc-runner`
— the scanner gates are satisfied with no egress and no tokens. Two caveats,
because "every gate" would be too strong. The language packs still resolve
**your** dependencies, so they reach your package index like any `uv sync`. And
`skill-layout` bakes nothing: it installs the Claude Code and Codex CLIs from
npm, skilllint from PyPI, and `curl`s its rule from `raw.githubusercontent.com`,
on every run, on any runner. Its `claude-version` and `codex-version` inputs
default to `latest` — a floating pin, in a library that tells you not to have
one. Pin them explicitly until that default changes.

Where the two genuinely differ, it is **not always in the baked image's favour**:
`actions/osv-scanner` reads an *offline* database baked at image-build time, so
it is only as fresh as the last image rebuild, while a github-hosted job hitting
osv.dev sees today's advisories. Neither runner is strictly better; they trade
egress for freshness in opposite directions. The gate no longer lets you find
that out the hard way — see
[osv-scanner: freshness is asserted too](#osv-scanner-freshness-is-asserted-too-because-a-stale-db-looks-clean).

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
— `@v3.0.0`. Never `@main`, never a bare major (`@v1`), never a commit SHA.

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
    runs-on: ubuntu-latest           # or your self-hosted pool's label
    steps:
      - uses: actions/checkout@v4
        with: { fetch-depth: 0 }
      # On ubuntu-latest, put gitleaks on PATH first (one install step, or the
      # public gitleaks action). On an image that bakes it, this is the whole job.
      - uses: ductiletoaster/harmony-ci/actions/gitleaks@v3.0.0
  semgrep:
    name: semgrep (SAST)
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: ductiletoaster/harmony-ci/actions/semgrep@v3.0.0
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
