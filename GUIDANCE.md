# CI Guidance — recommended patterns

Guidance, not a mandate. harmony-ci is a **library of convenient CI capabilities**
plus **opinions on how to use them well** — which check catches what, and when
it's worth gating a merge vs. running on a schedule. This document explains the
reasoning so you can make an informed choice.

**Adopt what fits your project; nothing here is required.** Take a template,
delete the jobs you don't want, keep the ones you do. The composite actions in
[`actions/`](actions/) and the workflows in [`templates/`](templates/) are there
to make reuse **easy** — pick and choose.

The opinions here cover **code quality + security** only. Dependency-automation
(Renovate / Dependabot / none) is entirely your call and isn't discussed.

---

## A way to think about CI checks — three tiers

A useful mental model, with the rationale for each. Treat it as a starting point,
not a rulebook.

| Tier | What | Suggested cadence | Suggested posture |
|------|------|-------------------|-------------------|
| **Code quality** | lint + format → typecheck → tests, per language | inline, per PR | gate — a broken build/test is a clear "not yet" |
| **Security floor** | secret-scan · SAST · dep-CVE · PR dependency-review | inline, per PR | gate on _new_ regressions (fast, deterministic) |
| **Security depth** | full/online OSV · Trivy · full semgrep · full-history secrets | scheduled (e.g. weekly) | don't gate — surface as a tracking issue |

**Why this split.** Fast, deterministic, env-independent checks are cheap to run
on every change, so gating them keeps `main` healthy without much friction.
Slower/online/noisier scans — the ones that would make every PR flaky, or that
re-scan _unchanged_ code against a fresher CVE feed — are a poor fit for a
per-PR gate; running them on a schedule and opening a to-do keeps them useful
without holding up unrelated work.

**On "gate on new regressions."** If you do choose to gate a floor check, the
kind approach is to green the repo first (fix real issues + baseline accepted
residue in the tool's own config — `osv-scanner.toml`, the semgrep baseline),
then turn it on. A check that fails on day-one legacy residue trains people to
ignore it.

---

## Recommended defaults + the reasoning

None of these are requirements — they're the defaults we'd reach for, with why.

- **Code quality per language you use** (lint + format, typecheck, tests).
  Rationale: the cheapest, highest-signal feedback; catches most "oops" before
  review. Gating it is usually worth the friction. For Python, the granular
  **language-pack actions** (`actions/python-lint` · `python-typecheck` ·
  `python-test`) run your own uv-pinned tools so CI matches local dev; adopt each
  independently. The default type-checker is **mypy** because it is the safest
  default, not because it is required; override or skip `python-typecheck` if
  you use basedpyright/pyrefly. All three ride on whatever `uv` the runner has —
  `astral-sh/setup-uv` on github-hosted, or a baked one.
- **A security floor** — secret scan (gitleaks), SAST (semgrep), dependency CVEs
  (osv-scanner), PR dependency-review. Rationale: these four catch the common
  supply-chain and secret-leak classes cheaply and deterministically, so they fit
  a per-PR gate. If you only adopt one thing, a secret scan is the highest-value.
- **A scheduled depth sweep** (`security-scan.yml`). Rationale: catches CVEs
  disclosed after your last commit, and heavier scans, without gating PRs.
  Non-blocking by construction — it files an issue.
- **Pin every `uses:` to an exact semver tag** (`@v4.0.0`) — never `@main`, never
  a bare major (`@v1`), never a SHA. Rationale: a workflow runs with a
  write-capable token, so a floating ref is a real supply-chain surface; but a
  SHA over-corrects — it pins without telling you *what changed*, so every bump
  is an unreviewable 40-character diff. An exact version is pinned in practice
  and readable, which is what makes the bump reviewable. harmony-ci publishes a
  release per change for exactly this (see the README's versioning table for what
  a major means here). Whether you use Renovate, Dependabot, or bump by hand is
  your choice.

Skip, reorder, or extend any of this to fit your project.

---

## Getting started — copy, then adapt

The templates are a **cookbook**, not a form to fill in. Grab one and make it
yours:

1. **Pick the template that matches your runner.** Copy
   `templates/ci-github-hosted.yml` to `.github/workflows/ci.yml` — that is the
   one that needs nothing you don't already have. Use `templates/ci-arc.yml`
   instead if you have a self-hosted pool whose image bakes the gate tools.
2. **Set the runner label.** The github-hosted template already says
   `ubuntu-latest` and needs no edit. In `ci-arc.yml`, replace
   `<YOUR-ARC-LABEL>` with your own pool's label.
3. **Turn on the language block(s) you use.** Uncomment the code-quality
   block(s) for your stack (Python / Node / IaC / Docker) and add each to the
   `ci-alls-green` job's `needs:` list. Delete the rest.
4. **(Optional) Add the scheduled sweep.** Copy `templates/security-scan.yml` to
   `.github/workflows/security-scan.yml`; trim the optional jobs (Trivy, full
   semgrep) you don't want.
5. **(Optional) Decide whether to make checks block** — see branch protection
   below. That's a per-project call, not something these templates impose.
6. **(github-hosted only) Choose your SAST approach** — see the semgrep caveat.

Nothing about the templates requires you to keep any particular job. They're a
head start, not a contract.

---

## The adoption playbook — gotchas, every one hit for real

Turning a security floor on for the first time goes wrong in a small number of
predictable ways. These are the ones that cost us a debugging session each;
none of them are obvious from the tools' own docs.

- **gitleaks on an organisation-owned repo needs a licence** — the marketplace
  *action* checks for one and fails without it; the **binary** does not. Either
  set `GITLEAKS_LICENSE` as a repo/org secret (what `ci-github-hosted.yml`
  documents), or run the binary directly (what the baked path does). Personal-
  account repos need neither.
- **`dependency-review` needs the dependency graph, and on a private repo that
  means GHAS.** On a public repo, enable the dependency graph first (it also
  turns on `vulnerability-alerts`) or the action has nothing to compare. On a
  private repo without Advanced Security, drop the job — it cannot work.
- **A baked offline OSV database only covers the ecosystems the image seeded.**
  osv-scanner decides which databases to download from the **lockfiles** it
  scans at bake time, so a bare `package.json` or `Cargo.toml` seeds nothing —
  the ecosystem is silently absent, and `--offline` then hard-errors on a real
  consumer lockfile. Check your image seeds your ecosystem, and keep an online
  osv run in the scheduled sweep as the backstop.
- **A fresh floor on an existing repo surfaces its whole backlog at once.**
  Expect it, and deal with it *before* the gate blocks anyone: one consumer went
  from 34 findings to 0, which included a `starlette` 0.46→1.3 and `fastapi`
  0.115→0.140 major bump. Remediate, or baseline the residue in the tool's own
  config with a tracked issue against it. A gate that is red on day one for
  reasons nobody caused teaches people to ignore gates.
- **`pnpm 11` reads `overrides` from `pnpm-workspace.yaml`, not
  `package.json`.** A transitive-CVE pin placed in the old location is silently
  ignored, and the CVE stays — with a diff that looks like you fixed it.
- **On a strict-branch-protected repo, run `gh pr update-branch` before merge.**
  Otherwise a required check that passed against a stale base blocks the merge
  with an error that does not mention staleness.

---

## Lessons that generalize — a green has to mean something

Each of these started as a single bug in a single consumer. They are written
down here because each one is a *class* of problem: once you know its shape
you find it everywhere.

### A gate states its own coverage

A check that exits 0 has told you nothing until it also says **what it looked
at**. Every action here prints its coverage on every run, pass or fail: commits
scanned, rules loaded, packages found, database age. Each of those lines exists
because the matching silent pass happened for real:

- a depth-1 clone gave gitleaks one commit to scan;
- a gitignored lockfile gave osv-scanner zero packages;
- a registry ruleset gave semgrep zero rules without a token;
- a months-old offline database gave osv-scanner no recent advisories.

All four were green. When you write your own gate, ask what "nothing found"
would look like if the tool had silently scanned nothing, and assert against
that.

### Prove offline claims offline

"Runs without egress" is a property you test with the network off
(`docker run --network none`), not one you assume from the docs. `semgrep
--validate` looked like a local syntax check. In fact it fetched a lint ruleset
from semgrep.dev; with no network it retried for about 100 seconds, then
**passed anyway**. The gate now counts rules from a local SARIF scan instead,
and fails closed if it can't.

### A check about history needs the history

`actions/checkout` defaults to `fetch-depth: 1`. Any check that reasons about
ancestry needs the history it reasons about: a secret scan over a branch, "is
this evidence commit still reachable from main", or "was this merged with a
merge commit". On a shallow clone such a check either errors, or worse, falls
back to something weaker without saying so. Fetch the depth the check needs,
and make the fallback fail in CI instead of quietly degrading.

### Suppress a class, not an instance

False positives are inevitable. How you silence them decides whether the gate
survives. **Precision** narrows what a rule matches and keeps detecting
everything else:

- anchored allowlist regexes;
- `targetRules` scoping;
- path scoping;
- entropy tuning.

**Blindness** switches detection off:

- per-commit fingerprints (`.gitleaksignore`);
- disabling a rule.

A fingerprint also re-fires the moment the same string lands in a new commit,
so the list only grows. In one consumer, converting fingerprints to class
allowlists cut the list from 44 entries to 26. Every entry left is a real
credential awaiting rotation, which is exactly what that list should hold.

gitleaks makes this subtle, so prove each allowlist with a probe that has to
be caught:

- `stopwords` are **substring** tests: a short stopword suppressed a freshly
  generated random key that happened to contain it.
- The combinator key is `condition`, not `matchCondition`.
- Unknown keys are **silently ignored**, so a typo turns AND into OR with no
  error.

Build the probe at runtime, both provider-shaped and generic high-entropy, and
assert gitleaks still finds it. Reading the TOML back proves nothing.

### A workflow that never ran is not passing

Absence of red is not green. Three patterns hid real breakage in one consumer
for months:

- **Dead triggers.** After a `master` → `main` rename, every workflow still
  filtering `push: branches: [master]` stopped firing. Nothing errors; the
  workflow simply never runs. Four workflows sat dead this way, including the
  deploy that would have shipped an image that could not start.
- **Failures nobody sees.** A `workflow_run`-triggered job never appears on a
  PR, so it failed 200 runs out of 200 without anyone noticing.
- **Protection that exists only in comments.** A job naming
  `environment: staging` makes GitHub create that environment on first use,
  **unprotected**. The workflow comment promising "required reviewers" was the
  only place the protection existed.

After a branch rename, or when adopting a repo, list its workflows by last-run
date and conclusion. Treat zero runs, and 100% failure, as findings.

### Keep secrets away from scanners

A security gate runs third-party code over your whole tree, including a
vulnerability database, a ruleset and a scanner binary. It needs `contents:
read` and nothing else. If your self-hosted pool injects credentials (a
secrets-manager token, a deploy key) into every runner pod, give the gates
their own small pool that injects none. Gates are also cheap: measured peaks
are a few hundred MiB, so sizing them like build runners wastes the capacity
the builds are queueing for. If the pool still grants privileged
Docker-in-Docker, the isolation holds only at the pod-spec level. A job that
can start a privileged container can leave it.

### One version, one source

When the same tool appears in two places, they drift, and nothing fails until
the day they disagree. A Playwright test image pinned in a Dockerfile drifted
from the `@playwright/test` version in `package.json`. The suite then hung
until the job timeout, for weeks. The fix is to derive one from the other (the
image tag read from the lockfile), not to bump both more carefully. The same
applies to `packageManager` and the pnpm version in CI, and to a baked scanner
version and the one your scheduled sweep downloads.

---

## Runners — github-hosted is the baseline, self-hosted is an optimization

**Start on `ubuntu-latest`** (`ci-github-hosted.yml`). It sources the floor from
public actions, needs no baked image, no cluster and no tokens beyond the ones
GitHub already gives the job, and it is the configuration anyone can reproduce.
For most projects this is the end of the decision.

A self-hosted pool (`ci-arc.yml`) buys you something real when you have one:
Harmony's `harmony-arc-runner` image bakes the gate tools, the semgrep ruleset
and an offline OSV DB, so the floor makes **no network calls** and needs no
registry login. That is worth having on a blocking gate, where flaky egress is
an outage. It is an optimization on top of the baseline, not a prerequisite for
using this library.

**The trade runs both ways, so know which way yours leans.** Baking buys
determinism and costs freshness — and the two templates do not source their
gates from the same place, which is the bigger difference of the two:

| | github-hosted (`ci-github-hosted.yml`) | baked image (`ci-arc.yml`) |
|---|---|---|
| where the gates come from | public marketplace actions | this library's `actions/*` |
| secret scan | `gitleaks/gitleaks-action` — the same binary, none of the assertions | `actions/gitleaks` — shallow-clone refusal, zero-commit guard, `scope`, coverage summary |
| dependency CVEs | `google/osv-scanner-action` — **online** osv.dev, sees today's advisories; no coverage assertion | `actions/osv-scanner` — **offline** DB, only as fresh as the last image rebuild; coverage and freshness asserted |
| semgrep | needs a token or a vendored ruleset — see below | `actions/semgrep` + the baked tokenless ruleset |
| egress at gate time | required | none |

**The hosted template gives you the same tools, not this library's
assertions.** It sources the floor from public actions, and those actions are
the plain tools: `gitleaks/gitleaks-action` never asks whether the clone is
shallow, never refuses a scan that covered zero commits, has no `scope` input
and prints no coverage line; `google/osv-scanner-action` invoked with
`--recursive ./` passes neither `--all-packages` nor `--no-ignore`, so a repo
that gitignores `uv.lock` gets "No package sources found" and a **green check** —
the silent pass this library exists to stop. The assertions live in `actions/*`,
which run a tool that is already on PATH rather than installing one, so having
them on `ubuntu-latest` means an install step first (see the README's **Runner
needs** column). The template is the quickest floor to stand up, not the
strongest one, and swapping a job for the matching `actions/*` is a two-line
change.

The osv row is the one people get backwards. An offline database cannot see an
advisory published after the image was built, and a scan against it still exits
**0** — so a green there means "no advisories as of whenever that image was
built", which is not the same claim as "no advisories". If you run the baked
path, treat the image's rebuild cadence as part of your CVE coverage, and keep
an online sweep on a schedule (`security-scan.yml`) to close the gap.

`actions/osv-scanner` enforces this rather than leaving it to diligence: it
prints the database's build date on every run and **fails** past `max-db-age`
(30 days by default). If your image's rebuild cadence is slower than that, raise
the threshold or set `allow-stale-db` — deliberately, and in a file someone can
review — rather than letting the gate keep reporting a clean bill of health it
cannot support.

**The semgrep-on-github-hosted caveat.** On ARC, semgrep uses the baked,
tokenless `harmony-baseline.yaml` ruleset. That ruleset is **private** (baked
into the runner image), and Semgrep's registry rulesets (`p/*`, `auto`) are
**login-gated** — tokenless they return zero findings. So on github-hosted,
semgrep needs **either**:

- a `SEMGREP_APP_TOKEN` secret (Semgrep Cloud / registry rules), **or**
- a **vendored ruleset** committed to the repo (e.g. `.semgrep/rules.yml`).

`actions/semgrep` takes the ruleset as its `config:` input for exactly this —
the baked path is only its default. It also **refuses** `auto` and `p/*`
outright rather than scanning with zero rules, because that particular green is
worse than having no SAST gate at all: it looks like coverage.

The floor on github-hosted **without** either is still solid — **gitleaks +
osv-scanner + dependency-review** — so the semgrep job ships **commented** in
`ci-github-hosted.yml` with both options noted. Solid, but sourced from the
public actions: the same three tools, without the coverage assertions, as the
table above sets out. The one place github-hosted is genuinely *ahead* is CVE
freshness, because its osv-scanner queries osv.dev rather than a baked snapshot.

---

## Branch protection — optional, your call

The templates don't enforce anything by themselves — a workflow only blocks a
merge if _you_ mark its check as required. That's a deliberate per-project
decision, not something harmony-ci prescribes.

**If** you want these checks to block merges, the convenient way is to require
just one check:

- **`CI all green`** — the `ci-alls-green` aggregator job. It's red unless every
  floor + code-quality job it `needs` succeeded, so requiring this single job
  means adding a new language toggle later doesn't mean editing branch protection
  again.

The rest — require-a-PR, require-review, dismiss-stale-approvals, no-force-push,
linear-history — are all worth considering, but they're each your choice.

If you do wire up scheduling, note that `security-scan.yml` is **not** a good
required check — it's the non-blocking depth tier and never runs on a PR.

> Aside — why the aggregator runs on `ubuntu-latest`: `re-actors/alls-green`
> exit-127s on the arc runner image (it needs no baked tooling), so the templates
> keep that one job on GitHub-hosted even in the arc template. This mirrors how
> Harmony and Lattice already wire it — a convenience worth copying.

---

## prek coexistence

If you use **prek** (or any pre-commit framework), a nice split is: prek as a
**local developer-ergonomics hook** for fast feedback before you push
(format-on-commit, quick lint), and CI as the backstop that actually runs on
infrastructure.

Worth keeping in mind: prek runs on the developer's machine and can be skipped
(`--no-verify`), so if you care about a check being reliably run, it's better to
have CI run it too rather than lean on prek alone. Treat prek as a convenience
that cuts CI round-trips, not as your only line for secrets/SAST/CVEs.

---

## See also

- [`README.md`](README.md) — the composite-action library and its security
  model.
- [`templates/`](templates/) — the copy-and-adapt workflows this guidance walks
  through.
- The composite actions are always available for **bespoke pipelines** that don't
  fit the templates — build whatever CI suits your project; these are here to
  make the common cases easy.
