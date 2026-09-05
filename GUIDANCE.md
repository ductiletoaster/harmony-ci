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
  independently. The default type-checker is **mypy** (the fleet standard —
  lattice + fire-risk-core); override or skip `python-typecheck` if you use
  basedpyright/pyrefly. This rides on the baked uv in the arc runner — the runner
  is the tooling; the actions are the convenience.
- **A security floor** — secret scan (gitleaks), SAST (semgrep), dependency CVEs
  (osv-scanner), PR dependency-review. Rationale: these four catch the common
  supply-chain and secret-leak classes cheaply and deterministically, so they fit
  a per-PR gate. If you only adopt one thing, a secret scan is the highest-value.
- **A scheduled depth sweep** (`security-scan.yml`). Rationale: catches CVEs
  disclosed after your last commit, and heavier scans, without gating PRs.
  Non-blocking by construction — it files an issue.
- **Pin every `uses:` to an exact semver tag** (`@v1.0.0`) — never `@main`, never
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

1. **Pick the template that matches your runner.** Copy `templates/ci-arc.yml`
   (if you have ARC access) or `templates/ci-github-hosted.yml` (if you don't) to
   `.github/workflows/ci.yml`.
2. **Set the runner label.** In `ci-arc.yml`, replace `<YOUR-ARC-LABEL>` with
   your ARC pool label (`harmony-cluster`, `fire-risk-ci`, `lattice`, …). The
   github-hosted template already uses `ubuntu-latest`.
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

## Runners — arc-first, github-hosted works great too

We reach for a self-hosted ARC pool built from the private `harmony-arc-runner`
image first, because it bakes the gate tools, the semgrep ruleset, and an offline
OSV DB — so the floor is egress-free and tokenless (`ci-arc.yml`). But
**github-hosted is fully supported** (`ci-github-hosted.yml`) and is often the
easiest on-ramp: it sources the same floor from public actions on
`ubuntu-latest`, no baked image needed. Use whichever you have.

**The semgrep-on-github-hosted caveat.** On ARC, semgrep uses the baked,
tokenless `harmony-baseline.yaml` ruleset. That ruleset is **private** (baked
into the runner image), and Semgrep's registry rulesets (`p/*`, `auto`) are
**login-gated** — tokenless they return zero findings. So on github-hosted,
semgrep needs **either**:

- a `SEMGREP_APP_TOKEN` secret (Semgrep Cloud / registry rules), **or**
- a **vendored ruleset** committed to the repo (e.g. `.semgrep/rules.yml`).

The floor on github-hosted **without** either is still solid — **gitleaks +
osv-scanner + dependency-review** — so the semgrep job ships **commented** in
`ci-github-hosted.yml` with both options noted. gitleaks and osv-scanner have
full parity on github-hosted (osv uses the online osv.dev DB instead of the baked
offline one).

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
