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
- **Pin every `uses:` to an exact semver tag** (`@v2.1.0`) — never `@main`, never
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

**The semgrep-on-github-hosted caveat.** On ARC, semgrep uses the baked,
tokenless `harmony-baseline.yaml` ruleset. That ruleset is **private** (baked
into the runner image), and Semgrep's registry rulesets (`p/*`, `auto`) are
**login-gated** — tokenless they return zero findings. So on github-hosted,
semgrep needs **either**:

- a `SEMGREP_APP_TOKEN` secret (Semgrep Cloud / registry rules), **or**
- a **vendored ruleset** committed to the repo (e.g. `.semgrep/rules.yml`).

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
