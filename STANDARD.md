# The Harmony CI Standard

The opinionated baseline every Harmony-platform consumer should adopt. The
composite actions in [`actions/`](actions/) are the mechanism; this document is
the **policy** — what to run, where, and what blocks a merge. The
[`templates/`](templates/) are copy-and-tune starting points that encode it.

Scope of the opinion is **code quality + security only**. Dependency-automation
(Renovate / Dependabot / none) is explicitly **each repo's own choice** and is
_not_ prescribed here.

---

## The taxonomy — three tiers

| Tier | What | When | Blocks? | Where it lives |
|------|------|------|---------|----------------|
| **Code quality** | lint + format → typecheck → tests, per detected language | Inline, every PR + push to main | **Yes** | `ci-<arc\|github-hosted>.yml` (uncomment your stack) |
| **Security FLOOR** | secret-scan · SAST · dep-CVE · PR dependency-review | Inline, every PR + push to main | **Yes — on new regressions** | `ci-<arc\|github-hosted>.yml` (security jobs) |
| **Security DEPTH** | full/online OSV · Trivy · full semgrep · full-history secrets | Scheduled (weekly cron) | **No — files a tracking issue** | `security-scan.yml` |

**Why this split.** Fast, deterministic, env-independent checks gate every
change (floor). Slow/online/noisy scans — the ones that would make every PR
flaky or that re-scan _unchanged_ code against a fresher CVE feed — run on a
schedule and open a to-do instead of blocking (depth). Code quality is always
inline because a broken build or failing test should never merge.

Each floor gate is **blocking on new regressions**, not on pre-existing residue:
you green the repo first (fix real issues + baseline accepted residue in the
tool's own config — `osv-scanner.toml`, the semgrep baseline), then enforce. A
gate that's "warn-only forever" is not a gate.

---

## Mandatory vs. optional

**Mandatory (every consumer repo):**

- **Code quality** for each language present — lint + format, typecheck, tests.
- **Security floor** — secret scan (gitleaks), SAST (semgrep), dependency CVEs
  (osv-scanner), and PR dependency-review.

**Recommended (every repo, but non-blocking):**

- **Security depth** — the scheduled `security-scan.yml` sweep.

**Each repo's own choice (NOT prescribed):**

- **Dependency automation** — Renovate _or_ Dependabot _or_ neither. Pick one to
  keep the SHA-pinned `uses:` in your CI fresh through reviewed PRs. The standard
  requires SHA-pinning; it does not require a particular bumping bot.

---

## Adoption checklist

1. **Pick a template.** Copy `templates/ci-arc.yml` (if you have ARC access) or
   `templates/ci-github-hosted.yml` (if you don't) to your repo as
   `.github/workflows/ci.yml`.
2. **Set the runner label.** In `ci-arc.yml`, replace every `<YOUR-ARC-LABEL>`
   with your ARC pool label (`harmony-cluster`, `fire-risk-ci`, `lattice`, …).
   The github-hosted template is already on `ubuntu-latest`.
3. **Enable your language toggles.** Uncomment the code-quality block(s) for your
   stack (Python / Node / IaC / Docker) and add each to the `ci-alls-green`
   job's `needs:` list.
4. **Add the scheduled sweep.** Copy `templates/security-scan.yml` to
   `.github/workflows/security-scan.yml`; trim the optional jobs (Trivy, full
   semgrep) you don't want.
5. **Set branch protection.** Mark the required checks below so the template
   actually _enforces_.
6. **(github-hosted only) Decide on SAST.** See the semgrep caveat — the floor
   works without it, but wire a token or a vendored ruleset to get SAST parity.

---

## Runner guidance

**arc-first, github-hosted first-class.** Prefer a self-hosted ARC pool built
from the private `harmony-arc-runner` image — it bakes the gate tools, the
semgrep ruleset, and an offline OSV DB, so the floor is egress-free and tokenless
(`ci-arc.yml`). But **github-hosted is fully supported** (`ci-github-hosted.yml`)
and is the on-ramp for the consumer repos that have no ARC access and zero
security today: it sources the same floor from public actions on `ubuntu-latest`.

**The semgrep-on-github-hosted caveat.** On ARC, semgrep uses the baked,
tokenless `harmony-baseline.yaml` ruleset. That ruleset is **private** (baked
into the runner image), and Semgrep's registry rulesets (`p/*`, `auto`) are
**login-gated** — tokenless they return zero findings. So on github-hosted,
semgrep needs **either**:

- a `SEMGREP_APP_TOKEN` secret (Semgrep Cloud / registry rules), **or**
- a **vendored ruleset** committed to the repo (e.g. `.semgrep/rules.yml`).

The working floor on github-hosted **without** either is **gitleaks +
osv-scanner + dependency-review** — the semgrep job ships **commented** in
`ci-github-hosted.yml` with both options noted. gitleaks and osv-scanner have
full parity on github-hosted (osv uses the online osv.dev DB instead of the baked
offline one).

---

## Branch protection — the required checks

For the template to _enforce_, mark these as required status checks on `main`
(GitHub → Settings → Branches → branch protection rule):

- **`CI all green`** — the `ci-alls-green` aggregator job. This is the single
  stable check to require; it is red unless every floor + code-quality job it
  `needs` succeeded. Requiring just this one job means adding a new language
  toggle doesn't require editing branch protection.

Also enable, consistent with harmony-ci's own policy: **require a PR before
merge**, **require review** (CODEOWNERS where applicable), **dismiss stale
approvals**, **no force-push**, **linear history**.

Do **not** mark `security-scan.yml` as a required check — it's the non-blocking
depth tier and never runs on a PR.

> Why aggregate on `ubuntu-latest`: `re-actors/alls-green` exit-127s on the arc
> runner image (it needs no baked tooling), so the aggregator job stays on
> GitHub-hosted even in the arc template. This mirrors how Harmony and Lattice
> already wire it.

---

## prek coexistence

Keep **prek** (or any pre-commit framework) as a **local developer-ergonomics
hook** — fast feedback before you push (format-on-commit, quick lint). It is
**not** the CI security gate:

- prek runs on the developer's machine and can be skipped (`--no-verify`); CI
  runs on infrastructure that holds write-capable tokens and cannot be skipped.
- CI still runs the full floor regardless of what prek did locally. Never rely on
  prek as the enforcement boundary for secrets/SAST/CVEs.

Treat prek as a convenience that reduces CI round-trips, and the CI floor as the
authority.

---

## See also

- [`README.md`](README.md) — the composite-action library and its security
  model.
- [`templates/`](templates/) — the copy-and-tune workflows this standard
  encodes.
- The composite actions remain available for **bespoke pipelines** that don't fit
  the templates; the standard is the recommended baseline, not a straitjacket.
