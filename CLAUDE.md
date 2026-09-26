# Working on harmony-ci

Notes for agents and humans changing this repo. `README.md` covers what the
library is and `GUIDANCE.md` covers how to use it; this file covers how to
change it without breaking the repos that consume it.

## This repo is public

Consumers include private repositories. Never put a private repo's name, issue
or PR number, hostname or internal detail into anything published here:
commits, PR titles and bodies, issues, docs or examples. Say "one consumer"
instead. Check the commit message before pushing, not after: a commit message
is the hardest place to scrub.

## Releases

- `VERSION` is the release. Bumping it on `main` cuts the tag and GitHub
  release. `release.yml` refuses a non-monotonic version, and the tag ruleset
  makes tags immutable, so a bad release can only be fixed forward.
- The README's semver table is binding. A change is **major** if a gate can now
  fail a build that used to pass, including by widening what it detects or by
  failing closed where it used to fail open.
- Every `@vX.Y.Z` in `README.md`, `GUIDANCE.md` and `templates/` must equal
  `VERSION`. CI enforces this ("Pinned versions match VERSION"). Update the
  examples in the same PR as the bump. Historical mentions without an `@` are
  fine.
- Selftests run here, not only on consumers. If you change `osv_coverage.py` or
  the semgrep rule count, extend its selftest in the same PR.

## Pull requests

- **No stacked PRs.** Squash-merge plus branch auto-delete closes the PR above
  a merged base and strands its commits; a whole release has been lost this
  way. Open each PR against `main`, and land one before starting the next that
  depends on it.
- Pass PR, issue and comment bodies with `--body-file`. Backticks inside a
  double-quoted `--body` are shell command substitution: one real comment ended
  up with `gh --help` output spliced into it.
- Agent commits are unsigned by design (`git -c commit.gpgsign=false`), with a
  `Co-Authored-By` trailer. Don't change git config to get around signing.
  Unsigned plus the trailer is the provenance signal.
- The operator merges. Get the PR green and say it's ready; don't merge on
  their behalf, and don't post approvals in their name.

## Rolling a release out to consumers

A release only helps once consumers pin it. Roll out deliberately:

1. Confirm the tag and GitHub release exist before touching any consumer.
2. Open one PR per consumer, against its `main`, from an isolated worktree.
   Never touch the operator's own checkout. Guard every directory change,
   because a failed `cd` under `set -e` does not stop the next `git` command:
   `cd "$W" && [ "$(pwd)" = "$W" ] && git ...`
3. Count the pins before and after the rewrite (`git grep -c`), and assert that
   no old pins remain. Leave historical records alone: an ADR that says "we
   pinned v2.1.0" is true.
4. Verify on the consumer's own CI that the changed behaviour actually happened,
   by looking at the log line, not just the check colour. For example, the
   semgrep rule count printed with no network fetch, or the osv database age
   printed on a passing run.
5. Remove worktrees with `git worktree remove`, never `rm -rf`, or git keeps
   orphaned registrations.

## Before you recommend something, check it

Most of the rework in this repo's history came from a confident premise that
was never checked:

- a rule assumed to see through subclasses;
- a check assumed wired that wasn't;
- "main is red" when it wasn't;
- a capacity sample that predated the change it was supposed to measure.

Run the command, read the log, build the image. When the claim is about the
network, test it with the network off.
