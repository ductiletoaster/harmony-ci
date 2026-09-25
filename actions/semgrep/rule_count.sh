#!/usr/bin/env bash
# How many rules does semgrep load from a ruleset? Asked OFFLINE.
#
#   rule_count.sh CONFIG       fail unless CONFIG loads >= 1 rule; print the count
#   rule_count.sh --selftest   prove that against THIS semgrep binary
#
# WHY THIS EXISTS. A ruleset semgrep loads ZERO rules from (`rules: []`, for
# one) scans nothing, finds nothing and exits 0 — a green check standing in for
# a scan that never happened. `-r CONFIG` proves the path is readable, not that
# it is populated, so the count has to come from somewhere.
#
# WHY NOT `semgrep --validate`. That is what 3.0.0 used, and it is NOT offline:
# --validate fetches the `p/semgrep-rule-lints` metacheck ruleset from
# semgrep.dev. Measured in harmony-arc-runner v0.3.8 under `docker run --network
# none`: it retried for 98 s, died on "Failed to resolve 'semgrep.dev'", printed
# no count, and the old probe then failed OPEN. On exactly the egress-free runner
# this gate is built for, the check skipped itself, slowly, and said so only in
# a warning. The question here is "does this ruleset load any rules", which
# needs no metacheck.
#
# THE MECHANISM: semgrep's own loader, over an EMPTY target, reporting in SARIF.
#   semgrep scan --config CONFIG --metrics=off --sarif <empty dir>
# runs the same config resolution the real scan does — same --config value,
# same file/directory walk, same YAML and schema validation, same rule-pattern
# parse — and lists every loaded rule in SARIF's `runs[0].tool.driver.rules`
# whether or not anything matched. Measured against semgrep 1.171.0 with
# `--network none`, ~1.5 s per call, and in every case the probe's exit code
# equalled the real scan's:
#
#   config                                   probe    rules   real scan
#   baked harmony-baseline.yaml              exit 0   8       runs 8 rules
#   directory, 3 rules across 2 files        exit 0   3       runs 3 rules
#   directory whose rules are in .hidden     exit 0   3       runs 3 rules
#   `rules: []`                              exit 0   0       exit 0  <- the silent pass
#   empty directory                          exit 7   -       exit 7
#   malformed YAML / missing `message:`      exit 7   -       exit 7
#   directory with ONE bad file among good   exit 7   -       exit 7
#   unparseable pattern                      exit 2   -       exit 2
#
# Counting top-level `rules:` entries in the YAML ourselves was the rejected
# alternative: it would have to re-implement which files in a directory semgrep
# reads (it reads hidden ones; it ignores non-YAML), that one bad file sinks the
# whole directory, that a rule with a broken pattern does not load, and JSON
# configs — and it would drift from semgrep the first time either changed. It
# would also add a PyYAML dependency on an image-provided python3
# (harmony-ci#23). This asks the binary that will do the scan.
#
# FAILS CLOSED, on everything. The old probe failed open because it could not
# run without the network, and failing a gate over the probe's own missing
# egress would have been a red build the caller could not act on. Nothing here
# touches the network, so that reason is gone, and each remaining way to get no
# count is one the caller CAN act on:
#   - semgrep exits non-zero: it could not load the config. The real scan runs
#     the same loader and fails the same way (table above), so failing here
#     changes no verdict — it only fails earlier, with the loader's own reason.
#   - semgrep exits 0 but the SARIF has no rules array: the output shape moved
#     under a semgrep this was not verified against. Passing would be the exact
#     "reports success while covering less than it claims" this library exists
#     to prevent; failing names the semgrep version to pin or report.
#
# NOT a coverage claim: a ruleset whose `languages:` never match this repo still
# counts as N rules and still finds nothing. N >= 1 is the strongest claim
# available without scanning; it is not a claim that anything applies.
#
# Needs semgrep and jq on PATH. jq rather than python3 on purpose: a stock
# actions/runner image and ubuntu-latest both ship jq, while python3 on the
# runner image is an accident of an unrelated install (harmony-ci#23). Asserted
# below with a named fix rather than left to surface as "command not found".

# No -e: semgrep's exit status is DATA here (it says whether the loader
# succeeded), and under -e the script would die before reading it.
set -uo pipefail

# The same variable the real scan sets: without it semgrep asks semgrep.dev
# whether it is current, which on an egress-free runner is a wait for DNS.
export SEMGREP_ENABLE_VERSION_CHECK=0

SELF="${BASH_SOURCE[0]}"
WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT

require() {
  local ok=0
  if ! command -v semgrep >/dev/null 2>&1; then
    echo "::error::semgrep is not on PATH, so the ruleset's rules cannot be" \
         "counted. Put it on PATH first ('uv tool install semgrep')."
    ok=1
  fi
  if ! command -v jq >/dev/null 2>&1; then
    echo "::error::jq is not on PATH, and the rule count is read out of" \
         "semgrep's SARIF with it. ubuntu-latest and the stock actions/runner" \
         "image ship jq; a custom image must install it (e.g. 'apt-get install" \
         "-y jq')."
    ok=1
  fi
  return "$ok"
}

assert_config() {
  local config="$1" target sarif err rc count
  target="$(mktemp -d "$WORK/target.XXXXXX")" # empty: load the rules, scan nothing
  sarif="$WORK/probe.sarif"
  err="$WORK/probe.err"

  semgrep scan --config "$config" --metrics=off --sarif "$target" \
    >"$sarif" 2>"$err"
  rc=$?

  if [ "$rc" -ne 0 ]; then
    # The loader's own reasons ride in the SARIF as tool notifications; stderr
    # carries the rest. Print both — this is the text that says what to fix.
    jq -r '.runs[]?.invocations[]?.toolExecutionNotifications[]?
             | select(.level == "error") | .message.text' "$sarif" 2>/dev/null
    cat "$err"
    echo "::error::semgrep could not load the ruleset '$config' (exit $rc;" \
         "its reasons are above). The real scan runs the same loader and would" \
         "fail the same way, so this gate stops here rather than reporting a" \
         "scan it cannot run. Fix the ruleset: an empty directory, invalid YAML," \
         "a rule missing a required key, or one bad file in a directory of good" \
         "ones all look like this."
    return 1
  fi

  # `length` of a missing key is 0 in jq, which would report a changed SARIF
  # shape as "ZERO rules" — a true-looking diagnosis of the wrong problem. So
  # anything but an array is an error, not a zero.
  count="$(jq -er '.runs[0].tool.driver.rules
                     | if type == "array" then length
                       else error("no rules array") end' "$sarif" 2>/dev/null)" \
    || count=""
  case "$count" in
    '' | *[!0-9]*)
      echo "::error::could not read a rule count from semgrep" \
           "$(semgrep --version 2>/dev/null)'s SARIF output for '$config'" \
           "(expected an array at .runs[0].tool.driver.rules). This check fails" \
           "CLOSED: passing without a count is the silent pass it exists to" \
           "stop. Pin semgrep to a version this was verified against (1.171.0)" \
           "or report the new output shape against harmony-ci."
      return 1
      ;;
  esac

  if [ "$count" -lt 1 ]; then
    echo "::error::the semgrep ruleset '$config' loads ZERO rules. This gate" \
         "would scan the repo against nothing, report no findings and exit 0 —" \
         "a green check standing in for a scan that never happened, which is" \
         "the one thing this action exists to refuse. Readable is not the same" \
         "as populated: an empty 'rules: []' looks like this. Point config: at" \
         "a ruleset that has rules in it:"
    echo "::error::    - uses: ductiletoaster/harmony-ci/actions/semgrep@<tag>"
    echo "::error::        with: { config: .semgrep/rules.yml }"
    return 1
  fi

  echo "ruleset '$config' loads $count rule(s)."
}

# Every case runs this script as a SUBPROCESS on a fixture built here, so what
# is asserted is the exit status and the message a caller would get — the
# whole path, not a helper. Fixtures are never committed.
selftest() {
  local fx="$WORK/fx" failures=0
  mkdir -p "$fx/dir/nested" "$fx/emptydir" "$fx/shim"

  rule() { # id pattern
    printf '  - id: %s\n    pattern: %s\n    message: selftest\n' "$1" "$2"
    printf '    languages: [python]\n    severity: ERROR\n'
  }
  { echo "rules:"; rule st-eval 'eval(...)'; rule st-exec 'exec(...)'; } \
    >"$fx/two.yaml"
  cp "$fx/two.yaml" "$fx/dir/a.yaml"
  { echo "rules:"; rule st-system 'os.system(...)'; } >"$fx/dir/nested/b.yml"
  echo "not a ruleset" >"$fx/dir/README.txt"
  echo "rules: []" >"$fx/norules.yaml"
  printf 'rules:\n  - id: x\n    pattern: [unclosed\n  foo: : :\n' \
    >"$fx/malformed.yaml"

  # A semgrep that exits 0 but whose SARIF carries no rules array: stands in
  # for an output-shape change in a future release. It must FAIL — the old
  # probe's warn-and-continue on "no count" is the regression this pins.
  cat >"$fx/shim/semgrep" <<'SHIM'
#!/usr/bin/env bash
if [ "${1:-}" = --version ]; then echo "0.0.0-selftest-shim"; exit 0; fi
echo '{"runs":[{"tool":{"driver":{"name":"semgrep"}}}]}'
SHIM
  chmod +x "$fx/shim/semgrep"

  check() { # name want-status want-text [PATH-prefix] config
    local name="$1" want="$2" text="$3" prefix="$4" config="$5" out got
    out="$(PATH="${prefix:+$prefix:}$PATH" bash "$SELF" "$config" 2>&1)"
    got=$?
    if [ "$got" -eq "$want" ] && printf '%s' "$out" | grep -qF -- "$text"; then
      echo "selftest ok: $name -> exit $got, '$text'"
    else
      echo "::error::selftest: $name: want exit $want and '$text'," \
           "got exit $got. Output was:"
      printf '%s\n' "$out"
      failures=$((failures + 1))
    fi
  }

  check "file with 2 rules" 0 "loads 2 rule(s)" "" "$fx/two.yaml"
  check "directory, nested, non-YAML ignored" 0 "loads 3 rule(s)" "" "$fx/dir"
  check "rules: [] (exits 0 in semgrep)" 1 "loads ZERO rules" "" "$fx/norules.yaml"
  check "empty directory" 1 "could not load" "" "$fx/emptydir"
  check "malformed YAML" 1 "could not load" "" "$fx/malformed.yaml"
  check "SARIF without a rules array" 1 "could not read a rule count" \
    "$fx/shim" "$fx/two.yaml"

  if [ "$failures" -ne 0 ]; then
    echo "::error::rule_count selftest: $failures case(s) failed against" \
         "semgrep $(semgrep --version 2>/dev/null)."
    return 1
  fi
  echo "rule_count selftest: all cases passed against semgrep $(semgrep --version)."
}

case "${1:-}" in
  --selftest) require && selftest ;;
  '' | -*)
    echo "usage: rule_count.sh CONFIG | --selftest" >&2
    exit 2
    ;;
  *) require && assert_config "$1" ;;
esac
