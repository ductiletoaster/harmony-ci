#!/usr/bin/env bash
# Does this runner's hardening actually hold? Asked FROM the runner.
#
#   runner_probe.sh run          probe this runner; exit 1 if any check FAILs
#   runner_probe.sh --selftest   prove every check's parser on fixtures
#
# WHY THIS EXISTS. A runner pool's hardening is usually stated in YAML: no
# service-account token, no secret env, nothing privileged except the Docker
# sidecar, no host namespaces. The YAML is a claim about the pod. This probe
# checks what a job running in the pod can actually see and reach, so the
# claim is tested where it matters. Run it after every change to the pool, and
# read the summary table rather than the check colour.
#
# Each check prints one of three verdicts and a one-line reason:
#   PASS    the forbidden thing was attempted and refused, or is absent.
#   FAIL    it worked. The job fails, and the reason names the fix.
#   REPORT  recorded, not enforced. Either a reachability finding while
#           network isolation is not expected yet, or a check that could not
#           be tested here (a name that does not resolve, a path that does not
#           exist). A REPORT is never a pass in disguise: it says which.
#
# THE CHECKS
#   sa-token          no Kubernetes service-account token in the pod.
#   kube-api          the Kubernetes API, by $KUBERNETES_SERVICE_HOST and by
#                     kubernetes.default.svc, gives no authorized response
#                     without a token. An AUTHORIZED anonymous answer always
#                     fails; a reachable-but-refused API is a network finding.
#   credential-env    no env var whose NAME looks like a credential. Names only:
#                     a value is never printed, logged or written anywhere.
#   privileged        the job's capability sets are not the full set, and do
#                     not include CAP_SYS_ADMIN.
#   host-pid          not in the host's PID namespace (kernel threads visible,
#                     or PID 1 is a host init).
#   host-network      no host-side interfaces in /sys/class/net. A HEURISTIC on
#                     interface names, and the reason says so.
#   cloud-metadata    169.254.169.254:80 is unreachable. Network finding.
#   unreachable       each caller-supplied host:port is unreachable. Network
#                     finding.
#   not-writable      each caller-supplied path is not writable.
#
# Network findings FAIL only with PROBE_EXPECT_NETWORK_ISOLATION=true. Until a
# pool has egress policy, a reachable target is the expected state, and failing
# on it would make the probe permanently red and therefore unread.
#
# INPUTS (environment; action.yml maps its inputs onto these):
#   PROBE_EXPECT_NETWORK_ISOLATION  true|false (default false)
#   PROBE_UNREACHABLE_TARGETS       host:port list; [v6]:port for IPv6
#   PROBE_NOT_WRITABLE_PATHS        path list
#   PROBE_ALLOWED_ENV_NAMES         exact env names credential-env should skip
#   PROBE_CONNECT_TIMEOUT           seconds per connection attempt (default 3)
# Lists are whitespace- or newline-separated, and `#` starts a comment that
# runs to the end of the line, so a YAML block can annotate each entry.
#
# Fixture knobs, used by the selftest and not meant for callers:
#   PROBE_ROOT              prefix for every /proc, /sys and /var/run path read
#   PROBE_KUBE_NAME         the API's DNS name (default kubernetes.default.svc;
#                           empty skips it)
#   PROBE_METADATA_TARGET   default 169.254.169.254:80
#
# NOT COVERED, deliberately: what a container started through a Docker daemon
# the job can reach would see. A privileged sidecar is a separate boundary from
# the job's own container, and testing it means starting containers. This probe
# is about the job.
#
# Needs bash (with /dev/tcp, which the selftest proves), coreutils `timeout`,
# and curl for the Kubernetes API's HTTP answer. Without curl, kube-api falls
# back to a TCP connect and says so. No python3: it is not guaranteed on a
# runner image, and this has to run on any pool.

# No -e: a refused connection or a failed write is DATA here, and under -e the
# script would die before recording it.
set -uo pipefail

SELF="${BASH_SOURCE[0]}"

# --- results ----------------------------------------------------------------

R_CHECK=()
R_RESULT=()
R_REASON=()
R_FIX=()

record() { # check result reason [fix]
  R_CHECK+=("$1")
  R_RESULT+=("$2")
  R_REASON+=("$3")
  R_FIX+=("${4:-}")
}

# Classifiers set these three rather than echoing, so a verdict never needs a
# subshell and the selftest can call the same functions the probe does.
V_RESULT=""
V_REASON=""
V_FIX=""

verdict() { # result reason [fix]
  V_RESULT="$1"
  V_REASON="$2"
  V_FIX="${3:-}"
}

# --- input parsing ----------------------------------------------------------

# Split a list input into LIST_ITEMS. Whitespace- or newline-separated, `#`
# comments to end of line, blank lines ignored.
LIST_ITEMS=()
parse_list() {
  LIST_ITEMS=()
  local line word
  while IFS= read -r line || [ -n "$line" ]; do
    line="${line%%#*}"
    for word in $line; do
      LIST_ITEMS+=("$word")
    done
  done <<<"$1"
}

# host:port, or [v6]:port. Sets T_HOST and T_PORT; returns 1 on anything else.
# An IPv6 literal must be bracketed: fd00::1:443 is ambiguous, and guessing
# which colon is the port would test the wrong target and report it as safe.
T_HOST=""
T_PORT=""
parse_target() {
  local entry="$1" host port
  T_HOST=""
  T_PORT=""
  if [[ "$entry" =~ ^\[([0-9A-Fa-f:.]+)\]:([0-9]+)$ ]]; then
    host="${BASH_REMATCH[1]}"
    port="${BASH_REMATCH[2]}"
  elif [[ "$entry" =~ ^([A-Za-z0-9._-]+):([0-9]+)$ ]]; then
    host="${BASH_REMATCH[1]}"
    port="${BASH_REMATCH[2]}"
  else
    return 1
  fi
  # 10# so a leading zero is not read as octal.
  if [ "${#port}" -gt 5 ] || [ $((10#$port)) -lt 1 ] || [ $((10#$port)) -gt 65535 ]; then
    return 1
  fi
  T_HOST="$host"
  T_PORT="$((10#$port))"
}

# --- network primitives -----------------------------------------------------

# One TCP connect attempt. Sets C_STATE to one of:
#   open        the connection was accepted
#   refused     nothing accepted on that port (closed, or a REJECT rule)
#   timeout     no answer within the timeout (dropped, which is what egress
#               policy usually does)
#   unreachable no route
#   unresolved  the name did not resolve, so nothing was tested
#   error       something else; C_DETAIL has the message
C_STATE=""
C_DETAIL=""
classify_connect() { # rc stderr
  local rc="$1" err="$2"
  C_DETAIL=""
  if [ "$rc" -eq 0 ]; then
    C_STATE=open
    return
  fi
  # timeout(1) exits 124 when it had to kill the attempt.
  if [ "$rc" -eq 124 ]; then
    C_STATE=timeout
    return
  fi
  case "$err" in
    *"Connection refused"*) C_STATE=refused ;;
    *"timed out"*) C_STATE=timeout ;;
    *"No route to host"* | *"Network is unreachable"* | *"Host is unreachable"*) C_STATE=unreachable ;;
    # glibc, musl and macOS each word a failed lookup differently.
    *"not known"* | *"resolution"* | *"resolve"* | *"No address associated"* | *"nodename nor servname"*)
      C_STATE=unresolved ;;
    *)
      C_STATE=error
      C_DETAIL="$(printf '%s' "$err" | head -n 1)"
      ;;
  esac
}

probe_connect() { # host port timeout
  local err rc
  # $0 and $1 inside the -c script are the host and port: passed as arguments
  # rather than interpolated, so a target string is never parsed as code.
  # shellcheck disable=SC2016
  err="$(timeout "$3" bash -c 'exec 3<>"/dev/tcp/$0/$1"' "$1" "$2" 2>&1 >/dev/null)"
  rc=$?
  classify_connect "$rc" "$err"
}

# A connect state, plus whether isolation is expected, to a verdict.
net_verdict() { # state expect_isolation what fix
  local state="$1" iso="$2" what="$3" fix="$4"
  case "$state" in
    open)
      if [ "$iso" = "true" ]; then
        verdict FAIL "$what is reachable (TCP connect accepted)" "$fix"
      else
        verdict REPORT "$what is reachable (TCP connect accepted); not failed because network isolation is not expected"
      fi
      ;;
    refused) verdict PASS "connection refused: nothing accepted on that port (closed, or rejected by policy)" ;;
    timeout) verdict PASS "no answer within the timeout (dropped)" ;;
    unreachable) verdict PASS "no route to it" ;;
    unresolved) verdict REPORT "the name did not resolve here, so nothing was tested" ;;
    *) verdict REPORT "could not test: ${C_DETAIL:-unknown connect error}" ;;
  esac
}

# What the Kubernetes API answered an anonymous request with.
kube_verdict() { # curl_rc http_code expect_isolation
  local rc="$1" code="$2" iso="$3"
  local fix_net="deny egress from this namespace to the API server's ClusterIP and its endpoints"
  case "$rc" in
    6)
      verdict REPORT "the name did not resolve here, so nothing was tested"
      return
      ;;
    7)
      verdict PASS "unreachable: the connection failed"
      return
      ;;
    28)
      verdict PASS "unreachable: no answer within the timeout"
      return
      ;;
  esac
  case "$code" in
    2??)
      # Always a failure, isolation or not: the API handed an unauthenticated
      # caller real data.
      verdict FAIL "an anonymous request to /api/v1/namespaces was AUTHORIZED (HTTP $code)" \
        "disable anonymous auth on the API server, or remove the RBAC bindings that grant system:anonymous or system:unauthenticated anything"
      ;;
    401 | 403)
      if [ "$iso" = "true" ]; then
        verdict FAIL "reachable; refused without a token (HTTP $code)" "$fix_net"
      else
        verdict REPORT "reachable; refused without a token (HTTP $code). Not failed because network isolation is not expected"
      fi
      ;;
    *)
      if [ "$iso" = "true" ]; then
        verdict FAIL "reachable, but gave no Kubernetes answer (curl exit $rc, HTTP $code)" "$fix_net"
      else
        verdict REPORT "reachable, but gave no Kubernetes answer (curl exit $rc, HTTP $code)"
      fi
      ;;
  esac
}

# --- host-side classifiers --------------------------------------------------

satoken_verdict() { # root
  local token="$1/var/run/secrets/kubernetes.io/serviceaccount/token"
  if [ -e "$token" ]; then
    verdict FAIL "a service-account token is mounted at /var/run/secrets/kubernetes.io/serviceaccount/token" \
      "set automountServiceAccountToken: false on the runner pod template"
  else
    verdict PASS "no token at /var/run/secrets/kubernetes.io/serviceaccount/token"
  fi
}

# Is this NAME credential-shaped? Returns 0 if so. Matches whole `_`-separated
# segments (with `-` and `.` treated as `_`), because substrings are useless
# here: PAT is inside PATH, KEY inside MONKEY, TOKEN inside
# TOKENIZERS_PARALLELISM. Short words must BE the segment; long words may END
# one, so GHTOKEN and OPENAI_APIKEY still match.
cred_name() { # name
  local up seg segs
  up="${1^^}"
  case "$up" in
    # GitHub's own: the runner's ACTIONS_* plumbing, and the job token, whose
    # scope the workflow's `permissions:` block already states.
    ACTIONS_* | GITHUB_TOKEN) return 1 ;;
  esac
  up="${up//[-.]/_}"
  IFS=_ read -ra segs <<<"$up"
  for seg in "${segs[@]}"; do
    case "$seg" in
      KEY | KEYS | PAT | PATS | PASS) return 0 ;;
      *TOKEN | *TOKENS | *SECRET | *SECRETS | *PASSWORD | *PASSWORDS | *PASSWD | *CREDENTIAL | *CREDENTIALS | *APIKEY)
        return 0 ;;
    esac
  done
  return 1
}

# Env names, one per line, without ever printing a value. `env -0` sees names
# bash cannot hold as variables (a Kubernetes env name may contain `.`), which
# `compgen -e` silently drops; it is the fallback where `env -0` is missing.
env_names_nonempty() {
  local entry
  if env -0 >/dev/null 2>&1; then
    while IFS= read -r -d '' entry; do
      # Name, and whether the value is non-empty. The value itself stops here.
      if [ -n "${entry#*=}" ]; then
        printf '%s\n' "${entry%%=*}"
      fi
    done < <(env -0)
  else
    local name
    while IFS= read -r name; do
      if [ -n "${!name-}" ]; then
        printf '%s\n' "$name"
      fi
    done < <(compgen -e)
  fi
}

credenv_verdict() { # allowed-names (space-separated)
  local allowed=" $1 " name found=()
  while IFS= read -r name; do
    case "$allowed" in *" $name "*) continue ;; esac
    if cred_name "$name"; then
      found+=("$name")
    fi
  done < <(env_names_nonempty | sort -u)
  if [ "${#found[@]}" -eq 0 ]; then
    verdict PASS "no credential-looking env var names (names only; no value is printed)"
  else
    verdict FAIL "credential-looking env var(s): ${found[*]} (names only; values not shown)" \
      "remove envFrom and secretKeyRef env from the runner pod template, and pass a secret to the one step that needs it; if a name is a false positive, list it in allowed-env-names"
  fi
}

caps_verdict() { # root
  local status="$1/proc/self/status" lastcap_file="$1/proc/sys/kernel/cap_last_cap"
  local eff bnd last full note=""
  eff="$(sed -n 's/^CapEff:[[:space:]]*//p' "$status" 2>/dev/null)"
  bnd="$(sed -n 's/^CapBnd:[[:space:]]*//p' "$status" 2>/dev/null)"
  if ! [[ "$eff" =~ ^[0-9a-fA-F]{1,16}$ && "$bnd" =~ ^[0-9a-fA-F]{1,16}$ ]]; then
    verdict REPORT "could not read CapEff/CapBnd from /proc/self/status, so nothing was tested"
    return
  fi
  last="$(cat "$lastcap_file" 2>/dev/null)"
  if ! [[ "$last" =~ ^[0-9]+$ ]]; then
    # 40 is CAP_CHECKPOINT_RESTORE, the last capability since Linux 5.9.
    last=40
    note=" (cap_last_cap unreadable; assumed 40)"
  fi
  if [ "$last" -ge 63 ]; then
    full=-1
  else
    full=$(((1 << (last + 1)) - 1))
  fi
  local e=$((16#$eff)) b=$((16#$bnd))
  local shown="CapEff=$eff CapBnd=$bnd"
  local fix="set privileged: false on the runner container and drop added capabilities; only a Docker sidecar may be privileged"
  if [ $((e & full)) -eq $((full)) ]; then
    verdict FAIL "the job holds every capability ($shown): the container is privileged$note" "$fix"
  elif [ $((b & full)) -eq $((full)) ]; then
    verdict FAIL "the bounding set is complete ($shown): a privileged container, where sudo or a setuid binary can take every capability$note" "$fix"
  elif [ $(((b >> 21) & 1)) -eq 1 ]; then
    verdict FAIL "CAP_SYS_ADMIN is in the bounding set ($shown)" "$fix"
  else
    verdict PASS "not the full capability set, no CAP_SYS_ADMIN ($shown)$note"
  fi
}

hostpid_verdict() { # root
  local comm2 pid1 base
  # kthreadd is PID 2 only in the initial PID namespace. A container's own
  # namespace never shows kernel threads, so this is close to proof.
  comm2="$(cat "$1/proc/2/comm" 2>/dev/null)"
  if [ "$comm2" = "kthreadd" ]; then
    verdict FAIL "PID 2 is kthreadd: this is the host's PID namespace" "remove hostPID: true from the pod spec"
    return
  fi
  # 2>/dev/null BEFORE the <: redirections apply left to right, so the other
  # order reports a missing file before stderr is silenced.
  pid1="$(tr '\0' '\n' 2>/dev/null <"$1/proc/1/cmdline" | head -n 1)"
  if [ -z "$pid1" ]; then
    verdict REPORT "could not read /proc/1/cmdline, so nothing was tested"
    return
  fi
  base="${pid1##*/}"
  case "$base" in
    systemd | init | launchd)
      verdict FAIL "PID 1 is $pid1, a host init: this looks like the host's PID namespace" "remove hostPID: true from the pod spec"
      ;;
    *)
      verdict PASS "PID 1 is $pid1 and no kernel threads are visible"
      ;;
  esac
}

# Interface names that belong on a node, not in a pod. Deliberately ABSENT:
# docker0, br-* and veth*, which a Docker-in-Docker sidecar creates inside the
# pod's own network namespace; and tunl0/sit0/gre0 and friends, which the
# kernel adds to every namespace when their module is loaded.
HOST_IFACE_GLOBS=(cni* flannel* cali* cilium* lxc* kube-ipvs* kube-bridge nodelocaldns
  vxlan* weave* en* wl* vmbr* virbr* bond* tailscale* ib*)

hostnet_verdict() { # root
  local dir="$1/sys/class/net" path name glob names=() host=()
  if [ ! -d "$dir" ]; then
    verdict REPORT "no /sys/class/net to read, so nothing was tested"
    return
  fi
  for path in "$dir"/*; do
    [ -e "$path" ] || continue
    name="${path##*/}"
    names+=("$name")
    for glob in "${HOST_IFACE_GLOBS[@]}"; do
      # shellcheck disable=SC2053
      if [[ "$name" == $glob ]]; then
        host+=("$name")
        break
      fi
    done
  done
  if [ "${#host[@]}" -gt 0 ]; then
    verdict FAIL "heuristic: host-side interface(s) visible: ${host[*]}" "remove hostNetwork: true from the pod spec"
  else
    verdict PASS "heuristic: only pod-side interface names (${names[*]:-none})"
  fi
}

writable_verdict() { # path
  local p="$1" probe
  if [ ! -e "$p" ]; then
    verdict REPORT "does not exist here, so nothing was tested"
    return
  fi
  local fix="mount it readOnly for this job, or don't mount it here"
  if [ -d "$p" ]; then
    # A real attempt, not `test -w`: access(2) can disagree with what a write
    # actually does on overlay and network filesystems.
    if probe="$(mktemp -p "$p" .runner-probe.XXXXXX 2>/dev/null)"; then
      rm -f "$probe"
      verdict FAIL "writable: created (and removed) a file in it" "$fix"
    else
      verdict PASS "write refused"
    fi
  else
    # Open for append and write nothing: proves write access without changing
    # the file's contents or mtime.
    if (: >>"$p") 2>/dev/null; then
      verdict FAIL "writable: opened for writing" "$fix"
    else
      verdict PASS "write refused"
    fi
  fi
}

# --- the probe --------------------------------------------------------------

check_kube_api() { # iso timeout
  local iso="$1" t="$2" endpoints=() ep host url code rc
  if [ -n "${KUBERNETES_SERVICE_HOST:-}" ]; then
    endpoints+=("$KUBERNETES_SERVICE_HOST|${KUBERNETES_SERVICE_PORT:-443}")
  fi
  local name="${PROBE_KUBE_NAME-kubernetes.default.svc}"
  if [ -n "$name" ]; then
    endpoints+=("$name|443")
  fi
  if [ "${#endpoints[@]}" -eq 0 ]; then
    record kube-api REPORT "no KUBERNETES_SERVICE_HOST and no API name to try, so nothing was tested"
    return
  fi
  for ep in "${endpoints[@]}"; do
    host="${ep%%|*}"
    local port="${ep##*|}"
    if command -v curl >/dev/null 2>&1; then
      url="$host"
      case "$host" in *:*) url="[$host]" ;; esac
      # No token, no proxy, no client certificate: exactly what an
      # unauthenticated job can do. -k because the cluster CA is not
      # something a job without a token should have either.
      code="$(curl -sk --noproxy '*' -o /dev/null -w '%{http_code}' \
        --connect-timeout "$t" --max-time "$((t * 2))" \
        "https://$url:$port/api/v1/namespaces" 2>/dev/null)"
      rc=$?
      kube_verdict "$rc" "${code:-000}" "$iso"
    else
      probe_connect "$host" "$port" "$t"
      net_verdict "$C_STATE" "$iso" "the API" \
        "deny egress from this namespace to the API server's ClusterIP and its endpoints"
      V_REASON="$V_REASON (curl not on PATH: TCP reachability only)"
    fi
    record "kube-api ($host:$port)" "$V_RESULT" "$V_REASON" "$V_FIX"
  done
}

render() { # iso
  local iso="$1" i n_fail=0 n_report=0 n_pass=0 summary="${GITHUB_STEP_SUMMARY:-/dev/null}"
  for i in "${!R_CHECK[@]}"; do
    case "${R_RESULT[$i]}" in
      FAIL) n_fail=$((n_fail + 1)) ;;
      REPORT) n_report=$((n_report + 1)) ;;
      PASS) n_pass=$((n_pass + 1)) ;;
    esac
  done

  echo
  for i in "${!R_CHECK[@]}"; do
    printf '%-6s  %-36s  %s\n' "${R_RESULT[$i]}" "${R_CHECK[$i]}" "${R_REASON[$i]}"
  done
  echo
  echo "runner probe: $n_fail FAIL, $n_report REPORT, $n_pass PASS."

  for i in "${!R_CHECK[@]}"; do
    case "${R_RESULT[$i]}" in
      FAIL)
        echo "::error title=runner-probe ${R_CHECK[$i]}::${R_REASON[$i]}. Fix: ${R_FIX[$i]}."
        ;;
      REPORT)
        echo "::warning title=runner-probe ${R_CHECK[$i]}::${R_REASON[$i]}."
        ;;
    esac
  done

  {
    echo "### Runner probe: $n_fail FAIL, $n_report REPORT, $n_pass PASS"
    echo
    if [ "$iso" = "true" ]; then
      echo "Network isolation expected: **yes**. A reachable target FAILs."
    else
      echo "Network isolation expected: **no**. A reachable target is REPORTed, not failed (\`expect-network-isolation\`)."
    fi
    echo
    echo "| Check | Result | Reason |"
    echo "|---|---|---|"
    for i in "${!R_CHECK[@]}"; do
      local reason="${R_REASON[$i]//|/\\|}"
      if [ -n "${R_FIX[$i]}" ]; then
        reason="$reason. **Fix:** ${R_FIX[$i]//|/\\|}"
      fi
      echo "| \`${R_CHECK[$i]}\` | **${R_RESULT[$i]}** | $reason |"
    done
  } >>"$summary"

  [ "$n_fail" -eq 0 ]
}

run() {
  local root="${PROBE_ROOT:-}"
  local iso="${PROBE_EXPECT_NETWORK_ISOLATION:-false}"
  local t="${PROBE_CONNECT_TIMEOUT:-3}"
  local item

  case "$iso" in
    true | false) ;;
    *)
      echo "::error::expect-network-isolation must be true or false (got '$iso')."
      return 1
      ;;
  esac
  if ! [[ "$t" =~ ^[1-9][0-9]*$ ]]; then
    echo "::error::connect-timeout must be a whole number of seconds, 1 or more (got '$t')."
    return 1
  fi

  # Validate the target list BEFORE probing anything: a typo'd target that
  # was skipped would read as one fewer thing to worry about.
  parse_list "${PROBE_UNREACHABLE_TARGETS:-}"
  local targets=("${LIST_ITEMS[@]}") bad=()
  for item in "${targets[@]}"; do
    parse_target "$item" || bad+=("$item")
  done
  if [ "${#bad[@]}" -gt 0 ]; then
    echo "::error::unreachable-targets has entries that are not host:port (or [ipv6]:port with a port from 1 to 65535): ${bad[*]}. Fix the input; nothing was probed."
    return 1
  fi

  satoken_verdict "$root"
  record sa-token "$V_RESULT" "$V_REASON" "$V_FIX"

  check_kube_api "$iso" "$t"

  parse_list "${PROBE_ALLOWED_ENV_NAMES:-}"
  credenv_verdict "${LIST_ITEMS[*]}"
  record credential-env "$V_RESULT" "$V_REASON" "$V_FIX"

  caps_verdict "$root"
  record privileged "$V_RESULT" "$V_REASON" "$V_FIX"

  hostpid_verdict "$root"
  record host-pid "$V_RESULT" "$V_REASON" "$V_FIX"

  hostnet_verdict "$root"
  record host-network "$V_RESULT" "$V_REASON" "$V_FIX"

  local md="${PROBE_METADATA_TARGET:-169.254.169.254:80}"
  parse_target "$md"
  probe_connect "$T_HOST" "$T_PORT" "$t"
  net_verdict "$C_STATE" "$iso" "the cloud metadata endpoint" "deny egress to 169.254.0.0/16"
  record "cloud-metadata ($md)" "$V_RESULT" "$V_REASON" "$V_FIX"

  for item in "${targets[@]}"; do
    parse_target "$item"
    probe_connect "$T_HOST" "$T_PORT" "$t"
    net_verdict "$C_STATE" "$iso" "the target" "deny egress to $item from this runner's namespace"
    record "unreachable ($item)" "$V_RESULT" "$V_REASON" "$V_FIX"
  done

  parse_list "${PROBE_NOT_WRITABLE_PATHS:-}"
  for item in "${LIST_ITEMS[@]}"; do
    writable_verdict "$item"
    record "not-writable ($item)" "$V_RESULT" "$V_REASON" "$V_FIX"
  done

  render "$iso"
}

# --- selftest ---------------------------------------------------------------

ST_FAILURES=0
expect() { # name got want
  if [ "$2" = "$3" ]; then
    printf '  ok    %s\n' "$1"
  else
    printf '  FAIL  %s: want %s, got %s\n' "$1" "$3" "$2"
    ST_FAILURES=$((ST_FAILURES + 1))
  fi
}

fixture_status() { # file capeff capbnd
  mkdir -p "$(dirname "$1")"
  printf 'Name:\tbash\nCapInh:\t0000000000000000\nCapPrm:\t%s\nCapEff:\t%s\nCapBnd:\t%s\n' "$2" "$2" "$3" >"$1"
}

# A pod-shaped root: no token, default container caps, a container PID 1,
# pod-side interfaces including a Docker sidecar's.
fixture_hardened() { # root
  local r="$1"
  fixture_status "$r/proc/self/status" 0000000000000000 00000000a80425fb
  mkdir -p "$r/proc/sys/kernel" "$r/proc/1" "$r/sys/class/net"
  echo 40 >"$r/proc/sys/kernel/cap_last_cap"
  printf '/home/runner/run.sh\0' >"$r/proc/1/cmdline"
  mkdir -p "$r/sys/class/net/lo" "$r/sys/class/net/eth0" "$r/sys/class/net/docker0"
}

# Everything this probe exists to catch, at once.
fixture_exposed() { # root
  local r="$1"
  fixture_status "$r/proc/self/status" 000001ffffffffff 000001ffffffffff
  mkdir -p "$r/proc/sys/kernel" "$r/proc/1" "$r/proc/2" "$r/sys/class/net"
  echo 40 >"$r/proc/sys/kernel/cap_last_cap"
  printf '/sbin/init\0' >"$r/proc/1/cmdline"
  echo kthreadd >"$r/proc/2/comm"
  mkdir -p "$r/sys/class/net/lo" "$r/sys/class/net/ens18" "$r/sys/class/net/cni0" "$r/sys/class/net/flannel.1"
  mkdir -p "$r/var/run/secrets/kubernetes.io/serviceaccount"
  echo not-a-real-token >"$r/var/run/secrets/kubernetes.io/serviceaccount/token"
}

selftest() {
  local work
  work="$(mktemp -d)"
  # shellcheck disable=SC2064
  trap "chmod -R u+w '$work' 2>/dev/null; rm -rf '$work'" EXIT

  echo "list parsing"
  parse_list $'10.0.0.1:443   # a comment\n\n  b:2 c:3\n# whole-line comment'
  expect "comments and blank lines are dropped" "${LIST_ITEMS[*]}" "10.0.0.1:443 b:2 c:3"
  parse_list ""
  expect "an empty list is empty" "${#LIST_ITEMS[@]}" "0"

  echo "target parsing"
  local entry want
  for entry in "10.0.0.1:443=10.0.0.1 443" "host.example:80=host.example 80" \
    "[fd00::1]:6443=fd00::1 6443" "svc.ns.svc.cluster.local:4000=svc.ns.svc.cluster.local 4000" \
    "10.0.0.1:0443=10.0.0.1 443"; do
    want="${entry#*=}"
    if parse_target "${entry%%=*}"; then
      expect "parses ${entry%%=*}" "$T_HOST $T_PORT" "$want"
    else
      expect "parses ${entry%%=*}" "rejected" "$want"
    fi
  done
  for entry in "nohost" "10.0.0.1:0" "10.0.0.1:65536" "10.0.0.1:443a" ":443" \
    "fd00::1:443" "host:" "10.0.0.1:443;id" "10.0.0.1:0000000000000443"; do
    if parse_target "$entry"; then
      expect "rejects '$entry'" "accepted" "rejected"
    else
      expect "rejects '$entry'" "rejected" "rejected"
    fi
  done

  echo "connect classification"
  local case_ rc err
  for case_ in "0||open" "124||timeout" \
    "1|bash: connect: Connection refused|refused" \
    "1|bash: connect: No route to host|unreachable" \
    "1|bash: connect: Network is unreachable|unreachable" \
    "1|bash: line 1: x.invalid: Name or service not known|unresolved" \
    "1|bash: line 1: x.invalid: Temporary failure in name resolution|unresolved" \
    "1|bash: x.invalid: Name does not resolve|unresolved" \
    "1|bash: line 1: /dev/tcp/a/1: No such file or directory|error"; do
    rc="${case_%%|*}"
    err="${case_#*|}"
    want="${err##*|}"
    err="${err%|*}"
    classify_connect "$rc" "$err"
    expect "rc=$rc '${err:-<none>}'" "$C_STATE" "$want"
  done

  echo "network verdicts"
  for case_ in "open false REPORT" "open true FAIL" "refused true PASS" "timeout true PASS" \
    "unreachable true PASS" "unresolved true REPORT" "unresolved false REPORT" "error true REPORT"; do
    read -r state iso want <<<"$case_"
    net_verdict "$state" "$iso" "it" "fix"
    expect "$state, isolation=$iso" "$V_RESULT" "$want"
  done

  echo "kube-api verdicts"
  for case_ in "7 000 false PASS" "28 000 true PASS" "6 000 true REPORT" \
    "0 401 false REPORT" "0 401 true FAIL" "0 403 true FAIL" \
    "0 200 false FAIL" "0 200 true FAIL" "35 000 false REPORT" "35 000 true FAIL"; do
    read -r rc code iso want <<<"$case_"
    kube_verdict "$rc" "$code" "$iso"
    expect "curl exit $rc, HTTP $code, isolation=$iso" "$V_RESULT" "$want"
  done

  echo "credential-looking names"
  local name
  for name in GH_TOKEN OP_SERVICE_ACCOUNT_TOKEN AWS_SECRET_ACCESS_KEY DB_PASSWORD API_KEY \
    OPENAI_APIKEY GH_PAT RUNNER_TOKEN CODER_SESSION_TOKEN NPM_TOKEN GPG_KEY DOCKER_PASS \
    GOOGLE_APPLICATION_CREDENTIALS GHTOKEN my.secret gh-token MYSQL_PASSWD; do
    if cred_name "$name"; then
      expect "$name is flagged" "flagged" "flagged"
    else
      expect "$name is flagged" "missed" "flagged"
    fi
  done
  for name in PATH PWD OLDPWD HOME MONKEY KEYBOARD_LAYOUT TOKENIZERS_PARALLELISM PATCH_LEVEL \
    GITHUB_TOKEN ACTIONS_RUNTIME_TOKEN ACTIONS_ID_TOKEN_REQUEST_TOKEN DOCKER_HOST UV_CACHE_DIR \
    SECRETARY KEYCLOAK_URL PASSTHROUGH KUBERNETES_SERVICE_HOST; do
    if cred_name "$name"; then
      expect "$name is not flagged" "flagged" "clean"
    else
      expect "$name is not flagged" "clean" "clean"
    fi
  done

  echo "service-account token"
  local r="$work/exposed" h="$work/hardened"
  fixture_exposed "$r"
  fixture_hardened "$h"
  satoken_verdict "$r"
  expect "a mounted token fails" "$V_RESULT" "FAIL"
  satoken_verdict "$h"
  expect "no token passes" "$V_RESULT" "PASS"

  echo "capabilities"
  caps_verdict "$h"
  expect "default container caps pass" "$V_RESULT" "PASS"
  caps_verdict "$r"
  expect "the full set fails" "$V_RESULT" "FAIL"
  local c="$work/caps"
  mkdir -p "$c/proc/sys/kernel"
  echo 40 >"$c/proc/sys/kernel/cap_last_cap"
  fixture_status "$c/proc/self/status" 0000000000000000 000001ffffffffff
  caps_verdict "$c"
  expect "an unprivileged process in a privileged container fails (full CapBnd)" "$V_RESULT" "FAIL"
  fixture_status "$c/proc/self/status" 0000000000000000 00000000a82425fb
  caps_verdict "$c"
  expect "CAP_SYS_ADMIN in the bounding set fails" "$V_RESULT" "FAIL"
  fixture_status "$c/proc/self/status" 0000000000000000 0000003fffffffff
  echo 37 >"$c/proc/sys/kernel/cap_last_cap"
  caps_verdict "$c"
  expect "the full set is measured against cap_last_cap" "$V_RESULT" "FAIL"
  rm -f "$c/proc/self/status"
  caps_verdict "$c"
  expect "an unreadable status is REPORTed, not passed" "$V_RESULT" "REPORT"

  echo "host PID namespace"
  hostpid_verdict "$h"
  expect "a container PID 1 passes" "$V_RESULT" "PASS"
  hostpid_verdict "$r"
  expect "visible kthreadd fails" "$V_RESULT" "FAIL"
  local p="$work/pid"
  mkdir -p "$p/proc/1"
  for case_ in "/usr/lib/systemd/systemd FAIL" "/sbin/init FAIL" "/pause PASS" "/usr/bin/tini PASS"; do
    read -r pid1 want <<<"$case_"
    printf '%s\0--flag\0' "$pid1" >"$p/proc/1/cmdline"
    hostpid_verdict "$p"
    expect "PID 1 $pid1" "$V_RESULT" "$want"
  done
  rm -f "$p/proc/1/cmdline"
  hostpid_verdict "$p"
  expect "an unreadable PID 1 is REPORTed, not passed" "$V_RESULT" "REPORT"

  echo "host network (heuristic)"
  hostnet_verdict "$h"
  expect "lo, eth0 and a dind docker0 pass" "$V_RESULT" "PASS"
  hostnet_verdict "$r"
  expect "cni0, flannel.1 and ens18 fail" "$V_RESULT" "FAIL"
  local n="$work/net"
  mkdir -p "$n/sys/class/net/lo" "$n/sys/class/net/eth0" "$n/sys/class/net/tunl0" \
    "$n/sys/class/net/sit0" "$n/sys/class/net/veth1a2b" "$n/sys/class/net/br-0f1e"
  hostnet_verdict "$n"
  expect "kernel tunnel devices and dind veth/br pass" "$V_RESULT" "PASS"
  hostnet_verdict "$work/nowhere"
  expect "no /sys/class/net is REPORTed" "$V_RESULT" "REPORT"

  echo "writable paths"
  local w="$work/w"
  mkdir -p "$w/open" "$w/closed"
  writable_verdict "$w/open"
  expect "a writable directory fails" "$V_RESULT" "FAIL"
  expect "the probe file is cleaned up" "$(find "$w/open" -mindepth 1 | wc -l | tr -d ' ')" "0"
  writable_verdict "$w/absent"
  expect "a missing path is REPORTed, not passed" "$V_RESULT" "REPORT"
  echo data >"$w/file"
  writable_verdict "$w/file"
  expect "a writable file fails" "$V_RESULT" "FAIL"
  expect "the file is unchanged" "$(cat "$w/file")" "data"
  if [ "$(id -u)" -eq 0 ]; then
    echo "  skip  read-only cases: running as root, which ignores file modes"
  else
    chmod 0555 "$w/closed"
    writable_verdict "$w/closed"
    expect "a read-only directory passes" "$V_RESULT" "PASS"
    chmod 0444 "$w/file"
    writable_verdict "$w/file"
    expect "a read-only file passes" "$V_RESULT" "PASS"
  fi

  echo "live: the TCP primitive"
  # Port 1 on loopback: nothing listens there. If this does not come back
  # `refused`, bash lacks /dev/tcp and every reachability check is inert.
  probe_connect 127.0.0.1 1 3
  expect "a closed loopback port reads as refused" "$C_STATE" "refused"

  echo "end to end: run, against fixture roots"
  local base_env=(env -i "PATH=$PATH" "HOME=${HOME:-/tmp}" "PROBE_KUBE_NAME="
    "KUBERNETES_SERVICE_HOST=127.0.0.1" "KUBERNETES_SERVICE_PORT=1"
    "PROBE_METADATA_TARGET=127.0.0.1:1" "PROBE_CONNECT_TIMEOUT=2")
  local out sum="$work/summary.md"
  out="$("${base_env[@]}" "PROBE_ROOT=$h" "GITHUB_STEP_SUMMARY=$sum" bash "$SELF" run 2>&1)"
  expect "a hardened pod exits 0" "$?" "0"
  expect "the summary has one row per check" "$(grep -c '^| `' "$sum")" "7"

  out="$("${base_env[@]}" "PROBE_ROOT=$h" "FIXTURE_SECRET_TOKEN=s3ntinel-v4lue" bash "$SELF" run 2>&1)"
  expect "a credential-looking env var fails the run" "$?" "1"
  expect "its name is reported" "$(grep -c 'FIXTURE_SECRET_TOKEN' <<<"$out" | tr -d ' ')" "2"
  expect "its value never appears" "$(grep -c 's3ntinel-v4lue' <<<"$out" | tr -d ' ')" "0"

  "${base_env[@]}" "PROBE_ROOT=$h" "FIXTURE_SECRET_TOKEN=x" \
    "PROBE_ALLOWED_ENV_NAMES=FIXTURE_SECRET_TOKEN" bash "$SELF" run >/dev/null 2>&1
  expect "allowed-env-names excuses a named false positive" "$?" "0"

  out="$("${base_env[@]}" "PROBE_ROOT=$r" bash "$SELF" run 2>&1)"
  expect "an exposed pod exits 1" "$?" "1"
  local check
  for check in sa-token privileged host-pid host-network; do
    expect "$check FAILs on the exposed pod" "$(grep -cE "^FAIL +$check " <<<"$out" | tr -d ' ')" "1"
  done

  "${base_env[@]}" "PROBE_ROOT=$h" "PROBE_UNREACHABLE_TARGETS=10.0.0.1" bash "$SELF" run >/dev/null 2>&1
  expect "a malformed target refuses to run" "$?" "1"
  "${base_env[@]}" "PROBE_ROOT=$h" "PROBE_EXPECT_NETWORK_ISOLATION=yes" bash "$SELF" run >/dev/null 2>&1
  expect "a non-boolean isolation input refuses to run" "$?" "1"

  out="$("${base_env[@]}" "PROBE_ROOT=$h" "PROBE_NOT_WRITABLE_PATHS=$w/open" bash "$SELF" run 2>&1)"
  expect "a writable not-writable path fails the run" "$?" "1"

  # An OPEN port needs a listener, which bash cannot make. Use python3 when it
  # happens to exist (it does on a hosted runner, where this repo's CI runs the
  # selftest); otherwise say so rather than pass silently.
  if command -v python3 >/dev/null 2>&1; then
    local portfile="$work/port" pid port=""
    python3 -c '
import socket, sys, time
s = socket.socket()
s.bind(("127.0.0.1", 0))
s.listen(8)
open(sys.argv[1], "w").write(str(s.getsockname()[1]))
time.sleep(30)
' "$portfile" &
    pid=$!
    for _ in 1 2 3 4 5 6 7 8 9 10; do
      [ -s "$portfile" ] && break
      sleep 0.2
    done
    port="$(cat "$portfile" 2>/dev/null)"
    if [ -n "$port" ]; then
      probe_connect 127.0.0.1 "$port" 3
      expect "a listening loopback port reads as open" "$C_STATE" "open"
      "${base_env[@]}" "PROBE_ROOT=$h" "PROBE_UNREACHABLE_TARGETS=127.0.0.1:$port" bash "$SELF" run >/dev/null 2>&1
      expect "a reachable target only REPORTs without isolation" "$?" "0"
      "${base_env[@]}" "PROBE_ROOT=$h" "PROBE_UNREACHABLE_TARGETS=127.0.0.1:$port" \
        "PROBE_EXPECT_NETWORK_ISOLATION=true" bash "$SELF" run >/dev/null 2>&1
      expect "a reachable target FAILs with isolation expected" "$?" "1"
    else
      expect "the python3 listener started" "no" "yes"
    fi
    kill "$pid" 2>/dev/null
    wait "$pid" 2>/dev/null
  else
    echo "  skip  open-port cases: no python3 to listen with (the classifier cases above still ran)"
  fi

  if [ "$ST_FAILURES" -gt 0 ]; then
    echo "::error::runner_probe selftest: $ST_FAILURES case(s) failed. A check whose parser is wrong reports a verdict about something it did not measure; fix the script before trusting the probe."
    return 1
  fi
  echo "runner_probe selftest: all cases passed"
}

case "${1:-}" in
  run) run ;;
  --selftest) selftest ;;
  *)
    echo "usage: $0 run | --selftest" >&2
    exit 2
    ;;
esac
