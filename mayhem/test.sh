#!/usr/bin/env bash
#
# mayhem/test.sh — RUN this repo's OWN functional test suite (already built by mayhem/build.sh).
# exit 0 = pass. EDIT per repo. PATCH-grade oracle: after an agent patches the source, the grader
# rebuilds (build.sh) then runs this. DELETE this file if the repo has no meaningful tests.
#
# IMPORTANT:
#  * Must assert BEHAVIOR/OUTPUT, not just exit status. The oracle has to check asserted values /
#    golden-output diffs / known-answer results — so a PATCH that "fixes" a bug by making the program
#    exit(0) (or any no-op) FAILS here. Running inputs and checking only "exit 0 / didn't crash" is
#    NOT a functional test (it's trivially reward-hackable) — use the project's real assertion suite.
#  * Do NOT build here — mayhem/build.sh already compiled the test suite (with the project's normal
#    flags). This script only RUNS the pre-built tests and reports counts. If the test runner is
#    missing, that's a build.sh bug — fail loudly rather than silently rebuilding.
#  * REQUIRED OUTPUT — a CTRF (https://ctrf.io) summary so Mayhem/the PATCH grader reads the counts:
#      - writes a CTRF JSON report to ${CTRF_REPORT:-$SRC/ctrf-report.json}, and
#      - prints a one-line `CTRF {...}` marker to stdout (same JSON, compact).
#    Only `results.summary` (with tests/passed/failed/pending/skipped/other) is required.
#    Use the emit_ctrf helper below; it computes tests = passed+failed+skipped and sets the exit
#    code (0 iff failed==0). Map your framework's output to passed/failed/skipped.
set -uo pipefail
[ -n "${SOURCE_DATE_EPOCH:-}" ] || unset SOURCE_DATE_EPOCH
: "${MAYHEM_JOBS:=$(nproc)}"   # build parallelism; env-overridable, falls back to nproc (use -j"$MAYHEM_JOBS")
cd "$SRC"

# emit_ctrf <tool> <passed> <failed> [skipped] [pending] [other]
# Writes a CTRF report (file + stdout `CTRF {...}` marker) and returns non-zero iff failed>0.
emit_ctrf() {
  local tool="$1" passed="$2" failed="$3" skipped="${4:-0}" pending="${5:-0}" other="${6:-0}"
  local tests=$(( passed + failed + skipped + pending + other ))
  cat > "${CTRF_REPORT:-$SRC/ctrf-report.json}" <<JSON
{
  "results": {
    "tool": { "name": "$tool" },
    "summary": {
      "tests": $tests,
      "passed": $passed,
      "failed": $failed,
      "pending": $pending,
      "skipped": $skipped,
      "other": $other
    }
  }
}
JSON
  printf 'CTRF {"results":{"tool":{"name":"%s"},"summary":{"tests":%d,"passed":%d,"failed":%d,"pending":%d,"skipped":%d,"other":%d}}}\n' \
    "$tool" "$tests" "$passed" "$failed" "$pending" "$skipped" "$other"
  [ "$failed" -eq 0 ]
}

# Upstream's own check (`make check` = TESTS = util/fi_info) plus fi_strerror, run against the
# normal-flags build from build.sh, asserting their OUTPUT (known answers), not just exit codes.
T="$SRC/mayhem/build/test/util"
for b in fi_info fi_strerror; do
  [ -x "$T/$b" ] || { echo "missing $T/$b — mayhem/build.sh did not build it" >&2; exit 1; }
done
export FI_LOG_LEVEL=none
pass=0 fail=0
check() { # name expected-regex command...
  local name="$1" re="$2"; shift 2
  local out; out="$("$@" 2>&1)"
  if grep -Eq -- "$re" <<<"$out"; then pass=$((pass+1)); echo "PASS $name";
  else fail=$((fail+1)); echo "FAIL $name"; echo "$out" | head -20; fi
}
check list-has-tcp      '^tcp:'                         "$T/fi_info" -l
check list-has-udp      '^udp:'                         "$T/fi_info" -l
check list-has-sockets  '^sockets:'                     "$T/fi_info" -l
check list-has-rxd      '^ofi_rxd:'                     "$T/fi_info" -l
check udp-dgram         'type:[[:space:]]+FI_EP_DGRAM'  "$T/fi_info" -p udp -t FI_EP_DGRAM -n 127.0.0.1
check tcp-msg-proto     'protocol:[[:space:]]+FI_PROTO_SOCK_TCP' "$T/fi_info" -p tcp -t FI_EP_MSG -n 127.0.0.1
check rxd-over-udp      'provider: udp;ofi_rxd'         "$T/fi_info" -p 'udp;ofi_rxd' -t FI_EP_RDM -n 127.0.0.1
check numeric-node      'dest_addr: fi_sockaddr_in://127\.0\.0\.1:4242' "$T/fi_info" -p udp -t FI_EP_DGRAM -n 127.0.0.1 -P 4242 -v
check bad-prov-nodata   'No data available'             "$T/fi_info" -p no_such_provider
check env-var-listing   'FI_TCP_IFACE'                  "$T/fi_info" -e
check strerror-enodata  '^No data available$'           "$T/fi_strerror" 61
check strerror-etrunc   '^Truncation error$'            "$T/fi_strerror" 265
emit_ctrf "libfabric-util" "$pass" "$fail" 0
