#!/usr/bin/env bash
#
# mayhem/build.sh — build this repo's fuzz harness(es). EDIT per repo.
#
# Runs inside the commit image (mayhem/Dockerfile) as `mayhem` in /mayhem. The base image
# (ghcr.io/savantenvs/base) already exports the build contract — use these, don't redefine:
#   CC, CXX             stock clang / clang++
#   LIB_FUZZING_ENGINE  -fsanitize=fuzzer   (link into each harness that has a LLVMFuzzer entry)
#   SANITIZER_FLAGS     -fsanitize=address,undefined -fno-sanitize-recover=all -fno-omit-frame-pointer
#                       (ASan + UBSan, both set to HALT — so Mayhem catches memory AND UB defects)
#   DEBUG_FLAGS         -g -gdwarf-3   (DWARF debug info — always on for fuzz/standalone builds,
#                       independent of the sanitizer off-switch; DWARF version must be < 4)
#   RUST_DEBUG_FLAGS    -C debuginfo=2 -C force-frame-pointers=yes -C llvm-args=-gdwarf-3
#                       (thread through RUSTFLAGS on every cargo-fuzz build)
#   GO_DEBUG_FLAGS      -gcflags=all=-N -l
#                       (thread through go build / go-fuzz-build so the linked ELF keeps symbols)
#   SRC                 /mayhem (the repo source)
#
# Contract: build EVERYTHING here — one runnable binary per fuzz harness, AND the project's test
# suite (so mayhem/test.sh only has to RUN it, never compile). Keep it ADDITIVE (build upstream as
# upstream documents; don't edit upstream files). IMPORTANT: build the PROJECT ITSELF with
# $SANITIZER_FLAGS and $DEBUG_FLAGS (not just the harness) so the fuzzed code is instrumented
# AND carries DWARF < 4 symbols — otherwise ASan/UBSan only see the harness, not the library
# you're trying to find bugs in, and backtraces won't resolve project source lines. Build the TEST
# suite with the project's NORMAL flags (a clean, independent build) so test.sh stays an honest
# functional oracle and won't false-fail on benign UB. Leave the test binary/runner where test.sh
# expects it.
set -euo pipefail

# clang rejects SOURCE_DATE_EPOCH='' (empty) — it must be unset or a valid integer.
[ -n "${SOURCE_DATE_EPOCH:-}" ] || unset SOURCE_DATE_EPOCH

# Build knobs come from the ENVIRONMENT (overridable), with sane defaults — no if-statements,
# just parameter-expansion fallbacks. Default sanitizers are the base's ASan+UBSan (halting); override
# per build via the Dockerfile's `--build-arg SANITIZER_FLAGS="..."`.
# NB: SANITIZER_FLAGS uses `=` (no colon) on purpose — `=` only fills when the var is UNSET, so an
# explicit EMPTY value (`--build-arg SANITIZER_FLAGS=`) is honored and builds with NO sanitizers
# (useful when you want the program's natural crash / full backtrace, not an ASan report). The other
# knobs use `:=` (default on empty too). MAYHEM_JOBS sets build parallelism (falls back to nproc).
: "${SANITIZER_FLAGS=-fsanitize=address,undefined -fno-sanitize-recover=all -fno-omit-frame-pointer}"
# DEBUG_FLAGS carries DWARF debug info INDEPENDENTLY of the sanitizer off-switch (so an empty
# SANITIZER_FLAGS still yields DWARF symbols). DWARF MUST be < 4 (Mayhem triage can't read >=4); clang-19's
# plain `-g` emits DWARF-5, so `-gdwarf-3` is explicit. Apply $DEBUG_FLAGS to the fuzz/harness/standalone
# builds (NOT the test/oracle build). Rust/Go carry the same intent via their language flags below.
: "${DEBUG_FLAGS:=-g -gdwarf-3}"
: "${RUST_DEBUG_FLAGS:=-C debuginfo=2 -C force-frame-pointers=yes -C llvm-args=-gdwarf-3}"
: "${GO_DEBUG_FLAGS:=-gcflags=all=-N -l}"
: "${CC:=clang}" ; : "${CXX:=clang++}" ; : "${LIB_FUZZING_ENGINE:=-fsanitize=fuzzer}"
: "${MAYHEM_JOBS:=$(nproc)}"
# COVERAGE_FLAGS: empty by default → no effect on the normal oracle build. Set it via the Dockerfile's
# `--build-arg COVERAGE_FLAGS="-fprofile-instr-generate -fcoverage-mapping"` to instrument the TEST
# build for source-coverage measurement (how much of the project the test suite actually exercises —
# a quality signal for the oracle; complements the anti-reward-hack sabotage check). APPEND it to the
# test build's compile+link flags in step 3 (NOT the fuzz build); after `test.sh` runs, merge with
# `llvm-profdata` and report with `llvm-cov`. Empty value is honored (`=`, not `:=`).
: "${COVERAGE_FLAGS=}"
export SANITIZER_FLAGS DEBUG_FLAGS RUST_DEBUG_FLAGS GO_DEBUG_FLAGS CC CXX LIB_FUZZING_ENGINE MAYHEM_JOBS COVERAGE_FLAGS

cd "$SRC"

# Providers built: the software ones that run without special hardware.
PROVIDERS=(--enable-tcp --enable-udp --enable-rxm --enable-rxd --enable-sockets --enable-shm
  --disable-efa --disable-verbs --disable-psm2 --disable-psm3 --disable-opx --disable-usnic
  --disable-ucx --disable-cxi --disable-lpp --disable-sm2 --disable-mrail --disable-lnx)
B="$SRC/mayhem/build"   # every build dir lives here; mayhem/.gitignore ignores it

# autogen generates configure (gitignored) from configure.ac; re-run only when missing.
[ -x "$SRC/configure" ] || ./autogen.sh

# 1) The library with the sanitizer + fuzzer-coverage flags (static), out of tree.
mkdir -p "$B/fuzz"
if [ ! -f "$B/fuzz/config.status" ]; then
  (cd "$B/fuzz" && "$SRC/configure" --enable-static --disable-shared --enable-debug=no "${PROVIDERS[@]}" \
      CC="$CC" CFLAGS="$SANITIZER_FLAGS $DEBUG_FLAGS -O1 -fsanitize=fuzzer-no-link")
fi
make -C "$B/fuzz" -j"$MAYHEM_JOBS" src/libfabric.la
LIB="$B/fuzz/src/.libs/libfabric.a"
LIBS="-lpthread -ldl -lrt -latomic -lm"

# 2) Harnesses: libFuzzer binary + standalone reproducer each.
$CC $SANITIZER_FLAGS $DEBUG_FLAGS -c "$SRC/mayhem/lsan_off.c" -o "$B/lsan_off.o"
$CC $SANITIZER_FLAGS $DEBUG_FLAGS -c "$STANDALONE_FUZZ_MAIN" -o "$B/standalone_main.o"
build_harness() { # name source [extra cflags]
  local name="$1" src="$2"; shift 2
  $CC $SANITIZER_FLAGS $DEBUG_FLAGS $LIB_FUZZING_ENGINE -I"$SRC/include" "$@" "$src" \
      "$B/lsan_off.o" "$LIB" $LIBS -o "/mayhem/$name"
  $CC $SANITIZER_FLAGS $DEBUG_FLAGS -I"$SRC/include" "$@" "$src" "$B/standalone_main.o" \
      "$B/lsan_off.o" "$LIB" $LIBS -o "/mayhem/$name-standalone"
}
H="$SRC/mayhem/harnesses"
build_harness fuzz_getinfo "$H/fuzz_getinfo.c"
build_harness fuzz_tcp_msg "$H/fuzz_tcp_msg.c"
build_harness fuzz_rxd_udp "$H/fuzz_rxd_udp.c"
build_harness fuzz_tcp_rdm "$H/fuzz_rdm_wire.c" '-DFUZZ_PROV="tcp"'
build_harness fuzz_sockets_rdm "$H/fuzz_rdm_wire.c" '-DFUZZ_PROV="sockets"'
build_harness fuzz_rxm_tcp "$H/fuzz_rdm_wire.c" '-DFUZZ_PROV="tcp;ofi_rxm"'
build_harness fuzz_sockets_msg "$H/fuzz_tcp_msg.c" '-DFUZZ_PROV="sockets"' -DFUZZ_SOCKETS
build_harness fuzz_tcp_connect "$H/fuzz_msg_connect.c" '-DFUZZ_PROV="tcp"'
build_harness fuzz_sockets_connect "$H/fuzz_msg_connect.c" '-DFUZZ_PROV="sockets"'

# 3) The functional test build, NORMAL flags: the library + upstream's own utilities
#    (util/fi_info, util/fi_strerror — upstream's `make check` runs util/fi_info).
mkdir -p "$B/test"
if [ ! -f "$B/test/config.status" ]; then
  (cd "$B/test" && env -u CFLAGS -u LDFLAGS "$SRC/configure" --enable-static --disable-shared "${PROVIDERS[@]}" \
      CC="$CC" CFLAGS="-O2 $COVERAGE_FLAGS" LDFLAGS="$COVERAGE_FLAGS")
fi
make -C "$B/test" -j"$MAYHEM_JOBS" util/fi_info util/fi_strerror
