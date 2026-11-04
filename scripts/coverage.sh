#!/bin/sh
# Line coverage per layer with rustc's source-based instrumentation (`-C instrument-coverage`) and the
# llvm-profdata / llvm-cov tools of the `llvm-tools` rustup component. No third-party coverage crate.
# Run it where the repository is mounted and dependencies are fetched, for example (see README):
#
#   docker run --rm -v "$PWD:/work" -v gate-target:/target -w /work gate-dev scripts/coverage.sh
#
# What is counted: the library and binary code of each crate. Not counted: files under tests/, the
# in-memory fakes (crates/gate-app/src/testing.rs), test helpers (testutil.rs, *_tests.rs) and everything
# after the first `#[cfg(test)]` of a source file (the unit tests themselves, which would otherwise
# inflate every number). A process that is killed with SIGKILL writes no profile, so the code paths that
# only that process runs are not counted.
#
# The script fails when a target is missed: domain >= 95, application >= 90, overall >= 85.
set -eu
cd "$(dirname "$0")/.."
SYSROOT=$(rustc --print sysroot)
HOST=$(rustc -vV | sed -n 's/^host: //p')
BIN="$SYSROOT/lib/rustlib/$HOST/bin"
COV=${COV_DIR:-/target/cov}
rm -rf "$COV"
mkdir -p "$COV/raw"
export RUSTFLAGS="-C instrument-coverage"
export CARGO_TARGET_DIR="$COV/build"
export LLVM_PROFILE_FILE="$COV/raw/p-%p-%m.profraw"

cargo test --workspace --locked --offline --no-fail-fast
objects=$(cargo test --workspace --locked --offline --no-run --message-format=json 2>/dev/null \
  | grep -o '"executable":"[^"]*"' | cut -d'"' -f4 | sort -u)
[ -x "$CARGO_TARGET_DIR/debug/mcp-remote-gate" ] && objects="$objects $CARGO_TARGET_DIR/debug/mcp-remote-gate"

"$BIN/llvm-profdata" merge -sparse "$COV"/raw/*.profraw -o "$COV/all.profdata"
first=""; rest=""
for o in $objects; do
  if [ -z "$first" ]; then first=$o; else rest="$rest -object=$o"; fi
done
# shellcheck disable=SC2086
"$BIN/llvm-cov" export --format=lcov --instr-profile="$COV/all.profdata" \
  --ignore-filename-regex='(/\.cargo/|/cargo/registry/|/rustc/|/tests/|/testing\.rs|testutil\.rs|_tests\.rs)' \
  "$first" $rest > "$COV/lcov.info"

awk -v enforce="${COVERAGE_ENFORCE:-1}" '
  /^SF:/ {
    file = substr($0, 4); cutoff = 1000000000
    cmd = "grep -n -m1 \"#\\[cfg(test)\\]\" \"" file "\" 2>/dev/null"
    if ((cmd | getline hit) > 0) { split(hit, parts, ":"); cutoff = parts[1] }
    close(cmd)
    crate = "other"
    if (file ~ /crates\/gate-domain\//) crate = "domain"
    else if (file ~ /crates\/gate-app\//) crate = "application"
    else if (file ~ /crates\/(gate-infra|gate-sys)\//) crate = "infrastructure"
    else if (file ~ /crates\/gate-fake-mcp\//) crate = "fake-server"
    else if (file ~ /crates\/gate-cli\//) crate = "cli"
    next
  }
  /^DA:/ {
    split(substr($0, 4), da, ",")
    if (da[1] + 0 < cutoff) { total[crate]++; if (da[2] + 0 > 0) covered[crate]++ }
  }
  END {
    printf "%-16s %8s %8s %8s\n", "layer", "lines", "covered", "percent"
    n = split("domain application infrastructure cli fake-server other", order, " ")
    for (i = 1; i <= n; i++) {
      c = order[i]
      if (total[c] == 0) continue
      pct[c] = 100 * covered[c] / total[c]
      printf "%-16s %8d %8d %7.1f%%\n", c, total[c], covered[c], pct[c]
      all += total[c]; allc += covered[c]
    }
    overall = 100 * allc / all
    printf "%-16s %8d %8d %7.1f%%\n", "overall", all, allc, overall
    bad = 0
    if (pct["domain"] < 95) { print "target missed: domain >= 95"; bad = 1 }
    if (pct["application"] < 90) { print "target missed: application >= 90"; bad = 1 }
    if (overall < 85) { print "target missed: overall >= 85"; bad = 1 }
    if (bad && enforce == 1) exit 1
  }
' "$COV/lcov.info" | tee "$COV/summary.txt"
