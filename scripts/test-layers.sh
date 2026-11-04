#!/bin/sh
# Runs the test suites layer by layer and prints a count per layer. Run it where the repository is
# mounted and the dependencies are fetched (see README, "Running the tests").
#
#   domain        unit and property tests of the pure rules: SHA-256, JSON, JSON-RPC, glob, tool policy,
#                 rate limiter, redaction, audit record, line framing, Host/Origin policy, restart policy,
#                 configuration validation (gate-domain)
#   application   the gateway request handler and the upstream session driven through the ports with
#                 in-memory fakes, a fake clock and a scripted child process (gate-app)
#   adapters      the TOML parser and config loader, the HTTP server and client over real loopback
#                 sockets (smuggling, oversized heads and bodies, slow clients, garbage), the child
#                 process adapter with real processes, the audit file, the kill switch, the system
#                 crate (process groups, limits, signals), the fake server, and the whole gateway in
#                 front of a real child process (gate-infra, gate-sys, gate-fake-mcp, gate-cli adapters)
#   end-to-end    the real `mcp-remote-gate` binary: token flow, run with signals, shutdown of the
#                 child tree, refusals, selftest, and the command line units (gate-cli)
#   architecture  the dependency and purity rules checked on the source tree
set -eu
cd "$(dirname "$0")/.."
OPTS="--locked"
[ "${OFFLINE:-1}" = 1 ] && OPTS="$OPTS --offline"

layer() {
  name=$1; shift
  printf '\n== %s ==\n' "$name"
  out=$("$@" 2>&1) || { printf '%s\n' "$out"; echo "FAILED: $name" >&2; exit 1; }
  printf '%s\n' "$out" | grep -E '^test result' | awk -v n="$name" '{p+=$4; f+=$6} END {printf "%s: %d passed, %d failed\n", n, p, f}'
}

layer domain       cargo test $OPTS -p gate-domain
layer application  cargo test $OPTS -p gate-app
layer adapters     cargo test $OPTS -p gate-infra -p gate-sys -p gate-fake-mcp
layer adapters-process cargo test $OPTS -p gate-cli --test adapters
layer end-to-end   cargo test $OPTS -p gate-cli --lib --test e2e
layer architecture cargo test $OPTS -p gate-cli --test architecture
