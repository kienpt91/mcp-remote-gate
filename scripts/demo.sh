#!/bin/sh
# Records the demo of the README against the bundled fake server: token creation, the read-only tool list,
# a denied send with its audit line, a rejected token, the kill switch and the one-line switch that enables
# sending. Everything is real output. Run it where curl and the Rust toolchain are available, for example:
#
#   docker run --rm -v "$PWD:/work" -v gate-target:/target -w /work -e CARGO_TARGET_DIR=/target \
#     --network none gate-dev sh scripts/demo.sh > docs/demo-output.txt
set -eu
cd "$(dirname "$0")/.."
cargo build --release --locked --offline -q
export PATH="${CARGO_TARGET_DIR:-$PWD/target}/release:$PATH"
WORK=$(mktemp -d)
cd "$WORK"
GATE=""
trap '[ -z "$GATE" ] || kill "$GATE" 2>/dev/null || true; rm -rf "$WORK"' EXIT
URL=http://127.0.0.1:8787/mcp

say() { printf '\n# %s\n' "$*"; }
run() { printf '$ %s\n' "$*"; "$@" 2>&1 || true; }

mcp() {
  shown='$TOKEN'; [ -z "${2:-}" ] || shown='mrg_wrong...'
  printf '$ curl -s -H "Authorization: Bearer %s" -H "Content-Type: application/json" -d '"'"'%s'"'"' %s\n' "$shown" "$1" "$URL"
  curl -s -w '\n[HTTP %{http_code}]\n' -H "Authorization: Bearer ${2:-$TOKEN}" -H 'Content-Type: application/json' \
    -H 'Accept: application/json' -d "$1" "$URL"
}

start_gate() {
  printf '$ mcp-remote-gate run --config gate.toml &\n'
  mcp-remote-gate run --config gate.toml 2> gate.log &
  GATE=$!
  i=0
  until grep -q 'ready on' gate.log; do
    i=$((i + 1)); [ "$i" -lt 200 ] || { cat gate.log; exit 1; }
    sleep 0.05
  done
}

stop_gate() {
  printf '$ kill -TERM $GATE_PID\n'
  kill -TERM "$GATE"
  wait "$GATE" || true
  GATE=""
  sed 's/^/  gate: /' gate.log
}

say "1. Create a token. It is shown once; the config stores only its SHA-256."
printf '$ mcp-remote-gate token new --id desktop\n'
mcp-remote-gate token new --id desktop > token.out 2> token.err
TOKEN=$(sed -n 's/^token: //p' token.out)
sed "s/$TOKEN/mrg_<the token, masked in this recording>/" token.out
cat token.err

say "2. Start from the example config, paste the [[token]] hash, and check it."
mcp-remote-gate init > gate.toml
HASH=$(sed -n 's/^hash = "\(sha256:[0-9a-f]*\)"$/\1/p' token.out)
sed -i "s|sha256:0000000000000000000000000000000000000000000000000000000000000000|$HASH|" gate.toml
sed -i 's|^# kill_switch_file = "KILL".*|kill_switch_file = "KILL"|; s|^# SOME_SETTING = "value"|FAKE_MCP_SENT_LOG = "sent.log"|' gate.toml
chmod 600 gate.toml
run mcp-remote-gate check --config gate.toml

say "3. Ask the real server which tools it has, and see which ones the policy lets through."
run mcp-remote-gate tools --config gate.toml

say "4. Run the gateway (read_only = true) and use it."
start_gate
mcp '{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-06-18","capabilities":{},"clientInfo":{"name":"curl","version":"1"}}}'
mcp '{"jsonrpc":"2.0","id":2,"method":"tools/list"}'
mcp '{"jsonrpc":"2.0","id":3,"method":"tools/call","params":{"name":"list_chats","arguments":{}}}'

say "5. A send is denied by the gateway; the server never sees it."
mcp '{"jsonrpc":"2.0","id":4,"method":"tools/call","params":{"name":"send_message","arguments":{"to":"alice","text":"hello"}}}'
printf '$ test -e sent.log && cat sent.log || echo "sent.log does not exist: the fake server never received a send"\n'
if test -e sent.log; then cat sent.log; else echo "sent.log does not exist: the fake server never received a send"; fi

say "6. A wrong token is rejected."
mcp '{"jsonrpc":"2.0","id":5,"method":"ping"}' mrg_wrongwrongwrongwrongwrongwrongwrongwrongwrong

say "7. The audit log: one JSON line per request, no token, no argument values."
run cat audit.jsonl

say "8. The kill switch: while the file exists every request gets 503."
run touch KILL
mcp '{"jsonrpc":"2.0","id":6,"method":"ping"}'
run rm KILL
mcp '{"jsonrpc":"2.0","id":7,"method":"ping"}'

say "9. Stop the gateway; it stops the server and its process group."
stop_gate

say "10. Enabling sending is one line: read_only = false."
printf '$ sed -i "s/^read_only = true/read_only = false/" gate.toml\n'
sed -i 's/^read_only = true/read_only = false/' gate.toml
start_gate
mcp '{"jsonrpc":"2.0","id":8,"method":"tools/call","params":{"name":"send_message","arguments":{"to":"alice","text":"hello"}}}'
run cat sent.log
stop_gate
