# mcp-remote-gate

Put any stdio MCP server (a WhatsApp server, a file-system server, your own) behind a small authenticated HTTP gateway, so that a remote MCP client can use it as a connector: **protected by a token, with the tools limited by an allowlist, and sending disabled by default**.

```text
remote MCP client --HTTPS--> TLS proxy or tunnel --HTTP--> 127.0.0.1:8787 mcp-remote-gate --stdio--> your MCP server
                                                              token | Host/Origin | rate limit | tool policy | audit log | kill switch
```

It answers a common freelance request: *"expose this MCP server as a remote connector, protected by a token, sending disabled by default, and write me a handover note"*. The gateway is one binary, written in Rust with `std` and one system-call crate (`libc`), no HTTP framework and no async runtime.

> **Status: not audited, and not tested with any real MCP client application or any real WhatsApp (or other messaging or file-system) MCP server.** It was verified against a fake MCP server (a real child process speaking JSON-RPC over pipes) and real loopback sockets, on Linux in a container. See [What was verified](#what-was-verified) and [SECURITY.md](SECURITY.md).

## What it does

- **Spawns the server** from a fixed argv (never a shell string) with a minimal environment, its own process group, resource limits and a restart policy; speaks MCP JSON-RPC to it over stdio; stops the server's whole process group on shutdown and when the server exits (so a descendant cannot hold the gateway up). If the gateway itself is killed with SIGKILL only the direct child is killed (Linux), not its descendants: see [SECURITY.md](SECURITY.md).
- **Serves MCP Streamable HTTP** (POST, JSON responses) on a loopback address. Concurrent HTTP requests are mapped to JSON-RPC ids of the gateway's own, so answers cannot cross.
- **Authenticates** with bearer tokens that are stored only as SHA-256 and compared in constant time; per-token scopes and tool lists; per-token rate limit and request size limit; `Host` and `Origin` checks against DNS rebinding.
- **Filters tools**: default-deny `allow`/`deny` globs on `tools/list` and `tools/call`; a `read_only = true` preset that exposes only tools whose names look like reads; per-tool argument rules (length, size, forbidden patterns); caps on results and an optional label prefix.
- **Records everything** in an append-only JSON-lines audit log (token id, method, tool, allowed or denied, duration, sizes; argument values only on request, redacted). An allowed tool call is written down as an *intent* line **before** it is forwarded, and refused with 503 if that line cannot be written; the outcome follows as a second line.
- **Can be switched off at once** with a kill-switch file or a signal (every request gets 503).
- **Has no TLS on purpose**: loopback plus a proxy or tunnel that terminates TLS, or a private network. It refuses to bind a non-loopback address without `--i-know-this-is-not-tls`.

## Quick start

```sh
cargo build --release                           # target/release/mcp-remote-gate (Rust 1.95, see rust-toolchain.toml)

mcp-remote-gate token new --id desktop          # prints the token once, and the [[token]] block to paste
mcp-remote-gate init > gate.toml                # an annotated example; edit [child] and paste the [[token]] block
chmod 600 gate.toml
mcp-remote-gate check --config gate.toml        # validates it and shows what it exposes
mcp-remote-gate tools --config gate.toml        # asks the real server for its tools and shows the verdict on each
mcp-remote-gate run   --config gate.toml        # serves on 127.0.0.1:8787/mcp
mcp-remote-gate selftest                        # proves the whole setup against the bundled fake server
```

The shipped policy is `read_only = true`: sending is off. Turning it on is one line (`read_only = false`), see below and the [handover note](docs/handover-note.md).

## Demo

All of the following is real output, recorded by [`scripts/demo.sh`](scripts/demo.sh) in a container, against the bundled fake "WhatsApp" server (full recording: [`docs/demo-output.txt`](docs/demo-output.txt); the token is masked in the recording, everything else is as printed).

**Create a token** (shown once; the config stores only its hash):

```text
$ mcp-remote-gate token new --id desktop
token: mrg_<the token, masked in this recording>

[[token]]
id = "desktop"
hash = "sha256:…"
scopes = ["tools:list", "tools:call"]
```

**Ask the real server which tools it has, and which the policy exposes:**

```text
$ mcp-remote-gate tools --config gate.toml
server: fake-whatsapp 0.1.0 (protocol 2025-06-18)
policy: read_only = true, allow = 1, deny = 0
  list_chats       exposed
  get_messages     exposed
  search_messages  exposed
  send_message     blocked (read_only)
  delete_chat      blocked (read_only)
  …
12 tools, 3 exposed, 9 blocked
```

**A remote client sees only the read tools, and a send is denied; the server never sees it:**

```text
$ curl -s -H "Authorization: Bearer $TOKEN" -H "Content-Type: application/json" -d '{"jsonrpc":"2.0","id":2,"method":"tools/list"}' http://127.0.0.1:8787/mcp
{"jsonrpc":"2.0","id":2,"result":{"tools":[{"name":"list_chats",…},{"name":"get_messages",…},{"name":"search_messages",…}]}}
[HTTP 200]
$ curl -s … -d '{"jsonrpc":"2.0","id":4,"method":"tools/call","params":{"name":"send_message","arguments":{"to":"alice","text":"hello"}}}' http://127.0.0.1:8787/mcp
{"jsonrpc":"2.0","id":4,"error":{"code":-32003,"message":"the tool \"send_message\" is not allowed by the gateway policy"}}
[HTTP 200]
$ test -e sent.log && cat sent.log || echo "sent.log does not exist: the fake server never received a send"
sent.log does not exist: the fake server never received a send
```

**A wrong token is rejected:**

```text
$ curl -s -H "Authorization: Bearer mrg_wrong..." … -d '{"jsonrpc":"2.0","id":5,"method":"ping"}' http://127.0.0.1:8787/mcp
{"jsonrpc":"2.0","id":null,"error":{"code":-32003,"message":"unauthorized"}}
[HTTP 401]
```

**The audit log has a line per request (two for an allowed tool call: the intent, written before the call runs, and its outcome), the denied send among them, and no token and no argument values:**

```text
{"v":1,"ts":"…","token":"desktop","peer":"127.0.0.1","method":"tools/call","tool":"list_chats","outcome":"started","reason":"intent","duration_ms":0,"request_bytes":92,"response_bytes":0}
{"v":1,"ts":"…","token":"desktop","peer":"127.0.0.1","method":"tools/call","tool":"list_chats","outcome":"allowed","reason":"ok","duration_ms":0,"request_bytes":92,"response_bytes":121}
{"v":1,"ts":"…","token":"desktop","peer":"127.0.0.1","method":"tools/call","tool":"send_message","outcome":"denied","reason":"read_only","duration_ms":0,"request_bytes":121,"response_bytes":123}
{"v":1,"ts":"…","token":null,"peer":"127.0.0.1","method":"http POST","tool":null,"outcome":"denied","reason":"bad_token","duration_ms":0,"request_bytes":0,"response_bytes":76}
```

**The kill switch** (a file; a signal works too): while it exists every request gets 503, and removing it restores service.

```text
$ touch KILL
$ curl -s … -d '{"jsonrpc":"2.0","id":6,"method":"ping"}' http://127.0.0.1:8787/mcp
{"jsonrpc":"2.0","id":null,"error":{"code":-32002,"message":"the gateway is switched off"}}
[HTTP 503]
$ rm KILL
{"jsonrpc":"2.0","id":7,"result":{}}
[HTTP 200]
```

**Enabling sending is one line**, and the gateway warns about it at start:

```text
$ sed -i "s/^read_only = true/read_only = false/" gate.toml
$ mcp-remote-gate run --config gate.toml &
{"jsonrpc":"2.0","id":8,"result":{"content":[{"type":"text","text":"message sent to alice"}]}}
$ cat sent.log
send_message to=alice text=hello
  gate: … WARN every tool of the server is callable, including any that send, write or delete: set read_only = true or add a deny list
```

## The policy in three lines

```toml
[tools]
allow = ["*"]
read_only = true       # reads only. false enables everything that `allow` lets through, sending included.
```

`deny` always wins; a token can carry a narrower `tools = [...]` list, never a wider one; `[[tools.rule]]` bounds what the arguments of a tool may contain. The preset works on tool **names**, so run `mcp-remote-gate tools` against your real server: the gateway cannot tell what a tool does, only what it is called. Details: [docs/configuration.md](docs/configuration.md).

## Security model

The short version of [SECURITY.md](SECURITY.md), which has the threat model, the table of guarantees with the tests that check each one, and the limitations.

| Concern | What the gateway does |
| --- | --- |
| Who may connect | Bearer token (256 bits), SHA-256 only in the config, constant-time lookup, per-token scopes; failed attempts are limited without locking out a valid token |
| DNS rebinding, cross-site requests | `Host` must be listed; any `Origin` header is refused unless listed |
| What a connected client may do | Default-deny tool policy on list and call; `read_only` preset (by tool **name**); argument rules (a speed bump); a call is forwarded only for a name the server itself lists; only `initialize`, `ping`, `tools/list`, `tools/call` exist |
| Floods and slow clients | Strict small HTTP/1.1 parser, a 5 s deadline for the request, size limits, a client without a valid token is refused before its body is read, connection cap (shared by all clients, no per-address limit: let the proxy hold slow clients), per-token rate limit, `max_inflight` |
| A misbehaving server | Per-call timeout and cancellation, bounded lines, crash handling and restart policy (a stalled but alive server is not restarted), resource limits, own process group |
| What leaves in results | `result_max_bytes`, optional `tool_result_prefix`; **no sanitizing of result text** ([docs/prompt-injection.md](docs/prompt-injection.md)) |
| Accountability | Audit log with token id, tool, verdict and sizes, no secrets; every text field escaped (control, C1, bidi, zero-width); the intent of a tool call is written, and checked, before the call runs, and the call is refused if it cannot be; the file is opened without following symlinks, owner-checked and kept 0600; not tamper-evident |
| Emergency | Kill-switch file or SIGUSR1/SIGUSR2; SIGTERM stops the server's whole process group; SIGKILL of the gateway kills only its direct child |
| Transport | No TLS in the process; loopback or a private network behind a TLS-terminating proxy or tunnel ([docs/deployment.md](docs/deployment.md)) |

## Documentation

- [docs/configuration.md](docs/configuration.md): every key, defaults, the audit line, signals, exit codes
- [docs/deployment.md](docs/deployment.md): the supported shapes, proxy and tunnel notes, a systemd unit
- [docs/handover-note.md](docs/handover-note.md): the template to hand to whoever runs it next (restart, rotate a token, enable sending)
- [docs/prompt-injection.md](docs/prompt-injection.md): what a gateway can and cannot do about it
- [docs/adr/](docs/adr/): ten decision records (layering, threads, own HTTP server, one dependency, no TLS, default-deny policy, stateless transport, session sharing, audit log, confined unsafe)
- [SECURITY.md](SECURITY.md), [CHANGELOG.md](CHANGELOG.md), [RELEASING.md](RELEASING.md)

## Architecture

```text
gate-domain   std only, no I/O, no clock: tokens, SHA-256, JSON, JSON-RPC, tool policy, rate limiter,
              redaction, audit record, line framing, Host/Origin policy, restart policy, config model
gate-app      the request handler (checks in a fixed order, one audit record per request) and the upstream
              session (id renumbering, handshake, timeouts, restarts), written against ports
gate-sys      the only unsafe code: process groups, resource limits, signal flags (libc)
gate-infra    adapters: TOML subset parser and config loader, strict HTTP/1.1 server and client, child process,
              audit file, clock, kill switch
gate-fake-mcp a small fake MCP server over stdio (read tools, send and delete tools, tools that misbehave)
gate-cli      the `mcp-remote-gate` binary: run, check, tools, token, selftest, init
```

Dependencies point inward only (`domain <- app <- infra <- cli`). `crates/gate-cli/tests/architecture.rs` enforces it on the source tree: which crate may depend on which, `libc` as the only third-party package (pinned `=0.2.190`), `unsafe` in `gate-sys` only with a SAFETY comment on each use, no files, sockets, processes, environment or clock in the domain and application crates, and lints that deny `unwrap`, `expect`, `panic` and indexing in production code.

Request path: kill switch, path, `Host`, `Origin`, token, rate limit, method, content type, JSON and JSON-RPC shape, then the method: `initialize` and `ping` are answered by the gateway; `tools/list` is forwarded and filtered; `tools/call` goes through scope, tool policy and argument rules before it is forwarded, and the result is capped and labelled on the way back.

## What was verified

Run in a container (Rust 1.95, Debian; `docker/Dockerfile.dev`), no network access during the tests:

| Layer | Tests | What they exercise |
| --- | --- | --- |
| domain | 113 | SHA-256 against NIST vectors, JSON (round trips, hostile input), JSON-RPC, globs, tool policy (including properties: deny wins, a token list never widens), rate limiter with a fake clock, redaction, audit record, line framing, `Host`/`Origin`, restart policy, configuration validation |
| application | 62 | The gateway handler and the upstream session driven through ports with in-memory fakes, a fake clock and a scripted child: auth, policy, limits, kill switch, hostile input (including a property test over random bodies), failure mapping, 64 concurrent calls, crash and restart, timeouts, oversized and rubbish lines |
| adapters | 141 | TOML parser and loader, HTTP server over real loopback sockets (smuggling, folding, bare LF, duplicate lengths, oversized heads and bodies, slow heads and bodies, garbage, connection cap, shutdown), the child adapter with real processes (environment, limits, tree termination), audit file (symlinks, rotation, a simulated full disk, torn lines), kill switch, system crate (process groups, `waitid`, limits, signals), and the whole gateway in front of a real child process (slow, crashing, noisy and oversized behavior, a descendant that holds the pipe, a client that never sends its body) |
| end to end | 31 | The real binary: `token new` to a working gateway, `check`, `tools`, `run` with SIGTERM, SIGINT, SIGUSR1/2 and SIGKILL (the direct child dies), the child's descendants stopped on SIGTERM, refusal of a non-loopback address, bad and group-writable configs, `selftest`, the hash against `sha256sum` |
| architecture | 15 | The dependency and purity rules above |
| shell | 29 | The release scripts (`scripts/test-release.sh`) |

Line coverage per layer, measured with the repository's own script (`scripts/coverage.sh`, rustc's source-based instrumentation; test code and everything after the first `#[cfg(test)]` of a file is excluded; targets: domain ≥ 95, application ≥ 90, overall ≥ 85):

| Layer | Lines | Covered | |
| --- | --- | --- | --- |
| domain | 1794 | 1757 | **97.9 %** |
| application | 1038 | 1007 | **97.0 %** |
| infrastructure (infra, sys) | 1744 | 1615 | **92.6 %** |
| cli | 719 | 667 | **92.8 %** |
| fake server | 270 | 252 | **93.3 %** |
| overall | 5565 | 5298 | **95.2 %** |

Also checked: `cargo clippy --workspace --all-targets -- -D warnings`, `cargo fmt --check`, `cargo check --target aarch64-apple-darwin` (type-checks, not run), the secret scan on the tree and the history.

### What was not verified

- **No real MCP client** (desktop assistants, IDE agents, SDK clients) was used. Whether they accept the JSON-only Streamable HTTP subset, the reduced capabilities and the protocol version handling is untested.
- **No real WhatsApp or other messaging or file-system MCP server** was put behind the gateway; only the bundled fake. Real servers print more, start slower and use more of the protocol (progress, sampling, list changes), and some of that is deliberately dropped (ADR 7).
- **No real TLS proxy or tunnel.** The configuration examples in `docs/deployment.md` and the systemd unit were not run.
- **macOS and Windows.** The code type-checks for macOS; nothing was run there. Windows is not supported.
- **No security audit and no fuzzing campaign.** Hostile-input tests and randomized property tests exist; a dedicated fuzzer was not run.
- Memory limits (`memory_mb`) were checked on Linux only and do not suit runtimes such as Node.

## Limitations

No TLS in the process; no server-sent events, sessions or server-initiated messages; client cancellation is not forwarded; one shared server process for all tokens; the policy sees names, not behavior; the server is not sandboxed beyond resource limits; the audit log is neither tamper-evident nor rotated. The reasons are in the ADRs.

## Dependencies

| Package | Why |
| --- | --- |
| `libc` `=0.2.190` (gate-sys only) | `setrlimit`, `killpg`, `sigaction`, `prctl`, `waitid`, `geteuid` and `O_NOFOLLOW` for resource limits, process groups, signal flags and file checks. It has no dependencies of its own and was published more than 7 days before it was pinned |

SHA-256, the JSON parser and the TOML subset parser are written here and tested against vectors, properties and hostile input (ADR 4). `cargo tree` shows one external package.

## Running the tests

No toolchain is needed on the host. Build the development image once, fetch the dependencies once (this is the only step that needs the network), then run everything in a container without network access:

```sh
docker build -f docker/Dockerfile.dev -t gate-dev docker/
RUN="docker run --rm -v $PWD:/work -v gate-cargo:/cargo -v gate-target:/target -w /work -e CARGO_HOME=/cargo -e CARGO_TARGET_DIR=/target"
$RUN gate-dev cargo fetch --locked
$RUN --network none gate-dev sh scripts/test-layers.sh
$RUN --network none gate-dev sh scripts/coverage.sh
```

`scripts/test-layers.sh` prints a count per layer; `scripts/coverage.sh` prints the table above and fails below the targets; `scripts/demo.sh` records the demo. With a local toolchain the same commands work: `cargo test --workspace`, `cargo clippy --workspace --all-targets -- -D warnings`.

Git hooks (`lefthook install`): a secret scan before each commit and push, and a check of commit messages. CI (`.github/workflows/ci.yml`) runs format, clippy, the tests, the coverage gate, the release-script tests and the secret scan; actions are pinned by commit SHA and dependabot waits 7 days before proposing a version.

## License

MIT, Copyright (c) 2026 Kien Phan. See [LICENSE](LICENSE).
