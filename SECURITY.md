# Security

`mcp-remote-gate` is a portfolio project. **It has not been audited and makes no production claims.** It sits in front of a program that can act for you (read and send your messages, touch your files), so read this file before pointing it at anything you care about.

## Reporting a vulnerability

Please use GitHub's private vulnerability reporting: on the repository page open **Security**, then **Report a vulnerability**. If that is not available, write to kienphan.dev@gmail.com. Do not open a public issue for a vulnerability. This is a small project: expect a reply within a few days, not an SLA.

## Platforms

Linux is what the tests, the coverage numbers and the demo were produced on (in a container). The code also type-checks for `aarch64-apple-darwin` (`cargo check --target aarch64-apple-darwin`), but nothing was run on macOS: there `RLIMIT_AS` is best effort, the "child dies with the gateway" setting does not exist, and some tests read `/proc`. Windows is not supported (process groups, signals, Unix permissions).

## What was and was not verified

Verified by the test suite: the behavior described below, against a fake MCP server (a real child process speaking JSON-RPC over pipes) and real loopback sockets. **Not tested: any real MCP client application, any real messaging or file-system MCP server, any real TLS proxy or tunnel, any real model.** The gateway follows the Streamable HTTP transport as written in the specification (JSON responses only); whether a given client accepts that has not been checked. The proxy and service snippets in `docs/deployment.md` were not run.

## Threat model

| Party | Trust |
| --- | --- |
| The operator, and `gate.toml` | Trusted. The file is code-like: it decides the policy and names the program to run. The gateway refuses a file that group or others can write. |
| A remote MCP client with a valid token | Trusted **only up to its scopes and the tool policy**. Assume the model behind it can be manipulated (prompt injection) and the token can leak: the policy is the control, not the client's good behavior. |
| Anyone else with a network path to the gateway | Untrusted. Gets nothing without a token; costs are bounded by the connection cap, the request limits, the deadlines and the failed-authentication limit. |
| A web page in a browser on the same machine or network (DNS rebinding, cross-site requests) | Untrusted. Refused by the `Host` and `Origin` checks. |
| The upstream MCP server | Its code runs with the gateway's user permissions and is **not sandboxed** (resource limits and a process group only). Its output is untrusted: tool results, tool descriptions and log lines can contain anything. |
| The TLS-terminating proxy or tunnel | Trusted with everything in plain text, including the bearer token and every result. |
| Other users on the machine | Untrusted. The audit file is created 0600, the config must not be writable by them. Anyone on the machine can connect to the loopback port; they still need a token. |
| Other processes of the same user | Not defended against. They can do what the operator can (read the config, signal the gateway, read the audit log). |

## What the design guarantees, and where it is tested

| Property | How | Tests |
| --- | --- | --- |
| Only a configured token passes | Bearer token; `mrg_` + 256 bits of entropy; only its SHA-256 is stored; the presented token's digest is compared in constant time with every configured hash, without stopping at a match | `gate-domain` auth and `ct_eq` tests (including a randomized property), gateway `authentication_failures`, e2e token flow |
| A token is never stored, logged or echoed | Config has hashes only; the audit log has the token id; a presented token appears in no response, log or audit line | gateway `authentication_failures`, adapters `the_audit_log_tells_the_story_without_secrets`, selftest |
| Wrong `Host` or any unlisted `Origin` is refused before authentication | Exact, case-insensitive `Host` list; `Origin` refused unless listed | `hostcheck` tests, gateway `host_and_origin_checks_come_before_authentication`, selftest |
| Guessing tokens is expensive and cannot lock out the owner | 256-bit tokens; bad tokens get 401 then 429 after `failed_auth_per_minute`, a valid token is never limited by it; audit lines of unauthenticated requests are throttled | gateway and adapters flood tests |
| A tool that is not allowed never runs | Default-deny policy; deny wins; `read_only` preset; the same decision filters `tools/list` and guards `tools/call`; a token can only narrow it | `policy` unit and property tests, gateway tests (the fake upstream sees no call), adapters (the fake server's record of writes stays empty), selftest, e2e `tools` |
| Other methods (resources, prompts, sampling, ...) are not a way around the policy | Only `initialize`, `ping`, `tools/list` and `tools/call` are available | gateway `methods_other_than_tools_are_not_available`, adapters |
| Arguments of a call can be bounded | `[[tools.rule]]` length, size and forbidden patterns, checked before the call | `policy` tests, gateway and adapters argument-rule tests |
| Request smuggling and parser differentials | Strict HTTP/1.1 parser, `Content-Length` only, duplicates refused, JSON that two parsers could read differently is refused (duplicate keys, lone surrogates, deep nesting) and every message is re-serialized before it is forwarded | `http` unit tests, `tests/http_server.rs`, `json` tests, gateway property test |
| Slow or oversized clients cannot hold or flood the gateway | Deadline for the whole request, 16 KiB heads, body limit checked before reading, connection cap, idle timeout, per-token rate limit, `max_inflight` | `tests/http_server.rs`, gateway and adapters rate-limit tests |
| Concurrent calls cannot see each other's answers | Ids of the gateway's own, a pending table, one-shot channels | upstream session tests (64 threads), adapters concurrency test |
| A misbehaving server cannot wedge the gateway | Per-call timeout with cancellation, bounded lines, crash handling with restart policy, bounded write queue | upstream session tests, adapters tests with a slow, crashing, noisy and oversized child |
| Results are bounded | `result_max_bytes`, `max_line_bytes`, optional label prefix | `mcp` tests, adapters `big_results_are_cut_and_labelled` |
| Nothing a client or the server wrote can forge or corrupt a log | Control characters, bidi and zero-width marks are escaped; fields are cut | `sanitize` and `audit` tests, adapters noisy-child test |
| Tool calls leave a trail or do not happen | Audit write failure makes `tools/call` fail with 503 | gateway `when_the_audit_log_cannot_be_written...` |
| The kill switch works at once | A file or a signal, checked before anything else; an unreadable location counts as engaged | adapters and e2e kill switch tests, `system` tests |
| Stopping the gateway stops the server and everything it started, even after SIGKILL of the gateway (Linux) | Process group, SIGTERM then SIGKILL, `PR_SET_PDEATHSIG` | `gate-sys` and `child` tests, e2e shutdown tests |
| No `unsafe` outside one 180-line crate; no `unwrap`/`expect`/`panic`/indexing in production code | Workspace lints and the architecture test | `tests/architecture.rs` |
| No credentials in the repository | `scripts/secret-scan.sh` in the pre-commit and pre-push hooks and in CI (tree and history); key-shaped strings in tests are built at run time | CI `secret-scan` job |

## Known limitations and non-goals

- **No TLS.** Never expose the port to the internet directly (ADR 5).
- **Prompt injection is not solved here**, and cannot be by a gateway: results are passed to the model as the server wrote them (`docs/prompt-injection.md`).
- **The policy sees names.** A write tool with a read-looking name passes `read_only`. Check the real tool names with `mcp-remote-gate tools`; consider `allow` lists instead of the preset for servers you do not know.
- **The upstream server is not sandboxed.** The gateway limits which tools can be called, not what the server can do when it runs. Run it as a user (or in a container) that has only the access it needs.
- **One shared server for all tokens.** Tokens are not isolated from each other in what they can do through the server.
- **The audit log is not tamper-evident, is not rotated and is not synced per line.**
- **No per-address rate limiting**: behind a tunnel every client has the address of the tunnel. The failed-authentication limit is global for that reason.
- **No SSE, no sessions, no server-initiated messages** (ADR 7); client cancellations are not forwarded.
- **Token hashes are plain SHA-256**, which is right for 256-bit random tokens and wrong for passwords. Do not put a human-chosen secret in `hash`.
- Timing: the constant-time comparison covers the hash comparison. The gateway does not claim that the rest of the request path takes the same time for every input.
