# Configuration reference

`gate.toml` is read once at start. `mcp-remote-gate init` prints an annotated example, `mcp-remote-gate check --config gate.toml` validates a file and shows what it exposes, and `mcp-remote-gate tools --config gate.toml` shows, for the real server, which tools the policy lets through.

Rules that apply to the whole file:

- **Unknown keys are errors.** A typo in `allow` or `deny` must never silently loosen a rule. Every problem is reported in one pass, each with its key (`server.listen`, `token[1].hash`).
- **The file must not be writable by group or others** (`chmod go-w gate.toml`), because whoever can edit it can widen the tool policy. It may be readable: it holds only token hashes.
- **Relative paths** (`audit.path`, `server.kill_switch_file`, `child.cwd`, and a program that starts with `./` or `../`) are taken relative to the directory of the file.
- **Only a TOML subset is read** (see ADR 4): tables, arrays of tables, strings, integers, booleans, arrays of scalars and single-line inline tables. Floats, dates, multi-line strings and dotted keys are rejected with a line number.
- The file is at most 256 KiB.

## `[server]`

| Key | Default | Meaning |
| --- | --- | --- |
| `listen` | `"127.0.0.1:8787"` | An IP address and a port, no host names (no DNS lookup decides where the gateway listens). Any address that is not a loopback address needs `--i-know-this-is-not-tls` on the command line and `allowed_hosts`. |
| `endpoint` | `"/mcp"` | The path that serves MCP. Any other path is 404. |
| `allowed_hosts` | `127.0.0.1:PORT`, `localhost:PORT`, `[::1]:PORT` for a loopback listener | `Host` header values that are accepted (DNS rebinding defense). Compared after lowercasing, exactly: the port counts. Required when `listen` is not a loopback address. Behind a proxy or tunnel add the public name, for example `["mcp.example.com", "127.0.0.1:8787"]`. |
| `allowed_origins` | `[]` | `Origin` values that are accepted, as `https://host[:port]`. Native clients send no `Origin`; a request that has one is refused unless it is listed. The gateway sends no CORS headers, so a listed origin helps non-browser clients only. |
| `max_request_bytes` | `1048576` | Largest request body (1 KiB to 16 MiB). A larger `Content-Length` is answered with 413 before the body is read. |
| `request_timeout_ms` | `30000` | How long one call may wait for the upstream server (100 ms to 10 min). |
| `header_timeout_ms` | `10000` | Time a client has to deliver a complete request, head and body, once it started. A client that sends a byte a second is cut off with 408. |
| `idle_timeout_ms` | `15000` | How long an idle keep-alive connection is kept. |
| `max_connections` | `64` | Simultaneous connections; more get 503. |
| `kill_switch_file` | none | While this file exists, every request is answered with 503. Signals work as well (below). |

## `[child]`

| Key | Default | Meaning |
| --- | --- | --- |
| `command` | required | The program and its arguments as a list. Never a shell string: the gateway does not run a shell. |
| `cwd` | the gateway's | Working directory of the server. |
| `inherit_env` | `["PATH"]` | Names of variables copied from the gateway's environment. The child gets nothing else of it. |
| `[child.env]` | empty | Variables set for the child; they win over inherited ones. This is where the server's own credentials go. |
| `restart` | `"on-failure"` | `"never"`, `"on-failure"` or `"always"`. |
| `max_restarts` | `5` | Consecutive failed runs before the gateway gives up (a run that stays up for a minute resets the count). |
| `restart_backoff_ms` | `500` | First delay before a restart; it doubles up to 30 s. |
| `startup_timeout_ms` | `15000` | Time the server has to answer the `initialize` handshake. `run` does not listen until it has. |
| `shutdown_grace_ms` | `3000` | After SIGTERM to the process group, how long before SIGKILL. |
| `max_line_bytes` | `4194304` | Longest line accepted from the server's standard output (4 KiB to 64 MiB). A longer line is dropped; if its beginning shows whose answer it was, that call fails at once with a "too large" error instead of waiting for the timeout. |
| `memory_mb` | none | Address-space limit (`RLIMIT_AS`). Enforced on Linux only. Runtimes that reserve a large address range, Node among them, do not start under it; use the other limits for those. |
| `cpu_seconds`, `max_open_files`, `max_file_mb` | none | `RLIMIT_CPU`, `RLIMIT_NOFILE`, `RLIMIT_FSIZE`, applied before the program starts. |

## `[tools]`: the policy

The rule is default-deny. A tool is exposed and callable when it matches `allow`, does not match `deny`, and (with `read_only`) looks like a read.

| Key | Default | Meaning |
| --- | --- | --- |
| `allow` | `[]` | Glob patterns (`*` any run of characters, `?` one character, case-sensitive). **Empty means nothing is allowed**, except that `read_only = true` with an empty `allow` allows the read patterns. |
| `deny` | `[]` | Patterns that are never exposed. Deny always wins. |
| `read_only` | `false` | The preset: also require the name to match `read_patterns`. This is the one-line switch for "sending disabled". |
| `read_patterns` | `get_*`, `list_*`, `read_*`, `search_*`, `find_*`, `fetch_*`, `describe_*`, `query_*`, `show_*`, `view_*`, `count_*`, `lookup_*` | What counts as a read. Names are the only signal: the gateway cannot tell what a tool does, so check the real names with `mcp-remote-gate tools`. |
| `[[tools.rule]]` | none | Limits on the arguments of the tools matching `tool`: `max_arg_bytes` (serialized `arguments`), `max_string_len` (characters, for every string value and object key) and `forbid_values` (glob patterns; a string value or key that matches is refused). A call that breaks a rule is refused before it reaches the server and the refused value is never echoed in the answer (it is in the audit log only when `log_arguments` is on, redacted). |

Examples:

```toml
# reads only (the shipped default): sending is off
[tools]
allow = ["*"]
read_only = true

# the same server with sending on: change one line
[tools]
allow = ["*"]
read_only = false

# everything except what can change the outside world, spelled out
[tools]
allow = ["*"]
deny = ["send_*", "delete_*", "post_*", "update_*"]

# sending allowed, but with limits on what a message can carry
[tools]
allow = ["list_*", "get_*", "send_message"]
[[tools.rule]]
tool = "send_message"
max_string_len = 500
forbid_values = ["*://*"]
```

## `[limits]`

| Key | Default | Meaning |
| --- | --- | --- |
| `requests_per_minute` | `120` | Per token, as a token bucket. Over the limit: 429 with `Retry-After`. |
| `burst` | `20` | Bucket size. |
| `failed_auth_per_minute` | `30` | Requests with a bad or missing token that are answered 401 per minute, then 429. This is not per address (behind a tunnel every client has the same address), and a valid token is never locked out by it. Audit lines of unauthenticated requests are limited too, and the number dropped is reported on the next line. |
| `max_inflight` | `16` | Calls waiting for the server at the same time; more get 429. |
| `result_max_bytes` | none | Cap on a `tools/call` result (1 KiB to 64 MiB). Text is cut to fit and a marker item is added; a result that cannot be cut (an image, structured content) is refused with a "too large" error. |
| `tool_result_prefix` | none | Text put in front of every text item of a result, for example `"[tool output, untrusted] "`. A label for the model; see `docs/prompt-injection.md` for what it can and cannot do. |

## `[audit]`

| Key | Default | Meaning |
| --- | --- | --- |
| `path` | `"audit.jsonl"` | Append-only JSON lines, created with mode 0600. |
| `log_arguments` | `false` | Also write the arguments of `tools/call`, redacted (sensitive key names and credential-shaped strings) and cut to `arguments_max_chars`. Redaction is heuristic: treat the file as sensitive anyway. |
| `arguments_max_chars` | `512` | |

A line has `v`, `ts`, `token` (the token id, `null` when the request was not authenticated), `peer`, `method`, `tool`, `outcome` (`allowed`, `denied`, `error`), `reason`, `duration_ms`, `request_bytes`, `response_bytes`, and `arguments` and `suppressed` when they apply. Reasons: `ok`, `bad_token`, `missing_token`, `malformed_token`, `host_rejected`, `origin_rejected`, `rate_limited`, `kill_switch`, `not_in_allowlist`, `denylist`, `read_only`, `token_tools`, `scope_missing`, `argument_forbidden`, `argument_string_too_long`, `arguments_too_large`, `bad_params`, `bad_json`, `bad_jsonrpc`, `method_not_allowed`, `upstream_unavailable`, `upstream_error`, `timeout`, `busy`, `result_too_large`, `audit_unavailable` and the HTTP format refusals.

If the audit file cannot be written (disk full), tool calls are refused with 503 until it can, instead of running without a trail. The file is not rotated by the gateway: use `logrotate` with `copytruncate`, or stop the gateway, move the file and start it again.

## `[[token]]`

| Key | Default | Meaning |
| --- | --- | --- |
| `id` | required | 1 to 64 characters of `[A-Za-z0-9_.-]`. This is what the audit log shows. |
| `hash` | required | `sha256:` and 64 hex digits, from `mcp-remote-gate token new` or `token hash`. |
| `scopes` | both | `"tools:list"` and/or `"tools:call"`. |
| `tools` | none | Patterns that narrow the global policy for this token: it sees and calls only tools that match one of them and also pass the global policy. It can remove tools, never add them. |

`mcp-remote-gate token new --id NAME [--scopes ...] [--tools ...]` prints the token once and the block to paste. To rotate: create a new token, add its block, give the new token to the client, remove the old block, restart (see the handover note).

## Signals and exit codes

| Signal | Effect |
| --- | --- |
| SIGTERM, SIGINT | Graceful shutdown: stop accepting, let requests in progress finish (5 s), terminate the server's process group (SIGTERM, then SIGKILL after `shutdown_grace_ms`). Exit status 0. |
| SIGUSR1 / SIGUSR2 | Engage / release the kill switch (503 for every request). |

Exit status: `0` success, `1` failure at run time (the server did not start, the port is taken, a selftest failed), `2` usage or configuration error (including a non-loopback address without the flag).
