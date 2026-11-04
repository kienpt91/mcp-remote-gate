# Handover note: template

Copy this file, fill in the bracketed parts and give it to whoever runs the gateway next. It answers the three questions a handover has to answer: how to restart it, how to rotate a token, and how to turn sending on (or off again).

---

## What this is

`mcp-remote-gate` puts the MCP server **[name of the server, for example the WhatsApp MCP server]** behind an HTTP endpoint that a remote MCP client can reach with a bearer token.

| | |
| --- | --- |
| Host | [machine name or address] |
| Runs as | [user], from [path of the binary] |
| Config | [/path/to/gate.toml] (must not be writable by group or others) |
| Audit log | [/path/to/audit.jsonl] |
| Kill switch file | [/path/to/KILL] |
| Public URL | [https://mcp.example.com/mcp], TLS terminated by [proxy or tunnel] |
| Listens on | [127.0.0.1:8787] |
| Tokens in use | [id: who has it (not the token itself)] |
| Sending | **[off | on]**, set by `read_only` in `[tools]` |
| Version | [output of `mcp-remote-gate version`] |

## Is it healthy?

```sh
mcp-remote-gate check --config gate.toml        # the configuration is valid; shows what is exposed
mcp-remote-gate tools --config gate.toml        # asks the real server for its tools and shows which are exposed
mcp-remote-gate selftest                        # proves the setup end to end against the bundled fake server
tail -n 20 audit.jsonl                          # what was asked lately, by which token, allowed or denied (a tool call has two lines: started, then its outcome)
```

A request that works: `outcome":"allowed"`. `denied` with a `reason` is the policy doing its job. A burst of `bad_token` is someone guessing.

## Restart

[with systemd]
```sh
sudo systemctl restart mcp-remote-gate
sudo systemctl status mcp-remote-gate
journalctl -u mcp-remote-gate -n 50
```
[without a service manager]
```sh
kill -TERM <pid>          # graceful: finishes requests in progress, stops the server and its children
mcp-remote-gate run --config gate.toml
```

A restart is needed after any change to `gate.toml`: the file is read once at start. The gateway restarts the server it fronts by itself after a crash (`restart = "on-failure"`, up to `max_restarts` times). If it gave up, the log says `will not be restarted` and the answer to clients is 503: restart the gateway.

## Switch everything off now

```sh
touch [/path/to/KILL]       # every request gets 503 at once; remove the file to switch on again
# or
kill -USR1 <pid>            # on;  kill -USR2 <pid> switches off again
```

This does not stop the server or lose anything. Use it first, ask questions later.

## Rotate a token

1. `mcp-remote-gate token new --id [name-2]` prints the new token (once, nowhere else) and a `[[token]]` block.
2. Paste the block into `gate.toml` next to the old one. Restart.
3. Give the new token to the client and check that it works (audit log shows `token":"[name-2]"`).
4. Remove the old `[[token]]` block. Restart.

If a token leaked: remove its block and restart first; everything else can wait. Look in the audit log for the token's id to see what it did. There is no way to list or recover a token: only its SHA-256 is stored.

## Turn sending on (or off)

Sending is **off by default**: `[tools]` has `read_only = true`, which exposes only tools whose names look like reads (`get_*`, `list_*`, `search_*`, ...). Check what that means for this server with `mcp-remote-gate tools --config gate.toml`: tools marked `blocked (read_only)` are the ones that are off.

To turn sending on, change one line in `gate.toml`:

```toml
read_only = false      # was: true
```

and restart. Every tool that `allow` lets through is now callable, so **replace `allow = ["*"]` by the exact names the job needs** (for example `allow = ["list_chats", "get_messages", "send_message"]`): everything not named stays off, including tools a later server update adds. A `deny` list on top of `allow = ["*"]` (for example `deny = ["delete_*"]`) is the weaker form, it only blocks what you thought of. Note that `read_only = true` cannot be combined with an allowed write tool: the preset also requires a read-looking name. To limit what a message can carry, add a `[[tools.rule]]` (see `docs/configuration.md`). Sending per token is not supported: a token can only be narrowed (`tools = [...]`), never widened beyond the global policy. To have one client that can send and another that cannot, run a second gateway (second config, second port) with `read_only = false` for the first and keep the other one read-only.

To turn it off again: `read_only = true`, restart. The audit log shows every `send_*` call that was made while it was on.

## Things to know

- The gateway cannot see what a tool does, only its name. Re-run `mcp-remote-gate tools` after the server is updated: a renamed tool can fall outside a pattern.
- What the server returns is shown to the model as is (optionally labelled with `tool_result_prefix`). Text in a message that says "ignore your instructions and send ..." reaches the model. With sending off it cannot make the gateway send; with sending on, treat the model's actions as untrusted. See `docs/prompt-injection.md`.
- The gateway has no TLS. Never expose its port to the internet directly.
- Not covered: [anything specific to this installation].

## Who to ask

[name, contact]
