# 6. A default-deny tool policy with a read-only preset by name

Status: accepted

## Context
The point of the gateway is that a remote model cannot make the local server do things the owner did not want, above all sending messages. The gateway sees tool names and arguments, nothing about what a tool does.

## Decision
A tool is callable only if it matches `allow`, does not match `deny` (deny always wins) and, with `read_only = true`, also matches `read_patterns` (`get_*`, `list_*`, `search_*`, ...). With an empty `allow`, `read_only = true` allows the read patterns, so the shortest safe configuration is one line. The same decision filters `tools/list` (blocked tools are not shown) and guards `tools/call` (a blocked tool is refused before the server sees it), because a model can call a tool that was never listed. Patterns are globs (`*`, `?`) matched in linear time. A token can carry a narrower list; it can never widen the policy (property-tested). `[[tools.rule]]` bounds the arguments of matching tools.

A `tools/call` is additionally forwarded only if the server itself lists a tool with exactly that name. The gateway fetches the server's tool list on first use (following the pagination cursors, at most 20 pages), keeps it for a minute, and fetches it again when it sees a name that is not in it, at most once every five seconds. This closes the case in which a lenient server normalises names (it would run `Send_Message` as `send_message`) and a denylist such as `deny = ["send_*"]` does not match the variant. Names with whitespace or invisible format characters are refused outright. The default read patterns leave out `query_*` and `fetch_*`, which can run arbitrary work (`query_sql`, `fetch_and_post`).

Methods other than `initialize`, `ping`, `tools/list` and `tools/call` (resources, prompts, logging, completion, sampling) are not available through the gateway at all: they would be paths around the tool policy.

## Consequences
"Sending disabled by default, one line to enable it" is `read_only = true` and `read_only = false`. The weakness is the name: a write tool called `get_and_delete` passes the preset, and a read tool called `fetch` is blocked if it is not in the patterns. A denylist is the weaker form of the policy (everything not named passes); an allowlist of exact names with `read_only = false` is the stronger one, and the documentation recommends it for servers whose tools you have not read. `mcp-remote-gate tools` shows the verdict for the real tool names so that this is checked, not assumed, and the documentation says so. The annotations a server may attach to its tools (`readOnlyHint`) are not trusted: they are the server's own claims.
