# 8. One shared session with the child, with ids of the gateway's own

Status: accepted

## Context
A stdio MCP server has one client: the process that owns its pipes. Many HTTP requests, possibly from several tokens, arrive concurrently and each needs its own answer.

## Decision
The gateway is the only JSON-RPC client of the child. Every call is renumbered with an id from a counter of the gateway's own; the pending table maps that id to the waiting thread, and the client's id is put back on the answer. Clients cannot collide with each other or choose an id that matches another call. Calls wait on a one-shot channel with a timeout; on timeout the entry is removed, `notifications/cancelled` is sent to the child, and a late answer is counted and dropped. At most `max_inflight` calls wait at once (429 beyond), and writes to the child go through a bounded queue and a writer thread, so a child that stops reading its input cannot block the gateway's threads.

When the child ends, every call in flight fails at once with "unavailable"; the restart policy decides whether to start it again (exponential backoff, a limit, a counter that resets after a run of a minute), and each start repeats the handshake before calls are accepted. Lines from the child are bounded; an oversized line is dropped, and when its beginning shows a numeric `"id"` the call it answers fails at once instead of timing out. Lines that are not JSON-RPC, answers with unknown ids, and requests the child makes of its client are counted and answered or dropped without disturbing the session.

## Consequences
Concurrent clients share one server process, so a slow tool delays nothing but its own caller, but a tool with side effects is shared state: two tokens act on the same server. A child that serializes its handling serializes the calls. Per-client isolation would need one child per token, which is not implemented.
