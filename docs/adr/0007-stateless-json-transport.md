# 7. Streamable HTTP without sessions and without server-sent events

Status: accepted

## Context
The MCP Streamable HTTP transport lets a server answer a POST with JSON or with an SSE stream, offer a GET stream for server-initiated messages, and assign a session id. A server may implement as little of that as it likes: JSON responses are allowed, and a server that has no stream answers GET with 405.

## Decision
The gateway answers every POST with a JSON body (or 202 for a notification or a response), answers GET and DELETE with 405 and `Allow: POST`, and keeps no session. It performs the `initialize` handshake with the upstream server itself, once per start of the child, and answers clients' `initialize` from that, repeating the server's protocol version and a reduced capability set (tools only, no `listChanged`). `MCP-Protocol-Version` is checked for shape only.

Requests that the upstream server makes of its client (sampling, roots) are answered with a method-not-found error by the gateway; notifications from the server (log messages, progress, list changes) are counted and dropped.

## Consequences
The implementation is small and each request is independent, which suits a shared child and a stateless proxy. What does not work: servers that need sampling or roots, progress notifications, clients that insist on a GET stream, and cancelling a call from the client (a client's `notifications/cancelled` is accepted and ignored; the gateway cancels the upstream call itself when its own timeout expires). SSE would be additive later: a POST answered by a one-event stream. It is left out because it was not needed for the use case and every extra path is attack surface.
