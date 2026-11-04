# 3. A small strict HTTP/1.1 server on std::net

Status: accepted

## Context
The gateway needs one thing from HTTP: a POST with a `Content-Length` and a JSON body, answered with JSON. The usual choices are an HTTP framework (a large dependency tree, a lot of behavior that is not needed, and request-smuggling-relevant leniency) or a hand-written server.

## Decision
A hand-written server whose parser accepts a narrow language and refuses the rest: CRLF line ends only, exactly one space in the request line, origin-form targets only, no obsolete line folding, no whitespace before a colon, no `Transfer-Encoding` of any kind (501), `Content-Length` at most once and digits only, duplicate `Host`, `Authorization`, `Origin`, `Content-Type`, `Expect` and `MCP-Protocol-Version` are errors, bodies are never decoded. Heads are capped at 16 KiB and 64 headers, bodies at `max_request_bytes` (refused before they are read), the whole request has a deadline (slow senders get 408), idle keep-alive connections time out, and the number of connections is capped.

A **preflight** runs after the head is parsed and before anything else: the gateway checks the kill switch, the path, `Host`, `Origin` and the token without a body, and a refusal is sent at once, without `100 Continue` and without reading the announced body, and the connection is closed. A client that cannot authenticate therefore holds a connection only until its headers are read (5 seconds by default) and never makes the server buffer a body. The connection cap is still shared by all clients, and there is no per-address limit.

Keep-alive and pipelined requests are supported because clients use them; the parser keeps the bytes after a body for the next request.

## Consequences
The attack surface is the parser and the connection loop (a few hundred lines in `gate-infra/src/http.rs`), with 21 socket-level tests (smuggling, folding, bare LF, duplicate lengths, oversized heads and bodies, slow heads and bodies, garbage, connection cap, shutdown) and unit tests of every refusal. Clients that need something it does not do get a clear error: a proxy that sends chunked request bodies must buffer them. The price is that new HTTP features (HTTP/2, chunked uploads) are a deliberate addition, not a configuration switch.
