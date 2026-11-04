# 9. An append-only audit log that never holds secrets, and fails closed

Status: accepted

## Context
Someone has to be able to answer "what did the remote client do?" and "who tried to get in?". The log must not become the place where the secrets leak.

## Decision
One JSON line per request: time, token id (never the token), peer address, method, tool name, `allowed`/`denied`/`error`, a stable reason code, duration, request and response sizes. Values of arguments are not written unless `log_arguments = true`; then they are redacted (sensitive key names, credential-shaped strings, known key prefixes) and cut to a length, and the documentation says the redaction is heuristic. Anything a client or the server wrote that reaches a log (tool names, methods, stderr of the child) is escaped so it cannot forge a line or drive a terminal; client-supplied fields are also cut to 128 characters.

The file is opened append-only with mode 0600 and written with one `write` per record. Lines about unauthenticated requests are rate limited (60 per minute, burst 30) and the number dropped is reported on the next line that is written, so a flood of bad requests cannot fill the disk. If a write fails, `tools/call` is refused with 503 until a write succeeds: the gateway does not run tools without a trail.

## Consequences
Not tamper-evident: a process with write access can edit the file (append-only is a property of how the gateway opens it, not of the file system; `chattr +a` or shipping lines off the host would add it). No rotation and no `fsync` per line. A hash chain would make edits detectable and is a possible addition.
