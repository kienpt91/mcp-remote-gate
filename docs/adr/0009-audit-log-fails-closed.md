# 9. An append-only audit log that never holds secrets, records the intent first, and fails closed

Status: accepted

## Context
Someone has to be able to answer "what did the remote client do?" and "who tried to get in?". The log must not become the place where the secrets leak, and a tool call that changes the outside world must not happen without a record of it.

## Decision
**What a line holds.** One JSON line per request: time, token id (never the token), peer address, method, tool name, `started`/`allowed`/`denied`/`error`, a stable reason code, duration, request and response sizes. Values of arguments are not written unless `log_arguments = true`; then they are redacted (sensitive key names, credential-shaped strings, known key prefixes) and cut to a length, and the documentation says the redaction is heuristic. Every text field is passed through the same escaping as the log lines on stderr (control characters including C1, line separators, bidirectional controls, zero-width and other format characters) and is cut to 128 characters, so nothing a client or the server wrote can forge a line or drive a terminal.

**Intent first.** For an allowed `tools/call` the gateway writes a record with `outcome: started`, `reason: intent` and checks that the write succeeded **before** it forwards the call. If the write fails, the call is not forwarded and the client gets 503. The completion record (`allowed` or `error`) follows when the call ends. A crash of the gateway or of the machine in the middle of a call therefore leaves the intent. Requests that never reach the server (denied, malformed, listing, ping) have a single record.

**Failures are not forgotten.** The file adapter keeps a failed state after any failed write. A later small record that would fit does not clear it: recovery requires a marker line, bigger than the record that failed (at least 4 KiB), to be written and synced to disk. A line that was half written is ended with a newline before anything follows it. Lines about unauthenticated requests are rate limited (60 per minute, burst 30) and the number dropped is reported on the next line that is written, so a flood of bad requests cannot fill the disk.

**The file is what the path says.** It is opened with `O_NOFOLLOW`, must be a regular file owned by the user running the gateway, is created with mode 0600, and a looser mode on an existing file is tightened (reported at start). Before every record the open file is compared with the path (device and inode): if it was moved away (rotation by rename) or deleted, the path is opened again and logging continues there; if the path now holds a symbolic link or anything that cannot be opened safely, the record fails and the call is refused.

## Consequences
The guarantee is: *an allowed tool call reaches the server only after its intent was written to the log file.* It is not tamper evidence: a process that can write to the file or its directory can edit it. Lines are not synced one by one (a crash of the gateway keeps the intent, a power cut may not). Rotation by copy and truncate can lose lines written between the copy and the truncate. A hash chain would make edits detectable and is a possible addition. The cost of the design is two lines per tool call and one extra `write` before the call.
