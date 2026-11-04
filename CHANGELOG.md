# Changelog

All notable changes are listed here. The project follows [Semantic Versioning](https://semver.org/).

## [0.1.0] - 2026-11-04

First version.

### Added

- `mcp-remote-gate run --config gate.toml`: starts a stdio MCP server as a child process (fixed argv, minimal environment, own process group, resource limits, restart policy) and serves the MCP Streamable HTTP transport in front of it (POST with JSON responses) on a loopback address by default.
- Authentication: bearer tokens (`mrg_` and 256 bits of entropy) stored only as SHA-256, compared in constant time; per-token scopes (`tools:list`, `tools:call`) and optional per-token tool lists that can only narrow the policy; `mcp-remote-gate token new` and `token hash`.
- Defense in depth at the HTTP layer: `Host` and `Origin` checks against DNS rebinding, per-token rate limit, request size limit, a global limit on failed authentications, request deadlines, connection cap, a strict HTTP/1.1 parser (no `Transfer-Encoding`, no duplicate lengths, no folding).
- Tool policy: default-deny `allow` and `deny` globs on `tools/list` and `tools/call`, a `read_only` preset with configurable read patterns, per-tool argument rules (size, string length, forbidden patterns).
- Results: `result_max_bytes` (text is cut to fit), `tool_result_prefix` label, bounded lines from the server, the server's `instructions` are not forwarded.
- Append-only JSON-lines audit log (token id, method, tool, outcome, reason, duration, sizes; arguments only with `log_arguments`, redacted); tool calls are refused while the log cannot be written.
- Kill switch by file or by SIGUSR1 and SIGUSR2; graceful shutdown on SIGTERM and SIGINT that stops the server's process group.
- Refusal to listen on a non-loopback address without `--i-know-this-is-not-tls`.
- `mcp-remote-gate check` (validate and show what is exposed), `tools` (the real server's tools and the policy's verdict on each), `selftest` (end-to-end proof against the bundled fake server), `init` (annotated example config).
- Documentation: configuration reference, deployment shapes, handover note template, prompt injection note, ten ADRs, SECURITY.md with the threat model.
- Tests per layer (domain, application with fakes, adapters over real sockets and processes, end to end through the binary, architecture rules), a coverage script with enforced targets, secret scanning in hooks and CI, a tag-triggered release workflow with checksums and a provenance attestation.

### Not in this version

TLS in the process, server-sent events and sessions, server-initiated messages, per-token isolation of the upstream server, audit log rotation.
