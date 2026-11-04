# 1. A layered cargo workspace with a std-only domain, enforced by a test

Status: accepted

## Context
The security rules of a gateway (who may call which tool, what a request may carry, when to refuse) should be readable and testable without sockets, processes or clocks. The code that touches sockets, processes and the operating system is where bugs and attacks live, and it should be small and kept apart.

## Decision
Six crates with a one-way dependency rule: `gate-domain` (std only: tokens, policy, rate limiter, JSON, JSON-RPC, redaction, configuration model) <- `gate-app` (the request handler and the upstream session, written against ports) <- `gate-infra` (TOML, HTTP server, child process, audit file, clock) <- `gate-cli`. `gate-sys` holds the only `unsafe` code, and `gate-fake-mcp` is a small fake server used by the selftest and the tests. The domain reads no clock and no entropy; time and randomness reach it as arguments, so the rate limiter and the audit timestamps are tested with a fake clock.

`crates/gate-cli/tests/architecture.rs` checks the rule on the source tree: which crate may depend on which, the closed list of third-party crates, `unsafe` in one crate only (with a SAFETY comment on each use), no files, sockets, processes, environment, clock or terminal in the pure layers, and the lint configuration that denies `unwrap`, `expect`, `panic` and indexing in production code.

## Consequences
The domain is covered by fast tests and the application layer by tests with in-memory fakes (the measured numbers are in the README), and a reviewer can read the policy code without reading the network code. The price is mapping code at the boundaries (a raw configuration of plain options validated by the domain, port traits and their fakes). Adding a dependency or an `unsafe` block anywhere else fails a test, which is the intent.
