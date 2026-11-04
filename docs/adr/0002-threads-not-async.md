# 2. Threads and blocking I/O, not an async runtime

Status: accepted

## Context
The gateway serves a handful of clients and one child process. An async runtime would be a large dependency (tens of crates) in the one place where the dependency list should be shortest, and it would colour every function.

## Decision
`std::thread` and blocking sockets: one thread per connection (bounded by `max_connections`), one reader thread and one writer thread per child run, one supervisor thread, and channels (`std::sync::mpsc`) to hand answers to the thread that waits for them. Every wait has a deadline.

## Consequences
No runtime dependency; the control flow reads top to bottom. The limit is scale: thousands of idle connections would need thousands of threads, which `max_connections` (default 64) refuses by design. For a connector in front of a local server that is the right trade. The accept loop polls a non-blocking listener every 15 ms instead of blocking, so that shutdown does not depend on interrupting `accept`.
