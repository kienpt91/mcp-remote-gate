# 10. Unsafe code confined to one small crate; the child in its own process group

Status: accepted

## Context
Starting the child with resource limits, stopping it together with everything it started, and reacting to signals need system calls that `std` does not offer (`setrlimit`, `killpg`, `sigaction`, `prctl`).

## Decision
`gate-sys` is the only crate that may contain `unsafe` (the workspace lint forbids it everywhere else; the architecture test checks the sources, requires a `// SAFETY:` comment on every use, and keeps the crate under 220 lines). It provides: `prepare_child` (a new process group, resource limits applied between fork and exec, and on Linux `PR_SET_PDEATHSIG` so the child dies if the gateway is killed with SIGKILL), `signal_group` (refuses group 0 and 1), and signal handlers that only set atomic flags (shutdown, kill switch on and off). The child adapter signals the whole group: SIGTERM, a grace period, then SIGKILL, also for a leader that already exited.

The shell is not used to start the server: the program and its arguments are an argv, the environment is cleared and rebuilt from `inherit_env` and `[child.env]`.

## Consequences
Killing the gateway (even with SIGKILL) does not leave the server behind on Linux; a test proves it. The resource limits are applied for real (a test reads them from inside the child). Limits and the death signal are Linux behavior: on macOS `RLIMIT_AS` is best effort and the death signal does not exist, and that code type-checks but was not run. The server is not sandboxed beyond these limits: it runs with the gateway's user permissions.
