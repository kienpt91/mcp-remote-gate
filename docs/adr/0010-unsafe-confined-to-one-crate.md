# 10. Unsafe code confined to one small crate; the child in its own process group

Status: accepted

## Context
Starting the child with resource limits, stopping it together with everything it started, and reacting to signals need system calls that `std` does not offer (`setrlimit`, `killpg`, `sigaction`, `prctl`).

## Decision
`gate-sys` is the only crate that may contain `unsafe` (the workspace lint forbids it everywhere else; the architecture test checks the sources, requires a `// SAFETY:` comment on every use, and keeps the crate small). It provides: `prepare_child` (a new process group, resource limits applied between fork and exec, and on Linux `PR_SET_PDEATHSIG` so the direct child dies if the gateway is killed with SIGKILL), `signal_group` (refuses group 0 and 1), `has_exited` (`waitid` with `WNOWAIT`: sees that the child ended without reaping it), the `O_NOFOLLOW` flag and the effective user id (for the file checks), and signal handlers that only set atomic flags (shutdown, kill switch on and off).

The child adapter sends every signal to the process group **before** the leader is reaped and none after: a leader that has exited but was not waited for is a zombie that still holds its process id, so the group number cannot have been given to somebody else. When the leader exits, the group is killed at that moment (this also releases pipes that a descendant inherited and would otherwise hold open); a stop sends SIGTERM, waits the grace period, then SIGKILL. The upstream session runs a watcher thread on the leader so that this happens without anyone having to ask.

The shell is not used to start the server: the program and its arguments are an argv, the environment is cleared and rebuilt from `inherit_env` and `[child.env]`.

## Consequences
A graceful stop, or the exit of the server, leaves nothing of its process group behind; tests cover a descendant that holds the pipe, a descendant at shutdown and a leader that ignores SIGTERM. **After SIGKILL of the gateway only the direct child is killed (Linux)**: the kernel sends the death signal to the direct child and clears it for that child's own children, so descendants (the real server behind an `npx`, `uv` or `sh` wrapper) keep running in an orphaned process group, and on macOS nothing is killed. A service manager that kills a control group (systemd `KillMode=control-group`) or a container closes that gap. The resource limits are applied for real (a test reads them from inside the child). Limits and the death signal are Linux behavior: on macOS `RLIMIT_AS` is best effort and the death signal does not exist, and that code type-checks but was not run. The server is not sandboxed beyond these limits: it runs with the gateway's user permissions. A server that is alive but silent is not restarted: the session notices exits, not stalls.
