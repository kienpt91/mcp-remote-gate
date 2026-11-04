# 5. No TLS in the process: loopback plus a TLS-terminating proxy or tunnel

Status: accepted

## Context
A remote client must reach the gateway over HTTPS. Implementing TLS in the gateway means a TLS library, certificates, renewal, protocol versions and cipher policy: a lot of code and operations in the process that guards the server, and everyone who exposes a service to the internet already runs something that does it better (a reverse proxy, a tunnel agent, a VPN).

## Decision
The gateway speaks plain HTTP and listens on loopback by default. An address that is not a loopback address is refused unless `--i-know-this-is-not-tls` is passed, and `allowed_hosts` must then be set; a warning is printed at every start. `docs/deployment.md` documents the supported shapes (loopback with a proxy or tunnel on the same machine; a private network) and says what each one trusts.

## Consequences
The attack surface of the gateway has no TLS stack. The operator has one more component to run, and the component that terminates TLS sees the bearer token and the results in plain text. The flag is a speed bump, not a lock: someone who wants to bind `0.0.0.0` can. The proxy snippets in the documentation were not run in this verification.
