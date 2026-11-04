# Deployment

`mcp-remote-gate` speaks plain HTTP. It has no TLS on purpose (ADR 5): a certificate store, renewal and a TLS stack are a lot of code to put in the one process that guards a server, and every deployment that needs the internet already has something that does TLS better. So the supported shapes are:

1. **Loopback plus a TLS-terminating proxy or tunnel** on the same machine (the default and the recommended one).
2. **A private network** (a VPN or an overlay network between the client and the host) where plain HTTP between trusted peers is acceptable. This needs `--i-know-this-is-not-tls` and `allowed_hosts`, and the gateway prints a warning at every start.

Binding an address that is not a loopback address without the flag is refused with exit status 2 and nothing is bound.

What the examples below have and have not had: the gateway side (loopback listener, `Host` handling for a public name, the Origin rule) is covered by tests. **The proxy and tunnel snippets are examples written from their documentation and were not run in this verification**; read them as a starting point and test them with your own client before relying on them.

## Shape 1: loopback and a reverse proxy

```toml
[server]
listen = "127.0.0.1:8787"
# the proxy forwards the public name in Host (most proxies do by default)
allowed_hosts = ["mcp.example.com", "127.0.0.1:8787"]
```

Caddy (terminates TLS, gets the certificate itself):

```caddyfile
mcp.example.com {
    reverse_proxy 127.0.0.1:8787
}
```

nginx (certificate handled elsewhere):

```nginx
server {
    listen 443 ssl;
    server_name mcp.example.com;
    # ssl_certificate ... ssl_certificate_key ...
    client_max_body_size 1m;
    location /mcp {
        proxy_pass http://127.0.0.1:8787;
        proxy_set_header Host $host;
        proxy_http_version 1.1;
        proxy_read_timeout 60s;
    }
}
```

The gateway refuses a client that has no valid token before it reads the body, but every client occupies a connection while its headers are read (5 seconds by default), and there is no per-address limit. **Let the proxy or tunnel enforce its own request header and body timeouts and connection limits** (nginx and Caddy do by default), so that slow or unauthenticated clients are held at the edge, not at the gateway.

Things to check with any proxy: it must pass `Authorization` through, must not add `Transfer-Encoding: chunked` to the request body towards the gateway (the gateway accepts only `Content-Length`; a proxy that buffers request bodies does this by itself), and must not cache responses. Do not let the proxy answer on a path other than the endpoint if you do not want it to.

## Shape 1b: loopback and a tunnel

A tunnel client on the same machine (Cloudflare Tunnel, ngrok, Tailscale Funnel and the like) exposes `127.0.0.1:8787` under a public name. The gateway sees `Host: <public name>`: put that name in `allowed_hosts`. The tunnel provider terminates TLS and **sees all traffic in plain text, including the bearer token and every tool result**: choose one you trust with that, and read the security section in the tunnel's own documentation about access policies that can sit in front of the gateway as a second layer.

```toml
[server]
listen = "127.0.0.1:8787"
allowed_hosts = ["my-gate.example.net", "127.0.0.1:8787"]
```

## Shape 2: a private network

```sh
mcp-remote-gate run --config gate.toml --i-know-this-is-not-tls
```

```toml
[server]
listen = "10.8.0.1:8787"            # the address on the private network
allowed_hosts = ["10.8.0.1:8787"]
```

Anyone who can reach that address can try tokens; the token and the rate limit are the only protection. Keep the interface off the public internet.

## Running it as a service

A systemd unit (example, not run in this verification). It runs as an unprivileged user, owns nothing it does not need and lets the gateway's own shutdown stop the child:

```ini
[Unit]
Description=mcp-remote-gate
After=network.target

[Service]
User=mcpgate
WorkingDirectory=/etc/mcp-remote-gate
ExecStart=/usr/local/bin/mcp-remote-gate run --config /etc/mcp-remote-gate/gate.toml
Restart=on-failure
RestartSec=5
KillMode=mixed
TimeoutStopSec=15
NoNewPrivileges=true
ProtectSystem=strict
ReadWritePaths=/var/lib/mcp-remote-gate
PrivateTmp=true

[Install]
WantedBy=multi-user.target
```

Put `audit.jsonl` and the kill switch file under the writable path (`audit.path = "/var/lib/mcp-remote-gate/audit.jsonl"`).

If the gateway itself is killed with SIGKILL, only its direct child is killed (Linux); the descendants of the server are not. systemd cleans up the whole control group of the unit when the main process ends (`KillMode=mixed` as above, or `control-group`), which is what closes that gap; without a service manager or a container it stays open. The server behind the gateway runs as the same user, with that user's permissions. The gateway limits which tools can be called, not what the server can do once it runs: give the user (or a container) only the access the server needs. For a messaging server that means its own data directory and nothing else.

## What to monitor

- The standard error of the gateway: start-up warnings, `upstream server ready`, restarts, refused requests (rate limited in the log), `cannot write the audit log`.
- The audit file: bursts of `bad_token`, `host_rejected` or `rate_limited` are somebody knocking; `denied` with `read_only` or `denylist` for a tool you expected to work is a policy that is too tight.
- The kill switch is one command away: `touch KILL` (or `kill -USR1 PID`).

See `docs/handover-note.md` for the template to give to whoever runs this next.
