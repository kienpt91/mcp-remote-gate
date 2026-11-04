//! Host and Origin checks, the defense against DNS rebinding.
//!
//! A web page can make a browser send requests to `127.0.0.1` under the page's own name (after
//! a DNS answer changes) or from its own origin. A request like that carries a `Host` that is
//! not one of ours or an `Origin` that is not allowed. Native MCP clients send no `Origin`, so
//! the default is: any `Origin` header is refused unless it is listed.

use std::net::SocketAddr;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HostError {
    Missing,
    NotAllowed,
}

#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct HostPolicy {
    hosts: Vec<String>,
    origins: Vec<String>,
}

fn is_dns_char(c: char) -> bool {
    c.is_ascii_alphanumeric() || matches!(c, '-' | '.' | '_')
}

fn valid_port(port: &str) -> bool {
    !port.is_empty()
        && port.len() <= 5
        && port.bytes().all(|b| b.is_ascii_digit())
        && port.parse::<u32>().is_ok_and(|p| p <= 65_535)
}

/// A `Host` header value or a configured host: `name`, `name:port`, `1.2.3.4:port` or
/// `[v6]:port`. Returned lowercased; `None` when it is not one of those forms.
pub fn normalize_host(text: &str) -> Option<String> {
    let text = text.to_ascii_lowercase();
    let (host, port) = if let Some(rest) = text.strip_prefix('[') {
        let (inner, after) = rest.split_once(']')?;
        if inner.is_empty()
            || !inner
                .chars()
                .all(|c| c.is_ascii_hexdigit() || c == ':' || c == '.')
        {
            return None;
        }
        let port = match after {
            "" => None,
            _ => Some(after.strip_prefix(':')?),
        };
        (format!("[{inner}]"), port)
    } else {
        let (host, port) = match text.split_once(':') {
            Some((h, p)) => (h, Some(p)),
            None => (text.as_str(), None),
        };
        if host.is_empty() || !host.chars().all(is_dns_char) || host.starts_with('.') {
            return None;
        }
        (host.to_string(), port)
    };
    match port {
        None => Some(host),
        Some(p) if valid_port(p) => Some(format!("{host}:{p}")),
        Some(_) => None,
    }
}

/// An origin as browsers send it: `http://host[:port]` or `https://host[:port]`, no path.
pub fn normalize_origin(text: &str) -> Option<String> {
    let lower = text.to_ascii_lowercase();
    let (scheme, host) = lower.split_once("://")?;
    if scheme != "http" && scheme != "https" {
        return None;
    }
    let host = normalize_host(host)?;
    Some(format!("{scheme}://{host}"))
}

/// The `Host` values that name a loopback listener: the literal addresses and `localhost`.
pub fn loopback_hosts(addr: SocketAddr) -> Vec<String> {
    let port = addr.port();
    vec![
        format!("127.0.0.1:{port}"),
        format!("localhost:{port}"),
        format!("[::1]:{port}"),
    ]
}

impl HostPolicy {
    /// Both lists must already be normalized with [`normalize_host`] and [`normalize_origin`].
    pub fn new(hosts: Vec<String>, origins: Vec<String>) -> HostPolicy {
        HostPolicy { hosts, origins }
    }

    pub fn hosts(&self) -> &[String] {
        &self.hosts
    }

    pub fn origins(&self) -> &[String] {
        &self.origins
    }

    pub fn check_host(&self, header: Option<&str>) -> Result<(), HostError> {
        let header = header.ok_or(HostError::Missing)?;
        match normalize_host(header) {
            Some(host) if self.hosts.contains(&host) => Ok(()),
            _ => Err(HostError::NotAllowed),
        }
    }

    /// No `Origin` header is fine (native clients); one that is present must be listed.
    pub fn check_origin(&self, header: Option<&str>) -> Result<(), HostError> {
        let Some(header) = header else { return Ok(()) };
        match normalize_origin(header) {
            Some(origin) if self.origins.contains(&origin) => Ok(()),
            _ => Err(HostError::NotAllowed),
        }
    }
}

#[cfg(test)]
mod tests {
    #![allow(
        clippy::unwrap_used,
        clippy::expect_used,
        clippy::indexing_slicing,
        clippy::panic
    )]
    use super::*;

    fn policy() -> HostPolicy {
        let addr: SocketAddr = "127.0.0.1:8787".parse().unwrap();
        let mut hosts = loopback_hosts(addr);
        hosts.push("mcp.example.com".into());
        HostPolicy::new(hosts, vec!["https://app.example.com".into()])
    }

    #[test]
    fn allowed_hosts() {
        let p = policy();
        for ok in [
            "127.0.0.1:8787",
            "localhost:8787",
            "LOCALHOST:8787",
            "[::1]:8787",
            "mcp.example.com",
            "MCP.Example.COM",
        ] {
            assert_eq!(p.check_host(Some(ok)), Ok(()), "{ok}");
        }
        assert_eq!(p.hosts().len(), 4);
    }

    #[test]
    fn rebinding_hosts_are_refused() {
        let p = policy();
        for bad in [
            "evil.example:8787",
            "127.0.0.1:9999",
            "127.0.0.1",
            "localhost",
            "127.0.0.1:8787.evil.example",
            "127.0.0.1:8787@evil.example",
            "evil.example\u{0}.localhost:8787",
            "localhost:8787 ",
            " localhost:8787",
            "localhost:8787/",
            "",
            "[::1",
            "[::1]x",
            "localhost:99999",
            "localhost:80a",
            "mcp.example.com:443",
            "mcp.example.com.",
        ] {
            assert_eq!(
                p.check_host(Some(bad)),
                Err(HostError::NotAllowed),
                "{bad:?}"
            );
        }
        assert_eq!(p.check_host(None), Err(HostError::Missing));
    }

    #[test]
    fn origins() {
        let p = policy();
        assert_eq!(p.check_origin(None), Ok(()));
        assert_eq!(p.check_origin(Some("https://app.example.com")), Ok(()));
        assert_eq!(p.check_origin(Some("HTTPS://App.Example.com")), Ok(()));
        for bad in [
            "null",
            "http://app.example.com",
            "https://app.example.com:8443",
            "https://evil.example",
            "https://app.example.com/",
            "https://app.example.com.evil.example",
            "file://",
            "",
            "http://localhost:8787",
        ] {
            assert_eq!(
                p.check_origin(Some(bad)),
                Err(HostError::NotAllowed),
                "{bad:?}"
            );
        }
    }

    #[test]
    fn by_default_nothing_with_an_origin_passes() {
        let p = HostPolicy::new(vec!["localhost:1".into()], vec![]);
        assert_eq!(
            p.check_origin(Some("http://localhost:1")),
            Err(HostError::NotAllowed)
        );
        assert!(p.origins().is_empty());
    }

    #[test]
    fn normalization() {
        assert_eq!(
            normalize_host("Example.COM:80").as_deref(),
            Some("example.com:80")
        );
        assert_eq!(
            normalize_host("[FE80::1]:9").as_deref(),
            Some("[fe80::1]:9")
        );
        assert_eq!(normalize_host("[::1]").as_deref(), Some("[::1]"));
        for bad in [
            "",
            ":80",
            "a b",
            "a:",
            "[]:1",
            "[zz]:1",
            ".x",
            "a/b",
            "a@b",
            "é.example",
            "a:65536",
        ] {
            assert_eq!(normalize_host(bad), None, "{bad:?}");
        }
        assert_eq!(
            normalize_origin("https://a.example:8443").as_deref(),
            Some("https://a.example:8443")
        );
        assert_eq!(normalize_origin("ftp://a"), None);
        assert_eq!(normalize_origin("a.example"), None);
        assert_eq!(normalize_origin("https://a.example/x"), None);
    }
}
