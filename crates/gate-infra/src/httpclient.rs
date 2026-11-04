//! A minimal blocking HTTP/1.1 client over `std::net`, used by `selftest` and by the tests. It
//! sends `Connection: close` and reads to the end of the stream.

use std::io::{self, Read as _, Write as _};
use std::net::{SocketAddr, TcpStream};
use std::time::Duration;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ClientResponse {
    pub status: u16,
    /// Names lowercased.
    pub headers: Vec<(String, String)>,
    pub body: Vec<u8>,
}

impl ClientResponse {
    pub fn header(&self, name: &str) -> Option<&str> {
        self.headers
            .iter()
            .find(|(k, _)| k == name)
            .map(|(_, v)| v.as_str())
    }

    pub fn text(&self) -> String {
        String::from_utf8_lossy(&self.body).into_owned()
    }
}

/// Writes `bytes` to `addr` and returns everything the server sends until it closes the
/// connection or `timeout` passes without data.
pub fn exchange_raw(addr: SocketAddr, bytes: &[u8], timeout: Duration) -> io::Result<Vec<u8>> {
    let mut stream = TcpStream::connect_timeout(&addr, timeout)?;
    stream.set_read_timeout(Some(timeout))?;
    stream.set_write_timeout(Some(timeout))?;
    // the server may answer and close before it has read everything (an oversized body, say)
    let _ = stream.write_all(bytes);
    let mut out = Vec::new();
    let mut chunk = [0u8; 8192];
    loop {
        match stream.read(&mut chunk) {
            Ok(0) => break,
            Ok(n) => out.extend_from_slice(chunk.get(..n).unwrap_or_default()),
            Err(e)
                if matches!(
                    e.kind(),
                    io::ErrorKind::WouldBlock | io::ErrorKind::TimedOut
                ) =>
            {
                break
            }
            Err(e) if e.kind() == io::ErrorKind::ConnectionReset && !out.is_empty() => break,
            Err(e) => return Err(e),
        }
    }
    Ok(out)
}

/// Splits a raw response into status, headers and body.
pub fn parse_response(raw: &[u8]) -> Option<ClientResponse> {
    let end = raw.windows(4).position(|w| w == b"\r\n\r\n")?;
    let head = std::str::from_utf8(raw.get(..end)?).ok()?;
    let mut lines = head.split("\r\n");
    let status = lines.next()?.split(' ').nth(1)?.parse().ok()?;
    let headers = lines
        .filter_map(|l| l.split_once(':'))
        .map(|(k, v)| (k.trim().to_ascii_lowercase(), v.trim().to_string()))
        .collect();
    Some(ClientResponse {
        status,
        headers,
        body: raw.get(end + 4..)?.to_vec(),
    })
}

/// One request on a fresh connection. A `Host` header is added unless `headers` has one.
pub fn request(
    addr: SocketAddr,
    method: &str,
    path: &str,
    headers: &[(&str, &str)],
    body: &[u8],
    timeout: Duration,
) -> io::Result<ClientResponse> {
    let mut head = format!("{method} {path} HTTP/1.1\r\n");
    if !headers.iter().any(|(k, _)| k.eq_ignore_ascii_case("host")) {
        head.push_str(&format!("Host: {addr}\r\n"));
    }
    for (k, v) in headers {
        head.push_str(&format!("{k}: {v}\r\n"));
    }
    if method == "POST" || !body.is_empty() {
        head.push_str(&format!("Content-Length: {}\r\n", body.len()));
    }
    head.push_str("Connection: close\r\n\r\n");
    let mut bytes = head.into_bytes();
    bytes.extend_from_slice(body);
    let raw = exchange_raw(addr, &bytes, timeout)?;
    parse_response(&raw).ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::InvalidData,
            "the server sent no valid HTTP response",
        )
    })
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

    #[test]
    fn responses_are_split() {
        let r = parse_response(
            b"HTTP/1.1 429 Too Many Requests\r\nRetry-After: 3\r\nContent-Length: 2\r\n\r\n{}",
        )
        .unwrap();
        assert_eq!(
            (r.status, r.header("retry-after"), r.text().as_str()),
            (429, Some("3"), "{}")
        );
        assert!(parse_response(b"garbage").is_none());
        assert!(parse_response(b"HTTP/1.1 abc OK\r\n\r\n").is_none());
        assert!(parse_response(b"").is_none());
    }
}
