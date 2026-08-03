//! Just enough HTTP to ask a vault for a secret.
//!
//! The Rust standard library has no HTTP client, and sekreto takes no
//! third-party dependencies, so this speaks HTTP/1.1 over a TcpStream
//! directly. It handles exactly what the vault providers need: a plaintext
//! GET with one header, a status line, and a body delimited either by
//! Content-Length or by the connection closing.
//!
//! It is not a general-purpose client. There is no TLS, no redirect
//! following and no chunked transfer decoding - a vault reachable only over
//! https needs a real client, and that is the one thing to change here.

use std::io::{Read, Write};
use std::net::TcpStream;
use std::time::Duration;

/// What a vault answered: the status code and the raw body.
pub struct Response {
    pub status: u16,
    pub body: String,
}

/// A url split into the parts a request needs.
struct Target {
    host: String,
    port: u16,
    path: String,
}

fn split(url: &str) -> Result<Target, String> {
    let rest = match url.strip_prefix("http://") {
        Some(rest) => rest,
        None => {
            if url.starts_with("https://") {
                return Err(format!("sekreto: https is not supported: {}", url));
            }
            return Err(format!("sekreto: not an http url: {}", url));
        }
    };

    let (authority, path) = match rest.find('/') {
        Some(at) => (&rest[..at], &rest[at..]),
        None => (rest, "/"),
    };

    let (host, port) = match authority.rfind(':') {
        Some(at) => (
            &authority[..at],
            authority[at + 1..]
                .parse::<u16>()
                .map_err(|_| format!("sekreto: bad port: {}", url))?,
        ),
        None => (authority, 80),
    };

    Ok(Target {
        host: host.to_string(),
        port,
        path: path.to_string(),
    })
}

/// GET a url with one extra header.
pub fn get(url: &str, header: &str, value: &str) -> Result<Response, String> {
    getwith(url, &[(header, value)])
}

/// GET a url with a set of headers. A non-2xx status is returned, not
/// raised: a 404 from a vault means "no such secret", which is a miss
/// rather than a failure.
pub fn getwith(url: &str, headers: &[(&str, &str)]) -> Result<Response, String> {
    let target = split(url)?;

    let mut stream = TcpStream::connect((target.host.as_str(), target.port))
        .map_err(|err| format!("sekreto: cannot reach {}: {}", url, err))?;

    stream
        .set_read_timeout(Some(Duration::from_secs(10)))
        .map_err(|err| format!("sekreto: cannot reach {}: {}", url, err))?;

    let mut request = format!(
        "GET {} HTTP/1.1\r\nHost: {}:{}\r\nAccept: application/json\r\nConnection: close\r\n",
        target.path, target.host, target.port
    );

    for (name, value) in headers {
        request.push_str(&format!("{}: {}\r\n", name, value));
    }

    request.push_str("\r\n");

    stream
        .write_all(request.as_bytes())
        .map_err(|err| format!("sekreto: cannot reach {}: {}", url, err))?;

    let mut raw = Vec::new();
    stream
        .read_to_end(&mut raw)
        .map_err(|err| format!("sekreto: cannot read {}: {}", url, err))?;

    let text = String::from_utf8_lossy(&raw).to_string();

    let split_at = text
        .find("\r\n\r\n")
        .ok_or_else(|| format!("sekreto: malformed response from {}", url))?;

    let head = &text[..split_at];
    let raw_body = &text[split_at + 4..];

    // "HTTP/1.1 200 OK" - the second field is the status.
    let status = head
        .lines()
        .next()
        .and_then(|line| line.split_whitespace().nth(1))
        .and_then(|code| code.parse::<u16>().ok())
        .ok_or_else(|| format!("sekreto: no status from {}", url))?;

    // A server that does not know the body length up front sends it in
    // chunks - which is what a vault answering from a store usually does.
    let chunked = head
        .lines()
        .skip(1)
        .filter_map(|line| line.split_once(':'))
        .any(|(name, value)| {
            name.eq_ignore_ascii_case("transfer-encoding")
                && value.to_ascii_lowercase().contains("chunked")
        });

    let body = if chunked {
        dechunk(raw_body).ok_or_else(|| format!("sekreto: malformed chunks from {}", url))?
    } else {
        raw_body.to_string()
    };

    Ok(Response { status, body })
}

/// Join a chunked body back together.
///
/// Each chunk is a hex length, CRLF, that many bytes, CRLF. A zero length
/// ends the body; any trailer after it is ignored.
fn dechunk(text: &str) -> Option<String> {
    let mut out = String::new();
    let mut rest = text;

    loop {
        let (header, body) = rest.split_once("\r\n")?;

        // A chunk length may carry extensions after a `;`.
        let size = usize::from_str_radix(header.split(';').next()?.trim(), 16).ok()?;

        if 0 == size {
            return Some(out);
        }

        if body.len() < size {
            return None;
        }

        out.push_str(&body[..size]);

        rest = body.get(size + 2..)?;
    }
}

/// Percent-encode a query-string value.
pub fn urlencode(text: &str) -> String {
    let mut out = String::new();

    for byte in text.bytes() {
        match byte {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => {
                out.push(byte as char)
            }
            _ => out.push_str(&format!("%{:02X}", byte)),
        }
    }

    out
}
