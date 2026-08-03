//! Just enough HTTP to ask a vault for a secret.
//!
//! The Rust standard library has no HTTP client, so this speaks HTTP/1.1
//! over a TcpStream directly: a GET with headers, a status line, and a body
//! delimited by Content-Length, by chunks, or by the connection closing.
//!
//! https goes over rustls - the one dependency this repo takes, and a
//! deliberate one. A secrets library reaching a remote vault needs TLS, and
//! hand-rolling TLS would be far worse than taking a well-audited crate.
//! Server certificates are verified against the Mozilla root set, plus any
//! extra roots named by `SEKRETO_CA_BUNDLE` - an internal Vault behind a
//! private CA is the common case, not the exotic one.
//!
//! It is still not a general-purpose client: no redirect following, no
//! request bodies, no client certificates.

use std::io::{Read, Write};
use std::net::TcpStream;
use std::sync::Arc;
use std::time::Duration;

use rustls::pki_types::{CertificateDer, ServerName};
use rustls::{ClientConfig, ClientConnection, RootCertStore, StreamOwned};

/// The environment variable naming extra trust roots, as a PEM bundle.
pub const CABUNDLE: &str = "SEKRETO_CA_BUNDLE";

/// Anything the exchange can run over: a plain TcpStream, or a rustls
/// stream wrapping one.
trait ReadWrite: Read + Write {}
impl<T: Read + Write> ReadWrite for T {}

/// What a vault answered: the status code and the raw body.
pub struct Response {
    pub status: u16,
    pub body: String,
}

/// A url split into the parts a request needs.
struct Target {
    /// The bare host: what we connect to, and what the certificate is
    /// checked against. An IPv6 literal appears here without brackets.
    host: String,
    /// The authority as it goes in the `Host:` header. An IPv6 literal
    /// keeps its brackets, because `Host: 2001:db8::1:8200` is not a valid
    /// authority and an intermediary may reject or misroute it.
    authority: String,
    port: u16,
    path: String,
    tls: bool,
}

fn split(url: &str) -> Result<Target, String> {
    let (rest, tls, defaultport) = match url.strip_prefix("http://") {
        Some(rest) => (rest, false, 80u16),
        None => match url.strip_prefix("https://") {
            Some(rest) => (rest, true, 443u16),
            None => return Err(format!("sekreto: not an http url: {}", url)),
        },
    };

    let (authority, path) = match rest.find('/') {
        Some(at) => (&rest[..at], &rest[at..]),
        None => (rest, "/"),
    };

    // rfind, so that an IPv6 literal's own colons are not mistaken for a
    // port separator when one is present.
    let (host, port) = match authority.rfind(':') {
        Some(at) if !authority[at + 1..].is_empty() && !authority.ends_with(']') => (
            &authority[..at],
            authority[at + 1..]
                .parse::<u16>()
                .map_err(|_| format!("sekreto: bad port: {}", url))?,
        ),
        _ => (authority, defaultport),
    };

    let bare = host
        .trim_start_matches('[')
        .trim_end_matches(']')
        .to_string();

    // Re-bracketed only if it really is an IPv6 literal, because
    // `Host: 2001:db8::1:8200` is not a valid authority.
    let hostheader = if bare.contains(':') {
        format!("[{}]", bare)
    } else {
        bare.clone()
    };

    Ok(Target {
        host: bare,
        authority: hostheader,
        port,
        path: path.to_string(),
        tls,
    })
}

/// Decode standard base64, which is all a PEM body is.
fn unbase64(text: &str) -> Option<Vec<u8>> {
    const ALPHABET: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

    let mut out = Vec::new();
    let mut acc: u32 = 0;
    let mut bits = 0u32;

    for head in text.bytes() {
        if head.is_ascii_whitespace() || b'=' == head {
            continue;
        }

        let value = ALPHABET.iter().position(|entry| *entry == head)? as u32;

        acc = (acc << 6) | value;
        bits += 6;

        if 8 <= bits {
            bits -= 8;
            out.push((acc >> bits) as u8);
        }
    }

    Some(out)
}

/// Pull every certificate out of a PEM bundle.
fn pemcerts(text: &str) -> Vec<CertificateDer<'static>> {
    const OPEN: &str = "-----BEGIN CERTIFICATE-----";
    const CLOSE: &str = "-----END CERTIFICATE-----";

    let mut out = Vec::new();
    let mut rest = text;

    while let Some(start) = rest.find(OPEN) {
        let body = &rest[start + OPEN.len()..];

        let end = match body.find(CLOSE) {
            Some(end) => end,
            None => break,
        };

        if let Some(der) = unbase64(&body[..end]) {
            out.push(CertificateDer::from(der));
        }

        rest = &body[end + CLOSE.len()..];
    }

    out
}

/// The trust roots: the Mozilla set, plus anything in `SEKRETO_CA_BUNDLE`.
///
/// A private CA is how most internal Vault deployments are set up, so the
/// bundle is additive rather than a replacement - a wrong path weakens
/// nothing, it just adds no roots.
fn rootstore() -> RootCertStore {
    let mut roots = RootCertStore::empty();
    roots.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());

    if let Ok(path) = std::env::var(CABUNDLE) {
        if !path.is_empty() {
            if let Ok(text) = std::fs::read_to_string(&path) {
                for cert in pemcerts(&text) {
                    let _ = roots.add(cert);
                }
            }
        }
    }

    roots
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

    if target.tls {
        let config = ClientConfig::builder()
            .with_root_certificates(rootstore())
            .with_no_client_auth();

        let servername = ServerName::try_from(target.host.clone())
            .map_err(|_| format!("sekreto: bad host name: {}", target.host))?;

        let connection = ClientConnection::new(Arc::new(config), servername)
            .map_err(|err| format!("sekreto: tls setup failed for {}: {}", url, err))?;

        // A handshake failure is a refusal to trust the server, so it must
        // surface as an error rather than as a missing secret.
        return exchange(
            &mut StreamOwned::new(connection, stream),
            &target,
            headers,
            url,
        );
    }

    exchange(&mut stream, &target, headers, url)
}

/// Write the request and read the response, over whatever the transport is.
fn exchange(
    stream: &mut impl ReadWrite,
    target: &Target,
    headers: &[(&str, &str)],
    url: &str,
) -> Result<Response, String> {
    let mut request = format!(
        "GET {} HTTP/1.1\r\nHost: {}:{}\r\nAccept: application/json\r\nConnection: close\r\n",
        target.path, target.authority, target.port
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

    let split_at = findbytes(&raw, b"\r\n\r\n")
        .ok_or_else(|| format!("sekreto: malformed response from {}", url))?;

    // Headers are ASCII; the body is not necessarily, so it stays bytes
    // until every length-counted slice has been taken.
    let head = String::from_utf8_lossy(&raw[..split_at]).to_string();
    let rawbody = &raw[split_at + 4..];

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

    let bodybytes = if chunked {
        dechunk(rawbody).ok_or_else(|| format!("sekreto: malformed chunks from {}", url))?
    } else {
        rawbody.to_vec()
    };

    let body = String::from_utf8_lossy(&bodybytes).to_string();

    Ok(Response { status, body })
}

/// The offset of `needle` in `hay`, if it is there.
fn findbytes(hay: &[u8], needle: &[u8]) -> Option<usize> {
    hay.windows(needle.len())
        .position(|window| window == needle)
}

/// Join a chunked body back together.
///
/// Each chunk is a hex length, CRLF, that many bytes, CRLF. A zero length
/// ends the body; any trailer after it is ignored.
///
/// Bytes, not `str`: a chunk length counts bytes, and a boundary may fall
/// inside a multibyte character. Slicing a `str` at such an offset panics,
/// so a secret containing any non-ASCII character could take the process
/// down rather than come back.
fn dechunk(raw: &[u8]) -> Option<Vec<u8>> {
    let mut out = Vec::new();
    let mut rest = raw;

    loop {
        let at = findbytes(rest, b"\r\n")?;

        // A chunk length may carry extensions after a `;`.
        let header = std::str::from_utf8(&rest[..at]).ok()?;
        let size = usize::from_str_radix(header.split(';').next()?.trim(), 16).ok()?;

        let body = rest.get(at + 2..)?;

        if 0 == size {
            return Some(out);
        }

        if body.len() < size {
            return None;
        }

        out.extend_from_slice(&body[..size]);

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
