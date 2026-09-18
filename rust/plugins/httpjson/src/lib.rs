
pub mod http;
pub mod json;

use std::cell::RefCell;
use std::env;
use std::time::{Duration, Instant};

use voxgig_sekreto::{Answer, SekretoError};

pub use crate::json::Json;

pub fn trimslash(addr: &str) -> &str {
    addr.strip_suffix('/').unwrap_or(addr)
}

pub fn firstof(config: &str, envnames: &[&str]) -> String {
    if !config.is_empty() {
        return config.to_string();
    }

    for name in envnames {
        if let Ok(value) = env::var(name) {
            if !value.is_empty() {
                return value;
            }
        }
    }

    String::new()
}

pub fn headerrefs(headers: &[(String, String)]) -> Vec<(&str, &str)> {
    headers
        .iter()
        .map(|(name, value)| (name.as_str(), value.as_str()))
        .collect()
}

pub struct JsonResponse {
    pub status: u16,
    pub body: Option<Json>,
}

/// One JSON round-trip. Network failure is always an error - an
/// unreachable store is a store that could not answer.
pub fn fetchjson(
    method: &str,
    url: &str,
    headers: &[(&str, &str)],
    body: Option<&str>,
) -> Answer<JsonResponse> {
    let response = crate::http::request(method, url, headers, body)?;

    let parsed = crate::json::parse(&response.body);

    if 200 == response.status && parsed.is_none() {
        return Err(SekretoError::new(format!(
            "sekreto: malformed response from {}",
            url.split('?').next().unwrap_or(url)
        )));
    }

    Ok(JsonResponse {
        status: response.status,
        body: parsed,
    })
}

/// When a token obtained by a login should be renewed: shortly before
/// the expiry the login response named, or never (None) when it named
/// none - a store that does not say when a token dies cannot have it
/// renewed on a guess.
pub fn renewtime(seconds: f64) -> Option<Instant> {
    if 0.0 < seconds && seconds.is_finite() {
        let bounded = (seconds - 60.0).max(1.0).min(3_153_600_000.0);
        Some(Instant::now() + Duration::from_secs_f64(bounded))
    } else {
        None
    }
}

pub fn expiryseconds(body: &Option<Json>, path: &[&str]) -> f64 {
    textat(body, path)
        .and_then(|text| text.parse::<f64>().ok())
        .unwrap_or(0.0)
}

pub fn renewdue(renewat: &RefCell<Option<Instant>>) -> bool {
    renewat.borrow().map_or(false, |at| Instant::now() >= at)
}

pub fn textat(body: &Option<Json>, path: &[&str]) -> Option<String> {
    let mut at = body.as_ref()?;

    for key in path {
        at = at.get(key)?;
    }

    if matches!(at, Json::Null) {
        return None;
    }

    Some(at.text())
}
