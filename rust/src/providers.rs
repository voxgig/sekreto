//! The providers a Sekreto chains together.
//!
//! A provider answers one question: "do you have this secret?" It returns
//! the value, or None to mean "ask the next one". Nothing else about a
//! provider is visible to the caller - which is the point: an app reads
//! `api.token` and never learns whether it came from the environment, a
//! .env file, HashiCorp Vault or a boru vault.
//!
//! A port of typescript/src/Providers.ts, which is canonical.

use std::collections::BTreeMap;
use std::env;
use std::fs;

use crate::http;
use crate::json;
use crate::sekreto::{envkey, vaultref, Answer, SekretoError};

/// A source of secrets.
pub trait Provider {
    /// The value, or None if this provider does not have it.
    fn lookup(&self, name: &str) -> Answer<Option<String>>;

    /// A short description, shown by `Sekreto::sources`.
    fn describe(&self) -> String;
}

/// The declarative form of a provider, as used in config and in the shared
/// spec.
#[derive(Clone, Debug, Default)]
pub struct ProviderSpec {
    pub kind: String,
    pub prefix: String,
    pub file: String,
    pub values: BTreeMap<String, String>,
    pub addr: String,
    pub token: String,
    pub mount: String,
}

impl ProviderSpec {
    pub fn of(kind: &str) -> Self {
        ProviderSpec {
            kind: kind.to_string(),
            ..Default::default()
        }
    }
}

/// Environment variables: `api.token` from `API_TOKEN`.
pub struct EnvProvider {
    pub prefix: String,
}

impl Provider for EnvProvider {
    fn lookup(&self, name: &str) -> Answer<Option<String>> {
        Ok(env::var(envkey(name, &self.prefix)?).ok())
    }

    fn describe(&self) -> String {
        if self.prefix.is_empty() {
            "env".to_string()
        } else {
            format!("env:{}", self.prefix)
        }
    }
}

/// A `.env` file, read once, keyed exactly like the environment.
pub struct DotenvProvider {
    pub file: String,
    pub prefix: String,
    values: BTreeMap<String, String>,
}

impl DotenvProvider {
    pub fn new(file: &str, prefix: &str) -> Self {
        // A missing .env file is not an error: it means "no secrets here".
        let values = match fs::read_to_string(file) {
            Ok(text) => crate::sekreto::parsedotenv(&text),
            Err(_) => BTreeMap::new(),
        };

        DotenvProvider {
            file: file.to_string(),
            prefix: prefix.to_string(),
            values,
        }
    }
}

impl Provider for DotenvProvider {
    fn lookup(&self, name: &str) -> Answer<Option<String>> {
        Ok(self.values.get(&envkey(name, &self.prefix)?).cloned())
    }

    fn describe(&self) -> String {
        format!("dotenv:{}", self.file)
    }
}

/// Literal values, keyed like environment variables. The spec uses this to
/// test chain behaviour without touching the outside world.
pub struct MemoryProvider {
    pub values: BTreeMap<String, String>,
    pub prefix: String,
}

impl Provider for MemoryProvider {
    fn lookup(&self, name: &str) -> Answer<Option<String>> {
        Ok(self.values.get(&envkey(name, &self.prefix)?).cloned())
    }

    fn describe(&self) -> String {
        if self.prefix.is_empty() {
            "memory".to_string()
        } else {
            format!("memory:{}", self.prefix)
        }
    }
}

/// HashiCorp Vault, KV v2.
///
/// `api.token` reads `{addr}/v1/{mount}/data/api` and takes the `token`
/// field of `data.data`. A 404 means "not here", which is a miss rather
/// than an error, so a vault can sit in a chain with fallbacks.
pub struct VaultProvider {
    pub addr: String,
    pub token: String,
    pub mount: String,
}

impl Provider for VaultProvider {
    fn lookup(&self, name: &str) -> Answer<Option<String>> {
        let reference = vaultref(name)?;

        let url = format!(
            "{}/v1/{}/data/{}",
            self.addr.trim_end_matches('/'),
            self.mount,
            reference.path
        );

        let response = http::get(&url, "X-Vault-Token", &self.token)?;

        if 404 == response.status {
            return Ok(None);
        }

        if 200 != response.status {
            return Err(SekretoError::new(format!(
                "sekreto: vault error: {}: {}",
                response.status, url
            )));
        }

        let body = match json::parse(&response.body) {
            Some(body) => body,
            None => return Ok(None),
        };

        Ok(body
            .get("data")
            .and_then(|outer| outer.get("data"))
            .and_then(|data| data.get(&reference.field))
            .filter(|value| !matches!(value, json::Json::Null))
            .map(|value| value.text()))
    }

    fn describe(&self) -> String {
        format!("vault:{}/{}", self.addr, self.mount)
    }
}

/// A boru vault.
///
/// The boru vault protocol as sekreto uses it: a GET of
/// `{addr}/vault/{path}?field={field}` with an `X-Boru-Token` header,
/// answering `{"ok":true,"value":"..."}` when the secret exists and
/// `{"ok":false}` (or 404) when it does not.
pub struct BoruProvider {
    pub addr: String,
    pub token: String,
}

impl Provider for BoruProvider {
    fn lookup(&self, name: &str) -> Answer<Option<String>> {
        let reference = vaultref(name)?;

        let url = format!(
            "{}/vault/{}?field={}",
            self.addr.trim_end_matches('/'),
            reference.path,
            http::urlencode(&reference.field)
        );

        let response = http::get(&url, "X-Boru-Token", &self.token)?;

        if 404 == response.status {
            return Ok(None);
        }

        if 200 != response.status {
            return Err(SekretoError::new(format!(
                "sekreto: boru vault error: {}: {}",
                response.status, url
            )));
        }

        let body = match json::parse(&response.body) {
            Some(body) => body,
            None => return Ok(None),
        };

        if !matches!(body.get("ok"), Some(json::Json::Bool(true))) {
            return Ok(None);
        }

        Ok(body
            .get("value")
            .filter(|value| !matches!(value, json::Json::Null))
            .map(|value| value.text()))
    }

    fn describe(&self) -> String {
        format!("boru:{}", self.addr)
    }
}

/// Build a provider from its declarative form.
pub fn makeprovider(spec: &ProviderSpec) -> Answer<Box<dyn Provider>> {
    match spec.kind.as_str() {
        "env" => Ok(Box::new(EnvProvider {
            prefix: spec.prefix.clone(),
        })),
        "dotenv" => {
            let file = if spec.file.is_empty() {
                ".env"
            } else {
                &spec.file
            };
            Ok(Box::new(DotenvProvider::new(file, &spec.prefix)))
        }
        "memory" => Ok(Box::new(MemoryProvider {
            values: spec.values.clone(),
            prefix: spec.prefix.clone(),
        })),
        "vault" => Ok(Box::new(VaultProvider {
            addr: spec.addr.clone(),
            token: spec.token.clone(),
            mount: if spec.mount.is_empty() {
                "secret".to_string()
            } else {
                spec.mount.clone()
            },
        })),
        "boru" => Ok(Box::new(BoruProvider {
            addr: spec.addr.clone(),
            token: spec.token.clone(),
        })),
        _ => Err(SekretoError::new(format!(
            "sekreto: unknown provider kind: {}",
            spec.kind
        ))),
    }
}

/// Build a whole provider chain from its declarative form.
pub fn makechain(specs: &[ProviderSpec]) -> Answer<Vec<Box<dyn Provider>>> {
    specs.iter().map(makeprovider).collect()
}
