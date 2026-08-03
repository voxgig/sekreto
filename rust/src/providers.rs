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
use std::process::Command;

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
    /// The store name `Sekreto::getfrom` addresses. Defaults to `kind`.
    pub name: String,
    pub prefix: String,
    pub file: String,
    pub values: BTreeMap<String, String>,
    /// hashicorp
    pub addr: String,
    pub token: String,
    pub mount: String,
    /// boru
    pub command: String,
    pub namespace: String,
    pub home: String,
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

/// Refuse to send a Vault token in the clear.
///
/// Vault's API is HTTPS in any real deployment; plaintext is a dev-mode
/// convenience. Sending `X-Vault-Token` over http to anything but the local
/// machine puts both the token and the secret it fetches on the wire for
/// anyone on the path, so sekreto will not do it. Loopback stays allowed:
/// that is `vault server -dev` and this repo's own test harness.
///
/// https goes over rustls, with the server certificate and host name both
/// verified; `SEKRETO_CA_BUNDLE` adds trust roots for an internal CA. See
/// `src/http.rs`.
pub fn checkaddr(addr: &str) -> Answer<()> {
    if addr.starts_with("https://") {
        return Ok(());
    }

    if !addr.starts_with("http://") {
        return Err(SekretoError::new(format!(
            "sekreto: not an http(s) address: {}",
            addr
        )));
    }

    let host = addr["http://".len()..]
        .split('/')
        .next()
        .unwrap_or("")
        .split(':')
        .next()
        .unwrap_or("");

    if matches!(host, "localhost" | "127.0.0.1" | "::1" | "[::1]") {
        return Ok(());
    }

    Err(SekretoError::new(format!(
        "sekreto: refusing to send a token in plaintext to {} (use https)",
        addr
    )))
}

/// HashiCorp Vault, KV v2.
///
/// `api.token` reads `{addr}/v1/{mount}/data/api` and takes the `token`
/// field of `data.data`. A 404 means "not here", which is a miss rather
/// than an error, so a vault can sit in a chain with fallbacks.
pub struct HashicorpProvider {
    pub addr: String,
    pub token: String,
    pub mount: String,
}

impl Provider for HashicorpProvider {
    fn lookup(&self, name: &str) -> Answer<Option<String>> {
        checkaddr(&self.addr)?;

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
                "sekreto: hashicorp error: {}: {}",
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
        format!("hashicorp:{}/{}", self.addr, self.mount)
    }
}

/// A boru vault (https://github.com/boru-lang/boru).
///
/// boru keeps secrets in a local encrypted keyring and hands a value out
/// through its own CLI: `boru vault get --reveal <alias>` prints the secret
/// on stdout, and nothing else.
///
/// There is deliberately no HTTP read here. boru's `vault proxy` and
/// `vault mcp` are a *credential broker*: they inject the real secret into an
/// outbound request and forward it, so an agent can call an API without ever
/// holding the credential. Handing a value back is the one thing that broker
/// is built not to do, so sekreto reads the vault the way boru itself does -
/// through the CLI.
///
/// A sekreto name is already a valid boru alias, so `api.token` crosses over
/// unchanged. A namespace qualifies it the way boru writes it, `ns:name`.
///
/// The passphrase is read by boru itself from `BORU_VAULT_PASSPHRASE`.
/// sekreto never accepts it as config and never puts it on a command line,
/// where it would show up in the process table.
pub struct BoruProvider {
    pub command: String,
    pub namespace: String,
    pub home: String,
}

impl Provider for BoruProvider {
    fn lookup(&self, name: &str) -> Answer<Option<String>> {
        crate::sekreto::checkname(name)?;

        let alias = if self.namespace.is_empty() {
            name.to_string()
        } else {
            format!("{}:{}", self.namespace, name)
        };

        let mut run = Command::new(&self.command);
        run.args(["vault", "get", "--reveal", &alias]);

        if !self.home.is_empty() {
            run.env("BORU_HOME", &self.home);
        }

        let done = run.output().map_err(|err| {
            SekretoError::new(format!("sekreto: cannot run {}: {}", self.command, err))
        })?;

        if done.status.success() {
            // boru prints the value and one newline, and nothing else.
            let out = String::from_utf8_lossy(&done.stdout).to_string();
            return Ok(Some(
                out.strip_suffix('\n').map(str::to_string).unwrap_or(out),
            ));
        }

        let why = String::from_utf8_lossy(&done.stderr).trim().to_string();

        // "no alias named" is boru saying it does not hold this secret, which
        // is a miss: the chain carries on to the next provider. A locked vault
        // or a wrong passphrase is not a miss - treating it as one would fall
        // through to a weaker store without saying so.
        if borumiss(&why) {
            return Ok(None);
        }

        let reason = if why.is_empty() {
            format!("exit {}", done.status.code().unwrap_or(-1))
        } else {
            why
        };

        Err(SekretoError::new(format!(
            "sekreto: boru vault error: {}",
            reason
        )))
    }

    fn describe(&self) -> String {
        if self.namespace.is_empty() {
            "boru".to_string()
        } else {
            format!("boru:{}", self.namespace)
        }
    }
}

/// Does this boru failure mean "no such secret" rather than "I could not
/// answer"? Matched on boru's own wording for a missing alias.
fn borumiss(why: &str) -> bool {
    why.contains("no alias named")
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
        "hashicorp" => Ok(Box::new(HashicorpProvider {
            addr: spec.addr.clone(),
            token: spec.token.clone(),
            mount: if spec.mount.is_empty() {
                "secret".to_string()
            } else {
                spec.mount.clone()
            },
        })),
        "boru" => Ok(Box::new(BoruProvider {
            command: if spec.command.is_empty() {
                "boru".to_string()
            } else {
                spec.command.clone()
            },
            namespace: spec.namespace.clone(),
            home: spec.home.clone(),
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
