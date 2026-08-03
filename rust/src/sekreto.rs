//! sekreto: one interface for secrets, wherever they live.
//!
//! A `Sekreto` is an ordered chain of providers. `get` asks each in turn and
//! returns the first hit, so an app can be configured from environment
//! variables in development and a vault in production without changing a
//! line of its own code.
//!
//! A port of typescript/src/Sekreto.ts, which is canonical.
//!
//! Rust has no exceptions, so where the canonical implementation throws a
//! `SekretoError` this port returns one in a `Result`.

use std::collections::BTreeMap;
use std::fmt;

use crate::providers::Provider;

/// Anything sekreto refuses to do: a bad name, a missing secret, a provider
/// that could not be reached.
#[derive(Clone, Debug, PartialEq)]
pub struct SekretoError {
    pub message: String,
}

impl SekretoError {
    pub fn new(message: impl Into<String>) -> Self {
        SekretoError {
            message: message.into(),
        }
    }
}

impl fmt::Display for SekretoError {
    fn fmt(&self, out: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(out, "{}", self.message)
    }
}

impl std::error::Error for SekretoError {}

impl From<String> for SekretoError {
    fn from(message: String) -> Self {
        SekretoError::new(message)
    }
}

pub type Answer<T> = Result<T, SekretoError>;

/// Is this a well-formed secret name?
pub fn validname(name: &str) -> bool {
    if name.is_empty() {
        return false;
    }

    name.split('.').all(|part| {
        !part.is_empty()
            && part
                .chars()
                .all(|head| head.is_ascii_lowercase() || head.is_ascii_digit() || '_' == head)
    })
}

pub fn checkname(name: &str) -> Answer<()> {
    if !validname(name) {
        return Err(SekretoError::new(format!(
            "sekreto: invalid name: {}",
            name
        )));
    }
    Ok(())
}

/// The environment-variable key for a name: `api.token` -> `API_TOKEN`.
pub fn envkey(name: &str, prefix: &str) -> Answer<String> {
    checkname(name)?;

    Ok(format!(
        "{}{}",
        prefix,
        name.split('.')
            .collect::<Vec<&str>>()
            .join("_")
            .to_uppercase()
    ))
}

/// Where a name lives in a KV vault.
#[derive(Clone, Debug, PartialEq)]
pub struct VaultRef {
    pub path: String,
    pub field: String,
}

/// Split a name into its vault path and field: `api.token` -> `api` /
/// `token`.
///
/// A single-segment name has no path of its own, so it becomes a secret of
/// that name with the conventional field `value`.
pub fn vaultref(name: &str) -> Answer<VaultRef> {
    checkname(name)?;

    let parts: Vec<&str> = name.split('.').collect();

    if 1 == parts.len() {
        return Ok(VaultRef {
            path: parts[0].to_string(),
            field: "value".to_string(),
        });
    }

    Ok(VaultRef {
        path: parts[..parts.len() - 1].join("/"),
        field: parts[parts.len() - 1].to_string(),
    })
}

/// A name flattened to one segment: `api.token` -> `api_token` (GCP
/// Secret Manager, `_`) or `api-token` (Azure Key Vault, `-`).
///
/// Those stores have no path hierarchy and reject dots in ids, so the
/// dots become the store's conventional separator.
pub fn flatname(name: &str, sep: &str) -> Answer<String> {
    checkname(name)?;
    Ok(name.split('.').collect::<Vec<&str>>().join(sep))
}

/// The AWS SSM Parameter Store name for a name: dots become the path
/// hierarchy, rooted at `/` (or at a prefix): `db.pass.main` ->
/// `/db/pass/main`, or `/app/db/pass/main` under prefix `/app`.
pub fn awsparam(name: &str, prefix: &str) -> Answer<String> {
    checkname(name)?;

    let mut base = prefix.to_string();
    if !base.is_empty() && !base.starts_with('/') {
        base = format!("/{}", base);
    }
    if base.ends_with('/') {
        base.truncate(base.len() - 1);
    }

    Ok(format!(
        "{}/{}",
        base,
        name.split('.').collect::<Vec<&str>>().join("/")
    ))
}

/// Parse `.env` text into a map of raw keys to values.
///
/// Deliberately small: `KEY=value`, optional `export`, `#` comments on their
/// own line, and single- or double-quoted values (double quotes also
/// unescape `\n`, `\r`, `\t` and `\\`). A line with no `=` is skipped.
pub fn parsedotenv(text: &str) -> BTreeMap<String, String> {
    let mut out = BTreeMap::new();

    for rawline in text.split('\n') {
        let line = rawline.trim_end_matches('\r').trim();

        if line.is_empty() || line.starts_with('#') {
            continue;
        }

        let body = match line.strip_prefix("export ") {
            Some(rest) => rest.trim(),
            None => line,
        };

        let eq = match body.find('=') {
            Some(at) if 0 < at => at,
            _ => continue,
        };

        let key = body[..eq].trim().to_string();
        let mut value = body[eq + 1..].trim().to_string();

        if 2 <= value.len() && value.starts_with('"') && value.ends_with('"') {
            value = unescape(&value[1..value.len() - 1]);
        } else if 2 <= value.len() && value.starts_with('\'') && value.ends_with('\'') {
            value = value[1..value.len() - 1].to_string();
        }

        out.insert(key, value);
    }

    out
}

fn unescape(text: &str) -> String {
    let chars: Vec<char> = text.chars().collect();
    let mut out = String::new();
    let mut index = 0;

    while index < chars.len() {
        if '\\' == chars[index] && index + 1 < chars.len() {
            let next = chars[index + 1];
            index += 2;
            match next {
                'n' => out.push('\n'),
                'r' => out.push('\r'),
                't' => out.push('\t'),
                '\\' => out.push('\\'),
                '"' => out.push('"'),
                _ => {
                    out.push('\\');
                    out.push(next);
                }
            }
        } else {
            out.push(chars[index]);
            index += 1;
        }
    }

    out
}

/// Replace known secret values in text with `[redacted]`.
///
/// Only values of four characters or more are replaced: shorter ones are too
/// likely to appear in ordinary text, and redacting them would make logs
/// unreadable without making them safer.
pub fn redact(text: &str, values: &[String]) -> String {
    let mut out = text.to_string();

    for value in values {
        if 4 > value.len() {
            continue;
        }
        out = out
            .split(value.as_str())
            .collect::<Vec<&str>>()
            .join("[redacted]");
    }

    out
}

/// The store name a provider answers to when nothing says otherwise.
///
/// `describe` opens with the provider's kind - `hashicorp:...`,
/// `dotenv:...`, plain `env` - so the kind is the natural default, and a
/// custom provider gets a sensible name without implementing anything extra.
pub fn storename(provider: &dyn Provider) -> String {
    provider
        .describe()
        .split(':')
        .next()
        .unwrap_or("")
        .to_string()
}

/// One provider in the chain, under the store name it answers to.
struct Entry {
    store: String,
    provider: Box<dyn Provider>,
}

/// The secrets facade: a chain of providers plus a cache.
///
/// Two ways to read. `get` is transparent - it walks the chain and takes the
/// first hit, and the caller never learns which store answered. `getfrom` is
/// directed - it names the store, and only that store is asked.
pub struct Sekreto {
    entries: Vec<Entry>,
    docache: bool,
    // A Vec, not a map: the store a value came from stays attached, and
    // redaction order does not vary between runs.
    cache: Vec<(String, String, String)>,
}

impl Sekreto {
    /// A Sekreto over this chain, caching resolved values. Each provider
    /// answers to its own kind as a store name.
    pub fn new(providers: Vec<Box<dyn Provider>>) -> Self {
        Sekreto::named(providers, &[], true)
    }

    /// A Sekreto that asks its providers afresh every time.
    pub fn uncached(providers: Vec<Box<dyn Provider>>) -> Self {
        Sekreto::named(providers, &[], false)
    }

    /// A Sekreto whose providers answer to the given store names, in the same
    /// order. A name left empty falls back to the provider's kind.
    pub fn named(providers: Vec<Box<dyn Provider>>, names: &[String], docache: bool) -> Self {
        let entries = providers
            .into_iter()
            .enumerate()
            .map(|(index, provider)| {
                let store = match names.get(index) {
                    Some(name) if !name.is_empty() => name.clone(),
                    _ => storename(provider.as_ref()),
                };
                Entry { store, provider }
            })
            .collect();

        Sekreto {
            entries,
            docache,
            cache: Vec::new(),
        }
    }

    /// The secret, or a SekretoError if no provider has it.
    pub fn get(&mut self, name: &str) -> Answer<String> {
        match self.trysecret(name)? {
            Some(found) => Ok(found),
            None => Err(SekretoError::new(format!(
                "sekreto: unknown secret: {}",
                name
            ))),
        }
    }

    /// The secret, or None if no provider has it.
    pub fn trysecret(&mut self, name: &str) -> Answer<Option<String>> {
        self.resolve("", name, None)
    }

    /// The secret from one named store, or a SekretoError if that store does
    /// not have it.
    pub fn getfrom(&mut self, store: &str, name: &str) -> Answer<String> {
        match self.tryfrom(store, name)? {
            Some(found) => Ok(found),
            None => Err(SekretoError::new(format!(
                "sekreto: unknown secret: {}:{}",
                store, name
            ))),
        }
    }

    /// The secret from one named store, or None if that store does not have
    /// it.
    ///
    /// Naming a store that is not in the chain is an error, not a miss:
    /// `trysecret` already means "this store may not have it", so it cannot
    /// also mean "this store may not exist" without hiding a typo.
    pub fn tryfrom(&mut self, store: &str, name: &str) -> Answer<Option<String>> {
        if !self.entries.iter().any(|entry| entry.store == store) {
            return Err(SekretoError::new(format!(
                "sekreto: unknown store: {}",
                store
            )));
        }

        self.resolve(store, name, Some(store))
    }

    /// Walk the chain, optionally restricted to one store.
    fn resolve(
        &mut self,
        cachestore: &str,
        name: &str,
        only: Option<&str>,
    ) -> Answer<Option<String>> {
        checkname(name)?;

        if self.docache {
            if let Some((_, _, found)) = self
                .cache
                .iter()
                .find(|(store, key, _)| store == cachestore && key == name)
            {
                return Ok(Some(found.clone()));
            }
        }

        for entry in &self.entries {
            if let Some(store) = only {
                if entry.store != store {
                    continue;
                }
            }

            if let Some(found) = entry.provider.lookup(name)? {
                if self.docache {
                    self.cache
                        .push((cachestore.to_string(), name.to_string(), found.clone()));
                }
                return Ok(Some(found));
            }
        }

        Ok(None)
    }

    /// Does any provider have this secret?
    pub fn has(&mut self, name: &str) -> Answer<bool> {
        Ok(self.trysecret(name)?.is_some())
    }

    /// Does this named store have this secret?
    pub fn hasin(&mut self, store: &str, name: &str) -> Answer<bool> {
        Ok(self.tryfrom(store, name)?.is_some())
    }

    /// Every named secret at once. Missing ones are an error.
    pub fn all(&mut self, names: &[String]) -> Answer<BTreeMap<String, String>> {
        let mut out = BTreeMap::new();

        for name in names {
            out.insert(name.clone(), self.get(name)?);
        }

        Ok(out)
    }

    /// A description of each provider, in resolution order.
    pub fn sources(&self) -> Vec<String> {
        self.entries
            .iter()
            .map(|entry| entry.provider.describe())
            .collect()
    }

    /// The name of each store that can be named by `getfrom`, in resolution
    /// order and without repeats.
    pub fn stores(&self) -> Vec<String> {
        let mut out: Vec<String> = Vec::new();

        for entry in &self.entries {
            if !out.contains(&entry.store) {
                out.push(entry.store.clone());
            }
        }

        out
    }

    /// Replace every value this Sekreto has resolved with `[redacted]`.
    pub fn redact(&self, text: &str) -> String {
        let values: Vec<String> = self
            .cache
            .iter()
            .map(|(_, _, value)| value.clone())
            .collect();
        redact(text, &values)
    }

    /// Drop cached values, so the next `get` asks the providers again.
    pub fn refresh(&mut self) {
        self.cache.clear();
    }
}
