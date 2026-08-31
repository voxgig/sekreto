//! The providers a Sekreto chains together.
//!
//! A provider answers one question: "do you have this secret?" It returns
//! the value, or None to mean "ask the next one". Nothing else about a
//! provider is visible to the caller - which is the point: an app reads
//! `api.token` and never learns whether it came from the environment, a
//! .env file, HashiCorp Vault, AWS, GCP, Azure or a boru vault.
//!
//! Two failure shapes, and they are never interchangeable. A store that
//! does not hold the secret is a MISS (None) - the chain carries on. A
//! store that could not answer - bad credentials, unreachable host,
//! missing configuration - is an ERROR: falling through there would
//! quietly reach for a weaker store.
//!
//! A port of typescript/src/Providers.ts, which is canonical.

use std::cell::RefCell;
use std::collections::BTreeMap;
use std::env;
use std::fs;
use std::io;
use std::path::Path;
use std::process::Command;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use crate::http;
use crate::json::{self, Json};
use crate::sekreto::{awsparam, checkname, envkey, flatname, vaultref, Answer, SekretoError};
use crate::sigv4::{sigv4, Sigv4Input};

/// A source of secrets.
pub trait Provider {
    /// The value, or None if this provider does not have it.
    fn lookup(&self, name: &str) -> Answer<Option<String>>;

    /// A short description, shown by `Sekreto::sources`.
    fn describe(&self) -> String;
}

/// hashicorp: log in for a token instead of being handed one.
#[derive(Clone, Debug, Default)]
pub struct AuthSpec {
    /// `kubernetes` or `approle`.
    pub method: String,
    /// The auth mount, defaulting to the method name.
    pub mount: String,
    /// kubernetes: the Vault role to log in as.
    pub role: String,
    /// kubernetes: the service-account JWT itself (tests); None means the
    /// jwt file is read instead.
    pub jwt: Option<String>,
    /// kubernetes: where the JWT lives; the conventional pod path by
    /// default.
    pub jwtfile: String,
    /// approle: the role and secret ids.
    pub roleid: String,
    pub secretid: String,
}

/// The declarative form of a provider, as used in config and in the shared
/// spec. Absent fields are empty strings (or zero, or None).
#[derive(Clone, Debug, Default)]
pub struct ProviderSpec {
    pub kind: String,
    /// The store name `Sekreto::getfrom` addresses. Defaults to `kind`.
    pub name: String,
    pub prefix: String,
    /// dotenv: the file to read.
    pub file: String,
    /// memory: literal values, keyed like environment variables.
    pub values: BTreeMap<String, String>,
    /// file: the directory of one-secret-per-file entries.
    pub dir: String,
    /// hashicorp / boru (wire) / gcp / 1password / doppler / infisical:
    /// the base URL.
    pub addr: String,
    /// hashicorp / boru (wire) / gcp / azure / 1password / doppler /
    /// infisical: the access token.
    pub token: String,
    /// hashicorp / boru (wire): the KV mount (default `secret`).
    pub mount: String,
    /// hashicorp: KV engine version, 1 or 2 (0 means the default, 2).
    pub kv: u32,
    /// hashicorp: Vault Enterprise namespace (X-Vault-Namespace).
    pub vaultnamespace: String,
    /// hashicorp: log in for a token instead of being handed one.
    pub auth: Option<AuthSpec>,
    /// boru / secretspec: the executable to run (default: the kind's own
    /// name).
    pub command: String,
    /// boru: the namespace qualifying the alias.
    pub namespace: String,
    /// boru: the vault home, passed as BORU_HOME.
    pub home: String,
    /// secretspec: the profile to read (`--profile`).
    pub profile: String,
    /// secretspec: which of ITS backends to read from (`--provider`),
    /// e.g. `keyring` or `dotenv://.env`. Named `backend` because
    /// `provider` already means a sekreto provider.
    pub backend: String,
    /// secretspec: the audit reason recorded for the read (`--reason`).
    /// SecretSpec refuses to read without one.
    pub reason: String,
    /// aws: region and credentials; the standard AWS_* environment
    /// variables fill whichever are not given.
    pub region: String,
    pub keyid: String,
    pub secret: String,
    pub session: String,
    /// gcp / doppler / infisical: the project (GCP project id, Doppler
    /// project slug, Infisical workspace id).
    pub project: String,
    /// azure: the Key Vault name or full URL. 1password: the vault name
    /// or id.
    pub vault: String,
    /// azure: client-credential login. infisical: universal-auth login
    /// (tenant is Azure-only).
    pub tenant: String,
    pub clientid: String,
    pub clientsecret: String,
    /// azure: where to log in / where IMDS answers. gcp: where the
    /// metadata server answers. Overridable for tests and for clouds with
    /// nonstandard endpoints.
    pub loginaddr: String,
    pub imdsaddr: String,
    pub metadataaddr: String,
    /// azure: the Key Vault API version (default 7.4).
    pub apiversion: String,
    /// doppler: the config slug (with `project`).
    pub config: String,
    /// infisical: the environment slug and secret path.
    pub environment: String,
    pub path: String,
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
    // A read failure other than "file not found", kept for lookup to
    // raise: construction stays infallible, but the failure must not be
    // swallowed as "no secrets here".
    fail: Option<SekretoError>,
}

impl DotenvProvider {
    pub fn new(file: &str, prefix: &str) -> Self {
        // An absent file - or an absent directory - means "no secrets
        // here", exactly like FileProvider. Anything else (permission
        // denied, an unreadable mount) is a store that could not answer,
        // and swallowing it would fall through to a weaker store.
        let (values, fail) = match fs::read_to_string(file) {
            Ok(text) => (crate::sekreto::parsedotenv(&text), None),
            Err(err) => {
                if matches!(
                    err.kind(),
                    io::ErrorKind::NotFound | io::ErrorKind::NotADirectory
                ) {
                    (BTreeMap::new(), None)
                } else {
                    (
                        BTreeMap::new(),
                        Some(SekretoError::new(format!(
                            "sekreto: dotenv provider cannot read {}: {}",
                            file, err
                        ))),
                    )
                }
            }
        };

        DotenvProvider {
            file: file.to_string(),
            prefix: prefix.to_string(),
            values,
            fail,
        }
    }
}

impl Provider for DotenvProvider {
    fn lookup(&self, name: &str) -> Answer<Option<String>> {
        if let Some(fail) = &self.fail {
            return Err(fail.clone());
        }
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

/// A directory of one-secret-per-file entries, keyed like the
/// environment: `api.token` reads `<dir>/API_TOKEN`.
///
/// This is the shape of a mounted Kubernetes Secret, a Docker or Swarm
/// secret, and a systemd credentials directory, so those all work with no
/// further configuration. One trailing newline is stripped - tools that
/// write these files disagree about it, and a newline is never part of a
/// secret on purpose.
pub struct FileProvider {
    pub dir: String,
    pub prefix: String,
}

impl Provider for FileProvider {
    fn lookup(&self, name: &str) -> Answer<Option<String>> {
        let file = Path::new(&self.dir).join(envkey(name, &self.prefix)?);

        let text = match fs::read_to_string(&file) {
            Ok(text) => text,
            Err(err) => {
                // An absent file - or an absent directory - means "no
                // secrets here", exactly like a missing .env. Anything else
                // (permission denied, an unreadable mount) is a store that
                // could not answer.
                if matches!(
                    err.kind(),
                    io::ErrorKind::NotFound | io::ErrorKind::NotADirectory
                ) {
                    return Ok(None);
                }
                return Err(SekretoError::new(format!(
                    "sekreto: file provider cannot read {}: {}",
                    file.display(),
                    err
                )));
            }
        };

        let text = match text.strip_suffix('\n') {
            Some(rest) => rest.strip_suffix('\r').unwrap_or(rest),
            None => &text,
        };

        Ok(Some(text.to_string()))
    }

    fn describe(&self) -> String {
        format!("file:{}", self.dir)
    }
}

/// Refuse to send a secret-bearing credential in the clear.
///
/// A vault API is HTTPS in any real deployment; plaintext is a dev-mode
/// convenience. Sending a token over http to anything but the local
/// machine puts both the token and the secret it fetches on the wire for
/// anyone on the path, so sekreto will not do it. Loopback stays allowed:
/// that is `vault server -dev`, `boru vault serve`, and this repo's own
/// test harness.
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

/// A base URL with one trailing slash removed, so paths join cleanly.
fn trimslash(addr: &str) -> &str {
    addr.strip_suffix('/').unwrap_or(addr)
}

/// The first non-empty answer: the configured value, then each named
/// environment variable in turn.
fn firstof(config: &str, envnames: &[&str]) -> String {
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

/// Owned headers as the borrowed pairs the http client takes.
fn headerrefs(headers: &[(String, String)]) -> Vec<(&str, &str)> {
    headers
        .iter()
        .map(|(name, value)| (name.as_str(), value.as_str()))
        .collect()
}

/// What a store answered: the status, and the body when it parsed as JSON.
struct JsonResponse {
    status: u16,
    body: Option<Json>,
}

/// One JSON round-trip. Network failure is always an error - an
/// unreachable store is a store that could not answer.
fn fetchjson(
    method: &str,
    url: &str,
    headers: &[(&str, &str)],
    body: Option<&str>,
) -> Answer<JsonResponse> {
    let response = http::request(method, url, headers, body)?;

    let parsed = json::parse(&response.body);

    // A success status promised JSON; a body that does not parse means
    // the store could not answer coherently, and treating it as a miss
    // would fall through to a weaker store. Error statuses may carry
    // any body - they are decided on status alone.
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
fn renewtime(seconds: f64) -> Option<Instant> {
    if 0.0 < seconds && seconds.is_finite() {
        // Clamp before constructing the Duration: from_secs_f64 panics on a
        // non-finite or too-large value, and a token expiry comes from the
        // (untrusted) auth response. A century is more than any real lease.
        let bounded = (seconds - 60.0).max(1.0).min(3_153_600_000.0);
        Some(Instant::now() + Duration::from_secs_f64(bounded))
    } else {
        None
    }
}

/// The expiry a login response named, in seconds - zero when it named
/// none (or named it unreadably). Some stores send the number as a JSON
/// string, so the text form is parsed rather than the number taken.
fn expiryseconds(body: &Option<Json>, path: &[&str]) -> f64 {
    textat(body, path)
        .and_then(|text| text.parse::<f64>().ok())
        .unwrap_or(0.0)
}

/// Is a cached login token due for renewal? A token that never expires
/// (a configured one, or one whose login named no expiry) never is.
fn renewdue(renewat: &RefCell<Option<Instant>>) -> bool {
    renewat.borrow().map_or(false, |at| Instant::now() >= at)
}

/// The value at a path of map keys, as text - or None when absent or null.
fn textat(body: &Option<Json>, path: &[&str]) -> Option<String> {
    let mut at = body.as_ref()?;

    for key in path {
        at = at.get(key)?;
    }

    if matches!(at, Json::Null) {
        return None;
    }

    Some(at.text())
}

/// HashiCorp Vault.
///
/// KV v2 (the default): `api.token` reads `{addr}/v1/{mount}/data/api`
/// and takes the `token` field of `data.data`. KV v1 (`kv: 1`) reads
/// `{addr}/v1/{mount}/api` and takes the field of `data`. A 404 means
/// "not here" - a miss - so a vault can sit in a chain with fallbacks.
///
/// A Vault Enterprise namespace rides the X-Vault-Namespace header, on
/// logins as well as reads.
///
/// Instead of being handed a token, the provider can log in: Kubernetes
/// auth (the pod's service-account JWT, from its conventional path) or
/// AppRole. A failed login is an error, never a miss - it means this
/// store could not answer at all.
#[derive(Default)]
pub struct HashicorpProvider {
    pub addr: String,
    pub token: String,
    pub mount: String,
    /// KV engine version, 1 or 2.
    pub kv: u32,
    pub vaultnamespace: String,
    pub auth: Option<AuthSpec>,
    // The working token: a configured token is kept forever, a logged-in
    // token is renewed shortly before its lease runs out - a long-running
    // process must not keep presenting a token the vault already expired.
    livetoken: RefCell<Option<String>>,
    renewat: RefCell<Option<Instant>>,
}

impl HashicorpProvider {
    fn baseheaders(&self) -> Vec<(String, String)> {
        let mut headers = Vec::new();
        if !self.vaultnamespace.is_empty() {
            headers.push((
                "X-Vault-Namespace".to_string(),
                self.vaultnamespace.clone(),
            ));
        }
        headers
    }

    fn login(&self) -> Answer<String> {
        let auth = match &self.auth {
            Some(auth) => auth,
            None => {
                return Err(SekretoError::new(
                    "sekreto: hashicorp: no token and no auth method",
                ))
            }
        };

        let mount = if auth.mount.is_empty() {
            &auth.method
        } else {
            &auth.mount
        };
        let url = format!(
            "{}/v1/auth/{}/login",
            trimslash(&self.addr),
            mount
        );

        let body = match auth.method.as_str() {
            "kubernetes" => {
                let jwt = match &auth.jwt {
                    Some(jwt) => jwt.clone(),
                    None => {
                        let file = if auth.jwtfile.is_empty() {
                            "/var/run/secrets/kubernetes.io/serviceaccount/token"
                        } else {
                            &auth.jwtfile
                        };
                        fs::read_to_string(file)
                            .map(|text| text.trim().to_string())
                            .map_err(|_| {
                                SekretoError::new(format!(
                                    "sekreto: hashicorp: cannot read jwt file {}",
                                    file
                                ))
                            })?
                    }
                };
                Json::Map(BTreeMap::from([
                    ("role".to_string(), Json::Str(auth.role.clone())),
                    ("jwt".to_string(), Json::Str(jwt)),
                ]))
            }
            "approle" => Json::Map(BTreeMap::from([
                ("role_id".to_string(), Json::Str(auth.roleid.clone())),
                ("secret_id".to_string(), Json::Str(auth.secretid.clone())),
            ])),
            _ => {
                return Err(SekretoError::new(format!(
                    "sekreto: hashicorp: unknown auth method: {}",
                    auth.method
                )))
            }
        };

        let headers = self.baseheaders();
        let response = fetchjson(
            "POST",
            &url,
            &headerrefs(&headers),
            Some(&json::stringify(&body)),
        )?;

        let got = textat(&response.body, &["auth", "client_token"]).unwrap_or_default();

        if 200 != response.status || got.is_empty() {
            return Err(SekretoError::new(format!(
                "sekreto: hashicorp login failed: {}: {}",
                response.status, url
            )));
        }

        let lease = expiryseconds(&response.body, &["auth", "lease_duration"]);
        *self.renewat.borrow_mut() = renewtime(lease);

        Ok(got)
    }
}

impl Provider for HashicorpProvider {
    fn lookup(&self, name: &str) -> Answer<Option<String>> {
        checkaddr(&self.addr)?;

        if self.livetoken.borrow().is_none() || renewdue(&self.renewat) {
            let token = if self.token.is_empty() {
                self.login()?
            } else {
                self.token.clone()
            };
            *self.livetoken.borrow_mut() = Some(token);
        }
        let livetoken = self.livetoken.borrow().clone().unwrap_or_default();

        let reference = vaultref(name)?;
        let base = format!("{}/v1/{}", trimslash(&self.addr), self.mount);
        let url = if 1 == self.kv {
            format!("{}/{}", base, reference.path)
        } else {
            format!("{}/data/{}", base, reference.path)
        };

        let mut headers = self.baseheaders();
        headers.push(("X-Vault-Token".to_string(), livetoken));

        let response = fetchjson("GET", &url, &headerrefs(&headers), None)?;

        if 404 == response.status {
            return Ok(None);
        }

        if 200 != response.status {
            return Err(SekretoError::new(format!(
                "sekreto: hashicorp error: {}: {}",
                response.status, url
            )));
        }

        if 1 == self.kv {
            return Ok(textat(&response.body, &["data", reference.field.as_str()]));
        }
        Ok(textat(
            &response.body,
            &["data", "data", reference.field.as_str()],
        ))
    }

    fn describe(&self) -> String {
        format!("hashicorp:{}/{}", self.addr, self.mount)
    }
}

/// A boru vault (https://github.com/boru-lang/boru).
///
/// Two ways in, both boru's own.
///
/// With no `addr`, the CLI: `boru vault get --reveal <alias>` prints the
/// secret on stdout and nothing else. The passphrase is read by boru
/// itself from `BORU_VAULT_PASSPHRASE`; sekreto never accepts it as
/// config and never puts it on a command line, where it would show up in
/// the process table.
///
/// With an `addr`, boru's wire protocol: `boru vault serve` publishes a
/// read-only, HashiCorp-shaped provision API (boru's
/// design/VAULT-WIRE-PROTOCOL.0.md), authenticated by a capability token
/// from `boru vault grant`. A sekreto name is already a valid boru
/// alias, and boru aliases keep their dots, so `api.token` is the single
/// path segment `api.token` - not the `api`/`token` split a HashiCorp KV
/// gets. The value is the `value` field. A 404 is a miss; anything else
/// the server refuses (a revoked capability, a sealed vault) is an
/// error.
///
/// boru's `vault proxy` and `vault mcp` remain out of bounds: they are a
/// credential *broker*, built precisely so the caller never receives the
/// credential. `vault serve` is the provision endpoint, built to hand
/// the value back - that is the one sekreto uses.
pub struct BoruProvider {
    pub command: String,
    pub namespace: String,
    pub home: String,
    /// The wire-protocol address; empty means the CLI is used instead.
    pub addr: String,
    pub token: String,
    pub mount: String,
}

impl Provider for BoruProvider {
    fn lookup(&self, name: &str) -> Answer<Option<String>> {
        checkname(name)?;

        if !self.addr.is_empty() {
            checkaddr(&self.addr)?;

            let mount = if self.mount.is_empty() {
                "secret"
            } else {
                &self.mount
            };
            let alias = if self.namespace.is_empty() {
                name.to_string()
            } else {
                format!("{}/{}", self.namespace, name)
            };
            let url = format!("{}/v1/{}/data/{}", trimslash(&self.addr), mount, alias);

            let response = fetchjson(
                "GET",
                &url,
                &[("X-Vault-Token", self.token.as_str())],
                None,
            )?;

            if 404 == response.status {
                return Ok(None);
            }

            if 200 != response.status {
                return Err(SekretoError::new(format!(
                    "sekreto: boru serve error: {}: {}",
                    response.status, url
                )));
            }

            return Ok(textat(&response.body, &["data", "data", "value"]));
        }

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
        if !self.addr.is_empty() {
            return format!("boru:{}", trimslash(&self.addr));
        }

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

/// SecretSpec (https://secretspec.dev).
///
/// SecretSpec is a declaration - a `secretspec.toml` naming the secrets a
/// project needs - plus a chain of its own backends to satisfy them from.
/// That makes it the same shape as sekreto one level down, and the reason
/// to support it is the same reason sekreto exists: a project that has
/// already declared its secrets there should not have to declare them
/// again here.
///
/// Read through its CLI, as boru is, because that is the interface it
/// offers a program in another language: `secretspec get API_TOKEN`
/// prints the value on stdout and nothing else. A sekreto name maps to a
/// SecretSpec key exactly as it maps to an environment variable -
/// `api.token` is `API_TOKEN` - which is the convention SecretSpec's own
/// examples use.
///
/// `backend` selects one of SecretSpec's backends (`--provider`, e.g.
/// `keyring` or `dotenv://.env`) and is called `backend` here only
/// because `provider` already means something else in this library.
///
/// A reason is required, not optional: SecretSpec records every read in
/// an audit log and refuses to read at all without one. sekreto sends
/// `sekreto` unless told otherwise, so the audit trail says which tool
/// asked.
pub struct SecretSpecProvider {
    pub command: String,
    pub file: String,
    pub profile: String,
    pub backend: String,
    pub reason: String,
    pub prefix: String,
}

impl Provider for SecretSpecProvider {
    fn lookup(&self, name: &str) -> Answer<Option<String>> {
        let key = envkey(name, &self.prefix)?;

        let mut args: Vec<&str> = Vec::new();
        if !self.file.is_empty() {
            args.push("--file");
            args.push(&self.file);
        }
        args.push("get");
        args.push(&key);
        if !self.backend.is_empty() {
            args.push("--provider");
            args.push(&self.backend);
        }
        if !self.profile.is_empty() {
            args.push("--profile");
            args.push(&self.profile);
        }
        args.push("--reason");
        args.push(if self.reason.is_empty() {
            "sekreto"
        } else {
            &self.reason
        });

        let mut run = Command::new(&self.command);
        run.args(&args);

        let done = run.output().map_err(|err| {
            SekretoError::new(format!("sekreto: cannot run {}: {}", self.command, err))
        })?;

        if done.status.success() {
            // The value and one newline, and nothing else.
            let out = String::from_utf8_lossy(&done.stdout).to_string();
            return Ok(Some(
                out.strip_suffix('\n').map(str::to_string).unwrap_or(out),
            ));
        }

        let why = String::from_utf8_lossy(&done.stderr).trim().to_string();

        if secretspecmiss(&why, &key) {
            return Ok(None);
        }

        let reason = if why.is_empty() {
            format!("exit {}", done.status.code().unwrap_or(-1))
        } else {
            why
        };

        Err(SekretoError::new(format!(
            "sekreto: secretspec error: {}",
            reason
        )))
    }

    fn describe(&self) -> String {
        if self.backend.is_empty() {
            "secretspec".to_string()
        } else {
            format!("secretspec:{}", self.backend)
        }
    }
}

/// Does this SecretSpec failure mean "no such secret" rather than "I
/// could not answer"?
///
/// SecretSpec says `Secret 'API_TOKEN' not found` for both a name it does
/// not declare and one declared with no value, and both are misses: this
/// store does not hold it, so the chain carries on.
///
/// MATCHED ON THE WHOLE PHRASE, NOT ON "not found". SecretSpec also says
/// `Provider backend 'keyring' not found`, which is a store that could
/// not answer at all - and reading that as a miss is the worst failure
/// this library has, because the chain then falls through to a weaker
/// store without saying so. The key is required to appear, so the two
/// cannot be confused.
fn secretspecmiss(why: &str, key: &str) -> bool {
    why.contains(&format!("Secret '{}' not found", key))
}

/// The `YYYYMMDDTHHMMSSZ` timestamp SigV4 wants, for now.
fn awsnow() -> String {
    let seconds = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();

    let (year, month, day) = civildate((seconds / 86400) as i64);
    let clock = seconds % 86400;

    format!(
        "{:04}{:02}{:02}T{:02}{:02}{:02}Z",
        year,
        month,
        day,
        clock / 3600,
        clock % 3600 / 60,
        clock % 60
    )
}

/// Days since the epoch as a civil date - the classic era-based
/// conversion (Howard Hinnant's `civil_from_days`), exact for any date
/// the epoch can name.
fn civildate(days: i64) -> (i64, u32, u32) {
    let z = days + 719468;
    let era = if 0 <= z { z } else { z - 146096 } / 146097;
    let dayofera = z - era * 146097;
    let yearofera = (dayofera - dayofera / 1460 + dayofera / 36524 - dayofera / 146096) / 365;
    let year = yearofera + era * 400;
    let dayofyear = dayofera - (365 * yearofera + yearofera / 4 - yearofera / 100);
    let monthish = (5 * dayofyear + 2) / 153;
    let day = (dayofyear - (153 * monthish + 2) / 5 + 1) as u32;
    let month = (if monthish < 10 {
        monthish + 3
    } else {
        monthish - 9
    }) as u32;

    (if month <= 2 { year + 1 } else { year }, month, day)
}

/// Region and credentials, resolved for one AWS call.
struct AwsAuth {
    region: String,
    keyid: String,
    secret: String,
    session: String,
}

/// Region and credentials, from config first and the standard AWS_*
/// environment variables second - those are AWS's own convention, and a
/// pod or CI job that has them set should just work. Missing either is
/// an error: an AWS store with no credentials could not answer.
fn awsauth(region: &str, keyid: &str, secret: &str, session: &str) -> Answer<AwsAuth> {
    let region = firstof(region, &["AWS_REGION", "AWS_DEFAULT_REGION"]);
    let keyid = firstof(keyid, &["AWS_ACCESS_KEY_ID"]);
    let secret = firstof(secret, &["AWS_SECRET_ACCESS_KEY"]);
    let session = firstof(session, &["AWS_SESSION_TOKEN"]);

    if region.is_empty() {
        return Err(SekretoError::new(
            "sekreto: aws: no region (set region or AWS_REGION)",
        ));
    }
    if keyid.is_empty() || secret.is_empty() {
        return Err(SekretoError::new(
            "sekreto: aws: no credentials (set keyid/secret or AWS_ACCESS_KEY_ID/AWS_SECRET_ACCESS_KEY)",
        ));
    }

    Ok(AwsAuth {
        region,
        keyid,
        secret,
        session,
    })
}

/// One signed call to an AWS JSON-1.1 API.
fn awscall(
    addr: &str,
    auth: &AwsAuth,
    service: &str,
    target: &str,
    payload: &Json,
) -> Answer<JsonResponse> {
    let addr = if addr.is_empty() {
        // The China partition lives under its own suffix; every other
        // commercial region is plain amazonaws.com.
        let suffix = if auth.region.starts_with("cn-") {
            ".amazonaws.com.cn"
        } else {
            ".amazonaws.com"
        };
        format!("https://{}.{}{}", service, auth.region, suffix)
    } else {
        addr.to_string()
    };
    checkaddr(&addr)?;

    let url = format!("{}/", trimslash(&addr));
    let body = json::stringify(payload);

    let mut headers = vec![
        (
            "content-type".to_string(),
            "application/x-amz-json-1.1".to_string(),
        ),
        ("x-amz-target".to_string(), target.to_string()),
    ];

    let signed = sigv4(&Sigv4Input {
        method: "POST".to_string(),
        url: url.clone(),
        headers: headers.clone(),
        body: body.clone(),
        service: service.to_string(),
        region: auth.region.clone(),
        keyid: auth.keyid.clone(),
        secret: auth.secret.clone(),
        session: auth.session.clone(),
        datetime: awsnow(),
    })?;

    for (name, value) in signed {
        headers.push((name, value));
    }

    fetchjson("POST", &url, &headerrefs(&headers), Some(&body))
}

/// Does this AWS error body name one of the not-found types? Those are
/// a miss; every other failure is a store that could not answer.
fn awsmiss(body: &Option<Json>, types: &[&str]) -> bool {
    let errtype = match body.as_ref().and_then(|body| body.get("__type")) {
        Some(Json::Str(errtype)) => errtype.clone(),
        _ => String::new(),
    };

    types.iter().any(|name| errtype.contains(name))
}

/// AWS Secrets Manager.
///
/// `api.token` reads the secret named `api` (the vaultref path, so
/// `db.pass.main` reads `db/pass`) and takes the `token` field of its
/// JSON SecretString - the AWS idiom of one JSON map per secret. A
/// SecretString that is not JSON is the value itself, under the
/// conventional field `value`. Requests are SigV4-signed in-tree; see
/// src/sigv4.rs.
pub struct AwsSecretsProvider {
    pub region: String,
    pub keyid: String,
    pub secret: String,
    pub session: String,
    pub addr: String,
}

impl Provider for AwsSecretsProvider {
    fn lookup(&self, name: &str) -> Answer<Option<String>> {
        let reference = vaultref(name)?;
        let auth = awsauth(&self.region, &self.keyid, &self.secret, &self.session)?;

        let payload = Json::Map(BTreeMap::from([(
            "SecretId".to_string(),
            Json::Str(reference.path.clone()),
        )]));

        let response = awscall(
            &self.addr,
            &auth,
            "secretsmanager",
            "secretsmanager.GetSecretValue",
            &payload,
        )?;

        if 400 == response.status && awsmiss(&response.body, &["ResourceNotFoundException"]) {
            return Ok(None);
        }

        if 200 != response.status {
            return Err(SekretoError::new(format!(
                "sekreto: aws secretsmanager error: {}",
                response.status
            )));
        }

        let text = match response.body.as_ref().and_then(|body| body.get("SecretString")) {
            Some(Json::Str(text)) => text.clone(),
            _ => {
                // A binary secret has no fields to address; only the
                // conventional `value` field can mean "the bytes
                // themselves".
                if "value" != reference.field {
                    return Ok(None);
                }
                let bin = match response.body.as_ref().and_then(|body| body.get("SecretBinary")) {
                    Some(Json::Str(bin)) => bin.clone(),
                    _ => return Ok(None),
                };
                return Ok(http::unbase64(&bin)
                    .map(|bytes| String::from_utf8_lossy(&bytes).to_string()));
            }
        };

        if let Some(Json::Map(fields)) = json::parse(&text) {
            return Ok(fields
                .get(&reference.field)
                .filter(|value| !matches!(value, Json::Null))
                .map(|value| value.text()));
        }

        // A plain-string secret is the whole value; it has no named fields.
        if "value" == reference.field {
            return Ok(Some(text));
        }
        Ok(None)
    }

    // Config only, never the environment: describe() feeds the spec's
    // sources group, which must answer the same everywhere.
    fn describe(&self) -> String {
        format!("awssecrets:{}", self.region)
    }
}

/// AWS SSM Parameter Store.
///
/// `db.pass.main` reads the parameter `/db/pass/main` (under an optional
/// prefix path), decrypted. Parameter Store carries flat strings, so
/// there is no field indirection.
pub struct AwsParamsProvider {
    pub region: String,
    pub keyid: String,
    pub secret: String,
    pub session: String,
    pub addr: String,
    pub prefix: String,
}

impl Provider for AwsParamsProvider {
    fn lookup(&self, name: &str) -> Answer<Option<String>> {
        let paramname = awsparam(name, &self.prefix)?;
        let auth = awsauth(&self.region, &self.keyid, &self.secret, &self.session)?;

        let payload = Json::Map(BTreeMap::from([
            ("Name".to_string(), Json::Str(paramname)),
            ("WithDecryption".to_string(), Json::Bool(true)),
        ]));

        let response = awscall(&self.addr, &auth, "ssm", "AmazonSSM.GetParameter", &payload)?;

        if 400 == response.status && awsmiss(&response.body, &["ParameterNotFound"]) {
            return Ok(None);
        }

        if 200 != response.status {
            return Err(SekretoError::new(format!(
                "sekreto: aws ssm error: {}",
                response.status
            )));
        }

        Ok(textat(&response.body, &["Parameter", "Value"]))
    }

    fn describe(&self) -> String {
        format!("awsparams:{}{}", self.region, self.prefix)
    }
}

/// GCP Secret Manager.
///
/// `api.token` reads secret `api_token` (dots flattened to `_`; Secret
/// Manager ids have no hierarchy and reject dots), latest version. The
/// token comes from config, then `GOOGLE_OAUTH_ACCESS_TOKEN`, then the
/// GCE/GKE metadata server - so on Google's own platform no credential
/// configuration is needed at all.
///
/// The metadata call itself is plain http to a link-local host by
/// platform design; no credential rides on it, so `checkaddr` guards the
/// Secret Manager address instead.
#[derive(Default)]
pub struct GcpSecretsProvider {
    pub project: String,
    pub token: String,
    pub addr: String,
    pub metadataaddr: String,
    // A configured token is kept forever; a metadata-server token carries
    // expires_in and is renewed shortly before it runs out.
    livetoken: RefCell<Option<String>>,
    renewat: RefCell<Option<Instant>>,
}

impl GcpSecretsProvider {
    fn metadataaddr(&self) -> String {
        if !self.metadataaddr.is_empty() {
            return self.metadataaddr.clone();
        }
        match env::var("GCE_METADATA_HOST") {
            Ok(host) if !host.is_empty() => format!("http://{}", host),
            _ => "http://metadata.google.internal".to_string(),
        }
    }

    fn login(&self) -> Answer<String> {
        let configured = firstof(&self.token, &["GOOGLE_OAUTH_ACCESS_TOKEN"]);
        if !configured.is_empty() {
            return Ok(configured);
        }

        let url = format!(
            "{}/computeMetadata/v1/instance/service-accounts/default/token",
            trimslash(&self.metadataaddr())
        );

        let response = fetchjson("GET", &url, &[("Metadata-Flavor", "Google")], None)?;

        let got = textat(&response.body, &["access_token"]).unwrap_or_default();

        if 200 != response.status || got.is_empty() {
            return Err(SekretoError::new(
                "sekreto: gcp: no token and metadata server did not answer",
            ));
        }

        let expires = expiryseconds(&response.body, &["expires_in"]);
        *self.renewat.borrow_mut() = renewtime(expires);

        Ok(got)
    }
}

impl Provider for GcpSecretsProvider {
    fn lookup(&self, name: &str) -> Answer<Option<String>> {
        if self.project.is_empty() {
            return Err(SekretoError::new("sekreto: gcp: no project"));
        }

        let addr = if self.addr.is_empty() {
            "https://secretmanager.googleapis.com"
        } else {
            &self.addr
        };
        checkaddr(addr)?;

        if self.livetoken.borrow().is_none() || renewdue(&self.renewat) {
            *self.livetoken.borrow_mut() = Some(self.login()?);
        }
        let livetoken = self.livetoken.borrow().clone().unwrap_or_default();

        let url = format!(
            "{}/v1/projects/{}/secrets/{}/versions/latest:access",
            trimslash(addr),
            self.project,
            flatname(name, "_")?
        );

        let bearer = format!("Bearer {}", livetoken);
        let response = fetchjson("GET", &url, &[("authorization", bearer.as_str())], None)?;

        if 404 == response.status {
            return Ok(None);
        }

        if 200 != response.status {
            return Err(SekretoError::new(format!(
                "sekreto: gcp error: {}: {}",
                response.status, url
            )));
        }

        let data = match response
            .body
            .as_ref()
            .and_then(|body| body.get("payload"))
            .and_then(|payload| payload.get("data"))
        {
            Some(Json::Str(data)) => data.clone(),
            _ => return Ok(None),
        };

        Ok(http::unbase64(&data).map(|bytes| String::from_utf8_lossy(&bytes).to_string()))
    }

    fn describe(&self) -> String {
        format!("gcpsecrets:{}", self.project)
    }
}

/// Azure Key Vault.
///
/// `api.token` reads secret `api-token` (dots flattened to `-`; Key
/// Vault names allow nothing else), current version. The token comes
/// from config, then a client-credentials login when tenant/clientid/
/// clientsecret are given, then the IMDS managed-identity endpoint - so
/// on Azure's own platform no credential configuration is needed.
///
/// As with GCP, the IMDS call is plain http to a link-local host by
/// platform design and carries no credential; the login and vault
/// addresses are `checkaddr`-guarded.
#[derive(Default)]
pub struct AzureSecretsProvider {
    pub vault: String,
    pub token: String,
    pub tenant: String,
    pub clientid: String,
    pub clientsecret: String,
    pub loginaddr: String,
    pub imdsaddr: String,
    pub apiversion: String,
    // A configured token is kept forever; logged-in and IMDS tokens carry
    // expires_in and are renewed shortly before they run out.
    livetoken: RefCell<Option<String>>,
    renewat: RefCell<Option<Instant>>,
}

/// The OAuth resource a Key Vault token is scoped to.
const AZURERESOURCE: &str = "https://vault.azure.net";

impl AzureSecretsProvider {
    fn login(&self) -> Answer<String> {
        if !self.token.is_empty() {
            return Ok(self.token.clone());
        }

        if !self.tenant.is_empty() && !self.clientid.is_empty() && !self.clientsecret.is_empty() {
            let loginaddr = if self.loginaddr.is_empty() {
                "https://login.microsoftonline.com"
            } else {
                &self.loginaddr
            };
            checkaddr(loginaddr)?;

            let url = format!("{}/{}/oauth2/v2.0/token", trimslash(loginaddr), self.tenant);
            let form = format!(
                "grant_type=client_credentials&client_id={}&client_secret={}&scope={}",
                http::urlencode(&self.clientid),
                http::urlencode(&self.clientsecret),
                http::urlencode(&format!("{}/.default", AZURERESOURCE))
            );

            let response = fetchjson(
                "POST",
                &url,
                &[("content-type", "application/x-www-form-urlencoded")],
                Some(&form),
            )?;

            let got = textat(&response.body, &["access_token"]).unwrap_or_default();

            if 200 != response.status || got.is_empty() {
                return Err(SekretoError::new(format!(
                    "sekreto: azure login failed: {}",
                    response.status
                )));
            }

            // expires_in may arrive as a string; expiryseconds reads both.
            *self.renewat.borrow_mut() =
                renewtime(expiryseconds(&response.body, &["expires_in"]));
            return Ok(got);
        }

        let imds = format!(
            "{}/metadata/identity/oauth2/token?api-version=2018-02-01&resource={}",
            trimslash(if self.imdsaddr.is_empty() {
                "http://169.254.169.254"
            } else {
                &self.imdsaddr
            }),
            http::urlencode(AZURERESOURCE)
        );

        let response = fetchjson("GET", &imds, &[("Metadata", "true")], None)?;

        let got = textat(&response.body, &["access_token"]).unwrap_or_default();

        if 200 != response.status || got.is_empty() {
            return Err(SekretoError::new(
                "sekreto: azure: no token, no client credentials, and IMDS did not answer",
            ));
        }

        *self.renewat.borrow_mut() = renewtime(expiryseconds(&response.body, &["expires_in"]));
        Ok(got)
    }
}

impl Provider for AzureSecretsProvider {
    fn lookup(&self, name: &str) -> Answer<Option<String>> {
        if self.vault.is_empty() {
            return Err(SekretoError::new("sekreto: azure: no vault"));
        }

        // Only an explicit scheme is a URL; a vault NAMED httpvault must
        // still become https://httpvault.vault.azure.net.
        let vaulturl = if self.vault.starts_with("http://") || self.vault.starts_with("https://") {
            self.vault.clone()
        } else {
            format!("https://{}.vault.azure.net", self.vault)
        };
        checkaddr(&vaulturl)?;

        if self.livetoken.borrow().is_none() || renewdue(&self.renewat) {
            *self.livetoken.borrow_mut() = Some(self.login()?);
        }
        let livetoken = self.livetoken.borrow().clone().unwrap_or_default();

        let url = format!(
            "{}/secrets/{}?api-version={}",
            trimslash(&vaulturl),
            flatname(name, "-")?,
            if self.apiversion.is_empty() {
                "7.4"
            } else {
                &self.apiversion
            }
        );

        let bearer = format!("Bearer {}", livetoken);
        let response = fetchjson("GET", &url, &[("authorization", bearer.as_str())], None)?;

        if 404 == response.status {
            return Ok(None);
        }

        if 200 != response.status {
            return Err(SekretoError::new(format!(
                "sekreto: azure error: {}: {}",
                response.status,
                url.split('?').next().unwrap_or(&url)
            )));
        }

        Ok(textat(&response.body, &["value"]))
    }

    fn describe(&self) -> String {
        format!("azuresecrets:{}", self.vault)
    }
}

/// 1Password, through a Connect server.
///
/// The item titled `api.token` (titles keep their dots), in the named
/// vault. The value is the field with purpose PASSWORD, or the field
/// labelled `value`. A vault that cannot be found is an error - config
/// names it, so its absence is a broken store, not a missing secret.
#[derive(Default)]
pub struct OnePasswordProvider {
    pub addr: String,
    pub token: String,
    pub vault: String,
    vaultid: RefCell<Option<String>>,
}

impl OnePasswordProvider {
    fn resolvevault(&self, addr: &str, bearer: &str) -> Answer<String> {
        if self.vault.is_empty() {
            return Err(SekretoError::new("sekreto: onepassword: no vault"));
        }

        let response = fetchjson(
            "GET",
            &format!("{}/v1/vaults", addr),
            &[("authorization", bearer)],
            None,
        )?;

        let entries = match (&response.body, response.status) {
            (Some(Json::List(entries)), 200) => entries.clone(),
            _ => {
                return Err(SekretoError::new(format!(
                    "sekreto: onepassword error: {}: listing vaults",
                    response.status
                )))
            }
        };

        for entry in &entries {
            let id = entry.get("id").map(|value| value.text());
            let name = entry.get("name").map(|value| value.text());
            if Some(&self.vault) == id.as_ref() || Some(&self.vault) == name.as_ref() {
                return Ok(id.unwrap_or_default());
            }
        }

        Err(SekretoError::new(format!(
            "sekreto: onepassword: no vault named {}",
            self.vault
        )))
    }
}

impl Provider for OnePasswordProvider {
    fn lookup(&self, name: &str) -> Answer<Option<String>> {
        checkname(name)?;

        let addr = trimslash(&self.addr).to_string();
        if addr.is_empty() {
            return Err(SekretoError::new("sekreto: onepassword: no addr"));
        }
        checkaddr(&addr)?;

        let bearer = format!("Bearer {}", self.token);

        if self.vaultid.borrow().is_none() {
            *self.vaultid.borrow_mut() = Some(self.resolvevault(&addr, &bearer)?);
        }
        let vaultid = self.vaultid.borrow().clone().unwrap_or_default();

        let filter = http::urlencode(&format!("title eq \"{}\"", name));
        let found = fetchjson(
            "GET",
            &format!("{}/v1/vaults/{}/items?filter={}", addr, vaultid, filter),
            &[("authorization", bearer.as_str())],
            None,
        )?;

        let entries = match (&found.body, found.status) {
            (Some(Json::List(entries)), 200) => entries.clone(),
            _ => {
                return Err(SekretoError::new(format!(
                    "sekreto: onepassword error: {}: finding {}",
                    found.status, name
                )))
            }
        };

        if entries.is_empty() {
            return Ok(None);
        }

        let itemid = entries[0].get("id").map(|value| value.text()).unwrap_or_default();

        let item = fetchjson(
            "GET",
            &format!("{}/v1/vaults/{}/items/{}", addr, vaultid, itemid),
            &[("authorization", bearer.as_str())],
            None,
        )?;

        if 200 != item.status {
            return Err(SekretoError::new(format!(
                "sekreto: onepassword error: {}: reading {}",
                item.status, name
            )));
        }

        let fields = match item.body.as_ref().and_then(|body| body.get("fields")) {
            Some(Json::List(fields)) => fields.clone(),
            _ => Vec::new(),
        };

        for field in &fields {
            if let Some(Json::Str(purpose)) = field.get("purpose") {
                if "PASSWORD" == purpose {
                    return Ok(field
                        .get("value")
                        .filter(|value| !matches!(value, Json::Null))
                        .map(|value| value.text()));
                }
            }
        }
        for field in &fields {
            if let Some(Json::Str(label)) = field.get("label") {
                if "value" == label {
                    return Ok(field
                        .get("value")
                        .filter(|value| !matches!(value, Json::Null))
                        .map(|value| value.text()));
                }
            }
        }

        Ok(None)
    }

    fn describe(&self) -> String {
        format!("onepassword:{}", self.vault)
    }
}

/// Doppler.
///
/// The whole config is downloaded once - Doppler's own bulk endpoint -
/// and answered from memory, like a remote .env: `api.token` is the
/// `API_TOKEN` entry. A service token is config-scoped, so project and
/// config are only needed with broader tokens.
#[derive(Default)]
pub struct DopplerProvider {
    pub token: String,
    pub project: String,
    pub config: String,
    pub addr: String,
    values: RefCell<Option<BTreeMap<String, String>>>,
}

impl DopplerProvider {
    fn load(&self) -> Answer<BTreeMap<String, String>> {
        if let Some(values) = self.values.borrow().as_ref() {
            return Ok(values.clone());
        }

        let addr = if self.addr.is_empty() {
            "https://api.doppler.com"
        } else {
            &self.addr
        };
        let addr = trimslash(addr);
        checkaddr(addr)?;

        let mut url = format!("{}/v3/configs/config/secrets/download?format=json", addr);
        if !self.project.is_empty() {
            url.push_str(&format!("&project={}", http::urlencode(&self.project)));
        }
        if !self.config.is_empty() {
            url.push_str(&format!("&config={}", http::urlencode(&self.config)));
        }

        let bearer = format!("Bearer {}", self.token);
        let response = fetchjson("GET", &url, &[("authorization", bearer.as_str())], None)?;

        let entries = match (response.status, &response.body) {
            (200, Some(Json::Map(entries))) => entries.clone(),
            _ => {
                return Err(SekretoError::new(format!(
                    "sekreto: doppler error: {}",
                    response.status
                )))
            }
        };

        let mut values = BTreeMap::new();
        for (key, value) in entries {
            if !matches!(value, Json::Null) {
                values.insert(key, value.text());
            }
        }

        *self.values.borrow_mut() = Some(values.clone());
        Ok(values)
    }
}

impl Provider for DopplerProvider {
    fn lookup(&self, name: &str) -> Answer<Option<String>> {
        Ok(self.load()?.get(&envkey(name, "")?).cloned())
    }

    fn describe(&self) -> String {
        if self.project.is_empty() {
            "doppler".to_string()
        } else {
            format!("doppler:{}/{}", self.project, self.config)
        }
    }
}

/// Infisical.
///
/// `api.token` reads the secret keyed `API_TOKEN` (Infisical's own
/// convention is environment-style keys) at a secret path in one
/// environment of a project. Auth is a token, or a universal-auth
/// (machine identity) login with clientid/clientsecret.
#[derive(Default)]
pub struct InfisicalProvider {
    pub addr: String,
    pub token: String,
    pub clientid: String,
    pub clientsecret: String,
    pub project: String,
    pub environment: String,
    pub path: String,
    // A configured token is kept forever; a universal-auth token carries
    // expiresIn and is renewed shortly before it runs out.
    livetoken: RefCell<Option<String>>,
    renewat: RefCell<Option<Instant>>,
}

impl InfisicalProvider {
    fn login(&self, addr: &str) -> Answer<String> {
        if !self.token.is_empty() {
            return Ok(self.token.clone());
        }

        if self.clientid.is_empty() || self.clientsecret.is_empty() {
            return Err(SekretoError::new(
                "sekreto: infisical: no token and no client credentials",
            ));
        }

        let body = json::stringify(&Json::Map(BTreeMap::from([
            ("clientId".to_string(), Json::Str(self.clientid.clone())),
            (
                "clientSecret".to_string(),
                Json::Str(self.clientsecret.clone()),
            ),
        ])));

        let response = fetchjson(
            "POST",
            &format!("{}/api/v1/auth/universal-auth/login", addr),
            &[("content-type", "application/json")],
            Some(&body),
        )?;

        let got = textat(&response.body, &["accessToken"]).unwrap_or_default();

        if 200 != response.status || got.is_empty() {
            return Err(SekretoError::new(format!(
                "sekreto: infisical login failed: {}",
                response.status
            )));
        }

        let expires = expiryseconds(&response.body, &["expiresIn"]);
        *self.renewat.borrow_mut() = renewtime(expires);

        Ok(got)
    }
}

impl Provider for InfisicalProvider {
    fn lookup(&self, name: &str) -> Answer<Option<String>> {
        let addr = if self.addr.is_empty() {
            "https://app.infisical.com"
        } else {
            &self.addr
        };
        let addr = trimslash(addr).to_string();
        checkaddr(&addr)?;

        if self.project.is_empty() || self.environment.is_empty() {
            return Err(SekretoError::new(
                "sekreto: infisical: no project/environment",
            ));
        }

        if self.livetoken.borrow().is_none() || renewdue(&self.renewat) {
            *self.livetoken.borrow_mut() = Some(self.login(&addr)?);
        }
        let livetoken = self.livetoken.borrow().clone().unwrap_or_default();

        let url = format!(
            "{}/api/v3/secrets/raw/{}?workspaceId={}&environment={}&secretPath={}",
            addr,
            envkey(name, "")?,
            http::urlencode(&self.project),
            http::urlencode(&self.environment),
            http::urlencode(if self.path.is_empty() { "/" } else { &self.path })
        );

        let bearer = format!("Bearer {}", livetoken);
        let response = fetchjson("GET", &url, &[("authorization", bearer.as_str())], None)?;

        if 404 == response.status {
            return Ok(None);
        }

        if 200 != response.status {
            return Err(SekretoError::new(format!(
                "sekreto: infisical error: {}",
                response.status
            )));
        }

        Ok(textat(&response.body, &["secret", "secretValue"]))
    }

    fn describe(&self) -> String {
        format!("infisical:{}/{}", self.project, self.environment)
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
        "file" => Ok(Box::new(FileProvider {
            dir: spec.dir.clone(),
            prefix: spec.prefix.clone(),
        })),
        "hashicorp" => {
            let kv = if 0 == spec.kv { 2 } else { spec.kv };

            // A version typo like kv: 3 must not quietly behave as v2 and
            // turn its 404s into misses; there is nothing safe to assume
            // it meant.
            if 1 != kv && 2 != kv {
                return Err(SekretoError::new(format!(
                    "sekreto: hashicorp: unsupported kv version: {}",
                    kv
                )));
            }

            Ok(Box::new(HashicorpProvider {
                addr: spec.addr.clone(),
                token: spec.token.clone(),
                mount: if spec.mount.is_empty() {
                    "secret".to_string()
                } else {
                    spec.mount.clone()
                },
                kv,
                vaultnamespace: spec.vaultnamespace.clone(),
                auth: spec.auth.clone(),
                ..Default::default()
            }))
        }
        "boru" => Ok(Box::new(BoruProvider {
            command: if spec.command.is_empty() {
                "boru".to_string()
            } else {
                spec.command.clone()
            },
            namespace: spec.namespace.clone(),
            home: spec.home.clone(),
            addr: spec.addr.clone(),
            token: spec.token.clone(),
            mount: spec.mount.clone(),
        })),
        "awssecrets" => Ok(Box::new(AwsSecretsProvider {
            region: spec.region.clone(),
            keyid: spec.keyid.clone(),
            secret: spec.secret.clone(),
            session: spec.session.clone(),
            addr: spec.addr.clone(),
        })),
        "awsparams" => Ok(Box::new(AwsParamsProvider {
            region: spec.region.clone(),
            keyid: spec.keyid.clone(),
            secret: spec.secret.clone(),
            session: spec.session.clone(),
            addr: spec.addr.clone(),
            prefix: spec.prefix.clone(),
        })),
        "gcpsecrets" => Ok(Box::new(GcpSecretsProvider {
            project: spec.project.clone(),
            token: spec.token.clone(),
            addr: spec.addr.clone(),
            metadataaddr: spec.metadataaddr.clone(),
            ..Default::default()
        })),
        "azuresecrets" => Ok(Box::new(AzureSecretsProvider {
            vault: spec.vault.clone(),
            token: spec.token.clone(),
            tenant: spec.tenant.clone(),
            clientid: spec.clientid.clone(),
            clientsecret: spec.clientsecret.clone(),
            loginaddr: spec.loginaddr.clone(),
            imdsaddr: spec.imdsaddr.clone(),
            apiversion: spec.apiversion.clone(),
            ..Default::default()
        })),
        "onepassword" => Ok(Box::new(OnePasswordProvider {
            addr: spec.addr.clone(),
            token: spec.token.clone(),
            vault: spec.vault.clone(),
            ..Default::default()
        })),
        "doppler" => Ok(Box::new(DopplerProvider {
            token: spec.token.clone(),
            project: spec.project.clone(),
            config: spec.config.clone(),
            addr: spec.addr.clone(),
            ..Default::default()
        })),
        "infisical" => Ok(Box::new(InfisicalProvider {
            addr: spec.addr.clone(),
            token: spec.token.clone(),
            clientid: spec.clientid.clone(),
            clientsecret: spec.clientsecret.clone(),
            project: spec.project.clone(),
            environment: spec.environment.clone(),
            path: spec.path.clone(),
            ..Default::default()
        })),
        "secretspec" => Ok(Box::new(SecretSpecProvider {
            command: if spec.command.is_empty() {
                "secretspec".to_string()
            } else {
                spec.command.clone()
            },
            file: spec.file.clone(),
            profile: spec.profile.clone(),
            backend: spec.backend.clone(),
            reason: spec.reason.clone(),
            prefix: spec.prefix.clone(),
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
