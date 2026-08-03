//! A tiny app that needs a secret.
//!
//! It asks sekreto for `api.token` and calls the token-protected API with
//! it. Every port ships this same CLI, and test/integration.sh runs all of
//! them against the same server from every secret source - which is
//! what proves the library, rather than the spec alone.
//!
//! Usage: sekreto-cli <api-url> [--source <source>] [--store <name>]
//!
//! Sources: env dotenv file hashicorp boru boruwire awssecrets awsparams
//!          gcpsecrets azuresecrets onepassword doppler infisical chain
//!
//! Each source's configuration arrives in the environment variables its
//! own ecosystem already uses (VAULT_*, AWS_*, OP_CONNECT_*, ...), listed
//! in chainfor below.

use std::env;
use std::process;

use voxgig_sekreto::http;
use voxgig_sekreto::json;
use voxgig_sekreto::{makechain, AuthSpec, ProviderSpec, Sekreto};

const LANG: &str = "rust";

fn envor(name: &str, fallback: &str) -> String {
    match env::var(name) {
        Ok(value) if !value.is_empty() => value,
        _ => fallback.to_string(),
    }
}

fn chainfor(source: &str) -> Vec<ProviderSpec> {
    let envspec = ProviderSpec {
        prefix: envor("SEKRETO_PREFIX", ""),
        ..ProviderSpec::of("env")
    };

    let dotenvspec = ProviderSpec {
        file: envor("SEKRETO_DOTENV", ".env"),
        ..ProviderSpec::of("dotenv")
    };

    let filespec = ProviderSpec {
        dir: envor("SEKRETO_FILEDIR", "/run/secrets"),
        ..ProviderSpec::of("file")
    };

    // VAULT_AUTH names a login method; without it the provider expects to
    // be handed VAULT_TOKEN.
    let vaultauth = match envor("VAULT_AUTH", "") {
        method if method.is_empty() => None,
        method => Some(AuthSpec {
            method,
            role: envor("VAULT_ROLE", ""),
            jwtfile: envor("VAULT_JWT_FILE", ""),
            roleid: envor("VAULT_ROLE_ID", ""),
            secretid: envor("VAULT_SECRET_ID", ""),
            ..Default::default()
        }),
    };

    let hashicorpspec = ProviderSpec {
        addr: envor("VAULT_ADDR", ""),
        token: envor("VAULT_TOKEN", ""),
        mount: envor("VAULT_MOUNT", ""),
        kv: envor("VAULT_KV", "").parse().unwrap_or(0),
        vaultnamespace: envor("VAULT_NAMESPACE", ""),
        auth: vaultauth,
        ..ProviderSpec::of("hashicorp")
    };

    let boruspec = ProviderSpec {
        command: envor("BORU_COMMAND", "boru"),
        namespace: envor("BORU_NAMESPACE", ""),
        home: envor("BORU_HOME", ""),
        ..ProviderSpec::of("boru")
    };

    // The same vault over its wire protocol (`boru vault serve`) instead
    // of the CLI: an address plus a capability token from `vault grant`.
    let boruwirespec = ProviderSpec {
        addr: envor("BORU_ADDR", ""),
        token: envor("BORU_TOKEN", ""),
        namespace: envor("BORU_NAMESPACE", ""),
        ..ProviderSpec::of("boru")
    };

    let awssecretsspec = ProviderSpec {
        region: envor("AWS_REGION", ""),
        addr: envor("AWS_ENDPOINT", ""),
        ..ProviderSpec::of("awssecrets")
    };

    let awsparamsspec = ProviderSpec {
        region: envor("AWS_REGION", ""),
        addr: envor("AWS_ENDPOINT", ""),
        prefix: envor("AWS_PARAM_PREFIX", ""),
        ..ProviderSpec::of("awsparams")
    };

    let gcpspec = ProviderSpec {
        project: envor("GCP_PROJECT", ""),
        addr: envor("GCP_ADDR", ""),
        metadataaddr: envor("GCP_METADATA_ADDR", ""),
        ..ProviderSpec::of("gcpsecrets")
    };

    let azurespec = ProviderSpec {
        vault: envor("AZURE_VAULT", ""),
        token: envor("AZURE_TOKEN", ""),
        tenant: envor("AZURE_TENANT", ""),
        clientid: envor("AZURE_CLIENT_ID", ""),
        clientsecret: envor("AZURE_CLIENT_SECRET", ""),
        loginaddr: envor("AZURE_LOGIN_ADDR", ""),
        imdsaddr: envor("AZURE_IMDS_ADDR", ""),
        ..ProviderSpec::of("azuresecrets")
    };

    let onepasswordspec = ProviderSpec {
        addr: envor("OP_CONNECT_HOST", ""),
        token: envor("OP_CONNECT_TOKEN", ""),
        vault: envor("OP_VAULT", ""),
        ..ProviderSpec::of("onepassword")
    };

    let dopplerspec = ProviderSpec {
        token: envor("DOPPLER_TOKEN", ""),
        project: envor("DOPPLER_PROJECT", ""),
        config: envor("DOPPLER_CONFIG", ""),
        addr: envor("DOPPLER_ADDR", ""),
        ..ProviderSpec::of("doppler")
    };

    let infisicalspec = ProviderSpec {
        addr: envor("INFISICAL_ADDR", ""),
        token: envor("INFISICAL_TOKEN", ""),
        clientid: envor("INFISICAL_CLIENT_ID", ""),
        clientsecret: envor("INFISICAL_CLIENT_SECRET", ""),
        project: envor("INFISICAL_PROJECT", ""),
        environment: envor("INFISICAL_ENV", ""),
        path: envor("INFISICAL_PATH", ""),
        ..ProviderSpec::of("infisical")
    };

    match source {
        "env" => vec![envspec],
        "dotenv" => vec![dotenvspec],
        "file" => vec![filespec],
        "hashicorp" => vec![hashicorpspec],
        "boru" => vec![boruspec],
        "boruwire" => vec![boruwirespec],
        "awssecrets" => vec![awssecretsspec],
        "awsparams" => vec![awsparamsspec],
        "gcpsecrets" => vec![gcpspec],
        "azuresecrets" => vec![azurespec],
        "onepassword" => vec![onepasswordspec],
        "doppler" => vec![dopplerspec],
        "infisical" => vec![infisicalspec],
        // The default: the chain an app would actually ship with - local
        // overrides first, shared vaults last.
        _ => vec![envspec, dotenvspec, hashicorpspec, boruspec],
    }
}

fn run() -> i32 {
    let args: Vec<String> = env::args().skip(1).collect();

    let url = args
        .first()
        .cloned()
        .unwrap_or_else(|| "http://127.0.0.1:8099/whoami".to_string());

    let source = match args.iter().position(|arg| "--source" == arg) {
        Some(at) if at + 1 < args.len() => args[at + 1].clone(),
        _ => "chain".to_string(),
    };

    // --store names a store outright: the secret must come from that one, not
    // from whichever provider happens to answer first.
    let store = match args.iter().position(|arg| "--store" == arg) {
        Some(at) if at + 1 < args.len() => args[at + 1].clone(),
        _ => String::new(),
    };

    let specs = chainfor(&source);
    let names: Vec<String> = specs.iter().map(|spec| spec.name.clone()).collect();

    let providers = match makechain(&specs) {
        Ok(providers) => providers,
        Err(err) => {
            eprintln!("sekreto-cli: {}", err);
            return 2;
        }
    };

    let mut secrets = Sekreto::named(providers, &names, true);

    let found = if store.is_empty() {
        secrets.get("api.token")
    } else {
        secrets.getfrom(&store, "api.token")
    };

    let token = match found {
        Ok(token) => token,
        Err(err) => {
            eprintln!("sekreto-cli: {}", err);
            return 2;
        }
    };

    let bearer = format!("Bearer {}", token);

    let response = match http::getwith(
        &url,
        &[("Authorization", &bearer), ("X-Sekreto-Lang", LANG)],
    ) {
        Ok(response) => response,
        Err(err) => {
            eprintln!("sekreto-cli: {}", secrets.redact(&err));
            return 1;
        }
    };

    if 200 != response.status {
        // Never print the token itself, even when the call fails.
        eprintln!("sekreto-cli: {}", secrets.redact(&response.body));
        return 1;
    }

    let caller = json::parse(&response.body)
        .and_then(|body| body.get("caller").map(|value| value.text()))
        .unwrap_or_default();

    // Assembled field by field: the shared JSON model sorts map keys, and
    // every port must print the same bytes.
    println!(
        "{{\"ok\":true,\"lang\":{},\"source\":{},\"store\":{},\"caller\":{}}}",
        json::quote(LANG),
        json::quote(&source),
        json::quote(&store),
        json::quote(&caller)
    );

    0
}

fn main() {
    process::exit(run());
}
