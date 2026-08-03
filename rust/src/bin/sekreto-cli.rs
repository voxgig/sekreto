//! A tiny app that needs a secret.
//!
//! It asks sekreto for `api.token` and calls the token-protected API with
//! it. Every port ships this same CLI, and test/integration.sh runs all of
//! them against the same server from all four secret sources - which is
//! what proves the library, rather than the spec alone.
//!
//! Usage: sekreto-cli <api-url> [--source env|dotenv|vault|boru|chain]

use std::env;
use std::process;

use voxgig_sekreto::http;
use voxgig_sekreto::json;
use voxgig_sekreto::{makechain, ProviderSpec, Sekreto};

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

    let vaultspec = ProviderSpec {
        addr: envor("VAULT_ADDR", ""),
        token: envor("VAULT_TOKEN", ""),
        mount: envor("VAULT_MOUNT", ""),
        ..ProviderSpec::of("vault")
    };

    let boruspec = ProviderSpec {
        addr: envor("BORU_VAULT_ADDR", ""),
        token: envor("BORU_VAULT_TOKEN", ""),
        ..ProviderSpec::of("boru")
    };

    match source {
        "env" => vec![envspec],
        "dotenv" => vec![dotenvspec],
        "vault" => vec![vaultspec],
        "boru" => vec![boruspec],
        // The default: the chain an app would actually ship with - local
        // overrides first, shared vaults last.
        _ => vec![envspec, dotenvspec, vaultspec, boruspec],
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

    let providers = match makechain(&chainfor(&source)) {
        Ok(providers) => providers,
        Err(err) => {
            eprintln!("sekreto-cli: {}", err);
            return 2;
        }
    };

    let mut secrets = Sekreto::new(providers);

    let token = match secrets.get("api.token") {
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
        "{{\"ok\":true,\"lang\":{},\"source\":{},\"caller\":{}}}",
        json::quote(LANG),
        json::quote(&source),
        json::quote(&caller)
    );

    0
}

fn main() {
    process::exit(run());
}
