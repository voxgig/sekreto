// RUN: make test
// RUN-SOME: cargo test -p voxgig_sekreto_plugins fullset
//
// THE PLUGIN SEAM, FROM THE PLUGINS' SIDE: the full set holds every kind,
// every kind builds from a spec, one plugin is enough for a chain that
// names only it, one plugin links only what it needs, and the CLI passes
// the whole set.
//
// Moving the provider kinds that open sockets and spawn processes out of
// the core made a consumer's PLUGIN LIST load-bearing: a kind nobody
// passed in is not in the catalog, and a chain naming it is refused. That
// is the intended behaviour, and it means a consumer can be broken without
// a single conformance test noticing - the conformance suite passes every
// plugin, so it can never see a missing one.
//
// The core's half of the seam is pinned in ../../tests/plugin.rs, which
// cannot import any of this: every plugin crate depends on the core, so
// the core's own tests naming one would be a dependency cycle.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

use voxgig_sekreto::{Options, ProviderSpec, Sekreto, BUILTIN_KINDS, PLUGIN_KINDS};
use voxgig_sekreto_plugins::{all, hashicorp};

const KINDS: [&str; 10] = [
    "awsparams",
    "awssecrets",
    "azuresecrets",
    "boru",
    "doppler",
    "gcpsecrets",
    "hashicorp",
    "infisical",
    "onepassword",
    "secretspec",
];

fn sorted(mut list: Vec<String>) -> Vec<String> {
    list.sort();
    list
}

fn here() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
}

#[test]
fn the_full_set_holds_every_kind() {
    let names = sorted(all().iter().map(|one| one.name.clone()).collect());
    assert_eq!(KINDS.to_vec(), names);

    // ...and the core's list of what ships as a plugin says the same. It
    // is what tells a typo from a plugin nobody passed in, so a kind added
    // on one side and not the other would give the wrong advice.
    assert_eq!(
        KINDS.to_vec(),
        sorted(PLUGIN_KINDS.iter().map(|k| k.to_string()).collect())
    );
}

// Naming a kind is not enough: a kind can be in the catalog and still fail
// to build. Construction is what the CLI does before any network.
#[test]
fn every_kind_builds_from_a_spec() {
    let mut every: Vec<String> = BUILTIN_KINDS.iter().map(|k| k.to_string()).collect();
    every.extend(KINDS.iter().map(|k| k.to_string()));
    let every = sorted(every);

    let chain: Vec<ProviderSpec> = every
        .iter()
        .map(|kind| ProviderSpec {
            addr: "http://127.0.0.1:8200".to_string(),
            token: "t".to_string(),
            dir: "/tmp".to_string(),
            file: "/tmp/.env".to_string(),
            ..ProviderSpec::of(kind)
        })
        .collect();

    let secrets = Sekreto::new(Options {
        plugins: all(),
        providers: chain,
        ..Default::default()
    })
    .expect("every kind builds");

    assert_eq!(every, secrets.stores());
    assert_eq!(every, secrets.host().list().keys());

    for entry in secrets.host().list().keys() {
        assert_eq!(
            Some("live"),
            secrets.host().list().get(entry.as_str()).as_str(),
            "{} is not live",
            entry
        );
    }
}

#[test]
fn the_cli_passes_the_full_set() {
    let src = std::fs::read_to_string(here().join("src/bin/sekreto-cli.rs")).expect("the CLI");

    assert!(src.contains("use voxgig_sekreto_plugins::all;"), "{}", src);
    assert!(src.contains("plugins: all(),"), "{}", src);
}

// --- what a consumer sees ----------------------------------------------

#[test]
fn one_plugin_is_enough_for_a_chain_that_names_only_it() {
    let mut secrets = Sekreto::new(Options {
        plugins: vec![hashicorp::plugin()],
        providers: vec![
            ProviderSpec {
                values: BTreeMap::from([("API_TOKEN".to_string(), "tok01".to_string())]),
                ..ProviderSpec::of("memory")
            },
            ProviderSpec {
                name: "prod".to_string(),
                addr: "https://vault.example.com".to_string(),
                token: "t".to_string(),
                ..ProviderSpec::of("hashicorp")
            },
        ],
        ..Default::default()
    })
    .expect("one plugin is enough");

    assert_eq!(vec!["memory", "prod"], secrets.stores());
    assert_eq!(
        vec!["memory", "hashicorp:https://vault.example.com/secret"],
        secrets.sources()
    );
    assert_eq!("tok01", secrets.get("api.token").unwrap());

    // The plugin host is what the chain is made of, and it reads like the
    // chain: the kind, or kind$store for a named store.
    assert_eq!(vec!["hashicorp$prod", "memory"], secrets.host().list().keys());
    assert_eq!(
        vec!["dotenv", "env", "file", "hashicorp", "memory"],
        secrets.catalog().names()
    );

    // ...and a kind that was not passed in is refused, naming the fix.
    let err = Sekreto::new(Options {
        plugins: vec![hashicorp::plugin()],
        providers: vec![ProviderSpec {
            token: "t".to_string(),
            ..ProviderSpec::of("doppler")
        }],
        ..Default::default()
    })
    .err()
    .expect("doppler was not passed in");

    assert_eq!(
        "sekreto: unknown provider kind: doppler \
         (available: dotenv, env, file, hashicorp, memory)"
            .to_string()
            + " - doppler is a sekreto plugin, not built in: pass it in the plugins option",
        err.message()
    );
}

// A provider that refuses its own configuration returns a SekretoError
// from inside the plugin's `define`. The spec pins that message byte for
// byte, so it must come back out of the host as itself - not wrapped as
// plugin_define_failed, and not as a PluginError.
#[test]
fn a_refusal_comes_back_out_as_itself() {
    let err = Sekreto::new(Options {
        plugins: vec![hashicorp::plugin()],
        providers: vec![ProviderSpec {
            addr: "http://127.0.0.1:1".to_string(),
            token: "t".to_string(),
            kv: 3,
            ..ProviderSpec::of("hashicorp")
        }],
        ..Default::default()
    })
    .err()
    .expect("kv: 3 is not a KV version");

    assert_eq!("sekreto: hashicorp: unsupported kv version: 3", err.message());
    assert!(
        matches!(err, voxgig_sekreto::ChainError::Sekreto(_)),
        "{:?}",
        err
    );
}

// --- what each crate actually links ------------------------------------

// The dependency list of one plugin crate, as its manifest declares it.
fn depsof(crate_dir: &str) -> Vec<String> {
    let manifest = here().join("..").join(crate_dir).join("Cargo.toml");
    let text = std::fs::read_to_string(&manifest)
        .unwrap_or_else(|_| panic!("no manifest at {}", manifest.display()));

    let mut out = Vec::new();
    let mut inside = false;

    for line in text.lines() {
        let line = line.trim();
        if line.starts_with('[') {
            inside = "[dependencies]" == line;
            continue;
        }
        if !inside || line.is_empty() || line.starts_with('#') {
            continue;
        }
        out.push(line.split('=').next().unwrap_or("").trim().to_string());
    }

    sorted(out)
}

// One plugin depends on itself, the core, the host library and - only if
// it dials one - the shared HTTP client. It never depends on another
// plugin, and it never names a TLS crate directly.
#[test]
fn one_plugin_links_only_what_it_needs() {
    assert_eq!(
        vec![
            "voxgig_plugin",
            "voxgig_sekreto",
            "voxgig_sekreto_httpjson"
        ],
        depsof("hashicorp")
    );

    // secretspec reads its own CLI and nothing else, so it takes no HTTP
    // client - and therefore no TLS anywhere in its closure. If that ever
    // stops being true it is a real change, not a tidy-up.
    assert_eq!(vec!["voxgig_plugin", "voxgig_sekreto"], depsof("secretspec"));

    // The TLS exception of AGENTS.md rule 3 lives in exactly one crate.
    assert_eq!(
        vec!["rustls", "voxgig_sekreto", "webpki-roots"],
        depsof("httpjson")
    );

    for kind in ["hashicorp", "boru", "aws", "gcpsecrets", "azuresecrets",
                 "onepassword", "doppler", "infisical", "secretspec"] {
        for named in depsof(kind) {
            assert!(
                !named.starts_with("rustls") && !named.starts_with("webpki"),
                "{} names a TLS crate directly - it belongs in httpjson",
                kind
            );
            assert!(
                named.starts_with("voxgig_"),
                "{} depends on {}, which is not a voxgig crate",
                kind,
                named
            );
        }
    }
}

// The full set is BUILT, not held: `all()` is a function returning fresh
// definitions, so two Sekretos never share one, and a consumer that wants
// one kind calls that kind's own crate and links nothing else.
#[test]
fn the_full_set_is_built_on_demand() {
    let first = all();
    let second = all();

    assert_eq!(10, first.len());
    assert_eq!(10, second.len());

    // Each plugin crate is its own directory with its own manifest, which
    // is what makes "depend on one" a thing a consumer can actually do.
    for kind in ["hashicorp", "boru", "aws", "gcpsecrets", "azuresecrets",
                 "onepassword", "doppler", "infisical", "secretspec", "httpjson"] {
        let manifest = here().join("..").join(kind).join("Cargo.toml");
        assert!(
            Path::new(&manifest).exists(),
            "no crate at {}",
            manifest.display()
        );
    }
}
