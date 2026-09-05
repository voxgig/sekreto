// RUN: make test
// RUN-SOME: cargo test --test plugin builtins
//
// THE PLUGIN SEAM, FROM THE CORE'S SIDE: what a chain of built-ins can do
// with no plugin loaded, how a kind that was not passed in is refused, how
// a custom kind joins, and what crosses the boundary when a provider
// refuses its own configuration.
//
// This file cannot import a plugin, and that is not discipline - it is
// Cargo. Every plugin crate depends on `voxgig_sekreto`, so naming one
// here would be a dependency cycle and the build would stop. The plugins
// are exercised from their own side, in plugins/all/tests/plugins.rs.
//
// The conformance suite can see none of this: it hands every plugin to
// every chain it builds, so it can never notice a missing one.

use std::collections::BTreeMap;
use std::rc::Rc;

use voxgig_sekreto::voxgig_plugin::catalog::Definition;
use voxgig_sekreto::voxgig_plugin::types::PluginError;
use voxgig_sekreto::{
    providerplugin, Answer, ChainError, Options, Provider, ProviderSpec, Sekreto, SekretoError,
};

fn spec(kind: &str) -> ProviderSpec {
    ProviderSpec::of(kind)
}

fn values(pairs: &[(&str, &str)]) -> BTreeMap<String, String> {
    pairs
        .iter()
        .map(|(key, value)| (key.to_string(), value.to_string()))
        .collect()
}

fn refs(secrets: &Sekreto) -> Vec<String> {
    secrets.host().list().keys()
}

// --- what a chain of built-ins can do alone ----------------------------

#[test]
fn builtins_need_no_plugin() {
    let mut secrets = Sekreto::new(Options {
        providers: vec![
            ProviderSpec {
                values: values(&[("API_TOKEN", "tok01")]),
                ..spec("memory")
            },
            spec("env"),
            ProviderSpec {
                file: "/nonexistent-sekreto-test/.env".to_string(),
                ..spec("dotenv")
            },
            ProviderSpec {
                dir: "/nonexistent-sekreto-test".to_string(),
                ..spec("file")
            },
        ],
        ..Default::default()
    })
    .expect("a chain of built-ins needs no plugin");

    assert_eq!("tok01", secrets.get("api.token").unwrap());
    assert_eq!(vec!["memory", "env", "dotenv", "file"], secrets.stores());
    assert_eq!(
        vec!["dotenv", "env", "file", "memory"],
        secrets.catalog().names()
    );

    // The host reads like the chain, and every entry is live.
    assert_eq!(vec!["dotenv", "env", "file", "memory"], refs(&secrets));
    for entry in refs(&secrets) {
        assert_eq!(
            Some("live"),
            secrets.host().list().get(entry.as_str()).as_str(),
            "{} is not live",
            entry
        );
    }
}

// --- what a consumer sees ----------------------------------------------

#[test]
fn a_kind_that_was_not_passed_in_is_refused_naming_the_fix() {
    let err = Sekreto::new(Options {
        providers: vec![ProviderSpec {
            addr: "https://vault.example.com".to_string(),
            token: "t".to_string(),
            ..spec("hashicorp")
        }],
        ..Default::default()
    })
    .err()
    .expect("a kind nobody passed in cannot be built");

    assert_eq!(
        "sekreto: unknown provider kind: hashicorp (available: dotenv, env, file, memory)"
            .to_string()
            + " - hashicorp is a sekreto plugin, not built in: pass it in the plugins option",
        err.message()
    );
    assert!(matches!(err, ChainError::Sekreto(_)), "{:?}", err);

    // A kind nobody ships is a typo, and gets no such hint.
    let err = Sekreto::new(Options {
        providers: vec![spec("vualt")],
        ..Default::default()
    })
    .err()
    .expect("a typo cannot be built either");

    assert_eq!(
        "sekreto: unknown provider kind: vualt (available: dotenv, env, file, memory)",
        err.message()
    );
}

// Two providers MAY share a store name - a directed read walks both, and
// the spec pins it - but an instance ref may not, so the second gets a
// numbered tag from the host and keeps its store name.
#[test]
fn a_repeated_store_name_keeps_the_store_and_numbers_the_instance() {
    let mut secrets = Sekreto::new(Options {
        providers: vec![
            spec("memory"),
            ProviderSpec {
                values: values(&[("API_TOKEN", "second")]),
                ..spec("memory")
            },
            ProviderSpec {
                name: "pair".to_string(),
                ..spec("memory")
            },
            ProviderSpec {
                name: "pair".to_string(),
                values: values(&[("API_TOKEN", "pair2")]),
                ..spec("memory")
            },
        ],
        ..Default::default()
    })
    .expect("a repeat is not a collision");

    assert_eq!(vec!["memory", "pair"], secrets.stores());
    assert_eq!(
        vec!["memory", "memory$1", "memory$2", "memory$pair"],
        refs(&secrets)
    );
    assert_eq!("second", secrets.getfrom("memory", "api.token").unwrap());
    assert_eq!("pair2", secrets.getfrom("pair", "api.token").unwrap());
}

#[test]
fn a_store_name_must_be_a_valid_tag() {
    let err = Sekreto::new(Options {
        providers: vec![ProviderSpec {
            name: "my store".to_string(),
            ..spec("memory")
        }],
        ..Default::default()
    })
    .err()
    .expect("a store name that is not a tag cannot address an instance");

    assert_eq!("sekreto: invalid store name: my store", err.message());
}

// --- custom kinds, and what crosses the boundary -----------------------

struct Shouty {
    values: BTreeMap<String, String>,
}

impl Provider for Shouty {
    fn lookup(&self, name: &str) -> Answer<Option<String>> {
        Ok(self.values.get(&name.to_uppercase()).cloned())
    }

    fn describe(&self) -> String {
        "shouty".to_string()
    }
}

#[test]
fn a_custom_kind_is_one_providerplugin_call() {
    let mut secrets = Sekreto::new(Options {
        plugins: vec![providerplugin("shouty", |spec| {
            Ok(Rc::new(Shouty {
                values: spec.values.clone(),
            }) as Rc<dyn Provider>)
        })],
        providers: vec![ProviderSpec {
            values: values(&[("API.TOKEN", "loud")]),
            ..spec("shouty")
        }],
        ..Default::default()
    })
    .expect("a custom kind is a plugin like any other");

    assert_eq!("loud", secrets.get("api.token").unwrap());
    assert_eq!(vec!["shouty"], refs(&secrets));
}

// A provider that refuses its own configuration returns a SekretoError
// from inside the plugin's `define`. The spec pins that message byte for
// byte, so it must come back out of the host as itself - not wrapped as
// plugin_define_failed, and not as a PluginError.
#[test]
fn a_sekreto_error_raised_in_define_comes_back_out_as_itself() {
    let err = Sekreto::new(Options {
        plugins: vec![providerplugin("picky", |spec| {
            if spec.values.is_empty() {
                return Err(SekretoError::new("sekreto: picky: no values"));
            }
            Ok(Rc::new(Shouty {
                values: spec.values.clone(),
            }) as Rc<dyn Provider>)
        })],
        providers: vec![spec("picky")],
        ..Default::default()
    })
    .err()
    .expect("a provider that refuses its configuration refuses the chain");

    assert_eq!("sekreto: picky: no values", err.message());
    match err {
        ChainError::Sekreto(err) => {
            assert_eq!(SekretoError::new("sekreto: picky: no values"), err)
        }
        other => panic!("not a SekretoError: {:?}", other),
    }
}

// ...and any other error is not sekreto's to rewrite: it surfaces as the
// host reports it, naming the instance and the cause.
//
// In this port `providerplugin` cannot produce one - its `make` returns a
// SekretoError or nothing - so the case is reachable only for a definition
// built by hand, which is exactly the definition sekreto did not write.
#[test]
fn any_other_error_raised_in_define_is_the_hosts_report_of_it() {
    let mut broken = Definition::named("broken");
    broken.define = Some(Rc::new(|_inst| Err(PluginError::bare("boom"))));

    let err = Sekreto::new(Options {
        plugins: vec![broken],
        providers: vec![spec("broken")],
        ..Default::default()
    })
    .err()
    .expect("a definition that raises does not build");

    match err {
        ChainError::Plugin(err) => {
            assert_eq!("plugin_define_failed", err.code);
            assert!(err.message.contains("boom"), "{}", err.message);
            assert!(err.message.contains("broken"), "{}", err.message);
        }
        other => panic!("sekreto rewrote an error that was not its own: {:?}", other),
    }
}

// A definition that is not a provider plugin at all - it loads, it
// activates, it exports nothing - is refused by name. Python's twin of
// this test passes a MODULE where a definition belongs; here the type
// system refuses that outright, and what remains checkable is a definition
// that is not one of ours.
#[test]
fn a_definition_that_is_not_a_provider_plugin_is_refused() {
    let err = Sekreto::new(Options {
        plugins: vec![Definition::named("hollow")],
        providers: vec![spec("hollow")],
        ..Default::default()
    })
    .err()
    .expect("a definition exporting no provider cannot join a chain");

    assert_eq!("sekreto: plugin hollow exported no provider", err.message());
}

// A plugin that names a built-in kind replaces it: that is how a host
// substitutes an implementation, and never an accident, because the four
// names are documented.
#[test]
fn a_plugin_may_replace_a_built_in_kind() {
    struct Replaced;

    impl Provider for Replaced {
        fn lookup(&self, _name: &str) -> Answer<Option<String>> {
            Ok(Some("replaced".to_string()))
        }

        fn describe(&self) -> String {
            "memory".to_string()
        }
    }

    let mut secrets = Sekreto::new(Options {
        plugins: vec![providerplugin("memory", |_spec| {
            Ok(Rc::new(Replaced) as Rc<dyn Provider>)
        })],
        providers: vec![ProviderSpec {
            values: values(&[("API_TOKEN", "original")]),
            ..spec("memory")
        }],
        ..Default::default()
    })
    .expect("a plugin may name a built-in kind");

    assert_eq!("replaced", secrets.get("api.token").unwrap());
    assert_eq!(vec!["dotenv", "env", "file", "memory"], secrets.catalog().names());
}

// A provider already built joins the chain as it is, under its own store
// name, backed by no instance.
#[test]
fn a_live_provider_joins_the_chain() {
    let mut secrets = Sekreto::new(Options {
        providers: vec![
            ProviderSpec {
                provider: Some(Rc::new(Shouty {
                    values: values(&[("API.TOKEN", "loud")]),
                })),
                ..Default::default()
            },
            ProviderSpec {
                name: "quiet".to_string(),
                provider: Some(Rc::new(Shouty {
                    values: BTreeMap::new(),
                })),
                ..Default::default()
            },
        ],
        ..Default::default()
    })
    .expect("a built provider needs no kind");

    assert_eq!(vec!["shouty", "quiet"], secrets.stores());
    assert!(refs(&secrets).is_empty());
    assert_eq!("loud", secrets.get("api.token").unwrap());
}

#[test]
fn close_tears_the_chain_down_and_keeps_redaction() {
    let mut secrets = Sekreto::new(Options {
        providers: vec![ProviderSpec {
            values: values(&[("API_TOKEN", "tok01")]),
            ..spec("memory")
        }],
        ..Default::default()
    })
    .expect("one built-in is a chain");

    assert_eq!("tok01", secrets.get("api.token").unwrap());

    secrets.close().expect("close");

    assert!(refs(&secrets).is_empty());
    assert!(secrets.stores().is_empty());
    assert_eq!(None, secrets.trysecret("api.token").unwrap());
    assert_eq!("token=[redacted]", secrets.redact("token=tok01"));
}

// --- the core reaches no plugin ----------------------------------------

// What the manifest says, because in Cargo the manifest IS the boundary.
// This crate's whole dependency list is voxgig/plugin: no rustls, and no
// crate under plugins/. `cargo tree -p voxgig_sekreto --edges normal`
// prints the same fact; this pins it so a re-added line fails the suite.
#[test]
fn the_core_depends_on_nothing_but_voxgig_plugin() {
    let manifest = std::fs::read_to_string(concat!(env!("CARGO_MANIFEST_DIR"), "/Cargo.toml"))
        .expect("Cargo.toml");

    let mut declared: Vec<String> = Vec::new();
    let mut inside = false;

    for line in manifest.lines() {
        let line = line.trim();
        if line.starts_with('[') {
            inside = "[dependencies]" == line;
            continue;
        }
        if !inside || line.is_empty() || line.starts_with('#') {
            continue;
        }
        declared.push(
            line.split('=')
                .next()
                .unwrap_or("")
                .trim()
                .trim_matches('"')
                .to_string(),
        );
    }

    assert_eq!(vec!["voxgig_plugin"], declared);
}

// ...and what the SOURCE says. A dependency can arrive without a manifest
// line - through a re-export, or through a module someone moves back - so
// the core is also read for the things a plugin is made of: TLS, a socket,
// a subprocess, a hash function, and the name of any plugin crate.
#[test]
fn the_core_names_no_plugin_and_reaches_no_platform() {
    let src = std::path::Path::new(concat!(env!("CARGO_MANIFEST_DIR"), "/src"));

    let banned = [
        "rustls",
        "webpki",
        "TcpStream",
        "std::process",
        "std::net",
        "voxgig_sekreto_",
    ];

    let mut files = 0;

    for entry in std::fs::read_dir(src).expect("src") {
        let path = entry.expect("entry").path();
        if Some("rs") != path.extension().and_then(|ext| ext.to_str()) {
            continue;
        }
        files += 1;

        // CODE, not prose: the doc comments here point at the plugins on
        // purpose - that is how a reader finds them - and a scan that
        // could not tell a `use` from a sentence would have to choose
        // between being wrong and being useless.
        let text = std::fs::read_to_string(&path).expect("source");
        let code: String = text
            .lines()
            .filter(|line| !line.trim_start().starts_with("//"))
            .collect::<Vec<&str>>()
            .join("\n");

        for word in banned {
            assert!(
                !code.contains(word),
                "{} names {} - it belongs in a plugin",
                path.display(),
                word
            );
        }
    }

    assert!(2 < files, "read only {} core sources", files);
}
