// RUN: cargo test
// RUN-SOME: cargo test envkey
//
// The sekreto conformance suite. Every port runs these same groups, from
// the same spec/sekreto.json, through its own voxgig/omni runner.

use std::collections::BTreeMap;
use std::path::PathBuf;
use std::rc::Rc;

use voxgig_omni::{
    make_runner, Flags, Json as OmniJson, Provider as OmniProvider, RunPack, Subject,
};
use voxgig_sekreto::{
    awsparam, envkey, flatname, makechain, parsedotenv, redact, sigv4, validname, vaultref,
    ProviderSpec, Sekreto, Sigv4Input,
};

// Find the shared spec directory by walking up from this file.
fn specfile(name: &str) -> String {
    let mut dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"));

    for _step in 0..8 {
        let cand = dir.join("spec").join(name);
        if cand.exists() {
            return cand.to_string_lossy().to_string();
        }
        dir = match dir.parent() {
            Some(parent) => parent.to_path_buf(),
            None => break,
        };
    }

    panic!("sekreto: spec not found: {}", name);
}

fn text(value: &OmniJson) -> String {
    match value {
        OmniJson::Str(entry) => entry.clone(),
        _ => String::new(),
    }
}

fn field(value: &OmniJson, key: &str) -> OmniJson {
    match value {
        OmniJson::Map(entries) => entries.get(key).cloned().unwrap_or(OmniJson::Absent),
        _ => OmniJson::Absent,
    }
}

// The spec describes a provider chain declaratively; this is the same shape
// an app's config file would have.
fn specof(value: &OmniJson) -> ProviderSpec {
    let mut values = BTreeMap::new();

    if let OmniJson::Map(entries) = field(value, "values") {
        for (key, entry) in entries {
            values.insert(key, text(&entry));
        }
    }

    let kv = match field(value, "kv") {
        OmniJson::Num(entry) => entry as u32,
        _ => 0,
    };

    ProviderSpec {
        kind: text(&field(value, "kind")),
        name: text(&field(value, "name")),
        prefix: text(&field(value, "prefix")),
        file: text(&field(value, "file")),
        values,
        dir: text(&field(value, "dir")),
        addr: text(&field(value, "addr")),
        token: text(&field(value, "token")),
        mount: text(&field(value, "mount")),
        kv,
        command: text(&field(value, "command")),
        namespace: text(&field(value, "namespace")),
        home: text(&field(value, "home")),
        region: text(&field(value, "region")),
        project: text(&field(value, "project")),
        vault: text(&field(value, "vault")),
        config: text(&field(value, "config")),
        environment: text(&field(value, "environment")),
        ..Default::default()
    }
}

fn chainof(value: &OmniJson) -> Result<Sekreto, String> {
    let specs = match field(value, "chain") {
        OmniJson::List(entries) => entries.iter().map(specof).collect::<Vec<ProviderSpec>>(),
        _ => Vec::new(),
    };

    let names: Vec<String> = specs.iter().map(|spec| spec.name.clone()).collect();
    let providers = makechain(&specs).map_err(|err| err.message)?;

    Ok(Sekreto::named(providers, &names, false))
}

fn runner() -> RunPack {
    make_runner(specfile("sekreto.json"), OmniProvider::default())
        .expect("sekreto: cannot make runner")
        .runner("sekreto", None)
        .expect("sekreto: cannot resolve spec")
}

#[test]
fn validname_group() {
    let R = runner();

    let subject: Subject =
        Rc::new(|args: &[OmniJson]| Ok(OmniJson::Bool(validname(&text(&args[0])))));

    R.runsetflags(&R.set("validname"), &Flags::nonull(), Some(&subject))
        .expect("validname");
}

#[test]
fn envkey_group() {
    let R = runner();

    let subject: Subject = Rc::new(|args: &[OmniJson]| {
        envkey(
            &text(&field(&args[0], "name")),
            &text(&field(&args[0], "prefix")),
        )
        .map(OmniJson::Str)
        .map_err(|err| err.message)
    });

    R.runset(&R.set("envkey"), Some(&subject)).expect("envkey");
}

#[test]
fn vaultref_group() {
    let R = runner();

    let subject: Subject = Rc::new(|args: &[OmniJson]| {
        let reference = vaultref(&text(&args[0])).map_err(|err| err.message)?;

        // omni compares against the spec's JSON, so answer in that shape.
        Ok(OmniJson::Map(BTreeMap::from([
            ("path".to_string(), OmniJson::Str(reference.path)),
            ("field".to_string(), OmniJson::Str(reference.field)),
        ])))
    });

    R.runset(&R.set("vaultref"), Some(&subject))
        .expect("vaultref");
}

#[test]
fn flatname_group() {
    let R = runner();

    let subject: Subject = Rc::new(|args: &[OmniJson]| {
        flatname(
            &text(&field(&args[0], "name")),
            &text(&field(&args[0], "sep")),
        )
        .map(OmniJson::Str)
        .map_err(|err| err.message)
    });

    R.runset(&R.set("flatname"), Some(&subject))
        .expect("flatname");
}

#[test]
fn awsparam_group() {
    let R = runner();

    let subject: Subject = Rc::new(|args: &[OmniJson]| {
        awsparam(
            &text(&field(&args[0], "name")),
            &text(&field(&args[0], "prefix")),
        )
        .map(OmniJson::Str)
        .map_err(|err| err.message)
    });

    R.runset(&R.set("awsparam"), Some(&subject))
        .expect("awsparam");
}

#[test]
fn parsedotenv_group() {
    let R = runner();

    let subject: Subject = Rc::new(|args: &[OmniJson]| {
        let parsed = parsedotenv(&text(&args[0]));

        Ok(OmniJson::Map(
            parsed
                .into_iter()
                .map(|(key, value)| (key, OmniJson::Str(value)))
                .collect(),
        ))
    });

    R.runset(&R.set("parsedotenv"), Some(&subject))
        .expect("parsedotenv");
}

#[test]
fn resolve_group() {
    let R = runner();

    let subject: Subject = Rc::new(|args: &[OmniJson]| {
        let mut secrets = chainof(&args[0])?;
        secrets
            .get(&text(&field(&args[0], "name")))
            .map(OmniJson::Str)
            .map_err(|err| err.message)
    });

    R.runset(&R.set("resolve"), Some(&subject))
        .expect("resolve");
}

#[test]
fn trysecret_group() {
    let R = runner();

    let subject: Subject = Rc::new(|args: &[OmniJson]| {
        let mut secrets = chainof(&args[0])?;

        match secrets
            .trysecret(&text(&field(&args[0], "name")))
            .map_err(|err| err.message)?
        {
            Some(found) => Ok(OmniJson::Str(found)),
            None => Ok(OmniJson::Null),
        }
    });

    R.runset(&R.set("trysecret"), Some(&subject))
        .expect("trysecret");
}

#[test]
fn sources_group() {
    let R = runner();

    let subject: Subject = Rc::new(|args: &[OmniJson]| {
        let secrets = chainof(&args[0])?;

        Ok(OmniJson::List(
            secrets.sources().into_iter().map(OmniJson::Str).collect(),
        ))
    });

    R.runset(&R.set("sources"), Some(&subject))
        .expect("sources");
}

#[test]
fn stores_group() {
    let R = runner();

    let subject: Subject = Rc::new(|args: &[OmniJson]| {
        let secrets = chainof(&args[0])?;

        Ok(OmniJson::List(
            secrets.stores().into_iter().map(OmniJson::Str).collect(),
        ))
    });

    R.runset(&R.set("stores"), Some(&subject)).expect("stores");
}

#[test]
fn getfrom_group() {
    let R = runner();

    let subject: Subject = Rc::new(|args: &[OmniJson]| {
        let mut secrets = chainof(&args[0])?;

        secrets
            .getfrom(
                &text(&field(&args[0], "store")),
                &text(&field(&args[0], "name")),
            )
            .map(OmniJson::Str)
            .map_err(|err| err.message)
    });

    R.runset(&R.set("getfrom"), Some(&subject))
        .expect("getfrom");
}

#[test]
fn tryfrom_group() {
    let R = runner();

    let subject: Subject = Rc::new(|args: &[OmniJson]| {
        let mut secrets = chainof(&args[0])?;

        match secrets
            .tryfrom(
                &text(&field(&args[0], "store")),
                &text(&field(&args[0], "name")),
            )
            .map_err(|err| err.message)?
        {
            Some(found) => Ok(OmniJson::Str(found)),
            None => Ok(OmniJson::Null),
        }
    });

    R.runset(&R.set("tryfrom"), Some(&subject))
        .expect("tryfrom");
}

#[test]
fn sigv4_group() {
    let R = runner();

    let subject: Subject = Rc::new(|args: &[OmniJson]| {
        let vin = &args[0];

        let mut headers: Vec<(String, String)> = Vec::new();
        if let OmniJson::Map(entries) = field(vin, "headers") {
            for (key, entry) in entries {
                headers.push((key, text(&entry)));
            }
        }

        let signed = sigv4(&Sigv4Input {
            method: text(&field(vin, "method")),
            url: text(&field(vin, "url")),
            headers,
            body: text(&field(vin, "body")),
            service: text(&field(vin, "service")),
            region: text(&field(vin, "region")),
            keyid: text(&field(vin, "keyid")),
            secret: text(&field(vin, "secret")),
            session: text(&field(vin, "session")),
            datetime: text(&field(vin, "datetime")),
        })
        .map_err(|err| err.message)?;

        // omni compares against the spec's JSON, so answer in that shape.
        Ok(OmniJson::Map(
            signed
                .into_iter()
                .map(|(key, value)| (key, OmniJson::Str(value)))
                .collect(),
        ))
    });

    R.runset(&R.set("sigv4"), Some(&subject)).expect("sigv4");
}

#[test]
fn redact_group() {
    let R = runner();

    let subject: Subject = Rc::new(|args: &[OmniJson]| {
        let values = match field(&args[0], "values") {
            OmniJson::List(entries) => entries.iter().map(text).collect::<Vec<String>>(),
            _ => Vec::new(),
        };

        Ok(OmniJson::Str(redact(
            &text(&field(&args[0], "text")),
            &values,
        )))
    });

    R.runset(&R.set("redact"), Some(&subject)).expect("redact");
}
