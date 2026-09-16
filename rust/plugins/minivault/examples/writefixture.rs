//! Writes this port's committed vault into test/fixture/.
//!
//! Run once when the format changes, never as part of a build:
//! `cargo run -p voxgig_sekreto_minivault --example writefixture -- <path>`.
//! The passphrases are published and the file holds no real secret; see
//! test/fixture/README.md.
use voxgig_sekreto_minivault::*;

fn main() {
    let path = std::env::args()
        .nth(1)
        .unwrap_or_else(|| "test/fixture/minivault-rs.skmv".to_string());

    let v = createvault(&VaultOptions {
        file: path.clone(),
        passphrase: "fixture-master".to_string(),
        iterations: 1000,
        ..Default::default()
    })
    .expect("createvault");

    v.set("api.token", "fixture-token").expect("api.token");
    v.set("db.pass", "fixture-pass").expect("db.pass");
    v.set("deep.nested.name", "fixture-deep").expect("deep.nested.name");

    v.grant(&GrantSpec {
        key: "reader".to_string(),
        passphrase: "fixture-reader".to_string(),
        names: vec!["api.token".to_string()],
        write: false,
        iterations: 1000,
    })
    .expect("reader");

    v.grant(&GrantSpec {
        key: "writer".to_string(),
        passphrase: "fixture-writer".to_string(),
        names: vec!["db.pass".to_string()],
        write: true,
        iterations: 1000,
    })
    .expect("writer");

    let size = std::fs::metadata(&path).expect("stat").len();
    println!("{}: {} bytes", path, size);
}
