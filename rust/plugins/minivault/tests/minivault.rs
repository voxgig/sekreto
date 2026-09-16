//! The mini vault, from both sides: the store a chain reads, and the
//! programmatic API a plugin definition can publish beside it.
//!
//! The vault is not in spec/sekreto.json and cannot be until every port
//! ships the kind. The spec runs against all twenty-three of them, so an
//! entry naming `minivault` would fail the ports that have no such
//! provider. What the shared corpus would have carried is here instead,
//! plus the one thing it could not carry either way: a file written by
//! this port and read by another, pinned by the vaults in test/fixture.
//!
//! A port of typescript/test/minivault.test.ts.

use std::collections::BTreeSet;
use std::path::PathBuf;
use std::sync::atomic::{AtomicUsize, Ordering};

use voxgig_sekreto::{Options, ProviderSpec, Sekreto};
use voxgig_sekreto_minivault::*;

const MASTER: &str = "master-passphrase";

/// The rounds every case here uses. The library default is 210000, which
/// is the point of PBKDF2 and the wrong thing to pay per assertion.
const ROUNDS: u32 = 1000;

static COUNT: AtomicUsize = AtomicUsize::new(0);

/// The process id is in the name because cargo runs these in threads of
/// ONE process but leaves the directory behind between runs: a fixed name
/// plus a counter that restarts at zero collides with the last run's
/// files, and `createvault` refuses an existing path by design.
fn work() -> PathBuf {
    let dir = std::env::temp_dir().join(format!("sekreto-minivault-rs-{}", std::process::id()));
    std::fs::create_dir_all(&dir).expect("work directory");
    dir
}

fn vaultpath() -> String {
    let at = COUNT.fetch_add(1, Ordering::SeqCst);
    work()
        .join(format!("vault{}.skmv", at))
        .to_string_lossy()
        .into_owned()
}

fn opts(file: &str, key: &str, passphrase: &str) -> VaultOptions {
    VaultOptions {
        file: file.to_string(),
        key: key.to_string(),
        passphrase: passphrase.to_string(),
        iterations: ROUNDS,
        create: false,
    }
}

fn fresh() -> Vault {
    createvault(&opts(&vaultpath(), "", MASTER)).expect("createvault")
}

fn openas(file: &str, key: &str, passphrase: &str) -> Vault {
    openvault(&opts(file, key, passphrase)).expect("openvault")
}

fn grantof(key: &str, passphrase: &str, names: &[&str], write: bool) -> GrantSpec {
    GrantSpec {
        key: key.to_string(),
        passphrase: passphrase.to_string(),
        names: names.iter().map(|one| one.to_string()).collect(),
        write,
        iterations: ROUNDS,
    }
}

/// The value, or a word no secret here is, so a miss is an assertion
/// rather than an unwrap.
fn valueof(v: &Vault, name: &str) -> String {
    v.get(name).expect("get").unwrap_or_else(|| "(miss)".to_string())
}

/// The refusal a call raised, or a panic when it did not refuse.
fn refusal<T>(what: &str, answer: voxgig_sekreto::Answer<T>) -> String {
    match answer {
        Ok(_) => panic!("{}: nothing was refused", what),
        Err(err) => err.message,
    }
}

fn holds(what: &str, want: &str, got: &str) {
    assert!(got.contains(want), "{}: want to contain {:?}, got {:?}", what, want, got);
}

// --- the fixtures ----------------------------------------------------

fn fixturedir() -> PathBuf {
    let mut dir = PathBuf::from(".");
    for _ in 0..8 {
        if dir.join("test/fixture/minivault.skmv").exists() {
            return dir.join("test/fixture");
        }
        dir = dir.join("..");
    }
    panic!("the fixture directory was not found");
}

/// EVERY committed vault, read off disk rather than listed here. A
/// hard-coded list is one more place to edit when a port lands, and the
/// edit that gets forgotten is the one that makes this suite stop checking
/// the port that just arrived.
fn fixtures() -> Vec<String> {
    let mut names: Vec<String> = std::fs::read_dir(fixturedir())
        .expect("fixture directory")
        .filter_map(|entry| entry.ok())
        .map(|entry| entry.file_name().to_string_lossy().into_owned())
        .filter(|name| name.ends_with(".skmv"))
        .collect();
    names.sort();
    names
}

/// A committed vault, copied so that a case which writes cannot edit the
/// bytes the format contract is made of.
fn fixture(name: &str) -> String {
    let mine = vaultpath();
    std::fs::write(&mine, std::fs::read(fixturedir().join(name)).expect("read")).expect("write");
    mine
}

// --- the file --------------------------------------------------------

#[test]
fn a_new_vault_holds_nothing() {
    let v = fresh();

    assert!(v.list().expect("list").is_empty());
    assert_eq!("master", v.key());

    let info = v.open().expect("open");
    assert!(info.master, "the master key is not master");
    assert!(info.write, "the master key may not write");
    assert!(info.grants.is_empty(), "a master is granted nothing");
}

#[test]
fn a_written_secret_comes_back() {
    let v = fresh();
    v.set("api.token", "tok01").expect("set");
    v.set("db.pass", "hunter2").expect("set");

    assert_eq!("tok01", valueof(&v, "api.token"));
    assert_eq!(vec!["api.token", "db.pass"], v.list().expect("list"));
    assert!(v.has("api.token").expect("has"));
    assert!(!v.has("nope").expect("has"));
    assert_eq!("(miss)", valueof(&v, "nope"));

    // A SECOND HANDLE on the same file, so the assertion is about the
    // bytes rather than about what this handle happens to remember.
    assert_eq!("tok01", valueof(&openas(v.file(), "", MASTER), "api.token"));
}

#[test]
fn the_file_is_binary_and_names_nothing_in_plaintext() {
    let v = fresh();
    v.set("api.token", "tok01").expect("set");

    let raw = std::fs::read(v.file()).expect("read");
    assert_eq!(b"SKMV", &raw[0..4]);

    // NOT ONE OF THESE IS IN THE FILE. The key id is plaintext by design;
    // the secret's name and its value are not, and neither is the
    // passphrase that unwrapped them.
    for secret in ["api.token", "tok01", MASTER] {
        assert!(
            !raw.windows(secret.len()).any(|held| held == secret.as_bytes()),
            "{} is in the file",
            secret
        );
    }

    assert!(raw.windows(6).any(|held| held == b"master"), "the key id is not in the file");
}

#[test]
fn rewriting_a_name_replaces_it() {
    let v = fresh();
    v.set("api.token", "first").expect("set");
    v.set("api.token", "second").expect("set");

    assert_eq!("second", valueof(&v, "api.token"));
    assert_eq!(vec!["api.token"], v.list().expect("list"));
}

#[test]
fn remove_drops_a_name() {
    let v = fresh();
    v.set("api.token", "tok01").expect("set");
    v.set("db.pass", "hunter2").expect("set");
    v.remove("api.token").expect("remove");

    assert_eq!(vec!["db.pass"], v.list().expect("list"));
    assert_eq!("(miss)", valueof(&v, "api.token"));
    holds(
        "remove again",
        "no such secret: api.token",
        &refusal("remove again", v.remove("api.token")),
    );
}

#[test]
fn a_bad_name_is_refused() {
    let v = fresh();
    holds("set", "invalid name", &refusal("set", v.set("API.TOKEN", "x")));
    holds("get", "invalid name", &refusal("get", v.get("api..token")));
    holds("remove", "invalid name", &refusal("remove", v.remove("")));
}

// --- the keys --------------------------------------------------------

#[test]
fn a_restricted_key_reads_its_grants() {
    let v = fresh();
    v.set("api.token", "tok01").expect("set");
    v.set("db.pass", "hunter2").expect("set");
    v.grant(&grantof("ci", "ci-passphrase", &["api.token"], false)).expect("grant");

    let ci = openas(v.file(), "ci", "ci-passphrase");
    assert_eq!("tok01", valueof(&ci, "api.token"));

    // THE RESTRICTION IS THE CRYPTOGRAPHY. `db.pass` is in the file and
    // this key cannot derive its key, so the answer is the one a stranger
    // gets: a miss.
    assert_eq!("(miss)", valueof(&ci, "db.pass"));
    assert_eq!(vec!["api.token"], ci.list().expect("list"));

    let info = ci.open().expect("open");
    assert!(!info.master, "a restricted key reports master");
    assert!(!info.write, "a read-only key reports write");
    assert_eq!(vec!["api.token"], info.grants);
}

#[test]
fn a_read_only_key_refuses_to_write() {
    let v = fresh();
    v.set("api.token", "tok01").expect("set");
    v.grant(&grantof("reader", "reader-passphrase", &["api.token"], false)).expect("grant");
    v.grant(&grantof("writer", "writer-passphrase", &["api.token"], true)).expect("grant");

    let reader = openas(v.file(), "reader", "reader-passphrase");
    holds(
        "read-only",
        "key reader is read-only",
        &refusal("read-only", reader.set("api.token", "x")),
    );

    let writer = openas(v.file(), "writer", "writer-passphrase");
    writer.set("api.token", "rewritten").expect("set");

    assert_eq!("rewritten", valueof(&v, "api.token"));
}

#[test]
fn a_restricted_key_cannot_write_an_ungranted_name() {
    let v = fresh();
    v.set("api.token", "tok01").expect("set");
    v.grant(&grantof("ci", "ci-passphrase", &["api.token"], true)).expect("grant");

    let ci = openas(v.file(), "ci", "ci-passphrase");
    holds(
        "ungranted",
        "key ci was not granted db.pass",
        &refusal("ungranted", ci.set("db.pass", "x")),
    );
}

#[test]
fn a_granted_name_that_does_not_exist_yet() {
    let v = fresh();

    // Granted BEFORE the name exists, which is the point: a deploy key is
    // minted from a list of what a service will need.
    v.grant(&grantof("ci", "ci-passphrase", &["api.token"], false)).expect("grant");

    let ci = openas(v.file(), "ci", "ci-passphrase");
    assert!(ci.list().expect("list").is_empty());
    assert_eq!("(miss)", valueof(&ci, "api.token"));

    v.set("api.token", "tok01").expect("set");

    assert_eq!("tok01", valueof(&ci, "api.token"));
    assert_eq!(vec!["api.token"], ci.list().expect("list"));
}

#[test]
fn the_master_lists_every_key() {
    let v = fresh();
    v.grant(&grantof("ci", "ci-passphrase", &["db.pass", "api.token"], true)).expect("grant");

    let keys = v.keys().expect("keys");
    assert_eq!(2, keys.len());

    assert_eq!("master", keys[0].key);
    assert!(keys[0].master);
    assert!(keys[0].grants.is_empty(), "a master is granted nothing");

    assert_eq!("ci", keys[1].key);
    assert!(!keys[1].master);
    assert!(keys[1].write);
    // SORTED, so the record reads the same however the grant was spelled.
    assert_eq!(vec!["api.token", "db.pass"], keys[1].grants);
}

#[test]
fn the_master_only_methods_refuse_a_restricted_key() {
    let v = fresh();
    v.set("api.token", "tok01").expect("set");
    v.grant(&grantof("ci", "ci-passphrase", &["api.token"], true)).expect("grant");

    let ci = openas(v.file(), "ci", "ci-passphrase");

    holds("keys", "listing the keys needs a master key", &refusal("keys", ci.keys()));
    holds(
        "grant",
        "granting a key needs a master key",
        &refusal("grant", ci.grant(&grantof("x", "y", &[], false))),
    );
    holds("revoke", "revoking a key needs a master key", &refusal("revoke", ci.revoke("master")));
    holds("rotate", "rotating the vault needs a master key", &refusal("rotate", ci.rotate()));
    holds(
        "remove",
        "removing a secret needs a master key",
        &refusal("remove", ci.remove("api.token")),
    );
}

#[test]
fn a_repeated_key_id_is_refused() {
    let v = fresh();
    v.grant(&grantof("ci", "p", &[], false)).expect("grant");

    holds(
        "repeated",
        "key already exists: ci",
        &refusal("repeated", v.grant(&grantof("ci", "q", &[], false))),
    );
    holds(
        "no id",
        "a grant needs a key id",
        &refusal("no id", v.grant(&grantof("", "p", &[], false))),
    );
    holds(
        "no passphrase",
        "a grant needs a passphrase",
        &refusal("no passphrase", v.grant(&grantof("x", "", &[], false))),
    );
}

/// A RESTRICTED KEY GRANTED NOTHING STILL WRITES A GRANTS MAP, and the
/// only evidence is the file's length.
///
/// The asymmetry is the format: a master's ring carries `root` and no
/// `grants`, a restricted key's carries `grants` - possibly empty - and no
/// `root`. A writer that drops an empty map produces a vault 12 bytes
/// shorter than every other port's, which reads back identically because
/// an absent `grants` parses as empty, and which no fixture can catch
/// because not one of them has a key granted nothing. Every length in the
/// format is fixed or derived, so the size IS deterministic for a given
/// input, and 401 is what typescript writes.
#[test]
fn a_key_granted_nothing_still_writes_a_grants_map() {
    let file = vaultpath();
    let v = createvault(&VaultOptions {
        file: file.clone(),
        passphrase: "p".to_string(),
        iterations: 1000,
        ..Default::default()
    })
    .expect("createvault");

    v.grant(&GrantSpec {
        key: "ci".to_string(),
        passphrase: "q".to_string(),
        names: vec![],
        write: false,
        iterations: 1000,
    })
    .expect("grant");

    assert_eq!(401, std::fs::metadata(&file).expect("stat").len());

    let ci = openas(&file, "ci", "q");
    assert!(ci.list().expect("list").is_empty());
}

#[test]
fn revoke_drops_a_key() {
    let v = fresh();
    v.set("api.token", "tok01").expect("set");
    v.grant(&grantof("ci", "ci-passphrase", &["api.token"], false)).expect("grant");
    v.revoke("ci").expect("revoke");

    let ci = openas(v.file(), "ci", "ci-passphrase");
    holds("revoked", "no such key: ci", &refusal("revoked", ci.get("api.token")));
    holds("revoke again", "no such key: ci", &refusal("revoke again", v.revoke("ci")));
    holds("itself", "a key cannot revoke itself", &refusal("itself", v.revoke("master")));

    // THE SECRET IS UNTOUCHED: revoking bars a key, not a value.
    assert_eq!("tok01", valueof(&v, "api.token"));
}

#[test]
fn rotate_keeps_the_secrets() {
    let v = fresh();
    v.set("api.token", "tok01").expect("set");
    v.set("db.pass", "hunter2").expect("set");
    v.grant(&grantof("ci", "ci-passphrase", &["api.token"], false)).expect("grant");

    v.rotate().expect("rotate");

    assert_eq!("tok01", valueof(&v, "api.token"));
    assert_eq!("hunter2", valueof(&v, "db.pass"));
    assert_eq!(vec!["api.token", "db.pass"], v.list().expect("list"));

    let keys = v.keys().expect("keys");
    assert_eq!(1, keys.len());
    assert_eq!("master", keys[0].key);

    // EVERY OTHER KEY IS GONE, which is what rotation has to mean: their
    // rings were sealed under passphrases this process does not have.
    let ci = openas(v.file(), "ci", "ci-passphrase");
    holds("ci is gone", "no such key: ci", &refusal("ci is gone", ci.get("api.token")));
}

// --- the refusals ----------------------------------------------------

#[test]
fn a_wrong_passphrase_and_a_missing_file() {
    let v = fresh();
    v.set("api.token", "tok01").expect("set");

    let wrong = openas(v.file(), "", "not-the-passphrase");
    holds(
        "wrong passphrase",
        "wrong passphrase for key master, or a damaged vault",
        &refusal("wrong passphrase", wrong.get("api.token")),
    );

    let unknown = openas(v.file(), "nope", MASTER);
    holds("unknown key", "no such key: nope", &refusal("unknown key", unknown.get("api.token")));

    let missing = openas(&vaultpath(), "", MASTER);
    holds("missing file", "no vault file", &refusal("missing file", missing.get("api.token")));
}

#[test]
fn a_damaged_file_is_refused() {
    let v = fresh();
    v.set("api.token", "tok01").expect("set");
    let raw = std::fs::read(v.file()).expect("read");

    let refuses = |what: &str, want: &str, made: Vec<u8>| {
        let where_ = vaultpath();
        std::fs::write(&where_, made).expect("write");
        let held = openas(&where_, "", MASTER);
        holds(what, want, &refusal(what, held.get("api.token")));
    };

    // Not a vault at all.
    refuses("not a vault", "not a vault file", b"nonsense".to_vec());
    // Cut off part way through.
    refuses("truncated", "truncated", raw[..raw.len() - 20].to_vec());
    // One byte of ciphertext flipped, which the GCM tag catches.
    let mut flipped = raw.clone();
    let last = flipped.len() - 1;
    flipped[last] ^= 0xff;
    refuses("flipped", "damaged", flipped);
    // Trailing bytes, which a reader that stopped at the last record would
    // have accepted.
    let mut trailing = raw.clone();
    trailing.extend_from_slice(b"junk");
    refuses("trailing", "trailing bytes", trailing);
}

#[test]
fn creating_over_an_existing_vault_is_refused() {
    let v = fresh();
    holds(
        "create over",
        "vault file already exists",
        &refusal("create over", createvault(&opts(v.file(), "", "other"))),
    );
}

#[test]
fn a_vault_needs_a_file_and_a_passphrase() {
    holds(
        "no file",
        "a vault needs a file",
        &refusal("no file", openvault(&opts("", "", "p"))),
    );
    holds(
        "no passphrase",
        "a vault needs a passphrase",
        &refusal("no passphrase", openvault(&opts("v.skmv", "", ""))),
    );
}

/// An EMPTY key is no key, so it means `master`. It is not a contrived
/// case: the CLI reads SEKRETO_VAULT_KEY, and an unset shell variable
/// expands to the empty string rather than to nothing at all.
#[test]
fn an_empty_key_means_the_master_key() {
    let v = fresh();
    v.set("api.token", "tok01").expect("set");

    let opened = openas(v.file(), "", MASTER);
    assert_eq!("tok01", valueof(&opened, "api.token"));
    assert_eq!("master", opened.open().expect("open").key);
}

#[test]
fn create_makes_the_file_only_when_asked() {
    let where_ = vaultpath();

    let off = openas(&where_, "", MASTER);
    holds("create off", "no vault file", &refusal("create off", off.get("api.token")));

    let on = openvault(&VaultOptions {
        create: true,
        ..opts(&where_, "", MASTER)
    })
    .expect("openvault");

    assert_eq!("(miss)", valueof(&on, "api.token"));
    on.set("api.token", "tok01").expect("set");
    assert_eq!("tok01", valueof(&on, "api.token"));

    // The file is there now, so the handle that refused reads it.
    assert_eq!("tok01", valueof(&openas(&where_, "", MASTER), "api.token"));
}

#[test]
fn a_key_id_longer_than_the_format_allows() {
    let v = fresh();
    let big = "k".repeat(300);

    holds(
        "grant",
        "key id is longer than 255 bytes",
        &refusal("grant", v.grant(&grantof(&big, "p", &[], false))),
    );
    holds(
        "open",
        "key id is longer than 255 bytes",
        &refusal("open", openvault(&opts(v.file(), &big, "p"))),
    );

    // AND THE VAULT IS UNHARMED: the refusal came before the write, so a
    // 300-character id did not shift every field after it.
    assert_eq!(1, v.keys().expect("keys").len());
}

/// NOTHING TO FLIP: `VaultKeyInfo` is a value, so the defect the review
/// round found in the canonical - a caller flipping its own `write` bit -
/// changes a copy and nothing the vault reads.
#[test]
fn the_info_a_caller_gets_cannot_change_what_the_key_may_do() {
    let v = fresh();
    v.set("api.token", "tok01").expect("set");
    v.grant(&grantof("reader", "reader-passphrase", &["api.token"], false)).expect("grant");

    let reader = openas(v.file(), "reader", "reader-passphrase");
    let info = reader.open().expect("open");
    assert!(!info.write, "the reader key may write");

    let mut copied = info.clone();
    copied.write = true;
    assert!(copied.write, "the copy did not take the change");

    holds(
        "still refused",
        "key reader is read-only",
        &refusal("still refused", reader.set("api.token", "x")),
    );
}

#[test]
fn a_revoked_key_stops_reading() {
    let v = fresh();
    v.set("api.token", "tok01").expect("set");
    v.grant(&grantof("ci", "ci-passphrase", &["api.token"], false)).expect("grant");

    // OPEN AND READING FIRST, so the handle holds its derived keys.
    let ci = openas(v.file(), "ci", "ci-passphrase");
    assert_eq!("tok01", valueof(&ci, "api.token"));

    v.revoke("ci").expect("revoke");

    // The live file no longer holds the key, and a handle that answered
    // from memory here would make `revoke` a suggestion.
    holds("after", "no such key: ci", &refusal("after", ci.get("api.token")));
}

#[test]
fn a_re_granted_key_id() {
    let v = fresh();
    v.set("api.token", "tok01").expect("set");
    v.grant(&grantof("ci", "first-passphrase", &["api.token"], false)).expect("grant");

    let ci = openas(v.file(), "ci", "first-passphrase");
    assert_eq!("tok01", valueof(&ci, "api.token"));

    v.revoke("ci").expect("revoke");
    v.grant(&grantof("ci", "second-passphrase", &["api.token"], false)).expect("grant");

    // SAME ID, DIFFERENT KEY. The handle re-derives because the sealed
    // ring changed, and the old passphrase does not unwrap the new one.
    holds(
        "the old passphrase",
        "wrong passphrase for key ci, or a damaged vault",
        &refusal("the old passphrase", ci.get("api.token")),
    );

    assert_eq!("tok01", valueof(&openas(v.file(), "ci", "second-passphrase"), "api.token"));
}

#[test]
fn close_forgets_the_derived_keys() {
    let v = fresh();
    v.set("api.token", "tok01").expect("set");
    assert_eq!("tok01", valueof(&v, "api.token"));

    v.close();

    assert_eq!("tok01", valueof(&v, "api.token"));
}

/// TWO HANDLES ON ONE FILE, WRITING AT ONCE, LOSE NOTHING. Each Vault has
/// its own snapshot, so without the shared per-path lock both threads
/// finish `load` before either saves and the second rename discards the
/// first one's secret while reporting success. DOCS.md promises this
/// within one process.
///
/// A `Vault` is `Rc` and never crosses a thread, so each thread opens its
/// own handle - which is exactly the case the lock exists for: what races
/// is the FILE, not the handle.
#[test]
fn two_handles_writing_at_once_lose_nothing() {
    let v = fresh();
    let file = v.file().to_string();
    let rounds = 40;

    let writer = |tag: &'static str, file: String| {
        std::thread::spawn(move || {
            let mine = openvault(&VaultOptions {
                file,
                passphrase: MASTER.to_string(),
                ..Default::default()
            })
            .expect("openvault");

            for round in 0..rounds {
                mine.set(&format!("t{}.n{}", tag, round), &format!("v{}", round))
                    .expect("set");
            }
        })
    };

    let one = writer("one", file.clone());
    let two = writer("two", file);
    one.join().expect("one");
    two.join().expect("two");

    assert_eq!(2 * rounds, v.list().expect("list").len());
}

// --- the committed files ---------------------------------------------

/// Every port's vault holds the same keys and the same secrets, so the
/// assertions do not vary with which file this is.
#[test]
fn every_committed_fixture_reads() {
    let names = fixtures();
    assert!(!names.is_empty(), "no committed vault was found");

    for name in &names {
        let file = fixture(name);
        let owner = openas(&file, "", "fixture-master");

        assert_eq!(
            vec!["api.token", "db.pass", "deep.nested.name"],
            owner.list().expect("list"),
            "{}",
            name
        );
        assert_eq!("fixture-token", valueof(&owner, "api.token"), "{}", name);
        assert_eq!("fixture-pass", valueof(&owner, "db.pass"), "{}", name);
        assert_eq!("fixture-deep", valueof(&owner, "deep.nested.name"), "{}", name);

        let keys: BTreeSet<String> =
            owner.keys().expect("keys").iter().map(|one| one.key.clone()).collect();
        assert_eq!(
            ["master", "reader", "writer"].iter().map(|s| s.to_string()).collect::<BTreeSet<_>>(),
            keys,
            "{}",
            name
        );

        let reader = openas(&file, "reader", "fixture-reader");
        assert_eq!(vec!["api.token"], reader.list().expect("list"), "{}", name);
        assert_eq!("fixture-token", valueof(&reader, "api.token"), "{}", name);
        assert_eq!("(miss)", valueof(&reader, "db.pass"), "{}", name);
        holds("reader writes", "read-only", &refusal("reader writes", reader.set("api.token", "x")));

        let writer = openas(&file, "writer", "fixture-writer");
        assert_eq!(vec!["db.pass"], writer.list().expect("list"), "{}", name);
        assert_eq!("fixture-pass", valueof(&writer, "db.pass"), "{}", name);

        // The copy is this case's own, so writing it proves the round trip
        // without touching the committed bytes.
        writer.set("db.pass", "rewritten").expect("set");
        assert_eq!("rewritten", valueof(&owner, "db.pass"), "{}", name);
    }
}

// --- the chain -------------------------------------------------------

fn vaultspec(file: &str, key: &str, passphrase: &str) -> ProviderSpec {
    ProviderSpec {
        file: file.to_string(),
        vaultkey: key.to_string(),
        passphrase: passphrase.to_string(),
        ..ProviderSpec::of("minivault")
    }
}

fn memoryspec(key: &str, value: &str) -> ProviderSpec {
    let mut values = std::collections::BTreeMap::new();
    values.insert(key.to_string(), value.to_string());
    ProviderSpec {
        values,
        ..ProviderSpec::of("memory")
    }
}

fn thechain(providers: Vec<ProviderSpec>) -> Result<Sekreto, voxgig_sekreto::ChainError> {
    Sekreto::new(Options {
        plugins: vec![minivault()],
        providers,
        nocache: true,
    })
}

#[test]
fn a_vault_is_one_store_in_a_chain() {
    let v = fresh();
    v.set("api.token", "from the vault").expect("set");

    let mut secrets = thechain(vec![
        vaultspec(v.file(), "", MASTER),
        memoryspec("DB_PASS", "from memory"),
    ])
    .expect("chain");

    assert_eq!(vec!["minivault", "memory"], secrets.stores());
    assert_eq!(
        vec![format!("minivault:{}", v.file()), "memory".to_string()],
        secrets.sources()
    );
    assert_eq!("from the vault", secrets.get("api.token").expect("get"));
    assert_eq!("from memory", secrets.get("db.pass").expect("get"));
}

#[test]
fn a_restricted_key_in_a_chain_falls_through() {
    let v = fresh();
    v.set("api.token", "from the vault").expect("set");
    v.set("db.pass", "also in the vault").expect("set");
    v.grant(&grantof("ci", "ci-passphrase", &["api.token"], false)).expect("grant");

    let mut secrets = thechain(vec![
        vaultspec(v.file(), "ci", "ci-passphrase"),
        memoryspec("DB_PASS", "from memory"),
    ])
    .expect("chain");

    assert_eq!("from the vault", secrets.get("api.token").expect("get"));
    // A NAME OUTSIDE THE GRANT IS A MISS, so the chain carries on rather
    // than stopping at a store that holds the name but not for this key.
    assert_eq!("from memory", secrets.get("db.pass").expect("get"));
}

#[test]
fn the_vault_behind_a_store_is_reachable() {
    let v = fresh();
    v.set("api.token", "tok01").expect("set");

    let mut secrets = thechain(vec![vaultspec(v.file(), "", MASTER)]).expect("chain");
    let api = vaultof(&secrets, "").expect("vaultof");

    assert_eq!(vec!["api.token"], api.list().expect("list"));

    // A CHAIN READS; the API writes. Both see the same file.
    api.set("db.pass", "written through the api").expect("set");
    assert_eq!("written through the api", secrets.get("db.pass").expect("get"));
}

#[test]
fn a_named_store_is_reached_by_name() {
    let first = fresh();
    first.set("api.token", "first").expect("set");
    let second = fresh();
    second.set("api.token", "second").expect("set");

    let secrets = thechain(vec![
        ProviderSpec {
            name: "app".to_string(),
            ..vaultspec(first.file(), "", MASTER)
        },
        ProviderSpec {
            name: "ops".to_string(),
            ..vaultspec(second.file(), "", MASTER)
        },
    ])
    .expect("chain");

    assert_eq!(first.file(), vaultof(&secrets, "app").expect("app").file());
    assert_eq!(second.file(), vaultof(&secrets, "ops").expect("ops").file());

    // A STORE THAT IS NOT THERE REFUSES, and the alias does not stand in
    // for it: picking one would be a guess, and the guess writes.
    holds(
        "a store that is not there",
        "no minivault store named nope in this chain",
        &refusal("a store that is not there", vaultof(&secrets, "nope")),
    );
}

#[test]
fn a_chain_with_no_vault_says_so() {
    let secrets = thechain(vec![memoryspec("API_TOKEN", "tok01")]).expect("chain");
    holds(
        "no vault",
        "no minivault store in this chain",
        &refusal("no vault", vaultof(&secrets, "")),
    );
}

#[test]
fn a_chain_missing_the_file_is_refused() {
    match thechain(vec![vaultspec("", "", "p")]) {
        Ok(_) => panic!("no file: nothing was refused"),
        Err(err) => holds("no file", "a vault needs a file", &format!("{:?}", err)),
    }
    match thechain(vec![vaultspec("v.skmv", "", "")]) {
        Ok(_) => panic!("no passphrase: nothing was refused"),
        Err(err) => holds("no passphrase", "a vault needs a passphrase", &format!("{:?}", err)),
    }
}

#[test]
fn the_file_is_reached_at_the_first_lookup() {
    // The file does not exist, and building the chain still succeeds: the
    // handle is lazy, so a chain costs no PBKDF2 until a secret is
    // actually wanted.
    let mut secrets = thechain(vec![vaultspec(&vaultpath(), "", MASTER)]).expect("chain");

    holds(
        "at the first lookup",
        "no vault file",
        &refusal("at the first lookup", secrets.get("api.token")),
    );
}
