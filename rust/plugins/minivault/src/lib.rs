//! The mini vault: every secret a project owns, encrypted, in one file.
//!
//! A store this library owns outright rather than a client for a server
//! somebody else runs. It has a master key and restricted keys, and it is
//! the port's worked example of a definition publishing an API beside its
//! provider: a chain READS, and writing is a deliberate act with an
//! interface of its own.
//!
//! ```no_run
//! use voxgig_sekreto::{Options, ProviderSpec, Sekreto};
//! use voxgig_sekreto_minivault::{createvault, minivault, vaultof, VaultOptions};
//!
//! let vault = createvault(&VaultOptions {
//!     file: "app.skmv".to_string(),
//!     passphrase: "master".to_string(),
//!     ..Default::default()
//! })
//! .unwrap();
//! vault.set("api.token", "tok01").unwrap();
//!
//! let mut secrets = Sekreto::new(Options {
//!     plugins: vec![minivault()],
//!     providers: vec![ProviderSpec {
//!         kind: "minivault".to_string(),
//!         file: "app.skmv".to_string(),
//!         passphrase: "master".to_string(),
//!         ..Default::default()
//!     }],
//!     ..Default::default()
//! })
//! .unwrap();
//!
//! let _ = secrets.get("api.token").unwrap();            // the chain reads
//! let _ = vaultof(&secrets, "").unwrap().list().unwrap(); // the API writes
//! ```
//!
//! A port of typescript/plugins/minivault.ts, which is canonical.

mod format;

use std::cell::RefCell;
use std::collections::BTreeMap;
use std::collections::HashMap;
use std::fs;
use std::io::Write;
use std::path::PathBuf;
use std::rc::Rc;
use std::sync::{Arc, Mutex, OnceLock};

use voxgig_plugin::catalog::Definition;
use voxgig_plugin::host::Inst;
use voxgig_plugin::types::{details, PluginError};
use voxgig_plugin::value::Value;

use voxgig_sekreto::{
    checkname, specof, Answer, Provider, Sekreto, ERROR_CODE, PROVIDER_EXPORT,
};

use format::{
    checkid, entryid, fail, kek, mac, random, readfile, seal, secretkey, unseal, writefile,
    EntryRecord, KeyRecord, Sealed, VaultFile, AAD_META, AAD_NAME, AAD_RING, AAD_SECRET, KEYLEN,
    LABEL_META, LABEL_NAMES, SALTLEN,
};

pub use format::{ITERATIONS, MASTERKEY};

/// The export key the vault API is published under, beside the provider.
pub const VAULT_EXPORT: &str = "vault";

// --- the lock every handle on one file shares -------------------------

/// Each `Vault` is its own object, so two handles on one path did not
/// coordinate: both could finish `load` before either saved, and the
/// second rename then discarded the first one's change while reporting
/// success. Keyed by the ABSOLUTE path, so two handles spelled
/// differently still meet.
///
/// A guarantee WITHIN one process, which is what DOCS.md promises and what
/// the go port arranges the same way. Two processes still race, and the
/// format's answer to that is the exclusive create and the atomic rename:
/// a reader sees one whole vault or the other, never half of one.
///
/// `std::sync`, although a `Vault` is `Rc` and never crosses a thread:
/// what races is the FILE, and two threads each opening their own handle
/// on one path is exactly the case this exists for.
static LOCKS: OnceLock<Mutex<HashMap<PathBuf, Arc<Mutex<()>>>>> = OnceLock::new();

fn lockfor(file: &str) -> Arc<Mutex<()>> {
    let key = fs::canonicalize(file).unwrap_or_else(|_| PathBuf::from(file));

    let table = LOCKS.get_or_init(|| Mutex::new(HashMap::new()));
    let mut held = table.lock().unwrap_or_else(|poisoned| poisoned.into_inner());

    held.entry(key).or_insert_with(|| Arc::new(Mutex::new(()))).clone()
}

// --- base64 ----------------------------------------------------------

/// Here rather than in the HTTP plugin: a vault opens no socket, and
/// reaching that crate for two functions would link a TLS stack into a
/// program whose only store is a local file.
const B64: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

fn b64(raw: &[u8]) -> String {
    let mut out = String::new();

    for chunk in raw.chunks(3) {
        let a = chunk[0] as u32;
        let b = if 1 < chunk.len() { chunk[1] as u32 } else { 0 };
        let c = if 2 < chunk.len() { chunk[2] as u32 } else { 0 };
        let triple = (a << 16) | (b << 8) | c;

        out.push(B64[(triple >> 18 & 63) as usize] as char);
        out.push(B64[(triple >> 12 & 63) as usize] as char);
        out.push(if 1 < chunk.len() {
            B64[(triple >> 6 & 63) as usize] as char
        } else {
            '='
        });
        out.push(if 2 < chunk.len() {
            B64[(triple & 63) as usize] as char
        } else {
            '='
        });
    }

    out
}

/// STRICT. A lenient decoder hands back plausible bytes for a corrupted
/// payload, and those bytes are then used AS A KEY.
fn unb64(text: &str, what: &str) -> Answer<Vec<u8>> {
    let missing = || fail::<Vec<u8>>(&format!("missing {}", what));

    let chars: Vec<u8> = text.bytes().filter(|byte| !byte.is_ascii_whitespace()).collect();
    if chars.is_empty() || 0 != chars.len() % 4 {
        return missing();
    }

    let body: Vec<u8> = chars.iter().copied().take_while(|byte| b'=' != *byte).collect();
    let pad = &chars[body.len()..];
    if 2 < pad.len() || !pad.iter().all(|byte| b'=' == *byte) {
        return missing();
    }

    let mut out = Vec::new();
    let (mut held, mut bits) = (0u32, 0u32);

    for byte in body {
        let value = match B64.iter().position(|one| *one == byte) {
            Some(at) => at as u32,
            None => return missing(),
        };

        held = (held << 6) | value;
        bits += 6;
        if 8 <= bits {
            bits -= 8;
            out.push((held >> bits & 0xff) as u8);
        }
    }

    Ok(out)
}

// --- the rings -------------------------------------------------------

/// A MASTER's ring holds the root and no grants; a RESTRICTED key's holds
/// grants and no root, EVEN WHEN IT WAS GRANTED NOTHING. That asymmetry is
/// the format rather than a saving: a ring with a root reaches every name
/// there will ever be, so a grant list beside it would be a second answer
/// to the same question - and an empty grant map is still a grant map, as
/// the go port learned by writing twelve bytes fewer than everyone else.
fn masterring(root: &[u8]) -> String {
    let mut out = Value::map();
    out.set("v", Value::Num(format::FORMAT as f64));
    out.set("write", Value::Bool(true));
    out.set("root", Value::str(&b64(root)));
    out.json()
}

fn grantring(write: bool, grants: &BTreeMap<String, Vec<u8>>) -> String {
    let mut held = Value::map();
    for (name, key) in grants {
        held.set(name, Value::str(&b64(key)));
    }

    let mut out = Value::map();
    out.set("v", Value::Num(format::FORMAT as f64));
    out.set("write", Value::Bool(write));
    out.set("grants", held);
    out.json()
}

fn metaof(master: bool, write: bool, names: &[String]) -> String {
    let mut out = Value::map();
    out.set("v", Value::Num(format::FORMAT as f64));
    out.set("master", Value::Bool(master));
    out.set("write", Value::Bool(write));
    out.set(
        "grants",
        Value::List(names.iter().map(|name| Value::str(name)).collect()),
    );
    out.json()
}

fn jsonof(plain: &[u8], what: &str) -> Answer<Value> {
    let text = String::from_utf8_lossy(plain);
    match voxgig_plugin::value::parse(&text) {
        Ok(held) if held.as_map().is_some() => Ok(held),
        _ => fail(&format!("unreadable {}", what)),
    }
}

fn jsontrue(held: &Value, key: &str) -> bool {
    matches!(held.get(key), Value::Bool(true))
}

// --- the vault -------------------------------------------------------

/// What a key may do. `grants` is empty for a master key, which reads and
/// writes every name there is.
///
/// FIELDS THE CALLER CANNOT WRITE THROUGH, so the defect the review round
/// found in the canonical - a caller flipping its own `write` bit on the
/// record it was handed - cannot be written at all. A clone makes a new
/// value and changes nothing the vault reads.
#[derive(Clone, Debug, Default, PartialEq)]
pub struct VaultKeyInfo {
    pub key: String,
    pub master: bool,
    pub write: bool,
    pub grants: Vec<String>,
}

/// How a vault file is opened as one key.
#[derive(Clone, Debug, Default)]
pub struct VaultOptions {
    /// The vault file.
    pub file: String,
    /// Which key to open with. Empty means `master`.
    pub key: String,
    /// What unwraps that key.
    pub passphrase: String,
    /// The PBKDF2 round count used when this handle CREATES a key.
    /// Reading uses what the file records for the key being opened.
    pub iterations: u32,
    /// Make the file, with this key as its master, if it is not there.
    ///
    /// Off by default. A missing vault is far more often a broken
    /// deployment than a new one, and a store that invents itself where a
    /// real vault was meant to be answers every read with a miss.
    pub create: bool,
}

/// What mints a restricted key.
#[derive(Clone, Debug, Default)]
pub struct GrantSpec {
    /// The id the new key answers to.
    pub key: String,
    /// What will unwrap it.
    pub passphrase: String,
    /// The names it may read.
    pub names: Vec<String>,
    /// Whether it may overwrite those names. It can never create one.
    pub write: bool,
    /// PBKDF2 rounds for this key; the vault's own when zero.
    pub iterations: u32,
}

/// What a handle remembers between calls: this key's ring, unwrapped.
struct Opened {
    info: VaultKeyInfo,
    root: Option<Vec<u8>>,
    grants: BTreeMap<String, Vec<u8>>,
    /// THE SEALED RING THIS WAS DERIVED FROM, kept so that every later
    /// call can check the file still says the same thing. A handle that
    /// cached its keys and never looked again kept reading a vault after
    /// its key was revoked, which is the one thing `revoke` promises.
    ring: Sealed,
}

struct Held {
    file: String,
    key: String,
    passphrase: String,
    iterations: u32,
    create: bool,
    opened: RefCell<Option<Opened>>,
}

/// A handle on one vault file, opened as ONE key.
///
/// Every method answers as that key: `list` shows the names it may read,
/// `get` answers for those and misses on the rest, and the master-only
/// ones refuse for any other key. Nothing is read or derived until the
/// first call that needs the file, so putting a vault in a chain costs no
/// key derivation until a secret is actually wanted.
///
/// Cheap to clone: the handle is shared, not copied, so the definition can
/// export one and keep one.
#[derive(Clone)]
pub struct Vault {
    held: Rc<Held>,
}

fn wantkey(value: &str) -> &str {
    // AN EMPTY KEY IS NO KEY, so it means `master`. A CLI reaches this
    // with SEKRETO_VAULT_KEY set and empty, which is what an unset shell
    // variable expands to.
    if value.is_empty() {
        MASTERKEY
    } else {
        value
    }
}

/// Open a vault file as one key. Nothing is read until the first call
/// that needs the file.
pub fn openvault(options: &VaultOptions) -> Answer<Vault> {
    if options.file.is_empty() {
        return fail("a vault needs a file");
    }
    if options.passphrase.is_empty() {
        return fail("a vault needs a passphrase");
    }

    let key = wantkey(&options.key);
    checkid(key, "a vault needs a key id")?;

    Ok(Vault {
        held: Rc::new(Held {
            file: options.file.clone(),
            key: key.to_string(),
            passphrase: options.passphrase.clone(),
            iterations: if 0 < options.iterations {
                options.iterations
            } else {
                ITERATIONS
            },
            create: options.create,
            opened: RefCell::new(None),
        }),
    })
}

/// Make a vault file and answer a handle on its master key.
///
/// Refuses a file that is already there: a vault is created once, and
/// overwriting one discards every secret in it.
pub fn createvault(options: &VaultOptions) -> Answer<Vault> {
    if options.file.is_empty() {
        return fail("a vault needs a file");
    }
    if options.passphrase.is_empty() {
        return fail("a vault needs a passphrase");
    }

    let key = wantkey(&options.key);
    checkid(key, "a vault needs a key id")?;

    let iterations = if 0 < options.iterations {
        options.iterations
    } else {
        ITERATIONS
    };

    // No existence check first: the check and the write would be two
    // steps, and `putnew` refuses an existing file in ONE.
    putnew(&options.file, &newvault(key, &options.passphrase, iterations)?)?;

    openvault(options)
}

fn newvault(key: &str, passphrase: &str, iterations: u32) -> Answer<VaultFile> {
    let root = random(KEYLEN)?;
    let record = sealkey(
        &root,
        key,
        passphrase,
        iterations,
        &masterring(&root),
        &metaof(true, true, &[]),
    )?;

    Ok(VaultFile {
        keys: vec![record],
        entries: vec![],
    })
}

fn sealkey(
    root: &[u8],
    id: &str,
    passphrase: &str,
    iters: u32,
    ring: &str,
    noted: &str,
) -> Answer<KeyRecord> {
    let salt = random(SALTLEN)?;
    let wrapping = kek(passphrase, &salt, iters)?;
    let metakey = mac(root, LABEL_META);

    Ok(KeyRecord {
        id: id.to_string(),
        salt,
        iters,
        ring: seal(&wrapping, ring.as_bytes(), &format!("{}{}", AAD_RING, id))?,
        meta: seal(&metakey, noted.as_bytes(), &format!("{}{}", AAD_META, id))?,
    })
}

// --- the file on disk -------------------------------------------------

/// Writes a vault file that is not there yet, and REFUSES one that is.
///
/// `create_new` is `O_EXCL`, and the mode goes on at creation rather than
/// after: a `set_permissions` once the bytes are written leaves the file
/// readable for as long as it takes to write them.
fn putnew(path: &str, made: &VaultFile) -> Answer<()> {
    let mut open = fs::OpenOptions::new();
    open.write(true).create_new(true);
    owneronly(&mut open);

    match open.open(path) {
        Ok(mut handle) => match handle.write_all(&writefile(made)) {
            Ok(()) => Ok(()),
            Err(_) => fail(&format!("cannot write {}", path)),
        },
        Err(err) if std::io::ErrorKind::AlreadyExists == err.kind() => {
            fail(&format!("vault file already exists: {}", path))
        }
        Err(_) => fail(&format!("cannot write {}", path)),
    }
}

#[cfg(unix)]
fn owneronly(open: &mut fs::OpenOptions) {
    use std::os::unix::fs::OpenOptionsExt;
    open.mode(0o600);
}

#[cfg(not(unix))]
fn owneronly(_open: &mut fs::OpenOptions) {
    // No POSIX mode to ask for. The file lands with whatever the platform
    // gives a new file, which is what every port can promise there.
}

fn readmaybe(path: &str) -> Answer<Option<Vec<u8>>> {
    match fs::read(path) {
        Ok(raw) => Ok(Some(raw)),
        Err(err) if std::io::ErrorKind::NotFound == err.kind() => Ok(None),
        Err(_) => fail(&format!("cannot read {}", path)),
    }
}

impl Vault {
    /// The file this handle reads.
    pub fn file(&self) -> &str {
        &self.held.file
    }

    /// The key id this handle opens with.
    pub fn key(&self) -> &str {
        &self.held.key
    }

    /// Forget the derived keys. The next call opens again.
    pub fn close(&self) {
        *self.held.opened.borrow_mut() = None;
    }

    /// Replaces the file rather than editing it in place. The rename is
    /// what makes a concurrent reader see either the old file or the new
    /// one, so a write interrupted halfway leaves a vault rather than
    /// wreckage.
    ///
    /// THE TEMPORARY IS RANDOM AND EXCLUSIVE. `<vault>.<pid>.tmp` is a
    /// name anyone can predict, and an ordinary create FOLLOWS a symlink,
    /// so anyone who could write the vault's directory could point that
    /// name at another file and have the next save truncate it.
    fn save(&self, made: &VaultFile) -> Answer<()> {
        let suffix = random(8)?;
        let temp = format!("{}.{}.tmp", self.held.file, hex(&suffix));

        putnew(&temp, made)?;

        match fs::rename(&temp, &self.held.file) {
            Ok(()) => Ok(()),
            Err(_) => {
                // The vault is unchanged either way, and the write error
                // is what the caller needs to be told about.
                let _ = fs::remove_file(&temp);
                fail(&format!("cannot write {}", self.held.file))
            }
        }
    }

    fn bytes(&self) -> Answer<Vec<u8>> {
        match readmaybe(&self.held.file)? {
            Some(raw) => Ok(raw),
            None => {
                // A vault is configured deliberately, with a key. Its
                // absence is a broken deployment and never "no secrets
                // here": answering a miss would send the chain on to a
                // weaker store, which is the failure mode this library
                // most has to avoid. `create` is the caller saying the
                // opposite, in writing.
                if !self.held.create {
                    return fail(&format!("no vault file: {}", self.held.file));
                }

                putnew(
                    &self.held.file,
                    &newvault(&self.held.key, &self.held.passphrase, self.held.iterations)?,
                )?;

                match readmaybe(&self.held.file)? {
                    Some(raw) => Ok(raw),
                    None => fail(&format!("cannot read {}", self.held.file)),
                }
            }
        }
    }

    /// The file as this key sees it: parsed every call - it is different
    /// bytes every time - while the unwrapped ring is kept, because
    /// stretching a passphrase once per lookup is the cost that caching
    /// exists to avoid.
    fn load(&self) -> Answer<VaultFile> {
        let file = readfile(&self.bytes()?)?;

        let record = match file.key(&self.held.key) {
            Some(held) => held.clone(),
            None => {
                // REVOKED, or never there. Either way this handle is
                // finished, and dropping what it derived is what stops the
                // next call answering from memory.
                self.close();
                return fail(&format!("no such key: {}", self.held.key));
            }
        };

        // The file still holds this key, and holds the SAME ring: a key
        // revoked and re-granted under another passphrase is a different
        // key wearing the id, and re-deriving is what refuses it.
        let fresh = match &*self.held.opened.borrow() {
            Some(held) => held.ring != record.ring,
            None => true,
        };

        if fresh {
            self.close();
            let made = self.derive(&record)?;
            *self.held.opened.borrow_mut() = Some(made);
        }

        Ok(file)
    }

    fn derive(&self, record: &KeyRecord) -> Answer<Opened> {
        let wrapping = kek(&self.held.passphrase, &record.salt, record.iters)?;
        let plain = unseal(
            &wrapping,
            &record.ring,
            &format!("{}{}", AAD_RING, self.held.key),
            &format!(
                "wrong passphrase for key {}, or a damaged vault",
                self.held.key
            ),
        )?;

        let ring = jsonof(&plain, &format!("key ring for {}", self.held.key))?;

        let mut grants = BTreeMap::new();
        if let Some(entries) = ring.get("grants").as_map() {
            for (name, key) in entries {
                match key.as_str() {
                    Some(text) => {
                        grants.insert(name.clone(), unb64(text, "a granted key")?);
                    }
                    None => return fail("missing a granted key"),
                }
            }
        }

        let root = match ring.get("root").as_str() {
            Some(text) => Some(unb64(text, "the root key")?),
            None => None,
        };

        Ok(Opened {
            info: VaultKeyInfo {
                key: self.held.key.clone(),
                master: root.is_some(),
                write: root.is_some() || jsontrue(&ring, "write"),
                grants: grants.keys().cloned().collect(),
            },
            root,
            grants,
            ring: record.ring.clone(),
        })
    }

    fn info(&self) -> VaultKeyInfo {
        match &*self.held.opened.borrow() {
            Some(held) => held.info.clone(),
            None => VaultKeyInfo::default(),
        }
    }

    fn rootof(&self, what: &str) -> Answer<Vec<u8>> {
        match &*self.held.opened.borrow() {
            Some(held) => match &held.root {
                Some(root) => Ok(root.clone()),
                None => fail(&format!(
                    "{} needs a master key, and {} is restricted",
                    what, self.held.key
                )),
            },
            None => fail(&format!("{} needs a master key", what)),
        }
    }

    /// The key for one name, or nothing when this key cannot reach it.
    fn keyfor(&self, name: &str) -> Option<Vec<u8>> {
        let held = self.held.opened.borrow();
        let open = held.as_ref()?;

        match &open.root {
            Some(root) => Some(secretkey(root, name)),
            None => open.grants.get(name).cloned(),
        }
    }

    /// Derive the key and read the file NOW rather than at first use.
    pub fn open(&self) -> Answer<VaultKeyInfo> {
        self.load()?;
        Ok(self.info())
    }

    /// The names this key can read, sorted.
    pub fn list(&self) -> Answer<Vec<String>> {
        let file = self.load()?;
        let info = self.info();

        let mut out = match &self.held.opened.borrow().as_ref().and_then(|h| h.root.clone()) {
            Some(root) => {
                let namekey = mac(root, LABEL_NAMES);
                let mut names = Vec::new();
                for entry in &file.entries {
                    let plain =
                        unseal(&namekey, &entry.name, AAD_NAME, "a secret name is damaged")?;
                    names.push(String::from_utf8_lossy(&plain).into_owned());
                }
                names
            }
            // A restricted key has no name key, so it reports the grants
            // it can actually find: the vault never tells it what else is
            // in there.
            None => info
                .grants
                .iter()
                .filter(|name| {
                    self.keyfor(name)
                        .map(|key| file.entry(&entryid(&key)).is_some())
                        .unwrap_or(false)
                })
                .cloned()
                .collect(),
        };

        out.sort();
        Ok(out)
    }

    /// The value, or a MISS. A name the vault does not hold and a name
    /// this key cannot read answer the same way, which is what makes a
    /// restricted vault in front of a broader store a workable chain.
    pub fn get(&self, name: &str) -> Answer<Option<String>> {
        checkname(name)?;
        let file = self.load()?;

        let key = match self.keyfor(name) {
            Some(held) => held,
            None => return Ok(None),
        };

        match file.entry(&entryid(&key)) {
            None => Ok(None),
            Some(entry) => {
                let plain = unseal(
                    &key,
                    &entry.value,
                    &format!("{}{}", AAD_SECRET, name),
                    &format!("the value of {} is damaged", name),
                )?;
                Ok(Some(String::from_utf8_lossy(&plain).into_owned()))
            }
        }
    }

    pub fn has(&self, name: &str) -> Answer<bool> {
        Ok(self.get(name)?.is_some())
    }

    /// Write a value. A master writes any name; a restricted key holding
    /// `write` overwrites the names it was granted, and creates none.
    pub fn set(&self, name: &str, value: &str) -> Answer<()> {
        checkname(name)?;

        // Every write on this file, from any handle in this process,
        // serializes here; see lockfor.
        let one = lockfor(&self.held.file);
        let _guard = one.lock().unwrap_or_else(|poisoned| poisoned.into_inner());

        let mut file = self.load()?;
        let info = self.info();

        if !info.write {
            return fail(&format!("key {} is read-only", self.held.key));
        }

        let key = match self.keyfor(name) {
            Some(held) => held,
            None => {
                return fail(&format!("key {} was not granted {}", self.held.key, name));
            }
        };

        let box_ = seal(&key, value.as_bytes(), &format!("{}{}", AAD_SECRET, name))?;
        let id = entryid(&key);

        match file.entries.iter_mut().find(|entry| id == entry.id) {
            Some(entry) => entry.value = box_,
            None => {
                // A NEW NAME NEEDS THE NAME KEY, which only a master
                // holds. So a restricted key with `write` updates what it
                // was granted and cannot grow the vault, which is what
                // "restricted" has to mean for the grant list to stay the
                // whole story.
                let root = self.rootof(&format!("creating the secret {}", name))?;
                let namekey = mac(&root, LABEL_NAMES);

                file.entries.push(EntryRecord {
                    id,
                    name: seal(&namekey, name.as_bytes(), AAD_NAME)?,
                    value: box_,
                });
            }
        }

        self.save(&file)
    }

    /// Drop a name. Master only.
    pub fn remove(&self, name: &str) -> Answer<()> {
        checkname(name)?;

        let one = lockfor(&self.held.file);
        let _guard = one.lock().unwrap_or_else(|poisoned| poisoned.into_inner());

        let mut file = self.load()?;
        let root = self.rootof("removing a secret")?;
        let want = entryid(&secretkey(&root, name));

        if file.entry(&want).is_none() {
            return fail(&format!("no such secret: {}", name));
        }

        file.entries.retain(|entry| want != entry.id);

        self.save(&file)
    }

    /// Every key in the file, with what it may do. Master only.
    pub fn keys(&self) -> Answer<Vec<VaultKeyInfo>> {
        let file = self.load()?;
        let root = self.rootof("listing the keys")?;
        let metakey = mac(&root, LABEL_META);

        let mut out = Vec::new();

        for record in &file.keys {
            let mut info = VaultKeyInfo {
                key: record.id.clone(),
                ..Default::default()
            };

            // A record written under a root key this one has replaced. The
            // key is still in the file and still opens with its own
            // passphrase, so it is reported rather than hidden - with what
            // it can do unknown.
            if let Ok(plain) = unseal(
                &metakey,
                &record.meta,
                &format!("{}{}", AAD_META, record.id),
                "metadata",
            ) {
                let noted = jsonof(&plain, &format!("metadata for key {}", record.id))?;
                info.master = jsontrue(&noted, "master");
                info.write = jsontrue(&noted, "write");
                if let Some(names) = noted.get("grants").as_list() {
                    info.grants = names
                        .iter()
                        .filter_map(|one| one.as_str().map(|text| text.to_string()))
                        .collect();
                    info.grants.sort();
                }
            }

            out.push(info);
        }

        Ok(out)
    }

    /// Mint a restricted key. Master only.
    pub fn grant(&self, spec: &GrantSpec) -> Answer<()> {
        let one = lockfor(&self.held.file);
        let _guard = one.lock().unwrap_or_else(|poisoned| poisoned.into_inner());

        let mut file = self.load()?;
        let root = self.rootof("granting a key")?;

        checkid(&spec.key, "a grant needs a key id")?;
        if spec.passphrase.is_empty() {
            return fail("a grant needs a passphrase");
        }
        if file.key(&spec.key).is_some() {
            return fail(&format!("key already exists: {}", spec.key));
        }

        let mut names = spec.names.clone();
        names.sort();

        let mut grants = BTreeMap::new();
        for name in &names {
            checkname(name)?;
            grants.insert(name.clone(), secretkey(&root, name));
        }

        let iterations = if 0 < spec.iterations {
            spec.iterations
        } else {
            self.held.iterations
        };

        let record = sealkey(
            &root,
            &spec.key,
            &spec.passphrase,
            iterations,
            &grantring(spec.write, &grants),
            &metaof(false, spec.write, &names),
        )?;

        file.keys.push(record);

        self.save(&file)
    }

    /// Drop a key. Master only.
    ///
    /// Anyone who already copied the file keeps whatever that key could
    /// read, so revoking bars future reads of the LIVE file and `rotate`
    /// is what takes a secret back.
    pub fn revoke(&self, key: &str) -> Answer<()> {
        let one = lockfor(&self.held.file);
        let _guard = one.lock().unwrap_or_else(|poisoned| poisoned.into_inner());

        let mut file = self.load()?;
        self.rootof("revoking a key")?;

        if key == self.held.key {
            return fail(&format!("a key cannot revoke itself: {}", key));
        }
        if file.key(key).is_none() {
            return fail(&format!("no such key: {}", key));
        }

        file.keys.retain(|record| key != record.id);

        self.save(&file)
    }

    /// Take a new root key, re-encrypt every value under it, and DROP
    /// EVERY OTHER KEY. Master only.
    ///
    /// The other keys go because they must: their rings are sealed under
    /// passphrases this process does not have, so there is no way to hand
    /// them keys they can unwrap. Re-grant afterwards.
    pub fn rotate(&self) -> Answer<()> {
        let one = lockfor(&self.held.file);
        let _guard = one.lock().unwrap_or_else(|poisoned| poisoned.into_inner());

        let file = self.load()?;
        let oldroot = self.rootof("rotating the vault")?;

        let iters = match file.key(&self.held.key) {
            Some(record) => record.iters,
            None => self.held.iterations,
        };

        // Read everything out under the old root before anything changes:
        // once the root is replaced the old derived keys are unreachable.
        let oldnamekey = mac(&oldroot, LABEL_NAMES);
        let mut held = Vec::new();

        for entry in &file.entries {
            let plain = unseal(&oldnamekey, &entry.name, AAD_NAME, "a secret name is damaged")?;
            let name = String::from_utf8_lossy(&plain).into_owned();
            let key = secretkey(&oldroot, &name);

            let value = unseal(
                &key,
                &entry.value,
                &format!("{}{}", AAD_SECRET, name),
                &format!("the value of {} is damaged", name),
            )?;

            held.push((name, String::from_utf8_lossy(&value).into_owned()));
        }

        let root = random(KEYLEN)?;
        let namekey = mac(&root, LABEL_NAMES);
        let mut entries = Vec::new();

        for (name, value) in &held {
            let key = secretkey(&root, name);
            entries.push(EntryRecord {
                id: entryid(&key),
                name: seal(&namekey, name.as_bytes(), AAD_NAME)?,
                value: seal(&key, value.as_bytes(), &format!("{}{}", AAD_SECRET, name))?,
            });
        }

        let record = sealkey(
            &root,
            &self.held.key,
            &self.held.passphrase,
            iters,
            &masterring(&root),
            &metaof(true, true, &[]),
        )?;

        self.save(&VaultFile {
            keys: vec![record],
            entries,
        })?;

        // The ring this handle holds is the OLD one, so the next call must
        // derive again rather than answer from it.
        self.close();

        Ok(())
    }
}

fn hex(raw: &[u8]) -> String {
    raw.iter().map(|byte| format!("{:02x}", byte)).collect()
}

// --- the provider and the definition ----------------------------------

/// Reads a vault as one store in a chain.
struct MiniVaultProvider {
    vault: Vault,
}

impl Provider for MiniVaultProvider {
    fn lookup(&self, name: &str) -> Answer<Option<String>> {
        self.vault.get(name)
    }

    fn describe(&self) -> String {
        format!("minivault:{}", self.vault.file())
    }
}

/// The `minivault` provider kind, as a voxgig/plugin definition.
///
/// Written out rather than built by `providerplugin`, because this
/// definition publishes TWO exports: `provider`, the read half every kind
/// publishes, and `vault`, the programmatic API. voxgig/plugin's exports
/// are how a definition offers an application more than the host's own
/// vocabulary, and a store that can only be read is half a vault.
///
/// Both cross as `Value::Opaque` - plugin's escape hatch for "a client the
/// library never inspects" - which is what `providerplugin` already does
/// for the provider. No slot table: unlike the ports whose value model
/// carries only numbers and strings, rust can put the handle itself in.
pub fn minivault() -> Definition {
    let mut definition = Definition::named("minivault");

    definition.define = Some(Rc::new(move |inst: &Inst| {
        let spec = specof(&inst.options());

        let built = openvault(&VaultOptions {
            file: spec.file.clone(),
            key: spec.vaultkey.clone(),
            passphrase: spec.passphrase.clone(),
            iterations: spec.iterations,
            create: spec.create,
        });

        match built {
            Ok(vault) => {
                let provider: Rc<dyn Provider> = Rc::new(MiniVaultProvider {
                    vault: vault.clone(),
                });
                inst.export(PROVIDER_EXPORT, Value::Opaque(Rc::new(provider)));
                inst.export(VAULT_EXPORT, Value::Opaque(Rc::new(vault)));
                Ok(())
            }
            // The message is the spec's, byte for byte, and the code is
            // what `Sekreto::new` reads it back under. This is the
            // `sekreto_error` bridge `providerplugin` would have done.
            Err(err) => Err(PluginError::new(
                ERROR_CODE,
                &err.message,
                details(&[
                    ("ref", Value::str(&inst.eref)),
                    ("cause", Value::str(&err.message)),
                ]),
            )),
        }
    }));

    definition
}

/// The vault behind a store in a chain, as its programmatic API.
///
/// With no store named, the unqualified alias answers: one vault in the
/// chain resolves whatever it is called, and two refuse rather than
/// picking one.
pub fn vaultof(secrets: &Sekreto, store: &str) -> Answer<Vault> {
    let held = |eref: &str, why: &str| -> Answer<Vault> {
        let exported = match secrets.host().exports(&format!("{}/{}", eref, VAULT_EXPORT)) {
            Ok(value) => value,
            Err(_) => return fail(why),
        };

        match &exported {
            Value::Opaque(one) => match one.downcast_ref::<Vault>() {
                Some(vault) => Ok(vault.clone()),
                None => fail(why),
            },
            _ => fail(why),
        }
    };

    if store.is_empty() {
        return held("minivault", "no minivault store in this chain");
    }

    // A NAMED STORE MUST EXIST, and the alias must not stand in for it.
    // `exports` falls back to the alias when the exact ref misses, so
    // asking for `minivault` in a chain whose only vault is named `app`
    // used to hand back the `app` vault - and then write to it.
    let missing = format!("no minivault store named {} in this chain", store);
    let eref = if "minivault" == store {
        "minivault".to_string()
    } else {
        format!("minivault${}", store)
    };

    match secrets.host().instance(&Value::str(&eref)) {
        Ok(Some(_)) => held(&eref, &missing),
        _ => fail(&missing),
    }
}
