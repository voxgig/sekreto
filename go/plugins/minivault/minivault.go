// A mini vault: every secret a project owns, encrypted, in ONE FILE.
//
// The store to reach for before there is a vault server. There is
// nothing to run and nothing to reach over a socket - the whole store is
// a single binary file - and the same chain that reads it in development
// reads HashiCorp or AWS in production by changing config, which is the
// reason sekreto exists.
//
// It is a plugin rather than a built-in kind because it needs crypto,
// which is the line the four built-ins stay behind.
//
// THE KEY DECIDES WHAT THE VAULT HOLDS. A master key reads and writes
// every name and mints restricted keys. A restricted key reads the names
// it was granted and CANNOT DERIVE ANY OTHER - the restriction is the
// cryptography rather than a check this code performs, so a copy of the
// file plus a restricted passphrase yields exactly what was granted and
// nothing else. What that does and does not protect is set out in
// DOCS.md under "What the mini vault protects".
//
// A port of typescript/plugins/minivault.ts, which is canonical.
package minivault

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"os"
	"sort"
	"strconv"
	"sync"

	plugin "github.com/voxgig/plugin/go/plugin"

	"github.com/voxgig/sekreto/go/sekreto"
)

// KeyInfo is what a key may do. Grants is empty for a master key, which
// reads and writes every name there is.
type KeyInfo struct {
	Key    string   `json:"key"`
	Master bool     `json:"master"`
	Write  bool     `json:"write"`
	Grants []string `json:"grants"`
}

// GrantSpec mints a restricted key.
type GrantSpec struct {
	// Key is the id the new key answers to.
	Key string
	// Passphrase is what unwraps it. Nothing else does, and no master can
	// recover it - a lost restricted passphrase is re-granted, never read
	// back.
	Passphrase string
	// Names the key may read. A name that does not exist yet is allowed
	// and means what it says: the key reads it once a master writes it.
	Names []string
	// Write says whether it may overwrite the values it can read.
	Write bool
	// Iterations for this key's PBKDF2, defaulting to the opening
	// handle's.
	Iterations int
}

// Options open one vault file as one key.
type Options struct {
	// File is the vault file.
	File string
	// Key is which key to open with. Default MasterKey.
	Key string
	// Passphrase unwraps that key.
	Passphrase string
	// Iterations is the PBKDF2 round count used when this handle CREATES
	// a key. Reading uses what the file records for the key being opened.
	Iterations int
	// Create makes the file, with this key as its master, if it is not
	// there.
	//
	// Off by default. A missing vault is far more often a broken
	// deployment than a new one, and a store that invents itself where a
	// real vault was meant to be answers every read with a miss.
	Create bool
}

// ring is what a key holds, as it is stored: EITHER a root key (master)
// OR a fixed set of derived per-secret keys (restricted).
type ring struct {
	V      int               `json:"v"`
	Write  bool              `json:"write"`
	Root   string            `json:"root,omitempty"`
	Grants map[string]string `json:"grants,omitempty"`
}

// meta is what a master recorded about a key when it minted it, sealed
// under the vault's meta key so that Keys can answer without holding any
// other key's passphrase.
type meta struct {
	V      int      `json:"v"`
	Master bool     `json:"master"`
	Write  bool     `json:"write"`
	Grants []string `json:"grants"`
}

// Vault is a handle on one vault file, opened as ONE key.
//
// Every method answers as that key: List shows the names it may read,
// Get answers for those and misses on the rest, and the master-only
// methods refuse for any other key. Nothing is read or derived until the
// first call that needs the file, so putting a vault in a chain costs no
// key derivation until a secret is actually wanted.
type Vault struct {
	file       string
	key        string
	passphrase string
	iterations int
	create     bool

	// Guards the derived state below. A Sekreto may resolve from several
	// goroutines, and two of them deriving the same ring concurrently is
	// wasted work at best and a torn map at worst.
	mu     sync.Mutex
	info   *KeyInfo
	root   []byte
	grants map[string][]byte
}

// Open a vault file as one key.
//
// The handle is lazy. Nothing is read, and no passphrase is stretched,
// until a method needs the file - so a chain of ten providers costs ten
// objects rather than ten PBKDF2 runs.
func Open(options *Options) (*Vault, error) {
	if nil == options || "" == options.File {
		return nil, fail("a vault needs a file")
	}
	if "" == options.Passphrase {
		return nil, fail("a vault needs a passphrase")
	}

	key := options.Key
	if "" == key {
		key = MasterKey
	}

	iterations := options.Iterations
	if 0 >= iterations {
		iterations = Iterations
	}

	return &Vault{
		file:       options.File,
		key:        key,
		passphrase: options.Passphrase,
		iterations: iterations,
		create:     options.Create,
	}, nil
}

// Create makes a vault file and returns a handle on its master key.
//
// Refuses a file that is already there: a vault is created once, and
// overwriting one discards every secret in it along with every key that
// could read them.
func Create(options *Options) (*Vault, error) {
	vault, err := Open(options)
	if nil != err {
		return nil, err
	}

	if _, err := os.Stat(vault.file); nil == err {
		return nil, fail("vault file already exists: " + vault.file)
	}

	fresh, err := newvault(vault.key, vault.passphrase, vault.iterations)
	if nil != err {
		return nil, err
	}

	if err := putnew(vault.file, fresh); nil != err {
		return nil, err
	}

	return vault, nil
}

// File is the vault file this handle reads.
func (vault *Vault) File() string { return vault.file }

// Key is the key id this handle opens with.
func (vault *Vault) Key() string { return vault.key }

// Info derives the key and reads the file NOW rather than at first use.
func (vault *Vault) Info() (*KeyInfo, error) {
	vault.mu.Lock()
	defer vault.mu.Unlock()

	_, info, err := vault.load()
	return info, err
}

// Close forgets the derived keys. The next call opens again.
func (vault *Vault) Close() {
	vault.mu.Lock()
	defer vault.mu.Unlock()

	vault.info = nil
	vault.root = nil
	vault.grants = nil
}

// --- reading the file ------------------------------------------------

func (vault *Vault) bytes() ([]byte, error) {
	raw, err := os.ReadFile(vault.file)
	if nil == err {
		return raw, nil
	}

	// A vault is configured deliberately, with a key. Its absence is a
	// broken deployment and never "no secrets here": answering a miss
	// would send the chain on to a weaker store, which is the failure
	// mode this library most has to avoid. Create is the caller saying
	// the opposite, in writing.
	if os.IsNotExist(err) {
		if !vault.create {
			return nil, fail("no vault file: " + vault.file)
		}

		fresh, err := newvault(vault.key, vault.passphrase, vault.iterations)
		if nil != err {
			return nil, err
		}
		if err := putnew(vault.file, fresh); nil != err {
			return nil, err
		}

		return os.ReadFile(vault.file)
	}

	return nil, fail("cannot read " + vault.file + ": " + err.Error())
}

// load reads the file and, the first time, unwraps this key's ring.
// Callers hold vault.mu.
func (vault *Vault) load() (*vaultFile, *KeyInfo, error) {
	raw, err := vault.bytes()
	if nil != err {
		return nil, nil, err
	}

	file, err := readfile(raw)
	if nil != err {
		return nil, nil, err
	}

	if nil != vault.info {
		return file, vault.info, nil
	}

	record := file.key(vault.key)
	if nil == record {
		return nil, nil, fail("no such key: " + vault.key)
	}

	plain, err := unseal(kek(vault.passphrase, record.Salt, record.Iters), record.Ring,
		aadRing+vault.key, "wrong passphrase for key "+vault.key+", or a damaged vault")
	if nil != err {
		return nil, nil, err
	}

	held := &ring{}
	if err := jsonof(plain, held, "key ring for "+vault.key); nil != err {
		return nil, nil, err
	}

	grants := map[string][]byte{}
	names := []string{}
	for name, key := range held.Grants {
		raw, err := unb64(key, "a granted key")
		if nil != err {
			return nil, nil, err
		}
		grants[name] = raw
		names = append(names, name)
	}
	sort.Strings(names)

	root := []byte(nil)
	if "" != held.Root {
		if root, err = unb64(held.Root, "the root key"); nil != err {
			return nil, nil, err
		}
	}

	vault.root = root
	vault.grants = grants
	vault.info = &KeyInfo{
		Key:    vault.key,
		Master: nil != root,
		Write:  nil != root || held.Write,
		Grants: names,
	}

	return file, vault.info, nil
}

// rootof is the root key, or a refusal naming what needed it.
func (vault *Vault) rootof(what string) ([]byte, error) {
	if nil == vault.root {
		return nil, fail(what + " needs a master key, and " + vault.key + " is restricted")
	}
	return vault.root, nil
}

// keyfor is the key for one name, or nil when this key cannot reach it.
func (vault *Vault) keyfor(name string) []byte {
	if nil != vault.root {
		return secretkey(vault.root, name)
	}
	return vault.grants[name]
}

// save replaces the file rather than editing it in place. The rename is
// what makes a concurrent reader see either the old file or the new one,
// so a write interrupted halfway leaves a vault rather than wreckage.
func (vault *Vault) save(file *vaultFile) error {
	temp := vault.file + "." + strconv.Itoa(os.Getpid()) + ".tmp"

	if err := os.WriteFile(temp, writefile(file), 0o600); nil != err {
		return fail("cannot write " + vault.file + ": " + err.Error())
	}

	if err := os.Rename(temp, vault.file); nil != err {
		// The vault is unchanged either way, and the write error is what
		// the caller needs to be told about.
		os.Remove(temp)
		return fail("cannot write " + vault.file + ": " + err.Error())
	}

	return nil
}

// --- reading secrets -------------------------------------------------

// List is the names this key can read, sorted.
func (vault *Vault) List() ([]string, error) {
	vault.mu.Lock()
	defer vault.mu.Unlock()

	file, info, err := vault.load()
	if nil != err {
		return nil, err
	}

	names := []string{}

	if nil != vault.root {
		namekey := mac(vault.root, labelNames)
		for _, entry := range file.Entries {
			plain, err := unseal(namekey, entry.Name, aadName, "a secret name is damaged")
			if nil != err {
				return nil, err
			}
			names = append(names, string(plain))
		}
	} else {
		// A restricted key has no name key, so it reports the grants it
		// can actually find: the vault never tells it what else is there.
		for _, name := range info.Grants {
			if nil != file.entry(entryid(vault.grants[name])) {
				names = append(names, name)
			}
		}
	}

	sort.Strings(names)

	return names, nil
}

// Get is the value, and whether this key could read it. A name the vault
// does not hold and a name this key was not granted are both a miss.
func (vault *Vault) Get(name string) (string, bool, error) {
	if err := sekreto.CheckName(name); nil != err {
		return "", false, err
	}

	vault.mu.Lock()
	defer vault.mu.Unlock()

	file, _, err := vault.load()
	if nil != err {
		return "", false, err
	}

	key := vault.keyfor(name)
	if nil == key {
		// OUTSIDE THE GRANT IS A MISS, deliberately. The vault answers as
		// the key that opened it, so a name this key cannot read is a
		// name this store does not hold for this caller - the same answer
		// a stranger's vault gives, and the one that makes a restricted
		// key in front of a broader store a workable chain.
		return "", false, nil
	}

	entry := file.entry(entryid(key))
	if nil == entry {
		return "", false, nil
	}

	plain, err := unseal(key, entry.Value, aadSecret+name, "the value of "+name+" is damaged")
	if nil != err {
		return "", false, err
	}

	return string(plain), true, nil
}

// Has says whether this key can read that name.
func (vault *Vault) Has(name string) (bool, error) {
	_, has, err := vault.Get(name)
	return has, err
}

// --- writing ---------------------------------------------------------

// Set writes a value. A master writes any name; a restricted key holding
// Write overwrites the names it was granted, and creates none.
func (vault *Vault) Set(name string, value string) error {
	if err := sekreto.CheckName(name); nil != err {
		return err
	}

	vault.mu.Lock()
	defer vault.mu.Unlock()

	file, info, err := vault.load()
	if nil != err {
		return err
	}

	if !info.Write {
		return fail("key " + info.Key + " is read-only")
	}

	key := vault.keyfor(name)
	if nil == key {
		return fail("key " + info.Key + " was not granted " + name)
	}

	box, err := seal(key, []byte(value), aadSecret+name)
	if nil != err {
		return err
	}

	if entry := file.entry(entryid(key)); nil != entry {
		entry.Value = box
	} else {
		// A NEW NAME NEEDS THE NAME KEY, which only a master holds. So a
		// restricted key with Write updates what it was granted and
		// cannot grow the vault, which is what "restricted" has to mean
		// for the grant list to stay the whole story.
		root, err := vault.rootof("creating the secret " + name)
		if nil != err {
			return err
		}

		sealedname, err := seal(mac(root, labelNames), []byte(name), aadName)
		if nil != err {
			return err
		}

		file.Entries = append(file.Entries,
			&entryRecord{ID: entryid(key), Name: sealedname, Value: box})
	}

	return vault.save(file)
}

// Remove drops a name. Master only.
func (vault *Vault) Remove(name string) error {
	if err := sekreto.CheckName(name); nil != err {
		return err
	}

	vault.mu.Lock()
	defer vault.mu.Unlock()

	file, _, err := vault.load()
	if nil != err {
		return err
	}

	root, err := vault.rootof("removing a secret")
	if nil != err {
		return err
	}

	want := entryid(secretkey(root, name))
	kept := []*entryRecord{}
	found := false

	for _, entry := range file.Entries {
		if !found && bytes.Equal(entry.ID, want) {
			found = true
			continue
		}
		kept = append(kept, entry)
	}

	if !found {
		return fail("no such secret: " + name)
	}

	file.Entries = kept

	return vault.save(file)
}

// --- keys ------------------------------------------------------------

// Keys is every key in the file, with what it may do. Master only.
func (vault *Vault) Keys() ([]*KeyInfo, error) {
	vault.mu.Lock()
	defer vault.mu.Unlock()

	file, _, err := vault.load()
	if nil != err {
		return nil, err
	}

	root, err := vault.rootof("listing the keys")
	if nil != err {
		return nil, err
	}

	metakey := mac(root, labelMeta)
	out := []*KeyInfo{}

	for _, record := range file.Keys {
		info := &KeyInfo{Key: record.ID, Grants: []string{}}

		plain, err := unseal(metakey, record.Meta, aadMeta+record.ID, "metadata")
		if nil == err {
			noted := &meta{}
			if err := jsonof(plain, noted, "metadata for key "+record.ID); nil != err {
				return nil, err
			}
			info.Master = noted.Master
			info.Write = noted.Write
			info.Grants = append([]string{}, noted.Grants...)
			sort.Strings(info.Grants)
		}
		// A record written under a root key this one has replaced. The
		// key is still in the file and still opens with its own
		// passphrase, so it is reported rather than hidden - with what it
		// can do unknown.

		out = append(out, info)
	}

	return out, nil
}

// Grant mints a restricted key. Master only.
func (vault *Vault) Grant(spec *GrantSpec) error {
	vault.mu.Lock()
	defer vault.mu.Unlock()

	file, _, err := vault.load()
	if nil != err {
		return err
	}

	root, err := vault.rootof("granting a key")
	if nil != err {
		return err
	}

	if nil == spec || "" == spec.Key {
		return fail("a grant needs a key id")
	}
	if "" == spec.Passphrase {
		return fail("a grant needs a passphrase")
	}
	if nil != file.key(spec.Key) {
		return fail("key already exists: " + spec.Key)
	}

	names := append([]string{}, spec.Names...)
	sort.Strings(names)

	grants := map[string]string{}
	for _, name := range names {
		if err := sekreto.CheckName(name); nil != err {
			return err
		}
		grants[name] = b64(secretkey(root, name))
	}

	iterations := spec.Iterations
	if 0 >= iterations {
		iterations = vault.iterations
	}

	record, err := sealkey(root, spec.Key, spec.Passphrase, iterations,
		&ring{V: format, Write: spec.Write, Grants: grants},
		&meta{V: format, Master: false, Write: spec.Write, Grants: names})
	if nil != err {
		return err
	}

	file.Keys = append(file.Keys, record)

	return vault.save(file)
}

// Revoke drops a key. Master only.
//
// Anyone who already copied the file keeps whatever that key could read,
// so revoking bars future reads of the LIVE file and Rotate is what
// takes a secret back.
func (vault *Vault) Revoke(key string) error {
	vault.mu.Lock()
	defer vault.mu.Unlock()

	file, info, err := vault.load()
	if nil != err {
		return err
	}

	if _, err := vault.rootof("revoking a key"); nil != err {
		return err
	}

	if key == info.Key {
		return fail("a key cannot revoke itself: " + key)
	}

	if nil == file.key(key) {
		return fail("no such key: " + key)
	}

	kept := []*keyRecord{}
	for _, record := range file.Keys {
		if key != record.ID {
			kept = append(kept, record)
		}
	}
	file.Keys = kept

	return vault.save(file)
}

// Rotate takes a new root key, re-encrypts every value under it, and
// DROPS EVERY OTHER KEY. Master only.
//
// The other keys go because they must: their rings are sealed under
// passphrases this process does not have, so there is no way to hand
// them keys they can unwrap. Re-grant afterwards.
func (vault *Vault) Rotate() error {
	vault.mu.Lock()
	defer vault.mu.Unlock()

	file, _, err := vault.load()
	if nil != err {
		return err
	}

	oldroot, err := vault.rootof("rotating the vault")
	if nil != err {
		return err
	}

	iters := file.key(vault.key).Iters

	// Read everything out under the old root before anything changes:
	// once the root is replaced the old derived keys are unreachable.
	oldnamekey := mac(oldroot, labelNames)
	held := [][2]string{}

	for _, entry := range file.Entries {
		plain, err := unseal(oldnamekey, entry.Name, aadName, "a secret name is damaged")
		if nil != err {
			return err
		}

		name := string(plain)
		key := secretkey(oldroot, name)

		value, err := unseal(key, entry.Value, aadSecret+name, "the value of "+name+" is damaged")
		if nil != err {
			return err
		}

		held = append(held, [2]string{name, string(value)})
	}

	root, err := random(keyLen)
	if nil != err {
		return err
	}

	namekey := mac(root, labelNames)
	entries := []*entryRecord{}

	for _, secret := range held {
		key := secretkey(root, secret[0])

		sealedname, err := seal(namekey, []byte(secret[0]), aadName)
		if nil != err {
			return err
		}

		box, err := seal(key, []byte(secret[1]), aadSecret+secret[0])
		if nil != err {
			return err
		}

		entries = append(entries, &entryRecord{ID: entryid(key), Name: sealedname, Value: box})
	}

	fresh, err := sealkey(root, vault.key, vault.passphrase, iters,
		&ring{V: format, Write: true, Root: b64(root)},
		&meta{V: format, Master: true, Write: true, Grants: []string{}})
	if nil != err {
		return err
	}

	// SAVE FIRST, adopt second. A handle holding the new root over a file
	// that still holds the old one reads nothing and says the vault is
	// damaged, which is the wrong story about a failed write.
	if err := vault.save(&vaultFile{Keys: []*keyRecord{fresh}, Entries: entries}); nil != err {
		return err
	}

	vault.root = root
	vault.grants = map[string][]byte{}
	vault.info = &KeyInfo{Key: vault.key, Master: true, Write: true, Grants: []string{}}

	return nil
}

// --- making one ------------------------------------------------------

func sealkey(
	root []byte, id string, passphrase string, iters int, held *ring, noted *meta,
) (*keyRecord, error) {
	salt, err := random(saltLen)
	if nil != err {
		return nil, err
	}

	sealedring, err := seal(kek(passphrase, salt, iters), tojson(held), aadRing+id)
	if nil != err {
		return nil, err
	}

	sealedmeta, err := seal(mac(root, labelMeta), tojson(noted), aadMeta+id)
	if nil != err {
		return nil, err
	}

	return &keyRecord{ID: id, Salt: salt, Iters: iters, Ring: sealedring, Meta: sealedmeta}, nil
}

// newvault is a new vault: one master key, no secrets.
func newvault(keyid string, passphrase string, iterations int) (*vaultFile, error) {
	root, err := random(keyLen)
	if nil != err {
		return nil, err
	}

	record, err := sealkey(root, keyid, passphrase, iterations,
		&ring{V: format, Write: true, Root: b64(root)},
		&meta{V: format, Master: true, Write: true, Grants: []string{}})
	if nil != err {
		return nil, err
	}

	return &vaultFile{Keys: []*keyRecord{record}, Entries: []*entryRecord{}}, nil
}

// putnew writes a vault file that is not there yet.
//
// O_EXCL on the temporary file and a rename onto the target: two
// processes racing to create one vault leave one vault, and the loser's
// secrets are not discarded because it never had any yet.
func putnew(file string, vault *vaultFile) error {
	temp := file + "." + strconv.Itoa(os.Getpid()) + ".tmp"

	handle, err := os.OpenFile(temp, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if nil != err {
		return fail("cannot write " + file + ": " + err.Error())
	}

	if _, err := handle.Write(writefile(vault)); nil != err {
		handle.Close()
		os.Remove(temp)
		return fail("cannot write " + file + ": " + err.Error())
	}

	if err := handle.Close(); nil != err {
		os.Remove(temp)
		return fail("cannot write " + file + ": " + err.Error())
	}

	if err := os.Rename(temp, file); nil != err {
		os.Remove(temp)
		return fail("cannot write " + file + ": " + err.Error())
	}

	return nil
}

// --- base64 and json -------------------------------------------------

func b64(raw []byte) string {
	return base64.StdEncoding.EncodeToString(raw)
}

func unb64(text string, what string) ([]byte, error) {
	raw, err := base64.StdEncoding.DecodeString(text)
	if nil != err {
		return nil, fail("missing " + what)
	}
	return raw, nil
}

// tojson is json.Marshal, and deliberately not WriteJSON: these bytes
// are sealed and then parsed again inside this process, so the HTML
// escaping WriteJSON turns off is unobservable here. WriteJSON is for
// what LEAVES the process.
func tojson(value any) []byte {
	raw, err := json.Marshal(value)
	if nil != err {
		return []byte("{}")
	}
	return raw
}

// --- the provider ----------------------------------------------------

// Provider reads a vault as one store in a chain.
//
// The provider is the READ half and nothing more: a chain resolves
// secrets, and writing one is a deliberate act with an API of its own.
// That API is the same handle, reached with VaultOf off a chain or built
// directly with Open.
type Provider struct {
	Vault *Vault
}

func (provider *Provider) Lookup(name string) (string, bool, error) {
	return provider.Vault.Get(name)
}

func (provider *Provider) Describe() string {
	return "minivault:" + provider.Vault.File()
}

// VaultExport is the export key the vault API is published under, beside
// the `provider` key every kind publishes.
const VaultExport = "vault"

// Plugin is the `minivault` provider kind, as a voxgig/plugin definition.
//
// Written out rather than built by sekreto.ProviderPlugin, because this
// definition publishes TWO exports: `provider`, the read half every kind
// publishes, and `vault`, the programmatic API. voxgig/plugin's exports
// are how a definition offers an application more than the host's own
// vocabulary, and a store that can only be read is half a vault.
//
// The SekretoError wrapping is what ProviderPlugin would have done:
// plugin wraps a code-less error returned from Define as
// `plugin_define_failed`, and keeps one that already carries a code, so a
// refusal of this provider's own configuration travels under
// `sekreto_error` and comes back out of the host as itself.
var Plugin = plugin.Definition{
	Name: "minivault",
	Define: func(inst *plugin.Inst) error {
		spec, err := sekreto.SpecOf(inst.Options())
		if nil != err {
			return err
		}

		// Configuration is refused HERE, so a mistyped chain fails at
		// construction. Reaching the file is not configuration: the
		// handle is lazy, and nothing is read or stretched until a
		// lookup.
		vault, err := Open(&Options{
			File:       spec.File,
			Key:        spec.VaultKey,
			Passphrase: spec.Passphrase,
			Iterations: spec.Iterations,
			Create:     spec.Create,
		})
		if nil != err {
			return wrap(inst, err)
		}

		inst.Export(sekreto.ProviderExport, &Provider{Vault: vault})
		inst.Export(VaultExport, vault)

		return nil
	},
}

func wrap(inst *plugin.Inst, err error) error {
	serr, is := err.(*sekreto.SekretoError)
	if !is {
		return err
	}
	return plugin.Fail(sekreto.ErrorCode, serr.Message,
		map[string]any{"ref": inst.Ref(), "cause": serr.Message})
}

// VaultOf is the vault behind a store in a chain, as its programmatic
// API.
//
// Host() is the voxgig/plugin host the chain is made of, and a
// definition's exports are readable off it by ref. This is the one call
// that turns a store into an API, and it lives here rather than on
// Sekreto because the core knows no plugin.
//
// With no store named, the unqualified alias answers: one vault in the
// chain resolves whatever it is called, and two raise rather than
// picking one.
func VaultOf(sek *sekreto.Sekreto, store string) (*Vault, error) {
	ref := "minivault"
	if "" != store && "minivault" != store {
		ref = "minivault$" + store
	}

	found, err := sek.Host().Exports(ref + "/" + VaultExport)
	if nil != err {
		return nil, err
	}

	vault, is := found.(*Vault)
	if !is {
		named := ""
		if "" != store {
			named = " named " + store
		}
		return nil, fail("no minivault store" + named + " in this chain")
	}

	return vault, nil
}
