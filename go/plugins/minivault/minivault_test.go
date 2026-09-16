// The mini vault, from both sides: the store a chain reads, and the
// programmatic API a plugin definition can publish beside it.
//
// The vault is not in spec/sekreto.json and cannot be until every port
// ships the kind. The spec runs against all twenty-three of them, so an
// entry naming `minivault` would fail twenty-one ports that have no such
// provider. What the shared corpus would have carried is here instead,
// plus the one thing it could not carry either way: a file written by
// the canonical port and read by this one,
// test/fixture/minivault.skmv.
//
// A port of typescript/test/minivault.test.ts.

package minivault_test

import (
	"bytes"
	"errors"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"

	plugin "github.com/voxgig/plugin/go/plugin"

	"github.com/voxgig/sekreto/go/plugins/minivault"
	"github.com/voxgig/sekreto/go/sekreto"
)

const master = "master-passphrase"

// The rounds every test here uses. The library default is 210000, which
// is the point of PBKDF2 and the wrong thing to pay per assertion.
const rounds = 1000

var made int

func vaultpath(t *testing.T) string {
	made++
	return filepath.Join(t.TempDir(), "vault"+strconv.Itoa(made)+".skmv")
}

func fresh(t *testing.T) *minivault.Vault {
	t.Helper()

	vault, err := minivault.Create(&minivault.Options{
		File: vaultpath(t), Passphrase: master, Iterations: rounds})
	if nil != err {
		t.Fatal(err)
	}

	return vault
}

// fixture copies the committed vault, so that a test which writes cannot
// edit the bytes the format contract is made of.
func fixture(t *testing.T) string {
	t.Helper()

	dir := "."
	for step := 0; step < 8; step++ {
		cand := filepath.Join(dir, "test", "fixture", "minivault.skmv")
		if raw, err := os.ReadFile(cand); nil == err {
			mine := vaultpath(t)
			if err := os.WriteFile(mine, raw, 0o600); nil != err {
				t.Fatal(err)
			}
			return mine
		}
		dir = filepath.Join(dir, "..")
	}

	t.Fatal("sekreto: fixture vault not found")
	return ""
}

func set(t *testing.T, vault *minivault.Vault, name string, value string) {
	t.Helper()
	if err := vault.Set(name, value); nil != err {
		t.Fatal(err)
	}
}

func get(t *testing.T, vault *minivault.Vault, name string) (string, bool) {
	t.Helper()
	value, has, err := vault.Get(name)
	if nil != err {
		t.Fatal(err)
	}
	return value, has
}

func list(t *testing.T, vault *minivault.Vault) []string {
	t.Helper()
	names, err := vault.List()
	if nil != err {
		t.Fatal(err)
	}
	return names
}

func same(t *testing.T, got []string, want ...string) {
	t.Helper()
	if strings.Join(got, ",") != strings.Join(want, ",") {
		t.Fatalf("got %v, want %v", got, want)
	}
}

func refuses(t *testing.T, err error, message string) {
	t.Helper()
	if nil == err {
		t.Fatalf("expected a refusal: %s", message)
	}
	if message != err.Error() {
		t.Fatalf("got %q, want %q", err.Error(), message)
	}
}

// --- one file, one key -------------------------------------------------

func TestANewVaultHoldsNothing(t *testing.T) {
	vault := fresh(t)

	info, err := vault.Info()
	if nil != err {
		t.Fatal(err)
	}
	if minivault.MasterKey != info.Key || !info.Master || !info.Write || 0 != len(info.Grants) {
		t.Fatalf("info: %+v", info)
	}

	same(t, list(t, vault))

	if _, has := get(t, vault, "api.token"); has {
		t.Fatal("a new vault answered")
	}
}

func TestAWrittenSecretComesBack(t *testing.T) {
	vault := fresh(t)

	set(t, vault, "api.token", "tok01")
	set(t, vault, "db.pass", "hunter2")

	same(t, list(t, vault), "api.token", "db.pass")

	if value, has := get(t, vault, "api.token"); "tok01" != value || !has {
		t.Fatalf("api.token: %q %v", value, has)
	}

	// A SECOND HANDLE, not the same object: what is being checked is the
	// file, and a handle that answered from memory would pass either way.
	reopened, err := minivault.Open(&minivault.Options{File: vault.File(), Passphrase: master})
	if nil != err {
		t.Fatal(err)
	}
	if value, has := get(t, reopened, "db.pass"); "hunter2" != value || !has {
		t.Fatalf("db.pass: %q %v", value, has)
	}
}

func TestTheFileNamesNothingInPlaintext(t *testing.T) {
	vault := fresh(t)
	set(t, vault, "api.token", "tok01")

	raw, err := os.ReadFile(vault.File())
	if nil != err {
		t.Fatal(err)
	}

	if "SKMV" != string(raw[0:4]) || 1 != raw[4] {
		t.Fatalf("header: % x", raw[0:5])
	}

	// The key ids are plaintext and documented as such; a secret name is
	// not, and neither is a value.
	if !bytes.Contains(raw, []byte(minivault.MasterKey)) {
		t.Fatal("the key id is not plaintext")
	}
	if bytes.Contains(raw, []byte("api.token")) {
		t.Fatal("a secret name is in the clear")
	}
	if bytes.Contains(raw, []byte("tok01")) {
		t.Fatal("a secret value is in the clear")
	}
}

func TestRewritingANameReplacesIt(t *testing.T) {
	vault := fresh(t)

	set(t, vault, "api.token", "first")
	set(t, vault, "api.token", "second")

	same(t, list(t, vault), "api.token")
	if value, _ := get(t, vault, "api.token"); "second" != value {
		t.Fatalf("api.token: %q", value)
	}
}

func TestRemoveDropsAName(t *testing.T) {
	vault := fresh(t)

	set(t, vault, "api.token", "tok01")
	if err := vault.Remove("api.token"); nil != err {
		t.Fatal(err)
	}

	same(t, list(t, vault))
	refuses(t, vault.Remove("api.token"), "sekreto: minivault: no such secret: api.token")
}

func TestABadNameIsRefused(t *testing.T) {
	vault := fresh(t)

	refuses(t, vault.Set("Api.Token", "x"), "sekreto: invalid name: Api.Token")

	_, _, err := vault.Get("api token")
	refuses(t, err, "sekreto: invalid name: api token")
}

// --- restricted keys ---------------------------------------------------

func TestARestrictedKeyMissesOnTheRest(t *testing.T) {
	vault := fresh(t)

	set(t, vault, "api.token", "tok01")
	set(t, vault, "db.pass", "hunter2")

	if err := vault.Grant(&minivault.GrantSpec{
		Key: "ci", Passphrase: "ci-pass", Names: []string{"api.token"}, Iterations: rounds,
	}); nil != err {
		t.Fatal(err)
	}

	ci, err := minivault.Open(&minivault.Options{
		File: vault.File(), Key: "ci", Passphrase: "ci-pass"})
	if nil != err {
		t.Fatal(err)
	}

	info, err := ci.Info()
	if nil != err {
		t.Fatal(err)
	}
	if info.Master || info.Write {
		t.Fatalf("info: %+v", info)
	}
	same(t, info.Grants, "api.token")

	if value, has := get(t, ci, "api.token"); "tok01" != value || !has {
		t.Fatalf("api.token: %q %v", value, has)
	}

	// Not an error: the vault answers as the key that opened it, so a
	// name outside the grant is a name this store does not hold.
	if _, has := get(t, ci, "db.pass"); has {
		t.Fatal("a restricted key read outside its grant")
	}

	// And it is never told the name exists.
	same(t, list(t, ci), "api.token")
}

func TestAReadOnlyKeyRefusesToWrite(t *testing.T) {
	vault := fresh(t)

	set(t, vault, "db.pass", "hunter2")

	if err := vault.Grant(&minivault.GrantSpec{
		Key: "ro", Passphrase: "ro-pass", Names: []string{"db.pass"}, Iterations: rounds,
	}); nil != err {
		t.Fatal(err)
	}
	if err := vault.Grant(&minivault.GrantSpec{
		Key: "rw", Passphrase: "rw-pass", Names: []string{"db.pass"}, Write: true,
		Iterations: rounds,
	}); nil != err {
		t.Fatal(err)
	}

	readonly, _ := minivault.Open(&minivault.Options{
		File: vault.File(), Key: "ro", Passphrase: "ro-pass"})
	refuses(t, readonly.Set("db.pass", "x"), "sekreto: minivault: key ro is read-only")

	writable, _ := minivault.Open(&minivault.Options{
		File: vault.File(), Key: "rw", Passphrase: "rw-pass"})
	if err := writable.Set("db.pass", "rotated"); nil != err {
		t.Fatal(err)
	}

	if value, _ := get(t, vault, "db.pass"); "rotated" != value {
		t.Fatalf("db.pass: %q", value)
	}
}

func TestARestrictedKeyCannotWriteWhatItWasNotGranted(t *testing.T) {
	vault := fresh(t)

	if err := vault.Grant(&minivault.GrantSpec{
		Key: "rw", Passphrase: "rw-pass", Names: []string{"db.pass"}, Write: true,
		Iterations: rounds,
	}); nil != err {
		t.Fatal(err)
	}

	writable, _ := minivault.Open(&minivault.Options{
		File: vault.File(), Key: "rw", Passphrase: "rw-pass"})

	refuses(t, writable.Set("api.token", "x"),
		"sekreto: minivault: key rw was not granted api.token")
}

// A GRANT CAN PRECEDE THE SECRET, because the key for a name is derived
// from the name rather than stored against an entry. This is also the one
// path on which a restricted key reaches Set for a name that has no entry
// yet - and is refused, because writing a NEW name needs the master's
// name key.
func TestAGrantedNameThatDoesNotExistYet(t *testing.T) {
	vault := fresh(t)

	if err := vault.Grant(&minivault.GrantSpec{
		Key: "rw", Passphrase: "rw-pass", Names: []string{"later.value"}, Write: true,
		Iterations: rounds,
	}); nil != err {
		t.Fatal(err)
	}

	writable, _ := minivault.Open(&minivault.Options{
		File: vault.File(), Key: "rw", Passphrase: "rw-pass"})

	same(t, list(t, writable))
	if _, has := get(t, writable, "later.value"); has {
		t.Fatal("a grant invented a secret")
	}
	refuses(t, writable.Set("later.value", "mine"),
		"sekreto: minivault: creating the secret later.value needs a master key, and rw is restricted")

	set(t, vault, "later.value", "from the master")

	same(t, list(t, writable), "later.value")
	if value, _ := get(t, writable, "later.value"); "from the master" != value {
		t.Fatalf("later.value: %q", value)
	}

	if err := writable.Set("later.value", "now mine"); nil != err {
		t.Fatal(err)
	}
	if value, _ := get(t, vault, "later.value"); "now mine" != value {
		t.Fatalf("later.value: %q", value)
	}
}

func TestTheMasterListsEveryKey(t *testing.T) {
	vault := fresh(t)

	if err := vault.Grant(&minivault.GrantSpec{
		Key: "ci", Passphrase: "ci-pass", Names: []string{"api.token"}, Iterations: rounds,
	}); nil != err {
		t.Fatal(err)
	}
	if err := vault.Grant(&minivault.GrantSpec{
		Key: "ops", Passphrase: "ops-pass", Names: []string{"db.pass", "api.token"},
		Write: true, Iterations: rounds,
	}); nil != err {
		t.Fatal(err)
	}

	keys, err := vault.Keys()
	if nil != err {
		t.Fatal(err)
	}
	if 3 != len(keys) {
		t.Fatalf("keys: %d", len(keys))
	}

	if minivault.MasterKey != keys[0].Key || !keys[0].Master || !keys[0].Write {
		t.Fatalf("master: %+v", keys[0])
	}
	if "ci" != keys[1].Key || keys[1].Master || keys[1].Write {
		t.Fatalf("ci: %+v", keys[1])
	}
	same(t, keys[1].Grants, "api.token")
	if "ops" != keys[2].Key || keys[2].Master || !keys[2].Write {
		t.Fatalf("ops: %+v", keys[2])
	}
	same(t, keys[2].Grants, "api.token", "db.pass")
}

func TestTheMasterOnlyMethodsRefuseARestrictedKey(t *testing.T) {
	vault := fresh(t)

	set(t, vault, "api.token", "tok01")
	if err := vault.Grant(&minivault.GrantSpec{
		Key: "ci", Passphrase: "ci-pass", Names: []string{"api.token"}, Iterations: rounds,
	}); nil != err {
		t.Fatal(err)
	}

	ci, _ := minivault.Open(&minivault.Options{
		File: vault.File(), Key: "ci", Passphrase: "ci-pass"})

	restricted := " needs a master key, and ci is restricted"

	_, err := ci.Keys()
	refuses(t, err, "sekreto: minivault: listing the keys"+restricted)
	refuses(t, ci.Remove("api.token"), "sekreto: minivault: removing a secret"+restricted)
	refuses(t, ci.Grant(&minivault.GrantSpec{Key: "x", Passphrase: "p"}),
		"sekreto: minivault: granting a key"+restricted)
	refuses(t, ci.Revoke(minivault.MasterKey), "sekreto: minivault: revoking a key"+restricted)
	refuses(t, ci.Rotate(), "sekreto: minivault: rotating the vault"+restricted)
}

func TestARepeatedKeyIdIsRefused(t *testing.T) {
	vault := fresh(t)

	if err := vault.Grant(&minivault.GrantSpec{
		Key: "ci", Passphrase: "ci-pass", Iterations: rounds}); nil != err {
		t.Fatal(err)
	}

	refuses(t, vault.Grant(&minivault.GrantSpec{
		Key: "ci", Passphrase: "other", Iterations: rounds}),
		"sekreto: minivault: key already exists: ci")
}

func TestRevokeDropsAKey(t *testing.T) {
	vault := fresh(t)

	set(t, vault, "api.token", "tok01")
	if err := vault.Grant(&minivault.GrantSpec{
		Key: "ci", Passphrase: "ci-pass", Names: []string{"api.token"}, Iterations: rounds,
	}); nil != err {
		t.Fatal(err)
	}
	if err := vault.Revoke("ci"); nil != err {
		t.Fatal(err)
	}

	keys, _ := vault.Keys()
	if 1 != len(keys) {
		t.Fatalf("keys: %d", len(keys))
	}

	gone, _ := minivault.Open(&minivault.Options{
		File: vault.File(), Key: "ci", Passphrase: "ci-pass"})
	_, err := gone.List()
	refuses(t, err, "sekreto: minivault: no such key: ci")

	refuses(t, vault.Revoke(minivault.MasterKey),
		"sekreto: minivault: a key cannot revoke itself: master")
	refuses(t, vault.Revoke("nobody"), "sekreto: minivault: no such key: nobody")
}

// Revoking bars the LIVE file; anyone who copied it keeps what they had.
// Rotating is what takes a secret back, and the cost is stated rather
// than hidden: every other key goes with it.
func TestRotateKeepsTheSecretsAndDropsEveryOtherKey(t *testing.T) {
	vault := fresh(t)

	set(t, vault, "api.token", "tok01")
	set(t, vault, "db.pass", "hunter2")
	if err := vault.Grant(&minivault.GrantSpec{
		Key: "ci", Passphrase: "ci-pass", Names: []string{"api.token"}, Iterations: rounds,
	}); nil != err {
		t.Fatal(err)
	}

	before, err := os.ReadFile(vault.File())
	if nil != err {
		t.Fatal(err)
	}

	if err := vault.Rotate(); nil != err {
		t.Fatal(err)
	}

	same(t, list(t, vault), "api.token", "db.pass")
	if value, _ := get(t, vault, "api.token"); "tok01" != value {
		t.Fatalf("api.token: %q", value)
	}

	keys, _ := vault.Keys()
	if 1 != len(keys) || minivault.MasterKey != keys[0].Key {
		t.Fatalf("keys: %+v", keys)
	}

	gone, _ := minivault.Open(&minivault.Options{
		File: vault.File(), Key: "ci", Passphrase: "ci-pass"})
	_, err = gone.List()
	refuses(t, err, "sekreto: minivault: no such key: ci")

	// The ciphertext changed, which is the part that makes a copy of the
	// old file useless for anything written after this point.
	after, _ := os.ReadFile(vault.File())
	if bytes.Equal(before, after) {
		t.Fatal("rotate left the bytes alone")
	}

	// The master passphrase is unchanged: rotating is not a password
	// change, and saying so is cheaper than a support question.
	reopened, _ := minivault.Open(&minivault.Options{File: vault.File(), Passphrase: master})
	if value, _ := get(t, reopened, "db.pass"); "hunter2" != value {
		t.Fatalf("db.pass: %q", value)
	}
}

// --- refusals ----------------------------------------------------------

func TestAWrongPassphraseAnUnknownKeyAndAMissingFile(t *testing.T) {
	vault := fresh(t)
	set(t, vault, "api.token", "tok01")

	wrong, _ := minivault.Open(&minivault.Options{File: vault.File(), Passphrase: "not it"})
	_, _, err := wrong.Get("api.token")
	refuses(t, err, "sekreto: minivault: wrong passphrase for key master, or a damaged vault")

	ghost, _ := minivault.Open(&minivault.Options{
		File: vault.File(), Key: "ghost", Passphrase: master})
	_, _, err = ghost.Get("api.token")
	refuses(t, err, "sekreto: minivault: no such key: ghost")

	missing := vaultpath(t)
	absent, _ := minivault.Open(&minivault.Options{File: missing, Passphrase: master})
	_, _, err = absent.Get("api.token")
	refuses(t, err, "sekreto: minivault: no vault file: "+missing)
}

func TestADamagedFileIsRefused(t *testing.T) {
	vault := fresh(t)
	set(t, vault, "api.token", "tok01")

	raw, err := os.ReadFile(vault.File())
	if nil != err {
		t.Fatal(err)
	}

	broken := func(name string, content []byte) error {
		file := filepath.Join(filepath.Dir(vault.File()), name)
		if err := os.WriteFile(file, content, 0o600); nil != err {
			t.Fatal(err)
		}
		handle, _ := minivault.Open(&minivault.Options{File: file, Passphrase: master})
		_, _, err := handle.Get("api.token")
		if nil == err {
			t.Fatalf("%s was read", name)
		}
		return err
	}

	if err := broken("cut.skmv", raw[:len(raw)-20]); !strings.Contains(err.Error(), "truncated") {
		t.Fatalf("cut: %v", err)
	}

	refuses(t, broken("extra.skmv", append(append([]byte{}, raw...), 0)),
		"sekreto: minivault: the vault file has trailing bytes")

	refuses(t, broken("wrong.skmv", []byte("not a vault at all, but long enough")),
		"sekreto: minivault: not a vault file")

	// A FLIPPED BIT IN THE CIPHERTEXT, which is what a GCM tag is for: a
	// vault that decrypts to something plausible would be worse than one
	// that refuses.
	bent := append([]byte{}, raw...)
	bent[len(bent)-1] ^= 0xff
	if err := broken("damaged.skmv", bent); !strings.Contains(err.Error(), "damaged") {
		t.Fatalf("damaged: %v", err)
	}
}

func TestCreatingOverAnExistingVaultIsRefused(t *testing.T) {
	vault := fresh(t)

	_, err := minivault.Create(&minivault.Options{
		File: vault.File(), Passphrase: "other", Iterations: rounds})
	refuses(t, err, "sekreto: minivault: vault file already exists: "+vault.File())
}

func TestAVaultNeedsAFileAndAPassphrase(t *testing.T) {
	_, err := minivault.Open(&minivault.Options{Passphrase: master})
	refuses(t, err, "sekreto: minivault: a vault needs a file")

	_, err = minivault.Open(&minivault.Options{File: vaultpath(t)})
	refuses(t, err, "sekreto: minivault: a vault needs a passphrase")
}

func TestCreateMakesTheFileWhenAsked(t *testing.T) {
	file := vaultpath(t)

	made, err := minivault.Open(&minivault.Options{
		File: file, Passphrase: master, Iterations: rounds, Create: true})
	if nil != err {
		t.Fatal(err)
	}
	set(t, made, "api.token", "tok01")

	reopened, _ := minivault.Open(&minivault.Options{File: file, Passphrase: master})
	if value, _ := get(t, reopened, "api.token"); "tok01" != value {
		t.Fatalf("api.token: %q", value)
	}
}

// --- the format, across ports ------------------------------------------

func TestTheCommittedFixtureReads(t *testing.T) {
	file := fixture(t)

	vault, err := minivault.Open(&minivault.Options{File: file, Passphrase: "fixture-master"})
	if nil != err {
		t.Fatal(err)
	}

	same(t, list(t, vault), "api.token", "db.pass", "deep.nested.name")

	for name, want := range map[string]string{
		"api.token":        "fixture-token",
		"db.pass":          "fixture-pass",
		"deep.nested.name": "fixture-deep",
	} {
		if value, has := get(t, vault, name); want != value || !has {
			t.Fatalf("%s: %q %v", name, value, has)
		}
	}

	keys, err := vault.Keys()
	if nil != err {
		t.Fatal(err)
	}
	if 3 != len(keys) {
		t.Fatalf("keys: %d", len(keys))
	}
	if !keys[0].Master || "reader" != keys[1].Key || keys[1].Write || !keys[2].Write {
		t.Fatalf("keys: %+v %+v %+v", keys[0], keys[1], keys[2])
	}
	same(t, keys[1].Grants, "api.token")
	same(t, keys[2].Grants, "db.pass")

	reader, _ := minivault.Open(&minivault.Options{
		File: file, Key: "reader", Passphrase: "fixture-reader"})
	same(t, list(t, reader), "api.token")
	if value, _ := get(t, reader, "api.token"); "fixture-token" != value {
		t.Fatalf("api.token: %q", value)
	}
	if _, has := get(t, reader, "db.pass"); has {
		t.Fatal("reader read outside its grant")
	}

	writer, _ := minivault.Open(&minivault.Options{
		File: file, Key: "writer", Passphrase: "fixture-writer"})
	if err := writer.Set("db.pass", "written by this port"); nil != err {
		t.Fatal(err)
	}
	if value, _ := get(t, vault, "db.pass"); "written by this port" != value {
		t.Fatalf("db.pass: %q", value)
	}
}

// --- the chain ---------------------------------------------------------

func TestAVaultIsOneStoreInAChain(t *testing.T) {
	vault := fresh(t)
	set(t, vault, "api.token", "from the vault")

	sek, err := sekreto.New(&sekreto.Options{
		Plugins: []plugin.Definition{minivault.Plugin},
		Providers: []*sekreto.ProviderSpec{
			{Kind: "memory", Values: map[string]string{"DB_PASS": "from memory"}},
			{Kind: "minivault", File: vault.File(), Passphrase: master},
		},
	})
	if nil != err {
		t.Fatal(err)
	}

	if value, err := sek.Get("api.token"); "from the vault" != value || nil != err {
		t.Fatalf("api.token: %q %v", value, err)
	}
	if value, err := sek.Get("db.pass"); "from memory" != value || nil != err {
		t.Fatalf("db.pass: %q %v", value, err)
	}
	if value, err := sek.GetFrom("minivault", "api.token"); "from the vault" != value || nil != err {
		t.Fatalf("getfrom: %q %v", value, err)
	}

	same(t, sek.Sources(), "memory", "minivault:"+vault.File())
	same(t, sek.Stores(), "memory", "minivault")
}

func TestARestrictedKeyInAChainFallsThrough(t *testing.T) {
	vault := fresh(t)
	set(t, vault, "api.token", "from the vault")
	set(t, vault, "db.pass", "vault password")

	if err := vault.Grant(&minivault.GrantSpec{
		Key: "ci", Passphrase: "ci-pass", Names: []string{"api.token"}, Iterations: rounds,
	}); nil != err {
		t.Fatal(err)
	}

	sek, err := sekreto.New(&sekreto.Options{
		Plugins: []plugin.Definition{minivault.Plugin},
		Providers: []*sekreto.ProviderSpec{
			{Kind: "minivault", File: vault.File(), VaultKey: "ci", Passphrase: "ci-pass"},
			{Kind: "memory", Values: map[string]string{"DB_PASS": "the fallback"}},
		},
	})
	if nil != err {
		t.Fatal(err)
	}

	if value, _ := sek.Get("api.token"); "from the vault" != value {
		t.Fatalf("api.token: %q", value)
	}
	if value, _ := sek.Get("db.pass"); "the fallback" != value {
		t.Fatalf("db.pass: %q", value)
	}
	if value, has, err := sek.TryFrom("minivault", "db.pass"); has || nil != err {
		t.Fatalf("tryfrom: %q %v %v", value, has, err)
	}
}

// --- the programmatic API ----------------------------------------------

// THE POINT OF THE EXPORT. A chain reads; a vault is also written to, and
// voxgig/plugin's exports are how a definition publishes an API of its
// own beside the provider the host asked it for.
func TestTheVaultBehindAStoreIsReachableAsAnAPI(t *testing.T) {
	vault := fresh(t)
	set(t, vault, "api.token", "first")

	sek, err := sekreto.New(&sekreto.Options{
		Plugins: []plugin.Definition{minivault.Plugin},
		Providers: []*sekreto.ProviderSpec{
			{Kind: "minivault", File: vault.File(), Passphrase: master},
		},
	})
	if nil != err {
		t.Fatal(err)
	}

	api, err := minivault.VaultOf(sek, "")
	if nil != err {
		t.Fatal(err)
	}

	if vault.File() != api.File() {
		t.Fatalf("file: %q", api.File())
	}
	same(t, list(t, api), "api.token")

	if err := api.Set("added.here", "through the host"); nil != err {
		t.Fatal(err)
	}
	if err := api.Grant(&minivault.GrantSpec{
		Key: "ci", Passphrase: "ci-pass", Names: []string{"added.here"}, Iterations: rounds,
	}); nil != err {
		t.Fatal(err)
	}

	// The file is what changed, so a chain built afterwards sees it.
	after, err := sekreto.New(&sekreto.Options{
		Plugins: []plugin.Definition{minivault.Plugin},
		Providers: []*sekreto.ProviderSpec{
			{Kind: "minivault", File: vault.File(), VaultKey: "ci", Passphrase: "ci-pass"},
		},
	})
	if nil != err {
		t.Fatal(err)
	}
	if value, err := after.Get("added.here"); "through the host" != value || nil != err {
		t.Fatalf("added.here: %q %v", value, err)
	}
}

func TestTwoVaultsAreTwoStores(t *testing.T) {
	one := fresh(t)
	set(t, one, "api.token", "first")
	two := fresh(t)
	set(t, two, "api.token", "second")

	sek, err := sekreto.New(&sekreto.Options{
		Plugins: []plugin.Definition{minivault.Plugin},
		Providers: []*sekreto.ProviderSpec{
			{Kind: "minivault", Name: "app", File: one.File(), Passphrase: master},
			{Kind: "minivault", Name: "ops", File: two.File(), Passphrase: master},
		},
	})
	if nil != err {
		t.Fatal(err)
	}

	same(t, sek.Stores(), "app", "ops")

	if value, _ := sek.GetFrom("app", "api.token"); "first" != value {
		t.Fatalf("app: %q", value)
	}
	if value, _ := sek.GetFrom("ops", "api.token"); "second" != value {
		t.Fatalf("ops: %q", value)
	}

	// One vault in the chain, whatever it is called: the unqualified
	// alias resolves it. Two make it ambiguous rather than lucky.
	if _, err := minivault.VaultOf(sek, ""); nil == err {
		t.Fatal("the alias picked one of two")
	}
	named, err := minivault.VaultOf(sek, "ops")
	if nil != err {
		t.Fatal(err)
	}
	if two.File() != named.File() {
		t.Fatalf("file: %q", named.File())
	}
}

func TestAChainWithNoVaultSaysSo(t *testing.T) {
	sek, err := sekreto.New(&sekreto.Options{
		Providers: []*sekreto.ProviderSpec{{Kind: "memory", Values: map[string]string{}}},
	})
	if nil != err {
		t.Fatal(err)
	}

	_, err = minivault.VaultOf(sek, "")
	refuses(t, err, "sekreto: minivault: no minivault store in this chain")
}

// --- configuration -----------------------------------------------------

// A provider that refuses its own configuration returns a SekretoError
// from inside Define, and it must come back out of the host as itself
// rather than wrapped as plugin_define_failed. The definition is written
// out by hand rather than built by sekreto.ProviderPlugin, because it
// publishes two exports, so this is the half of ProviderPlugin it has to
// reproduce.
func TestAChainMissingTheFileOrThePassphraseIsRefused(t *testing.T) {
	_, err := sekreto.New(&sekreto.Options{
		Plugins:   []plugin.Definition{minivault.Plugin},
		Providers: []*sekreto.ProviderSpec{{Kind: "minivault"}},
	})
	refuses(t, err, "sekreto: minivault: a vault needs a file")

	var serr *sekreto.SekretoError
	if !errors.As(err, &serr) {
		t.Fatalf("not a SekretoError: %T", err)
	}

	_, err = sekreto.New(&sekreto.Options{
		Plugins:   []plugin.Definition{minivault.Plugin},
		Providers: []*sekreto.ProviderSpec{{Kind: "minivault", File: vaultpath(t)}},
	})
	refuses(t, err, "sekreto: minivault: a vault needs a passphrase")
}

// Nothing is opened at construction, which is what makes a chain with a
// vault in it cost no key derivation until a secret is wanted - and also
// means a missing file surfaces at the first lookup.
func TestTheFileIsReachedAtTheFirstLookup(t *testing.T) {
	file := vaultpath(t)

	sek, err := sekreto.New(&sekreto.Options{
		Plugins: []plugin.Definition{minivault.Plugin},
		Providers: []*sekreto.ProviderSpec{
			{Kind: "minivault", File: file, Passphrase: master},
		},
	})
	if nil != err {
		t.Fatal(err)
	}

	if status := sek.Host().List()["minivault"]; "live" != string(status) {
		t.Fatalf("status: %v", status)
	}

	_, err = sek.Get("api.token")
	refuses(t, err, "sekreto: minivault: no vault file: "+file)
}

func TestCloseForgetsTheDerivedKeys(t *testing.T) {
	vault := fresh(t)
	set(t, vault, "api.token", "tok01")

	vault.Close()

	if value, _ := get(t, vault, "api.token"); "tok01" != value {
		t.Fatalf("api.token: %q", value)
	}
}
