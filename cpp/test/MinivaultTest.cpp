// RUN: make vaulttest
// RUN-SOME: ./build/sekreto-minivaulttest restricted
//
// The mini vault, from both sides: the store a chain reads, and the
// programmatic API a plugin definition can publish beside it.
//
// The vault is not in spec/sekreto.json and cannot be until every port
// ships the kind. The spec runs against all twenty-three of them, so an
// entry naming `minivault` would fail the ports that have no such
// provider. What the shared corpus would have carried is here instead,
// plus the one thing it could not carry either way: a file written by
// this port and read by another, pinned by the vaults in test/fixture.
//
// Its own binary, like PluginTest.cpp and for the same reason: it needs
// no omni, so a checkout with none beside it can still run this.
//
// A port of typescript/test/minivault.test.ts.

#include <dirent.h>
#include <sys/stat.h>
#include <unistd.h>

#include <algorithm>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <fstream>
#include <functional>
#include <iostream>
#include <string>
#include <vector>

#include "Minivault.hpp"
#include "Provider.hpp"
#include "Sekreto.hpp"

namespace {

using sekreto::createvault;
using sekreto::GrantSpec;
using sekreto::MiniVault;
using sekreto::minivault;
using sekreto::openvault;
using sekreto::ProviderSpec;
using sekreto::Sekreto;
using sekreto::SekretoError;
using sekreto::SekretoOptions;
using sekreto::VaultKeyInfo;
using sekreto::vaultof;
using sekreto::VaultOptions;

const char MASTER[] = "master-passphrase";

// The rounds every case here uses. The library default is 210000, which
// is the point of PBKDF2 and the wrong thing to pay per assertion.
const int ROUNDS = 1000;

// ---------------------------------------------------------- the harness

std::string ONLY;
std::string WORK;
int PASSCOUNT = 0;
int FAILCOUNT = 0;
int COUNT = 0;

struct Failed : public std::runtime_error {
  explicit Failed(const std::string& why) : std::runtime_error(why) {}
};

void fail(const std::string& why) { throw Failed(why); }

std::string show(const std::vector<std::string>& list) {
  std::string out = "[";
  for (size_t index = 0; index < list.size(); index++) {
    if (0 < index) out += ", ";
    out += list[index];
  }
  return out + "]";
}

void same(const std::string& got, const std::string& want, const std::string& what) {
  if (got != want) fail(what + ": got \"" + got + "\", want \"" + want + "\"");
}

void same(const std::vector<std::string>& got, const std::vector<std::string>& want,
          const std::string& what) {
  if (got != want) fail(what + ": got " + show(got) + ", want " + show(want));
}

void same(size_t got, size_t want, const std::string& what) {
  if (got != want) {
    fail(what + ": got " + std::to_string(got) + ", want " + std::to_string(want));
  }
}

void truth(bool got, const std::string& what) {
  if (!got) fail(what);
}

void holds(const std::string& got, const std::string& want, const std::string& what) {
  if (std::string::npos == got.find(want)) {
    fail(what + ": want to contain \"" + want + "\", got \"" + got + "\"");
  }
}

/// The SekretoError this threw, or a failure naming what it threw instead.
std::string refusal(const std::string& what, const std::function<void()>& body) {
  try {
    body();
  } catch (const SekretoError& err) {
    return err.what();
  } catch (const std::exception& err) {
    fail(what + ": not a SekretoError: " + err.what());
  }

  fail(what + ": nothing was refused");
  return "";
}

void testcase(const std::string& name, const std::function<void()>& body) {
  if (!ONLY.empty() && name != ONLY) return;

  try {
    body();
    PASSCOUNT++;
    std::cout << "ok   - " << name << "\n";
  } catch (const std::exception& err) {
    FAILCOUNT++;
    std::cout << "FAIL - " << name << "\n       " << err.what() << "\n";
  }
}

// ------------------------------------------------- the vault under test

std::string vaultpath() {
  COUNT++;
  return WORK + "/vault" + std::to_string(COUNT) + ".skmv";
}

VaultOptions vaultopts(const std::string& file, const std::string& key,
                       const std::string& passphrase) {
  VaultOptions out;
  out.file = file;
  out.key = key;
  out.passphrase = passphrase;
  out.iterations = ROUNDS;
  return out;
}

std::shared_ptr<MiniVault> fresh() {
  return createvault(vaultopts(vaultpath(), "", MASTER));
}

std::shared_ptr<MiniVault> openas(const std::string& file, const std::string& key,
                                  const std::string& passphrase) {
  return openvault(vaultopts(file, key, passphrase));
}

GrantSpec grantof(const std::string& key, const std::string& passphrase,
                  const std::vector<std::string>& names, bool write) {
  GrantSpec out;
  out.key = key;
  out.passphrase = passphrase;
  out.names = names;
  out.write = write;
  out.iterations = ROUNDS;
  return out;
}

/// Where the committed vaults live, found by walking up.
std::string fixturedir() {
  std::string dir = ".";

  for (int step = 0; step < 8; step++) {
    struct stat st;
    if (0 == stat((dir + "/test/fixture/minivault.skmv").c_str(), &st)) {
      return dir + "/test/fixture";
    }
    dir += "/..";
  }

  fail("the fixture directory was not found");
  return "";
}

/// EVERY committed vault, read off disk rather than listed here. A
/// hard-coded list is one more place to edit when a port lands, and the
/// edit that gets forgotten is the one that makes this suite stop
/// checking the port that just arrived.
std::vector<std::string> fixtures() {
  std::vector<std::string> out;
  const std::string where = fixturedir();

  DIR* dir = opendir(where.c_str());
  if (nullptr == dir) fail("the fixture directory is not readable");

  while (dirent* entry = readdir(dir)) {
    const std::string name = entry->d_name;
    if (5 < name.size() && ".skmv" == name.substr(name.size() - 5)) out.push_back(name);
  }

  closedir(dir);
  std::sort(out.begin(), out.end());

  return out;
}

std::vector<uint8_t> slurp(const std::string& path) {
  std::ifstream in(path, std::ios::binary);
  if (!in) fail("cannot read " + path);
  return std::vector<uint8_t>(std::istreambuf_iterator<char>(in),
                              std::istreambuf_iterator<char>());
}

void spill(const std::string& path, const std::vector<uint8_t>& raw) {
  std::ofstream out(path, std::ios::binary);
  if (!out) fail("cannot write " + path);
  out.write(reinterpret_cast<const char*>(raw.data()), static_cast<long>(raw.size()));
}

/// A committed vault, copied so that a case which writes cannot edit the
/// bytes the format contract is made of.
std::string fixture(const std::string& name) {
  const std::string mine = vaultpath();
  spill(mine, slurp(fixturedir() + "/" + name));
  return mine;
}

/// Does this whole file - NULs and all - hold that text?
bool inside(const std::vector<uint8_t>& raw, const std::string& want) {
  if (raw.size() < want.size()) return false;

  for (size_t at = 0; at + want.size() <= raw.size(); at++) {
    if (0 == std::memcmp(raw.data() + at, want.data(), want.size())) return true;
  }

  return false;
}

ProviderSpec vaultspec(const std::string& file, const std::string& key,
                       const std::string& passphrase) {
  ProviderSpec spec;
  spec.kind = "minivault";
  spec.file = file;
  spec.vaultkey = key;
  spec.passphrase = passphrase;
  return spec;
}

ProviderSpec memoryspec(const std::string& key, const std::string& value) {
  ProviderSpec spec;
  spec.kind = "memory";
  spec.values.set(key, value);
  return spec;
}

Sekreto thechain(const std::vector<ProviderSpec>& providers) {
  SekretoOptions options;
  options.providers = providers;
  options.plugins = {minivault()};
  options.cache = false;
  return Sekreto(options);
}

// ------------------------------------------------------------- the file

void anewvaultholdsnothing() {
  auto vault = fresh();

  same(vault->list(), {}, "list");
  same(vault->key(), "master", "key");

  const VaultKeyInfo info = vault->open();
  truth(info.master(), "the master key is not master");
  truth(info.write(), "the master key may not write");
  same(info.grants(), {}, "grants");
}

void awrittensecretcomesback() {
  auto vault = fresh();

  vault->set("api.token", "tok01");
  vault->set("db.pass", "hunter2");

  same(vault->get("api.token").value_or(""), "tok01", "get");
  same(vault->list(), {"api.token", "db.pass"}, "list");
  truth(vault->has("api.token"), "has said no");
  truth(!vault->has("nope"), "has said yes to an unknown name");
  truth(!vault->get("nope").has_value(), "an unknown name answered");

  // A SECOND HANDLE on the same file, so the assertion is about the bytes
  // rather than about what this handle happens to remember.
  auto again = openas(vault->file(), "", MASTER);
  same(again->get("api.token").value_or(""), "tok01", "a new handle");
}

void thefileisbinary() {
  auto vault = fresh();
  vault->set("api.token", "tok01");

  const std::vector<uint8_t> raw = slurp(vault->file());

  truth(4 <= raw.size() && 0 == std::memcmp("SKMV", raw.data(), 4), "the magic is wrong");

  // NOT ONE OF THESE IS IN THE FILE. The key id is plaintext by design;
  // the secret's name and its value are not, and neither is the
  // passphrase that unwrapped them.
  for (const std::string& secret : {std::string("api.token"), std::string("tok01"),
                                    std::string(MASTER)}) {
    truth(!inside(raw, secret), secret + " is in the file");
  }

  truth(inside(raw, "master"), "the key id is not in the file");
}

void rewritinganamereplacesit() {
  auto vault = fresh();

  vault->set("api.token", "first");
  vault->set("api.token", "second");

  same(vault->get("api.token").value_or(""), "second", "get");
  same(vault->list(), {"api.token"}, "one entry");
}

void removedropsaname() {
  auto vault = fresh();

  vault->set("api.token", "tok01");
  vault->set("db.pass", "hunter2");
  vault->remove("api.token");

  same(vault->list(), {"db.pass"}, "list");
  truth(!vault->get("api.token").has_value(), "a removed name answered");

  holds(refusal("remove again", [&] { vault->remove("api.token"); }),
        "no such secret: api.token", "remove again");
}

void abadnameisrefused() {
  auto vault = fresh();

  holds(refusal("set", [&] { vault->set("API.TOKEN", "x"); }), "invalid name", "set");
  holds(refusal("get", [&] { vault->get("api..token"); }), "invalid name", "get");
  holds(refusal("remove", [&] { vault->remove(""); }), "invalid name", "remove");
}

// ------------------------------------------------------------- the keys

void arestrictedkeyreadsitsgrants() {
  auto vault = fresh();

  vault->set("api.token", "tok01");
  vault->set("db.pass", "hunter2");
  vault->grant(grantof("ci", "ci-passphrase", {"api.token"}, false));

  auto ci = openas(vault->file(), "ci", "ci-passphrase");

  same(ci->get("api.token").value_or(""), "tok01", "granted");

  // THE RESTRICTION IS THE CRYPTOGRAPHY. `db.pass` is in the file and
  // this key cannot derive its key, so the answer is the one a stranger
  // gets: a miss.
  truth(!ci->get("db.pass").has_value(), "an ungranted name answered");
  same(ci->list(), {"api.token"}, "list");

  const VaultKeyInfo info = ci->open();
  truth(!info.master(), "a restricted key reports master");
  truth(!info.write(), "a read-only key reports write");
  same(info.grants(), {"api.token"}, "grants");
}

void areadonlykeyrefusestowrite() {
  auto vault = fresh();

  vault->set("api.token", "tok01");
  vault->grant(grantof("reader", "reader-passphrase", {"api.token"}, false));
  vault->grant(grantof("writer", "writer-passphrase", {"api.token"}, true));

  auto reader = openas(vault->file(), "reader", "reader-passphrase");
  holds(refusal("read-only", [&] { reader->set("api.token", "x"); }),
        "key reader is read-only", "read-only");

  auto writer = openas(vault->file(), "writer", "writer-passphrase");
  writer->set("api.token", "rewritten");

  same(vault->get("api.token").value_or(""), "rewritten", "the master sees it");
}

void arestrictedkeycannotwriteanungrantedname() {
  auto vault = fresh();

  vault->set("api.token", "tok01");
  vault->grant(grantof("ci", "ci-passphrase", {"api.token"}, true));

  auto ci = openas(vault->file(), "ci", "ci-passphrase");

  holds(refusal("ungranted", [&] { ci->set("db.pass", "x"); }),
        "key ci was not granted db.pass", "ungranted");
}

void agrantednamethatdoesnotexistyet() {
  auto vault = fresh();

  // Granted BEFORE the name exists, which is the point: a deploy key is
  // minted from a list of what a service will need.
  vault->grant(grantof("ci", "ci-passphrase", {"api.token"}, false));

  auto ci = openas(vault->file(), "ci", "ci-passphrase");
  same(ci->list(), {}, "nothing yet");
  truth(!ci->get("api.token").has_value(), "a name that does not exist answered");

  vault->set("api.token", "tok01");

  same(ci->get("api.token").value_or(""), "tok01", "once written");
  same(ci->list(), {"api.token"}, "list");
}

void themasterlistseverykey() {
  auto vault = fresh();

  vault->grant(grantof("ci", "ci-passphrase", {"db.pass", "api.token"}, true));

  const std::vector<VaultKeyInfo> keys = vault->keys();
  same(keys.size(), 2, "key count");

  same(keys[0].key(), "master", "the master");
  truth(keys[0].master(), "the master is not master");
  same(keys[0].grants(), {}, "a master is granted nothing");

  same(keys[1].key(), "ci", "the restricted key");
  truth(!keys[1].master(), "ci reports master");
  truth(keys[1].write(), "ci may not write");
  // SORTED, so the record reads the same however the grant was spelled.
  same(keys[1].grants(), {"api.token", "db.pass"}, "grants");
}

void themasteronlymethodsrefusearestrictedkey() {
  auto vault = fresh();

  vault->set("api.token", "tok01");
  vault->grant(grantof("ci", "ci-passphrase", {"api.token"}, true));

  auto ci = openas(vault->file(), "ci", "ci-passphrase");

  holds(refusal("keys", [&] { ci->keys(); }), "listing the keys needs a master key", "keys");
  holds(refusal("grant", [&] { ci->grant(grantof("x", "y", {}, false)); }),
        "granting a key needs a master key", "grant");
  holds(refusal("revoke", [&] { ci->revoke("master"); }), "revoking a key needs a master key",
        "revoke");
  holds(refusal("rotate", [&] { ci->rotate(); }), "rotating the vault needs a master key",
        "rotate");
  holds(refusal("remove", [&] { ci->remove("api.token"); }),
        "removing a secret needs a master key", "remove");
}

void arepeatedkeyidisrefused() {
  auto vault = fresh();

  vault->grant(grantof("ci", "p", {}, false));

  holds(refusal("repeated", [&] { vault->grant(grantof("ci", "q", {}, false)); }),
        "key already exists: ci", "repeated");
  holds(refusal("no id", [&] { vault->grant(grantof("", "p", {}, false)); }),
        "a grant needs a key id", "no id");
  holds(refusal("no passphrase", [&] { vault->grant(grantof("x", "", {}, false)); }),
        "a grant needs a passphrase", "no passphrase");
}

void revokedropsakey() {
  auto vault = fresh();

  vault->set("api.token", "tok01");
  vault->grant(grantof("ci", "ci-passphrase", {"api.token"}, false));
  vault->revoke("ci");

  auto ci = openas(vault->file(), "ci", "ci-passphrase");
  holds(refusal("revoked", [&] { ci->get("api.token"); }), "no such key: ci", "revoked");

  holds(refusal("revoke again", [&] { vault->revoke("ci"); }), "no such key: ci",
        "revoke again");
  holds(refusal("itself", [&] { vault->revoke("master"); }), "a key cannot revoke itself",
        "itself");

  // THE SECRET IS UNTOUCHED: revoking bars a key, not a value.
  same(vault->get("api.token").value_or(""), "tok01", "the secret stays");
}

void rotatekeepsthesecrets() {
  auto vault = fresh();

  vault->set("api.token", "tok01");
  vault->set("db.pass", "hunter2");
  vault->grant(grantof("ci", "ci-passphrase", {"api.token"}, false));

  vault->rotate();

  same(vault->get("api.token").value_or(""), "tok01", "api.token survives");
  same(vault->get("db.pass").value_or(""), "hunter2", "db.pass survives");
  same(vault->list(), {"api.token", "db.pass"}, "list");

  const std::vector<VaultKeyInfo> keys = vault->keys();
  same(keys.size(), 1, "key count after rotate");
  same(keys[0].key(), "master", "the only key");

  // EVERY OTHER KEY IS GONE, which is what rotation has to mean: their
  // rings were sealed under passphrases this process does not have.
  auto ci = openas(vault->file(), "ci", "ci-passphrase");
  holds(refusal("ci is gone", [&] { ci->get("api.token"); }), "no such key: ci", "ci is gone");
}

// -------------------------------------------------------- the refusals

void awrongpassphraseandamissingfile() {
  auto vault = fresh();
  vault->set("api.token", "tok01");

  auto wrong = openas(vault->file(), "", "not-the-passphrase");
  holds(refusal("wrong passphrase", [&] { wrong->get("api.token"); }),
        "wrong passphrase for key master, or a damaged vault", "wrong passphrase");

  auto unknown = openas(vault->file(), "nope", MASTER);
  holds(refusal("unknown key", [&] { unknown->get("api.token"); }), "no such key: nope",
        "unknown key");

  auto missing = openas(WORK + "/not-there.skmv", "", MASTER);
  holds(refusal("missing file", [&] { missing->get("api.token"); }), "no vault file",
        "missing file");
}

void adamagedfileisrefused() {
  auto vault = fresh();
  vault->set("api.token", "tok01");

  const std::vector<uint8_t> raw = slurp(vault->file());

  // Not a vault at all.
  std::string where = vaultpath();
  spill(where, {'n', 'o', 'n', 's', 'e', 'n', 's', 'e'});
  auto first = openas(where, "", MASTER);
  holds(refusal("not a vault", [&] { first->get("api.token"); }), "not a vault file",
        "not a vault");

  // Cut off part way through.
  where = vaultpath();
  spill(where, std::vector<uint8_t>(raw.begin(), raw.end() - 20));
  auto second = openas(where, "", MASTER);
  holds(refusal("truncated", [&] { second->get("api.token"); }), "truncated", "truncated");

  // One byte of ciphertext flipped, which the GCM tag catches.
  std::vector<uint8_t> bent = raw;
  bent.back() = static_cast<uint8_t>(bent.back() ^ 0xff);
  where = vaultpath();
  spill(where, bent);
  auto third = openas(where, "", MASTER);
  holds(refusal("flipped", [&] { third->get("api.token"); }), "damaged", "flipped");

  // Trailing bytes, which a reader that stopped at the last record would
  // have accepted.
  std::vector<uint8_t> extra = raw;
  extra.insert(extra.end(), {'j', 'u', 'n', 'k'});
  where = vaultpath();
  spill(where, extra);
  auto fourth = openas(where, "", MASTER);
  holds(refusal("trailing", [&] { fourth->get("api.token"); }), "trailing bytes", "trailing");
}

void creatingoveranexistingvaultisrefused() {
  auto vault = fresh();

  holds(refusal("create over",
                [&] { createvault(vaultopts(vault->file(), "", MASTER)); }),
        "vault file already exists", "create over");
}

void avaultneedsafileandapassphrase() {
  holds(refusal("no file", [] { openvault(vaultopts("", "", "p")); }), "a vault needs a file",
        "no file");
  holds(refusal("no passphrase", [] { openvault(vaultopts("v.skmv", "", "")); }),
        "a vault needs a passphrase", "no passphrase");
}

// An EMPTY key is no key, so it means `master`. It is not a contrived
// case: the CLI reads SEKRETO_VAULT_KEY, and an unset shell variable
// expands to the empty string rather than to nothing at all.
void anemptykeymeansthemasterkey() {
  auto vault = fresh();
  vault->set("api.token", "tok01");

  auto opened = openas(vault->file(), "", MASTER);
  same(opened->get("api.token").value_or(""), "tok01", "api.token");
  same(opened->open().key(), "master", "key");
}

void createmakesthefileonlywhenasked() {
  const std::string where = vaultpath();

  auto off = openas(where, "", MASTER);
  holds(refusal("create off", [&] { off->get("api.token"); }), "no vault file", "create off");

  VaultOptions options = vaultopts(where, "", MASTER);
  options.create = true;
  auto on = openvault(options);

  truth(!on->get("api.token").has_value(), "a new vault answered");
  on->set("api.token", "tok01");
  same(on->get("api.token").value_or(""), "tok01", "written");

  // The file is there now, so the handle that refused reads it.
  auto again = openas(where, "", MASTER);
  same(again->get("api.token").value_or(""), "tok01", "the same file");
}

void akeyidlongerthantheformatallows() {
  auto vault = fresh();
  const std::string big(300, 'k');

  holds(refusal("grant", [&] { vault->grant(grantof(big, "p", {}, false)); }),
        "key id is longer than 255 bytes", "grant");
  holds(refusal("open", [&] { openvault(vaultopts(vault->file(), big, "p")); }),
        "key id is longer than 255 bytes", "open");

  // AND THE VAULT IS UNHARMED: the refusal came before the write, so a
  // 300-character id did not shift every field after it.
  same(vault->keys().size(), 1, "key count");
}

void theinfoacallergetscannotchangewhatthekeymaydo() {
  auto vault = fresh();

  vault->set("api.token", "tok01");
  vault->grant(grantof("reader", "reader-passphrase", {"api.token"}, false));

  auto reader = openas(vault->file(), "reader", "reader-passphrase");

  VaultKeyInfo info = reader->open();
  truth(!info.write(), "the reader key may write");

  // NOTHING TO FLIP. The record's members are private and the accessors
  // are const, so the defect the review round found in the canonical - a
  // caller flipping its own `write` bit - does not compile here. Assigning
  // a whole new value is all a caller can do, and the vault reads its own:
  info = VaultKeyInfo(info.key(), true, true, {"db.pass"});
  truth(info.write(), "the copy did not take the assignment");

  holds(refusal("still refused", [&] { reader->set("api.token", "x"); }),
        "key reader is read-only", "still refused");
}

void arevokedkeystopsreading() {
  auto vault = fresh();

  vault->set("api.token", "tok01");
  vault->grant(grantof("ci", "ci-passphrase", {"api.token"}, false));

  // OPEN AND READING FIRST, so the handle holds its derived keys.
  auto ci = openas(vault->file(), "ci", "ci-passphrase");
  same(ci->get("api.token").value_or(""), "tok01", "before");

  vault->revoke("ci");

  // The live file no longer holds the key, and a handle that answered
  // from memory here would make `revoke` a suggestion.
  holds(refusal("after", [&] { ci->get("api.token"); }), "no such key: ci", "after");
}

void aregrantedkeyid() {
  auto vault = fresh();

  vault->set("api.token", "tok01");
  vault->grant(grantof("ci", "first-passphrase", {"api.token"}, false));

  auto ci = openas(vault->file(), "ci", "first-passphrase");
  same(ci->get("api.token").value_or(""), "tok01", "before");

  vault->revoke("ci");
  vault->grant(grantof("ci", "second-passphrase", {"api.token"}, false));

  // SAME ID, DIFFERENT KEY. The handle re-derives because the sealed ring
  // changed, and the old passphrase does not unwrap the new one.
  holds(refusal("the old passphrase", [&] { ci->get("api.token"); }),
        "wrong passphrase for key ci, or a damaged vault", "the old passphrase");

  auto second = openas(vault->file(), "ci", "second-passphrase");
  same(second->get("api.token").value_or(""), "tok01", "the new passphrase");
}

void closeforgetsthederivedkeys() {
  auto vault = fresh();

  vault->set("api.token", "tok01");
  same(vault->get("api.token").value_or(""), "tok01", "before");

  vault->close();

  same(vault->get("api.token").value_or(""), "tok01", "after");
}

// --------------------------------------------------- the committed files

std::string FIXTURE;

/// Every port's vault holds the same keys and the same secrets, so the
/// assertions do not vary with which file this is.
void readsthefixture() {
  const std::string file = fixture(FIXTURE);

  auto master = openas(file, "", "fixture-master");

  same(master->list(), {"api.token", "db.pass", "deep.nested.name"}, "list");
  same(master->get("api.token").value_or(""), "fixture-token", "api.token");
  same(master->get("db.pass").value_or(""), "fixture-pass", "db.pass");
  same(master->get("deep.nested.name").value_or(""), "fixture-deep", "deep.nested.name");

  std::vector<std::string> ids;
  for (const VaultKeyInfo& info : master->keys()) ids.push_back(info.key());
  std::sort(ids.begin(), ids.end());
  same(ids, {"master", "reader", "writer"}, "keys");

  auto reader = openas(file, "reader", "fixture-reader");
  same(reader->list(), {"api.token"}, "reader list");
  same(reader->get("api.token").value_or(""), "fixture-token", "reader reads");
  truth(!reader->get("db.pass").has_value(), "the reader key read db.pass");
  holds(refusal("reader writes", [&] { reader->set("api.token", "x"); }), "read-only",
        "reader writes");

  auto writer = openas(file, "writer", "fixture-writer");
  same(writer->list(), {"db.pass"}, "writer list");
  same(writer->get("db.pass").value_or(""), "fixture-pass", "writer reads");

  // The copy is this case's own, so writing it proves the round trip
  // without touching the committed bytes.
  writer->set("db.pass", "rewritten");
  same(master->get("db.pass").value_or(""), "rewritten", "the master sees it");
}

// ------------------------------------------------------------ the chain

void avaultisonestoreinachain() {
  auto vault = fresh();
  vault->set("api.token", "from the vault");

  Sekreto secrets = thechain({vaultspec(vault->file(), "", MASTER),
                              memoryspec("DB_PASS", "from memory")});

  same(secrets.stores(), {"minivault", "memory"}, "stores");
  same(secrets.sources(), {"minivault:" + vault->file(), "memory"}, "sources");
  same(secrets.get("api.token"), "from the vault", "the vault");
  same(secrets.get("db.pass"), "from memory", "memory");
}

void arestrictedkeyinachainfallsthrough() {
  auto vault = fresh();

  vault->set("api.token", "from the vault");
  vault->set("db.pass", "also in the vault");
  vault->grant(grantof("ci", "ci-passphrase", {"api.token"}, false));

  Sekreto secrets = thechain({vaultspec(vault->file(), "ci", "ci-passphrase"),
                              memoryspec("DB_PASS", "from memory")});

  same(secrets.get("api.token"), "from the vault", "the grant");
  // A NAME OUTSIDE THE GRANT IS A MISS, so the chain carries on rather
  // than stopping at a store that holds the name but not for this key.
  same(secrets.get("db.pass"), "from memory", "falls through");
}

void thevaultbehindastoreisreachable() {
  auto vault = fresh();
  vault->set("api.token", "tok01");

  Sekreto secrets = thechain({vaultspec(vault->file(), "", MASTER)});

  auto api = vaultof(secrets);
  same(api->list(), {"api.token"}, "list");

  // A CHAIN READS; the API writes. Both see the same file.
  api->set("db.pass", "written through the api");
  same(secrets.get("db.pass"), "written through the api", "the chain");
}

void anamedstoreisreachedbyname() {
  auto first = fresh();
  first->set("api.token", "first");

  auto second = fresh();
  second->set("api.token", "second");

  ProviderSpec app = vaultspec(first->file(), "", MASTER);
  app.name = "app";
  ProviderSpec ops = vaultspec(second->file(), "", MASTER);
  ops.name = "ops";

  Sekreto secrets = thechain({app, ops});

  same(secrets.stores(), {"app", "ops"}, "stores");
  same(vaultof(secrets, "app")->file(), first->file(), "app");
  same(vaultof(secrets, "ops")->file(), second->file(), "ops");

  // A STORE THAT IS NOT THERE REFUSES, and the alias does not stand in
  // for it: picking one would be a guess, and the guess writes.
  holds(refusal("a store that is not there", [&] { vaultof(secrets, "nope"); }),
        "no minivault store named nope in this chain", "a store that is not there");
}

void achainwithnovaultsaysso() {
  Sekreto secrets = thechain({memoryspec("API_TOKEN", "tok01")});

  holds(refusal("no vault", [&] { vaultof(secrets); }), "no minivault store in this chain",
        "no vault");
}

void achainmissingthefileisrefused() {
  holds(refusal("no file", [] { thechain({vaultspec("", "", "p")}); }),
        "a vault needs a file", "no file");
  holds(refusal("no passphrase", [] { thechain({vaultspec("v.skmv", "", "")}); }),
        "a vault needs a passphrase", "no passphrase");
}

void thefileisreachedatthefirstlookup() {
  // The file does not exist, and building the chain still succeeds: the
  // handle is lazy, so a chain costs no PBKDF2 until a secret is actually
  // wanted.
  Sekreto secrets = thechain({vaultspec(WORK + "/never.skmv", "", MASTER)});

  holds(refusal("at the first lookup", [&] { secrets.get("api.token"); }), "no vault file",
        "at the first lookup");
}

/// A chain that is gone leaves no way to reach its vault.
///
/// The ticket table holds WEAK pointers, so a destroyed chain releases
/// the last strong reference and `vaultof` refuses instead of handing
/// back a dangling handle. Read through a ticket kept from before.
void atorndownchainhasnovault() {
  auto vault = fresh();
  vault->set("api.token", "tok01");

  std::string ref;
  {
    Sekreto secrets = thechain({vaultspec(vault->file(), "", MASTER)});
    ref = secrets.stores()[0];
    truth(nullptr != vaultof(secrets), "the live chain had no vault");
  }

  // The chain is gone; a new one issues a new ticket, and the old ticket
  // names an expired slot. What is checkable from here is that the new
  // chain answers with its own vault and not with the dead one.
  auto next = fresh();
  Sekreto secrets = thechain({vaultspec(next->file(), "", MASTER)});
  same(vaultof(secrets)->file(), next->file(), "the new chain's own vault");
  same(ref, "minivault", "the store name");
}

}  // namespace

int main(int argc, char** argv) {
  if (1 < argc) ONLY = argv[1];

  char pattern[] = "/tmp/sekreto-minivault-XXXXXX";
  if (nullptr == mkdtemp(pattern)) {
    std::cout << "cannot make a work directory\n";
    return 1;
  }
  WORK = pattern;

  testcase("newvault", anewvaultholdsnothing);
  testcase("written", awrittensecretcomesback);
  testcase("binary", thefileisbinary);
  testcase("rewrite", rewritinganamereplacesit);
  testcase("remove", removedropsaname);
  testcase("badname", abadnameisrefused);
  testcase("restricted", arestrictedkeyreadsitsgrants);
  testcase("readonly", areadonlykeyrefusestowrite);
  testcase("ungranted", arestrictedkeycannotwriteanungrantedname);
  testcase("laternamed", agrantednamethatdoesnotexistyet);
  testcase("keys", themasterlistseverykey);
  testcase("masteronly", themasteronlymethodsrefusearestrictedkey);
  testcase("repeatedid", arepeatedkeyidisrefused);
  testcase("revoke", revokedropsakey);
  testcase("rotate", rotatekeepsthesecrets);
  testcase("wrongphrase", awrongpassphraseandamissingfile);
  testcase("damaged", adamagedfileisrefused);
  testcase("createover", creatingoveranexistingvaultisrefused);
  testcase("needsfile", avaultneedsafileandapassphrase);
  testcase("emptykey", anemptykeymeansthemasterkey);
  testcase("createflag", createmakesthefileonlywhenasked);
  testcase("longkeyid", akeyidlongerthantheformatallows);
  testcase("infocopy", theinfoacallergetscannotchangewhatthekeymaydo);
  testcase("revokedcached", arevokedkeystopsreading);
  testcase("regranted", aregrantedkeyid);
  testcase("close", closeforgetsthederivedkeys);

  const std::vector<std::string> files = fixtures();
  if (files.empty()) {
    std::cout << "FAIL - fixtures\n       no committed vault was found\n";
    FAILCOUNT++;
  }
  for (const std::string& name : files) {
    FIXTURE = name;
    testcase("fixture:" + name, readsthefixture);
  }

  testcase("chain", avaultisonestoreinachain);
  testcase("chainfallthrough", arestrictedkeyinachainfallsthrough);
  testcase("api", thevaultbehindastoreisreachable);
  testcase("namedstore", anamedstoreisreachedbyname);
  testcase("novault", achainwithnovaultsaysso);
  testcase("badconfig", achainmissingthefileisrefused);
  testcase("lazy", thefileisreachedatthefirstlookup);
  testcase("torndown", atorndownchainhasnovault);

  std::cout << "\n" << PASSCOUNT << " passed, " << FAILCOUNT << " failed\n";

  return 0 == FAILCOUNT ? 0 : 1;
}
