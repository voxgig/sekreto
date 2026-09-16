// RUN: java -cp build/plugin:build/core:build/plugins:build/test MinivaultTest
// RUN-SOME: ... MinivaultTest written
//
// The mini vault, from both sides: the store a chain reads, and the
// programmatic API a plugin definition can publish beside it.
//
// The vault is not in spec/sekreto.json and cannot be until every port
// ships the kind. The spec runs against all twenty-three of them, so an
// entry naming `minivault` would fail the ports that have no such
// provider. What the shared corpus would have carried is here instead,
// plus the one thing it could not carry either way: a file written by
// this port and read by another, pinned by test/fixture/*.skmv.

import com.voxgig.sekreto.Sekreto;
import com.voxgig.sekreto.Sekreto.SekretoError;
import com.voxgig.sekreto.plugins.Minivault;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.nio.file.StandardCopyOption;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

public final class MinivaultTest {

  private MinivaultTest() {}

  private static final String MASTER = "master-passphrase";

  /**
   * The rounds every test here uses. The library default is 210000, which is the point of PBKDF2
   * and the wrong thing to pay per assertion.
   */
  private static final int ROUNDS = 1000;

  private static String only = null;
  private static int passcount = 0;
  private static int failcount = 0;
  private static Path work;
  private static int count = 0;

  interface Body {
    void run() throws Exception;
  }

  static String vaultpath() {
    count++;
    return work.resolve("vault" + count + ".skmv").toString();
  }

  static Minivault.Vault fresh() {
    return Minivault.createvault(
        new Minivault.Options().file(vaultpath()).passphrase(MASTER).iterations(ROUNDS));
  }

  static Minivault.Vault open(String file, String key, String phrase) {
    return Minivault.openvault(new Minivault.Options().file(file).key(key).passphrase(phrase));
  }

  /** Where the committed vaults live, found by walking up. */
  static Path fixturedir() {
    Path dir = Paths.get(System.getProperty("user.dir")).toAbsolutePath();

    for (int step = 0; step < 8 && null != dir; step++) {
      Path cand = dir.resolve("test").resolve("fixture");
      if (Files.exists(cand.resolve("minivault.skmv"))) {
        return cand;
      }
      dir = dir.getParent();
    }
    throw new AssertionError("sekreto: fixture directory not found");
  }

  /**
   * EVERY committed vault, read off disk rather than listed here. A hard-coded list is one more
   * place to edit when a port lands, and the edit that gets forgotten is the one that makes this
   * suite stop checking the port that just arrived.
   */
  static List<String> fixtures() throws IOException {
    List<String> out = new ArrayList<>();
    try (var names = Files.list(fixturedir())) {
      names
          .filter(path -> path.getFileName().toString().endsWith(".skmv"))
          .forEach(path -> out.add(path.getFileName().toString()));
    }
    out.sort(null);
    return out;
  }

  /**
   * A committed vault, copied so that a test which writes cannot edit the bytes the format contract
   * is made of.
   */
  static String fixture(String name) throws IOException {
    String mine = vaultpath();
    Files.copy(fixturedir().resolve(name), Path.of(mine), StandardCopyOption.REPLACE_EXISTING);
    return mine;
  }

  /**
   * A key's permissions as one line.
   *
   * <p>KeyInfo has no public constructor - what a key may do is the vault's
   * to say - so the expected value here is the printed form rather than a
   * built object.
   */
  static String show(Minivault.KeyInfo one) {
    return one.key + "/" + one.master + "/" + one.write + "/" + one.grants;
  }

  static List<String> show(List<Minivault.KeyInfo> many) {
    List<String> out = new ArrayList<>();
    for (Minivault.KeyInfo one : many) {
      out.add(show(one));
    }
    return out;
  }

  // --- the file --------------------------------------------------------

  static void anewvaultholdsnothing() {
    Minivault.Vault vault = fresh();

    same(List.of(), vault.list(), "list()");
    same("master", vault.key(), "key()");
    same("master/true/true/[]", show(vault.open()), "open()");
  }

  static void awrittensecretcomesback() {
    Minivault.Vault vault = fresh();
    vault.set("api.token", "tok01");
    vault.set("db.pass", "hunter2");

    same("tok01", vault.get("api.token"), "get()");
    same(List.of("api.token", "db.pass"), vault.list(), "list()");
    same(true, vault.has("api.token"), "has()");
    same(false, vault.has("nope"), "has(nope)");
    same(null, vault.get("nope"), "get(nope)");

    Minivault.Vault again = open(vault.file(), null, MASTER);
    same("tok01", again.get("api.token"), "a new handle");
  }

  static void thefileisbinaryandnamesnothinginplaintext() throws IOException {
    Minivault.Vault vault = fresh();
    vault.set("api.token", "tok01");

    String raw = new String(Files.readAllBytes(Path.of(vault.file())), StandardCharsets.ISO_8859_1);

    same("SKMV", raw.substring(0, 4), "magic");
    // The key ids are plaintext and documented as such; a secret name is
    // not, and neither is a value.
    same(true, raw.contains("master"), "the key id is plaintext");
    same(false, raw.contains("api.token"), "the name is not");
    same(false, raw.contains("tok01"), "the value is not");
  }

  static void rewritinganamereplacesit() {
    Minivault.Vault vault = fresh();
    vault.set("api.token", "one");
    vault.set("api.token", "two");

    same("two", vault.get("api.token"), "get()");
    same(List.of("api.token"), vault.list(), "list()");
  }

  static void removedropsaname() {
    Minivault.Vault vault = fresh();
    vault.set("api.token", "tok01");
    vault.remove("api.token");

    same(List.of(), vault.list(), "list()");
    same(null, vault.get("api.token"), "get()");
    contains(threw(() -> vault.remove("api.token")), "no such secret", "remove() again");
  }

  static void abadnameisrefused() {
    Minivault.Vault vault = fresh();

    threw(() -> vault.get(""));
    threw(() -> vault.set("bad name", "x"));
  }

  // --- the keys --------------------------------------------------------

  static void arestrictedkeyreadsitsgrants() {
    Minivault.Vault vault = fresh();
    vault.set("api.token", "tok01");
    vault.set("db.pass", "hunter2");
    vault.grant(
        new Minivault.Grant()
            .key("ci")
            .passphrase("ci-phrase")
            .names(List.of("api.token"))
            .iterations(ROUNDS));

    Minivault.Vault ci = open(vault.file(), "ci", "ci-phrase");

    same(List.of("api.token"), ci.list(), "list()");
    same("tok01", ci.get("api.token"), "the grant");
    // Not an error: the vault answers as the key that opened it, so a name
    // outside the grant is a miss.
    same(null, ci.get("db.pass"), "outside the grant");
    same("ci/false/false/[api.token]", show(ci.open()), "open()");
  }

  static void areadonlykeyrefusestowrite() {
    Minivault.Vault vault = fresh();
    vault.set("db.pass", "hunter2");
    vault.grant(
        new Minivault.Grant()
            .key("ro")
            .passphrase("ro-phrase")
            .names(List.of("db.pass"))
            .iterations(ROUNDS));
    vault.grant(
        new Minivault.Grant()
            .key("rw")
            .passphrase("rw-phrase")
            .names(List.of("db.pass"))
            .write(true)
            .iterations(ROUNDS));

    Minivault.Vault ro = open(vault.file(), "ro", "ro-phrase");
    contains(threw(() -> ro.set("db.pass", "nope")), "read-only", "a read-only key");

    Minivault.Vault rw = open(vault.file(), "rw", "rw-phrase");
    rw.set("db.pass", "changed");
    same("changed", vault.get("db.pass"), "a write key");
  }

  static void arestrictedkeycannotwriteanungrantedname() {
    Minivault.Vault vault = fresh();
    vault.set("db.pass", "hunter2");
    vault.grant(
        new Minivault.Grant()
            .key("rw")
            .passphrase("rw-phrase")
            .names(List.of("db.pass"))
            .write(true)
            .iterations(ROUNDS));

    Minivault.Vault rw = open(vault.file(), "rw", "rw-phrase");
    contains(threw(() -> rw.set("other.name", "x")), "was not granted", "an ungranted name");
  }

  static void agrantednamethatdoesnotexistyet() {
    Minivault.Vault vault = fresh();
    vault.grant(
        new Minivault.Grant()
            .key("ci")
            .passphrase("ci-phrase")
            .names(List.of("later.name"))
            .iterations(ROUNDS));

    Minivault.Vault ci = open(vault.file(), "ci", "ci-phrase");
    same(List.of(), ci.list(), "before");
    same(null, ci.get("later.name"), "before");

    vault.set("later.name", "here now");

    same("here now", ci.get("later.name"), "after");
    same(List.of("later.name"), ci.list(), "after");
  }

  static void themasterlistseverykey() {
    Minivault.Vault vault = fresh();
    vault.grant(
        new Minivault.Grant()
            .key("ro")
            .passphrase("p1")
            .names(List.of("a.one"))
            .iterations(ROUNDS));
    vault.grant(
        new Minivault.Grant()
            .key("rw")
            .passphrase("p2")
            .names(List.of("a.one", "b.two"))
            .write(true)
            .iterations(ROUNDS));

    same(
        List.of("master/true/true/[]", "ro/false/false/[a.one]", "rw/false/true/[a.one, b.two]"),
        show(vault.keys()),
        "keys()");
  }

  static void themasteronlymethodsrefusearestrictedkey() {
    Minivault.Vault vault = fresh();
    vault.set("a.one", "x");
    vault.grant(
        new Minivault.Grant()
            .key("ci")
            .passphrase("ci-phrase")
            .names(List.of("a.one"))
            .write(true)
            .iterations(ROUNDS));

    Minivault.Vault ci = open(vault.file(), "ci", "ci-phrase");

    contains(threw(ci::keys), "master key", "keys()");
    contains(threw(() -> ci.remove("a.one")), "master key", "remove()");
    contains(threw(ci::rotate), "master key", "rotate()");
    contains(threw(() -> ci.revoke("master")), "master key", "revoke()");
    contains(
        threw(() -> ci.grant(new Minivault.Grant().key("x").passphrase("y"))),
        "master key",
        "grant()");
  }

  static void arepeatedkeyidisrefused() {
    Minivault.Vault vault = fresh();
    vault.grant(new Minivault.Grant().key("ci").passphrase("one").iterations(ROUNDS));

    contains(
        threw(() -> vault.grant(new Minivault.Grant().key("ci").passphrase("two")
            .iterations(ROUNDS))),
        "key already exists",
        "a repeated id");
  }

  static void revokedropsakey() {
    Minivault.Vault vault = fresh();
    vault.set("a.one", "x");
    vault.grant(
        new Minivault.Grant()
            .key("ci")
            .passphrase("ci-phrase")
            .names(List.of("a.one"))
            .iterations(ROUNDS));

    Minivault.Vault ci = open(vault.file(), "ci", "ci-phrase");
    same("x", ci.get("a.one"), "before");

    vault.revoke("ci");

    contains(threw(() -> ci.get("a.one")), "no such key", "after");
    contains(threw(() -> vault.revoke("master")), "cannot revoke itself", "itself");
  }

  static void rotatekeepsthesecrets() {
    Minivault.Vault vault = fresh();
    vault.set("api.token", "tok01");
    vault.set("db.pass", "hunter2");
    vault.grant(
        new Minivault.Grant()
            .key("ci")
            .passphrase("ci-phrase")
            .names(List.of("api.token"))
            .iterations(ROUNDS));

    vault.rotate();

    same(List.of("api.token", "db.pass"), vault.list(), "list()");
    same("tok01", vault.get("api.token"), "api.token");
    same("hunter2", vault.get("db.pass"), "db.pass");
    same(List.of("master/true/true/[]"), show(vault.keys()), "keys()");

    Minivault.Vault ci = open(vault.file(), "ci", "ci-phrase");
    threw(() -> ci.get("api.token"));
  }

  // --- refusals --------------------------------------------------------

  static void awrongpassphraseandamissingfilerefuse() {
    Minivault.Vault vault = fresh();
    vault.set("a.one", "x");

    Minivault.Vault bad = open(vault.file(), null, "wrong");
    contains(threw(() -> bad.get("a.one")), "wrong passphrase", "a wrong passphrase");

    Minivault.Vault nokey = open(vault.file(), "nope", MASTER);
    threw(() -> nokey.get("a.one"));

    Minivault.Vault missing = open(work.resolve("nothing.skmv").toString(), null, MASTER);
    contains(threw(() -> missing.get("a.one")), "no vault file", "a missing file");
  }

  static void adamagedfileisrefused() throws IOException {
    Minivault.Vault vault = fresh();
    vault.set("a.one", "x");
    byte[] raw = Files.readAllBytes(Path.of(vault.file()));

    String short1 = vaultpath();
    Files.write(Path.of(short1), Arrays.copyOf(raw, raw.length - 10));
    contains(threw(() -> open(short1, null, MASTER).get("a.one")), "truncated", "short");

    String trailing = vaultpath();
    byte[] more = Arrays.copyOf(raw, raw.length + 4);
    System.arraycopy("junk".getBytes(StandardCharsets.ISO_8859_1), 0, more, raw.length, 4);
    Files.write(Path.of(trailing), more);
    contains(threw(() -> open(trailing, null, MASTER).get("a.one")), "trailing bytes", "trailing");

    String notvault = vaultpath();
    byte[] wrong = raw.clone();
    System.arraycopy("NOPE".getBytes(StandardCharsets.ISO_8859_1), 0, wrong, 0, 4);
    Files.write(Path.of(notvault), wrong);
    contains(threw(() -> open(notvault, null, MASTER).get("a.one")), "not a vault file", "magic");
  }

  static void creatingoveranexistingvaultisrefused() {
    Minivault.Vault vault = fresh();

    contains(
        threw(
            () ->
                Minivault.createvault(
                    new Minivault.Options()
                        .file(vault.file())
                        .passphrase(MASTER)
                        .iterations(ROUNDS))),
        "already exists",
        "createvault over one");
  }

  static void avaultneedsafileandapassphrase() {
    threw(() -> Minivault.openvault(new Minivault.Options().file("").passphrase(MASTER)));
    threw(() -> Minivault.openvault(new Minivault.Options().file(vaultpath()).passphrase("")));
  }

  /**
   * An EMPTY key is no key, so it means {@code master}. It is not a
   * contrived case: the CLI reads SEKRETO_VAULT_KEY, and an unset shell
   * variable expands to the empty string rather than to nothing at all -
   * and {@code null ==} answers for null alone.
   */
  static void anemptykeymeansthemasterkey() {
    Minivault.Vault vault = fresh();
    vault.set("api.token", "tok01");

    Minivault.Vault opened =
        Minivault.openvault(
            new Minivault.Options().file(vault.file()).key("").passphrase(MASTER));

    same("tok01", opened.get("api.token"), "api.token");
    same("master", opened.open().key, "key");
  }

  static void createmakesthefileonlywhenasked() {
    String path = vaultpath();

    Minivault.Vault refuses =
        Minivault.openvault(
            new Minivault.Options().file(path).passphrase(MASTER).iterations(ROUNDS));
    threw(refuses::list);
    same(false, Files.exists(Path.of(path)), "no file");

    Minivault.Vault makes =
        Minivault.openvault(
            new Minivault.Options()
                .file(path)
                .passphrase(MASTER)
                .iterations(ROUNDS)
                .create(true));
    same(List.of(), makes.list(), "created");
    same(true, Files.exists(Path.of(path)), "the file");
  }

  static void akeyidlongerthantheformatallowsisrefused() {
    Minivault.Vault vault = fresh();
    String over = "k".repeat(256);

    contains(
        threw(
            () ->
                vault.grant(
                    new Minivault.Grant().key(over).passphrase("p").iterations(ROUNDS))),
        "longer than 255",
        "a long key id");
    same(List.of("master/true/true/[]"), show(vault.keys()), "the vault is unchanged");
  }

  // --- the handle ------------------------------------------------------

  static void theinfoacallergetscannotchangewhatthekeymaydo() {
    Minivault.Vault vault = fresh();
    vault.set("a.one", "x");
    vault.grant(
        new Minivault.Grant()
            .key("ro")
            .passphrase("ro-phrase")
            .names(List.of("a.one"))
            .iterations(ROUNDS));

    Minivault.Vault ro = open(vault.file(), "ro", "ro-phrase");

    // KeyInfo's fields are final and `grants` is an immutable copy, so the
    // only way to try this in java is to mutate the list - which raises.
    Minivault.KeyInfo got = ro.open();
    boolean refused = false;
    try {
      got.grants.add("b.two");
    } catch (UnsupportedOperationException err) {
      refused = true;
    }
    same(true, refused, "grants is immutable");

    contains(threw(() -> ro.set("a.one", "nope")), "read-only", "still read-only");
    same(List.of("a.one"), ro.open().grants, "still one grant");
  }

  static void arevokedkeystopsreadingfromacachedhandle() {
    Minivault.Vault vault = fresh();
    vault.set("a.one", "x");
    vault.grant(
        new Minivault.Grant()
            .key("ci")
            .passphrase("ci-phrase")
            .names(List.of("a.one"))
            .iterations(ROUNDS));

    Minivault.Vault ci = open(vault.file(), "ci", "ci-phrase");
    same("x", ci.get("a.one"), "before");

    vault.revoke("ci");
    threw(() -> ci.get("a.one"));
  }

  static void aregrantedkeyiddoesnotkeeptheoldpassphraseworking() {
    Minivault.Vault vault = fresh();
    vault.set("a.one", "x");
    vault.grant(
        new Minivault.Grant()
            .key("ci")
            .passphrase("first")
            .names(List.of("a.one"))
            .iterations(ROUNDS));

    Minivault.Vault ci = open(vault.file(), "ci", "first");
    same("x", ci.get("a.one"), "before");

    vault.revoke("ci");
    vault.grant(
        new Minivault.Grant()
            .key("ci")
            .passphrase("second")
            .names(List.of("a.one"))
            .iterations(ROUNDS));

    contains(threw(() -> ci.get("a.one")), "wrong passphrase", "the old passphrase");
    same("x", open(vault.file(), "ci", "second").get("a.one"), "the new one");
  }

  static void closeforgetsthederivedkeys() {
    Minivault.Vault vault = fresh();
    vault.set("a.one", "x");
    same("x", vault.get("a.one"), "before");

    vault.close();
    same("x", vault.get("a.one"), "after");
  }

  // --- the format, across ports ----------------------------------------

  // EVERY COMMITTED VAULT, not only this port's. A suite that reads only
  // the vault its own port wrote proves the reader agrees with the writer
  // beside it - which a port whose serializer and parser share a mistake
  // satisfies perfectly.
  static void thecommittedfixturesread() throws IOException {
    for (String name : fixtures()) {
      String file = fixture(name);

      Minivault.Vault master = open(file, null, "fixture-master");
      same(List.of("api.token", "db.pass", "deep.nested.name"), master.list(), name + " list()");
      same("fixture-token", master.get("api.token"), name + " api.token");
      same("fixture-pass", master.get("db.pass"), name + " db.pass");
      same("fixture-deep", master.get("deep.nested.name"), name + " deep");

      same(
          List.of(
              "master/true/true/[]",
              "reader/false/false/[api.token]",
              "writer/false/true/[db.pass]"),
          show(master.keys()),
          name + " keys()");

      Minivault.Vault reader = open(file, "reader", "fixture-reader");
      same(List.of("api.token"), reader.list(), name + " reader list()");
      same("fixture-token", reader.get("api.token"), name + " reader grant");
      same(null, reader.get("db.pass"), name + " reader miss");

      Minivault.Vault writer = open(file, "writer", "fixture-writer");
      writer.set("db.pass", "written by this port");
      same("written by this port", master.get("db.pass"), name + " writer");
    }
  }

  // --- the chain -------------------------------------------------------

  static void avaultisonestoreinachain() {
    Minivault.Vault vault = fresh();
    vault.set("api.token", "from the vault");

    Map<String, Object> memory = new LinkedHashMap<>();
    memory.put("kind", "memory");
    memory.put("values", Map.of("DB_PASS", "from memory"));

    Map<String, Object> mv = new LinkedHashMap<>();
    mv.put("kind", "minivault");
    mv.put("file", vault.file());
    mv.put("passphrase", MASTER);

    Sekreto secrets =
        new Sekreto(
            new Sekreto.Options()
                .plugins(List.of(Minivault.PLUGIN))
                .providers(List.of(memory, mv)));

    same("from the vault", secrets.get("api.token"), "the vault");
    same("from memory", secrets.get("db.pass"), "memory");
  }

  static void arestrictedkeyinachainfallsthrough() {
    Minivault.Vault vault = fresh();
    vault.set("api.token", "from the vault");
    vault.set("db.pass", "in the vault, not granted");
    vault.grant(
        new Minivault.Grant()
            .key("ci")
            .passphrase("ci-phrase")
            .names(List.of("api.token"))
            .iterations(ROUNDS));

    Map<String, Object> mv = new LinkedHashMap<>();
    mv.put("kind", "minivault");
    mv.put("file", vault.file());
    mv.put("vaultkey", "ci");
    mv.put("passphrase", "ci-phrase");

    Map<String, Object> memory = new LinkedHashMap<>();
    memory.put("kind", "memory");
    memory.put("values", Map.of("DB_PASS", "from memory"));

    Sekreto secrets =
        new Sekreto(
            new Sekreto.Options()
                .plugins(List.of(Minivault.PLUGIN))
                .providers(List.of(mv, memory)));

    same("from the vault", secrets.get("api.token"), "the grant");
    same("from memory", secrets.get("db.pass"), "falls through");
  }

  static void thevaultbehindastoreisreachableasanapi() {
    Minivault.Vault vault = fresh();
    vault.set("api.token", "tok01");

    Map<String, Object> mv = new LinkedHashMap<>();
    mv.put("kind", "minivault");
    mv.put("file", vault.file());
    mv.put("passphrase", MASTER);

    Sekreto secrets =
        new Sekreto(new Sekreto.Options().plugins(List.of(Minivault.PLUGIN)).providers(List.of(mv)));

    Minivault.Vault api = Minivault.vaultof(secrets);
    same(List.of("api.token"), api.list(), "list()");

    api.set("db.pass", "written through the api");
    same("written through the api", secrets.get("db.pass"), "the chain sees it");
  }

  static void anamedstoreisreachedbyname() {
    Minivault.Vault vault = fresh();
    vault.set("api.token", "tok01");

    Map<String, Object> mv = new LinkedHashMap<>();
    mv.put("kind", "minivault");
    mv.put("name", "app");
    mv.put("file", vault.file());
    mv.put("passphrase", MASTER);

    Sekreto secrets =
        new Sekreto(new Sekreto.Options().plugins(List.of(Minivault.PLUGIN)).providers(List.of(mv)));

    same(List.of("api.token"), Minivault.vaultof(secrets, "app").list(), "by name");
    same(List.of("api.token"), Minivault.vaultof(secrets).list(), "by alias");
    contains(
        threw(() -> Minivault.vaultof(secrets, "minivault")),
        "no minivault store named",
        "a name that is not there");
  }

  static void achainwithnovaultsaysso() {
    Map<String, Object> memory = new LinkedHashMap<>();
    memory.put("kind", "memory");
    memory.put("values", Map.of());

    Sekreto secrets =
        new Sekreto(
            new Sekreto.Options().plugins(List.of(Minivault.PLUGIN)).providers(List.of(memory)));

    contains(threw(() -> Minivault.vaultof(secrets)), "no minivault store", "no vault");
  }

  static void achainmissingthefileisrefusedatconstruction() {
    Map<String, Object> nofile = new LinkedHashMap<>();
    nofile.put("kind", "minivault");
    nofile.put("passphrase", MASTER);

    contains(
        threw(
            () ->
                new Sekreto(
                    new Sekreto.Options()
                        .plugins(List.of(Minivault.PLUGIN))
                        .providers(List.of(nofile)))),
        "a vault needs a file",
        "no file");

    Map<String, Object> nophrase = new LinkedHashMap<>();
    nophrase.put("kind", "minivault");
    nophrase.put("file", vaultpath());

    contains(
        threw(
            () ->
                new Sekreto(
                    new Sekreto.Options()
                        .plugins(List.of(Minivault.PLUGIN))
                        .providers(List.of(nophrase)))),
        "a vault needs a passphrase",
        "no passphrase");
  }

  static void thefileisreachedatthefirstlookup() {
    Map<String, Object> mv = new LinkedHashMap<>();
    mv.put("kind", "minivault");
    mv.put("file", vaultpath());
    mv.put("passphrase", MASTER);

    // No file, and construction still succeeds: the handle is lazy.
    Sekreto secrets =
        new Sekreto(new Sekreto.Options().plugins(List.of(Minivault.PLUGIN)).providers(List.of(mv)));

    contains(threw(() -> secrets.get("api.token")), "no vault file", "at the first lookup");
  }

  // --- the harness -----------------------------------------------------

  static void same(Object want, Object got, String what) {
    if (null == want ? null != got : !want.equals(got)) {
      throw new AssertionError(what + ":\n  want: " + want + "\n  got:  " + got);
    }
  }

  static void contains(String got, String want, String what) {
    if (null == got || !got.contains(want)) {
      throw new AssertionError(what + ":\n  want to contain: " + want + "\n  got: " + got);
    }
  }

  /** The message of the SekretoError the body raised. */
  static String threw(Runnable body) {
    try {
      body.run();
    } catch (SekretoError err) {
      return err.getMessage();
    }
    throw new AssertionError("want a SekretoError, nothing was thrown");
  }

  static void testcase(String name, Body body) {
    if (null != only && !name.equals(only)) {
      return;
    }

    try {
      body.run();
      passcount++;
      System.out.println("ok   - " + name);
    } catch (Throwable err) {
      failcount++;
      System.out.println("FAIL - " + name);
      System.out.println("  " + err);
    }
  }

  public static void main(String[] args) throws IOException {
    if (0 < args.length) {
      only = args[0];
    }

    work = Files.createTempDirectory("sekreto-minivault");

    testcase("newvault", MinivaultTest::anewvaultholdsnothing);
    testcase("written", MinivaultTest::awrittensecretcomesback);
    testcase("binary", MinivaultTest::thefileisbinaryandnamesnothinginplaintext);
    testcase("rewrite", MinivaultTest::rewritinganamereplacesit);
    testcase("remove", MinivaultTest::removedropsaname);
    testcase("badname", MinivaultTest::abadnameisrefused);
    testcase("restricted", MinivaultTest::arestrictedkeyreadsitsgrants);
    testcase("readonly", MinivaultTest::areadonlykeyrefusestowrite);
    testcase("ungranted", MinivaultTest::arestrictedkeycannotwriteanungrantedname);
    testcase("laternamed", MinivaultTest::agrantednamethatdoesnotexistyet);
    testcase("keys", MinivaultTest::themasterlistseverykey);
    testcase("masteronly", MinivaultTest::themasteronlymethodsrefusearestrictedkey);
    testcase("repeatedid", MinivaultTest::arepeatedkeyidisrefused);
    testcase("revoke", MinivaultTest::revokedropsakey);
    testcase("rotate", MinivaultTest::rotatekeepsthesecrets);
    testcase("wrongphrase", MinivaultTest::awrongpassphraseandamissingfilerefuse);
    testcase("damaged", MinivaultTest::adamagedfileisrefused);
    testcase("createover", MinivaultTest::creatingoveranexistingvaultisrefused);
    testcase("needsfile", MinivaultTest::avaultneedsafileandapassphrase);
    testcase("emptykey", MinivaultTest::anemptykeymeansthemasterkey);
    testcase("createflag", MinivaultTest::createmakesthefileonlywhenasked);
    testcase("longkeyid", MinivaultTest::akeyidlongerthantheformatallowsisrefused);
    testcase("infoimmutable", MinivaultTest::theinfoacallergetscannotchangewhatthekeymaydo);
    testcase("revokedcached", MinivaultTest::arevokedkeystopsreadingfromacachedhandle);
    testcase("regranted", MinivaultTest::aregrantedkeyiddoesnotkeeptheoldpassphraseworking);
    testcase("close", MinivaultTest::closeforgetsthederivedkeys);
    testcase("fixtures", MinivaultTest::thecommittedfixturesread);
    testcase("chain", MinivaultTest::avaultisonestoreinachain);
    testcase("chainfallthrough", MinivaultTest::arestrictedkeyinachainfallsthrough);
    testcase("api", MinivaultTest::thevaultbehindastoreisreachableasanapi);
    testcase("namedstore", MinivaultTest::anamedstoreisreachedbyname);
    testcase("novault", MinivaultTest::achainwithnovaultsaysso);
    testcase("badconfig", MinivaultTest::achainmissingthefileisrefusedatconstruction);
    testcase("lazy", MinivaultTest::thefileisreachedatthefirstlookup);

    System.out.println();
    System.out.println(passcount + " passed, " + failcount + " failed");
    System.exit(0 == failcount ? 0 : 1);
  }
}
