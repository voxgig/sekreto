// The mini vault, from both sides: the store a chain reads, and the
// programmatic API a plugin definition can publish beside it.
//
// The vault is not in spec/sekreto.json and cannot be until every port
// ships the kind. The spec runs against all twenty-three of them, so an
// entry naming `minivault` would fail the ports that have no such
// provider. What the shared corpus would have carried is here instead,
// plus the one thing it could not carry either way: a file written by this
// port and read by another, pinned by test/fixture/*.skmv.

import java.io.File
import java.nio.charset.StandardCharsets
import java.nio.file.Files
import java.nio.file.Path
import java.nio.file.StandardCopyOption
import scala.util.control.NonFatal

import com.voxgig.sekreto.ProviderSpec
import com.voxgig.sekreto.Sekreto
import com.voxgig.sekreto.SekretoError
import com.voxgig.sekreto.plugins.*

object MinivaultTest:

  private val MASTER = "master-passphrase"

  /** The rounds every test here uses. The library default is 210000, which
    * is the point of PBKDF2 and the wrong thing to pay per assertion.
    */
  private val ROUNDS = 1000

  private class Failed(message: String) extends RuntimeException(message)

  private var only: Option[String] = None
  private var passcount = 0
  private var failcount = 0
  private var work: Path = null
  private var count = 0

  private def testcase(name: String)(body: => Unit): Unit =
    if only.forall(_ == name) then
      try
        body
        passcount += 1
        println(s"ok   - $name")
      catch
        case NonFatal(err) =>
          failcount += 1
          println(s"FAIL - $name")
          println("       " + Option(err.getMessage).getOrElse(err.toString).replace("\n", "\n       "))

  private def eq[T](want: T, got: T, what: String = ""): Unit =
    if want != got then throw Failed(s"$what\n  want: $want\n  got:  $got")

  private def has(got: String, want: String, what: String): Unit =
    if !got.contains(want) then
      throw Failed(s"$what\n  want to contain: $want\n  got: $got")

  /** The message of the SekretoError the body raised. */
  private def threw(body: => Unit): String =
    try
      body
      throw Failed("want a SekretoError, nothing was thrown")
    catch case err: SekretoError => Option(err.getMessage).getOrElse("")

  private def vaultpath(): String =
    count += 1
    work.resolve(s"vault$count.skmv").toString

  private def fresh(): MiniVault =
    createvault(VaultOptions(file = vaultpath(), passphrase = MASTER, iterations = ROUNDS))

  private def openas(file: String, key: String, phrase: String): MiniVault =
    openvault(VaultOptions(file = file, key = key, passphrase = phrase))

  /** Where the committed vaults live, found by walking up. */
  private def fixturedir(): File =
    var dir = File(System.getProperty("user.dir")).getAbsoluteFile
    var out: File = null

    for _ <- 0 until 8 if out == null && dir != null do
      val cand = File(File(dir, "test"), "fixture")
      if File(cand, "minivault.skmv").exists then out = cand else dir = dir.getParentFile

    if out == null then throw Failed("sekreto: fixture directory not found")
    out

  /** EVERY committed vault, read off disk rather than listed here. A
    * hard-coded list is one more place to edit when a port lands, and the
    * edit that gets forgotten is the one that makes this suite stop
    * checking the port that just arrived.
    */
  private def fixtures(): List[String] =
    fixturedir().listFiles((_, n) => n.endsWith(".skmv")).map(_.getName).toList.sorted

  /** A committed vault, copied so that a test which writes cannot edit the
    * bytes the format contract is made of.
    */
  private def fixture(name: String): String =
    val mine = vaultpath()
    Files.copy(File(fixturedir(), name).toPath, Path.of(mine),
      StandardCopyOption.REPLACE_EXISTING)
    mine

  private def chain(providers: ProviderSpec*): Sekreto =
    Sekreto(providers = providers.toList, plugins = List(minivault))

  def main(args: Array[String]): Unit =
    only = args.headOption
    work = Files.createTempDirectory("sekreto-minivault")

    // --- the file ---------------------------------------------------

    testcase("a new vault holds nothing"):
      val vault = fresh()
      eq(Nil, vault.list, "list")
      eq("master", vault.key, "key")
      eq("master/true/true/[]", vault.open.show, "open")

    testcase("a written secret comes back"):
      val vault = fresh()
      vault.set("api.token", "tok01")
      vault.set("db.pass", "hunter2")

      eq(Some("tok01"), vault.get("api.token"), "get")
      eq(List("api.token", "db.pass"), vault.list, "list")
      eq(true, vault.has("api.token"), "has")
      eq(false, vault.has("nope"), "has nope")
      eq(None, vault.get("nope"), "get nope")

      eq(Some("tok01"), openas(vault.file, MASTERKEY, MASTER).get("api.token"), "a new handle")

    testcase("the file is binary and names nothing in plaintext"):
      val vault = fresh()
      vault.set("api.token", "tok01")
      val raw = String(Files.readAllBytes(Path.of(vault.file)), StandardCharsets.ISO_8859_1)

      eq("SKMV", raw.substring(0, 4), "magic")
      // The key ids are plaintext and documented as such; a secret name is
      // not, and neither is a value.
      eq(true, raw.contains("master"), "the key id is plaintext")
      eq(false, raw.contains("api.token"), "the name is not")
      eq(false, raw.contains("tok01"), "the value is not")

    testcase("rewriting a name replaces it"):
      val vault = fresh()
      vault.set("api.token", "one")
      vault.set("api.token", "two")

      eq(Some("two"), vault.get("api.token"), "get")
      eq(List("api.token"), vault.list, "list")

    testcase("remove drops a name"):
      val vault = fresh()
      vault.set("api.token", "tok01")
      vault.remove("api.token")

      eq(Nil, vault.list, "list")
      eq(None, vault.get("api.token"), "get")
      has(threw(vault.remove("api.token")), "no such secret", "remove again")

    testcase("a bad name is refused"):
      val vault = fresh()
      threw(vault.get(""))
      threw(vault.set("bad name", "x"))

    // --- the keys ---------------------------------------------------

    testcase("a restricted key reads its grants"):
      val vault = fresh()
      vault.set("api.token", "tok01")
      vault.set("db.pass", "hunter2")
      vault.grant(GrantSpec("ci", "ci-phrase", List("api.token"), iterations = Some(ROUNDS)))

      val ci = openas(vault.file, "ci", "ci-phrase")
      eq(List("api.token"), ci.list, "list")
      eq(Some("tok01"), ci.get("api.token"), "the grant")
      // Not an error: the vault answers as the key that opened it, so a
      // name outside the grant is a miss.
      eq(None, ci.get("db.pass"), "outside the grant")
      eq("ci/false/false/[api.token]", ci.open.show, "open")

    testcase("a read-only key refuses to write"):
      val vault = fresh()
      vault.set("db.pass", "hunter2")
      vault.grant(GrantSpec("ro", "ro-phrase", List("db.pass"), iterations = Some(ROUNDS)))
      vault.grant(GrantSpec("rw", "rw-phrase", List("db.pass"), true, Some(ROUNDS)))

      has(threw(openas(vault.file, "ro", "ro-phrase").set("db.pass", "nope")),
        "read-only", "a read-only key")

      openas(vault.file, "rw", "rw-phrase").set("db.pass", "changed")
      eq(Some("changed"), vault.get("db.pass"), "a write key")

    testcase("a restricted key cannot write an ungranted name"):
      val vault = fresh()
      vault.set("db.pass", "hunter2")
      vault.grant(GrantSpec("rw", "rw-phrase", List("db.pass"), true, Some(ROUNDS)))

      has(threw(openas(vault.file, "rw", "rw-phrase").set("other.name", "x")),
        "was not granted", "ungranted")

    testcase("a granted name that does not exist yet"):
      val vault = fresh()
      vault.grant(GrantSpec("ci", "ci-phrase", List("later.name"), iterations = Some(ROUNDS)))

      val ci = openas(vault.file, "ci", "ci-phrase")
      eq(Nil, ci.list, "before")
      eq(None, ci.get("later.name"), "before")

      vault.set("later.name", "here now")

      eq(Some("here now"), ci.get("later.name"), "after")
      eq(List("later.name"), ci.list, "after")

    testcase("the master lists every key"):
      val vault = fresh()
      vault.grant(GrantSpec("ro", "p1", List("a.one"), iterations = Some(ROUNDS)))
      vault.grant(GrantSpec("rw", "p2", List("a.one", "b.two"), true, Some(ROUNDS)))

      eq(
        List("master/true/true/[]", "ro/false/false/[a.one]", "rw/false/true/[a.one, b.two]"),
        vault.keys.map(_.show),
        "keys",
      )

    testcase("the master-only methods refuse a restricted key"):
      val vault = fresh()
      vault.set("a.one", "x")
      vault.grant(GrantSpec("ci", "ci-phrase", List("a.one"), true, Some(ROUNDS)))

      val ci = openas(vault.file, "ci", "ci-phrase")

      has(threw(ci.keys), "master key", "keys")
      has(threw(ci.remove("a.one")), "master key", "remove")
      has(threw(ci.rotate()), "master key", "rotate")
      has(threw(ci.revoke("master")), "master key", "revoke")
      has(threw(ci.grant(GrantSpec("x", "y"))), "master key", "grant")

    testcase("a repeated key id is refused"):
      val vault = fresh()
      vault.grant(GrantSpec("ci", "one", iterations = Some(ROUNDS)))
      has(threw(vault.grant(GrantSpec("ci", "two", iterations = Some(ROUNDS)))),
        "key already exists", "a repeated id")

    testcase("revoke drops a key"):
      val vault = fresh()
      vault.set("a.one", "x")
      vault.grant(GrantSpec("ci", "ci-phrase", List("a.one"), iterations = Some(ROUNDS)))

      val ci = openas(vault.file, "ci", "ci-phrase")
      eq(Some("x"), ci.get("a.one"), "before")

      vault.revoke("ci")

      has(threw(ci.get("a.one")), "no such key", "after")
      has(threw(vault.revoke("master")), "cannot revoke itself", "itself")

    testcase("rotate keeps the secrets"):
      val vault = fresh()
      vault.set("api.token", "tok01")
      vault.set("db.pass", "hunter2")
      vault.grant(GrantSpec("ci", "ci-phrase", List("api.token"), iterations = Some(ROUNDS)))

      vault.rotate()

      eq(List("api.token", "db.pass"), vault.list, "list")
      eq(Some("tok01"), vault.get("api.token"), "api.token")
      eq(Some("hunter2"), vault.get("db.pass"), "db.pass")
      eq(List("master"), vault.keys.map(_.key), "keys")

      threw(openas(vault.file, "ci", "ci-phrase").get("api.token"))

    // --- refusals ---------------------------------------------------

    testcase("a wrong passphrase and a missing file refuse"):
      val vault = fresh()
      vault.set("a.one", "x")

      has(threw(openas(vault.file, MASTERKEY, "wrong").get("a.one")),
        "wrong passphrase", "a wrong passphrase")
      threw(openas(vault.file, "nope", MASTER).get("a.one"))
      has(threw(openas(work.resolve("nothing.skmv").toString, MASTERKEY, MASTER).get("a.one")),
        "no vault file", "a missing file")

    testcase("a damaged file is refused"):
      val vault = fresh()
      vault.set("a.one", "x")
      val raw = Files.readAllBytes(Path.of(vault.file))

      val short = vaultpath()
      Files.write(Path.of(short), raw.take(raw.length - 10))
      has(threw(openas(short, MASTERKEY, MASTER).get("a.one")), "truncated", "short")

      val trailing = vaultpath()
      Files.write(Path.of(trailing), raw ++ "junk".getBytes(StandardCharsets.ISO_8859_1))
      has(threw(openas(trailing, MASTERKEY, MASTER).get("a.one")), "trailing bytes", "trailing")

      val notvault = vaultpath()
      Files.write(Path.of(notvault),
        "NOPE".getBytes(StandardCharsets.ISO_8859_1) ++ raw.drop(4))
      has(threw(openas(notvault, MASTERKEY, MASTER).get("a.one")), "not a vault file", "magic")

    testcase("creating over an existing vault is refused"):
      val vault = fresh()
      has(
        threw(createvault(VaultOptions(file = vault.file, passphrase = MASTER,
          iterations = ROUNDS))),
        "already exists", "createvault over one",
      )

    testcase("a vault needs a file and a passphrase"):
      threw(openvault(VaultOptions(file = "", passphrase = MASTER)))
      threw(openvault(VaultOptions(file = vaultpath(), passphrase = "")))

    // An EMPTY key is no key, so it means `master`. It is not a contrived
    // case: the CLI reads SEKRETO_VAULT_KEY, and an unset shell variable
    // expands to the empty string rather than to nothing at all - and
    // `getOrElse` answers for absent alone.
    // TWO HANDLES ON ONE FILE, WRITING AT ONCE, LOSE NOTHING. Each
    // MiniVault is its own object with its own snapshot, so without the
    // shared per-path lock both threads finish `load` before either saves
    // and the second rename discards the first one's secret while
    // reporting success. DOCS.md promises this within one process.
    testcase("two handles writing at once lose nothing"):
      val vault = fresh()
      val path = vault.file
      val rounds = 40
      val broke = java.util.Collections.synchronizedList(java.util.ArrayList[String]())

      def writer(tag: String): Thread =
        Thread(new Runnable:
          def run(): Unit =
            try
              val mine = openvault(VaultOptions(file = path, passphrase = MASTER))
              for round <- 0 until rounds do mine.set(s"t$tag.n$round", s"v$round")
            catch case err: Throwable => broke.add(err.toString)
        )

      val one = writer("one")
      val two = writer("two")
      one.start()
      two.start()
      one.join()
      two.join()

      eq(0, broke.size, "a writer raised")
      eq(2 * rounds, vault.list.length, "every write survived")

    testcase("an empty key means the master key"):
      val vault = fresh()
      vault.set("api.token", "tok01")

      val opened = openvault(VaultOptions(file = vault.file, key = "", passphrase = MASTER))

      eq(Some("tok01"), opened.get("api.token"), "api.token")
      eq("master", opened.open.key, "key")

    testcase("create makes the file only when asked"):
      val path = vaultpath()

      val refuses = openvault(VaultOptions(file = path, passphrase = MASTER,
        iterations = ROUNDS))
      threw(refuses.list)
      eq(false, File(path).exists, "no file")

      val makes = openvault(VaultOptions(file = path, passphrase = MASTER,
        iterations = ROUNDS, create = true))
      eq(Nil, makes.list, "created")
      eq(true, File(path).exists, "the file")

    testcase("a key id longer than the format allows is refused"):
      val vault = fresh()
      has(threw(vault.grant(GrantSpec("k" * 256, "p", iterations = Some(ROUNDS)))),
        "longer than 255", "a long key id")
      eq(List("master"), vault.keys.map(_.key), "unchanged")

    // --- the handle -------------------------------------------------

    testcase("the key information a caller gets cannot change what the key may do"):
      val vault = fresh()
      vault.set("a.one", "x")
      vault.grant(GrantSpec("ro", "ro-phrase", List("a.one"), iterations = Some(ROUNDS)))

      val ro = openas(vault.file, "ro", "ro-phrase")

      // VaultKeyInfo is a case class of `val` fields over an immutable
      // list, so the defect the review round found - a caller flipping its
      // own `write` bit - does not compile. `copy` makes a NEW value and
      // changes nothing the vault reads.
      val mine = ro.open.copy(write = true, grants = List("a.one", "b.two"))
      eq(true, mine.write, "the copy says so")

      has(threw(ro.set("a.one", "nope")), "read-only", "still read-only")
      eq(List("a.one"), ro.open.grants, "still one grant")

    testcase("a revoked key stops reading from a cached handle"):
      val vault = fresh()
      vault.set("a.one", "x")
      vault.grant(GrantSpec("ci", "ci-phrase", List("a.one"), iterations = Some(ROUNDS)))

      val ci = openas(vault.file, "ci", "ci-phrase")
      eq(Some("x"), ci.get("a.one"), "before")

      vault.revoke("ci")
      threw(ci.get("a.one"))

    testcase("a re-granted key id does not keep the old passphrase working"):
      val vault = fresh()
      vault.set("a.one", "x")
      vault.grant(GrantSpec("ci", "first", List("a.one"), iterations = Some(ROUNDS)))

      val ci = openas(vault.file, "ci", "first")
      eq(Some("x"), ci.get("a.one"), "before")

      vault.revoke("ci")
      vault.grant(GrantSpec("ci", "second", List("a.one"), iterations = Some(ROUNDS)))

      has(threw(ci.get("a.one")), "wrong passphrase", "the old passphrase")
      eq(Some("x"), openas(vault.file, "ci", "second").get("a.one"), "the new one")

    testcase("close forgets the derived keys"):
      val vault = fresh()
      vault.set("a.one", "x")
      eq(Some("x"), vault.get("a.one"), "before")

      vault.close()
      eq(Some("x"), vault.get("a.one"), "after")

    // --- the format, across ports -----------------------------------

    // EVERY COMMITTED VAULT, not only this port's. A suite that reads only
    // the vault its own port wrote proves the reader agrees with the
    // writer beside it - which a port whose serializer and parser share a
    // mistake satisfies perfectly.
    for name <- fixtures() do
      testcase(s"the committed fixture reads, key by key: $name"):
        val file = fixture(name)

        val master = openas(file, MASTERKEY, "fixture-master")
        eq(List("api.token", "db.pass", "deep.nested.name"), master.list, "list")
        eq(Some("fixture-token"), master.get("api.token"), "api.token")
        eq(Some("fixture-pass"), master.get("db.pass"), "db.pass")
        eq(Some("fixture-deep"), master.get("deep.nested.name"), "deep")

        eq(
          List("master/true/true/[]", "reader/false/false/[api.token]",
            "writer/false/true/[db.pass]"),
          master.keys.map(_.show),
          "keys",
        )

        val reader = openas(file, "reader", "fixture-reader")
        eq(List("api.token"), reader.list, "reader list")
        eq(Some("fixture-token"), reader.get("api.token"), "reader grant")
        eq(None, reader.get("db.pass"), "reader miss")

        openas(file, "writer", "fixture-writer").set("db.pass", "written by this port")
        eq(Some("written by this port"), master.get("db.pass"), "writer")

    // --- the chain --------------------------------------------------

    testcase("a vault is one store in a chain"):
      val vault = fresh()
      vault.set("api.token", "from the vault")

      val secrets = chain(
        ProviderSpec(kind = "memory", values = Some(Map("DB_PASS" -> "from memory"))),
        ProviderSpec(kind = "minivault", file = Some(vault.file),
          passphrase = Some(MASTER)),
      )

      eq("from the vault", secrets.get("api.token"), "the vault")
      eq("from memory", secrets.get("db.pass"), "memory")
      secrets.close()

    testcase("a restricted key in a chain falls through"):
      val vault = fresh()
      vault.set("api.token", "from the vault")
      vault.set("db.pass", "in the vault, not granted")
      vault.grant(GrantSpec("ci", "ci-phrase", List("api.token"), iterations = Some(ROUNDS)))

      val secrets = chain(
        ProviderSpec(kind = "minivault", file = Some(vault.file), vaultkey = Some("ci"),
          passphrase = Some("ci-phrase")),
        ProviderSpec(kind = "memory", values = Some(Map("DB_PASS" -> "from memory"))),
      )

      eq("from the vault", secrets.get("api.token"), "the grant")
      eq("from memory", secrets.get("db.pass"), "falls through")
      secrets.close()

    testcase("the vault behind a store is reachable as an API"):
      val vault = fresh()
      vault.set("api.token", "tok01")

      val secrets = chain(
        ProviderSpec(kind = "minivault", file = Some(vault.file), passphrase = Some(MASTER)),
      )

      val api = vaultof(secrets)
      eq(List("api.token"), api.list, "list")

      api.set("db.pass", "written through the api")
      eq("written through the api", secrets.get("db.pass"), "the chain sees it")
      secrets.close()

    testcase("a named store is reached by name"):
      val vault = fresh()
      vault.set("api.token", "tok01")

      val secrets = chain(
        ProviderSpec(kind = "minivault", name = Some("app"), file = Some(vault.file),
          passphrase = Some(MASTER)),
      )

      eq(List("api.token"), vaultof(secrets, Some("app")).list, "by name")
      eq(List("api.token"), vaultof(secrets).list, "by alias")
      has(threw(vaultof(secrets, Some("minivault"))), "no minivault store named",
        "a name that is not there")
      secrets.close()

    testcase("a chain with no vault says so"):
      val secrets = chain(ProviderSpec(kind = "memory", values = Some(Map.empty)))
      has(threw(vaultof(secrets)), "no minivault store", "no vault")
      secrets.close()

    testcase("a chain missing the file is refused at construction"):
      has(threw(chain(ProviderSpec(kind = "minivault", passphrase = Some(MASTER)))),
        "a vault needs a file", "no file")
      has(threw(chain(ProviderSpec(kind = "minivault", file = Some(vaultpath())))),
        "a vault needs a passphrase", "no passphrase")

    testcase("the file is reached at the first lookup"):
      // No file, and construction still succeeds: the handle is lazy.
      val secrets = chain(
        ProviderSpec(kind = "minivault", file = Some(vaultpath()), passphrase = Some(MASTER)),
      )

      has(threw(secrets.get("api.token")), "no vault file", "at the first lookup")
      secrets.close()

    println()
    println(s"$passcount passed, $failcount failed")
    System.exit(if failcount == 0 then 0 else 1)
