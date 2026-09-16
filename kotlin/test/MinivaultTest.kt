// The mini vault, from both sides: the store a chain reads, and the
// programmatic API a plugin definition can publish beside it.
//
// The vault is not in spec/sekreto.json and cannot be until every port
// ships the kind. The spec runs against all twenty-three of them, so an
// entry naming `minivault` would fail the ports that have no such
// provider. What the shared corpus would have carried is here instead,
// plus the one thing it could not carry either way: a file written by
// this port and read by another, pinned by test/fixture/*.skmv.

import com.voxgig.sekreto.ProviderSpec
import com.voxgig.sekreto.Sekreto
import com.voxgig.sekreto.SekretoError
import com.voxgig.sekreto.plugins.GrantSpec
import com.voxgig.sekreto.plugins.MASTERKEY
import com.voxgig.sekreto.plugins.MiniVault
import com.voxgig.sekreto.plugins.VaultOptions
import com.voxgig.sekreto.plugins.createvault
import com.voxgig.sekreto.plugins.minivault
import com.voxgig.sekreto.plugins.openvault
import com.voxgig.sekreto.plugins.vaultof
import java.io.File
import java.nio.charset.StandardCharsets
import java.nio.file.Files
import java.nio.file.Path
import java.nio.file.StandardCopyOption
import kotlin.system.exitProcess

private const val MASTER = "master-passphrase"

/** The rounds every test here uses. The library default is 210000, which
 * is the point of PBKDF2 and the wrong thing to pay per assertion. */
private const val ROUNDS = 1000

private var only: String? = null
private var passcount = 0
private var failcount = 0
private lateinit var work: Path
private var count = 0

private class Failed(message: String) : RuntimeException(message)

private fun testcase(name: String, body: () -> Unit) {
    val filter = only
    if (null != filter && name != filter) {
        return
    }

    try {
        body()
        passcount++
        println("ok   - $name")
    } catch (err: Throwable) {
        failcount++
        println("FAIL - $name")
        println("       " + (err.message ?: err.toString()).replace("\n", "\n       "))
    }
}

private fun <T> eq(want: T, got: T, what: String = "") {
    if (want != got) {
        throw Failed("$what\n  want: $want\n  got:  $got")
    }
}

private fun has(got: String, want: String, what: String) {
    if (!got.contains(want)) {
        throw Failed("$what\n  want to contain: $want\n  got: $got")
    }
}

/** The message of the SekretoError the body raised. */
private fun threw(body: () -> Unit): String {
    try {
        body()
    } catch (err: SekretoError) {
        return err.message ?: ""
    }
    throw Failed("want a SekretoError, nothing was thrown")
}

private fun vaultpath(): String {
    count++
    return work.resolve("vault$count.skmv").toString()
}

private fun fresh(): MiniVault =
    createvault(VaultOptions(file = vaultpath(), passphrase = MASTER, iterations = ROUNDS))

private fun openas(file: String, key: String?, phrase: String): MiniVault =
    openvault(VaultOptions(file = file, key = key ?: MASTERKEY, passphrase = phrase))

/** Where the committed vaults live, found by walking up. */
private fun fixturedir(): File {
    var dir = File(System.getProperty("user.dir")).absoluteFile

    for (step in 0 until 8) {
        val cand = File(File(dir, "test"), "fixture")
        if (File(cand, "minivault.skmv").exists()) {
            return cand
        }
        dir = dir.parentFile ?: break
    }
    throw Failed("sekreto: fixture directory not found")
}

/** EVERY committed vault, read off disk rather than listed here. A
 * hard-coded list is one more place to edit when a port lands, and the
 * edit that gets forgotten is the one that makes this suite stop checking
 * the port that just arrived. */
private fun fixtures(): List<String> =
    fixturedir().listFiles { _, n -> n.endsWith(".skmv") }!!.map { it.name }.sorted()

/** A committed vault, copied so that a test which writes cannot edit the
 * bytes the format contract is made of. */
private fun fixture(name: String): String {
    val mine = vaultpath()
    Files.copy(File(fixturedir(), name).toPath(), Path.of(mine),
        StandardCopyOption.REPLACE_EXISTING)
    return mine
}

private fun chain(vararg providers: ProviderSpec): Sekreto =
    Sekreto(providers = providers.toList(), plugins = listOf(minivault))

private fun show(one: com.voxgig.sekreto.plugins.VaultKeyInfo): String =
    "${one.key}/${one.master}/${one.write}/${one.grants}"

fun main(args: Array<String>) {
    if (args.isNotEmpty()) {
        only = args[0]
    }

    work = Files.createTempDirectory("sekreto-minivault")

    // --- the file -----------------------------------------------------

    testcase("a new vault holds nothing") {
        val vault = fresh()
        eq(emptyList<String>(), vault.list(), "list")
        eq("master", vault.key(), "key")
        eq("master/true/true/[]", show(vault.open()), "open")
    }

    testcase("a written secret comes back") {
        val vault = fresh()
        vault.set("api.token", "tok01")
        vault.set("db.pass", "hunter2")

        eq("tok01", vault.get("api.token"), "get")
        eq(listOf("api.token", "db.pass"), vault.list(), "list")
        eq(true, vault.has("api.token"), "has")
        eq(false, vault.has("nope"), "has nope")
        eq(null, vault.get("nope"), "get nope")

        eq("tok01", openas(vault.file(), null, MASTER).get("api.token"), "a new handle")
    }

    testcase("the file is binary and names nothing in plaintext") {
        val vault = fresh()
        vault.set("api.token", "tok01")
        val raw = String(Files.readAllBytes(Path.of(vault.file())), StandardCharsets.ISO_8859_1)

        eq("SKMV", raw.substring(0, 4), "magic")
        // The key ids are plaintext and documented as such; a secret name
        // is not, and neither is a value.
        eq(true, raw.contains("master"), "the key id is plaintext")
        eq(false, raw.contains("api.token"), "the name is not")
        eq(false, raw.contains("tok01"), "the value is not")
    }

    testcase("rewriting a name replaces it") {
        val vault = fresh()
        vault.set("api.token", "one")
        vault.set("api.token", "two")

        eq("two", vault.get("api.token"), "get")
        eq(listOf("api.token"), vault.list(), "list")
    }

    testcase("remove drops a name") {
        val vault = fresh()
        vault.set("api.token", "tok01")
        vault.remove("api.token")

        eq(emptyList<String>(), vault.list(), "list")
        eq(null, vault.get("api.token"), "get")
        has(threw { vault.remove("api.token") }, "no such secret", "remove again")
    }

    testcase("a bad name is refused") {
        val vault = fresh()
        threw { vault.get("") }
        threw { vault.set("bad name", "x") }
    }

    // --- the keys -----------------------------------------------------

    testcase("a restricted key reads its grants") {
        val vault = fresh()
        vault.set("api.token", "tok01")
        vault.set("db.pass", "hunter2")
        vault.grant(GrantSpec("ci", "ci-phrase", listOf("api.token"), iterations = ROUNDS))

        val ci = openas(vault.file(), "ci", "ci-phrase")
        eq(listOf("api.token"), ci.list(), "list")
        eq("tok01", ci.get("api.token"), "the grant")
        // Not an error: the vault answers as the key that opened it, so a
        // name outside the grant is a miss.
        eq(null, ci.get("db.pass"), "outside the grant")
        eq("ci/false/false/[api.token]", show(ci.open()), "open")
    }

    testcase("a read-only key refuses to write") {
        val vault = fresh()
        vault.set("db.pass", "hunter2")
        vault.grant(GrantSpec("ro", "ro-phrase", listOf("db.pass"), iterations = ROUNDS))
        vault.grant(GrantSpec("rw", "rw-phrase", listOf("db.pass"), true, ROUNDS))

        val ro = openas(vault.file(), "ro", "ro-phrase")
        has(threw { ro.set("db.pass", "nope") }, "read-only", "a read-only key")

        openas(vault.file(), "rw", "rw-phrase").set("db.pass", "changed")
        eq("changed", vault.get("db.pass"), "a write key")
    }

    testcase("a restricted key cannot write an ungranted name") {
        val vault = fresh()
        vault.set("db.pass", "hunter2")
        vault.grant(GrantSpec("rw", "rw-phrase", listOf("db.pass"), true, ROUNDS))

        val rw = openas(vault.file(), "rw", "rw-phrase")
        has(threw { rw.set("other.name", "x") }, "was not granted", "ungranted")
    }

    testcase("a granted name that does not exist yet") {
        val vault = fresh()
        vault.grant(GrantSpec("ci", "ci-phrase", listOf("later.name"), iterations = ROUNDS))

        val ci = openas(vault.file(), "ci", "ci-phrase")
        eq(emptyList<String>(), ci.list(), "before")
        eq(null, ci.get("later.name"), "before")

        vault.set("later.name", "here now")

        eq("here now", ci.get("later.name"), "after")
        eq(listOf("later.name"), ci.list(), "after")
    }

    testcase("the master lists every key") {
        val vault = fresh()
        vault.grant(GrantSpec("ro", "p1", listOf("a.one"), iterations = ROUNDS))
        vault.grant(GrantSpec("rw", "p2", listOf("a.one", "b.two"), true, ROUNDS))

        eq(
            listOf(
                "master/true/true/[]", "ro/false/false/[a.one]",
                "rw/false/true/[a.one, b.two]",
            ),
            vault.keys().map { show(it) },
            "keys",
        )
    }

    testcase("the master-only methods refuse a restricted key") {
        val vault = fresh()
        vault.set("a.one", "x")
        vault.grant(GrantSpec("ci", "ci-phrase", listOf("a.one"), true, ROUNDS))

        val ci = openas(vault.file(), "ci", "ci-phrase")

        has(threw { ci.keys() }, "master key", "keys")
        has(threw { ci.remove("a.one") }, "master key", "remove")
        has(threw { ci.rotate() }, "master key", "rotate")
        has(threw { ci.revoke("master") }, "master key", "revoke")
        has(threw { ci.grant(GrantSpec("x", "y")) }, "master key", "grant")
    }

    testcase("a repeated key id is refused") {
        val vault = fresh()
        vault.grant(GrantSpec("ci", "one", iterations = ROUNDS))
        has(
            threw { vault.grant(GrantSpec("ci", "two", iterations = ROUNDS)) },
            "key already exists", "a repeated id",
        )
    }

    testcase("revoke drops a key") {
        val vault = fresh()
        vault.set("a.one", "x")
        vault.grant(GrantSpec("ci", "ci-phrase", listOf("a.one"), iterations = ROUNDS))

        val ci = openas(vault.file(), "ci", "ci-phrase")
        eq("x", ci.get("a.one"), "before")

        vault.revoke("ci")

        has(threw { ci.get("a.one") }, "no such key", "after")
        has(threw { vault.revoke("master") }, "cannot revoke itself", "itself")
    }

    testcase("rotate keeps the secrets") {
        val vault = fresh()
        vault.set("api.token", "tok01")
        vault.set("db.pass", "hunter2")
        vault.grant(GrantSpec("ci", "ci-phrase", listOf("api.token"), iterations = ROUNDS))

        vault.rotate()

        eq(listOf("api.token", "db.pass"), vault.list(), "list")
        eq("tok01", vault.get("api.token"), "api.token")
        eq("hunter2", vault.get("db.pass"), "db.pass")
        eq(listOf("master"), vault.keys().map { it.key }, "keys")

        threw { openas(vault.file(), "ci", "ci-phrase").get("api.token") }
    }

    // --- refusals -----------------------------------------------------

    testcase("a wrong passphrase and a missing file refuse") {
        val vault = fresh()
        vault.set("a.one", "x")

        has(threw { openas(vault.file(), null, "wrong").get("a.one") },
            "wrong passphrase", "a wrong passphrase")
        threw { openas(vault.file(), "nope", MASTER).get("a.one") }
        has(threw { openas(work.resolve("nothing.skmv").toString(), null, MASTER).get("a.one") },
            "no vault file", "a missing file")
    }

    testcase("a damaged file is refused") {
        val vault = fresh()
        vault.set("a.one", "x")
        val raw = Files.readAllBytes(Path.of(vault.file()))

        val short = vaultpath()
        Files.write(Path.of(short), raw.copyOf(raw.size - 10))
        has(threw { openas(short, null, MASTER).get("a.one") }, "truncated", "short")

        val trailing = vaultpath()
        Files.write(Path.of(trailing), raw + "junk".toByteArray(StandardCharsets.ISO_8859_1))
        has(threw { openas(trailing, null, MASTER).get("a.one") }, "trailing bytes", "trailing")

        val notvault = vaultpath()
        val wrong = raw.copyOf()
        "NOPE".toByteArray(StandardCharsets.ISO_8859_1).copyInto(wrong)
        Files.write(Path.of(notvault), wrong)
        has(threw { openas(notvault, null, MASTER).get("a.one") }, "not a vault file", "magic")
    }

    testcase("creating over an existing vault is refused") {
        val vault = fresh()
        has(
            threw {
                createvault(VaultOptions(file = vault.file(), passphrase = MASTER,
                    iterations = ROUNDS))
            },
            "already exists", "createvault over one",
        )
    }

    testcase("a vault needs a file and a passphrase") {
        threw { openvault(VaultOptions(file = "", passphrase = MASTER)) }
        threw { openvault(VaultOptions(file = vaultpath(), passphrase = "")) }
    }

    // An EMPTY key is no key, so it means `master`. It is not a contrived
    // case: the CLI reads SEKRETO_VAULT_KEY, and an unset shell variable
    // expands to the empty string rather than to nothing at all - and `?:`
    // answers for null alone.
    // TWO HANDLES ON ONE FILE, WRITING AT ONCE, LOSE NOTHING. Each
    // MiniVault is its own object with its own snapshot, so without the
    // shared per-path lock both threads finish `load()` before either
    // saves and the second rename discards the first one's secret while
    // reporting success. DOCS.md promises this within one process.
    testcase("two handles writing at once lose nothing") {
        val vault = fresh()
        val path = vault.file()
        val rounds = 40
        val broke = java.util.Collections.synchronizedList(mutableListOf<Throwable>())

        val writer = { tag: String ->
            Thread {
                try {
                    val mine = openvault(VaultOptions(file = path, passphrase = MASTER))
                    for (round in 0 until rounds) {
                        mine.set("t$tag.n$round", "v$round")
                    }
                } catch (err: Throwable) {
                    broke.add(err)
                }
            }
        }

        val one = writer("one")
        val two = writer("two")
        one.start()
        two.start()
        one.join()
        two.join()

        eq(emptyList<String>(), broke.map { it.toString() }, "a writer raised")
        eq(2 * rounds, vault.list().size, "every write survived")
    }

    testcase("an empty key means the master key") {
        val vault = fresh()
        vault.set("api.token", "tok01")

        val opened = openvault(VaultOptions(file = vault.file(), key = "", passphrase = MASTER))

        eq("tok01", opened.get("api.token"), "api.token")
        eq("master", opened.open().key, "key")
    }

    testcase("create makes the file only when asked") {
        val path = vaultpath()

        val refuses = openvault(VaultOptions(file = path, passphrase = MASTER,
            iterations = ROUNDS))
        threw { refuses.list() }
        eq(false, File(path).exists(), "no file")

        val makes = openvault(VaultOptions(file = path, passphrase = MASTER,
            iterations = ROUNDS, create = true))
        eq(emptyList<String>(), makes.list(), "created")
        eq(true, File(path).exists(), "the file")
    }

    testcase("a key id longer than the format allows is refused") {
        val vault = fresh()
        has(
            threw { vault.grant(GrantSpec("k".repeat(256), "p", iterations = ROUNDS)) },
            "longer than 255", "a long key id",
        )
        eq(listOf("master"), vault.keys().map { it.key }, "unchanged")
    }

    // --- the handle ---------------------------------------------------

    testcase("the key information a caller gets cannot change what the key may do") {
        val vault = fresh()
        vault.set("a.one", "x")
        vault.grant(GrantSpec("ro", "ro-phrase", listOf("a.one"), iterations = ROUNDS))

        val ro = openas(vault.file(), "ro", "ro-phrase")

        // VaultKeyInfo is a data class of `val` fields over an immutable
        // list, so the defect the review round found - a caller flipping
        // its own `write` bit - does not compile. `copy` makes a NEW value
        // and changes nothing the vault reads.
        val mine = ro.open().copy(write = true, grants = listOf("a.one", "b.two"))
        eq(true, mine.write, "the copy says so")

        has(threw { ro.set("a.one", "nope") }, "read-only", "still read-only")
        eq(listOf("a.one"), ro.open().grants, "still one grant")
    }

    testcase("a revoked key stops reading from a cached handle") {
        val vault = fresh()
        vault.set("a.one", "x")
        vault.grant(GrantSpec("ci", "ci-phrase", listOf("a.one"), iterations = ROUNDS))

        val ci = openas(vault.file(), "ci", "ci-phrase")
        eq("x", ci.get("a.one"), "before")

        vault.revoke("ci")
        threw { ci.get("a.one") }
    }

    testcase("a re-granted key id does not keep the old passphrase working") {
        val vault = fresh()
        vault.set("a.one", "x")
        vault.grant(GrantSpec("ci", "first", listOf("a.one"), iterations = ROUNDS))

        val ci = openas(vault.file(), "ci", "first")
        eq("x", ci.get("a.one"), "before")

        vault.revoke("ci")
        vault.grant(GrantSpec("ci", "second", listOf("a.one"), iterations = ROUNDS))

        has(threw { ci.get("a.one") }, "wrong passphrase", "the old passphrase")
        eq("x", openas(vault.file(), "ci", "second").get("a.one"), "the new one")
    }

    testcase("close forgets the derived keys") {
        val vault = fresh()
        vault.set("a.one", "x")
        eq("x", vault.get("a.one"), "before")

        vault.close()
        eq("x", vault.get("a.one"), "after")
    }

    // --- the format, across ports -------------------------------------

    // EVERY COMMITTED VAULT, not only this port\'s. A suite that reads only
    // the vault its own port wrote proves the reader agrees with the
    // writer beside it - which a port whose serializer and parser share a
    // mistake satisfies perfectly.
    for (name in fixtures()) {
        testcase("the committed fixture reads, key by key: $name") {
            val file = fixture(name)

            val master = openas(file, null, "fixture-master")
            eq(listOf("api.token", "db.pass", "deep.nested.name"), master.list(), "list")
            eq("fixture-token", master.get("api.token"), "api.token")
            eq("fixture-pass", master.get("db.pass"), "db.pass")
            eq("fixture-deep", master.get("deep.nested.name"), "deep")

            eq(
                listOf(
                    "master/true/true/[]", "reader/false/false/[api.token]",
                    "writer/false/true/[db.pass]",
                ),
                master.keys().map { show(it) },
                "keys",
            )

            val reader = openas(file, "reader", "fixture-reader")
            eq(listOf("api.token"), reader.list(), "reader list")
            eq("fixture-token", reader.get("api.token"), "reader grant")
            eq(null, reader.get("db.pass"), "reader miss")

            openas(file, "writer", "fixture-writer").set("db.pass", "written by this port")
            eq("written by this port", master.get("db.pass"), "writer")
        }
    }

    // --- the chain ----------------------------------------------------

    testcase("a vault is one store in a chain") {
        val vault = fresh()
        vault.set("api.token", "from the vault")

        val secrets = chain(
            ProviderSpec(kind = "memory", values = mapOf("DB_PASS" to "from memory")),
            ProviderSpec(kind = "minivault", file = vault.file(), passphrase = MASTER),
        )

        eq("from the vault", secrets.get("api.token"), "the vault")
        eq("from memory", secrets.get("db.pass"), "memory")
        secrets.close()
    }

    testcase("a restricted key in a chain falls through") {
        val vault = fresh()
        vault.set("api.token", "from the vault")
        vault.set("db.pass", "in the vault, not granted")
        vault.grant(GrantSpec("ci", "ci-phrase", listOf("api.token"), iterations = ROUNDS))

        val secrets = chain(
            ProviderSpec(kind = "minivault", file = vault.file(), vaultkey = "ci",
                passphrase = "ci-phrase"),
            ProviderSpec(kind = "memory", values = mapOf("DB_PASS" to "from memory")),
        )

        eq("from the vault", secrets.get("api.token"), "the grant")
        eq("from memory", secrets.get("db.pass"), "falls through")
        secrets.close()
    }

    testcase("the vault behind a store is reachable as an API") {
        val vault = fresh()
        vault.set("api.token", "tok01")

        val secrets = chain(
            ProviderSpec(kind = "minivault", file = vault.file(), passphrase = MASTER),
        )

        val api = vaultof(secrets)
        eq(listOf("api.token"), api.list(), "list")

        api.set("db.pass", "written through the api")
        eq("written through the api", secrets.get("db.pass"), "the chain sees it")
        secrets.close()
    }

    testcase("a named store is reached by name") {
        val vault = fresh()
        vault.set("api.token", "tok01")

        val secrets = chain(
            ProviderSpec(kind = "minivault", name = "app", file = vault.file(),
                passphrase = MASTER),
        )

        eq(listOf("api.token"), vaultof(secrets, "app").list(), "by name")
        eq(listOf("api.token"), vaultof(secrets).list(), "by alias")
        has(threw { vaultof(secrets, "minivault") }, "no minivault store named",
            "a name that is not there")
        secrets.close()
    }

    testcase("a chain with no vault says so") {
        val secrets = chain(ProviderSpec(kind = "memory", values = emptyMap()))
        has(threw { vaultof(secrets) }, "no minivault store", "no vault")
        secrets.close()
    }

    testcase("a chain missing the file is refused at construction") {
        has(threw { chain(ProviderSpec(kind = "minivault", passphrase = MASTER)) },
            "a vault needs a file", "no file")
        has(threw { chain(ProviderSpec(kind = "minivault", file = vaultpath())) },
            "a vault needs a passphrase", "no passphrase")
    }

    testcase("the file is reached at the first lookup") {
        // No file, and construction still succeeds: the handle is lazy.
        val secrets = chain(
            ProviderSpec(kind = "minivault", file = vaultpath(), passphrase = MASTER),
        )

        has(threw { secrets.get("api.token") }, "no vault file", "at the first lookup")
        secrets.close()
    }

    println()
    println("$passcount passed, $failcount failed")
    exitProcess(if (0 == failcount) 0 else 1)
}
