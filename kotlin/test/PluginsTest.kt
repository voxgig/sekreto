// RUN: make seam
// RUN-SOME: java -cp build/seam:... PluginsTest "one plugin is enough..."
//
// THE PLUGIN SEAM, from both sides.
//
// Moving the provider kinds that open sockets and spawn processes out of
// the core made a consumer's PLUGIN LIST load-bearing: a kind nobody
// passed in is not in the catalog, and a chain naming it is refused. That
// is the intended behaviour, and it means a consumer can be broken
// without a single conformance test noticing - the conformance suite
// passes every plugin to every chain it builds, so it can never see a
// missing one. So the full set is pinned here: it holds every kind, every
// kind builds, and the CLI passes it.
//
// The kotlin half of the seam is a LINKING one, so the boundary tests
// below work on the compiled jars rather than on the source: a class
// loader over the core jar alone, and the constant pools of the classes
// in it. `make check-core` runs test/CoreOnly.kt against the same
// classpath as a whole program; this file is the assertions.
//
// A translation of python/tests/test_plugins.py, which is the model.

@file:JvmName("PluginsTest")

import com.voxgig.sekreto.AuthSpec
import com.voxgig.sekreto.BUILTINS
import com.voxgig.sekreto.KINDS
import com.voxgig.sekreto.Provider
import com.voxgig.sekreto.ProviderSpec
import com.voxgig.sekreto.Sekreto
import com.voxgig.sekreto.SekretoError
import com.voxgig.sekreto.optionsof
import com.voxgig.sekreto.providerplugin
import com.voxgig.sekreto.specof
import com.voxgig.sekreto.plugins.Plugins
import com.voxgig.sekreto.plugins.hashicorp
import java.io.File
import java.net.URL
import java.net.URLClassLoader
import java.util.zip.ZipFile
import kotlin.system.exitProcess
import voxgig.plugin.PluginError

private val PLUGINS = listOf(
    "awsparams", "awssecrets", "azuresecrets", "boru", "doppler", "gcpsecrets",
    "hashicorp", "infisical", "onepassword", "secretspec",
)

private val EVERY = (listOf("dotenv", "env", "file", "memory") + PLUGINS).sorted()

// --------------------------------------------------------- the harness

private var only: String? = null
private var passcount = 0
private var failcount = 0

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

private fun ok(what: String, condition: Boolean) {
    if (!condition) {
        throw Failed(what)
    }
}

/** The message of the SekretoError `body` must raise. */
private fun refusal(body: () -> Unit): String {
    try {
        body()
    } catch (err: SekretoError) {
        return err.message ?: ""
    }

    throw Failed("no SekretoError was raised")
}

// ------------------------------------------------------- the classpath
//
// The jars this run was given, which is how the boundary tests reach the
// artifacts rather than the source. `make seam` puts the core jar, the
// plugins jar, voxgig/plugin and the kotlin stdlib on it.

private val CLASSPATH: List<String> =
    System.getProperty("java.class.path").split(File.pathSeparator)

private fun jar(name: String): String =
    CLASSPATH.find { it.endsWith(name) }
        ?: throw Failed("$name is not on the classpath: $CLASSPATH")

/** A class loader over exactly these jars - the PLATFORM loader as its
 * parent, so nothing on this run's own classpath leaks into it. */
private fun loaderover(paths: List<String>): URLClassLoader =
    URLClassLoader(
        paths.map { File(it).toURI().toURL() }.toTypedArray<URL>(),
        ClassLoader.getPlatformClassLoader(),
    )

/** A loader that records every plugin class asked of it. */
private class Recorder(paths: List<String>) : URLClassLoader(
    paths.map { File(it).toURI().toURL() }.toTypedArray<URL>(),
    ClassLoader.getPlatformClassLoader(),
) {
    val asked = mutableListOf<String>()

    override fun loadClass(name: String, resolve: Boolean): Class<*> {
        if (name.startsWith("com.voxgig.sekreto.plugins.") && !asked.contains(name)) {
            asked.add(name)
        }
        return super.loadClass(name, resolve)
    }

    /** The plugin KINDS whose file class was loaded, by their file name. */
    fun kinds(): List<String> = asked
        .filter { it.endsWith("Kt") }
        .map { it.removePrefix("com.voxgig.sekreto.plugins.").removeSuffix("Kt").lowercase() }
        .sorted()
}

fun main(args: Array<String>) {
    if (args.isNotEmpty()) {
        only = args[0]
    }

    // ------------------------------------------------- the full set

    testcase("the full set holds every kind") {
        eq(PLUGINS, Plugins.ALL.map { it["name"] as String }.sorted(), "Plugins.ALL")
        eq(KINDS.builtin, BUILTINS.map { it["name"] as String }, "BUILTINS")
        eq(PLUGINS, KINDS.plugin.sorted(), "KINDS.plugin")
        eq(10, Plugins.ALL.size, "ten plugins")
    }

    // Naming a kind is not enough: a kind can be in the catalog and still
    // fail to build. Construction is what the CLI does before any network.
    testcase("every kind builds from a spec") {
        val chain = EVERY.map { kind ->
            ProviderSpec(
                kind = kind,
                addr = "http://127.0.0.1:8200",
                token = "t",
                dir = "/tmp",
                file = "/tmp/.env",
                values = emptyMap(),
            )
        }

        val secrets = Sekreto(providers = chain, plugins = Plugins.ALL)

        eq(EVERY, secrets.stores(), "stores")
        eq(EVERY, secrets.host.list().keys.toList().sorted(), "host.list")
        eq(setOf<Any?>("live"), secrets.host.list().values.toSet(), "every instance live")
        secrets.close()
    }

    testcase("the CLI passes the full set") {
        val src = File("cli/Cli.kt").readText()
        ok("Cli.kt imports the full set", src.contains("import com.voxgig.sekreto.plugins.Plugins"))
        ok("Cli.kt passes the full set", src.contains("Plugins.ALL"))
    }

    // ------------------------------------------- what a consumer sees

    testcase("one plugin is enough for a chain that names only it") {
        val secrets = Sekreto(
            providers = listOf(
                ProviderSpec(kind = "memory", values = mapOf("API_TOKEN" to "tok01")),
                ProviderSpec(
                    kind = "hashicorp", name = "prod",
                    addr = "https://vault.example.com", token = "t",
                ),
            ),
            plugins = listOf(hashicorp),
        )

        eq(listOf("memory", "prod"), secrets.stores(), "stores")
        eq(
            listOf("memory", "hashicorp:https://vault.example.com/secret"),
            secrets.sources(), "sources",
        )
        eq("tok01", secrets.get("api.token"), "the chain answers")

        // The plugin host is what the chain is made of, and it reads like
        // the chain: the kind, or kind$store for a named store.
        eq(
            mapOf<String, Any?>("hashicorp\$prod" to "live", "memory" to "live"),
            secrets.host.list().toMap(), "host.list",
        )
        eq(
            listOf("dotenv", "env", "file", "hashicorp", "memory"),
            secrets.catalog.names(), "catalog",
        )
        secrets.close()
    }

    testcase("a kind that was not passed in is refused, naming the fix") {
        eq(
            "sekreto: unknown provider kind: doppler" +
                " (available: dotenv, env, file, hashicorp, memory)" +
                " - doppler is a sekreto plugin, not built in: pass it in the plugins option",
            refusal {
                Sekreto(
                    providers = listOf(ProviderSpec(kind = "doppler", token = "t")),
                    plugins = listOf(hashicorp),
                )
            },
            "a plugin that was not passed",
        )

        // A kind nobody ships is a typo, and gets no such hint.
        eq(
            "sekreto: unknown provider kind: vualt (available: dotenv, env, file, memory)",
            refusal { Sekreto(providers = listOf(ProviderSpec(kind = "vualt"))) },
            "a typo",
        )
    }

    // Two providers MAY share a store name - a directed read walks both,
    // and the spec pins it - but an instance ref may not, so the second
    // gets a numbered tag from the host and keeps its store name.
    testcase("a repeated store name keeps the store and numbers the instance") {
        val secrets = Sekreto(
            providers = listOf(
                ProviderSpec(kind = "memory", values = emptyMap()),
                ProviderSpec(kind = "memory", values = mapOf("API_TOKEN" to "second")),
                ProviderSpec(kind = "memory", name = "pair", values = emptyMap()),
                ProviderSpec(kind = "memory", name = "pair", values = mapOf("API_TOKEN" to "pair2")),
            ),
        )

        eq(listOf("memory", "pair"), secrets.stores(), "stores")
        eq(
            listOf("memory", "memory\$1", "memory\$2", "memory\$pair"),
            secrets.host.list().keys.toList(), "host.list",
        )
        eq("second", secrets.getfrom("memory", "api.token"), "the second memory answers")
        eq("pair2", secrets.getfrom("pair", "api.token"), "the second pair answers")
        secrets.close()
    }

    testcase("a store name must be a valid tag") {
        eq(
            "sekreto: invalid store name: my store",
            refusal {
                Sekreto(
                    providers = listOf(
                        ProviderSpec(kind = "memory", name = "my store", values = emptyMap()),
                    ),
                )
            },
        )
    }

    // A provider that refuses its own configuration raises a SekretoError
    // from inside the plugin's `define`. The spec pins that message byte
    // for byte, so it must come back out of the host as itself - not
    // wrapped as plugin_define_failed, and not as a PluginError.
    testcase("a SekretoError raised in define comes back out as itself") {
        eq(
            "sekreto: hashicorp: unsupported kv version: 3",
            refusal {
                Sekreto(
                    providers = listOf(
                        ProviderSpec(
                            kind = "hashicorp", addr = "http://127.0.0.1:1",
                            token = "t", kv = 3,
                        ),
                    ),
                    plugins = listOf(hashicorp),
                )
            },
        )
    }

    // ...and any other error is not sekreto's to rewrite: it surfaces as
    // the host reports it, naming the instance and the cause.
    testcase("any other error raised in define is the host's report of it") {
        val broken = providerplugin("broken") { throw IllegalStateException("boom") }

        val err = try {
            Sekreto(providers = listOf(ProviderSpec(kind = "broken")), plugins = listOf(broken))
            throw Failed("no error was raised")
        } catch (caught: PluginError) {
            caught
        }

        eq("plugin_define_failed", err.code, "code")
        ok("names the cause: ${err.message}", (err.message ?: "").contains("boom"))
        ok("names the instance: ${err.message}", (err.message ?: "").contains("broken"))
    }

    testcase("a custom kind is one providerplugin call") {
        class Shouty(private val values: Map<String, String>) : Provider {
            override fun lookup(name: String): String? = values[name.uppercase()]
            override fun describe(): String = "shouty"
        }

        val shouty = providerplugin("shouty") { spec -> Shouty(spec.values ?: emptyMap()) }

        val secrets = Sekreto(
            providers = listOf(ProviderSpec(kind = "shouty", values = mapOf("API.TOKEN" to "loud"))),
            plugins = listOf(shouty),
        )

        eq("loud", secrets.get("api.token"), "the custom kind answers")
        eq(mapOf<String, Any?>("shouty" to "live"), secrets.host.list().toMap(), "host.list")
        secrets.close()
    }

    // A plugin that names a built-in kind replaces it: that is how a host
    // substitutes an implementation, and never an accident, because the
    // four names are documented.
    testcase("a plugin may replace a built-in kind") {
        class Replaced : Provider {
            override fun lookup(name: String): String = "replaced"
            override fun describe(): String = "memory"
        }

        val secrets = Sekreto(
            providers = listOf(
                ProviderSpec(kind = "memory", values = mapOf("API_TOKEN" to "original")),
            ),
            plugins = listOf(providerplugin("memory") { Replaced() }),
        )

        eq("replaced", secrets.get("api.token"))
        eq(4, secrets.catalog.names().size, "still four kinds")
        secrets.close()
    }

    testcase("close tears the chain down and keeps redaction") {
        val secrets = Sekreto(
            providers = listOf(ProviderSpec(kind = "memory", values = mapOf("API_TOKEN" to "tok01"))),
        )
        eq("tok01", secrets.get("api.token"))

        secrets.close()

        eq(0, secrets.host.list().size, "the host is empty")
        eq(emptyList(), secrets.stores(), "no stores")
        eq(null, secrets.tryget("api.token"), "nothing answers")
        eq("token=[redacted]", secrets.redact("token=tok01"), "redaction survives")
    }

    // A definition that is not a `providerplugin` - one whose `define`
    // exports no provider - is refused by name. plugin runs a `define`
    // that is not a function SILENTLY (its `run` returns when the callback
    // is not a Function1), so without this check the chain would carry a
    // hole and the first lookup would blame the wrong thing. This is
    // kotlin's shape of python's "a module passed as a plugin is refused":
    // the mistake a static type system still lets through.
    testcase("a definition that exports no provider is refused") {
        eq(
            "sekreto: plugin shouty exported no provider",
            refusal {
                Sekreto(
                    providers = listOf(ProviderSpec(kind = "shouty")),
                    plugins = listOf(mapOf("name" to "shouty")),
                )
            },
        )
    }

    // The spec crosses the boundary as plugin's own value model - a map of
    // strings to null, Double, String and Map - and comes back typed. A
    // field added to `optionsof` and forgotten in `specof` would be lost
    // in silence, and only for the kinds no conformance case exercises.
    testcase("a provider spec survives the plugin boundary") {
        val full = ProviderSpec(
            kind = "hashicorp", name = "prod", prefix = "P_", file = "f", dir = "d",
            values = mapOf("A" to "1"), addr = "https://a", token = "t", mount = "m",
            kv = 1, vaultnamespace = "ns",
            auth = AuthSpec(
                method = "approle", mount = "am", role = "r", jwt = "j",
                jwtfile = "jf", roleid = "ri", secretid = "si",
            ),
            command = "c", profile = "pr", backend = "b", reason = "re",
            namespace = "n", home = "h", region = "eu", keyid = "k", secret = "s",
            session = "se", project = "pj", vault = "v", tenant = "tn",
            clientid = "ci", clientsecret = "cs", loginaddr = "la", imdsaddr = "ia",
            metadataaddr = "ma", apiversion = "7.4", config = "cf",
            environment = "dev", path = "/p",
        )

        eq(full, specof(optionsof(full)), "the round trip")

        // Every field is set above, so nothing may be missing from the
        // options either - a field dropped from BOTH sides would round
        // trip and still be gone.
        eq(34, optionsof(full).size, "every ProviderSpec field crossed")
        eq(7, (optionsof(full)["auth"] as Map<*, *>).size, "every AuthSpec field crossed")
    }

    // ------------------------------------------------- the boundary

    // The core does not reach a plugin: a class loader over voxgig/plugin
    // and the CORE JAR ALONE builds a chain of built-in kinds, and cannot
    // even name a plugin class. `make check-core` runs the whole of
    // test/CoreOnly.kt against that classpath; this is the assertion.
    testcase("the core imports no plugin") {
        val coreonly = listOf(jar("voxgigplugin.jar"), jar("sekreto.jar"), jar("kotlin-stdlib.jar"))

        loaderover(coreonly).use { loader ->
            // The core loads, and its four built-in definitions with it.
            val builtins = loader.loadClass("com.voxgig.sekreto.ProvidersKt")
                .getMethod("getBUILTINS").invoke(null) as List<*>
            eq(4, builtins.size, "four built-ins, with no plugin jar in reach")

            for (kind in PLUGINS + listOf("Plugins", "Sigv4", "Httpjson")) {
                val name = "com.voxgig.sekreto.plugins." +
                    kind.replaceFirstChar { it.uppercase() } + "Kt"
                val found = try {
                    loader.loadClass(name)
                    true
                } catch (err: ClassNotFoundException) {
                    false
                }
                ok("$name is not reachable from the core", !found)
            }
        }

        // ...and no class IN the core jar so much as mentions one, nor a
        // socket, a cipher or a child process. A class file carries every
        // type it refers to as a UTF8 constant, so the bytes are the
        // record - including for a reference only reflection would reach.
        val banned = listOf(
            "com/voxgig/sekreto/plugins", "java/net/http", "java/net/Socket",
            "javax/crypto", "java/security/MessageDigest", "java/lang/ProcessBuilder",
        )

        var classes = 0
        ZipFile(jar("sekreto.jar")).use { zip ->
            for (entry in zip.entries()) {
                if (!entry.name.endsWith(".class")) {
                    continue
                }
                classes++
                val bytes = zip.getInputStream(entry).use { it.readBytes() }
                val text = String(bytes, Charsets.ISO_8859_1)
                for (pattern in banned) {
                    ok("${entry.name} reaches $pattern", !text.contains(pattern))
                }
            }
        }
        ok("the core jar has classes to check", 0 < classes)
    }

    // ...and one plugin loads only itself. Reaching for `hashicorp` must
    // not drag in the AWS signer and eight other vault clients - which is
    // what a full-set import in the plugins package would do, and what the
    // python port's package initializer used to do.
    testcase("one plugin loads only itself") {
        val all = listOf(
            jar("voxgigplugin.jar"), jar("sekreto.jar"),
            jar("sekreto-plugins.jar"), jar("kotlin-stdlib.jar"),
        )

        val recorder = Recorder(all)
        recorder.use { loader ->
            // Initialize the file class that holds `val hashicorp`, which
            // is what `import ...plugins.hashicorp` compiles to a read of.
            Class.forName("com.voxgig.sekreto.plugins.HashicorpKt", true, loader)
        }

        eq(listOf("hashicorp"), recorder.kinds(), "the plugin kinds loaded")
        ok(
            "no aws, doppler or infisical class was loaded: ${recorder.asked}",
            recorder.asked.none { it.contains("Aws") || it.contains("Doppler") || it.contains("Infisical") },
        )
    }

    // The full set is what pulls all ten in, and reaching for it is the
    // deliberate act of a CLI or a test harness rather than a side effect
    // of importing the library.
    testcase("the full set is loaded on demand") {
        val all = listOf(
            jar("voxgigplugin.jar"), jar("sekreto.jar"),
            jar("sekreto-plugins.jar"), jar("kotlin-stdlib.jar"),
        )

        val recorder = Recorder(all)
        val loaded = recorder.use { loader ->
            val cls = Class.forName("com.voxgig.sekreto.plugins.Plugins", true, loader)
            (cls.getField("ALL").get(null) as List<*>).size
        }

        eq(10, loaded, "the full set is ten")
        eq(
            listOf(
                "aws", "azuresecrets", "boru", "doppler", "gcpsecrets",
                "hashicorp", "infisical", "onepassword", "secretspec",
            ),
            recorder.kinds().filter { "plugins" != it && "httpjson" != it && "sigv4" != it },
            "reaching the full set loads every plugin file",
        )
    }

    println("\n$passcount passed, $failcount failed")

    exitProcess(if (0 == failcount) 0 else 1)
}
