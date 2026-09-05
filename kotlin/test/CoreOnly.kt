// RUN: make check-core
//
// THE CORE, RUN WITH THE PLUGINS ABSENT.
//
// This file is compiled and run against a classpath that holds
// voxgig/plugin and `build/sekreto.jar` and NOTHING ELSE -
// `build/sekreto-plugins.jar` is not on it. So the proof is the JVM's
// rather than a reviewer's:
//
//   - a core that NAMED a plugin would not compile here, because the
//     class it named is not on the classpath;
//   - a core that reached one at run time - a reflective load, a lazily
//     initialised holder - would throw NoClassDefFoundError below;
//   - and a chain of the four built-in kinds must work anyway, which is
//     the promise the split makes to an app whose chain is
//     [dotenv, env].
//
// It is the kotlin analogue of python's `test_the_core_imports_no_plugin`
// (a fresh interpreter listing sys.modules) and go's linking boundary.
// `corecheck.sh` greps the same jar for a socket, a cipher and a
// subprocess; between them they cover naming and reaching.

@file:JvmName("CoreOnly")

import com.voxgig.sekreto.BUILTINS
import com.voxgig.sekreto.KINDS
import com.voxgig.sekreto.ProviderSpec
import com.voxgig.sekreto.Sekreto
import com.voxgig.sekreto.SekretoError
import java.io.File
import kotlin.system.exitProcess

private var failed = 0

private fun check(what: String, ok: Boolean) {
    if (ok) {
        println("ok   - $what")
    } else {
        failed++
        println("FAIL - $what")
    }
}

private fun <T> checkeq(what: String, want: T, got: T) {
    check("$what" + if (want == got) "" else " (want $want, got $got)", want == got)
}

fun main() {
    val dir = File(System.getProperty("java.io.tmpdir"), "sekreto-coreonly")
    dir.mkdirs()
    File(dir, ".env").writeText("API_TOKEN=fromdotenv\n")
    File(dir, "DB_PASS").writeText("fromfile\n")

    // The four built-in kinds, in one chain, with no plugin anywhere on
    // the classpath. If the core reached a plugin to build any of them,
    // this line would not survive class loading.
    val secrets = Sekreto(
        providers = listOf(
            ProviderSpec(kind = "memory", values = mapOf("API_KEY" to "frommemory")),
            ProviderSpec(kind = "dotenv", file = File(dir, ".env").path),
            ProviderSpec(kind = "file", dir = dir.path),
            ProviderSpec(kind = "env", prefix = "SEKRETO_CORE_"),
        ),
    )

    checkeq("the four built-in kinds are the catalog", KINDS.builtin.sorted(), secrets.catalog.names())
    checkeq("the built-in definitions are four", 4, BUILTINS.size)
    checkeq("memory answers", "frommemory", secrets.get("api.key"))
    checkeq("dotenv answers", "fromdotenv", secrets.get("api.token"))
    checkeq("file answers", "fromfile", secrets.get("db.pass"))
    checkeq("the chain is four stores", listOf("memory", "dotenv", "file", "env"), secrets.stores())
    checkeq("redaction still works", "t=[redacted]", secrets.redact("t=fromdotenv"))

    // ...and a plugin kind is refused HERE TOO, naming the fix. The core
    // knows the ten names without linking one of them: KINDS.plugin is a
    // list of strings.
    val refused = try {
        secrets.host // touched so the host is real, not elided
        Sekreto(providers = listOf(ProviderSpec(kind = "hashicorp", addr = "https://v", token = "t")))
        "no error"
    } catch (err: SekretoError) {
        err.message ?: ""
    }

    checkeq(
        "a plugin kind is refused, naming the fix",
        "sekreto: unknown provider kind: hashicorp (available: dotenv, env, file, memory)" +
            " - hashicorp is a sekreto plugin, not built in: pass it in the plugins option",
        refused,
    )

    // The class is not merely unloaded - it is not on this classpath at
    // all, which is what makes every check above a statement about the
    // artifact rather than about class-loading order.
    val absent = try {
        Class.forName("com.voxgig.sekreto.plugins.HashicorpKt")
        false
    } catch (err: ClassNotFoundException) {
        true
    }

    check("no plugin class is on the core classpath", absent)

    secrets.close()
    checkeq("close empties the host", 0, secrets.host.list().size)

    println(if (0 == failed) "\ncore: the core runs with the plugins absent" else "\ncore: $failed failed")

    exitProcess(if (0 == failed) 0 else 1)
}
