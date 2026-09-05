// RUN: make check-core
//
// THE CORE, RUN WITH THE PLUGINS ABSENT.
//
// This file is compiled and run against a classpath that holds voxgig/plugin
// and `build/sekreto.jar` and NOTHING ELSE - `build/sekreto-plugins.jar` is
// not on it. So the proof is the JVM's rather than a reviewer's:
//
//   - a core that NAMED a plugin would not compile here, because the class
//     it named is not on the classpath;
//   - a core that reached one at run time - a reflective load, a lazily
//     initialised holder - would throw NoClassDefFoundError below;
//   - and a chain of the four built-in kinds must work anyway, which is the
//     promise the split makes to an app whose chain is [dotenv, env].
//
// It is the scala analogue of python's `test_the_core_imports_no_plugin` (a
// fresh interpreter listing sys.modules) and go's linking boundary.
// `corecheck.sh` greps the same jar for a socket, a cipher and a subprocess;
// between them they cover naming and reaching.

import java.nio.charset.StandardCharsets
import java.nio.file.Files
import java.nio.file.Paths

import com.voxgig.sekreto.BUILTINS
import com.voxgig.sekreto.KINDS
import com.voxgig.sekreto.ProviderSpec
import com.voxgig.sekreto.Sekreto
import com.voxgig.sekreto.SekretoError

object CoreOnly:

  private var failed = 0

  private def check(what: String, ok: Boolean): Unit =
    if ok then println(s"ok   - $what")
    else
      failed += 1
      println(s"FAIL - $what")

  private def checkeq[T](what: String, want: T, got: T): Unit =
    check(what + (if want == got then "" else s" (want $want, got $got)"), want == got)

  def main(args: Array[String]): Unit =
    val dir = Paths.get(System.getProperty("java.io.tmpdir"), "sekreto-coreonly")
    Files.createDirectories(dir)
    Files.write(dir.resolve(".env"), "API_TOKEN=fromdotenv\n".getBytes(StandardCharsets.UTF_8))
    Files.write(dir.resolve("DB_PASS"), "fromfile\n".getBytes(StandardCharsets.UTF_8))

    // The four built-in kinds, in one chain, with no plugin anywhere on the
    // classpath. If the core reached a plugin to build any of them, this
    // would not survive class loading.
    val secrets = Sekreto(
      providers = List(
        ProviderSpec(kind = "memory", values = Some(Map("API_KEY" -> "frommemory"))),
        ProviderSpec(kind = "dotenv", file = Some(dir.resolve(".env").toString)),
        ProviderSpec(kind = "file", dir = Some(dir.toString)),
        ProviderSpec(kind = "env", prefix = Some("SEKRETO_CORE_")),
      ),
    )

    checkeq("the four built-in kinds are the catalog", KINDS.builtin.sorted, secrets.catalog.names)
    checkeq("the built-in definitions are four", 4, BUILTINS.length)
    checkeq("memory answers", "frommemory", secrets.get("api.key"))
    checkeq("dotenv answers", "fromdotenv", secrets.get("api.token"))
    checkeq("file answers", "fromfile", secrets.get("db.pass"))
    checkeq(
      "the chain is four stores",
      List("memory", "dotenv", "file", "env"),
      secrets.stores(),
    )
    checkeq("redaction still works", "t=[redacted]", secrets.redact("t=fromdotenv"))

    // ...and a plugin kind is refused HERE TOO, naming the fix. The core
    // knows the ten names without linking one of them: KINDS.plugin is a list
    // of strings.
    val refused =
      try
        Sekreto(providers =
          List(ProviderSpec(kind = "hashicorp", addr = Some("https://v"), token = Some("t"))),
        )
        "no error"
      catch case err: SekretoError => Option(err.getMessage).getOrElse("")

    checkeq(
      "a plugin kind is refused, naming the fix",
      "sekreto: unknown provider kind: hashicorp (available: dotenv, env, file, memory)" +
        " - hashicorp is a sekreto plugin, not built in: pass it in the plugins option",
      refused,
    )

    // The class is not merely unloaded - it is not on this classpath at all,
    // which is what makes every check above a statement about the artifact
    // rather than about class-loading order.
    val absent =
      try
        Class.forName("com.voxgig.sekreto.plugins.Hashicorp$package")
        false
      catch case _: ClassNotFoundException => true

    check("no plugin class is on the core classpath", absent)

    secrets.close()
    checkeq("close empties the host", 0, secrets.host.list.keys.length)

    println(
      if 0 == failed then "\ncore: the core runs with the plugins absent"
      else s"\ncore: $failed failed",
    )

    System.exit(if 0 == failed then 0 else 1)
