// RUN: make seam
// RUN-SOME: java -cp build/seam:... PluginsTest "a store name must be a valid tag"
//
// THE PLUGIN SEAM, from both sides.
//
// Moving the provider kinds that open sockets and spawn processes out of the
// core made a consumer's PLUGIN LIST load-bearing: a kind nobody passed in is
// not in the catalog, and a chain naming it is refused. That is the intended
// behaviour, and it means a consumer can be broken without a single
// conformance test noticing - the conformance suite passes every plugin to
// every chain it builds, so it can never see a missing one. So the full set
// is pinned here: it holds every kind, every kind builds, and the CLI passes
// it.
//
// The scala half of the seam is a LINKING one, so the boundary tests below
// work on the compiled jars rather than on the source: a class loader over
// the core jar alone, and the bytes of the entries in it. `make check-core`
// runs test/CoreOnly.scala against the same classpath as a whole program;
// this file is the assertions.
//
// A translation of python/tests/test_plugins.py, which is the model.

import java.io.File
import java.net.URL
import java.net.URLClassLoader
import java.nio.charset.StandardCharsets
import java.util.zip.ZipFile
import scala.collection.immutable.ListMap
import scala.collection.mutable.ListBuffer
import scala.jdk.CollectionConverters.*
import scala.util.Using

import voxgig.plugin.PluginError
import voxgig.plugin.VStr

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

object PluginsTest:

  private val PLUGINS = List(
    "awsparams",
    "awssecrets",
    "azuresecrets",
    "boru",
    "doppler",
    "gcpsecrets",
    "hashicorp",
    "infisical",
    "onepassword",
    "secretspec",
  )

  private val EVERY = (List("dotenv", "env", "file", "memory") ++ PLUGINS).sorted

  // ONE FILE PER PLUGIN, and the two AWS kinds share theirs because they
  // share the whole of the signing machinery. A scala 3 file's top-level
  // definitions live in a synthetic `<File>$package` class, so these are the
  // class names the boundary tests below ask a class loader for.
  private val KINDFILES = List(
    "Aws",
    "Azuresecrets",
    "Boru",
    "Doppler",
    "Gcpsecrets",
    "Hashicorp",
    "Infisical",
    "Onepassword",
    "Secretspec",
  )

  // --------------------------------------------------------- the harness

  private var only: Option[String] = None
  private var passcount = 0
  private var failcount = 0

  private class Failed(message: String) extends RuntimeException(message)

  private def testcase(name: String)(body: => Unit): Unit =
    if only.exists(_ != name) then return

    try
      body
      passcount += 1
      println(s"ok   - $name")
    catch
      case err: Throwable =>
        failcount += 1
        println(s"FAIL - $name")
        val text = Option(err.getMessage).getOrElse(err.toString)
        println("       " + text.replace("\n", "\n       "))

  private def eq[T](want: T, got: T, what: String = ""): Unit =
    if want != got then throw Failed(s"$what\n  want: $want\n  got:  $got")

  private def ok(what: String, condition: Boolean): Unit =
    if !condition then throw Failed(what)

  /** The message of the SekretoError `body` must raise. */
  private def refusal(body: => Unit): String =
    try
      body
      throw Failed("no SekretoError was raised")
    catch case err: SekretoError => Option(err.getMessage).getOrElse("")

  // ------------------------------------------------------- the classpath
  //
  // The jars this run was given, which is how the boundary tests reach the
  // artifacts rather than the source. `make seam` puts the core jar, the
  // plugins jar, voxgig/plugin and the scala runtime on it.

  private val CLASSPATH: List[String] =
    System.getProperty("java.class.path").split(File.pathSeparator).toList

  private def jar(name: String): String =
    CLASSPATH
      .find(_.endsWith(name))
      .getOrElse(throw Failed(s"$name is not on the classpath: $CLASSPATH"))

  /** The scala runtime, which `java -cp` does not supply of itself. Every
    * loader below needs it, and the core is no more able to run without it
    * than a kotlin core is without kotlin-stdlib.
    */
  private def runtime: List[String] =
    CLASSPATH.filter: entry =>
      val base = File(entry).getName
      base.startsWith("scala3-library") || base.startsWith("scala-library")

  private def coreonly: List[String] = List(jar("voxgigplugin.jar"), jar("sekreto.jar")) ++ runtime

  private def withplugins: List[String] = coreonly ++ List(jar("sekreto-plugins.jar"))

  private def urls(paths: List[String]): Array[URL] =
    paths.map(path => File(path).toURI.toURL).toArray

  /** A class loader over exactly these jars - the PLATFORM loader as its
    * parent, so nothing on this run's own classpath leaks into it.
    */
  private def loaderover(paths: List[String]): URLClassLoader =
    URLClassLoader(urls(paths), ClassLoader.getPlatformClassLoader)

  /** A loader that records every plugin class asked of it. */
  private class Recorder(paths: List[String])
      extends URLClassLoader(urls(paths), ClassLoader.getPlatformClassLoader):

    val asked = ListBuffer.empty[String]

    override def loadClass(name: String, resolve: Boolean): Class[?] =
      if name.startsWith("com.voxgig.sekreto.plugins.") && !asked.contains(name) then
        asked += name
      super.loadClass(name, resolve)

    /** The plugin FILES whose synthetic class was loaded, by their name.
      *
      * BOTH SPELLINGS OF IT. A scala 3 file's top-level definitions live in a
      * module `<File>$package$` with static forwarders on a class
      * `<File>$package`; a call from scala reaches the module, a call through
      * reflection reaches the forwarder, and either one means the file was
      * loaded.
      */
    def files(): List[String] = asked.toList
      .map(_.stripPrefix("com.voxgig.sekreto.plugins."))
      .filter(_.contains("$package"))
      .map(_.takeWhile(_ != '$'))
      .distinct
      .sorted

  /** A static top-level definition, read off its file's synthetic class in
    * another loader - which is what `import ...plugins.hashicorp` compiles
    * to a call of, and so is the loading a consumer's import really does.
    */
  private def toplevel(loader: ClassLoader, cls: String, name: String): Any =
    Class.forName(cls, true, loader).getMethod(name).invoke(null)

  /** How long a list from ANOTHER LOADER is.
    *
    * Reflectively, because it has to be: an isolated loader carries its own
    * scala runtime, so the `List` it hands back is a different class from
    * this run's `List` and a cast to it throws. That the two are unrelated is
    * the whole point of the loader - it is what makes the boundary tests
    * statements about the artifact rather than about this classpath.
    */
  private def count(list: Any): Int =
    list.getClass.getMethod("length").invoke(list).asInstanceOf[Integer].intValue

  def main(args: Array[String]): Unit =
    if args.nonEmpty then only = Some(args(0))

    // ------------------------------------------------- the full set

    testcase("the full set holds every kind"):
      eq(PLUGINS, Plugins.ALL.map(_.name).sorted, "Plugins.ALL")
      eq(KINDS.builtin, BUILTINS.map(_.name), "BUILTINS")
      eq(PLUGINS, KINDS.plugin.sorted, "KINDS.plugin")
      eq(10, Plugins.ALL.length, "ten plugins")

    // Naming a kind is not enough: a kind can be in the catalog and still
    // fail to build. Construction is what the CLI does before any network.
    testcase("every kind builds from a spec"):
      val chain = EVERY.map: kind =>
        ProviderSpec(
          kind = kind,
          addr = Some("http://127.0.0.1:8200"),
          token = Some("t"),
          dir = Some("/tmp"),
          file = Some("/tmp/.env"),
          values = Some(Map.empty),
        )

      val secrets = Sekreto(providers = chain, plugins = Plugins.ALL)

      eq(EVERY, secrets.stores(), "stores")
      eq(EVERY, secrets.host.list.keys, "host.list")
      eq(Set(VStr("live")), secrets.host.list.entries.values.toSet, "every instance live")
      secrets.close()

    testcase("the CLI passes the full set"):
      val src = String(java.nio.file.Files.readAllBytes(java.nio.file.Paths.get("cli/Cli.scala")))
      ok(
        "Cli.scala imports the full set",
        src.contains("import com.voxgig.sekreto.plugins.Plugins"),
      )
      ok("Cli.scala passes the full set", src.contains("Plugins.ALL"))

    // ------------------------------------------- what a consumer sees

    testcase("one plugin is enough for a chain that names only it"):
      val secrets = Sekreto(
        providers = List(
          ProviderSpec(kind = "memory", values = Some(Map("API_TOKEN" -> "tok01"))),
          ProviderSpec(
            kind = "hashicorp",
            name = Some("prod"),
            addr = Some("https://vault.example.com"),
            token = Some("t"),
          ),
        ),
        plugins = List(hashicorp),
      )

      eq(List("memory", "prod"), secrets.stores(), "stores")
      eq(
        List("memory", "hashicorp:https://vault.example.com/secret"),
        secrets.sources(),
        "sources",
      )
      eq("tok01", secrets.get("api.token"), "the chain answers")

      // The plugin host is what the chain is made of, and it reads like the
      // chain: the kind, or kind$store for a named store.
      eq(
        ListMap("hashicorp$prod" -> VStr("live"), "memory" -> VStr("live")),
        ListMap.from(secrets.host.list.keys.map(key => (key, secrets.host.list.at(key)))),
        "host.list",
      )
      eq(
        List("dotenv", "env", "file", "hashicorp", "memory"),
        secrets.catalog.names,
        "catalog",
      )
      secrets.close()

    testcase("a kind that was not passed in is refused, naming the fix"):
      eq(
        "sekreto: unknown provider kind: doppler" +
          " (available: dotenv, env, file, hashicorp, memory)" +
          " - doppler is a sekreto plugin, not built in: pass it in the plugins option",
        refusal(
          Sekreto(
            providers = List(ProviderSpec(kind = "doppler", token = Some("t"))),
            plugins = List(hashicorp),
          ),
        ),
        "a plugin that was not passed",
      )

      // A kind nobody ships is a typo, and gets no such hint.
      eq(
        "sekreto: unknown provider kind: vualt (available: dotenv, env, file, memory)",
        refusal(Sekreto(providers = List(ProviderSpec(kind = "vualt")))),
        "a typo",
      )

    // Two providers MAY share a store name - a directed read walks both, and
    // the spec pins it - but an instance ref may not, so the second gets a
    // numbered tag from the host and keeps its store name.
    testcase("a repeated store name keeps the store and numbers the instance"):
      val secrets = Sekreto(
        providers = List(
          ProviderSpec(kind = "memory", values = Some(Map.empty)),
          ProviderSpec(kind = "memory", values = Some(Map("API_TOKEN" -> "second"))),
          ProviderSpec(kind = "memory", name = Some("pair"), values = Some(Map.empty)),
          ProviderSpec(
            kind = "memory",
            name = Some("pair"),
            values = Some(Map("API_TOKEN" -> "pair2")),
          ),
        ),
      )

      eq(List("memory", "pair"), secrets.stores(), "stores")
      eq(
        List("memory", "memory$1", "memory$2", "memory$pair"),
        secrets.host.list.keys,
        "host.list",
      )
      eq("second", secrets.getfrom("memory", "api.token"), "the second memory answers")
      eq("pair2", secrets.getfrom("pair", "api.token"), "the second pair answers")
      secrets.close()

    testcase("a store name must be a valid tag"):
      eq(
        "sekreto: invalid store name: my store",
        refusal(
          Sekreto(providers =
            List(ProviderSpec(kind = "memory", name = Some("my store"), values = Some(Map.empty))),
          ),
        ),
      )

    // A provider that refuses its own configuration raises a SekretoError
    // from inside the plugin's `define`. The spec pins that message byte for
    // byte, so it must come back out of the host as itself - not wrapped as
    // plugin_define_failed, and not as a PluginError.
    testcase("a SekretoError raised in define comes back out as itself"):
      eq(
        "sekreto: hashicorp: unsupported kv version: 3",
        refusal(
          Sekreto(
            providers = List(
              ProviderSpec(
                kind = "hashicorp",
                addr = Some("http://127.0.0.1:1"),
                token = Some("t"),
                kv = Some(3),
              ),
            ),
            plugins = List(hashicorp),
          ),
        ),
      )

    // ...and any other error is not sekreto's to rewrite: it surfaces as the
    // host reports it, naming the instance and the cause.
    testcase("any other error raised in define is the host's report of it"):
      val broken = providerplugin("broken", _ => throw IllegalStateException("boom"))

      val err =
        try
          Sekreto(providers = List(ProviderSpec(kind = "broken")), plugins = List(broken))
          throw Failed("no error was raised")
        catch case caught: PluginError => caught

      eq("plugin_define_failed", err.code, "code")
      ok(s"names the cause: ${err.getMessage}", err.getMessage.contains("boom"))
      ok(s"names the instance: ${err.getMessage}", err.getMessage.contains("broken"))

    testcase("a custom kind is one providerplugin call"):
      class Shouty(values: Map[String, String]) extends Provider:
        override def lookup(name: String): Option[String] = values.get(name.toUpperCase)
        override def describe(): String = "shouty"

      val shouty = providerplugin("shouty", spec => Shouty(spec.values.getOrElse(Map.empty)))

      val secrets = Sekreto(
        providers =
          List(ProviderSpec(kind = "shouty", values = Some(Map("API.TOKEN" -> "loud")))),
        plugins = List(shouty),
      )

      eq("loud", secrets.get("api.token"), "the custom kind answers")
      eq(List("shouty"), secrets.host.list.keys, "host.list")
      secrets.close()

    // A plugin that names a built-in kind replaces it: that is how a host
    // substitutes an implementation, and never an accident, because the four
    // names are documented.
    testcase("a plugin may replace a built-in kind"):
      class Replaced extends Provider:
        override def lookup(name: String): Option[String] = Some("replaced")
        override def describe(): String = "memory"

      val secrets = Sekreto(
        providers =
          List(ProviderSpec(kind = "memory", values = Some(Map("API_TOKEN" -> "original")))),
        plugins = List(providerplugin("memory", _ => Replaced())),
      )

      eq("replaced", secrets.get("api.token"))
      eq(4, secrets.catalog.names.length, "still four kinds")
      secrets.close()

    testcase("close tears the chain down and keeps redaction"):
      val secrets = Sekreto(providers =
        List(ProviderSpec(kind = "memory", values = Some(Map("API_TOKEN" -> "tok01")))),
      )
      eq("tok01", secrets.get("api.token"))

      secrets.close()

      eq(0, secrets.host.list.keys.length, "the host is empty")
      eq(List.empty, secrets.stores(), "no stores")
      eq(None, secrets.tryget("api.token"), "nothing answers")
      eq("token=[redacted]", secrets.redact("token=tok01"), "redaction survives")

    // A definition that is not a `providerplugin` - one whose `define`
    // exports no provider - is refused by name. plugin's `run` simply returns
    // when a definition has no callback, so without this check the chain
    // would carry a hole and the first lookup would blame the wrong thing.
    // This is scala's shape of python's "a module passed as a plugin is
    // refused": the mistake a static type system still lets through.
    testcase("a definition that exports no provider is refused"):
      eq(
        "sekreto: plugin shouty exported no provider",
        refusal(
          Sekreto(
            providers = List(ProviderSpec(kind = "shouty")),
            plugins = List(voxgig.plugin.Definition(name = "shouty")),
          ),
        ),
      )

    // The spec crosses the boundary as plugin's own value model - a sealed
    // hierarchy of null, boolean, number, string, list and map - and comes
    // back typed. A field added to `optionsof` and forgotten in `specof`
    // would be lost in silence, and only for the kinds no conformance case
    // exercises.
    testcase("a provider spec survives the plugin boundary"):
      val full = ProviderSpec(
        kind = "hashicorp",
        name = Some("prod"),
        prefix = Some("P_"),
        file = Some("f"),
        values = Some(Map("A" -> "1")),
        dir = Some("d"),
        addr = Some("https://a"),
        token = Some("t"),
        mount = Some("m"),
        kv = Some(1),
        vaultnamespace = Some("ns"),
        auth = Some(
          AuthSpec(
            method = "approle",
            mount = Some("am"),
            role = Some("r"),
            jwt = Some("j"),
            jwtfile = Some("jf"),
            roleid = Some("ri"),
            secretid = Some("si"),
          ),
        ),
        command = Some("c"),
        profile = Some("pr"),
        backend = Some("b"),
        reason = Some("re"),
        namespace = Some("n"),
        home = Some("h"),
        region = Some("eu"),
        keyid = Some("k"),
        secret = Some("s"),
        session = Some("se"),
        project = Some("pj"),
        vault = Some("v"),
        tenant = Some("tn"),
        clientid = Some("ci"),
        clientsecret = Some("cs"),
        loginaddr = Some("la"),
        imdsaddr = Some("ia"),
        metadataaddr = Some("ma"),
        apiversion = Some("7.4"),
        config = Some("cf"),
        environment = Some("dev"),
        path = Some("/p"),
      )

      eq(full, specof(optionsof(full)), "the round trip")

      // Every field is set above, so nothing may be missing from the options
      // either - a field dropped from BOTH sides would round trip and still
      // be gone.
      eq(34, optionsof(full).entries.size, "every ProviderSpec field crossed")
      eq(7, optionsof(full).at("auth").entries.size, "every AuthSpec field crossed")

    // ------------------------------------------------- the boundary

    // The core does not reach a plugin: a class loader over voxgig/plugin and
    // the CORE JAR ALONE builds a chain of built-in kinds, and cannot even
    // name a plugin class. `make check-core` runs the whole of
    // test/CoreOnly.scala against that classpath; this is the assertion.
    testcase("the core imports no plugin"):
      Using.resource(loaderover(coreonly)): loader =>
        // The core loads, and its four built-in definitions with it.
        val builtins = toplevel(loader, "com.voxgig.sekreto.Providers$package", "BUILTINS")
        eq(4, count(builtins), "four built-ins, with no plugin jar in reach")

        val absent = (KINDFILES ++ List("Httpjson", "Sigv4")).map(_ + "$package")

        for name <- absent ++ List("Plugins") do
          val cls = "com.voxgig.sekreto.plugins." + name
          val found =
            try
              loader.loadClass(cls)
              true
            catch case _: ClassNotFoundException => false

          ok(s"$cls is not reachable from the core", !found)

      // ...and no entry IN the core jar so much as mentions one, nor a
      // socket, a cipher or a child process. A class file carries every type
      // it refers to as a UTF8 constant and scala 3 writes a `.tasty` beside
      // it, so the bytes are the record.
      //
      // BOTH SPELLINGS, and the dotted half is why. The constant pool holds a
      // resolved type with slashes, so the slash list covers every reference
      // the COMPILER resolved. A reference only REFLECTION would reach is a
      // Class.forName string literal, which is dotted - so the slash list
      // alone could not see that case at all.
      val banned = List(
        "com/voxgig/sekreto/plugins",
        "java/net/http",
        "java/net/Socket",
        "javax/crypto",
        "java/security/MessageDigest",
        "java/lang/ProcessBuilder",
        "com.voxgig.sekreto.plugins",
        "java.net.http",
        "java.net.Socket",
        "javax.crypto",
        "java.security.MessageDigest",
        "java.lang.ProcessBuilder",
      )

      var entries = 0
      Using.resource(ZipFile(jar("sekreto.jar"))): zip =>
        for entry <- zip.entries.asScala do
          if !entry.isDirectory then
            entries += 1
            val bytes = Using.resource(zip.getInputStream(entry))(_.readAllBytes)
            val text = String(bytes, StandardCharsets.ISO_8859_1)
            for pattern <- banned do ok(s"${entry.getName} reaches $pattern", !text.contains(pattern))

      ok("the core jar has entries to check", 0 < entries)

    // ...and one plugin loads only itself. Reaching for `hashicorp` must not
    // drag in the AWS signer and eight other vault clients - which is what a
    // full-set import in the plugins package would do, and what the python
    // port's package initializer used to do.
    testcase("one plugin loads only itself"):
      val recorder = Recorder(withplugins)

      Using.resource(recorder): loader =>
        // Read the top-level `val hashicorp` off its file's class, which is
        // what `import com.voxgig.sekreto.plugins.hashicorp` compiles to.
        val definition = toplevel(loader, "com.voxgig.sekreto.plugins.Hashicorp$package", "hashicorp")
        ok("the definition came back", null != definition)

      // EXACTLY ONE FILE, and the shared HTTP-JSON transport is not even
      // among them: the JVM resolves `Httpjson$package` at the first call
      // that needs it, which is a lookup, and a lookup is what the chain has
      // not done yet.
      eq(List("Hashicorp"), recorder.files(), "the kind files loaded")
      ok(
        s"no aws, doppler or infisical class was loaded: ${recorder.asked}",
        !recorder.asked.exists(name =>
          name.contains("Aws") || name.contains("Doppler") || name.contains("Infisical"),
        ),
      )

    // The full set is what pulls all ten in, and reaching for it is the
    // deliberate act of a CLI or a test harness rather than a side effect of
    // importing the library.
    testcase("the full set is loaded on demand"):
      val recorder = Recorder(withplugins)

      val loaded = Using.resource(recorder): loader =>
        count(toplevel(loader, "com.voxgig.sekreto.plugins.Plugins", "ALL"))

      eq(10, loaded, "the full set is ten")
      eq(KINDFILES, recorder.files(), "reaching the full set loads every plugin file")

    println(s"\n$passcount passed, $failcount failed")

    System.exit(if 0 == failcount then 0 else 1)
