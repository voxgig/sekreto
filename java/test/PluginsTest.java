// RUN: make test
// RUN-SOME: java -cp build/plugin:build/core:build/plugins:build/test PluginsTest unknownkind
//
// THE PLUGIN SEAM, from both sides.
//
// Moving the provider kinds that open sockets and spawn processes out of
// the core made a consumer's PLUGIN LIST load-bearing: a kind nobody
// passed in is not in the catalog, and a chain naming it is refused.
// That is the intended behaviour, and it means a consumer can be broken
// without a single conformance test noticing - the conformance suite
// passes every plugin to every chain it builds, so it can never see a
// missing one. So the full set is pinned here: it holds every kind,
// every kind builds, and the CLI passes it.
//
// The other half is the boundary itself, and in java that is the
// classpath. These tests read it two ways that no assertion in the
// library could fake: a class loader over build/core alone, which can
// build a chain of built-ins and cannot even NAME a plugin, and the
// compiled class files themselves, which say what each one references.
//
// A translation of python/tests/test_plugins.py, which is the model.

import com.voxgig.sekreto.Provider;
import com.voxgig.sekreto.Sekreto;
import com.voxgig.sekreto.Sekreto.SekretoError;
import com.voxgig.sekreto.Support;
import com.voxgig.sekreto.plugins.Aws;
import com.voxgig.sekreto.plugins.Hashicorp;
import com.voxgig.sekreto.plugins.Plugins;
import java.io.File;
import java.net.URL;
import java.net.URLClassLoader;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.TreeSet;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import voxgig.plugin.Definition;
import voxgig.plugin.Plugin;

public final class PluginsTest {

  private PluginsTest() {}

  private static final List<String> PLUGINKINDS = List.of(
      "awsparams", "awssecrets", "azuresecrets", "boru", "doppler", "gcpsecrets",
      "hashicorp", "infisical", "onepassword", "secretspec");

  /** All fourteen kinds, sorted, as the catalog and `stores()` order them. */
  private static final List<String> EVERY = sorted(
      concat(List.of("dotenv", "env", "file", "memory"), PLUGINKINDS));

  private static String only = null;
  private static int passcount = 0;
  private static int failcount = 0;

  // --- the full set -----------------------------------------------------

  static void thefullsetholdseverykind() {
    List<String> names = new ArrayList<>();
    for (Definition def : Plugins.ALL) {
      names.add(def.name);
    }
    same(PLUGINKINDS, sorted(names), "Plugins.ALL");

    // Two kinds, one plugin: aws ships both stores because they share a
    // signer, so the list is ten definitions from nine classes.
    same("awssecrets", Aws.SECRETS.name, "Aws.SECRETS");
    same("awsparams", Aws.PARAMS.name, "Aws.PARAMS");
    same(10, Plugins.ALL.size(), "Plugins.ALL.size()");
  }

  // Naming a kind is not enough: a kind can be in the catalog and still
  // fail to build. Construction is what the CLI does before any network.
  static void everykindbuildsfromaspec() {
    List<Object> chain = new ArrayList<>();
    for (String kind : EVERY) {
      Map<String, Object> spec = new LinkedHashMap<>();
      spec.put("kind", kind);
      spec.put("addr", "http://127.0.0.1:8200");
      spec.put("token", "t");
      spec.put("dir", "/tmp");
      spec.put("file", "/tmp/.env");
      spec.put("values", new LinkedHashMap<String, Object>());
      chain.add(spec);
    }

    Sekreto secrets = new Sekreto(
        new Sekreto.Options().plugins(Plugins.ALL).providers(chain));

    same(EVERY, secrets.stores(), "stores()");
    same(EVERY, sorted(new ArrayList<>(secrets.host().list().keySet())), "host().list()");

    for (Object status : secrets.host().list().values()) {
      same("live", status, "instance status");
    }

    same(EVERY, secrets.catalog().names(), "catalog().names()");
  }

  static void theclipassesthefullset() {
    String src = read(here().resolve("cli").resolve("Cli.java"));
    contains(src, "import com.voxgig.sekreto.plugins.Plugins;", "Cli.java");
    contains(src, ".plugins(Plugins.ALL)", "Cli.java");
  }

  // --- what a consumer sees ---------------------------------------------

  static void onepluginisenoughforachainthatnamesonlyit() {
    Sekreto secrets = new Sekreto(new Sekreto.Options()
        .plugins(List.of(Hashicorp.PLUGIN))
        .providers(List.of(
            Map.of("kind", "memory", "values", Map.of("API_TOKEN", "tok01")),
            Map.of("kind", "hashicorp", "name", "prod",
                "addr", "https://vault.example.com", "token", "t"))));

    same(List.of("memory", "prod"), secrets.stores(), "stores()");
    same(List.of("memory", "hashicorp:https://vault.example.com/secret"),
        secrets.sources(), "sources()");
    same("tok01", secrets.get("api.token"), "get");

    // The plugin host is what the chain is made of, and it reads like the
    // chain: the kind, or kind$store for a named store.
    same(Map.of("memory", "live", "hashicorp$prod", "live"),
        secrets.host().list(), "host().list()");
    same(List.of("dotenv", "env", "file", "hashicorp", "memory"),
        secrets.catalog().names(), "catalog().names()");
  }

  static void akindthatwasnotpassedinisrefusednamingthefix() {
    same("sekreto: unknown provider kind: doppler"
            + " (available: dotenv, env, file, hashicorp, memory)"
            + " - doppler is a sekreto plugin, not built in: pass it in the plugins option",
        refused(() -> new Sekreto(new Sekreto.Options()
            .plugins(List.of(Hashicorp.PLUGIN))
            .providers(List.of(Map.of("kind", "doppler", "token", "t"))))),
        "a plugin that was not passed in");

    // A kind nobody ships is a typo, and gets no such hint.
    same("sekreto: unknown provider kind: vualt (available: dotenv, env, file, memory)",
        refused(() -> new Sekreto(
            new Sekreto.Options().providers(List.of(Map.of("kind", "vualt"))))),
        "a kind nobody ships");
  }

  // Two providers MAY share a store name - a directed read walks both,
  // and the spec pins it - but an instance ref may not, so the second
  // gets a numbered tag from the host and keeps its store name.
  static void arepeatedstorenamekeepsthestoreandnumberstheinstance() {
    Sekreto secrets = new Sekreto(new Sekreto.Options().providers(List.of(
        Map.of("kind", "memory", "values", Map.of()),
        Map.of("kind", "memory", "values", Map.of("API_TOKEN", "second")),
        Map.of("kind", "memory", "name", "pair", "values", Map.of()),
        Map.of("kind", "memory", "name", "pair", "values", Map.of("API_TOKEN", "pair2")))));

    same(List.of("memory", "pair"), secrets.stores(), "stores()");
    same(List.of("memory", "memory$1", "memory$2", "memory$pair"),
        new ArrayList<>(secrets.host().list().keySet()), "host().list()");
    same("second", secrets.getfrom("memory", "api.token"), "getfrom memory");
    same("pair2", secrets.getfrom("pair", "api.token"), "getfrom pair");
  }

  static void astorenamemustbeavalidtag() {
    same("sekreto: invalid store name: my store",
        refused(() -> new Sekreto(new Sekreto.Options().providers(
            List.of(Map.of("kind", "memory", "name", "my store", "values", Map.of()))))),
        "an invalid store name");
  }

  // A provider that refuses its own configuration raises a SekretoError
  // from inside the plugin's `define`. The spec pins that message byte
  // for byte, so it must come back out of the host as itself - not
  // wrapped as plugin_define_failed, and not as a PluginException.
  static void asekretoerrorraisedindefinecomesbackoutasitself() {
    same("sekreto: hashicorp: unsupported kv version: 3",
        refused(() -> new Sekreto(new Sekreto.Options()
            .plugins(List.of(Hashicorp.PLUGIN))
            .providers(List.of(Map.of("kind", "hashicorp",
                "addr", "http://127.0.0.1:1", "token", "t", "kv", 3))))),
        "a provider refusing its own configuration");
  }

  // ...and any other error is not sekreto's to rewrite: it surfaces as
  // the host reports it, naming the instance and the cause.
  static void anyothererrorraisedindefineisthehostsreportofit() {
    Definition broken = Support.providerplugin("broken", spec -> {
      throw new IllegalStateException("boom");
    });

    RuntimeException caught = null;
    try {
      new Sekreto(new Sekreto.Options()
          .plugins(List.of(broken))
          .providers(List.of(Map.of("kind", "broken"))));
    } catch (RuntimeException err) {
      caught = err;
    }

    if (null == caught) {
      throw new AssertionError("nothing raised");
    }
    if (caught instanceof SekretoError) {
      throw new AssertionError("rewritten as a SekretoError: " + caught.getMessage());
    }
    same("plugin_define_failed", Plugin.codeof(caught), "the host's code");
    contains(caught.getMessage(), "boom", "the host's report");
  }

  static void acustomkindisoneproviderplugincall() {
    Definition shouty = Support.providerplugin("shouty", spec -> new Provider() {
      @Override
      public String lookup(String name) {
        Map<String, Object> values = Support.map(spec.get("values"));
        Object found = null == values ? null : values.get(name.toUpperCase());
        return null == found ? null : String.valueOf(found);
      }

      @Override
      public String describe() {
        return "shouty";
      }
    });

    Sekreto secrets = new Sekreto(new Sekreto.Options()
        .plugins(List.of(shouty))
        .providers(List.of(Map.of("kind", "shouty", "values", Map.of("API.TOKEN", "loud")))));

    same("loud", secrets.get("api.token"), "a custom kind");
    same(Map.of("shouty", "live"), secrets.host().list(), "host().list()");
  }

  // A plugin that names a built-in kind replaces it: that is how a host
  // substitutes an implementation, and never an accident, because the
  // four names are documented.
  static void apluginmayreplaceabuiltinkind() {
    Definition replaced = Support.providerplugin("memory", spec -> new Provider() {
      @Override
      public String lookup(String name) {
        return "replaced";
      }

      @Override
      public String describe() {
        return "memory";
      }
    });

    Sekreto secrets = new Sekreto(new Sekreto.Options()
        .plugins(List.of(replaced))
        .providers(List.of(Map.of("kind", "memory", "values", Map.of("API_TOKEN", "original")))));

    same("replaced", secrets.get("api.token"), "the replacement");
    same(List.of("dotenv", "env", "file", "memory"), secrets.catalog().names(), "catalog()");
  }

  static void closetearsthechaindownandkeepsredaction() {
    Sekreto secrets = new Sekreto(new Sekreto.Options().providers(
        List.of(Map.of("kind", "memory", "values", Map.of("API_TOKEN", "tok01")))));

    same("tok01", secrets.get("api.token"), "get");

    secrets.close();

    same(0, secrets.host().list().size(), "host().list()");
    same(List.of(), secrets.stores(), "stores()");
    same(null, secrets.tryget("api.token"), "tryget after close");
    same("token=[redacted]", secrets.redact("token=tok01"), "redact after close");
  }

  // --- the boundary itself ----------------------------------------------

  // THE CORE REACHES NO PLUGIN, read off the compiled classes rather than
  // asserted. A loader over build/core and voxgig/plugin - and nothing
  // else - can build a chain of the four built-in kinds and answer from
  // it, and cannot so much as name a plugin.
  static void thecoreimportsnoplugin() throws Exception {
    ClassLoader coreonly = new URLClassLoader(
        new URL[] {
            here().resolve("build/core").toUri().toURL(),
            here().resolve("build/plugin").toUri().toURL(),
        },
        // The PLATFORM loader, not the application one: with the ordinary
        // parent the plugin classes would be found on this suite's own
        // classpath and the test would pass without meaning anything.
        ClassLoader.getPlatformClassLoader());

    Class<?> sekreto = Class.forName("com.voxgig.sekreto.Sekreto", true, coreonly);
    Class<?> options = Class.forName("com.voxgig.sekreto.Sekreto$Options", true, coreonly);

    Object opts = options.getConstructor().newInstance();
    options.getMethod("providers", Object.class).invoke(opts, List.of(
        Map.of("kind", "memory", "values", Map.of("API_TOKEN", "tok01")),
        Map.of("kind", "env"),
        Map.of("kind", "dotenv", "file", "/nonexistent-sekreto-test/.env"),
        Map.of("kind", "file", "dir", "/nonexistent-sekreto-test")));

    Object built = sekreto.getConstructor(options).newInstance(opts);
    same("tok01", sekreto.getMethod("get", String.class).invoke(built, "api.token"),
        "a chain of built-ins, with no plugin on the classpath");

    for (String kind : List.of("Hashicorp", "Aws", "Doppler", "Plugins", "Sigv4", "Httpjson")) {
      try {
        Class.forName("com.voxgig.sekreto.plugins." + kind, false, coreonly);
        throw new AssertionError("the core can reach " + kind);
      } catch (ClassNotFoundException wanted) {
        continue;
      }
    }

    // And the class files agree: nothing the core was compiled to even
    // names the plugins package.
    for (Path cls : classfiles(here().resolve("build/core"))) {
      Set<String> found = references(cls);
      if (!found.isEmpty()) {
        throw new AssertionError(cls + " references " + found);
      }
    }
  }

  // ...and one plugin reaches only itself and the shared HTTP edge. The
  // full set is one class away, and naming it would link all ten.
  static void onepluginreachesonlyitself() throws Exception {
    same(new TreeSet<>(List.of("Hashicorp", "Httpjson")),
        references(here().resolve("build/plugins/com/voxgig/sekreto/plugins/Hashicorp.class")),
        "Hashicorp.class");

    same(new TreeSet<>(List.of("Proc", "Secretspec")),
        references(here().resolve("build/plugins/com/voxgig/sekreto/plugins/Secretspec.class")),
        "Secretspec.class");
  }

  // The full set costs what it says it costs: naming Plugins reaches
  // every kind this library ships, which is the thing a lean consumer
  // does not do.
  static void thefullsetreacheseveryplugin() throws Exception {
    same(new TreeSet<>(List.of(
            "Aws", "Azuresecrets", "Boru", "Doppler", "Gcpsecrets", "Hashicorp",
            "Infisical", "Onepassword", "Plugins", "Secretspec")),
        references(here().resolve("build/plugins/com/voxgig/sekreto/plugins/Plugins.class")),
        "Plugins.class");
  }

  // java's types stop a module being passed as a plugin, which is what
  // python has to refuse by name. What they do NOT stop is a hand-rolled
  // Definition that exports no provider - so that is refused here, and
  // named with the call that would have built it.
  static void adefinitionthatisnotaproviderpluginisrefused() {
    Definition bare = new Definition("bare");

    contains(
        refused(() -> new Sekreto(new Sekreto.Options()
            .plugins(List.of(bare))
            .providers(List.of(Map.of("kind", "bare"))))),
        "sekreto: not a provider plugin: bare", "a definition with no define");

    List<Definition> withnull = new ArrayList<>();
    withnull.add(null);

    contains(
        refused(() -> new Sekreto(new Sekreto.Options().plugins(withnull))),
        "sekreto: not a plugin definition: null", "a null in the plugins list");
  }

  // --- the harness ------------------------------------------------------

  interface Body {
    void run() throws Exception;
  }

  interface Built {
    void build();
  }

  /** The message a SekretoError refused a construction with. */
  static String refused(Built built) {
    try {
      built.build();
    } catch (SekretoError err) {
      return err.getMessage();
    }
    throw new AssertionError("nothing refused");
  }

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

  static List<String> sorted(List<String> items) {
    List<String> out = new ArrayList<>(items);
    out.sort(null);
    return out;
  }

  static List<String> concat(List<String> left, List<String> right) {
    List<String> out = new ArrayList<>(left);
    out.addAll(right);
    return out;
  }

  /** This port's own directory, wherever the suite was started from. */
  static Path here() {
    Path dir = Paths.get(System.getProperty("user.dir")).toAbsolutePath();

    for (int step = 0; step < 8 && null != dir; step++) {
      if (Files.exists(dir.resolve("cli").resolve("Cli.java"))) {
        return dir;
      }
      dir = dir.getParent();
    }

    throw new IllegalStateException("sekreto: java port directory not found");
  }

  static String read(Path path) {
    try {
      return new String(Files.readAllBytes(path), StandardCharsets.UTF_8);
    } catch (Exception err) {
      throw new IllegalStateException("sekreto: cannot read " + path, err);
    }
  }

  static List<Path> classfiles(Path dir) throws Exception {
    List<Path> out = new ArrayList<>();
    try (java.util.stream.Stream<Path> walk = Files.walk(dir)) {
      for (Path path : (Iterable<Path>) walk.filter(p -> p.toString().endsWith(".class"))::iterator) {
        out.add(path);
      }
    }
    return out;
  }

  /**
   * Which plugin classes a compiled class actually names.
   *
   * <p>Read from the class file, not from the source: a type a compiler
   * would erase, a constant it would inline and an import it would drop
   * are exactly the things a source-level check cannot see. The first
   * typescript draft failed on precisely that.
   */
  static Set<String> references(Path classfile) throws Exception {
    String bytes = new String(Files.readAllBytes(classfile), StandardCharsets.ISO_8859_1);
    Matcher found = Pattern.compile("com/voxgig/sekreto/plugins/([A-Za-z0-9]+)").matcher(bytes);

    Set<String> out = new TreeSet<>();
    while (found.find()) {
      out.add(found.group(1));
    }
    return out;
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

  public static void main(String[] args) {
    if (0 < args.length) {
      only = args[0];
    }

    testcase("fullset", PluginsTest::thefullsetholdseverykind);
    testcase("everykindbuilds", PluginsTest::everykindbuildsfromaspec);
    testcase("clipassesfullset", PluginsTest::theclipassesthefullset);
    testcase("oneplugin", PluginsTest::onepluginisenoughforachainthatnamesonlyit);
    testcase("unknownkind", PluginsTest::akindthatwasnotpassedinisrefusednamingthefix);
    testcase("repeatedstore", PluginsTest::arepeatedstorenamekeepsthestoreandnumberstheinstance);
    testcase("storenametag", PluginsTest::astorenamemustbeavalidtag);
    testcase("sekretoerror", PluginsTest::asekretoerrorraisedindefinecomesbackoutasitself);
    testcase("othererror", PluginsTest::anyothererrorraisedindefineisthehostsreportofit);
    testcase("customkind", PluginsTest::acustomkindisoneproviderplugincall);
    testcase("replacebuiltin", PluginsTest::apluginmayreplaceabuiltinkind);
    testcase("close", PluginsTest::closetearsthechaindownandkeepsredaction);
    testcase("corereachesnoplugin", PluginsTest::thecoreimportsnoplugin);
    testcase("onepluginreachesitself", PluginsTest::onepluginreachesonlyitself);
    testcase("fullsetreacheseveryplugin", PluginsTest::thefullsetreacheseveryplugin);
    testcase("notaproviderplugin", PluginsTest::adefinitionthatisnotaproviderpluginisrefused);

    System.out.println("\n" + passcount + " passed, " + failcount + " failed");
    System.exit(0 == failcount ? 0 : 1);
  }
}
