// RUN: make test
// RUN-SOME: java -cp build/classes:$(OMNI)/java/build SekretoTest envkey
//
// The sekreto conformance suite. Every port runs these same groups, from
// the same spec/sekreto.json, through its own voxgig/omni runner.
//
// No third-party test framework: a failing omni check throws OmniError, so
// any host framework (JUnit included) reports it as a failure. This harness
// keeps `make test` dependency-free.

import com.voxgig.omni.Runner;
import com.voxgig.omni.Runner.RunPack;
import com.voxgig.omni.Runner.Subject;
import com.voxgig.sekreto.Provider;
import com.voxgig.sekreto.Providers;
import com.voxgig.sekreto.Sekreto;
import java.io.File;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;

public final class SekretoTest {

  private static String only = null;
  private static int passcount = 0;
  private static int failcount = 0;

  private SekretoTest() {}

  /** Find the shared spec directory by walking up from the working directory. */
  static String specfile(String name) {
    File dir = new File(System.getProperty("user.dir"));

    for (int step = 0; step < 8 && null != dir; step++) {
      File cand = new File(new File(dir, "spec"), name);
      if (cand.exists()) {
        return cand.getAbsolutePath();
      }
      dir = dir.getParentFile();
    }

    throw new IllegalStateException("sekreto: spec not found: " + name);
  }

  /** Build a Sekreto from the spec's declarative chain description. */
  @SuppressWarnings("unchecked")
  static Sekreto chainof(Object value) {
    Map<String, Object> entry = (Map<String, Object>) value;
    List<Provider> providers = Providers.makechain(entry.get("chain"));
    return new Sekreto(providers, false);
  }

  @SuppressWarnings("unchecked")
  static Map<String, Object> entry(Object value) {
    return (Map<String, Object>) value;
  }

  static String text(Object value) {
    return null == value ? null : String.valueOf(value);
  }

  static final Subject VALIDNAME = args -> Sekreto.validname(args[0]);

  static final Subject ENVKEY =
      args -> Sekreto.envkey(entry(args[0]).get("name"), text(entry(args[0]).get("prefix")));

  static final Subject VAULTREF = args -> Sekreto.vaultref(args[0]);

  static final Subject PARSEDOTENV = args -> Sekreto.parsedotenv(args[0]);

  static final Subject RESOLVE = args -> chainof(args[0]).get(text(entry(args[0]).get("name")));

  static final Subject TRYSECRET =
      args -> chainof(args[0]).tryget(text(entry(args[0]).get("name")));

  static final Subject SOURCES = args -> chainof(args[0]).sources();

  @SuppressWarnings("unchecked")
  static final Subject REDACT =
      args -> Sekreto.redact(entry(args[0]).get("text"), (List<Object>) entry(args[0]).get("values"));

  interface Body {
    void run();
  }

  /** Run one named test case, reporting pass or fail. */
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
      System.out.println(err.getMessage());
    }
  }

  public static void main(String[] args) {
    if (0 < args.length) {
      only = args[0];
    }

    RunPack R = Runner.makeRunner(specfile("sekreto.json"), null).runner("sekreto");

    testcase(
        "validname",
        () -> R.runsetflags(R.set("validname"), Runner.flags("null", false), VALIDNAME));
    testcase("envkey", () -> R.runset(R.set("envkey"), ENVKEY));
    testcase("vaultref", () -> R.runset(R.set("vaultref"), VAULTREF));
    testcase("parsedotenv", () -> R.runset(R.set("parsedotenv"), PARSEDOTENV));
    testcase("resolve", () -> R.runset(R.set("resolve"), RESOLVE));
    testcase("trysecret", () -> R.runset(R.set("trysecret"), TRYSECRET));
    testcase("sources", () -> R.runset(R.set("sources"), SOURCES));
    testcase("redact", () -> R.runset(R.set("redact"), REDACT));

    System.out.println("\n" + passcount + " passed, " + failcount + " failed");
    System.exit(0 == failcount ? 0 : 1);
  }
}
