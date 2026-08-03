// A tiny app that needs a secret.
//
// It asks sekreto for `api.token` and calls the token-protected API with
// it. Every port ships this same CLI, and test/integration.sh runs all of
// them against the same server from all four secret sources - which is what
// proves the library, rather than the spec alone.
//
// Usage: java -cp build/classes sekreto.Cli <api-url> [--source <source>]
//                                                     [--store <name>]

package sekreto;

import com.voxgig.sekreto.Json;
import com.voxgig.sekreto.Provider;
import com.voxgig.sekreto.Providers;
import com.voxgig.sekreto.Sekreto;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

public final class Cli {

  private static final String LANG = "java";

  private Cli() {}

  static String envor(String name, String fallback) {
    String value = System.getenv(name);
    return null == value || value.isEmpty() ? fallback : value;
  }

  static Map<String, Object> spec(Object... pairs) {
    Map<String, Object> out = new LinkedHashMap<>();
    for (int index = 0; index + 1 < pairs.length; index += 2) {
      out.put(String.valueOf(pairs[index]), pairs[index + 1]);
    }
    return out;
  }

  static List<Object> chainspecs(String source) {
    Map<String, Object> envspec = spec("kind", "env", "prefix", System.getenv("SEKRETO_PREFIX"));
    Map<String, Object> dotenvspec =
        spec("kind", "dotenv", "file", envor("SEKRETO_DOTENV", ".env"));
    Map<String, Object> hashicorpspec = spec(
        "kind", "hashicorp",
        "addr", envor("VAULT_ADDR", ""),
        "token", envor("VAULT_TOKEN", ""),
        "mount", System.getenv("VAULT_MOUNT"));
    Map<String, Object> boruspec = spec(
        "kind", "boru",
        "command", envor("BORU_COMMAND", "boru"),
        "namespace", System.getenv("BORU_NAMESPACE"),
        "home", System.getenv("BORU_HOME"));

    List<Object> chain = new ArrayList<>();

    if ("env".equals(source)) {
      chain.add(envspec);
    } else if ("dotenv".equals(source)) {
      chain.add(dotenvspec);
    } else if ("hashicorp".equals(source)) {
      chain.add(hashicorpspec);
    } else if ("boru".equals(source)) {
      chain.add(boruspec);
    } else {
      // The default: the chain an app would actually ship with - local
      // overrides first, shared vaults last.
      chain.addAll(Arrays.asList(envspec, dotenvspec, hashicorpspec, boruspec));
    }

    return chain;
  }

  @SuppressWarnings("unchecked")
  static int run(String[] args) {
    String url = 0 < args.length ? args[0] : "http://127.0.0.1:8099/whoami";

    String source = "chain";
    for (int index = 0; index < args.length; index++) {
      if ("--source".equals(args[index]) && index + 1 < args.length) {
        source = args[index + 1];
      }
    }

    // --store names a store outright: the secret must come from that one, not
    // from whichever provider happens to answer first.
    String store = "";
    for (int index = 0; index < args.length; index++) {
      if ("--store".equals(args[index]) && index + 1 < args.length) {
        store = args[index + 1];
      }
    }

    Object chain = chainspecs(source);
    Sekreto secrets =
        new Sekreto(Providers.makechain(chain), Providers.chainnames(chain), true);

    String token;
    try {
      token = store.isEmpty() ? secrets.get("api.token") : secrets.getfrom(store, "api.token");
    } catch (RuntimeException err) {
      System.err.println("sekreto-cli: " + err.getMessage());
      return 2;
    }

    HttpRequest request = HttpRequest.newBuilder()
        .uri(URI.create(url))
        .header("Authorization", "Bearer " + token)
        .header("X-Sekreto-Lang", LANG)
        .GET()
        .build();

    HttpResponse<String> response;
    try {
      response = HttpClient.newHttpClient().send(request, HttpResponse.BodyHandlers.ofString());
    } catch (Exception err) {
      System.err.println("sekreto-cli: " + secrets.redact(String.valueOf(err.getMessage())));
      return 1;
    }

    if (200 != response.statusCode()) {
      // Never print the token itself, even when the call fails.
      System.err.println("sekreto-cli: " + secrets.redact(response.body()));
      return 1;
    }

    Object body = Json.parse(response.body());
    Object caller = body instanceof Map ? ((Map<String, Object>) body).get("caller") : null;

    System.out.println(
        Json.stringify(
            spec("ok", Boolean.TRUE, "lang", LANG, "source", source, "store", store,
                "caller", caller)));

    return 0;
  }

  public static void main(String[] args) {
    System.exit(run(args));
  }
}
