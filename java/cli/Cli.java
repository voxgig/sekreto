// A tiny app that needs a secret.
//
// It asks sekreto for `api.token` and calls the token-protected API with
// it. Every port ships this same CLI, and test/integration.sh runs all of
// them against the same server from every secret source - which is what
// proves the library, rather than the spec alone.
//
// Usage: java -cp build/classes sekreto.Cli <api-url> [--source <source>]
//                                                     [--store <name>]
//
// Sources: env dotenv file hashicorp boru boruwire awssecrets awsparams
//          gcpsecrets azuresecrets onepassword doppler infisical
//          secretspec chain
//
// Each source's configuration arrives in the environment variables its
// own ecosystem already uses (VAULT_*, AWS_*, OP_CONNECT_*, ...), listed
// in chainspecs below.

package sekreto;

import com.voxgig.sekreto.Json;
import com.voxgig.sekreto.Sekreto;
import com.voxgig.sekreto.plugins.Plugins;
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
    Map<String, Object> filespec =
        spec("kind", "file", "dir", envor("SEKRETO_FILEDIR", "/run/secrets"));

    Map<String, Object> hashicorpspec = spec(
        "kind", "hashicorp",
        "addr", envor("VAULT_ADDR", ""),
        "token", envor("VAULT_TOKEN", ""),
        "mount", System.getenv("VAULT_MOUNT"),
        "vaultnamespace", System.getenv("VAULT_NAMESPACE"));
    String vaultkv = System.getenv("VAULT_KV");
    if (null != vaultkv && !vaultkv.isEmpty()) {
      hashicorpspec.put("kv", Integer.parseInt(vaultkv));
    }
    String vaultauth = System.getenv("VAULT_AUTH");
    if (null != vaultauth && !vaultauth.isEmpty()) {
      hashicorpspec.put("auth", spec(
          "method", vaultauth,
          "role", System.getenv("VAULT_ROLE"),
          "jwtfile", System.getenv("VAULT_JWT_FILE"),
          "roleid", System.getenv("VAULT_ROLE_ID"),
          "secretid", System.getenv("VAULT_SECRET_ID")));
    }

    Map<String, Object> boruspec = spec(
        "kind", "boru",
        "command", envor("BORU_COMMAND", "boru"),
        "namespace", System.getenv("BORU_NAMESPACE"),
        "home", System.getenv("BORU_HOME"));

    // The same vault over its wire protocol (`boru vault serve`) instead
    // of the CLI: an address plus a capability token from `vault grant`.
    Map<String, Object> boruwirespec = spec(
        "kind", "boru",
        "addr", envor("BORU_ADDR", ""),
        "token", envor("BORU_TOKEN", ""),
        "namespace", System.getenv("BORU_NAMESPACE"));

    Map<String, Object> awssecretsspec = spec(
        "kind", "awssecrets",
        "region", System.getenv("AWS_REGION"),
        "addr", System.getenv("AWS_ENDPOINT"));

    Map<String, Object> awsparamsspec = spec(
        "kind", "awsparams",
        "region", System.getenv("AWS_REGION"),
        "addr", System.getenv("AWS_ENDPOINT"),
        "prefix", System.getenv("AWS_PARAM_PREFIX"));

    Map<String, Object> gcpspec = spec(
        "kind", "gcpsecrets",
        "project", System.getenv("GCP_PROJECT"),
        "addr", System.getenv("GCP_ADDR"),
        "metadataaddr", System.getenv("GCP_METADATA_ADDR"));

    Map<String, Object> azurespec = spec(
        "kind", "azuresecrets",
        "vault", System.getenv("AZURE_VAULT"),
        "token", System.getenv("AZURE_TOKEN"),
        "tenant", System.getenv("AZURE_TENANT"),
        "clientid", System.getenv("AZURE_CLIENT_ID"),
        "clientsecret", System.getenv("AZURE_CLIENT_SECRET"),
        "loginaddr", System.getenv("AZURE_LOGIN_ADDR"),
        "imdsaddr", System.getenv("AZURE_IMDS_ADDR"));

    Map<String, Object> onepasswordspec = spec(
        "kind", "onepassword",
        "addr", System.getenv("OP_CONNECT_HOST"),
        "token", System.getenv("OP_CONNECT_TOKEN"),
        "vault", System.getenv("OP_VAULT"));

    Map<String, Object> dopplerspec = spec(
        "kind", "doppler",
        "token", System.getenv("DOPPLER_TOKEN"),
        "project", System.getenv("DOPPLER_PROJECT"),
        "config", System.getenv("DOPPLER_CONFIG"),
        "addr", System.getenv("DOPPLER_ADDR"));

    // SecretSpec's own environment variables where it has them, so a
    // shell already set up for secretspec needs nothing further.
    Map<String, Object> secretspecspec = spec(
        "kind", "secretspec",
        "command", envor("SECRETSPEC_COMMAND", "secretspec"),
        "file", System.getenv("SECRETSPEC_FILE"),
        "profile", System.getenv("SECRETSPEC_PROFILE"),
        "backend", System.getenv("SECRETSPEC_PROVIDER"),
        "reason", System.getenv("SECRETSPEC_REASON"));

    Map<String, Object> infisicalspec = spec(
        "kind", "infisical",
        "addr", System.getenv("INFISICAL_ADDR"),
        "token", System.getenv("INFISICAL_TOKEN"),
        "clientid", System.getenv("INFISICAL_CLIENT_ID"),
        "clientsecret", System.getenv("INFISICAL_CLIENT_SECRET"),
        "project", System.getenv("INFISICAL_PROJECT"),
        "environment", System.getenv("INFISICAL_ENV"),
        "path", System.getenv("INFISICAL_PATH"));

    List<Object> chain = new ArrayList<>();

    if ("env".equals(source)) {
      chain.add(envspec);
    } else if ("dotenv".equals(source)) {
      chain.add(dotenvspec);
    } else if ("file".equals(source)) {
      chain.add(filespec);
    } else if ("hashicorp".equals(source)) {
      chain.add(hashicorpspec);
    } else if ("boru".equals(source)) {
      chain.add(boruspec);
    } else if ("boruwire".equals(source)) {
      chain.add(boruwirespec);
    } else if ("awssecrets".equals(source)) {
      chain.add(awssecretsspec);
    } else if ("awsparams".equals(source)) {
      chain.add(awsparamsspec);
    } else if ("gcpsecrets".equals(source)) {
      chain.add(gcpspec);
    } else if ("azuresecrets".equals(source)) {
      chain.add(azurespec);
    } else if ("onepassword".equals(source)) {
      chain.add(onepasswordspec);
    } else if ("doppler".equals(source)) {
      chain.add(dopplerspec);
    } else if ("infisical".equals(source)) {
      chain.add(infisicalspec);
    } else if ("secretspec".equals(source)) {
      chain.add(secretspecspec);
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

    // THE CLI PASSES THE FULL SET, because its --source names any of the
    // fourteen kinds at run time. An app that knows its chain names only
    // the plugins it configures, and javac links no more than those.
    Sekreto secrets = new Sekreto(new Sekreto.Options()
        .plugins(Plugins.ALL)
        .providers(chainspecs(source)));

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
      // HTTP/1.1, for the same reason the library pins it (see CLIENT in
      // Providers.java): java.net.http defaults to HTTP_2, and over
      // cleartext that means an h2c upgrade a strict server rejects.
      // This request is a GET with no body, so the Content-Length
      // mismatch that breaks POSTs cannot bite here - but that is luck,
      // not design, and this is the request that carries the bearer
      // token to a URL the caller supplied.
      HttpClient client = HttpClient.newBuilder()
          .version(HttpClient.Version.HTTP_1_1)
          .build();
      response = client.send(request, HttpResponse.BodyHandlers.ofString());
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
