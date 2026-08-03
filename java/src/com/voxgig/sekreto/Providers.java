// The providers a Sekreto chains together.
//
// A port of typescript/src/Providers.ts, which is canonical.

package com.voxgig.sekreto;

import com.voxgig.sekreto.Sekreto.SekretoError;
import java.io.IOException;
import java.net.URI;
import java.net.URLEncoder;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.time.Duration;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

public final class Providers {

  private Providers() {}

  /** Environment variables: `api.token` from `API_TOKEN`. */
  public static final class Env implements Provider {
    private final String prefix;
    private final Map<String, Object> source;

    public Env(String prefix) {
      this(prefix, null);
    }

    public Env(String prefix, Map<String, Object> source) {
      this.prefix = prefix;
      this.source = source;
    }

    @Override
    public String lookup(String name) {
      String key = Sekreto.envkey(name, prefix);
      Object value = null == source ? System.getenv(key) : source.get(key);
      return null == value ? null : String.valueOf(value);
    }

    @Override
    public String describe() {
      return "env" + (null == prefix || prefix.isEmpty() ? "" : ":" + prefix);
    }
  }

  /** A `.env` file, read once, keyed exactly like the environment. */
  public static final class Dotenv implements Provider {
    private final String file;
    private final String prefix;
    private Map<String, Object> values;

    public Dotenv(String file, String prefix) {
      this.file = file;
      this.prefix = prefix;
    }

    private Map<String, Object> load() {
      if (null == values) {
        try {
          values = Sekreto.parsedotenv(
              new String(Files.readAllBytes(Paths.get(file)), StandardCharsets.UTF_8));
        } catch (IOException | RuntimeException err) {
          // A missing .env file is not an error: it means "no secrets here".
          values = new LinkedHashMap<>();
        }
      }
      return values;
    }

    @Override
    public String lookup(String name) {
      Object value = load().get(Sekreto.envkey(name, prefix));
      return null == value ? null : String.valueOf(value);
    }

    @Override
    public String describe() {
      return "dotenv:" + file;
    }
  }

  /**
   * Literal values, keyed like environment variables. The spec uses this to
   * test chain behaviour without touching the outside world.
   */
  public static final class Memory implements Provider {
    private final Map<String, Object> values;
    private final String prefix;

    public Memory(Map<String, Object> values, String prefix) {
      this.values = null == values ? new LinkedHashMap<>() : values;
      this.prefix = prefix;
    }

    @Override
    public String lookup(String name) {
      Object value = values.get(Sekreto.envkey(name, prefix));
      return null == value ? null : String.valueOf(value);
    }

    @Override
    public String describe() {
      return "memory" + (null == prefix || prefix.isEmpty() ? "" : ":" + prefix);
    }
  }

  /**
   * Refuse to send a Vault token in the clear.
   *
   * <p>Vault's API is HTTPS in any real deployment; plaintext is a dev-mode
   * convenience. Sending `X-Vault-Token` over http to anything but the local
   * machine puts both the token and the secret it fetches on the wire for
   * anyone on the path, so sekreto will not do it. Loopback stays allowed:
   * that is `vault server -dev` and this repo's own test harness.
   */
  public static void checkaddr(String addr) {
    if (addr.startsWith("https://")) {
      return;
    }

    if (!addr.startsWith("http://")) {
      throw new SekretoError("sekreto: not an http(s) address: " + addr);
    }

    String host = addr.substring("http://".length()).split("/")[0].split(":")[0];

    if ("localhost".equals(host)
        || "127.0.0.1".equals(host)
        || "::1".equals(host)
        || "[::1]".equals(host)) {
      return;
    }

    throw new SekretoError(
        "sekreto: refusing to send a token in plaintext to " + addr + " (use https)");
  }

  private static final HttpClient CLIENT =
      HttpClient.newBuilder().connectTimeout(Duration.ofSeconds(10)).build();

  /**
   * GET a URL. A 404 is a normal answer here, not a failure: it means the
   * vault does not hold this secret.
   */
  static HttpResponse<String> httpget(String url, String header, String token) {
    HttpRequest request = HttpRequest.newBuilder()
        .uri(URI.create(url))
        .header(header, token)
        .timeout(Duration.ofSeconds(10))
        .GET()
        .build();

    try {
      return CLIENT.send(request, HttpResponse.BodyHandlers.ofString());
    } catch (IOException | InterruptedException err) {
      throw new SekretoError("sekreto: cannot reach " + url + ": " + err.getMessage());
    }
  }

  /**
   * HashiCorp Vault, KV v2.
   *
   * <p>`api.token` reads `{addr}/v1/{mount}/data/api` and takes the `token`
   * field of `data.data`. A 404 means "not here", which is a miss rather
   * than an error, so a vault can sit in a chain with fallbacks.
   */
  public static final class Hashicorp implements Provider {
    private final String addr;
    private final String token;
    private final String mount;

    public Hashicorp(String addr, String token, String mount) {
      this.addr = null == addr ? "" : addr;
      this.token = null == token ? "" : token;
      this.mount = null == mount || mount.isEmpty() ? "secret" : mount;
    }

    @Override
    @SuppressWarnings("unchecked")
    public String lookup(String name) {
      checkaddr(addr);

      Map<String, Object> ref = Sekreto.vaultref(name);
      String url = trimslash(addr) + "/v1/" + mount + "/data/" + ref.get("path");

      HttpResponse<String> response = httpget(url, "X-Vault-Token", token);

      if (404 == response.statusCode()) {
        return null;
      }

      if (200 != response.statusCode()) {
        throw new SekretoError("sekreto: hashicorp error: " + response.statusCode() + ": " + url);
      }

      Object body = Json.parse(response.body());
      if (!(body instanceof Map)) {
        return null;
      }

      Object outer = ((Map<String, Object>) body).get("data");
      if (!(outer instanceof Map)) {
        return null;
      }

      Object data = ((Map<String, Object>) outer).get("data");
      if (!(data instanceof Map)) {
        return null;
      }

      Object value = ((Map<String, Object>) data).get(ref.get("field"));

      return null == value ? null : String.valueOf(value);
    }

    @Override
    public String describe() {
      return "hashicorp:" + addr + "/" + mount;
    }
  }

  /**
   * A boru vault (https://github.com/boru-lang/boru).
   *
   * <p>boru keeps secrets in a local encrypted keyring and hands a value out
   * through its own CLI: `boru vault get --reveal <alias>` prints the secret
   * on stdout, and nothing else.
   *
   * <p>There is deliberately no HTTP read here. boru's `vault proxy` and
   * `vault mcp` are a *credential broker*: they inject the real secret into
   * an outbound request and forward it, so an agent can call an API without
   * ever holding the credential. Handing a value back is the one thing that
   * broker is built not to do, so sekreto reads the vault the way boru itself
   * does - through the CLI.
   *
   * <p>A sekreto name is already a valid boru alias, so `api.token` crosses
   * over unchanged. A namespace qualifies it the way boru writes it,
   * `ns:name`.
   *
   * <p>The passphrase is read by boru itself from `BORU_VAULT_PASSPHRASE`.
   * sekreto never accepts it as config and never puts it on a command line,
   * where it would show up in the process table.
   */
  public static final class Boru implements Provider {
    private final String command;
    private final String namespace;
    private final String home;

    public Boru(String command, String namespace, String home) {
      this.command = null == command || command.isEmpty() ? "boru" : command;
      this.namespace = namespace;
      this.home = home;
    }

    @Override
    public String lookup(String name) {
      Sekreto.checkname(name);

      String alias = null == namespace || namespace.isEmpty() ? name : namespace + ":" + name;

      ProcessBuilder builder =
          new ProcessBuilder(command, "vault", "get", "--reveal", alias);

      if (null != home && !home.isEmpty()) {
        builder.environment().put("BORU_HOME", home);
      }

      String out;
      String why;
      int status;

      try {
        Process process = builder.start();
        out = new String(process.getInputStream().readAllBytes(), StandardCharsets.UTF_8);
        why = new String(process.getErrorStream().readAllBytes(), StandardCharsets.UTF_8).trim();
        status = process.waitFor();
      } catch (IOException err) {
        throw new SekretoError("sekreto: cannot run " + command + ": " + err.getMessage());
      } catch (InterruptedException err) {
        Thread.currentThread().interrupt();
        throw new SekretoError("sekreto: interrupted running " + command);
      }

      if (0 == status) {
        // boru prints the value and one newline, and nothing else.
        return out.endsWith("\n") ? out.substring(0, out.length() - 1) : out;
      }

      // "no alias named" is boru saying it does not hold this secret, which is
      // a miss: the chain carries on to the next provider. A locked vault or a
      // wrong passphrase is not a miss - treating it as one would fall through
      // to a weaker store without saying so.
      if (borumiss(why)) {
        return null;
      }

      throw new SekretoError(
          "sekreto: boru vault error: " + (why.isEmpty() ? "exit " + status : why));
    }

    @Override
    public String describe() {
      return "boru" + (null == namespace || namespace.isEmpty() ? "" : ":" + namespace);
    }
  }

  /**
   * Does this boru failure mean "no such secret" rather than "I could not
   * answer"? Matched on boru's own wording for a missing alias.
   */
  static boolean borumiss(String why) {
    return why.contains("no alias named");
  }

  static String trimslash(String text) {
    return text.endsWith("/") ? text.substring(0, text.length() - 1) : text;
  }

  static String text(Object value) {
    return null == value ? null : String.valueOf(value);
  }

  static String textor(Object value, String fallback) {
    return null == value ? fallback : String.valueOf(value);
  }

  /**
   * Build a provider from its declarative form - the same shape the shared
   * spec and an app's config file use.
   */
  @SuppressWarnings("unchecked")
  public static Provider makeprovider(Map<String, Object> spec) {
    String kind = text(spec.get("kind"));

    if ("env".equals(kind)) {
      return new Env(text(spec.get("prefix")));
    }
    if ("dotenv".equals(kind)) {
      return new Dotenv(textor(spec.get("file"), ".env"), text(spec.get("prefix")));
    }
    if ("memory".equals(kind)) {
      Object values = spec.get("values");
      return new Memory(
          values instanceof Map ? (Map<String, Object>) values : null, text(spec.get("prefix")));
    }
    if ("hashicorp".equals(kind)) {
      return new Hashicorp(
          textor(spec.get("addr"), ""), textor(spec.get("token"), ""), text(spec.get("mount")));
    }
    if ("boru".equals(kind)) {
      return new Boru(
          text(spec.get("command")), text(spec.get("namespace")), text(spec.get("home")));
    }

    throw new SekretoError("sekreto: unknown provider kind: " + (null == kind ? "" : kind));
  }

  /**
   * The store name each spec asks for, in order, so Sekreto.getfrom can
   * address them. An entry is empty when the spec does not name one.
   */
  @SuppressWarnings("unchecked")
  public static List<String> chainnames(Object specs) {
    List<String> out = new ArrayList<>();

    if (!(specs instanceof List)) {
      return out;
    }

    for (Object entry : (List<Object>) specs) {
      if (entry instanceof Map) {
        Object name = ((Map<String, Object>) entry).get("name");
        out.add(null == name ? "" : String.valueOf(name));
      }
    }

    return out;
  }

  /** Build a whole provider chain from its declarative form. */
  @SuppressWarnings("unchecked")
  public static List<Provider> makechain(Object specs) {
    List<Provider> out = new ArrayList<>();

    if (!(specs instanceof List)) {
      return out;
    }

    for (Object entry : (List<Object>) specs) {
      if (entry instanceof Map) {
        out.add(makeprovider((Map<String, Object>) entry));
      }
    }

    return out;
  }
}
