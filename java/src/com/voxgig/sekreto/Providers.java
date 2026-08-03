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
  public static final class Vault implements Provider {
    private final String addr;
    private final String token;
    private final String mount;

    public Vault(String addr, String token, String mount) {
      this.addr = null == addr ? "" : addr;
      this.token = null == token ? "" : token;
      this.mount = null == mount || mount.isEmpty() ? "secret" : mount;
    }

    @Override
    @SuppressWarnings("unchecked")
    public String lookup(String name) {
      Map<String, Object> ref = Sekreto.vaultref(name);
      String url = trimslash(addr) + "/v1/" + mount + "/data/" + ref.get("path");

      HttpResponse<String> response = httpget(url, "X-Vault-Token", token);

      if (404 == response.statusCode()) {
        return null;
      }

      if (200 != response.statusCode()) {
        throw new SekretoError("sekreto: vault error: " + response.statusCode() + ": " + url);
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
      return "vault:" + addr + "/" + mount;
    }
  }

  /**
   * A boru vault.
   *
   * <p>The boru vault protocol as sekreto uses it: a GET of
   * `{addr}/vault/{path}?field={field}` with an `X-Boru-Token` header,
   * answering `{"ok":true,"value":"..."}` when the secret exists and
   * `{"ok":false}` (or 404) when it does not.
   */
  public static final class Boru implements Provider {
    private final String addr;
    private final String token;

    public Boru(String addr, String token) {
      this.addr = null == addr ? "" : addr;
      this.token = null == token ? "" : token;
    }

    @Override
    @SuppressWarnings("unchecked")
    public String lookup(String name) {
      Map<String, Object> ref = Sekreto.vaultref(name);
      String url = trimslash(addr) + "/vault/" + ref.get("path") + "?field="
          + URLEncoder.encode(String.valueOf(ref.get("field")), StandardCharsets.UTF_8);

      HttpResponse<String> response = httpget(url, "X-Boru-Token", token);

      if (404 == response.statusCode()) {
        return null;
      }

      if (200 != response.statusCode()) {
        throw new SekretoError("sekreto: boru vault error: " + response.statusCode() + ": " + url);
      }

      Object body = Json.parse(response.body());
      if (!(body instanceof Map)) {
        return null;
      }

      if (!Boolean.TRUE.equals(((Map<String, Object>) body).get("ok"))) {
        return null;
      }

      Object value = ((Map<String, Object>) body).get("value");

      return null == value ? null : String.valueOf(value);
    }

    @Override
    public String describe() {
      return "boru:" + addr;
    }
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
    if ("vault".equals(kind)) {
      return new Vault(
          textor(spec.get("addr"), ""), textor(spec.get("token"), ""), text(spec.get("mount")));
    }
    if ("boru".equals(kind)) {
      return new Boru(textor(spec.get("addr"), ""), textor(spec.get("token"), ""));
    }

    throw new SekretoError("sekreto: unknown provider kind: " + (null == kind ? "" : kind));
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
