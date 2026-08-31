// The providers a Sekreto chains together.
//
// A provider answers one question: "do you have this secret?" It returns
// the value, or null to mean "ask the next one". Nothing else about a
// provider is visible to the caller - which is the point: an app reads
// `api.token` and never learns whether it came from the environment, a
// .env file, HashiCorp Vault, AWS, GCP, Azure or a boru vault.
//
// Two failure shapes, and they are never interchangeable. A store that
// does not hold the secret is a MISS (null) - the chain carries on. A
// store that could not answer - bad credentials, unreachable host,
// missing configuration - is an ERROR: falling through there would
// quietly reach for a weaker store.
//
// A port of typescript/src/Providers.ts, which is canonical.

package com.voxgig.sekreto;

import com.voxgig.sekreto.Sekreto.SekretoError;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.NoSuchFileException;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.time.Duration;
import java.time.Instant;
import java.time.ZoneOffset;
import java.time.format.DateTimeFormatter;
import java.util.ArrayList;
import java.util.Base64;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

public final class Providers {

  private Providers() {}

  /**
   * Does this read failure mean "no secrets here", rather than "I could not
   * answer"?
   *
   * <p>Absence is a MISS and the chain carries on; anything else - permission
   * denied, an unreadable mount, a failing disk - is an ERROR, because
   * returning a miss there falls silently through to a weaker store.
   *
   * <p>Asked of the directory, not of the file. The obvious spelling,
   * {@code !Files.exists(file)}, is wrong in exactly the case the rule exists
   * for: {@code Files.exists} is "did checkAccess throw", so it answers
   * <em>false</em> for an {@code AccessDeniedException} and turned a locked
   * directory - the canonical "unreadable mount" - into a miss. A path whose
   * parent is a plain file (ENOTDIR) really is "no secrets here", and that is
   * what this asks. The reason string is not consulted: it comes from the C
   * library's strerror and follows the machine's locale.
   */
  static boolean absent(Path file) {
    Path dir = file.getParent();
    return null != dir && !Files.isDirectory(dir);
  }

  /**
   * How much of a response body will be read before the store is treated as
   * having answered incoherently. Ports carry the same bound.
   *
   * <p>Far above anything real - the largest legitimate payload this library
   * fetches is Doppler's whole-config download, measured in kilobytes. A
   * bound is needed because the TIMEOUT is not one: ten seconds on a loopback
   * or datacentre link is gigabytes, and the body is accumulated in memory
   * before it is parsed. This runs on an application's startup path, so the
   * failure is the application never starting.
   */
  private static final int MAXBODY = 8 * 1024 * 1024;

  /** What a finished child process left behind. */
  static final class Ran {
    final String out;
    final String why;
    final int status;

    Ran(String out, String why, int status) {
      this.out = out;
      this.why = why;
      this.status = status;
    }
  }

  /**
   * Run a child to completion and collect both its streams.
   *
   * <p>The two streams are drained CONCURRENTLY. Reading stdout to EOF and
   * only then reading stderr deadlocks the moment the child writes more than
   * one pipe buffer (64 KiB on Linux) to stderr: the parent is blocked
   * waiting for stdout, the child is blocked waiting for room on stderr, and
   * neither can move. Nothing in this library sets a timeout, so that hang is
   * permanent - `get()` simply never returns. secretspec's diagnostics are
   * box-drawn and reach that size easily.
   *
   * <p>The child's stdin is closed rather than left open on a pipe nobody
   * writes to, so a CLI that reads it - one prompting for a passphrase when
   * its environment variable is absent - sees EOF and gives up instead of
   * waiting forever.
   */
  static Ran runcmd(ProcessBuilder builder, String command) {
    try {
      Process process = builder.start();

      process.getOutputStream().close();

      ByteArrayOutputStream errbuf = new ByteArrayOutputStream();
      Thread drain =
          new Thread(
              () -> {
                try {
                  process.getErrorStream().transferTo(errbuf);
                } catch (IOException err) {
                  // The child went away mid-write; waitFor reports how.
                }
              });
      drain.setDaemon(true);
      drain.start();

      String out = new String(process.getInputStream().readAllBytes(), StandardCharsets.UTF_8);
      int status = process.waitFor();
      drain.join();

      return new Ran(out, new String(errbuf.toByteArray(), StandardCharsets.UTF_8).trim(), status);
    } catch (IOException err) {
      throw new SekretoError("sekreto: cannot run " + command + ": " + err.getMessage());
    } catch (InterruptedException err) {
      Thread.currentThread().interrupt();
      throw new SekretoError("sekreto: interrupted running " + command);
    }
  }

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
        Path path = Paths.get(file);
        try {
          values = Sekreto.parsedotenv(
              new String(Files.readAllBytes(path), StandardCharsets.UTF_8));
        } catch (NoSuchFileException err) {
          // An absent file - or an absent directory - means "no secrets
          // here", exactly like the file provider.
          values = new LinkedHashMap<>();
        } catch (IOException err) {
          if (absent(path)) {
            values = new LinkedHashMap<>();
          } else {
            throw new SekretoError(
                "sekreto: dotenv provider cannot read " + file + ": " + err.getMessage());
          }
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
   * A directory of one-secret-per-file entries, keyed like the environment:
   * `api.token` reads `<dir>/API_TOKEN`.
   *
   * <p>This is the shape of a mounted Kubernetes Secret, a Docker or Swarm
   * secret, and a systemd credentials directory, so those all work with no
   * further configuration. One trailing newline is stripped - tools that
   * write these files disagree about it, and a newline is never part of a
   * secret on purpose.
   */
  public static final class File implements Provider {
    private final String dir;
    private final String prefix;

    public File(String dir, String prefix) {
      this.dir = null == dir ? "" : dir;
      this.prefix = prefix;
    }

    @Override
    public String lookup(String name) {
      Path file = Paths.get(dir, Sekreto.envkey(name, prefix));

      String text;
      try {
        text = new String(Files.readAllBytes(file), StandardCharsets.UTF_8);
      } catch (NoSuchFileException err) {
        // An absent file - or an absent directory - means "no secrets
        // here", exactly like a missing .env.
        return null;
      } catch (IOException err) {
        if (absent(file)) {
          return null;
        }
        throw new SekretoError(
            "sekreto: file provider cannot read " + file + ": " + err.getMessage());
      }

      if (text.endsWith("\r\n")) {
        return text.substring(0, text.length() - 2);
      }
      if (text.endsWith("\n")) {
        return text.substring(0, text.length() - 1);
      }
      return text;
    }

    @Override
    public String describe() {
      return "file:" + dir;
    }
  }

  /**
   * An address with any userinfo replaced by `[redacted]`, for messages.
   *
   * <p>Every refusal below names the address it refused, and one of them
   * fires precisely because the address carries a credential - so printing it
   * verbatim wrote the password to stderr and into the logs. It cannot be
   * cleaned up afterwards either: that password was never resolved as a
   * secret, so redact() has never seen it and never will. The host is what a
   * reader needs to identify which chain entry is at fault; the userinfo is
   * not.
   */
  static String safeaddr(String addr) {
    int mark = addr.indexOf("://");
    if (-1 == mark) {
      return addr;
    }

    String rest = addr.substring(mark + 3);
    int end = rest.length();
    for (String mark2 : new String[] {"/", "?", "#"}) {
      int found = rest.indexOf(mark2);
      if (-1 != found && found < end) {
        end = found;
      }
    }

    int at = rest.substring(0, end).lastIndexOf('@');
    if (-1 == at) {
      return addr;
    }

    return addr.substring(0, mark + 3) + "[redacted]" + addr.substring(mark + 3 + at);
  }

  /**
   * Refuse to send a secret-bearing credential in the clear.
   *
   * <p>A vault API is HTTPS in any real deployment; plaintext is a dev-mode
   * convenience. Sending a token over http to anything but the local machine
   * puts both the token and the secret it fetches on the wire for anyone on
   * the path, so sekreto will not do it. Loopback stays allowed: that is
   * `vault server -dev`, `boru vault serve`, and this repo's own test
   * harness.
   *
   * <p>The address is read by hand, in the same handful of steps in every
   * port, rather than by each platform's URL parser. That is deliberate.
   * Twelve parsers disagree about malformed input - where userinfo ends,
   * whether `0177.0.0.1` is loopback, what an unclosed bracket means - and a
   * check that answers differently in different ports is not a check.
   *
   * <p>The rule this parse obeys, and the reason it can be trusted: it is
   * never more permissive than the HTTP client that will dial the address. It
   * ends the authority at `/`, `?` or `#` only, so a client that also breaks
   * on `\` (WHATWG does) can only ever see a SHORTER host than this does. It
   * refuses userinfo outright rather than locating its end. It compares the
   * host literally, so a numeric form no parser here agrees on is refused
   * rather than guessed at.
   */
  public static void checkaddr(String addr) {
    String scheme;
    if (addr.startsWith("https://")) {
      scheme = "https://";
    } else if (addr.startsWith("http://")) {
      scheme = "http://";
    } else {
      throw new SekretoError("sekreto: not an http(s) address: " + safeaddr(addr));
    }

    String rest = addr.substring(scheme.length());

    int end = rest.length();
    for (String mark : new String[] {"/", "?", "#"}) {
      int at = rest.indexOf(mark);
      if (-1 != at && at < end) {
        end = at;
      }
    }
    String authority = rest.substring(0, end);

    // Userinfo is refused outright rather than parsed around, and on https as
    // well as http. No store this library speaks authenticates by userinfo -
    // they take a token or a signature - so an address carrying one is a
    // mistake at best. At worst it is the attack this whole function exists
    // to stop: http://localhost:8200@evil.example.com/ is a request to
    // evil.example.com that reads, to anything that splits the authority on
    // ':', as loopback.
    if (authority.contains("@")) {
      throw new SekretoError("sekreto: refusing an address with embedded credentials: " + safeaddr(addr));
    }

    // An opening bracket with no closing one is not an address at all.
    if (authority.startsWith("[") && !authority.contains("]")) {
      throw new SekretoError("sekreto: not a valid http(s) address: " + safeaddr(addr));
    }

    if ("https://".equals(scheme)) {
      return;
    }

    // A bracketed IPv6 literal keeps its brackets. Splitting the authority on
    // the first colon yields "[", so http://[::1]:8200 could never match -
    // which made the "[::1]" entry below unreachable, and refused a
    // legitimate local vault.
    String host;
    if (authority.startsWith("[")) {
      host = authority.substring(0, authority.indexOf("]") + 1);
    } else {
      int colon = authority.indexOf(':');
      host = -1 == colon ? authority : authority.substring(0, colon);
    }
    host = host.toLowerCase(java.util.Locale.ROOT);

    if ("localhost".equals(host)
        || "127.0.0.1".equals(host)
        || "::1".equals(host)
        || "[::1]".equals(host)) {
      return;
    }

    throw new SekretoError(
        "sekreto: refusing to send a token in plaintext to " + safeaddr(addr) + " (use https)");
  }

  // HTTP/1.1, explicitly.
  //
  // java.net.http defaults to HTTP_2, and over cleartext that means an h2c
  // upgrade: the first request goes out with `Upgrade: h2c`, the declared
  // Content-Length, and NO BODY, and the body follows only after the server
  // declines. A server that checks the two against each other - Fastify
  // does, and Infisical is Fastify - rejects that request outright with
  // "Request body size did not match Content-Length", so every POST this
  // port makes to such a server fails before it is even read.
  //
  // The mocks in test/ are Node's own http module, which does not object,
  // which is why this survived until the same code met a real Infisical.
  // No vault API this library speaks needs HTTP/2.
  private static final HttpClient CLIENT = HttpClient.newBuilder()
      .version(HttpClient.Version.HTTP_1_1)
      .connectTimeout(Duration.ofSeconds(10))
      .build();

  /** One JSON round-trip's result: the status, and the parsed body. */
  static final class Answer {
    final int status;
    final Object body;

    Answer(int status, Object body) {
      this.status = status;
      this.body = body;
    }
  }

  /**
   * One JSON round-trip. Network failure is always an error - an
   * unreachable store is a store that could not answer.
   */
  static Answer fetchjson(String method, String url, Map<String, String> headers, String body) {
    HttpRequest.Builder builder = HttpRequest.newBuilder()
        .uri(URI.create(url))
        .timeout(Duration.ofSeconds(10))
        .method(method, null == body
            ? HttpRequest.BodyPublishers.noBody()
            : HttpRequest.BodyPublishers.ofString(body, StandardCharsets.UTF_8));

    if (null != headers) {
      for (Map.Entry<String, String> entry : headers.entrySet()) {
        builder.header(entry.getKey(), entry.getValue());
      }
    }

    // ofInputStream, not ofString: ofString buffers whatever arrives, so an
    // endless body would be accumulated in memory until the deadline - which
    // on a loopback or datacentre link is gigabytes.
    HttpResponse<java.io.InputStream> response;
    try {
      response = CLIENT.send(builder.build(), HttpResponse.BodyHandlers.ofInputStream());
    } catch (IOException err) {
      throw new SekretoError(
          "sekreto: cannot reach " + url.split("\\?")[0] + ": " + err.getMessage());
    } catch (InterruptedException err) {
      Thread.currentThread().interrupt();
      throw new SekretoError("sekreto: cannot reach " + url.split("\\?")[0] + ": interrupted");
    }

    String text;
    try (java.io.InputStream stream = response.body()) {
      // One byte over the bound is enough to know it was exceeded. An
      // endless body is a store that could not answer, so this raises
      // rather than returning a miss - the latter would fall through to a
      // weaker store on an attacker's cue.
      byte[] raw = stream.readNBytes(MAXBODY + 1);
      if (MAXBODY < raw.length) {
        throw new SekretoError("sekreto: oversized response from " + url.split("\\?")[0]);
      }
      text = new String(raw, StandardCharsets.UTF_8);
    } catch (IOException err) {
      throw new SekretoError(
          "sekreto: cannot reach " + url.split("\\?")[0] + ": " + err.getMessage());
    }

    // A success status promised JSON; a body that does not parse means
    // the store could not answer coherently, and treating it as a miss
    // would fall through to a weaker store. Error statuses may carry
    // any body - they are decided on status alone. (Json.parse answers
    // null for anything unreadable, and only a literal `null` body is a
    // genuine JSON null.)
    Object parsed = Json.parse(text);
    if (200 == response.statusCode() && null == parsed && !"null".equals(text.trim())) {
      throw new SekretoError("sekreto: malformed response from " + url.split("\\?")[0]);
    }

    return new Answer(response.statusCode(), parsed);
  }

  /** A one-pair header map, the shape most requests here need. */
  static Map<String, String> headers(String... pairs) {
    Map<String, String> out = new LinkedHashMap<>();
    for (int index = 0; index + 1 < pairs.length; index += 2) {
      out.put(pairs[index], pairs[index + 1]);
    }
    return out;
  }

  /** Walk nested JSON maps; null the moment a step is not there. */
  @SuppressWarnings("unchecked")
  static Object dig(Object value, String... keys) {
    for (String key : keys) {
      if (!(value instanceof Map)) {
        return null;
      }
      value = ((Map<String, Object>) value).get(key);
    }
    return value;
  }

  /** The first value that is set and non-empty, or empty. */
  static String first(String... candidates) {
    for (String candidate : candidates) {
      if (null != candidate && !candidate.isEmpty()) {
        return candidate;
      }
    }
    return "";
  }

  /**
   * When a logged-in token must be renewed, from its expiry in seconds
   * (a JSON number, or a string as Azure IMDS sends it): now +
   * max(seconds - 60, 1). A missing or zero expiry means never renew.
   */
  static long renewtime(Object expires) {
    double seconds = 0;
    if (expires instanceof Number) {
      seconds = ((Number) expires).doubleValue();
    } else if (expires instanceof String) {
      try {
        seconds = Double.parseDouble((String) expires);
      } catch (NumberFormatException err) {
        seconds = 0;
      }
    }

    if (0 >= seconds || Double.isNaN(seconds)) {
      return Long.MAX_VALUE;
    }

    return System.currentTimeMillis() + (long) (Math.max(seconds - 60, 1) * 1000);
  }

  /**
   * HashiCorp Vault.
   *
   * <p>KV v2 (the default): `api.token` reads `{addr}/v1/{mount}/data/api`
   * and takes the `token` field of `data.data`. KV v1 (`kv: 1`) reads
   * `{addr}/v1/{mount}/api` and takes the field of `data`. A 404 means "not
   * here" - a miss - so a vault can sit in a chain with fallbacks.
   *
   * <p>A Vault Enterprise namespace rides the X-Vault-Namespace header, on
   * logins as well as reads.
   *
   * <p>Instead of being handed a token, the provider can log in: Kubernetes
   * auth (the pod's service-account JWT, from its conventional path) or
   * AppRole. A failed login is an error, never a miss - it means this store
   * could not answer at all.
   */
  public static final class Hashicorp implements Provider {
    private final String addr;
    private final String mount;
    private final int kv;
    private final String vaultnamespace;
    private final Map<String, Object> auth;

    // The working token: a configured token is kept forever, a logged-in
    // token is renewed shortly before its lease runs out - a long-running
    // process must not keep presenting a token the vault already expired.
    private String livetoken;
    private long renewat = Long.MAX_VALUE;

    public Hashicorp(String addr, String token, String mount) {
      this(addr, token, mount, 0, null, null);
    }

    public Hashicorp(String addr, String token, String mount, int kv,
        String vaultnamespace, Map<String, Object> auth) {
      this.addr = null == addr ? "" : addr;
      this.mount = null == mount || mount.isEmpty() ? "secret" : mount;
      this.kv = 0 == kv ? 2 : kv;

      // A version typo like kv: 3 must not quietly behave as v2 and turn
      // its 404s into misses; there is nothing safe to assume it meant.
      if (1 != this.kv && 2 != this.kv) {
        throw new SekretoError("sekreto: hashicorp: unsupported kv version: " + this.kv);
      }

      this.vaultnamespace = vaultnamespace;
      this.auth = auth;
      this.livetoken = null == token || token.isEmpty() ? null : token;
    }

    private Map<String, String> baseheaders() {
      Map<String, String> out = new LinkedHashMap<>();
      if (null != vaultnamespace && !vaultnamespace.isEmpty()) {
        out.put("X-Vault-Namespace", vaultnamespace);
      }
      return out;
    }

    private String login() {
      if (null == auth) {
        throw new SekretoError("sekreto: hashicorp: no token and no auth method");
      }

      String method = text(auth.get("method"));
      String authmount = first(text(auth.get("mount")), null == method ? "" : method);
      String url = trimslash(addr) + "/v1/auth/" + authmount + "/login";

      Map<String, Object> body = new LinkedHashMap<>();
      if ("kubernetes".equals(method)) {
        String jwt = text(auth.get("jwt"));
        if (null == jwt) {
          String file = textor(
              auth.get("jwtfile"), "/var/run/secrets/kubernetes.io/serviceaccount/token");
          try {
            jwt = new String(Files.readAllBytes(Paths.get(file)), StandardCharsets.UTF_8).trim();
          } catch (IOException err) {
            throw new SekretoError("sekreto: hashicorp: cannot read jwt file " + file);
          }
        }
        body.put("role", textor(auth.get("role"), ""));
        body.put("jwt", jwt);
      } else if ("approle".equals(method)) {
        body.put("role_id", textor(auth.get("roleid"), ""));
        body.put("secret_id", textor(auth.get("secretid"), ""));
      } else {
        throw new SekretoError(
            "sekreto: hashicorp: unknown auth method: " + (null == method ? "" : method));
      }

      Answer res = fetchjson("POST", url, baseheaders(), Json.stringify(body));

      Object got = dig(res.body, "auth", "client_token");
      if (200 != res.status || null == got || String.valueOf(got).isEmpty()) {
        throw new SekretoError("sekreto: hashicorp login failed: " + res.status + ": " + url);
      }

      renewat = renewtime(dig(res.body, "auth", "lease_duration"));

      return String.valueOf(got);
    }

    @Override
    @SuppressWarnings("unchecked")
    public String lookup(String name) {
      checkaddr(addr);

      if (null == livetoken || System.currentTimeMillis() >= renewat) {
        livetoken = login();
      }

      Map<String, Object> ref = Sekreto.vaultref(name);
      String base = trimslash(addr) + "/v1/" + mount;
      String url = 1 == kv ? base + "/" + ref.get("path") : base + "/data/" + ref.get("path");

      Map<String, String> requestheaders = baseheaders();
      requestheaders.put("X-Vault-Token", livetoken);

      Answer res = fetchjson("GET", url, requestheaders, null);

      if (404 == res.status) {
        return null;
      }

      if (200 != res.status) {
        throw new SekretoError("sekreto: hashicorp error: " + res.status + ": " + url);
      }

      Object data = 1 == kv ? dig(res.body, "data") : dig(res.body, "data", "data");

      Object value = data instanceof Map ? ((Map<String, Object>) data).get(ref.get("field")) : null;
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
   * <p>Two ways in, both boru's own.
   *
   * <p>With no `addr`, the CLI: `boru vault get --reveal <alias>` prints the
   * secret on stdout and nothing else. The passphrase is read by boru itself
   * from `BORU_VAULT_PASSPHRASE`; sekreto never accepts it as config and
   * never puts it on a command line, where it would show up in the process
   * table.
   *
   * <p>With an `addr`, boru's wire protocol: `boru vault serve` publishes a
   * read-only, HashiCorp-shaped provision API (boru's
   * design/VAULT-WIRE-PROTOCOL.0.md), authenticated by a capability token
   * from `boru vault grant`. A sekreto name is already a valid boru alias,
   * and boru aliases keep their dots, so `api.token` is the single path
   * segment `api.token` - not the `api`/`token` split a HashiCorp KV gets.
   * The value is the `value` field. A 404 is a miss; anything else the
   * server refuses (a revoked capability, a sealed vault) is an error.
   *
   * <p>boru's `vault proxy` and `vault mcp` remain out of bounds: they are a
   * credential *broker*, built precisely so the caller never receives the
   * credential. `vault serve` is the provision endpoint, built to hand the
   * value back - that is the one sekreto uses.
   */
  public static final class Boru implements Provider {
    private final String command;
    private final String namespace;
    private final String home;
    private final String addr;
    private final String token;
    private final String mount;

    public Boru(String command, String namespace, String home) {
      this(command, namespace, home, null, null, null);
    }

    public Boru(String command, String namespace, String home,
        String addr, String token, String mount) {
      this.command = null == command || command.isEmpty() ? "boru" : command;
      this.namespace = namespace;
      this.home = home;
      this.addr = null == addr ? "" : trimslash(addr);
      this.token = null == token ? "" : token;
      this.mount = null == mount || mount.isEmpty() ? "secret" : mount;
    }

    @Override
    public String lookup(String name) {
      Sekreto.checkname(name);

      if (!addr.isEmpty()) {
        return wirelookup(name);
      }

      String alias = null == namespace || namespace.isEmpty() ? name : namespace + ":" + name;

      ProcessBuilder builder =
          new ProcessBuilder(command, "vault", "get", "--reveal", alias);

      if (null != home && !home.isEmpty()) {
        builder.environment().put("BORU_HOME", home);
      }

      Ran ran = runcmd(builder, command);
      String out = ran.out;
      String why = ran.why;
      int status = ran.status;

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

    @SuppressWarnings("unchecked")
    private String wirelookup(String name) {
      checkaddr(addr);

      // The dotted name stays one path segment: boru aliases keep their dots.
      String alias = null == namespace || namespace.isEmpty() ? name : namespace + "/" + name;
      String url = addr + "/v1/" + mount + "/data/" + alias;

      Answer res = fetchjson("GET", url, headers("X-Vault-Token", token), null);

      if (404 == res.status) {
        return null;
      }

      if (200 != res.status) {
        throw new SekretoError("sekreto: boru serve error: " + res.status + ": " + url);
      }

      Object data = dig(res.body, "data", "data");
      Object value = data instanceof Map ? ((Map<String, Object>) data).get("value") : null;
      return null == value ? null : String.valueOf(value);
    }

    @Override
    public String describe() {
      if (!addr.isEmpty()) {
        return "boru:" + addr;
      }
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

  /**
   * SecretSpec (https://secretspec.dev).
   *
   * <p>SecretSpec is a declaration - a `secretspec.toml` naming the secrets a
   * project needs - plus a chain of its own backends to satisfy them from.
   * That makes it the same shape as sekreto one level down, and the reason to
   * support it is the same reason sekreto exists: a project that has already
   * declared its secrets there should not have to declare them again here.
   *
   * <p>Read through its CLI, as boru is, because that is the interface it
   * offers a program in another language: `secretspec get API_TOKEN` prints
   * the value on stdout and nothing else. A sekreto name maps to a SecretSpec
   * key exactly as it maps to an environment variable - `api.token` is
   * `API_TOKEN` - which is the convention SecretSpec's own examples use.
   *
   * <p>`backend` selects one of SecretSpec's backends (`--provider`, e.g.
   * `keyring` or `dotenv://.env`) and is called `backend` here only because
   * `provider` already means something else in this library.
   *
   * <p>A reason is required, not optional: SecretSpec records every read in
   * an audit log and refuses to read at all without one. sekreto sends
   * `sekreto` unless told otherwise, so the audit trail says which tool
   * asked.
   */
  public static final class Secretspec implements Provider {
    private final String command;
    private final String file;
    private final String profile;
    private final String backend;
    private final String reason;
    private final String prefix;

    public Secretspec(String command, String file, String profile,
        String backend, String reason, String prefix) {
      this.command = null == command || command.isEmpty() ? "secretspec" : command;
      this.file = file;
      this.profile = profile;
      this.backend = backend;
      this.reason = reason;
      this.prefix = prefix;
    }

    @Override
    public String lookup(String name) {
      String key = Sekreto.envkey(name, prefix);

      List<String> args = new ArrayList<>();
      args.add(command);
      if (null != file && !file.isEmpty()) {
        args.add("--file");
        args.add(file);
      }
      args.add("get");
      args.add(key);
      if (null != backend && !backend.isEmpty()) {
        args.add("--provider");
        args.add(backend);
      }
      if (null != profile && !profile.isEmpty()) {
        args.add("--profile");
        args.add(profile);
      }
      args.add("--reason");
      args.add(null == reason || reason.isEmpty() ? "sekreto" : reason);

      Ran ran = runcmd(new ProcessBuilder(args), command);
      String out = ran.out;
      String why = ran.why;
      int status = ran.status;

      if (0 == status) {
        // The value and one newline, and nothing else.
        return out.endsWith("\n") ? out.substring(0, out.length() - 1) : out;
      }

      if (secretspecmiss(why, key)) {
        return null;
      }

      throw new SekretoError(
          "sekreto: secretspec error: " + (why.isEmpty() ? "exit " + status : why));
    }

    @Override
    public String describe() {
      return "secretspec" + (null == backend || backend.isEmpty() ? "" : ":" + backend);
    }
  }

  /**
   * Does this SecretSpec failure mean "no such secret" rather than "I could
   * not answer"?
   *
   * <p>SecretSpec says `Secret 'API_TOKEN' not found` for both a name it does
   * not declare and one declared with no value, and both are misses: this
   * store does not hold it, so the chain carries on.
   *
   * <p>MATCHED ON THE WHOLE PHRASE, NOT ON "not found". SecretSpec also says
   * `Provider backend 'keyring' not found`, which is a store that could not
   * answer at all - and reading that as a miss is the worst failure this
   * library has, because the chain then falls through to a weaker store
   * without saying so. The key is required to appear, so the two cannot be
   * confused.
   */
  static boolean secretspecmiss(String why, String key) {
    return why.contains("Secret '" + key + "' not found");
  }

  /** The `YYYYMMDDTHHMMSSZ` timestamp SigV4 wants, for now. */
  static String awsnow() {
    return DateTimeFormatter.ofPattern("yyyyMMdd'T'HHmmss'Z'")
        .withZone(ZoneOffset.UTC)
        .format(Instant.now());
  }

  /** Region and credentials, resolved for one call. */
  private static final class Awsauth {
    final String region;
    final String keyid;
    final String secret;
    final String session;

    Awsauth(String region, String keyid, String secret, String session) {
      this.region = region;
      this.keyid = keyid;
      this.secret = secret;
      this.session = session;
    }
  }

  /**
   * Region and credentials, from config first and the standard AWS_*
   * environment variables second - those are AWS's own convention, and a
   * pod or CI job that has them set should just work. Missing either is an
   * error: an AWS store with no credentials could not answer.
   */
  static Awsauth awsauth(String region, String keyid, String secret, String session) {
    String useregion =
        first(region, System.getenv("AWS_REGION"), System.getenv("AWS_DEFAULT_REGION"));
    String usekeyid = first(keyid, System.getenv("AWS_ACCESS_KEY_ID"));
    String usesecret = first(secret, System.getenv("AWS_SECRET_ACCESS_KEY"));
    String usesession = first(session, System.getenv("AWS_SESSION_TOKEN"));

    if (useregion.isEmpty()) {
      throw new SekretoError("sekreto: aws: no region (set region or AWS_REGION)");
    }
    if (usekeyid.isEmpty() || usesecret.isEmpty()) {
      throw new SekretoError(
          "sekreto: aws: no credentials"
              + " (set keyid/secret or AWS_ACCESS_KEY_ID/AWS_SECRET_ACCESS_KEY)");
    }

    return new Awsauth(useregion, usekeyid, usesecret,
        usesession.isEmpty() ? null : usesession);
  }

  /** One signed call to an AWS JSON-1.1 API. */
  static Answer awscall(String region, String keyid, String secret, String session,
      String addr, String service, String target, String payload) {
    Awsauth auth = awsauth(region, keyid, secret, session);
    // The China partition lives under its own suffix; every other
    // commercial region is plain amazonaws.com.
    String suffix = auth.region.startsWith("cn-") ? ".amazonaws.com.cn" : ".amazonaws.com";
    String useaddr = first(addr, "https://" + service + "." + auth.region + suffix);
    checkaddr(useaddr);

    String url = trimslash(useaddr) + "/";

    Map<String, Object> extras = new LinkedHashMap<>();
    extras.put("content-type", "application/x-amz-json-1.1");
    extras.put("x-amz-target", target);

    Map<String, Object> input = new LinkedHashMap<>();
    input.put("method", "POST");
    input.put("url", url);
    input.put("headers", extras);
    input.put("body", payload);
    input.put("service", service);
    input.put("region", auth.region);
    input.put("keyid", auth.keyid);
    input.put("secret", auth.secret);
    if (null != auth.session) {
      input.put("session", auth.session);
    }
    input.put("datetime", awsnow());

    Map<String, Object> signed = Sigv4.sigv4(input);

    Map<String, String> send = new LinkedHashMap<>();
    for (Map.Entry<String, Object> entry : extras.entrySet()) {
      send.put(entry.getKey(), String.valueOf(entry.getValue()));
    }
    for (Map.Entry<String, Object> entry : signed.entrySet()) {
      send.put(entry.getKey(), String.valueOf(entry.getValue()));
    }

    return fetchjson("POST", url, send, payload);
  }

  /**
   * Does this AWS error body name one of the not-found types? Those are a
   * miss; every other failure is a store that could not answer.
   */
  static boolean awsmiss(Object body, String... types) {
    Object errtype = dig(body, "__type");
    if (!(errtype instanceof String)) {
      return false;
    }
    for (String type : types) {
      if (((String) errtype).contains(type)) {
        return true;
      }
    }
    return false;
  }

  /**
   * AWS Secrets Manager.
   *
   * <p>`api.token` reads the secret named `api` (the vaultref path, so
   * `db.pass.main` reads `db/pass`) and takes the `token` field of its JSON
   * SecretString - the AWS idiom of one JSON map per secret. A SecretString
   * that is not JSON is the value itself, under the conventional field
   * `value`. Requests are SigV4-signed in-tree; see Sigv4.java.
   */
  public static final class Awssecrets implements Provider {
    private final String region;
    private final String keyid;
    private final String secret;
    private final String session;
    private final String addr;

    public Awssecrets(String region, String keyid, String secret, String session, String addr) {
      this.region = region;
      this.keyid = keyid;
      this.secret = secret;
      this.session = session;
      this.addr = addr;
    }

    @Override
    @SuppressWarnings("unchecked")
    public String lookup(String name) {
      Map<String, Object> ref = Sekreto.vaultref(name);

      Map<String, Object> payload = new LinkedHashMap<>();
      payload.put("SecretId", ref.get("path"));

      Answer res = awscall(region, keyid, secret, session, addr,
          "secretsmanager", "secretsmanager.GetSecretValue", Json.stringify(payload));

      if (400 == res.status && awsmiss(res.body, "ResourceNotFoundException")) {
        return null;
      }

      if (200 != res.status) {
        throw new SekretoError("sekreto: aws secretsmanager error: " + res.status);
      }

      Object text = dig(res.body, "SecretString");

      if (!(text instanceof String)) {
        // A binary secret has no fields to address; only the conventional
        // `value` field can mean "the bytes themselves".
        Object bin = dig(res.body, "SecretBinary");
        if (bin instanceof String && "value".equals(ref.get("field"))) {
          // decode() throws IllegalArgumentException on a bad payload,
          // which is not a SekretoError and so escaped the library's own
          // error type. A store that answered incoherently is an error.
          try {
            return new String(
                Base64.getDecoder().decode((String) bin), StandardCharsets.UTF_8);
          } catch (IllegalArgumentException err) {
            throw new SekretoError("sekreto: aws secretsmanager: undecodable secret");
          }
        }
        return null;
      }

      Object parsed = Json.parse((String) text);

      if (parsed instanceof Map) {
        Object value = ((Map<String, Object>) parsed).get(ref.get("field"));
        return null == value ? null : String.valueOf(value);
      }

      // A plain-string secret is the whole value; it has no named fields.
      return "value".equals(ref.get("field")) ? (String) text : null;
    }

    // Config only, never the environment: describe() feeds the spec's
    // sources group, which must answer the same everywhere.
    @Override
    public String describe() {
      return "awssecrets:" + (null == region ? "" : region);
    }
  }

  /**
   * AWS SSM Parameter Store.
   *
   * <p>`db.pass.main` reads the parameter `/db/pass/main` (under an
   * optional prefix path), decrypted. Parameter Store carries flat strings,
   * so there is no field indirection.
   */
  public static final class Awsparams implements Provider {
    private final String region;
    private final String keyid;
    private final String secret;
    private final String session;
    private final String addr;
    private final String prefix;

    public Awsparams(String region, String keyid, String secret, String session,
        String addr, String prefix) {
      this.region = region;
      this.keyid = keyid;
      this.secret = secret;
      this.session = session;
      this.addr = addr;
      this.prefix = prefix;
    }

    @Override
    public String lookup(String name) {
      Map<String, Object> payload = new LinkedHashMap<>();
      payload.put("Name", Sekreto.awsparam(name, prefix));
      payload.put("WithDecryption", Boolean.TRUE);

      Answer res = awscall(region, keyid, secret, session, addr,
          "ssm", "AmazonSSM.GetParameter", Json.stringify(payload));

      if (400 == res.status && awsmiss(res.body, "ParameterNotFound")) {
        return null;
      }

      if (200 != res.status) {
        throw new SekretoError("sekreto: aws ssm error: " + res.status);
      }

      Object value = dig(res.body, "Parameter", "Value");
      return null == value ? null : String.valueOf(value);
    }

    @Override
    public String describe() {
      return "awsparams:" + (null == region ? "" : region) + (null == prefix ? "" : prefix);
    }
  }

  /**
   * GCP Secret Manager.
   *
   * <p>`api.token` reads secret `api_token` (dots flattened to `_`; Secret
   * Manager ids have no hierarchy and reject dots), latest version. The
   * token comes from config, then `GOOGLE_OAUTH_ACCESS_TOKEN`, then the
   * GCE/GKE metadata server - so on Google's own platform no credential
   * configuration is needed at all.
   *
   * <p>The metadata call itself is plain http to a link-local host by
   * platform design; no credential rides on it, so `checkaddr` guards the
   * Secret Manager address instead.
   */
  public static final class Gcpsecrets implements Provider {
    private final String project;
    private final String token;
    private final String addr;
    private final String metadataaddr;

    // A configured token is kept forever; a metadata-server token carries
    // expires_in and is renewed shortly before it runs out.
    private String livetoken;
    private long renewat = Long.MAX_VALUE;

    public Gcpsecrets(String project, String token, String addr, String metadataaddr) {
      this.project = project;
      this.token = token;
      this.addr = addr;
      this.metadataaddr = metadataaddr;
    }

    private String usemetadataaddr() {
      if (null != metadataaddr && !metadataaddr.isEmpty()) {
        return metadataaddr;
      }
      String host = System.getenv("GCE_METADATA_HOST");
      return null == host || host.isEmpty()
          ? "http://metadata.google.internal" : "http://" + host;
    }

    private String login() {
      String configured = first(token, System.getenv("GOOGLE_OAUTH_ACCESS_TOKEN"));
      if (!configured.isEmpty()) {
        return configured;
      }

      String url = trimslash(usemetadataaddr())
          + "/computeMetadata/v1/instance/service-accounts/default/token";

      Answer res = fetchjson("GET", url, headers("Metadata-Flavor", "Google"), null);

      Object got = dig(res.body, "access_token");
      if (200 != res.status || null == got || String.valueOf(got).isEmpty()) {
        throw new SekretoError("sekreto: gcp: no token and metadata server did not answer");
      }

      renewat = renewtime(dig(res.body, "expires_in"));

      return String.valueOf(got);
    }

    @Override
    public String lookup(String name) {
      String useproject = null == project ? "" : project;
      if (useproject.isEmpty()) {
        throw new SekretoError("sekreto: gcp: no project");
      }

      String useaddr = first(addr, "https://secretmanager.googleapis.com");
      checkaddr(useaddr);

      if (null == livetoken || System.currentTimeMillis() >= renewat) {
        livetoken = login();
      }

      String url = trimslash(useaddr) + "/v1/projects/" + useproject + "/secrets/"
          + Sekreto.flatname(name, "_") + "/versions/latest:access";

      Answer res = fetchjson("GET", url, headers("authorization", "Bearer " + livetoken), null);

      if (404 == res.status) {
        return null;
      }

      if (200 != res.status) {
        throw new SekretoError("sekreto: gcp error: " + res.status + ": " + url);
      }

      Object data = dig(res.body, "payload", "data");
      if (!(data instanceof String)) {
        return null;
      }

      // See the aws provider: an undecodable payload is a SekretoError.
      try {
        return new String(
            Base64.getDecoder().decode((String) data), StandardCharsets.UTF_8);
      } catch (IllegalArgumentException err) {
        throw new SekretoError("sekreto: gcp: undecodable secret");
      }
    }

    @Override
    public String describe() {
      return "gcpsecrets:" + (null == project ? "" : project);
    }
  }

  /**
   * Azure Key Vault.
   *
   * <p>`api.token` reads secret `api-token` (dots flattened to `-`; Key
   * Vault names allow nothing else), current version. The token comes from
   * config, then a client-credentials login when tenant/clientid/
   * clientsecret are given, then the IMDS managed-identity endpoint - so on
   * Azure's own platform no credential configuration is needed.
   *
   * <p>As with GCP, the IMDS call is plain http to a link-local host by
   * platform design and carries no credential; the login and vault
   * addresses are `checkaddr`-guarded.
   */
  public static final class Azuresecrets implements Provider {
    private static final String RESOURCE = "https://vault.azure.net";

    private final String vault;
    private final String token;
    private final String tenant;
    private final String clientid;
    private final String clientsecret;
    private final String loginaddr;
    private final String imdsaddr;
    private final String apiversion;

    // A configured token is kept forever; logged-in and IMDS tokens carry
    // expires_in and are renewed shortly before they run out.
    private String livetoken;
    private long renewat = Long.MAX_VALUE;

    public Azuresecrets(String vault, String token, String tenant, String clientid,
        String clientsecret, String loginaddr, String imdsaddr, String apiversion) {
      this.vault = vault;
      this.token = token;
      this.tenant = tenant;
      this.clientid = clientid;
      this.clientsecret = clientsecret;
      this.loginaddr = loginaddr;
      this.imdsaddr = imdsaddr;
      this.apiversion = apiversion;
    }

    private String login() {
      if (null != token && !token.isEmpty()) {
        return token;
      }

      if (null != tenant && !tenant.isEmpty()
          && null != clientid && !clientid.isEmpty()
          && null != clientsecret && !clientsecret.isEmpty()) {
        String useloginaddr = first(loginaddr, "https://login.microsoftonline.com");
        checkaddr(useloginaddr);

        String url = trimslash(useloginaddr) + "/" + tenant + "/oauth2/v2.0/token";
        String form = "grant_type=client_credentials&client_id=" + Sigv4.uriescape(clientid)
            + "&client_secret=" + Sigv4.uriescape(clientsecret)
            + "&scope=" + Sigv4.uriescape(RESOURCE + "/.default");

        Answer res = fetchjson(
            "POST", url, headers("content-type", "application/x-www-form-urlencoded"), form);

        Object got = dig(res.body, "access_token");
        if (200 != res.status || null == got || String.valueOf(got).isEmpty()) {
          throw new SekretoError("sekreto: azure login failed: " + res.status);
        }

        renewat = renewtime(dig(res.body, "expires_in"));
        return String.valueOf(got);
      }

      String imds = trimslash(first(imdsaddr, "http://169.254.169.254"))
          + "/metadata/identity/oauth2/token?api-version=2018-02-01&resource="
          + Sigv4.uriescape(RESOURCE);

      Answer res = fetchjson("GET", imds, headers("Metadata", "true"), null);

      Object got = dig(res.body, "access_token");
      if (200 != res.status || null == got || String.valueOf(got).isEmpty()) {
        throw new SekretoError(
            "sekreto: azure: no token, no client credentials, and IMDS did not answer");
      }

      renewat = renewtime(dig(res.body, "expires_in"));
      return String.valueOf(got);
    }

    @Override
    public String lookup(String name) {
      String usevault = null == vault ? "" : vault;
      if (usevault.isEmpty()) {
        throw new SekretoError("sekreto: azure: no vault");
      }

      // Only an explicit scheme is a URL; a vault NAMED httpvault must
      // still become https://httpvault.vault.azure.net.
      String vaulturl =
          usevault.startsWith("http://") || usevault.startsWith("https://")
              ? usevault
              : "https://" + usevault + ".vault.azure.net";
      checkaddr(vaulturl);

      if (null == livetoken || System.currentTimeMillis() >= renewat) {
        livetoken = login();
      }

      String url = trimslash(vaulturl) + "/secrets/" + Sekreto.flatname(name, "-")
          + "?api-version=" + first(apiversion, "7.4");

      Answer res = fetchjson("GET", url, headers("authorization", "Bearer " + livetoken), null);

      if (404 == res.status) {
        return null;
      }

      if (200 != res.status) {
        throw new SekretoError(
            "sekreto: azure error: " + res.status + ": " + url.split("\\?")[0]);
      }

      Object value = dig(res.body, "value");
      return null == value ? null : String.valueOf(value);
    }

    @Override
    public String describe() {
      return "azuresecrets:" + (null == vault ? "" : vault);
    }
  }

  /**
   * 1Password, through a Connect server.
   *
   * <p>The item titled `api.token` (titles keep their dots), in the named
   * vault. The value is the field with purpose PASSWORD, or the field
   * labelled `value`. A vault that cannot be found is an error - config
   * names it, so its absence is a broken store, not a missing secret.
   */
  public static final class Onepassword implements Provider {
    private final String addr;
    private final String token;
    private final String vault;

    private String vaultid;

    public Onepassword(String addr, String token, String vault) {
      this.addr = addr;
      this.token = token;
      this.vault = vault;
    }

    private Map<String, String> auth() {
      return headers("authorization", "Bearer " + (null == token ? "" : token));
    }

    private String resolvevault(String useaddr) {
      String want = null == vault ? "" : vault;
      if (want.isEmpty()) {
        throw new SekretoError("sekreto: onepassword: no vault");
      }

      Answer res = fetchjson("GET", useaddr + "/v1/vaults", auth(), null);

      if (200 != res.status || !(res.body instanceof List)) {
        throw new SekretoError("sekreto: onepassword error: " + res.status + ": listing vaults");
      }

      for (Object entry : (List<?>) res.body) {
        Object id = dig(entry, "id");
        if (want.equals(id) || want.equals(dig(entry, "name"))) {
          return String.valueOf(id);
        }
      }

      throw new SekretoError("sekreto: onepassword: no vault named " + want);
    }

    @Override
    public String lookup(String name) {
      Sekreto.checkname(name);

      String useaddr = trimslash(null == addr ? "" : addr);
      if (useaddr.isEmpty()) {
        throw new SekretoError("sekreto: onepassword: no addr");
      }
      checkaddr(useaddr);

      if (null == vaultid) {
        vaultid = resolvevault(useaddr);
      }

      String filter = Sigv4.uriescape("title eq \"" + name + "\"");
      Answer found = fetchjson(
          "GET", useaddr + "/v1/vaults/" + vaultid + "/items?filter=" + filter, auth(), null);

      if (200 != found.status || !(found.body instanceof List)) {
        throw new SekretoError(
            "sekreto: onepassword error: " + found.status + ": finding " + name);
      }

      List<?> items = (List<?>) found.body;
      if (items.isEmpty()) {
        return null;
      }

      Answer item = fetchjson(
          "GET", useaddr + "/v1/vaults/" + vaultid + "/items/" + dig(items.get(0), "id"),
          auth(), null);

      if (200 != item.status) {
        throw new SekretoError(
            "sekreto: onepassword error: " + item.status + ": reading " + name);
      }

      Object fields = dig(item.body, "fields");
      List<?> fieldlist = fields instanceof List ? (List<?>) fields : new ArrayList<>();

      for (Object field : fieldlist) {
        if ("PASSWORD".equals(dig(field, "purpose"))) {
          Object value = dig(field, "value");
          return null == value ? null : String.valueOf(value);
        }
      }
      for (Object field : fieldlist) {
        if ("value".equals(dig(field, "label"))) {
          Object value = dig(field, "value");
          return null == value ? null : String.valueOf(value);
        }
      }

      return null;
    }

    @Override
    public String describe() {
      return "onepassword:" + (null == vault ? "" : vault);
    }
  }

  /**
   * Doppler.
   *
   * <p>The whole config is downloaded once - Doppler's own bulk endpoint -
   * and answered from memory, like a remote .env: `api.token` is the
   * `API_TOKEN` entry. A service token is config-scoped, so project and
   * config are only needed with broader tokens.
   */
  public static final class Doppler implements Provider {
    private final String token;
    private final String project;
    private final String config;
    private final String addr;

    private Map<String, String> values;

    public Doppler(String token, String project, String config, String addr) {
      this.token = token;
      this.project = project;
      this.config = config;
      this.addr = addr;
    }

    @SuppressWarnings("unchecked")
    private Map<String, String> load() {
      if (null != values) {
        return values;
      }

      String useaddr = trimslash(first(addr, "https://api.doppler.com"));
      checkaddr(useaddr);

      String url = useaddr + "/v3/configs/config/secrets/download?format=json";
      if (null != project && !project.isEmpty()) {
        url += "&project=" + Sigv4.uriescape(project);
      }
      if (null != config && !config.isEmpty()) {
        url += "&config=" + Sigv4.uriescape(config);
      }

      Answer res = fetchjson(
          "GET", url, headers("authorization", "Bearer " + (null == token ? "" : token)), null);

      if (200 != res.status || !(res.body instanceof Map)) {
        throw new SekretoError("sekreto: doppler error: " + res.status);
      }

      values = new LinkedHashMap<>();
      for (Map.Entry<String, Object> entry : ((Map<String, Object>) res.body).entrySet()) {
        if (null != entry.getValue()) {
          values.put(entry.getKey(), String.valueOf(entry.getValue()));
        }
      }

      return values;
    }

    @Override
    public String lookup(String name) {
      return load().get(Sekreto.envkey(name, null));
    }

    @Override
    public String describe() {
      return "doppler"
          + (null == project || project.isEmpty()
              ? "" : ":" + project + "/" + (null == config ? "" : config));
    }
  }

  /**
   * Infisical.
   *
   * <p>`api.token` reads the secret keyed `API_TOKEN` (Infisical's own
   * convention is environment-style keys) at a secret path in one
   * environment of a project. Auth is a token, or a universal-auth (machine
   * identity) login with clientid/clientsecret.
   */
  public static final class Infisical implements Provider {
    private final String addr;
    private final String token;
    private final String clientid;
    private final String clientsecret;
    private final String project;
    private final String environment;
    private final String path;

    // A configured token is kept forever; a universal-auth token carries
    // expiresIn and is renewed shortly before it runs out.
    private String livetoken;
    private long renewat = Long.MAX_VALUE;

    public Infisical(String addr, String token, String clientid, String clientsecret,
        String project, String environment, String path) {
      this.addr = addr;
      this.token = token;
      this.clientid = clientid;
      this.clientsecret = clientsecret;
      this.project = project;
      this.environment = environment;
      this.path = path;
    }

    private String login(String useaddr) {
      if (null != token && !token.isEmpty()) {
        return token;
      }

      if (null == clientid || clientid.isEmpty()
          || null == clientsecret || clientsecret.isEmpty()) {
        throw new SekretoError("sekreto: infisical: no token and no client credentials");
      }

      Map<String, Object> body = new LinkedHashMap<>();
      body.put("clientId", clientid);
      body.put("clientSecret", clientsecret);

      Answer res = fetchjson("POST", useaddr + "/api/v1/auth/universal-auth/login",
          headers("content-type", "application/json"), Json.stringify(body));

      Object got = dig(res.body, "accessToken");
      if (200 != res.status || null == got || String.valueOf(got).isEmpty()) {
        throw new SekretoError("sekreto: infisical login failed: " + res.status);
      }

      renewat = renewtime(dig(res.body, "expiresIn"));

      return String.valueOf(got);
    }

    @Override
    public String lookup(String name) {
      String useaddr = trimslash(first(addr, "https://app.infisical.com"));
      checkaddr(useaddr);

      String useproject = null == project ? "" : project;
      String useenvironment = null == environment ? "" : environment;
      if (useproject.isEmpty() || useenvironment.isEmpty()) {
        throw new SekretoError("sekreto: infisical: no project/environment");
      }

      if (null == livetoken || System.currentTimeMillis() >= renewat) {
        livetoken = login(useaddr);
      }

      String url = useaddr + "/api/v3/secrets/raw/" + Sekreto.envkey(name, null)
          + "?workspaceId=" + Sigv4.uriescape(useproject)
          + "&environment=" + Sigv4.uriescape(useenvironment)
          + "&secretPath=" + Sigv4.uriescape(first(path, "/"));

      Answer res = fetchjson("GET", url, headers("authorization", "Bearer " + livetoken), null);

      if (404 == res.status) {
        return null;
      }

      if (200 != res.status) {
        throw new SekretoError("sekreto: infisical error: " + res.status);
      }

      Object value = dig(res.body, "secret", "secretValue");
      return null == value ? null : String.valueOf(value);
    }

    @Override
    public String describe() {
      return "infisical:" + (null == project ? "" : project)
          + "/" + (null == environment ? "" : environment);
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
    if ("file".equals(kind)) {
      return new File(textor(spec.get("dir"), ""), text(spec.get("prefix")));
    }
    if ("hashicorp".equals(kind)) {
      Object kv = spec.get("kv");
      Object auth = spec.get("auth");
      return new Hashicorp(
          textor(spec.get("addr"), ""),
          textor(spec.get("token"), ""),
          text(spec.get("mount")),
          kv instanceof Number ? ((Number) kv).intValue() : 0,
          text(spec.get("vaultnamespace")),
          auth instanceof Map ? (Map<String, Object>) auth : null);
    }
    if ("boru".equals(kind)) {
      return new Boru(
          text(spec.get("command")), text(spec.get("namespace")), text(spec.get("home")),
          text(spec.get("addr")), text(spec.get("token")), text(spec.get("mount")));
    }
    if ("awssecrets".equals(kind)) {
      return new Awssecrets(
          text(spec.get("region")), text(spec.get("keyid")), text(spec.get("secret")),
          text(spec.get("session")), text(spec.get("addr")));
    }
    if ("awsparams".equals(kind)) {
      return new Awsparams(
          text(spec.get("region")), text(spec.get("keyid")), text(spec.get("secret")),
          text(spec.get("session")), text(spec.get("addr")), text(spec.get("prefix")));
    }
    if ("gcpsecrets".equals(kind)) {
      return new Gcpsecrets(
          text(spec.get("project")), text(spec.get("token")), text(spec.get("addr")),
          text(spec.get("metadataaddr")));
    }
    if ("azuresecrets".equals(kind)) {
      return new Azuresecrets(
          text(spec.get("vault")), text(spec.get("token")), text(spec.get("tenant")),
          text(spec.get("clientid")), text(spec.get("clientsecret")),
          text(spec.get("loginaddr")), text(spec.get("imdsaddr")),
          text(spec.get("apiversion")));
    }
    if ("onepassword".equals(kind)) {
      return new Onepassword(
          text(spec.get("addr")), text(spec.get("token")), text(spec.get("vault")));
    }
    if ("doppler".equals(kind)) {
      return new Doppler(
          text(spec.get("token")), text(spec.get("project")), text(spec.get("config")),
          text(spec.get("addr")));
    }
    if ("infisical".equals(kind)) {
      return new Infisical(
          text(spec.get("addr")), text(spec.get("token")), text(spec.get("clientid")),
          text(spec.get("clientsecret")), text(spec.get("project")),
          text(spec.get("environment")), text(spec.get("path")));
    }
    if ("secretspec".equals(kind)) {
      return new Secretspec(
          text(spec.get("command")), text(spec.get("file")), text(spec.get("profile")),
          text(spec.get("backend")), text(spec.get("reason")), text(spec.get("prefix")));
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
