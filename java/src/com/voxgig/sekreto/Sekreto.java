// sekreto: one interface for secrets, wherever they live.
//
// A Sekreto is an ordered chain of providers. `get` asks each in turn and
// returns the first hit, so an app can be configured from environment
// variables in development and a vault in production without changing a
// line of its own code.
//
// A port of typescript/src/Sekreto.ts, which is canonical.

package com.voxgig.sekreto;

import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.regex.Pattern;

public final class Sekreto {

  /**
   * Anything sekreto refuses to do: a bad name, a missing secret, a
   * provider that could not be reached.
   */
  public static class SekretoError extends RuntimeException {
    private static final long serialVersionUID = 1L;

    public SekretoError(String message) {
      super(message);
    }
  }

  private static final Pattern NAMEPART = Pattern.compile("^[a-z0-9_]+$");

  /** One provider in the chain, under the store name it answers to. */
  private static final class Entry {
    final String store;
    final Provider provider;

    Entry(String store, Provider provider) {
      this.store = store;
      this.provider = provider;
    }
  }

  /** One resolved value, with the store it came from. */
  private static final class Cached {
    final String store;
    final String name;
    final String value;

    Cached(String store, String name, String value) {
      this.store = store;
      this.name = name;
      this.value = value;
    }
  }

  private final List<Entry> entries = new ArrayList<>();
  private final boolean docache;

  // A list, not a map: the store a value came from stays attached, and
  // redaction order does not vary between runs.
  private final List<Cached> cache = new ArrayList<>();

  public Sekreto(List<Provider> useproviders) {
    this(useproviders, true);
  }

  public Sekreto(List<Provider> useproviders, boolean usecache) {
    this(useproviders, null, usecache);
  }

  /**
   * A Sekreto whose providers answer to the given store names, in the same
   * order. A name left null or empty falls back to the provider's kind.
   */
  public Sekreto(List<Provider> useproviders, List<String> names, boolean usecache) {
    if (null != useproviders) {
      for (int index = 0; index < useproviders.size(); index++) {
        Provider provider = useproviders.get(index);

        String store = storename(provider);
        if (null != names && index < names.size()) {
          String given = names.get(index);
          if (null != given && !given.isEmpty()) {
            store = given;
          }
        }

        entries.add(new Entry(store, provider));
      }
    }

    this.docache = usecache;
  }

  /**
   * The store name a provider answers to when nothing says otherwise.
   *
   * <p>`describe()` opens with the provider's kind - `hashicorp:...`,
   * `dotenv:...`, plain `env` - so the kind is the natural default, and a
   * custom provider gets a sensible name without implementing anything extra.
   */
  public static String storename(Provider provider) {
    return provider.describe().split(":", 2)[0];
  }

  /** Is this a well-formed secret name? */
  public static boolean validname(Object name) {
    if (!(name instanceof String) || ((String) name).isEmpty()) {
      return false;
    }

    for (String part : ((String) name).split("\\.", -1)) {
      if (!NAMEPART.matcher(part).matches()) {
        return false;
      }
    }

    return true;
  }

  static String checkname(Object name) {
    if (!validname(name)) {
      throw new SekretoError("sekreto: invalid name: " + (null == name ? "" : name));
    }
    return (String) name;
  }

  /** The environment-variable key for a name: `api.token` -> `API_TOKEN`. */
  public static String envkey(Object name, String prefix) {
    checkname(name);

    return (null == prefix ? "" : prefix)
        + String.join("_", ((String) name).split("\\.", -1)).toUpperCase();
  }

  /**
   * Where a name lives in a KV vault: `api.token` -> `api` / `token`.
   *
   * <p>A single-segment name has no path of its own, so it becomes a secret
   * of that name with the conventional field `value`.
   */
  public static Map<String, Object> vaultref(Object name) {
    checkname(name);

    String[] parts = ((String) name).split("\\.", -1);

    Map<String, Object> out = new LinkedHashMap<>();

    if (1 == parts.length) {
      out.put("path", parts[0]);
      out.put("field", "value");
      return out;
    }

    List<String> head = new ArrayList<>();
    for (int index = 0; index < parts.length - 1; index++) {
      head.add(parts[index]);
    }

    out.put("path", String.join("/", head));
    out.put("field", parts[parts.length - 1]);

    return out;
  }

  /**
   * Parse `.env` text into a map of raw keys to values.
   *
   * <p>Deliberately small: `KEY=value`, optional `export`, `#` comments on
   * their own line, and single- or double-quoted values (double quotes also
   * unescape \n, \r, \t and \\). A line with no `=` is skipped.
   */
  public static Map<String, Object> parsedotenv(Object text) {
    Map<String, Object> out = new LinkedHashMap<>();

    if (!(text instanceof String)) {
      return out;
    }

    for (String rawline : ((String) text).split("\n", -1)) {
      String line = (rawline.endsWith("\r") ? rawline.substring(0, rawline.length() - 1) : rawline)
          .trim();

      if (line.isEmpty() || line.startsWith("#")) {
        continue;
      }

      String body = line.startsWith("export ") ? line.substring(7).trim() : line;

      int eq = body.indexOf('=');
      if (0 >= eq) {
        continue;
      }

      String key = body.substring(0, eq).trim();
      String value = body.substring(eq + 1).trim();

      if (2 <= value.length() && value.startsWith("\"") && value.endsWith("\"")) {
        value = unescape(value.substring(1, value.length() - 1));
      } else if (2 <= value.length() && value.startsWith("'") && value.endsWith("'")) {
        value = value.substring(1, value.length() - 1);
      }

      out.put(key, value);
    }

    return out;
  }

  static String unescape(String text) {
    StringBuilder out = new StringBuilder();

    for (int index = 0; index < text.length(); index++) {
      if ('\\' == text.charAt(index) && index + 1 < text.length()) {
        char next = text.charAt(index + 1);
        index++;
        switch (next) {
          case 'n':
            out.append('\n');
            break;
          case 'r':
            out.append('\r');
            break;
          case 't':
            out.append('\t');
            break;
          case '\\':
            out.append('\\');
            break;
          case '"':
            out.append('"');
            break;
          default:
            out.append('\\').append(next);
        }
      } else {
        out.append(text.charAt(index));
      }
    }

    return out.toString();
  }

  /**
   * Replace known secret values in text with `[redacted]`.
   *
   * <p>Only values of four characters or more are replaced: shorter ones are
   * too likely to appear in ordinary text, and redacting them would make
   * logs unreadable without making them safer.
   */
  public static String redact(Object text, List<Object> values) {
    String out = text instanceof String ? (String) text : "";

    if (null == values) {
      return out;
    }

    for (Object value : values) {
      if (!(value instanceof String) || 4 > ((String) value).length()) {
        continue;
      }
      out = String.join("[redacted]", out.split(Pattern.quote((String) value), -1));
    }

    return out;
  }

  /** The secret, or a SekretoError if no provider has it. */
  public String get(String name) {
    String found = tryget(name);

    if (null == found) {
      throw new SekretoError("sekreto: unknown secret: " + name);
    }

    return found;
  }

  /**
   * The secret, or null if no provider has it. Named `tryget` because `try`
   * is a Java keyword.
   */
  public String tryget(String name) {
    return resolve("", name, entries);
  }

  /**
   * The secret from one named store, or a SekretoError if that store does not
   * have it.
   */
  public String getfrom(String store, String name) {
    String found = tryfrom(store, name);

    if (null == found) {
      throw new SekretoError("sekreto: unknown secret: " + store + ":" + name);
    }

    return found;
  }

  /**
   * The secret from one named store, or null if that store does not have it.
   *
   * <p>Naming a store that is not in the chain is an error, not a miss:
   * `tryget` already means "this store may not have it", so it cannot also
   * mean "this store may not exist" without hiding a typo.
   */
  public String tryfrom(String store, String name) {
    List<Entry> matching = new ArrayList<>();

    for (Entry entry : entries) {
      if (entry.store.equals(store)) {
        matching.add(entry);
      }
    }

    if (matching.isEmpty()) {
      throw new SekretoError("sekreto: unknown store: " + store);
    }

    return resolve(store, name, matching);
  }

  private String resolve(String store, String name, List<Entry> useentries) {
    checkname(name);

    if (docache) {
      for (Cached hit : cache) {
        if (hit.store.equals(store) && hit.name.equals(name)) {
          return hit.value;
        }
      }
    }

    for (Entry entry : useentries) {
      String found = entry.provider.lookup(name);

      if (null != found) {
        if (docache) {
          cache.add(new Cached(store, name, found));
        }
        return found;
      }
    }

    return null;
  }

  /** Does any provider have this secret? */
  public boolean has(String name) {
    return null != tryget(name);
  }

  /** Does this named store have this secret? */
  public boolean hasin(String store, String name) {
    return null != tryfrom(store, name);
  }

  /** Every named secret at once. Missing ones are an error. */
  public Map<String, String> all(List<String> names) {
    Map<String, String> out = new LinkedHashMap<>();

    for (String name : names) {
      out.put(name, get(name));
    }

    return out;
  }

  /** A description of each provider, in resolution order. */
  public List<Object> sources() {
    List<Object> out = new ArrayList<>();

    for (Entry entry : entries) {
      out.add(entry.provider.describe());
    }

    return out;
  }

  /**
   * The name of each store that can be named by `getfrom`, in resolution
   * order and without repeats.
   */
  public List<Object> stores() {
    List<Object> out = new ArrayList<>();

    for (Entry entry : entries) {
      if (!out.contains(entry.store)) {
        out.add(entry.store);
      }
    }

    return out;
  }

  /** Replace every value this Sekreto has resolved with `[redacted]`. */
  public String redact(String text) {
    List<Object> values = new ArrayList<>();

    for (Cached hit : cache) {
      values.add(hit.value);
    }

    return redact(text, values);
  }

  /** Drop cached values, so the next `get` asks the providers again. */
  public void refresh() {
    cache.clear();
  }
}
