/* The providers a Sekreto chains together.
 *
 * A provider answers one question: "do you have this secret?" It returns
 * the value, or a miss to mean "ask the next one". Nothing else about a
 * provider is visible to the caller - which is the point: an app reads
 * `api.token` and never learns whether it came from the environment, a
 * .env file, HashiCorp Vault, AWS, GCP, Azure or a boru vault.
 *
 * TWO FAILURE SHAPES, AND THEY ARE NEVER INTERCHANGEABLE. A store that
 * does not hold the secret is a MISS (`*out = NULL`, no error) and the
 * chain carries on. A store that could not answer - bad credentials,
 * unreachable host, missing configuration - is an ERROR: falling through
 * there would quietly reach for a weaker store.
 *
 * A port of typescript/src/Providers.ts, which is canonical.
 */

#define _POSIX_C_SOURCE 200809L

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>

#include "internal.h"

/* ---- spec ---------------------------------------------------------- */

sek_spec sek_spec_new(const char *kind) {
  sek_spec spec;

  memset(&spec, 0, sizeof(spec));
  spec.kind = kind;

  return spec;
}

/* What a credential field reports about itself: whether it is set, never
 * what it is. */
static const char *setornot(const char *value) { return sek_empty(value) ? "[unset]" : "[set]"; }

char *sek_authspec_show(sek_pool *pool, const sek_authspec *auth) {
  if (NULL == auth) {
    return sek_strdup(pool, "(none)");
  }

  return sek_fmt(pool,
                 "AuthSpec(method=%s, mount=%s, role=%s, jwtfile=%s, roleid=%s, jwt=%s, "
                 "secretid=%s)",
                 sek_orempty(auth->method), sek_orempty(auth->mount), sek_orempty(auth->role),
                 sek_orempty(auth->jwtfile), sek_orempty(auth->roleid), setornot(auth->jwt),
                 setornot(auth->secretid));
}

/* Printed without its credentials. The obvious debug print of a chain
 * that will not build - which is exactly what someone writes when a chain
 * will not build - would otherwise put the Vault token, the AWS secret
 * access key and the Azure client secret wherever it was printed. */
char *sek_spec_show(sek_pool *pool, const sek_spec *spec) {
  return sek_fmt(pool,
                 "ProviderSpec(kind=%s, name=%s, addr=%s, token=%s, secret=%s, clientsecret=%s, "
                 "auth=%s)",
                 sek_orempty(spec->kind), sek_orempty(spec->name), sek_orempty(spec->addr),
                 setornot(spec->token), setornot(spec->secret), setornot(spec->clientsecret),
                 sek_authspec_show(pool, spec->auth));
}

/* ---- addresses ----------------------------------------------------- */

/* Every refusal below names the address it refused, and one of them fires
 * precisely because the address carries a credential - so printing it
 * verbatim would write that password to stderr and into the logs. It
 * cannot be cleaned up afterwards either: that password was never
 * resolved as a secret, so redact() has never seen it and never will. */
char *sek_safeaddr(sek_pool *pool, const char *addr) {
  const char *mark = strstr(addr, "://");
  const char *rest;
  const char *stop;
  char *authority;
  const char *at;
  size_t head;

  if (NULL == mark) {
    return sek_strdup(pool, addr);
  }

  rest = mark + 3;
  stop = rest;
  while ('\0' != *stop && '/' != *stop && '?' != *stop && '#' != *stop) {
    stop++;
  }

  authority = sek_strndup(pool, rest, (size_t)(stop - rest));
  at = strrchr(authority, '@');

  if (NULL == at) {
    return sek_strdup(pool, addr);
  }

  head = (size_t)(rest - addr);

  return sek_fmt(pool, "%.*s[redacted]%s", (int)head, addr, rest + (size_t)(at - authority));
}

/* Refuse to send a secret-bearing credential in the clear.
 *
 * A vault API is HTTPS in any real deployment; plaintext is a dev-mode
 * convenience. Sending a token over http to anything but the local
 * machine puts both the token and the secret it fetches on the wire for
 * anyone on the path, so sekreto will not do it. Loopback stays allowed:
 * that is `vault server -dev`, `boru vault serve` and this repository's
 * own test harness.
 *
 * The address is read BY HAND, in the same handful of steps in every
 * port, rather than by a platform URL parser. Twelve parsers disagree
 * about malformed input - where userinfo ends, whether `0177.0.0.1` is
 * loopback, what an unclosed bracket means - and a check that answers
 * differently in different ports is not a check.
 *
 * The rule this parse obeys, and the reason it can be trusted: it is
 * never MORE PERMISSIVE than the HTTP client that will dial the address.
 * It ends the authority at `/`, `?` or `#` only, so a client that also
 * breaks on `\` can only ever see a SHORTER host than this does. It
 * refuses userinfo outright rather than locating its end. It compares the
 * host literally, so a numeric form no parser agrees on is refused rather
 * than guessed at. */
sek_err sek_checkaddr(sek_pool *pool, const char *addr) {
  const char *rest;
  const char *stop;
  char *authority;
  char *host;
  int tls;

  if (NULL == addr) {
    addr = "";
  }

  /* A literal, case-sensitive prefix. `HTTP://localhost` is refused. */
  if (sek_has_prefix(addr, "https://")) {
    rest = addr + 8;
    tls = 1;
  } else if (sek_has_prefix(addr, "http://")) {
    rest = addr + 7;
    tls = 0;
  } else {
    return sek_fmt(pool, "sekreto: not an http(s) address: %s", sek_safeaddr(pool, addr));
  }

  stop = rest;
  while ('\0' != *stop && '/' != *stop && '?' != *stop && '#' != *stop) {
    stop++;
  }
  authority = sek_strndup(pool, rest, (size_t)(stop - rest));

  /* Userinfo is refused outright rather than parsed around, and on https
   * as well as http. No store this library speaks authenticates by
   * userinfo - they take a token or a signature - so an address carrying
   * one is a mistake at best. At worst it is the attack this whole
   * function exists to stop: `http://localhost:8200@evil.example.com/` is
   * a request to evil.example.com that reads, to anything splitting the
   * authority on ':', as loopback. */
  if (NULL != strchr(authority, '@')) {
    return sek_fmt(pool, "sekreto: refusing an address with embedded credentials: %s",
                   sek_safeaddr(pool, addr));
  }

  /* An opening bracket with no closing one is not an address at all. */
  if ('[' == authority[0] && NULL == strchr(authority, ']')) {
    return sek_fmt(pool, "sekreto: not a valid http(s) address: %s", sek_safeaddr(pool, addr));
  }

  if (tls) {
    return NULL;
  }

  /* A bracketed IPv6 literal keeps its brackets. Splitting the authority
   * on the first colon yields `[`, so `http://[::1]:8200` could never
   * match the allowlist below - which refuses a legitimate local vault. */
  if ('[' == authority[0]) {
    const char *close = strchr(authority, ']');
    host = sek_strndup(pool, authority, (size_t)(close - authority) + 1);
  } else {
    const char *colon = strchr(authority, ':');
    host = NULL == colon ? sek_strdup(pool, authority)
                         : sek_strndup(pool, authority, (size_t)(colon - authority));
  }
  host = sek_lowercase(pool, host);

  /* Literal, and exactly four entries. Nothing is normalised:
   * `0177.0.0.1`, `2130706433`, `127.0.0.2` and `[::ffff:127.0.0.1]` are
   * all refused, because no two URL parsers agree on what they mean. */
  if (0 == strcmp(host, "localhost") || 0 == strcmp(host, "127.0.0.1") ||
      0 == strcmp(host, "::1") || 0 == strcmp(host, "[::1]")) {
    return NULL;
  }

  return sek_fmt(pool, "sekreto: refusing to send a token in plaintext to %s (use https)",
                 sek_safeaddr(pool, addr));
}

/* ---- shared read helpers ------------------------------------------- */

/* Does this read failure mean "no secrets here", rather than "I could not
 * answer"?
 *
 * Absence is a MISS and the chain carries on; anything else - permission
 * denied, an unreadable mount, a failing disk - is an ERROR, because
 * returning a miss there falls silently through to a weaker store.
 *
 * ENOENT and ENOTDIR are the two absence codes: a missing file, a missing
 * directory, and a path whose parent is a plain file. EACCES is NOT one
 * of them, which is the case the rule exists for - the obvious spelling,
 * an `exists()` predicate, answers false for a locked mount and would
 * turn it into a miss. */
static int absent(int why) { return ENOENT == why || ENOTDIR == why; }

/* The whole file, or NULL with `*why` set to errno. */
static char *readfile(sek_pool *pool, const char *path, int *why) {
  FILE *file = fopen(path, "rb");
  sek_buf out;
  char chunk[8192];
  size_t got;

  *why = 0;

  if (NULL == file) {
    *why = errno;
    return NULL;
  }

  sek_buf_init(&out, pool);
  while (0 < (got = fread(chunk, 1, sizeof(chunk), file))) {
    sek_buf_addn(&out, chunk, got);
  }

  if (0 != ferror(file)) {
    *why = errno;
    fclose(file);
    return NULL;
  }

  fclose(file);

  return out.data;
}

/* The first candidate that is set and non-empty, or "". */
static const char *first3(const char *a, const char *b, const char *c) {
  if (!sek_empty(a)) {
    return a;
  }
  if (!sek_empty(b)) {
    return b;
  }
  return sek_orempty(c);
}

/* ---- env ----------------------------------------------------------- */

typedef struct {
  sek_pool *pool;
  const char *prefix;
  char *described;
} envdata;

static sek_err env_lookup(sek_provider *self, const char *name, char **out) {
  envdata *data = (envdata *)self->data;
  char *key = NULL;
  sek_err err = sek_envkey(data->pool, name, data->prefix, &key);
  const char *found;

  *out = NULL;

  if (NULL != err) {
    return err;
  }

  found = getenv(key);
  if (NULL != found) {
    *out = sek_strdup(data->pool, found);
  }

  return NULL;
}

static const char *env_describe(sek_provider *self) {
  return ((envdata *)self->data)->described;
}

/* ---- memory -------------------------------------------------------- */

typedef struct {
  sek_pool *pool;
  sek_map *values;
  const char *prefix;
  char *described;
} memorydata;

static sek_err memory_lookup(sek_provider *self, const char *name, char **out) {
  memorydata *data = (memorydata *)self->data;
  char *key = NULL;
  sek_err err = sek_envkey(data->pool, name, data->prefix, &key);
  const char *found;

  *out = NULL;

  if (NULL != err) {
    return err;
  }

  /* An absent key is a miss and the empty string is a HIT, so this asks
   * the map rather than reading a value and testing it for emptiness. */
  found = sek_map_get(data->values, key);
  if (NULL != found) {
    *out = sek_strdup(data->pool, found);
  }

  return NULL;
}

static const char *memory_describe(sek_provider *self) {
  return ((memorydata *)self->data)->described;
}

/* ---- dotenv -------------------------------------------------------- */

typedef struct {
  sek_pool *pool;
  const char *file;
  const char *prefix;
  sek_map *values; /* NULL until the first lookup */
  char *described;
} dotenvdata;

/* Read once, LAZILY, and memoised. Lazily because the `stores` corpus
 * group puts a dotenv provider in a chain and never looks anything up: an
 * eager constructor would read whatever .env happened to sit in the
 * test's working directory. */
static sek_err dotenv_load(dotenvdata *data) {
  char *text;
  int why = 0;

  if (NULL != data->values) {
    return NULL;
  }

  text = readfile(data->pool, data->file, &why);

  if (NULL == text) {
    if (absent(why)) {
      /* No file, or no directory: "no secrets here", not a failure. */
      data->values = sek_map_new(data->pool);
      return NULL;
    }
    return sek_fmt(data->pool, "sekreto: dotenv provider cannot read %s: %s", data->file,
                   strerror(why));
  }

  data->values = sek_parsedotenv(data->pool, text);

  return NULL;
}

static sek_err dotenv_lookup(sek_provider *self, const char *name, char **out) {
  dotenvdata *data = (dotenvdata *)self->data;
  char *key = NULL;
  sek_err err;
  const char *found;

  *out = NULL;

  err = sek_envkey(data->pool, name, data->prefix, &key);
  if (NULL != err) {
    return err;
  }

  err = dotenv_load(data);
  if (NULL != err) {
    return err;
  }

  found = sek_map_get(data->values, key);
  if (NULL != found) {
    *out = sek_strdup(data->pool, found);
  }

  return NULL;
}

static const char *dotenv_describe(sek_provider *self) {
  return ((dotenvdata *)self->data)->described;
}

/* ---- file ---------------------------------------------------------- */

typedef struct {
  sek_pool *pool;
  const char *dir;
  const char *prefix;
  char *described;
} filedata;

/* One secret per file, keyed like the environment: `api.token` reads
 * `<dir>/API_TOKEN`. This is the shape of a mounted Kubernetes Secret, a
 * Docker or Swarm secret, and a systemd credentials directory, so those
 * all work with no further configuration. Read on EVERY lookup, with no
 * caching: a rotated secret is a rewritten file. */
static sek_err file_lookup(sek_provider *self, const char *name, char **out) {
  filedata *data = (filedata *)self->data;
  char *key = NULL;
  sek_err err = sek_envkey(data->pool, name, data->prefix, &key);
  char *path;
  char *text;
  size_t len;
  int why = 0;

  *out = NULL;

  if (NULL != err) {
    return err;
  }

  path = sek_empty(data->dir) ? key : sek_fmt(data->pool, "%s/%s", data->dir, key);

  text = readfile(data->pool, path, &why);

  if (NULL == text) {
    if (absent(why)) {
      return NULL;
    }
    /* The JOINED path, not the directory: that is what could not be
     * read. */
    return sek_fmt(data->pool, "sekreto: file provider cannot read %s: %s", path, strerror(why));
  }

  /* Exactly one trailing newline, `\r\n` before `\n`, and only at the
   * end. Tools that write these files disagree about it, and a newline is
   * never part of a secret on purpose - one left on turns a bearer header
   * into a malformed one. */
  len = strlen(text);
  if (2 <= len && '\r' == text[len - 2] && '\n' == text[len - 1]) {
    text = sek_strndup(data->pool, text, len - 2);
  } else if (1 <= len && '\n' == text[len - 1]) {
    text = sek_strndup(data->pool, text, len - 1);
  }

  *out = text;

  return NULL;
}

static const char *file_describe(sek_provider *self) {
  return ((filedata *)self->data)->described;
}

/* ---- hashicorp ----------------------------------------------------- */

typedef struct {
  sek_pool *pool;
  const char *addr;
  const char *mount;
  int kv;
  const char *vaultnamespace;
  sek_authspec *auth;
  char *livetoken;
  long long renewat;
  char *described;
} hashicorpdata;

static sek_map *vaultheaders(hashicorpdata *data) {
  sek_map *out = sek_map_new(data->pool);

  /* A Vault Enterprise namespace rides the header on LOGINS as well as
   * reads: a login to the wrong namespace fails in a way that reads like
   * a bad credential. */
  if (!sek_empty(data->vaultnamespace)) {
    sek_map_set(out, "X-Vault-Namespace", data->vaultnamespace);
  }

  return out;
}

static sek_err hashicorp_login(hashicorpdata *data, char **out) {
  sek_pool *pool = data->pool;
  sek_authspec *use = data->auth;
  char *url;
  sek_json *payload;
  sek_answer res;
  sek_err err;
  const char *got;

  if (NULL == use) {
    return sek_strdup(pool, "sekreto: hashicorp: no token and no auth method");
  }

  url = sek_fmt(pool, "%s/v1/auth/%s/login", sek_trimslash(pool, data->addr),
                sek_first(use->mount, use->method));

  if (NULL != use->method && 0 == strcmp(use->method, "kubernetes")) {
    const char *jwt = use->jwt;

    if (sek_empty(jwt)) {
      const char *path = sek_empty(use->jwtfile)
                             ? "/var/run/secrets/kubernetes.io/serviceaccount/token"
                             : use->jwtfile;
      int why = 0;
      char *text = readfile(pool, path, &why);

      if (NULL == text) {
        /* No underlying error text: the path is what a reader needs, and
         * the strerror string follows the machine's locale. */
        return sek_fmt(pool, "sekreto: hashicorp: cannot read jwt file %s", path);
      }

      {
        size_t start = 0;
        size_t end = strlen(text);
        while (start < end && (' ' == text[start] || '\n' == text[start] || '\r' == text[start] ||
                               '\t' == text[start])) {
          start++;
        }
        while (end > start && (' ' == text[end - 1] || '\n' == text[end - 1] ||
                               '\r' == text[end - 1] || '\t' == text[end - 1])) {
          end--;
        }
        jwt = sek_strndup(pool, text + start, end - start);
      }
    }

    payload = sek_json_obj(pool);
    sek_json_set(pool, payload, "role", sek_json_str(pool, sek_orempty(use->role)));
    sek_json_set(pool, payload, "jwt", sek_json_str(pool, jwt));
  } else if (NULL != use->method && 0 == strcmp(use->method, "approle")) {
    payload = sek_json_obj(pool);
    sek_json_set(pool, payload, "role_id", sek_json_str(pool, sek_orempty(use->roleid)));
    sek_json_set(pool, payload, "secret_id", sek_json_str(pool, sek_orempty(use->secretid)));
  } else {
    return sek_fmt(pool, "sekreto: hashicorp: unknown auth method: %s", sek_orempty(use->method));
  }

  err = sek_fetchjson(pool, "POST", url, vaultheaders(data), sek_json_stringify(pool, payload),
                      &res);
  if (NULL != err) {
    return err;
  }

  got = sek_json_text(pool, sek_json_dig(res.body, "auth", "client_token", NULL));

  /* A failed login is an ERROR, never a miss: it means this store could
   * not answer at all. */
  if (200 != res.status || sek_empty(got)) {
    return sek_fmt(pool, "sekreto: hashicorp login failed: %d: %s", res.status, url);
  }

  data->renewat = sek_renewtime(sek_json_dig(res.body, "auth", "lease_duration", NULL));
  *out = sek_strdup(pool, got);

  return NULL;
}

static sek_err hashicorp_lookup(sek_provider *self, const char *name, char **out) {
  hashicorpdata *data = (hashicorpdata *)self->data;
  sek_pool *pool = data->pool;
  sek_vaultref ref;
  sek_map *headers;
  sek_answer res;
  sek_err err;
  char *url;
  sek_json *found;

  *out = NULL;

  err = sek_checkaddr(pool, data->addr);
  if (NULL != err) {
    return err;
  }

  if (NULL == data->livetoken || sek_nowms() >= data->renewat) {
    err = hashicorp_login(data, &data->livetoken);
    if (NULL != err) {
      return err;
    }
  }

  err = sek_vaultref_of(pool, name, &ref);
  if (NULL != err) {
    return err;
  }

  if (1 == data->kv) {
    url = sek_fmt(pool, "%s/v1/%s/%s", sek_trimslash(pool, data->addr), data->mount, ref.path);
  } else {
    url = sek_fmt(pool, "%s/v1/%s/data/%s", sek_trimslash(pool, data->addr), data->mount, ref.path);
  }

  headers = vaultheaders(data);
  sek_map_set(headers, "X-Vault-Token", sek_orempty(data->livetoken));

  err = sek_fetchjson(pool, "GET", url, headers, NULL, &res);
  if (NULL != err) {
    return err;
  }

  /* A 404 means "not here" - a miss - so a vault can sit in a chain with
   * fallbacks behind it. */
  if (404 == res.status) {
    return NULL;
  }

  if (200 != res.status) {
    return sek_fmt(pool, "sekreto: hashicorp error: %d: %s", res.status, url);
  }

  if (1 == data->kv) {
    found = sek_json_dig(res.body, "data", ref.field, NULL);
  } else {
    found = sek_json_dig(res.body, "data", "data", ref.field, NULL);
  }

  {
    const char *text = sek_json_text(pool, found);
    if (NULL != text) {
      *out = sek_strdup(pool, text);
    }
  }

  return NULL;
}

static const char *hashicorp_describe(sek_provider *self) {
  return ((hashicorpdata *)self->data)->described;
}

/* ---- boru ---------------------------------------------------------- */

typedef struct {
  sek_pool *pool;
  const char *command;
  const char *namespace_;
  const char *home;
  char *addr;
  const char *token;
  const char *mount;
  char *described;
} borudata;

/* Does this boru failure mean "no such secret" rather than "I could not
 * answer"? Matched on boru's own wording for a missing alias. A locked
 * vault or a wrong passphrase is NOT a miss. */
static int borumiss(const char *why) { return sek_contains(why, "no alias named"); }

static sek_err boru_wire(borudata *data, const char *name, char **out) {
  sek_pool *pool = data->pool;
  sek_map *headers;
  sek_answer res;
  sek_err err = sek_checkaddr(pool, data->addr);
  char *url;
  const char *text;

  if (NULL != err) {
    return err;
  }

  /* The dotted name stays ONE path segment: a boru alias keeps its dots,
   * unlike the api/token split a HashiCorp KV gets. */
  if (sek_empty(data->namespace_)) {
    url = sek_fmt(pool, "%s/v1/%s/data/%s", data->addr, data->mount, name);
  } else {
    url = sek_fmt(pool, "%s/v1/%s/data/%s/%s", data->addr, data->mount, data->namespace_, name);
  }

  headers = sek_map_new(pool);
  sek_map_set(headers, "X-Vault-Token", sek_orempty(data->token));

  err = sek_fetchjson(pool, "GET", url, headers, NULL, &res);
  if (NULL != err) {
    return err;
  }

  if (404 == res.status) {
    return NULL;
  }

  if (200 != res.status) {
    return sek_fmt(pool, "sekreto: boru serve error: %d: %s", res.status, url);
  }

  text = sek_json_text(pool, sek_json_dig(res.body, "data", "data", "value", NULL));
  if (NULL != text) {
    *out = sek_strdup(pool, text);
  }

  return NULL;
}

static sek_err boru_lookup(sek_provider *self, const char *name, char **out) {
  borudata *data = (borudata *)self->data;
  sek_pool *pool = data->pool;
  sek_err err = sek_checkname(pool, name);
  char *alias;
  char *argv[6];
  sek_ran ran;
  size_t len;

  *out = NULL;

  if (NULL != err) {
    return err;
  }

  if (!sek_empty(data->addr)) {
    return boru_wire(data, name, out);
  }

  /* CLI mode: a COLON joins the namespace, not a slash. */
  alias = sek_empty(data->namespace_) ? sek_strdup(pool, name)
                                      : sek_fmt(pool, "%s:%s", data->namespace_, name);

  argv[0] = (char *)data->command;
  argv[1] = (char *)"vault";
  argv[2] = (char *)"get";
  argv[3] = (char *)"--reveal";
  argv[4] = alias;
  argv[5] = NULL;

  /* The passphrase is never config and never on a command line, where the
   * process table publishes it: boru reads BORU_VAULT_PASSPHRASE itself. */
  err = sek_runcmd(pool, argv, data->command, sek_empty(data->home) ? NULL : "BORU_HOME",
                   data->home, &ran);
  if (NULL != err) {
    return err;
  }

  if (0 == ran.status) {
    /* boru prints the value and one newline, and nothing else. */
    len = strlen(ran.out);
    *out = 1 <= len && '\n' == ran.out[len - 1] ? sek_strndup(pool, ran.out, len - 1) : ran.out;
    return NULL;
  }

  if (borumiss(ran.why)) {
    return NULL;
  }

  return sek_fmt(pool, "sekreto: boru vault error: %s",
                 sek_empty(ran.why) ? sek_fmt(pool, "exit %d", ran.status) : ran.why);
}

static const char *boru_describe(sek_provider *self) {
  return ((borudata *)self->data)->described;
}

/* ---- secretspec ---------------------------------------------------- */

typedef struct {
  sek_pool *pool;
  const char *command;
  const char *file;
  const char *profile;
  const char *backend;
  const char *reason;
  const char *prefix;
  char *described;
} secretspecdata;

/* Does this SecretSpec failure mean "no such secret" rather than "I could
 * not answer"?
 *
 * MATCHED ON THE WHOLE PHRASE, NOT ON "not found". SecretSpec also says
 * `Provider backend 'keyring' not found`, which is a store that could not
 * answer at all - and reading that as a miss is the worst failure this
 * library has, because the chain then falls through to a weaker store
 * without saying so. The key is required to appear, so the two cannot be
 * confused. */
static int secretspecmiss(sek_pool *pool, const char *why, const char *key) {
  return sek_contains(why, sek_fmt(pool, "Secret '%s' not found", key));
}

static sek_err secretspec_lookup(sek_provider *self, const char *name, char **out) {
  secretspecdata *data = (secretspecdata *)self->data;
  sek_pool *pool = data->pool;
  char *key = NULL;
  sek_err err = sek_envkey(pool, name, data->prefix, &key);
  char *argv[12];
  size_t at = 0;
  sek_ran ran;
  size_t len;

  *out = NULL;

  if (NULL != err) {
    return err;
  }

  /* The order is exact: --file comes BEFORE the subcommand, and --reason
   * is always sent, because SecretSpec audits every read and refuses
   * without one. */
  argv[at++] = (char *)data->command;
  if (!sek_empty(data->file)) {
    argv[at++] = (char *)"--file";
    argv[at++] = (char *)data->file;
  }
  argv[at++] = (char *)"get";
  argv[at++] = key;
  if (!sek_empty(data->backend)) {
    argv[at++] = (char *)"--provider";
    argv[at++] = (char *)data->backend;
  }
  if (!sek_empty(data->profile)) {
    argv[at++] = (char *)"--profile";
    argv[at++] = (char *)data->profile;
  }
  argv[at++] = (char *)"--reason";
  argv[at++] = (char *)sek_first(data->reason, "sekreto");
  argv[at] = NULL;

  err = sek_runcmd(pool, argv, data->command, NULL, NULL, &ran);
  if (NULL != err) {
    return err;
  }

  if (0 == ran.status) {
    len = strlen(ran.out);
    *out = 1 <= len && '\n' == ran.out[len - 1] ? sek_strndup(pool, ran.out, len - 1) : ran.out;
    return NULL;
  }

  if (secretspecmiss(pool, ran.why, key)) {
    return NULL;
  }

  return sek_fmt(pool, "sekreto: secretspec error: %s",
                 sek_empty(ran.why) ? sek_fmt(pool, "exit %d", ran.status) : ran.why);
}

static const char *secretspec_describe(sek_provider *self) {
  return ((secretspecdata *)self->data)->described;
}

/* ---- aws ----------------------------------------------------------- */

typedef struct {
  sek_pool *pool;
  const char *region;
  const char *keyid;
  const char *secret;
  const char *session;
  const char *addr;
  const char *prefix;
  char *described;
} awsdata;

/* Region and credentials, from config first and the standard AWS_*
 * environment variables second - those are AWS's own convention, and a
 * pod or CI job that has them set should just work. Missing either is an
 * error: an AWS store with no credentials could not answer. */
static sek_err awscall(awsdata *data, const char *service, const char *targetname,
                       const char *payload, sek_answer *out) {
  sek_pool *pool = data->pool;
  const char *region = first3(data->region, getenv("AWS_REGION"), getenv("AWS_DEFAULT_REGION"));
  const char *keyid = sek_first(data->keyid, getenv("AWS_ACCESS_KEY_ID"));
  const char *secret = sek_first(data->secret, getenv("AWS_SECRET_ACCESS_KEY"));
  const char *session = sek_first(data->session, getenv("AWS_SESSION_TOKEN"));
  const char *addr;
  char *url;
  sek_map *extras;
  sek_map *signed_;
  sek_signing input;
  sek_err err;
  size_t index;

  if (sek_empty(region)) {
    return sek_strdup(pool, "sekreto: aws: no region (set region or AWS_REGION)");
  }
  if (sek_empty(keyid) || sek_empty(secret)) {
    return sek_strdup(pool, "sekreto: aws: no credentials (set keyid/secret or "
                            "AWS_ACCESS_KEY_ID/AWS_SECRET_ACCESS_KEY)");
  }

  /* The China partition lives under its own suffix; every other
   * commercial region is plain amazonaws.com. */
  addr = sek_first(data->addr, sek_fmt(pool, "https://%s.%s%s", service, region,
                                       sek_has_prefix(region, "cn-") ? ".amazonaws.com.cn"
                                                                     : ".amazonaws.com"));

  err = sek_checkaddr(pool, addr);
  if (NULL != err) {
    return err;
  }

  url = sek_fmt(pool, "%s/", sek_trimslash(pool, addr));

  extras = sek_map_new(pool);
  sek_map_set(extras, "content-type", "application/x-amz-json-1.1");
  sek_map_set(extras, "x-amz-target", targetname);

  memset(&input, 0, sizeof(input));
  input.method = "POST";
  input.url = url;
  input.service = service;
  input.region = region;
  input.keyid = keyid;
  input.secret = secret;
  input.datetime = sek_awsnow(pool);
  input.headers = extras;
  input.body = payload;
  input.session = sek_empty(session) ? NULL : session;

  signed_ = sek_sigv4(pool, &input);

  /* The signed headers go on top of the caller's. */
  for (index = 0; index < signed_->len; index++) {
    sek_map_set(extras, signed_->keys[index], signed_->vals[index]);
  }

  return sek_fetchjson(pool, "POST", url, extras, payload, out);
}

/* Does this AWS error body name the not-found type? AWS sends it fully
 * qualified - `com.amazonaws...#ResourceNotFoundException` - so this is a
 * containment test, and it is only ever consulted alongside a 400. */
static int awsmiss(sek_json *body, const char *type) {
  const char *errtype = sek_json_asstr(sek_json_dig(body, "__type", NULL));

  return NULL != errtype && sek_contains(errtype, type);
}

static sek_err awssecrets_lookup(sek_provider *self, const char *name, char **out) {
  awsdata *data = (awsdata *)self->data;
  sek_pool *pool = data->pool;
  sek_vaultref ref;
  sek_json *payload;
  sek_answer res;
  sek_err err;
  const char *text;

  *out = NULL;

  err = sek_vaultref_of(pool, name, &ref);
  if (NULL != err) {
    return err;
  }

  payload = sek_json_obj(pool);
  sek_json_set(pool, payload, "SecretId", sek_json_str(pool, ref.path));

  err = awscall(data, "secretsmanager", "secretsmanager.GetSecretValue",
                sek_json_stringify(pool, payload), &res);
  if (NULL != err) {
    return err;
  }

  if (400 == res.status && awsmiss(res.body, "ResourceNotFoundException")) {
    return NULL;
  }

  if (200 != res.status) {
    return sek_fmt(pool, "sekreto: aws secretsmanager error: %d", res.status);
  }

  text = sek_json_asstr(sek_json_dig(res.body, "SecretString", NULL));

  if (NULL == text) {
    /* A binary secret has no fields to address, so only the conventional
     * `value` field can mean "the bytes themselves". */
    const char *bin = sek_json_asstr(sek_json_dig(res.body, "SecretBinary", NULL));

    if (NULL != bin && 0 == strcmp(ref.field, "value")) {
      size_t len = 0;
      unsigned char *raw = sek_unbase64(pool, bin, &len);

      if (NULL == raw) {
        return sek_strdup(pool, "sekreto: aws secretsmanager: undecodable secret");
      }

      *out = sek_strndup(pool, (const char *)raw, len);
      return NULL;
    }

    return NULL;
  }

  {
    /* The AWS idiom is one JSON map per secret, so the secret's own value
     * is parsed and the field taken out of it. */
    sek_json *parsed = sek_json_parse(pool, text);

    if (NULL != parsed && SEK_JSON_OBJ == parsed->type) {
      const char *found = sek_json_text(pool, sek_json_dig(parsed, ref.field, NULL));
      if (NULL != found) {
        *out = sek_strdup(pool, found);
      }
      return NULL;
    }
  }

  /* A plain-string secret is the whole value; it has no named fields. */
  if (0 == strcmp(ref.field, "value")) {
    *out = sek_strdup(pool, text);
  }

  return NULL;
}

static sek_err awsparams_lookup(sek_provider *self, const char *name, char **out) {
  awsdata *data = (awsdata *)self->data;
  sek_pool *pool = data->pool;
  char *param = NULL;
  sek_json *payload;
  sek_answer res;
  sek_err err = sek_awsparam(pool, name, data->prefix, &param);
  const char *text;

  *out = NULL;

  if (NULL != err) {
    return err;
  }

  payload = sek_json_obj(pool);
  sek_json_set(pool, payload, "Name", sek_json_str(pool, param));
  sek_json_set(pool, payload, "WithDecryption", sek_json_bool(pool, 1));

  err = awscall(data, "ssm", "AmazonSSM.GetParameter", sek_json_stringify(pool, payload), &res);
  if (NULL != err) {
    return err;
  }

  if (400 == res.status && awsmiss(res.body, "ParameterNotFound")) {
    return NULL;
  }

  if (200 != res.status) {
    return sek_fmt(pool, "sekreto: aws ssm error: %d", res.status);
  }

  /* Parameter Store carries flat strings: no field indirection. */
  text = sek_json_text(pool, sek_json_dig(res.body, "Parameter", "Value", NULL));
  if (NULL != text) {
    *out = sek_strdup(pool, text);
  }

  return NULL;
}

static const char *aws_describe(sek_provider *self) {
  return ((awsdata *)self->data)->described;
}

/* ---- gcp ----------------------------------------------------------- */

typedef struct {
  sek_pool *pool;
  const char *project;
  const char *token;
  const char *addr;
  const char *metadataaddr;
  char *livetoken;
  long long renewat;
  char *described;
} gcpdata;

static sek_err gcp_login(gcpdata *data, char **out) {
  sek_pool *pool = data->pool;
  const char *configured = sek_first(data->token, getenv("GOOGLE_OAUTH_ACCESS_TOKEN"));
  const char *base;
  char *url;
  sek_map *headers;
  sek_answer res;
  sek_err err;
  const char *got;

  if (!sek_empty(configured)) {
    *out = sek_strdup(pool, configured);
    return NULL;
  }

  if (!sek_empty(data->metadataaddr)) {
    base = data->metadataaddr;
  } else {
    const char *host = getenv("GCE_METADATA_HOST");
    base = sek_empty(host) ? "http://metadata.google.internal" : sek_fmt(pool, "http://%s", host);
  }

  url = sek_fmt(pool, "%s/computeMetadata/v1/instance/service-accounts/default/token",
                sek_trimslash(pool, base));

  headers = sek_map_new(pool);
  sek_map_set(headers, "Metadata-Flavor", "Google");

  /* The metadata call is plain http to a link-local host by platform
   * design and carries no credential, so it is deliberately NOT
   * checkaddr-guarded; the Secret Manager address is. */
  err = sek_fetchjson(pool, "GET", url, headers, NULL, &res);
  if (NULL != err) {
    return err;
  }

  got = sek_json_text(pool, sek_json_dig(res.body, "access_token", NULL));
  if (200 != res.status || sek_empty(got)) {
    return sek_strdup(pool, "sekreto: gcp: no token and metadata server did not answer");
  }

  data->renewat = sek_renewtime(sek_json_dig(res.body, "expires_in", NULL));
  *out = sek_strdup(pool, got);

  return NULL;
}

static sek_err gcp_lookup(sek_provider *self, const char *name, char **out) {
  gcpdata *data = (gcpdata *)self->data;
  sek_pool *pool = data->pool;
  const char *addr;
  char *flat = NULL;
  char *url;
  sek_map *headers;
  sek_answer res;
  sek_err err;
  const char *encoded;

  *out = NULL;

  if (sek_empty(data->project)) {
    return sek_strdup(pool, "sekreto: gcp: no project");
  }

  addr = sek_first(data->addr, "https://secretmanager.googleapis.com");
  err = sek_checkaddr(pool, addr);
  if (NULL != err) {
    return err;
  }

  if (NULL == data->livetoken || sek_nowms() >= data->renewat) {
    err = gcp_login(data, &data->livetoken);
    if (NULL != err) {
      return err;
    }
  }

  /* Dots flatten to `_`: Secret Manager ids have no hierarchy and reject
   * dots. */
  err = sek_flatname(pool, name, "_", &flat);
  if (NULL != err) {
    return err;
  }

  url = sek_fmt(pool, "%s/v1/projects/%s/secrets/%s/versions/latest:access",
                sek_trimslash(pool, addr), data->project, flat);

  headers = sek_map_new(pool);
  sek_map_set(headers, "authorization", sek_fmt(pool, "Bearer %s", sek_orempty(data->livetoken)));

  err = sek_fetchjson(pool, "GET", url, headers, NULL, &res);
  if (NULL != err) {
    return err;
  }

  if (404 == res.status) {
    return NULL;
  }

  if (200 != res.status) {
    return sek_fmt(pool, "sekreto: gcp error: %d: %s", res.status, url);
  }

  encoded = sek_json_asstr(sek_json_dig(res.body, "payload", "data", NULL));
  if (NULL == encoded) {
    return NULL;
  }

  {
    size_t len = 0;
    unsigned char *raw = sek_unbase64(pool, encoded, &len);

    if (NULL == raw) {
      return sek_strdup(pool, "sekreto: gcp: undecodable secret");
    }

    *out = sek_strndup(pool, (const char *)raw, len);
  }

  return NULL;
}

static const char *gcp_describe(sek_provider *self) {
  return ((gcpdata *)self->data)->described;
}

/* ---- azure --------------------------------------------------------- */

#define AZURE_RESOURCE "https://vault.azure.net"

typedef struct {
  sek_pool *pool;
  const char *vault;
  const char *token;
  const char *tenant;
  const char *clientid;
  const char *clientsecret;
  const char *loginaddr;
  const char *imdsaddr;
  const char *apiversion;
  char *livetoken;
  long long renewat;
  char *described;
} azuredata;

static sek_err azure_login(azuredata *data, char **out) {
  sek_pool *pool = data->pool;
  sek_map *headers;
  sek_answer res;
  sek_err err;
  const char *got;
  char *url;

  if (!sek_empty(data->token)) {
    *out = sek_strdup(pool, data->token);
    return NULL;
  }

  if (!sek_empty(data->tenant) && !sek_empty(data->clientid) && !sek_empty(data->clientsecret)) {
    const char *base = sek_first(data->loginaddr, "https://login.microsoftonline.com");
    char *form;

    err = sek_checkaddr(pool, base);
    if (NULL != err) {
      return err;
    }

    url = sek_fmt(pool, "%s/%s/oauth2/v2.0/token", sek_trimslash(pool, base), data->tenant);
    form = sek_fmt(pool, "grant_type=client_credentials&client_id=%s&client_secret=%s&scope=%s",
                   sek_uriescape(pool, data->clientid), sek_uriescape(pool, data->clientsecret),
                   sek_uriescape(pool, AZURE_RESOURCE "/.default"));

    headers = sek_map_new(pool);
    sek_map_set(headers, "content-type", "application/x-www-form-urlencoded");

    err = sek_fetchjson(pool, "POST", url, headers, form, &res);
    if (NULL != err) {
      return err;
    }

    got = sek_json_text(pool, sek_json_dig(res.body, "access_token", NULL));
    if (200 != res.status || sek_empty(got)) {
      return sek_fmt(pool, "sekreto: azure login failed: %d", res.status);
    }

    data->renewat = sek_renewtime(sek_json_dig(res.body, "expires_in", NULL));
    *out = sek_strdup(pool, got);
    return NULL;
  }

  /* IMDS: link-local by platform design, and it returns expires_in as a
   * STRING, which renewtime accepts. */
  url = sek_fmt(pool, "%s/metadata/identity/oauth2/token?api-version=2018-02-01&resource=%s",
                sek_trimslash(pool, sek_first(data->imdsaddr, "http://169.254.169.254")),
                sek_uriescape(pool, AZURE_RESOURCE));

  headers = sek_map_new(pool);
  sek_map_set(headers, "Metadata", "true");

  err = sek_fetchjson(pool, "GET", url, headers, NULL, &res);
  if (NULL != err) {
    return err;
  }

  got = sek_json_text(pool, sek_json_dig(res.body, "access_token", NULL));
  if (200 != res.status || sek_empty(got)) {
    return sek_strdup(pool,
                      "sekreto: azure: no token, no client credentials, and IMDS did not answer");
  }

  data->renewat = sek_renewtime(sek_json_dig(res.body, "expires_in", NULL));
  *out = sek_strdup(pool, got);

  return NULL;
}

static sek_err azure_lookup(sek_provider *self, const char *name, char **out) {
  azuredata *data = (azuredata *)self->data;
  sek_pool *pool = data->pool;
  char *vaulturl;
  char *flat = NULL;
  char *url;
  sek_map *headers;
  sek_answer res;
  sek_err err;
  const char *text;

  *out = NULL;

  if (sek_empty(data->vault)) {
    return sek_strdup(pool, "sekreto: azure: no vault");
  }

  /* ONLY an explicit scheme is a URL: a vault NAMED `httpvault` must
   * still become https://httpvault.vault.azure.net. */
  if (sek_has_prefix(data->vault, "http://") || sek_has_prefix(data->vault, "https://")) {
    vaulturl = sek_strdup(pool, data->vault);
  } else {
    vaulturl = sek_fmt(pool, "https://%s.vault.azure.net", data->vault);
  }

  err = sek_checkaddr(pool, vaulturl);
  if (NULL != err) {
    return err;
  }

  if (NULL == data->livetoken || sek_nowms() >= data->renewat) {
    err = azure_login(data, &data->livetoken);
    if (NULL != err) {
      return err;
    }
  }

  /* Dots flatten to `-`: Key Vault names allow letters, digits and
   * hyphens and nothing else. */
  err = sek_flatname(pool, name, "-", &flat);
  if (NULL != err) {
    return err;
  }

  url = sek_fmt(pool, "%s/secrets/%s?api-version=%s", sek_trimslash(pool, vaulturl), flat,
                sek_first(data->apiversion, "7.4"));

  headers = sek_map_new(pool);
  sek_map_set(headers, "authorization", sek_fmt(pool, "Bearer %s", sek_orempty(data->livetoken)));

  err = sek_fetchjson(pool, "GET", url, headers, NULL, &res);
  if (NULL != err) {
    return err;
  }

  if (404 == res.status) {
    return NULL;
  }

  if (200 != res.status) {
    return sek_fmt(pool, "sekreto: azure error: %d: %s", res.status, sek_bareurl(pool, url));
  }

  text = sek_json_text(pool, sek_json_dig(res.body, "value", NULL));
  if (NULL != text) {
    *out = sek_strdup(pool, text);
  }

  return NULL;
}

static const char *azure_describe(sek_provider *self) {
  return ((azuredata *)self->data)->described;
}

/* ---- 1password ----------------------------------------------------- */

typedef struct {
  sek_pool *pool;
  const char *addr;
  const char *token;
  const char *vault;
  char *vaultid;
  char *described;
} onepassworddata;

static sek_map *opauth(onepassworddata *data) {
  sek_map *out = sek_map_new(data->pool);

  sek_map_set(out, "authorization", sek_fmt(data->pool, "Bearer %s", sek_orempty(data->token)));

  return out;
}

/* The vault id, resolved once and memoised. A vault that cannot be found
 * is an ERROR, not a miss: config names it, so its absence is a broken
 * store rather than a missing secret. */
static sek_err opvault(onepassworddata *data, const char *addr, char **out) {
  sek_pool *pool = data->pool;
  sek_answer res;
  sek_err err;
  const sek_json *list;
  size_t index;

  if (sek_empty(data->vault)) {
    return sek_strdup(pool, "sekreto: onepassword: no vault");
  }

  err = sek_fetchjson(pool, "GET", sek_fmt(pool, "%s/v1/vaults", addr), opauth(data), NULL, &res);
  if (NULL != err) {
    return err;
  }

  list = sek_json_asarr(res.body);
  if (200 != res.status || NULL == list) {
    return sek_fmt(pool, "sekreto: onepassword error: %d: listing vaults", res.status);
  }

  for (index = 0; index < list->itemlen; index++) {
    const char *id = sek_json_text(pool, sek_json_dig(list->items[index], "id", NULL));
    const char *label = sek_json_text(pool, sek_json_dig(list->items[index], "name", NULL));

    if ((NULL != id && 0 == strcmp(data->vault, id)) ||
        (NULL != label && 0 == strcmp(data->vault, label))) {
      *out = sek_strdup(pool, sek_orempty(id));
      return NULL;
    }
  }

  return sek_fmt(pool, "sekreto: onepassword: no vault named %s", data->vault);
}

static sek_err onepassword_lookup(sek_provider *self, const char *name, char **out) {
  onepassworddata *data = (onepassworddata *)self->data;
  sek_pool *pool = data->pool;
  sek_err err = sek_checkname(pool, name);
  char *addr;
  sek_answer found;
  sek_answer item;
  const sek_json *items;
  const sek_json *fields;
  size_t index;

  *out = NULL;

  if (NULL != err) {
    return err;
  }

  addr = sek_trimslash(pool, sek_orempty(data->addr));
  if (sek_empty(addr)) {
    return sek_strdup(pool, "sekreto: onepassword: no addr");
  }

  err = sek_checkaddr(pool, addr);
  if (NULL != err) {
    return err;
  }

  if (NULL == data->vaultid) {
    err = opvault(data, addr, &data->vaultid);
    if (NULL != err) {
      return err;
    }
  }

  /* Item titles keep their dots. */
  err = sek_fetchjson(
      pool, "GET",
      sek_fmt(pool, "%s/v1/vaults/%s/items?filter=%s", addr, data->vaultid,
              sek_uriescape(pool, sek_fmt(pool, "title eq \"%s\"", name))),
      opauth(data), NULL, &found);
  if (NULL != err) {
    return err;
  }

  items = sek_json_asarr(found.body);
  if (200 != found.status || NULL == items) {
    return sek_fmt(pool, "sekreto: onepassword error: %d: finding %s", found.status, name);
  }

  /* An empty list is the secret not being there: a miss. */
  if (0 == items->itemlen) {
    return NULL;
  }

  err = sek_fetchjson(pool, "GET",
                      sek_fmt(pool, "%s/v1/vaults/%s/items/%s", addr, data->vaultid,
                              sek_orempty(sek_json_text(pool, sek_json_dig(items->items[0], "id",
                                                                          NULL)))),
                      opauth(data), NULL, &item);
  if (NULL != err) {
    return err;
  }

  if (200 != item.status) {
    return sek_fmt(pool, "sekreto: onepassword error: %d: reading %s", item.status, name);
  }

  fields = sek_json_asarr(sek_json_dig(item.body, "fields", NULL));
  if (NULL == fields) {
    return NULL;
  }

  /* Two full passes, in this order: the password field first, then a
   * field labelled `value`. */
  for (index = 0; index < fields->itemlen; index++) {
    const char *purpose = sek_json_asstr(sek_json_dig(fields->items[index], "purpose", NULL));
    if (NULL != purpose && 0 == strcmp(purpose, "PASSWORD")) {
      const char *value = sek_json_text(pool, sek_json_dig(fields->items[index], "value", NULL));
      if (NULL != value) {
        *out = sek_strdup(pool, value);
      }
      return NULL;
    }
  }

  for (index = 0; index < fields->itemlen; index++) {
    const char *label = sek_json_asstr(sek_json_dig(fields->items[index], "label", NULL));
    if (NULL != label && 0 == strcmp(label, "value")) {
      const char *value = sek_json_text(pool, sek_json_dig(fields->items[index], "value", NULL));
      if (NULL != value) {
        *out = sek_strdup(pool, value);
      }
      return NULL;
    }
  }

  return NULL;
}

static const char *onepassword_describe(sek_provider *self) {
  return ((onepassworddata *)self->data)->described;
}

/* ---- doppler ------------------------------------------------------- */

typedef struct {
  sek_pool *pool;
  const char *token;
  const char *project;
  const char *config;
  const char *addr;
  sek_map *values;
  char *described;
} dopplerdata;

/* The whole config is downloaded ONCE - Doppler's own bulk endpoint - and
 * answered from memory, like a remote .env. A failure caches nothing, so
 * a failed load retries on the next lookup. */
static sek_err doppler_load(dopplerdata *data) {
  sek_pool *pool = data->pool;
  char *addr;
  sek_buf url;
  sek_map *headers;
  sek_answer res;
  sek_err err;
  const sek_json *body;
  sek_map *loaded;
  size_t index;

  if (NULL != data->values) {
    return NULL;
  }

  addr = sek_trimslash(pool, sek_first(data->addr, "https://api.doppler.com"));
  err = sek_checkaddr(pool, addr);
  if (NULL != err) {
    return err;
  }

  sek_buf_init(&url, pool);
  sek_buf_addfmt(&url, "%s/v3/configs/config/secrets/download?format=json", addr);
  if (!sek_empty(data->project)) {
    sek_buf_addfmt(&url, "&project=%s", sek_uriescape(pool, data->project));
  }
  if (!sek_empty(data->config)) {
    sek_buf_addfmt(&url, "&config=%s", sek_uriescape(pool, data->config));
  }

  headers = sek_map_new(pool);
  sek_map_set(headers, "authorization", sek_fmt(pool, "Bearer %s", sek_orempty(data->token)));

  err = sek_fetchjson(pool, "GET", url.data, headers, NULL, &res);
  if (NULL != err) {
    return err;
  }

  body = sek_json_asobj(res.body);
  if (200 != res.status || NULL == body) {
    return sek_fmt(pool, "sekreto: doppler error: %d", res.status);
  }

  loaded = sek_map_new(pool);
  for (index = 0; index < body->maplen; index++) {
    /* Entries with null values are skipped; the rest are stringified. */
    const char *text = sek_json_text(pool, body->vals[index]);
    if (NULL != text) {
      sek_map_set(loaded, body->keys[index], text);
    }
  }

  data->values = loaded;

  return NULL;
}

static sek_err doppler_lookup(sek_provider *self, const char *name, char **out) {
  dopplerdata *data = (dopplerdata *)self->data;
  sek_pool *pool = data->pool;
  char *key = NULL;
  sek_err err;
  const char *found;

  *out = NULL;

  /* The `prefix` option is deliberately not consulted by this kind. */
  err = sek_envkey(pool, name, NULL, &key);
  if (NULL != err) {
    return err;
  }

  err = doppler_load(data);
  if (NULL != err) {
    return err;
  }

  found = sek_map_get(data->values, key);
  if (NULL != found) {
    *out = sek_strdup(pool, found);
  }

  return NULL;
}

static const char *doppler_describe(sek_provider *self) {
  return ((dopplerdata *)self->data)->described;
}

/* ---- infisical ----------------------------------------------------- */

typedef struct {
  sek_pool *pool;
  const char *addr;
  const char *token;
  const char *clientid;
  const char *clientsecret;
  const char *project;
  const char *environment;
  const char *path;
  char *livetoken;
  long long renewat;
  char *described;
} infisicaldata;

static sek_err infisical_login(infisicaldata *data, const char *addr, char **out) {
  sek_pool *pool = data->pool;
  sek_json *payload;
  sek_map *headers;
  sek_answer res;
  sek_err err;
  const char *got;

  if (!sek_empty(data->token)) {
    *out = sek_strdup(pool, data->token);
    return NULL;
  }

  if (sek_empty(data->clientid) || sek_empty(data->clientsecret)) {
    return sek_strdup(pool, "sekreto: infisical: no token and no client credentials");
  }

  payload = sek_json_obj(pool);
  sek_json_set(pool, payload, "clientId", sek_json_str(pool, data->clientid));
  sek_json_set(pool, payload, "clientSecret", sek_json_str(pool, data->clientsecret));

  headers = sek_map_new(pool);
  sek_map_set(headers, "content-type", "application/json");

  err = sek_fetchjson(pool, "POST", sek_fmt(pool, "%s/api/v1/auth/universal-auth/login", addr),
                      headers, sek_json_stringify(pool, payload), &res);
  if (NULL != err) {
    return err;
  }

  got = sek_json_text(pool, sek_json_dig(res.body, "accessToken", NULL));
  if (200 != res.status || sek_empty(got)) {
    return sek_fmt(pool, "sekreto: infisical login failed: %d", res.status);
  }

  /* camelCase, unlike everyone else's expires_in. */
  data->renewat = sek_renewtime(sek_json_dig(res.body, "expiresIn", NULL));
  *out = sek_strdup(pool, got);

  return NULL;
}

static sek_err infisical_lookup(sek_provider *self, const char *name, char **out) {
  infisicaldata *data = (infisicaldata *)self->data;
  sek_pool *pool = data->pool;
  char *addr = sek_trimslash(pool, sek_first(data->addr, "https://app.infisical.com"));
  char *key = NULL;
  char *url;
  sek_map *headers;
  sek_answer res;
  sek_err err = sek_checkaddr(pool, addr);
  const char *text;

  *out = NULL;

  if (NULL != err) {
    return err;
  }

  if (sek_empty(data->project) || sek_empty(data->environment)) {
    return sek_strdup(pool, "sekreto: infisical: no project/environment");
  }

  if (NULL == data->livetoken || sek_nowms() >= data->renewat) {
    err = infisical_login(data, addr, &data->livetoken);
    if (NULL != err) {
      return err;
    }
  }

  /* envkey here takes NO prefix: Infisical's own convention is plain
   * environment-style keys. */
  err = sek_envkey(pool, name, NULL, &key);
  if (NULL != err) {
    return err;
  }

  url = sek_fmt(pool, "%s/api/v3/secrets/raw/%s?workspaceId=%s&environment=%s&secretPath=%s", addr,
                key, sek_uriescape(pool, data->project), sek_uriescape(pool, data->environment),
                sek_uriescape(pool, sek_first(data->path, "/")));

  headers = sek_map_new(pool);
  sek_map_set(headers, "authorization", sek_fmt(pool, "Bearer %s", sek_orempty(data->livetoken)));

  err = sek_fetchjson(pool, "GET", url, headers, NULL, &res);
  if (NULL != err) {
    return err;
  }

  if (404 == res.status) {
    return NULL;
  }

  if (200 != res.status) {
    return sek_fmt(pool, "sekreto: infisical error: %d", res.status);
  }

  text = sek_json_text(pool, sek_json_dig(res.body, "secret", "secretValue", NULL));
  if (NULL != text) {
    *out = sek_strdup(pool, text);
  }

  return NULL;
}

static const char *infisical_describe(sek_provider *self) {
  return ((infisicaldata *)self->data)->described;
}

/* ---- the factory --------------------------------------------------- */

static sek_provider *provider(sek_pool *pool,
                              sek_err (*lookup)(sek_provider *, const char *, char **),
                              const char *(*describe)(sek_provider *), void *data) {
  sek_provider *out = (sek_provider *)sek_alloc(pool, sizeof(sek_provider));

  out->lookup = lookup;
  out->describe = describe;
  out->data = data;
  out->pool = pool;

  return out;
}

/* A spec string, copied into the pool: a spec is the caller's and may be
 * a stack value that is gone by the first lookup. */
static const char *own(sek_pool *pool, const char *text) {
  return NULL == text ? NULL : sek_strdup(pool, text);
}

sek_err sek_makeprovider(sek_pool *pool, const sek_spec *spec, sek_provider **out) {
  const char *kind = sek_orempty(spec->kind);

  if (0 == strcmp(kind, "env")) {
    envdata *data = (envdata *)sek_alloc(pool, sizeof(envdata));
    data->pool = pool;
    data->prefix = own(pool, spec->prefix);
    data->described = sek_empty(spec->prefix) ? sek_strdup(pool, "env")
                                              : sek_fmt(pool, "env:%s", spec->prefix);
    *out = provider(pool, env_lookup, env_describe, data);
    return NULL;
  }

  if (0 == strcmp(kind, "memory")) {
    memorydata *data = (memorydata *)sek_alloc(pool, sizeof(memorydata));
    data->pool = pool;
    data->prefix = own(pool, spec->prefix);
    data->values = sek_map_new(pool);
    if (NULL != spec->values) {
      size_t index;
      for (index = 0; index < spec->values->len; index++) {
        sek_map_set(data->values, spec->values->keys[index], spec->values->vals[index]);
      }
    }
    data->described = sek_empty(spec->prefix) ? sek_strdup(pool, "memory")
                                              : sek_fmt(pool, "memory:%s", spec->prefix);
    *out = provider(pool, memory_lookup, memory_describe, data);
    return NULL;
  }

  if (0 == strcmp(kind, "dotenv")) {
    dotenvdata *data = (dotenvdata *)sek_alloc(pool, sizeof(dotenvdata));
    data->pool = pool;
    data->file = own(pool, sek_empty(spec->file) ? ".env" : spec->file);
    data->prefix = own(pool, spec->prefix);
    data->values = NULL;
    data->described = sek_fmt(pool, "dotenv:%s", data->file);
    *out = provider(pool, dotenv_lookup, dotenv_describe, data);
    return NULL;
  }

  if (0 == strcmp(kind, "file")) {
    filedata *data = (filedata *)sek_alloc(pool, sizeof(filedata));
    data->pool = pool;
    data->dir = own(pool, sek_orempty(spec->dir));
    data->prefix = own(pool, spec->prefix);
    data->described = sek_fmt(pool, "file:%s", data->dir);
    *out = provider(pool, file_lookup, file_describe, data);
    return NULL;
  }

  if (0 == strcmp(kind, "hashicorp")) {
    hashicorpdata *data = (hashicorpdata *)sek_alloc(pool, sizeof(hashicorpdata));
    data->pool = pool;
    data->addr = own(pool, sek_orempty(spec->addr));
    data->mount = own(pool, sek_empty(spec->mount) ? "secret" : spec->mount);
    data->kv = spec->haskv ? spec->kv : 2;
    data->vaultnamespace = own(pool, spec->vaultnamespace);
    data->livetoken = sek_empty(spec->token) ? NULL : sek_strdup(pool, spec->token);
    data->renewat = SEK_NEVER;
    data->described = sek_fmt(pool, "hashicorp:%s/%s", data->addr, data->mount);

    if (NULL != spec->auth) {
      data->auth = (sek_authspec *)sek_alloc(pool, sizeof(sek_authspec));
      data->auth->method = own(pool, spec->auth->method);
      data->auth->mount = own(pool, spec->auth->mount);
      data->auth->role = own(pool, spec->auth->role);
      data->auth->jwt = own(pool, spec->auth->jwt);
      data->auth->jwtfile = own(pool, spec->auth->jwtfile);
      data->auth->roleid = own(pool, spec->auth->roleid);
      data->auth->secretid = own(pool, spec->auth->secretid);
    } else {
      data->auth = NULL;
    }

    /* A version typo like `kv: 3` must not quietly behave as v2 and turn
     * its 404s into misses; there is nothing safe to assume it meant. So
     * it is refused at CONSTRUCTION, before an address is even looked at. */
    if (1 != data->kv && 2 != data->kv) {
      return sek_fmt(pool, "sekreto: hashicorp: unsupported kv version: %d", data->kv);
    }

    *out = provider(pool, hashicorp_lookup, hashicorp_describe, data);
    return NULL;
  }

  if (0 == strcmp(kind, "boru")) {
    borudata *data = (borudata *)sek_alloc(pool, sizeof(borudata));
    data->pool = pool;
    data->command = own(pool, sek_empty(spec->command) ? "boru" : spec->command);
    data->namespace_ = own(pool, spec->namespace_);
    data->home = own(pool, spec->home);
    data->addr = NULL == spec->addr ? sek_strdup(pool, "") : sek_trimslash(pool, spec->addr);
    data->token = own(pool, sek_orempty(spec->token));
    data->mount = own(pool, sek_empty(spec->mount) ? "secret" : spec->mount);

    if (!sek_empty(data->addr)) {
      data->described = sek_fmt(pool, "boru:%s", data->addr);
    } else {
      data->described = sek_empty(data->namespace_)
                            ? sek_strdup(pool, "boru")
                            : sek_fmt(pool, "boru:%s", data->namespace_);
    }

    *out = provider(pool, boru_lookup, boru_describe, data);
    return NULL;
  }

  if (0 == strcmp(kind, "secretspec")) {
    secretspecdata *data = (secretspecdata *)sek_alloc(pool, sizeof(secretspecdata));
    data->pool = pool;
    data->command = own(pool, sek_empty(spec->command) ? "secretspec" : spec->command);
    data->file = own(pool, spec->file);
    data->profile = own(pool, spec->profile);
    data->backend = own(pool, spec->backend);
    data->reason = own(pool, spec->reason);
    data->prefix = own(pool, spec->prefix);
    data->described = sek_empty(spec->backend) ? sek_strdup(pool, "secretspec")
                                               : sek_fmt(pool, "secretspec:%s", spec->backend);
    *out = provider(pool, secretspec_lookup, secretspec_describe, data);
    return NULL;
  }

  if (0 == strcmp(kind, "awssecrets") || 0 == strcmp(kind, "awsparams")) {
    awsdata *data = (awsdata *)sek_alloc(pool, sizeof(awsdata));
    int params = 0 == strcmp(kind, "awsparams");

    data->pool = pool;
    data->region = own(pool, spec->region);
    data->keyid = own(pool, spec->keyid);
    data->secret = own(pool, spec->secret);
    data->session = own(pool, spec->session);
    data->addr = own(pool, spec->addr);
    data->prefix = own(pool, spec->prefix);

    /* Config only, never the environment: describe() feeds the spec's
     * sources group, which must answer the same everywhere. */
    if (params) {
      data->described =
          sek_fmt(pool, "awsparams:%s%s", sek_orempty(spec->region), sek_orempty(spec->prefix));
    } else {
      data->described = sek_fmt(pool, "awssecrets:%s", sek_orempty(spec->region));
    }

    *out = provider(pool, params ? awsparams_lookup : awssecrets_lookup, aws_describe, data);
    return NULL;
  }

  if (0 == strcmp(kind, "gcpsecrets")) {
    gcpdata *data = (gcpdata *)sek_alloc(pool, sizeof(gcpdata));
    data->pool = pool;
    data->project = own(pool, spec->project);
    data->token = own(pool, spec->token);
    data->addr = own(pool, spec->addr);
    data->metadataaddr = own(pool, spec->metadataaddr);
    data->livetoken = NULL;
    data->renewat = SEK_NEVER;
    data->described = sek_fmt(pool, "gcpsecrets:%s", sek_orempty(spec->project));
    *out = provider(pool, gcp_lookup, gcp_describe, data);
    return NULL;
  }

  if (0 == strcmp(kind, "azuresecrets")) {
    azuredata *data = (azuredata *)sek_alloc(pool, sizeof(azuredata));
    data->pool = pool;
    data->vault = own(pool, spec->vault);
    data->token = own(pool, spec->token);
    data->tenant = own(pool, spec->tenant);
    data->clientid = own(pool, spec->clientid);
    data->clientsecret = own(pool, spec->clientsecret);
    data->loginaddr = own(pool, spec->loginaddr);
    data->imdsaddr = own(pool, spec->imdsaddr);
    data->apiversion = own(pool, spec->apiversion);
    data->livetoken = NULL;
    data->renewat = SEK_NEVER;
    data->described = sek_fmt(pool, "azuresecrets:%s", sek_orempty(spec->vault));
    *out = provider(pool, azure_lookup, azure_describe, data);
    return NULL;
  }

  if (0 == strcmp(kind, "onepassword")) {
    onepassworddata *data = (onepassworddata *)sek_alloc(pool, sizeof(onepassworddata));
    data->pool = pool;
    data->addr = own(pool, spec->addr);
    data->token = own(pool, spec->token);
    data->vault = own(pool, spec->vault);
    data->vaultid = NULL;
    data->described = sek_fmt(pool, "onepassword:%s", sek_orempty(spec->vault));
    *out = provider(pool, onepassword_lookup, onepassword_describe, data);
    return NULL;
  }

  if (0 == strcmp(kind, "doppler")) {
    dopplerdata *data = (dopplerdata *)sek_alloc(pool, sizeof(dopplerdata));
    data->pool = pool;
    data->token = own(pool, spec->token);
    data->project = own(pool, spec->project);
    data->config = own(pool, spec->config);
    data->addr = own(pool, spec->addr);
    data->values = NULL;
    data->described = sek_empty(spec->project)
                          ? sek_strdup(pool, "doppler")
                          : sek_fmt(pool, "doppler:%s/%s", spec->project, sek_orempty(spec->config));
    *out = provider(pool, doppler_lookup, doppler_describe, data);
    return NULL;
  }

  if (0 == strcmp(kind, "infisical")) {
    infisicaldata *data = (infisicaldata *)sek_alloc(pool, sizeof(infisicaldata));
    data->pool = pool;
    data->addr = own(pool, spec->addr);
    data->token = own(pool, spec->token);
    data->clientid = own(pool, spec->clientid);
    data->clientsecret = own(pool, spec->clientsecret);
    data->project = own(pool, spec->project);
    data->environment = own(pool, spec->environment);
    data->path = own(pool, spec->path);
    data->livetoken = NULL;
    data->renewat = SEK_NEVER;
    data->described = sek_fmt(pool, "infisical:%s/%s", sek_orempty(spec->project),
                              sek_orempty(spec->environment));
    *out = provider(pool, infisical_lookup, infisical_describe, data);
    return NULL;
  }

  return sek_fmt(pool, "sekreto: unknown provider kind: %s", kind);
}
