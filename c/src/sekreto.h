/* sekreto: one interface for secrets, wherever they live.
 *
 * A Sekreto is an ordered chain of providers. `get` asks each in turn and
 * returns the first hit, so an app can be configured from environment
 * variables in development and a vault in production without changing a
 * line of its own code.
 *
 * A port of typescript/src/Sekreto.ts, which is canonical.
 *
 * Two conventions run through this header, and everything else follows
 * from them.
 *
 * OWNERSHIP. Every allocation comes from a sek_pool and is freed in one
 * go by sek_pool_free. Nothing returned by this library is freed by the
 * caller, and nothing returned outlives the pool it came from. A Sekreto
 * borrows the pool it is built with; sek_close releases its chain but not
 * the pool.
 *
 * FAILURE. C has no exceptions, so a fallible call returns `sek_err` - a
 * pool-owned message, or NULL for success - and writes its result through
 * an out-parameter. A MISS is not a failure: a lookup that succeeds with
 * `*out == NULL` means "this store does not hold it", and the chain
 * carries on. Collapsing the two would make a chain fall silently through
 * to a weaker store, which is the worst failure this library has.
 */

#ifndef VOXGIG_SEKRETO_H
#define VOXGIG_SEKRETO_H

#include <stddef.h>

/* An error message, or NULL when the call succeeded. Pool-owned. */
typedef const char *sek_err;

/* ---- pool ---------------------------------------------------------- */

typedef struct sek_pool sek_pool;

sek_pool *sek_pool_new(void);
void sek_pool_free(sek_pool *pool);

/* Zeroed memory from the pool. Never returns NULL: an arena that cannot
 * grow is a process that cannot continue, and a library that answers a
 * secret request with a half-filled buffer is worse than one that stops. */
void *sek_alloc(sek_pool *pool, size_t size);
char *sek_strdup(sek_pool *pool, const char *text);
char *sek_strndup(sek_pool *pool, const char *text, size_t len);

/* printf into the pool. */
char *sek_fmt(sek_pool *pool, const char *fmt, ...);

/* ---- buffer -------------------------------------------------------- */

/* A growable byte buffer. `data` is always NUL-terminated, so a buffer of
 * text is a C string the moment it is needed as one, while `len` stays
 * authoritative for a body that may carry embedded NULs. */
typedef struct {
  sek_pool *pool;
  char *data;
  size_t len;
  size_t cap;
} sek_buf;

void sek_buf_init(sek_buf *buf, sek_pool *pool);
void sek_buf_add(sek_buf *buf, const char *text);
void sek_buf_addn(sek_buf *buf, const char *text, size_t len);
void sek_buf_addch(sek_buf *buf, char ch);
void sek_buf_addfmt(sek_buf *buf, const char *fmt, ...);

/* ---- ordered string map -------------------------------------------- */

/* Insertion-ordered, because the spec compares whole maps and an AWS
 * payload's field order is signed. A list of pairs, not a hash: these are
 * never big enough for the difference to matter. */
typedef struct {
  sek_pool *pool;
  char **keys;
  char **vals;
  size_t len;
  size_t cap;
} sek_map;

sek_map *sek_map_new(sek_pool *pool);
void sek_map_set(sek_map *map, const char *key, const char *val);
const char *sek_map_get(const sek_map *map, const char *key);

/* ---- string list --------------------------------------------------- */

typedef struct {
  sek_pool *pool;
  char **items;
  size_t len;
  size_t cap;
} sek_list;

sek_list *sek_list_new(sek_pool *pool);
void sek_list_add(sek_list *list, const char *text);

/* ---- json ---------------------------------------------------------- */

typedef enum {
  SEK_JSON_NULL = 0,
  SEK_JSON_BOOL,
  SEK_JSON_NUM,
  SEK_JSON_STR,
  SEK_JSON_ARR,
  SEK_JSON_OBJ
} sek_jsontype;

typedef struct sek_json sek_json;

struct sek_json {
  sek_jsontype type;
  int boolval;
  double numval;
  char *strval;
  sek_json **items; /* ARR */
  size_t itemlen;
  size_t itemcap;
  char **keys; /* OBJ, insertion ordered */
  sek_json **vals;
  size_t maplen;
  size_t mapcap;
};

/* Parse JSON text. Returns NULL when the text is not JSON - which is a
 * different answer from a parsed literal `null`, and fetchjson needs the
 * difference: only the first means the store could not answer. */
sek_json *sek_json_parse(sek_pool *pool, const char *text);

sek_json *sek_json_null(sek_pool *pool);
sek_json *sek_json_bool(sek_pool *pool, int val);
sek_json *sek_json_num(sek_pool *pool, double val);
sek_json *sek_json_str(sek_pool *pool, const char *val);
sek_json *sek_json_arr(sek_pool *pool);
sek_json *sek_json_obj(sek_pool *pool);
void sek_json_push(sek_pool *pool, sek_json *arr, sek_json *val);
void sek_json_set(sek_pool *pool, sek_json *obj, const char *key, sek_json *val);

/* Walk nested objects, stopping at the first missing step. NULL-terminated
 * key list: sek_json_dig(body, "auth", "client_token", NULL). */
sek_json *sek_json_dig(sek_json *val, ...);

/* Typed reads. Each answers NULL/0 for the wrong type, so a `__type` that
 * is not a string, or a vault list that is not an array, is not mistaken
 * for one. */
const char *sek_json_asstr(const sek_json *val);
const sek_json *sek_json_asarr(const sek_json *val);
const sek_json *sek_json_asobj(const sek_json *val);

/* Printable text, or NULL. A JSON null yields NULL, so a null field is a
 * miss rather than the string "null". */
const char *sek_json_text(sek_pool *pool, const sek_json *val);

char *sek_json_stringify(sek_pool *pool, const sek_json *val);
char *sek_json_quote(sek_pool *pool, const char *text);

/* A JSON number as every port prints it: 1 rather than 1.0. */
char *sek_numstr(sek_pool *pool, double val);

/* ---- names --------------------------------------------------------- */

/* Is this a well-formed secret name? NULL, empty and anything outside
 * `[a-z0-9_]` per dot-separated segment answer false. Never fails. */
int sek_validname(const char *name);

/* The name, or `sekreto: invalid name: <name>`. Every entry point checks
 * its name here. A NULL name renders as the empty string. */
sek_err sek_checkname(sek_pool *pool, const char *name);

sek_err sek_envkey(sek_pool *pool, const char *name, const char *prefix, char **out);

typedef struct {
  char *path;
  char *field;
} sek_vaultref;

sek_err sek_vaultref_of(sek_pool *pool, const char *name, sek_vaultref *out);
sek_err sek_flatname(sek_pool *pool, const char *name, const char *sep, char **out);
sek_err sek_awsparam(sek_pool *pool, const char *name, const char *prefix, char **out);

/* Parse `.env` text. Never fails: a NULL input is an empty map. */
sek_map *sek_parsedotenv(sek_pool *pool, const char *text);

/* Replace every value of four characters or more with `[redacted]`,
 * longest first. A NULL text answers "". */
char *sek_redact(sek_pool *pool, const char *text, const sek_list *values);

/* ---- provider ------------------------------------------------------ */

typedef struct sek_provider sek_provider;

struct sek_provider {
  /* The value, or a miss (`*out = NULL`), or an error. */
  sek_err (*lookup)(sek_provider *self, const char *name, char **out);
  /* A short description, shown by sek_sources. Leads with the kind. */
  const char *(*describe)(sek_provider *self);
  void *data;
  sek_pool *pool;
};

/* The store name a provider answers to when nothing says otherwise:
 * describe() up to the first `:`. */
char *sek_storename(sek_pool *pool, sek_provider *provider);

/* ---- provider specs ------------------------------------------------ */

/* Logging in to a vault instead of being handed a token. */
typedef struct {
  const char *method;
  const char *mount;
  const char *role;
  const char *jwt;
  const char *jwtfile;
  const char *roleid;
  const char *secretid;
} sek_authspec;

/* The declarative form of a provider, as used in config and in the shared
 * spec. `kind` picks the provider; everything else is that kind's own.
 * Every string field defaults to NULL, which means the same as empty
 * everywhere in this library: "not configured". */
typedef struct {
  const char *kind;
  const char *name;
  const char *prefix;
  const char *file;
  sek_map *values;
  const char *dir;
  const char *addr;
  const char *token;
  const char *mount;
  int kv; /* 0 means unset, so the default of 2 still applies. */
  int haskv;
  const char *vaultnamespace;
  sek_authspec *auth;
  const char *command;
  const char *profile;
  const char *backend;
  const char *reason;
  const char *namespace_;
  const char *home;
  const char *region;
  const char *keyid;
  const char *secret;
  const char *session;
  const char *project;
  const char *vault;
  const char *tenant;
  const char *clientid;
  const char *clientsecret;
  const char *loginaddr;
  const char *imdsaddr;
  const char *metadataaddr;
  const char *apiversion;
  const char *config;
  const char *environment;
  const char *path;
} sek_spec;

/* A spec with every field at its default. */
sek_spec sek_spec_new(const char *kind);

/* Printed without its credentials: the obvious debug print of a chain
 * that will not build would otherwise put the Vault token, the AWS secret
 * key and the Azure client secret wherever it was printed. */
char *sek_spec_show(sek_pool *pool, const sek_spec *spec);
char *sek_authspec_show(sek_pool *pool, const sek_authspec *auth);

/* Build a provider from its declarative form. */
sek_err sek_makeprovider(sek_pool *pool, const sek_spec *spec, sek_provider **out);

/* ---- addresses ----------------------------------------------------- */

/* An address with any userinfo replaced by `[redacted]`, for messages. */
char *sek_safeaddr(sek_pool *pool, const char *addr);

/* Refuse to send a secret-bearing credential in the clear. Hand-parsed,
 * never with a platform URL type: twelve parsers disagree about malformed
 * input, and a check that answers differently per port is not a check. */
sek_err sek_checkaddr(sek_pool *pool, const char *addr);

/* ---- sekreto ------------------------------------------------------- */

typedef struct sek_sekreto sek_sekreto;

/* A chain of live providers, under the store names given positionally. A
 * NULL or empty name falls back to the provider's kind. `cache` is a
 * strict flag: only 0 disables the read cache. */
sek_sekreto *sek_new(sek_pool *pool, sek_provider **providers, const char **names, size_t count,
                     int cache);

/* A chain from declarative specs - the same shape the shared spec and an
 * app's config file use. Construction contacts nothing; it may still fail,
 * because a kind can refuse its own configuration. */
sek_err sek_sekreto_of(sek_pool *pool, const sek_spec *specs, size_t count, int cache,
                       sek_sekreto **out);

/* The secret, or `sekreto: unknown secret: <name>`. */
sek_err sek_get(sek_sekreto *sek, const char *name, char **out);

/* The secret, or a miss (`*out = NULL`). Named `sek_try` after canonical's
 * `try`, which is a keyword in several of the ports. */
sek_err sek_try(sek_sekreto *sek, const char *name, char **out);

/* The secret from one named store. Naming a store that is not in the
 * chain is an error, not a miss - and it is raised before the name is
 * validated. */
sek_err sek_getfrom(sek_sekreto *sek, const char *store, const char *name, char **out);
sek_err sek_tryfrom(sek_sekreto *sek, const char *store, const char *name, char **out);

sek_err sek_has(sek_sekreto *sek, const char *name, int *out);
sek_err sek_hasin(sek_sekreto *sek, const char *store, const char *name, int *out);

/* Every named secret at once. Missing ones are an error. */
sek_err sek_all(sek_sekreto *sek, const char **names, size_t count, sek_map **out);

/* A description of each provider, in resolution order, repeats kept. */
sek_list *sek_sources(sek_sekreto *sek);

/* The name of each store `sek_getfrom` can address, in resolution order
 * and without repeats. */
sek_list *sek_stores(sek_sekreto *sek);

/* Replace every value this Sekreto has resolved with `[redacted]`. Works
 * whether or not caching is on, and keeps working after sek_close. */
char *sek_redact_text(sek_sekreto *sek, const char *text);

/* Drop cached values, so the next read asks the providers again. The
 * redaction history is not a cache and survives this. */
void sek_refresh(sek_sekreto *sek);

/* Tear the chain down. Afterwards the chain is empty, reads miss, and
 * redaction still knows every value ever resolved. */
void sek_close(sek_sekreto *sek);

/* The print hook. `cache` and `seen` are ordinary fields, so a debug
 * print of a Sekreto would otherwise emit every resolved secret; this one
 * cannot reach a value. */
char *sek_show(sek_sekreto *sek);

/* ---- transport ----------------------------------------------------- */

/* One HTTP round-trip, published because a C consumer has no HTTP client
 * of its own to reach the API it just fetched a token for - and the CLI
 * every port ships is exactly such a consumer. Every other port calls its
 * platform's client here.
 *
 * https is verified: chain, hostname, SNI, and `SEKRETO_CA_BUNDLE` for
 * extra roots. A non-2xx status is returned rather than raised. */
sek_err sek_fetch(sek_pool *pool, const char *method, const char *url, const sek_map *headers,
                  const char *body, int *status, char **out);

/* ---- sigv4 --------------------------------------------------------- */

/* One request to sign. `datetime` is `YYYYMMDDTHHMMSSZ` and it is the
 * caller's, so signing is a pure function of its input - which is what
 * lets the shared spec carry known-answer cases. */
typedef struct {
  const char *method;
  const char *url;
  const char *service;
  const char *region;
  const char *keyid;
  const char *secret;
  const char *datetime;
  sek_map *headers;
  const char *body;
  const char *session;
} sek_signing;

/* The headers to attach: authorization, x-amz-date, and
 * x-amz-security-token when a session was given, in that order. */
sek_map *sek_sigv4(sek_pool *pool, const sek_signing *input);

/* RFC 3986 escaping, stricter than any stdlib encoder. */
char *sek_uriescape(sek_pool *pool, const char *text);

#endif /* VOXGIG_SEKRETO_H */
