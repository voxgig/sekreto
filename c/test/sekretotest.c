/* RUN: make test
 * RUN-SOME: ./build/sekretotest envkey
 *
 * The sekreto conformance suite. Every port runs these same fourteen
 * groups, from the same spec/sekreto.json, through its own voxgig/omni
 * runner.
 *
 * No third-party test framework: a failing omni check comes back as a
 * message, which this harness reports. Any host framework could do the
 * same.
 *
 * Two value models meet here. omni has an `omni_json` with an ABSENT case
 * distinct from null; the library takes plain C strings and a flat
 * `sek_spec`. The bridge below converts between them explicitly, so
 * nothing about absent, null and value is guessed - and the conversion
 * lives in the test, never in the library, which is why `sek_validname`
 * answers a C int rather than a JSON boolean.
 *
 * This is also the only file in the port that names voxgig/omni. Nothing
 * shipped does, which is what the repository's isolation guard checks.
 */

#define _POSIX_C_SOURCE 200809L

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "omni.h"
#include "sekreto.h"
#include "sekretoplugins.h"

static omni_pool *POOL = NULL;  /* omni's values */
static sek_pool *SEK = NULL;    /* the library's */
static const char *ONLY = NULL;
static int PASSCOUNT = 0;
static int FAILCOUNT = 0;

/* ---- the bridge ---------------------------------------------------- */

/* omni's model -> a C string, or NULL. ABSENT, null and every non-string
 * all read as NULL, which is what the library's entry points take for
 * "not a name" - and what makes `validname(42)` false rather than a
 * crash. */
static const char *plainstr(const omni_json *val) {
  if (NULL == val || !omni_isstr(val)) {
    return NULL;
  }
  return omni_strval(val);
}

static const char *field(const omni_json *entry, const char *key) {
  return plainstr(omni_map_get(entry, key));
}

/* A list of strings, as omni compares them. */
static omni_json *textlist(sek_list *values) {
  omni_json *out = omni_list(POOL);
  size_t index;

  for (index = 0; index < values->len; index++) {
    omni_list_push(out, omni_str(POOL, values->items[index]));
  }

  return out;
}

static omni_json *textmap(sek_map *values) {
  omni_json *out = omni_map(POOL);
  size_t index;

  for (index = 0; index < values->len; index++) {
    omni_map_set(out, values->keys[index], omni_str(POOL, values->vals[index]));
  }

  return out;
}

/* One provider spec, out of the spec's declarative chain description. */
static sek_spec specof(omni_json *entry) {
  sek_spec spec = sek_spec_new(field(entry, "kind"));
  omni_json *values = omni_map_get(entry, "values");
  omni_json *auth = omni_map_get(entry, "auth");
  omni_json *kv = omni_map_get(entry, "kv");

  spec.name = field(entry, "name");
  spec.prefix = field(entry, "prefix");
  spec.file = field(entry, "file");
  spec.dir = field(entry, "dir");
  spec.addr = field(entry, "addr");
  spec.token = field(entry, "token");
  spec.mount = field(entry, "mount");
  spec.vaultnamespace = field(entry, "vaultnamespace");
  spec.command = field(entry, "command");
  spec.profile = field(entry, "profile");
  spec.backend = field(entry, "backend");
  spec.reason = field(entry, "reason");
  spec.namespace_ = field(entry, "namespace");
  spec.home = field(entry, "home");
  spec.region = field(entry, "region");
  spec.keyid = field(entry, "keyid");
  spec.secret = field(entry, "secret");
  spec.session = field(entry, "session");
  spec.project = field(entry, "project");
  spec.vault = field(entry, "vault");
  spec.tenant = field(entry, "tenant");
  spec.clientid = field(entry, "clientid");
  spec.clientsecret = field(entry, "clientsecret");
  spec.loginaddr = field(entry, "loginaddr");
  spec.imdsaddr = field(entry, "imdsaddr");
  spec.metadataaddr = field(entry, "metadataaddr");
  spec.apiversion = field(entry, "apiversion");
  spec.config = field(entry, "config");
  spec.environment = field(entry, "environment");
  spec.path = field(entry, "path");

  if (omni_isnum(kv)) {
    spec.kv = (int)omni_numval(kv);
    spec.haskv = 1;
  }

  if (omni_ismap(values)) {
    size_t index;
    spec.values = sek_map_new(SEK);
    for (index = 0; index < values->maplen; index++) {
      /* Stringified, not read as a string: the spec's `values` map is
       * JSON and a value there need not already be one. */
      sek_map_set(spec.values, values->keys[index],
                  omni_stringify(POOL, values->vals[index]));
    }
  }

  if (omni_ismap(auth)) {
    sek_authspec *use = (sek_authspec *)sek_alloc(SEK, sizeof(sek_authspec));
    use->method = field(auth, "method");
    use->mount = field(auth, "mount");
    use->role = field(auth, "role");
    use->jwt = field(auth, "jwt");
    use->jwtfile = field(auth, "jwtfile");
    use->roleid = field(auth, "roleid");
    use->secretid = field(auth, "secretid");
    spec.auth = use;
  }

  return spec;
}

/* Build a Sekreto from the spec's declarative chain description.
 *
 * Called INSIDE each chain subject, not before it. Four corpus entries
 * expect `unsupported kv version`, which the CONSTRUCTOR raises, so the
 * construction has to happen where omni can see the failure as a subject
 * error.
 *
 * EVERY PLUGIN IS PASSED TO EVERY CHAIN, which is what makes this suite
 * blind to a consumer's plugin list: it can see that a kind is missing
 * from the full set, because `sources` and `stores` name all ten, and it
 * can never see that a consumer passed the wrong list. test/plugintest.c
 * is where that is pinned.
 *
 * Caching is off on every constructed chain, as in every port. */
static sek_err chainof(omni_json *entry, sek_sekreto **out) {
  omni_json *chain = omni_map_get(entry, "chain");
  size_t count = omni_islist(chain) ? chain->listlen : 0;
  sek_spec *specs = (sek_spec *)sek_alloc(SEK, (0 == count ? 1 : count) * sizeof(sek_spec));
  sek_options options;
  size_t index;

  for (index = 0; index < count; index++) {
    specs[index] = specof(chain->list[index]);
  }

  memset(&options, 0, sizeof(options));
  options.providers = specs;
  options.count = count;
  options.plugincount = sek_allplugins(&options.plugins);
  options.nocache = 1;

  return sek_new(SEK, &options, out);
}

static omni_result ok(omni_json *val) {
  omni_result out;
  out.val = val;
  out.err = NULL;
  return out;
}

static omni_result bad(sek_err err) {
  omni_result out;
  out.val = NULL;
  out.err = err;
  return out;
}

/* ---- the subjects -------------------------------------------------- */

/* `sek_validname` answers a C int; the spec wants a JSON boolean, so the
 * adaptation happens here rather than in the library. */
static omni_result subject_validname(omni_subject *self, omni_json **args, size_t nargs) {
  (void)self;
  return ok(omni_bool(POOL, sek_validname(plainstr(0 < nargs ? args[0] : NULL))));
}

static omni_result subject_envkey(omni_subject *self, omni_json **args, size_t nargs) {
  char *found = NULL;
  sek_err err;

  (void)self;
  (void)nargs;

  err = sek_envkey(SEK, field(args[0], "name"), field(args[0], "prefix"), &found);

  return NULL != err ? bad(err) : ok(omni_str(POOL, found));
}

static omni_result subject_vaultref(omni_subject *self, omni_json **args, size_t nargs) {
  sek_vaultref ref;
  sek_err err;
  omni_json *out;

  (void)self;
  (void)nargs;

  err = sek_vaultref_of(SEK, plainstr(args[0]), &ref);
  if (NULL != err) {
    return bad(err);
  }

  /* The spec's JSON shape, not the library's struct. */
  out = omni_map(POOL);
  omni_map_set(out, "path", omni_str(POOL, ref.path));
  omni_map_set(out, "field", omni_str(POOL, ref.field));

  return ok(out);
}

static omni_result subject_flatname(omni_subject *self, omni_json **args, size_t nargs) {
  char *found = NULL;
  const char *sep = field(args[0], "sep");
  sek_err err;

  (void)self;
  (void)nargs;

  err = sek_flatname(SEK, field(args[0], "name"), NULL == sep ? "" : sep, &found);

  return NULL != err ? bad(err) : ok(omni_str(POOL, found));
}

static omni_result subject_awsparam(omni_subject *self, omni_json **args, size_t nargs) {
  char *found = NULL;
  sek_err err;

  (void)self;
  (void)nargs;

  err = sek_awsparam(SEK, field(args[0], "name"), field(args[0], "prefix"), &found);

  return NULL != err ? bad(err) : ok(omni_str(POOL, found));
}

static omni_result subject_parsedotenv(omni_subject *self, omni_json **args, size_t nargs) {
  (void)self;
  (void)nargs;
  return ok(textmap(sek_parsedotenv(SEK, plainstr(args[0]))));
}

static omni_result subject_resolve(omni_subject *self, omni_json **args, size_t nargs) {
  sek_sekreto *secrets = NULL;
  char *found = NULL;
  sek_err err;

  (void)self;
  (void)nargs;

  err = chainof(args[0], &secrets);
  if (NULL != err) {
    return bad(err);
  }

  err = sek_get(secrets, field(args[0], "name"), &found);

  return NULL != err ? bad(err) : ok(omni_str(POOL, found));
}

static omni_result subject_trysecret(omni_subject *self, omni_json **args, size_t nargs) {
  sek_sekreto *secrets = NULL;
  char *found = NULL;
  sek_err err;

  (void)self;
  (void)nargs;

  err = chainof(args[0], &secrets);
  if (NULL != err) {
    return bad(err);
  }

  err = sek_try(secrets, field(args[0], "name"), &found);
  if (NULL != err) {
    return bad(err);
  }

  /* A miss is omni's own Null, which the runner rewrites to the
   * __NULL__ sentinel the spec asserts. */
  return ok(NULL == found ? omni_null(POOL) : omni_str(POOL, found));
}

static omni_result subject_sources(omni_subject *self, omni_json **args, size_t nargs) {
  sek_sekreto *secrets = NULL;
  sek_err err;

  (void)self;
  (void)nargs;

  err = chainof(args[0], &secrets);

  return NULL != err ? bad(err) : ok(textlist(sek_sources(secrets)));
}

static omni_result subject_stores(omni_subject *self, omni_json **args, size_t nargs) {
  sek_sekreto *secrets = NULL;
  sek_err err;

  (void)self;
  (void)nargs;

  err = chainof(args[0], &secrets);

  return NULL != err ? bad(err) : ok(textlist(sek_stores(secrets)));
}

static omni_result subject_getfrom(omni_subject *self, omni_json **args, size_t nargs) {
  sek_sekreto *secrets = NULL;
  char *found = NULL;
  const char *store = field(args[0], "store");
  sek_err err;

  (void)self;
  (void)nargs;

  err = chainof(args[0], &secrets);
  if (NULL != err) {
    return bad(err);
  }

  err = sek_getfrom(secrets, NULL == store ? "" : store, field(args[0], "name"), &found);

  return NULL != err ? bad(err) : ok(omni_str(POOL, found));
}

static omni_result subject_tryfrom(omni_subject *self, omni_json **args, size_t nargs) {
  sek_sekreto *secrets = NULL;
  char *found = NULL;
  const char *store = field(args[0], "store");
  sek_err err;

  (void)self;
  (void)nargs;

  err = chainof(args[0], &secrets);
  if (NULL != err) {
    return bad(err);
  }

  err = sek_tryfrom(secrets, NULL == store ? "" : store, field(args[0], "name"), &found);
  if (NULL != err) {
    return bad(err);
  }

  return ok(NULL == found ? omni_null(POOL) : omni_str(POOL, found));
}

/* Answers the ordered output map itself, which omni compares as a JSON
 * object against the spec's known-answer signatures. */
static omni_result subject_sigv4(omni_subject *self, omni_json **args, size_t nargs) {
  omni_json *entry = args[0];
  omni_json *headers = omni_map_get(entry, "headers");
  sek_signing input;
  sek_map *signed_;

  (void)self;
  (void)nargs;

  memset(&input, 0, sizeof(input));
  input.method = field(entry, "method");
  input.url = field(entry, "url");
  input.service = field(entry, "service");
  input.region = field(entry, "region");
  input.keyid = field(entry, "keyid");
  input.secret = field(entry, "secret");
  input.datetime = field(entry, "datetime");
  input.body = field(entry, "body");
  input.session = field(entry, "session");

  if (omni_ismap(headers)) {
    size_t index;
    input.headers = sek_map_new(SEK);
    for (index = 0; index < headers->maplen; index++) {
      sek_map_set(input.headers, headers->keys[index],
                  omni_stringify(POOL, headers->vals[index]));
    }
  }

  signed_ = sek_sigv4(SEK, &input);

  return ok(textmap(signed_));
}

static omni_result subject_redact(omni_subject *self, omni_json **args, size_t nargs) {
  omni_json *values = omni_map_get(args[0], "values");
  sek_list *use = sek_list_new(SEK);

  (void)self;
  (void)nargs;

  if (omni_islist(values)) {
    size_t index;
    for (index = 0; index < values->listlen; index++) {
      const char *text = plainstr(values->list[index]);
      if (NULL != text) {
        sek_list_add(use, text);
      }
    }
  }

  return ok(omni_str(POOL, sek_redact(SEK, field(args[0], "text"), use)));
}

/* ---- the runner ---------------------------------------------------- */

static omni_subject *makesubject(omni_result (*call)(omni_subject *, omni_json **, size_t)) {
  omni_subject *subject = (omni_subject *)omni_pool_alloc(POOL, sizeof(omni_subject));
  subject->call = call;
  subject->data = NULL;
  return subject;
}

static void report(const char *name, int failed, const char *message) {
  if (failed) {
    FAILCOUNT++;
    printf("FAIL - %s\n%s\n", name, NULL == message ? "" : message);
  } else {
    PASSCOUNT++;
    printf("ok   - %s\n", name);
  }
}

/* Find the shared spec directory by walking up from the working dir. */
static char *specfile(const char *name) {
  static char path[4200];
  char dir[4096];
  int step;

  if (NULL == getcwd(dir, sizeof(dir))) {
    return NULL;
  }

  for (step = 0; step < 8; step++) {
    FILE *probe;
    snprintf(path, sizeof(path), "%s/spec/%s", dir, name);
    probe = fopen(path, "rb");
    if (NULL != probe) {
      fclose(probe);
      return path;
    }

    {
      char *slash = strrchr(dir, '/');
      if (NULL == slash || dir == slash) {
        break;
      }
      *slash = '\0';
    }
  }

  return NULL;
}

static void rungroup(omni_runpack *pack, const char *name,
                     omni_result (*call)(omni_subject *, omni_json **, size_t),
                     omni_flags flags) {
  char *err = NULL;
  int failed;

  if (NULL != ONLY && 0 != strcmp(ONLY, name)) {
    return;
  }

  failed = omni_runsetflags(pack, omni_set(pack, name), flags, makesubject(call), &err);
  report(name, failed, err);
}

int main(int argc, char **argv) {
  char *path;
  char *err = NULL;
  omni_runner *runner;
  omni_runpack *pack;

  POOL = omni_pool_new();
  SEK = sek_pool_new();

  if (1 < argc) {
    ONLY = argv[1];
  }

  path = specfile("sekreto.json");
  if (NULL == path) {
    printf("sekreto: spec not found: sekreto.json\n");
    return 1;
  }

  /* No DEF section in this spec, so there are no clients and no provider
   * hooks: a null provider is what every port passes. */
  runner = omni_make_runner(POOL, path, NULL, NULL, &err);
  if (NULL == runner) {
    printf("%s\n", err);
    return 1;
  }

  pack = omni_runner_run(runner, "sekreto", NULL, &err);
  if (NULL == pack) {
    printf("%s\n", err);
    return 1;
  }

  /* `validname` is the only group with real JSON nulls among its inputs,
   * so it is the only one run with nonull. */
  rungroup(pack, "validname", subject_validname, omni_flags_nonull());
  rungroup(pack, "envkey", subject_envkey, omni_flags_default());
  rungroup(pack, "vaultref", subject_vaultref, omni_flags_default());
  rungroup(pack, "flatname", subject_flatname, omni_flags_default());
  rungroup(pack, "awsparam", subject_awsparam, omni_flags_default());
  rungroup(pack, "parsedotenv", subject_parsedotenv, omni_flags_default());
  rungroup(pack, "resolve", subject_resolve, omni_flags_default());
  rungroup(pack, "trysecret", subject_trysecret, omni_flags_default());
  rungroup(pack, "sources", subject_sources, omni_flags_default());
  rungroup(pack, "stores", subject_stores, omni_flags_default());
  rungroup(pack, "getfrom", subject_getfrom, omni_flags_default());
  rungroup(pack, "tryfrom", subject_tryfrom, omni_flags_default());
  rungroup(pack, "sigv4", subject_sigv4, omni_flags_default());
  rungroup(pack, "redact", subject_redact, omni_flags_default());

  printf("\n%d passed, %d failed\n", PASSCOUNT, FAILCOUNT);

  omni_pool_free(POOL);
  sek_pool_free(SEK);

  return 0 == FAILCOUNT ? 0 : 1;
}
