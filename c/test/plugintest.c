/* RUN: make seam
 * RUN-ONE: ./build/sekretoseam unknownkind
 *
 * THE PLUGIN SEAM, from both sides.
 *
 * Moving the provider kinds that open sockets and spawn processes out of
 * the core made a consumer's PLUGIN LIST load-bearing: a kind nobody
 * passed in is not in the catalog, and a chain naming it is refused. That
 * is the intended behaviour, and it means a consumer can be broken
 * without a single conformance check noticing - the conformance suite
 * hands every plugin to every chain it builds, so it can never see a
 * missing one. So the full set is pinned here: it holds every kind, every
 * kind builds, and the CLI passes it.
 *
 * The conformance suite CAN see a kind missing from the full set, because
 * `sources` and `stores` name all ten. The seam test for that is still
 * worth keeping - it fails faster and names the kind - but it is not
 * covering a blind spot. What the suite genuinely cannot see is the
 * CONSUMER's list: a CLI passing one plugin instead of ten leaves all
 * fourteen groups green and fails nine integration checks.
 *
 * The three cases at the foot read the BUILD, not the source: which
 * symbols the core archive needs from outside itself, and which each
 * plugin object needs. `make check-core` does the same read at link
 * level, with the negative controls; these are here so that a regression
 * fails the suite and not only that target.
 */

#define _POSIX_C_SOURCE 200809L

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* internal.h for the string helpers and the local-file read the two
 * source pins use. A test may reach for those; nothing shipped does. */
#include "internal.h"
#include "sekreto.h"
#include "sekretoplugins.h"

static sek_pool *POOL = NULL;
static const char *ONLY = NULL;
static int PASSCOUNT = 0;
static int FAILCOUNT = 0;
static const char *WHY = NULL;

/* ---- the harness --------------------------------------------------- */

/* A check answers a message on failure and NULL on success, so a case is
 * a function that returns the first thing that went wrong. No framework:
 * the conformance runner next door does the same. */
typedef const char *(*checkfn)(void);

static const char *same(const char *want, const char *got, const char *what) {
  if (NULL == got) {
    got = "(null)";
  }
  if (0 == strcmp(want, got)) {
    return NULL;
  }
  return sek_fmt(POOL, "%s: want %s, got %s", what, want, got);
}

static const char *truth(int held, const char *what) {
  return held ? NULL : sek_fmt(POOL, "%s", what);
}

/* A list of strings as one space-separated line, which is how every
 * comparison below reads. */
static const char *line(sek_list *list) {
  sek_buf out;
  size_t index;

  sek_buf_init(&out, POOL);
  for (index = 0; index < list->len; index++) {
    if (0 < index) {
      sek_buf_addch(&out, ' ');
    }
    sek_buf_add(&out, list->items[index]);
  }

  return out.data;
}

/* A plugin Value list of strings, the same way. */
static const char *vline(Value *list) {
  sek_buf out;
  size_t index;

  sek_buf_init(&out, POOL);
  for (index = 0; index < vlen(list); index++) {
    if (0 < index) {
      sek_buf_addch(&out, ' ');
    }
    sek_buf_add(&out, vasstr(vat(list, index)));
  }

  return out.data;
}

/* The host's instance list as `ref=status`, in sorted ref order - which is
 * the order host_list answers in. */
static const char *hostline(sek_sekreto *sek) {
  Value *list = host_list(sek_host(sek));
  const char **keys;
  size_t count = vkeys(list, &keys);
  sek_buf out;
  size_t index;

  sek_buf_init(&out, POOL);
  for (index = 0; index < count; index++) {
    if (0 < index) {
      sek_buf_addch(&out, ' ');
    }
    sek_buf_addfmt(&out, "%s=%s", keys[index], vasstr(vget(list, keys[index])));
  }

  return out.data;
}

/* ---- helpers ------------------------------------------------------- */

static sek_options *options(void) {
  sek_options *opts = (sek_options *)sek_alloc(POOL, sizeof(sek_options));
  memset(opts, 0, sizeof(*opts));
  opts->nocache = 1;
  return opts;
}

static sek_map *values1(const char *key, const char *value) {
  sek_map *out = sek_map_new(POOL);
  sek_map_set(out, key, value);
  return out;
}

/* The refusal a construction answers, or "" when it did not refuse. */
static const char *refusal(sek_options *opts) {
  sek_sekreto *secrets = NULL;
  sek_err err = sek_new(POOL, opts, &secrets);

  return NULL == err ? "" : err;
}

/* ---- the full set -------------------------------------------------- */

static const char *KINDS =
    "hashicorp boru awssecrets awsparams gcpsecrets azuresecrets onepassword "
    "doppler infisical secretspec";

static const char *EVERY =
    "awsparams awssecrets azuresecrets boru doppler dotenv env file gcpsecrets "
    "hashicorp infisical memory onepassword secretspec";

static const char *thefullsetholdseverykind(void) {
  Definition **all;
  size_t count = sek_allplugins(&all);
  Definition **builtins;
  size_t builtincount = sek_builtins(&builtins);
  sek_buf names;
  sek_buf shipped;
  size_t index;

  sek_buf_init(&names, POOL);
  for (index = 0; index < count; index++) {
    if (0 < index) {
      sek_buf_addch(&names, ' ');
    }
    sek_buf_add(&names, all[index]->name);
  }

  sek_buf_init(&shipped, POOL);
  for (index = 0; NULL != SEK_PLUGIN_KINDS[index]; index++) {
    if (0 < index) {
      sek_buf_addch(&shipped, ' ');
    }
    sek_buf_add(&shipped, SEK_PLUGIN_KINDS[index]);
  }

  WHY = same(KINDS, names.data, "sek_allplugins");
  if (NULL != WHY) {
    return WHY;
  }

  WHY = same(KINDS, shipped.data, "SEK_PLUGIN_KINDS");
  if (NULL != WHY) {
    return WHY;
  }

  /* ...and the four built-ins, in the order a catalog takes them. */
  sek_buf_init(&names, POOL);
  for (index = 0; index < builtincount; index++) {
    if (0 < index) {
      sek_buf_addch(&names, ' ');
    }
    sek_buf_add(&names, builtins[index]->name);
  }

  sek_buf_init(&shipped, POOL);
  for (index = 0; NULL != SEK_BUILTIN_KINDS[index]; index++) {
    if (0 < index) {
      sek_buf_addch(&shipped, ' ');
    }
    sek_buf_add(&shipped, SEK_BUILTIN_KINDS[index]);
  }

  WHY = same("env memory dotenv file", names.data, "sek_builtins");
  if (NULL != WHY) {
    return WHY;
  }

  return same("env memory dotenv file", shipped.data, "SEK_BUILTIN_KINDS");
}

/* Naming a kind is not enough: a kind can be in the catalog and still
 * fail to build. Construction is what the CLI does before any network. */
static const char *everykindbuildsfromaspec(void) {
  static const char *const ALL[] = {
      "awsparams", "awssecrets", "azuresecrets", "boru",     "doppler",
      "dotenv",    "env",        "file",         "gcpsecrets", "hashicorp",
      "infisical", "memory",     "onepassword",  "secretspec", NULL};

  sek_options *opts = options();
  sek_spec *chain = (sek_spec *)sek_alloc(POOL, 14 * sizeof(sek_spec));
  sek_sekreto *secrets = NULL;
  sek_err err;
  size_t index;

  for (index = 0; NULL != ALL[index]; index++) {
    chain[index] = sek_spec_new(ALL[index]);
    chain[index].addr = "http://127.0.0.1:8200";
    chain[index].token = "t";
    chain[index].dir = "/tmp";
    chain[index].file = "/tmp/.env";
    chain[index].values = sek_map_new(POOL);
  }

  opts->providers = chain;
  opts->count = 14;
  opts->plugincount = sek_allplugins(&opts->plugins);

  err = sek_new(POOL, opts, &secrets);
  if (NULL != err) {
    return err;
  }

  WHY = same(EVERY, line(sek_stores(secrets)), "stores");
  if (NULL != WHY) {
    return WHY;
  }

  {
    Value *list = host_list(sek_host(secrets));
    const char **refs;
    size_t count = vkeys(list, &refs);

    if (14 != count) {
      return sek_fmt(POOL, "host holds %d instances", (int)count);
    }

    for (index = 0; index < count; index++) {
      if (0 != strcmp("live", vasstr(vget(list, refs[index])))) {
        return sek_fmt(POOL, "%s is %s", refs[index], vasstr(vget(list, refs[index])));
      }
    }
  }

  return same(EVERY, vline(catalog_names(sek_catalog(secrets))), "catalog");
}

/* ---- what the conformance suite cannot see ------------------------- */

/* The whole of a file, for the two source pins below. */
static const char *slurp(const char *path) {
  int why = 0;
  char *text = sek_readfile(POOL, path, &why);

  return NULL == text ? "" : text;
}

static size_t occurrences(const char *hay, const char *needle) {
  size_t count = 0;
  const char *at = hay;

  for (;;) {
    const char *found = strstr(at, needle);
    if (NULL == found) {
      return count;
    }
    count++;
    at = found + strlen(needle);
  }
}

/* THE ONE THE SUITE IS BLIND TO. A CLI that passed one plugin instead of
 * ten would leave all fourteen conformance groups green and fail nine
 * integration checks, so the call site is pinned here - and pinned so
 * that a PREFIX does not satisfy it. The closing bracket and the
 * semicolon are part of the match, because `sek_allplugins(&p)` is a
 * prefix of a line that then throws nine of them away, and the count
 * pins are what stop a second assignment putting the number back to one. */
static const char *theclipassesthefullset(void) {
  const char *src = slurp("cli/cli.c");

  WHY = truth(NULL != strstr(src, "#include \"sekretoplugins.h\""),
              "the CLI does not include the plugins header");
  if (NULL != WHY) {
    return WHY;
  }

  WHY = truth(NULL != strstr(src, "\n  options.plugincount = sek_allplugins(&options.plugins);\n"),
              "the CLI does not pass the full set");
  if (NULL != WHY) {
    return WHY;
  }

  WHY = truth(1 == occurrences(src, "options.plugincount"),
              "the CLI assigns plugincount more than once");
  if (NULL != WHY) {
    return WHY;
  }

  return truth(1 == occurrences(src, "options.plugins"),
               "the CLI assigns options.plugins more than once");
}

/* A chain of built-ins works with NO plugin loaded at all, which is the
 * property the whole split exists to give a consumer. */
static const char *builtinsneednoplugin(void) {
  sek_options *opts = options();
  sek_spec chain[4];
  sek_sekreto *secrets = NULL;
  char *found = NULL;
  sek_err err;

  chain[0] = sek_spec_new("memory");
  chain[0].values = values1("API_TOKEN", "tok01");
  chain[1] = sek_spec_new("env");
  chain[2] = sek_spec_new("dotenv");
  chain[2].file = "/nonexistent-sekreto-test/.env";
  chain[3] = sek_spec_new("file");
  chain[3].dir = "/nonexistent-sekreto-test";

  opts->providers = chain;
  opts->count = 4;

  err = sek_new(POOL, opts, &secrets);
  if (NULL != err) {
    return err;
  }

  err = sek_get(secrets, "api.token", &found);
  if (NULL != err) {
    return err;
  }

  WHY = same("tok01", found, "get");
  if (NULL != WHY) {
    return WHY;
  }

  WHY = same("memory env dotenv file", line(sek_stores(secrets)), "stores");
  if (NULL != WHY) {
    return WHY;
  }

  WHY = same("dotenv env file memory", vline(catalog_names(sek_catalog(secrets))), "catalog");
  if (NULL != WHY) {
    return WHY;
  }

  return same("dotenv=live env=live file=live memory=live", hostline(secrets), "host");
}

static const char *onepluginisenough(void) {
  sek_options *opts = options();
  sek_spec chain[2];
  Definition *plugins[1];
  sek_sekreto *secrets = NULL;
  char *found = NULL;
  sek_err err;

  chain[0] = sek_spec_new("memory");
  chain[0].values = values1("API_TOKEN", "tok01");
  chain[1] = sek_spec_new("hashicorp");
  chain[1].name = "prod";
  chain[1].addr = "https://vault.example.com";
  chain[1].token = "t";

  plugins[0] = sek_plugin_hashicorp();

  opts->providers = chain;
  opts->count = 2;
  opts->plugins = plugins;
  opts->plugincount = 1;

  err = sek_new(POOL, opts, &secrets);
  if (NULL != err) {
    return err;
  }

  WHY = same("memory prod", line(sek_stores(secrets)), "stores");
  if (NULL != WHY) {
    return WHY;
  }

  WHY = same("memory hashicorp:https://vault.example.com/secret", line(sek_sources(secrets)),
             "sources");
  if (NULL != WHY) {
    return WHY;
  }

  err = sek_get(secrets, "api.token", &found);
  if (NULL != err) {
    return err;
  }

  WHY = same("tok01", found, "get");
  if (NULL != WHY) {
    return WHY;
  }

  /* The plugin host is what the chain is made of, and it reads like the
   * chain: the kind, or kind$store for a named store. */
  WHY = same("hashicorp$prod=live memory=live", hostline(secrets), "host");
  if (NULL != WHY) {
    return WHY;
  }

  return same("dotenv env file hashicorp memory", vline(catalog_names(sek_catalog(secrets))),
              "catalog");
}

static const char *akindthatwasnotpassedin(void) {
  sek_options *opts = options();
  sek_spec chain[1];
  Definition *plugins[1];

  chain[0] = sek_spec_new("doppler");
  chain[0].token = "t";
  plugins[0] = sek_plugin_hashicorp();

  opts->providers = chain;
  opts->count = 1;
  opts->plugins = plugins;
  opts->plugincount = 1;

  WHY = same("sekreto: unknown provider kind: doppler"
             " (available: dotenv, env, file, hashicorp, memory)"
             " - doppler is a sekreto plugin, not built in: pass it in the plugins option",
             refusal(opts), "the refusal");
  if (NULL != WHY) {
    return WHY;
  }

  /* A kind nobody ships is a typo, and gets no such hint. */
  opts = options();
  chain[0] = sek_spec_new("vualt");
  opts->providers = chain;
  opts->count = 1;

  return same("sekreto: unknown provider kind: vualt (available: dotenv, env, file, memory)",
              refusal(opts), "a typo");
}

/* Two providers MAY share a store name - a directed read walks both, and
 * the spec pins it - but an instance ref may not, so the second gets a
 * numbered tag from the host and keeps its store name. */
static const char *arepeatedstorename(void) {
  sek_options *opts = options();
  sek_spec chain[4];
  sek_sekreto *secrets = NULL;
  char *found = NULL;
  sek_err err;

  chain[0] = sek_spec_new("memory");
  chain[0].values = sek_map_new(POOL);
  chain[1] = sek_spec_new("memory");
  chain[1].values = values1("API_TOKEN", "second");
  chain[2] = sek_spec_new("memory");
  chain[2].name = "pair";
  chain[2].values = sek_map_new(POOL);
  chain[3] = sek_spec_new("memory");
  chain[3].name = "pair";
  chain[3].values = values1("API_TOKEN", "pair2");

  opts->providers = chain;
  opts->count = 4;

  err = sek_new(POOL, opts, &secrets);
  if (NULL != err) {
    return err;
  }

  WHY = same("memory pair", line(sek_stores(secrets)), "stores");
  if (NULL != WHY) {
    return WHY;
  }

  WHY = same("memory=live memory$1=live memory$2=live memory$pair=live", hostline(secrets),
             "host");
  if (NULL != WHY) {
    return WHY;
  }

  err = sek_getfrom(secrets, "memory", "api.token", &found);
  if (NULL != err) {
    return err;
  }
  WHY = same("second", found, "memory");
  if (NULL != WHY) {
    return WHY;
  }

  err = sek_getfrom(secrets, "pair", "api.token", &found);
  if (NULL != err) {
    return err;
  }

  return same("pair2", found, "pair");
}

static const char *astorenamemustbeatag(void) {
  sek_options *opts = options();
  sek_spec chain[1];

  chain[0] = sek_spec_new("memory");
  chain[0].name = "my store";
  chain[0].values = sek_map_new(POOL);

  opts->providers = chain;
  opts->count = 1;

  return same("sekreto: invalid store name: my store", refusal(opts), "the refusal");
}

/* A provider that refuses its own configuration answers a sek_err from
 * inside the plugin's `define`. The spec pins that message byte for byte,
 * so it must come back out of the host as itself - not wrapped as
 * plugin_define_failed, and not as a plugin error. */
static const char *asekretoerrorcomesbackout(void) {
  sek_options *opts = options();
  sek_spec chain[1];
  Definition *plugins[1];

  chain[0] = sek_spec_new("hashicorp");
  chain[0].addr = "http://127.0.0.1:1";
  chain[0].token = "t";
  chain[0].kv = 3;
  chain[0].haskv = 1;
  plugins[0] = sek_plugin_hashicorp();

  opts->providers = chain;
  opts->count = 1;
  opts->plugins = plugins;
  opts->plugincount = 1;

  return same("sekreto: hashicorp: unsupported kv version: 3", refusal(opts), "the refusal");
}

/* ...and any other error is not sekreto's to rewrite: it surfaces as the
 * host reports it, naming the instance and the cause.
 *
 * sek_providerplugin cannot produce one - a `make` answers a sek_err and
 * nothing else - so the case is reachable only for a definition written
 * by hand, which is exactly the definition sekreto did not write.
 * `plugin_bare` is voxgig/plugin's C port's spelling of "an error with no
 * code of its own", which is the one the host wraps. */
static void boom_define(Inst *inst) {
  (void)inst;
  fail("plugin_bare", "boom", NULL);
}

static Definition BROKEN = {"broken", NULL, boom_define, NULL, NULL, NULL, NULL};

static const char *anyothererroristhehostsreport(void) {
  sek_options *opts = options();
  sek_spec chain[1];
  Definition *plugins[1];
  const char *got;

  chain[0] = sek_spec_new("broken");
  plugins[0] = &BROKEN;

  opts->providers = chain;
  opts->count = 1;
  opts->plugins = plugins;
  opts->plugincount = 1;

  got = refusal(opts);

  WHY = truth(NULL != strstr(got, "plugin_define_failed"),
              sek_fmt(POOL, "not the host's report: %s", got));
  if (NULL != WHY) {
    return WHY;
  }

  return truth(NULL != strstr(got, "boom"), sek_fmt(POOL, "the cause is not in %s", got));
}

/* A definition that is not a provider plugin at all - it loads, it
 * activates, it exports nothing - is refused by name. Python's twin of
 * this test passes a MODULE where a definition belongs; C has no modules,
 * and what remains checkable is a definition that is not one of ours. */
static Definition HOLLOW = {"hollow", NULL, NULL, NULL, NULL, NULL, NULL};

static const char *adefinitionthatisnotaproviderplugin(void) {
  sek_options *opts = options();
  sek_spec chain[1];
  Definition *plugins[1];

  chain[0] = sek_spec_new("hollow");
  plugins[0] = &HOLLOW;

  opts->providers = chain;
  opts->count = 1;
  opts->plugins = plugins;
  opts->plugincount = 1;

  return same("sekreto: plugin hollow exported no provider", refusal(opts), "the refusal");
}

/* A custom kind is one sek_providerplugin call. */
typedef struct {
  sek_pool *pool;
  sek_map *values;
} shoutydata;

static sek_err shouty_lookup(sek_provider *self, const char *name, char **out) {
  shoutydata *data = (shoutydata *)self->data;
  sek_buf key;
  size_t index;
  const char *found;

  *out = NULL;

  sek_buf_init(&key, data->pool);
  for (index = 0; '\0' != name[index]; index++) {
    sek_buf_addch(&key, sek_upper(name[index]));
  }

  found = sek_map_get(data->values, key.data);
  if (NULL != found) {
    *out = sek_strdup(data->pool, found);
  }

  return NULL;
}

static const char *shouty_describe(sek_provider *self) {
  (void)self;
  return "shouty";
}

static sek_err shouty_make(sek_pool *pool, const sek_spec *spec, sek_provider **out) {
  shoutydata *data;

  if (NULL == spec->values) {
    return sek_strdup(pool, "sekreto: shouty: no values");
  }

  data = (shoutydata *)sek_alloc(pool, sizeof(shoutydata));
  data->pool = pool;
  data->values = spec->values;

  *out = sek_provider_new(pool, shouty_lookup, shouty_describe, data);

  return NULL;
}

static sek_providerkind SHOUTY;

static const char *acustomkindisonecall(void) {
  sek_options *opts = options();
  sek_spec chain[1];
  Definition *plugins[1];
  sek_sekreto *secrets = NULL;
  char *found = NULL;
  sek_err err;

  plugins[0] = sek_providerplugin(&SHOUTY, "shouty", shouty_make);

  chain[0] = sek_spec_new("shouty");
  chain[0].values = values1("API.TOKEN", "loud");

  opts->providers = chain;
  opts->count = 1;
  opts->plugins = plugins;
  opts->plugincount = 1;

  err = sek_new(POOL, opts, &secrets);
  if (NULL != err) {
    return err;
  }

  err = sek_get(secrets, "api.token", &found);
  if (NULL != err) {
    return err;
  }

  WHY = same("loud", found, "get");
  if (NULL != WHY) {
    return WHY;
  }

  WHY = same("shouty=live", hostline(secrets), "host");
  if (NULL != WHY) {
    return WHY;
  }

  /* ...and a custom kind that refuses its own configuration comes back
   * out as itself, exactly as a shipped one does. */
  opts = options();
  chain[0] = sek_spec_new("shouty");
  opts->providers = chain;
  opts->count = 1;
  opts->plugins = plugins;
  opts->plugincount = 1;

  return same("sekreto: shouty: no values", refusal(opts), "the refusal");
}

/* A plugin that names a built-in kind replaces it: that is how a host
 * substitutes an implementation, and never an accident, because the four
 * names are documented. */
static sek_err replaced_lookup(sek_provider *self, const char *name, char **out) {
  (void)name;
  *out = sek_strdup(self->pool, "replaced");
  return NULL;
}

static const char *replaced_describe(sek_provider *self) {
  (void)self;
  return "memory";
}

static sek_err replaced_make(sek_pool *pool, const sek_spec *spec, sek_provider **out) {
  (void)spec;
  *out = sek_provider_new(pool, replaced_lookup, replaced_describe, NULL);
  return NULL;
}

static sek_providerkind REPLACED;

static const char *apluginmayreplaceabuiltin(void) {
  sek_options *opts = options();
  sek_spec chain[1];
  Definition *plugins[1];
  sek_sekreto *secrets = NULL;
  char *found = NULL;
  sek_err err;

  plugins[0] = sek_providerplugin(&REPLACED, "memory", replaced_make);

  chain[0] = sek_spec_new("memory");
  chain[0].values = values1("API_TOKEN", "original");

  opts->providers = chain;
  opts->count = 1;
  opts->plugins = plugins;
  opts->plugincount = 1;

  err = sek_new(POOL, opts, &secrets);
  if (NULL != err) {
    return err;
  }

  err = sek_get(secrets, "api.token", &found);
  if (NULL != err) {
    return err;
  }

  WHY = same("replaced", found, "get");
  if (NULL != WHY) {
    return WHY;
  }

  /* Still four kinds: it replaced one, it did not add one. */
  return same("dotenv env file memory", vline(catalog_names(sek_catalog(secrets))), "catalog");
}

/* A provider already built joins the chain as it is, under its own store
 * name, backed by no instance. */
static const char *aliveproviderjoinsthechain(void) {
  sek_options *opts = options();
  sek_spec chain[2];
  shoutydata *data = (shoutydata *)sek_alloc(POOL, sizeof(shoutydata));
  sek_sekreto *secrets = NULL;
  char *found = NULL;
  sek_err err;

  data->pool = POOL;
  data->values = values1("API.TOKEN", "loud");

  chain[0] = sek_spec_new(NULL);
  chain[0].provider = sek_provider_new(POOL, shouty_lookup, shouty_describe, data);
  chain[1] = sek_spec_new(NULL);
  chain[1].name = "quiet";
  chain[1].provider = sek_provider_new(POOL, shouty_lookup, shouty_describe, data);

  opts->providers = chain;
  opts->count = 2;

  err = sek_new(POOL, opts, &secrets);
  if (NULL != err) {
    return err;
  }

  WHY = same("shouty quiet", line(sek_stores(secrets)), "stores");
  if (NULL != WHY) {
    return WHY;
  }

  WHY = same("", hostline(secrets), "host");
  if (NULL != WHY) {
    return WHY;
  }

  err = sek_get(secrets, "api.token", &found);
  if (NULL != err) {
    return err;
  }

  return same("loud", found, "get");
}

static const char *closetearsthechaindown(void) {
  sek_options *opts = options();
  sek_spec chain[1];
  sek_sekreto *secrets = NULL;
  char *found = NULL;
  sek_err err;

  chain[0] = sek_spec_new("memory");
  chain[0].values = values1("API_TOKEN", "tok01");

  opts->providers = chain;
  opts->count = 1;

  err = sek_new(POOL, opts, &secrets);
  if (NULL != err) {
    return err;
  }

  err = sek_get(secrets, "api.token", &found);
  if (NULL != err) {
    return err;
  }

  err = sek_close(secrets);
  if (NULL != err) {
    return err;
  }

  WHY = same("", hostline(secrets), "host");
  if (NULL != WHY) {
    return WHY;
  }

  WHY = same("", line(sek_stores(secrets)), "stores");
  if (NULL != WHY) {
    return WHY;
  }

  err = sek_try(secrets, "api.token", &found);
  if (NULL != err) {
    return err;
  }

  WHY = truth(NULL == found, "still resolving after close");
  if (NULL != WHY) {
    return WHY;
  }

  return same("token=[redacted]", sek_redact_text(secrets, "token=tok01"), "redaction");
}

/* Every field of a spec survives the trip out to an instance's options
 * and back into the `define` that reads it. Thirty-one strings, a map, a
 * number and a nested map, and the conformance suite exercises eight of
 * them: a field written but never read is a store configured with a value
 * it never sees. */
static sek_spec ROUNDTRIP;
static const char *SEEN = NULL;

static sek_err echo_make(sek_pool *pool, const sek_spec *spec, sek_provider **out) {
  sek_buf got;
  sek_authspec *auth = spec->auth;

  (void)out;

  sek_buf_init(&got, pool);
  sek_buf_addfmt(&got, "%s|%s|%s|%s|%s|%s|%s|%s|%d", sek_orempty(spec->kind),
                 sek_orempty(spec->prefix), sek_orempty(spec->file), sek_orempty(spec->dir),
                 sek_orempty(spec->addr), sek_orempty(spec->token), sek_orempty(spec->mount),
                 sek_orempty(spec->vaultnamespace), spec->haskv ? spec->kv : -1);
  sek_buf_addfmt(&got, "|%s|%s|%s|%s|%s|%s", sek_orempty(spec->command),
                 sek_orempty(spec->profile), sek_orempty(spec->backend), sek_orempty(spec->reason),
                 sek_orempty(spec->namespace_), sek_orempty(spec->home));
  sek_buf_addfmt(&got, "|%s|%s|%s|%s", sek_orempty(spec->region), sek_orempty(spec->keyid),
                 sek_orempty(spec->secret), sek_orempty(spec->session));
  sek_buf_addfmt(&got, "|%s|%s|%s|%s|%s", sek_orempty(spec->project), sek_orempty(spec->vault),
                 sek_orempty(spec->tenant), sek_orempty(spec->clientid),
                 sek_orempty(spec->clientsecret));
  sek_buf_addfmt(&got, "|%s|%s|%s|%s", sek_orempty(spec->loginaddr), sek_orempty(spec->imdsaddr),
                 sek_orempty(spec->metadataaddr), sek_orempty(spec->apiversion));
  sek_buf_addfmt(&got, "|%s|%s|%s", sek_orempty(spec->config), sek_orempty(spec->environment),
                 sek_orempty(spec->path));
  sek_buf_addfmt(&got, "|%s", NULL == spec->values ? "-" : sek_map_get(spec->values, "K"));
  sek_buf_addfmt(&got, "|%s|%s|%s|%s|%s|%s|%s", NULL == auth ? "-" : sek_orempty(auth->method),
                 NULL == auth ? "-" : sek_orempty(auth->mount),
                 NULL == auth ? "-" : sek_orempty(auth->role),
                 NULL == auth ? "-" : sek_orempty(auth->jwt),
                 NULL == auth ? "-" : sek_orempty(auth->jwtfile),
                 NULL == auth ? "-" : sek_orempty(auth->roleid),
                 NULL == auth ? "-" : sek_orempty(auth->secretid));

  SEEN = sek_strdup(pool, got.data);

  return sek_strdup(pool, "echoed");
}

static sek_providerkind ECHO;

static const char *everyspecfieldsurvives(void) {
  sek_options *opts = options();
  sek_authspec auth;
  Definition *plugins[1];

  memset(&auth, 0, sizeof(auth));
  auth.method = "kubernetes";
  auth.mount = "authmount";
  auth.role = "therole";
  auth.jwt = "thejwt";
  auth.jwtfile = "thejwtfile";
  auth.roleid = "theroleid";
  auth.secretid = "thesecretid";

  ROUNDTRIP = sek_spec_new("echo");
  ROUNDTRIP.prefix = "PRE_";
  ROUNDTRIP.file = "afile";
  ROUNDTRIP.dir = "adir";
  ROUNDTRIP.addr = "anaddr";
  ROUNDTRIP.token = "atoken";
  ROUNDTRIP.mount = "amount";
  ROUNDTRIP.vaultnamespace = "ans";
  ROUNDTRIP.kv = 1;
  ROUNDTRIP.haskv = 1;
  ROUNDTRIP.command = "acommand";
  ROUNDTRIP.profile = "aprofile";
  ROUNDTRIP.backend = "abackend";
  ROUNDTRIP.reason = "areason";
  ROUNDTRIP.namespace_ = "anamespace";
  ROUNDTRIP.home = "ahome";
  ROUNDTRIP.region = "aregion";
  ROUNDTRIP.keyid = "akeyid";
  ROUNDTRIP.secret = "asecret";
  ROUNDTRIP.session = "asession";
  ROUNDTRIP.project = "aproject";
  ROUNDTRIP.vault = "avault";
  ROUNDTRIP.tenant = "atenant";
  ROUNDTRIP.clientid = "aclientid";
  ROUNDTRIP.clientsecret = "aclientsecret";
  ROUNDTRIP.loginaddr = "aloginaddr";
  ROUNDTRIP.imdsaddr = "animdsaddr";
  ROUNDTRIP.metadataaddr = "ametadataaddr";
  ROUNDTRIP.apiversion = "anapiversion";
  ROUNDTRIP.config = "aconfig";
  ROUNDTRIP.environment = "anenvironment";
  ROUNDTRIP.path = "apath";
  ROUNDTRIP.values = values1("K", "V");
  ROUNDTRIP.auth = &auth;

  plugins[0] = sek_providerplugin(&ECHO, "echo", echo_make);

  opts->providers = &ROUNDTRIP;
  opts->count = 1;
  opts->plugins = plugins;
  opts->plugincount = 1;

  SEEN = NULL;
  WHY = same("echoed", refusal(opts), "the echo");
  if (NULL != WHY) {
    return WHY;
  }

  return same("echo|PRE_|afile|adir|anaddr|atoken|amount|ans|1"
              "|acommand|aprofile|abackend|areason|anamespace|ahome"
              "|aregion|akeyid|asecret|asession"
              "|aproject|avault|atenant|aclientid|aclientsecret"
              "|aloginaddr|animdsaddr|ametadataaddr|anapiversion"
              "|aconfig|anenvironment|apath"
              "|V"
              "|kubernetes|authmount|therole|thejwt|thejwtfile|theroleid|thesecretid",
              SEEN, "the round trip");
}

/* ---- what the build says ------------------------------------------- */

/* The undefined symbols of an archive or an object, one exact name per
 * line, with the `file.o:` header lines `nm -u` prints for an archive
 * dropped. */
static const char *needs(const char *path) {
  FILE *pipe = popen(sek_fmt(POOL, "nm -u %s 2>/dev/null | sed -n 's/^ *U //p' | sort -u", path),
                     "r");
  sek_buf out;
  char chunk[512];

  if (NULL == pipe) {
    return "";
  }

  sek_buf_init(&out, POOL);
  sek_buf_addch(&out, '\n');
  while (NULL != fgets(chunk, (int)sizeof(chunk), pipe)) {
    sek_buf_add(&out, chunk);
  }
  pclose(pipe);

  return out.data;
}

/* An EXACT name, never a substring: `connect` is a substring of
 * `disconnect`, and a substring test on a symbol table is what let a real
 * socket hide in another port's audit. */
static int wants(const char *list, const char *name) {
  return sek_contains(list, sek_fmt(POOL, "\n%s\n", name));
}

/* THE CORE ARCHIVE NEEDS NO PLUGIN, read off the artifact rather than
 * asserted. A static archive records every symbol it needs from outside
 * itself; the core's list holds no socket, no child process, no digest
 * and nothing defined under plugins/.
 *
 * `make check-core` does the same read at LINK level, with the negative
 * controls and the per-plugin links. This is here so that a regression
 * fails the suite and not only that target. */
static const char *thecorearchiveneedsnoplugin(void) {
  static const char *const FORBIDDEN[] = {
      "socket",       "connect",      "bind",        "listen",      "accept",
      "getaddrinfo",  "poll",         "select",      "fork",        "vfork",
      "posix_spawn",  "execv",        "execve",      "execvp",      "popen",
      "system",       "waitpid",      "pipe",        "dlopen",      "dlsym",
      "SSL_new",      "SSL_connect",  "d2i_X509",    "HMAC",        "SHA256",
      "sek_http",     "sek_fetch",    "sek_fetchjson", "sek_sha256", "sek_hmac_sha256",
      "sek_sigv4",    "sek_uriescape", "sek_unbase64", "sek_runcmd", "sek_nowms",
      "sek_tls_open", "sek_allplugins", "sek_plugin_hashicorp", "sek_plugin_doppler", NULL};

  const char *core = needs("build/libsekreto.a");
  size_t index;

  /* THE CONTROL, first. The core needs libc for memory and strings, so a
   * list with none of these in it is a list that was not read - and an
   * empty intersection below would then mean nothing at all. */
  WHY = truth(wants(core, "memcpy") || wants(core, "malloc") || wants(core, "calloc") ||
                  wants(core, "free") || wants(core, "strlen"),
              "no libc name came out of nm - the symbol read has no teeth");
  if (NULL != WHY) {
    return WHY;
  }

  for (index = 0; NULL != FORBIDDEN[index]; index++) {
    if (wants(core, FORBIDDEN[index])) {
      return sek_fmt(POOL, "the core archive needs %s", FORBIDDEN[index]);
    }
  }

  /* ...and the same read of the plugins archive DOES find a socket, which
   * is what makes the half above a measurement and not a tautology. */
  return truth(wants(needs("build/libsekretoplugins.a"), "socket"),
               "the plugins archive needs no socket - the read is wrong");
}

/* ONE PLUGIN NEEDS ONLY ITSELF. A C source file has no import list to
 * read, so the object it compiles to is what says which of its neighbours
 * it reaches: hashicorp needs the transport under it and no other kind,
 * no digest and no child process. */
static const char *onepluginneedsonlyitself(void) {
  const char *hashicorp = needs("build/pobj/hashicorp.o");
  static const char *const OTHERS[] = {
      "sek_plugin_boru",     "sek_plugin_awssecrets",   "sek_plugin_awsparams",
      "sek_plugin_doppler",  "sek_plugin_gcpsecrets",   "sek_plugin_azuresecrets",
      "sek_plugin_onepassword", "sek_plugin_infisical", "sek_plugin_secretspec",
      "sek_sigv4",           "sek_sha256",              "sek_hmac_sha256",
      "sek_runcmd",          NULL};
  size_t index;

  WHY = truth(wants(hashicorp, "sek_fetchjson"),
              "the hashicorp object needs no transport - the read is wrong");
  if (NULL != WHY) {
    return WHY;
  }

  for (index = 0; NULL != OTHERS[index]; index++) {
    if (wants(hashicorp, OTHERS[index])) {
      return sek_fmt(POOL, "the hashicorp object needs %s", OTHERS[index]);
    }
  }

  /* The negative control: aws IS the kind that signs, so its object must
   * need the signer. Without this the loop above proves nothing. */
  return truth(wants(needs("build/pobj/aws.o"), "sek_sigv4"),
               "the aws object needs no signer - the read has no teeth");
}

/* THE FULL SET IS ONE OBJECT, and it is the only one that names all ten.
 * That is what makes `sek_allplugins` the fat choice and a per-kind link
 * the lean one: an object that does not reference this file pulls in no
 * plugin it did not name. */
static const char *thefullsetisoneobject(void) {
  const char *all = needs("build/pobj/all.o");
  size_t index;

  for (index = 0; NULL != SEK_PLUGIN_KINDS[index]; index++) {
    const char *symbol = sek_fmt(POOL, "sek_plugin_%s", SEK_PLUGIN_KINDS[index]);
    if (!wants(all, symbol)) {
      return sek_fmt(POOL, "all.o does not name %s", symbol);
    }
  }

  /* ...and no other plugin object names another kind's definition, which
   * the case above checked for hashicorp and this one for the rest. */
  for (index = 0; NULL != SEK_PLUGIN_KINDS[index]; index++) {
    const char *file =
        sek_fmt(POOL, "build/pobj/%s.o",
                sek_has_prefix(SEK_PLUGIN_KINDS[index], "aws") ? "aws" : SEK_PLUGIN_KINDS[index]);
    const char *object = needs(file);
    size_t other;

    for (other = 0; NULL != SEK_PLUGIN_KINDS[other]; other++) {
      const char *symbol = sek_fmt(POOL, "sek_plugin_%s", SEK_PLUGIN_KINDS[other]);
      if (wants(object, symbol)) {
        return sek_fmt(POOL, "%s names %s", file, symbol);
      }
    }
  }

  return NULL;
}

/* ---- the runner ---------------------------------------------------- */

static void runcase(const char *name, checkfn body) {
  const char *why;

  if (NULL != ONLY && 0 != strcmp(ONLY, name)) {
    return;
  }

  why = body();

  if (NULL == why) {
    PASSCOUNT++;
    printf("ok   - %s\n", name);
  } else {
    FAILCOUNT++;
    printf("FAIL - %s\n       %s\n", name, why);
  }
}

int main(int argc, char **argv) {
  POOL = sek_pool_new();

  if (1 < argc) {
    ONLY = argv[1];
  }

  runcase("fullset", thefullsetholdseverykind);
  runcase("everykind", everykindbuildsfromaspec);
  runcase("cli", theclipassesthefullset);
  runcase("builtinsalone", builtinsneednoplugin);
  runcase("oneplugin", onepluginisenough);
  runcase("unknownkind", akindthatwasnotpassedin);
  runcase("repeatedstore", arepeatedstorename);
  runcase("storename", astorenamemustbeatag);
  runcase("sekretoerror", asekretoerrorcomesbackout);
  runcase("othererror", anyothererroristhehostsreport);
  runcase("notaplugin", adefinitionthatisnotaproviderplugin);
  runcase("customkind", acustomkindisonecall);
  runcase("replacebuiltin", apluginmayreplaceabuiltin);
  runcase("liveprovider", aliveproviderjoinsthechain);
  runcase("close", closetearsthechaindown);
  runcase("specroundtrip", everyspecfieldsurvives);
  runcase("corearchive", thecorearchiveneedsnoplugin);
  runcase("oneobject", onepluginneedsonlyitself);
  runcase("fullsetobject", thefullsetisoneobject);

  printf("\n%d passed, %d failed\n", PASSCOUNT, FAILCOUNT);

  sek_pool_free(POOL);

  return 0 == FAILCOUNT ? 0 : 1;
}
