/* RUN: make vaulttest
 * RUN-ONE: ./build/minivaulttest restricted
 *
 * The mini vault, from both sides: the store a chain reads, and the
 * programmatic API a plugin definition can publish beside it.
 *
 * The vault is not in spec/sekreto.json and cannot be until every port
 * ships the kind. The spec runs against all twenty-three of them, so an
 * entry naming `minivault` would fail the ports that have no such
 * provider. What the shared corpus would have carried is here instead,
 * plus the one thing it could not carry either way: a file written by
 * this port and read by another, pinned by the vaults in test/fixture.
 *
 * A port of typescript/test/minivault.test.ts.
 */

#define _POSIX_C_SOURCE 200809L

#include <dirent.h>
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

#include "internal.h"
#include "sekreto.h"
#include "sekretoplugins.h"

#define MASTER "master-passphrase"

/* The rounds every case here uses. The library default is 210000, which
 * is the point of PBKDF2 and the wrong thing to pay per assertion. */
#define ROUNDS 1000

static sek_pool *POOL = NULL;
static const char *ONLY = NULL;
static const char *WORK = NULL;
static int PASSCOUNT = 0;
static int FAILCOUNT = 0;
static int COUNT = 0;

/* A check answers a message on failure and NULL on success, so a case is
 * a function that returns the first thing that went wrong. No framework:
 * the seam suite next door does the same. */
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

static const char *holds(const char *got, const char *want, const char *what) {
  if (NULL != got && sek_contains(got, want)) {
    return NULL;
  }
  return sek_fmt(POOL, "%s: want to contain %s, got %s", what, want, NULL == got ? "(null)" : got);
}

/* A list of strings as one space-separated line, which is how every
 * comparison below reads. */
static const char *line(sek_list *list) {
  sek_buf out;
  size_t index;

  sek_buf_init(&out, POOL);
  for (index = 0; NULL != list && index < list->len; index++) {
    if (0 < index) {
      sek_buf_addch(&out, ' ');
    }
    sek_buf_add(&out, list->items[index]);
  }

  return out.data;
}

/* ---- the vault under test ------------------------------------------ */

static const char *vaultpath(void) {
  COUNT++;
  return sek_fmt(POOL, "%s/vault%d.skmv", WORK, COUNT);
}

static sek_vaultoptions *vaultopts(const char *file, const char *key, const char *passphrase) {
  sek_vaultoptions *out = (sek_vaultoptions *)sek_alloc(POOL, sizeof(sek_vaultoptions));

  memset(out, 0, sizeof(*out));
  out->file = file;
  out->key = key;
  out->passphrase = passphrase;
  out->iterations = ROUNDS;

  return out;
}

/* A fresh vault, or NULL with `*why` set. */
static sek_minivault *fresh(const char **why) {
  sek_minivault *vault = NULL;
  *why = sek_vault_create(POOL, vaultopts(vaultpath(), NULL, MASTER), &vault);
  return vault;
}

static sek_minivault *openas(const char *file, const char *key, const char *passphrase,
                             const char **why) {
  sek_minivault *vault = NULL;
  *why = sek_vault_open(POOL, vaultopts(file, key, passphrase), &vault);
  return vault;
}

/* The message a call refused with, or "" when it did not refuse. */
static const char *refused(sek_err err) { return NULL == err ? "" : err; }

/* Where the committed vaults live, found by walking up. */
static const char *fixturedir(void) {
  const char *dir = ".";
  int step;

  for (step = 0; step < 8; step++) {
    struct stat st;
    if (0 == stat(sek_fmt(POOL, "%s/test/fixture/minivault.skmv", dir), &st)) {
      return sek_fmt(POOL, "%s/test/fixture", dir);
    }
    dir = sek_fmt(POOL, "%s/..", dir);
  }

  return NULL;
}

/* EVERY committed vault, read off disk rather than listed here. A
 * hard-coded list is one more place to edit when a port lands, and the
 * edit that gets forgotten is the one that makes this suite stop
 * checking the port that just arrived. */
static sek_list *fixtures(void) {
  sek_list *out = sek_list_new(POOL);
  const char *where = fixturedir();
  struct dirent *entry;
  DIR *dir;

  if (NULL == where) {
    return out;
  }

  dir = opendir(where);
  if (NULL == dir) {
    return out;
  }

  while (NULL != (entry = readdir(dir))) {
    size_t len = strlen(entry->d_name);
    if (5 < len && 0 == strcmp(".skmv", entry->d_name + len - 5)) {
      sek_list_add(out, entry->d_name);
    }
  }

  closedir(dir);
  sek_list_sort(out);

  return out;
}

/* A committed vault, copied so that a case which writes cannot edit the
 * bytes the format contract is made of. */
static const char *fixture(const char *name) {
  const char *mine = vaultpath();
  const char *from = sek_fmt(POOL, "%s/%s", fixturedir(), name);
  FILE *in = fopen(from, "rb");
  FILE *out = NULL;
  char chunk[4096];
  size_t got;

  if (NULL == in) {
    return NULL;
  }

  out = fopen(mine, "wb");
  if (NULL == out) {
    fclose(in);
    return NULL;
  }

  while (0 < (got = fread(chunk, 1, sizeof(chunk), in))) {
    fwrite(chunk, 1, got, out);
  }

  fclose(in);
  fclose(out);

  return mine;
}

static sek_options *chainopts(void) {
  sek_options *opts = (sek_options *)sek_alloc(POOL, sizeof(sek_options));
  Definition **plugins = (Definition **)sek_alloc(POOL, sizeof(Definition *));

  memset(opts, 0, sizeof(*opts));
  plugins[0] = sek_plugin_minivault();
  opts->plugins = plugins;
  opts->plugincount = 1;
  opts->nocache = 1;

  return opts;
}

static sek_spec *chain2(sek_spec first, sek_spec second) {
  sek_spec *out = (sek_spec *)sek_alloc(POOL, 2 * sizeof(sek_spec));
  out[0] = first;
  out[1] = second;
  return out;
}

static sek_spec vaultspec(const char *file, const char *key, const char *passphrase) {
  sek_spec spec = sek_spec_new("minivault");
  spec.file = file;
  spec.vaultkey = key;
  spec.passphrase = passphrase;
  return spec;
}

static sek_spec memoryspec(const char *key, const char *value) {
  sek_spec spec = sek_spec_new("memory");
  spec.values = sek_map_new(POOL);
  sek_map_set(spec.values, key, value);
  return spec;
}

/* The whole file as bytes, since a vault is binary and `sek_readfile`
 * stops at the first NUL. */
static char *slurp(const char *path, size_t *len) {
  FILE *in = fopen(path, "rb");
  sek_buf out;
  char chunk[4096];
  size_t got;

  *len = 0;
  if (NULL == in) {
    return NULL;
  }

  sek_buf_init(&out, POOL);
  while (0 < (got = fread(chunk, 1, sizeof(chunk), in))) {
    sek_buf_addn(&out, chunk, got);
  }
  fclose(in);

  *len = out.len;

  return out.data;
}

static const char *spill(const char *path, const char *data, size_t len) {
  FILE *out = fopen(path, "wb");

  if (NULL == out) {
    return "cannot write";
  }
  fwrite(data, 1, len, out);
  fclose(out);

  return NULL;
}

/* Does this whole file - NULs and all - hold that text? `strstr` would
 * stop at the first NUL, which in a vault is byte 7. */
static int held(const char *raw, size_t len, const char *want) {
  size_t wantlen = strlen(want);
  size_t at;

  if (len < wantlen) {
    return 0;
  }

  for (at = 0; at + wantlen <= len; at++) {
    if (0 == memcmp(raw + at, want, wantlen)) {
      return 1;
    }
  }

  return 0;
}

/* ---- the file ------------------------------------------------------ */

static const char *anewvaultholdsnothing(void) {
  const char *why;
  sek_minivault *vault = fresh(&why);
  sek_vaultinfo *info = NULL;
  sek_list *names = NULL;

  if (NULL != why) {
    return why;
  }
  why = sek_vault_list(vault, &names);
  if (NULL != why) {
    return why;
  }
  if (NULL != (why = same("", line(names), "list"))) {
    return why;
  }
  if (NULL != (why = same("master", sek_vault_key(vault), "key"))) {
    return why;
  }

  why = sek_vault_info(vault, &info);
  if (NULL != why) {
    return why;
  }
  if (NULL != (why = truth(info->master, "the master key is not master"))) {
    return why;
  }
  if (NULL != (why = truth(info->write, "the master key may not write"))) {
    return why;
  }

  return same("", line(info->grants), "grants");
}

static const char *awrittensecretcomesback(void) {
  const char *why;
  sek_minivault *vault = fresh(&why);
  sek_minivault *again;
  sek_list *names = NULL;
  char *found = NULL;
  int has = 0;

  if (NULL != why) {
    return why;
  }
  if (NULL != (why = sek_vault_set(vault, "api.token", "tok01"))) {
    return why;
  }
  if (NULL != (why = sek_vault_set(vault, "db.pass", "hunter2"))) {
    return why;
  }
  if (NULL != (why = sek_vault_get(vault, "api.token", &found))) {
    return why;
  }
  if (NULL != (why = same("tok01", found, "get"))) {
    return why;
  }
  if (NULL != (why = sek_vault_list(vault, &names))) {
    return why;
  }
  if (NULL != (why = same("api.token db.pass", line(names), "list"))) {
    return why;
  }
  if (NULL != (why = sek_vault_has(vault, "api.token", &has))) {
    return why;
  }
  if (NULL != (why = truth(has, "has said no"))) {
    return why;
  }
  if (NULL != (why = sek_vault_has(vault, "nope", &has))) {
    return why;
  }
  if (NULL != (why = truth(!has, "has said yes to an unknown name"))) {
    return why;
  }

  found = NULL;
  if (NULL != (why = sek_vault_get(vault, "nope", &found))) {
    return why;
  }
  if (NULL != (why = truth(NULL == found, "an unknown name answered"))) {
    return why;
  }

  /* A SECOND HANDLE on the same file, so the assertion is about the
   * bytes rather than about what this handle happens to remember. */
  again = openas(sek_vault_file(vault), NULL, MASTER, &why);
  if (NULL != why) {
    return why;
  }
  found = NULL;
  if (NULL != (why = sek_vault_get(again, "api.token", &found))) {
    return why;
  }

  return same("tok01", found, "a new handle");
}

static const char *thefileisbinary(void) {
  const char *why;
  sek_minivault *vault = fresh(&why);
  const char *secrets[] = {"api.token", "tok01", MASTER};
  char *raw;
  size_t len = 0;
  int index;

  if (NULL != why) {
    return why;
  }
  if (NULL != (why = sek_vault_set(vault, "api.token", "tok01"))) {
    return why;
  }

  raw = slurp(sek_vault_file(vault), &len);
  if (NULL == raw) {
    return "cannot read the vault back";
  }
  if (NULL != (why = truth(4 <= len && 0 == memcmp("SKMV", raw, 4), "the magic is wrong"))) {
    return why;
  }

  /* NOT ONE OF THESE IS IN THE FILE. The key id is plaintext by design;
   * the secret's name and its value are not, and neither is the
   * passphrase that unwrapped them. */
  for (index = 0; index < 3; index++) {
    if (held(raw, len, secrets[index])) {
      return sek_fmt(POOL, "%s is in the file", secrets[index]);
    }
  }

  return truth(held(raw, len, "master"), "the key id is not in the file");
}

static const char *rewritinganamereplacesit(void) {
  const char *why;
  sek_minivault *vault = fresh(&why);
  sek_list *names = NULL;
  char *found = NULL;

  if (NULL != why) {
    return why;
  }
  if (NULL != (why = sek_vault_set(vault, "api.token", "first"))) {
    return why;
  }
  if (NULL != (why = sek_vault_set(vault, "api.token", "second"))) {
    return why;
  }
  if (NULL != (why = sek_vault_get(vault, "api.token", &found))) {
    return why;
  }
  if (NULL != (why = same("second", found, "get"))) {
    return why;
  }
  if (NULL != (why = sek_vault_list(vault, &names))) {
    return why;
  }

  return same("api.token", line(names), "one entry");
}

static const char *removedropsaname(void) {
  const char *why;
  sek_minivault *vault = fresh(&why);
  sek_list *names = NULL;
  char *found = NULL;

  if (NULL != why) {
    return why;
  }
  if (NULL != (why = sek_vault_set(vault, "api.token", "tok01"))) {
    return why;
  }
  if (NULL != (why = sek_vault_set(vault, "db.pass", "hunter2"))) {
    return why;
  }
  if (NULL != (why = sek_vault_remove(vault, "api.token"))) {
    return why;
  }
  if (NULL != (why = sek_vault_list(vault, &names))) {
    return why;
  }
  if (NULL != (why = same("db.pass", line(names), "list"))) {
    return why;
  }
  if (NULL != (why = sek_vault_get(vault, "api.token", &found))) {
    return why;
  }
  if (NULL != (why = truth(NULL == found, "a removed name answered"))) {
    return why;
  }

  return holds(refused(sek_vault_remove(vault, "api.token")), "no such secret: api.token",
               "remove again");
}

static const char *abadnameisrefused(void) {
  const char *why;
  sek_minivault *vault = fresh(&why);
  char *found = NULL;

  if (NULL != why) {
    return why;
  }
  if (NULL != (why = holds(refused(sek_vault_set(vault, "API.TOKEN", "x")), "invalid name",
                           "set"))) {
    return why;
  }
  if (NULL != (why = holds(refused(sek_vault_get(vault, "api..token", &found)), "invalid name",
                           "get"))) {
    return why;
  }

  return holds(refused(sek_vault_remove(vault, "")), "invalid name", "remove");
}

/* ---- keys ---------------------------------------------------------- */

static sek_vaultgrant *grantof(const char *key, const char *passphrase, const char *name,
                               int write) {
  sek_vaultgrant *out = (sek_vaultgrant *)sek_alloc(POOL, sizeof(sek_vaultgrant));

  memset(out, 0, sizeof(*out));
  out->key = key;
  out->passphrase = passphrase;
  out->write = write;
  out->iterations = ROUNDS;

  if (NULL != name) {
    out->names = sek_list_new(POOL);
    sek_list_add(out->names, name);
  }

  return out;
}

static const char *arestrictedkeyreadsitsgrants(void) {
  const char *why;
  sek_minivault *vault = fresh(&why);
  sek_minivault *ci;
  sek_vaultinfo *info = NULL;
  sek_list *names = NULL;
  char *found = NULL;

  if (NULL != why) {
    return why;
  }
  if (NULL != (why = sek_vault_set(vault, "api.token", "tok01"))) {
    return why;
  }
  if (NULL != (why = sek_vault_set(vault, "db.pass", "hunter2"))) {
    return why;
  }
  if (NULL != (why = sek_vault_grant(vault, grantof("ci", "ci-passphrase", "api.token", 0)))) {
    return why;
  }

  ci = openas(sek_vault_file(vault), "ci", "ci-passphrase", &why);
  if (NULL != why) {
    return why;
  }
  if (NULL != (why = sek_vault_get(ci, "api.token", &found))) {
    return why;
  }
  if (NULL != (why = same("tok01", found, "granted"))) {
    return why;
  }

  /* THE RESTRICTION IS THE CRYPTOGRAPHY. `db.pass` is in the file and
   * this key cannot derive its key, so the answer is the one a stranger
   * gets: a miss. */
  found = NULL;
  if (NULL != (why = sek_vault_get(ci, "db.pass", &found))) {
    return why;
  }
  if (NULL != (why = truth(NULL == found, "an ungranted name answered"))) {
    return why;
  }
  if (NULL != (why = sek_vault_list(ci, &names))) {
    return why;
  }
  if (NULL != (why = same("api.token", line(names), "list"))) {
    return why;
  }

  if (NULL != (why = sek_vault_info(ci, &info))) {
    return why;
  }
  if (NULL != (why = truth(!info->master, "a restricted key reports master"))) {
    return why;
  }
  if (NULL != (why = truth(!info->write, "a read-only key reports write"))) {
    return why;
  }

  return same("api.token", line(info->grants), "grants");
}

static const char *areadonlykeyrefusestowrite(void) {
  const char *why;
  sek_minivault *vault = fresh(&why);
  sek_minivault *reader;
  sek_minivault *writer;
  char *found = NULL;

  if (NULL != why) {
    return why;
  }
  if (NULL != (why = sek_vault_set(vault, "api.token", "tok01"))) {
    return why;
  }
  if (NULL != (why = sek_vault_grant(vault, grantof("reader", "reader-passphrase", "api.token",
                                                    0)))) {
    return why;
  }
  if (NULL != (why = sek_vault_grant(vault, grantof("writer", "writer-passphrase", "api.token",
                                                    1)))) {
    return why;
  }

  reader = openas(sek_vault_file(vault), "reader", "reader-passphrase", &why);
  if (NULL != why) {
    return why;
  }
  if (NULL != (why = holds(refused(sek_vault_set(reader, "api.token", "x")),
                           "key reader is read-only", "read-only"))) {
    return why;
  }

  writer = openas(sek_vault_file(vault), "writer", "writer-passphrase", &why);
  if (NULL != why) {
    return why;
  }
  if (NULL != (why = sek_vault_set(writer, "api.token", "rewritten"))) {
    return why;
  }
  if (NULL != (why = sek_vault_get(vault, "api.token", &found))) {
    return why;
  }

  return same("rewritten", found, "the master sees it");
}

static const char *arestrictedkeycannotwriteanungrantedname(void) {
  const char *why;
  sek_minivault *vault = fresh(&why);
  sek_minivault *ci;

  if (NULL != why) {
    return why;
  }
  if (NULL != (why = sek_vault_set(vault, "api.token", "tok01"))) {
    return why;
  }
  if (NULL != (why = sek_vault_grant(vault, grantof("ci", "ci-passphrase", "api.token", 1)))) {
    return why;
  }

  ci = openas(sek_vault_file(vault), "ci", "ci-passphrase", &why);
  if (NULL != why) {
    return why;
  }

  return holds(refused(sek_vault_set(ci, "db.pass", "x")), "key ci was not granted db.pass",
               "ungranted");
}

static const char *agrantednamethatdoesnotexistyet(void) {
  const char *why;
  sek_minivault *vault = fresh(&why);
  sek_minivault *ci;
  sek_list *names = NULL;
  char *found = NULL;

  if (NULL != why) {
    return why;
  }

  /* Granted BEFORE the name exists, which is the point: a deploy key is
   * minted from a list of what a service will need. */
  if (NULL != (why = sek_vault_grant(vault, grantof("ci", "ci-passphrase", "api.token", 0)))) {
    return why;
  }

  ci = openas(sek_vault_file(vault), "ci", "ci-passphrase", &why);
  if (NULL != why) {
    return why;
  }
  if (NULL != (why = sek_vault_list(ci, &names))) {
    return why;
  }
  if (NULL != (why = same("", line(names), "nothing yet"))) {
    return why;
  }
  if (NULL != (why = sek_vault_get(ci, "api.token", &found))) {
    return why;
  }
  if (NULL != (why = truth(NULL == found, "a name that does not exist answered"))) {
    return why;
  }

  if (NULL != (why = sek_vault_set(vault, "api.token", "tok01"))) {
    return why;
  }

  found = NULL;
  if (NULL != (why = sek_vault_get(ci, "api.token", &found))) {
    return why;
  }
  if (NULL != (why = same("tok01", found, "once written"))) {
    return why;
  }
  if (NULL != (why = sek_vault_list(ci, &names))) {
    return why;
  }

  return same("api.token", line(names), "list");
}

static const char *themasterlistseverykey(void) {
  const char *why;
  sek_minivault *vault = fresh(&why);
  sek_vaultgrant *grant;
  sek_vaultinfo **keys = NULL;
  size_t count = 0;

  if (NULL != why) {
    return why;
  }

  grant = grantof("ci", "ci-passphrase", NULL, 1);
  grant->names = sek_list_new(POOL);
  sek_list_add(grant->names, "db.pass");
  sek_list_add(grant->names, "api.token");

  if (NULL != (why = sek_vault_grant(vault, grant))) {
    return why;
  }
  if (NULL != (why = sek_vault_keys(vault, &keys, &count))) {
    return why;
  }
  if (NULL != (why = truth(2 == count, sek_fmt(POOL, "want 2 keys, got %d", (int)count)))) {
    return why;
  }
  if (NULL != (why = same("master", keys[0]->key, "the master"))) {
    return why;
  }
  if (NULL != (why = truth(keys[0]->master, "the master is not master"))) {
    return why;
  }
  if (NULL != (why = same("", line(keys[0]->grants), "a master is granted nothing"))) {
    return why;
  }
  if (NULL != (why = same("ci", keys[1]->key, "the restricted key"))) {
    return why;
  }
  if (NULL != (why = truth(!keys[1]->master, "ci reports master"))) {
    return why;
  }
  if (NULL != (why = truth(keys[1]->write, "ci may not write"))) {
    return why;
  }

  /* SORTED, so the record reads the same however the grant was spelled. */
  return same("api.token db.pass", line(keys[1]->grants), "grants");
}

static const char *themasteronlymethodsrefusearestrictedkey(void) {
  const char *why;
  sek_minivault *vault = fresh(&why);
  sek_minivault *ci;
  sek_vaultinfo **keys = NULL;
  size_t count = 0;

  if (NULL != why) {
    return why;
  }
  if (NULL != (why = sek_vault_set(vault, "api.token", "tok01"))) {
    return why;
  }
  if (NULL != (why = sek_vault_grant(vault, grantof("ci", "ci-passphrase", "api.token", 1)))) {
    return why;
  }

  ci = openas(sek_vault_file(vault), "ci", "ci-passphrase", &why);
  if (NULL != why) {
    return why;
  }

  if (NULL != (why = holds(refused(sek_vault_keys(ci, &keys, &count)),
                           "listing the keys needs a master key", "keys"))) {
    return why;
  }
  if (NULL != (why = holds(refused(sek_vault_grant(ci, grantof("x", "y", NULL, 0))),
                           "granting a key needs a master key", "grant"))) {
    return why;
  }
  if (NULL != (why = holds(refused(sek_vault_revoke(ci, "master")),
                           "revoking a key needs a master key", "revoke"))) {
    return why;
  }
  if (NULL != (why = holds(refused(sek_vault_rotate(ci)), "rotating the vault needs a master key",
                           "rotate"))) {
    return why;
  }

  return holds(refused(sek_vault_remove(ci, "api.token")), "removing a secret needs a master key",
               "remove");
}

static const char *arepeatedkeyidisrefused(void) {
  const char *why;
  sek_minivault *vault = fresh(&why);

  if (NULL != why) {
    return why;
  }
  if (NULL != (why = sek_vault_grant(vault, grantof("ci", "p", NULL, 0)))) {
    return why;
  }
  if (NULL != (why = holds(refused(sek_vault_grant(vault, grantof("ci", "q", NULL, 0))),
                           "key already exists: ci", "repeated"))) {
    return why;
  }
  if (NULL != (why = holds(refused(sek_vault_grant(vault, grantof("", "p", NULL, 0))),
                           "a grant needs a key id", "no id"))) {
    return why;
  }

  return holds(refused(sek_vault_grant(vault, grantof("x", "", NULL, 0))),
               "a grant needs a passphrase", "no passphrase");
}

static const char *revokedropsakey(void) {
  const char *why;
  sek_minivault *vault = fresh(&why);
  sek_minivault *ci;
  char *found = NULL;

  if (NULL != why) {
    return why;
  }
  if (NULL != (why = sek_vault_set(vault, "api.token", "tok01"))) {
    return why;
  }
  if (NULL != (why = sek_vault_grant(vault, grantof("ci", "ci-passphrase", "api.token", 0)))) {
    return why;
  }
  if (NULL != (why = sek_vault_revoke(vault, "ci"))) {
    return why;
  }

  ci = openas(sek_vault_file(vault), "ci", "ci-passphrase", &why);
  if (NULL != why) {
    return why;
  }
  if (NULL != (why = holds(refused(sek_vault_get(ci, "api.token", &found)), "no such key: ci",
                           "revoked"))) {
    return why;
  }
  if (NULL != (why = holds(refused(sek_vault_revoke(vault, "ci")), "no such key: ci",
                           "revoke again"))) {
    return why;
  }
  if (NULL != (why = holds(refused(sek_vault_revoke(vault, "master")),
                           "a key cannot revoke itself", "itself"))) {
    return why;
  }

  /* THE SECRET IS UNTOUCHED: revoking bars a key, not a value. */
  found = NULL;
  if (NULL != (why = sek_vault_get(vault, "api.token", &found))) {
    return why;
  }

  return same("tok01", found, "the secret stays");
}

static const char *rotatekeepsthesecrets(void) {
  const char *why;
  sek_minivault *vault = fresh(&why);
  sek_minivault *ci;
  sek_vaultinfo **keys = NULL;
  sek_list *names = NULL;
  char *found = NULL;
  size_t count = 0;

  if (NULL != why) {
    return why;
  }
  if (NULL != (why = sek_vault_set(vault, "api.token", "tok01"))) {
    return why;
  }
  if (NULL != (why = sek_vault_set(vault, "db.pass", "hunter2"))) {
    return why;
  }
  if (NULL != (why = sek_vault_grant(vault, grantof("ci", "ci-passphrase", "api.token", 0)))) {
    return why;
  }
  if (NULL != (why = sek_vault_rotate(vault))) {
    return why;
  }

  if (NULL != (why = sek_vault_get(vault, "api.token", &found))) {
    return why;
  }
  if (NULL != (why = same("tok01", found, "api.token survives"))) {
    return why;
  }
  found = NULL;
  if (NULL != (why = sek_vault_get(vault, "db.pass", &found))) {
    return why;
  }
  if (NULL != (why = same("hunter2", found, "db.pass survives"))) {
    return why;
  }
  if (NULL != (why = sek_vault_list(vault, &names))) {
    return why;
  }
  if (NULL != (why = same("api.token db.pass", line(names), "list"))) {
    return why;
  }
  if (NULL != (why = sek_vault_keys(vault, &keys, &count))) {
    return why;
  }
  if (NULL != (why = truth(1 == count, sek_fmt(POOL, "want 1 key, got %d", (int)count)))) {
    return why;
  }
  if (NULL != (why = same("master", keys[0]->key, "the only key"))) {
    return why;
  }

  /* EVERY OTHER KEY IS GONE, which is what rotation has to mean: their
   * rings were sealed under passphrases this process does not have. */
  ci = openas(sek_vault_file(vault), "ci", "ci-passphrase", &why);
  if (NULL != why) {
    return why;
  }
  found = NULL;

  return holds(refused(sek_vault_get(ci, "api.token", &found)), "no such key: ci", "ci is gone");
}

/* ---- refusals ------------------------------------------------------ */

static const char *awrongpassphraseandamissingfile(void) {
  const char *why;
  sek_minivault *vault = fresh(&why);
  sek_minivault *wrong;
  sek_minivault *unknown;
  sek_minivault *missing;
  char *found = NULL;

  if (NULL != why) {
    return why;
  }
  if (NULL != (why = sek_vault_set(vault, "api.token", "tok01"))) {
    return why;
  }

  wrong = openas(sek_vault_file(vault), NULL, "not-the-passphrase", &why);
  if (NULL != why) {
    return why;
  }
  if (NULL != (why = holds(refused(sek_vault_get(wrong, "api.token", &found)),
                           "wrong passphrase for key master, or a damaged vault",
                           "wrong passphrase"))) {
    return why;
  }

  unknown = openas(sek_vault_file(vault), "nope", MASTER, &why);
  if (NULL != why) {
    return why;
  }
  if (NULL != (why = holds(refused(sek_vault_get(unknown, "api.token", &found)),
                           "no such key: nope", "unknown key"))) {
    return why;
  }

  missing = openas(sek_fmt(POOL, "%s/not-there.skmv", WORK), NULL, MASTER, &why);
  if (NULL != why) {
    return why;
  }

  return holds(refused(sek_vault_get(missing, "api.token", &found)), "no vault file",
               "missing file");
}

static const char *adamagedfileisrefused(void) {
  const char *why;
  sek_minivault *vault = fresh(&why);
  sek_minivault *held;
  const char *where;
  char *raw;
  char *bent;
  char *extra;
  char *found = NULL;
  size_t len = 0;

  if (NULL != why) {
    return why;
  }
  if (NULL != (why = sek_vault_set(vault, "api.token", "tok01"))) {
    return why;
  }

  raw = slurp(sek_vault_file(vault), &len);
  if (NULL == raw) {
    return "cannot read the vault back";
  }

  /* Not a vault at all. */
  where = vaultpath();
  if (NULL != (why = spill(where, "nonsense", 8))) {
    return why;
  }
  held = openas(where, NULL, MASTER, &why);
  if (NULL != why) {
    return why;
  }
  if (NULL != (why = holds(refused(sek_vault_get(held, "api.token", &found)), "not a vault file",
                           "not a vault"))) {
    return why;
  }

  /* Cut off part way through. */
  where = vaultpath();
  if (NULL != (why = spill(where, raw, len - 20))) {
    return why;
  }
  held = openas(where, NULL, MASTER, &why);
  if (NULL != why) {
    return why;
  }
  if (NULL != (why = holds(refused(sek_vault_get(held, "api.token", &found)), "truncated",
                           "truncated"))) {
    return why;
  }

  /* One byte of ciphertext flipped, which the GCM tag catches. */
  bent = (char *)sek_alloc(POOL, len);
  memcpy(bent, raw, len);
  bent[len - 1] = (char)(bent[len - 1] ^ 0xff);
  where = vaultpath();
  if (NULL != (why = spill(where, bent, len))) {
    return why;
  }
  held = openas(where, NULL, MASTER, &why);
  if (NULL != why) {
    return why;
  }
  if (NULL != (why = holds(refused(sek_vault_get(held, "api.token", &found)), "damaged",
                           "flipped"))) {
    return why;
  }

  /* Trailing bytes, which a reader that stopped at the last record would
   * have accepted. */
  extra = (char *)sek_alloc(POOL, len + 4);
  memcpy(extra, raw, len);
  memcpy(extra + len, "junk", 4);
  where = vaultpath();
  if (NULL != (why = spill(where, extra, len + 4))) {
    return why;
  }
  held = openas(where, NULL, MASTER, &why);
  if (NULL != why) {
    return why;
  }

  return holds(refused(sek_vault_get(held, "api.token", &found)), "trailing bytes", "trailing");
}

static const char *creatingoveranexistingvaultisrefused(void) {
  const char *why;
  sek_minivault *vault = fresh(&why);
  sek_minivault *again = NULL;

  if (NULL != why) {
    return why;
  }

  return holds(refused(sek_vault_create(POOL, vaultopts(sek_vault_file(vault), NULL, MASTER),
                                        &again)),
               "vault file already exists", "create over");
}

static const char *avaultneedsafileandapassphrase(void) {
  const char *why;
  sek_minivault *vault = NULL;

  if (NULL != (why = holds(refused(sek_vault_open(POOL, vaultopts(NULL, NULL, "p"), &vault)),
                           "a vault needs a file", "no file"))) {
    return why;
  }

  return holds(refused(sek_vault_open(POOL, vaultopts("v.skmv", NULL, NULL), &vault)),
               "a vault needs a passphrase", "no passphrase");
}

/* TWO HANDLES ON ONE FILE, WRITING AT ONCE, LOSE NOTHING. Each handle is
 * its own object with its own snapshot, so without the shared per-path
 * lock both threads finish `mvload` before either saves and the second
 * rename discards the first one's secret while reporting success.
 * DOCS.md promises this within one process.
 *
 * EACH THREAD GETS ITS OWN POOL, because a pool is not thread-safe:
 * sharing one would test the allocator rather than the vault. */
#define MV_ROUNDS 40

typedef struct {
  const char *path;
  const char *tag;
  int broke;
} mvwriter;

static void *writerrun(void *given) {
  mvwriter *self = (mvwriter *)given;
  sek_pool *pool = sek_pool_new();
  sek_vaultoptions *options = (sek_vaultoptions *)sek_alloc(pool, sizeof(sek_vaultoptions));
  sek_minivault *mine = NULL;
  int round;

  memset(options, 0, sizeof(*options));
  options->file = self->path;
  options->passphrase = MASTER;

  if (NULL != sek_vault_open(pool, options, &mine)) {
    self->broke = 1;
    sek_pool_free(pool);
    return NULL;
  }

  for (round = 0; round < MV_ROUNDS; round++) {
    char name[64];
    snprintf(name, sizeof(name), "t%s.n%d", self->tag, round);
    if (NULL != sek_vault_set(mine, name, "v")) {
      self->broke = 1;
      break;
    }
  }

  sek_pool_free(pool);

  return NULL;
}

static const char *twohandleswritingatoncelosenothing(void) {
  const char *why;
  sek_minivault *vault = fresh(&why);
  sek_list *names = NULL;
  mvwriter one, two;
  pthread_t first, second;
  char count[32];
  char got[32];

  if (NULL != why) {
    return why;
  }

  one.path = sek_vault_file(vault);
  one.tag = "one";
  one.broke = 0;
  two = one;
  two.tag = "two";

  if (0 != pthread_create(&first, NULL, writerrun, &one) ||
      0 != pthread_create(&second, NULL, writerrun, &two)) {
    return "a thread would not start";
  }
  pthread_join(first, NULL);
  pthread_join(second, NULL);

  if (NULL != (why = truth(!one.broke && !two.broke, "a writer raised"))) {
    return why;
  }

  if (NULL != (why = sek_vault_list(vault, &names))) {
    return why;
  }

  snprintf(count, sizeof(count), "%d", 2 * MV_ROUNDS);
  snprintf(got, sizeof(got), "%lu", (unsigned long) (NULL == names ? 0 : names->len));

  return same(count, got, "every write survived");
}

/* An EMPTY key is no key, so it means `master`. It is not a contrived
 * case: the CLI reads SEKRETO_VAULT_KEY, and an unset shell variable
 * expands to the empty string rather than to nothing at all. */
static const char *anemptykeymeansthemasterkey(void) {
  const char *why;
  sek_minivault *vault = fresh(&why);
  sek_minivault *opened;
  sek_vaultinfo *info = NULL;
  char *found = NULL;

  if (NULL != why) {
    return why;
  }
  if (NULL != (why = sek_vault_set(vault, "api.token", "tok01"))) {
    return why;
  }

  opened = openas(sek_vault_file(vault), "", MASTER, &why);
  if (NULL != why) {
    return why;
  }
  if (NULL != (why = sek_vault_get(opened, "api.token", &found))) {
    return why;
  }
  if (NULL != (why = same("tok01", found, "api.token"))) {
    return why;
  }

  if (NULL != (why = sek_vault_info(opened, &info))) {
    return why;
  }

  return same("master", info->key, "key");
}

static const char *createmakesthefileonlywhenasked(void) {
  const char *why;
  const char *where = vaultpath();
  sek_vaultoptions *options;
  sek_minivault *off;
  sek_minivault *on = NULL;
  sek_minivault *again;
  char *found = NULL;

  off = openas(where, NULL, MASTER, &why);
  if (NULL != why) {
    return why;
  }
  if (NULL != (why = holds(refused(sek_vault_get(off, "api.token", &found)), "no vault file",
                           "create off"))) {
    return why;
  }

  options = vaultopts(where, NULL, MASTER);
  options->create = 1;
  if (NULL != (why = sek_vault_open(POOL, options, &on))) {
    return why;
  }
  found = NULL;
  if (NULL != (why = sek_vault_get(on, "api.token", &found))) {
    return why;
  }
  if (NULL != (why = truth(NULL == found, "a new vault answered"))) {
    return why;
  }
  if (NULL != (why = sek_vault_set(on, "api.token", "tok01"))) {
    return why;
  }

  /* The file is there now, so the handle that refused reads it. */
  again = openas(where, NULL, MASTER, &why);
  if (NULL != why) {
    return why;
  }
  found = NULL;
  if (NULL != (why = sek_vault_get(again, "api.token", &found))) {
    return why;
  }

  return same("tok01", found, "the same file");
}

static const char *akeyidlongerthantheformatallows(void) {
  const char *why;
  sek_minivault *vault = fresh(&why);
  sek_minivault *held = NULL;
  sek_vaultinfo **keys = NULL;
  char *big = (char *)sek_alloc(POOL, 301);
  size_t count = 0;

  if (NULL != why) {
    return why;
  }

  memset(big, 'k', 300);
  big[300] = '\0';

  if (NULL != (why = holds(refused(sek_vault_grant(vault, grantof(big, "p", NULL, 0))),
                           "key id is longer than 255 bytes", "grant"))) {
    return why;
  }
  if (NULL != (why = holds(refused(sek_vault_open(POOL,
                                                  vaultopts(sek_vault_file(vault), big, "p"),
                                                  &held)),
                           "key id is longer than 255 bytes", "open"))) {
    return why;
  }

  /* AND THE VAULT IS UNHARMED: the refusal came before the write, so a
   * 300-character id did not shift every field after it. */
  if (NULL != (why = sek_vault_keys(vault, &keys, &count))) {
    return why;
  }

  return truth(1 == count, sek_fmt(POOL, "want 1 key, got %d", (int)count));
}

static const char *theinfoacallergetscannotchangewhatthekeymaydo(void) {
  const char *why;
  sek_minivault *vault = fresh(&why);
  sek_minivault *reader;
  sek_vaultinfo *info = NULL;

  if (NULL != why) {
    return why;
  }
  if (NULL != (why = sek_vault_set(vault, "api.token", "tok01"))) {
    return why;
  }
  if (NULL != (why = sek_vault_grant(vault, grantof("reader", "reader-passphrase", "api.token",
                                                    0)))) {
    return why;
  }

  reader = openas(sek_vault_file(vault), "reader", "reader-passphrase", &why);
  if (NULL != why) {
    return why;
  }
  if (NULL != (why = sek_vault_info(reader, &info))) {
    return why;
  }
  if (NULL != (why = truth(!info->write, "the reader key may write"))) {
    return why;
  }

  /* A COPY, and the vault reads its own. Flipping the bit and adding a
   * grant here is the defect the review round found in the canonical,
   * and it changes nothing. */
  info->write = 1;
  sek_list_add(info->grants, "db.pass");

  return holds(refused(sek_vault_set(reader, "api.token", "x")), "key reader is read-only",
               "still refused");
}

static const char *arevokedkeystopsreading(void) {
  const char *why;
  sek_minivault *vault = fresh(&why);
  sek_minivault *ci;
  char *found = NULL;

  if (NULL != why) {
    return why;
  }
  if (NULL != (why = sek_vault_set(vault, "api.token", "tok01"))) {
    return why;
  }
  if (NULL != (why = sek_vault_grant(vault, grantof("ci", "ci-passphrase", "api.token", 0)))) {
    return why;
  }

  /* OPEN AND READING FIRST, so the handle holds its derived keys. */
  ci = openas(sek_vault_file(vault), "ci", "ci-passphrase", &why);
  if (NULL != why) {
    return why;
  }
  if (NULL != (why = sek_vault_get(ci, "api.token", &found))) {
    return why;
  }
  if (NULL != (why = same("tok01", found, "before"))) {
    return why;
  }

  if (NULL != (why = sek_vault_revoke(vault, "ci"))) {
    return why;
  }

  /* The live file no longer holds the key, and a handle that answered
   * from memory here would make `revoke` a suggestion. */
  found = NULL;

  return holds(refused(sek_vault_get(ci, "api.token", &found)), "no such key: ci", "after");
}

static const char *aregrantedkeyid(void) {
  const char *why;
  sek_minivault *vault = fresh(&why);
  sek_minivault *ci;
  sek_minivault *second;
  char *found = NULL;

  if (NULL != why) {
    return why;
  }
  if (NULL != (why = sek_vault_set(vault, "api.token", "tok01"))) {
    return why;
  }
  if (NULL != (why = sek_vault_grant(vault, grantof("ci", "first-passphrase", "api.token", 0)))) {
    return why;
  }

  ci = openas(sek_vault_file(vault), "ci", "first-passphrase", &why);
  if (NULL != why) {
    return why;
  }
  if (NULL != (why = sek_vault_get(ci, "api.token", &found))) {
    return why;
  }
  if (NULL != (why = same("tok01", found, "before"))) {
    return why;
  }

  if (NULL != (why = sek_vault_revoke(vault, "ci"))) {
    return why;
  }
  if (NULL != (why = sek_vault_grant(vault, grantof("ci", "second-passphrase", "api.token", 0)))) {
    return why;
  }

  /* SAME ID, DIFFERENT KEY. The handle re-derives because the sealed
   * ring changed, and the old passphrase does not unwrap the new one. */
  found = NULL;
  if (NULL != (why = holds(refused(sek_vault_get(ci, "api.token", &found)),
                           "wrong passphrase for key ci, or a damaged vault",
                           "the old passphrase"))) {
    return why;
  }

  second = openas(sek_vault_file(vault), "ci", "second-passphrase", &why);
  if (NULL != why) {
    return why;
  }
  found = NULL;
  if (NULL != (why = sek_vault_get(second, "api.token", &found))) {
    return why;
  }

  return same("tok01", found, "the new passphrase");
}

static const char *closeforgetsthederivedkeys(void) {
  const char *why;
  sek_minivault *vault = fresh(&why);
  char *found = NULL;

  if (NULL != why) {
    return why;
  }
  if (NULL != (why = sek_vault_set(vault, "api.token", "tok01"))) {
    return why;
  }
  if (NULL != (why = sek_vault_get(vault, "api.token", &found))) {
    return why;
  }
  if (NULL != (why = same("tok01", found, "before"))) {
    return why;
  }

  sek_vault_close(vault);

  found = NULL;
  if (NULL != (why = sek_vault_get(vault, "api.token", &found))) {
    return why;
  }

  return same("tok01", found, "after");
}

/* ---- the committed files ------------------------------------------- */

static const char *FIXTURE = NULL;

/* Every port's vault holds the same keys and the same secrets, so the
 * assertions do not vary with which file this is. */
static const char *readsthefixture(void) {
  const char *file = fixture(FIXTURE);
  const char *why;
  sek_minivault *master;
  sek_minivault *reader;
  sek_minivault *writer;
  sek_vaultinfo **keys = NULL;
  sek_list *names = NULL;
  sek_list *ids;
  char *found = NULL;
  size_t count = 0;
  size_t at;

  if (NULL == file) {
    return sek_fmt(POOL, "cannot copy %s", FIXTURE);
  }

  master = openas(file, NULL, "fixture-master", &why);
  if (NULL != why) {
    return why;
  }
  if (NULL != (why = sek_vault_list(master, &names))) {
    return why;
  }
  if (NULL != (why = same("api.token db.pass deep.nested.name", line(names), "list"))) {
    return why;
  }
  if (NULL != (why = sek_vault_get(master, "api.token", &found))) {
    return why;
  }
  if (NULL != (why = same("fixture-token", found, "api.token"))) {
    return why;
  }
  found = NULL;
  if (NULL != (why = sek_vault_get(master, "db.pass", &found))) {
    return why;
  }
  if (NULL != (why = same("fixture-pass", found, "db.pass"))) {
    return why;
  }
  found = NULL;
  if (NULL != (why = sek_vault_get(master, "deep.nested.name", &found))) {
    return why;
  }
  if (NULL != (why = same("fixture-deep", found, "deep.nested.name"))) {
    return why;
  }

  if (NULL != (why = sek_vault_keys(master, &keys, &count))) {
    return why;
  }
  ids = sek_list_new(POOL);
  for (at = 0; at < count; at++) {
    sek_list_add(ids, keys[at]->key);
  }
  sek_list_sort(ids);
  if (NULL != (why = same("master reader writer", line(ids), "keys"))) {
    return why;
  }

  reader = openas(file, "reader", "fixture-reader", &why);
  if (NULL != why) {
    return why;
  }
  if (NULL != (why = sek_vault_list(reader, &names))) {
    return why;
  }
  if (NULL != (why = same("api.token", line(names), "reader list"))) {
    return why;
  }
  found = NULL;
  if (NULL != (why = sek_vault_get(reader, "api.token", &found))) {
    return why;
  }
  if (NULL != (why = same("fixture-token", found, "reader reads"))) {
    return why;
  }
  found = NULL;
  if (NULL != (why = sek_vault_get(reader, "db.pass", &found))) {
    return why;
  }
  if (NULL != (why = truth(NULL == found, "the reader key read db.pass"))) {
    return why;
  }
  if (NULL != (why = holds(refused(sek_vault_set(reader, "api.token", "x")), "read-only",
                           "reader writes"))) {
    return why;
  }

  writer = openas(file, "writer", "fixture-writer", &why);
  if (NULL != why) {
    return why;
  }
  if (NULL != (why = sek_vault_list(writer, &names))) {
    return why;
  }
  if (NULL != (why = same("db.pass", line(names), "writer list"))) {
    return why;
  }
  found = NULL;
  if (NULL != (why = sek_vault_get(writer, "db.pass", &found))) {
    return why;
  }
  if (NULL != (why = same("fixture-pass", found, "writer reads"))) {
    return why;
  }

  /* The copy is this case's own, so writing it proves the round trip
   * without touching the committed bytes. */
  if (NULL != (why = sek_vault_set(writer, "db.pass", "rewritten"))) {
    return why;
  }
  found = NULL;
  if (NULL != (why = sek_vault_get(master, "db.pass", &found))) {
    return why;
  }

  return same("rewritten", found, "the master sees it");
}

/* ---- the chain ----------------------------------------------------- */

static const char *avaultisonestoreinachain(void) {
  const char *why;
  sek_minivault *vault = fresh(&why);
  sek_options *opts = chainopts();
  sek_sekreto *secrets = NULL;
  char *found = NULL;

  if (NULL != why) {
    return why;
  }
  if (NULL != (why = sek_vault_set(vault, "api.token", "from the vault"))) {
    return why;
  }

  opts->providers = chain2(vaultspec(sek_vault_file(vault), NULL, MASTER),
                           memoryspec("DB_PASS", "from memory"));
  opts->count = 2;

  if (NULL != (why = sek_new(POOL, opts, &secrets))) {
    return why;
  }
  if (NULL != (why = same("minivault memory", line(sek_stores(secrets)), "stores"))) {
    return why;
  }
  if (NULL != (why = same(sek_fmt(POOL, "minivault:%s memory", sek_vault_file(vault)),
                          line(sek_sources(secrets)), "sources"))) {
    return why;
  }
  if (NULL != (why = sek_get(secrets, "api.token", &found))) {
    return why;
  }
  if (NULL != (why = same("from the vault", found, "the vault"))) {
    return why;
  }
  if (NULL != (why = sek_get(secrets, "db.pass", &found))) {
    return why;
  }

  return same("from memory", found, "memory");
}

static const char *arestrictedkeyinachainfallsthrough(void) {
  const char *why;
  sek_minivault *vault = fresh(&why);
  sek_options *opts = chainopts();
  sek_sekreto *secrets = NULL;
  char *found = NULL;

  if (NULL != why) {
    return why;
  }
  if (NULL != (why = sek_vault_set(vault, "api.token", "from the vault"))) {
    return why;
  }
  if (NULL != (why = sek_vault_set(vault, "db.pass", "also in the vault"))) {
    return why;
  }
  if (NULL != (why = sek_vault_grant(vault, grantof("ci", "ci-passphrase", "api.token", 0)))) {
    return why;
  }

  opts->providers = chain2(vaultspec(sek_vault_file(vault), "ci", "ci-passphrase"),
                           memoryspec("DB_PASS", "from memory"));
  opts->count = 2;

  if (NULL != (why = sek_new(POOL, opts, &secrets))) {
    return why;
  }
  if (NULL != (why = sek_get(secrets, "api.token", &found))) {
    return why;
  }
  if (NULL != (why = same("from the vault", found, "the grant"))) {
    return why;
  }

  /* A NAME OUTSIDE THE GRANT IS A MISS, so the chain carries on rather
   * than stopping at a store that holds the name but not for this key. */
  if (NULL != (why = sek_get(secrets, "db.pass", &found))) {
    return why;
  }

  return same("from memory", found, "falls through");
}

static const char *thevaultbehindastoreisreachable(void) {
  const char *why;
  sek_minivault *vault = fresh(&why);
  sek_minivault *api = NULL;
  sek_options *opts = chainopts();
  sek_sekreto *secrets = NULL;
  sek_spec *chain;
  sek_list *names = NULL;
  char *found = NULL;

  if (NULL != why) {
    return why;
  }
  if (NULL != (why = sek_vault_set(vault, "api.token", "tok01"))) {
    return why;
  }

  chain = (sek_spec *)sek_alloc(POOL, sizeof(sek_spec));
  chain[0] = vaultspec(sek_vault_file(vault), NULL, MASTER);
  opts->providers = chain;
  opts->count = 1;

  if (NULL != (why = sek_new(POOL, opts, &secrets))) {
    return why;
  }
  if (NULL != (why = sek_vaultof(POOL, secrets, NULL, &api))) {
    return why;
  }
  if (NULL != (why = sek_vault_list(api, &names))) {
    return why;
  }
  if (NULL != (why = same("api.token", line(names), "list"))) {
    return why;
  }

  /* A CHAIN READS; the API writes. Both see the same file. */
  if (NULL != (why = sek_vault_set(api, "db.pass", "written through the api"))) {
    return why;
  }
  if (NULL != (why = sek_get(secrets, "db.pass", &found))) {
    return why;
  }

  return same("written through the api", found, "the chain");
}

static const char *anamedstoreisreachedbyname(void) {
  const char *why;
  sek_minivault *first = fresh(&why);
  sek_minivault *second;
  sek_minivault *held = NULL;
  sek_options *opts = chainopts();
  sek_sekreto *secrets = NULL;
  sek_spec app, ops;

  if (NULL != why) {
    return why;
  }
  second = fresh(&why);
  if (NULL != why) {
    return why;
  }

  app = vaultspec(sek_vault_file(first), NULL, MASTER);
  app.name = "app";
  ops = vaultspec(sek_vault_file(second), NULL, MASTER);
  ops.name = "ops";

  opts->providers = chain2(app, ops);
  opts->count = 2;

  if (NULL != (why = sek_new(POOL, opts, &secrets))) {
    return why;
  }
  if (NULL != (why = same("app ops", line(sek_stores(secrets)), "stores"))) {
    return why;
  }
  if (NULL != (why = sek_vaultof(POOL, secrets, "app", &held))) {
    return why;
  }
  if (NULL != (why = same(sek_vault_file(first), sek_vault_file(held), "app"))) {
    return why;
  }
  if (NULL != (why = sek_vaultof(POOL, secrets, "ops", &held))) {
    return why;
  }
  if (NULL != (why = same(sek_vault_file(second), sek_vault_file(held), "ops"))) {
    return why;
  }

  /* A STORE THAT IS NOT THERE REFUSES, and the alias does not stand in
   * for it: picking one would be a guess, and the guess writes. */
  return holds(refused(sek_vaultof(POOL, secrets, "nope", &held)),
               "no minivault store named nope in this chain", "a store that is not there");
}

static const char *achainwithnovaultsaysso(void) {
  const char *why;
  sek_options *opts = chainopts();
  sek_sekreto *secrets = NULL;
  sek_minivault *held = NULL;
  sek_spec *chain = (sek_spec *)sek_alloc(POOL, sizeof(sek_spec));

  chain[0] = memoryspec("API_TOKEN", "tok01");
  opts->providers = chain;
  opts->count = 1;

  if (NULL != (why = sek_new(POOL, opts, &secrets))) {
    return why;
  }

  return holds(refused(sek_vaultof(POOL, secrets, NULL, &held)),
               "no minivault store in this chain", "no vault");
}

static const char *achainmissingthefileisrefused(void) {
  const char *why;
  sek_options *opts = chainopts();
  sek_sekreto *secrets = NULL;
  sek_spec *chain = (sek_spec *)sek_alloc(POOL, sizeof(sek_spec));

  chain[0] = vaultspec(NULL, NULL, "p");
  opts->providers = chain;
  opts->count = 1;

  if (NULL != (why = holds(refused(sek_new(POOL, opts, &secrets)), "a vault needs a file",
                           "no file"))) {
    return why;
  }

  chain[0] = vaultspec("v.skmv", NULL, NULL);

  return holds(refused(sek_new(POOL, opts, &secrets)), "a vault needs a passphrase",
               "no passphrase");
}

static const char *thefileisreachedatthefirstlookup(void) {
  const char *why;
  sek_options *opts = chainopts();
  sek_sekreto *secrets = NULL;
  sek_spec *chain = (sek_spec *)sek_alloc(POOL, sizeof(sek_spec));
  char *found = NULL;

  /* The file does not exist, and building the chain still succeeds: the
   * handle is lazy, so a chain costs no PBKDF2 until a secret is
   * actually wanted. */
  chain[0] = vaultspec(sek_fmt(POOL, "%s/never.skmv", WORK), NULL, MASTER);
  opts->providers = chain;
  opts->count = 1;

  if (NULL != (why = sek_new(POOL, opts, &secrets))) {
    return why;
  }

  return holds(refused(sek_get(secrets, "api.token", &found)), "no vault file",
               "at the first lookup");
}

/* ---- the run ------------------------------------------------------- */

static void runcase(const char *name, checkfn check) {
  const char *failure;

  if (NULL != ONLY && 0 != strcmp(ONLY, name)) {
    return;
  }

  failure = check();

  if (NULL == failure) {
    PASSCOUNT++;
    printf("ok   - %s\n", name);
  } else {
    FAILCOUNT++;
    printf("FAIL - %s\n       %s\n", name, failure);
  }
}

int main(int argc, char **argv) {
  char template[] = "/tmp/sekreto-minivault-XXXXXX";
  sek_list *files;
  size_t at;

  POOL = sek_pool_new();

  if (1 < argc) {
    ONLY = argv[1];
  }

  if (NULL == mkdtemp(template)) {
    printf("cannot make a work directory\n");
    return 1;
  }
  WORK = sek_strdup(POOL, template);

  runcase("newvault", anewvaultholdsnothing);
  runcase("written", awrittensecretcomesback);
  runcase("binary", thefileisbinary);
  runcase("rewrite", rewritinganamereplacesit);
  runcase("remove", removedropsaname);
  runcase("badname", abadnameisrefused);
  runcase("restricted", arestrictedkeyreadsitsgrants);
  runcase("readonly", areadonlykeyrefusestowrite);
  runcase("ungranted", arestrictedkeycannotwriteanungrantedname);
  runcase("laternamed", agrantednamethatdoesnotexistyet);
  runcase("keys", themasterlistseverykey);
  runcase("masteronly", themasteronlymethodsrefusearestrictedkey);
  runcase("repeatedid", arepeatedkeyidisrefused);
  runcase("revoke", revokedropsakey);
  runcase("rotate", rotatekeepsthesecrets);
  runcase("wrongphrase", awrongpassphraseandamissingfile);
  runcase("damaged", adamagedfileisrefused);
  runcase("createover", creatingoveranexistingvaultisrefused);
  runcase("needsfile", avaultneedsafileandapassphrase);
  runcase("concurrent", twohandleswritingatoncelosenothing);
  runcase("emptykey", anemptykeymeansthemasterkey);
  runcase("createflag", createmakesthefileonlywhenasked);
  runcase("longkeyid", akeyidlongerthantheformatallows);
  runcase("infocopy", theinfoacallergetscannotchangewhatthekeymaydo);
  runcase("revokedcached", arevokedkeystopsreading);
  runcase("regranted", aregrantedkeyid);
  runcase("close", closeforgetsthederivedkeys);

  files = fixtures();
  if (0 == files->len) {
    printf("FAIL - fixtures\n       no committed vault was found\n");
    FAILCOUNT++;
  }
  for (at = 0; at < files->len; at++) {
    FIXTURE = files->items[at];
    runcase(sek_fmt(POOL, "fixture:%s", FIXTURE), readsthefixture);
  }

  runcase("chain", avaultisonestoreinachain);
  runcase("chainfallthrough", arestrictedkeyinachainfallsthrough);
  runcase("api", thevaultbehindastoreisreachable);
  runcase("namedstore", anamedstoreisreachedbyname);
  runcase("novault", achainwithnovaultsaysso);
  runcase("badconfig", achainmissingthefileisrefused);
  runcase("lazy", thefileisreachedatthefirstlookup);

  printf("\n%d passed, %d failed\n", PASSCOUNT, FAILCOUNT);

  return 0 == FAILCOUNT ? 0 : 1;
}
