/* A tiny app that needs a secret.
 *
 * It asks sekreto for `api.token` and calls the token-protected API with
 * it. Every port ships this same CLI, and test/integration.sh runs all of
 * them against the same server from every secret source - which is what
 * proves the library, rather than the spec alone.
 *
 * Usage: sekreto-cli <api-url> [--source <source>] [--store <name>]
 *
 * Sources: env dotenv file hashicorp boru boruwire awssecrets awsparams
 *          gcpsecrets azuresecrets onepassword doppler infisical
 *          secretspec chain
 *
 * Each source's configuration arrives in the environment variables its own
 * ecosystem already uses (VAULT_*, AWS_*, OP_CONNECT_*, ...), listed in
 * chainfor below.
 *
 * It runs from an EMPTY working directory with a wiped environment, so it
 * needs nothing on disk beside itself: a single statically-linked-against-
 * libsekreto binary, with only libssl, libcrypto and libc dynamic.
 */

#define _POSIX_C_SOURCE 200809L

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "../src/sekreto.h"

static const char *LANG = "c";

/* An environment value, treating empty as absent - which is what the
 * suite's `VAR=` means. */
static const char *env(const char *name) {
  const char *value = getenv(name);
  return NULL == value || '\0' == value[0] ? NULL : value;
}

static const char *envor(const char *name, const char *fallback) {
  const char *value = env(name);
  return NULL == value ? fallback : value;
}

/* The value of a `--flag value` pair, or "" when the flag is absent.
 * Found by index, with no argument-parsing library: the contract is four
 * fixed shapes and nothing more. */
static const char *flag(int argc, char **argv, const char *name) {
  int index;

  for (index = 1; index < argc; index++) {
    if (0 == strcmp(argv[index], name)) {
      return index + 1 < argc ? argv[index + 1] : "";
    }
  }

  return "";
}

static size_t chainfor(sek_pool *pool, const char *source, sek_spec *specs) {
  sek_spec envspec = sek_spec_new("env");
  sek_spec dotenvspec = sek_spec_new("dotenv");
  sek_spec filespec = sek_spec_new("file");
  sek_spec hashicorpspec = sek_spec_new("hashicorp");
  sek_spec boruspec = sek_spec_new("boru");
  sek_spec boruwirespec = sek_spec_new("boru");
  sek_spec awssecretsspec = sek_spec_new("awssecrets");
  sek_spec awsparamsspec = sek_spec_new("awsparams");
  sek_spec gcpspec = sek_spec_new("gcpsecrets");
  sek_spec azurespec = sek_spec_new("azuresecrets");
  sek_spec onepasswordspec = sek_spec_new("onepassword");
  sek_spec dopplerspec = sek_spec_new("doppler");
  sek_spec infisicalspec = sek_spec_new("infisical");
  sek_spec secretspecspec = sek_spec_new("secretspec");

  (void)pool;

  envspec.prefix = env("SEKRETO_PREFIX");

  dotenvspec.file = envor("SEKRETO_DOTENV", ".env");

  filespec.dir = envor("SEKRETO_FILEDIR", "/run/secrets");

  hashicorpspec.addr = envor("VAULT_ADDR", "");
  hashicorpspec.token = envor("VAULT_TOKEN", "");
  hashicorpspec.mount = env("VAULT_MOUNT");
  if (NULL != env("VAULT_KV")) {
    hashicorpspec.kv = (int)strtol(env("VAULT_KV"), NULL, 10);
    hashicorpspec.haskv = 1;
  }
  hashicorpspec.vaultnamespace = env("VAULT_NAMESPACE");
  if (NULL != env("VAULT_AUTH")) {
    static sek_authspec auth;
    memset(&auth, 0, sizeof(auth));
    auth.method = env("VAULT_AUTH");
    auth.role = env("VAULT_ROLE");
    auth.jwtfile = env("VAULT_JWT_FILE");
    auth.roleid = env("VAULT_ROLE_ID");
    auth.secretid = env("VAULT_SECRET_ID");
    hashicorpspec.auth = &auth;
  }

  boruspec.command = envor("BORU_COMMAND", "boru");
  boruspec.namespace_ = env("BORU_NAMESPACE");
  boruspec.home = env("BORU_HOME");

  /* The same vault over its wire protocol (`boru vault serve`) instead of
   * the CLI: an address plus a capability token from `vault grant`. */
  boruwirespec.addr = envor("BORU_ADDR", "");
  boruwirespec.token = envor("BORU_TOKEN", "");
  boruwirespec.namespace_ = env("BORU_NAMESPACE");

  awssecretsspec.region = env("AWS_REGION");
  awssecretsspec.addr = env("AWS_ENDPOINT");

  awsparamsspec.region = env("AWS_REGION");
  awsparamsspec.addr = env("AWS_ENDPOINT");
  awsparamsspec.prefix = env("AWS_PARAM_PREFIX");

  gcpspec.project = env("GCP_PROJECT");
  gcpspec.addr = env("GCP_ADDR");
  gcpspec.metadataaddr = env("GCP_METADATA_ADDR");

  azurespec.vault = env("AZURE_VAULT");
  azurespec.token = env("AZURE_TOKEN");
  azurespec.tenant = env("AZURE_TENANT");
  azurespec.clientid = env("AZURE_CLIENT_ID");
  azurespec.clientsecret = env("AZURE_CLIENT_SECRET");
  azurespec.loginaddr = env("AZURE_LOGIN_ADDR");
  azurespec.imdsaddr = env("AZURE_IMDS_ADDR");

  onepasswordspec.addr = env("OP_CONNECT_HOST");
  onepasswordspec.token = env("OP_CONNECT_TOKEN");
  onepasswordspec.vault = env("OP_VAULT");

  dopplerspec.token = env("DOPPLER_TOKEN");
  dopplerspec.project = env("DOPPLER_PROJECT");
  dopplerspec.config = env("DOPPLER_CONFIG");
  dopplerspec.addr = env("DOPPLER_ADDR");

  infisicalspec.addr = env("INFISICAL_ADDR");
  infisicalspec.token = env("INFISICAL_TOKEN");
  infisicalspec.clientid = env("INFISICAL_CLIENT_ID");
  infisicalspec.clientsecret = env("INFISICAL_CLIENT_SECRET");
  infisicalspec.project = env("INFISICAL_PROJECT");
  infisicalspec.environment = env("INFISICAL_ENV");
  infisicalspec.path = env("INFISICAL_PATH");

  /* SecretSpec's own environment variables where it has them
   * (SECRETSPEC_FILE, _PROFILE, _PROVIDER, _REASON are read by the
   * secretspec CLI itself), so a shell already set up for secretspec needs
   * nothing further. */
  secretspecspec.command = envor("SECRETSPEC_COMMAND", "secretspec");
  secretspecspec.file = env("SECRETSPEC_FILE");
  secretspecspec.profile = env("SECRETSPEC_PROFILE");
  secretspecspec.backend = env("SECRETSPEC_PROVIDER");
  secretspecspec.reason = env("SECRETSPEC_REASON");

  if (0 == strcmp(source, "env")) {
    specs[0] = envspec;
    return 1;
  }
  if (0 == strcmp(source, "dotenv")) {
    specs[0] = dotenvspec;
    return 1;
  }
  if (0 == strcmp(source, "file")) {
    specs[0] = filespec;
    return 1;
  }
  if (0 == strcmp(source, "hashicorp")) {
    specs[0] = hashicorpspec;
    return 1;
  }
  if (0 == strcmp(source, "boru")) {
    specs[0] = boruspec;
    return 1;
  }
  if (0 == strcmp(source, "boruwire")) {
    specs[0] = boruwirespec;
    return 1;
  }
  if (0 == strcmp(source, "awssecrets")) {
    specs[0] = awssecretsspec;
    return 1;
  }
  if (0 == strcmp(source, "awsparams")) {
    specs[0] = awsparamsspec;
    return 1;
  }
  if (0 == strcmp(source, "gcpsecrets")) {
    specs[0] = gcpspec;
    return 1;
  }
  if (0 == strcmp(source, "azuresecrets")) {
    specs[0] = azurespec;
    return 1;
  }
  if (0 == strcmp(source, "onepassword")) {
    specs[0] = onepasswordspec;
    return 1;
  }
  if (0 == strcmp(source, "doppler")) {
    specs[0] = dopplerspec;
    return 1;
  }
  if (0 == strcmp(source, "infisical")) {
    specs[0] = infisicalspec;
    return 1;
  }
  if (0 == strcmp(source, "secretspec")) {
    specs[0] = secretspecspec;
    return 1;
  }

  /* The default: the chain an app would actually ship with - local
   * overrides first, shared vaults last. */
  specs[0] = envspec;
  specs[1] = dotenvspec;
  specs[2] = hashicorpspec;
  specs[3] = boruspec;

  return 4;
}

/* The API call. Not sek_http: that is the library's private transport,
 * and the CLI is a consumer like any other. This is the same handful of
 * lines every port's CLI writes against its own HTTP client - here, one
 * plain GET over a socket. */
static int callapi(sek_pool *pool, const char *url, const char *token, int *status,
                   char **body) {
  sek_map *headers = sek_map_new(pool);
  sek_spec probe;

  (void)probe;

  sek_map_set(headers, "Authorization", sek_fmt(pool, "Bearer %s", token));
  sek_map_set(headers, "X-Sekreto-Lang", LANG);

  return sek_cli_fetch(pool, url, headers, status, body);
}

int main(int argc, char **argv) {
  sek_pool *pool = sek_pool_new();
  const char *url = 1 < argc && '-' != argv[1][0] ? argv[1] : "http://127.0.0.1:8099/whoami";
  const char *source = flag(argc, argv, "--source");
  const char *store = flag(argc, argv, "--store");
  sek_spec specs[4];
  size_t count;
  sek_sekreto *secrets = NULL;
  sek_err err;
  char *token = NULL;
  int status = 0;
  char *body = NULL;
  sek_buf line;
  const char *caller;

  if ('\0' == source[0]) {
    source = "chain";
  }

  memset(specs, 0, sizeof(specs));
  count = chainfor(pool, source, specs);

  err = sek_sekreto_of(pool, specs, count, 1, &secrets);
  if (NULL != err) {
    /* A construction failure is still "the secret could not be
     * obtained", which is exit 2. */
    fprintf(stderr, "sekreto-cli: %s\n", err);
    sek_pool_free(pool);
    return 2;
  }

  /* --store names a store outright: the secret must come from that one,
   * not from whichever provider happens to answer first. An unknown store
   * raises, and one integration check depends on that. */
  if ('\0' == store[0]) {
    err = sek_get(secrets, "api.token", &token);
  } else {
    err = sek_getfrom(secrets, store, "api.token", &token);
  }

  if (NULL != err) {
    fprintf(stderr, "sekreto-cli: %s\n", sek_redact_text(secrets, err));
    sek_pool_free(pool);
    return 2;
  }

  if (0 != callapi(pool, url, token, &status, &body)) {
    /* Every failure path is redacted: the suite greps stdout AND stderr
     * on both the pass and the fail path, and a leak fails the check
     * whatever the exit code was. */
    fprintf(stderr, "sekreto-cli: %s\n", sek_redact_text(secrets, body));
    sek_pool_free(pool);
    return 1;
  }

  if (200 != status) {
    fprintf(stderr, "sekreto-cli: %s\n", sek_redact_text(secrets, body));
    sek_pool_free(pool);
    return 1;
  }

  caller = sek_json_text(pool, sek_json_dig(sek_json_parse(pool, body), "caller", NULL));

  /* Assembled field by field, in the spec's order. Printing a map here is
   * what has bitten port after port: the language's own key order is not
   * the one every other port prints. */
  sek_buf_init(&line, pool);
  sek_buf_add(&line, "{\"ok\":true");
  sek_buf_addfmt(&line, ",\"lang\":%s", sek_json_quote(pool, LANG));
  sek_buf_addfmt(&line, ",\"source\":%s", sek_json_quote(pool, source));
  sek_buf_addfmt(&line, ",\"store\":%s", sek_json_quote(pool, store));
  sek_buf_addfmt(&line, ",\"caller\":%s",
                 NULL == caller ? "null" : sek_json_quote(pool, caller));
  sek_buf_add(&line, "}");

  printf("%s\n", line.data);

  sek_pool_free(pool);

  return 0;
}
