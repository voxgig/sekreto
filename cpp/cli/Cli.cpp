// A tiny app that needs a secret.
//
// It asks sekreto for `api.token` and calls the token-protected API with
// it. Every port ships this same CLI, and test/integration.sh runs all of
// them against the same server from every secret source - which is what
// proves the library, rather than the spec alone.
//
// Usage: sekreto-cli <api-url> [--source <source>] [--store <name>]
//
// Sources: env dotenv file hashicorp boru boruwire awssecrets awsparams
//          gcpsecrets azuresecrets onepassword doppler infisical
//          secretspec chain
//
// Each source's configuration arrives in the environment variables its own
// ecosystem already uses (VAULT_*, AWS_*, OP_CONNECT_*, ...), listed in
// chainfor below.

#include <cstdlib>
#include <iostream>
#include <string>
#include <vector>

#include "Http.hpp"
#include "Json.hpp"
#include "Providers.hpp"
#include "Sekreto.hpp"

namespace {

const char* const LANG = "cpp";

using sekreto::Json;
using sekreto::Ordered;
using sekreto::ProviderSpec;

/// An environment variable, or "". An empty value is treated as absent:
/// every port does, so a variable exported blank is the same as one never
/// set.
std::string envvar(const std::string& name) {
  const char* value = std::getenv(name.c_str());
  return (nullptr == value) ? "" : value;
}

std::string envor(const std::string& name, const std::string& fallback) {
  std::string value = envvar(name);
  return value.empty() ? fallback : value;
}

std::vector<ProviderSpec> chainfor(const std::string& source) {
  ProviderSpec envspec;
  envspec.kind = "env";
  envspec.prefix = envvar("SEKRETO_PREFIX");

  ProviderSpec dotenvspec;
  dotenvspec.kind = "dotenv";
  dotenvspec.file = envor("SEKRETO_DOTENV", ".env");

  ProviderSpec filespec;
  filespec.kind = "file";
  filespec.dir = envor("SEKRETO_FILEDIR", "/run/secrets");

  ProviderSpec hashicorpspec;
  hashicorpspec.kind = "hashicorp";
  hashicorpspec.addr = envvar("VAULT_ADDR");
  hashicorpspec.token = envvar("VAULT_TOKEN");
  hashicorpspec.mount = envvar("VAULT_MOUNT");
  hashicorpspec.vaultnamespace = envvar("VAULT_NAMESPACE");

  std::string kv = envvar("VAULT_KV");
  if (!kv.empty()) hashicorpspec.kv = std::atoi(kv.c_str());

  std::string method = envvar("VAULT_AUTH");
  if (!method.empty()) {
    sekreto::AuthSpec auth;
    auth.method = method;
    auth.role = envvar("VAULT_ROLE");
    auth.jwtfile = envvar("VAULT_JWT_FILE");
    auth.roleid = envvar("VAULT_ROLE_ID");
    auth.secretid = envvar("VAULT_SECRET_ID");
    hashicorpspec.auth = auth;
  }

  ProviderSpec boruspec;
  boruspec.kind = "boru";
  boruspec.command = envor("BORU_COMMAND", "boru");
  boruspec.namespace_ = envvar("BORU_NAMESPACE");
  boruspec.home = envvar("BORU_HOME");

  // The same vault over its wire protocol (`boru vault serve`) instead of
  // the CLI: an address plus a capability token from `vault grant`.
  ProviderSpec boruwirespec;
  boruwirespec.kind = "boru";
  boruwirespec.addr = envvar("BORU_ADDR");
  boruwirespec.token = envvar("BORU_TOKEN");
  boruwirespec.namespace_ = envvar("BORU_NAMESPACE");

  ProviderSpec awssecretsspec;
  awssecretsspec.kind = "awssecrets";
  awssecretsspec.addr = envvar("AWS_ENDPOINT");
  awssecretsspec.region = envvar("AWS_REGION");

  ProviderSpec awsparamsspec;
  awsparamsspec.kind = "awsparams";
  awsparamsspec.prefix = envvar("AWS_PARAM_PREFIX");
  awsparamsspec.addr = envvar("AWS_ENDPOINT");
  awsparamsspec.region = envvar("AWS_REGION");

  ProviderSpec gcpspec;
  gcpspec.kind = "gcpsecrets";
  gcpspec.addr = envvar("GCP_ADDR");
  gcpspec.project = envvar("GCP_PROJECT");
  gcpspec.metadataaddr = envvar("GCP_METADATA_ADDR");

  ProviderSpec azurespec;
  azurespec.kind = "azuresecrets";
  azurespec.token = envvar("AZURE_TOKEN");
  azurespec.vault = envvar("AZURE_VAULT");
  azurespec.tenant = envvar("AZURE_TENANT");
  azurespec.clientid = envvar("AZURE_CLIENT_ID");
  azurespec.clientsecret = envvar("AZURE_CLIENT_SECRET");
  azurespec.loginaddr = envvar("AZURE_LOGIN_ADDR");
  azurespec.imdsaddr = envvar("AZURE_IMDS_ADDR");

  ProviderSpec onepasswordspec;
  onepasswordspec.kind = "onepassword";
  onepasswordspec.addr = envvar("OP_CONNECT_HOST");
  onepasswordspec.token = envvar("OP_CONNECT_TOKEN");
  onepasswordspec.vault = envvar("OP_VAULT");

  ProviderSpec dopplerspec;
  dopplerspec.kind = "doppler";
  dopplerspec.addr = envvar("DOPPLER_ADDR");
  dopplerspec.token = envvar("DOPPLER_TOKEN");
  dopplerspec.project = envvar("DOPPLER_PROJECT");
  dopplerspec.config = envvar("DOPPLER_CONFIG");

  ProviderSpec infisicalspec;
  infisicalspec.kind = "infisical";
  infisicalspec.addr = envvar("INFISICAL_ADDR");
  infisicalspec.token = envvar("INFISICAL_TOKEN");
  infisicalspec.project = envvar("INFISICAL_PROJECT");
  infisicalspec.clientid = envvar("INFISICAL_CLIENT_ID");
  infisicalspec.clientsecret = envvar("INFISICAL_CLIENT_SECRET");
  infisicalspec.environment = envvar("INFISICAL_ENV");
  infisicalspec.path = envvar("INFISICAL_PATH");

  // SecretSpec's own environment variables where it has them
  // (SECRETSPEC_FILE, _PROFILE, _PROVIDER, _REASON are read by the
  // secretspec CLI itself), so a shell already set up for secretspec needs
  // nothing further.
  ProviderSpec secretspecspec;
  secretspecspec.kind = "secretspec";
  secretspecspec.file = envvar("SECRETSPEC_FILE");
  secretspecspec.command = envor("SECRETSPEC_COMMAND", "secretspec");
  secretspecspec.profile = envvar("SECRETSPEC_PROFILE");
  secretspecspec.backend = envvar("SECRETSPEC_PROVIDER");
  secretspecspec.reason = envvar("SECRETSPEC_REASON");

  if ("env" == source) return {envspec};
  if ("dotenv" == source) return {dotenvspec};
  if ("file" == source) return {filespec};
  if ("hashicorp" == source) return {hashicorpspec};
  if ("boru" == source) return {boruspec};
  if ("boruwire" == source) return {boruwirespec};
  if ("awssecrets" == source) return {awssecretsspec};
  if ("awsparams" == source) return {awsparamsspec};
  if ("gcpsecrets" == source) return {gcpspec};
  if ("azuresecrets" == source) return {azurespec};
  if ("onepassword" == source) return {onepasswordspec};
  if ("doppler" == source) return {dopplerspec};
  if ("infisical" == source) return {infisicalspec};
  if ("secretspec" == source) return {secretspecspec};

  // The default: the chain an app would actually ship with - local
  // overrides first, shared vaults last.
  return {envspec, dotenvspec, hashicorpspec, boruspec};
}

/// The value of a `--flag value` pair, or "" when the flag is absent.
/// Found by index, because an argument-parsing library is a dependency.
std::string flag(const std::vector<std::string>& args, const std::string& name) {
  for (size_t index = 0; index + 1 < args.size(); index++) {
    if (name == args[index]) return args[index + 1];
  }
  return "";
}

}  // namespace

int main(int argc, char** argv) {
  std::vector<std::string> args;
  for (int index = 1; index < argc; index++) {
    args.push_back(argv[index]);
  }

  std::string url = args.empty() ? "http://127.0.0.1:8099/whoami" : args[0];

  std::string named = flag(args, "--source");
  std::string source = named.empty() ? "chain" : named;

  // --store names a store outright: the secret must come from that one,
  // not from whichever provider happens to answer first. getfrom
  // semantics, so an unknown store is an error.
  std::string store = flag(args, "--store");

  std::vector<sekreto::ProviderSpec> chain = chainfor(source);

  try {
    sekreto::Sekreto secrets = sekreto::makesekreto(chain);

    std::string token;

    try {
      token = store.empty() ? secrets.get("api.token") : secrets.getfrom(store, "api.token");
    } catch (const std::exception& err) {
      // Routed through redact like every other failure path: a chain that
      // answered from one store and then failed in another must not put
      // the value it did resolve into a diagnostic.
      std::cerr << "sekreto-cli: " << secrets.redact(err.what()) << "\n";
      return 2;
    }

    sekreto::Ordered headers;
    headers.set("Authorization", "Bearer " + token);
    headers.set("X-Sekreto-Lang", LANG);

    sekreto::Response res;

    try {
      res = sekreto::httprequest("GET", url, headers, std::nullopt);
    } catch (const std::exception& err) {
      // Never print the token itself, even when the call fails.
      std::cerr << "sekreto-cli: " << secrets.redact(err.what()) << "\n";
      return 1;
    }

    if (200 != res.status) {
      std::cerr << "sekreto-cli: " << secrets.redact(res.body) << "\n";
      return 1;
    }

    Json body;
    Json::parse(res.body, body);
    Json caller = body.get("caller");

    // Assembled field by field, in the spec's order. Printing a map here
    // is what has bitten port after port: the language's own key order is
    // not the one every other port prints.
    std::string line = "{\"ok\":true";
    line += ",\"lang\":" + Json::quote(LANG);
    line += ",\"source\":" + Json::quote(source);
    line += ",\"store\":" + Json::quote(store);
    line += ",\"caller\":" + Json::stringify(caller);
    line += "}";

    std::cout << line << "\n";

    return 0;
  } catch (const std::exception& err) {
    // A construction failure: nothing has been resolved yet, so there is
    // nothing to redact.
    std::cerr << "sekreto-cli: " << err.what() << "\n";
    return 2;
  }
}
