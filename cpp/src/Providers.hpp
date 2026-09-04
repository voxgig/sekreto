// The providers a Sekreto chains together.
//
// Two failure shapes, and they are never interchangeable. A store that
// does not hold the secret is a MISS (`std::nullopt`) - the chain carries
// on. A store that could not answer - bad credentials, unreachable host,
// missing configuration - throws a SekretoError, because falling through
// there would quietly reach for a weaker store.
//
// A port of typescript/src/Providers.ts, which is canonical.

#ifndef SEKRETO_PROVIDERS_HPP
#define SEKRETO_PROVIDERS_HPP

#include <memory>
#include <optional>
#include <string>
#include <vector>

#include "Json.hpp"
#include "Provider.hpp"
#include "Sekreto.hpp"

namespace sekreto {

/// Logging in to a vault instead of being handed a token. `method` is
/// `kubernetes` or `approle`; `mount` defaults to the method name.
struct AuthSpec {
  std::string method;
  std::string mount;
  /// kubernetes: the Vault role to log in as.
  std::string role;
  /// kubernetes: the service-account JWT itself (tests).
  std::string jwt;
  /// kubernetes: where the JWT lives; the conventional pod path by default.
  std::string jwtfile;
  /// approle: the role and secret ids.
  std::string roleid;
  std::string secretid;

  /// Printed without its credentials. A derived printer would put the
  /// service-account JWT and the AppRole secret id into
  /// `log("bad chain: " + spec)`, which is what someone writes when a
  /// chain will not build.
  std::string str() const;
};

/// The declarative form of a provider, as used in config and in the shared
/// spec. `kind` picks the provider; everything else is that kind's own.
///
/// String fields default to the empty string rather than to an optional:
/// "not configured" and "configured empty" mean the same thing everywhere
/// in this library.
struct ProviderSpec {
  std::string kind;
  /// The store name `Sekreto::getfrom` addresses. Defaults to `kind`.
  std::string name;
  std::string prefix;
  /// dotenv: the file to read. secretspec: the declaration to read.
  std::string file;
  /// memory: literal values, keyed like environment variables.
  Ordered values;
  /// file: the directory of one-secret-per-file entries.
  std::string dir;
  /// hashicorp / boru (wire) / gcp / 1password / doppler / infisical: the base URL.
  std::string addr;
  /// hashicorp / boru (wire) / gcp / azure / 1password / doppler / infisical: the token.
  std::string token;
  /// hashicorp / boru (wire): the KV mount (default `secret`).
  std::string mount;
  /// hashicorp: KV engine version, 1 or 2 (default 2).
  std::optional<int> kv;
  /// hashicorp: Vault Enterprise namespace (X-Vault-Namespace).
  std::string vaultnamespace;
  /// hashicorp: log in for a token instead of being handed one.
  std::optional<AuthSpec> auth;
  /// boru / secretspec: the executable to run.
  std::string command;
  /// secretspec: the profile to read (`--profile`).
  std::string profile;
  /// secretspec: which of ITS backends to read from (`--provider`). Named
  /// `backend` here because `provider` already means a sekreto provider.
  std::string backend;
  /// secretspec: the audit reason recorded for the read (`--reason`).
  std::string reason;
  /// boru: the namespace qualifying the alias.
  std::string namespace_;
  /// boru: the vault home, passed as BORU_HOME.
  std::string home;
  /// aws: region and credentials; the standard AWS_* variables fill the rest.
  std::string region;
  std::string keyid;
  std::string secret;
  std::string session;
  /// gcp / doppler / infisical: the project, however that store names it.
  std::string project;
  /// azure: the Key Vault name or full URL. 1password: the vault name or id.
  std::string vault;
  /// azure: client-credential login. infisical: universal-auth login.
  std::string tenant;
  std::string clientid;
  std::string clientsecret;
  /// azure: where to log in / where IMDS answers. gcp: the metadata server.
  std::string loginaddr;
  std::string imdsaddr;
  std::string metadataaddr;
  /// azure: the Key Vault API version (default 7.4).
  std::string apiversion;
  /// doppler: the config slug (with `project`).
  std::string config;
  /// infisical: the environment slug and secret path.
  std::string environment;
  std::string path;

  /// Printed without its credentials. See AuthSpec::str.
  std::string str() const;
};

/// An address with any userinfo replaced by `[redacted]`, for messages.
std::string safeaddr(const std::string& addr);

/// Refuse to send a secret-bearing credential in the clear, and refuse an
/// address this library will not dial. Raises; answers nothing otherwise.
void checkaddr(const std::string& addr);

/// The first candidate that is non-empty, or the empty string.
std::string first(const std::string& one, const std::string& two);
std::string first(const std::string& one, const std::string& two, const std::string& three);

/// Does this boru failure mean "no such secret" rather than "I could not
/// answer"?
bool borumiss(const std::string& why);

/// Does this SecretSpec failure mean "no such secret"? Matched on the
/// WHOLE phrase, key included.
bool secretspecmiss(const std::string& why, const std::string& key);

/// Build a provider from its declarative form.
std::shared_ptr<Provider> makeprovider(const ProviderSpec& spec);

/// Make a Sekreto from declarative provider specs - the same shape the
/// shared spec and an app's config file use.
///
/// Eager and in chain order, so a chain that cannot be built says so at
/// once. Construction contacts nothing: the first network call is the
/// first lookup.
Sekreto makesekreto(const std::vector<ProviderSpec>& specs, bool cache = true);

}  // namespace sekreto

#endif
