// sekreto: one interface for secrets, wherever they live.
//
// A Sekreto is an ordered chain of providers. `get` asks each in turn and
// returns the first hit, so an app can be configured from environment
// variables in development and a vault in production without changing a
// line of its own code.
//
// A port of typescript/src/Sekreto.ts, which is canonical.

#ifndef SEKRETO_SEKRETO_HPP
#define SEKRETO_SEKRETO_HPP

#include <memory>
#include <optional>
#include <stdexcept>
#include <string>
#include <utility>
#include <vector>

#include "Json.hpp"
#include "Provider.hpp"

namespace sekreto {

/// A secret name: dot-separated lowercase segments, e.g. `api.token`.
using Name = std::string;

/// Anything sekreto refuses to do: a bad name, a missing secret, a
/// provider that could not be reached.
///
/// The message is the whole contract - no code, no fields, no cause - and
/// the shared spec pins it byte for byte.
class SekretoError : public std::runtime_error {
 public:
  explicit SekretoError(const std::string& message) : std::runtime_error(message) {}
};

/// An insertion-ordered string map.
///
/// `std::map` orders by key and `std::unordered_map` by nothing at all;
/// the spec compares whole maps, and a signed AWS payload's field order is
/// part of what was signed. So this is a vector of pairs.
class Ordered {
 public:
  std::vector<std::pair<std::string, std::string>> pairs;

  bool has(const std::string& key) const;
  /// The value, or nothing. Absence is nothing; an empty string is a value.
  std::optional<std::string> get(const std::string& key) const;
  /// Insert, or overwrite in place so the original position is kept.
  void set(const std::string& key, const std::string& value);
  bool empty() const { return pairs.empty(); }
};

/// Uppercase and lowercase the ASCII letters and nothing else. The C
/// library's `toupper` is locale-sensitive, and envkey must answer the
/// same in every locale on every port.
std::string asciiupper(const std::string& text);
std::string asciilower(const std::string& text);

/// Split on the literal dot, KEEPING empties, so `a.` is two segments (one
/// of them empty) and therefore not a valid name.
std::vector<std::string> segments(const std::string& name);

/// Is this a well-formed secret name?
bool validname(const std::string& name);
/// The same, for whatever a caller passed: anything that is not a string
/// is not a name. Never raises.
bool validname(const Json& name);

/// The name, or a SekretoError. Every entry point checks its name here.
Name checkname(const std::string& name);
Name checkname(const Json& name);

/// The environment-variable key for a name: `api.token` -> `API_TOKEN`.
/// The prefix is used verbatim, and is NOT uppercased.
std::string envkey(const std::string& name, const std::string& prefix = "");

/// Where a name lives in a KV vault.
struct VaultRef {
  std::string path;
  std::string field;
};

/// `api.token` -> `api` / `token`. A single-segment name has no path of
/// its own, so it becomes a secret of that name with the field `value`.
VaultRef vaultref(const std::string& name);

/// A name flattened to one segment: `api.token` -> `api_token` (GCP) or
/// `api-token` (Azure). With `-`, underscores flatten too, because Key
/// Vault's alphabet is letters, digits and hyphens only.
std::string flatname(const std::string& name, const std::string& sep);

/// The AWS SSM Parameter Store name: `db.pass.main` -> `/db/pass/main`,
/// or `/app/db/pass/main` under prefix `app`.
std::string awsparam(const std::string& name, const std::string& prefix = "");

/// Parse `.env` text into raw keys and values. There is no `.env`
/// standard, so this function is the specification; see the source.
Ordered parsedotenv(const std::string& text);
Ordered parsedotenv(const Json& text);

/// Replace known secret values in text with `[redacted]`. Only values of
/// four characters or more: shorter ones are too likely to appear in
/// ordinary text, and redacting them would make logs unreadable without
/// making them safer.
std::string redact(const std::string& text, const std::vector<std::string>& values);

/// The store name a provider answers to when nothing says otherwise:
/// `describe()` up to the first `:`.
std::string storename(const Provider& provider);

/// The secrets facade: a chain of providers plus a cache.
///
/// Two ways to read. `get` is transparent - it walks the chain and takes
/// the first hit, and the caller never learns which store answered.
/// `getfrom` is directed - it names the store, and only that store is
/// asked.
class Sekreto {
 public:
  Sekreto(std::vector<std::shared_ptr<Provider>> providers,
          std::vector<std::string> names, bool docache = true);

  /// The secret, or a SekretoError if no provider has it.
  std::string get(const Name& name);
  /// The secret, or nothing. Named `tryget` because `try` is a keyword.
  std::optional<std::string> tryget(const Name& name);
  /// The secret from one named store, or a SekretoError.
  std::string getfrom(const std::string& store, const Name& name);
  /// The secret from one named store, or nothing. Naming a store that is
  /// not in the chain is an error, not a miss.
  std::optional<std::string> tryfrom(const std::string& store, const Name& name);

  bool has(const Name& name);
  bool hasin(const std::string& store, const Name& name);
  /// Every named secret at once. Missing ones are an error.
  Ordered all(const std::vector<Name>& names);

  /// A description of each provider, in resolution order.
  std::vector<std::string> sources() const;
  /// The name of each store `getfrom` can address, in order, deduped.
  std::vector<std::string> stores() const;

  /// Replace every value this Sekreto has resolved with `[redacted]`.
  std::string redact(const std::string& text) const;

  /// Drop cached values, so the next `get` asks the providers again.
  void refresh();
  /// Tear the chain down. Afterwards nothing resolves - but redaction
  /// still knows every value ever resolved.
  void close();

  /// Printed without its secrets. `cache` and `seen` are ordinary fields,
  /// so a derived printer would put every resolved secret into whatever
  /// formatted it. Note the literal spacing: an empty chain prints
  /// `Sekreto { stores: [  ] }`.
  std::string str() const;
  /// The same, as data: the store names and nothing else.
  Json tojson() const;

 private:
  struct Entry {
    std::string store;
    std::shared_ptr<Provider> provider;
  };

  struct Cached {
    std::string store;
    Name name;
    std::string value;
  };

  std::optional<std::string> resolve(const std::string& store, const Name& name,
                                     const std::vector<Entry>& useentries);

  std::vector<Entry> entries_;
  // A list, not a map: the store a value came from stays attached, and
  // redaction order does not vary between runs.
  std::vector<Cached> cache_;
  // Every value ever resolved, for redact(). Kept independently of the
  // read cache, so `cache: false` does not silently disable redaction.
  // Append-only for the object's life: neither refresh() nor close()
  // clears it.
  std::vector<std::string> seen_;
  bool docache_;
};

}  // namespace sekreto

#endif
