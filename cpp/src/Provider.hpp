// A source of secrets.
//
// A provider answers one question: "do you have this secret?" It returns
// the value, or nothing to mean "ask the next one". Nothing else about a
// provider is visible to the caller - which is the point: an app reads
// `api.token` and never learns whether it came from the environment, a
// .env file, HashiCorp Vault or a boru vault.
//
// A MISS is `std::nullopt` and a FAILURE is a thrown SekretoError. They
// are never interchangeable: a store that could not answer must not read
// as a store that does not hold the secret, or the chain falls quietly
// through to a weaker one.

#ifndef SEKRETO_PROVIDER_HPP
#define SEKRETO_PROVIDER_HPP

#include <optional>
#include <string>

namespace sekreto {

class Provider {
 public:
  virtual ~Provider() = default;

  /// The value, or nothing if this provider does not have it. May throw
  /// SekretoError when the store could not answer at all.
  virtual std::optional<std::string> lookup(const std::string& name) = 0;

  /// A short description, shown by `Sekreto::sources()`.
  virtual std::string describe() const = 0;
};

}  // namespace sekreto

#endif
