// A CONSUMER OF THE CORE AND NOTHING ELSE - the boundary as a link line.
//
// `make check-core` builds this against build/libsekreto.a and
// build/libvoxgigplugin.a with NO -lssl, NO -lcrypto and NO plugins
// archive. If one object in the core needed a socket, a child process or a
// digest, this link would fail and name the symbol.
//
// It is the claim itself, not a proxy for it: this is exactly what an app
// whose chain is `[dotenv, env]` links, and the whole point of the split is
// that such an app carries no vault client and no TLS library.
//
// The negative control is next to it in the Makefile: the same program plus
// build/libsekretoplugins.a must NOT link without OpenSSL. Without that,
// "it linked" would only mean the link line asked for nothing.

#include <iostream>

#include "Providers.hpp"
#include "Sekreto.hpp"

int main() {
  sekreto::ProviderSpec values;
  values.kind = "memory";
  values.values.set("API_TOKEN", "tok01");

  sekreto::ProviderSpec fromenv;
  fromenv.kind = "env";

  sekreto::ProviderSpec dotenv;
  dotenv.kind = "dotenv";
  dotenv.file = "/nonexistent-sekreto-test/.env";

  sekreto::ProviderSpec fromdir;
  fromdir.kind = "file";
  fromdir.dir = "/nonexistent-sekreto-test";

  // No `plugins` argument at all: the four built-ins are what a Sekreto can
  // always build.
  sekreto::Sekreto secrets = sekreto::makesekreto({values, fromenv, dotenv, fromdir});

  const std::string token = secrets.get("api.token");

  if ("tok01" != token) {
    std::cerr << "coreonly: got " << token << "\n";
    return 1;
  }

  if (4 != secrets.stores().size()) {
    std::cerr << "coreonly: " << secrets.stores().size() << " stores\n";
    return 1;
  }

  // ...and a kind that was not passed in is refused rather than built.
  sekreto::ProviderSpec vault;
  vault.kind = "hashicorp";
  vault.addr = "https://vault.example.com";
  vault.token = "t";

  try {
    sekreto::makesekreto({vault});
    std::cerr << "coreonly: hashicorp was built with no plugin\n";
    return 1;
  } catch (const sekreto::SekretoError&) {
    // As it should be.
  }

  std::cout << "coreonly: a chain of built-ins, linked without OpenSSL\n";
  return 0;
}
