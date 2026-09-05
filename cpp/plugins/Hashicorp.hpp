// HashiCorp Vault, over its HTTP API.
//
// A PLUGIN, not a built-in: this kind opens a socket, signs a request or
// spawns a process, so a chain that does not name it links none of that.
// The calling project includes this header and passes what it declares to
// the Sekreto constructor (docs/design/plugin-providers.md).

#ifndef SEKRETO_PLUGINS_HASHICORP_HPP
#define SEKRETO_PLUGINS_HASHICORP_HPP

#include "Provider.hpp"

namespace sekreto {

/// The `hashicorp` provider kind, as a voxgig/plugin definition.
Definition hashicorp();

}  // namespace sekreto

#endif
