// SecretSpec, read through its own CLI.
//
// A PLUGIN, not a built-in: this kind opens a socket, signs a request or
// spawns a process, so a chain that does not name it links none of that.
// The calling project includes this header and passes what it declares to
// the Sekreto constructor (docs/design/plugin-providers.md).

#ifndef SEKRETO_PLUGINS_SECRETSPEC_HPP
#define SEKRETO_PLUGINS_SECRETSPEC_HPP

#include "Provider.hpp"

namespace sekreto {

/// The `secretspec` provider kind, as a voxgig/plugin definition.
Definition secretspec();

/// Does this SecretSpec failure mean "no such secret"? Matched on the
/// WHOLE phrase, key included.
bool secretspecmiss(const std::string& why, const std::string& key);

}  // namespace sekreto

#endif
