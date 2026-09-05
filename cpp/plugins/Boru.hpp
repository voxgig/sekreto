// A boru vault, read through its CLI or over its wire protocol.
//
// A PLUGIN, not a built-in: this kind opens a socket, signs a request or
// spawns a process, so a chain that does not name it links none of that.
// The calling project includes this header and passes what it declares to
// the Sekreto constructor (docs/design/plugin-providers.md).

#ifndef SEKRETO_PLUGINS_BORU_HPP
#define SEKRETO_PLUGINS_BORU_HPP

#include "Provider.hpp"

namespace sekreto {

/// The `boru` provider kind, as a voxgig/plugin definition.
Definition boru();

/// Does this boru failure mean "no such secret" rather than "I could not
/// answer"?
bool borumiss(const std::string& why);

}  // namespace sekreto

#endif
