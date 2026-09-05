// THE FULL SET: all ten plugin kinds at once.
//
// For the consumer that genuinely wants every kind - the CLI, whose
// `--source` names any of them at run time, and the conformance suite,
// which builds chains the shared spec describes. An app that knows its
// chain includes the kinds it configures instead and links nothing else:
// that is the whole point of the split, and this header is the one place
// where taking all ten is the right answer.
//
// Including this file reaches every plugin, and therefore the HTTP client,
// TLS and SigV4 behind them. Nothing under src/ includes it, and nothing
// may.

#ifndef SEKRETO_PLUGINS_ALL_HPP
#define SEKRETO_PLUGINS_ALL_HPP

#include <vector>

#include "Provider.hpp"

namespace sekreto {

/// The ten kinds this library ships as plugins, in the order the design
/// lists them. BUILT, not held: fresh definitions on every call, so two
/// Sekretos never share one.
std::vector<Definition> allplugins();

}  // namespace sekreto

#endif
