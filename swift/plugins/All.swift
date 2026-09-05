// THE FULL SET - every plugin this library ships, in one name.
//
// It exists for the callers that genuinely want all ten kinds: the CLI,
// the conformance suite, an app whose chain is decided at run time.
//
//     import SekretoPlugins
//     let secrets = try makesekreto(chain, plugins: allplugins)
//
// IT IS ALSO THE THING TO AVOID IF YOU CARE ABOUT SIZE - though in swift
// the cost is paid a module at a time rather than a name at a time.
// Linking `libSekretoPlugins.a` links AWS request signing and seven HTTP
// vault clients whether or not `allplugins` is ever mentioned, because a
// swift module is compiled and archived whole. A lean consumer therefore
// builds a SMALLER MODULE from the files it wants rather than reaching for
// a smaller name from this one:
//
//     swiftc -emit-module -emit-library -static -module-name SekretoPlugins \
//       plugins/Hashicorp.swift plugins/Httpjson.swift
//
// `make lean` does exactly that, and it is a test as well as an example:
// each plugin file must compile beside Httpjson.swift and nothing else, so
// a plugin that quietly reached into its neighbour - which one swift
// module would let it do with no import to give it away - fails there.
//
// See docs/design/plugin-providers.md.

// A SCOPED import: plugin exports a `Json` of its own, and the only name
// this file wants from it is `Definition`.
import struct VoxgigPlugin.Definition

/// Every plugin definition this library ships, in chain-documentation
/// order: the vaults, then the clouds, then the CLIs.
public let allplugins: [Definition] = [
  hashicorp, boru, awssecrets, awsparams, gcpsecrets, azuresecrets,
  onepassword, doppler, infisical, secretspec,
]
