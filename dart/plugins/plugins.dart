// THE FULL SET - every provider kind that is not built in, in one import.
//
// It exists for the callers that genuinely want all ten kinds: the CLI, the
// conformance suite, an app whose chain is decided at run time.
//
//     import '../plugins/plugins.dart';
//     sekreto(chain, plugins: allplugins);
//
// IT IS ALSO THE THING TO AVOID IF YOU CARE ABOUT SIZE. Importing one
// plugin through this file makes every other one reachable too - AWS
// request signing, SHA-256 and eight HTTP vault clients included - which is
// the cost the core/plugin split exists to remove. A lean consumer imports
// the kinds it actually configures, each from its own file:
//
//     import '../plugins/hashicorp.dart';
//     sekreto(chain, plugins: [hashicorp]);
//
// The difference is visible in the compiler's own dependency listing:
// `make check-core` writes one for each and the seam tests compare them.
// See docs/design/plugin-providers.md.

import '../src/support.dart';

import 'aws.dart';
import 'azuresecrets.dart';
import 'boru.dart';
import 'doppler.dart';
import 'gcpsecrets.dart';
import 'hashicorp.dart';
import 'infisical.dart';
import 'onepassword.dart';
import 'secretspec.dart';

export 'aws.dart' show Awsparams, Awssecrets, awsparams, awssecrets;
export 'azuresecrets.dart' show Azuresecrets, azuresecrets;
export 'boru.dart' show Boru, boru;
export 'doppler.dart' show Doppler, doppler;
export 'gcpsecrets.dart' show Gcpsecrets, gcpsecrets;
export 'hashicorp.dart' show Hashicorp, hashicorp;
export 'httpjson.dart' show fetchjson;
export 'infisical.dart' show Infisical, infisical;
export 'onepassword.dart' show Onepassword, onepassword;
export 'secretspec.dart' show Secretspec, secretspec;
export 'sigv4.dart' show Signing, sigv4;

/// The ten plugin kinds, in the order docs/design/plugin-providers.md lists
/// them.
final List<Definition> allplugins = [
  hashicorp,
  boru,
  awssecrets,
  awsparams,
  gcpsecrets,
  azuresecrets,
  onepassword,
  doppler,
  infisical,
  secretspec,
];
