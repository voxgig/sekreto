// THE FULL SET - every provider kind that is not built in.
//
// A consumer that wants the lot passes this; a consumer that wants one
// vault imports one definition and passes that. The list is what a CLI or a
// test harness hands to `Sekreto`, and nothing in the core reaches it:
// loading is a list handed to a constructor, never a side effect of
// importing (docs/design/plugin-providers.md).
//
// Referring to a definition here loads only the file that holds it, so the
// set is assembled on demand and a consumer that names one plugin links
// one - the JVM resolves a class when it is first used, and each definition
// is a top-level `val` in its own file's synthetic class.
//
// A port of typescript/plugins/index.ts, which is canonical.

package com.voxgig.sekreto.plugins

import com.voxgig.sekreto.Definition

object Plugins:

  /** The ten plugin kinds, in the order docs/design/plugin-providers.md
    * lists them.
    */
  val ALL: List[Definition] = List(
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
  )
