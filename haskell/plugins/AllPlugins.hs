-- | THE FULL SET - every plugin this port ships, in one import.
--
-- It exists for the callers that genuinely want all ten kinds: the CLI,
-- the conformance suite, an app whose chain is decided at run time.
--
-- > secrets <- sekreto emptyoptions {optplugins = allplugins, optproviders = chain}
--
-- IT IS ALSO THE THING TO AVOID IF YOU CARE ABOUT SIZE. Importing this
-- module compiles every plugin into the program - AWS request signing,
-- seven HTTP vault clients and the OpenSSL binding under them - which is
-- the cost the core/plugin split exists to remove. A lean consumer
-- imports the kinds it actually configures, each from its own module:
--
-- > import Hashicorp (hashicorp)
-- > secrets <- sekreto emptyoptions {optplugins = [hashicorp], optproviders = chain}

module AllPlugins
  ( allplugins,
    awsparams,
    awssecrets,
    azuresecrets,
    boru,
    doppler,
    gcpsecrets,
    hashicorp,
    infisical,
    onepassword,
    secretspec,
  )
where

import Aws (awsparams, awssecrets)
import Azuresecrets (azuresecrets)
import Boru (boru)
import Defs (Definition)
import Doppler (doppler)
import Gcpsecrets (gcpsecrets)
import Hashicorp (hashicorp)
import Infisical (infisical)
import Onepassword (onepassword)
import Secretspec (secretspec)

-- | Every plugin definition this port ships, in a fresh list and in the
-- order the canonical lists them.
allplugins :: [Definition]
allplugins =
  [ hashicorp,
    boru,
    awssecrets,
    awsparams,
    gcpsecrets,
    azuresecrets,
    onepassword,
    doppler,
    infisical,
    secretspec
  ]
