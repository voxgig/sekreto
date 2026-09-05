-- | SecretSpec, as a plugin.
--
-- A child process rather than a socket, which is still a platform reach
-- and still not something a built-in kind may do.
--
-- A port of typescript/plugins/secretspec.ts, which is canonical.

module Secretspec
  ( secretspec,
    secretspecprovider,
  )
where

import Data.List (isInfixOf)
import Defs (Definition)
import Names (envkey)
import Provider (Provider (..), forced)
import Providers (ProviderSpec (..), chomp, fail', first, providerplugin)
import Subproc (Ran (..), runcmd)


-- | SecretSpec (https://secretspec.dev).
--
-- SecretSpec is a declaration - a @secretspec.toml@ naming the secrets a
-- project needs - plus a chain of its own backends to satisfy them from.
-- That makes it the same shape as sekreto one level down, and the reason
-- to support it is the reason sekreto exists: a project that has already
-- declared its secrets there should not have to declare them again here.
--
-- A reason is required, not optional: SecretSpec records every read in an
-- audit log and refuses to read at all without one.
secretspecprovider :: ProviderSpec -> Provider
secretspecprovider spec =
  Provider
    { lookupsecret = \name -> do
        key <- forced (envkey name (specprefix spec))

        let args =
              [w | not (null (specfile spec)), w <- ["--file", specfile spec]]
                ++ ["get", key]
                ++ [w | not (null (specbackend spec)), w <- ["--provider", specbackend spec]]
                ++ [w | not (null (specprofile spec)), w <- ["--profile", specprofile spec]]
                ++ ["--reason", first [specreason spec, "sekreto"]]

        ran <- runcmd command args []

        if 0 == ranstatus ran
          then pure (Just (chomp (ranout ran)))
          else
            if secretspecmiss (ranwhy ran) key
              then pure Nothing
              else
                fail'
                  ( "sekreto: secretspec error: "
                      ++ ( if null (ranwhy ran)
                             then "exit " ++ show (ranstatus ran)
                             else ranwhy ran
                         )
                  ),
      describe = "secretspec" ++ (if null (specbackend spec) then "" else ":" ++ specbackend spec)
    }
  where
    command = first [speccommand spec, "secretspec"]

-- | Does this SecretSpec failure mean "no such secret" rather than "I
-- could not answer"?
--
-- SecretSpec says @Secret 'API_TOKEN' not found@ for both a name it does
-- not declare and one declared with no value, and both are misses.
--
-- MATCHED ON THE WHOLE PHRASE, NOT ON "not found". SecretSpec also says
-- @Provider backend 'keyring' not found@, which is a store that could not
-- answer at all - and reading that as a miss is the worst failure this
-- library has, because the chain then falls through to a weaker store
-- without saying so. The key is required to appear, so the two cannot be
-- confused.
secretspecmiss :: String -> String -> Bool
secretspecmiss why key = isInfixOf ("Secret '" ++ key ++ "' not found") why


-- | @secretspec@, as a voxgig/plugin definition.
secretspec :: Definition
secretspec = providerplugin "secretspec" (pure . secretspecprovider)
