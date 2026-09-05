-- | A boru vault, as a plugin.
--
-- Two ways in and both leave the process: a child @boru@ and a socket to
-- @boru vault serve@. Neither is something a built-in kind may do.
--
-- A port of typescript/plugins/boru.ts, which is canonical.

module Boru
  ( boru,
    boruprovider,
  )
where

import Data.List (isInfixOf)
import Defs (Definition)
import Httpjson (Answer (..), fetchjson)
import qualified Json
import Names (checkname)
import Provider (Provider (..), forced)
import Providers
  ( ProviderSpec (..),
    checkaddr,
    chomp,
    fail',
    first,
    providerplugin,
    trimslash,
  )
import Subproc (Ran (..), runcmd)


-- | A boru vault (https://github.com/boru-lang/boru).
--
-- Two ways in, both boru's own.
--
-- With no @addr@, the CLI: @boru vault get --reveal \<alias>@ prints the
-- secret on stdout and nothing else. The passphrase is read by boru
-- itself from @BORU_VAULT_PASSPHRASE@; sekreto never accepts it as config
-- and never puts it on a command line, where it would show up in the
-- process table.
--
-- With an @addr@, boru's wire protocol: @boru vault serve@ publishes a
-- read-only, HashiCorp-shaped provision API, authenticated by a
-- capability token from @boru vault grant@. A sekreto name is already a
-- valid boru alias, and boru aliases keep their dots, so @api.token@ is
-- the single path segment @api.token@ - not the @api@/@token@ split a
-- HashiCorp KV gets. The value is the @value@ field. A 404 is a miss;
-- anything else the server refuses is an error.
boruprovider :: ProviderSpec -> Provider
boruprovider spec =
  Provider
    { lookupsecret = \name -> do
        _ <- forced (checkname name)

        if not (null addr)
          then wirelookup name
          else do
            let alias = if null namespace then name else namespace ++ ":" ++ name

            ran <-
              runcmd
                command
                ["vault", "get", "--reveal", alias]
                [("BORU_HOME", spechome spec) | not (null (spechome spec))]

            if 0 == ranstatus ran
              then -- boru prints the value and one newline, and nothing else.
                pure (Just (chomp (ranout ran)))
              else -- "no alias named" is boru saying it does not hold this
              -- secret, which is a miss: the chain carries on. A locked
              -- vault or a wrong passphrase is not a miss - treating it as
              -- one would fall through to a weaker store without saying so.

                if borumiss (ranwhy ran)
                  then pure Nothing
                  else
                    fail'
                      ( "sekreto: boru vault error: "
                          ++ ( if null (ranwhy ran)
                                 then "exit " ++ show (ranstatus ran)
                                 else ranwhy ran
                             )
                      ),
      describe =
        if not (null addr)
          then "boru:" ++ addr
          else "boru" ++ (if null namespace then "" else ":" ++ namespace)
    }
  where
    command = first [speccommand spec, "boru"]
    namespace = specnamespace spec
    addr = trimslash (specaddr spec)
    mount = first [specmount spec, "secret"]

    wirelookup name = do
      checkaddr addr

      -- The dotted name stays one path segment: boru aliases keep dots.
      let alias = if null namespace then name else namespace ++ "/" ++ name
          url = addr ++ "/v1/" ++ mount ++ "/data/" ++ alias

      res <- fetchjson "GET" url [("X-Vault-Token", spectoken spec)] Nothing

      if 404 == ansstatus res
        then pure Nothing
        else
          if 200 /= ansstatus res
            then fail' ("sekreto: boru serve error: " ++ show (ansstatus res) ++ ": " ++ url)
            else pure (Json.text (Json.dig (ansbody res) ["data", "data", "value"]))

-- | Does this boru failure mean "no such secret" rather than "I could not
-- answer"? Matched on boru's own wording for a missing alias.
borumiss :: String -> Bool
borumiss why = isInfixOf "no alias named" why


-- | @boru@, as a voxgig/plugin definition.
boru :: Definition
boru = providerplugin "boru" (pure . boruprovider)
