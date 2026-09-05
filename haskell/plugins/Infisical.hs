-- | Infisical, as a plugin.
--
-- A port of typescript/plugins/infisical.ts, which is canonical.

module Infisical
  ( infisical,
    infisicalprovider,
  )
where

import Control.Monad (when)
import Data.IORef (newIORef, writeIORef)
import Data.Maybe (fromMaybe)
import Defs (Definition)
import Httpjson (Answer (..), currenttoken, fetchjson, never, renewtime)
import Json (Json (..))
import qualified Json
import Names (envkey)
import Provider (Provider (..), forced)
import Providers
  ( ProviderSpec (..),
    checkaddr,
    fail',
    first,
    providerplugin,
    trimslash,
  )
import Sigv4 (uriescape)


-- | Infisical.
--
-- @api.token@ reads the secret keyed @API_TOKEN@ (Infisical's own
-- convention is environment-style keys) at a secret path in one
-- environment of a project. Auth is a token, or a universal-auth (machine
-- identity) login with clientid/clientsecret.
infisicalprovider :: ProviderSpec -> IO Provider
infisicalprovider spec = do
  livetoken <- newIORef Nothing
  renewat <- newIORef never

  let login useaddr
        | not (null (spectoken spec)) = pure (spectoken spec)
        | otherwise = do
            when (null (specclientid spec) || null (specclientsecret spec)) $
              fail' "sekreto: infisical: no token and no client credentials"

            let body =
                  JObj
                    [ ("clientId", JStr (specclientid spec)),
                      ("clientSecret", JStr (specclientsecret spec))
                    ]

            res <-
              fetchjson
                "POST"
                (useaddr ++ "/api/v1/auth/universal-auth/login")
                [("content-type", "application/json")]
                (Just (Json.stringify body))

            let got = Json.text (Json.dig (ansbody res) ["accessToken"])

            when (200 /= ansstatus res || maybe True null got) $
              fail' ("sekreto: infisical login failed: " ++ show (ansstatus res))

            -- camelCase, unlike everyone else's expires_in.
            renewtime (Json.dig (ansbody res) ["expiresIn"]) >>= writeIORef renewat
            pure (fromMaybe "" got)

  pure
    Provider
      { lookupsecret = \name -> do
          let useaddr = trimslash (first [specaddr spec, "https://app.infisical.com"])
          checkaddr useaddr

          when (null (specproject spec) || null (specenvironment spec)) $
            fail' "sekreto: infisical: no project/environment"

          token <- currenttoken livetoken renewat (login useaddr)

          key <- forced (envkey name "")

          let url =
                useaddr
                  ++ "/api/v3/secrets/raw/"
                  ++ key
                  ++ "?workspaceId="
                  ++ uriescape (specproject spec)
                  ++ "&environment="
                  ++ uriescape (specenvironment spec)
                  ++ "&secretPath="
                  ++ uriescape (first [specpath spec, "/"])

          res <- fetchjson "GET" url [("authorization", "Bearer " ++ token)] Nothing

          if 404 == ansstatus res
            then pure Nothing
            else
              if 200 /= ansstatus res
                then fail' ("sekreto: infisical error: " ++ show (ansstatus res))
                else pure (Json.text (Json.dig (ansbody res) ["secret", "secretValue"])),
        describe = "infisical:" ++ specproject spec ++ "/" ++ specenvironment spec
      }


-- | @infisical@, as a voxgig/plugin definition.
infisical :: Definition
infisical = providerplugin "infisical" infisicalprovider
