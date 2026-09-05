-- | Azure Key Vault, as a plugin.
--
-- A port of typescript/plugins/azure.ts, which is canonical.

module Azuresecrets
  ( azuresecrets,
    azuresecretsprovider,
  )
where

import Control.Monad (when)
import Data.IORef (newIORef, writeIORef)
import Data.List (isPrefixOf)
import Data.Maybe (fromMaybe)
import Defs (Definition)
import Httpjson (Answer (..), currenttoken, fetchjson, nakedurl, never, renewtime)
import qualified Json
import Names (flatname)
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


-- | The Key Vault audience an Azure token is minted for.
azureresource :: String
azureresource = "https://vault.azure.net"

-- | Azure Key Vault.
--
-- @api.token@ reads secret @api-token@ (dots flattened to @-@; Key Vault
-- names allow nothing else), current version. The token comes from
-- config, then a client-credentials login when tenant/clientid/
-- clientsecret are given, then the IMDS managed-identity endpoint.
--
-- As with GCP, the IMDS call is plain http to a link-local host by
-- platform design and carries no credential; the login and vault
-- addresses are `checkaddr`-guarded.
azuresecretsprovider :: ProviderSpec -> IO Provider
azuresecretsprovider spec = do
  livetoken <- newIORef Nothing
  renewat <- newIORef never

  let login
        | not (null (spectoken spec)) = pure (spectoken spec)
        | not (null (spectenant spec))
            && not (null (specclientid spec))
            && not (null (specclientsecret spec)) = do
            let useloginaddr = first [specloginaddr spec, "https://login.microsoftonline.com"]
            checkaddr useloginaddr

            let url = trimslash useloginaddr ++ "/" ++ spectenant spec ++ "/oauth2/v2.0/token"
                form =
                  "grant_type=client_credentials&client_id="
                    ++ uriescape (specclientid spec)
                    ++ "&client_secret="
                    ++ uriescape (specclientsecret spec)
                    ++ "&scope="
                    ++ uriescape (azureresource ++ "/.default")

            res <-
              fetchjson
                "POST"
                url
                [("content-type", "application/x-www-form-urlencoded")]
                (Just form)

            let got = Json.text (Json.dig (ansbody res) ["access_token"])

            when (200 /= ansstatus res || maybe True null got) $
              fail' ("sekreto: azure login failed: " ++ show (ansstatus res))

            renewtime (Json.dig (ansbody res) ["expires_in"]) >>= writeIORef renewat
            pure (fromMaybe "" got)
        | otherwise = do
            let imds =
                  trimslash (first [specimdsaddr spec, "http://169.254.169.254"])
                    ++ "/metadata/identity/oauth2/token?api-version=2018-02-01&resource="
                    ++ uriescape azureresource

            res <- fetchjson "GET" imds [("Metadata", "true")] Nothing

            let got = Json.text (Json.dig (ansbody res) ["access_token"])

            when (200 /= ansstatus res || maybe True null got) $
              fail' "sekreto: azure: no token, no client credentials, and IMDS did not answer"

            renewtime (Json.dig (ansbody res) ["expires_in"]) >>= writeIORef renewat
            pure (fromMaybe "" got)

  pure
    Provider
      { lookupsecret = \name -> do
          when (null (specvault spec)) $ fail' "sekreto: azure: no vault"

          -- Only an explicit scheme is a URL; a vault NAMED httpvault must
          -- still become https://httpvault.vault.azure.net.
          let usevault = specvault spec
              vaulturl =
                if "http://" `isPrefixOf` usevault || "https://" `isPrefixOf` usevault
                  then usevault
                  else "https://" ++ usevault ++ ".vault.azure.net"

          checkaddr vaulturl

          token <- currenttoken livetoken renewat login

          flat <- forced (flatname name "-")

          let url =
                trimslash vaulturl
                  ++ "/secrets/"
                  ++ flat
                  ++ "?api-version="
                  ++ first [specapiversion spec, "7.4"]

          res <- fetchjson "GET" url [("authorization", "Bearer " ++ token)] Nothing

          if 404 == ansstatus res
            then pure Nothing
            else
              if 200 /= ansstatus res
                then
                  fail'
                    ("sekreto: azure error: " ++ show (ansstatus res) ++ ": " ++ nakedurl url)
                else pure (Json.text (Json.dig (ansbody res) ["value"])),
        describe = "azuresecrets:" ++ specvault spec
      }


-- | @azuresecrets@, as a voxgig/plugin definition.
azuresecrets :: Definition
azuresecrets = providerplugin "azuresecrets" azuresecretsprovider
