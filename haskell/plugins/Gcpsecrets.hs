-- | Google Secret Manager, as a plugin.
--
-- A port of typescript/plugins/gcp.ts, which is canonical.

module Gcpsecrets
  ( gcpsecrets,
    gcpsecretsprovider,
  )
where

import Bytes (unbase64, utf8decode)
import Control.Monad (when)
import Data.IORef (newIORef, writeIORef)
import Data.Maybe (fromMaybe)
import Defs (Definition)
import Httpjson (Answer (..), currenttoken, fetchjson, fromenv, never, renewtime)
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


-- | GCP Secret Manager.
--
-- @api.token@ reads secret @api_token@ (dots flattened to @_@; Secret
-- Manager ids have no hierarchy and reject dots), latest version. The
-- token comes from config, then @GOOGLE_OAUTH_ACCESS_TOKEN@, then the
-- GCE/GKE metadata server - so on Google's own platform no credential
-- configuration is needed at all.
--
-- The metadata call itself is plain http to a link-local host by platform
-- design, and no credential rides on it, so `checkaddr` guards the Secret
-- Manager address instead.
gcpsecretsprovider :: ProviderSpec -> IO Provider
gcpsecretsprovider spec = do
  livetoken <- newIORef Nothing
  renewat <- newIORef never

  let metadataaddr = do
        given <- pure (specmetadataaddr spec)
        if not (null given)
          then pure given
          else do
            host <- fromenv "GCE_METADATA_HOST"
            pure (if null host then "http://metadata.google.internal" else "http://" ++ host)

      login = do
        configured <- first <$> sequence [pure (spectoken spec), fromenv "GOOGLE_OAUTH_ACCESS_TOKEN"]

        if not (null configured)
          then pure configured
          else do
            base <- metadataaddr
            let url =
                  trimslash base
                    ++ "/computeMetadata/v1/instance/service-accounts/default/token"

            res <- fetchjson "GET" url [("Metadata-Flavor", "Google")] Nothing

            let got = Json.text (Json.dig (ansbody res) ["access_token"])

            when (200 /= ansstatus res || maybe True null got) $
              fail' "sekreto: gcp: no token and metadata server did not answer"

            renewtime (Json.dig (ansbody res) ["expires_in"]) >>= writeIORef renewat

            pure (fromMaybe "" got)

  pure
    Provider
      { lookupsecret = \name -> do
          when (null (specproject spec)) $ fail' "sekreto: gcp: no project"

          let useaddr = first [specaddr spec, "https://secretmanager.googleapis.com"]
          checkaddr useaddr

          token <- currenttoken livetoken renewat login

          flat <- forced (flatname name "_")

          let url =
                trimslash useaddr
                  ++ "/v1/projects/"
                  ++ specproject spec
                  ++ "/secrets/"
                  ++ flat
                  ++ "/versions/latest:access"

          res <- fetchjson "GET" url [("authorization", "Bearer " ++ token)] Nothing

          if 404 == ansstatus res
            then pure Nothing
            else
              if 200 /= ansstatus res
                then fail' ("sekreto: gcp error: " ++ show (ansstatus res) ++ ": " ++ url)
                else case Json.asstr (Json.dig (ansbody res) ["payload", "data"]) of
                  Nothing -> pure Nothing
                  Just payload -> case unbase64 payload of
                    Just raw -> pure (Just (utf8decode raw))
                    Nothing -> fail' "sekreto: gcp: undecodable secret",
        describe = "gcpsecrets:" ++ specproject spec
      }


-- | @gcpsecrets@, as a voxgig/plugin definition.
gcpsecrets :: Definition
gcpsecrets = providerplugin "gcpsecrets" gcpsecretsprovider
