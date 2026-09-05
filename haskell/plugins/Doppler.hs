-- | Doppler, as a plugin.
--
-- A port of typescript/plugins/doppler.ts, which is canonical.

module Doppler
  ( doppler,
    dopplerprovider,
  )
where

import Data.IORef (newIORef, readIORef, writeIORef)
import Defs (Definition)
import Httpjson (Answer (..), fetchjson, uriescape)
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


-- | Doppler.
--
-- The whole config is downloaded once - Doppler's own bulk endpoint - and
-- answered from memory, like a remote .env: @api.token@ is the
-- @API_TOKEN@ entry. A service token is config-scoped, so project and
-- config are only needed with broader tokens.
--
-- A failed load caches nothing, so it retries.
dopplerprovider :: ProviderSpec -> IO Provider
dopplerprovider spec = do
  loaded <- newIORef Nothing

  let load = do
        cached <- readIORef loaded
        case cached of
          Just values -> pure values
          Nothing -> do
            let useaddr = trimslash (first [specaddr spec, "https://api.doppler.com"])
            checkaddr useaddr

            let url =
                  useaddr
                    ++ "/v3/configs/config/secrets/download?format=json"
                    ++ ( if null (specproject spec)
                           then ""
                           else "&project=" ++ uriescape (specproject spec)
                       )
                    ++ ( if null (specconfig spec)
                           then ""
                           else "&config=" ++ uriescape (specconfig spec)
                       )

            res <- fetchjson "GET" url [("authorization", "Bearer " ++ spectoken spec)] Nothing

            entries <- case Json.asobj (ansbody res) of
              Just found | 200 == ansstatus res -> pure found
              _ -> fail' ("sekreto: doppler error: " ++ show (ansstatus res))

            -- Entries with null values are skipped; the rest stringified.
            let values = [(key, text) | (key, value) <- entries, Just text <- [Json.text (Just value)]]

            writeIORef loaded (Just values)
            pure values

  pure
    Provider
      { lookupsecret = \name -> do
          -- The prefix option is not consulted by this kind.
          key <- forced (envkey name "")
          values <- load
          pure (lookup key values),
        describe =
          "doppler"
            ++ ( if null (specproject spec)
                   then ""
                   else ":" ++ specproject spec ++ "/" ++ specconfig spec
               )
      }


-- | @doppler@, as a voxgig/plugin definition.
doppler :: Definition
doppler = providerplugin "doppler" dopplerprovider
