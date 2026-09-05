-- | 1Password Connect, as a plugin.
--
-- A port of typescript/plugins/onepassword.ts, which is canonical.

module Onepassword
  ( onepassword,
    onepasswordprovider,
  )
where

import Control.Monad (when)
import Data.IORef (newIORef, readIORef, writeIORef)
import Data.Maybe (fromMaybe)
import Defs (Definition)
import Httpjson (Answer (..), fetchjson, uriescape)
import qualified Json
import Names (checkname)
import Provider (Provider (..), forced)
import Providers
  ( ProviderSpec (..),
    checkaddr,
    fail',
    providerplugin,
    trimslash,
  )


-- | 1Password, through a Connect server.
--
-- The item titled @api.token@ (titles keep their dots), in the named
-- vault. The value is the field with purpose PASSWORD, or the field
-- labelled @value@. A vault that cannot be found is an error - config
-- names it, so its absence is a broken store, not a missing secret.
onepasswordprovider :: ProviderSpec -> IO Provider
onepasswordprovider spec = do
  vaultid <- newIORef Nothing

  let auth = [("authorization", "Bearer " ++ spectoken spec)]

      resolvevault useaddr = do
        let want = specvault spec
        when (null want) $ fail' "sekreto: onepassword: no vault"

        res <- fetchjson "GET" (useaddr ++ "/v1/vaults") auth Nothing

        entries <- case Json.asarr (ansbody res) of
          Just found | 200 == ansstatus res -> pure found
          _ -> fail' ("sekreto: onepassword error: " ++ show (ansstatus res) ++ ": listing vaults")

        let matches entry =
              Just want == Json.text (Json.dig (Just entry) ["id"])
                || Just want == Json.text (Json.dig (Just entry) ["name"])

        case filter matches entries of
          (entry : _) -> pure (fromMaybe "" (Json.text (Json.dig (Just entry) ["id"])))
          [] -> fail' ("sekreto: onepassword: no vault named " ++ want)

  pure
    Provider
      { lookupsecret = \name -> do
          _ <- forced (checkname name)

          let useaddr = trimslash (specaddr spec)
          when (null useaddr) $ fail' "sekreto: onepassword: no addr"
          checkaddr useaddr

          held <- readIORef vaultid
          vid <- case held of
            Just found -> pure found
            Nothing -> do
              found <- resolvevault useaddr
              writeIORef vaultid (Just found)
              pure found

          let filterexp = uriescape ("title eq \"" ++ name ++ "\"")
              findurl = useaddr ++ "/v1/vaults/" ++ vid ++ "/items?filter=" ++ filterexp

          found <- fetchjson "GET" findurl auth Nothing

          items <- case Json.asarr (ansbody found) of
            Just entries | 200 == ansstatus found -> pure entries
            _ ->
              fail'
                ("sekreto: onepassword error: " ++ show (ansstatus found) ++ ": finding " ++ name)

          case items of
            [] -> pure Nothing
            (entry : _) -> do
              let itemid = fromMaybe "" (Json.text (Json.dig (Just entry) ["id"]))
                  readurl = useaddr ++ "/v1/vaults/" ++ vid ++ "/items/" ++ itemid

              item <- fetchjson "GET" readurl auth Nothing

              when (200 /= ansstatus item) $
                fail'
                  ( "sekreto: onepassword error: "
                      ++ show (ansstatus item)
                      ++ ": reading "
                      ++ name
                  )

              let fields = fromMaybe [] (Json.asarr (Json.dig (ansbody item) ["fields"]))

                  -- The FIRST field carrying this role, if any. Deliberately
                  -- NOT "the first field carrying this role whose value is
                  -- text": those are different, and conflating them is a
                  -- wrong-secret bug rather than a cosmetic one.
                  firstwith role wanted =
                    case filter
                      (\field -> Just wanted == Json.asstr (Json.dig (Just field) [role]))
                      fields of
                      (field : _) -> Just field
                      [] -> Nothing

                  valueof field = Json.text (Json.dig (Just field) ["value"])

              -- Two passes, purpose first -- and the FIRST pass is TERMINAL.
              -- Canonical returns from inside the loop
              -- (kotlin/src/Providers.kt:1417 and the typescript plugin), so
              -- a PASSWORD field whose value is null is a MISS and must not
              -- fall through to the label pass. Returning Nothing from the
              -- purpose lookup for both "no such field" and "field with a
              -- null value" made it fall through, and the label pass then
              -- answered with a DIFFERENT field's value: the caller got a
              -- secret where canonical gives it nothing.
              pure
                ( case firstwith "purpose" "PASSWORD" of
                    Just field -> valueof field
                    Nothing -> maybe Nothing valueof (firstwith "label" "value")
                ),
        describe = "onepassword:" ++ specvault spec
      }


-- | @onepassword@, as a voxgig/plugin definition.
onepassword :: Definition
onepassword = providerplugin "onepassword" onepasswordprovider
