-- | HashiCorp Vault, as a plugin.
--
-- The kind opens a socket and can log in for a token, so it is not built
-- in: a chain that does not name it links no part of this module.
--
-- A port of typescript/plugins/hashicorp.ts, which is canonical.

module Hashicorp
  ( hashicorp,
    hashicorpprovider,
  )
where

import qualified Data.ByteString as B
import Bytes (utf8decode)
import Control.Exception (IOException, try)
import Control.Monad (when)
import Data.IORef (newIORef, writeIORef)
import Data.Maybe (fromMaybe)
import Defs (Definition)
import Httpjson (Answer (..), currenttoken, fetchjson, never, renewtime, vaultrefof)
import Json (Json (..))
import qualified Json
import Names (VaultRef (..))
import Provider (Provider (..))
import Providers
  ( AuthSpec (..),
    ProviderSpec (..),
    checkaddr,
    fail',
    first,
    providerplugin,
    trim,
    trimslash,
  )


-- | HashiCorp Vault.
--
-- KV v2 (the default): @api.token@ reads @{addr}/v1/{mount}/data/api@ and
-- takes the @token@ field of @data.data@. KV v1 reads
-- @{addr}/v1/{mount}/api@ and takes the field of @data@. A 404 means "not
-- here" - a miss - so a vault can sit in a chain with fallbacks.
--
-- A Vault Enterprise namespace rides the X-Vault-Namespace header, on
-- logins as well as reads.
--
-- Instead of being handed a token, the provider can log in: Kubernetes
-- auth (the pod's service-account JWT, from its conventional path) or
-- AppRole. A failed login is an error, never a miss - it means this store
-- could not answer at all.
hashicorpprovider :: ProviderSpec -> IO Provider
hashicorpprovider spec = do
  -- A version typo like kv: 3 must not quietly behave as v2 and turn its
  -- 404s into misses; there is nothing safe to assume it meant.
  when (1 /= kv && 2 /= kv) $
    fail' ("sekreto: hashicorp: unsupported kv version: " ++ show kv)

  livetoken <- newIORef (if null (spectoken spec) then Nothing else Just (spectoken spec))
  renewat <- newIORef never

  let baseheaders =
        [("X-Vault-Namespace", specvaultnamespace spec) | not (null (specvaultnamespace spec))]

      login = do
        use <- case specauth spec of
          Nothing -> fail' "sekreto: hashicorp: no token and no auth method"
          Just found -> pure found

        let authmountname = first [authmount use, authmethod use]
            url = trimslash addr ++ "/v1/auth/" ++ authmountname ++ "/login"

        body <- case authmethod use of
          "kubernetes" -> do
            jwt <-
              if not (null (authjwt use))
                then pure (authjwt use)
                else do
                  let file =
                        first
                          [ authjwtfile use,
                            "/var/run/secrets/kubernetes.io/serviceaccount/token"
                          ]
                  outcome <- try (B.readFile file)
                  case outcome :: Either IOException B.ByteString of
                    Left _ -> fail' ("sekreto: hashicorp: cannot read jwt file " ++ file)
                    Right raw -> pure (trim (utf8decode raw))

            pure (JObj [("role", JStr (authrole use)), ("jwt", JStr jwt)])
          "approle" ->
            pure
              ( JObj
                  [ ("role_id", JStr (authroleid use)),
                    ("secret_id", JStr (authsecretid use))
                  ]
              )
          other -> fail' ("sekreto: hashicorp: unknown auth method: " ++ other)

        res <- fetchjson "POST" url baseheaders (Just (Json.stringify body))

        let got = Json.text (Json.dig (ansbody res) ["auth", "client_token"])

        when (200 /= ansstatus res || maybe True null got) $
          fail' ("sekreto: hashicorp login failed: " ++ show (ansstatus res) ++ ": " ++ url)

        renewtime (Json.dig (ansbody res) ["auth", "lease_duration"]) >>= writeIORef renewat

        pure (fromMaybe "" got)

  pure
    Provider
      { lookupsecret = \name -> do
          checkaddr addr

          token <- currenttoken livetoken renewat login

          ref <- vaultrefof name

          let base = trimslash addr ++ "/v1/" ++ mount
              url =
                if 1 == kv
                  then base ++ "/" ++ refpath ref
                  else base ++ "/data/" ++ refpath ref

          res <- fetchjson "GET" url (baseheaders ++ [("X-Vault-Token", token)]) Nothing

          if 404 == ansstatus res
            then pure Nothing
            else
              if 200 /= ansstatus res
                then fail' ("sekreto: hashicorp error: " ++ show (ansstatus res) ++ ": " ++ url)
                else do
                  let holder =
                        if 1 == kv
                          then Json.dig (ansbody res) ["data"]
                          else Json.dig (ansbody res) ["data", "data"]
                  pure (Json.text (Json.dig holder [reffield ref])),
        describe = "hashicorp:" ++ addr ++ "/" ++ mount
      }
  where
    addr = specaddr spec
    mount = first [specmount spec, "secret"]
    kv = fromMaybe 2 (speckv spec)


-- | @hashicorp@, as a voxgig/plugin definition. Hand it to
-- 'Sekreto.sekreto' in @optplugins@ and a chain may name the kind.
hashicorp :: Definition
hashicorp = providerplugin "hashicorp" hashicorpprovider
