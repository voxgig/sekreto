-- | AWS Secrets Manager and SSM Parameter Store, as plugins.
--
-- SigV4 TRAVELS WITH THEM. Request signing is HMAC-SHA256, and the core
-- of no port imports a hash function - so "Sigv4" and "Crypto" are under
-- @plugins/@ and reachable only from here.
--
-- A port of typescript/plugins/aws.ts, which is canonical.

module Aws
  ( awsparams,
    awsparamsprovider,
    awssecrets,
    awssecretsprovider,
  )
where

import Bytes (unbase64, utf8decode)
import Control.Monad (when)
import Data.List (isInfixOf, isPrefixOf)
import Data.Maybe (fromMaybe, isJust)
import Data.Time.Clock (getCurrentTime)
import Data.Time.Format (defaultTimeLocale, formatTime)
import Defs (Definition)
import Httpjson (Answer (..), fetchjson, fromenv, vaultrefof)
import Json (Json (..))
import qualified Json
import Names (VaultRef (..), awsparam)
import Provider (Provider (..), forced)
import Providers
  ( ProviderSpec (..),
    checkaddr,
    fail',
    first,
    providerplugin,
    trimslash,
  )
import Sigv4 (Signing (..), emptysigning, sigv4)


-- | The @YYYYMMDDTHHMMSSZ@ timestamp SigV4 wants, for now.
awsnow :: IO String
awsnow = formatTime defaultTimeLocale "%Y%m%dT%H%M%SZ" <$> getCurrentTime

-- | Region and credentials, from config first and the standard AWS_*
-- environment variables second - those are AWS's own convention, and a
-- pod or CI job that has them set should just work. Missing either is an
-- error: an AWS store with no credentials could not answer.
awsauth :: ProviderSpec -> IO (String, String, String, String)
awsauth spec = do
  region <- first <$> sequence [pure (specregion spec), fromenv "AWS_REGION", fromenv "AWS_DEFAULT_REGION"]
  keyid <- first <$> sequence [pure (speckeyid spec), fromenv "AWS_ACCESS_KEY_ID"]
  secret <- first <$> sequence [pure (specsecret spec), fromenv "AWS_SECRET_ACCESS_KEY"]
  session <- first <$> sequence [pure (specsession spec), fromenv "AWS_SESSION_TOKEN"]

  when (null region) $ fail' "sekreto: aws: no region (set region or AWS_REGION)"

  when (null keyid || null secret) $
    fail'
      "sekreto: aws: no credentials (set keyid/secret or AWS_ACCESS_KEY_ID/AWS_SECRET_ACCESS_KEY)"

  pure (region, keyid, secret, session)

-- | One signed call to an AWS JSON-1.1 API.
awscall :: ProviderSpec -> String -> String -> String -> IO Answer
awscall spec service target payload = do
  (region, keyid, secret, session) <- awsauth spec

  -- The China partition lives under its own suffix; every other
  -- commercial region is plain amazonaws.com.
  let suffix = if "cn-" `isPrefixOf` region then ".amazonaws.com.cn" else ".amazonaws.com"
      useaddr = first [specaddr spec, "https://" ++ service ++ "." ++ region ++ suffix]

  checkaddr useaddr

  let url = trimslash useaddr ++ "/"
      extras =
        [ ("content-type", "application/x-amz-json-1.1"),
          ("x-amz-target", target)
        ]

  datetime <- awsnow

  let signed =
        sigv4
          emptysigning
            { signmethod = "POST",
              signurl = url,
              signservice = service,
              signregion = region,
              signkeyid = keyid,
              signsecret = secret,
              signdatetime = datetime,
              signheaders = extras,
              signbody = payload,
              signsession = session
            }

  fetchjson "POST" url (extras ++ signed) (Just payload)

-- | Does this AWS error body name one of the not-found types? Those are a
-- miss; every other failure is a store that could not answer.
awsmiss :: Maybe Json -> String -> Bool
awsmiss body wanted = case Json.asstr (Json.dig body ["__type"]) of
  Just errtype -> isInfixOf wanted errtype
  Nothing -> False

-- | AWS Secrets Manager.
--
-- @api.token@ reads the secret named @api@ (the vaultref path, so
-- @db.pass.main@ reads @db/pass@) and takes the @token@ field of its JSON
-- SecretString - the AWS idiom of one JSON map per secret. A SecretString
-- that is not JSON is the value itself, under the conventional field
-- @value@.
awssecretsprovider :: ProviderSpec -> Provider
awssecretsprovider spec =
  Provider
    { lookupsecret = \name -> do
        ref <- vaultrefof name

        res <-
          awscall
            spec
            "secretsmanager"
            "secretsmanager.GetSecretValue"
            (Json.stringify (JObj [("SecretId", JStr (refpath ref))]))

        if 400 == ansstatus res && awsmiss (ansbody res) "ResourceNotFoundException"
          then pure Nothing
          else
            if 200 /= ansstatus res
              then fail' ("sekreto: aws secretsmanager error: " ++ show (ansstatus res))
              else case Json.asstr (Json.dig (ansbody res) ["SecretString"]) of
                Just text -> case Json.parse text of
                  Just (JObj fields) -> pure (Json.text (lookup (reffield ref) fields))
                  -- A plain-string secret is the whole value; it has no
                  -- named fields.
                  _ -> pure (if "value" == reffield ref then Just text else Nothing)
                Nothing -> do
                  -- A binary secret has no fields to address; only the
                  -- conventional `value` field can mean "the bytes".
                  let binary = Json.asstr (Json.dig (ansbody res) ["SecretBinary"])

                  if isJust binary && "value" == reffield ref
                    then case unbase64 (fromMaybe "" binary) of
                      Just raw -> pure (Just (utf8decode raw))
                      Nothing -> fail' "sekreto: aws secretsmanager: undecodable secret"
                    else pure Nothing,
      -- Config only, never the environment: describe() feeds the spec's
      -- sources group, which must answer the same everywhere.
      describe = "awssecrets:" ++ specregion spec
    }

-- | AWS SSM Parameter Store.
--
-- @db.pass.main@ reads the parameter @/db/pass/main@ (under an optional
-- prefix path), decrypted. Parameter Store carries flat strings, so there
-- is no field indirection.
awsparamsprovider :: ProviderSpec -> Provider
awsparamsprovider spec =
  Provider
    { lookupsecret = \name -> do
        parameter <- forced (awsparam name (specprefix spec))

        let payload =
              Json.stringify
                (JObj [("Name", JStr parameter), ("WithDecryption", JBool True)])

        res <- awscall spec "ssm" "AmazonSSM.GetParameter" payload

        if 400 == ansstatus res && awsmiss (ansbody res) "ParameterNotFound"
          then pure Nothing
          else
            if 200 /= ansstatus res
              then fail' ("sekreto: aws ssm error: " ++ show (ansstatus res))
              else pure (Json.text (Json.dig (ansbody res) ["Parameter", "Value"])),
      describe = "awsparams:" ++ specregion spec ++ specprefix spec
    }


-- | @awssecrets@, as a voxgig/plugin definition.
awssecrets :: Definition
awssecrets = providerplugin "awssecrets" (pure . awssecretsprovider)

-- | @awsparams@, as a voxgig/plugin definition.
awsparams :: Definition
awsparams = providerplugin "awsparams" (pure . awsparamsprovider)
