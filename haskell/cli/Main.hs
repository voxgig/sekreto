-- | A tiny app that needs a secret.
--
-- It asks sekreto for @api.token@ and calls the token-protected API with
-- it. Every port ships this same CLI, and test/integration.sh runs all of
-- them against the same server from every secret source - which is what
-- proves the library, rather than the spec alone.
--
-- Usage: sekreto-cli \<api-url> [--source \<source>] [--store \<name>]
--
-- Sources: env dotenv file hashicorp boru boruwire awssecrets awsparams
--          gcpsecrets azuresecrets onepassword doppler infisical
--          secretspec chain
--
-- Each source's configuration arrives in the environment variables its
-- own ecosystem already uses (VAULT_*, AWS_*, OP_CONNECT_*, ...), listed
-- in `chainfor` below. The working directory is empty when the suite runs
-- this, so nothing may be looked for there.

module Main (main) where

import Control.Exception (SomeException, displayException, try)
import qualified Http
import qualified Json
import Providers (AuthSpec (..), ProviderSpec (..), emptyauth, emptyspec, sekreto)
import Sekreto (Sekreto, get, getfrom, redactall)
import System.Environment (getArgs, lookupEnv)
import System.Exit (ExitCode (..), exitWith)
import System.IO (hPutStrLn, stderr)

lang :: String
lang = "haskell"

-- | An environment variable, treating empty as absent.
envor :: String -> String -> IO String
envor name fallback = do
  found <- lookupEnv name
  pure (case found of Just value | not (null value) -> value; _ -> fallback)

chainfor :: String -> IO [ProviderSpec]
chainfor source = do
  prefix <- envor "SEKRETO_PREFIX" ""
  dotenvfile <- envor "SEKRETO_DOTENV" ".env"
  filedir <- envor "SEKRETO_FILEDIR" "/run/secrets"

  let envspec = emptyspec {speckind = "env", specprefix = prefix}
      dotenvspec = emptyspec {speckind = "dotenv", specfile = dotenvfile}
      filespec = emptyspec {speckind = "file", specdir = filedir}

  vaultaddr <- envor "VAULT_ADDR" ""
  vaulttoken <- envor "VAULT_TOKEN" ""
  vaultmount <- envor "VAULT_MOUNT" ""
  vaultkv <- envor "VAULT_KV" ""
  vaultnamespace <- envor "VAULT_NAMESPACE" ""
  vaultauth <- envor "VAULT_AUTH" ""
  vaultrole <- envor "VAULT_ROLE" ""
  vaultjwtfile <- envor "VAULT_JWT_FILE" ""
  vaultroleid <- envor "VAULT_ROLE_ID" ""
  vaultsecretid <- envor "VAULT_SECRET_ID" ""

  let hashicorpspec =
        emptyspec
          { speckind = "hashicorp",
            specaddr = vaultaddr,
            spectoken = vaulttoken,
            specmount = vaultmount,
            speckv = case reads vaultkv :: [(Int, String)] of
              [(version, "")] -> Just version
              _ -> Nothing,
            specvaultnamespace = vaultnamespace,
            specauth =
              if null vaultauth
                then Nothing
                else
                  Just
                    emptyauth
                      { authmethod = vaultauth,
                        authrole = vaultrole,
                        authjwtfile = vaultjwtfile,
                        authroleid = vaultroleid,
                        authsecretid = vaultsecretid
                      }
          }

  borucommand <- envor "BORU_COMMAND" "boru"
  borunamespace <- envor "BORU_NAMESPACE" ""
  boruhome <- envor "BORU_HOME" ""
  boruaddr <- envor "BORU_ADDR" ""
  borutoken <- envor "BORU_TOKEN" ""

  let boruspec =
        emptyspec
          { speckind = "boru",
            speccommand = borucommand,
            specnamespace = borunamespace,
            spechome = boruhome
          }
      -- The same vault over its wire protocol (`boru vault serve`)
      -- instead of the CLI: an address plus a capability token.
      boruwirespec =
        emptyspec
          { speckind = "boru",
            specaddr = boruaddr,
            spectoken = borutoken,
            specnamespace = borunamespace
          }

  awsregion <- envor "AWS_REGION" ""
  awsendpoint <- envor "AWS_ENDPOINT" ""
  awsprefix <- envor "AWS_PARAM_PREFIX" ""

  let awssecretsspec =
        emptyspec {speckind = "awssecrets", specregion = awsregion, specaddr = awsendpoint}
      awsparamsspec =
        emptyspec
          { speckind = "awsparams",
            specregion = awsregion,
            specaddr = awsendpoint,
            specprefix = awsprefix
          }

  gcpproject <- envor "GCP_PROJECT" ""
  gcpaddr <- envor "GCP_ADDR" ""
  gcpmetadata <- envor "GCP_METADATA_ADDR" ""

  let gcpspec =
        emptyspec
          { speckind = "gcpsecrets",
            specproject = gcpproject,
            specaddr = gcpaddr,
            specmetadataaddr = gcpmetadata
          }

  azurevault <- envor "AZURE_VAULT" ""
  azuretoken <- envor "AZURE_TOKEN" ""
  azuretenant <- envor "AZURE_TENANT" ""
  azureclientid <- envor "AZURE_CLIENT_ID" ""
  azureclientsecret <- envor "AZURE_CLIENT_SECRET" ""
  azureloginaddr <- envor "AZURE_LOGIN_ADDR" ""
  azureimdsaddr <- envor "AZURE_IMDS_ADDR" ""

  let azurespec =
        emptyspec
          { speckind = "azuresecrets",
            specvault = azurevault,
            spectoken = azuretoken,
            spectenant = azuretenant,
            specclientid = azureclientid,
            specclientsecret = azureclientsecret,
            specloginaddr = azureloginaddr,
            specimdsaddr = azureimdsaddr
          }

  ophost <- envor "OP_CONNECT_HOST" ""
  optoken <- envor "OP_CONNECT_TOKEN" ""
  opvault <- envor "OP_VAULT" ""

  let onepasswordspec =
        emptyspec
          { speckind = "onepassword",
            specaddr = ophost,
            spectoken = optoken,
            specvault = opvault
          }

  dopplertoken <- envor "DOPPLER_TOKEN" ""
  dopplerproject <- envor "DOPPLER_PROJECT" ""
  dopplerconfig <- envor "DOPPLER_CONFIG" ""
  doppleraddr <- envor "DOPPLER_ADDR" ""

  let dopplerspec =
        emptyspec
          { speckind = "doppler",
            spectoken = dopplertoken,
            specproject = dopplerproject,
            specconfig = dopplerconfig,
            specaddr = doppleraddr
          }

  infisicaladdr <- envor "INFISICAL_ADDR" ""
  infisicaltoken <- envor "INFISICAL_TOKEN" ""
  infisicalclientid <- envor "INFISICAL_CLIENT_ID" ""
  infisicalclientsecret <- envor "INFISICAL_CLIENT_SECRET" ""
  infisicalproject <- envor "INFISICAL_PROJECT" ""
  infisicalenv <- envor "INFISICAL_ENV" ""
  infisicalpath <- envor "INFISICAL_PATH" ""

  let infisicalspec =
        emptyspec
          { speckind = "infisical",
            specaddr = infisicaladdr,
            spectoken = infisicaltoken,
            specclientid = infisicalclientid,
            specclientsecret = infisicalclientsecret,
            specproject = infisicalproject,
            specenvironment = infisicalenv,
            specpath = infisicalpath
          }

  -- SecretSpec's own environment variables where it has them, so a shell
  -- already set up for secretspec needs nothing further.
  secretspeccommand <- envor "SECRETSPEC_COMMAND" "secretspec"
  secretspecfile <- envor "SECRETSPEC_FILE" ""
  secretspecprofile <- envor "SECRETSPEC_PROFILE" ""
  secretspecbackend <- envor "SECRETSPEC_PROVIDER" ""
  secretspecreason <- envor "SECRETSPEC_REASON" ""

  let secretspecspec =
        emptyspec
          { speckind = "secretspec",
            speccommand = secretspeccommand,
            specfile = secretspecfile,
            specprofile = secretspecprofile,
            specbackend = secretspecbackend,
            specreason = secretspecreason
          }

  pure $ case source of
    "env" -> [envspec]
    "dotenv" -> [dotenvspec]
    "file" -> [filespec]
    "hashicorp" -> [hashicorpspec]
    "boru" -> [boruspec]
    "boruwire" -> [boruwirespec]
    "awssecrets" -> [awssecretsspec]
    "awsparams" -> [awsparamsspec]
    "gcpsecrets" -> [gcpspec]
    "azuresecrets" -> [azurespec]
    "onepassword" -> [onepasswordspec]
    "doppler" -> [dopplerspec]
    "infisical" -> [infisicalspec]
    "secretspec" -> [secretspecspec]
    -- The default: the chain an app would actually ship with - local
    -- overrides first, shared vaults last.
    _ -> [envspec, dotenvspec, hashicorpspec, boruspec]

-- | The value of a @--flag value@ pair, or "" when the flag is absent.
-- Positional, by index-of: no argument-parsing library.
flag :: [String] -> String -> String
flag args name = go args
  where
    go (head' : next : _) | name == head' = next
    go (_ : rest) = go rest
    go [] = ""

main :: IO ()
main = do
  args <- getArgs

  let url = case args of
        (first : _) | not ("--" `startswith` first) -> first
        _ -> "http://127.0.0.1:8099/whoami"

      source = case flag args "--source" of
        "" -> "chain"
        given -> given

      -- --store names a store outright: the secret must come from that
      -- one, not from whichever provider happens to answer first.
      store = flag args "--store"

  outcome <- try (run url source store)

  case outcome of
    Right code -> exitWith code
    Left err -> do
      hPutStrLn stderr ("sekreto-cli: " ++ displayException (err :: SomeException))
      exitWith (ExitFailure 2)
  where
    startswith prefix body = take (length prefix) body == prefix

run :: String -> String -> String -> IO ExitCode
run url source store = do
  specs <- chainfor source

  -- Construction can fail too, and that is still "the secret could not be
  -- obtained".
  built <- try (sekreto specs True)

  case built of
    Left err -> deny (err :: SomeException)
    Right secrets -> do
      got <- try (if null store then get secrets "api.token" else getfrom secrets store "api.token")

      case got of
        Left err -> deny (err :: SomeException)
        Right token -> call secrets url source store token
  where
    deny err = do
      hPutStrLn stderr ("sekreto-cli: " ++ displayException err)
      pure (ExitFailure 2)

call :: Sekreto -> String -> String -> String -> String -> IO ExitCode
call secrets url source store token = do
  answered <-
    try
      ( Http.request
          "GET"
          url
          [("Authorization", "Bearer " ++ token), ("X-Sekreto-Lang", lang)]
          Nothing
      )

  case answered of
    Left err -> do
      -- Every failure path goes through redaction: the suite greps stdout
      -- and stderr on the pass and the fail path alike.
      clean <- redactall secrets (displayException (err :: SomeException))
      hPutStrLn stderr ("sekreto-cli: " ++ clean)
      pure (ExitFailure 1)
    Right res
      | 200 /= Http.resstatus res -> do
          clean <- redactall secrets (Http.resbody res)
          hPutStrLn stderr ("sekreto-cli: " ++ clean)
          pure (ExitFailure 1)
      | otherwise -> do
          let caller = Json.dig (Json.parse (Http.resbody res)) ["caller"]

          -- Assembled field by field, in the spec's order. Printing a map
          -- here is what has bitten port after port: the language's own
          -- key order is not the one every other port prints.
          putStrLn
            ( "{\"ok\":true"
                ++ ",\"lang\":"
                ++ Json.quote lang
                ++ ",\"source\":"
                ++ Json.quote source
                ++ ",\"store\":"
                ++ Json.quote store
                ++ ",\"caller\":"
                ++ maybe "null" Json.stringify caller
                ++ "}"
            )

          pure ExitSuccess
