-- | What a provider is, what its declarative form looks like, how a
-- provider kind becomes a voxgig/plugin definition - and the four
-- BUILT-IN kinds.
--
-- A provider answers one question: "do you have this secret?" It returns
-- the value, or 'Nothing' to mean "ask the next one". Nothing else about a
-- provider is visible to the caller - which is the point: an app reads
-- @api.token@ and never learns whether it came from the environment, a
-- .env file, HashiCorp Vault, AWS, GCP, Azure or a boru vault.
--
-- Two failure shapes, and they are never interchangeable. A store that
-- does not hold the secret is a MISS ('Nothing') - the chain carries on. A
-- store that could not answer - bad credentials, unreachable host, missing
-- configuration - is an ERROR: falling through there would silently reach
-- for a weaker store.
--
-- THIS MODULE OPENS NO SOCKET, SPEAKS NO TLS AND SPAWNS NO CHILD. What
-- makes a kind built in is that it reads at most a local file; every kind
-- that opens a socket, signs a request or spawns a process is a
-- voxgig/plugin definition in its own module under @plugins/@, which is
-- not on the include path this module is compiled with.
--
-- A port of typescript/src/provider/support.ts and
-- typescript/src/provider/builtin.ts, which are canonical.

module Providers
  ( AuthSpec (..),
    ProviderSpec (..),
    builtinkinds,
    builtins,
    checkaddr,
    chomp,
    emptyauth,
    emptyspec,
    errorcode,
    fail',
    first,
    optionsof,
    pluginkinds,
    providerexport,
    providerplugin,
    readsecret,
    safeaddr,
    specof,
    takeprovider,
    trim,
    trimslash,
  )
where

import Bytes (utf8decode)
import Control.Exception (IOException, evaluate, throwIO, try)
import Control.Monad (when)
import qualified Data.ByteString as B
import Data.Char (isSpace, toLower)
import Data.IORef (IORef, atomicModifyIORef', newIORef, readIORef, writeIORef)
import Data.List (isPrefixOf, isSuffixOf)
import Defs (Definition (..), Inst (..))
import Host (instExport)
import Names (envkey, parsedotenv)
import Provider (Provider (..), SekretoError (..), forced)
import System.Directory (doesDirectoryExist)
import System.Environment (lookupEnv)
import System.FilePath (takeDirectory, (</>))
import System.IO.Error (isDoesNotExistError)
import System.IO.Unsafe (unsafePerformIO)
import Types (details2, raise)
import Value (Value (..), asNum, asStr, isMap, isNum, vget, vhas, vkeys, vset)

-- ------------------------------------------------------------ the specs


-- | Logging in to a vault instead of being handed a token. @method@ is
-- @kubernetes@ or @approle@; @mount@ defaults to the method name.
data AuthSpec = AuthSpec
  { authmethod :: String,
    authmount :: String,
    -- | kubernetes: the Vault role to log in as.
    authrole :: String,
    -- | kubernetes: the service-account JWT itself (tests).
    authjwt :: String,
    -- | kubernetes: where the JWT lives; the conventional pod path by
    -- default.
    authjwtfile :: String,
    -- | approle: the role and secret ids.
    authroleid :: String,
    authsecretid :: String
  }

-- | Printed without its credentials.
--
-- A derived instance would print every field, so
-- @putStrLn ("bad chain: " ++ show specs)@ - which is what someone writes
-- when a chain will not build - would put the service-account JWT and the
-- AppRole secret id on the terminal and into the logs.
instance Show AuthSpec where
  show spec =
    "AuthSpec(method="
      ++ authmethod spec
      ++ ", mount="
      ++ authmount spec
      ++ ", role="
      ++ authrole spec
      ++ ", jwtfile="
      ++ authjwtfile spec
      ++ ", roleid="
      ++ authroleid spec
      ++ ", jwt="
      ++ setornot (authjwt spec)
      ++ ", secretid="
      ++ setornot (authsecretid spec)
      ++ ")"

-- | What a credential field reports about itself.
setornot :: String -> String
setornot value = if null value then "[unset]" else "[set]"

emptyauth :: AuthSpec
emptyauth =
  AuthSpec
    { authmethod = "",
      authmount = "",
      authrole = "",
      authjwt = "",
      authjwtfile = "",
      authroleid = "",
      authsecretid = ""
    }

-- | The declarative form of a provider, as used in config and in the
-- shared spec. @kind@ picks the provider; everything else is that kind's
-- own. A string field left empty means "not configured", which is the
-- same thing everywhere in this library.
data ProviderSpec = ProviderSpec
  { speckind :: String,
    -- | The store name 'Sekreto.getfrom' addresses. Defaults to @kind@.
    specname :: String,
    specprefix :: String,
    -- | dotenv: the file to read. secretspec: the declaration to read.
    specfile :: String,
    -- | memory: literal values, keyed like environment variables, and
    -- ordered by insertion because the spec compares whole maps.
    specvalues :: [(String, String)],
    -- | file: the directory of one-secret-per-file entries.
    specdir :: String,
    -- | hashicorp / boru (wire) / gcp / 1password / doppler / infisical:
    -- the base URL.
    specaddr :: String,
    -- | The store's token, wherever it has one.
    spectoken :: String,
    -- | hashicorp / boru (wire): the KV mount (default @secret@).
    specmount :: String,
    -- | hashicorp: KV engine version, 1 or 2 (default 2).
    speckv :: Maybe Int,
    -- | hashicorp: Vault Enterprise namespace (X-Vault-Namespace).
    specvaultnamespace :: String,
    -- | hashicorp: log in for a token instead of being handed one.
    specauth :: Maybe AuthSpec,
    -- | boru / secretspec: the executable to run.
    speccommand :: String,
    -- | secretspec: the profile to read (@--profile@).
    specprofile :: String,
    -- | secretspec: which of ITS backends to read from (@--provider@).
    -- Named @backend@ here because @provider@ already means a sekreto
    -- provider.
    specbackend :: String,
    -- | secretspec: the audit reason recorded for the read.
    specreason :: String,
    -- | boru: the namespace qualifying the alias.
    specnamespace :: String,
    -- | boru: the vault home, passed as BORU_HOME.
    spechome :: String,
    -- | aws: region and credentials; the standard AWS_* variables fill
    -- the rest.
    specregion :: String,
    speckeyid :: String,
    specsecret :: String,
    specsession :: String,
    -- | gcp / doppler / infisical: the project, however that store names
    -- it.
    specproject :: String,
    -- | azure: the Key Vault name or full URL. 1password: the vault name
    -- or id.
    specvault :: String,
    -- | azure: client-credential login. infisical: universal-auth login.
    spectenant :: String,
    specclientid :: String,
    specclientsecret :: String,
    -- | azure: where to log in / where IMDS answers. gcp: the metadata
    -- server.
    specloginaddr :: String,
    specimdsaddr :: String,
    specmetadataaddr :: String,
    -- | azure: the Key Vault API version (default 7.4).
    specapiversion :: String,
    -- | doppler: the config slug (with @project@).
    specconfig :: String,
    -- | infisical: the environment slug and secret path.
    specenvironment :: String,
    specpath :: String
  }

-- | Printed without its credentials. See the 'AuthSpec' instance: a
-- derived one would put the Vault token, the AWS secret access key and
-- the Azure client secret into whatever formatted it.
instance Show ProviderSpec where
  show spec =
    "ProviderSpec(kind="
      ++ speckind spec
      ++ ", name="
      ++ specname spec
      ++ ", addr="
      ++ specaddr spec
      ++ ", token="
      ++ setornot (spectoken spec)
      ++ ", secret="
      ++ setornot (specsecret spec)
      ++ ", clientsecret="
      ++ setornot (specclientsecret spec)
      ++ ", auth="
      ++ maybe "[none]" show (specauth spec)
      ++ ")"

emptyspec :: ProviderSpec
emptyspec =
  ProviderSpec
    { speckind = "",
      specname = "",
      specprefix = "",
      specfile = "",
      specvalues = [],
      specdir = "",
      specaddr = "",
      spectoken = "",
      specmount = "",
      speckv = Nothing,
      specvaultnamespace = "",
      specauth = Nothing,
      speccommand = "",
      specprofile = "",
      specbackend = "",
      specreason = "",
      specnamespace = "",
      spechome = "",
      specregion = "",
      speckeyid = "",
      specsecret = "",
      specsession = "",
      specproject = "",
      specvault = "",
      spectenant = "",
      specclientid = "",
      specclientsecret = "",
      specloginaddr = "",
      specimdsaddr = "",
      specmetadataaddr = "",
      specapiversion = "",
      specconfig = "",
      specenvironment = "",
      specpath = ""
    }

-- --------------------------------------------------------- the plumbing

-- | The first candidate that is set and non-empty, or empty.
first :: [String] -> String
first candidates = case filter (not . null) candidates of
  (found : _) -> found
  [] -> ""

fail' :: String -> IO a
fail' message = throwIO (SekretoError message)

trim :: String -> String
trim = dropWhile isSpace . reverse . dropWhile isSpace . reverse

dropsuffix :: String -> String -> String
dropsuffix suffix body
  | suffix `isSuffixOf` body = take (length body - length suffix) body
  | otherwise = body

trimslash :: String -> String
trimslash = dropsuffix "/"

-- | An address with any userinfo replaced by @[redacted]@, for messages.
--
-- Every refusal below names the address it refused, and one of them fires
-- precisely because the address carries a credential - so printing it
-- verbatim would write the password to stderr and into the logs. It
-- cannot be cleaned up afterwards either: that password was never
-- resolved as a secret, so redaction has never seen it and never will.
safeaddr :: String -> String
safeaddr addr = case findsub "://" addr of
  Nothing -> addr
  Just mark ->
    let rest = drop (mark + 3) addr
        authority = takeWhile (\head -> not (elem head "/?#")) rest
     in case lastindex '@' authority of
          Nothing -> addr
          Just at -> take (mark + 3) addr ++ "[redacted]" ++ drop (mark + 3 + at) addr

findsub :: String -> String -> Maybe Int
findsub needle hay = go 0 hay
  where
    go _ [] = Nothing
    go at rest
      | needle `isPrefixOf` rest = Just at
      | otherwise = go (at + 1) (tail rest)

lastindex :: Char -> String -> Maybe Int
lastindex want body = case [at | (at, head) <- zip [0 ..] body, want == head] of
  [] -> Nothing
  found -> Just (last found)

-- | Refuse to send a secret-bearing credential in the clear.
--
-- A vault API is HTTPS in any real deployment; plaintext is a dev-mode
-- convenience. Sending a token over http to anything but the local
-- machine puts both the token and the secret it fetches on the wire for
-- anyone on the path, so sekreto will not do it. Loopback stays allowed:
-- that is @vault server -dev@, @boru vault serve@, and this repository's
-- own test harness.
--
-- The address is read by hand, in the same handful of steps in every
-- port, rather than by each platform's URL parser. A dozen parsers
-- disagree about malformed input - where userinfo ends, whether
-- @0177.0.0.1@ is loopback, what an unclosed bracket means - and a check
-- that answers differently in different ports is not a check.
--
-- The rule this parse obeys: it is never more permissive than the client
-- that will dial the address. It ends the authority at @/@, @?@ or @#@
-- only, so a client that also breaks on @\\@ can see only a SHORTER host
-- than this does. It refuses userinfo outright rather than locating its
-- end. It compares the host literally, so a numeric form no parser here
-- agrees on is refused rather than guessed at.
checkaddr :: String -> IO ()
checkaddr addr = do
  scheme <-
    if "https://" `isPrefixOf` addr
      then pure "https://"
      else
        if "http://" `isPrefixOf` addr
          then pure "http://"
          else fail' ("sekreto: not an http(s) address: " ++ safeaddr addr)

  let rest = drop (length scheme) addr
      authority = takeWhile (\head -> not (elem head "/?#")) rest

  -- Userinfo is refused outright rather than parsed around, and on https
  -- as well as http. No store this library speaks authenticates by
  -- userinfo - they take a token or a signature - so an address carrying
  -- one is a mistake at best. At worst it is the attack this whole
  -- function exists to stop: `http://localhost:8200@evil.example.com/` is
  -- a request to evil.example.com that reads, to anything that splits the
  -- authority on ':', as loopback.
  when (elem '@' authority) $
    fail' ("sekreto: refusing an address with embedded credentials: " ++ safeaddr addr)

  -- An opening bracket with no closing one is not an address at all.
  when ("[" `isPrefixOf` authority && not (elem ']' authority)) $
    fail' ("sekreto: not a valid http(s) address: " ++ safeaddr addr)

  when ("https://" /= scheme) $ do
    -- A bracketed IPv6 literal keeps its brackets. Splitting the
    -- authority on the first colon yields '[', so `http://[::1]:8200`
    -- could never match, and a legitimate local vault would be refused.
    let host =
          map toLower $
            if "[" `isPrefixOf` authority
              then takeWhile (']' /=) authority ++ "]"
              else takeWhile (':' /=) authority

    when (not (elem host ["localhost", "127.0.0.1", "::1", "[::1]"])) $
      fail'
        ("sekreto: refusing to send a token in plaintext to " ++ safeaddr addr ++ " (use https)")

-- | Read a whole file. Absence - of the file, or of a directory on the
-- way to it - is a MISS, because it means "no secrets here"; anything
-- else is an error, because returning a miss there falls silently through
-- to a weaker store.
--
-- Absence is asked of the directory, not through an @exists@ predicate:
-- the obvious spelling answers "does not exist" for a permission error
-- too, and that would turn a locked mount - the canonical "unreadable
-- store" - into a miss.
readsecret :: String -> IO (Either String (Maybe String))
readsecret path = do
  outcome <- try (B.readFile path)

  case outcome of
    Right raw -> pure (Right (Just (utf8decode raw)))
    Left err
      | isDoesNotExistError err -> pure (Right Nothing)
      | otherwise -> do
          here <- doesDirectoryExist (takeDirectory path)
          if not here
            then pure (Right Nothing)
            else pure (Left (show (err :: IOException)))

-- ---------------------------------------------------------- built in

-- | Environment variables: @api.token@ from @API_TOKEN@.
envprovider :: String -> Provider
envprovider prefix =
  Provider
    { lookupsecret = \name -> do
        key <- forced (envkey name prefix)
        lookupEnv key,
      describe = "env" ++ (if null prefix then "" else ":" ++ prefix)
    }

-- | Literal values, keyed like environment variables. The spec uses this
-- to test chain behaviour without touching the outside world.
memoryprovider :: [(String, String)] -> String -> Provider
memoryprovider values prefix =
  Provider
    { lookupsecret = \name -> do
        key <- forced (envkey name prefix)
        -- `lookup`, not a default: an absent key is a miss, and the
        -- empty string is a hit.
        pure (lookup key values),
      describe = "memory" ++ (if null prefix then "" else ":" ++ prefix)
    }

-- | A @.env@ file, read once, keyed exactly like the environment.
--
-- Loaded LAZILY: the spec's stores group puts a dotenv provider in a
-- chain and never looks anything up, and an eager constructor would read
-- whatever @.env@ happened to sit in the working directory.
dotenvprovider :: String -> String -> IO Provider
dotenvprovider file prefix = do
  loaded <- newIORef Nothing

  let load = do
        cached <- readIORef loaded
        case cached of
          Just values -> pure values
          Nothing -> do
            outcome <- readsecret file
            values <- case outcome of
              Right Nothing -> pure []
              Right (Just body) -> pure (parsedotenv body)
              Left why -> fail' ("sekreto: dotenv provider cannot read " ++ file ++ ": " ++ why)
            writeIORef loaded (Just values)
            pure values

  pure
    Provider
      { lookupsecret = \name -> do
          key <- forced (envkey name prefix)
          values <- load
          pure (lookup key values),
        describe = "dotenv:" ++ file
      }

-- | A directory of one-secret-per-file entries, keyed like the
-- environment: @api.token@ reads @\<dir>/API_TOKEN@.
--
-- This is the shape of a mounted Kubernetes Secret, a Docker or Swarm
-- secret, and a systemd credentials directory, so those all work with no
-- further configuration. Read on every lookup, never cached. One trailing
-- newline is stripped - tools that write these files disagree about it,
-- and a newline is never part of a secret on purpose.
fileprovider :: String -> String -> Provider
fileprovider dir prefix =
  Provider
    { lookupsecret = \name -> do
        key <- forced (envkey name prefix)
        let path = dir </> key

        outcome <- readsecret path

        case outcome of
          Right Nothing -> pure Nothing
          Right (Just body) -> pure (Just (chomp body))
          Left why -> fail' ("sekreto: file provider cannot read " ++ path ++ ": " ++ why),
      describe = "file:" ++ dir
    }

-- | Strip exactly one trailing newline, @\\r\\n@ before @\\n@.
chomp :: String -> String
chomp body
  | "\r\n" `isSuffixOf` body = take (length body - 2) body
  | "\n" `isSuffixOf` body = take (length body - 1) body
  | otherwise = body

-- ------------------------------------- providers as plugin definitions

-- | The export key under which a provider definition publishes the
-- provider it built. 'Sekreto.sekreto' reads @\<ref>/provider@ off the
-- host.
providerexport :: String
providerexport = "provider"

-- | The voxgig/plugin error code a 'SekretoError' travels under when a
-- definition's @define@ refuses.
--
-- plugin wraps a code-less error raised by a callback as
-- @plugin_define_failed@ and keeps one that already carries a code. A
-- provider that refuses its own configuration - @kv: 3@, a missing
-- project - raises a 'SekretoError', and that message is pinned by the
-- spec byte for byte, so it must come back out of the host exactly as it
-- went in. 'providerplugin' puts this code on; 'Sekreto.sekreto' takes it
-- off. Nowhere else catches and rewraps.
errorcode :: String
errorcode = "sekreto_error"

-- | THE PROVIDER SLOT TABLE, and the one place this port diverges from
-- the canonical.
--
-- plugin's value model carries JSON - null, booleans, numbers, strings,
-- lists and maps - and a 'Provider' is a record of two functions, so
-- there is no @Opaque@ case to hand one through. A definition's @define@
-- therefore exports the SLOT NUMBER of the provider it built, and
-- 'Sekreto.sekreto' reads it back. plugin's own zig port carries its
-- error slot the same way, for the same reason.
--
-- It is NOT a registry of kinds, and importing a module puts nothing in
-- it. A slot is filled by @define@, which runs only when a constructor
-- was handed the definition and a chain named that kind, and it is
-- emptied the moment the chain has the provider - so between two
-- constructions the table is empty. Two constructions running at once
-- share the counter and no more; this port claims no thread safety
-- across them, as zig's does not.
{-# NOINLINE slots #-}
slots :: IORef (Integer, [(Integer, Provider)])
slots = unsafePerformIO (newIORef (1, []))

-- | Hold a provider, answering the slot it went into.
holdprovider :: Provider -> IO Integer
holdprovider provider = atomicModifyIORef' slots step
  where
    step (next, held) = ((next + 1, (next, provider) : held), next)

-- | The provider a @define@ exported, TAKEN out of the table: a chain
-- reads its provider once. Answers 'Nothing' for a definition that
-- exported something else, or nothing at all.
takeprovider :: Value -> IO (Maybe Provider)
takeprovider exported
  | not (isNum exported) = pure Nothing
  | otherwise = atomicModifyIORef' slots step
  where
    slot = round (asNum exported) :: Integer
    step (next, held) = ((next, filter ((slot /=) . fst) held), lookup slot held)

-- | A provider kind, as a voxgig/plugin definition.
--
-- This is the whole bridge between the two libraries. The definition's
-- name is the @kind@ a 'ProviderSpec' names; its @define@ reads the spec
-- back off the instance's options, builds the provider with @make@, and
-- exports it. Nothing runs at activate: a provider opens nothing until
-- its first lookup, so there is nothing to capture - a provider that does
-- hold a resource acquires it there and lets the instance scope unwind
-- it.
--
-- Every built-in and every plugin is made this way, so a custom provider
-- kind is one call:
--
-- > providerplugin "mystore" (\spec -> pure (mystore (specaddr spec)))
providerplugin :: String -> (ProviderSpec -> IO Provider) -> Definition
providerplugin kind make =
  Definition
    { dName = kind,
      dShape = VNull,
      dDefine = Just define,
      dActivate = Nothing,
      dDeactivate = Nothing,
      -- An instance torn down before its chain read the slot - a define
      -- that succeeded and an activate that did not - gives it back
      -- here, so an abandoned host leaves nothing behind.
      dClose = Just release,
      dReconfigure = Nothing
    }
  where
    define inst = do
      options <- readIORef (iOptions inst)

      -- `try` on 'SekretoError' alone: anything else a `make` raises is
      -- not sekreto's to rewrite, and travels out as the host reports it.
      built <- try (make (specof options) >>= evaluate)

      case built of
        Right provider -> do
          slot <- holdprovider provider
          instExport inst providerexport (VNum (fromIntegral slot))
        Left (SekretoError message) ->
          raise errorcode message (details2 "ref" (VStr (iRef inst)) "cause" (VStr message))

    release inst = do
      exported <- readIORef (iExports inst)
      _ <- takeprovider (vget exported providerexport)
      pure ()

-- | A 'ProviderSpec' read back off a plugin instance's options map - the
-- shape 'optionsof' produced, and the shape a config document would.
specof :: Value -> ProviderSpec
specof options =
  emptyspec
    { speckind = text "kind",
      specname = text "name",
      specprefix = text "prefix",
      specfile = text "file",
      specvalues = [(key, asStr (vget held key)) | key <- vkeys held],
      specdir = text "dir",
      specaddr = text "addr",
      spectoken = text "token",
      specmount = text "mount",
      speckv = if vhas options "kv" then Just (round (asNum (vget options "kv"))) else Nothing,
      specvaultnamespace = text "vaultnamespace",
      specauth = if isMap auth then Just (authof auth) else Nothing,
      speccommand = text "command",
      specprofile = text "profile",
      specbackend = text "backend",
      specreason = text "reason",
      specnamespace = text "namespace",
      spechome = text "home",
      specregion = text "region",
      speckeyid = text "keyid",
      specsecret = text "secret",
      specsession = text "session",
      specproject = text "project",
      specvault = text "vault",
      spectenant = text "tenant",
      specclientid = text "clientid",
      specclientsecret = text "clientsecret",
      specloginaddr = text "loginaddr",
      specimdsaddr = text "imdsaddr",
      specmetadataaddr = text "metadataaddr",
      specapiversion = text "apiversion",
      specconfig = text "config",
      specenvironment = text "environment",
      specpath = text "path"
    }
  where
    text key = asStr (vget options key)
    held = vget options "values"
    auth = vget options "auth"

authof :: Value -> AuthSpec
authof entry =
  emptyauth
    { authmethod = text "method",
      authmount = text "mount",
      authrole = text "role",
      authjwt = text "jwt",
      authjwtfile = text "jwtfile",
      authroleid = text "roleid",
      authsecretid = text "secretid"
    }
  where
    text key = asStr (vget entry key)

-- | A 'ProviderSpec' as a plugin instance's options map.
--
-- Only the keys actually set are written, so @hostList@ and a declaration
-- document read like the configuration someone wrote rather than like the
-- record.
optionsof :: ProviderSpec -> Value
optionsof spec = foldl set (VMap []) fields
  where
    set out (key, value) = case value of VNull -> out; _ -> vset out key value

    fields =
      [ ("kind", text (speckind spec)),
        ("name", text (specname spec)),
        ("prefix", text (specprefix spec)),
        ("file", text (specfile spec)),
        ("values", if null (specvalues spec) then VNull else VMap [(key, VStr value) | (key, value) <- specvalues spec]),
        ("dir", text (specdir spec)),
        ("addr", text (specaddr spec)),
        ("token", text (spectoken spec)),
        ("mount", text (specmount spec)),
        ("kv", maybe VNull (VNum . fromIntegral) (speckv spec)),
        ("vaultnamespace", text (specvaultnamespace spec)),
        ("auth", maybe VNull authoptions (specauth spec)),
        ("command", text (speccommand spec)),
        ("profile", text (specprofile spec)),
        ("backend", text (specbackend spec)),
        ("reason", text (specreason spec)),
        ("namespace", text (specnamespace spec)),
        ("home", text (spechome spec)),
        ("region", text (specregion spec)),
        ("keyid", text (speckeyid spec)),
        ("secret", text (specsecret spec)),
        ("session", text (specsession spec)),
        ("project", text (specproject spec)),
        ("vault", text (specvault spec)),
        ("tenant", text (spectenant spec)),
        ("clientid", text (specclientid spec)),
        ("clientsecret", text (specclientsecret spec)),
        ("loginaddr", text (specloginaddr spec)),
        ("imdsaddr", text (specimdsaddr spec)),
        ("metadataaddr", text (specmetadataaddr spec)),
        ("apiversion", text (specapiversion spec)),
        ("config", text (specconfig spec)),
        ("environment", text (specenvironment spec)),
        ("path", text (specpath spec))
      ]

    text value = if null value then VNull else VStr value

authoptions :: AuthSpec -> Value
authoptions use = foldl set (VMap []) fields
  where
    set out (key, value) = case value of VNull -> out; _ -> vset out key value

    fields =
      [ ("method", text (authmethod use)),
        ("mount", text (authmount use)),
        ("role", text (authrole use)),
        ("jwt", text (authjwt use)),
        ("jwtfile", text (authjwtfile use)),
        ("roleid", text (authroleid use)),
        ("secretid", text (authsecretid use))
      ]

    text value = if null value then VNull else VStr value

-- | The four built-in provider kinds, as definitions, in a fresh list:
-- @env@, @memory@, @dotenv@ and @file@ - the same four in every port.
-- 'Sekreto.sekreto' puts them in every catalog ahead of the plugins it is
-- handed.
builtins :: [Definition]
builtins =
  [ providerplugin "env" (\spec -> pure (envprovider (specprefix spec))),
    providerplugin "memory" (\spec -> pure (memoryprovider (specvalues spec) (specprefix spec))),
    providerplugin "dotenv" (\spec -> dotenvprovider (first [specfile spec, ".env"]) (specprefix spec)),
    providerplugin "file" (\spec -> pure (fileprovider (specdir spec) (specprefix spec)))
  ]

-- | The four kinds built into this module.
builtinkinds :: [String]
builtinkinds = ["env", "memory", "dotenv", "file"]

-- | Every kind that ships as a plugin, so that an unknown kind can be
-- told from a plugin that was not passed in.
--
-- This module names the KINDS, which are spec, and imports none of the
-- modules that implement them - a list of ten strings reaches nothing.
pluginkinds :: [String]
pluginkinds =
  [ "hashicorp",
    "boru",
    "awssecrets",
    "awsparams",
    "gcpsecrets",
    "azuresecrets",
    "onepassword",
    "doppler",
    "infisical",
    "secretspec"
  ]
