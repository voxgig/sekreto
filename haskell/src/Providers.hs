-- | The providers a 'Sekreto' chains together.
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
-- configuration - is an ERROR: falling through there would quietly reach
-- for a weaker store.
--
-- A port of typescript/src/Providers.ts, which is canonical.

module Providers
  ( AuthSpec (..),
    ProviderSpec (..),
    checkaddr,
    emptyauth,
    emptyspec,
    makeprovider,
    renewtime,
    safeaddr,
    sekreto,
  )
where

import Bytes (unbase64, utf8decode)
import Control.Exception (IOException, throwIO, try)
import Control.Monad (when)
import qualified Data.ByteString as B
import Data.Char (isSpace, toLower)
import Data.IORef (IORef, newIORef, readIORef, writeIORef)
import Data.List (isInfixOf, isPrefixOf, isSuffixOf)
import Data.Maybe (fromMaybe, isJust, isNothing)
import Data.Time.Clock (getCurrentTime)
import Data.Time.Clock.POSIX (getPOSIXTime)
import Data.Time.Format (defaultTimeLocale, formatTime)
import Http (Response (..), nakedurl)
import qualified Http
import Json (Json (..))
import qualified Json
import Provider (Name, Provider (..), SekretoError (..), forced)
import Sekreto
  ( Sekreto,
    VaultRef (..),
    awsparam,
    checkname,
    envkey,
    flatname,
    makechain,
    parsedotenv,
    vaultref,
  )
import Sigv4 (Signing (..), emptysigning, sigv4, uriescape)
import System.Directory (doesDirectoryExist)
import System.Environment (getEnvironment, lookupEnv)
import System.Exit (ExitCode (..))
import System.FilePath (takeDirectory, (</>))
import System.IO.Error (isDoesNotExistError)
import System.Process (CreateProcess (..), proc, readCreateProcessWithExitCode)

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

fromenv :: String -> IO String
fromenv name = fromMaybe "" <$> lookupEnv name

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

-- | Milliseconds since the epoch: the clock the renewal deadline uses.
nowms :: IO Integer
nowms = round . (1000 *) <$> getPOSIXTime

-- | A deadline that never arrives: a configured token never expires, and
-- neither does a login whose expiry was absent or zero. Integer is
-- unbounded, so this is a chosen far future rather than a maxBound.
never :: Integer
never = 10 ^ (18 :: Int)

-- | When a logged-in token must be renewed, from its expiry in seconds -
-- a JSON number, or a string, as Azure IMDS sends it: now + max(seconds -
-- 60, 1). A missing or zero expiry means never renew.
renewtime :: Maybe Json -> IO Integer
renewtime expires =
  case seconds of
    value
      | isNaN value || 0 >= value -> pure never
      | otherwise -> do
          at <- nowms
          pure (at + round (1000 * max (value - 60) 1))
  where
    seconds = case expires of
      Just (JNum value) -> value
      Just (JStr value) -> case reads value :: [(Double, String)] of
        [(parsed, "")] -> parsed
        _ -> 0
      _ -> 0

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
              then take (maybe 0 (+ 1) (lastindex ']' authority)) authority
              else takeWhile (':' /=) authority

    when (not (elem host ["localhost", "127.0.0.1", "::1", "[::1]"])) $
      fail'
        ("sekreto: refusing to send a token in plaintext to " ++ safeaddr addr ++ " (use https)")

-- | One JSON round-trip's result: the status, and the parsed body.
data Answer = Answer {ansstatus :: Int, ansbody :: Maybe Json}

-- | One JSON round-trip. Network failure is always an error - an
-- unreachable store is a store that could not answer.
fetchjson :: String -> String -> [(String, String)] -> Maybe String -> IO Answer
fetchjson method url headers body = do
  res <- Http.request method url headers body

  let parsed = Json.parse (resbody res)

  -- A success status promised JSON; a body that does not parse means the
  -- store could not answer coherently, and treating it as a miss would
  -- fall through to a weaker store. Error statuses may carry any body -
  -- they are decided on status alone.
  when (200 == resstatus res && isNothing parsed) $
    fail' ("sekreto: malformed response from " ++ nakedurl url)

  pure (Answer (resstatus res) parsed)

-- | What a finished child process left behind.
data Ran = Ran {ranout :: String, ranwhy :: String, ranstatus :: Int}

-- | Run a child to completion and collect both its streams.
--
-- @readCreateProcessWithExitCode@ closes the child's stdin - so a CLI
-- that reads it, one prompting for a passphrase when its environment
-- variable is absent, sees EOF and gives up instead of waiting forever -
-- and drains stdout and stderr CONCURRENTLY. Reading stdout to EOF and
-- only then reading stderr deadlocks the moment the child writes more
-- than one pipe buffer (64 KiB on Linux) to stderr, and nothing here sets
-- a timeout, so that hang would be permanent. secretspec's diagnostics
-- are box-drawn and reach that size easily.
--
-- Arguments are passed as a list, never through a shell, and no secret
-- ever goes on a command line where the process table would publish it.
runcmd :: String -> [String] -> [(String, String)] -> IO Ran
runcmd command args extraenv = do
  base <- getEnvironment

  let shaped =
        (proc command args)
          { env = if null extraenv then Nothing else Just (foldl setvar base extraenv)
          }

  outcome <- try (readCreateProcessWithExitCode shaped "")

  case outcome :: Either IOException (ExitCode, String, String) of
    Left err -> fail' ("sekreto: cannot run " ++ command ++ ": " ++ show err)
    Right (code, out, why) ->
      pure
        Ran
          { ranout = out,
            ranwhy = trim why,
            ranstatus = case code of
              ExitSuccess -> 0
              ExitFailure status -> status
          }
  where
    setvar entries (key, value) = (key, value) : filter ((key /=) . fst) entries

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

-- ----------------------------------------------------------- hashicorp

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

-- | The working token: a configured token is kept forever, a logged-in
-- token is renewed shortly before its lease runs out - a long-running
-- process must not keep presenting a token the vault already expired.
currenttoken :: IORef (Maybe String) -> IORef Integer -> IO String -> IO String
currenttoken livetoken renewat login = do
  held <- readIORef livetoken
  at <- nowms
  due <- readIORef renewat

  case held of
    Just token | at < due -> pure token
    _ -> do
      fresh <- login
      writeIORef livetoken (Just fresh)
      pure fresh

-- | The name's vault location, forced here so that an invalid name is
-- refused before any request is built.
vaultrefof :: Name -> IO VaultRef
vaultrefof name = do
  let ref = vaultref name
  _ <- forced (refpath ref)
  _ <- forced (reffield ref)
  pure ref

-- ---------------------------------------------------------------- boru

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

-- ---------------------------------------------------------- secretspec

-- | SecretSpec (https://secretspec.dev).
--
-- SecretSpec is a declaration - a @secretspec.toml@ naming the secrets a
-- project needs - plus a chain of its own backends to satisfy them from.
-- That makes it the same shape as sekreto one level down, and the reason
-- to support it is the reason sekreto exists: a project that has already
-- declared its secrets there should not have to declare them again here.
--
-- A reason is required, not optional: SecretSpec records every read in an
-- audit log and refuses to read at all without one.
secretspecprovider :: ProviderSpec -> Provider
secretspecprovider spec =
  Provider
    { lookupsecret = \name -> do
        key <- forced (envkey name (specprefix spec))

        let args =
              [w | not (null (specfile spec)), w <- ["--file", specfile spec]]
                ++ ["get", key]
                ++ [w | not (null (specbackend spec)), w <- ["--provider", specbackend spec]]
                ++ [w | not (null (specprofile spec)), w <- ["--profile", specprofile spec]]
                ++ ["--reason", first [specreason spec, "sekreto"]]

        ran <- runcmd command args []

        if 0 == ranstatus ran
          then pure (Just (chomp (ranout ran)))
          else
            if secretspecmiss (ranwhy ran) key
              then pure Nothing
              else
                fail'
                  ( "sekreto: secretspec error: "
                      ++ ( if null (ranwhy ran)
                             then "exit " ++ show (ranstatus ran)
                             else ranwhy ran
                         )
                  ),
      describe = "secretspec" ++ (if null (specbackend spec) then "" else ":" ++ specbackend spec)
    }
  where
    command = first [speccommand spec, "secretspec"]

-- | Does this SecretSpec failure mean "no such secret" rather than "I
-- could not answer"?
--
-- SecretSpec says @Secret 'API_TOKEN' not found@ for both a name it does
-- not declare and one declared with no value, and both are misses.
--
-- MATCHED ON THE WHOLE PHRASE, NOT ON "not found". SecretSpec also says
-- @Provider backend 'keyring' not found@, which is a store that could not
-- answer at all - and reading that as a miss is the worst failure this
-- library has, because the chain then falls through to a weaker store
-- without saying so. The key is required to appear, so the two cannot be
-- confused.
secretspecmiss :: String -> String -> Bool
secretspecmiss why key = isInfixOf ("Secret '" ++ key ++ "' not found") why

-- ----------------------------------------------------------------- aws

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

-- ----------------------------------------------------------------- gcp

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
gcpprovider :: ProviderSpec -> IO Provider
gcpprovider spec = do
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

-- --------------------------------------------------------------- azure

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
azureprovider :: ProviderSpec -> IO Provider
azureprovider spec = do
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

-- ----------------------------------------------------------- 1password

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

                  byrole role wanted =
                    case filter
                      (\field -> Just wanted == Json.asstr (Json.dig (Just field) [role]))
                      fields of
                      (field : _) -> Json.text (Json.dig (Just field) ["value"])
                      [] -> Nothing

              -- Two full passes, in order: purpose first, then label.
              pure (maybe (byrole "label" "value") Just (byrole "purpose" "PASSWORD")),
        describe = "onepassword:" ++ specvault spec
      }

-- ------------------------------------------------------------- doppler

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

-- ------------------------------------------------------------ infisical

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

-- ------------------------------------------------------------- factory

-- | Build a provider from its declarative form - the same shape the
-- shared spec and an app's config file use.
makeprovider :: ProviderSpec -> IO Provider
makeprovider spec = case speckind spec of
  "env" -> pure (envprovider (specprefix spec))
  "dotenv" -> dotenvprovider (first [specfile spec, ".env"]) (specprefix spec)
  "memory" -> pure (memoryprovider (specvalues spec) (specprefix spec))
  "file" -> pure (fileprovider (specdir spec) (specprefix spec))
  "hashicorp" -> hashicorpprovider spec
  "boru" -> pure (boruprovider spec)
  "secretspec" -> pure (secretspecprovider spec)
  "awssecrets" -> pure (awssecretsprovider spec)
  "awsparams" -> pure (awsparamsprovider spec)
  "gcpsecrets" -> gcpprovider spec
  "azuresecrets" -> azureprovider spec
  "onepassword" -> onepasswordprovider spec
  "doppler" -> dopplerprovider spec
  "infisical" -> infisicalprovider spec
  other -> fail' ("sekreto: unknown provider kind: " ++ other)

-- | Make a chain from declarative provider specs.
--
-- Eager and in chain order, so a spec that cannot be built raises here
-- rather than at the first read. Construction still contacts nothing.
sekreto :: [ProviderSpec] -> Bool -> IO Sekreto
sekreto specs docache = do
  providers <- mapM makeprovider specs
  makechain providers (map (Just . specname) specs) docache
