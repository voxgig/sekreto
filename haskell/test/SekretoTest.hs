-- RUN: make test
-- RUN-SOME: ./build/sekreto-test envkey
--
-- The sekreto conformance suite. Every port runs these same groups, from
-- the same spec/sekreto.json, through its own voxgig/omni runner.
--
-- No third-party test framework: a failing omni check throws OmniError, so
-- any host framework (hspec, tasty) would report it as a failure. This
-- harness keeps `make test` dependency-free.
--
-- Two value models meet here. omni has a `Json` type with an `Absent`
-- case; the library takes plain Haskell values and a typed spec. The
-- bridge below converts between them explicitly, so nothing about absent,
-- null and value is guessed.
--
-- This is the ONLY part of the port that names voxgig/omni.

module Main (main) where

import AllPlugins (allplugins)
import Control.Exception (SomeException, throwIO, try)
import Data.IORef (IORef, modifyIORef', newIORef, readIORef)
import Data.Maybe (fromMaybe)
import Omni
import Provider (forceall, forced)
import Providers (AuthSpec (..), ProviderSpec (..), emptyauth, emptyspec)
import Sekreto
  ( Options (..),
    Sekreto,
    VaultRef (..),
    awsparam,
    emptyoptions,
    envkey,
    flatname,
    get,
    getfrom,
    parsedotenv,
    redact,
    sekreto,
    sources,
    stores,
    tryfrom,
    tryget,
    validname,
    vaultref,
  )
import Sigv4 (Signing (..), emptysigning, sigv4)
import System.Environment (getArgs)
import System.Exit (exitFailure, exitSuccess)
import System.IO (hFlush, stdout)

-- | Find the shared spec directory by walking up from the working
-- directory. Named `findspec` because `specfile` and `specpath` are both
-- field names on ProviderSpec.
findspec :: String -> IO String
findspec name = search "." (0 :: Int)
  where
    search dir step
      | 8 <= step = throwIO (OmniError ("sekreto: spec not found: " ++ name))
      | otherwise = do
          let cand = dir ++ "/spec/" ++ name
          found <- try (readFile cand) :: IO (Either SomeException String)
          case found of
            Right _ -> pure cand
            Left _ -> search (dir ++ "/..") (step + 1)

-- ------------------------------------------------------------ the bridge

-- | omni's model as the plain string the library's entry points take.
-- Absent, null and every non-string read as the empty string, which is
-- what the corpus asks of a name that is not one.
text :: Json -> String
text (Str value) = value
text _ = ""

-- | A list of strings, as omni compares them.
textlist :: [String] -> Json
textlist values = JList (map Str values)

-- | An optional value: a miss is a JSON null, which omni rewrites to its
-- __NULL__ sentinel under the default flags.
maybestr :: Maybe String -> Json
maybestr = maybe Null Str

-- | One provider spec, out of the spec's declarative chain description.
specof :: Json -> ProviderSpec
specof entry =
  emptyspec
    { speckind = field "kind",
      specname = field "name",
      specprefix = field "prefix",
      specfile = field "file",
      specvalues = [(key, stringify value) | (key, value) <- fromMaybe [] (asmap (jget entry "values"))],
      specdir = field "dir",
      specaddr = field "addr",
      spectoken = field "token",
      specmount = field "mount",
      speckv = truncate <$> asnum (jget entry "kv"),
      specvaultnamespace = field "vaultnamespace",
      specauth = authof (jget entry "auth"),
      speccommand = field "command",
      specprofile = field "profile",
      specbackend = field "backend",
      specreason = field "reason",
      specnamespace = field "namespace",
      spechome = field "home",
      specregion = field "region",
      speckeyid = field "keyid",
      specsecret = field "secret",
      specsession = field "session",
      specproject = field "project",
      specvault = field "vault",
      spectenant = field "tenant",
      specclientid = field "clientid",
      specclientsecret = field "clientsecret",
      specloginaddr = field "loginaddr",
      specimdsaddr = field "imdsaddr",
      specmetadataaddr = field "metadataaddr",
      specapiversion = field "apiversion",
      specconfig = field "config",
      specenvironment = field "environment",
      specpath = field "path"
    }
  where
    field key = text (jget entry key)

authof :: Json -> Maybe AuthSpec
authof entry
  | not (ismap entry) = Nothing
  | otherwise =
      Just
        emptyauth
          { authmethod = field "method",
            authmount = field "mount",
            authrole = field "role",
            authjwt = field "jwt",
            authjwtfile = field "jwtfile",
            authroleid = field "roleid",
            authsecretid = field "secretid"
          }
  where
    field key = text (jget entry key)

-- | Build a Sekreto from the spec's declarative chain description.
--
-- Called INSIDE each subject, never once outside: four entries expect
-- `unsupported kv version`, which the constructor raises, and only a
-- construction inside the subject delivers that to omni as a subject
-- failure.
--
-- Caching is off on every chain the suite builds.
chainof :: Json -> IO Sekreto
chainof entry =
  sekreto
    emptyoptions
      { -- EVERY plugin, to every chain: which is exactly why this suite
        -- can never notice a missing one, and why test/PluginTest.hs
        -- exists beside it.
        optplugins = allplugins,
        optproviders = map specof (fromMaybe [] (aslist (jget entry "chain"))),
        optcache = False
      }

-- | The name a group's entry asks about.
namearg :: Json -> String
namearg entry = text (jget entry "name")

-- ----------------------------------------------------------- the subjects

-- `validname` answers whatever the language calls true; the spec says
-- JSON true, so the adaptation happens here rather than in the library.
validnamesub :: Subject
validnamesub args = pure (Bool (validname (text (head args))))

envkeysub :: Subject
envkeysub args =
  Str <$> forced (envkey (namearg (head args)) (text (jget (head args) "prefix")))

vaultrefsub :: Subject
vaultrefsub args = do
  let ref = vaultref (text (head args))
  path <- forced (refpath ref)
  field <- forced (reffield ref)
  pure (JMap [("path", Str path), ("field", Str field)])

flatnamesub :: Subject
flatnamesub args =
  Str <$> forced (flatname (namearg (head args)) (text (jget (head args) "sep")))

awsparamsub :: Subject
awsparamsub args =
  Str <$> forced (awsparam (namearg (head args)) (text (jget (head args) "prefix")))

parsedotenvsub :: Subject
parsedotenvsub args = do
  entries <- forceall (parsedotenv (text (head args)))
  pure (JMap [(key, Str value) | (key, value) <- entries])

resolvesub :: Subject
resolvesub args = do
  secrets <- chainof (head args)
  Str <$> get secrets (namearg (head args))

trysecretsub :: Subject
trysecretsub args = do
  secrets <- chainof (head args)
  maybestr <$> tryget secrets (namearg (head args))

sourcessub :: Subject
sourcessub args = chainof (head args) >>= fmap textlist . sources

storessub :: Subject
storessub args = chainof (head args) >>= fmap textlist . stores

getfromsub :: Subject
getfromsub args = do
  secrets <- chainof (head args)
  Str <$> getfrom secrets (text (jget (head args) "store")) (namearg (head args))

tryfromsub :: Subject
tryfromsub args = do
  secrets <- chainof (head args)
  maybestr <$> tryfrom secrets (text (jget (head args) "store")) (namearg (head args))

-- Answers the ordered output map itself, which omni compares as a JSON
-- object against the spec's known-answer signatures.
sigv4sub :: Subject
sigv4sub args =
  pure (JMap [(key, Str value) | (key, value) <- sigv4 input])
  where
    entry = head args

    field key = text (jget entry key)

    input =
      emptysigning
        { signmethod = field "method",
          signurl = field "url",
          signservice = field "service",
          signregion = field "region",
          signkeyid = field "keyid",
          signsecret = field "secret",
          signdatetime = field "datetime",
          signheaders =
            [(key, stringify value) | (key, value) <- fromMaybe [] (asmap (jget entry "headers"))],
          signbody = field "body",
          signsession = field "session"
        }

redactsub :: Subject
redactsub args =
  pure
    ( Str
        ( redact
            (text (jget (head args) "text"))
            (map text (fromMaybe [] (aslist (jget (head args) "values"))))
        )
    )

-- ------------------------------------------------------------ the runner

testcase :: IORef Int -> IORef Int -> Maybe String -> String -> IO () -> IO ()
testcase passcount failcount only name body =
  case only of
    Just wanted | wanted /= name -> pure ()
    _ -> do
      outcome <- try body :: IO (Either SomeException ())
      case outcome of
        Right () -> do
          modifyIORef' passcount (+ 1)
          putStrLn ("ok   - " ++ name)
        Left err -> do
          modifyIORef' failcount (+ 1)
          putStrLn ("FAIL - " ++ name)
          putStrLn (errmessage err)
      hFlush stdout

main :: IO ()
main = do
  args <- getArgs
  let only = case args of
        (wanted : _) -> Just wanted
        [] -> Nothing

  passcount <- newIORef 0
  failcount <- newIORef 0

  path <- findspec "sekreto.json"
  pack <- makeRunner path emptyProvider "sekreto"

  let check = testcase passcount failcount only
      group name subject = check name (runset pack (packSet pack name) (Just subject))

  -- validname is the only group with real JSON nulls in its inputs, so it
  -- is the only one that runs with the null modifier off.
  check "validname" (runsetFlags pack (packSet pack "validname") nonullFlags (Just validnamesub))

  group "envkey" envkeysub
  group "vaultref" vaultrefsub
  group "flatname" flatnamesub
  group "awsparam" awsparamsub
  group "parsedotenv" parsedotenvsub
  group "resolve" resolvesub
  group "trysecret" trysecretsub
  group "sources" sourcessub
  group "stores" storessub
  group "getfrom" getfromsub
  group "tryfrom" tryfromsub
  group "sigv4" sigv4sub
  group "redact" redactsub

  passed <- readIORef passcount
  failed <- readIORef failcount

  putStrLn ("\n" ++ show passed ++ " passed, " ++ show failed ++ " failed")

  if 0 == failed then exitSuccess else exitFailure
