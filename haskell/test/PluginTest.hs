-- RUN: make test-plugins
-- RUN-SOME: ./build/sekreto-plugins "a store name must be a valid tag"
--
-- THE PLUGIN SEAM, from both sides.
--
-- Moving the provider kinds that open sockets and spawn processes out of
-- the core made a consumer's plugin list decide what a chain may name: a
-- kind nobody passed in is not in the catalog, and a chain naming it is
-- refused. That is the intended behaviour, and it means a consumer can be
-- broken without a single conformance entry noticing - the conformance
-- suite passes every plugin to every chain it builds, so it can never see
-- a missing one. So the full set is pinned here: it holds every kind,
-- every kind builds, and the CLI passes it.
--
-- The two claims that can only be read out of a BUILT ARTIFACT - the core
-- carries no plugin, and one plugin links one - are test/checkcore.py,
-- which this suite runs. `nm` is the authority there, not a grep of the
-- source: three other ports were audited with a source-level check and
-- found cores that could open a socket and spawn a child without naming
-- one word on its list.

module Main (main) where

import AllPlugins (allplugins)
import Catalog (catalogNames)
import Control.Exception (Exception, SomeException, displayException, fromException, throwIO, try)
import Control.Monad (when)
import Data.IORef (IORef, modifyIORef', newIORef, readIORef)
import Data.List (isInfixOf, nub, sort)
import Data.Maybe (isJust)
import Defs (Definition (..))
import Hashicorp (hashicorp)
import qualified Host as Plugin
import Provider (Provider (..), SekretoError (..))
import Providers
  ( ProviderSpec (..),
    builtinkinds,
    builtins,
    emptyspec,
    pluginkinds,
    providerplugin,
    takeprovider,
  )
import Sekreto
  ( Options (..),
    Sekreto,
    catalog,
    close,
    emptyoptions,
    get,
    getfrom,
    host,
    redactall,
    sekreto,
    sources,
    stores,
    tryget,
  )
import System.Environment (getArgs)
import System.Exit (ExitCode (..), exitFailure, exitSuccess)
import System.IO (hFlush, hPutStrLn, stderr, stdout)
import System.Process (proc, readCreateProcessWithExitCode)
import Types (PluginError (..), raise)
import Value (Value (..), asStr, vget, vkeys)

-- ------------------------------------------------------------ assertions

newtype Failed = Failed String

instance Show Failed where
  show (Failed message) = message

instance Exception Failed

same :: (Eq a, Show a) => String -> a -> a -> IO ()
same what wanted got =
  when (wanted /= got) $
    throwIO (Failed (what ++ "\n  wanted " ++ show wanted ++ "\n  got    " ++ show got))

-- | The message a chain refused with, AS A 'SekretoError'. Catching that
-- type and no other is the assertion: a 'PluginError' that reached here
-- would escape uncaught and fail the entry, which is what pins the
-- @sekreto_error@ bridge.
refusal :: IO Sekreto -> IO String
refusal build = do
  outcome <- try build
  case outcome of
    Left (SekretoError message) -> pure message
    Right _ -> throwIO (Failed "the chain built, and it should not have")

-- | The same for anything else a definition raised, which sekreto must
-- hand back untouched.
raised :: IO Sekreto -> IO SomeException
raised build = do
  outcome <- try build
  case outcome of
    Left err -> pure err
    Right _ -> throwIO (Failed "the chain built, and it should not have")

refs :: Sekreto -> IO [String]
refs secrets = vkeys <$> Plugin.hostList (host secrets)

statuses :: Sekreto -> IO [String]
statuses secrets = do
  listed <- Plugin.hostList (host secrets)
  pure (nub [asStr (vget listed ref) | ref <- vkeys listed])

names :: Sekreto -> IO [String]
names secrets = do
  listed <- catalogNames (catalog secrets)
  pure (map asStr (case listed of VList held -> held; _ -> []))

memoryspec :: [(String, String)] -> ProviderSpec
memoryspec values = emptyspec {speckind = "memory", specvalues = values}

-- ------------------------------------------------------------- the seam

thefullsetholdseverykind :: IO ()
thefullsetholdseverykind = do
  same "the full set" (sort pluginkinds) (sort (map dName allplugins))
  same "no kind twice" (length pluginkinds) (length allplugins)
  same "the built-in definitions" builtinkinds (map dName builtins)

-- Naming a kind is not enough: a kind can be in the catalog and still
-- fail to build. Construction is what the CLI does before any network.
everykindbuildsfromaspec :: IO ()
everykindbuildsfromaspec = do
  let every = sort (builtinkinds ++ pluginkinds)
      chain =
        [ emptyspec
            { speckind = kind,
              specaddr = "http://127.0.0.1:8200",
              spectoken = "t",
              specdir = "/tmp",
              specfile = "/tmp/.env"
            }
          | kind <- every
        ]

  secrets <- sekreto emptyoptions {optplugins = allplugins, optproviders = chain}

  same "stores" every =<< stores secrets
  same "instance refs" every =<< refs secrets
  same "every instance live" ["live"] =<< statuses secrets

-- THE CONSUMER'S LIST is what no conformance run can see: a CLI passing
-- one plugin instead of ten leaves all fourteen groups green and fails
-- nine integration checks. The whole expression is pinned, closing brace
-- included, so that `take 1 allplugins` cannot satisfy it.
theclipassesthefullset :: IO ()
theclipassesthefullset = do
  body <- readFile "cli/Main.hs"

  let wanted =
        [ "import AllPlugins (allplugins)",
          "sekreto emptyoptions {optplugins = allplugins, optproviders = specs}"
        ]

  mapM_
    (\line -> when (not (line `isInfixOf` body)) $ throwIO (Failed ("cli/Main.hs has no " ++ show line)))
    wanted

onepluginisenough :: IO ()
onepluginisenough = do
  secrets <-
    sekreto
      emptyoptions
        { optplugins = [hashicorp],
          optproviders =
            [ memoryspec [("API_TOKEN", "tok01")],
              emptyspec
                { speckind = "hashicorp",
                  specname = "prod",
                  specaddr = "https://vault.example.com",
                  spectoken = "t"
                }
            ]
        }

  same "stores" ["memory", "prod"] =<< stores secrets
  same "sources" ["memory", "hashicorp:https://vault.example.com/secret"] =<< sources secrets
  same "get" "tok01" =<< get secrets "api.token"

  -- The plugin host is what the chain is made of, and it reads like the
  -- chain: the kind, or kind$store for a named store.
  same "instance refs" ["hashicorp$prod", "memory"] =<< refs secrets
  same "catalog" ["dotenv", "env", "file", "hashicorp", "memory"] =<< names secrets

akindnotpassedinisrefused :: IO ()
akindnotpassedinisrefused = do
  message <-
    refusal
      ( sekreto
          emptyoptions
            { optplugins = [hashicorp],
              optproviders = [emptyspec {speckind = "doppler", spectoken = "t"}]
            }
      )

  same
    "the refusal names the fix"
    ( "sekreto: unknown provider kind: doppler (available: dotenv, env, file, hashicorp, memory)"
        ++ " - doppler is a sekreto plugin, not built in: pass it in the plugins option"
    )
    message

  -- A kind nobody ships is a typo, and gets no such hint.
  typo <- refusal (sekreto emptyoptions {optproviders = [emptyspec {speckind = "vualt"}]})

  same
    "a typo gets no hint"
    "sekreto: unknown provider kind: vualt (available: dotenv, env, file, memory)"
    typo

-- Two providers MAY share a store name - a directed read walks both, and
-- the spec pins it - but an instance ref may not, so the second gets a
-- numbered tag from the host and keeps its store name.
arepeatedstorenamenumberstheinstance :: IO ()
arepeatedstorenamenumberstheinstance = do
  secrets <-
    sekreto
      emptyoptions
        { optproviders =
            [ memoryspec [],
              memoryspec [("API_TOKEN", "second")],
              (memoryspec []) {specname = "pair"},
              (memoryspec [("API_TOKEN", "pair2")]) {specname = "pair"}
            ]
        }

  same "stores" ["memory", "pair"] =<< stores secrets
  same "instance refs" ["memory", "memory$1", "memory$2", "memory$pair"] =<< refs secrets
  same "memory" "second" =<< getfrom secrets "memory" "api.token"
  same "pair" "pair2" =<< getfrom secrets "pair" "api.token"

astorenamemustbeavalidtag :: IO ()
astorenamemustbeavalidtag = do
  message <- refusal (sekreto emptyoptions {optproviders = [(memoryspec []) {specname = "my store"}]})
  same "the refusal" "sekreto: invalid store name: my store" message

-- A provider that refuses its own configuration raises a SekretoError
-- from inside the plugin's `define`. The spec pins that message byte for
-- byte, so it must come back out of the host as itself - not wrapped as
-- plugin_define_failed, and not as a PluginError.
asekretoerrorcomesbackoutasitself :: IO ()
asekretoerrorcomesbackoutasitself = do
  message <-
    refusal
      ( sekreto
          emptyoptions
            { optplugins = [hashicorp],
              optproviders =
                [ emptyspec
                    { speckind = "hashicorp",
                      specaddr = "http://127.0.0.1:1",
                      spectoken = "t",
                      speckv = Just 3
                    }
                ]
            }
      )

  same "the refusal" "sekreto: hashicorp: unsupported kv version: 3" message

-- ...and any other error is not sekreto's to rewrite: it surfaces as the
-- host reports it, naming the instance and the cause.
anyothererroristhehostsreport :: IO ()
anyothererroristhehostsreport = do
  let bare = PluginError "" "boom" (VMap []) "boom"
      broken =
        Definition
          { dName = "broken",
            dShape = VNull,
            dDefine = Just (\_ -> throwIO bare),
            dActivate = Nothing,
            dDeactivate = Nothing,
            dClose = Nothing,
            dReconfigure = Nothing
          }

  err <- raised (sekreto emptyoptions {optplugins = [broken], optproviders = [emptyspec {speckind = "broken"}]})

  -- The TYPE, and the code on it - not a substring of what it renders
  -- to. The canonical reads `err.code`, which a SekretoError has not
  -- got; here that is a PluginError, which is what "the host's report"
  -- means. A rewrap into a SekretoError carrying the host's own text
  -- renders identically, so rendering it can never be the check.
  case fromException err :: Maybe PluginError of
    Just found -> same "the host's own code" "plugin_define_failed" (peCode found)
    Nothing ->
      throwIO (Failed ("sekreto rewrote an error that was not its own: " ++ displayException err))

  when (not ("boom" `isInfixOf` displayException err)) $
    throwIO (Failed ("the cause is gone: " ++ displayException err))
  when (not ("broken" `isInfixOf` displayException err)) $
    throwIO (Failed ("the instance is unnamed: " ++ displayException err))

  -- And an ordinary Haskell exception, which the host does not wrap at
  -- all, reaches the caller exactly as it was thrown.
  loud <-
    raised
      ( sekreto
          emptyoptions
            { optplugins = [providerplugin "loud" (\_ -> ioError (userError "not a plugin error"))],
              optproviders = [emptyspec {speckind = "loud"}]
            }
      )

  when (not ("not a plugin error" `isInfixOf` displayException loud)) $
    throwIO (Failed ("the exception was rewritten: " ++ displayException loud))

  case fromException loud :: Maybe SekretoError of
    Just _ -> throwIO (Failed ("sekreto rewrapped an error that was not its own as its own"))
    Nothing -> pure ()

shouty :: [(String, String)] -> Provider
shouty values =
  Provider
    { lookupsecret = \name -> pure (lookup (upper name) values),
      describe = "shouty"
    }
  where
    upper = map (\letter -> if 'a' <= letter && 'z' >= letter then toEnum (fromEnum letter - 32) else letter)

acustomkindisoneproviderplugincall :: IO ()
acustomkindisoneproviderplugincall = do
  secrets <-
    sekreto
      emptyoptions
        { optplugins = [providerplugin "shouty" (pure . shouty . specvalues)],
          optproviders = [emptyspec {speckind = "shouty", specvalues = [("API.TOKEN", "loud")]}]
        }

  same "get" "loud" =<< get secrets "api.token"
  same "instance refs" ["shouty"] =<< refs secrets

-- A plugin that names a built-in kind replaces it: that is how a host
-- substitutes an implementation, and never an accident, because the four
-- names are documented.
apluginmayreplaceabuiltinkind :: IO ()
apluginmayreplaceabuiltinkind = do
  let replaced =
        Provider {lookupsecret = \_ -> pure (Just "replaced"), describe = "memory"}

  secrets <-
    sekreto
      emptyoptions
        { optplugins = [providerplugin "memory" (\_ -> pure replaced)],
          optproviders = [memoryspec [("API_TOKEN", "original")]]
        }

  same "get" "replaced" =<< get secrets "api.token"
  same "catalog" ["dotenv", "env", "file", "memory"] =<< names secrets

closetearsthechaindown :: IO ()
closetearsthechaindown = do
  secrets <- sekreto emptyoptions {optproviders = [memoryspec [("API_TOKEN", "tok01")]]}

  same "get" "tok01" =<< get secrets "api.token"

  close secrets

  same "instance refs" [] =<< refs secrets
  same "stores" [] =<< stores secrets
  same "tryget" Nothing =<< tryget secrets "api.token"
  same "redaction survives" "token=[redacted]" =<< redactall secrets "token=tok01"

-- Handing over ten definitions constructs nothing. A definition is data:
-- a name and a set of callbacks, and the callbacks run when a chain names
-- the kind, not when the list is passed.
thefullsetisbuiltondemand :: IO ()
thefullsetisbuiltondemand = do
  secrets <- sekreto emptyoptions {optplugins = allplugins, optproviders = []}

  same "no instance" [] =<< refs secrets
  same "no store" [] =<< stores secrets
  same
    "the catalog holds all fourteen"
    (sort (builtinkinds ++ pluginkinds))
    =<< names secrets

-- Python's twin of this passes a MODULE where a definition belongs; here
-- the type system refuses that outright, and what remains checkable is a
-- definition that is not one of sekreto's: it loads, it activates, and it
-- exports no provider.
adefinitionthatisnotaproviderpluginisrefused :: IO ()
adefinitionthatisnotaproviderpluginisrefused = do
  let hollow = Definition "hollow" VNull Nothing Nothing Nothing Nothing Nothing

  message <-
    refusal
      (sekreto emptyoptions {optplugins = [hollow], optproviders = [emptyspec {speckind = "hollow"}]})

  same "the refusal" "sekreto: plugin hollow exported no provider" message

-- | How many provider slots the module-global table is still holding.
--
-- 'takeprovider' is the only window onto it, and it TAKES - which is
-- exactly right here, because anything it finds is a provider nothing
-- was coming back for. The bound is far above anything a whole run of
-- this suite reaches: a run builds under a hundred providers.
heldslots :: IO Int
heldslots =
  length . filter isJust <$> mapM (takeprovider . VNum . fromIntegral) [1 .. 4096 :: Int]

-- THE PROVIDER SLOT TABLE, which is this port's one divergence from the
-- canonical: plugin's value model carries no function, so a `define`
-- exports the SLOT NUMBER of the provider it built and the chain reads
-- it back. The invariant is that the table is EMPTY the moment a
-- construction is over, however it ended - a slot no chain took is a
-- provider held for the life of the process, and nothing else here can
-- see one. The C++ port shipped exactly that leak with its own suite
-- green against it.
theslottableisemptyafteraconstruction :: IO ()
theslottableisemptyafteraconstruction = do
  same "nothing the entries above built is still held" 0 =<< heldslots

  secrets <- sekreto emptyoptions {optproviders = [memoryspec [], memoryspec []]}
  same "a chain that built" 0 =<< heldslots

  close secrets
  same "a chain that was torn down" 0 =<< heldslots

  -- A chain that refuses PART WAY gives back what it had already built:
  -- the host goes down with it, and every instance's `close` runs.
  partway <-
    raised
      ( sekreto
          emptyoptions
            {optproviders = [memoryspec [], memoryspec [], emptyspec {speckind = "vualt"}]}
      )
  when (not ("unknown provider kind" `isInfixOf` displayException partway)) $
    throwIO (Failed ("the wrong refusal: " ++ displayException partway))
  same "a chain that refused part way" 0 =<< heldslots

  -- ...and so does the one path a chain cannot reach by refusing: a
  -- `define` that SUCCEEDED and an `activate` that did not. The slot is
  -- filled and the chain never reads it, so `close` is the only thing
  -- that gives it back.
  let refuses tag =
        (providerplugin tag (\_ -> pure (Provider (\_ -> pure Nothing) tag)))
          {dActivate = Just (\_ -> raise "boom_failed" "activate refused" (VMap []))}

  _ <- raised (sekreto emptyoptions {optplugins = [refuses "boom"],
                                     optproviders = [emptyspec {speckind = "boom"}]})
  same "a define that succeeded and an activate that did not" 0 =<< heldslots

  -- CONTROL: the probe can see a held slot. The same definition without
  -- its `close` leaks the provider its `define` built, and exactly one
  -- must be found - so the zeroes above are a check that looked.
  _ <- raised (sekreto emptyoptions {optplugins = [(refuses "leaky") {dClose = Nothing}],
                                     optproviders = [emptyspec {speckind = "leaky"}]})
  same "CONTROL: a definition with no close leaks its slot" 1 =<< heldslots

-- --------------------------------------------------- the built artifact

-- | One claim of test/checkcore.py, which reads `nm` rather than the
-- source. A missing artifact fails here rather than passing silently,
-- which is the point: a check that read nothing must not report green.
artifact :: String -> IO ()
artifact claim = do
  (code, out, why) <- readCreateProcessWithExitCode (proc "python3" ["test/checkcore.py", claim]) ""

  when (ExitSuccess /= code) $
    throwIO (Failed (trimmed (out ++ why)))
  where
    trimmed = unlines . filter (not . null) . lines

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
          hPutStrLn stderr (displayException err)
      hFlush stdout

main :: IO ()
main = do
  args <- getArgs
  let only = case args of
        (wanted : _) -> Just wanted
        [] -> Nothing

  passcount <- newIORef 0
  failcount <- newIORef 0

  let check = testcase passcount failcount only

  check "the full set holds every kind" thefullsetholdseverykind
  check "every kind builds from a spec" everykindbuildsfromaspec
  check "the CLI passes the full set" theclipassesthefullset
  check "one plugin is enough for a chain that names only it" onepluginisenough
  check "a kind that was not passed in is refused, naming the fix" akindnotpassedinisrefused
  check "a repeated store name keeps the store and numbers the instance" arepeatedstorenamenumberstheinstance
  check "a store name must be a valid tag" astorenamemustbeavalidtag
  check "a SekretoError raised in define comes back out as itself" asekretoerrorcomesbackoutasitself
  check "any other error raised in define is the host's report of it" anyothererroristhehostsreport
  check "a custom kind is one providerplugin call" acustomkindisoneproviderplugincall
  check "a plugin may replace a built-in kind" apluginmayreplaceabuiltinkind
  check "close tears the chain down and keeps redaction" closetearsthechaindown
  check "the full set is built on demand" thefullsetisbuiltondemand
  check "a definition that is not a provider plugin is refused" adefinitionthatisnotaproviderpluginisrefused
  check "the provider slot table is empty after a construction" theslottableisemptyafteraconstruction
  check "the core imports no plugin" (artifact "core")
  check "one plugin imports only itself" (artifact "one")
  check "the core reaches no socket, no TLS and no child process" (artifact "platform")

  passed <- readIORef passcount
  failed <- readIORef failcount

  putStrLn ("\n" ++ show passed ++ " passed, " ++ show failed ++ " failed")

  if 0 == failed then exitSuccess else exitFailure
