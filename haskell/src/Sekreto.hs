-- | sekreto: one interface for secrets, wherever they live.
--
-- A 'Sekreto' is an ordered chain of providers. 'get' asks each in turn
-- and returns the first hit, so an app can be configured from environment
-- variables in development and a vault in production without changing a
-- line of its own code.
--
-- Every configured provider is a voxgig/plugin instance on 'host',
-- addressed by name and tag - @hashicorp@ for a store named after its
-- kind, @hashicorp$prod@ otherwise - so @hostList@ reads like the chain.
-- The catalog holds the four built-in kinds and EXACTLY the definitions
-- 'optplugins' handed in: a kind nobody passed in cannot be built, and
-- the refusal says so.
--
-- A port of typescript/src/Sekreto.ts, which is canonical.

module Sekreto
  ( Options (..),
    Sekreto,
    VaultRef (..),
    awsparam,
    catalog,
    checkname,
    close,
    emptyoptions,
    envkey,
    flatname,
    get,
    getall,
    getfrom,
    has,
    hasin,
    host,
    makechain,
    parsedotenv,
    redact,
    redactall,
    refresh,
    sekreto,
    show',
    sources,
    storename,
    stores,
    tryfrom,
    tryget,
    validname,
    vaultref,
  )
where

import Catalog (catalogAdd, catalogHas, catalogNames, makeCatalog)
import Control.Exception (SomeException, catch, onException, throwIO)
import Control.Monad (when)
import Data.IORef (IORef, modifyIORef', newIORef, readIORef, writeIORef)
import Data.List (intercalate, isPrefixOf, sortBy)
import Data.Maybe (fromMaybe, isJust)
import Data.Ord (comparing)
import Defs
  ( Catalog,
    DeclareSpec (..),
    Definition,
    Host,
    HostOptions (..),
    Inst (..),
    noHostOptions,
    noSpec,
  )
import qualified Host as Plugin
import Names
  ( VaultRef (..),
    awsparam,
    checkname,
    envkey,
    flatname,
    parsedotenv,
    validname,
    vaultref,
  )
import Provider (Name, Provider (..), SekretoError (..), forced)
import Providers
  ( ProviderSpec (..),
    builtins,
    errorcode,
    optionsof,
    pluginkinds,
    providerexport,
    takeprovider,
  )
import Ref (checktag, formatRef)
import Types (PluginError (..))
import Value (Value (..), asStr, isStr, vget, vitems)

-- | Replace known secret values in text with @[redacted]@.
--
-- Only values of four characters or more are replaced: shorter ones are
-- too likely to appear in ordinary text, and redacting them would make
-- logs unreadable without making them safer.
--
-- Longest first, always, so that a value which is a prefix of another
-- cannot mask it. The list is sorted here, never in place: the caller's
-- copy is the live redaction history when this is reached through
-- 'redactall'.
redact :: String -> [String] -> String
redact body values = foldl replace body ordered
  where
    ordered = sortBy (comparing (negate . length)) (filter ((4 <=) . length) values)

-- | Literal substring replacement, never a regex: a secret containing
-- metacharacters must not be interpreted.
replace :: String -> String -> String
replace body needle
  | null needle = body
  | otherwise = walk body
  where
    walk [] = []
    walk rest
      | needle `isPrefixOf` rest = "[redacted]" ++ walk (drop (length needle) rest)
      | otherwise = head rest : walk (tail rest)

-- | The store name a provider answers to when nothing says otherwise.
--
-- 'describe' opens with the provider's kind - @hashicorp:...@,
-- @dotenv:...@, plain @env@ - so the kind is the natural default, and a
-- custom provider gets a sensible name without implementing anything
-- extra.
storename :: Provider -> String
storename = takeWhile (':' /=) . describe

-- ----------------------------------------------------------- the facade

-- | One provider in the chain, under the store name it answers to.
data Entry = Entry {entrystore :: String, entryprovider :: Provider}

-- | One resolved value, with the store it came from.
data Cached = Cached {cachedstore :: String, cachedname :: Name, cachedvalue :: String}

-- | How a 'Sekreto' is built.
--
-- 'optplugins' is the one that decides what a chain may name: a 'Sekreto'
-- can build the four built-in kinds and exactly the plugin definitions
-- handed in here. Loading is explicit, never a side effect of importing -
-- a list given to a constructor cannot be erased by a compiler, and the
-- set of stores an app can reach is not something to discover at run
-- time.
data Options = Options
  { -- | The provider kinds this 'Sekreto' may build, beyond the
    -- built-ins. A plugin naming a built-in kind replaces it.
    optplugins :: [Definition],
    -- | The chain, in resolution order.
    optproviders :: [ProviderSpec],
    -- | Ask the providers afresh every time when this is 'False'.
    optcache :: Bool
  }

-- | No plugins, no providers, caching on. Record-update syntax names only
-- what a chain actually sets, the way 'Providers.emptyspec' does.
emptyoptions :: Options
emptyoptions = Options {optplugins = [], optproviders = [], optcache = True}

-- | The secrets facade: a chain of providers plus a cache.
--
-- Two ways to read. 'get' is transparent - it walks the chain and takes
-- the first hit, and the caller never learns which store answered.
-- 'getfrom' is directed - it names the store, and only that store is
-- asked. Use the first for ordinary configuration, the second when
-- /which/ store holds a secret is part of what you mean.
data Sekreto = Sekreto
  { -- The voxgig/plugin host every spec'd provider is an instance of, and
    -- the catalog of definitions it can build.
    skhost :: Host,
    skcatalog :: Catalog,
    skentries :: IORef [Entry],
    -- A list, not a map: the store a value came from stays attached, and
    -- redaction order does not vary between runs.
    skcache :: IORef [Cached],
    -- Every value ever resolved, for 'redactall'. Kept independently of
    -- the read cache so that redaction still works with the cache off -
    -- otherwise an uncached Sekreto would silently stop redacting.
    -- Append-only for the object's life: neither 'refresh' nor 'close'
    -- clears it.
    skseen :: IORef [String],
    skdocache :: Bool
  }

-- | The voxgig/plugin host every spec'd provider is an instance of. Read
-- it for introspection - @hostList@ names each store's ref and status -
-- and nothing on it advances the chain.
host :: Sekreto -> Host
host = skhost

-- | The definitions this 'Sekreto' can build: the built-ins plus what
-- 'optplugins' handed in.
catalog :: Sekreto -> Catalog
catalog = skcatalog

-- | Make a chain from declarative provider specs.
--
-- Eager and in chain order, so a spec that cannot be built raises here
-- rather than at the first read. Construction still contacts nothing: a
-- provider opens nothing until its first lookup.
sekreto :: Options -> IO Sekreto
sekreto options = do
  -- Built-ins first, then the plugins, into one catalog: a plugin that
  -- names a built-in kind replaces it, which is how a host substitutes an
  -- implementation and never an accident, because the four names are
  -- documented.
  cat <- makeCatalog
  mapM_ (catalogAdd cat) (builtins ++ optplugins options)

  live <- Plugin.makeHost noHostOptions {oCatalog = Just cat}

  entries <- newIORef []
  cache <- newIORef []
  seen <- newIORef []

  let secrets = Sekreto live cat entries cache seen (optcache options)

  -- A chain that refuses halfway leaves no instance loaded: the host it
  -- had built goes down with it, which is also what returns every
  -- provider slot the definitions took.
  built <- mapM (declare secrets) (optproviders options) `onException` quiet (Plugin.hostClose live)

  writeIORef entries built

  pure secrets
  where
    quiet action = action `catch` \err -> let _ = (err :: SomeException) in pure ()

-- | One chain entry, as a plugin instance.
--
-- The instance is @kind@ for a store named after its kind and
-- @kind$store@ otherwise - @hashicorp$prod@ - so @hostList@ reads like
-- the chain. A store name that is already taken gets a numbered tag from
-- the host instead, because two providers MAY share a store name (a
-- directed read walks both) and an instance ref may not.
declare :: Sekreto -> ProviderSpec -> IO Entry
declare secrets spec = do
  known <- catalogHas (skcatalog secrets) kind

  when (not known) $ do
    names <- catalogNames (skcatalog secrets)
    throwIO (SekretoError (unknownkind kind names))

  when (not (checktag (VStr store))) $
    throwIO (SekretoError ("sekreto: invalid store name: " ++ store))

  wanted <-
    if store == kind
      then pure kind
      else unwrapped (formatRef (VStr kind) (VStr store))

  taken <- unwrapped (Plugin.hostInstance (skhost secrets) wanted)

  -- A repeat keeps its STORE name and takes a numbered tag: @?@ is the
  -- host's own request for the lowest unused one.
  let declaration =
        if isJust taken
          then noSpec {sDefinition = kind, sTag = "?", sOptions = Just (optionsof spec)}
          else noSpec {sOptions = Just (optionsof spec)}

  -- `load` runs the definition's `define`, which builds the provider from
  -- the spec; `activate` takes the instance live. Nothing is contacted by
  -- either.
  loaded <- unwrapped (Plugin.hostLoad (skhost secrets) wanted declaration)

  let ref = iRef loaded

  _ <- unwrapped (Plugin.hostActivate (skhost secrets) ref)

  exported <- unwrapped (Plugin.hostExports (skhost secrets) (ref ++ "/" ++ providerexport))

  found <- takeprovider (fromMaybe VNull exported)

  case found of
    Just provider -> pure (Entry store provider)
    Nothing -> throwIO (SekretoError ("sekreto: plugin " ++ kind ++ " exported no provider"))
  where
    kind = speckind spec
    store = if null (specname spec) then kind else specname spec

-- | A 'SekretoError' that crossed the plugin boundary comes back out as
-- itself, byte for byte. Anything else a definition raised is not
-- sekreto's to rewrite and surfaces as the host reports it, naming the
-- instance. Nowhere else catches and rewraps.
unwrapped :: IO a -> IO a
unwrapped action = action `catch` handler
  where
    handler err
      | errorcode == peCode err && isStr (vget (peDetails err) "cause") =
          throwIO (SekretoError (asStr (vget (peDetails err) "cause")))
      | otherwise = throwIO err

-- | The message for a kind the catalog does not hold.
--
-- A kind sekreto has never heard of is a typo; a kind that exists as a
-- plugin but was not passed in is the split working as designed, and
-- telling you what to pass. Collapsing the two was the first thing that
-- made the split confusing to use.
unknownkind :: String -> Value -> String
unknownkind kind names =
  "sekreto: unknown provider kind: "
    ++ kind
    ++ " (available: "
    ++ intercalate ", " (map asStr (vitems names))
    ++ ")"
    ++ ( if elem kind pluginkinds
           then " - " ++ kind ++ " is a sekreto plugin, not built in: pass it in the plugins option"
           else ""
       )

-- | Build a chain from live providers, backed by no plugin instance.
-- @names@ is positional; an entry left 'Nothing' or empty falls back to
-- the provider's kind.
--
-- This is the way to put a provider the library has never seen into a
-- chain without writing a definition for it. A kind worth naming is one
-- 'Providers.providerplugin' call instead.
makechain :: [Provider] -> [Maybe String] -> Bool -> IO Sekreto
makechain providers names docache = do
  cat <- makeCatalog
  mapM_ (catalogAdd cat) builtins
  live <- Plugin.makeHost noHostOptions {oCatalog = Just cat}

  entries <- newIORef (zipWith entry providers (names ++ repeat Nothing))
  cache <- newIORef []
  seen <- newIORef []

  pure (Sekreto live cat entries cache seen docache)
  where
    entry provider given = case given of
      Just wanted | not (null wanted) -> Entry wanted provider
      _ -> Entry (storename provider) provider

-- | The secret, or a 'SekretoError' if no provider has it.
get :: Sekreto -> Name -> IO String
get secrets name = do
  found <- tryget secrets name
  case found of
    Just value -> pure value
    Nothing -> throwIO (SekretoError ("sekreto: unknown secret: " ++ name))

-- | The secret, or 'Nothing' if no provider has it. Named @tryget@
-- because @try@ is taken by "Control.Exception".
tryget :: Sekreto -> Name -> IO (Maybe String)
tryget secrets name = do
  entries <- readIORef (skentries secrets)
  resolve secrets "" name entries

-- | The secret from one named store, or a 'SekretoError' if that store
-- does not have it.
getfrom :: Sekreto -> String -> Name -> IO String
getfrom secrets store name = do
  found <- tryfrom secrets store name
  case found of
    Just value -> pure value
    Nothing -> throwIO (SekretoError ("sekreto: unknown secret: " ++ store ++ ":" ++ name))

-- | The secret from one named store, or 'Nothing' if that store does not
-- have it.
--
-- Naming a store that is not in the chain is an error, not a miss:
-- 'tryget' already means "this store may not have it", so it cannot also
-- mean "this store may not exist" without hiding a typo. Raised BEFORE
-- the name is validated.
tryfrom :: Sekreto -> String -> Name -> IO (Maybe String)
tryfrom secrets store name = do
  entries <- readIORef (skentries secrets)

  let matching = filter ((store ==) . entrystore) entries

  when (null matching) $ throwIO (SekretoError ("sekreto: unknown store: " ++ store))

  resolve secrets store name matching

-- | The one path both readers share.
resolve :: Sekreto -> String -> Name -> [Entry] -> IO (Maybe String)
resolve secrets store name useentries = do
  -- Validated FIRST: before the cache, before the first provider.
  _ <- forced (checkname name)

  cache <- readIORef (skcache secrets)

  let hit =
        if skdocache secrets
          then
            case filter (\entry -> store == cachedstore entry && name == cachedname entry) cache of
              (entry : _) -> Just (cachedvalue entry)
              [] -> Nothing
          else Nothing

  case hit of
    -- A cache hit does not push to `seen`: the value is already there.
    Just value -> pure (Just value)
    Nothing -> do
      found <- walk useentries
      case found of
        -- Misses are never cached.
        Nothing -> pure Nothing
        Just value -> do
          when (skdocache secrets) $
            modifyIORef' (skcache secrets) (++ [Cached store name value])
          modifyIORef' (skseen secrets) (++ [value])
          pure (Just value)
  where
    -- Sequential and short-circuiting: chain order is precedence, and a
    -- provider that raises is not caught.
    walk [] = pure Nothing
    walk (entry : rest) = do
      found <- lookupsecret (entryprovider entry) name
      case found of
        -- The empty string is a hit.
        Just value -> pure (Just value)
        Nothing -> walk rest

-- | Does any provider have this secret?
has :: Sekreto -> Name -> IO Bool
has secrets name = maybe False (const True) <$> tryget secrets name

-- | Does this named store have this secret?
hasin :: Sekreto -> String -> Name -> IO Bool
hasin secrets store name = maybe False (const True) <$> tryfrom secrets store name

-- | Every named secret at once. Missing ones are an error, and the walk
-- stops at the first.
getall :: Sekreto -> [Name] -> IO [(String, String)]
getall secrets names = mapM one names
  where
    one name = (,) name <$> get secrets name

-- | A description of each provider, in resolution order. Repeats kept.
sources :: Sekreto -> IO [String]
sources secrets = map (describe . entryprovider) <$> readIORef (skentries secrets)

-- | The name of each store 'getfrom' can address, in resolution order and
-- without repeats.
stores :: Sekreto -> IO [String]
stores secrets = nub' . map entrystore <$> readIORef (skentries secrets)
  where
    nub' [] = []
    nub' (head : rest) = head : nub' (filter (head /=) rest)

-- | Replace every value this chain has resolved with @[redacted]@.
--
-- Named @redactall@ because the module-level 'redact' keeps its name; the
-- perl port made the same choice for the same reason.
redactall :: Sekreto -> String -> IO String
redactall secrets body = redact body <$> readIORef (skseen secrets)

-- | Drop cached values, so the next 'get' asks the providers again. The
-- redaction history survives.
refresh :: Sekreto -> IO ()
refresh secrets = writeIORef (skcache secrets) []

-- | Tear the chain down: every plugin instance is deactivated and
-- unloaded, in reverse, releasing whatever a provider acquired at
-- activation. Afterwards 'stores' and 'sources' are empty, 'tryget'
-- misses and 'get' raises - and redaction still knows every value ever
-- resolved.
close :: Sekreto -> IO ()
close secrets = do
  Plugin.hostClose (skhost secrets)

  writeIORef (skentries secrets) []
  writeIORef (skcache secrets) []

-- | How a chain prints.
--
-- There is deliberately no @deriving Show@: 'skcache' and 'skseen' are
-- ordinary fields, and a derived instance would put every resolved secret
-- into whatever formatted it. This reaches the store names and nothing
-- else. Note the literal spacing, which every port shares: an empty chain
-- is @Sekreto { stores: [  ] }@.
show' :: Sekreto -> IO String
show' secrets = do
  names <- stores secrets
  pure ("Sekreto { stores: [ " ++ intercalate ", " names ++ " ] }")
