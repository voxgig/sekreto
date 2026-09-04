-- | sekreto: one interface for secrets, wherever they live.
--
-- A 'Sekreto' is an ordered chain of providers. 'get' asks each in turn
-- and returns the first hit, so an app can be configured from environment
-- variables in development and a vault in production without changing a
-- line of its own code.
--
-- A port of typescript/src/Sekreto.ts, which is canonical.

module Sekreto
  ( Sekreto,
    VaultRef (..),
    awsparam,
    checkname,
    close,
    envkey,
    flatname,
    get,
    getall,
    getfrom,
    has,
    hasin,
    makechain,
    parsedotenv,
    redact,
    redactall,
    refresh,
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

import Control.Exception (throw, throwIO)
import Control.Monad (when)
import Data.Char (chr, isSpace, ord)
import Data.IORef (IORef, modifyIORef', newIORef, readIORef, writeIORef)
import Data.List (intercalate, isPrefixOf, isSuffixOf, sortBy)
import Data.Ord (comparing)
import Provider (Name, Provider (..), SekretoError (..), forced)

-- ------------------------------------------------------------ the names

-- | Is this a well-formed secret name?
--
-- Split on the dot, keeping empty segments, and every segment must be one
-- or more of @a-z0-9_@. Written as a character scan rather than as
-- @^[a-z0-9_]+$@ because in four of this library's target languages @$@
-- also matches before a final newline, and @api.token\\n@ was accepted by
-- all four. The spec pins that case, and @api\\n.token@ and
-- @api.token\\r@ with it.
validname :: String -> Bool
validname name = not (null name) && all part (segments name)
  where
    part piece = not (null piece) && all allowed piece
    allowed head = ('a' <= head && 'z' >= head) || ('0' <= head && '9' >= head) || '_' == head

-- | Split on the literal dot, KEEPING empty segments: dropping them would
-- make @a.@ a valid one-segment name.
segments :: String -> [String]
segments name = case break ('.' ==) name of
  (piece, []) -> [piece]
  (piece, _ : rest) -> piece : segments rest

-- | The name, or a 'SekretoError'. Every entry point checks its name here.
checkname :: String -> Name
checkname name
  | validname name = name
  | otherwise = throw (SekretoError ("sekreto: invalid name: " ++ name))

-- | ASCII uppercase, deliberately not the locale's. A Turkish locale maps
-- @i@ to a dotted capital, and @api.token@ would stop being @API_TOKEN@.
upper :: String -> String
upper = map head'
  where
    head' letter
      | 'a' <= letter && 'z' >= letter = chr (ord letter - 32)
      | otherwise = letter

-- | The environment-variable key for a name: @api.token@ -> @API_TOKEN@.
-- The prefix is NOT uppercased: it is written the way it is meant to
-- appear.
envkey :: String -> String -> String
envkey name prefix = prefix ++ upper (intercalate "_" (segments (checkname name)))

-- | Where a name lives in a KV vault.
data VaultRef = VaultRef {refpath :: String, reffield :: String}
  deriving (Eq, Show)

-- | Where a name lives in a KV vault: @api.token@ -> @api@ / @token@.
--
-- A single-segment name has no path of its own, so it becomes a secret of
-- that name with the conventional field @value@.
vaultref :: String -> VaultRef
vaultref name = case segments (checkname name) of
  [one] -> VaultRef one "value"
  parts -> VaultRef (intercalate "/" (init parts)) (last parts)

-- | A name flattened to one segment: @api.token@ -> @api_token@ (GCP
-- Secret Manager, @_@) or @api-token@ (Azure Key Vault, @-@).
--
-- Those stores have no path hierarchy and reject dots in ids, so the dots
-- become the store's conventional separator. With @-@ as the separator,
-- underscores flatten too: Azure Key Vault's alphabet is letters, digits
-- and hyphens only, and a valid sekreto name like @with_underscore@ must
-- still be representable there.
flatname :: String -> String -> String
flatname name sep
  | "-" == sep = map dashed flat
  | otherwise = flat
  where
    flat = intercalate sep (segments (checkname name))
    dashed head = if '_' == head then '-' else head

-- | The AWS SSM Parameter Store name for a name: dots become the path
-- hierarchy, rooted at @/@ (or at a prefix): @db.pass.main@ ->
-- @/db/pass/main@, or @/app/db/pass/main@ under prefix @/app@.
awsparam :: String -> String -> String
awsparam name prefix = base ++ "/" ++ intercalate "/" (segments (checkname name))
  where
    rooted = if not (null prefix) && not ("/" `isPrefixOf` prefix) then '/' : prefix else prefix
    base = dropsuffix "/" rooted

-- | Drop a suffix if it is there. Both @.@ and @_@ appear in names, so
-- this is spelled out rather than reached for through a regex.
dropsuffix :: String -> String -> String
dropsuffix suffix body
  | suffix `isSuffixOf` body = take (length body - length suffix) body
  | otherwise = body

-- | Parse @.env@ text into an ordered list of raw keys and values.
--
-- Deliberately small: @KEY=value@, an optional @export@, @#@ comments on
-- their own line, and single- or double-quoted values (double quotes also
-- unescape @\\n@, @\\r@, @\\t@, @\\\\@ and @\\"@). A line with no @=@, or
-- with an empty key, is skipped silently rather than aborting the rest.
--
-- Never raises: a file that is not a .env is a file with no secrets in it.
parsedotenv :: String -> [(String, String)]
parsedotenv body = foldl entry [] (lines' body)
  where
    entry sofar raw
      | null line = sofar
      | "#" `isPrefixOf` line = sofar
      | 0 >= eq = sofar
      | otherwise = put sofar key (unquote (trim (drop (eq + 1) stripped)))
      where
        line = trim (dropsuffix "\r" raw)
        stripped = if "export " `isPrefixOf` line then trim (drop 7 line) else line
        eq = maybe (-1) id (elemindex '=' stripped)
        key = trim (take eq stripped)

    unquote text
      | 2 <= length text && "\"" `isPrefixOf` text && "\"" `isSuffixOf` text =
          unescape (inner text)
      | 2 <= length text && "'" `isPrefixOf` text && "'" `isSuffixOf` text = inner text
      | otherwise = text

    inner text = take (length text - 2) (drop 1 text)

-- | Set a key in an insertion-ordered association list. A repeat replaces
-- the value and KEEPS the first position, which is what every port's
-- ordered map does with a second write.
put :: [(String, String)] -> String -> String -> [(String, String)]
put entries key value
  | any ((key ==) . fst) entries = map swap entries
  | otherwise = entries ++ [(key, value)]
  where
    swap (at, was) = if key == at then (at, value) else (at, was)

-- | Split on newlines, keeping trailing empties. `Data.List.lines` drops a
-- final empty segment, which would make @A=1\\n@ and @A=1@ differ.
lines' :: String -> [String]
lines' body = case break ('\n' ==) body of
  (piece, []) -> [piece]
  (piece, _ : rest) -> piece : lines' rest

elemindex :: Char -> String -> Maybe Int
elemindex want body = go 0 body
  where
    go _ [] = Nothing
    go at (head : rest) = if want == head then Just at else go (at + 1) rest

trim :: String -> String
trim = dropWhile isSpace . reverse . dropWhile isSpace . reverse

-- | Unescape a double-quoted .env value. A scan, not a chain of
-- replacements: any escape that is not one of the five is kept as the
-- backslash and the character, and a trailing backslash is literal.
unescape :: String -> String
unescape [] = []
unescape ['\\'] = "\\"
unescape ('\\' : next : rest) = case next of
  'n' -> '\n' : unescape rest
  'r' -> '\r' : unescape rest
  't' -> '\t' : unescape rest
  '\\' -> '\\' : unescape rest
  '"' -> '"' : unescape rest
  _ -> '\\' : next : unescape rest
unescape (head : rest) = head : unescape rest

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

-- | The secrets facade: a chain of providers plus a cache.
--
-- Two ways to read. 'get' is transparent - it walks the chain and takes
-- the first hit, and the caller never learns which store answered.
-- 'getfrom' is directed - it names the store, and only that store is
-- asked. Use the first for ordinary configuration, the second when
-- /which/ store holds a secret is part of what you mean.
data Sekreto = Sekreto
  { skentries :: IORef [Entry],
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

-- | Build a chain from live providers. @names@ is positional; an entry
-- left 'Nothing' or empty falls back to the provider's kind.
--
-- Construction contacts nothing: the first network call is the first
-- lookup.
makechain :: [Provider] -> [Maybe String] -> Bool -> IO Sekreto
makechain providers names docache = do
  entries <- newIORef (zipWith entry providers (names ++ repeat Nothing))
  cache <- newIORef []
  seen <- newIORef []
  pure (Sekreto entries cache seen docache)
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

-- | Tear the chain down. Afterwards 'stores' and 'sources' are empty,
-- 'tryget' misses and 'get' raises - and redaction still knows every
-- value ever resolved.
close :: Sekreto -> IO ()
close secrets = do
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
