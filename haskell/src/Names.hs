-- | The secret name, how each store spells it, and the @.env@ reader.
--
-- These are pure functions over text, and they are here rather than in
-- "Sekreto" for one reason: 'Providers' needs them and "Sekreto" needs
-- 'Providers', and Haskell has no import cycles to fall back on. The
-- same reason puts 'Provider.SekretoError' in its own module. "Sekreto"
-- re-exports everything below, so a caller still reads it there.
--
-- A port of typescript/src/Sekreto.ts, which is canonical.

module Names
  ( Name,
    VaultRef (..),
    awsparam,
    checkname,
    envkey,
    flatname,
    parsedotenv,
    validname,
    vaultref,
  )
where

import Control.Exception (throw)
import Data.Char (chr, isSpace, ord)
import Data.List (intercalate, isPrefixOf, isSuffixOf)
import Provider (Name, SekretoError (..))

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

