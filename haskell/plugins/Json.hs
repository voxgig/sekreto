-- | Minimal JSON support for sekreto.
--
-- sekreto adds no third-party dependencies, so it carries just enough JSON
-- to read a vault's answer and write the CLI's own line of output. It is
-- deliberately not a general-purpose library.
--
-- 'parse' answers @Maybe Json@, where 'Nothing' means "this text is not
-- JSON" and @Just JNull@ means "this text is the JSON literal null" - a
-- distinction the callers of fetchjson need, since only the first is a
-- malformed response.
--
-- Objects keep their fields in the order they arrived: a payload's field
-- order is signed, and `Data.Map` orders by key.
--
-- A port of typescript/src/Json.ts, which is canonical.

module Json
  ( Json (..),
    asarr,
    asnum,
    asobj,
    asstr,
    dig,
    numstr,
    parse,
    quote,
    stringify,
    text,
  )
where

import Data.Char (chr, isDigit, isHexDigit, isSpace, ord)
import Data.List (foldl')
import Numeric (readHex, showHex)

-- | A JSON value. Numbers are 'Double' only, as in the canonical port;
-- objects are an association list, so the order fields arrived in is the
-- order they leave in.
data Json
  = JNull
  | JBool Bool
  | JNum Double
  | JStr String
  | JArr [Json]
  | JObj [(String, Json)]
  deriving (Eq, Show)

asstr :: Maybe Json -> Maybe String
asstr (Just (JStr value)) = Just value
asstr _ = Nothing

asnum :: Maybe Json -> Maybe Double
asnum (Just (JNum value)) = Just value
asnum _ = Nothing

asarr :: Maybe Json -> Maybe [Json]
asarr (Just (JArr value)) = Just value
asarr _ = Nothing

asobj :: Maybe Json -> Maybe [(String, Json)]
asobj (Just (JObj value)) = Just value
asobj _ = Nothing

-- | Walk nested objects, stopping the moment a step is not there. The
-- argument is optional because a response body is optional: a store may
-- not have answered with JSON at all.
dig :: Maybe Json -> [String] -> Maybe Json
dig = foldl' step
  where
    step (Just (JObj entries)) key = lookup key entries
    step _ _ = Nothing

-- | This value as the text a caller would print, or nothing at all when
-- there is no value. A JSON null is "no value": every provider here treats
-- it as a miss rather than as the string @null@.
text :: Maybe Json -> Maybe String
text Nothing = Nothing
text (Just JNull) = Nothing
text (Just (JStr value)) = Just value
text (Just (JNum value)) = Just (numstr value)
text (Just (JBool value)) = Just (if value then "true" else "false")
text (Just other) = Just (stringify other)

-- | Render a number the way every other port does: a whole number has no
-- fractional tail, so a JSON @1@ read back and printed stays @1@.
numstr :: Double -> String
numstr value
  | isNaN value || isInfinite value = "null"
  | value == fromIntegral rounded && 9007199254740992.0 > abs value = show rounded
  | otherwise = show value
  where
    rounded = truncate value :: Integer

-- | Render a string as a JSON string literal, quotes included. Public,
-- because the CLI assembles its output line field by field.
quote :: String -> String
quote body = '"' : concatMap escape body ++ "\""
  where
    escape '"' = "\\\""
    escape '\\' = "\\\\"
    escape '\n' = "\\n"
    escape '\r' = "\\r"
    escape '\t' = "\\t"
    escape head
      | 0x20 > ord head = "\\u" ++ pad (showHex (ord head) "")
      | otherwise = [head]

    pad digits = replicate (4 - length digits) '0' ++ digits

-- | Render a value as compact JSON: no spaces, no newlines.
stringify :: Json -> String
stringify JNull = "null"
stringify (JBool value) = if value then "true" else "false"
stringify (JNum value) = numstr value
stringify (JStr value) = quote value
stringify (JArr entries) = "[" ++ joined (map stringify entries) ++ "]"
stringify (JObj entries) = "{" ++ joined (map field entries) ++ "}"
  where
    field (key, value) = quote key ++ ":" ++ stringify value

joined :: [String] -> String
joined [] = ""
joined [one] = one
joined (head : rest) = head ++ "," ++ joined rest

-- | Parse JSON text. 'Nothing' for anything unreadable - which the caller
-- must tell apart from a literal @null@ body, since only the first means
-- the store could not answer coherently.
--
-- No error escapes: every failure is 'Nothing'. Nesting is capped, because
-- a response body arrives before any trust check and @[[[[...@ must not
-- take the stack down.
parse :: String -> Maybe Json
parse body
  | null body = Nothing
  | otherwise = case value 0 (skip body) of
      Just (parsed, rest) | null (skip rest) -> Just parsed
      _ -> Nothing

maxdepth :: Int
maxdepth = 128

skip :: String -> String
skip = dropWhile isSpace

value :: Int -> String -> Maybe (Json, String)
value depth body
  | maxdepth < depth = Nothing
  | otherwise = case body of
      ('{' : rest) -> object depth (skip rest) []
      ('[' : rest) -> array depth (skip rest) []
      ('"' : rest) -> fmap (\(parsed, left) -> (JStr parsed, left)) (jstring rest)
      _ -> literal body
  where
    literal text'
      | "true" == take 4 text' = Just (JBool True, drop 4 text')
      | "false" == take 5 text' = Just (JBool False, drop 5 text')
      | "null" == take 4 text' = Just (JNull, drop 4 text')
      | otherwise = number text'

object :: Int -> String -> [(String, Json)] -> Maybe (Json, String)
object _ ('}' : rest) sofar = Just (JObj (reverse sofar), rest)
object depth body sofar = do
  (key, afterkey) <- case body of
    ('"' : rest) -> jstring rest
    _ -> Nothing

  rest <- case skip afterkey of
    (':' : left) -> Just left
    _ -> Nothing

  (entry, afterentry) <- value (depth + 1) (skip rest)

  -- A later duplicate overwrites the earlier one rather than sitting
  -- beside it, so that `lookup` cannot answer with the value the writer
  -- replaced.
  let kept = (key, entry) : filter ((key /=) . fst) sofar

  case skip afterentry of
    (',' : left) -> object depth (skip left) kept
    ('}' : left) -> Just (JObj (reverse kept), left)
    _ -> Nothing

array :: Int -> String -> [Json] -> Maybe (Json, String)
array _ (']' : rest) sofar = Just (JArr (reverse sofar), rest)
array depth body sofar = do
  (entry, afterentry) <- value (depth + 1) body

  case skip afterentry of
    (',' : left) -> array depth (skip left) (entry : sofar)
    (']' : left) -> Just (JArr (reverse (entry : sofar)), left)
    _ -> Nothing

-- | The body of a string, the opening quote already taken.
jstring :: String -> Maybe (String, String)
jstring = walk ""
  where
    walk sofar ('"' : rest) = Just (reverse sofar, rest)
    walk _ [] = Nothing
    walk sofar ('\\' : escape : rest) = case escape of
      '"' -> walk ('"' : sofar) rest
      '\\' -> walk ('\\' : sofar) rest
      '/' -> walk ('/' : sofar) rest
      'b' -> walk ('\b' : sofar) rest
      'f' -> walk ('\f' : sofar) rest
      'n' -> walk ('\n' : sofar) rest
      'r' -> walk ('\r' : sofar) rest
      't' -> walk ('\t' : sofar) rest
      -- Exactly four hex digits, appended as one UTF-16 code unit: no
      -- port recombines surrogate pairs.
      'u' ->
        let digits = take 4 rest
         in if 4 == length digits && all isHexDigit digits
              then case readHex digits of
                [(code, "")] -> walk (chr code : sofar) (drop 4 rest)
                _ -> Nothing
              else Nothing
      _ -> Nothing
    walk sofar (head : rest) = walk (head : sofar) rest

-- | A number, handed to the platform's float reader. A non-finite result -
-- @1e999@ parses to infinity - is refused: JSON has no infinity, and one
-- reaching a token-expiry computation blows it up later.
number :: String -> Maybe (Json, String)
number body
  | null span' = Nothing
  | otherwise = case reads (fixup span') :: [(Double, String)] of
      [(parsed, "")] | not (isNaN parsed) && not (isInfinite parsed) -> Just (JNum parsed, rest)
      _ -> Nothing
  where
    (span', rest) = Prelude.span numeric body
    numeric head = isDigit head || elem head "+-.eE"

    -- `reads` for Double will not take a leading '+' or '.', nor a bare
    -- trailing '.', so the span is normalised before it is handed over.
    fixup text' = case dropWhile ('+' ==) text' of
      ('-' : left) -> '-' : mantissa left
      left -> mantissa left

    mantissa text' = case text' of
      ('.' : left) -> "0." ++ left
      left -> left
