-- | AWS Signature Version 4, hand-rolled.
--
-- The AWS providers need exactly one thing from the AWS SDK - request
-- signing - and taking the SDK for it would break the no-dependency rule
-- that keeps the ports honest. SigV4 is a stable, published algorithm
-- built from HMAC-SHA256, which "Crypto" supplies in-tree.
--
-- 'sigv4' is pure: the caller passes the timestamp, so the same input
-- yields the same signature everywhere. That is what lets the shared spec
-- carry known-answer cases all ports must reproduce bit for bit, and lets
-- the integration mock recompute the signature server-side. Nothing here
-- samples the clock.
--
-- A port of typescript/plugins/sigv4.ts, which is canonical.

module Sigv4
  ( Signing (..),
    canonicalquery,
    emptysigning,
    sigv4,
    uridecode,
  )
where

import Bytes (hex, utf8decode, utf8encode)
import qualified Data.ByteString as B
import Crypto (hmacsha256, sha256hex)
import Http (uriescape)
import Data.Char (chr, digitToInt, isHexDigit, ord, toLower)
import Data.List (intercalate, isPrefixOf, sortBy)
import Data.Ord (comparing)
import Data.Word (Word8)

-- | One request to sign - the same declarative shape the shared spec uses.
-- @datetime@ is @YYYYMMDDTHHMMSSZ@, and it is the caller's.
data Signing = Signing
  { signmethod :: String,
    signurl :: String,
    signservice :: String,
    signregion :: String,
    signkeyid :: String,
    signsecret :: String,
    signdatetime :: String,
    signheaders :: [(String, String)],
    signbody :: String,
    signsession :: String
  }

emptysigning :: Signing
emptysigning =
  Signing
    { signmethod = "",
      signurl = "",
      signservice = "",
      signregion = "",
      signkeyid = "",
      signsecret = "",
      signdatetime = "",
      signheaders = [],
      signbody = "",
      signsession = ""
    }

-- | Percent-decode, and nothing else: @+@ stays @+@, as on the wire, and
-- a malformed escape is kept literal.
uridecode :: String -> String
uridecode = utf8decode . B.pack . walk
  where
    walk [] = []
    walk ('%' : first : second : rest)
      | isHexDigit first && isHexDigit second =
          (fromIntegral (16 * digitToInt first + digitToInt second) :: Word8) : walk rest
    walk (head : rest) = B.unpack (utf8encode [head]) ++ walk rest

-- | The canonical query string: each half decoded then RFC 3986-escaped,
-- sorted by escaped key then escaped value.
canonicalquery :: String -> String
canonicalquery query
  | null query = ""
  | otherwise = intercalate "&" (map render (sortBy (comparing id) (map pair (spliton '&' query))))
  where
    pair text = case break ('=' ==) text of
      (key, []) -> (uriescape (uridecode key), "")
      (key, _ : value) -> (uriescape (uridecode key), uriescape (uridecode value))

    render (key, value) = key ++ "=" ++ value

spliton :: Char -> String -> [String]
spliton sep body = case break (sep ==) body of
  (piece, []) -> [piece]
  (piece, _ : rest) -> piece : spliton sep rest

-- | The WHATWG @URL.host@: the host lowercased, userinfo stripped, and the
-- port appended only when it is not the scheme's default.
--
-- Hand-split. A platform URL type would have to agree with eleven other
-- ports about malformed input, and none of them do.
authorityof :: String -> String
authorityof url = hostpart ++ portpart
  where
    afterscheme = case break (':' ==) url of
      (_, ':' : '/' : '/' : rest) -> rest
      _ -> url

    scheme = takeWhile (':' /=) url

    authority = takeWhile (\head -> not (elem head "/?#")) afterscheme

    -- Everything after the LAST @, so that userinfo is stripped whether or
    -- not it carries a colon.
    naked = reverse (takeWhile ('@' /=) (reverse authority))

    hostpart = map toLower (if bracketed then take (closing + 1) naked else takeWhile (':' /=) naked)

    bracketed = "[" `isPrefixOf` naked
    closing = maybe (length naked - 1) id (elemindex ']' naked)

    rest' = drop (length hostpart) naked
    port = case rest' of
      (':' : digits) -> digits
      _ -> ""

    portpart
      | null port = ""
      | "https" == scheme && "443" == port = ""
      | "http" == scheme && "80" == port = ""
      | otherwise = ':' : port

elemindex :: Char -> String -> Maybe Int
elemindex want body = go 0 body
  where
    go _ [] = Nothing
    go at (head : rest) = if want == head then Just at else go (at + 1) rest

-- | The path as it appears in the url, already percent-encoded and not
-- re-escaped; @/@ when there is none.
pathof :: String -> String
pathof url = if null raw then "/" else raw
  where
    afterscheme = case break (':' ==) url of
      (_, ':' : '/' : '/' : rest) -> rest
      _ -> url

    raw = takeWhile (\head -> not (elem head "?#")) (dropWhile (\head -> '/' /= head) afterscheme)

queryof :: String -> String
queryof url = case break ('?' ==) url of
  (_, []) -> ""
  (_, _ : rest) -> takeWhile ('#' /=) rest

-- | Trim, then collapse every internal run of spaces and tabs to one.
-- AWS folds sequential whitespace before signing, so @a  b\\tc@ must sign
-- as @a b c@ or the service refuses the request.
foldspace :: String -> String
foldspace = unwords . words

-- | Sign one request. Answers the headers to attach: @authorization@,
-- @x-amz-date@, and @x-amz-security-token@ only when a session was given,
-- in that order - the spec compares the whole map, so the order is
-- contract.
sigv4 :: Signing -> [(String, String)]
sigv4 input =
  [("authorization", authorization)]
    ++ [("x-amz-date", signdatetime input)]
    ++ [("x-amz-security-token", signsession input) | not (null (signsession input))]
  where
    date = take 8 (signdatetime input)

    -- The caller's headers first, then host, x-amz-date and the session
    -- token, so that those win over anything the caller passed.
    given = [(map toLower key, foldspace value) | (key, value) <- signheaders input]

    withhost =
      foldl set given $
        [("host", authorityof (signurl input)), ("x-amz-date", signdatetime input)]
          ++ [("x-amz-security-token", signsession input) | not (null (signsession input))]

    set entries (key, value) =
      if any ((key ==) . fst) entries
        then map (\(at, was) -> if key == at then (at, value) else (at, was)) entries
        else entries ++ [(key, value)]

    headers = sortBy (comparing fst) withhost

    canonicalheaders = concat [key ++ ":" ++ value ++ "\n" | (key, value) <- headers]
    signedheaders = intercalate ";" (map fst headers)

    canonicalrequest =
      intercalate
        "\n"
        [ map upperhead (signmethod input),
          pathof (signurl input),
          canonicalquery (queryof (signurl input)),
          canonicalheaders,
          signedheaders,
          sha256hex (signbody input)
        ]

    scope = date ++ "/" ++ signregion input ++ "/" ++ signservice input ++ "/aws4_request"

    stringtosign =
      intercalate
        "\n"
        ["AWS4-HMAC-SHA256", signdatetime input, scope, sha256hex canonicalrequest]

    kdate = hmacsha256 (utf8encode ("AWS4" ++ signsecret input)) (utf8encode date)
    kregion = hmacsha256 kdate (utf8encode (signregion input))
    kservice = hmacsha256 kregion (utf8encode (signservice input))
    ksigning = hmacsha256 kservice (utf8encode "aws4_request")
    signature = hex (hmacsha256 ksigning (utf8encode stringtosign))

    authorization =
      "AWS4-HMAC-SHA256 Credential="
        ++ signkeyid input
        ++ "/"
        ++ scope
        ++ ", SignedHeaders="
        ++ signedheaders
        ++ ", Signature="
        ++ signature

    upperhead head = if 'a' <= head && 'z' >= head then chr (ord head - 32) else head
