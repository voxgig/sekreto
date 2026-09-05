-- | Just enough HTTP to ask a vault for a secret.
--
-- GHC has no HTTP client - it has no socket either - so this speaks
-- HTTP/1.1 over the connection "Tls" hands back: a GET or POST with
-- headers and an optional body, a status line, and a response body
-- delimited by @Content-Length@, by chunks, or by the connection closing.
--
-- It is deliberately not a general-purpose client. No redirect is
-- followed: a vault API does not legitimately redirect, and a followed
-- redirect would carry @X-Vault-Token@ to a host `checkaddr` never saw,
-- and could downgrade https to http. No proxy is consulted: the GCP and
-- Azure metadata endpoints are not loopback, and an @http_proxy@ in the
-- environment has sent a Vault token in the clear before. No keep-alive,
-- no client certificates.

module Http
  ( Response (..),
    nakedurl,
    request,
    uriescape,
  )
where

import Bytes (utf8decode, utf8encode)
import Control.Exception (finally, throwIO)
import qualified Data.ByteString as B
import Data.Char (chr, isSpace, toLower)
import Data.List (isInfixOf, isPrefixOf, isSuffixOf)
import Numeric (readHex)
import Provider (SekretoError (..))
import Tls (Conn (..), dial, havetls)

-- | What a vault answered: the status code and the raw body.
data Response = Response {resstatus :: Int, resbody :: String}

-- | How much of a response body will be read before the store is treated
-- as having answered incoherently. Ports carry the same bound.
--
-- Far above anything real - the largest legitimate payload this library
-- fetches is Doppler's whole-config download, measured in kilobytes. A
-- bound is needed because the timeout is not one: it is per read, so a
-- server that keeps sending resets it forever, and the body is
-- accumulated in memory before it is parsed. This runs on an
-- application's startup path, so the failure is the application never
-- starting.
maxbody :: Int
maxbody = 8 * 1024 * 1024

-- | A url without its query string, for messages.
--
-- A query here carries the vault path, the secret name or a filter -
-- @secretPath=/prod/payments/stripe@ - which does not belong in a log or
-- a stack trace.
nakedurl :: String -> String
nakedurl = takeWhile ('?' /=)

-- | A url split into the parts a request needs.
data Target = Target
  { -- | The bare host: what we connect to, and what the certificate is
    -- checked against. An IPv6 literal appears here without brackets.
    tgthost :: String,
    -- | The authority as it goes in the @Host:@ header. An IPv6 literal
    -- keeps its brackets, because @Host: 2001:db8::1:8200@ is not a valid
    -- authority and an intermediary may reject or misroute it.
    tgtauthority :: String,
    tgtport :: Int,
    tgtpath :: String,
    tgttls :: Bool
  }

split :: String -> Either String Target
split url
  | "http://" `isPrefixOf` url = shape (drop 7 url) False 80
  | "https://" `isPrefixOf` url = shape (drop 8 url) True 443
  | otherwise = Left ("sekreto: not an http url: " ++ nakedurl url)
  where
    shape rest usetls defaultport =
      case portof of
        Nothing -> Left ("sekreto: bad port: " ++ nakedurl url)
        Just port ->
          Right
            Target
              { tgthost = bare,
                -- Re-bracketed only if it really is an IPv6 literal.
                tgtauthority = if elem ':' bare then "[" ++ bare ++ "]" else bare,
                tgtport = port,
                tgtpath = path,
                tgttls = usetls
              }
      where
        (authority, path) = case break ('/' ==) rest of
          (front, []) -> (front, "/")
          (front, tail') -> (front, tail')

        -- The port is found by a search for the LAST colon, so that an
        -- IPv6 literal's own colons are not read as a separator; a
        -- bracketed literal with no port has none at all.
        (hostraw, portraw)
          | "]" `isSuffixOf` authority = (authority, "")
          | otherwise = case lastcolon authority of
              Nothing -> (authority, "")
              Just at -> (take at authority, drop (at + 1) authority)

        bare = filter (\head -> '[' /= head && ']' /= head) hostraw

        portof
          | null portraw = Just defaultport
          | otherwise = case reads portraw :: [(Int, String)] of
              [(port, "")] -> Just port
              _ -> Nothing

    lastcolon body = case [at | (at, head) <- zip [0 ..] body, ':' == head] of
      [] -> Nothing
      found -> Just (last found)

-- | One HTTP exchange: any method, a set of headers, an optional body.
--
-- A non-2xx status is returned, not raised: a 404 from a vault means "no
-- such secret", which is a miss rather than a failure. Everything that
-- stops the exchange happening at all is raised, because a store that
-- could not answer must never read as a store that answered "no".
request :: String -> String -> [(String, String)] -> Maybe String -> IO Response
request method url headers body = do
  target <- case split url of
    Left why -> throwIO (SekretoError why)
    Right found -> pure found

  -- A build with no TLS backend must say so loudly. Reaching a plaintext
  -- loopback mock and silently reaching nowhere over https is the one
  -- outcome this library must never ship.
  usable <- havetls
  if tgttls target && not usable
    then unreachable url "this build has no TLS backend"
    else pure ()

  opened <- dial (tgthost target) (tgtport target) (tgttls target)

  case opened of
    Left why -> unreachable url why
    Right conn -> exchange conn target method url headers body `finally` connclose conn

unreachable :: String -> String -> IO a
unreachable url why =
  throwIO (SekretoError ("sekreto: cannot reach " ++ nakedurl url ++ ": " ++ why))

exchange ::
  Conn -> Target -> String -> String -> [(String, String)] -> Maybe String -> IO Response
exchange conn target method url headers body = do
  wrote <- connsend conn (utf8encode wire)
  case wrote of
    Left why -> unreachable url why
    Right () -> pure ()

  raw <- drain conn url B.empty

  if maxbody < B.length raw
    then throwIO (SekretoError ("sekreto: oversized response from " ++ nakedurl url))
    else pure ()

  case findbytes (utf8encode "\r\n\r\n") raw of
    Nothing -> throwIO (SekretoError ("sekreto: malformed response from " ++ nakedurl url))
    Just at -> do
      -- Headers are ASCII; the body is not necessarily, so it stays bytes
      -- until every length-counted slice has been taken. A chunk boundary
      -- may fall inside a multibyte character.
      let head' = utf8decode (B.take at raw)
          rawbody = B.drop (at + 4) raw

      status <- case statusof head' of
        Nothing -> throwIO (SekretoError ("sekreto: no status from " ++ nakedurl url))
        Just code -> pure code

      bodybytes <-
        if chunkedof head'
          then case dechunk rawbody of
            Nothing ->
              throwIO (SekretoError ("sekreto: malformed response from " ++ nakedurl url))
            Just joined -> pure joined
          else pure rawbody

      pure (Response status (utf8decode bodybytes))
  where
    -- A default port stays implicit in the Host header, the way a URL
    -- normalises it: a SigV4 signature covers `host`, and `Host: x:443`
    -- is not what was signed.
    hostheader
      | tgttls target && 443 == tgtport target = tgtauthority target
      | not (tgttls target) && 80 == tgtport target = tgtauthority target
      | otherwise = tgtauthority target ++ ":" ++ show (tgtport target)

    wire =
      method
        ++ " "
        ++ tgtpath target
        ++ " HTTP/1.1\r\nHost: "
        ++ hostheader
        ++ "\r\nAccept: application/json\r\nConnection: close\r\n"
        ++ concat [name ++ ": " ++ value ++ "\r\n" | (name, value) <- headers]
        ++ maybe "" (\text -> "Content-Length: " ++ show (B.length (utf8encode text)) ++ "\r\n") body
        ++ "\r\n"
        ++ maybe "" id body

-- | Read to end of stream, one byte past the bound so that exceeding it
-- can be detected. An endless body is a store that could not answer, so
-- the caller raises rather than returning a miss - the latter would fall
-- through to a weaker store on an attacker's cue.
drain :: Conn -> String -> B.ByteString -> IO B.ByteString
drain conn url sofar
  | maxbody < B.length sofar = pure sofar
  | otherwise = do
      got <- connrecv conn 65536
      case got of
        Left why -> unreachable url why
        Right chunk
          | B.null chunk -> pure sofar
          | otherwise -> drain conn url (B.append sofar chunk)

-- | "HTTP/1.1 200 OK" - the second whitespace-separated field.
statusof :: String -> Maybe Int
statusof head' = case words (takeWhile ('\r' /=) (takeWhile ('\n' /=) head')) of
  (_ : code : _) -> case reads code :: [(Int, String)] of
    [(status, "")] -> Just status
    _ -> Nothing
  _ -> Nothing

-- | A server that does not know the body length up front sends it in
-- chunks - which is what a vault answering from a store usually does.
chunkedof :: String -> Bool
chunkedof head' = any ischunked (drop 1 (headerlines head'))
  where
    ischunked line = case break (':' ==) line of
      (name, ':' : value) ->
        "transfer-encoding" == map toLower (trim name) && isInfixOf "chunked" (map toLower value)
      _ -> False

headerlines :: String -> [String]
headerlines head' = map (takeWhile ('\r' /=)) (splitlines head')

splitlines :: String -> [String]
splitlines body = case break ('\n' ==) body of
  (piece, []) -> [piece]
  (piece, _ : rest) -> piece : splitlines rest

trim :: String -> String
trim = dropWhile isSpace . reverse . dropWhile isSpace . reverse

-- | The offset of a needle in a haystack.
findbytes :: B.ByteString -> B.ByteString -> Maybe Int
findbytes needle hay =
  case B.breakSubstring needle hay of
    (front, rest) | B.null rest -> Nothing
                  | otherwise -> Just (B.length front)

-- | Join a chunked body back together.
--
-- Each chunk is a hex length, CRLF, that many BYTES, CRLF. A zero length
-- ends the body; any trailer after it is ignored. Bytes, not characters:
-- a chunk length counts bytes, and a boundary may fall inside a multibyte
-- character - so slicing text here would corrupt any secret with a
-- non-ASCII character in it.
dechunk :: B.ByteString -> Maybe B.ByteString
dechunk = go B.empty
  where
    crlf = utf8encode "\r\n"

    go sofar rest = do
      at <- findbytes crlf rest

      -- A chunk length may carry extensions after a semicolon.
      let header = utf8decode (B.take at rest)
      size <- case readHex (trim (takeWhile (';' /=) header)) :: [(Int, String)] of
        [(value, "")] -> Just value
        _ -> Nothing

      let payload = B.drop (at + 2) rest

      if 0 == size
        then Just sofar
        else
          if B.length payload < size
            then Nothing
            else go (B.append sofar (B.take size payload)) (B.drop (size + 2) payload)

-- | RFC 3986 escaping, for the plugins that build a URL by hand.
--
-- Stricter than the usual URL encoder: everything but the unreserved set
-- is escaped, with uppercase hex, which is what AWS request signing
-- needs. @!'()*@ are escaped here and are not by JavaScript's
-- @encodeURIComponent@, which is the gap that catches ports out.
--
-- It lives here rather than beside the signer so that a chain naming
-- @doppler@ escapes a secret id without linking SHA-256 and HMAC.
uriescape :: String -> String
uriescape = concatMap byte . B.unpack . utf8encode
  where
    byte value
      | unreserved head = [head]
      | otherwise = ['%', digit (fromIntegral value `div` 16), digit (fromIntegral value `mod` 16)]
      where
        head = chr (fromIntegral value)

    unreserved head =
      ('A' <= head && 'Z' >= head)
        || ('a' <= head && 'z' >= head)
        || ('0' <= head && '9' >= head)
        || elem head "-_.~"

    digit nibble = "0123456789ABCDEF" !! nibble
