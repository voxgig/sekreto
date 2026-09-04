-- | Bytes, and the three conversions sekreto needs between them and text.
--
-- UTF-8 is hand-rolled rather than taken from `text`: everything the wire
-- carries is bytes, everything the library reasons about is 'String', and
-- the conversion is small enough to own. Decoding is lenient - a vault
-- that answered with a broken byte answered badly, but the answer is not
-- the place to raise, and the JSON parser above will say so.
--
-- base64 DECODING only; nothing here ever encodes. It is deliberately
-- strict: a lenient decoder silently skips bytes outside the alphabet and
-- hands back plausible bytes for a corrupted payload, which then get
-- returned as the secret.

module Bytes
  ( hex,
    unbase64,
    utf8decode,
    utf8encode,
  )
where

import Data.Bits (shiftL, shiftR, (.&.), (.|.))
import qualified Data.ByteString as B
import Data.Char (chr, isSpace, ord)
import Data.List (elemIndex)
import Data.Word (Word8)

-- | Bytes as lowercase hex, two digits each. Uppercase hex is needed in
-- exactly one place in this library, and that is percent-escaping.
hex :: B.ByteString -> String
hex = concatMap byte . B.unpack
  where
    byte value = [digit (fromIntegral value `shiftR` 4), digit (fromIntegral value .&. 15)]
    digit nibble = "0123456789abcdef" !! nibble

-- | A string as UTF-8 bytes.
utf8encode :: String -> B.ByteString
utf8encode = B.pack . concatMap encode
  where
    encode head
      | 0x80 > code = [fromIntegral code]
      | 0x800 > code =
          [ fromIntegral (0xc0 .|. (code `shiftR` 6)),
            trail code
          ]
      | 0x10000 > code =
          [ fromIntegral (0xe0 .|. (code `shiftR` 12)),
            trail (code `shiftR` 6),
            trail code
          ]
      | otherwise =
          [ fromIntegral (0xf0 .|. (code `shiftR` 18)),
            trail (code `shiftR` 12),
            trail (code `shiftR` 6),
            trail code
          ]
      where
        code = ord head

    trail :: Int -> Word8
    trail value = fromIntegral (0x80 .|. (value .&. 0x3f))

-- | UTF-8 bytes as a string. A malformed sequence becomes U+FFFD, so that
-- a response body is always readable and the decision about whether it
-- made sense belongs to the JSON parser.
utf8decode :: B.ByteString -> String
utf8decode = walk . B.unpack
  where
    walk [] = []
    walk (head : rest)
      | 0x80 > value = chr value : walk rest
      | 0xc0 <= value && 0xe0 > value = wide 1 (value .&. 0x1f) rest
      | 0xe0 <= value && 0xf0 > value = wide 2 (value .&. 0x0f) rest
      | 0xf0 <= value && 0xf8 > value = wide 3 (value .&. 0x07) rest
      | otherwise = '\xfffd' : walk rest
      where
        value = fromIntegral head :: Int

    wide want acc rest
      | length taken < want || any (not . iscont) taken = '\xfffd' : walk rest
      | 0x10ffff < code = '\xfffd' : walk left
      | otherwise = chr code : walk left
      where
        taken = take want rest
        left = drop want rest
        code = foldl (\at byte -> (at `shiftL` 6) .|. (fromIntegral byte .&. 0x3f)) acc taken

    iscont byte = 0x80 == (byte .&. 0xc0)

-- | Decode standard (not URL-safe) base64. Nothing when the payload is not
-- base64 at all, which is an error at every call site and never a miss.
--
-- Whitespace is stripped first because the canonical function accepts
-- embedded newlines; everything else outside the alphabet, and any length
-- that is not a multiple of four, is a refusal.
unbase64 :: String -> Maybe B.ByteString
unbase64 text
  | 0 /= length body `mod` 4 = Nothing
  | not (all ok body) = Nothing
  | not (padok body) = Nothing
  | otherwise = B.pack <$> decode (takeWhile ('=' /=) body) 0 0
  where
    body = filter (not . isSpace) text

    ok head = '=' == head || elem head alphabet

    -- At most two '=', and only at the very end.
    padok payload = 2 >= length pad && all ('=' ==) pad
      where
        pad = dropWhile ('=' /=) payload

    -- A sliding six-bit accumulator, masked back down after every byte is
    -- taken off it so that it cannot grow without bound.
    decode [] _ _ = Just []
    decode (head : rest) acc bits =
      case elemIndex head alphabet of
        Nothing -> Nothing
        Just value ->
          let widened = (acc `shiftL` 6) .|. value
              held = bits + 6
           in if 8 <= held
                then
                  let left = held - 8
                      kept = widened .&. ((1 `shiftL` left) - 1)
                   in (fromIntegral (widened `shiftR` left) :) <$> decode rest kept left
                else decode rest widened held

alphabet :: String
alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"
