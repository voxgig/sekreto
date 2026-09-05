-- | SHA-256 and HMAC-SHA256, hand-rolled.
--
-- GHC ships no hash functions, and SigV4 signing needs exactly these two.
-- The TLS exception covers cryptographic TRANSPORT and nothing else, so
-- calling libcrypto's EVP_Digest here - which is linked in, and would work
-- - would be a rule violation rather than a shortcut. Rust is the worked
-- precedent: `ring` is already inside rustls's closure and the Rust port
-- still hand-rolls both.
--
-- SHA-256 is FIPS 180-4 straight from the standard; HMAC is RFC 2104 over
-- it. Both are proved by the spec's sigv4 known-answer cases, AWS's own
-- published `get-vanilla` vector among them: a signature is a chain of
-- these primitives, so one wrong bit anywhere fails there.

module Crypto
  ( hmacsha256,
    sha256,
    sha256hex,
  )
where

import Bytes (hex, utf8encode)
import Data.Bits (complement, rotateR, shiftL, shiftR, xor, (.&.), (.|.))
import qualified Data.ByteString as B
import Data.List (foldl')
import Data.Word (Word32, Word64, Word8)

-- | The round constants: the fractional parts of the cube roots of the
-- first 64 primes.
constants :: [Word32]
constants =
  [ 0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1,
    0x923f82a4, 0xab1c5ed5, 0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3,
    0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174, 0xe49b69c1, 0xefbe4786,
    0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147,
    0x06ca6351, 0x14292967, 0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13,
    0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85, 0xa2bfe8a1, 0xa81a664b,
    0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a,
    0x5b9cca4f, 0x682e6ff3, 0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208,
    0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2
  ]

-- | The initial hash: the fractional parts of the square roots of the
-- first eight primes.
initial :: [Word32]
initial =
  [0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19]

-- | The SHA-256 digest of a byte string.
sha256 :: B.ByteString -> B.ByteString
sha256 message = B.pack (concatMap bebytes (foldl' block initial (chunks padded)))
  where
    bits = 8 * fromIntegral (B.length message) :: Word64

    -- 0x80, zeros up to 56 bytes into the last block, then the message
    -- length in BITS, big-endian.
    padded =
      B.concat
        [ message,
          B.singleton 0x80,
          B.replicate zeros 0,
          B.pack [fromIntegral (bits `shiftR` shift) | shift <- [56, 48 .. 0]]
        ]

    zeros = (56 - (B.length message + 1) `mod` 64 + 64) `mod` 64

    chunks raw
      | B.null raw = []
      | otherwise = B.take 64 raw : chunks (B.drop 64 raw)

-- | Bytes as lowercase hex, the form SigV4 embeds.
sha256hex :: String -> String
sha256hex = hex . sha256 . utf8encode

-- | One 64-byte block folded into the running hash.
block :: [Word32] -> B.ByteString -> [Word32]
block hash raw = zipWith (+) hash (compress hash schedule)
  where
    first16 = [word (B.take 4 (B.drop (4 * slot) raw)) | slot <- [0 .. 15]]

    -- The message schedule, defined in terms of itself: laziness gives the
    -- recurrence directly, and taking 64 of it forces exactly what is used.
    schedule = take 64 grown
    grown =
      first16
        ++ [ small0 (grown !! (slot - 15))
               + grown !! (slot - 16)
               + grown !! (slot - 7)
               + small1 (grown !! (slot - 2))
             | slot <- [16 .. 63]
           ]

    small0 value = rotateR value 7 `xor` rotateR value 18 `xor` (value `shiftR` 3)
    small1 value = rotateR value 17 `xor` rotateR value 19 `xor` (value `shiftR` 10)

    word bytes = foldl' (\at byte -> (at `shiftL` 8) .|. fromIntegral byte) 0 (B.unpack bytes)

compress :: [Word32] -> [Word32] -> [Word32]
compress hash schedule = foldl' round8 hash (zip constants schedule)
  where
    round8 [a, b, c, d, e, f, g, h] (constant, word) =
      [temp1 + temp2, a, b, c, d + temp1, e, f, g]
      where
        big1 = rotateR e 6 `xor` rotateR e 11 `xor` rotateR e 25
        choose = (e .&. f) `xor` (complement e .&. g)
        temp1 = h + big1 + choose + constant + word
        big0 = rotateR a 2 `xor` rotateR a 13 `xor` rotateR a 22
        majority = (a .&. b) `xor` (a .&. c) `xor` (b .&. c)
        temp2 = big0 + majority
    round8 other _ = other

bebytes :: Word32 -> [Word8]
bebytes value = [fromIntegral (value `shiftR` shift) | shift <- [24, 16, 8, 0]]

-- | HMAC-SHA256 (RFC 2104): the primitive SigV4's key derivation chains.
--
-- The argument order is (key, data), which is the convention every port
-- uses; some standard libraries take them the other way round.
hmacsha256 :: B.ByteString -> B.ByteString -> B.ByteString
hmacsha256 key payload = sha256 (B.append (mask 0x5c) (sha256 (B.append (mask 0x36) payload)))
  where
    -- A key longer than the 64-byte block is hashed down; a shorter one is
    -- zero-padded up.
    shortened = if 64 < B.length key then sha256 key else key
    block64 = B.append shortened (B.replicate (64 - B.length shortened) 0)
    mask pad = B.map (`xor` pad) block64
