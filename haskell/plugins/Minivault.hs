-- | A mini vault: every secret a project owns, encrypted, in ONE FILE.
--
-- The store to reach for before there is a vault server. There is nothing
-- to run and nothing to reach over a socket - the whole store is a single
-- binary file - and the same chain that reads it in development reads
-- HashiCorp or AWS in production by changing config, which is the reason
-- sekreto exists.
--
-- A PLUGIN, not a built-in: this kind needs crypto, which is the line the
-- four built-in kinds stay behind. GHC's boot libraries carry no
-- cryptography whatever and the no-new-package rule stands, so the four
-- primitives come from the OpenSSL this port already links, through
-- @plugins\/minivault.c@ - whose header says why the dependency exception
-- now reaches this far.
--
-- THE KEY DECIDES WHAT THE VAULT HOLDS. A master key reads and writes
-- every name and mints restricted keys. A restricted key reads the names
-- it was granted and CANNOT DERIVE ANY OTHER - the restriction is the
-- cryptography rather than a check this code performs, so a copy of the
-- file plus a restricted passphrase yields exactly what was granted and
-- nothing else. What that does and does not protect is set out in DOCS.md
-- under "What the mini vault protects".
--
-- THE FILE FORMAT, which is the contract between the ports:
--
-- >   magic       4   'SKMV'
-- >   version     1   format
-- >   kdf         1   1 = PBKDF2-HMAC-SHA256
-- >   cipher      1   1 = AES-256-GCM
-- >   reserved    1   0
-- >   keycount    4   uint32
-- >   per key:
-- >     id        1 + bytes      the key id, PLAINTEXT
-- >     salt      1 + bytes
-- >     iters     4              PBKDF2 rounds for this key
-- >     ring      1 + iv, 4 + bytes    sealed under the passphrase
-- >     meta      1 + iv, 4 + bytes    sealed under the vault's meta key
-- >   entrycount  4   uint32
-- >   per entry:
-- >     id        1 + bytes      the blinded lookup id
-- >     name      1 + iv, 4 + bytes    sealed under the vault's name key
-- >     value     1 + iv, 4 + bytes    sealed under that secret's own key
--
-- Integers are big-endian and every length precedes its bytes, so the
-- file is written with the same two primitives it is read with.
--
-- NOTHING OUTSIDE A KEY RECORD IS PLAINTEXT. Secret names are sealed, and
-- an entry is addressed by a blinded id derived from its own key, so a
-- restricted key finds what it was granted without the file ever naming
-- the rest. What the file does show anyone is the key ids and how many
-- secrets there are.
--
-- A port of typescript/plugins/minivault.ts, which is canonical. The
-- bytes are pinned by the vaults in test/fixture rather than left to
-- agreement between implementations.

{-# LANGUAGE ForeignFunctionInterface #-}

module Minivault
  ( Vault,
    VaultKeyInfo (..),
    VaultOptions (..),
    GrantSpec (..),
    novaultoptions,
    nogrant,
    createvault,
    openvault,
    vaultfile,
    vaultkeyid,
    vaultopen,
    vaultclose,
    vaultlist,
    vaultget,
    vaulthas,
    vaultset,
    vaultremove,
    vaultkeys,
    vaultgrant,
    vaultrevoke,
    vaultrotate,
    vaultof,
    minivault,
    vaultexport,
    heldvaults,
  )
where

import Control.Exception (SomeException, throwIO, try)
import Control.Monad (when)
import qualified Data.ByteString as B
import qualified Data.ByteString.Char8 as C
import Data.Bits (shiftL, shiftR, (.&.), (.|.))
import Data.IORef (IORef, atomicModifyIORef', newIORef, readIORef, writeIORef)
import Data.List (find, sort, sortOn)
import Data.Word (Word8)
import Defs (Definition (..), Host, Inst (..))
import Foreign.C.Types (CChar, CInt (..))
import Foreign.Marshal.Alloc (allocaBytes)
import Foreign.Ptr (Ptr)
import Host (hostExports, hostInstance, instExport)
import qualified Json as J
import Names (checkname)
import Provider (Provider (..), SekretoError (..), forced)
import Providers
  ( ProviderSpec (..),
    errorcode,
    holdprovider,
    providerexport,
    specof,
    takeprovider,
  )
import Foreign.C.String (withCString)
import System.Directory (removeFile, renameFile)
import System.IO.Unsafe (unsafePerformIO)
import System.IO (hClose)
import System.Posix.IO (fdToHandle)
import System.Posix.Types (Fd (..))
import Types (details2, raise)
import Value (Value (..), asNum, isNum, vget)

-- --------------------------------------------------------- the primitives

foreign import ccall unsafe "sekreto_mv_open"
  c_open :: Ptr CChar -> CInt -> IO CInt

foreign import ccall unsafe "sekreto_mv_random"
  c_random :: Ptr CChar -> CInt -> IO CInt

foreign import ccall unsafe "sekreto_mv_hmac"
  c_hmac :: Ptr CChar -> CInt -> Ptr CChar -> CInt -> Ptr CChar -> IO CInt

foreign import ccall safe "sekreto_mv_pbkdf2"
  c_pbkdf2 :: Ptr CChar -> CInt -> Ptr CChar -> CInt -> CInt -> Ptr CChar -> CInt -> IO CInt

foreign import ccall unsafe "sekreto_mv_seal"
  c_seal ::
    Ptr CChar -> Ptr CChar -> Ptr CChar -> CInt -> Ptr CChar -> CInt -> Ptr CChar -> IO CInt

foreign import ccall unsafe "sekreto_mv_unseal"
  c_unseal ::
    Ptr CChar -> Ptr CChar -> Ptr CChar -> CInt -> Ptr CChar -> CInt -> Ptr CChar -> IO CInt

-- ------------------------------------------------------------- the format

magic :: B.ByteString
magic = C.pack "SKMV"

format, kdfpbkdf2, cipheraesgcm :: Int
format = 1
kdfpbkdf2 = 1
cipheraesgcm = 1

-- | AES-256-GCM: 32-byte keys, 12-byte nonces, 16-byte tags.
keylen, ivlen, taglen, saltlen :: Int
keylen = 32
ivlen = 12
taglen = 16
saltlen = 16

-- | The PBKDF2-HMAC-SHA256 round count when a caller names none.
iterations :: Int
iterations = 210000

-- | The key id a vault gets when a caller names none.
masterkeyid :: String
masterkeyid = "master"

-- | The export key the vault API is published under, beside the
-- @provider@ key every kind publishes.
vaultexport :: String
vaultexport = "vault"

-- Additional authenticated data. Every blob is bound to its PLACE in the
-- file, so no ciphertext can be moved: a restricted key's ring cannot be
-- relabelled as the master's, and one secret's value cannot be served
-- under a name it was never written for.
aadring, aadmeta, aadname, aadsecret :: String
aadring = "skmv1:ring:"
aadmeta = "skmv1:meta:"
aadname = "skmv1:name"
aadsecret = "skmv1:secret:"

-- Everything a master reaches is derived from the root key, so rotating
-- is one new random value rather than a re-wrap of each part.
labelnames, labelmeta, labelid :: String
labelnames = "skmv1:names"
labelmeta = "skmv1:meta"
labelid = "skmv1:id"

-- | The largest key id the format can record.
--
-- A length is written in ONE byte. A longer id wrapped that byte and the
-- writer then appended the whole thing, so every field after it shifted:
-- a grant with a 300-character id replaced a working vault with an
-- unreadable one, and said nothing. Checked where an id is ACCEPTED, so
-- the refusal names the id rather than the file.
idmax :: Int
idmax = 255

mvfail :: String -> IO a
mvfail why = throwIO (SekretoError ("sekreto: minivault: " ++ why))

checkid :: String -> String -> IO String
checkid held what
  | null held = mvfail what
  | idmax < length held =
      mvfail ("key id is longer than " ++ show idmax ++ " bytes: " ++ take 32 held ++ "...")
  | otherwise = pure held

-- ---------------------------------------------------------------- bytes

bytesof :: String -> B.ByteString
bytesof = C.pack

-- | The bytes as text. Every plaintext this is used on is a secret name
-- or a secret value, and both are text by the library's own rules.
textof :: B.ByteString -> String
textof = C.unpack

-- | Bytes into a C buffer and out again, which is every call below.
withbytes :: B.ByteString -> ((Ptr CChar, Int) -> IO a) -> IO a
withbytes raw body = B.useAsCStringLen raw body

-- ------------------------------------------------------------------ keys

randombytes :: Int -> IO B.ByteString
randombytes len =
  allocaBytes len $ \out -> do
    got <- c_random out (fromIntegral len)
    if 0 > got then mvfail "no randomness available" else B.packCStringLen (out, len)

mac :: B.ByteString -> String -> IO B.ByteString
mac key text =
  withbytes key $ \(kp, klen) ->
    withbytes (bytesof text) $ \(mp, mlen) ->
      allocaBytes keylen $ \out -> do
        got <- c_hmac kp (fromIntegral klen) mp (fromIntegral mlen) out
        if 0 > got then mvfail "cannot compute a mac" else B.packCStringLen (out, keylen)

-- | The key-encryption key a passphrase unwraps a ring with.
--
-- A round count below one is refused in the shim, which is what a damaged
-- or hostile file records to make the derivation free.
kek :: String -> B.ByteString -> Int -> IO B.ByteString
kek passphrase salt iters =
  withbytes (bytesof passphrase) $ \(pp, plen) ->
    withbytes salt $ \(sp, slen) ->
      allocaBytes keylen $ \out -> do
        got <-
          c_pbkdf2 pp (fromIntegral plen) sp (fromIntegral slen) (fromIntegral iters) out
            (fromIntegral keylen)
        if 0 > got
          then mvfail ("unusable round count: " ++ show iters)
          else B.packCStringLen (out, keylen)

-- | The key one named secret's value is encrypted with.
--
-- DERIVED, never stored, for a master: it holds the root key and so
-- reaches every name, including ones written after it was made. A
-- restricted key holds the derived keys it was granted and nothing that
-- produces another, so every other name is ciphertext to it in exactly
-- the way it is to a stranger.
secretkey :: B.ByteString -> String -> IO B.ByteString
secretkey root name = mac root (aadsecret ++ name)

-- | Where a secret lives in the file, derived from its own key so that
-- finding it needs no plaintext name. One-way: an id yields nothing about
-- the key that produced it.
entryid :: B.ByteString -> IO B.ByteString
entryid key = mac key labelid

-- --------------------------------------------------------------- sealing

data Sealed = Sealed {sealediv :: B.ByteString, sealedblob :: B.ByteString}
  deriving (Eq)

-- | The tag rides at the END of the blob, which is where every other
-- port's AEAD leaves it and therefore what the format records.
seal :: B.ByteString -> B.ByteString -> String -> IO Sealed
seal key plain aad = do
  when (keylen /= B.length key) (() <$ mvfail "bad key")
  iv <- randombytes ivlen

  blob <-
    withbytes key $ \(kp, _) ->
      withbytes iv $ \(ip, _) ->
        withbytes plain $ \(pp, plen) ->
          withbytes (bytesof aad) $ \(ap, alen) ->
            allocaBytes (plen + taglen) $ \out -> do
              got <- c_seal kp ip pp (fromIntegral plen) ap (fromIntegral alen) out
              if 0 > got then mvfail "cannot seal" else B.packCStringLen (out, plen + taglen)

  pure (Sealed iv blob)

-- | The plaintext, or a refusal. A GCM tag that fails to verify is the
-- only evidence there is, and it cannot tell a wrong passphrase from a
-- damaged file, so @what@ names the attempt and the message admits both.
unseal :: B.ByteString -> Sealed -> String -> String -> IO B.ByteString
unseal key box aad what
  | taglen > B.length (sealedblob box) || ivlen /= B.length (sealediv box) =
      mvfail (what ++ ": truncated")
  | keylen /= B.length key = mvfail "bad key"
  | otherwise =
      withbytes key $ \(kp, _) ->
        withbytes (sealediv box) $ \(ip, _) ->
          withbytes (sealedblob box) $ \(bp, blen) ->
            withbytes (bytesof aad) $ \(ap, alen) ->
              allocaBytes (blen - taglen) $ \out -> do
                got <- c_unseal kp ip bp (fromIntegral blen) ap (fromIntegral alen) out
                if 0 > got then mvfail what else B.packCStringLen (out, blen - taglen)

-- ---------------------------------------------------------------- base64

-- Here rather than @Http.unbase64@: naming that module would link the
-- socket and the TLS binding beneath it into a binary whose only store
-- opens nothing, which is the cost the core/plugin split exists to
-- remove.
b64alphabet :: String
b64alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"

b64 :: B.ByteString -> String
b64 raw = go (map fromIntegral (B.unpack raw) :: [Int])
  where
    go [] = []
    go [a] = [pick (triple a 0 0) 0, pick (triple a 0 0) 1, '=', '=']
    go [a, b] = [pick (triple a b 0) at | at <- [0 .. 2]] ++ "="
    go (a : b : c : rest) = [pick (triple a b c) at | at <- [0 .. 3]] ++ go rest

    triple :: Int -> Int -> Int -> Int
    triple a b c = (a `shiftL` 16) .|. (b `shiftL` 8) .|. c

    pick held at = b64alphabet !! ((held `shiftR` (18 - 6 * at)) .&. 0x3f)

-- | STRICT. A lenient decoder hands back plausible bytes for a corrupted
-- payload, and those bytes are then used AS A KEY.
unb64 :: String -> String -> IO B.ByteString
unb64 text what
  | null text || 0 /= length text `mod` 4 = missing
  | 2 < length pad || any ('=' /=) pad = missing
  | any (`notElem` b64alphabet) body = missing
  | otherwise = pure (B.pack (concatMap group (chunks body)))
  where
    missing = mvfail ("missing " ++ what)

    (body, pad) = span ('=' /=) text

    chunks [] = []
    chunks held = take 4 held : chunks (drop 4 held)

    -- The last chunk is short by as many characters as there was padding,
    -- and each missing character is two bytes fewer out of every three.
    group held = take (length held - 1) (bytes (foldl step 0 (held ++ replicate (4 - length held) 'A')))

    step acc ch = (acc `shiftL` 6) .|. sextet ch

    sextet ch = length (takeWhile (ch /=) b64alphabet)

    bytes :: Int -> [Word8]
    bytes held = [fromIntegral ((held `shiftR` at) .&. 0xff) | at <- [16, 8, 0]]

-- ------------------------------------------------------------- the file

data KeyRecord = KeyRecord
  { recid :: String,
    recsalt :: B.ByteString,
    reciters :: Int,
    recring :: Sealed,
    recmeta :: Sealed
  }

data EntryRecord = EntryRecord
  { entid :: B.ByteString,
    entname :: Sealed,
    entvalue :: Sealed
  }

data VaultFile = VaultFile {filekeys :: [KeyRecord], fileentries :: [EntryRecord]}

keyrecordof :: VaultFile -> String -> Maybe KeyRecord
keyrecordof file held = find ((held ==) . recid) (filekeys file)

entryrecordof :: VaultFile -> B.ByteString -> Maybe EntryRecord
entryrecordof file held = find ((held ==) . entid) (fileentries file)

-- | A cursor, so that every length check is in one place: a truncated
-- vault is refused rather than read as a short one.
data Cursor = Cursor {cursorraw :: B.ByteString, cursorat :: Int}

-- | Reads @length@ bytes, or refuses.
--
-- The bound is checked AGAINST WHAT IS LEFT, never by adding the length
-- to the cursor. Haskell's Int is 64-bit so the sum cannot wrap here, but
-- the check reads the same in every port and is the one that is right
-- everywhere.
take' :: Cursor -> Int -> IO (B.ByteString, Cursor)
take' cur len
  | 0 > len || B.length (cursorraw cur) - cursorat cur < len =
      mvfail "the vault file is truncated"
  | otherwise =
      pure (B.take len (B.drop (cursorat cur) (cursorraw cur)), cur {cursorat = cursorat cur + len})

u8' :: Cursor -> IO (Int, Cursor)
u8' cur = do
  (raw, next) <- take' cur 1
  pure (fromIntegral (B.head raw), next)

u32' :: Cursor -> IO (Int, Cursor)
u32' cur = do
  (raw, next) <- take' cur 4
  let byte at = fromIntegral (B.index raw at) :: Int
  pure ((byte 0 `shiftL` 24) .|. (byte 1 `shiftL` 16) .|. (byte 2 `shiftL` 8) .|. byte 3, next)

small' :: Cursor -> IO (B.ByteString, Cursor)
small' cur = u8' cur >>= uncurry (flip take')

large' :: Cursor -> IO (B.ByteString, Cursor)
large' cur = u32' cur >>= uncurry (flip take')

sealed' :: Cursor -> IO (Sealed, Cursor)
sealed' cur = do
  (iv, after) <- small' cur
  (blob, next) <- large' after
  pure (Sealed iv blob, next)

readfile :: B.ByteString -> IO VaultFile
readfile raw = do
  (found, c1) <- take' (Cursor raw 0) 4
  when (magic /= found) (() <$ mvfail "not a vault file")

  (version, c2) <- u8' c1
  when (format /= version) (() <$ mvfail ("unsupported format version: " ++ show version))

  (kdf, c3) <- u8' c2
  (cipher, c4) <- u8' c3
  when
    (kdfpbkdf2 /= kdf || cipheraesgcm /= cipher)
    (() <$ mvfail ("unsupported kdf or cipher: " ++ show kdf ++ "/" ++ show cipher))
  (_, c5) <- u8' c4

  -- A COUNT IS BOUNDED BY WHAT IS LEFT. Each record carries at least a
  -- few bytes, so a file claiming four billion of them is damaged; the
  -- loop would find that out one truncation at a time.
  let bounded cur count =
        when
          (B.length raw - cursorat cur < count)
          (() <$ mvfail "the vault file is truncated")

  (keycount, c6) <- u32' c5
  bounded c6 keycount
  (keys, c7) <- readmany keycount readkey c6

  (entrycount, c8) <- u32' c7
  bounded c8 entrycount
  (entries, c9) <- readmany entrycount readentry c8

  when (cursorat c9 /= B.length raw) (() <$ mvfail "the vault file has trailing bytes")

  pure (VaultFile keys entries)
  where
    readmany 0 _ cur = pure ([], cur)
    readmany count body cur = do
      (one, after) <- body cur
      (rest, next) <- readmany (count - 1) body after
      pure (one : rest, next)

    readkey cur = do
      (held, c1) <- small' cur
      (salt, c2) <- small' c1
      (iters, c3) <- u32' c2
      (ring, c4) <- sealed' c3
      (meta, c5) <- sealed' c4
      pure (KeyRecord (textof held) salt iters ring meta, c5)

    readentry cur = do
      (held, c1) <- small' cur
      (name, c2) <- sealed' c1
      (value, c3) <- sealed' c2
      pure (EntryRecord held name value, c3)

putu32 :: Int -> B.ByteString
putu32 value =
  B.pack
    (map
       (\at -> fromIntegral ((value `shiftR` at) .&. 0xff) :: Word8)
       [24, 16, 8, 0])

putsmall :: B.ByteString -> B.ByteString
putsmall value = B.cons (fromIntegral (B.length value .&. 0xff)) value

putlarge :: B.ByteString -> B.ByteString
putlarge value = B.append (putu32 (B.length value)) value

putsealed :: Sealed -> B.ByteString
putsealed box = B.append (putsmall (sealediv box)) (putlarge (sealedblob box))

writefile :: VaultFile -> B.ByteString
writefile file =
  B.concat
    ( [magic, B.pack (map fromIntegral [format, kdfpbkdf2, cipheraesgcm, 0])]
        ++ [putu32 (length (filekeys file))]
        ++ concatMap
          (\r ->
             [ putsmall (bytesof (recid r)),
               putsmall (recsalt r),
               putu32 (reciters r),
               putsealed (recring r),
               putsealed (recmeta r)
             ])
          (filekeys file)
        ++ [putu32 (length entries)]
        ++ concatMap
          (\r -> [putsmall (entid r), putsealed (entname r), putsealed (entvalue r)])
          entries
    )
  where
    -- SORTED BY ID, which is a blinded value: the file therefore records
    -- nothing about the order secrets were written in.
    entries = sortOn entid (fileentries file)

-- ------------------------------------------------------- the file on disk

-- | Read as BINARY, byte for byte: a vault is full of NULs and of bytes
-- no encoding claims.
slurp :: String -> IO (Maybe B.ByteString)
slurp path = do
  got <- try (B.readFile path) :: IO (Either SomeException B.ByteString)
  pure (either (const Nothing) Just got)

-- | Owner-only, because a vault file is the whole store, and EXCLUSIVE
-- when asked: an exclusive create refuses an existing path and will not
-- follow a symlink to make one, which is what makes the temporary below
-- safe to name in a directory somebody else can write.
--
-- @open(2)@ through the C binding rather than @B.writeFile@, because the
-- standard library has no way to ask for either - and rather than the
-- @unix@ package's @openFd@, whose arity changed at unix-2.8. See
-- @sekreto_mv_open@ in plugins\/minivault.c.
spill :: String -> B.ByteString -> Bool -> IO ()
spill path raw exclusive = do
  fd <- withCString path (\cpath -> c_open cpath (if exclusive then 1 else 0))
  if 0 > fd
    then mvfail ("cannot write " ++ path)
    else do
      -- THROUGH A HANDLE, AND `B.hPut`. `fdWrite` in the unix package
      -- takes a String and encodes it with the process locale, which
      -- under the wiped environment the integration suite uses is C - and
      -- every byte above 0x7f in a sealed blob would come out as a
      -- question mark. `B.hPut` writes the bytes.
      handle <- fdToHandle (Fd fd)
      B.hPut handle raw
      hClose handle

hex :: B.ByteString -> String
hex = concatMap (\byte -> [digit (byte `shiftR` 4), digit (byte .&. 0x0f)]) . B.unpack
  where
    digit nibble = "0123456789abcdef" !! fromIntegral nibble

-- ------------------------------------------------------------- the vault

-- | What a key may do. @grants@ is empty for a master key, which reads
-- and writes every name there is.
--
-- An IMMUTABLE record over an immutable list, so the defect the review
-- round found in the canonical - a caller flipping its own @write@ bit on
-- the record it was handed - cannot be written at all.
data VaultKeyInfo = VaultKeyInfo
  { vaultinfokey :: String,
    vaultinfomaster :: Bool,
    vaultinfowrite :: Bool,
    vaultinfogrants :: [String]
  }
  deriving (Eq, Show)

-- | How a vault file is opened as one key.
data VaultOptions = VaultOptions
  { -- | The vault file.
    optfile :: String,
    -- | Which key to open with. Empty means @master@.
    optkey :: String,
    -- | What unwraps that key.
    optpassphrase :: String,
    -- | The PBKDF2 round count used when this handle CREATES a key.
    -- Reading uses what the file records for the key being opened.
    optiterations :: Int,
    -- | Make the file, with this key as its master, if it is not there.
    --
    -- Off by default. A missing vault is far more often a broken
    -- deployment than a new one, and a store that invents itself where a
    -- real vault was meant to be answers every read with a miss.
    optcreate :: Bool
  }

novaultoptions :: VaultOptions
novaultoptions =
  VaultOptions {optfile = "", optkey = "", optpassphrase = "", optiterations = 0, optcreate = False}

-- | What mints a restricted key.
data GrantSpec = GrantSpec
  { -- | The id the new key answers to.
    grantkey :: String,
    -- | What unwraps it. Nothing else does, and no master can recover it
    -- - a lost restricted passphrase is re-granted, never read back.
    grantpassphrase :: String,
    -- | The names the key may read. A name that does not exist yet is
    -- allowed and means what it says: the key reads it once a master
    -- writes it.
    grantnames :: [String],
    -- | Whether it may overwrite the values it can read.
    grantwrite :: Bool,
    -- | PBKDF2 rounds for this key, defaulting to the opening handle's.
    grantiterations :: Int
  }

nogrant :: GrantSpec
nogrant =
  GrantSpec
    {grantkey = "", grantpassphrase = "", grantnames = [], grantwrite = False, grantiterations = 0}

-- | What a handle remembers between calls: this key's ring, unwrapped.
data Opened = Opened
  { openedroot :: Maybe B.ByteString,
    openedgrants :: [(String, B.ByteString)],
    openedwrite :: Bool,
    -- THE SEALED RING THIS WAS DERIVED FROM, kept so that every later
    -- call can check the file still says the same thing. A handle that
    -- cached its keys and never looked again kept reading a vault after
    -- its key was revoked, which is the one thing @vaultrevoke@ promises.
    openedring :: Sealed
  }

-- | A handle on one vault file, opened as ONE key.
--
-- Every call answers as that key: 'vaultlist' shows the names it may
-- read, 'vaultget' answers for those and misses on the rest, and the
-- master-only ones refuse for any other key. Nothing is read or derived
-- until the first call that needs the file, so putting a vault in a chain
-- costs no key derivation until a secret is actually wanted.
data Vault = Vault
  { vfile :: String,
    vkey :: String,
    vpassphrase :: String,
    viterations :: Int,
    vcreate :: Bool,
    vopened :: IORef (Maybe Opened)
  }

vaultfile :: Vault -> String
vaultfile = vfile

vaultkeyid :: Vault -> String
vaultkeyid = vkey

-- | Forget the derived keys. The next call opens again.
vaultclose :: Vault -> IO ()
vaultclose v = writeIORef (vopened v) Nothing

-- A MASTER'S ring holds the root and no grants; a RESTRICTED key's holds
-- grants and no root, even when it was granted nothing. That asymmetry is
-- the format rather than a saving: a ring with a root reaches every name
-- there will ever be, so a grant list beside it would be a second answer
-- to the same question.
masterring :: B.ByteString -> String
masterring root =
  J.stringify
    (J.JObj
       [ ("v", J.JNum (fromIntegral format)),
         ("write", J.JBool True),
         ("root", J.JStr (b64 root))
       ])

grantring :: Bool -> [(String, B.ByteString)] -> String
grantring write grants =
  J.stringify
    (J.JObj
       [ ("v", J.JNum (fromIntegral format)),
         ("write", J.JBool write),
         ("grants", J.JObj (map (\(name, k) -> (name, J.JStr (b64 k))) grants))
       ])

metaof :: Bool -> Bool -> [String] -> String
metaof master write names =
  J.stringify
    (J.JObj
       [ ("v", J.JNum (fromIntegral format)),
         ("master", J.JBool master),
         ("write", J.JBool write),
         ("grants", J.JArr (map J.JStr names))
       ])

sealkey :: B.ByteString -> String -> String -> Int -> String -> String -> IO KeyRecord
sealkey root held passphrase iters ring meta = do
  salt <- randombytes saltlen
  wrapping <- kek passphrase salt iters
  sealedring <- seal wrapping (bytesof ring) (aadring ++ held)
  metakey <- mac root labelmeta
  sealedmeta <- seal metakey (bytesof meta) (aadmeta ++ held)
  pure (KeyRecord held salt iters sealedring sealedmeta)

-- | The one key record a new or rotated vault starts with: a master
-- holding the root, granted nothing because it needs nothing.
masterrecord :: B.ByteString -> String -> String -> Int -> IO KeyRecord
masterrecord root held passphrase iters =
  sealkey root held passphrase iters (masterring root) (metaof True True [])

newvault :: String -> String -> Int -> IO VaultFile
newvault held passphrase iters = do
  root <- randombytes keylen
  record <- masterrecord root held passphrase iters
  pure (VaultFile [record] [])

-- | Writes a vault file that is not there yet, and REFUSES one that is.
--
-- Straight to the target under an exclusive create rather than through a
-- temporary and a rename. A rename REPLACES its destination, so two
-- processes creating the same vault both succeeded and the second
-- discarded the first one's secrets; a stat beforehand only narrows that
-- window. There is nothing to lose by writing the target directly here,
-- because there is no file to damage: either this call creates it or it
-- fails.
putnew :: String -> VaultFile -> IO ()
putnew path made = do
  there <- slurp path
  got <- try (spill path (writefile made) True) :: IO (Either SomeException ())
  case got of
    Right () -> pure ()
    Left _ ->
      if maybe False (const True) there
        then mvfail ("vault file already exists: " ++ path)
        else mvfail ("cannot write " ++ path)

-- | Replaces the file rather than editing it in place. The rename is what
-- makes a concurrent reader see either the old file or the new one, so a
-- write interrupted halfway leaves a vault rather than wreckage.
--
-- THE TEMPORARY IS RANDOM AND EXCLUSIVE. @\<vault\>.\<pid\>.tmp@ is a name
-- anyone can predict, and an ordinary create FOLLOWS a symlink, so anyone
-- who could write the vault's directory could point that name at another
-- file and have the next save truncate it.
save :: Vault -> VaultFile -> IO ()
save v made = do
  suffix <- randombytes 8
  let temp = vfile v ++ "." ++ hex suffix ++ ".tmp"

  written <- try (spill temp (writefile made) True) :: IO (Either SomeException ())
  case written of
    Left _ -> mvfail ("cannot write " ++ vfile v)
    Right () -> do
      moved <- try (renameFile temp (vfile v)) :: IO (Either SomeException ())
      case moved of
        Right () -> pure ()
        Left _ -> do
          -- The vault is unchanged either way, and the write error is
          -- what the caller needs to be told about.
          _ <- try (removeFile temp) :: IO (Either SomeException ())
          mvfail ("cannot write " ++ vfile v)

bytesofvault :: Vault -> IO B.ByteString
bytesofvault v = do
  got <- slurp (vfile v)
  case got of
    Just raw -> pure raw
    Nothing ->
      -- A vault is configured deliberately, with a key. Its absence is a
      -- broken deployment and never "no secrets here": answering a miss
      -- would send the chain on to a weaker store, which is the failure
      -- mode this library most has to avoid. @create@ is the caller
      -- saying the opposite, in writing.
      if not (vcreate v)
        then mvfail ("no vault file: " ++ vfile v)
        else do
          made <- newvault (vkey v) (vpassphrase v) (viterations v)
          putnew (vfile v) made
          again <- slurp (vfile v)
          maybe (mvfail ("cannot read " ++ vfile v)) pure again

jsontrue :: Maybe J.Json -> String -> Bool
jsontrue held key = case J.dig held [key] of
  Just (J.JBool value) -> value
  _ -> False

-- | The file as this key sees it: parsed every call - it is different
-- bytes every time - while the unwrapped ring is kept, because stretching
-- a passphrase once per lookup is the cost that caching exists to avoid.
load :: Vault -> IO (VaultFile, Opened)
load v = do
  file <- readfile =<< bytesofvault v

  case keyrecordof file (vkey v) of
    Nothing -> do
      -- REVOKED, or never there. Either way this handle is finished, and
      -- dropping what it derived is what stops the next call answering
      -- from memory.
      vaultclose v
      mvfail ("no such key: " ++ vkey v)
    Just record -> do
      held <- readIORef (vopened v)

      -- The file still holds this key, and holds the SAME ring: a key
      -- revoked and re-granted under another passphrase is a different
      -- key wearing the id, and re-deriving is what refuses it.
      case held of
        Just open | openedring open == recring record -> pure (file, open)
        _ -> do
          vaultclose v

          wrapping <- kek (vpassphrase v) (recsalt record) (reciters record)
          plain <-
            unseal
              wrapping
              (recring record)
              (aadring ++ vkey v)
              ("wrong passphrase for key " ++ vkey v ++ ", or a damaged vault")

          ring <- case J.parse (textof plain) of
            Just held'@(J.JObj _) -> pure (Just held')
            _ -> mvfail ("unreadable key ring for " ++ vkey v)

          grants <- case J.dig ring ["grants"] of
            Just (J.JObj entries) ->
              mapM
                (\(name, value) -> case value of
                   J.JStr text -> (,) name <$> unb64 text "a granted key"
                   _ -> mvfail "missing a granted key")
                entries
            _ -> pure []

          root <- case J.dig ring ["root"] of
            Just (J.JStr text) -> Just <$> unb64 text "the root key"
            _ -> pure Nothing

          let open =
                Opened
                  { openedroot = root,
                    openedgrants = grants,
                    openedwrite = maybe (jsontrue ring "write") (const True) root,
                    openedring = recring record
                  }

          writeIORef (vopened v) (Just open)
          pure (file, open)

-- | The root key, or a refusal naming what needed it.
rootof :: Vault -> Opened -> String -> IO B.ByteString
rootof v open what =
  maybe
    (mvfail (what ++ " needs a master key, and " ++ vkey v ++ " is restricted"))
    pure
    (openedroot open)

-- | The key for one name, or nothing when this key cannot reach it.
keyfor :: Opened -> String -> IO (Maybe B.ByteString)
keyfor open name = case openedroot open of
  Just root -> Just <$> secretkey root name
  Nothing -> pure (lookup name (openedgrants open))

-- | Derive the key and read the file NOW rather than at first use.
vaultopen :: Vault -> IO VaultKeyInfo
vaultopen v = do
  (_, open) <- load v
  pure
    (VaultKeyInfo
       { vaultinfokey = vkey v,
         vaultinfomaster = maybe False (const True) (openedroot open),
         vaultinfowrite = openedwrite open,
         vaultinfogrants = sort (map fst (openedgrants open))
       })

-- | The names this key can read, sorted.
vaultlist :: Vault -> IO [String]
vaultlist v = do
  (file, open) <- load v

  names <- case openedroot open of
    Just root -> do
      namekey <- mac root labelnames
      mapM
        (\entry -> textof <$> unseal namekey (entname entry) aadname "a secret name is damaged")
        (fileentries file)
    Nothing ->
      -- A restricted key has no name key, so it reports the grants it can
      -- actually find: the vault never tells it what else is there.
      concat
        <$> mapM
          (\(name, k) -> do
             held <- entryid k
             pure [name | Just _ <- [entryrecordof file held]])
          (openedgrants open)

  pure (sort names)

-- | The value, or a MISS. A name the vault does not hold and a name this
-- key was not granted are both a miss.
vaultget :: Vault -> String -> IO (Maybe String)
vaultget v name = do
  _ <- forced (checkname name)
  (file, open) <- load v

  -- OUTSIDE THE GRANT IS A MISS, deliberately. The vault answers as the
  -- key that opened it, so a name this key cannot read is a name this
  -- store does not hold for this caller - the same answer a stranger's
  -- vault gives, and the one that makes a restricted key in front of a
  -- broader store a workable chain.
  found <- keyfor open name
  case found of
    Nothing -> pure Nothing
    Just k -> do
      held <- entryid k
      case entryrecordof file held of
        Nothing -> pure Nothing
        Just entry ->
          Just . textof
            <$> unseal
              k
              (entvalue entry)
              (aadsecret ++ name)
              ("the value of " ++ name ++ " is damaged")

vaulthas :: Vault -> String -> IO Bool
vaulthas v name = maybe False (const True) <$> vaultget v name

-- | Write a value. A master writes any name; a restricted key holding
-- @write@ overwrites the names it was granted, and creates none.
vaultset :: Vault -> String -> String -> IO ()
vaultset v name value = do
  _ <- forced (checkname name)
  (file, open) <- load v

  when (not (openedwrite open)) (() <$ mvfail ("key " ++ vkey v ++ " is read-only"))

  found <- keyfor open name
  case found of
    Nothing -> mvfail ("key " ++ vkey v ++ " was not granted " ++ name)
    Just k -> do
      box <- seal k (bytesof value) (aadsecret ++ name)
      held <- entryid k

      entries <- case entryrecordof file held of
        Just _ ->
          pure
            (map
               (\entry -> if held == entid entry then entry {entvalue = box} else entry)
               (fileentries file))
        Nothing -> do
          -- A NEW NAME NEEDS THE NAME KEY, which only a master holds. So
          -- a restricted key with @write@ updates what it was granted and
          -- cannot grow the vault, which is what "restricted" has to mean
          -- for the grant list to stay the whole story.
          root <- rootof v open ("creating the secret " ++ name)
          namekey <- mac root labelnames
          sealedname <- seal namekey (bytesof name) aadname
          pure (fileentries file ++ [EntryRecord held sealedname box])

      save v file {fileentries = entries}

-- | Drop a name. Master only.
vaultremove :: Vault -> String -> IO ()
vaultremove v name = do
  _ <- forced (checkname name)
  (file, open) <- load v
  root <- rootof v open "removing a secret"
  want <- entryid =<< secretkey root name

  case entryrecordof file want of
    Nothing -> mvfail ("no such secret: " ++ name)
    Just _ ->
      save v file {fileentries = filter ((want /=) . entid) (fileentries file)}

-- | Every key in the file, with what it may do. Master only.
vaultkeys :: Vault -> IO [VaultKeyInfo]
vaultkeys v = do
  (file, open) <- load v
  root <- rootof v open "listing the keys"
  metakey <- mac root labelmeta

  mapM
    (\record -> do
       -- A record written under a root key this one has replaced is still
       -- in the file and still opens with its own passphrase, so it is
       -- reported rather than hidden - with what it can do unknown.
       got <-
         try (unseal metakey (recmeta record) (aadmeta ++ recid record) "metadata")
           :: IO (Either SekretoError B.ByteString)
       case got of
         Left _ -> pure (VaultKeyInfo (recid record) False False [])
         Right plain -> case J.parse (textof plain) of
           Just noted@(J.JObj _) ->
             pure
               (VaultKeyInfo
                  (recid record)
                  (jsontrue (Just noted) "master")
                  (jsontrue (Just noted) "write")
                  (sort [name | Just (J.JArr items) <- [J.dig (Just noted) ["grants"]],
                                J.JStr name <- items]))
           _ -> mvfail ("unreadable metadata for key " ++ recid record))
    (filekeys file)

-- | Mint a restricted key. Master only.
vaultgrant :: Vault -> GrantSpec -> IO ()
vaultgrant v spec = do
  (file, open) <- load v
  root <- rootof v open "granting a key"

  _ <- checkid (grantkey spec) "a grant needs a key id"
  when (null (grantpassphrase spec)) (() <$ mvfail "a grant needs a passphrase")
  when
    (maybe False (const True) (keyrecordof file (grantkey spec)))
    (() <$ mvfail ("key already exists: " ++ grantkey spec))

  let names = sort (grantnames spec)
  mapM_ (forced . checkname) names

  grants <- mapM (\name -> (,) name <$> secretkey root name) names

  record <-
    sealkey
      root
      (grantkey spec)
      (grantpassphrase spec)
      (if 0 < grantiterations spec then grantiterations spec else viterations v)
      (grantring (grantwrite spec) grants)
      (metaof False (grantwrite spec) names)

  save v file {filekeys = filekeys file ++ [record]}

-- | Drop a key. Master only.
--
-- Anyone who already copied the file keeps whatever that key could read,
-- so revoking bars future reads of the LIVE file and 'vaultrotate' is
-- what takes a secret back.
vaultrevoke :: Vault -> String -> IO ()
vaultrevoke v held = do
  (file, open) <- load v
  _ <- rootof v open "revoking a key"

  when (held == vkey v) (() <$ mvfail ("a key cannot revoke itself: " ++ held))
  when
    (maybe True (const False) (keyrecordof file held))
    (() <$ mvfail ("no such key: " ++ held))

  save v file {filekeys = filter ((held /=) . recid) (filekeys file)}

-- | Take a new root key, re-encrypt every value under it, and DROP EVERY
-- OTHER KEY. Master only.
--
-- The other keys go because they must: their rings are sealed under
-- passphrases this process does not have, so there is no way to hand them
-- keys they can unwrap. Re-grant afterwards.
vaultrotate :: Vault -> IO ()
vaultrotate v = do
  (file, open) <- load v
  oldroot <- rootof v open "rotating the vault"

  let iters = maybe (viterations v) reciters (keyrecordof file (vkey v))

  -- Read everything out under the old root before anything changes: once
  -- the root is replaced the old derived keys are unreachable.
  oldnamekey <- mac oldroot labelnames
  held <-
    mapM
      (\entry -> do
         name <- textof <$> unseal oldnamekey (entname entry) aadname "a secret name is damaged"
         k <- secretkey oldroot name
         value <-
           textof
             <$> unseal
               k
               (entvalue entry)
               (aadsecret ++ name)
               ("the value of " ++ name ++ " is damaged")
         pure (name, value))
      (fileentries file)

  root <- randombytes keylen
  namekey <- mac root labelnames

  entries <-
    mapM
      (\(name, value) -> do
         k <- secretkey root name
         held' <- entryid k
         sealedname <- seal namekey (bytesof name) aadname
         box <- seal k (bytesof value) (aadsecret ++ name)
         pure (EntryRecord held' sealedname box))
      held

  record <- masterrecord root (vkey v) (vpassphrase v) iters

  -- SAVE FIRST, adopt second. A handle holding the new root over a file
  -- that still holds the old one reads nothing and says the vault is
  -- damaged, which is the wrong story about a failed write.
  save v (VaultFile [record] entries)

  -- Dropped rather than replaced: the next call re-derives from the file
  -- this one just wrote, which is the same rule every other change
  -- follows.
  vaultclose v

-- --------------------------------------------------- opening and creating

-- | Open a vault file as one key.
--
-- The handle is LAZY. Nothing is read, and no passphrase is stretched,
-- until a call needs the file - so a chain of ten providers costs ten
-- records rather than ten PBKDF2 runs.
openvault :: VaultOptions -> IO Vault
openvault options = do
  when (null (optfile options)) (() <$ mvfail "a vault needs a file")
  when (null (optpassphrase options)) (() <$ mvfail "a vault needs a passphrase")

  held <- checkid (if null (optkey options) then masterkeyid else optkey options)
            "a vault needs a key id"
  opened <- newIORef Nothing

  pure
    (Vault
       { vfile = optfile options,
         vkey = held,
         vpassphrase = optpassphrase options,
         viterations = if 0 < optiterations options then optiterations options else iterations,
         vcreate = optcreate options,
         vopened = opened
       })

-- | Make a vault file and answer a handle on its master key.
--
-- Refuses a file that is already there: a vault is created once, and
-- overwriting one discards every secret in it along with every key that
-- could read them.
createvault :: VaultOptions -> IO Vault
createvault options = do
  v <- openvault options
  made <- newvault (vkey v) (vpassphrase v) (viterations v)
  putnew (vfile v) made
  pure v

-- ---------------------------------------------------------- the provider

-- | The vaults this module has built.
--
-- voxgig/plugin's values are numbers and strings, not handles, so a
-- definition exports the SLOT of what it made and 'vaultof' looks it up -
-- exactly as @providerplugin@ exports one for the provider.
--
-- The definition's @close@ drops the slot, so a chain that was torn down
-- and a chain whose construction was refused both hand their vaults back
-- and nothing accumulates. 'heldvaults' reads the table, which is what
-- makes that checkable rather than merely intended.
{-# NOINLINE vaultslots #-}
vaultslots :: IORef (Integer, [(Integer, Vault)])
vaultslots = unsafePerformIO (newIORef (1, []))

holdvault :: Vault -> IO Integer
holdvault v = atomicModifyIORef' vaultslots step
  where
    step (next, held) = ((next + 1, (next, v) : held), next)

-- | The vault a slot names, LEFT in the table: a chain reads its vault as
-- often as an application likes.
vaultat :: Value -> IO (Maybe Vault)
vaultat exported
  | not (isNum exported) = pure Nothing
  | otherwise = lookup (round (asNum exported) :: Integer) . snd <$> readIORef vaultslots

dropvault :: Value -> IO ()
dropvault exported
  | not (isNum exported) = pure ()
  | otherwise = atomicModifyIORef' vaultslots step
  where
    slot = round (asNum exported) :: Integer
    step (next, held) = ((next, filter ((slot /=) . fst) held), ())

-- | How many vaults the table is holding. A chain that has been closed
-- must leave this where it found it.
heldvaults :: IO Int
heldvaults = length . snd <$> readIORef vaultslots

-- | Reads a vault as one store in a chain.
--
-- The provider is the READ half and nothing more: a chain resolves
-- secrets, and writing one is a deliberate act with an API of its own.
-- That API is the same handle, reached with 'vaultof' off a chain or
-- built directly with 'openvault'.
minivaultprovider :: Vault -> Provider
minivaultprovider v =
  Provider {lookupsecret = vaultget v, describe = "minivault:" ++ vaultfile v}

-- | The @minivault@ provider kind, as a voxgig/plugin definition.
--
-- Written out rather than built by @providerplugin@, because this
-- definition publishes TWO exports: @provider@, the read half every kind
-- publishes, and @vault@, the programmatic API. voxgig/plugin's exports
-- are how a definition offers an application more than the host's own
-- vocabulary, and a store that can only be read is half a vault.
--
-- The @sekreto_error@ wrapping is what @providerplugin@ would have done:
-- plugin wraps a code-less error raised in @define@ as
-- @plugin_define_failed@ and keeps one that already carries a code, so a
-- refusal of this provider's own configuration travels under
-- @sekreto_error@ and comes back out of the host as itself.
minivault :: Definition
minivault =
  Definition
    { dName = "minivault",
      dShape = VNull,
      dDefine = Just define,
      dActivate = Nothing,
      dDeactivate = Nothing,
      dClose = Just release,
      dReconfigure = Nothing
    }
  where
    define inst = do
      options <- readIORef (iOptions inst)
      let spec = specof options

      -- Configuration is refused HERE, so a mistyped chain fails at
      -- construction. Reaching the file is not configuration: the handle
      -- is lazy, and nothing is read or stretched until a lookup.
      built <-
        try
          (openvault
             VaultOptions
               { optfile = specfile spec,
                 optkey = specvaultkey spec,
                 optpassphrase = specpassphrase spec,
                 optiterations = maybe 0 id (speciterations spec),
                 optcreate = speccreate spec
               })

      case built of
        Right v -> do
          slot <- holdprovider (minivaultprovider v)
          instExport inst providerexport (VNum (fromIntegral slot))
          vslot <- holdvault v
          instExport inst vaultexport (VNum (fromIntegral vslot))
        Left (SekretoError message) ->
          raise errorcode message (details2 "ref" (VStr (iRef inst)) "cause" (VStr message))

    release inst = do
      exported <- readIORef (iExports inst)
      _ <- takeprovider (vget exported providerexport)
      dropvault (vget exported vaultexport)

-- | The vault behind a store in a chain, as its programmatic API.
--
-- The host is the voxgig/plugin host the chain is made of, and a
-- definition's exports are readable off it by ref. This is the one call
-- that turns a store into an API, and it lives here rather than in the
-- core because the core knows no plugin.
--
-- With no store named, the unqualified alias answers: one vault in the
-- chain resolves whatever it is called, and two refuse rather than
-- picking one.
vaultof :: Host -> String -> IO Vault
vaultof h store
  | null store = held "minivault" "no minivault store in this chain"
  | otherwise = do
      -- A NAMED STORE MUST EXIST, and the alias must not stand in for it.
      -- @hostExports@ falls back to the alias when the exact ref misses,
      -- so asking for @minivault@ in a chain whose only vault is named
      -- @app@ used to hand back the @app@ vault - and then write to it.
      -- Naming a store that is not there refuses, which is the rule the
      -- whole library follows: @tryget@ already means "may not have it",
      -- so it cannot also mean "may not exist".
      let ref = if "minivault" == store then "minivault" else "minivault$" ++ store
      live <- hostInstance h ref
      case live of
        Nothing -> mvfail missing
        Just _ -> held ref missing
  where
    missing = "no minivault store named " ++ store ++ " in this chain"

    held ref why = do
      exported <- hostExports h (ref ++ "/" ++ vaultexport)
      case exported of
        Nothing -> mvfail why
        Just value -> do
          found <- vaultat value
          maybe (mvfail why) pure found
