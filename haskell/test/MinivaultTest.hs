-- RUN: make vaulttest
-- RUN-SOME: ./build/sekreto-minivault restricted
--
-- The mini vault, from both sides: the store a chain reads, and the
-- programmatic API a plugin definition can publish beside it.
--
-- The vault is not in spec/sekreto.json and cannot be until every port
-- ships the kind. The spec runs against all twenty-three of them, so an
-- entry naming `minivault` would fail the ports that have no such
-- provider. What the shared corpus would have carried is here instead,
-- plus the one thing it could not carry either way: a file written by
-- this port and read by another, pinned by the vaults in test/fixture.
--
-- Its own binary, like test/PluginTest.hs and for the same reason: it
-- needs no omni, so a checkout with none beside it can still run this.
--
-- A port of typescript/test/minivault.test.ts.

{-# LANGUAGE ScopedTypeVariables #-}

module Main (main) where

import Control.Exception (Exception, SomeException, displayException, throwIO, try)
import Control.Monad (forM_, when)
import qualified Data.ByteString as B
import qualified Data.ByteString.Char8 as C
import Data.Bits (xor)
import Data.IORef (IORef, modifyIORef', newIORef, readIORef, writeIORef)
import Data.List (isInfixOf, sort)
import Minivault
import Provider (SekretoError (..))
import Providers (ProviderSpec (..), emptyspec)
import Sekreto (Options (..), Sekreto, close, emptyoptions, get, host, sekreto, sources, stores)
import System.Directory (listDirectory)
import System.Environment (getArgs)
import System.Exit (exitFailure, exitSuccess)
import System.FilePath ((</>))
import System.IO (hFlush, hPutStrLn, stderr, stdout)
import System.IO.Unsafe (unsafePerformIO)
import System.Posix.Temp (mkdtemp)

master :: String
master = "master-passphrase"

-- | The rounds every case here uses. The library default is 210000, which
-- is the point of PBKDF2 and the wrong thing to pay per assertion.
rounds :: Int
rounds = 1000

-- ------------------------------------------------------------ assertions

newtype Failed = Failed String

instance Show Failed where
  show (Failed message) = message

instance Exception Failed

same :: (Eq a, Show a) => String -> a -> a -> IO ()
same what wanted got =
  when (wanted /= got) $
    throwIO (Failed (what ++ "\n  wanted " ++ show wanted ++ "\n  got    " ++ show got))

truth :: String -> Bool -> IO ()
truth what got = when (not got) (throwIO (Failed what))

holds :: String -> String -> String -> IO ()
holds what wanted got =
  when (not (wanted `isInfixOf` got)) $
    throwIO (Failed (what ++ "\n  wanted to contain " ++ show wanted ++ "\n  got " ++ show got))

-- | The message a call refused with, AS A 'SekretoError'. Catching that
-- type and no other is the assertion.
refusal :: String -> IO a -> IO String
refusal what body = do
  outcome <- try body
  case outcome of
    Left (SekretoError message) -> pure message
    Right _ -> throwIO (Failed (what ++ ": nothing was refused"))

-- ------------------------------------------------- the vault under test

-- The work directory and a counter, as file-scope refs: every case below
-- is a nullary IO action, and `main` has no way to hand one an argument.
{-# NOINLINE work #-}
work :: IORef String
work = unsafePerformIO (newIORef "")

{-# NOINLINE counter #-}
counter :: IORef Int
counter = unsafePerformIO (newIORef 0)

vaultpath :: IO String
vaultpath = do
  modifyIORef' counter (+ 1)
  at <- readIORef counter
  dir <- readIORef work
  pure (dir </> ("vault" ++ show at ++ ".skmv"))

vaultopts :: String -> String -> String -> VaultOptions
vaultopts file key passphrase =
  novaultoptions {optfile = file, optkey = key, optpassphrase = passphrase, optiterations = rounds}

fresh :: IO Vault
fresh = do
  path <- vaultpath
  createvault (vaultopts path "" master)

openas :: String -> String -> String -> IO Vault
openas file key passphrase = openvault (vaultopts file key passphrase)

grantof :: String -> String -> [String] -> Bool -> GrantSpec
grantof key passphrase names write =
  nogrant
    { grantkey = key,
      grantpassphrase = passphrase,
      grantnames = names,
      grantwrite = write,
      grantiterations = rounds
    }

-- | Where the committed vaults live, found by walking up.
fixturedir :: IO String
fixturedir = walk "." (0 :: Int)
  where
    walk dir step
      | 8 < step = throwIO (Failed "the fixture directory was not found")
      | otherwise = do
          found <- try (B.readFile (dir </> "test/fixture/minivault.skmv"))
          case found of
            Right _ -> pure (dir </> "test/fixture")
            Left (_ :: SomeException) -> walk (dir </> "..") (step + 1)

-- | EVERY committed vault, read off disk rather than listed here. A
-- hard-coded list is one more place to edit when a port lands, and the
-- edit that gets forgotten is the one that makes this suite stop checking
-- the port that just arrived.
fixtures :: IO [String]
fixtures = do
  dir <- fixturedir
  sort . filter (".skmv" `isSuffix`) <$> listDirectory dir
  where
    isSuffix want held = want == drop (length held - length want) held

-- | A committed vault, copied so that a case which writes cannot edit the
-- bytes the format contract is made of.
fixture :: String -> IO String
fixture name = do
  dir <- fixturedir
  raw <- B.readFile (dir </> name)
  mine <- vaultpath
  B.writeFile mine raw
  pure mine

vaultspec :: String -> String -> String -> ProviderSpec
vaultspec file key passphrase =
  emptyspec {speckind = "minivault", specfile = file, specvaultkey = key, specpassphrase = passphrase}

memoryspec :: String -> String -> ProviderSpec
memoryspec key value = emptyspec {speckind = "memory", specvalues = [(key, value)]}

thechain :: [ProviderSpec] -> IO Sekreto
thechain providers =
  sekreto emptyoptions {optplugins = [minivault], optproviders = providers, optcache = False}

-- ------------------------------------------------------------- the file

anewvaultholdsnothing :: IO ()
anewvaultholdsnothing = do
  v <- fresh
  same "list" [] =<< vaultlist v
  same "key" "master" (vaultkeyid v)

  info <- vaultopen v
  truth "the master key is not master" (vaultinfomaster info)
  truth "the master key may not write" (vaultinfowrite info)
  same "grants" [] (vaultinfogrants info)

awrittensecretcomesback :: IO ()
awrittensecretcomesback = do
  v <- fresh
  vaultset v "api.token" "tok01"
  vaultset v "db.pass" "hunter2"

  same "get" (Just "tok01") =<< vaultget v "api.token"
  same "list" ["api.token", "db.pass"] =<< vaultlist v
  same "has" True =<< vaulthas v "api.token"
  same "has an unknown name" False =<< vaulthas v "nope"
  same "an unknown name answered" Nothing =<< vaultget v "nope"

  -- A SECOND HANDLE on the same file, so the assertion is about the bytes
  -- rather than about what this handle happens to remember.
  again <- openas (vaultfile v) "" master
  same "a new handle" (Just "tok01") =<< vaultget again "api.token"

thefileisbinary :: IO ()
thefileisbinary = do
  v <- fresh
  vaultset v "api.token" "tok01"

  raw <- B.readFile (vaultfile v)
  same "the magic" (C.pack "SKMV") (B.take 4 raw)

  -- NOT ONE OF THESE IS IN THE FILE. The key id is plaintext by design;
  -- the secret's name and its value are not, and neither is the
  -- passphrase that unwrapped them.
  forM_ ["api.token", "tok01", master] $ \secret ->
    truth (secret ++ " is in the file") (not (C.pack secret `B.isInfixOf` raw))

  truth "the key id is not in the file" (C.pack "master" `B.isInfixOf` raw)

rewritinganamereplacesit :: IO ()
rewritinganamereplacesit = do
  v <- fresh
  vaultset v "api.token" "first"
  vaultset v "api.token" "second"

  same "get" (Just "second") =<< vaultget v "api.token"
  same "one entry" ["api.token"] =<< vaultlist v

removedropsaname :: IO ()
removedropsaname = do
  v <- fresh
  vaultset v "api.token" "tok01"
  vaultset v "db.pass" "hunter2"
  vaultremove v "api.token"

  same "list" ["db.pass"] =<< vaultlist v
  same "a removed name answered" Nothing =<< vaultget v "api.token"
  holds "remove again" "no such secret: api.token"
    =<< refusal "remove again" (vaultremove v "api.token")

abadnameisrefused :: IO ()
abadnameisrefused = do
  v <- fresh
  holds "set" "invalid name" =<< refusal "set" (vaultset v "API.TOKEN" "x")
  holds "get" "invalid name" =<< refusal "get" (vaultget v "api..token")
  holds "remove" "invalid name" =<< refusal "remove" (vaultremove v "")

-- ------------------------------------------------------------- the keys

arestrictedkeyreadsitsgrants :: IO ()
arestrictedkeyreadsitsgrants = do
  v <- fresh
  vaultset v "api.token" "tok01"
  vaultset v "db.pass" "hunter2"
  vaultgrant v (grantof "ci" "ci-passphrase" ["api.token"] False)

  ci <- openas (vaultfile v) "ci" "ci-passphrase"
  same "granted" (Just "tok01") =<< vaultget ci "api.token"

  -- THE RESTRICTION IS THE CRYPTOGRAPHY. `db.pass` is in the file and
  -- this key cannot derive its key, so the answer is the one a stranger
  -- gets: a miss.
  same "an ungranted name answered" Nothing =<< vaultget ci "db.pass"
  same "list" ["api.token"] =<< vaultlist ci

  info <- vaultopen ci
  truth "a restricted key reports master" (not (vaultinfomaster info))
  truth "a read-only key reports write" (not (vaultinfowrite info))
  same "grants" ["api.token"] (vaultinfogrants info)

areadonlykeyrefusestowrite :: IO ()
areadonlykeyrefusestowrite = do
  v <- fresh
  vaultset v "api.token" "tok01"
  vaultgrant v (grantof "reader" "reader-passphrase" ["api.token"] False)
  vaultgrant v (grantof "writer" "writer-passphrase" ["api.token"] True)

  reader <- openas (vaultfile v) "reader" "reader-passphrase"
  holds "read-only" "key reader is read-only"
    =<< refusal "read-only" (vaultset reader "api.token" "x")

  writer <- openas (vaultfile v) "writer" "writer-passphrase"
  vaultset writer "api.token" "rewritten"

  same "the master sees it" (Just "rewritten") =<< vaultget v "api.token"

arestrictedkeycannotwriteanungrantedname :: IO ()
arestrictedkeycannotwriteanungrantedname = do
  v <- fresh
  vaultset v "api.token" "tok01"
  vaultgrant v (grantof "ci" "ci-passphrase" ["api.token"] True)

  ci <- openas (vaultfile v) "ci" "ci-passphrase"
  holds "ungranted" "key ci was not granted db.pass"
    =<< refusal "ungranted" (vaultset ci "db.pass" "x")

agrantednamethatdoesnotexistyet :: IO ()
agrantednamethatdoesnotexistyet = do
  v <- fresh

  -- Granted BEFORE the name exists, which is the point: a deploy key is
  -- minted from a list of what a service will need.
  vaultgrant v (grantof "ci" "ci-passphrase" ["api.token"] False)

  ci <- openas (vaultfile v) "ci" "ci-passphrase"
  same "nothing yet" [] =<< vaultlist ci
  same "a name that does not exist answered" Nothing =<< vaultget ci "api.token"

  vaultset v "api.token" "tok01"

  same "once written" (Just "tok01") =<< vaultget ci "api.token"
  same "list" ["api.token"] =<< vaultlist ci

themasterlistseverykey :: IO ()
themasterlistseverykey = do
  v <- fresh
  vaultgrant v (grantof "ci" "ci-passphrase" ["db.pass", "api.token"] True)

  keys <- vaultkeys v
  same "key count" 2 (length keys)

  let first' = head keys
  same "the master" "master" (vaultinfokey first')
  truth "the master is not master" (vaultinfomaster first')
  same "a master is granted nothing" [] (vaultinfogrants first')

  let second = keys !! 1
  same "the restricted key" "ci" (vaultinfokey second)
  truth "ci reports master" (not (vaultinfomaster second))
  truth "ci may not write" (vaultinfowrite second)
  -- SORTED, so the record reads the same however the grant was spelled.
  same "grants" ["api.token", "db.pass"] (vaultinfogrants second)

themasteronlymethodsrefusearestrictedkey :: IO ()
themasteronlymethodsrefusearestrictedkey = do
  v <- fresh
  vaultset v "api.token" "tok01"
  vaultgrant v (grantof "ci" "ci-passphrase" ["api.token"] True)

  ci <- openas (vaultfile v) "ci" "ci-passphrase"

  holds "keys" "listing the keys needs a master key" =<< refusal "keys" (vaultkeys ci)
  holds "grant" "granting a key needs a master key"
    =<< refusal "grant" (vaultgrant ci (grantof "x" "y" [] False))
  holds "revoke" "revoking a key needs a master key" =<< refusal "revoke" (vaultrevoke ci "master")
  holds "rotate" "rotating the vault needs a master key" =<< refusal "rotate" (vaultrotate ci)
  holds "remove" "removing a secret needs a master key"
    =<< refusal "remove" (vaultremove ci "api.token")

arepeatedkeyidisrefused :: IO ()
arepeatedkeyidisrefused = do
  v <- fresh
  vaultgrant v (grantof "ci" "p" [] False)

  holds "repeated" "key already exists: ci"
    =<< refusal "repeated" (vaultgrant v (grantof "ci" "q" [] False))
  holds "no id" "a grant needs a key id"
    =<< refusal "no id" (vaultgrant v (grantof "" "p" [] False))
  holds "no passphrase" "a grant needs a passphrase"
    =<< refusal "no passphrase" (vaultgrant v (grantof "x" "" [] False))

revokedropsakey :: IO ()
revokedropsakey = do
  v <- fresh
  vaultset v "api.token" "tok01"
  vaultgrant v (grantof "ci" "ci-passphrase" ["api.token"] False)
  vaultrevoke v "ci"

  ci <- openas (vaultfile v) "ci" "ci-passphrase"
  holds "revoked" "no such key: ci" =<< refusal "revoked" (vaultget ci "api.token")
  holds "revoke again" "no such key: ci" =<< refusal "revoke again" (vaultrevoke v "ci")
  holds "itself" "a key cannot revoke itself" =<< refusal "itself" (vaultrevoke v "master")

  -- THE SECRET IS UNTOUCHED: revoking bars a key, not a value.
  same "the secret stays" (Just "tok01") =<< vaultget v "api.token"

rotatekeepsthesecrets :: IO ()
rotatekeepsthesecrets = do
  v <- fresh
  vaultset v "api.token" "tok01"
  vaultset v "db.pass" "hunter2"
  vaultgrant v (grantof "ci" "ci-passphrase" ["api.token"] False)

  vaultrotate v

  same "api.token survives" (Just "tok01") =<< vaultget v "api.token"
  same "db.pass survives" (Just "hunter2") =<< vaultget v "db.pass"
  same "list" ["api.token", "db.pass"] =<< vaultlist v

  keys <- vaultkeys v
  same "key count after rotate" 1 (length keys)
  same "the only key" "master" (vaultinfokey (head keys))

  -- EVERY OTHER KEY IS GONE, which is what rotation has to mean: their
  -- rings were sealed under passphrases this process does not have.
  ci <- openas (vaultfile v) "ci" "ci-passphrase"
  holds "ci is gone" "no such key: ci" =<< refusal "ci is gone" (vaultget ci "api.token")

-- --------------------------------------------------------- the refusals

awrongpassphraseandamissingfile :: IO ()
awrongpassphraseandamissingfile = do
  v <- fresh
  vaultset v "api.token" "tok01"

  wrong <- openas (vaultfile v) "" "not-the-passphrase"
  holds "wrong passphrase" "wrong passphrase for key master, or a damaged vault"
    =<< refusal "wrong passphrase" (vaultget wrong "api.token")

  unknown <- openas (vaultfile v) "nope" master
  holds "unknown key" "no such key: nope" =<< refusal "unknown key" (vaultget unknown "api.token")

  dir <- readIORef work
  missing <- openas (dir </> "not-there.skmv") "" master
  holds "missing file" "no vault file" =<< refusal "missing file" (vaultget missing "api.token")

adamagedfileisrefused :: IO ()
adamagedfileisrefused = do
  v <- fresh
  vaultset v "api.token" "tok01"
  raw <- B.readFile (vaultfile v)

  let refuses what want made = do
        where' <- vaultpath
        B.writeFile where' made
        held <- openas where' "" master
        holds what want =<< refusal what (vaultget held "api.token")

  -- Not a vault at all.
  refuses "not a vault" "not a vault file" (C.pack "nonsense")
  -- Cut off part way through.
  refuses "truncated" "truncated" (B.take (B.length raw - 20) raw)
  -- One byte of ciphertext flipped, which the GCM tag catches.
  refuses
    "flipped"
    "damaged"
    (B.snoc (B.init raw) (B.last raw `xor` 0xff))
  -- Trailing bytes, which a reader that stopped at the last record would
  -- have accepted.
  refuses "trailing" "trailing bytes" (B.append raw (C.pack "junk"))

creatingoveranexistingvaultisrefused :: IO ()
creatingoveranexistingvaultisrefused = do
  v <- fresh
  holds "create over" "vault file already exists"
    =<< refusal "create over" (createvault (vaultopts (vaultfile v) "" master))

avaultneedsafileandapassphrase :: IO ()
avaultneedsafileandapassphrase = do
  holds "no file" "a vault needs a file" =<< refusal "no file" (openvault (vaultopts "" "" "p"))
  holds "no passphrase" "a vault needs a passphrase"
    =<< refusal "no passphrase" (openvault (vaultopts "v.skmv" "" ""))

-- | An EMPTY key is no key, so it means `master`. It is not a contrived
-- case: the CLI reads SEKRETO_VAULT_KEY, and an unset shell variable
-- expands to the empty string rather than to nothing at all.
anemptykeymeansthemasterkey :: IO ()
anemptykeymeansthemasterkey = do
  v <- fresh
  vaultset v "api.token" "tok01"

  opened <- openas (vaultfile v) "" master
  same "api.token" (Just "tok01") =<< vaultget opened "api.token"
  info <- vaultopen opened
  same "key" "master" (vaultinfokey info)

createmakesthefileonlywhenasked :: IO ()
createmakesthefileonlywhenasked = do
  where' <- vaultpath

  off <- openas where' "" master
  holds "create off" "no vault file" =<< refusal "create off" (vaultget off "api.token")

  on <- openvault (vaultopts where' "" master) {optcreate = True}
  same "a new vault answered" Nothing =<< vaultget on "api.token"
  vaultset on "api.token" "tok01"
  same "written" (Just "tok01") =<< vaultget on "api.token"

  -- The file is there now, so the handle that refused reads it.
  again <- openas where' "" master
  same "the same file" (Just "tok01") =<< vaultget again "api.token"

akeyidlongerthantheformatallows :: IO ()
akeyidlongerthantheformatallows = do
  v <- fresh
  let big = replicate 300 'k'

  holds "grant" "key id is longer than 255 bytes"
    =<< refusal "grant" (vaultgrant v (grantof big "p" [] False))
  holds "open" "key id is longer than 255 bytes"
    =<< refusal "open" (openvault (vaultopts (vaultfile v) big "p"))

  -- AND THE VAULT IS UNHARMED: the refusal came before the write, so a
  -- 300-character id did not shift every field after it.
  keys <- vaultkeys v
  same "key count" 1 (length keys)

theinfoacallergetscannotchangewhatthekeymaydo :: IO ()
theinfoacallergetscannotchangewhatthekeymaydo = do
  v <- fresh
  vaultset v "api.token" "tok01"
  vaultgrant v (grantof "reader" "reader-passphrase" ["api.token"] False)

  reader <- openas (vaultfile v) "reader" "reader-passphrase"
  info <- vaultopen reader
  truth "the reader key may write" (not (vaultinfowrite info))

  -- NOTHING TO FLIP: the record is immutable, so the defect the review
  -- round found in the canonical - a caller flipping its own `write` bit
  -- - cannot be written. Record update syntax makes a NEW value, and the
  -- vault reads its own.
  let copied = info {vaultinfowrite = True}
  truth "the copy did not take the change" (vaultinfowrite copied)

  holds "still refused" "key reader is read-only"
    =<< refusal "still refused" (vaultset reader "api.token" "x")

arevokedkeystopsreading :: IO ()
arevokedkeystopsreading = do
  v <- fresh
  vaultset v "api.token" "tok01"
  vaultgrant v (grantof "ci" "ci-passphrase" ["api.token"] False)

  -- OPEN AND READING FIRST, so the handle holds its derived keys.
  ci <- openas (vaultfile v) "ci" "ci-passphrase"
  same "before" (Just "tok01") =<< vaultget ci "api.token"

  vaultrevoke v "ci"

  -- The live file no longer holds the key, and a handle that answered
  -- from memory here would make `vaultrevoke` a suggestion.
  holds "after" "no such key: ci" =<< refusal "after" (vaultget ci "api.token")

aregrantedkeyid :: IO ()
aregrantedkeyid = do
  v <- fresh
  vaultset v "api.token" "tok01"
  vaultgrant v (grantof "ci" "first-passphrase" ["api.token"] False)

  ci <- openas (vaultfile v) "ci" "first-passphrase"
  same "before" (Just "tok01") =<< vaultget ci "api.token"

  vaultrevoke v "ci"
  vaultgrant v (grantof "ci" "second-passphrase" ["api.token"] False)

  -- SAME ID, DIFFERENT KEY. The handle re-derives because the sealed ring
  -- changed, and the old passphrase does not unwrap the new one.
  holds "the old passphrase" "wrong passphrase for key ci, or a damaged vault"
    =<< refusal "the old passphrase" (vaultget ci "api.token")

  second <- openas (vaultfile v) "ci" "second-passphrase"
  same "the new passphrase" (Just "tok01") =<< vaultget second "api.token"

closeforgetsthederivedkeys :: IO ()
closeforgetsthederivedkeys = do
  v <- fresh
  vaultset v "api.token" "tok01"
  same "before" (Just "tok01") =<< vaultget v "api.token"

  vaultclose v

  same "after" (Just "tok01") =<< vaultget v "api.token"

-- -------------------------------------------------- the committed files

-- | Every port's vault holds the same keys and the same secrets, so the
-- assertions do not vary with which file this is.
readsthefixture :: String -> IO ()
readsthefixture name = do
  file <- fixture name
  owner <- openas file "" "fixture-master"

  same "list" ["api.token", "db.pass", "deep.nested.name"] =<< vaultlist owner
  same "api.token" (Just "fixture-token") =<< vaultget owner "api.token"
  same "db.pass" (Just "fixture-pass") =<< vaultget owner "db.pass"
  same "deep.nested.name" (Just "fixture-deep") =<< vaultget owner "deep.nested.name"

  keys <- vaultkeys owner
  same "keys" ["master", "reader", "writer"] (sort (map vaultinfokey keys))

  reader <- openas file "reader" "fixture-reader"
  same "reader list" ["api.token"] =<< vaultlist reader
  same "reader reads" (Just "fixture-token") =<< vaultget reader "api.token"
  same "the reader key read db.pass" Nothing =<< vaultget reader "db.pass"
  holds "reader writes" "read-only" =<< refusal "reader writes" (vaultset reader "api.token" "x")

  writer <- openas file "writer" "fixture-writer"
  same "writer list" ["db.pass"] =<< vaultlist writer
  same "writer reads" (Just "fixture-pass") =<< vaultget writer "db.pass"

  -- The copy is this case's own, so writing it proves the round trip
  -- without touching the committed bytes.
  vaultset writer "db.pass" "rewritten"
  same "the master sees it" (Just "rewritten") =<< vaultget owner "db.pass"

-- ------------------------------------------------------------ the chain

avaultisonestoreinachain :: IO ()
avaultisonestoreinachain = do
  v <- fresh
  vaultset v "api.token" "from the vault"

  secrets <- thechain [vaultspec (vaultfile v) "" master, memoryspec "DB_PASS" "from memory"]

  same "stores" ["minivault", "memory"] =<< stores secrets
  same "sources" ["minivault:" ++ vaultfile v, "memory"] =<< sources secrets
  same "the vault" "from the vault" =<< get secrets "api.token"
  same "memory" "from memory" =<< get secrets "db.pass"

arestrictedkeyinachainfallsthrough :: IO ()
arestrictedkeyinachainfallsthrough = do
  v <- fresh
  vaultset v "api.token" "from the vault"
  vaultset v "db.pass" "also in the vault"
  vaultgrant v (grantof "ci" "ci-passphrase" ["api.token"] False)

  secrets <-
    thechain [vaultspec (vaultfile v) "ci" "ci-passphrase", memoryspec "DB_PASS" "from memory"]

  same "the grant" "from the vault" =<< get secrets "api.token"
  -- A NAME OUTSIDE THE GRANT IS A MISS, so the chain carries on rather
  -- than stopping at a store that holds the name but not for this key.
  same "falls through" "from memory" =<< get secrets "db.pass"

thevaultbehindastoreisreachable :: IO ()
thevaultbehindastoreisreachable = do
  v <- fresh
  vaultset v "api.token" "tok01"

  secrets <- thechain [vaultspec (vaultfile v) "" master]
  api <- vaultof (host secrets) ""

  same "list" ["api.token"] =<< vaultlist api

  -- A CHAIN READS; the API writes. Both see the same file.
  vaultset api "db.pass" "written through the api"
  same "the chain" "written through the api" =<< get secrets "db.pass"

anamedstoreisreachedbyname :: IO ()
anamedstoreisreachedbyname = do
  first' <- fresh
  vaultset first' "api.token" "first"
  second <- fresh
  vaultset second "api.token" "second"

  secrets <-
    thechain
      [ (vaultspec (vaultfile first') "" master) {specname = "app"},
        (vaultspec (vaultfile second) "" master) {specname = "ops"}
      ]

  same "stores" ["app", "ops"] =<< stores secrets
  app <- vaultof (host secrets) "app"
  same "app" (vaultfile first') (vaultfile app)
  ops <- vaultof (host secrets) "ops"
  same "ops" (vaultfile second) (vaultfile ops)

  -- A STORE THAT IS NOT THERE REFUSES, and the alias does not stand in
  -- for it: picking one would be a guess, and the guess writes.
  holds "a store that is not there" "no minivault store named nope in this chain"
    =<< refusal "a store that is not there" (vaultof (host secrets) "nope")

achainwithnovaultsaysso :: IO ()
achainwithnovaultsaysso = do
  secrets <- thechain [memoryspec "API_TOKEN" "tok01"]
  holds "no vault" "no minivault store in this chain"
    =<< refusal "no vault" (vaultof (host secrets) "")

achainmissingthefileisrefused :: IO ()
achainmissingthefileisrefused = do
  holds "no file" "a vault needs a file"
    =<< refusal "no file" (thechain [vaultspec "" "" "p"])
  holds "no passphrase" "a vault needs a passphrase"
    =<< refusal "no passphrase" (thechain [vaultspec "v.skmv" "" ""])

thefileisreachedatthefirstlookup :: IO ()
thefileisreachedatthefirstlookup = do
  -- The file does not exist, and building the chain still succeeds: the
  -- handle is lazy, so a chain costs no PBKDF2 until a secret is actually
  -- wanted.
  dir <- readIORef work
  secrets <- thechain [vaultspec (dir </> "never.skmv") "" master]

  holds "at the first lookup" "no vault file"
    =<< refusal "at the first lookup" (get secrets "api.token")

-- | A chain that is closed hands its vault back.
--
-- The definition's @close@ drops the slot, as it does the provider's, so
-- a torn-down chain leaves the table where it found it - and @vaultof@
-- refuses rather than answering from a slot nothing holds.
closehandsthevaultback :: IO ()
closehandsthevaultback = do
  v <- fresh
  vaultset v "api.token" "tok01"

  before <- heldvaults
  secrets <- thechain [vaultspec (vaultfile v) "" master]

  same "one vault while the chain is live" (before + 1) =<< heldvaults

  close secrets

  same "none after close" before =<< heldvaults
  holds "vaultof after close" "no minivault store in this chain"
    =<< refusal "vaultof after close" (vaultof (host secrets) "")

-- --------------------------------------------------------------- the run

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

  dir <- mkdtemp "/tmp/sekreto-minivault-"
  writeIORef work dir

  passcount <- newIORef 0
  failcount <- newIORef 0

  let check = testcase passcount failcount only

  check "newvault" anewvaultholdsnothing
  check "written" awrittensecretcomesback
  check "binary" thefileisbinary
  check "rewrite" rewritinganamereplacesit
  check "remove" removedropsaname
  check "badname" abadnameisrefused
  check "restricted" arestrictedkeyreadsitsgrants
  check "readonly" areadonlykeyrefusestowrite
  check "ungranted" arestrictedkeycannotwriteanungrantedname
  check "laternamed" agrantednamethatdoesnotexistyet
  check "keys" themasterlistseverykey
  check "masteronly" themasteronlymethodsrefusearestrictedkey
  check "repeatedid" arepeatedkeyidisrefused
  check "revoke" revokedropsakey
  check "rotate" rotatekeepsthesecrets
  check "wrongphrase" awrongpassphraseandamissingfile
  check "damaged" adamagedfileisrefused
  check "createover" creatingoveranexistingvaultisrefused
  check "needsfile" avaultneedsafileandapassphrase
  check "emptykey" anemptykeymeansthemasterkey
  check "createflag" createmakesthefileonlywhenasked
  check "longkeyid" akeyidlongerthantheformatallows
  check "infocopy" theinfoacallergetscannotchangewhatthekeymaydo
  check "revokedcached" arevokedkeystopsreading
  check "regranted" aregrantedkeyid
  check "close" closeforgetsthederivedkeys

  files <- fixtures
  when (null files) $ do
    modifyIORef' failcount (+ 1)
    putStrLn "FAIL - fixtures\n       no committed vault was found"
  forM_ files $ \name -> check ("fixture:" ++ name) (readsthefixture name)

  check "chain" avaultisonestoreinachain
  check "chainfallthrough" arestrictedkeyinachainfallsthrough
  check "api" thevaultbehindastoreisreachable
  check "namedstore" anamedstoreisreachedbyname
  check "novault" achainwithnovaultsaysso
  check "badconfig" achainmissingthefileisrefused
  check "lazy" thefileisreachedatthefirstlookup
  check "closed" closehandsthevaultback

  passed <- readIORef passcount
  failed <- readIORef failcount
  putStrLn ("\n" ++ show passed ++ " passed, " ++ show failed ++ " failed")

  if 0 == failed then exitSuccess else exitFailure
