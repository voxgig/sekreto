-- | The HTTP-JSON round trip every network plugin makes, the token clock
-- three of them keep, and the small helpers they all share.
--
-- It is under @plugins/@ because it reaches "Http", which reaches "Tls",
-- which is the FFI to OpenSSL: a chain of built-in kinds must never link
-- any of it. The core keeps 'Providers.checkaddr', which decides whether
-- an address may carry a token at all, because that is a decision about
-- configuration rather than a socket.
--
-- A port of typescript/plugins/httpjson.ts, which is canonical.

module Httpjson
  ( Answer (..),
    currenttoken,
    fetchjson,
    fromenv,
    nakedurl,
    never,
    nowms,
    renewtime,
    uriescape,
    vaultrefof,
  )
where

import Control.Monad (when)
import Data.IORef (IORef, readIORef, writeIORef)
import Data.Maybe (fromMaybe, isNothing)
import Data.Time.Clock.POSIX (getPOSIXTime)
import Http (Response (..), nakedurl, uriescape)
import qualified Http
import Json (Json (..))
import qualified Json
import Names (Name, VaultRef (..), vaultref)
import Provider (forced)
import Providers (fail')
import System.Environment (lookupEnv)

fromenv :: String -> IO String
fromenv name = fromMaybe "" <$> lookupEnv name

-- | Milliseconds since the epoch: the clock the renewal deadline uses.
nowms :: IO Integer
nowms = round . (1000 *) <$> getPOSIXTime

-- | A deadline that never arrives: a configured token never expires, and
-- neither does a login whose expiry was absent or zero. Integer is
-- unbounded, so this is a chosen far future rather than a maxBound.
never :: Integer
never = 10 ^ (18 :: Int)

-- | When a logged-in token must be renewed, from its expiry in seconds -
-- a JSON number, or a string, as Azure IMDS sends it: now + max(seconds -
-- 60, 1). A missing or zero expiry means never renew.
renewtime :: Maybe Json -> IO Integer
renewtime expires =
  case seconds of
    value
      | isNaN value || 0 >= value -> pure never
      | otherwise -> do
          at <- nowms
          pure (at + round (1000 * max (value - 60) 1))
  where
    seconds = case expires of
      Just (JNum value) -> value
      Just (JStr value) -> case reads value :: [(Double, String)] of
        [(parsed, "")] -> parsed
        _ -> 0
      _ -> 0

-- | One JSON round-trip's result: the status, and the parsed body.
data Answer = Answer {ansstatus :: Int, ansbody :: Maybe Json}

-- | One JSON round-trip. Network failure is always an error - an
-- unreachable store is a store that could not answer.
fetchjson :: String -> String -> [(String, String)] -> Maybe String -> IO Answer
fetchjson method url headers body = do
  res <- Http.request method url headers body

  let parsed = Json.parse (resbody res)

  -- A success status promised JSON; a body that does not parse means the
  -- store could not answer coherently, and treating it as a miss would
  -- fall through to a weaker store. Error statuses may carry any body -
  -- they are decided on status alone.
  when (200 == resstatus res && isNothing parsed) $
    fail' ("sekreto: malformed response from " ++ nakedurl url)

  pure (Answer (resstatus res) parsed)

-- | The working token: a configured token is kept forever, a logged-in
-- token is renewed shortly before its lease runs out - a long-running
-- process must not keep presenting a token the vault already expired.
currenttoken :: IORef (Maybe String) -> IORef Integer -> IO String -> IO String
currenttoken livetoken renewat login = do
  held <- readIORef livetoken
  at <- nowms
  due <- readIORef renewat

  case held of
    Just token | at < due -> pure token
    _ -> do
      fresh <- login
      writeIORef livetoken (Just fresh)
      pure fresh

-- | The name's vault location, forced here so that an invalid name is
-- refused before any request is built. Shared, because a store that maps
-- a name onto a path and a field wants the refusal at the same moment.
vaultrefof :: Name -> IO VaultRef
vaultrefof name = do
  let ref = vaultref name
  _ <- forced (refpath ref)
  _ <- forced (reffield ref)
  pure ref
