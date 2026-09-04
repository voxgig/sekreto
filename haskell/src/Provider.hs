-- | A source of secrets, and the one error type the library raises.
--
-- A provider answers one question: "do you have this secret?" It returns
-- the value, or 'Nothing' to mean "ask the next one". Nothing else about a
-- provider is visible to the caller - which is the point: an app reads
-- @api.token@ and never learns whether it came from the environment, a
-- .env file, HashiCorp Vault or a boru vault.
--
-- A record of functions rather than a class, so the provider set stays
-- open: an application can pass its own provider without the library
-- knowing its type.
--
-- 'SekretoError' lives here rather than beside the facade because every
-- other module raises it and none of them should have to import the
-- facade to do so. Haskell has no import cycles to fall back on.

module Provider
  ( Name,
    Provider (..),
    SekretoError (..),
    forceall,
    forced,
  )
where

import Control.Exception (Exception, evaluate)

-- | A secret name: dot-separated lowercase segments, e.g. @api.token@.
type Name = String

-- | Anything sekreto refuses to do: a bad name, a missing secret, a
-- provider that could not be reached. The message is the whole contract -
-- there is no code and no cause, because the shared spec pins the text.
newtype SekretoError = SekretoError String

instance Show SekretoError where
  show (SekretoError message) = message

instance Exception SekretoError

data Provider = Provider
  { -- | The value, or 'Nothing' if this provider does not have it. A
    -- provider that could not ANSWER raises instead; the two are never
    -- interchangeable, because a miss falls through to a weaker store.
    lookupsecret :: Name -> IO (Maybe String),
    -- | A short description, shown by 'Sekreto.sources'.
    describe :: String
  }

-- | Force a string to the last character.
--
-- The pure name functions raise by calling 'Control.Exception.throw', and
-- a thrown value inside a lazy structure surfaces wherever it is finally
-- demanded - which may be outside the handler that was meant to catch it,
-- or after a side effect that should never have happened. Every entry
-- point that must raise AT A PARTICULAR MOMENT - `resolve` validating the
-- name before it looks in the cache, a conformance subject reporting a
-- refusal - forces the value here instead of hoping.
forced :: String -> IO String
forced value = evaluate (length value) >> pure value

-- | The same, for a whole association list of strings.
forceall :: [(String, String)] -> IO [(String, String)]
forceall entries =
  evaluate (sum [length key + length item | (key, item) <- entries]) >> pure entries
