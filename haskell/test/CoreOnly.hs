-- | The CORE, as a program that can be read.
--
-- It builds a chain of the four built-in kinds, resolves a secret from it
-- and prints what answered - a whole working sekreto with no plugin
-- anywhere near it. `make check-core` compiles this WITHOUT @-iplugins@
-- and then reads the binary: what is not in here is the proof the split
-- is real.
--
-- Nothing but the core may be imported below. GHC enforces that half by
-- itself, since @plugins/@ is not on the include path this is compiled
-- with; test/checkcore.py enforces the half GHC cannot see.

module Main (main) where

import Providers (ProviderSpec (..), emptyspec)
import Sekreto (Options (..), emptyoptions, get, sekreto, sources, stores)

main :: IO ()
main = do
  secrets <-
    sekreto
      emptyoptions
        { optproviders =
            [ emptyspec {speckind = "memory", specvalues = [("API_TOKEN", "tok01")]},
              emptyspec {speckind = "env"},
              emptyspec {speckind = "dotenv", specfile = "/nonexistent-sekreto-core/.env"},
              emptyspec {speckind = "file", specdir = "/nonexistent-sekreto-core"}
            ]
        }

  token <- get secrets "api.token"
  named <- stores secrets
  described <- sources secrets

  putStrLn (token ++ " " ++ unwords named ++ " " ++ unwords described)
