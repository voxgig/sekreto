-- | ONE PLUGIN, and only one.
--
-- A consumer that configures HashiCorp Vault and nothing else imports
-- @Hashicorp@ and nothing else. `make check-core` compiles this and then
-- reads the binary for the other nine kinds: none of them may be there,
-- because a lean consumer that still links seven vault clients has not
-- been made lean.
--
-- Import exactly one plugin module below.

module Main (main) where

import Hashicorp (hashicorp)
import Providers (ProviderSpec (..), emptyspec)
import Sekreto (Options (..), emptyoptions, sekreto, sources, stores)

main :: IO ()
main = do
  secrets <-
    sekreto
      emptyoptions
        { optplugins = [hashicorp],
          optproviders =
            [ emptyspec {speckind = "memory", specvalues = [("API_TOKEN", "tok01")]},
              emptyspec
                { speckind = "hashicorp",
                  specname = "prod",
                  specaddr = "https://vault.example.com",
                  spectoken = "t"
                }
            ]
        }

  named <- stores secrets
  described <- sources secrets

  putStrLn (unwords named ++ " " ++ unwords described)
