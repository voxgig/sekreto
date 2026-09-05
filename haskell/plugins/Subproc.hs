-- | Running a child process to completion, for the two kinds that read a
-- CLI rather than a socket.
--
-- Under @plugins/@ with the rest: a chain of built-in kinds spawns
-- nothing, and the way to know that is that "System.Process" is not
-- reachable from the core at all.
--
-- A port of the child-process half of typescript/plugins/boru.ts and
-- typescript/plugins/secretspec.ts, which are canonical.

module Subproc (Ran (..), runcmd) where

import Control.Exception (IOException, try)
import Providers (fail', trim)
import System.Environment (getEnvironment)
import System.Exit (ExitCode (..))
import System.Process (CreateProcess (..), proc, readCreateProcessWithExitCode)

-- | What a finished child process left behind.
data Ran = Ran {ranout :: String, ranwhy :: String, ranstatus :: Int}

-- | Run a child to completion and collect both its streams.
--
-- @readCreateProcessWithExitCode@ closes the child's stdin - so a CLI
-- that reads it, one prompting for a passphrase when its environment
-- variable is absent, sees EOF and gives up instead of waiting forever -
-- and drains stdout and stderr CONCURRENTLY. Reading stdout to EOF and
-- only then reading stderr deadlocks the moment the child writes more
-- than one pipe buffer (64 KiB on Linux) to stderr, and nothing here sets
-- a timeout, so that hang would be permanent. secretspec's diagnostics
-- are box-drawn and reach that size easily.
--
-- Arguments are passed as a list, never through a shell, and no secret
-- ever goes on a command line where the process table would publish it.
runcmd :: String -> [String] -> [(String, String)] -> IO Ran
runcmd command args extraenv = do
  base <- getEnvironment

  let shaped =
        (proc command args)
          { env = if null extraenv then Nothing else Just (foldl setvar base extraenv)
          }

  outcome <- try (readCreateProcessWithExitCode shaped "")

  case outcome :: Either IOException (ExitCode, String, String) of
    Left err -> fail' ("sekreto: cannot run " ++ command ++ ": " ++ show err)
    Right (code, out, why) ->
      pure
        Ran
          { ranout = out,
            ranwhy = trim why,
            ranstatus = case code of
              ExitSuccess -> 0
              ExitFailure status -> status
          }
  where
    setvar entries (key, value) = (key, value) : filter ((key /=) . fst) entries
