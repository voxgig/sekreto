/-
RUN: make check-core

WHAT A CHAIN OF BUILT-INS CAN DO WITH NO PLUGIN LOADED - and the program
whose LINK is the proof that it needs none.

`make check-core` builds this from the core objects and voxgig/plugin
alone: no `ffi/` object file, no `-lcurl`, no `-lssl`, no `-lcrypto`.
`sekreto_curl_fetch` and `sekreto_epoch_seconds` are the only symbols
those C files define, and both are declared in modules under `plugins/`,
so a core module that reached for either - or for anything behind them -
would fail this link rather than produce a binary.

It cannot import a plugin either, and that is not discipline: the core is
compiled with the plugin tree off LEAN_PATH, so `import SekretoPlugins.*`
here does not resolve. The plugin side of the seam is exercised from
`SekretoTest.lean`, which links both.
-/

import Sekreto

open Sekreto

def want (what : String) (wanted got : String) : IO Bool := do
  if wanted == got then return true
  IO.println s!"FAIL - {what}\n  wanted: {wanted}\n  got:    {got}"
  return false

def main : IO UInt32 := do
  let secrets ← sekreto { providers := [
    { kind := "memory", values := [("API_TOKEN", "tok01")] },
    { kind := "env" },
    { kind := "dotenv", file := "/nonexistent-sekreto-core/.env" },
    { kind := "file", dir := "/nonexistent-sekreto-core" }] }

  let mut ok := true
  ok := (← want "get" "tok01" (← secrets.get "api.token")) && ok
  ok := (← want "stores" "memory env dotenv file"
    (String.intercalate " " (← secrets.stores))) && ok
  ok := (← want "kinds" "dotenv env file memory"
    (String.intercalate " " (← secrets.kinds))) && ok
  ok := (← want "instances" "dotenv=live env=live file=live memory=live"
    (String.intercalate " " ((← secrets.instances).map (fun e => e.1 ++ "=" ++ e.2)))) && ok

  -- ...and a kind that was not passed in is refused, naming the fix.
  let refused ← tryCatch (do let _ ← sekreto { providers := [{ kind := "hashicorp" }] }; pure "")
    (fun err => pure (why err))
  ok := (← want "unknown kind"
    ("sekreto: unknown provider kind: hashicorp (available: dotenv, env, file, memory)" ++
     " - hashicorp is a sekreto plugin, not built in: pass it in the plugins option")
    refused) && ok

  -- ...and a chain of LIVE providers, which names no kind at all: the
  -- host stays empty, and `close` and `instances` still mean what they
  -- mean for a chain built from specs.
  let live ← Sekreto.make
    [{ lookup := fun name => pure (some ("live:" ++ name)), describe := "own:here" }]
  ok := (← want "live get" "live:api.token" (← live.get "api.token")) && ok
  ok := (← want "live stores" "own" (String.intercalate " " (← live.stores))) && ok
  ok := (← want "live instances" ""
    (String.intercalate " " ((← live.instances).map (fun e => e.1)))) && ok

  if ok then IO.println "core: a chain of built-ins needs no plugin"
  return (if ok then 0 else 1)
