/-
A tiny app that needs a secret.

It asks sekreto for `api.token` and calls the token-protected API with
it. Every port ships this same CLI, and test/integration.sh runs all of
them against the same server from every secret source - which is what
proves the library, rather than the spec alone.

Usage: build/sekreto-cli <api-url> [--source <source>] [--store <name>]

Sources: env dotenv file hashicorp boru boruwire awssecrets awsparams
         gcpsecrets azuresecrets onepassword doppler infisical
         secretspec chain

Each source's configuration arrives in the environment variables its own
ecosystem already uses (VAULT_*, AWS_*, OP_CONNECT_*, ...), listed in
`chainfor` below.

It runs from an EMPTY working directory with a wiped environment, so it
needs nothing on disk beside itself: the binary is statically linked
against the library and carries no module path of its own.
-/

import Sekreto

open Sekreto

def LANG : String := "lean"

private def envor (name fallback : String) : IO String := do
  let value ← getenv name
  return (if value.isEmpty then fallback else value)

/-- The chain a `--source` names. An empty environment value is absent. -/
def chainfor (source : String) : IO (List ProviderSpec) := do
  let envspec : ProviderSpec := { kind := "env", «prefix» := ← getenv "SEKRETO_PREFIX" }
  let dotenvspec : ProviderSpec := { kind := "dotenv", file := ← envor "SEKRETO_DOTENV" ".env" }
  let filespec : ProviderSpec := { kind := "file", dir := ← envor "SEKRETO_FILEDIR" "/run/secrets" }

  let method ← getenv "VAULT_AUTH"
  let authspec : AuthSpec := {
    method := method,
    role := ← getenv "VAULT_ROLE",
    jwtfile := ← getenv "VAULT_JWT_FILE",
    roleid := ← getenv "VAULT_ROLE_ID",
    secretid := ← getenv "VAULT_SECRET_ID" }

  let hashicorpspec : ProviderSpec := {
    kind := "hashicorp",
    addr := ← getenv "VAULT_ADDR",
    token := ← getenv "VAULT_TOKEN",
    mount := ← getenv "VAULT_MOUNT",
    kv := (← getenv "VAULT_KV").toNat?,
    vaultnamespace := ← getenv "VAULT_NAMESPACE",
    auth := if method.isEmpty then none else some authspec }

  let boruspec : ProviderSpec := {
    kind := "boru",
    command := ← envor "BORU_COMMAND" "boru",
    «namespace» := ← getenv "BORU_NAMESPACE",
    home := ← getenv "BORU_HOME" }

  -- The same vault over its wire protocol (`boru vault serve`) instead
  -- of the CLI: an address plus a capability token from `vault grant`.
  let boruwirespec : ProviderSpec := {
    kind := "boru",
    addr := ← getenv "BORU_ADDR",
    token := ← getenv "BORU_TOKEN",
    «namespace» := ← getenv "BORU_NAMESPACE" }

  let awssecretsspec : ProviderSpec := {
    kind := "awssecrets", region := ← getenv "AWS_REGION", addr := ← getenv "AWS_ENDPOINT" }

  let awsparamsspec : ProviderSpec := {
    kind := "awsparams", region := ← getenv "AWS_REGION", addr := ← getenv "AWS_ENDPOINT",
    «prefix» := ← getenv "AWS_PARAM_PREFIX" }

  let gcpspec : ProviderSpec := {
    kind := "gcpsecrets", project := ← getenv "GCP_PROJECT", addr := ← getenv "GCP_ADDR",
    metadataaddr := ← getenv "GCP_METADATA_ADDR" }

  let azurespec : ProviderSpec := {
    kind := "azuresecrets",
    vault := ← getenv "AZURE_VAULT",
    token := ← getenv "AZURE_TOKEN",
    tenant := ← getenv "AZURE_TENANT",
    clientid := ← getenv "AZURE_CLIENT_ID",
    clientsecret := ← getenv "AZURE_CLIENT_SECRET",
    loginaddr := ← getenv "AZURE_LOGIN_ADDR",
    imdsaddr := ← getenv "AZURE_IMDS_ADDR" }

  let onepasswordspec : ProviderSpec := {
    kind := "onepassword", addr := ← getenv "OP_CONNECT_HOST",
    token := ← getenv "OP_CONNECT_TOKEN", vault := ← getenv "OP_VAULT" }

  let dopplerspec : ProviderSpec := {
    kind := "doppler", token := ← getenv "DOPPLER_TOKEN",
    project := ← getenv "DOPPLER_PROJECT", config := ← getenv "DOPPLER_CONFIG",
    addr := ← getenv "DOPPLER_ADDR" }

  -- SecretSpec's own environment variables where it has them, so a shell
  -- already set up for secretspec needs nothing further.
  let secretspecspec : ProviderSpec := {
    kind := "secretspec", command := ← envor "SECRETSPEC_COMMAND" "secretspec",
    file := ← getenv "SECRETSPEC_FILE", profile := ← getenv "SECRETSPEC_PROFILE",
    backend := ← getenv "SECRETSPEC_PROVIDER", reason := ← getenv "SECRETSPEC_REASON" }

  let infisicalspec : ProviderSpec := {
    kind := "infisical", addr := ← getenv "INFISICAL_ADDR",
    token := ← getenv "INFISICAL_TOKEN", clientid := ← getenv "INFISICAL_CLIENT_ID",
    clientsecret := ← getenv "INFISICAL_CLIENT_SECRET",
    project := ← getenv "INFISICAL_PROJECT", environment := ← getenv "INFISICAL_ENV",
    path := ← getenv "INFISICAL_PATH" }

  if "env" == source then return [envspec]
  if "dotenv" == source then return [dotenvspec]
  if "file" == source then return [filespec]
  if "hashicorp" == source then return [hashicorpspec]
  if "boru" == source then return [boruspec]
  if "boruwire" == source then return [boruwirespec]
  if "awssecrets" == source then return [awssecretsspec]
  if "awsparams" == source then return [awsparamsspec]
  if "gcpsecrets" == source then return [gcpspec]
  if "azuresecrets" == source then return [azurespec]
  if "onepassword" == source then return [onepasswordspec]
  if "doppler" == source then return [dopplerspec]
  if "infisical" == source then return [infisicalspec]
  if "secretspec" == source then return [secretspecspec]

  -- The default: the chain an app would actually ship with - local
  -- overrides first, shared vaults last.
  return [envspec, dotenvspec, hashicorpspec, boruspec]

/-- The value of a `--flag value` pair, or "" when the flag is absent.
Positional, by index-of: no argument-parsing library. -/
def flag (args : List String) (name : String) : String :=
  match args with
  | [] => ""
  | found :: rest => if found == name then rest.headD "" else flag rest name

def run (args : List String) : IO UInt32 := do
  let url := args.headD "http://127.0.0.1:8099/whoami"
  let source := first [flag args "--source", "chain"]
  -- --store names a store outright: the secret must come from that one,
  -- not from whichever provider happens to answer first.
  let store := flag args "--store"

  -- The chain is built first and on its own, so that everything after it
  -- can route its own failure through `redactText`: once a provider has
  -- answered, an error message may quote what it answered, and the suite
  -- greps stderr as well as stdout on both the pass and the fail path.
  let chain ← tryCatch (do return some (← sekreto (← chainfor source)))
    (fun err => do
      IO.eprintln ("sekreto-cli: " ++ why err)
      return none)

  match chain with
  | none => return 2
  | some secrets =>

  let held ← tryCatch (do
      let token ← if store.isEmpty then secrets.get "api.token"
                  else secrets.getfrom store "api.token"
      return some token)
    (fun err => do
      IO.eprintln ("sekreto-cli: " ++ (← secrets.redactText (why err)))
      return none)

  match held with
  | none => return 2
  | some token =>

  let res ← tryCatch (do
      let answer ← fetchjson "GET" url [
        ("Authorization", "Bearer " ++ token),
        ("X-Sekreto-Lang", LANG)]
      return some answer)
    (fun err => do
      IO.eprintln ("sekreto-cli: " ++ (← secrets.redactText (why err)))
      return none)

  match res with
  | none => return 1
  | some answer =>

  if 200 != answer.status then
    -- Never print the token itself, even when the call fails.
    let body := (answer.body.map Json.stringify).getD ("status " ++ toString answer.status)
    IO.eprintln ("sekreto-cli: " ++ (← secrets.redactText body))
    return 1

  let caller := OptJson.dig answer.body ["caller"]

  -- Assembled field by field, in the spec's order. Printing a map here is
  -- what has bitten port after port: the language's own key order is not
  -- the one every other port prints.
  IO.println ("{\"ok\":true" ++
    ",\"lang\":" ++ Json.quote LANG ++
    ",\"source\":" ++ Json.quote source ++
    ",\"store\":" ++ Json.quote store ++
    ",\"caller\":" ++ (caller.map Json.stringify).getD "null" ++
    "}")

  return 0

def main (args : List String) : IO UInt32 := run args
