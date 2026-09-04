/-
The providers a Sekreto chains together.

A provider answers one question: "do you have this secret?" It returns
the value, or `none` to mean "ask the next one". Nothing else about a
provider is visible to the caller - which is the point: an app reads
`api.token` and never learns whether it came from the environment, a
.env file, HashiCorp Vault, AWS, GCP, Azure or a boru vault.

Two failure shapes, and they are never interchangeable. A store that does
not hold the secret is a MISS (`none`) - the chain carries on. A store
that could not answer - bad credentials, unreachable host, missing
configuration - RAISES: falling through there would quietly reach for a
weaker store.

A port of typescript/src/Providers.ts, which is canonical.
-/

import Sekreto.Text
import Sekreto.Json
import Sekreto.Crypto
import Sekreto.Provider
import Sekreto.Core
import Sekreto.Sigv4
import Sekreto.Clock
import Sekreto.Addr
import Sekreto.Curl

namespace Sekreto

/-- Logging in to a vault instead of being handed a token. `method` is
`kubernetes` or `approle`; `mount` defaults to the method name. -/
structure AuthSpec where
  method : String := ""
  mount : String := ""
  /-- kubernetes: the Vault role to log in as. -/
  role : String := ""
  /-- kubernetes: the service-account JWT itself (tests). -/
  jwt : String := ""
  /-- kubernetes: where the JWT lives; the conventional pod path by
  default. -/
  jwtfile : String := ""
  /-- approle: the role and secret ids. -/
  roleid : String := ""
  secretid : String := ""
  deriving Inhabited

/-- Printed without its credentials.

There is no `deriving Repr` on this structure and there must not be: a
derived printer would put the service-account JWT and the AppRole secret
id into `IO.eprintln s!"bad chain: {specs}"`, which is exactly what
someone writes when a chain will not build. Fields that hold a
credential report whether they are set, never what they are. -/
instance : ToString AuthSpec where
  toString spec :=
    "AuthSpec(method=" ++ spec.method ++ ", mount=" ++ spec.mount ++
    ", role=" ++ spec.role ++ ", jwtfile=" ++ spec.jwtfile ++
    ", roleid=" ++ spec.roleid ++ ", jwt=" ++ setornot spec.jwt ++
    ", secretid=" ++ setornot spec.secretid ++ ")"

/-- The declarative form of a provider, as used in config and in the
shared spec. `kind` picks the provider; everything else is that kind's
own.

Every string field defaults to empty rather than being optional: "not
configured" and "configured empty" mean the same thing everywhere in this
library. `kv` is the only number and `values` the only map. -/
structure ProviderSpec where
  kind : String := ""
  /-- The store name `Sekreto.getfrom` addresses. Defaults to `kind`. -/
  name : String := ""
  «prefix» : String := ""
  /-- dotenv: the file to read. secretspec: the declaration to read. -/
  file : String := ""
  /-- memory: literal values, keyed like environment variables. -/
  values : Pairs String := []
  /-- file: the directory of one-secret-per-file entries. -/
  dir : String := ""
  /-- hashicorp / boru (wire) / gcp / 1password / doppler / infisical:
  the base URL. -/
  addr : String := ""
  /-- hashicorp / boru (wire) / gcp / azure / 1password / doppler /
  infisical: the token. -/
  token : String := ""
  /-- hashicorp / boru (wire): the KV mount (default `secret`). -/
  mount : String := ""
  /-- hashicorp: KV engine version, 1 or 2 (default 2). -/
  kv : Option Nat := none
  /-- hashicorp: Vault Enterprise namespace (X-Vault-Namespace). -/
  vaultnamespace : String := ""
  /-- hashicorp: log in for a token instead of being handed one. -/
  auth : Option AuthSpec := none
  /-- boru / secretspec: the executable to run. -/
  command : String := ""
  /-- secretspec: the profile to read (`--profile`). -/
  profile : String := ""
  /-- secretspec: which of ITS backends to read from (`--provider`).
  Named `backend` here because `provider` already means a sekreto
  provider. -/
  backend : String := ""
  /-- secretspec: the audit reason recorded for the read (`--reason`).
  SecretSpec refuses to read without one. -/
  reason : String := ""
  /-- boru: the namespace qualifying the alias. -/
  «namespace» : String := ""
  /-- boru: the vault home, passed as BORU_HOME. -/
  home : String := ""
  /-- aws: region and credentials; the standard AWS_* variables fill the
  rest. -/
  region : String := ""
  keyid : String := ""
  secret : String := ""
  session : String := ""
  /-- gcp / doppler / infisical: the project, however that store names
  it. -/
  project : String := ""
  /-- azure: the Key Vault name or full URL. 1password: the vault name or
  id. -/
  vault : String := ""
  /-- azure: client-credential login. infisical: universal-auth login. -/
  tenant : String := ""
  clientid : String := ""
  clientsecret : String := ""
  /-- azure: where to log in / where IMDS answers. gcp: the metadata
  server. -/
  loginaddr : String := ""
  imdsaddr : String := ""
  metadataaddr : String := ""
  /-- azure: the Key Vault API version (default 7.4). -/
  apiversion : String := ""
  /-- doppler: the config slug (with `project`). -/
  config : String := ""
  /-- infisical: the environment slug and secret path. -/
  environment : String := ""
  path : String := ""
  deriving Inhabited

/-- Printed without its credentials. See `AuthSpec`: a derived printer
would put the Vault token, the AWS secret access key and the Azure client
secret into whatever formatted it. -/
instance : ToString ProviderSpec where
  toString spec :=
    "ProviderSpec(kind=" ++ spec.kind ++ ", name=" ++ spec.name ++
    ", addr=" ++ spec.addr ++ ", token=" ++ setornot spec.token ++
    ", secret=" ++ setornot spec.secret ++
    ", clientsecret=" ++ setornot spec.clientsecret ++
    ", auth=" ++ (match spec.auth with | none => "none" | some auth => toString auth) ++ ")"

/-- An environment variable, or the empty string. -/
def getenv (name : String) : IO String := do
  return ((← IO.getEnv name).getD "")

/-- What a failure has to say for itself, on one line. Lean's `IO.Error`
renders a file error across two, and a message in this library is one. -/
def why (err : IO.Error) : String :=
  ((toString err).splitOn "\n").headD (toString err)

private def trimslash (text : String) : String := dropsuffix text "/"

/-- An expiry in seconds, from a JSON number OR a numeric string: Azure
IMDS sends `expires_in` as `"3599"`, and a port that reads only numbers
renews a managed-identity token every request. Anything else is zero,
which means never renew. -/
def expiryof (value : Option Json) : Float :=
  match value with
  | some (.num held) => held
  | some (.str held) => ((Json.parse held).bind Json.asnum).getD 0.0
  | _ => 0.0

/-- Does this read failure mean "no secrets here", rather than "I could
not answer"?

Absence is a MISS and the chain carries on; anything else - permission
denied, an unreadable mount, a failing disk - is an ERROR, because
returning a miss there falls silently through to a weaker store.

Asked of the DIRECTORY, not of the file. The obvious spelling, "does the
file exist", is wrong in exactly the case the rule exists for: an
existence predicate answers false for a permission error, and would turn
a locked directory - the canonical unreadable mount - into a miss. A path
whose parent is a plain file really is "no secrets here", and that is
what this asks. -/
private def absentpath (path : String) : IO Bool := do
  match (System.FilePath.mk path).parent with
  | none => return false
  | some dir => return !(← dir.isDir)

/-- The bytes of a file; `none` when there are no secrets there.

`noFileOrDirectory` is ENOENT and is always absence. Anything else is
put to `absentpath`, which answers for ENOTDIR and refuses for everything
else - the refusal carries the underlying failure out to the caller,
which names the provider in the message. -/
private def readmaybe (path : String) : IO (Option ByteArray) :=
  tryCatch (do return some (← IO.FS.readBinFile path))
    (fun err =>
      match err with
      | .noFileOrDirectory _ _ _ => return none
      | _ => do if ← absentpath path then return none else throw err)

/-- Bytes as text, or the empty string when they are not UTF-8. -/
private def astext (bytes : ByteArray) : String := (String.fromUTF8? bytes).getD ""

/-- What a finished child process left behind. -/
structure Ran where
  out : String
  why : String
  status : Nat

/-- Run a child to completion and collect both its streams.

`IO.Process.output` is the right primitive and not merely a convenient
one: it closes the child's stdin (so a CLI prompting for a passphrase
sees EOF instead of hanging) and it drains stdout and stderr
CONCURRENTLY. Draining them one after the other deadlocks the moment the
child writes more than one pipe buffer - 64 KiB on Linux - to stderr, and
secretspec's box-drawn diagnostics reach that size. Nothing here sets a
timeout, so that hang would be permanent.

Arguments go as an array and never through a shell, and no secret ever
reaches a command line, where the process table publishes it.

A BINARY THAT CANNOT BE EXECUTED IS ITS OWN FAILURE, not a vault error,
and Lean makes that awkward: `IO.Process.output` does NOT throw for a
missing command. It answers exit 255 with the runtime's own wording on
stderr, which without the check below is reported as `boru vault error:
could not execute external process` - a store that could not be started
dressed up as a store that answered. The `tryCatch` stays for the
platforms and releases where it does throw.

The phrase is Lean's, and matching it can only ever turn one ERROR into
another, more accurate one: a miss is decided further up, on wording the
child itself chose. -/
def runcmd (command : String) (args : List String)
    (env : List (String × Option String) := []) : IO Ran := do
  let done ← tryCatch
    (IO.Process.output { cmd := command, args := args.toArray, env := env.toArray })
    (fun err => fail ("sekreto: cannot run " ++ command ++ ": " ++ why err))

  let status := done.exitCode.toNat
  let said := done.stderr.trim

  if 255 == status && hasText said "could not execute external process" then
    fail ("sekreto: cannot run " ++ command ++ ": " ++ said)

  return { out := done.stdout, why := said, status := status }

-- --------------------------------------------------------------- built in

/-- Environment variables: `api.token` from `API_TOKEN`. -/
def envprovider (pre : String := "") : Provider := {
  lookup := fun name => do IO.getEnv (← ofResult (envkey name pre))
  describe := "env" ++ (if pre.isEmpty then "" else ":" ++ pre) }

/-- Literal values, keyed like environment variables. The spec uses this
to test chain behaviour without touching the outside world. An absent key
is a miss; the EMPTY STRING IS A HIT. -/
def memoryprovider (values : Pairs String := []) (pre : String := "") : Provider := {
  lookup := fun name => do return Pairs.find? values (← ofResult (envkey name pre))
  describe := "memory" ++ (if pre.isEmpty then "" else ":" ++ pre) }

/-- A `.env` file, read once, keyed exactly like the environment.

LAZILY: the `stores` corpus group puts a dotenv provider in a chain and
never looks anything up, so an eager constructor would read whatever
`.env` happened to sit in the working directory. -/
def dotenvprovider (file : String := ".env") (pre : String := "") : IO Provider := do
  let cell ← IO.mkRef (none : Option (Pairs String))

  let load : IO (Pairs String) := do
    match ← cell.get with
    | some held => return held
    | none =>
      let bytes ← tryCatch (readmaybe file)
        (fun err => fail ("sekreto: dotenv provider cannot read " ++ file ++ ": " ++ why err))
      let loaded := match bytes with
        | none => []
        | some held => parsedotenv (astext held)
      cell.set (some loaded)
      return loaded

  return {
    lookup := fun name => do
      let key ← ofResult (envkey name pre)
      return Pairs.find? (← load) key
    describe := "dotenv:" ++ file }

/-- A directory of one-secret-per-file entries, keyed like the
environment: `api.token` reads `<dir>/API_TOKEN`.

This is the shape of a mounted Kubernetes Secret, a Docker or Swarm
secret, and a systemd credentials directory, so those all work with no
further configuration. Read on EVERY lookup, with no caching. One
trailing newline is stripped - tools that write these files disagree
about it, and a newline is never part of a secret on purpose. -/
def fileprovider (dir : String := "") (pre : String := "") : Provider := {
  lookup := fun name => do
    let key ← ofResult (envkey name pre)
    let path := if dir.isEmpty then key else trimslash dir ++ "/" ++ key
    let bytes ← tryCatch (readmaybe path)
      (fun err => fail ("sekreto: file provider cannot read " ++ path ++ ": " ++ why err))
    match bytes with
    | none => return none
    | some held =>
      let body := astext held
      return some (
        if body.endsWith "\r\n" then body.dropRight 2
        else if body.endsWith "\n" then body.dropRight 1
        else body)
  describe := "file:" ++ dir }

-- ------------------------------------------------------------- hashicorp

/-- HashiCorp Vault.

KV v2 (the default): `api.token` reads `{addr}/v1/{mount}/data/api` and
takes the `token` field of `data.data`. KV v1 reads
`{addr}/v1/{mount}/api` and takes the field of `data`. A 404 means "not
here" - a miss - so a vault can sit in a chain with fallbacks.

A Vault Enterprise namespace rides the X-Vault-Namespace header, on
logins as well as reads.

Instead of being handed a token, the provider can log in: Kubernetes auth
(the pod's service-account JWT, from its conventional path) or AppRole. A
failed login is an error, never a miss - it means this store could not
answer at all. -/
def hashicorpprovider (addr : String) (token mount vaultnamespace : String := "")
    (kv : Option Nat := none) (auth : Option AuthSpec := none) : IO Provider := do
  let usemount := if mount.isEmpty then "secret" else mount
  let usekv := kv.getD 2

  -- A version typo like kv: 3 must not quietly behave as v2 and turn its
  -- 404s into misses; there is nothing safe to assume it meant.
  if 1 != usekv && 2 != usekv then
    fail ("sekreto: hashicorp: unsupported kv version: " ++ toString usekv)

  let livetoken ← IO.mkRef (if token.isEmpty then none else some token)
  let renewat ← IO.mkRef NEVER

  let baseheaders : Pairs String :=
    if vaultnamespace.isEmpty then [] else [("X-Vault-Namespace", vaultnamespace)]

  let login : IO String := do
    let use ← match auth with
      | some found => pure found
      | none => fail "sekreto: hashicorp: no token and no auth method"

    let authmount := first [use.mount, use.method]
    let url := trimslash addr ++ "/v1/auth/" ++ authmount ++ "/login"

    let body ←
      if "kubernetes" == use.method then do
        let jwt ←
          if !use.jwt.isEmpty then pure use.jwt
          else
            let file := first [use.jwtfile, "/var/run/secrets/kubernetes.io/serviceaccount/token"]
            match ← tryCatch (readmaybe file) (fun _ => pure none) with
            | some held => pure (astext held).trim
            | none => fail ("sekreto: hashicorp: cannot read jwt file " ++ file)
        pure (Json.object [("role", Json.str use.role), ("jwt", Json.str jwt)])
      else if "approle" == use.method then
        pure (Json.object [("role_id", Json.str use.roleid), ("secret_id", Json.str use.secretid)])
      else
        fail ("sekreto: hashicorp: unknown auth method: " ++ use.method)

    let res ← fetchjson "POST" url baseheaders (some (Json.stringify body))
    let got := OptJson.text (OptJson.dig res.body ["auth", "client_token"])

    match got with
    | some value =>
      if 200 != res.status || value.isEmpty then
        fail ("sekreto: hashicorp login failed: " ++ toString res.status ++ ": " ++ url)
      renewat.set (← Sekreto.renewat (expiryof (OptJson.dig res.body ["auth", "lease_duration"])))
      return value
    | none => fail ("sekreto: hashicorp login failed: " ++ toString res.status ++ ": " ++ url)

  return {
    lookup := fun name => do
      ofResult (checkaddr addr)

      let held ← livetoken.get
      if held.isNone || (← IO.monoMsNow) ≥ (← renewat.get) then
        livetoken.set (some (← login))

      let ref ← ofResult (vaultref name)
      let base := trimslash addr ++ "/v1/" ++ usemount
      let url := if 1 == usekv then base ++ "/" ++ ref.path else base ++ "/data/" ++ ref.path

      let headers := Pairs.put baseheaders "X-Vault-Token" ((← livetoken.get).getD "")
      let res ← fetchjson "GET" url headers

      if 404 == res.status then return none
      if 200 != res.status then
        fail ("sekreto: hashicorp error: " ++ toString res.status ++ ": " ++ url)

      let data := if 1 == usekv then OptJson.dig res.body ["data"]
                  else OptJson.dig res.body ["data", "data"]
      return OptJson.text (OptJson.dig data [ref.field])
    describe := "hashicorp:" ++ addr ++ "/" ++ usemount }

-- ------------------------------------------------------------------ boru

/-- Does this boru failure mean "no such secret" rather than "I could not
answer"? Matched on boru's own wording for a missing alias. -/
def borumiss (text : String) : Bool := hasText text "no alias named"

/-- A boru vault.

Two ways in, both boru's own.

With no `addr`, the CLI: `boru vault get --reveal <alias>` prints the
secret on stdout and nothing else. The passphrase is read by boru itself
from `BORU_VAULT_PASSPHRASE`; sekreto never accepts it as config and
never puts it on a command line, where it would show up in the process
table.

With an `addr`, boru's wire protocol: a read-only, HashiCorp-shaped
provision API authenticated by a capability token. A sekreto name is
already a valid boru alias, and BORU ALIASES KEEP THEIR DOTS, so
`api.token` is the single path segment `api.token` - not the `api`/`token`
split a HashiCorp KV gets. A 404 is a miss; anything else the server
refuses is an error. -/
def boruprovider (command space home addrgiven token mount : String := "") : Provider :=
  let usecommand := if command.isEmpty then "boru" else command
  let addr := trimslash addrgiven
  let usemount := if mount.isEmpty then "secret" else mount
  {
    lookup := fun name => do
      let _ ← ofResult (checkname name)

      if !addr.isEmpty then
        ofResult (checkaddr addr)
        let alias := if space.isEmpty then name else space ++ "/" ++ name
        let url := addr ++ "/v1/" ++ usemount ++ "/data/" ++ alias
        let res ← fetchjson "GET" url [("X-Vault-Token", token)]
        if 404 == res.status then return none
        if 200 != res.status then
          fail ("sekreto: boru serve error: " ++ toString res.status ++ ": " ++ url)
        return OptJson.text (OptJson.dig res.body ["data", "data", "value"])
      else
        let alias := if space.isEmpty then name else space ++ ":" ++ name
        let env := if home.isEmpty then [] else [("BORU_HOME", some home)]
        let ran ← runcmd usecommand ["vault", "get", "--reveal", alias] env

        if 0 == ran.status then
          -- boru prints the value and one newline, and nothing else.
          return some (dropsuffix ran.out "\n")
        -- "no alias named" is boru saying it does not hold this secret,
        -- which is a miss. A locked vault or a wrong passphrase is not.
        if borumiss ran.why then return none
        fail ("sekreto: boru vault error: " ++
          (if ran.why.isEmpty then "exit " ++ toString ran.status else ran.why))
    describe :=
      if !addr.isEmpty then "boru:" ++ addr
      else "boru" ++ (if space.isEmpty then "" else ":" ++ space) }

-- ------------------------------------------------------------ secretspec

/-- Does this SecretSpec failure mean "no such secret" rather than "I
could not answer"?

MATCHED ON THE WHOLE PHRASE, NOT ON "not found". SecretSpec also says
`Provider backend 'keyring' not found`, which is a store that could not
answer at all - and reading that as a miss is the worst failure this
library has, because the chain then falls through to a weaker store
without saying so. The key is required to appear, so the two cannot be
confused. -/
def secretspecmiss (text key : String) : Bool :=
  hasText text ("Secret '" ++ key ++ "' not found")

/-- SecretSpec (https://secretspec.dev), through its CLI.

`secretspec get API_TOKEN` prints the value on stdout and nothing else. A
sekreto name maps to a SecretSpec key exactly as it maps to an
environment variable.

A reason is required, not optional: SecretSpec records every read in an
audit log and refuses to read at all without one. -/
def secretspecprovider (command file profile backend reason pre : String := "") : Provider :=
  let usecommand := if command.isEmpty then "secretspec" else command
  {
    lookup := fun name => do
      let key ← ofResult (envkey name pre)

      -- The order is exact: `--file` before the subcommand, `--reason`
      -- always sent.
      let args :=
        (if file.isEmpty then [] else ["--file", file]) ++
        ["get", key] ++
        (if backend.isEmpty then [] else ["--provider", backend]) ++
        (if profile.isEmpty then [] else ["--profile", profile]) ++
        ["--reason", first [reason, "sekreto"]]

      let ran ← runcmd usecommand args

      if 0 == ran.status then return some (dropsuffix ran.out "\n")
      if secretspecmiss ran.why key then return none
      fail ("sekreto: secretspec error: " ++
        (if ran.why.isEmpty then "exit " ++ toString ran.status else ran.why))
    describe := "secretspec" ++ (if backend.isEmpty then "" else ":" ++ backend) }

-- ------------------------------------------------------------------- aws

/-- Region and credentials, from config first and the standard AWS_*
environment variables second - those are AWS's own convention, and a pod
or CI job that has them set should just work. Missing either is an error:
an AWS store with no credentials could not answer. -/
def awsauth (region keyid secret session : String) : IO (String × String × String × String) := do
  let useregion := first [region, ← getenv "AWS_REGION", ← getenv "AWS_DEFAULT_REGION"]
  let usekeyid := first [keyid, ← getenv "AWS_ACCESS_KEY_ID"]
  let usesecret := first [secret, ← getenv "AWS_SECRET_ACCESS_KEY"]
  let usesession := first [session, ← getenv "AWS_SESSION_TOKEN"]

  if useregion.isEmpty then
    fail "sekreto: aws: no region (set region or AWS_REGION)"

  if usekeyid.isEmpty || usesecret.isEmpty then
    fail ("sekreto: aws: no credentials" ++
      " (set keyid/secret or AWS_ACCESS_KEY_ID/AWS_SECRET_ACCESS_KEY)")

  return (useregion, usekeyid, usesecret, usesession)

/-- One signed call to an AWS JSON-1.1 API. -/
def awscall (region keyid secret session addr service target payload : String) : IO Answer := do
  let (useregion, usekeyid, usesecret, usesession) ← awsauth region keyid secret session

  -- The China partition lives under its own suffix; every other
  -- commercial region is plain amazonaws.com.
  let suffix := if useregion.startsWith "cn-" then ".amazonaws.com.cn" else ".amazonaws.com"
  let useaddr := first [addr, "https://" ++ service ++ "." ++ useregion ++ suffix]
  ofResult (checkaddr useaddr)

  let url := trimslash useaddr ++ "/"

  let extras : Pairs String := [
    ("content-type", "application/x-amz-json-1.1"),
    ("x-amz-target", target)]

  let signed := sigv4 {
    method := "POST", url := url, service := service, region := useregion,
    keyid := usekeyid, secret := usesecret, datetime := ← awsnow,
    headers := extras, body := payload, session := usesession }

  fetchjson "POST" url (signed.foldl (fun out kv => Pairs.put out kv.1 kv.2) extras) (some payload)

/-- Does this AWS error body name one of the not-found types? Those are a
miss; every other failure is a store that could not answer. AWS sends
`com.amazonaws...#ResourceNotFoundException`, so this CONTAINS. -/
def awsmiss (body : Option Json) (want : String) : Bool :=
  match OptJson.asstr (OptJson.dig body ["__type"]) with
  | some errtype => hasText errtype want
  | none => false

/-- AWS Secrets Manager.

`api.token` reads the secret named `api` (the vaultref path) and takes the
`token` field of its JSON SecretString - the AWS idiom of one JSON map per
secret. A SecretString that is not JSON is the value itself, under the
conventional field `value`. -/
def awssecretsprovider (region keyid secret session addr : String := "") : Provider := {
  lookup := fun name => do
    let ref ← ofResult (vaultref name)

    let res ← awscall region keyid secret session addr "secretsmanager"
      "secretsmanager.GetSecretValue"
      (Json.stringify (Json.object [("SecretId", Json.str ref.path)]))

    if 400 == res.status && awsmiss res.body "ResourceNotFoundException" then return none
    if 200 != res.status then
      fail ("sekreto: aws secretsmanager error: " ++ toString res.status)

    match OptJson.asstr (OptJson.dig res.body ["SecretString"]) with
    | none =>
      -- A binary secret has no fields to address; only the conventional
      -- `value` field can mean "the bytes themselves".
      match OptJson.asstr (OptJson.dig res.body ["SecretBinary"]) with
      | some encoded =>
        if "value" != ref.field then return none
        match unbase64text encoded with
        | some decoded => return some decoded
        | none => fail "sekreto: aws secretsmanager: undecodable secret"
      | none => return none
    | some text =>
      match Json.parse text with
      | some (.obj fields) => return OptJson.text (Pairs.find? fields ref.field)
      -- A plain-string secret is the whole value; it has no named fields.
      | _ => return (if "value" == ref.field then some text else none)
  -- Config only, never the environment: describe feeds the spec's
  -- sources group, which must answer the same everywhere.
  describe := "awssecrets:" ++ region }

/-- AWS SSM Parameter Store.

`db.pass.main` reads the parameter `/db/pass/main` (under an optional
prefix path), decrypted. Parameter Store carries flat strings, so there
is no field indirection. -/
def awsparamsprovider (region keyid secret session addr pre : String := "") : Provider := {
  lookup := fun name => do
    let payload := Json.object [
      ("Name", Json.str (← ofResult (awsparam name pre))),
      ("WithDecryption", Json.bool true)]

    let res ← awscall region keyid secret session addr "ssm" "AmazonSSM.GetParameter"
      (Json.stringify payload)

    if 400 == res.status && awsmiss res.body "ParameterNotFound" then return none
    if 200 != res.status then fail ("sekreto: aws ssm error: " ++ toString res.status)

    return OptJson.text (OptJson.dig res.body ["Parameter", "Value"])
  describe := "awsparams:" ++ region ++ pre }

-- ------------------------------------------------------------------- gcp

/-- GCP Secret Manager.

`api.token` reads secret `api_token` (dots flattened to `_`; Secret
Manager ids have no hierarchy and reject dots), latest version. The token
comes from config, then `GOOGLE_OAUTH_ACCESS_TOKEN`, then the GCE/GKE
metadata server - so on Google's own platform no credential configuration
is needed at all.

The metadata call is plain http to a link-local host by platform design
and carries no credential, so `checkaddr` guards the Secret Manager
address instead. -/
def gcpsecretsprovider (project token addr metadataaddr : String := "") : IO Provider := do
  let livetoken ← IO.mkRef (none : Option String)
  let renewat ← IO.mkRef NEVER

  let login : IO String := do
    let configured := first [token, ← getenv "GOOGLE_OAUTH_ACCESS_TOKEN"]
    if !configured.isEmpty then return configured

    let host ← getenv "GCE_METADATA_HOST"
    let usemeta := first [metadataaddr,
      if host.isEmpty then "" else "http://" ++ host,
      "http://metadata.google.internal"]

    let url := trimslash usemeta ++
      "/computeMetadata/v1/instance/service-accounts/default/token"
    let res ← fetchjson "GET" url [("Metadata-Flavor", "Google")]

    match OptJson.text (OptJson.dig res.body ["access_token"]) with
    | some value =>
      if 200 != res.status || value.isEmpty then
        fail "sekreto: gcp: no token and metadata server did not answer"
      renewat.set (← Sekreto.renewat (expiryof (OptJson.dig res.body ["expires_in"])))
      return value
    | none => fail "sekreto: gcp: no token and metadata server did not answer"

  return {
    lookup := fun name => do
      if project.isEmpty then fail "sekreto: gcp: no project"

      let useaddr := first [addr, "https://secretmanager.googleapis.com"]
      ofResult (checkaddr useaddr)

      if (← livetoken.get).isNone || (← IO.monoMsNow) ≥ (← renewat.get) then
        livetoken.set (some (← login))

      let url := trimslash useaddr ++ "/v1/projects/" ++ project ++ "/secrets/" ++
        (← ofResult (flatname name "_")) ++ "/versions/latest:access"

      let res ← fetchjson "GET" url [("authorization", "Bearer " ++ ((← livetoken.get).getD ""))]

      if 404 == res.status then return none
      if 200 != res.status then
        fail ("sekreto: gcp error: " ++ toString res.status ++ ": " ++ url)

      match OptJson.asstr (OptJson.dig res.body ["payload", "data"]) with
      | none => return none
      | some data =>
        match unbase64text data with
        | some decoded => return some decoded
        | none => fail "sekreto: gcp: undecodable secret"
    describe := "gcpsecrets:" ++ project }

-- ----------------------------------------------------------------- azure

/-- The Key Vault audience an Azure token is minted for. -/
private def AZURERESOURCE : String := "https://vault.azure.net"

/-- Azure Key Vault.

`api.token` reads secret `api-token` (dots flattened to `-`; Key Vault
names allow nothing else), current version. The token comes from config,
then a client-credentials login when tenant/clientid/clientsecret are
given, then the IMDS managed-identity endpoint.

As with GCP, the IMDS call is plain http to a link-local host by platform
design and carries no credential; the login and vault addresses are
`checkaddr`-guarded. -/
def azuresecretsprovider (vault token tenant clientid clientsecret loginaddr imdsaddr
    apiversion : String := "") : IO Provider := do
  let livetoken ← IO.mkRef (none : Option String)
  let renewat ← IO.mkRef NEVER

  let login : IO String := do
    if !token.isEmpty then return token

    if !tenant.isEmpty && !clientid.isEmpty && !clientsecret.isEmpty then
      let useloginaddr := first [loginaddr, "https://login.microsoftonline.com"]
      ofResult (checkaddr useloginaddr)

      let url := trimslash useloginaddr ++ "/" ++ tenant ++ "/oauth2/v2.0/token"
      let form := "grant_type=client_credentials&client_id=" ++ uriescape clientid ++
        "&client_secret=" ++ uriescape clientsecret ++
        "&scope=" ++ uriescape (AZURERESOURCE ++ "/.default")

      let res ← fetchjson "POST" url
        [("content-type", "application/x-www-form-urlencoded")] (some form)

      match OptJson.text (OptJson.dig res.body ["access_token"]) with
      | some value =>
        if 200 != res.status || value.isEmpty then
          fail ("sekreto: azure login failed: " ++ toString res.status)
        renewat.set (← Sekreto.renewat (expiryof (OptJson.dig res.body ["expires_in"])))
        return value
      | none => fail ("sekreto: azure login failed: " ++ toString res.status)
    else
      let imds := trimslash (first [imdsaddr, "http://169.254.169.254"]) ++
        "/metadata/identity/oauth2/token?api-version=2018-02-01&resource=" ++
        uriescape AZURERESOURCE

      let res ← fetchjson "GET" imds [("Metadata", "true")]

      match OptJson.text (OptJson.dig res.body ["access_token"]) with
      | some value =>
        if 200 != res.status || value.isEmpty then
          fail "sekreto: azure: no token, no client credentials, and IMDS did not answer"
        renewat.set (← Sekreto.renewat (expiryof (OptJson.dig res.body ["expires_in"])))
        return value
      | none => fail "sekreto: azure: no token, no client credentials, and IMDS did not answer"

  return {
    lookup := fun name => do
      if vault.isEmpty then fail "sekreto: azure: no vault"

      -- Only an explicit scheme is a URL; a vault NAMED httpvault must
      -- still become https://httpvault.vault.azure.net.
      let vaulturl :=
        if vault.startsWith "http://" || vault.startsWith "https://" then vault
        else "https://" ++ vault ++ ".vault.azure.net"
      ofResult (checkaddr vaulturl)

      if (← livetoken.get).isNone || (← IO.monoMsNow) ≥ (← renewat.get) then
        livetoken.set (some (← login))

      let url := trimslash vaulturl ++ "/secrets/" ++ (← ofResult (flatname name "-")) ++
        "?api-version=" ++ first [apiversion, "7.4"]

      let res ← fetchjson "GET" url [("authorization", "Bearer " ++ ((← livetoken.get).getD ""))]

      if 404 == res.status then return none
      if 200 != res.status then
        fail ("sekreto: azure error: " ++ toString res.status ++ ": " ++ bareurl url)

      return OptJson.text (OptJson.dig res.body ["value"])
    describe := "azuresecrets:" ++ vault }

-- ----------------------------------------------------------- 1password

/-- 1Password, through a Connect server.

The item titled `api.token` (titles keep their dots), in the named vault.
The value is the field with purpose PASSWORD, or the field labelled
`value`. A VAULT THAT CANNOT BE FOUND IS AN ERROR - config names it, so
its absence is a broken store, not a missing secret. -/
def onepasswordprovider (addr token vault : String := "") : IO Provider := do
  let vaultid ← IO.mkRef (none : Option String)

  let auth : Pairs String := [("authorization", "Bearer " ++ token)]

  let resolvevault (useaddr : String) : IO String := do
    if vault.isEmpty then fail "sekreto: onepassword: no vault"

    let res ← fetchjson "GET" (useaddr ++ "/v1/vaults") auth

    match OptJson.asarr res.body with
    | none => fail ("sekreto: onepassword error: " ++ toString res.status ++ ": listing vaults")
    | some list =>
      if 200 != res.status then
        fail ("sekreto: onepassword error: " ++ toString res.status ++ ": listing vaults")
      match list.find? (fun entry =>
          OptJson.text (entry.get? "id") == some vault ||
          OptJson.text (entry.get? "name") == some vault) with
      | some entry => return (OptJson.text (entry.get? "id")).getD ""
      | none => fail ("sekreto: onepassword: no vault named " ++ vault)

  return {
    lookup := fun name => do
      let _ ← ofResult (checkname name)

      let useaddr := trimslash addr
      if useaddr.isEmpty then fail "sekreto: onepassword: no addr"
      ofResult (checkaddr useaddr)

      let id ← match ← vaultid.get with
        | some held => pure held
        | none =>
          let found ← resolvevault useaddr
          vaultid.set (some found)
          pure found

      let filter := uriescape ("title eq \"" ++ name ++ "\"")
      let found ← fetchjson "GET" (useaddr ++ "/v1/vaults/" ++ id ++ "/items?filter=" ++ filter) auth

      match OptJson.asarr found.body with
      | none => fail ("sekreto: onepassword error: " ++ toString found.status ++ ": finding " ++ name)
      | some items =>
        if 200 != found.status then
          fail ("sekreto: onepassword error: " ++ toString found.status ++ ": finding " ++ name)
        match items with
        | [] => return none
        | head :: _ =>
          let itemid := (OptJson.text (head.get? "id")).getD ""
          let item ← fetchjson "GET" (useaddr ++ "/v1/vaults/" ++ id ++ "/items/" ++ itemid) auth
          if 200 != item.status then
            fail ("sekreto: onepassword error: " ++ toString item.status ++ ": reading " ++ name)

          let fields := (OptJson.asarr (OptJson.dig item.body ["fields"])).getD []

          -- Two full passes, in this order.
          match fields.find? (fun field => OptJson.asstr (field.get? "purpose") == some "PASSWORD") with
          | some field => return OptJson.text (field.get? "value")
          | none =>
            match fields.find? (fun field => OptJson.asstr (field.get? "label") == some "value") with
            | some field => return OptJson.text (field.get? "value")
            | none => return none
    describe := "onepassword:" ++ vault }

-- --------------------------------------------------------------- doppler

/-- Doppler.

The whole config is downloaded once - Doppler's own bulk endpoint - and
answered from memory, like a remote .env: `api.token` is the `API_TOKEN`
entry. A FAILED LOAD CACHES NOTHING, so it is retried. -/
def dopplerprovider (token project config addr : String := "") : IO Provider := do
  let cell ← IO.mkRef (none : Option (Pairs String))

  let load : IO (Pairs String) := do
    match ← cell.get with
    | some held => return held
    | none =>
      let useaddr := trimslash (first [addr, "https://api.doppler.com"])
      ofResult (checkaddr useaddr)

      let url := useaddr ++ "/v3/configs/config/secrets/download?format=json" ++
        (if project.isEmpty then "" else "&project=" ++ uriescape project) ++
        (if config.isEmpty then "" else "&config=" ++ uriescape config)

      let res ← fetchjson "GET" url [("authorization", "Bearer " ++ token)]

      match OptJson.asobj res.body with
      | none => fail ("sekreto: doppler error: " ++ toString res.status)
      | some body =>
        if 200 != res.status then fail ("sekreto: doppler error: " ++ toString res.status)
        let loaded := body.foldl (fun out kv =>
          match Json.text kv.2 with
          | some value => Pairs.put out kv.1 value
          | none => out) ([] : Pairs String)
        cell.set (some loaded)
        return loaded

  return {
    -- The `prefix` option is not consulted by this kind.
    lookup := fun name => do return Pairs.find? (← load) (← ofResult (envkey name))
    describe := "doppler" ++
      (if project.isEmpty then "" else ":" ++ project ++ "/" ++ config) }

-- ------------------------------------------------------------- infisical

/-- Infisical.

`api.token` reads the secret keyed `API_TOKEN` at a secret path in one
environment of a project. Auth is a token, or a universal-auth (machine
identity) login with clientid/clientsecret - whose expiry field is
`expiresIn`, camelCase, unlike everyone else's `expires_in`. -/
def infisicalprovider (addr token clientid clientsecret project environment
    path : String := "") : IO Provider := do
  let livetoken ← IO.mkRef (none : Option String)
  let renewat ← IO.mkRef NEVER

  let login (useaddr : String) : IO String := do
    if !token.isEmpty then return token

    if clientid.isEmpty || clientsecret.isEmpty then
      fail "sekreto: infisical: no token and no client credentials"

    let body := Json.object [
      ("clientId", Json.str clientid),
      ("clientSecret", Json.str clientsecret)]

    let res ← fetchjson "POST" (useaddr ++ "/api/v1/auth/universal-auth/login")
      [("content-type", "application/json")] (some (Json.stringify body))

    match OptJson.text (OptJson.dig res.body ["accessToken"]) with
    | some value =>
      if 200 != res.status || value.isEmpty then
        fail ("sekreto: infisical login failed: " ++ toString res.status)
      renewat.set (← Sekreto.renewat (expiryof (OptJson.dig res.body ["expiresIn"])))
      return value
    | none => fail ("sekreto: infisical login failed: " ++ toString res.status)

  return {
    lookup := fun name => do
      let useaddr := trimslash (first [addr, "https://app.infisical.com"])
      ofResult (checkaddr useaddr)

      if project.isEmpty || environment.isEmpty then
        fail "sekreto: infisical: no project/environment"

      if (← livetoken.get).isNone || (← IO.monoMsNow) ≥ (← renewat.get) then
        livetoken.set (some (← login useaddr))

      -- envkey here takes NO prefix.
      let url := useaddr ++ "/api/v3/secrets/raw/" ++ (← ofResult (envkey name)) ++
        "?workspaceId=" ++ uriescape project ++
        "&environment=" ++ uriescape environment ++
        "&secretPath=" ++ uriescape (first [path, "/"])

      let res ← fetchjson "GET" url [("authorization", "Bearer " ++ ((← livetoken.get).getD ""))]

      if 404 == res.status then return none
      if 200 != res.status then fail ("sekreto: infisical error: " ++ toString res.status)

      return OptJson.text (OptJson.dig res.body ["secret", "secretValue"])
    describe := "infisical:" ++ project ++ "/" ++ environment }

-- ------------------------------------------------------------------ make

/-- Build a provider from its declarative form - the same shape the
shared spec and an app's config file use. -/
def makeprovider (spec : ProviderSpec) : IO Provider :=
  if "env" == spec.kind then pure (envprovider spec.«prefix»)
  else if "dotenv" == spec.kind then
    dotenvprovider (if spec.file.isEmpty then ".env" else spec.file) spec.«prefix»
  else if "memory" == spec.kind then pure (memoryprovider spec.values spec.«prefix»)
  else if "file" == spec.kind then pure (fileprovider spec.dir spec.«prefix»)
  else if "hashicorp" == spec.kind then
    hashicorpprovider spec.addr spec.token spec.mount spec.vaultnamespace spec.kv spec.auth
  else if "boru" == spec.kind then
    pure (boruprovider spec.command spec.«namespace» spec.home spec.addr spec.token spec.mount)
  else if "secretspec" == spec.kind then
    pure (secretspecprovider spec.command spec.file spec.profile spec.backend spec.reason
      spec.«prefix»)
  else if "awssecrets" == spec.kind then
    pure (awssecretsprovider spec.region spec.keyid spec.secret spec.session spec.addr)
  else if "awsparams" == spec.kind then
    pure (awsparamsprovider spec.region spec.keyid spec.secret spec.session spec.addr spec.«prefix»)
  else if "gcpsecrets" == spec.kind then
    gcpsecretsprovider spec.project spec.token spec.addr spec.metadataaddr
  else if "azuresecrets" == spec.kind then
    azuresecretsprovider spec.vault spec.token spec.tenant spec.clientid spec.clientsecret
      spec.loginaddr spec.imdsaddr spec.apiversion
  else if "onepassword" == spec.kind then
    onepasswordprovider spec.addr spec.token spec.vault
  else if "doppler" == spec.kind then
    dopplerprovider spec.token spec.project spec.config spec.addr
  else if "infisical" == spec.kind then
    infisicalprovider spec.addr spec.token spec.clientid spec.clientsecret spec.project
      spec.environment spec.path
  else fail ("sekreto: unknown provider kind: " ++ spec.kind)

/-- Make a Sekreto from declarative provider specs - the same shape the
shared spec and an app's config file use.

Eager, in chain order, and it may refuse: `hashicorp`'s KV version is
checked here, before anything is looked up. Construction contacts
nothing; the first network call is the first lookup. -/
def sekreto (specs : List ProviderSpec) (cache : Bool := true) : IO Sekreto := do
  let mut providers : List Provider := []
  for spec in specs do
    providers := providers ++ [← makeprovider spec]
  Sekreto.make providers (specs.map (fun spec => some spec.name)) cache

end Sekreto
