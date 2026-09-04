(* The providers a Sekreto chains together.

   A provider answers one question: "do you have this secret?" It answers
   with the value, or None to mean "ask the next one".

   Two failure shapes, and they are never interchangeable. A store that does
   not hold the secret is a MISS (None) - the chain carries on. A store that
   could not answer - bad credentials, unreachable host, missing
   configuration - is an ERROR: falling through there would quietly reach
   for a weaker store, which is the worst failure this library has.

   A port of typescript/src/Providers.ts, which is canonical. *)

open Sekreto

(* ---- the declarative form -------------------------------------------- *)

(* Logging in to a vault instead of being handed a token. `amethod` is
   `kubernetes` or `approle`; `amount` defaults to the method name. *)
type authspec = {
  amethod : string;
  amount : string;
  (* kubernetes: the Vault role to log in as. *)
  role : string;
  (* kubernetes: the service-account JWT itself (tests). *)
  jwt : string;
  (* kubernetes: where the JWT lives; the conventional pod path by default. *)
  jwtfile : string;
  (* approle: the role and secret ids. *)
  roleid : string;
  secretid : string;
}

let noauth =
  { amethod = ""; amount = ""; role = ""; jwt = ""; jwtfile = ""; roleid = ""; secretid = "" }

(* What a credential field reports about itself. *)
let setornot (value : string) : string = if "" = value then "[unset]" else "[set]"

(* Printed without its credentials.

   A derived printer would put the service-account JWT and the AppRole
   secret id into `Printf.eprintf "bad chain: %s"`, which is what someone
   writes when a chain will not build. *)
let authtostring (auth : authspec) : string =
  Printf.sprintf "AuthSpec(method=%s, mount=%s, role=%s, jwtfile=%s, roleid=%s, jwt=%s, secretid=%s)"
    auth.amethod auth.amount auth.role auth.jwtfile auth.roleid (setornot auth.jwt)
    (setornot auth.secretid)

(* The declarative form of a provider, as used in config and in the shared
   spec. `kind` picks the provider; everything else is that kind's own.

   String fields carry an empty-string default rather than an option:
   "not configured" and "configured empty" mean the same thing everywhere in
   this library. `kv` is the only number and `values` the only map - and it
   is an ordered association list, not a hash table, because the spec
   compares whole maps. *)
type spec = {
  kind : string;
  (* The store name `getfrom` addresses. Defaults to `kind`. *)
  name : string;
  prefix : string;
  (* dotenv: the file to read. secretspec: the declaration to read. *)
  file : string;
  (* memory: literal values, keyed like environment variables. *)
  values : (string * string) list;
  (* file: the directory of one-secret-per-file entries. *)
  dir : string;
  (* hashicorp / boru (wire) / gcp / 1password / doppler / infisical: the base URL. *)
  addr : string;
  token : string;
  (* hashicorp / boru (wire): the KV mount (default `secret`). *)
  mount : string;
  (* hashicorp: KV engine version, 1 or 2 (default 2). *)
  kv : int;
  (* hashicorp: Vault Enterprise namespace (X-Vault-Namespace). *)
  vaultnamespace : string;
  (* hashicorp: log in for a token instead of being handed one. *)
  auth : authspec option;
  (* boru / secretspec: the executable to run. *)
  command : string;
  (* secretspec: the profile to read. *)
  profile : string;
  (* secretspec: which of ITS backends to read from, named `backend` here
     because `provider` already means a sekreto provider. *)
  backend : string;
  (* secretspec: the audit reason recorded for the read. *)
  reason : string;
  (* boru: the namespace qualifying the alias, and the vault home. *)
  namespace : string;
  home : string;
  (* aws: region and credentials; the standard AWS_* variables fill the rest. *)
  region : string;
  keyid : string;
  secret : string;
  session : string;
  (* gcp / doppler / infisical: the project, however that store names it. *)
  project : string;
  (* azure: the Key Vault name or full URL. 1password: the vault name or id. *)
  vault : string;
  (* azure: client-credential login. infisical: universal-auth login. *)
  tenant : string;
  clientid : string;
  clientsecret : string;
  (* azure: where to log in / where IMDS answers. gcp: the metadata server. *)
  loginaddr : string;
  imdsaddr : string;
  metadataaddr : string;
  (* azure: the Key Vault API version (default 7.4). *)
  apiversion : string;
  (* doppler: the config slug (with `project`). *)
  config : string;
  (* infisical: the environment slug and secret path. *)
  environment : string;
  secretpath : string;
}

let nospec =
  {
    kind = "";
    name = "";
    prefix = "";
    file = "";
    values = [];
    dir = "";
    addr = "";
    token = "";
    mount = "";
    kv = 2;
    vaultnamespace = "";
    auth = None;
    command = "";
    profile = "";
    backend = "";
    reason = "";
    namespace = "";
    home = "";
    region = "";
    keyid = "";
    secret = "";
    session = "";
    project = "";
    vault = "";
    tenant = "";
    clientid = "";
    clientsecret = "";
    loginaddr = "";
    imdsaddr = "";
    metadataaddr = "";
    apiversion = "";
    config = "";
    environment = "";
    secretpath = "";
  }

(* Printed without its credentials. See authtostring: the obvious printer
   would put the Vault token, the AWS secret access key and the Azure client
   secret into whatever formatted it. *)
let spectostring (spec : spec) : string =
  Printf.sprintf "ProviderSpec(kind=%s, name=%s, addr=%s, token=%s, secret=%s, clientsecret=%s, auth=%s)"
    spec.kind spec.name spec.addr (setornot spec.token) (setornot spec.secret)
    (setornot spec.clientsecret)
    (match spec.auth with None -> "none" | Some auth -> authtostring auth)

(* ---- shared machinery ------------------------------------------------ *)

let getenv (name : string) : string =
  match Sys.getenv_opt name with Some value -> value | None -> ""

(* The first candidate that is set and non-empty, or empty. *)
let firstof (candidates : string list) : string =
  match List.find_opt (fun value -> "" <> value) candidates with Some value -> value | None -> ""

let trimslash (text : string) : string = dropsuffix text "/"

(* A url without its query string, for a message that must not leak one. *)
let bare = Http.bare

(* An address with any userinfo replaced by `[redacted]`, for messages.

   Every refusal below names the address it refused, and one of them fires
   precisely because the address carries a credential - so printing it
   verbatim would write the password to stderr and into the logs. It cannot
   be cleaned up afterwards either: that password was never resolved as a
   secret, so `redact` has never seen it and never will. *)
let safeaddr (addr : string) : string =
  match Sigv4.findsub addr "://" with
  | None -> addr
  | Some mark ->
    let rest = String.sub addr (mark + 3) (String.length addr - mark - 3) in
    let stop = match Sigv4.splitfirst rest "/?#" with Some at -> at | None -> String.length rest in
    let authority = String.sub rest 0 stop in
    (match String.rindex_opt authority '@' with
    | None -> addr
    | Some at ->
      String.sub addr 0 (mark + 3)
      ^ "[redacted]"
      ^ String.sub addr (mark + 3 + at) (String.length addr - mark - 3 - at))

(* Refuse to send a secret-bearing credential in the clear.

   A vault API is HTTPS in any real deployment; plaintext is a dev-mode
   convenience. Sending a token over http to anything but the local machine
   puts both the token and the secret it fetches on the wire for anyone on
   the path, so sekreto will not do it. Loopback stays allowed: that is
   `vault server -dev`, `boru vault serve`, and this repo's own harness.

   The address is read by hand, in the same handful of steps in every port,
   rather than by each platform's URL parser. A dozen parsers disagree about
   malformed input - where userinfo ends, whether `0177.0.0.1` is loopback,
   what an unclosed bracket means - and a check that answers differently in
   different ports is not a check.

   The rule this parse obeys: it is never MORE PERMISSIVE than the client
   that will dial the address. It ends the authority at `/`, `?` or `#`
   only, so a client that also breaks on a backslash can only ever see a
   shorter host than this does. It refuses userinfo outright rather than
   locating its end. It compares the host literally, so a numeric form no
   parser here agrees on is refused rather than guessed at. *)
let checkaddr (addr : string) : unit =
  let scheme =
    if String.starts_with ~prefix:"https://" addr then "https://"
    else if String.starts_with ~prefix:"http://" addr then "http://"
    else fail ("sekreto: not an http(s) address: " ^ safeaddr addr)
  in

  let rest = String.sub addr (String.length scheme) (String.length addr - String.length scheme) in
  let stop = match Sigv4.splitfirst rest "/?#" with Some at -> at | None -> String.length rest in
  let authority = String.sub rest 0 stop in

  (* Userinfo is refused outright rather than parsed around, and on https as
     well as http. No store this library speaks authenticates by userinfo -
     they take a token or a signature - so an address carrying one is a
     mistake at best. At worst it is the attack this whole function exists
     to stop: `http://localhost:8200@evil.example.com/` is a request to
     evil.example.com that reads, to anything splitting the authority on a
     colon, as loopback. *)
  if String.contains authority '@' then
    fail ("sekreto: refusing an address with embedded credentials: " ^ safeaddr addr);

  (* An opening bracket with no closing one is not an address at all. *)
  if String.length authority > 0 && '[' = authority.[0] && not (String.contains authority ']') then
    fail ("sekreto: not a valid http(s) address: " ^ safeaddr addr);

  if "https://" <> scheme then begin
    (* A bracketed IPv6 literal keeps its brackets. Splitting the authority
       on the first colon yields `[`, which could never match the allowlist
       and refused a legitimate local vault. *)
    let host =
      String.lowercase_ascii
        (if String.length authority > 0 && '[' = authority.[0] then
           String.sub authority 0 (String.index authority ']' + 1)
         else
           match String.index_opt authority ':' with
           | Some at -> String.sub authority 0 at
           | None -> authority)
    in

    (* Literal, and exactly four entries. Nothing is normalised, so
       `0177.0.0.1`, `2130706433`, `127.0.0.2` and `[::ffff:127.0.0.1]` are
       all refused rather than guessed at. *)
    if "localhost" <> host && "127.0.0.1" <> host && "::1" <> host && "[::1]" <> host then
      fail ("sekreto: refusing to send a token in plaintext to " ^ safeaddr addr ^ " (use https)")
  end

(* One JSON round-trip's result: the status, and the parsed body. *)
type answer = { status : int; jbody : Json.t option }

(* One JSON round-trip. Network failure is always an error - an unreachable
   store is a store that could not answer, never a store without the
   secret. *)
let fetchjson ?(headers = []) ?body (meth : string) (url : string) : answer =
  let res = Http.request meth url headers body in
  let parsed = Json.parse res.Http.body in

  (* A success status promised JSON; a body that does not parse means the
     store could not answer coherently, and treating it as a miss would fall
     through to a weaker store. Error statuses may carry any body - they are
     decided on status alone. *)
  if 200 = res.Http.status && None = parsed then
    fail ("sekreto: malformed response from " ^ bare url);

  { status = res.Http.status; jbody = parsed }

(* When a logged-in token must be renewed, from its expiry in seconds (a
   JSON number, or a string as Azure IMDS sends it): now + max(seconds - 60,
   1). A missing or zero expiry means never renew. *)
let never = infinity

let renewtime (expires : Json.t option) : float =
  let seconds =
    match expires with
    | Some (Json.Num value) -> value
    | Some (Json.Str value) -> ( match float_of_string_opt value with Some v -> v | None -> 0.0)
    | _ -> 0.0
  in
  if Float.is_nan seconds || 0.0 >= seconds then never
  else (Unix.gettimeofday () *. 1000.0) +. (Float.max (seconds -. 60.0) 1.0 *. 1000.0)

let nowms () : float = Unix.gettimeofday () *. 1000.0

(* Read a whole file, letting the platform's own error code through so that
   the caller can tell "no secrets here" from "I could not answer". *)
let readfile (path : string) : string =
  let fd = Unix.openfile path [ Unix.O_RDONLY ] 0 in
  Fun.protect
    ~finally:(fun () -> try Unix.close fd with _ -> ())
    (fun () ->
      let out = Buffer.create 4096 in
      let chunk = Bytes.create 65536 in
      let rec loop () =
        let got = Unix.read fd chunk 0 65536 in
        if 0 < got then begin
          Buffer.add_subbytes out chunk 0 got;
          loop ()
        end
      in
      loop ();
      Buffer.contents out)

(* Does this read failure mean "no secrets here" rather than "I could not
   answer"?

   Absence is a MISS and the chain carries on; anything else - permission
   denied, an unreadable mount, a failing disk - is an ERROR, because
   returning a miss there falls silently through to a weaker store. Keyed on
   the platform's not-found codes rather than on an `exists` predicate,
   which answers false for a permission error and would turn a locked mount
   into a miss. *)
let notfound (err : Unix.error) : bool = Unix.ENOENT = err || Unix.ENOTDIR = err

(* Join a directory and a file name. `Filename.concat` would turn an empty
   directory into a leading slash and read from the root. *)
let joinpath (dir : string) (name : string) : string =
  if "" = dir then name else Filename.concat dir name

(* ---- the subprocess runner ------------------------------------------- *)

type ran = { out : string; why : string; status : int }

(* Where a command lives, or nowhere.

   Resolved before forking: OCaml's `create_process` execs in the child, so
   a command that is not there makes the child exit 127 with no error in the
   parent - which is indistinguishable from a command that ran and failed.
   "cannot run" and "the store said no" are different answers. *)
let findexe (command : string) : string option =
  let executable path = match Unix.access path [ Unix.X_OK ] with () -> true | exception _ -> false in

  if String.contains command '/' then if executable command then Some command else None
  else
    let path = match Sys.getenv_opt "PATH" with Some value -> value | None -> "/usr/bin:/bin" in
    let rec walk = function
      | [] -> None
      | dir :: rest ->
        let cand = (if "" = dir then "." else dir) ^ "/" ^ command in
        if executable cand then Some cand else walk rest
    in
    walk (String.split_on_char ':' path)

(* Run a child to completion and collect both its streams.

   The two streams are drained CONCURRENTLY, through one select loop.
   Reading stdout to EOF and only then reading stderr deadlocks the moment
   the child writes more than one pipe buffer (64 KiB on Linux) to stderr:
   the parent is blocked waiting for stdout, the child is blocked waiting
   for room on stderr, and neither can move. Nothing here sets a timeout, so
   that hang is permanent - `get` simply never returns. secretspec's
   diagnostics are box-drawn and reach that size easily.

   The child's stdin is closed rather than left open on a pipe nobody writes
   to, so a CLI that reads it - one prompting for a passphrase when its
   environment variable is absent - sees EOF and gives up instead of waiting
   forever.

   Arguments go as an array, never through a shell, and no secret is ever
   put on a command line where the process table would publish it. *)
let runcmd (argv : string list) (env : string array) (command : string) : ran =
  let exe =
    match findexe command with
    | Some path -> path
    | None -> fail ("sekreto: cannot run " ^ command ^ ": No such file or directory")
  in

  let outr, outw = Unix.pipe () in
  let errr, errw = Unix.pipe () in
  let inr, inw = Unix.pipe () in
  Unix.close inw;

  let pid =
    match Unix.create_process_env exe (Array.of_list argv) env inr outw errw with
    | pid -> pid
    | exception Unix.Unix_error (err, _, _) ->
      List.iter (fun fd -> try Unix.close fd with _ -> ()) [ inr; outr; outw; errr; errw ];
      fail ("sekreto: cannot run " ^ command ^ ": " ^ Unix.error_message err)
  in

  Unix.close inr;
  Unix.close outw;
  Unix.close errw;

  let obuf = Buffer.create 4096 and ebuf = Buffer.create 4096 in
  let live = ref [ outr; errr ] in
  let chunk = Bytes.create 65536 in

  while [] <> !live do
    let ready, _, _ = Unix.select !live [] [] (-1.0) in
    List.iter
      (fun fd ->
        let got = try Unix.read fd chunk 0 65536 with Unix.Unix_error _ -> 0 in
        if 0 = got then begin
          (try Unix.close fd with _ -> ());
          live := List.filter (fun other -> other <> fd) !live
        end
        else Buffer.add_subbytes (if fd = outr then obuf else ebuf) chunk 0 got)
      ready
  done;

  let status = match snd (Unix.waitpid [] pid) with
    | Unix.WEXITED code -> code
    | Unix.WSIGNALED code | Unix.WSTOPPED code -> 128 + code
  in

  { out = Buffer.contents obuf; why = trim (Buffer.contents ebuf); status }

(* ---- the four built-in kinds ------------------------------------------

   The criterion for "built in": needs nothing of the platform beyond
   reading a local file - no socket, no TLS, no crypto, no child process. *)

(* Environment variables: `api.token` from `API_TOKEN`. *)
let env_provider ?(source : (string * string) list option) (prefix : string) : provider =
  {
    lookup =
      (fun name ->
        let key = envkey ~prefix name in
        match source with None -> Sys.getenv_opt key | Some values -> List.assoc_opt key values);
    describe = (fun () -> if "" = prefix then "env" else "env:" ^ prefix);
  }

(* Literal values, keyed like environment variables. The spec uses this to
   test chain behaviour without touching the outside world. *)
let memory_provider (values : (string * string) list) (prefix : string) : provider =
  {
    lookup = (fun name -> List.assoc_opt (envkey ~prefix name) values);
    describe = (fun () -> if "" = prefix then "memory" else "memory:" ^ prefix);
  }

(* A `.env` file, read ONCE, LAZILY, keyed exactly like the environment.

   Lazy is required, not a nicety: the `stores` corpus group puts a dotenv
   provider in a chain and never looks anything up, so an eager constructor
   would read whatever `.env` happens to sit in the working directory. *)
let dotenv_provider (file : string) (prefix : string) : provider =
  let values = ref None in

  let load () =
    match !values with
    | Some loaded -> loaded
    | None ->
      let loaded =
        match parsedotenv (readfile file) with
        | parsed -> parsed
        (* An absent file - or an absent directory - means "no secrets
           here", exactly like the file provider. *)
        | exception Unix.Unix_error (err, _, _) when notfound err -> []
        | exception Unix.Unix_error (err, _, _) ->
          fail ("sekreto: dotenv provider cannot read " ^ file ^ ": " ^ Unix.error_message err)
      in
      values := Some loaded;
      loaded
  in

  {
    lookup = (fun name -> List.assoc_opt (envkey ~prefix name) (load ()));
    describe = (fun () -> "dotenv:" ^ file);
  }

(* A directory of one-secret-per-file entries, keyed like the environment:
   `api.token` reads `<dir>/API_TOKEN`.

   This is the shape of a mounted Kubernetes Secret, a Docker or Swarm
   secret, and a systemd credentials directory, so those all work with no
   further configuration. Read on every lookup, never cached - a mounted
   secret is rotated underneath a running process. One trailing newline is
   stripped: tools that write these files disagree about it, and a newline
   is never part of a secret on purpose. *)
let file_provider (dir : string) (prefix : string) : provider =
  {
    lookup =
      (fun name ->
        let path = joinpath dir (envkey ~prefix name) in
        match readfile path with
        | body ->
          let body =
            if String.ends_with ~suffix:"\r\n" body then String.sub body 0 (String.length body - 2)
            else if String.ends_with ~suffix:"\n" body then String.sub body 0 (String.length body - 1)
            else body
          in
          Some body
        | exception Unix.Unix_error (err, _, _) when notfound err -> None
        | exception Unix.Unix_error (err, _, _) ->
          fail ("sekreto: file provider cannot read " ^ path ^ ": " ^ Unix.error_message err));
    describe = (fun () -> "file:" ^ dir);
  }

(* ---- reading a response ---------------------------------------------- *)

(* The text at a path in a response body, or nothing. A JSON null is nothing
   - a null field is a miss, never the string `null`. *)
let digtext (body : Json.t option) (keys : string list) : string option =
  Json.otext (Json.odig body keys)

(* The string at a path, insisting it really is a string: `__type` must be
   one, a 1Password vault list must be an array, a Doppler config an
   object. *)
let digstr (body : Json.t option) (keys : string list) : string option =
  Json.oasstr (Json.odig body keys)

let isset (value : string option) : bool =
  match value with Some text -> "" <> text | None -> false

(* ---- hashicorp -------------------------------------------------------- *)

(* HashiCorp Vault.

   KV v2 (the default): `api.token` reads `{addr}/v1/{mount}/data/api` and
   takes the `token` field of `data.data`. KV v1 reads
   `{addr}/v1/{mount}/api` and takes the field of `data`. A 404 means "not
   here" - a miss - so a vault can sit in a chain with fallbacks.

   A Vault Enterprise namespace rides the X-Vault-Namespace header, on
   logins as well as reads.

   Instead of being handed a token, the provider can log in: Kubernetes auth
   (the pod's service-account JWT, from its conventional path) or AppRole. A
   failed login is an error, never a miss - it means this store could not
   answer at all. *)
let hashicorp_provider (addr : string) (token : string) (mountgiven : string) (kv : int)
    (vaultnamespace : string) (auth : authspec option) : provider =
  let mount = if "" = mountgiven then "secret" else mountgiven in

  (* A version typo like kv: 3 must not quietly behave as v2 and turn its
     404s into misses; there is nothing safe to assume it meant. *)
  if 1 <> kv && 2 <> kv then
    fail ("sekreto: hashicorp: unsupported kv version: " ^ string_of_int kv);

  (* The working token: a configured token is kept forever, a logged-in one
     is renewed shortly before its lease runs out - a long-running process
     must not keep presenting a token the vault already expired. *)
  let livetoken = ref (if "" = token then None else Some token) in
  let renewat = ref never in

  let baseheaders () =
    if "" = vaultnamespace then [] else [ ("X-Vault-Namespace", vaultnamespace) ]
  in

  let login () =
    let use = match auth with
      | Some use -> use
      | None -> fail "sekreto: hashicorp: no token and no auth method"
    in

    let authmount = firstof [ use.amount; use.amethod ] in
    let url = trimslash addr ^ "/v1/auth/" ^ authmount ^ "/login" in

    let body =
      match use.amethod with
      | "kubernetes" ->
        let jwt =
          if "" <> use.jwt then use.jwt
          else begin
            let path =
              if "" = use.jwtfile then "/var/run/secrets/kubernetes.io/serviceaccount/token"
              else use.jwtfile
            in
            match readfile path with
            | text -> trim text
            | exception Unix.Unix_error _ ->
              fail ("sekreto: hashicorp: cannot read jwt file " ^ path)
          end
        in
        Json.obj [ ("role", Json.str use.role); ("jwt", Json.str jwt) ]
      | "approle" ->
        Json.obj [ ("role_id", Json.str use.roleid); ("secret_id", Json.str use.secretid) ]
      | other -> fail ("sekreto: hashicorp: unknown auth method: " ^ other)
    in

    let res = fetchjson ~headers:(baseheaders ()) ~body:(Json.stringify body) "POST" url in
    let got = digtext res.jbody [ "auth"; "client_token" ] in

    if 200 <> res.status || not (isset got) then
      fail ("sekreto: hashicorp login failed: " ^ string_of_int res.status ^ ": " ^ url);

    renewat := renewtime (Json.odig res.jbody [ "auth"; "lease_duration" ]);
    Option.get got
  in

  {
    lookup =
      (fun name ->
        checkaddr addr;

        if None = !livetoken || nowms () >= !renewat then livetoken := Some (login ());

        let ref_ = vaultref name in
        let base = trimslash addr ^ "/v1/" ^ mount in
        let url = if 1 = kv then base ^ "/" ^ ref_.path else base ^ "/data/" ^ ref_.path in

        let headers =
          baseheaders () @ [ ("X-Vault-Token", Option.value ~default:"" !livetoken) ]
        in

        let res = fetchjson ~headers "GET" url in

        if 404 = res.status then None
        else if 200 <> res.status then
          fail ("sekreto: hashicorp error: " ^ string_of_int res.status ^ ": " ^ url)
        else
          let data = if 1 = kv then Json.odig res.jbody [ "data" ] else Json.odig res.jbody [ "data"; "data" ] in
          digtext data [ ref_.field ]);
    describe = (fun () -> "hashicorp:" ^ addr ^ "/" ^ mount);
  }

(* ---- boru -------------------------------------------------------------- *)

(* Does this boru failure mean "no such secret" rather than "I could not
   answer"? Matched on boru's own wording for a missing alias: a locked
   vault or a wrong passphrase is not a miss, and treating it as one would
   fall through to a weaker store without saying so. *)
let borumiss (why : string) : bool = None <> Sigv4.findsub why "no alias named"

(* A boru vault (https://github.com/boru-lang/boru).

   Two ways in, both boru's own.

   With no `addr`, the CLI: `boru vault get --reveal <alias>` prints the
   secret on stdout and nothing else. The passphrase is read by boru itself
   from BORU_VAULT_PASSPHRASE; sekreto never accepts it as config and never
   puts it on a command line, where it would show up in the process table.

   With an `addr`, boru's wire protocol: a read-only, HashiCorp-shaped
   provision API authenticated by a capability token. A sekreto name is
   already a valid boru alias, and boru aliases KEEP THEIR DOTS, so
   `api.token` is the single path segment `api.token` - not the `api`/`token`
   split a HashiCorp KV gets. The value is the `value` field. *)
let boru_provider (commandgiven : string) (namespace : string) (home : string)
    (addrgiven : string) (token : string) (mountgiven : string) : provider =
  let command = if "" = commandgiven then "boru" else commandgiven in
  let addr = trimslash addrgiven in
  let mount = if "" = mountgiven then "secret" else mountgiven in

  let wirelookup name =
    checkaddr addr;

    let alias = if "" = namespace then name else namespace ^ "/" ^ name in
    let url = addr ^ "/v1/" ^ mount ^ "/data/" ^ alias in

    let res = fetchjson ~headers:[ ("X-Vault-Token", token) ] "GET" url in

    if 404 = res.status then None
    else if 200 <> res.status then
      fail ("sekreto: boru serve error: " ^ string_of_int res.status ^ ": " ^ url)
    else digtext res.jbody [ "data"; "data"; "value" ]
  in

  {
    lookup =
      (fun name ->
        ignore (checkname name);

        if "" <> addr then wirelookup name
        else begin
          let alias = if "" = namespace then name else namespace ^ ":" ^ name in
          let env =
            if "" = home then Unix.environment ()
            else
              Array.append
                (Array.of_list
                   (List.filter
                      (fun entry -> not (String.starts_with ~prefix:"BORU_HOME=" entry))
                      (Array.to_list (Unix.environment ()))))
                [| "BORU_HOME=" ^ home |]
          in

          let ran = runcmd [ command; "vault"; "get"; "--reveal"; alias ] env command in

          if 0 = ran.status then
            (* boru prints the value and one newline, and nothing else. *)
            Some (dropsuffix ran.out "\n")
          else if borumiss ran.why then None
          else
            fail
              ("sekreto: boru vault error: "
              ^ if "" = ran.why then "exit " ^ string_of_int ran.status else ran.why)
        end);
    describe =
      (fun () ->
        if "" <> addr then "boru:" ^ addr
        else if "" = namespace then "boru"
        else "boru:" ^ namespace);
  }

(* ---- secretspec --------------------------------------------------------- *)

(* Does this SecretSpec failure mean "no such secret" rather than "I could
   not answer"?

   MATCHED ON THE WHOLE PHRASE, NOT ON "not found". SecretSpec says
   `Secret 'API_TOKEN' not found` for both a name it does not declare and
   one declared with no value, and both are misses. It also says
   `Provider backend 'keyring' not found`, which is a store that could not
   answer at all - and reading that as a miss is the worst failure this
   library has. The key is required to appear, so the two cannot be
   confused. *)
let secretspecmiss (why : string) (key : string) : bool =
  None <> Sigv4.findsub why ("Secret '" ^ key ^ "' not found")

(* SecretSpec (https://secretspec.dev), read through its CLI.

   `backend` selects one of SecretSpec's own backends (`--provider`) and is
   called `backend` here only because `provider` already means something
   else in this library.

   A reason is required, not optional: SecretSpec records every read in an
   audit log and refuses to read at all without one. *)
let secretspec_provider (commandgiven : string) (file : string) (profile : string)
    (backend : string) (reason : string) (prefix : string) : provider =
  let command = if "" = commandgiven then "secretspec" else commandgiven in

  {
    lookup =
      (fun name ->
        let key = envkey ~prefix name in

        (* `--file` before the subcommand, `--reason` always sent. *)
        let argv =
          [ command ]
          @ (if "" = file then [] else [ "--file"; file ])
          @ [ "get"; key ]
          @ (if "" = backend then [] else [ "--provider"; backend ])
          @ (if "" = profile then [] else [ "--profile"; profile ])
          @ [ "--reason"; firstof [ reason; "sekreto" ] ]
        in

        let ran = runcmd argv (Unix.environment ()) command in

        if 0 = ran.status then Some (dropsuffix ran.out "\n")
        else if secretspecmiss ran.why key then None
        else
          fail
            ("sekreto: secretspec error: "
            ^ if "" = ran.why then "exit " ^ string_of_int ran.status else ran.why));
    describe = (fun () -> if "" = backend then "secretspec" else "secretspec:" ^ backend);
  }

(* ---- aws ---------------------------------------------------------------- *)

(* The `YYYYMMDDTHHMMSSZ` timestamp SigV4 wants, for now. The only place in
   this library that samples the clock for a signature; `Sigv4.sigv4` itself
   never does. *)
let awsnow () : string =
  let t = Unix.gmtime (Unix.gettimeofday ()) in
  Printf.sprintf "%04d%02d%02dT%02d%02d%02dZ" (t.Unix.tm_year + 1900) (t.Unix.tm_mon + 1)
    t.Unix.tm_mday t.Unix.tm_hour t.Unix.tm_min t.Unix.tm_sec

type awsauth = { aregion : string; akeyid : string; asecret : string; asession : string }

(* Region and credentials, from config first and the standard AWS_*
   environment variables second - those are AWS's own convention, and a pod
   or CI job that has them set should just work. Missing either is an error:
   an AWS store with no credentials could not answer. *)
let awsauthof (region : string) (keyid : string) (secret : string) (session : string) : awsauth =
  let useregion = firstof [ region; getenv "AWS_REGION"; getenv "AWS_DEFAULT_REGION" ] in
  let usekeyid = firstof [ keyid; getenv "AWS_ACCESS_KEY_ID" ] in
  let usesecret = firstof [ secret; getenv "AWS_SECRET_ACCESS_KEY" ] in
  let usesession = firstof [ session; getenv "AWS_SESSION_TOKEN" ] in

  if "" = useregion then fail "sekreto: aws: no region (set region or AWS_REGION)";

  if "" = usekeyid || "" = usesecret then
    fail "sekreto: aws: no credentials (set keyid/secret or AWS_ACCESS_KEY_ID/AWS_SECRET_ACCESS_KEY)";

  { aregion = useregion; akeyid = usekeyid; asecret = usesecret; asession = usesession }

(* One signed call to an AWS JSON-1.1 API. *)
let awscall (region : string) (keyid : string) (secret : string) (session : string)
    (addr : string) (service : string) (target : string) (payload : string) : answer =
  let auth = awsauthof region keyid secret session in

  (* The China partition lives under its own suffix; every other commercial
     region is plain amazonaws.com. *)
  let suffix =
    if String.starts_with ~prefix:"cn-" auth.aregion then ".amazonaws.com.cn" else ".amazonaws.com"
  in
  let useaddr = firstof [ addr; "https://" ^ service ^ "." ^ auth.aregion ^ suffix ] in
  checkaddr useaddr;

  let url = trimslash useaddr ^ "/" in

  let extras =
    [ ("content-type", "application/x-amz-json-1.1"); ("x-amz-target", target) ]
  in

  let signed =
    Sigv4.sigv4
      {
        Sigv4.smethod = "POST";
        url;
        service;
        region = auth.aregion;
        keyid = auth.akeyid;
        secret = auth.asecret;
        datetime = awsnow ();
        headers = extras;
        body = payload;
        session = auth.asession;
      }
  in

  fetchjson ~headers:(extras @ signed) ~body:payload "POST" url

(* Does this AWS error body name one of the not-found types? Those are a
   miss; every other failure is a store that could not answer. AWS sends
   `com.amazonaws...#ResourceNotFoundException`, so this contains rather
   than equals. *)
let awsmiss (body : Json.t option) (types : string list) : bool =
  match digstr body [ "__type" ] with
  | Some errtype -> List.exists (fun want -> None <> Sigv4.findsub errtype want) types
  | None -> false

(* AWS Secrets Manager.

   `api.token` reads the secret named `api` (the vaultref path, so
   `db.pass.main` reads `db/pass`) and takes the `token` field of its JSON
   SecretString - the AWS idiom of one JSON map per secret. A SecretString
   that is not JSON is the value itself, under the conventional field
   `value`. *)
let awssecrets_provider (region : string) (keyid : string) (secret : string) (session : string)
    (addr : string) : provider =
  {
    lookup =
      (fun name ->
        let ref_ = vaultref name in

        let res =
          awscall region keyid secret session addr "secretsmanager"
            "secretsmanager.GetSecretValue"
            (Json.stringify (Json.obj [ ("SecretId", Json.str ref_.path) ]))
        in

        if 400 = res.status && awsmiss res.jbody [ "ResourceNotFoundException" ] then None
        else if 200 <> res.status then
          fail ("sekreto: aws secretsmanager error: " ^ string_of_int res.status)
        else
          match digstr res.jbody [ "SecretString" ] with
          | None -> (
            (* A binary secret has no fields to address; only the
               conventional `value` field can mean "the bytes themselves". *)
            match digstr res.jbody [ "SecretBinary" ] with
            | Some raw when "value" = ref_.field -> (
              match Http.unbase64 raw with
              | Some bytes -> Some bytes
              | None -> fail "sekreto: aws secretsmanager: undecodable secret")
            | _ -> None)
          | Some text -> (
            match Json.parse text with
            | Some (Json.Obj fields) -> (
              match List.assoc_opt ref_.field fields with
              | Some value -> Json.text value
              | None -> None)
            (* A plain-string secret is the whole value; it has no named
               fields. *)
            | _ -> if "value" = ref_.field then Some text else None));
    (* Config only, never the environment: `describe` feeds the spec's
       sources group, which must answer the same everywhere. *)
    describe = (fun () -> "awssecrets:" ^ region);
  }

(* AWS SSM Parameter Store.

   `db.pass.main` reads the parameter `/db/pass/main` (under an optional
   prefix path), decrypted. Parameter Store carries flat strings, so there
   is no field indirection. *)
let awsparams_provider (region : string) (keyid : string) (secret : string) (session : string)
    (addr : string) (prefix : string) : provider =
  {
    lookup =
      (fun name ->
        let payload =
          Json.obj
            [ ("Name", Json.str (awsparam ~prefix name)); ("WithDecryption", Json.bool true) ]
        in

        let res =
          awscall region keyid secret session addr "ssm" "AmazonSSM.GetParameter"
            (Json.stringify payload)
        in

        if 400 = res.status && awsmiss res.jbody [ "ParameterNotFound" ] then None
        else if 200 <> res.status then fail ("sekreto: aws ssm error: " ^ string_of_int res.status)
        else digtext res.jbody [ "Parameter"; "Value" ]);
    describe = (fun () -> "awsparams:" ^ region ^ prefix);
  }

(* ---- gcp ---------------------------------------------------------------- *)

(* GCP Secret Manager.

   `api.token` reads secret `api_token` (dots flattened to `_`; Secret
   Manager ids have no hierarchy and reject dots), latest version. The token
   comes from config, then GOOGLE_OAUTH_ACCESS_TOKEN, then the GCE/GKE
   metadata server - so on Google's own platform no credential configuration
   is needed at all.

   The metadata call itself is plain http to a link-local host by platform
   design and carries no credential, so `checkaddr` guards the Secret
   Manager address instead. *)
let gcpsecrets_provider (project : string) (token : string) (addr : string)
    (metadataaddr : string) : provider =
  let livetoken = ref None in
  let renewat = ref never in

  let usemetadataaddr () =
    if "" <> metadataaddr then metadataaddr
    else
      let host = getenv "GCE_METADATA_HOST" in
      if "" <> host then "http://" ^ host else "http://metadata.google.internal"
  in

  let login () =
    let configured = firstof [ token; getenv "GOOGLE_OAUTH_ACCESS_TOKEN" ] in
    if "" <> configured then configured
    else begin
      let url =
        trimslash (usemetadataaddr ()) ^ "/computeMetadata/v1/instance/service-accounts/default/token"
      in

      let res = fetchjson ~headers:[ ("Metadata-Flavor", "Google") ] "GET" url in
      let got = digtext res.jbody [ "access_token" ] in

      if 200 <> res.status || not (isset got) then
        fail "sekreto: gcp: no token and metadata server did not answer";

      renewat := renewtime (Json.odig res.jbody [ "expires_in" ]);
      Option.get got
    end
  in

  {
    lookup =
      (fun name ->
        if "" = project then fail "sekreto: gcp: no project";

        let useaddr = firstof [ addr; "https://secretmanager.googleapis.com" ] in
        checkaddr useaddr;

        if None = !livetoken || nowms () >= !renewat then livetoken := Some (login ());

        let url =
          trimslash useaddr ^ "/v1/projects/" ^ project ^ "/secrets/" ^ flatname name "_"
          ^ "/versions/latest:access"
        in

        let res =
          fetchjson
            ~headers:[ ("authorization", "Bearer " ^ Option.value ~default:"" !livetoken) ]
            "GET" url
        in

        if 404 = res.status then None
        else if 200 <> res.status then
          fail ("sekreto: gcp error: " ^ string_of_int res.status ^ ": " ^ url)
        else
          match digstr res.jbody [ "payload"; "data" ] with
          | None -> None
          | Some data -> (
            match Http.unbase64 data with
            | Some bytes -> Some bytes
            | None -> fail "sekreto: gcp: undecodable secret"));
    describe = (fun () -> "gcpsecrets:" ^ project);
  }

(* ---- azure -------------------------------------------------------------- *)

(* The Key Vault audience an Azure token is minted for. *)
let azureresource = "https://vault.azure.net"

(* Azure Key Vault.

   `api.token` reads secret `api-token` (dots flattened to `-`; Key Vault
   names allow nothing else), current version. The token comes from config,
   then a client-credentials login when tenant/clientid/clientsecret are
   given, then the IMDS managed-identity endpoint.

   As with GCP, the IMDS call is plain http to a link-local host by platform
   design and carries no credential; the login and vault addresses are
   `checkaddr`-guarded. IMDS answers `expires_in` as a STRING, which is why
   `renewtime` accepts one. *)
let azuresecrets_provider (vault : string) (token : string) (tenant : string) (clientid : string)
    (clientsecret : string) (loginaddr : string) (imdsaddr : string) (apiversion : string) :
    provider =
  let livetoken = ref None in
  let renewat = ref never in

  let login () =
    if "" <> token then token
    else if "" <> tenant && "" <> clientid && "" <> clientsecret then begin
      let useloginaddr = firstof [ loginaddr; "https://login.microsoftonline.com" ] in
      checkaddr useloginaddr;

      let url = trimslash useloginaddr ^ "/" ^ tenant ^ "/oauth2/v2.0/token" in
      let form =
        "grant_type=client_credentials&client_id=" ^ Sigv4.uriescape clientid ^ "&client_secret="
        ^ Sigv4.uriescape clientsecret ^ "&scope="
        ^ Sigv4.uriescape (azureresource ^ "/.default")
      in

      let res =
        fetchjson
          ~headers:[ ("content-type", "application/x-www-form-urlencoded") ]
          ~body:form "POST" url
      in

      let got = digtext res.jbody [ "access_token" ] in
      if 200 <> res.status || not (isset got) then
        fail ("sekreto: azure login failed: " ^ string_of_int res.status);

      renewat := renewtime (Json.odig res.jbody [ "expires_in" ]);
      Option.get got
    end
    else begin
      let url =
        trimslash (firstof [ imdsaddr; "http://169.254.169.254" ])
        ^ "/metadata/identity/oauth2/token?api-version=2018-02-01&resource="
        ^ Sigv4.uriescape azureresource
      in

      let res = fetchjson ~headers:[ ("Metadata", "true") ] "GET" url in
      let got = digtext res.jbody [ "access_token" ] in

      if 200 <> res.status || not (isset got) then
        fail "sekreto: azure: no token, no client credentials, and IMDS did not answer";

      renewat := renewtime (Json.odig res.jbody [ "expires_in" ]);
      Option.get got
    end
  in

  {
    lookup =
      (fun name ->
        if "" = vault then fail "sekreto: azure: no vault";

        (* ONLY an explicit scheme is a URL: a vault NAMED httpvault must
           still become https://httpvault.vault.azure.net. *)
        let vaulturl =
          if String.starts_with ~prefix:"http://" vault || String.starts_with ~prefix:"https://" vault
          then vault
          else "https://" ^ vault ^ ".vault.azure.net"
        in
        checkaddr vaulturl;

        if None = !livetoken || nowms () >= !renewat then livetoken := Some (login ());

        let url =
          trimslash vaulturl ^ "/secrets/" ^ flatname name "-" ^ "?api-version="
          ^ firstof [ apiversion; "7.4" ]
        in

        let res =
          fetchjson
            ~headers:[ ("authorization", "Bearer " ^ Option.value ~default:"" !livetoken) ]
            "GET" url
        in

        if 404 = res.status then None
        else if 200 <> res.status then
          fail ("sekreto: azure error: " ^ string_of_int res.status ^ ": " ^ bare url)
        else digtext res.jbody [ "value" ]);
    describe = (fun () -> "azuresecrets:" ^ vault);
  }

(* ---- 1password ---------------------------------------------------------- *)

(* 1Password, through a Connect server.

   The item titled `api.token` (titles KEEP THEIR DOTS), in the named vault.
   The value is the field with purpose PASSWORD, or the field labelled
   `value`. A vault that cannot be found is an ERROR, not a miss - config
   names it, so its absence is a broken store rather than a missing
   secret. *)
let onepassword_provider (addr : string) (token : string) (vault : string) : provider =
  let vaultid = ref None in

  let auth () = [ ("authorization", "Bearer " ^ token) ] in

  let resolvevault useaddr =
    if "" = vault then fail "sekreto: onepassword: no vault";

    let res = fetchjson ~headers:(auth ()) "GET" (useaddr ^ "/v1/vaults") in
    let list = Json.oasarr res.jbody in

    if 200 <> res.status || None = list then
      fail ("sekreto: onepassword error: " ^ string_of_int res.status ^ ": listing vaults");

    let entries = Option.get list in
    let found =
      List.find_opt
        (fun entry ->
          Some vault = Json.otext (Json.dig entry [ "id" ])
          || Some vault = Json.otext (Json.dig entry [ "name" ]))
        entries
    in

    match found with
    | Some entry -> Option.value ~default:"" (Json.otext (Json.dig entry [ "id" ]))
    | None -> fail ("sekreto: onepassword: no vault named " ^ vault)
  in

  {
    lookup =
      (fun name ->
        ignore (checkname name);

        let useaddr = trimslash addr in
        if "" = useaddr then fail "sekreto: onepassword: no addr";
        checkaddr useaddr;

        let id =
          match !vaultid with
          | Some found -> found
          | None ->
            let resolved = resolvevault useaddr in
            vaultid := Some resolved;
            resolved
        in

        let filter = Sigv4.uriescape ("title eq \"" ^ name ^ "\"") in
        let found =
          fetchjson ~headers:(auth ()) "GET" (useaddr ^ "/v1/vaults/" ^ id ^ "/items?filter=" ^ filter)
        in

        let items = Json.oasarr found.jbody in
        if 200 <> found.status || None = items then
          fail ("sekreto: onepassword error: " ^ string_of_int found.status ^ ": finding " ^ name);

        match Option.get items with
        (* No item with that title: a miss, and the chain carries on. *)
        | [] -> None
        | head :: _ ->
          let itemid = Option.value ~default:"" (Json.otext (Json.dig head [ "id" ])) in
          let item =
            fetchjson ~headers:(auth ()) "GET" (useaddr ^ "/v1/vaults/" ^ id ^ "/items/" ^ itemid)
          in

          if 200 <> item.status then
            fail ("sekreto: onepassword error: " ^ string_of_int item.status ^ ": reading " ^ name);

          let fields =
            match Json.oasarr (Json.odig item.jbody [ "fields" ]) with
            | Some list -> list
            | None -> []
          in

          (* Two full passes, in this order. *)
          let bypurpose =
            List.find_opt (fun field -> Some "PASSWORD" = Json.oasstr (Json.dig field [ "purpose" ])) fields
          in

          (match bypurpose with
          | Some field -> Json.otext (Json.dig field [ "value" ])
          | None -> (
            match
              List.find_opt (fun field -> Some "value" = Json.oasstr (Json.dig field [ "label" ])) fields
            with
            | Some field -> Json.otext (Json.dig field [ "value" ])
            | None -> None)));
    describe = (fun () -> "onepassword:" ^ vault);
  }

(* ---- doppler ------------------------------------------------------------ *)

(* Doppler.

   The whole config is downloaded ONCE - Doppler's own bulk endpoint - and
   answered from memory, like a remote .env: `api.token` is the `API_TOKEN`
   entry. A service token is config-scoped, so project and config are only
   needed with broader tokens. A failed load caches nothing, so it retries.

   The `prefix` option is deliberately not consulted by this kind. *)
let doppler_provider (token : string) (project : string) (config : string) (addr : string) :
    provider =
  let values = ref None in

  let load () =
    match !values with
    | Some loaded -> loaded
    | None ->
      let useaddr = trimslash (firstof [ addr; "https://api.doppler.com" ]) in
      checkaddr useaddr;

      let url = ref (useaddr ^ "/v3/configs/config/secrets/download?format=json") in
      if "" <> project then url := !url ^ "&project=" ^ Sigv4.uriescape project;
      if "" <> config then url := !url ^ "&config=" ^ Sigv4.uriescape config;

      let res = fetchjson ~headers:[ ("authorization", "Bearer " ^ token) ] "GET" !url in
      let body = Json.oasobj res.jbody in

      if 200 <> res.status || None = body then
        fail ("sekreto: doppler error: " ^ string_of_int res.status);

      let loaded =
        List.filter_map
          (fun (key, value) -> match Json.text value with Some text -> Some (key, text) | None -> None)
          (Option.get body)
      in

      values := Some loaded;
      loaded
  in

  {
    lookup = (fun name -> List.assoc_opt (envkey name) (load ()));
    describe =
      (fun () -> if "" = project then "doppler" else "doppler:" ^ project ^ "/" ^ config);
  }

(* ---- infisical ---------------------------------------------------------- *)

(* Infisical.

   `api.token` reads the secret keyed `API_TOKEN` (Infisical's own
   convention is environment-style keys) at a secret path in one environment
   of a project. Auth is a token, or a universal-auth (machine identity)
   login. Its expiry field is `expiresIn`, camelCase, unlike everyone
   else's `expires_in`. *)
let infisical_provider (addr : string) (token : string) (clientid : string)
    (clientsecret : string) (project : string) (environment : string) (secretpath : string) :
    provider =
  let livetoken = ref None in
  let renewat = ref never in

  let login useaddr =
    if "" <> token then token
    else begin
      if "" = clientid || "" = clientsecret then
        fail "sekreto: infisical: no token and no client credentials";

      let body =
        Json.obj [ ("clientId", Json.str clientid); ("clientSecret", Json.str clientsecret) ]
      in

      let res =
        fetchjson
          ~headers:[ ("content-type", "application/json") ]
          ~body:(Json.stringify body) "POST"
          (useaddr ^ "/api/v1/auth/universal-auth/login")
      in

      let got = digtext res.jbody [ "accessToken" ] in
      if 200 <> res.status || not (isset got) then
        fail ("sekreto: infisical login failed: " ^ string_of_int res.status);

      renewat := renewtime (Json.odig res.jbody [ "expiresIn" ]);
      Option.get got
    end
  in

  {
    lookup =
      (fun name ->
        let useaddr = trimslash (firstof [ addr; "https://app.infisical.com" ]) in
        checkaddr useaddr;

        if "" = project || "" = environment then fail "sekreto: infisical: no project/environment";

        if None = !livetoken || nowms () >= !renewat then livetoken := Some (login useaddr);

        let url =
          useaddr ^ "/api/v3/secrets/raw/" ^ envkey name ^ "?workspaceId="
          ^ Sigv4.uriescape project ^ "&environment=" ^ Sigv4.uriescape environment
          ^ "&secretPath=" ^ Sigv4.uriescape (firstof [ secretpath; "/" ])
        in

        let res =
          fetchjson
            ~headers:[ ("authorization", "Bearer " ^ Option.value ~default:"" !livetoken) ]
            "GET" url
        in

        if 404 = res.status then None
        else if 200 <> res.status then fail ("sekreto: infisical error: " ^ string_of_int res.status)
        else digtext res.jbody [ "secret"; "secretValue" ]);
    describe = (fun () -> "infisical:" ^ project ^ "/" ^ environment);
  }

(* ---- the kind table ------------------------------------------------------ *)

(* Build a provider from its declarative form - the same shape the shared
   spec and an app's config file use. *)
let makeprovider (spec : spec) : provider =
  match spec.kind with
  | "env" -> env_provider spec.prefix
  | "dotenv" -> dotenv_provider (if "" = spec.file then ".env" else spec.file) spec.prefix
  | "memory" -> memory_provider spec.values spec.prefix
  | "file" -> file_provider spec.dir spec.prefix
  | "hashicorp" ->
    hashicorp_provider spec.addr spec.token spec.mount spec.kv spec.vaultnamespace spec.auth
  | "boru" ->
    boru_provider spec.command spec.namespace spec.home spec.addr spec.token spec.mount
  | "awssecrets" ->
    awssecrets_provider spec.region spec.keyid spec.secret spec.session spec.addr
  | "awsparams" ->
    awsparams_provider spec.region spec.keyid spec.secret spec.session spec.addr spec.prefix
  | "gcpsecrets" ->
    gcpsecrets_provider spec.project spec.token spec.addr spec.metadataaddr
  | "azuresecrets" ->
    azuresecrets_provider spec.vault spec.token spec.tenant spec.clientid spec.clientsecret
      spec.loginaddr spec.imdsaddr spec.apiversion
  | "onepassword" -> onepassword_provider spec.addr spec.token spec.vault
  | "doppler" -> doppler_provider spec.token spec.project spec.config spec.addr
  | "infisical" ->
    infisical_provider spec.addr spec.token spec.clientid spec.clientsecret spec.project
      spec.environment spec.secretpath
  | "secretspec" ->
    secretspec_provider spec.command spec.file spec.profile spec.backend spec.reason spec.prefix
  | other -> fail ("sekreto: unknown provider kind: " ^ other)

(* Make a Sekreto from declarative provider specs.

   It lives here rather than in src/sekreto.ml only because OCaml compiles a
   module before anything that uses it: the facade cannot name the kind
   table without the kind table naming the facade back. *)
let sekreto ?(cache = true) (specs : spec list) : Sekreto.t =
  Sekreto.make ~names:(List.map (fun spec -> spec.name) specs) ~cache
    (List.map makeprovider specs)
