(* A tiny app that needs a secret.

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
   needs nothing on disk beside itself: a native binary with the library
   linked in. *)

let lang = "ocaml"

let env (name : string) : string =
  match Sys.getenv_opt name with Some value -> value | None -> ""

let envor (name : string) (fallback : string) : string =
  let value = env name in
  if "" = value then fallback else value

let chainfor (source : string) : Provider.spec list =
  let open Provider in
  let envspec = { nospec with kind = "env"; prefix = env "SEKRETO_PREFIX" } in
  let dotenvspec = { nospec with kind = "dotenv"; file = envor "SEKRETO_DOTENV" ".env" } in
  let filespec = { nospec with kind = "file"; dir = envor "SEKRETO_FILEDIR" "/run/secrets" } in

  let hashicorpspec =
    {
      nospec with
      kind = "hashicorp";
      addr = env "VAULT_ADDR";
      token = env "VAULT_TOKEN";
      mount = env "VAULT_MOUNT";
      kv = (match int_of_string_opt (env "VAULT_KV") with Some value -> value | None -> 2);
      vaultnamespace = env "VAULT_NAMESPACE";
      auth =
        (if "" = env "VAULT_AUTH" then None
         else
           Some
             {
               noauth with
               amethod = env "VAULT_AUTH";
               role = env "VAULT_ROLE";
               jwtfile = env "VAULT_JWT_FILE";
               roleid = env "VAULT_ROLE_ID";
               secretid = env "VAULT_SECRET_ID";
             });
    }
  in

  let boruspec =
    {
      nospec with
      kind = "boru";
      command = envor "BORU_COMMAND" "boru";
      namespace = env "BORU_NAMESPACE";
      home = env "BORU_HOME";
    }
  in

  (* The same vault over its wire protocol (`boru vault serve`) instead of
     the CLI: an address plus a capability token from `vault grant`. *)
  let boruwirespec =
    {
      nospec with
      kind = "boru";
      addr = env "BORU_ADDR";
      token = env "BORU_TOKEN";
      namespace = env "BORU_NAMESPACE";
    }
  in

  let awssecretsspec =
    { nospec with kind = "awssecrets"; region = env "AWS_REGION"; addr = env "AWS_ENDPOINT" }
  in

  let awsparamsspec =
    {
      nospec with
      kind = "awsparams";
      region = env "AWS_REGION";
      addr = env "AWS_ENDPOINT";
      prefix = env "AWS_PARAM_PREFIX";
    }
  in

  let gcpspec =
    {
      nospec with
      kind = "gcpsecrets";
      project = env "GCP_PROJECT";
      addr = env "GCP_ADDR";
      metadataaddr = env "GCP_METADATA_ADDR";
    }
  in

  let azurespec =
    {
      nospec with
      kind = "azuresecrets";
      vault = env "AZURE_VAULT";
      token = env "AZURE_TOKEN";
      tenant = env "AZURE_TENANT";
      clientid = env "AZURE_CLIENT_ID";
      clientsecret = env "AZURE_CLIENT_SECRET";
      loginaddr = env "AZURE_LOGIN_ADDR";
      imdsaddr = env "AZURE_IMDS_ADDR";
    }
  in

  let onepasswordspec =
    {
      nospec with
      kind = "onepassword";
      addr = env "OP_CONNECT_HOST";
      token = env "OP_CONNECT_TOKEN";
      vault = env "OP_VAULT";
    }
  in

  let dopplerspec =
    {
      nospec with
      kind = "doppler";
      token = env "DOPPLER_TOKEN";
      project = env "DOPPLER_PROJECT";
      config = env "DOPPLER_CONFIG";
      addr = env "DOPPLER_ADDR";
    }
  in

  (* SecretSpec's own environment variables where it has them
     (SECRETSPEC_FILE, _PROFILE, _PROVIDER, _REASON are read by the
     secretspec CLI itself), so a shell already set up for secretspec needs
     nothing further. *)
  let secretspecspec =
    {
      nospec with
      kind = "secretspec";
      command = envor "SECRETSPEC_COMMAND" "secretspec";
      file = env "SECRETSPEC_FILE";
      profile = env "SECRETSPEC_PROFILE";
      backend = env "SECRETSPEC_PROVIDER";
      reason = env "SECRETSPEC_REASON";
    }
  in

  let infisicalspec =
    {
      nospec with
      kind = "infisical";
      addr = env "INFISICAL_ADDR";
      token = env "INFISICAL_TOKEN";
      clientid = env "INFISICAL_CLIENT_ID";
      clientsecret = env "INFISICAL_CLIENT_SECRET";
      project = env "INFISICAL_PROJECT";
      environment = env "INFISICAL_ENV";
      secretpath = env "INFISICAL_PATH";
    }
  in

  match source with
  | "env" -> [ envspec ]
  | "dotenv" -> [ dotenvspec ]
  | "file" -> [ filespec ]
  | "hashicorp" -> [ hashicorpspec ]
  | "boru" -> [ boruspec ]
  | "boruwire" -> [ boruwirespec ]
  | "awssecrets" -> [ awssecretsspec ]
  | "awsparams" -> [ awsparamsspec ]
  | "gcpsecrets" -> [ gcpspec ]
  | "azuresecrets" -> [ azurespec ]
  | "onepassword" -> [ onepasswordspec ]
  | "doppler" -> [ dopplerspec ]
  | "infisical" -> [ infisicalspec ]
  | "secretspec" -> [ secretspecspec ]
  (* The default: the chain an app would actually ship with - local
     overrides first, shared vaults last. *)
  | _ -> [ envspec; dotenvspec; hashicorpspec; boruspec ]

(* The value of a `--flag value` pair, or empty when the flag is absent.
   Positional, by index-of: no argument-parsing library. *)
let flag (args : string array) (name : string) : string =
  let len = Array.length args in
  let rec walk index =
    if index >= len then ""
    else if args.(index) = name then if index + 1 < len then args.(index + 1) else ""
    else walk (index + 1)
  in
  walk 0

let why (err : exn) : string =
  match err with
  | Sekreto.Sekreto_error message -> message
  | Unix.Unix_error (code, _, _) -> Unix.error_message code
  | other -> Printexc.to_string other

let run (args : string array) : int =
  let url = if 0 < Array.length args then args.(0) else "http://127.0.0.1:8099/whoami" in
  let source = match flag args "--source" with "" -> "chain" | given -> given in

  (* --store names a store outright: the secret must come from that one, not
     from whichever provider happens to answer first. An unknown store is an
     error, and one integration check depends on that. *)
  let store = flag args "--store" in

  match
    (* THE FULL SET, because this CLI is asked for any of the fourteen
       kinds on the command line and cannot know which. An app that ships
       one chain passes only the plugins that chain names, and links only
       those. The conformance suite cannot see this line - it hands every
       plugin to every chain it builds - so test/plugins.ml pins it. *)
    let secrets = Sekreto.sekreto ~plugins:(Allplugins.all ()) (chainfor source) in

    let token =
      match (if "" = store then Sekreto.get secrets "api.token"
             else Sekreto.getfrom secrets store "api.token")
      with
      | value -> value
      | exception err ->
        prerr_endline ("sekreto-cli: " ^ Sekreto.redacttext secrets (why err));
        raise Exit
    in

    let response =
      match
        Http.request "GET" url
          [ ("Authorization", "Bearer " ^ token); ("X-Sekreto-Lang", lang) ]
          None
      with
      | response -> response
      | exception err ->
        (* Never print the token itself, even when the call fails. *)
        prerr_endline ("sekreto-cli: " ^ Sekreto.redacttext secrets (why err));
        raise Not_found
    in

    if 200 <> response.Http.status then begin
      prerr_endline ("sekreto-cli: " ^ Sekreto.redacttext secrets response.Http.body);
      raise Not_found
    end;

    let caller = Json.odig (Json.parse response.Http.body) [ "caller" ] in

    (* Assembled field by field, in the spec's order. Printing a map here is
       what has bitten port after port: the language's own key order is not
       the one every other port prints. *)
    let line = Buffer.create 128 in
    Buffer.add_string line "{\"ok\":true";
    Buffer.add_string line (",\"lang\":" ^ Json.quote lang);
    Buffer.add_string line (",\"source\":" ^ Json.quote source);
    Buffer.add_string line (",\"store\":" ^ Json.quote store);
    Buffer.add_string line
      (",\"caller\":" ^ match caller with Some value -> Json.stringify value | None -> "null");
    Buffer.add_string line "}";

    print_endline (Buffer.contents line);
    0
  with
  | code -> code
  (* Exit 2: the secret could not be obtained, construction included. *)
  | exception Exit -> 2
  (* Exit 1: the secret was obtained but the API refused it, or the
     transport failed. *)
  | exception Not_found -> 1
  | exception err ->
    prerr_endline ("sekreto-cli: " ^ why err);
    2

let () = exit (run (Array.sub Sys.argv 1 (Array.length Sys.argv - 1)))
