(* RUN: make test
   RUN-SOME: ./build/sekretotest envkey

   The sekreto conformance suite. Every port runs these same groups, from
   the same spec/sekreto.json, through its own voxgig/omni runner.

   No third-party test framework: a failing omni check raises Omni_error, so
   any host framework (alcotest, ounit) reports it as a failure, and this
   harness keeps `make test` dependency-free. It is also the only file in
   the port that may name omni.

   Two value models meet here. omni has a `json` type with an `Absent` case;
   the library takes plain OCaml strings and a typed spec record. The bridge
   below converts between them explicitly, so nothing about absent, null and
   value is guessed. *)

let only = ref None
let passcount = ref 0
let failcount = ref 0

(* Find the shared spec directory by walking up from the working dir. *)
let specfile (name : string) : string =
  let rec search dir step =
    if step >= 8 then raise (Omni.Omni_error ("sekreto: spec not found: " ^ name))
    else
      let cand = Filename.concat (Filename.concat dir "spec") name in
      if Sys.file_exists cand then cand
      else search (Filename.concat dir Filename.parent_dir_name) (step + 1)
  in
  search (Sys.getcwd ()) 0

(* ---- the bridge ------------------------------------------------------ *)

(* omni's model -> the text the library's entry points take. Absent and null
   both read as the empty string, which is what makes `checkname` report
   `sekreto: invalid name: ` with its trailing space. *)
let text (value : Omni.json) : string =
  match value with
  | Omni.Str entry -> entry
  | Omni.Absent | Omni.Null -> ""
  | other -> Omni.stringify other

let field (entry : Omni.json) (key : string) : string = text (Omni.jget entry key)

let textlist (values : string list) : Omni.json =
  Omni.JList (List.map (fun value -> Omni.Str value) values)

let pairs (values : (string * string) list) : Omni.json =
  Omni.JMap (List.map (fun (key, value) -> (key, Omni.Str value)) values)

(* One provider spec, out of the spec's declarative chain description.
   Sixteen fields are all the corpus exercises; the rest keep their
   defaults. *)
let specof (entry : Omni.json) : Providers.spec =
  let values =
    match Omni.jget entry "values" with
    | Omni.JMap items -> List.map (fun (key, value) -> (key, text value)) items
    | _ -> []
  in

  let auth =
    match Omni.jget entry "auth" with
    | Omni.JMap _ as useauth ->
      Some
        {
          Providers.amethod = field useauth "method";
          amount = field useauth "mount";
          role = field useauth "role";
          jwt = field useauth "jwt";
          jwtfile = field useauth "jwtfile";
          roleid = field useauth "roleid";
          secretid = field useauth "secretid";
        }
    | _ -> None
  in

  {
    Providers.kind = field entry "kind";
    name = field entry "name";
    prefix = field entry "prefix";
    file = field entry "file";
    values;
    dir = field entry "dir";
    addr = field entry "addr";
    token = field entry "token";
    mount = field entry "mount";
    kv = (match Omni.jget entry "kv" with Omni.Num value -> int_of_float value | _ -> 2);
    vaultnamespace = field entry "vaultnamespace";
    auth;
    command = field entry "command";
    profile = field entry "profile";
    backend = field entry "backend";
    reason = field entry "reason";
    namespace = field entry "namespace";
    home = field entry "home";
    region = field entry "region";
    keyid = field entry "keyid";
    secret = field entry "secret";
    session = field entry "session";
    project = field entry "project";
    vault = field entry "vault";
    tenant = field entry "tenant";
    clientid = field entry "clientid";
    clientsecret = field entry "clientsecret";
    loginaddr = field entry "loginaddr";
    imdsaddr = field entry "imdsaddr";
    metadataaddr = field entry "metadataaddr";
    apiversion = field entry "apiversion";
    config = field entry "config";
    environment = field entry "environment";
    secretpath = field entry "path";
  }

(* Build a Sekreto from the spec's declarative chain description.

   Called INSIDE each subject, never outside: four entries expect
   `unsupported kv version`, which the constructor raises, and only a
   constructor run inside the subject delivers that to omni as a subject
   failure. Caching is off on every constructed chain. *)
let chainof (entry : Omni.json) : Sekreto.t =
  let chain = match Omni.jget entry "chain" with Omni.JList items -> items | _ -> [] in
  Providers.sekreto ~cache:false (List.map specof chain)

let namearg (entry : Omni.json) : string = field entry "name"

(* ---- the subjects ---------------------------------------------------- *)

(* `validname` answers whatever OCaml calls true; the spec says JSON true,
   so the adaptation happens here rather than in the library. *)
let validname_sub args = Omni.Bool (Sekreto.validname (text (List.nth args 0)))

let envkey_sub args =
  let entry = List.nth args 0 in
  Omni.Str (Sekreto.envkey ~prefix:(field entry "prefix") (field entry "name"))

let vaultref_sub args =
  let ref_ = Sekreto.vaultref (text (List.nth args 0)) in
  Omni.JMap [ ("path", Omni.Str ref_.Sekreto.path); ("field", Omni.Str ref_.Sekreto.field) ]

let flatname_sub args =
  let entry = List.nth args 0 in
  Omni.Str (Sekreto.flatname (field entry "name") (field entry "sep"))

let awsparam_sub args =
  let entry = List.nth args 0 in
  Omni.Str (Sekreto.awsparam ~prefix:(field entry "prefix") (field entry "name"))

let parsedotenv_sub args = pairs (Sekreto.parsedotenv (text (List.nth args 0)))

let resolve_sub args =
  let entry = List.nth args 0 in
  Omni.Str (Sekreto.get (chainof entry) (namearg entry))

(* A miss is omni's Null, which under default flags matches the spec's
   `__NULL__` sentinel. *)
let trysecret_sub args =
  let entry = List.nth args 0 in
  match Sekreto.tryget (chainof entry) (namearg entry) with
  | Some value -> Omni.Str value
  | None -> Omni.Null

let sources_sub args = textlist (Sekreto.sources (chainof (List.nth args 0)))
let stores_sub args = textlist (Sekreto.stores (chainof (List.nth args 0)))

let getfrom_sub args =
  let entry = List.nth args 0 in
  Omni.Str (Sekreto.getfrom (chainof entry) (field entry "store") (namearg entry))

let tryfrom_sub args =
  let entry = List.nth args 0 in
  match Sekreto.tryfrom (chainof entry) (field entry "store") (namearg entry) with
  | Some value -> Omni.Str value
  | None -> Omni.Null

(* Answers the ordered output map itself, which omni compares as a JSON
   object against the spec's known-answer signatures. *)
let sigv4_sub args =
  let entry = List.nth args 0 in
  let headers =
    match Omni.jget entry "headers" with
    | Omni.JMap items -> List.map (fun (key, value) -> (key, text value)) items
    | _ -> []
  in

  pairs
    (Sigv4.sigv4
       {
         Sigv4.smethod = field entry "method";
         url = field entry "url";
         service = field entry "service";
         region = field entry "region";
         keyid = field entry "keyid";
         secret = field entry "secret";
         datetime = field entry "datetime";
         headers;
         body = field entry "body";
         session = field entry "session";
       })

let redact_sub args =
  let entry = List.nth args 0 in
  let values =
    match Omni.jget entry "values" with Omni.JList items -> List.map text items | _ -> []
  in
  Omni.Str (Sekreto.redact (text (Omni.jget entry "text")) values)

(* ---- the runner ------------------------------------------------------ *)

let testcase (name : string) (body : unit -> unit) : unit =
  match !only with
  | Some wanted when wanted <> name -> ()
  | _ -> (
    match body () with
    | () ->
      incr passcount;
      print_endline ("ok   - " ^ name)
    | exception err ->
      incr failcount;
      print_endline ("FAIL - " ^ name);
      print_endline (Printexc.to_string err))

let () =
  if 1 < Array.length Sys.argv then only := Some Sys.argv.(1);

  let pack = (Omni.make_runner (specfile "sekreto.json") Omni.empty_provider) "sekreto" None in

  testcase "validname" (fun () ->
      pack.Omni.runsetflags (pack.Omni.set "validname") Omni.nonull_flags (Some validname_sub));
  testcase "envkey" (fun () -> pack.Omni.runset (pack.Omni.set "envkey") (Some envkey_sub));
  testcase "vaultref" (fun () -> pack.Omni.runset (pack.Omni.set "vaultref") (Some vaultref_sub));
  testcase "flatname" (fun () -> pack.Omni.runset (pack.Omni.set "flatname") (Some flatname_sub));
  testcase "awsparam" (fun () -> pack.Omni.runset (pack.Omni.set "awsparam") (Some awsparam_sub));
  testcase "parsedotenv" (fun () ->
      pack.Omni.runset (pack.Omni.set "parsedotenv") (Some parsedotenv_sub));
  testcase "resolve" (fun () -> pack.Omni.runset (pack.Omni.set "resolve") (Some resolve_sub));
  testcase "trysecret" (fun () -> pack.Omni.runset (pack.Omni.set "trysecret") (Some trysecret_sub));
  testcase "sources" (fun () -> pack.Omni.runset (pack.Omni.set "sources") (Some sources_sub));
  testcase "stores" (fun () -> pack.Omni.runset (pack.Omni.set "stores") (Some stores_sub));
  testcase "getfrom" (fun () -> pack.Omni.runset (pack.Omni.set "getfrom") (Some getfrom_sub));
  testcase "tryfrom" (fun () -> pack.Omni.runset (pack.Omni.set "tryfrom") (Some tryfrom_sub));
  testcase "sigv4" (fun () -> pack.Omni.runset (pack.Omni.set "sigv4") (Some sigv4_sub));
  testcase "redact" (fun () -> pack.Omni.runset (pack.Omni.set "redact") (Some redact_sub));

  Printf.printf "\n%d passed, %d failed\n" !passcount !failcount;

  exit (if 0 = !failcount then 0 else 1)
