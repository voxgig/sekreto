(* RUN: make test
   RUN-SOME: ./build/plugintest

   THE PLUGIN SEAM, WHICH THE CORPUS CANNOT SEE.

   Moving the provider kinds that open sockets, sign requests and spawn
   processes out of the core made a consumer's PLUGIN LIST decide what a
   chain can build: a kind nobody passed in is not in the catalog, and a
   chain naming it is refused. That is the intended behaviour, and it means
   a consumer can be broken without a single conformance case noticing -
   `test/sekreto_test.ml` hands the full set to every chain it builds, so
   it can never see a chain that is missing a kind, and it never reads
   `cli/cli.ml` at all.

   Two of the checks below read BUILT ARTIFACTS rather than sources,
   because that is where the boundary actually is: `nm build/coreonly`
   names every compilation unit the core-only program links, and
   `ocamlobjinfo` names every implementation each module imports. Both are
   compared by EXACT unit name, and both carry a control - a check whose
   inputs came back empty passes vacuously, and would have been a green
   suite over an unread binary. *)

module V = Value

let passcount = ref 0
let failcount = ref 0

let check (label : string) (ok : bool) : unit =
  if ok then incr passcount
  else begin
    incr failcount;
    print_endline ("FAIL - " ^ label)
  end

let same (label : string) (want : 'a) (got : 'a) : unit =
  if want = got then incr passcount
  else begin
    incr failcount;
    print_endline ("FAIL - " ^ label)
  end

let samelist (label : string) (want : string list) (got : string list) : unit =
  if want = got then incr passcount
  else begin
    incr failcount;
    print_endline ("FAIL - " ^ label);
    print_endline ("  want: " ^ String.concat " " want);
    print_endline ("  got:  " ^ String.concat " " got)
  end

(* The refusal a call raises, or the empty string when it did not raise. *)
let refusal (body : unit -> unit) : string =
  match body () with
  | () -> ""
  | exception Sekreto.Sekreto_error message -> message

let sorted (names : string list) : string list = List.sort compare names

let spec (kind : string) : Provider.spec = { Provider.nospec with kind }

let refsof (secrets : Sekreto.t) : string list =
  V.keys (Host.list (Sekreto.host secrets))

let statusof (secrets : Sekreto.t) (r : string) : string =
  V.as_str (V.get (Host.list (Sekreto.host secrets)) r)

let names (catalog : Defs.catalog) : string list =
  List.map V.as_str (V.items (Catalog.names catalog))

(* Everything a command wrote to stdout, as lines. *)
let lines (command : string) : string list =
  let channel = Unix.open_process_in command in
  let out = ref [] in
  (try
     while true do
       out := input_line channel :: !out
     done
   with End_of_file -> ());
  ignore (Unix.close_process_in channel);
  List.rev !out

let readfile (path : string) : string =
  let channel = open_in_bin path in
  Fun.protect
    ~finally:(fun () -> close_in_noerr channel)
    (fun () -> really_input_string channel (in_channel_length channel))

(* ---- the full set ----------------------------------------------------- *)

let () =
  let full = Allplugins.all () in

  samelist "the full set holds every kind"
    (sorted Provider.pluginkinds)
    (sorted (List.map (fun d -> d.Defs.dname) full));

  (* ...and the core's list of what ships as a plugin says the same. It is
     what tells a typo from a plugin nobody passed in, so a kind added on
     one side and not the other would give the wrong advice. *)
  same "ten plugin kinds" 10 (List.length Provider.pluginkinds);
  samelist "four built-in kinds"
    [ "dotenv"; "env"; "file"; "memory" ]
    (sorted Provider.builtinkinds);

  (* Built, not held: `all` is a function returning fresh definitions, so
     two chains never share one and nothing is constructed at load time. *)
  let again = Allplugins.all () in
  same "the full set is built on demand" 10 (List.length again);
  check "two calls share no definition"
    (List.for_all2 (fun l r -> l != r) full again)

(* Naming a kind is not enough: a kind can be in the catalog and still fail
   to build. Construction is what the CLI does before any network. *)
let () =
  let every = Provider.builtinkinds @ Provider.pluginkinds in

  let secrets =
    Sekreto.sekreto ~plugins:(Allplugins.all ())
      (List.map
         (fun kind ->
           { (spec kind) with addr = "http://127.0.0.1:8200"; token = "t"; dir = "/tmp";
             file = "/tmp/.env" })
         every)
  in

  samelist "every kind builds from a spec" every (Sekreto.stores secrets);
  samelist "the host reads like the chain" (sorted every) (refsof secrets);
  check "every instance is live"
    (List.for_all (fun r -> "live" = statusof secrets r) (refsof secrets));
  Sekreto.close secrets

(* THE CONSUMER'S LIST IS THE BLIND SPOT THAT BITES. A CLI passing one
   plugin instead of ten leaves all fourteen conformance groups green and
   fails nine integration checks, because every corpus chain is handed the
   full set.

   Matched with the closing bracket, because a prefix is not the same
   claim: `~plugins:(Allplugins.all ())` is still a substring of
   `~plugins:(List.filteri ... (Allplugins.all ()))` if the bracket is left
   off the pattern. *)
let () =
  let source = readfile "cli/cli.ml" in

  check "the CLI source was read" (1000 < String.length source);
  check "the CLI passes the full set"
    (None <> Sekreto.findsub source "Sekreto.sekreto ~plugins:(Allplugins.all ()) (chainfor source)")

(* ---- what a consumer sees --------------------------------------------- *)

let () =
  let secrets =
    Sekreto.sekreto
      ~plugins:[ Hashicorp.plugin () ]
      [
        { (spec "memory") with values = [ ("API_TOKEN", "tok01") ] };
        { (spec "hashicorp") with name = "prod"; addr = "https://vault.example.com"; token = "t" };
      ]
  in

  samelist "one plugin is enough" [ "memory"; "prod" ] (Sekreto.stores secrets);
  samelist "one plugin: sources"
    [ "memory"; "hashicorp:https://vault.example.com/secret" ]
    (Sekreto.sources secrets);
  same "one plugin: the chain answers" "tok01" (Sekreto.get secrets "api.token");

  (* The plugin host is what the chain is made of, and it reads like the
     chain: the kind, or kind$store for a named store. *)
  samelist "one plugin: the refs" [ "hashicorp$prod"; "memory" ] (refsof secrets);
  samelist "one plugin: the catalog"
    [ "dotenv"; "env"; "file"; "hashicorp"; "memory" ]
    (names (Sekreto.catalog secrets));

  Sekreto.close secrets;

  (* ...and a kind that was not passed in is refused, naming the fix. *)
  same "a kind that was not passed in is refused, naming the fix"
    ("sekreto: unknown provider kind: doppler (available: dotenv, env, file, hashicorp, memory)"
   ^ " - doppler is a sekreto plugin, not built in: pass it in the plugins option")
    (refusal (fun () ->
         ignore
           (Sekreto.sekreto ~plugins:[ Hashicorp.plugin () ]
              [ { (spec "doppler") with token = "t" } ])));

  (* A kind nobody ships is a typo, and gets no such hint. *)
  same "a typo gets no plugin hint"
    "sekreto: unknown provider kind: vualt (available: dotenv, env, file, memory)"
    (refusal (fun () -> ignore (Sekreto.sekreto [ spec "vualt" ])))

(* Two providers MAY share a store name - a directed read walks both, and
   the spec pins it - but an instance ref may not, so the second gets a
   numbered tag from the host and keeps its store name. *)
let () =
  let secrets =
    Sekreto.sekreto
      [
        spec "memory";
        { (spec "memory") with values = [ ("API_TOKEN", "second") ] };
        { (spec "memory") with name = "pair" };
        { (spec "memory") with name = "pair"; values = [ ("API_TOKEN", "pair2") ] };
      ]
  in

  samelist "a repeat keeps the store" [ "memory"; "pair" ] (Sekreto.stores secrets);
  samelist "a repeat numbers the instance"
    [ "memory"; "memory$1"; "memory$2"; "memory$pair" ]
    (refsof secrets);
  same "a directed read walks both" "second" (Sekreto.getfrom secrets "memory" "api.token");
  same "a directed read walks both, named" "pair2" (Sekreto.getfrom secrets "pair" "api.token");
  Sekreto.close secrets

let () =
  same "a store name must be a valid tag" "sekreto: invalid store name: my store"
    (refusal (fun () ->
         ignore (Sekreto.sekreto [ { (spec "memory") with name = "my store" } ])))

(* ---- custom kinds, and what crosses the boundary ---------------------- *)

let shouty (values : (string * string) list) : Sekreto.provider =
  {
    Sekreto.lookup = (fun name -> List.assoc_opt (String.uppercase_ascii name) values);
    describe = (fun () -> "shouty");
  }

let () =
  let secrets =
    Sekreto.sekreto
      ~plugins:[ Provider.providerplugin "shouty" (fun spec -> shouty spec.Provider.values) ]
      [ { (spec "shouty") with values = [ ("API.TOKEN", "loud") ] } ]
  in

  same "a custom kind is one providerplugin call" "loud" (Sekreto.get secrets "api.token");
  samelist "a custom kind is an instance like any other" [ "shouty" ] (refsof secrets);
  Sekreto.close secrets

(* A provider that refuses its own configuration raises a Sekreto_error from
   inside the plugin's `define`. The spec pins that message byte for byte,
   so it must come back out of the host as itself - not wrapped as
   plugin_define_failed, and not as a plugin error. *)
let () =
  let picky =
    Provider.providerplugin "picky" (fun spec ->
        if [] = spec.Provider.values then Sekreto.fail "sekreto: picky: no values"
        else shouty spec.Provider.values)
  in

  same "a Sekreto_error raised in define comes back out as itself"
    "sekreto: picky: no values"
    (refusal (fun () -> ignore (Sekreto.sekreto ~plugins:[ picky ] [ spec "picky" ])));

  (* The real one, from a shipped plugin, through the same door. *)
  same "a plugin's own refusal crosses intact"
    "sekreto: hashicorp: unsupported kv version: 3"
    (refusal (fun () ->
         ignore
           (Sekreto.sekreto ~plugins:(Allplugins.all ())
              [ { (spec "hashicorp") with addr = "http://127.0.0.1:1"; token = "t"; kv = 3 } ])))

(* ...and any other error is not sekreto's to rewrite: it surfaces as the
   host reports it, naming the instance and the cause.

   `providerplugin` cannot produce one - its `make` raises a Sekreto_error
   or nothing - so the case is reachable only for a definition built by
   hand, which is exactly the definition sekreto did not write. *)
let () =
  let broken =
    {
      Defs.dname = "broken";
      shape = V.vnull;
      define = Some (fun _inst -> Types.fail "plugin_bare" "boom");
      activate = None;
      deactivate = None;
      close = None;
      reconfigure = None;
    }
  in

  match Sekreto.sekreto ~plugins:[ broken ] [ spec "broken" ] with
  | _ -> check "a definition that raises does not build" false
  | exception Types.Plugin_error err ->
    same "any other error raised in define is the host's report of it" "plugin_define_failed"
      err.Types.code;
    check "the host's report names the cause"
      (None <> Sekreto.findsub err.Types.message "boom");
    check "the host's report names the instance"
      (None <> Sekreto.findsub err.Types.message "broken")
  | exception Sekreto.Sekreto_error message ->
    check ("sekreto rewrote an error that was not its own: " ^ message) false

(* A definition that is not a provider plugin at all - it loads, it
   activates, it exports nothing - is refused by name. Python's twin of
   this test passes a MODULE where a definition belongs; OCaml's type
   system refuses that outright, and what remains checkable is a definition
   that is not one of sekreto's. *)
let () =
  let hollow =
    {
      Defs.dname = "hollow";
      shape = V.vnull;
      define = None;
      activate = None;
      deactivate = None;
      close = None;
      reconfigure = None;
    }
  in

  same "a definition that is not a provider plugin is refused"
    "sekreto: plugin hollow exported no provider"
    (refusal (fun () -> ignore (Sekreto.sekreto ~plugins:[ hollow ] [ spec "hollow" ])))

(* A plugin that names a built-in kind replaces it: that is how a host
   substitutes an implementation, and never an accident, because the four
   names are documented. *)
let () =
  let replaced =
    Provider.providerplugin "memory" (fun _spec ->
        { Sekreto.lookup = (fun _name -> Some "replaced"); describe = (fun () -> "memory") })
  in

  let secrets =
    Sekreto.sekreto ~plugins:[ replaced ]
      [ { (spec "memory") with values = [ ("API_TOKEN", "original") ] } ]
  in

  same "a plugin may replace a built-in kind" "replaced" (Sekreto.get secrets "api.token");
  samelist "replacing adds no kind"
    [ "dotenv"; "env"; "file"; "memory" ]
    (names (Sekreto.catalog secrets));
  Sekreto.close secrets

(* A provider already built joins the chain as it is, under its own store
   name, backed by no instance. *)
let () =
  let secrets =
    Sekreto.make ~names:[ ""; "quiet" ]
      [ shouty [ ("API.TOKEN", "loud") ]; shouty [] ]
  in

  samelist "a live provider joins the chain" [ "shouty"; "quiet" ] (Sekreto.stores secrets);
  samelist "a live provider is backed by no instance" [] (refsof secrets);
  same "a live provider answers" "loud" (Sekreto.get secrets "api.token")

let () =
  (* The provider table is module-global, so a chain that has been closed
     and one that was refused must both leave it where they found it. *)
  let before = Provider.stashed () in

  let secrets =
    Sekreto.sekreto [ { (spec "memory") with values = [ ("API_TOKEN", "tok01") ] } ]
  in

  same "one built-in is a chain" "tok01" (Sekreto.get secrets "api.token");
  same "a live chain holds its provider" (before + 1) (Provider.stashed ());
  Sekreto.close secrets;

  samelist "close unloads every instance" [] (refsof secrets);
  samelist "close empties the chain" [] (Sekreto.stores secrets);
  same "close makes a read miss" None (Sekreto.tryget secrets "api.token");
  same "close keeps redaction" "token=[redacted]" (Sekreto.redacttext secrets "token=tok01");
  same "close hands every handle back" before (Provider.stashed ());

  (* A construction that fails partway leaves nothing behind either: the
     first entry was built before the second was refused. *)
  ignore
    (refusal (fun () ->
         ignore
           (Sekreto.sekreto
              [ { (spec "memory") with values = [ ("API_TOKEN", "tok01") ] }; spec "doppler" ])));
  same "a refused chain leaves nothing behind" before (Provider.stashed ())

(* ---- the core reaches no plugin --------------------------------------- *)

(* THE UNIT NAMES, TAKEN FROM THE SOURCE TREE rather than written out, so a
   plugin module added tomorrow is covered today. `plugins/http.ml` is the
   compilation unit `Http`; nothing here matches on a substring. *)
let pluginunits : string list =
  sorted
    (List.filter_map
       (fun entry ->
         if Filename.check_suffix entry ".ml" then Some (String.capitalize_ascii (Filename.remove_extension entry))
         else None)
       (Array.to_list (Sys.readdir "plugins")))

(* Every compilation unit linked into a native binary has exactly one
   `caml<Unit>__entry` symbol. Read them back by exact name. *)
let unitsof (binary : string) : string list =
  let wanted = "__entry" in
  sorted
    (List.filter_map
       (fun line ->
         match String.rindex_opt line ' ' with
         | None -> None
         | Some at ->
           let symbol = String.sub line (at + 1) (String.length line - at - 1) in
           if
             String.starts_with ~prefix:"caml" symbol
             && String.ends_with ~suffix:wanted symbol
           then
             Some
               (String.sub symbol 4 (String.length symbol - 4 - String.length wanted))
           else None)
       (lines ("nm " ^ Filename.quote binary)))

let () =
  (* THE CONTROL COMES FIRST. Sixteen modules live under plugins/, and if
     the listing came back short the intersection below would be empty for
     the wrong reason. *)
  check "the plugin modules were listed" (15 < List.length pluginunits);
  check "the plugin modules include Hashicorp" (List.mem "Hashicorp" pluginunits);

  let core = unitsof "build/coreonly" in
  let cli = unitsof "build/sekreto-cli" in

  (* AND THE SECOND CONTROL: the same extraction, run over a binary that
     DOES link every plugin, finds every one of them. An extraction that
     read nothing, or that read the wrong symbols, fails here rather than
     passing the check it is meant to police. *)
  check "nm read the core-only binary" (20 < List.length core);
  check "nm read the CLI binary" (20 < List.length cli);
  List.iter
    (fun unit ->
      check ("the CLI links " ^ unit) (List.mem unit cli))
    pluginunits;

  (* The claim itself, unit by unit and by exact name. *)
  List.iter
    (fun unit ->
      check ("the core links no " ^ unit) (not (List.mem unit core)))
    pluginunits;

  (* ...and it linked the core, so the absence above is absence and not an
     empty read. *)
  List.iter
    (fun unit -> check ("the core links " ^ unit) (List.mem unit core))
    [ "Sekreto"; "Provider"; "Secret"; "Json"; "Host"; "Catalog"; "Value"; "Defs" ];

  (* A LIST THAT IS NOT THE DIRECTORY LISTING, because the listing answers
     the wrong question if a module MOVES. `plugins/http.ml` dragged back
     into `src/` would leave the check above with nothing to find; these
     names may not be in a core-only binary wherever their source sits. *)
  List.iter
    (fun unit -> check ("the core links no " ^ unit ^ " under any name") (not (List.mem unit core)))
    ([ "Http"; "Httpjson"; "Tls"; "Sigv4"; "Crypto"; "Runcmd"; "Allplugins" ]
    @ List.map String.capitalize_ascii Provider.pluginkinds);

  (* And the general form of the same question: every unit in the binary
     that is not the OCaml runtime was compiled against build/core, the
     staging directory that holds the core's interfaces and voxgig/plugin's
     and no interface from `plugins/`. A unit with no interface there got
     in by a route nobody intended. *)
  let runtime unit =
    String.starts_with ~prefix:"Stdlib" unit
    || String.starts_with ~prefix:"Camlinternal" unit
    || List.mem unit [ "Unix"; "UnixLabels"; "Std_exit" ]
  in
  let own = List.filter (fun unit -> not (runtime unit)) core in

  check "the core-only binary has units of its own" (5 < List.length own);
  List.iter
    (fun unit ->
      check
        ("the core was compiled against " ^ unit)
        (Sys.file_exists ("build/core/" ^ String.uncapitalize_ascii unit ^ ".cmi")))
    own;

  (* The C side says the same thing louder: the TLS binding is a plugin
     concern, so a core-only program loads no OpenSSL at all. *)
  let names binary =
    String.concat " " (lines ("ldd " ^ Filename.quote binary))
  in
  let corelibs = names "build/coreonly" and clilibs = names "build/sekreto-cli" in

  check "ldd read the core-only binary" (None <> Sekreto.findsub corelibs "libc.so");
  check "ldd read the CLI binary" (None <> Sekreto.findsub clilibs "libc.so");
  check "the CLI loads libssl" (None <> Sekreto.findsub clilibs "libssl");
  check "the CLI loads libcrypto" (None <> Sekreto.findsub clilibs "libcrypto");
  check "the core loads no libssl" (None = Sekreto.findsub corelibs "libssl");
  check "the core loads no libcrypto" (None = Sekreto.findsub corelibs "libcrypto")

(* WHAT EACH MODULE IMPORTS, from the compiled unit rather than from a
   `open` line: ocamlobjinfo's "Implementations imported" is the linker's
   own answer, and it names a module reached through a re-export as
   readily as one named outright. *)
let importsof (unit : string) : string list =
  let out = ref [] in
  let inside = ref false in

  List.iter
    (fun line ->
      let trimmed = String.trim line in
      if String.starts_with ~prefix:"Implementations imported" trimmed then inside := true
      else if "" <> trimmed && not (String.starts_with ~prefix:"\t" line) then inside := false
      else if !inside then
        match String.rindex_opt trimmed '\t' with
        | Some at -> out := String.sub trimmed (at + 1) (String.length trimmed - at - 1) :: !out
        | None -> out := trimmed :: !out)
    (lines ("ocamlobjinfo " ^ Filename.quote unit));

  sorted !out

let () =
  let coremodules = [ "json"; "secret"; "provider"; "sekreto" ] in

  List.iter
    (fun name ->
      let imported = importsof ("build/core/" ^ name ^ ".cmx") in
      check ("ocamlobjinfo read " ^ name) (2 < List.length imported);
      List.iter
        (fun unit ->
          check ("src/" ^ name ^ ".ml imports no " ^ unit) (not (List.mem unit imported)))
        pluginunits)
    coremodules;

  (* The control for the reader itself: the core's own graph is there to be
     read, so a parser that answered nothing would fail here. *)
  check "the facade imports the built-ins"
    (List.mem "Provider" (importsof "build/core/sekreto.cmx"));
  check "the facade imports the plugin host"
    (List.mem "Host" (importsof "build/core/sekreto.cmx"));

  (* One plugin imports itself, the core, and - only if it dials one - the
     shared HTTP-JSON helper. It never imports another provider kind, and
     it never imports the full set. *)
  let hashicorp = importsof "build/plugins/hashicorp.cmx" in
  samelist "one plugin imports only what it needs"
    [ "Httpjson"; "Json"; "Provider"; "Secret"; "Stdlib"; "Stdlib__Option"; "Unix" ]
    hashicorp;

  (* secretspec reads its own CLI and nothing else, so it takes no HTTP
     client - and therefore no TLS anywhere in its closure. If that ever
     stops being true it is a real change, not a tidy-up. *)
  samelist "secretspec reaches no transport"
    [ "Provider"; "Runcmd"; "Secret"; "Stdlib"; "Unix" ]
    (importsof "build/plugins/secretspec.cmx");

  (* ...and no plugin reaches the full set, which is what makes naming one
     kind cost one kind. *)
  List.iter
    (fun unit ->
      let file = "build/plugins/" ^ String.uncapitalize_ascii unit ^ ".cmx" in
      if "Allplugins" <> unit && Sys.file_exists file then
        check (unit ^ " imports no full set") (not (List.mem "Allplugins" (importsof file))))
    pluginunits

let () =
  Printf.printf "\n%d passed, %d failed\n" !passcount !failcount;
  exit (if 0 = !failcount then 0 else 1)
