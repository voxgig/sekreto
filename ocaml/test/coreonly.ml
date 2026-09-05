(* RUN: make coreproof
   RUN-SOME: ./build/coreonly

   A CONSUMER WHOSE CHAIN IS BUILT-INS ONLY, AS A WHOLE PROGRAM.

   It is compiled against build/core alone - a directory that holds the
   core's interfaces and voxgig/plugin's, and not one interface from
   `plugins/` - and linked with neither the plugin archive, nor the TLS
   stubs, nor `-lssl`. So it is the split as an artifact rather than as a
   claim: a core module that named a plugin would not compile, and a core
   that dragged one in would not link.

   test/plugins.ml reads the binary back with `nm` and names, unit by unit,
   what is in it and what is not. *)

let () =
  let secrets =
    Sekreto.sekreto
      [
        { Provider.nospec with kind = "memory"; values = [ ("API_TOKEN", "tok01") ] };
        { Provider.nospec with kind = "env" };
        { Provider.nospec with kind = "dotenv"; file = "/nonexistent-sekreto-core/.env" };
        { Provider.nospec with kind = "file"; dir = "/nonexistent-sekreto-core" };
      ]
  in

  (* A chain of the four built-ins answers, with no plugin loaded at all. *)
  print_endline ("secret: " ^ Sekreto.get secrets "api.token");
  print_endline ("stores: " ^ String.concat " " (Sekreto.stores secrets));

  (* ...and it is a voxgig/plugin host like any other: the refs read like
     the chain, and every one of them is live. *)
  let status = Host.list (Sekreto.host secrets) in
  print_endline
    ("host: "
    ^ String.concat " "
        (List.map
           (fun r -> r ^ "=" ^ Value.as_str (Value.get status r))
           (Value.keys status)));

  Sekreto.close secrets
