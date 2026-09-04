(* One vault read, reported in three words, for test/tlsproof.sh.

   The CLI would do as well, but it needs the repo's API server too; this
   asks the library the one question the TLS proof is about and prints what
   it answered. *)

let () =
  let addr = if 1 < Array.length Sys.argv then Sys.argv.(1) else "" in
  let provider =
    Providers.makeprovider { Providers.nospec with kind = "hashicorp"; addr; token = "t" }
  in
  match provider.Sekreto.lookup "api.token" with
  | Some value -> print_endline ("OK " ^ value)
  | None -> print_endline "MISS"
  | exception Sekreto.Sekreto_error message -> print_endline ("ERR " ^ message)
