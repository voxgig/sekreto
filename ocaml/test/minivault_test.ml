(* RUN: make vaulttest
   RUN-SOME: ./build/minivaulttest restricted

   The mini vault, from both sides: the store a chain reads, and the
   programmatic API a plugin definition can publish beside it.

   The vault is not in spec/sekreto.json and cannot be until every port
   ships the kind. The spec runs against all twenty-three of them, so an
   entry naming `minivault` would fail the ports that have no such
   provider. What the shared corpus would have carried is here instead,
   plus the one thing it could not carry either way: a file written by
   this port and read by another, pinned by the vaults in test/fixture.

   Its own binary, like test/plugins.ml and for the same reason: it needs
   no omni, so a checkout with none beside it can still run this.

   A port of typescript/test/minivault.test.ts. *)

module V = Value

let master = "master-passphrase"

(* The rounds every case here uses. The library default is 210000, which is
   the point of PBKDF2 and the wrong thing to pay per assertion. *)
let rounds = 1000

let only = ref ""
let passcount = ref 0
let failcount = ref 0
let count = ref 0
let work = ref ""

exception Refused of string

let raisefail (why : string) = raise (Refused why)

let same (what : string) (want : string) (got : string) : unit =
  if want <> got then raisefail (what ^ ":\n    want: " ^ want ^ "\n    got:  " ^ got)

let samelist (what : string) (want : string list) (got : string list) : unit =
  same what (String.concat " " want) (String.concat " " got)

let truth (what : string) (got : bool) : unit = if not got then raisefail what

let holds (what : string) (want : string) (got : string) : unit =
  match Secret.findsub got want with
  | Some _ -> ()
  | None -> raisefail (what ^ ":\n    want to contain: " ^ want ^ "\n    got: " ^ got)

(* The refusal a call raises, or a failure when it did not refuse. *)
let refusal (what : string) (body : unit -> unit) : string =
  match body () with
  | () -> raisefail (what ^ ": nothing was refused")
  | exception Sekreto.Sekreto_error message -> message

let testcase (name : string) (body : unit -> unit) : unit =
  if "" = !only || name = !only then
    match body () with
    | () ->
      incr passcount;
      print_endline ("ok   - " ^ name)
    | exception Refused why ->
      incr failcount;
      print_endline ("FAIL - " ^ name ^ "\n       " ^ why)
    | exception Sekreto.Sekreto_error why ->
      incr failcount;
      print_endline ("FAIL - " ^ name ^ "\n       refused: " ^ why)
    | exception err ->
      incr failcount;
      print_endline ("FAIL - " ^ name ^ "\n       " ^ Printexc.to_string err)

(* ---- the vault under test ---------------------------------------------- *)

let vaultpath () : string =
  incr count;
  Printf.sprintf "%s/vault%d.skmv" !work !count

let vaultopts (file : string) (key : string) (passphrase : string) : Minivault.options =
  { Minivault.nooptions with ofile = file; okey = key; opassphrase = passphrase;
    oiterations = rounds }

let fresh () : Minivault.vault = Minivault.createvault (vaultopts (vaultpath ()) "" master)

let openas (file : string) (key : string) (passphrase : string) : Minivault.vault =
  Minivault.openvault (vaultopts file key passphrase)

let grantof (key : string) (passphrase : string) (names : string list) (write : bool) :
    Minivault.grantspec =
  { Minivault.nogrant with gkey = key; gpassphrase = passphrase; gnames = names; gwrite = write;
    giterations = rounds }

let valueof (v : Minivault.vault) (name : string) : string =
  match Minivault.get v name with Some held -> held | None -> "(miss)"

(* Where the committed vaults live, found by walking up. *)
let fixturedir () : string =
  let rec walk dir step =
    if 8 < step then raisefail "the fixture directory was not found"
    else if Sys.file_exists (Filename.concat dir "test/fixture/minivault.skmv") then
      Filename.concat dir "test/fixture"
    else walk (Filename.concat dir "..") (step + 1)
  in
  walk "." 0

(* EVERY committed vault, read off disk rather than listed here. A
   hard-coded list is one more place to edit when a port lands, and the
   edit that gets forgotten is the one that makes this suite stop checking
   the port that just arrived. *)
let fixtures () : string list =
  Array.to_list (Sys.readdir (fixturedir ()))
  |> List.filter (fun name -> Filename.check_suffix name ".skmv")
  |> List.sort compare

let slurp (path : string) : string =
  let channel = open_in_bin path in
  Fun.protect
    ~finally:(fun () -> close_in_noerr channel)
    (fun () -> really_input_string channel (in_channel_length channel))

let spill (path : string) (raw : string) : unit =
  let channel = open_out_bin path in
  Fun.protect ~finally:(fun () -> close_out_noerr channel) (fun () -> output_string channel raw)

(* A committed vault, copied so that a case which writes cannot edit the
   bytes the format contract is made of. *)
let fixture (name : string) : string =
  let mine = vaultpath () in
  spill mine (slurp (Filename.concat (fixturedir ()) name));
  mine

let vaultspec (file : string) (key : string) (passphrase : string) : Provider.spec =
  { Provider.nospec with kind = "minivault"; file; vaultkey = key; passphrase }

let memoryspec (key : string) (value : string) : Provider.spec =
  { Provider.nospec with kind = "memory"; values = [ (key, value) ] }

let thechain (specs : Provider.spec list) : Sekreto.t =
  Sekreto.sekreto ~cache:false ~plugins:[ Minivault.plugin () ] specs

(* ---- the file ----------------------------------------------------------- *)

let anewvaultholdsnothing () =
  let v = fresh () in
  samelist "list" [] (Minivault.list v);
  same "key" "master" (Minivault.key v);

  let info = Minivault.opened v in
  truth "the master key is not master" info.Minivault.master;
  truth "the master key may not write" info.Minivault.write;
  samelist "grants" [] info.Minivault.grants

let awrittensecretcomesback () =
  let v = fresh () in
  Minivault.set v "api.token" "tok01";
  Minivault.set v "db.pass" "hunter2";

  same "get" "tok01" (valueof v "api.token");
  samelist "list" [ "api.token"; "db.pass" ] (Minivault.list v);
  truth "has said no" (Minivault.has v "api.token");
  truth "has said yes to an unknown name" (not (Minivault.has v "nope"));
  same "an unknown name answered" "(miss)" (valueof v "nope");

  (* A SECOND HANDLE on the same file, so the assertion is about the bytes
     rather than about what this handle happens to remember. *)
  same "a new handle" "tok01" (valueof (openas (Minivault.file v) "" master) "api.token")

let thefileisbinary () =
  let v = fresh () in
  Minivault.set v "api.token" "tok01";

  let raw = slurp (Minivault.file v) in
  same "the magic is wrong" "SKMV" (String.sub raw 0 4);

  (* NOT ONE OF THESE IS IN THE FILE. The key id is plaintext by design;
     the secret's name and its value are not, and neither is the
     passphrase that unwrapped them. *)
  List.iter
    (fun secret ->
      if None <> Secret.findsub raw secret then raisefail (secret ^ " is in the file"))
    [ "api.token"; "tok01"; master ];

  truth "the key id is not in the file" (None <> Secret.findsub raw "master")

let rewritinganamereplacesit () =
  let v = fresh () in
  Minivault.set v "api.token" "first";
  Minivault.set v "api.token" "second";

  same "get" "second" (valueof v "api.token");
  samelist "one entry" [ "api.token" ] (Minivault.list v)

let removedropsaname () =
  let v = fresh () in
  Minivault.set v "api.token" "tok01";
  Minivault.set v "db.pass" "hunter2";
  Minivault.remove v "api.token";

  samelist "list" [ "db.pass" ] (Minivault.list v);
  same "a removed name answered" "(miss)" (valueof v "api.token");
  holds "remove again" "no such secret: api.token"
    (refusal "remove again" (fun () -> Minivault.remove v "api.token"))

let abadnameisrefused () =
  let v = fresh () in
  holds "set" "invalid name" (refusal "set" (fun () -> Minivault.set v "API.TOKEN" "x"));
  holds "get" "invalid name" (refusal "get" (fun () -> ignore (Minivault.get v "api..token")));
  holds "remove" "invalid name" (refusal "remove" (fun () -> Minivault.remove v ""))

(* ---- the keys ------------------------------------------------------------ *)

let arestrictedkeyreadsitsgrants () =
  let v = fresh () in
  Minivault.set v "api.token" "tok01";
  Minivault.set v "db.pass" "hunter2";
  Minivault.grant v (grantof "ci" "ci-passphrase" [ "api.token" ] false);

  let ci = openas (Minivault.file v) "ci" "ci-passphrase" in
  same "granted" "tok01" (valueof ci "api.token");

  (* THE RESTRICTION IS THE CRYPTOGRAPHY. `db.pass` is in the file and this
     key cannot derive its key, so the answer is the one a stranger gets:
     a miss. *)
  same "an ungranted name answered" "(miss)" (valueof ci "db.pass");
  samelist "list" [ "api.token" ] (Minivault.list ci);

  let info = Minivault.opened ci in
  truth "a restricted key reports master" (not info.Minivault.master);
  truth "a read-only key reports write" (not info.Minivault.write);
  samelist "grants" [ "api.token" ] info.Minivault.grants

let areadonlykeyrefusestowrite () =
  let v = fresh () in
  Minivault.set v "api.token" "tok01";
  Minivault.grant v (grantof "reader" "reader-passphrase" [ "api.token" ] false);
  Minivault.grant v (grantof "writer" "writer-passphrase" [ "api.token" ] true);

  let reader = openas (Minivault.file v) "reader" "reader-passphrase" in
  holds "read-only" "key reader is read-only"
    (refusal "read-only" (fun () -> Minivault.set reader "api.token" "x"));

  let writer = openas (Minivault.file v) "writer" "writer-passphrase" in
  Minivault.set writer "api.token" "rewritten";

  same "the master sees it" "rewritten" (valueof v "api.token")

let arestrictedkeycannotwriteanungrantedname () =
  let v = fresh () in
  Minivault.set v "api.token" "tok01";
  Minivault.grant v (grantof "ci" "ci-passphrase" [ "api.token" ] true);

  let ci = openas (Minivault.file v) "ci" "ci-passphrase" in
  holds "ungranted" "key ci was not granted db.pass"
    (refusal "ungranted" (fun () -> Minivault.set ci "db.pass" "x"))

let agrantednamethatdoesnotexistyet () =
  let v = fresh () in

  (* Granted BEFORE the name exists, which is the point: a deploy key is
     minted from a list of what a service will need. *)
  Minivault.grant v (grantof "ci" "ci-passphrase" [ "api.token" ] false);

  let ci = openas (Minivault.file v) "ci" "ci-passphrase" in
  samelist "nothing yet" [] (Minivault.list ci);
  same "a name that does not exist answered" "(miss)" (valueof ci "api.token");

  Minivault.set v "api.token" "tok01";

  same "once written" "tok01" (valueof ci "api.token");
  samelist "list" [ "api.token" ] (Minivault.list ci)

let themasterlistseverykey () =
  let v = fresh () in
  Minivault.grant v (grantof "ci" "ci-passphrase" [ "db.pass"; "api.token" ] true);

  let keys = Minivault.keys v in
  same "key count" "2" (string_of_int (List.length keys));

  let first = List.nth keys 0 in
  same "the master" "master" first.Minivault.key;
  truth "the master is not master" first.Minivault.master;
  samelist "a master is granted nothing" [] first.Minivault.grants;

  let second = List.nth keys 1 in
  same "the restricted key" "ci" second.Minivault.key;
  truth "ci reports master" (not second.Minivault.master);
  truth "ci may not write" second.Minivault.write;
  (* SORTED, so the record reads the same however the grant was spelled. *)
  samelist "grants" [ "api.token"; "db.pass" ] second.Minivault.grants

let themasteronlymethodsrefusearestrictedkey () =
  let v = fresh () in
  Minivault.set v "api.token" "tok01";
  Minivault.grant v (grantof "ci" "ci-passphrase" [ "api.token" ] true);

  let ci = openas (Minivault.file v) "ci" "ci-passphrase" in

  holds "keys" "listing the keys needs a master key"
    (refusal "keys" (fun () -> ignore (Minivault.keys ci)));
  holds "grant" "granting a key needs a master key"
    (refusal "grant" (fun () -> Minivault.grant ci (grantof "x" "y" [] false)));
  holds "revoke" "revoking a key needs a master key"
    (refusal "revoke" (fun () -> Minivault.revoke ci "master"));
  holds "rotate" "rotating the vault needs a master key"
    (refusal "rotate" (fun () -> Minivault.rotate ci));
  holds "remove" "removing a secret needs a master key"
    (refusal "remove" (fun () -> Minivault.remove ci "api.token"))

let arepeatedkeyidisrefused () =
  let v = fresh () in
  Minivault.grant v (grantof "ci" "p" [] false);

  holds "repeated" "key already exists: ci"
    (refusal "repeated" (fun () -> Minivault.grant v (grantof "ci" "q" [] false)));
  holds "no id" "a grant needs a key id"
    (refusal "no id" (fun () -> Minivault.grant v (grantof "" "p" [] false)));
  holds "no passphrase" "a grant needs a passphrase"
    (refusal "no passphrase" (fun () -> Minivault.grant v (grantof "x" "" [] false)))

let revokedropsakey () =
  let v = fresh () in
  Minivault.set v "api.token" "tok01";
  Minivault.grant v (grantof "ci" "ci-passphrase" [ "api.token" ] false);
  Minivault.revoke v "ci";

  let ci = openas (Minivault.file v) "ci" "ci-passphrase" in
  holds "revoked" "no such key: ci"
    (refusal "revoked" (fun () -> ignore (Minivault.get ci "api.token")));
  holds "revoke again" "no such key: ci"
    (refusal "revoke again" (fun () -> Minivault.revoke v "ci"));
  holds "itself" "a key cannot revoke itself"
    (refusal "itself" (fun () -> Minivault.revoke v "master"));

  (* THE SECRET IS UNTOUCHED: revoking bars a key, not a value. *)
  same "the secret stays" "tok01" (valueof v "api.token")

let rotatekeepsthesecrets () =
  let v = fresh () in
  Minivault.set v "api.token" "tok01";
  Minivault.set v "db.pass" "hunter2";
  Minivault.grant v (grantof "ci" "ci-passphrase" [ "api.token" ] false);

  Minivault.rotate v;

  same "api.token survives" "tok01" (valueof v "api.token");
  same "db.pass survives" "hunter2" (valueof v "db.pass");
  samelist "list" [ "api.token"; "db.pass" ] (Minivault.list v);

  let keys = Minivault.keys v in
  same "key count after rotate" "1" (string_of_int (List.length keys));
  same "the only key" "master" (List.nth keys 0).Minivault.key;

  (* EVERY OTHER KEY IS GONE, which is what rotation has to mean: their
     rings were sealed under passphrases this process does not have. *)
  let ci = openas (Minivault.file v) "ci" "ci-passphrase" in
  holds "ci is gone" "no such key: ci"
    (refusal "ci is gone" (fun () -> ignore (Minivault.get ci "api.token")))

(* ---- the refusals -------------------------------------------------------- *)

let awrongpassphraseandamissingfile () =
  let v = fresh () in
  Minivault.set v "api.token" "tok01";

  let wrong = openas (Minivault.file v) "" "not-the-passphrase" in
  holds "wrong passphrase" "wrong passphrase for key master, or a damaged vault"
    (refusal "wrong passphrase" (fun () -> ignore (Minivault.get wrong "api.token")));

  let unknown = openas (Minivault.file v) "nope" master in
  holds "unknown key" "no such key: nope"
    (refusal "unknown key" (fun () -> ignore (Minivault.get unknown "api.token")));

  let missing = openas (!work ^ "/not-there.skmv") "" master in
  holds "missing file" "no vault file"
    (refusal "missing file" (fun () -> ignore (Minivault.get missing "api.token")))

let adamagedfileisrefused () =
  let v = fresh () in
  Minivault.set v "api.token" "tok01";
  let raw = slurp (Minivault.file v) in

  let refuses what want made =
    let where = vaultpath () in
    spill where made;
    let held = openas where "" master in
    holds what want (refusal what (fun () -> ignore (Minivault.get held "api.token")))
  in

  (* Not a vault at all. *)
  refuses "not a vault" "not a vault file" "nonsense";
  (* Cut off part way through. *)
  refuses "truncated" "truncated" (String.sub raw 0 (String.length raw - 20));
  (* One byte of ciphertext flipped, which the GCM tag catches. *)
  refuses "flipped" "damaged"
    (String.sub raw 0 (String.length raw - 1)
    ^ String.make 1 (Char.chr (Char.code raw.[String.length raw - 1] lxor 0xff)));
  (* Trailing bytes, which a reader that stopped at the last record would
     have accepted. *)
  refuses "trailing" "trailing bytes" (raw ^ "junk")

let creatingoveranexistingvaultisrefused () =
  let v = fresh () in
  holds "create over" "vault file already exists"
    (refusal "create over" (fun () ->
         ignore (Minivault.createvault (vaultopts (Minivault.file v) "" master))))

let avaultneedsafileandapassphrase () =
  holds "no file" "a vault needs a file"
    (refusal "no file" (fun () -> ignore (Minivault.openvault (vaultopts "" "" "p"))));
  holds "no passphrase" "a vault needs a passphrase"
    (refusal "no passphrase" (fun () -> ignore (Minivault.openvault (vaultopts "v.skmv" "" ""))))

let createmakesthefileonlywhenasked () =
  let where = vaultpath () in

  let off = openas where "" master in
  holds "create off" "no vault file"
    (refusal "create off" (fun () -> ignore (Minivault.get off "api.token")));

  let on = Minivault.openvault { (vaultopts where "" master) with ocreate = true } in
  same "a new vault answered" "(miss)" (valueof on "api.token");
  Minivault.set on "api.token" "tok01";
  same "written" "tok01" (valueof on "api.token");

  (* The file is there now, so the handle that refused reads it. *)
  same "the same file" "tok01" (valueof (openas where "" master) "api.token")

let akeyidlongerthantheformatallows () =
  let v = fresh () in
  let big = String.make 300 'k' in

  holds "grant" "key id is longer than 255 bytes"
    (refusal "grant" (fun () -> Minivault.grant v (grantof big "p" [] false)));
  holds "open" "key id is longer than 255 bytes"
    (refusal "open" (fun () ->
         ignore (Minivault.openvault (vaultopts (Minivault.file v) big "p"))));

  (* AND THE VAULT IS UNHARMED: the refusal came before the write, so a
     300-character id did not shift every field after it. *)
  same "key count" "1" (string_of_int (List.length (Minivault.keys v)))

let theinfoacallergetscannotchangewhatthekeymaydo () =
  let v = fresh () in
  Minivault.set v "api.token" "tok01";
  Minivault.grant v (grantof "reader" "reader-passphrase" [ "api.token" ] false);

  let reader = openas (Minivault.file v) "reader" "reader-passphrase" in
  let info = Minivault.opened reader in
  truth "the reader key may write" (not info.Minivault.write);

  (* NOTHING TO FLIP: the record's fields are immutable, so the defect the
     review round found in the canonical - a caller flipping its own
     `write` bit - does not compile. `with` makes a new value, and the
     vault reads its own. *)
  let copied = { info with Minivault.write = true } in
  truth "the copy did not take the change" copied.Minivault.write;

  holds "still refused" "key reader is read-only"
    (refusal "still refused" (fun () -> Minivault.set reader "api.token" "x"))

let arevokedkeystopsreading () =
  let v = fresh () in
  Minivault.set v "api.token" "tok01";
  Minivault.grant v (grantof "ci" "ci-passphrase" [ "api.token" ] false);

  (* OPEN AND READING FIRST, so the handle holds its derived keys. *)
  let ci = openas (Minivault.file v) "ci" "ci-passphrase" in
  same "before" "tok01" (valueof ci "api.token");

  Minivault.revoke v "ci";

  (* The live file no longer holds the key, and a handle that answered from
     memory here would make `revoke` a suggestion. *)
  holds "after" "no such key: ci"
    (refusal "after" (fun () -> ignore (Minivault.get ci "api.token")))

let aregrantedkeyid () =
  let v = fresh () in
  Minivault.set v "api.token" "tok01";
  Minivault.grant v (grantof "ci" "first-passphrase" [ "api.token" ] false);

  let ci = openas (Minivault.file v) "ci" "first-passphrase" in
  same "before" "tok01" (valueof ci "api.token");

  Minivault.revoke v "ci";
  Minivault.grant v (grantof "ci" "second-passphrase" [ "api.token" ] false);

  (* SAME ID, DIFFERENT KEY. The handle re-derives because the sealed ring
     changed, and the old passphrase does not unwrap the new one. *)
  holds "the old passphrase" "wrong passphrase for key ci, or a damaged vault"
    (refusal "the old passphrase" (fun () -> ignore (Minivault.get ci "api.token")));

  same "the new passphrase" "tok01"
    (valueof (openas (Minivault.file v) "ci" "second-passphrase") "api.token")

let closeforgetsthederivedkeys () =
  let v = fresh () in
  Minivault.set v "api.token" "tok01";
  same "before" "tok01" (valueof v "api.token");

  Minivault.close v;

  same "after" "tok01" (valueof v "api.token")

(* ---- the committed files ------------------------------------------------- *)

(* Every port's vault holds the same keys and the same secrets, so the
   assertions do not vary with which file this is. *)
let readsthefixture (name : string) () =
  let file = fixture name in
  let owner = openas file "" "fixture-master" in

  samelist "list" [ "api.token"; "db.pass"; "deep.nested.name" ] (Minivault.list owner);
  same "api.token" "fixture-token" (valueof owner "api.token");
  same "db.pass" "fixture-pass" (valueof owner "db.pass");
  same "deep.nested.name" "fixture-deep" (valueof owner "deep.nested.name");

  samelist "keys" [ "master"; "reader"; "writer" ]
    (List.sort compare (List.map (fun (k : Minivault.keyinfo) -> k.Minivault.key)
                          (Minivault.keys owner)));

  let reader = openas file "reader" "fixture-reader" in
  samelist "reader list" [ "api.token" ] (Minivault.list reader);
  same "reader reads" "fixture-token" (valueof reader "api.token");
  same "the reader key read db.pass" "(miss)" (valueof reader "db.pass");
  holds "reader writes" "read-only"
    (refusal "reader writes" (fun () -> Minivault.set reader "api.token" "x"));

  let writer = openas file "writer" "fixture-writer" in
  samelist "writer list" [ "db.pass" ] (Minivault.list writer);
  same "writer reads" "fixture-pass" (valueof writer "db.pass");

  (* The copy is this case's own, so writing it proves the round trip
     without touching the committed bytes. *)
  Minivault.set writer "db.pass" "rewritten";
  same "the master sees it" "rewritten" (valueof owner "db.pass")

(* ---- the chain ------------------------------------------------------------ *)

let avaultisonestoreinachain () =
  let v = fresh () in
  Minivault.set v "api.token" "from the vault";

  let secrets =
    thechain [ vaultspec (Minivault.file v) "" master; memoryspec "DB_PASS" "from memory" ]
  in

  samelist "stores" [ "minivault"; "memory" ] (Sekreto.stores secrets);
  samelist "sources" [ "minivault:" ^ Minivault.file v; "memory" ] (Sekreto.sources secrets);
  same "the vault" "from the vault" (Sekreto.get secrets "api.token");
  same "memory" "from memory" (Sekreto.get secrets "db.pass")

let arestrictedkeyinachainfallsthrough () =
  let v = fresh () in
  Minivault.set v "api.token" "from the vault";
  Minivault.set v "db.pass" "also in the vault";
  Minivault.grant v (grantof "ci" "ci-passphrase" [ "api.token" ] false);

  let secrets =
    thechain
      [ vaultspec (Minivault.file v) "ci" "ci-passphrase"; memoryspec "DB_PASS" "from memory" ]
  in

  same "the grant" "from the vault" (Sekreto.get secrets "api.token");
  (* A NAME OUTSIDE THE GRANT IS A MISS, so the chain carries on rather
     than stopping at a store that holds the name but not for this key. *)
  same "falls through" "from memory" (Sekreto.get secrets "db.pass")

let thevaultbehindastoreisreachable () =
  let v = fresh () in
  Minivault.set v "api.token" "tok01";

  let secrets = thechain [ vaultspec (Minivault.file v) "" master ] in
  let api = Minivault.vaultof (Sekreto.host secrets) in

  samelist "list" [ "api.token" ] (Minivault.list api);

  (* A CHAIN READS; the API writes. Both see the same file. *)
  Minivault.set api "db.pass" "written through the api";
  same "the chain" "written through the api" (Sekreto.get secrets "db.pass")

let anamedstoreisreachedbyname () =
  let first = fresh () in
  Minivault.set first "api.token" "first";
  let second = fresh () in
  Minivault.set second "api.token" "second";

  let secrets =
    thechain
      [
        { (vaultspec (Minivault.file first) "" master) with name = "app" };
        { (vaultspec (Minivault.file second) "" master) with name = "ops" };
      ]
  in

  samelist "stores" [ "app"; "ops" ] (Sekreto.stores secrets);
  same "app" (Minivault.file first)
    (Minivault.file (Minivault.vaultof ~store:"app" (Sekreto.host secrets)));
  same "ops" (Minivault.file second)
    (Minivault.file (Minivault.vaultof ~store:"ops" (Sekreto.host secrets)));

  (* A STORE THAT IS NOT THERE REFUSES, and the alias does not stand in for
     it: picking one would be a guess, and the guess writes. *)
  holds "a store that is not there" "no minivault store named nope in this chain"
    (refusal "a store that is not there" (fun () ->
         ignore (Minivault.vaultof ~store:"nope" (Sekreto.host secrets))))

let achainwithnovaultsaysso () =
  let secrets = thechain [ memoryspec "API_TOKEN" "tok01" ] in
  holds "no vault" "no minivault store in this chain"
    (refusal "no vault" (fun () -> ignore (Minivault.vaultof (Sekreto.host secrets))))

let achainmissingthefileisrefused () =
  holds "no file" "a vault needs a file"
    (refusal "no file" (fun () -> ignore (thechain [ vaultspec "" "" "p" ])));
  holds "no passphrase" "a vault needs a passphrase"
    (refusal "no passphrase" (fun () -> ignore (thechain [ vaultspec "v.skmv" "" "" ])))

let thefileisreachedatthefirstlookup () =
  (* The file does not exist, and building the chain still succeeds: the
     handle is lazy, so a chain costs no PBKDF2 until a secret is actually
     wanted. *)
  let secrets = thechain [ vaultspec (!work ^ "/never.skmv") "" master ] in

  holds "at the first lookup" "no vault file"
    (refusal "at the first lookup" (fun () -> ignore (Sekreto.get secrets "api.token")))

(* A chain that is closed hands its vault back.

   The definition's `close` drops the handle, as it does the provider's, so
   a torn-down chain leaves the table where it found it - and `vaultof`
   refuses rather than answering from a handle nothing holds. *)
let closehandsthevaultback () =
  let v = fresh () in
  Minivault.set v "api.token" "tok01";

  let before = Minivault.stashedvaults () in
  let secrets = thechain [ vaultspec (Minivault.file v) "" master ] in

  same "one vault while the chain is live" (string_of_int (before + 1))
    (string_of_int (Minivault.stashedvaults ()));

  Sekreto.close secrets;

  same "none after close" (string_of_int before) (string_of_int (Minivault.stashedvaults ()));
  holds "vaultof after close" "no minivault store in this chain"
    (refusal "vaultof after close" (fun () ->
         ignore (Minivault.vaultof (Sekreto.host secrets))))

(* ---- the run --------------------------------------------------------------- *)

let () =
  if 1 < Array.length Sys.argv then only := Sys.argv.(1);

  work := Filename.temp_file "sekreto-minivault-" "";
  Sys.remove !work;
  Unix.mkdir !work 0o700;

  testcase "newvault" anewvaultholdsnothing;
  testcase "written" awrittensecretcomesback;
  testcase "binary" thefileisbinary;
  testcase "rewrite" rewritinganamereplacesit;
  testcase "remove" removedropsaname;
  testcase "badname" abadnameisrefused;
  testcase "restricted" arestrictedkeyreadsitsgrants;
  testcase "readonly" areadonlykeyrefusestowrite;
  testcase "ungranted" arestrictedkeycannotwriteanungrantedname;
  testcase "laternamed" agrantednamethatdoesnotexistyet;
  testcase "keys" themasterlistseverykey;
  testcase "masteronly" themasteronlymethodsrefusearestrictedkey;
  testcase "repeatedid" arepeatedkeyidisrefused;
  testcase "revoke" revokedropsakey;
  testcase "rotate" rotatekeepsthesecrets;
  testcase "wrongphrase" awrongpassphraseandamissingfile;
  testcase "damaged" adamagedfileisrefused;
  testcase "createover" creatingoveranexistingvaultisrefused;
  testcase "needsfile" avaultneedsafileandapassphrase;
  testcase "createflag" createmakesthefileonlywhenasked;
  testcase "longkeyid" akeyidlongerthantheformatallows;
  testcase "infocopy" theinfoacallergetscannotchangewhatthekeymaydo;
  testcase "revokedcached" arevokedkeystopsreading;
  testcase "regranted" aregrantedkeyid;
  testcase "close" closeforgetsthederivedkeys;

  let files = fixtures () in
  if [] = files then begin
    incr failcount;
    print_endline "FAIL - fixtures\n       no committed vault was found"
  end;
  List.iter (fun name -> testcase ("fixture:" ^ name) (readsthefixture name)) files;

  testcase "chain" avaultisonestoreinachain;
  testcase "chainfallthrough" arestrictedkeyinachainfallsthrough;
  testcase "api" thevaultbehindastoreisreachable;
  testcase "namedstore" anamedstoreisreachedbyname;
  testcase "novault" achainwithnovaultsaysso;
  testcase "badconfig" achainmissingthefileisrefused;
  testcase "lazy" thefileisreachedatthefirstlookup;
  testcase "closed" closehandsthevaultback;

  print_newline ();
  Printf.printf "%d passed, %d failed\n" !passcount !failcount;

  exit (if 0 = !failcount then 0 else 1)
