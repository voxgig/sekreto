(* RUN: make test
   RUN-SOME: ./build/behaviour

   What the shared corpus cannot reach.

   `spec/sekreto.json` never opens a socket and touches the filesystem
   exactly once, so a port could pass all fourteen groups with no transport
   at all. These are the rules that live outside it: the whole `checkaddr`
   decision table, strict base64, a miss that is not a failure on a real
   file, the cache and redaction lifecycle, and the name-versus-address
   decision that routes hostname verification and SNI in the TLS binding.

   The handshake itself is proved against a real server by
   `test/tlsproof.sh` (`make tlscheck`), which is the only thing that can
   prove it. *)

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

(* The refusal a call raises, or the empty string when it did not raise. *)
let refusal (body : unit -> unit) : string =
  match body () with
  | () -> ""
  | exception Sekreto.Sekreto_error message -> message

(* ---- checkaddr: the whole decision table ----------------------------- *)

let () =
  let allowed =
    [
      "https://vault.example.com:8200";
      "https://vault.example.com";
      "http://localhost:8200";
      "http://LOCALHOST:8200";
      "http://127.0.0.1:8200";
      "http://[::1]:8200";
      (* An `@` AFTER the authority is path, not userinfo. *)
      "http://localhost:8200/v1/a@b";
    ]
  in
  List.iter
    (fun addr -> same ("checkaddr allows " ^ addr) "" (refusal (fun () -> Providers.checkaddr addr)))
    allowed;

  let refused =
    [
      (* Nothing is normalised: a numeric form the parsers disagree about is
         refused rather than guessed at. *)
      ("http://vault.example.com:8200", "sekreto: refusing to send a token in plaintext to http://vault.example.com:8200 (use https)");
      ("http://10.0.0.5:8200", "sekreto: refusing to send a token in plaintext to http://10.0.0.5:8200 (use https)");
      ("http://0177.0.0.1:8200", "sekreto: refusing to send a token in plaintext to http://0177.0.0.1:8200 (use https)");
      ("http://2130706433:8200", "sekreto: refusing to send a token in plaintext to http://2130706433:8200 (use https)");
      ("http://127.0.0.2:8200", "sekreto: refusing to send a token in plaintext to http://127.0.0.2:8200 (use https)");
      ("http://[::ffff:127.0.0.1]:8200", "sekreto: refusing to send a token in plaintext to http://[::ffff:127.0.0.1]:8200 (use https)");
      (* The authority ends at / ? # and NOT at a backslash, so this whole
         string is the host and it is not loopback. *)
      ("http://localhost\\.evil.example.com/", "sekreto: refusing to send a token in plaintext to http://localhost\\.evil.example.com/ (use https)");
      (* Userinfo, on https as well as http, and always through safeaddr. *)
      ("https://user:pass@vault.example.com", "sekreto: refusing an address with embedded credentials: https://[redacted]@vault.example.com");
      ("http://localhost:8200@evil.example.com/", "sekreto: refusing an address with embedded credentials: http://[redacted]@evil.example.com/");
      ("http://a@127.0.0.1@evil.example.com/", "sekreto: refusing an address with embedded credentials: http://[redacted]@evil.example.com/");
      ("http://[::1", "sekreto: not a valid http(s) address: http://[::1");
      ("ftp://127.0.0.1/", "sekreto: not an http(s) address: ftp://127.0.0.1/");
      ("127.0.0.1:8200", "sekreto: not an http(s) address: 127.0.0.1:8200");
      ("HTTP://localhost:8200", "sekreto: not an http(s) address: HTTP://localhost:8200");
      ("", "sekreto: not an http(s) address: ");
    ]
  in
  List.iter
    (fun (addr, want) ->
      same ("checkaddr refuses " ^ addr) want (refusal (fun () -> Providers.checkaddr addr)))
    refused

(* ---- strict base64 ---------------------------------------------------- *)

let () =
  same "unbase64 decodes" (Some "hello world") (Http.unbase64 "aGVsbG8gd29ybGQ=");
  same "unbase64 skips whitespace" (Some "hello world") (Http.unbase64 "aGVsbG8g\n d29ybGQ=");
  (* A lenient decoder answers plausible bytes for each of these, and those
     bytes would then be returned AS THE SECRET. *)
  same "unbase64 refuses a stray byte" None (Http.unbase64 "aGVs*bG8=");
  same "unbase64 refuses url-safe" None (Http.unbase64 "a-_x");
  same "unbase64 refuses a short group" None (Http.unbase64 "aGVsbG");
  same "unbase64 refuses three pads" None (Http.unbase64 "aGV===")

(* ---- a miss is not a failure ------------------------------------------ *)

let () =
  let dir = Filename.get_temp_dir_name () in
  let holder = Filename.concat dir "sekreto-behaviour-check" in

  (try Unix.mkdir holder 0o700 with Unix.Unix_error _ -> ());

  let secret = Filename.concat holder "API_TOKEN" in
  let och = open_out_bin secret in
  output_string och "from-a-file\n";
  close_out och;

  let provider = Providers.makeprovider { Providers.nospec with kind = "file"; dir = holder } in
  same "file strips one trailing newline" (Some "from-a-file") (provider.Sekreto.lookup "api.token");
  same "file: no such name is a MISS" None (provider.Sekreto.lookup "other.name");

  let gone = Providers.makeprovider
      { Providers.nospec with kind = "file"; dir = "/nonexistent-sekreto-behaviour" } in
  same "file: no such directory is a MISS" None (gone.Sekreto.lookup "api.token");

  (* A directory where a file should be is EISDIR, which is a store that
     could not answer, not a store without the secret. *)
  let subdir = Filename.concat holder "SUB_KEY" in
  (try Unix.mkdir subdir 0o700 with Unix.Unix_error _ -> ());
  check "file: an unreadable entry RAISES"
    (String.length (refusal (fun () -> ignore (provider.Sekreto.lookup "sub.key"))) > 0);

  (* dotenv is read once, lazily: a chain that never looks anything up must
     not read whatever .env sits in the working directory. *)
  let absent = Providers.makeprovider
      { Providers.nospec with kind = "dotenv"; file = "/nonexistent-sekreto-behaviour/.env" } in
  same "dotenv: absent file describes" "dotenv:/nonexistent-sekreto-behaviour/.env"
    (absent.Sekreto.describe ());
  same "dotenv: absent file is a MISS" None (absent.Sekreto.lookup "api.token");

  let unreadable = Providers.makeprovider
      { Providers.nospec with kind = "dotenv"; file = holder } in
  check "dotenv: a directory RAISES"
    (String.starts_with ~prefix:"sekreto: dotenv provider cannot read "
       (refusal (fun () -> ignore (unreadable.Sekreto.lookup "api.token"))));

  (try Unix.rmdir subdir with Unix.Unix_error _ -> ());
  (try Unix.unlink secret with Unix.Unix_error _ -> ());
  (try Unix.rmdir holder with Unix.Unix_error _ -> ())

(* ---- the chain lifecycle ---------------------------------------------- *)

let () =
  let chain =
    Providers.sekreto
      [
        { Providers.nospec with kind = "memory"; name = "local"; values = [ ("API_TOKEN", "AAAA1111") ] };
        { Providers.nospec with kind = "memory"; name = "shared"; values = [ ("API_TOKEN", "BBBB2222"); ("EMPTY_ONE", "") ] };
      ]
  in

  same "get takes the first hit" "AAAA1111" (Sekreto.get chain "api.token");
  same "getfrom names a store" "BBBB2222" (Sekreto.getfrom chain "shared" "api.token");
  (* The cache key is (store, name), so a transparent read and a directed
     read never alias. *)
  same "the two reads do not alias" "AAAA1111" (Sekreto.get chain "api.token");
  same "the empty string is a HIT" (Some "") (Sekreto.tryfrom chain "shared" "empty.one");
  same "stores dedupes" [ "local"; "shared" ] (Sekreto.stores chain);
  same "sources keeps repeats" [ "memory"; "memory" ] (Sekreto.sources chain);
  same "an unknown store raises" "sekreto: unknown store: nosuch"
    (refusal (fun () -> ignore (Sekreto.tryfrom chain "nosuch" "api.token")));
  (* Raised BEFORE the name is validated. *)
  same "unknown store beats a bad name" "sekreto: unknown store: nosuch"
    (refusal (fun () -> ignore (Sekreto.tryfrom chain "nosuch" "a b")));

  same "redact knows both values" "a=[redacted] b=[redacted]"
    (Sekreto.redacttext chain "a=AAAA1111 b=BBBB2222");

  same "print hooks reach no value" "Sekreto { stores: [ local, shared ] }" (Sekreto.to_string chain);
  same "to_json reaches no value" "{\"stores\":[\"local\",\"shared\"]}" (Sekreto.to_json chain);

  Sekreto.refresh chain;
  same "refresh keeps the redaction history" "[redacted]" (Sekreto.redacttext chain "AAAA1111");

  Sekreto.close chain;
  same "close empties the chain" [] (Sekreto.stores chain);
  same "close makes get raise" "sekreto: unknown secret: api.token"
    (refusal (fun () -> ignore (Sekreto.get chain "api.token")));
  (* The whole reason `seen` is kept apart from the read cache. *)
  same "redaction survives close" "[redacted]" (Sekreto.redacttext chain "AAAA1111");

  let uncached =
    Providers.sekreto ~cache:false
      [ { Providers.nospec with kind = "memory"; values = [ ("API_TOKEN", "CCCC3333") ] } ]
  in
  ignore (Sekreto.get uncached "api.token");
  same "cache:false still redacts" "[redacted]" (Sekreto.redacttext uncached "CCCC3333");

  same "an empty chain prints" "Sekreto { stores: [  ] }" (Sekreto.to_string (Providers.sekreto []))

(* ---- the kind roll-call ------------------------------------------------ *)

let () =
  let kinds =
    [ "env"; "memory"; "dotenv"; "file"; "hashicorp"; "boru"; "awssecrets"; "awsparams";
      "gcpsecrets"; "azuresecrets"; "onepassword"; "doppler"; "infisical"; "secretspec" ]
  in
  same "fourteen kinds" 14 (List.length kinds);
  List.iter
    (fun kind ->
      same ("kind builds: " ^ kind) ""
        (refusal (fun () -> ignore (Providers.makeprovider { Providers.nospec with kind }))))
    kinds;
  same "an unknown kind is named" "sekreto: unknown provider kind: nope"
    (refusal (fun () -> ignore (Providers.makeprovider { Providers.nospec with kind = "nope" })));
  same "a kv typo is refused at construction" "sekreto: hashicorp: unsupported kv version: 3"
    (refusal (fun () ->
         ignore (Providers.makeprovider { Providers.nospec with kind = "hashicorp"; kv = 3 })));
  (* A spec printer must never hand a credential to a log line. *)
  let printed =
    Providers.spectostring
      { Providers.nospec with kind = "hashicorp"; token = "s3cr3t"; secret = "s3cr3t";
        clientsecret = "s3cr3t"; auth = Some { Providers.noauth with amethod = "approle"; secretid = "s3cr3t" } }
  in
  check "the spec printer suppresses credentials" (None = Sigv4.findsub printed "s3cr3t")

(* ---- JSON ------------------------------------------------------------- *)

let () =
  same "a whole number round-trips" "1" (Json.numstr 1.0);
  same "a fraction keeps its shortest form" "0.1" (Json.numstr 0.1);
  same "infinity has no JSON form" "null" (Json.numstr infinity);
  same "not JSON is not null" None (Json.parse "nope");
  same "the literal null is a value" (Some Json.Null) (Json.parse "null");
  same "1e999 is refused, not infinite" None (Json.parse "1e999");
  same "trailing content is refused" None (Json.parse "{} {}");
  (* A body arrives before any trust check, so it must not be able to
     recurse until the stack gives out. *)
  same "deep nesting is refused" None (Json.parse (String.concat "" (List.init 200 (fun _ -> "["))));
  same "a control character is escaped" "\"a\\u0001b\"" (Json.quote "a\001b");
  same "non-ASCII is not escaped" "\"\xc3\xa9\"" (Json.quote "\xc3\xa9")

(* ---- the name-or-address decision, which routes the TLS binding ------- *)

let () =
  (* An IP literal is verified against an iPAddress SAN and gets NO SNI;
     a name is verified by DNS-name matching and does. Getting this wrong
     is how a port ends up accepting any certificate for 127.0.0.1. *)
  check "127.0.0.1 is an address" (Tls.isip "127.0.0.1");
  check "::1 is an address" (Tls.isip "::1");
  check "vault.example.com is a name" (not (Tls.isip "vault.example.com"));
  check "localhost is a name" (not (Tls.isip "localhost"));
  check "127.0.0.1.example.com is a name" (not (Tls.isip "127.0.0.1.example.com"))

let () =
  Printf.printf "\n%d passed, %d failed\n" !passcount !failcount;
  exit (if 0 = !failcount then 0 else 1)
