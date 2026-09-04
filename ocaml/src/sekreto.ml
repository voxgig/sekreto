(* sekreto: one interface for secrets, wherever they live.

   A Sekreto is an ordered chain of providers. `get` asks each in turn and
   returns the first hit, so an app can be configured from environment
   variables in development and a vault in production without changing a
   line of its own code.

   A provider answers one question: "do you have this secret?" It answers
   with the value, or None to mean "ask the next one". Nothing else about a
   provider is visible to the caller - which is the point: an app reads
   `api.token` and never learns whether it came from the environment, a
   .env file, HashiCorp Vault or a boru vault.

   A port of typescript/src/Sekreto.ts, which is canonical. *)

(* Anything sekreto refuses to do: a bad name, a missing secret, a provider
   that could not be reached. The message is the whole contract - no code,
   no fields, no cause. *)
exception Sekreto_error of string

(* The conformance runner reads a subject's failure with
   `Printexc.to_string`, and so does any OCaml host that catches this.
   Without a printer the message would be reported as
   `Sekreto.Sekreto_error("...")`, and the corpus pins refusal messages
   byte for byte. *)
let () = Printexc.register_printer (function Sekreto_error m -> Some m | _ -> None)

let fail message = raise (Sekreto_error message)

(* A source of secrets.

   A record of two functions rather than a class or a module type: the
   provider set is open, a provider carries its own state in its closures,
   and a caller can hand in one of its own with no ceremony. *)
type provider = {
  (* The value, or None if this provider does not have it. *)
  lookup : string -> string option;
  (* A short description, shown by `sources`. *)
  describe : unit -> string;
}

(* ---- pure name functions -------------------------------------------- *)

(* Drop a suffix if it is there. `.` and `_` both appear in names, so this
   is spelled out rather than reached for through a pattern. *)
let dropsuffix (text : string) (suffix : string) : string =
  let tlen = String.length text and slen = String.length suffix in
  if tlen >= slen && String.sub text (tlen - slen) slen = suffix then
    String.sub text 0 (tlen - slen)
  else text

(* Split on the literal dot, KEEPING trailing empties, so that `a.` is two
   segments and not one. *)
let segments (name : string) : string list = String.split_on_char '.' name

(* A segment is one or more of [a-z0-9_], scanned rather than matched.

   The obvious `^[a-z0-9_]+$` is not the check it looks like: in several
   regex dialects `$` also matches before a final newline, and four ports
   accepted `api.token\n` because of it. The corpus pins that case, and
   `api\n.token` and `api.token\r` with it. A character scan cannot have
   the bug. *)
let validsegment (part : string) : bool =
  "" <> part
  && String.for_all (fun ch -> ('a' <= ch && ch <= 'z') || ('0' <= ch && ch <= '9') || '_' = ch) part

(* Is this a well-formed secret name? Never raises. *)
let validname (name : string) : bool =
  "" <> name && List.for_all validsegment (segments name)

(* The name, or a Sekreto_error. Every entry point checks its name here. *)
let checkname (name : string) : string =
  if not (validname name) then fail ("sekreto: invalid name: " ^ name);
  name

(* ASCII uppercasing, deliberately locale-invariant: a Turkish locale turns
   `i` into a dotted capital on several platforms, and `api.token` would
   stop being `API_TOKEN`. *)
let upper (text : string) : string = String.uppercase_ascii text

(* The environment-variable key for a name: `api.token` -> `API_TOKEN`.

   The prefix is NOT uppercased - it is given exactly as it will appear. *)
let envkey ?(prefix = "") (name : string) : string =
  prefix ^ upper (String.concat "_" (segments (checkname name)))

(* Where a name lives in a KV vault. *)
type vaultref = { path : string; field : string }

(* `api.token` -> `api` / `token`.

   A single-segment name has no path of its own, so it becomes a secret of
   that name with the conventional field `value`. *)
let vaultref (name : string) : vaultref =
  let parts = segments (checkname name) in
  match parts with
  | [ only ] -> { path = only; field = "value" }
  | _ ->
    let count = List.length parts in
    let head = List.filteri (fun index _ -> index < count - 1) parts in
    { path = String.concat "/" head; field = List.nth parts (count - 1) }

(* A name flattened to one segment: `api.token` -> `api_token` (GCP Secret
   Manager, `_`) or `api-token` (Azure Key Vault, `-`).

   Those stores have no path hierarchy and reject dots in ids, so the dots
   become the store's conventional separator. With `-` as the separator,
   underscores flatten too: Azure Key Vault's alphabet is letters, digits
   and hyphens only, and a valid sekreto name like `with_underscore` must
   still be representable there. *)
let flatname (name : string) (sep : string) : string =
  let flat = String.concat sep (segments (checkname name)) in
  if "-" = sep then String.concat "-" (String.split_on_char '_' flat) else flat

(* The AWS SSM Parameter Store name for a name: dots become the path
   hierarchy, rooted at `/` (or at a prefix): `db.pass.main` ->
   `/db/pass/main`, or `/app/db/pass/main` under prefix `/app`. *)
let awsparam ?(prefix = "") (name : string) : string =
  let checked = checkname name in
  let base = if "" <> prefix && not (String.starts_with ~prefix:"/" prefix) then "/" ^ prefix else prefix in
  let base = dropsuffix base "/" in
  base ^ "/" ^ String.concat "/" (segments checked)

(* Newline, carriage return, tab, backslash and double quote are the five
   escapes a double-quoted .env value may carry. ANY OTHER escape is
   preserved as backslash plus character, and a trailing backslash is
   literal - a scan, not a chain of replacements. *)
let unescape (text : string) : string =
  let out = Buffer.create (String.length text) in
  let index = ref 0 in
  let len = String.length text in

  while !index < len do
    if '\\' = text.[!index] && !index + 1 < len then begin
      let next = text.[!index + 1] in
      index := !index + 2;
      match next with
      | 'n' -> Buffer.add_char out '\n'
      | 'r' -> Buffer.add_char out '\r'
      | 't' -> Buffer.add_char out '\t'
      | '\\' -> Buffer.add_char out '\\'
      | '"' -> Buffer.add_char out '"'
      | other ->
        Buffer.add_char out '\\';
        Buffer.add_char out other
    end
    else begin
      Buffer.add_char out text.[!index];
      incr index
    end
  done;

  Buffer.contents out

let istrimmable = function ' ' | '\t' | '\n' | '\r' | '\012' -> true | _ -> false

let trim (text : string) : string =
  let len = String.length text in
  let start = ref 0 and stop = ref len in
  while !start < !stop && istrimmable text.[!start] do incr start done;
  while !stop > !start && istrimmable text.[!stop - 1] do decr stop done;
  String.sub text !start (!stop - !start)

(* Set a key in an insertion-ordered association list; a later duplicate
   overwrites in place. *)
let assocset (entries : (string * string) list) (key : string) (value : string) :
    (string * string) list =
  if List.mem_assoc key entries then
    List.map (fun (k, v) -> if k = key then (k, value) else (k, v)) entries
  else entries @ [ (key, value) ]

(* Parse `.env` text into raw keys and values, in the order they appear.

   There is no `.env` standard, so this function is the specification.
   Deliberately small: `KEY=value`, an optional `export`, `#` comments on
   their own line, and single- or double-quoted values (double quotes also
   unescape). A line with no `=`, or with an empty key, is skipped in
   silence rather than aborting the lines after it. *)
let parsedotenv (text : string) : (string * string) list =
  let out = ref [] in

  List.iter
    (fun rawline ->
      let line = trim (dropsuffix rawline "\r") in

      if "" <> line && '#' <> line.[0] then begin
        let entry =
          if String.starts_with ~prefix:"export " line then
            trim (String.sub line 7 (String.length line - 7))
          else line
        in

        match String.index_opt entry '=' with
        | Some eq when 0 < eq ->
          let key = trim (String.sub entry 0 eq) in
          let value = trim (String.sub entry (eq + 1) (String.length entry - eq - 1)) in
          let vlen = String.length value in

          let value =
            if 2 <= vlen && '"' = value.[0] && '"' = value.[vlen - 1] then
              unescape (String.sub value 1 (vlen - 2))
            else if 2 <= vlen && '\'' = value.[0] && '\'' = value.[vlen - 1] then
              String.sub value 1 (vlen - 2)
            else value
          in

          out := assocset !out key value
        (* No `=` at all, or an empty key: skipped, and the rest of the file
           is still read. *)
        | _ -> ()
      end)
    (String.split_on_char '\n' text);

  !out

(* Every occurrence of `needle` in `text` replaced by `into`, literally.

   Not a pattern substitution: a secret containing pattern metacharacters
   must not be interpreted as one. *)
let replaceall (text : string) (needle : string) (into : string) : string =
  if "" = needle then text
  else begin
    let out = Buffer.create (String.length text) in
    let nlen = String.length needle and tlen = String.length text in
    let index = ref 0 in

    while !index < tlen do
      if !index + nlen <= tlen && String.sub text !index nlen = needle then begin
        Buffer.add_string out into;
        index := !index + nlen
      end
      else begin
        Buffer.add_char out text.[!index];
        incr index
      end
    done;

    Buffer.contents out
  end

(* Replace known secret values in text with `[redacted]`.

   Only values of four characters or more are replaced: shorter ones are too
   likely to appear in ordinary text, and redacting them would make logs
   unreadable without making them safer.

   Longest first, always, so that a value which is a prefix of another
   cannot redact the shorter half and leave the rest on the page. The
   corpus pins both arrival orders of the same pair, so the case cannot pass
   by luck. The sort is over a COPY: `values` is the caller's, and it is the
   live `seen` list when this is called through a Sekreto. *)
let redact (text : string) (values : string list) : string =
  let usable = List.filter (fun value -> 4 <= String.length value) values in
  let ordered =
    List.stable_sort (fun l r -> compare (String.length r) (String.length l)) usable
  in
  List.fold_left (fun out value -> replaceall out value "[redacted]") text ordered

(* The store name a provider answers to when nothing says otherwise.

   `describe()` opens with the provider's kind - `hashicorp:...`,
   `dotenv:...`, plain `env` - so the kind is the natural default, and a
   custom provider gets a sensible name without implementing anything
   extra. *)
let storename (provider : provider) : string =
  let text = provider.describe () in
  match String.index_opt text ':' with
  | None -> text
  | Some at -> String.sub text 0 at

(* ---- the facade ------------------------------------------------------ *)

type entry = { store : string; eprovider : provider }
type cached = { cstore : string; cname : string; cvalue : string }

type t = {
  mutable entries : entry list;
  (* A list, not a map: the store a value came from stays attached, and
     redaction order does not vary between runs. *)
  mutable cache : cached list;
  (* Every value ever resolved, for `redacttext`. Kept independently of the
     read cache so that redaction still works when caching is off -
     otherwise an uncached Sekreto would silently disable redaction and leak
     secrets to logs. Append-only for the object's life: neither `refresh`
     nor `close` clears it. Held reversed, and reversed back on read. *)
  mutable seen : string list;
  docache : bool;
}

(* Build a chain. `names` is positional; an entry left empty falls back to
   the provider's kind. Construction contacts nothing - the first network
   call is the first lookup. *)
let make ?(names = []) ?(cache = true) (providers : provider list) : t =
  let entries =
    List.mapi
      (fun index provider ->
        let named = match List.nth_opt names index with Some n -> n | None -> "" in
        { store = (if "" <> named then named else storename provider); eprovider = provider })
      providers
  in
  { entries; cache = []; seen = []; docache = cache }

(* The single path both readers share. The name is validated FIRST, before
   the cache and before the first provider is asked. *)
let resolve (self : t) (store : string) (name : string) (useentries : entry list) :
    string option =
  ignore (checkname name);

  let hit =
    if self.docache then
      List.find_opt (fun c -> store = c.cstore && name = c.cname) self.cache
    else None
  in

  match hit with
  | Some c -> Some c.cvalue
  | None ->
    let rec walk = function
      | [] -> None
      | e :: rest -> (
        (* The empty string is a hit; None and only None is a miss. *)
        match e.eprovider.lookup name with Some value -> Some value | None -> walk rest)
    in
    let found = walk useentries in
    (match found with
    | Some value ->
      if self.docache then self.cache <- self.cache @ [ { cstore = store; cname = name; cvalue = value } ];
      self.seen <- value :: self.seen
    (* Misses are never cached. *)
    | None -> ());
    found

(* The secret, or None if no provider has it. Named `tryget` because `try`
   is an OCaml keyword. *)
let tryget (self : t) (name : string) : string option = resolve self "" name self.entries

(* The secret, or a Sekreto_error if no provider has it. *)
let get (self : t) (name : string) : string =
  match tryget self name with
  | Some value -> value
  | None -> fail ("sekreto: unknown secret: " ^ name)

(* The secret from one named store, or None if that store does not have it.

   Naming a store that is not in the chain is an error, not a miss:
   `tryget` already means "this store may not have it", so it cannot also
   mean "this store may not exist" without hiding a typo. The refusal comes
   before the name is validated. *)
let tryfrom (self : t) (store : string) (name : string) : string option =
  let matching = List.filter (fun e -> store = e.store) self.entries in
  if [] = matching then fail ("sekreto: unknown store: " ^ store);
  resolve self store name matching

let getfrom (self : t) (store : string) (name : string) : string =
  match tryfrom self store name with
  | Some value -> value
  | None -> fail ("sekreto: unknown secret: " ^ store ^ ":" ^ name)

let has (self : t) (name : string) : bool = None <> tryget self name
let hasin (self : t) (store : string) (name : string) : bool = None <> tryfrom self store name

(* Every named secret at once. Missing ones are an error. *)
let all (self : t) (names : string list) : (string * string) list =
  List.map (fun name -> (name, get self name)) names

(* A description of each provider, in resolution order, repeats kept. *)
let sources (self : t) : string list = List.map (fun e -> e.eprovider.describe ()) self.entries

(* The name of each store `getfrom` can address, in resolution order and
   without repeats. *)
let stores (self : t) : string list =
  let rec dedupe seen = function
    | [] -> []
    | head :: rest ->
      if List.mem head seen then dedupe seen rest else head :: dedupe (head :: seen) rest
  in
  dedupe [] (List.map (fun e -> e.store) self.entries)

(* Replace every value this Sekreto has resolved with `[redacted]`. Works
   whether or not caching is on. *)
let redacttext (self : t) (text : string) : string = redact text (List.rev self.seen)

(* Drop cached values, so the next `get` asks the providers again. The
   redaction history is not touched. *)
let refresh (self : t) : unit = self.cache <- []

(* Tear the chain down. Afterwards `stores` and `sources` are empty, `get`
   raises and `tryget` misses - and redaction still knows every value ever
   resolved, which is the whole point of keeping `seen` separately. *)
let close (self : t) : unit =
  self.entries <- [];
  self.cache <- []

(* ---- print hooks -----------------------------------------------------

   `cache` and `seen` are ordinary fields, so the default printer of a
   `t` would put every resolved secret on the page. Neither hook below can
   reach a value. *)

let to_string (self : t) : string = "Sekreto { stores: [ " ^ String.concat ", " (stores self) ^ " ] }"
let to_json (self : t) : string =
  "{\"stores\":[" ^ String.concat "," (List.map (fun s -> "\"" ^ s ^ "\"") (stores self)) ^ "]}"
