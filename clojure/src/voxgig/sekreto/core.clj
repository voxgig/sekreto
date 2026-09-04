;; sekreto: one interface for secrets, wherever they live.
;;
;; A Sekreto is an ordered chain of providers. `get` asks each in turn and
;; returns the first hit, so an app can be configured from environment
;; variables in development and a vault in production without changing a
;; line of its own code.
;;
;; This namespace is the facade and the name helpers - everything that does
;; not know what a provider kind is. `voxgig.sekreto.providers` knows the
;; kinds and depends on this; `voxgig.sekreto` is the one namespace a
;; consumer requires, and republishes both.
;;
;; A port of typescript/src/Sekreto.ts, which is canonical.

(ns voxgig.sekreto.core
  (:refer-clojure :exclude [get])
  (:require [clojure.string :as string]
            [voxgig.sekreto.json :as json]
            [voxgig.sekreto.provider :as provider])
  (:import [java.util Locale]))

(defn sekretoerror
  "Anything sekreto refuses to do: a bad name, a missing secret, a provider
  that could not be reached. One error type, carrying the message the spec
  pins, so a caller can tell the library's own refusals from a bug."
  [message]
  (ex-info message {:sekreto true}))

(defn sekretoerror?
  "Is this one of sekreto's own errors?"
  [err]
  (boolean (:sekreto (ex-data err))))

;; `re-matches` anchors at both ends of the whole input. The obvious `^...$`
;; with a find would not: in java.util.regex `$` also matches BEFORE a final
;; newline, so `token\n` would pass - and the spec has that exact case.
(def ^:private NAMEPART #"[a-z0-9_]+")

(defn dropsuffix
  "Drop a suffix if it is there. `.` and `_` both appear in names, so this
  is spelled out rather than reached for through a regex."
  [^String text ^String suffix]
  (if (.endsWith text suffix) (subs text 0 (- (count text) (count suffix))) text))

(defn- upper
  "Upper case in the root locale. The default locale is the machine's, and
  in a Turkish one `i` upper-cases to a dotted capital that is not ASCII -
  so an environment variable's name would depend on where the process runs."
  [^String text]
  (.toUpperCase text Locale/ROOT))

(defn segments
  "Split on the literal dot, KEEPING trailing empties: the usual split drops
  them, which would make `a.` a valid one-segment name."
  [^String name]
  (string/split name #"\." -1))

(defn validname
  "Is this a well-formed secret name: dot-separated lowercase segments?"
  [name]
  (and (string? name)
       (not= "" name)
       (every? (fn [part] (some? (re-matches NAMEPART part))) (segments name))))

(defn checkname
  "The name, or a sekreto error. Every entry point checks its name here."
  [name]
  (when-not (validname name)
    (throw (sekretoerror (str "sekreto: invalid name: " (if (nil? name) "" name)))))
  name)

(defn envkey
  "The environment-variable key for a name: `api.token` -> `API_TOKEN`."
  ([name] (envkey name nil))
  ([name prefix]
   (str (or prefix "") (upper (string/join "_" (segments (checkname name)))))))

(defn vaultref
  "Where a name lives in a KV vault: `api.token` -> `api` / `token`.

  A single-segment name has no path of its own, so it becomes a secret of
  that name with the conventional field `value`."
  [name]
  (let [parts (segments (checkname name))]
    (if (= 1 (count parts))
      {:path (nth parts 0) :field "value"}
      {:path (string/join "/" (butlast parts)) :field (last parts)})))

(defn flatname
  "A name flattened to one segment: `api.token` -> `api_token` (GCP Secret
  Manager, `_`) or `api-token` (Azure Key Vault, `-`).

  Those stores have no path hierarchy and reject dots in ids, so the dots
  become the store's conventional separator. With `-` as the separator,
  underscores flatten too: Azure Key Vault's alphabet is letters, digits
  and hyphens only, and a valid sekreto name like `with_underscore` must
  still be representable there. (The resulting `.`/`_` collision mirrors
  the documented envkey behaviour, where both already map to `_`.)"
  [name sep]
  (let [flat (string/join sep (segments (checkname name)))]
    (if (= "-" sep) (string/replace flat "_" "-") flat)))

(defn awsparam
  "The AWS SSM Parameter Store name for a name: dots become the path
  hierarchy, rooted at `/` (or at a prefix): `db.pass.main` ->
  `/db/pass/main`, or `/app/db/pass/main` under prefix `/app`."
  ([name] (awsparam name nil))
  ([name prefix]
   (let [checked (checkname name)
         base (or prefix "")
         base (if (and (not= "" base) (not (string/starts-with? base "/"))) (str "/" base) base)
         base (dropsuffix base "/")]
     (str base "/" (string/join "/" (segments checked))))))

(defn- unescape [^String text]
  (let [out (StringBuilder.)]
    (loop [index 0]
      (if (<= (count text) index)
        (.toString out)
        (let [ch (.charAt text index)]
          (if (and (= \\ ch) (> (count text) (inc index)))
            (let [next (.charAt text (inc index))]
              (case next
                \n (.append out \newline)
                \r (.append out \return)
                \t (.append out \tab)
                \\ (.append out \\)
                \" (.append out \")
                (.append (.append out \\) next))
              (recur (+ index 2)))
            (do (.append out ch)
                (recur (inc index)))))))))

(defn- quoted? [^String value ^String mark]
  (and (<= 2 (count value)) (string/starts-with? value mark) (string/ends-with? value mark)))

(defn parsedotenv
  "Parse `.env` text into a map of raw keys to values, in the file's order.

  Deliberately small: `KEY=value`, optional `export`, `#` comments on their
  own line, and single- or double-quoted values (double quotes also
  unescape `\\n`, `\\r`, `\\t` and `\\\\`). A line with no `=` is skipped."
  [text]
  (if-not (string? text)
    (json/omap [])
    (json/omap
     (for [rawline (string/split text #"\n" -1)
           :let [line (string/trim (dropsuffix rawline "\r"))]
           :when (and (not= "" line) (not (string/starts-with? line "#")))
           :let [entry (if (string/starts-with? line "export ")
                         (string/trim (subs line 7))
                         line)
                 eq (string/index-of entry "=")]
           :when (and (some? eq) (< 0 eq))
           :let [key (string/trim (subs entry 0 eq))
                 value (string/trim (subs entry (inc eq)))]]
       [key (cond
              (quoted? value "\"") (unescape (subs value 1 (dec (count value))))
              (quoted? value "'") (subs value 1 (dec (count value)))
              :else value)]))))

(defn redact
  "Replace known secret values in text with `[redacted]`.

  Only values of four characters or more are replaced: shorter ones are too
  likely to appear in ordinary text, and redacting them would make logs
  unreadable without making them safer."
  [text values]
  (let [body (if (string? text) text "")
        ;; Longest first, so a value that contains a shorter one is redacted
        ;; whole rather than left with a `[redacted]` in its middle. `sort-by`
        ;; is stable, so equal lengths keep the caller's order - and the
        ;; caller's own list is never reordered.
        usable (->> (or values [])
                    (filter string?)
                    (filter (fn [value] (<= 4 (count value))))
                    (sort-by (fn [value] (- (count value)))))]
    (reduce (fn [out value] (string/replace out value "[redacted]")) body usable)))

(defn storename
  "The store name a provider answers to when nothing says otherwise.

  `describe` opens with the provider's kind - `hashicorp:...`,
  `dotenv:...`, plain `env` - so the kind is the natural default, and a
  custom provider gets a sensible name without implementing anything extra."
  [prov]
  (apply str (take-while (fn [ch] (not= \: ch)) (provider/describe prov))))

;; --------------------------------------------------------------- the chain

(defn notempty
  "The string, when it is one and is not empty; nil otherwise. Config that
  arrives as an empty string means \"not set\" everywhere in this library."
  [value]
  (when (and (string? value) (not= "" value)) value))

(defrecord Sekreto [entries docache cache seen])

(defn make
  "A Sekreto from live providers.

  `:names` gives the store names, positionally; an entry left nil or empty
  falls back to the provider's kind. `:cache` turns the read cache off,
  which the spec's chain groups do so that each entry starts clean."
  ([providers] (make providers nil))
  ([providers {:keys [names cache] :or {cache true}}]
   (let [named (vec names)]
     (->Sekreto
      (vec (map-indexed
            (fn [index prov]
              {:store (or (notempty (nth named index nil)) (storename prov))
               :provider prov})
            providers))
      cache
      ;; A vector, not a map: the store a value came from stays attached, and
      ;; redaction order does not vary between runs.
      (atom [])
      ;; Every value ever resolved, for `redactall`. Kept independently of
      ;; the read cache so that redaction still works when the cache is off -
      ;; otherwise an uncached Sekreto would silently disable redaction and
      ;; leak secrets to logs.
      (atom [])))))

(defn- resolvechain [secrets store name entries]
  (checkname name)

  (let [hit (when (:docache secrets)
              (some (fn [entry] (when (and (= store (:store entry)) (= name (:name entry))) entry))
                    @(:cache secrets)))]
    (if (some? hit)
      (:value hit)
      (let [found (some (fn [entry] (provider/lookup (:provider entry) name)) entries)]
        (when (some? found)
          (when (:docache secrets)
            (swap! (:cache secrets) conj {:store store :name name :value found}))
          (swap! (:seen secrets) conj found))
        found))))

(defn tryget
  "The secret, or nil if no provider has it. Named `tryget` because `try`
  is a Clojure special form."
  [secrets name]
  (resolvechain secrets "" name (:entries secrets)))

(defn get
  "The secret, or a sekreto error if no provider has it."
  [secrets name]
  (let [found (tryget secrets name)]
    (when (nil? found)
      (throw (sekretoerror (str "sekreto: unknown secret: " name))))
    found))

(defn tryfrom
  "The secret from one named store, or nil if that store does not have it.

  Naming a store that is not in the chain is an error, not a miss: `tryget`
  already means \"this store may not have it\", so it cannot also mean
  \"this store may not exist\" without hiding a typo."
  [secrets store name]
  (let [matching (filterv (fn [entry] (= store (:store entry))) (:entries secrets))]
    (when (empty? matching)
      (throw (sekretoerror (str "sekreto: unknown store: " store))))
    (resolvechain secrets store name matching)))

(defn getfrom
  "The secret from one named store, or a sekreto error if that store does
  not have it."
  [secrets store name]
  (let [found (tryfrom secrets store name)]
    (when (nil? found)
      (throw (sekretoerror (str "sekreto: unknown secret: " store ":" name))))
    found))

(defn has
  "Does any provider have this secret?"
  [secrets name]
  (some? (tryget secrets name)))

(defn hasin
  "Does this named store have this secret?"
  [secrets store name]
  (some? (tryfrom secrets store name)))

(defn all
  "Every named secret at once, in the order asked. Missing ones are an error."
  [secrets names]
  (json/omap (map (fn [name] [name (get secrets name)]) names)))

(defn sources
  "A description of each provider, in resolution order."
  [secrets]
  (mapv (fn [entry] (provider/describe (:provider entry))) (:entries secrets)))

(defn stores
  "The name of each store that can be named by `getfrom`, in resolution
  order and without repeats."
  [secrets]
  (vec (distinct (map :store (:entries secrets)))))

(defn redactall
  "Replace every value THIS Sekreto has resolved with `[redacted]`.

  Named `redactall` - as in the Perl port - because `redact` is already the
  pure two-argument function above, and both take two arguments here.

  Works whether or not caching is enabled: the redaction list is kept
  independently of the read cache."
  [secrets text]
  (redact text @(:seen secrets)))

(defn refresh
  "Drop cached values, so the next `get` asks the providers again."
  [secrets]
  (reset! (:cache secrets) [])
  nil)
