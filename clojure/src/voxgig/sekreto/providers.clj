;; The providers a Sekreto chains together.
;;
;; A provider answers one question: "do you have this secret?" It returns
;; the value, or nil to mean "ask the next one". Nothing else about a
;; provider is visible to the caller - which is the point: an app reads
;; `api.token` and never learns whether it came from the environment, a
;; .env file, HashiCorp Vault, AWS, GCP, Azure or a boru vault.
;;
;; Two failure shapes, and they are never interchangeable. A store that does
;; not hold the secret is a MISS (nil) - the chain carries on. A store that
;; could not answer - bad credentials, unreachable host, missing
;; configuration - is an ERROR, because falling through there would quietly
;; reach for a weaker store.
;;
;; A port of typescript/src/Providers.ts, which is canonical.

(ns voxgig.sekreto.providers
  (:require [clojure.string :as string]
            [voxgig.sekreto.core :as core]
            [voxgig.sekreto.json :as json]
            [voxgig.sekreto.provider :as provider]
            [voxgig.sekreto.sigv4 :as sigv4])
  (:import [java.io ByteArrayOutputStream IOException]
           [java.net URI]
           [java.net.http HttpClient HttpClient$Redirect HttpClient$Version
            HttpRequest HttpRequest$BodyPublishers HttpResponse HttpResponse$BodyHandlers]
           [java.nio.charset StandardCharsets]
           [java.nio.file Files LinkOption NoSuchFileException Path Paths]
           [java.time Duration Instant ZoneOffset]
           [java.time.format DateTimeFormatter]
           [java.util Base64 Locale]))

;; How long any single vault round-trip may take before it is treated as
;; unreachable. Ports carry the same bound.
(def ^:private TIMEOUT (Duration/ofSeconds 10))

;; How much of a response body will be read before the store is treated as
;; having answered incoherently. Ports carry the same bound.
;;
;; Far above anything real - the largest legitimate payload this library
;; fetches is Doppler's whole-config download, measured in kilobytes. A
;; bound is needed because the TIMEOUT is not one: ten seconds on a loopback
;; or datacentre link is gigabytes, and the body is accumulated in memory
;; before it is parsed. This runs on an application's startup path, so the
;; failure is the application never starting.
(def ^:private MAXBODY (* 8 1024 1024))

(defn- getenv
  "An environment variable, or nil. NOT emptied: a variable set to the empty
  string is a value the env provider answers with, and only the callers that
  treat empty as unset - `firstof` below - say so."
  [name]
  (System/getenv name))

(defn firstof
  "The first candidate that is set and non-empty, or the empty string."
  [& candidates]
  (or (some core/notempty candidates) ""))

(defn- trimslash [text] (core/dropsuffix text "/"))

(defn- authorityend
  "Where an address's authority ends: the position of the first `/`, `?` or
  `#`, or nil for none. The EARLIEST of the three - looking for them one
  after another instead answers with whichever was asked about first, so
  `http://host?a=/b` would be read as having the authority `host?a=`."
  [text]
  (let [marks (keep (fn [ch] (string/index-of text ch)) ["/" "?" "#"])]
    (when (seq marks) (apply min marks))))

(defn- path-of ^Path [& parts]
  (Paths/get ^String (first parts) ^"[Ljava.lang.String;" (into-array String (rest parts))))

(defn absent?
  "Does this read failure mean \"no secrets here\", rather than \"I could
  not answer\"?

  Absence is a MISS and the chain carries on; anything else - permission
  denied, an unreadable mount, a failing disk - is an ERROR, because
  returning a miss there falls silently through to a weaker store.

  Asked of the directory, not of the file. The obvious spelling, \"the file
  does not exist\", is wrong in exactly the case the rule exists for: that
  question is \"did the access check throw\", so it answers *no* for a
  permission failure and turned a locked directory - the canonical
  \"unreadable mount\" - into a miss. A path whose parent is a plain file
  really is \"no secrets here\", and that is what this asks. The reason
  string is not consulted: it comes from the C library's strerror and
  follows the machine's locale."
  [^Path file]
  (let [dir (.getParent file)]
    (and (some? dir) (not (Files/isDirectory dir (make-array LinkOption 0))))))

(defn- readfile
  "A file's whole text, or nil when there is simply no file there."
  [^Path file what]
  (try
    (String. (Files/readAllBytes file) StandardCharsets/UTF_8)
    ;; An absent file - or an absent directory - means "no secrets here".
    (catch NoSuchFileException _ nil)
    (catch IOException err
      (if (absent? file)
        nil
        (throw (core/sekretoerror (str "sekreto: " what " cannot read " file ": "
                                       (.getMessage err))))))))

(defn runcmd
  "Run a child to completion and collect both its streams.

  The two streams are drained CONCURRENTLY. Reading stdout to EOF and only
  then reading stderr deadlocks the moment the child writes more than one
  pipe buffer (64 KiB on Linux) to stderr: the parent is blocked waiting for
  stdout, the child is blocked waiting for room on stderr, and neither can
  move. Nothing in this library sets a timeout, so that hang is permanent -
  `get` simply never returns. secretspec's diagnostics are box-drawn and
  reach that size easily.

  The child's stdin is closed rather than left open on a pipe nobody writes
  to, so a CLI that reads it - one prompting for a passphrase when its
  environment variable is absent - sees EOF and gives up instead of waiting
  forever."
  [^ProcessBuilder builder command]
  (try
    (let [process (.start builder)]
      (.close (.getOutputStream process))

      (let [errbuf (ByteArrayOutputStream.)
            pump (fn []
                   (try
                     (.transferTo (.getErrorStream process) errbuf)
                     ;; The child went away mid-write; waitFor reports how.
                     (catch IOException _ nil)))
            drain (doto (Thread. ^Runnable pump) (.setDaemon true) (.start))
            out (String. (.readAllBytes (.getInputStream process)) StandardCharsets/UTF_8)
            status (.waitFor process)]
        (.join drain)
        {:out out
         :why (string/trim (String. (.toByteArray errbuf) StandardCharsets/UTF_8))
         :status status}))
    (catch IOException err
      (throw (core/sekretoerror (str "sekreto: cannot run " command ": " (.getMessage err)))))
    (catch InterruptedException _
      (.interrupt (Thread/currentThread))
      (throw (core/sekretoerror (str "sekreto: interrupted running " command))))))

;; HTTP/1.1, explicitly.
;;
;; java.net.http defaults to HTTP_2, and over cleartext that means an h2c
;; upgrade: the first request goes out with `Upgrade: h2c`, the declared
;; Content-Length, and NO BODY, and the body follows only after the server
;; declines. A server that checks the two against each other - Fastify does,
;; and Infisical is Fastify - rejects that request outright with "Request
;; body size did not match Content-Length", so every POST this port makes to
;; such a server fails before it is even read.
;;
;; The mocks in test/ are Node's own http module, which does not object,
;; which is why this survived until the same code met a real Infisical. No
;; vault API this library speaks needs HTTP/2.
;;
;; Redirects are never followed: a vault API does not legitimately redirect,
;; and a followed redirect would carry X-Vault-Token to the redirect's host
;; (and could downgrade https to http), which checkaddr - it only validates
;; the configured address - cannot see.
;;
;; A delay, so that requiring this namespace opens no resources: the client
;; is built by the first fetch, in a process that has one to make.
(def ^:private CLIENT
  (delay (-> (HttpClient/newBuilder)
             (.version HttpClient$Version/HTTP_1_1)
             (.followRedirects HttpClient$Redirect/NEVER)
             (.connectTimeout TIMEOUT)
             (.build))))

(defn- why
  "What an exception has to say for itself, never the empty string."
  [^Throwable err]
  (or (core/notempty (.getMessage err)) (str err)))

(defn- bare
  "A URL without its query string, for a message that must not leak one."
  [url]
  (apply str (take-while (fn [ch] (not= \? ch)) url)))

(defn safeaddr
  "An address with any userinfo replaced by `[redacted]`, for messages.

  Every refusal below names the address it refused, and one of them fires
  precisely because the address carries a credential - so printing it
  verbatim wrote the password to stderr and into the logs. It cannot be
  cleaned up afterwards either: that password was never resolved as a
  secret, so redaction has never seen it and never will. The host is what a
  reader needs to identify which chain entry is at fault; the userinfo is
  not."
  [addr]
  (let [mark (string/index-of addr "://")]
    (if (nil? mark)
      addr
      (let [rest (subs addr (+ mark 3))
            stop (authorityend rest)
            authority (if (nil? stop) rest (subs rest 0 stop))
            at (string/last-index-of authority "@")]
        (if (nil? at)
          addr
          (str (subs addr 0 (+ mark 3)) "[redacted]" (subs addr (+ mark 3 at))))))))

(defn checkaddr
  "Refuse to send a secret-bearing credential in the clear.

  A vault API is HTTPS in any real deployment; plaintext is a dev-mode
  convenience. Sending a token over http to anything but the local machine
  puts both the token and the secret it fetches on the wire for anyone on
  the path, so sekreto will not do it. Loopback stays allowed: that is
  `vault server -dev`, `boru vault serve`, and this repo's own test harness.

  The address is read by hand, in the same handful of steps in every port,
  rather than by each platform's URL parser. That is deliberate. A dozen
  parsers disagree about malformed input - where userinfo ends, whether
  `0177.0.0.1` is loopback, what an unclosed bracket means - and a check
  that answers differently in different ports is not a check.

  The rule this parse obeys, and the reason it can be trusted: it is never
  more permissive than the HTTP client that will dial the address. It ends
  the authority at `/`, `?` or `#` only, so a client that also breaks on
  `\\` (WHATWG does) can only ever see a SHORTER host than this does. It
  refuses userinfo outright rather than locating its end. It compares the
  host literally, so a numeric form no parser here agrees on is refused
  rather than guessed at."
  [addr]
  (let [scheme (cond
                 (string/starts-with? addr "https://") "https://"
                 (string/starts-with? addr "http://") "http://"
                 :else (throw (core/sekretoerror
                               (str "sekreto: not an http(s) address: " (safeaddr addr)))))
        rest (subs addr (count scheme))
        stop (authorityend rest)
        authority (if (nil? stop) rest (subs rest 0 stop))]

    ;; Userinfo is refused outright rather than parsed around, and on https
    ;; as well as http. No store this library speaks authenticates by
    ;; userinfo - they take a token or a signature - so an address carrying
    ;; one is a mistake at best. At worst it is the attack this whole
    ;; function exists to stop: `http://localhost:8200@evil.example.com/` is
    ;; a request to evil.example.com that reads, to anything that splits the
    ;; authority on ':', as loopback.
    (when (string/includes? authority "@")
      (throw (core/sekretoerror
              (str "sekreto: refusing an address with embedded credentials: " (safeaddr addr)))))

    ;; An opening bracket with no closing one is not an address at all.
    (when (and (string/starts-with? authority "[") (not (string/includes? authority "]")))
      (throw (core/sekretoerror
              (str "sekreto: not a valid http(s) address: " (safeaddr addr)))))

    (when (not= "https://" scheme)
      ;; A bracketed IPv6 literal keeps its brackets. Splitting the
      ;; authority on the first colon yields '[', so `http://[::1]:8200`
      ;; could never match - which made the '[::1]' entry below unreachable,
      ;; and refused a legitimate local vault.
      (let [host (.toLowerCase
                  ^String (if (string/starts-with? authority "[")
                            (subs authority 0 (inc (string/index-of authority "]")))
                            (apply str (take-while (fn [ch] (not= \: ch)) authority)))
                  Locale/ROOT)]
        (when-not (contains? #{"localhost" "127.0.0.1" "::1" "[::1]"} host)
          (throw (core/sekretoerror
                  (str "sekreto: refusing to send a token in plaintext to "
                       (safeaddr addr) " (use https)"))))))))

(defn fetchjson
  "One JSON round-trip: `{:status <int> :body <json>}`, where the body is
  `json/NONE` when there was nothing readable. Network failure is always an
  error - an unreachable store is a store that could not answer."
  ([method url] (fetchjson method url {} nil))
  ([method url headers] (fetchjson method url headers nil))
  ([method url headers body]
   (let [builder (doto (HttpRequest/newBuilder)
                   (.uri (URI/create url))
                   (.timeout TIMEOUT)
                   (.method method (if (nil? body)
                                     (HttpRequest$BodyPublishers/noBody)
                                     (HttpRequest$BodyPublishers/ofString
                                      body StandardCharsets/UTF_8))))

         _ (doseq [[key value] headers] (.header builder key value))

         ;; ofInputStream, not ofString: ofString buffers whatever arrives,
         ;; so an endless body would be accumulated in memory until the
         ;; deadline - which on a loopback or datacentre link is gigabytes.
         response (try
                    (.send ^HttpClient @CLIENT (.build builder)
                           (HttpResponse$BodyHandlers/ofInputStream))
                    ;; A refused connection arrives with a null message, so
                    ;; the class name stands in - "cannot reach ...: null"
                    ;; says nothing at all.
                    (catch IOException err
                      (throw (core/sekretoerror
                              (str "sekreto: cannot reach " (bare url) ": " (why err)))))
                    (catch InterruptedException _
                      (.interrupt (Thread/currentThread))
                      (throw (core/sekretoerror
                              (str "sekreto: cannot reach " (bare url) ": interrupted")))))

         ^java.io.InputStream stream (.body ^HttpResponse response)

         ;; One byte over the bound is enough to know it was exceeded. An
         ;; endless body is a store that could not answer, so this raises
         ;; rather than returning a miss - the latter would fall through to
         ;; a weaker store on an attacker's cue.
         text (try
                (let [raw (.readNBytes stream (inc MAXBODY))]
                  (when (< MAXBODY (alength raw))
                    (throw (core/sekretoerror (str "sekreto: oversized response from " (bare url)))))
                  (String. raw StandardCharsets/UTF_8))
                (catch IOException err
                  (throw (core/sekretoerror
                          (str "sekreto: cannot reach " (bare url) ": " (why err)))))
                (finally (.close stream)))

         parsed (json/parse text)]

     ;; A success status promised JSON; a body that does not parse means the
     ;; store could not answer coherently, and treating it as a miss would
     ;; fall through to a weaker store. Error statuses may carry any body -
     ;; they are decided on status alone.
     (when (and (= 200 (.statusCode ^HttpResponse response)) (json/none? parsed))
       (throw (core/sekretoerror (str "sekreto: malformed response from " (bare url)))))

     {:status (.statusCode ^HttpResponse response) :body parsed})))

(defn renewtime
  "When a logged-in token must be renewed, from its expiry in seconds (a
  JSON number, or a string as Azure IMDS sends it): now + max(seconds - 60,
  1). A missing or zero expiry means never renew."
  [expires]
  (let [seconds (cond
                  (json/asnum expires) (double expires)
                  (string? expires) (or (parse-double expires) 0.0)
                  :else 0.0)]
    (if (or (Double/isNaN seconds) (>= 0 seconds))
      Long/MAX_VALUE
      (+ (System/currentTimeMillis) (long (* 1000 (max (- seconds 60) 1.0)))))))

(defn- withtoken
  "The working token. `state` is an atom holding `{:token :renewat}`: a
  configured token is kept forever, a logged-in one is renewed shortly
  before its lease runs out - a long-running process must not keep
  presenting a token the vault already expired. `login` answers
  `[token renewat]`."
  [state login]
  (let [{:keys [token renewat]} @state]
    (if (and (some? token) (> (or renewat Long/MAX_VALUE) (System/currentTimeMillis)))
      token
      (let [[fresh until] (login)]
        (reset! state {:token fresh :renewat until})
        fresh))))

;; ------------------------------------------------------------- the builtins
;;
;; What makes a kind built in is that it reads at most a local file: it
;; opens no socket, signs no request and spawns no process.

(defrecord Env [prefix source]
  provider/Provider

  (lookup [_ name]
    (let [key (core/envkey name prefix)]
      (if (nil? source) (getenv key) (get source key))))

  (describe [_]
    (str "env" (when (core/notempty prefix) (str ":" prefix)))))

(defrecord Dotenv [file prefix values]
  provider/Provider

  (lookup [_ name]
    ;; Read once. A file that was not there when the chain was built is not
    ;; read again either: a missing .env means "no secrets here", and
    ;; re-reading it on every lookup would make a chain's answers depend on
    ;; when it was asked.
    (get (or @values (reset! values (core/parsedotenv (readfile (path-of file) "dotenv provider"))))
         (core/envkey name prefix)))

  (describe [_] (str "dotenv:" file)))

(defrecord Memory [values prefix]
  provider/Provider

  (lookup [_ name] (get values (core/envkey name prefix)))

  (describe [_]
    (str "memory" (when (core/notempty prefix) (str ":" prefix)))))

(defrecord Filedir [dir prefix]
  provider/Provider

  ;; A directory of one-secret-per-file entries, keyed like the environment:
  ;; `api.token` reads `<dir>/API_TOKEN`.
  ;;
  ;; This is the shape of a mounted Kubernetes Secret, a Docker or Swarm
  ;; secret, and a systemd credentials directory, so those all work with no
  ;; further configuration. One trailing newline is stripped - tools that
  ;; write these files disagree about it, and a newline is never part of a
  ;; secret on purpose.
  (lookup [_ name]
    (when-let [text (readfile (path-of dir (core/envkey name prefix)) "file provider")]
      (cond
        (string/ends-with? text "\r\n") (subs text 0 (- (count text) 2))
        (string/ends-with? text "\n") (subs text 0 (dec (count text)))
        :else text)))

  (describe [_] (str "file:" dir)))

;; -------------------------------------------------------------- the vaults

(defrecord Hashicorp [addr token mount kv vaultnamespace auth state]
  provider/Provider

  ;; HashiCorp Vault.
  ;;
  ;; KV v2 (the default): `api.token` reads `{addr}/v1/{mount}/data/api` and
  ;; takes the `token` field of `data.data`. KV v1 (`kv: 1`) reads
  ;; `{addr}/v1/{mount}/api` and takes the field of `data`. A 404 means "not
  ;; here" - a miss - so a vault can sit in a chain with fallbacks.
  ;;
  ;; A Vault Enterprise namespace rides the X-Vault-Namespace header, on
  ;; logins as well as reads.
  ;;
  ;; Instead of being handed a token, the provider can log in: Kubernetes
  ;; auth (the pod's service-account JWT, from its conventional path) or
  ;; AppRole. A failed login is an error, never a miss - it means this store
  ;; could not answer at all.
  (lookup [_ name]
    (checkaddr addr)

    (let [baseheaders (if (core/notempty vaultnamespace)
                        {"X-Vault-Namespace" vaultnamespace}
                        {})

          login (fn []
                  (when (nil? auth)
                    (throw (core/sekretoerror "sekreto: hashicorp: no token and no auth method")))

                  (let [method (:method auth)
                        url (str (trimslash addr) "/v1/auth/"
                                 (firstof (:mount auth) method) "/login")
                        body (case method
                               "kubernetes"
                               (let [file (or (core/notempty (:jwtfile auth))
                                              "/var/run/secrets/kubernetes.io/serviceaccount/token")
                                     jwt (or (core/notempty (:jwt auth))
                                             (core/notempty
                                              (some-> (readfile (path-of file) "hashicorp") string/trim))
                                             (throw (core/sekretoerror
                                                     (str "sekreto: hashicorp: cannot read jwt file "
                                                          file))))]
                                 (json/omap [["role" (or (:role auth) "")] ["jwt" jwt]]))

                               "approle"
                               (json/omap [["role_id" (or (:roleid auth) "")]
                                           ["secret_id" (or (:secretid auth) "")]])

                               (throw (core/sekretoerror
                                       (str "sekreto: hashicorp: unknown auth method: " method))))

                        res (fetchjson "POST" url baseheaders (json/stringify body))
                        got (json/astext (json/dig (:body res) "auth" "client_token"))]

                    (when (or (not= 200 (:status res)) (nil? (core/notempty got)))
                      (throw (core/sekretoerror
                              (str "sekreto: hashicorp login failed: " (:status res) ": " url))))

                    [got (renewtime (json/dig (:body res) "auth" "lease_duration"))]))

          live (withtoken state login)
          ref (core/vaultref name)
          base (str (trimslash addr) "/v1/" mount)
          url (if (= 1 kv)
                (str base "/" (:path ref))
                (str base "/data/" (:path ref)))

          res (fetchjson "GET" url (assoc baseheaders "X-Vault-Token" (or live "")))]

      (cond
        (= 404 (:status res)) nil

        (not= 200 (:status res))
        (throw (core/sekretoerror (str "sekreto: hashicorp error: " (:status res) ": " url)))

        :else
        (let [data (if (= 1 kv)
                     (json/dig (:body res) "data")
                     (json/dig (:body res) "data" "data"))]
          (json/astext (json/dig data (:field ref)))))))

  (describe [_] (str "hashicorp:" addr "/" mount)))

(defn borumiss?
  "Does this boru failure mean \"no such secret\" rather than \"I could not
  answer\"? Matched on boru's own wording for a missing alias."
  [why]
  (string/includes? why "no alias named"))

(defrecord Boru [command namespace home addr token mount]
  provider/Provider

  ;; A boru vault (https://github.com/boru-lang/boru).
  ;;
  ;; Two ways in, both boru's own.
  ;;
  ;; With no `addr`, the CLI: `boru vault get --reveal <alias>` prints the
  ;; secret on stdout and nothing else. The passphrase is read by boru
  ;; itself from `BORU_VAULT_PASSPHRASE`; sekreto never accepts it as config
  ;; and never puts it on a command line, where it would show up in the
  ;; process table.
  ;;
  ;; With an `addr`, boru's wire protocol: `boru vault serve` publishes a
  ;; read-only, HashiCorp-shaped provision API (boru's
  ;; design/VAULT-WIRE-PROTOCOL.0.md), authenticated by a capability token
  ;; from `boru vault grant`. A sekreto name is already a valid boru alias,
  ;; and boru aliases keep their dots, so `api.token` is the single path
  ;; segment `api.token` - not the `api`/`token` split a HashiCorp KV gets.
  ;; The value is the `value` field. A 404 is a miss; anything else the
  ;; server refuses (a revoked capability, a sealed vault) is an error.
  ;;
  ;; boru's `vault proxy` and `vault mcp` remain out of bounds: they are a
  ;; credential *broker*, built precisely so the caller never receives the
  ;; credential. `vault serve` is the provision endpoint, built to hand the
  ;; value back - that is the one sekreto uses.
  (lookup [_ name]
    (core/checkname name)

    (if (core/notempty addr)
      (do
        (checkaddr addr)
        ;; The dotted name stays one path segment: boru aliases keep dots.
        (let [alias (if (core/notempty namespace) (str namespace "/" name) name)
              url (str (trimslash addr) "/v1/" mount "/data/" alias)
              res (fetchjson "GET" url {"X-Vault-Token" (or token "")})]
          (cond
            (= 404 (:status res)) nil

            (not= 200 (:status res))
            (throw (core/sekretoerror (str "sekreto: boru serve error: " (:status res) ": " url)))

            :else (json/astext (json/dig (:body res) "data" "data" "value")))))

      (let [alias (if (core/notempty namespace) (str namespace ":" name) name)
            builder (ProcessBuilder. ^"[Ljava.lang.String;"
                                     (into-array String [command "vault" "get" "--reveal" alias]))]

        (when (core/notempty home)
          (.put (.environment builder) "BORU_HOME" home))

        (let [ran (runcmd builder command)]
          (cond
            ;; boru prints the value and one newline, and nothing else.
            (= 0 (:status ran)) (core/dropsuffix (:out ran) "\n")

            ;; "no alias named" is boru saying it does not hold this secret,
            ;; which is a miss: the chain carries on to the next provider. A
            ;; locked vault or a wrong passphrase is not a miss - treating
            ;; it as one would fall through to a weaker store without saying
            ;; so.
            (borumiss? (:why ran)) nil

            :else
            (throw (core/sekretoerror
                    (str "sekreto: boru vault error: "
                         (if (= "" (:why ran)) (str "exit " (:status ran)) (:why ran))))))))))

  (describe [_]
    (if (core/notempty addr)
      (str "boru:" addr)
      (str "boru" (when (core/notempty namespace) (str ":" namespace))))))

(defn secretspecmiss?
  "Does this SecretSpec failure mean \"no such secret\" rather than \"I
  could not answer\"?

  SecretSpec says `Secret 'API_TOKEN' not found` for both a name it does not
  declare and one declared with no value, and both are misses: this store
  does not hold it, so the chain carries on.

  MATCHED ON THE WHOLE PHRASE, NOT ON \"not found\". SecretSpec also says
  `Provider backend 'keyring' not found`, which is a store that could not
  answer at all - and reading that as a miss is the worst failure this
  library has, because the chain then falls through to a weaker store
  without saying so. The key is required to appear, so the two cannot be
  confused."
  [why key]
  (string/includes? why (str "Secret '" key "' not found")))

(defrecord Secretspec [command file profile backend reason prefix]
  provider/Provider

  ;; SecretSpec (https://secretspec.dev).
  ;;
  ;; SecretSpec is a declaration - a `secretspec.toml` naming the secrets a
  ;; project needs - plus a chain of its own backends to satisfy them from.
  ;; That makes it the same shape as sekreto one level down, and the reason
  ;; to support it is the same reason sekreto exists: a project that has
  ;; already declared its secrets there should not have to declare them
  ;; again here.
  ;;
  ;; Read through its CLI, as boru is, because that is the interface it
  ;; offers a program in another language: `secretspec get API_TOKEN` prints
  ;; the value on stdout and nothing else. A sekreto name maps to a
  ;; SecretSpec key exactly as it maps to an environment variable -
  ;; `api.token` is `API_TOKEN` - which is the convention SecretSpec's own
  ;; examples use.
  ;;
  ;; `backend` selects one of SecretSpec's backends (`--provider`, e.g.
  ;; `keyring` or `dotenv://.env`) and is called `backend` here only because
  ;; `provider` already means something else in this library.
  ;;
  ;; A reason is required, not optional: SecretSpec records every read in an
  ;; audit log and refuses to read at all without one. sekreto sends
  ;; `sekreto` unless told otherwise, so the audit trail says which tool
  ;; asked.
  (lookup [_ name]
    (let [key (core/envkey name prefix)
          args (cond-> [command]
                 (core/notempty file) (conj "--file" file)
                 true (conj "get" key)
                 (core/notempty backend) (conj "--provider" backend)
                 (core/notempty profile) (conj "--profile" profile)
                 true (conj "--reason" (firstof reason "sekreto")))
          ran (runcmd (ProcessBuilder. ^"[Ljava.lang.String;" (into-array String args)) command)]

      (cond
        ;; The value and one newline, and nothing else.
        (= 0 (:status ran)) (core/dropsuffix (:out ran) "\n")

        (secretspecmiss? (:why ran) key) nil

        :else
        (throw (core/sekretoerror
                (str "sekreto: secretspec error: "
                     (if (= "" (:why ran)) (str "exit " (:status ran)) (:why ran))))))))

  (describe [_]
    (str "secretspec" (when (core/notempty backend) (str ":" backend)))))

;; ----------------------------------------------------------------- the AWS

(defn awsnow
  "The `YYYYMMDDTHHMMSSZ` timestamp SigV4 wants, for now."
  []
  (.format (.withZone (DateTimeFormatter/ofPattern "yyyyMMdd'T'HHmmss'Z'") ZoneOffset/UTC)
           (Instant/now)))

(defn awsauth
  "Region and credentials, from config first and the standard AWS_*
  environment variables second - those are AWS's own convention, and a pod
  or CI job that has them set should just work. Missing either is an error:
  an AWS store with no credentials could not answer."
  [{:keys [region keyid secret session]}]
  (let [useregion (firstof region (getenv "AWS_REGION") (getenv "AWS_DEFAULT_REGION"))
        usekeyid (firstof keyid (getenv "AWS_ACCESS_KEY_ID"))
        usesecret (firstof secret (getenv "AWS_SECRET_ACCESS_KEY"))
        usesession (firstof session (getenv "AWS_SESSION_TOKEN"))]

    (when (= "" useregion)
      (throw (core/sekretoerror "sekreto: aws: no region (set region or AWS_REGION)")))

    (when (or (= "" usekeyid) (= "" usesecret))
      (throw (core/sekretoerror
              (str "sekreto: aws: no credentials"
                   " (set keyid/secret or AWS_ACCESS_KEY_ID/AWS_SECRET_ACCESS_KEY)"))))

    {:region useregion :keyid usekeyid :secret usesecret :session (core/notempty usesession)}))

(defn awscall
  "One signed call to an AWS JSON-1.1 API."
  [config service target payload]
  (let [auth (awsauth config)
        ;; The China partition lives under its own suffix; every other
        ;; commercial region is plain amazonaws.com.
        suffix (if (string/starts-with? (:region auth) "cn-") ".amazonaws.com.cn" ".amazonaws.com")
        useaddr (firstof (:addr config) (str "https://" service "." (:region auth) suffix))
        _ (checkaddr useaddr)
        url (str (trimslash useaddr) "/")
        extras (json/omap [["content-type" "application/x-amz-json-1.1"] ["x-amz-target" target]])
        signed (sigv4/sigv4 {:method "POST"
                             :url url
                             :service service
                             :region (:region auth)
                             :keyid (:keyid auth)
                             :secret (:secret auth)
                             :datetime (awsnow)
                             :headers extras
                             :body payload
                             :session (:session auth)})]
    (fetchjson "POST" url (merge extras signed) payload)))

(defn awsmiss?
  "Does this AWS error body name one of the not-found types? Those are a
  miss; every other failure is a store that could not answer."
  [body & types]
  (let [errtype (json/asstr (json/dig body "__type"))]
    (boolean (and errtype (some (fn [want] (string/includes? errtype want)) types)))))

(defrecord Awssecrets [region keyid secret session addr]
  provider/Provider

  ;; AWS Secrets Manager.
  ;;
  ;; `api.token` reads the secret named `api` (the vaultref path, so
  ;; `db.pass.main` reads `db/pass`) and takes the `token` field of its JSON
  ;; SecretString - the AWS idiom of one JSON map per secret. A SecretString
  ;; that is not JSON is the value itself, under the conventional field
  ;; `value`. Requests are SigV4-signed in-tree; see sigv4.clj.
  (lookup [this name]
    (let [ref (core/vaultref name)
          res (awscall this "secretsmanager" "secretsmanager.GetSecretValue"
                       (json/stringify (json/omap [["SecretId" (:path ref)]])))]

      (cond
        (and (= 400 (:status res)) (awsmiss? (:body res) "ResourceNotFoundException")) nil

        (not= 200 (:status res))
        (throw (core/sekretoerror (str "sekreto: aws secretsmanager error: " (:status res))))

        :else
        (if-let [text (json/asstr (json/dig (:body res) "SecretString"))]
          (let [fields (json/parse text)]
            (if (map? fields)
              (json/astext (json/dig fields (:field ref)))
              ;; A plain-string secret is the whole value; it has no named
              ;; fields.
              (when (= "value" (:field ref)) text)))

          ;; A binary secret has no fields to address; only the conventional
          ;; `value` field can mean "the bytes themselves".
          (let [bin (json/asstr (json/dig (:body res) "SecretBinary"))]
            (when (and bin (= "value" (:field ref)))
              (try
                (String. (.decode (Base64/getDecoder) ^String bin) StandardCharsets/UTF_8)
                ;; A store that answered incoherently is an error, and the
                ;; decoder's own complaint is not one of this library's.
                (catch IllegalArgumentException _
                  (throw (core/sekretoerror
                          "sekreto: aws secretsmanager: undecodable secret"))))))))))

  ;; Config only, never the environment: `describe` feeds the spec's sources
  ;; group, which must answer the same everywhere.
  (describe [_] (str "awssecrets:" (or region ""))))

(defrecord Awsparams [region keyid secret session addr prefix]
  provider/Provider

  ;; AWS SSM Parameter Store.
  ;;
  ;; `db.pass.main` reads the parameter `/db/pass/main` (under an optional
  ;; prefix path), decrypted. Parameter Store carries flat strings, so there
  ;; is no field indirection.
  (lookup [this name]
    (let [payload (json/omap [["Name" (core/awsparam name prefix)] ["WithDecryption" true]])
          res (awscall this "ssm" "AmazonSSM.GetParameter" (json/stringify payload))]

      (cond
        (and (= 400 (:status res)) (awsmiss? (:body res) "ParameterNotFound")) nil

        (not= 200 (:status res))
        (throw (core/sekretoerror (str "sekreto: aws ssm error: " (:status res))))

        :else (json/astext (json/dig (:body res) "Parameter" "Value")))))

  (describe [_] (str "awsparams:" (or region "") (or prefix ""))))

;; ------------------------------------------------------------ the clouds

(defrecord Gcpsecrets [project token addr metadataaddr state]
  provider/Provider

  ;; GCP Secret Manager.
  ;;
  ;; `api.token` reads secret `api_token` (dots flattened to `_`; Secret
  ;; Manager ids have no hierarchy and reject dots), latest version. The
  ;; token comes from config, then `GOOGLE_OAUTH_ACCESS_TOKEN`, then the
  ;; GCE/GKE metadata server - so on Google's own platform no credential
  ;; configuration is needed at all.
  ;;
  ;; The metadata call itself is plain http to a link-local host by platform
  ;; design; no credential rides on it, so `checkaddr` guards the Secret
  ;; Manager address instead.
  (lookup [_ name]
    (when (= "" (or project ""))
      (throw (core/sekretoerror "sekreto: gcp: no project")))

    (let [useaddr (firstof addr "https://secretmanager.googleapis.com")
          _ (checkaddr useaddr)

          login (fn []
                  (let [configured (firstof token (getenv "GOOGLE_OAUTH_ACCESS_TOKEN"))]
                    (if (not= "" configured)
                      [configured Long/MAX_VALUE]
                      (let [host (or (core/notempty metadataaddr)
                                     (when-let [named (core/notempty (getenv "GCE_METADATA_HOST"))]
                                       (str "http://" named))
                                     "http://metadata.google.internal")
                            url (str (trimslash host)
                                     "/computeMetadata/v1/instance/service-accounts/default/token")
                            res (fetchjson "GET" url {"Metadata-Flavor" "Google"})
                            got (json/astext (json/dig (:body res) "access_token"))]

                        (when (or (not= 200 (:status res)) (nil? (core/notempty got)))
                          (throw (core/sekretoerror
                                  "sekreto: gcp: no token and metadata server did not answer")))

                        [got (renewtime (json/dig (:body res) "expires_in"))]))))

          live (withtoken state login)
          url (str (trimslash useaddr) "/v1/projects/" project "/secrets/"
                   (core/flatname name "_") "/versions/latest:access")
          res (fetchjson "GET" url {"authorization" (str "Bearer " (or live ""))})]

      (cond
        (= 404 (:status res)) nil

        (not= 200 (:status res))
        (throw (core/sekretoerror (str "sekreto: gcp error: " (:status res) ": " url)))

        :else
        (when-let [data (json/asstr (json/dig (:body res) "payload" "data"))]
          (try
            (String. (.decode (Base64/getDecoder) ^String data) StandardCharsets/UTF_8)
            ;; See the aws provider: an undecodable payload is an error.
            (catch IllegalArgumentException _
              (throw (core/sekretoerror "sekreto: gcp: undecodable secret"))))))))

  (describe [_] (str "gcpsecrets:" (or project ""))))

;; The Key Vault audience an Azure token is minted for.
(def ^:private RESOURCE "https://vault.azure.net")

(defrecord Azuresecrets [vault token tenant clientid clientsecret
                         loginaddr imdsaddr apiversion state]
  provider/Provider

  ;; Azure Key Vault.
  ;;
  ;; `api.token` reads secret `api-token` (dots flattened to `-`; Key Vault
  ;; names allow nothing else), current version. The token comes from
  ;; config, then a client-credentials login when tenant/clientid/
  ;; clientsecret are given, then the IMDS managed-identity endpoint - so on
  ;; Azure's own platform no credential configuration is needed.
  ;;
  ;; As with GCP, the IMDS call is plain http to a link-local host by
  ;; platform design and carries no credential; the login and vault
  ;; addresses are `checkaddr`-guarded.
  (lookup [_ name]
    (when (= "" (or vault ""))
      (throw (core/sekretoerror "sekreto: azure: no vault")))

    ;; Only an explicit scheme is a URL; a vault NAMED httpvault must still
    ;; become https://httpvault.vault.azure.net.
    (let [vaulturl (if (or (string/starts-with? vault "http://")
                           (string/starts-with? vault "https://"))
                     vault
                     (str "https://" vault ".vault.azure.net"))
          _ (checkaddr vaulturl)

          login (fn []
                  (cond
                    (core/notempty token) [token Long/MAX_VALUE]

                    (and (core/notempty tenant)
                         (core/notempty clientid)
                         (core/notempty clientsecret))
                    (let [useloginaddr (firstof loginaddr "https://login.microsoftonline.com")
                          _ (checkaddr useloginaddr)
                          url (str (trimslash useloginaddr) "/" tenant "/oauth2/v2.0/token")
                          form (str "grant_type=client_credentials"
                                    "&client_id=" (sigv4/uriescape clientid)
                                    "&client_secret=" (sigv4/uriescape clientsecret)
                                    "&scope=" (sigv4/uriescape (str RESOURCE "/.default")))
                          res (fetchjson "POST" url
                                         {"content-type" "application/x-www-form-urlencoded"}
                                         form)
                          got (json/astext (json/dig (:body res) "access_token"))]

                      (when (or (not= 200 (:status res)) (nil? (core/notempty got)))
                        (throw (core/sekretoerror
                                (str "sekreto: azure login failed: " (:status res)))))

                      [got (renewtime (json/dig (:body res) "expires_in"))])

                    :else
                    (let [imds (str (trimslash (firstof imdsaddr "http://169.254.169.254"))
                                    "/metadata/identity/oauth2/token?api-version=2018-02-01"
                                    "&resource=" (sigv4/uriescape RESOURCE))
                          res (fetchjson "GET" imds {"Metadata" "true"})
                          got (json/astext (json/dig (:body res) "access_token"))]

                      (when (or (not= 200 (:status res)) (nil? (core/notempty got)))
                        (throw (core/sekretoerror
                                (str "sekreto: azure: no token, no client credentials,"
                                     " and IMDS did not answer"))))

                      [got (renewtime (json/dig (:body res) "expires_in"))])))

          live (withtoken state login)
          url (str (trimslash vaulturl) "/secrets/" (core/flatname name "-")
                   "?api-version=" (firstof apiversion "7.4"))
          res (fetchjson "GET" url {"authorization" (str "Bearer " (or live ""))})]

      (cond
        (= 404 (:status res)) nil

        (not= 200 (:status res))
        (throw (core/sekretoerror (str "sekreto: azure error: " (:status res) ": " (bare url))))

        :else (json/astext (json/dig (:body res) "value")))))

  (describe [_] (str "azuresecrets:" (or vault ""))))

(defrecord Onepassword [addr token vault vaultid]
  provider/Provider

  ;; 1Password, through a Connect server.
  ;;
  ;; The item titled `api.token` (titles keep their dots), in the named
  ;; vault. The value is the field with purpose PASSWORD, or the field
  ;; labelled `value`. A vault that cannot be found is an error - config
  ;; names it, so its absence is a broken store, not a missing secret.
  (lookup [_ name]
    (core/checkname name)

    (let [useaddr (trimslash (or addr ""))
          _ (when (= "" useaddr)
              (throw (core/sekretoerror "sekreto: onepassword: no addr")))
          _ (checkaddr useaddr)

          auth {"authorization" (str "Bearer " (or token ""))}

          id (or @vaultid
                 (reset! vaultid
                         (let [want (or vault "")]
                           (when (= "" want)
                             (throw (core/sekretoerror "sekreto: onepassword: no vault")))

                           (let [res (fetchjson "GET" (str useaddr "/v1/vaults") auth)
                                 list (json/asarr (:body res))]
                             (when (or (not= 200 (:status res)) (nil? list))
                               (throw (core/sekretoerror
                                       (str "sekreto: onepassword error: " (:status res)
                                            ": listing vaults"))))

                             (let [found (some (fn [entry]
                                                 (when (or (= want (json/astext (json/dig entry "id")))
                                                           (= want (json/astext (json/dig entry "name"))))
                                                   entry))
                                               list)]
                               (when (nil? found)
                                 (throw (core/sekretoerror
                                         (str "sekreto: onepassword: no vault named " want))))

                               (or (json/astext (json/dig found "id")) ""))))))

          filter (sigv4/uriescape (str "title eq \"" name "\""))
          found (fetchjson "GET" (str useaddr "/v1/vaults/" id "/items?filter=" filter) auth)
          items (json/asarr (:body found))]

      (when (or (not= 200 (:status found)) (nil? items))
        (throw (core/sekretoerror
                (str "sekreto: onepassword error: " (:status found) ": finding " name))))

      (when (seq items)
        (let [itemid (or (json/astext (json/dig (first items) "id")) "")
              item (fetchjson "GET" (str useaddr "/v1/vaults/" id "/items/" itemid) auth)]

          (when (not= 200 (:status item))
            (throw (core/sekretoerror
                    (str "sekreto: onepassword error: " (:status item) ": reading " name))))

          (let [fields (or (json/asarr (json/dig (:body item) "fields")) [])
                pick (fn [key want]
                       (some (fn [field]
                               (when (= want (json/asstr (json/dig field key))) field))
                             fields))]
            (json/astext (json/dig (or (pick "purpose" "PASSWORD") (pick "label" "value"))
                                   "value")))))))

  (describe [_] (str "onepassword:" (or vault ""))))

(defrecord Doppler [token project config addr values]
  provider/Provider

  ;; Doppler.
  ;;
  ;; The whole config is downloaded once - Doppler's own bulk endpoint - and
  ;; answered from memory, like a remote .env: `api.token` is the
  ;; `API_TOKEN` entry. A service token is config-scoped, so project and
  ;; config are only needed with broader tokens.
  (lookup [_ name]
    (let [loaded (or @values
                     (reset! values
                             (let [useaddr (trimslash (firstof addr "https://api.doppler.com"))
                                   _ (checkaddr useaddr)
                                   url (cond-> (str useaddr
                                                    "/v3/configs/config/secrets/download?format=json")
                                         (core/notempty project)
                                         (str "&project=" (sigv4/uriescape project))

                                         (core/notempty config)
                                         (str "&config=" (sigv4/uriescape config)))
                                   res (fetchjson "GET" url
                                                  {"authorization" (str "Bearer " (or token ""))})
                                   body (json/asobj (:body res))]

                               (when (or (not= 200 (:status res)) (nil? body))
                                 (throw (core/sekretoerror
                                         (str "sekreto: doppler error: " (:status res)))))

                               (json/omap (keep (fn [[key value]]
                                                  (when-let [text (json/astext value)] [key text]))
                                                body)))))]
      (get loaded (core/envkey name))))

  (describe [_]
    (str "doppler" (when (core/notempty project) (str ":" project "/" (or config ""))))))

(defrecord Infisical [addr token clientid clientsecret project environment path state]
  provider/Provider

  ;; Infisical.
  ;;
  ;; `api.token` reads the secret keyed `API_TOKEN` (Infisical's own
  ;; convention is environment-style keys) at a secret path in one
  ;; environment of a project. Auth is a token, or a universal-auth (machine
  ;; identity) login with clientid/clientsecret.
  (lookup [_ name]
    (let [useaddr (trimslash (firstof addr "https://app.infisical.com"))
          _ (checkaddr useaddr)

          _ (when (or (= "" (or project "")) (= "" (or environment "")))
              (throw (core/sekretoerror "sekreto: infisical: no project/environment")))

          login (fn []
                  (if (core/notempty token)
                    [token Long/MAX_VALUE]
                    (do
                      (when (or (nil? (core/notempty clientid))
                                (nil? (core/notempty clientsecret)))
                        (throw (core/sekretoerror
                                "sekreto: infisical: no token and no client credentials")))

                      (let [body (json/omap [["clientId" clientid] ["clientSecret" clientsecret]])
                            res (fetchjson "POST"
                                           (str useaddr "/api/v1/auth/universal-auth/login")
                                           {"content-type" "application/json"}
                                           (json/stringify body))
                            got (json/astext (json/dig (:body res) "accessToken"))]

                        (when (or (not= 200 (:status res)) (nil? (core/notempty got)))
                          (throw (core/sekretoerror
                                  (str "sekreto: infisical login failed: " (:status res)))))

                        [got (renewtime (json/dig (:body res) "expiresIn"))]))))

          live (withtoken state login)
          url (str useaddr "/api/v3/secrets/raw/" (core/envkey name)
                   "?workspaceId=" (sigv4/uriescape project)
                   "&environment=" (sigv4/uriescape environment)
                   "&secretPath=" (sigv4/uriescape (firstof path "/")))
          res (fetchjson "GET" url {"authorization" (str "Bearer " (or live ""))})]

      (cond
        (= 404 (:status res)) nil

        (not= 200 (:status res))
        (throw (core/sekretoerror (str "sekreto: infisical error: " (:status res))))

        :else (json/astext (json/dig (:body res) "secret" "secretValue")))))

  (describe [_] (str "infisical:" (or project "") "/" (or environment ""))))

;; ------------------------------------------------------------ the builder

(defn makeprovider
  "Build a provider from its declarative form - the same shape the shared
  spec and an app's config file use. `:kind` picks the provider; every other
  key is that kind's own."
  [{:keys [kind prefix file values dir addr token mount kv vaultnamespace auth
           command profile backend reason namespace home
           region keyid secret session project vault tenant clientid clientsecret
           loginaddr imdsaddr metadataaddr apiversion config environment path]}]
  (case kind
    "env" (->Env prefix nil)
    "dotenv" (->Dotenv (or (core/notempty file) ".env") prefix (atom nil))
    "memory" (->Memory (or values {}) prefix)
    "file" (->Filedir (or dir "") prefix)

    "hashicorp"
    (let [usekv (or kv 2)]
      ;; A version typo like kv: 3 must not quietly behave as v2 and turn
      ;; its 404s into misses; there is nothing safe to assume it meant.
      (when (and (not= 1 usekv) (not= 2 usekv))
        (throw (core/sekretoerror (str "sekreto: hashicorp: unsupported kv version: " usekv))))
      (->Hashicorp (or addr "") (core/notempty token) (or (core/notempty mount) "secret")
                   usekv vaultnamespace auth
                   (atom {:token (core/notempty token) :renewat Long/MAX_VALUE})))

    "boru" (->Boru (or (core/notempty command) "boru") namespace home
                   (some-> (core/notempty addr) trimslash) token
                   (or (core/notempty mount) "secret"))

    "awssecrets" (->Awssecrets region keyid secret session addr)

    "awsparams" (->Awsparams region keyid secret session addr prefix)

    "gcpsecrets" (->Gcpsecrets project token addr metadataaddr
                               (atom {:token nil :renewat Long/MAX_VALUE}))

    "azuresecrets" (->Azuresecrets vault token tenant clientid clientsecret
                                   loginaddr imdsaddr apiversion
                                   (atom {:token nil :renewat Long/MAX_VALUE}))

    "onepassword" (->Onepassword addr token vault (atom nil))

    "doppler" (->Doppler token project config addr (atom nil))

    "infisical" (->Infisical addr token clientid clientsecret project environment path
                             (atom {:token nil :renewat Long/MAX_VALUE}))

    "secretspec" (->Secretspec (or (core/notempty command) "secretspec")
                               file profile backend reason prefix)

    (throw (core/sekretoerror (str "sekreto: unknown provider kind: " kind)))))
