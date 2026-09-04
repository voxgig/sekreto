;; RUN: make test
;; RUN-SOME: clojure -Sdeps '{:aliases {:omni {:extra-paths ["'$OMNI'/clojure/src"]}}}' \
;;             -M:test:omni -m voxgig.sekreto.test.main envkey
;;
;; The sekreto conformance suite. Every port runs these same groups, from
;; the same spec/sekreto.json, through its own voxgig/omni runner.
;;
;; No third-party test framework: a failing check throws, so any host
;; framework (clojure.test, kaocha) reports it as a failure. This harness
;; keeps `make test` dependency-free.
;;
;; Two value models meet here, and the bridge between them is explicit.
;; The runner hands over the spec's own JSON - maps keyed by string, numbers
;; as doubles, and an ABSENT marker for a key that is not there - while a
;; provider spec in this port is a map keyed by keyword. `specof` converts
;; one to the other field by field rather than guessing, so absent, null and
;; value stay distinct across the boundary.

(ns voxgig.sekreto.test.main
  (:require [voxgig.omni.runner :as runner]
            [voxgig.omni.util :as u]
            [voxgig.sekreto :as sekreto]
            [voxgig.sekreto.json :as json])
  (:import [java.io File])
  (:gen-class))

(def ONLY (atom nil))
(def PASSCOUNT (atom 0))
(def FAILCOUNT (atom 0))

(defn specfile
  "Find the shared spec directory by walking up from the working directory."
  [name]
  (loop [dir (File. (System/getProperty "user.dir"))
         step 0]
    (if (or (nil? dir) (<= 8 step))
      (throw (runner/omni-error (str "sekreto: spec not found: " name)))
      (let [cand (File. (File. dir "spec") ^String name)]
        (if (.exists cand)
          (.getAbsolutePath cand)
          (recur (.getParentFile dir) (inc step)))))))

;; ------------------------------------------------------------- the bridge

(defn plain
  "The runner's value as the library sees it: a key that is not there is
  nil, which is what every entry point here treats as \"not a name\"."
  [value]
  (if (u/isabsent value) nil value))

(defn asstr
  "A spec field, when it is a string. A field the spec leaves out is absent
  rather than null, and neither is a value to configure a provider with."
  [entry key]
  (let [value (get entry key)]
    (when (string? value) value)))

;; Every provider-spec field the spec can carry that is plain text. The
;; three that are not - `values`, `kv` and `auth` - are converted below.
(def SPECKEYS
  ["kind" "name" "prefix" "file" "dir" "addr" "token" "mount" "vaultnamespace"
   "command" "profile" "backend" "reason" "namespace" "home"
   "region" "keyid" "secret" "session" "project" "vault" "tenant"
   "clientid" "clientsecret" "loginaddr" "imdsaddr" "metadataaddr" "apiversion"
   "config" "environment" "path"])

(def AUTHKEYS ["method" "mount" "role" "jwt" "jwtfile" "roleid" "secretid"])

(defn- keyed [entry keys]
  (reduce (fn [out key]
            (if-let [value (asstr entry key)] (assoc out (keyword key) value) out))
          {}
          keys))

(defn specof
  "One provider spec, out of the spec's declarative chain description."
  [entry]
  (let [values (get entry "values")
        kv (get entry "kv")
        auth (get entry "auth")]
    (cond-> (keyed entry SPECKEYS)
      ;; The spec's memory values are JSON, so a number there is a number;
      ;; the provider stores text.
      (u/ismap values)
      (assoc :values (json/omap (map (fn [[key value]] [key (u/stringify value)]) values)))

      ;; A version arrives as a JSON number and is compared as an integer -
      ;; and `kv: 3` must be refused, so it is carried through as given.
      (u/isnum kv) (assoc :kv (long kv))

      (u/ismap auth) (assoc :auth (keyed auth AUTHKEYS)))))

(defn chainof
  "Build a Sekreto from the spec's declarative chain description. The cache
  is off: each entry is its own chain, and a cached read would answer for
  the next one."
  [entry]
  (sekreto/sekreto (mapv specof (get entry "chain" [])) {:cache false}))

(defn namearg
  "The name a group's entry asks about."
  [entry]
  (plain (get entry "name")))

;; ------------------------------------------------------------ the subjects

;; `validname` answers whatever the language calls true; the spec says JSON
;; true, so the adaptation happens here rather than in the library.
(defn VALIDNAME [args] (boolean (sekreto/validname (plain (first args)))))

(defn ENVKEY [args]
  (let [entry (first args)]
    (sekreto/envkey (namearg entry) (asstr entry "prefix"))))

(defn VAULTREF [args]
  (let [ref (sekreto/vaultref (plain (first args)))]
    (json/omap [["path" (:path ref)] ["field" (:field ref)]])))

(defn FLATNAME [args]
  (let [entry (first args)]
    (sekreto/flatname (namearg entry) (or (asstr entry "sep") ""))))

(defn AWSPARAM [args]
  (let [entry (first args)]
    (sekreto/awsparam (namearg entry) (asstr entry "prefix"))))

(defn PARSEDOTENV [args] (sekreto/parsedotenv (plain (first args))))

(defn RESOLVE [args] (sekreto/get (chainof (first args)) (namearg (first args))))

(defn TRYSECRET [args] (sekreto/tryget (chainof (first args)) (namearg (first args))))

(defn SOURCES [args] (sekreto/sources (chainof (first args))))

(defn STORES [args] (sekreto/stores (chainof (first args))))

(defn GETFROM [args]
  (let [entry (first args)]
    (sekreto/getfrom (chainof entry) (or (asstr entry "store") "") (namearg entry))))

(defn TRYFROM [args]
  (let [entry (first args)]
    (sekreto/tryfrom (chainof entry) (or (asstr entry "store") "") (namearg entry))))

;; Answers the ordered output map itself, which the runner compares as a
;; JSON object against the spec's known-answer signatures.
(defn SIGV4 [args]
  (let [entry (first args)
        headers (get entry "headers")]
    (sekreto/sigv4 {:method (or (asstr entry "method") "")
                    :url (or (asstr entry "url") "")
                    :service (or (asstr entry "service") "")
                    :region (or (asstr entry "region") "")
                    :keyid (or (asstr entry "keyid") "")
                    :secret (or (asstr entry "secret") "")
                    :datetime (or (asstr entry "datetime") "")
                    :headers (when (u/ismap headers)
                               (json/omap (map (fn [[key value]] [key (u/stringify value)])
                                               headers)))
                    :body (or (asstr entry "body") "")
                    :session (asstr entry "session")})))

(defn REDACT [args]
  (let [entry (first args)]
    (sekreto/redact (plain (get entry "text"))
                    (mapv plain (get entry "values" [])))))

;; ------------------------------------------------------------- the runner

(defn testcase [name body]
  (when (or (nil? @ONLY) (= @ONLY name))
    (try
      (body)
      (swap! PASSCOUNT inc)
      (println (str "ok   - " name))
      (catch Throwable err
        (swap! FAILCOUNT inc)
        (println (str "FAIL - " name))
        (println (runner/errmessage err))))))

(defn -main [& args]
  (when (seq args)
    (reset! ONLY (first args)))

  (let [R ((runner/make-runner (specfile "sekreto.json")) "sekreto")
        group (:set R)
        runset (:runset R)
        runsetflags (:runsetflags R)]

    ;; The one group run with nulls left alone: `validname` is asked about
    ;; values, not about names, and a null normalised to the text "__NULL__"
    ;; would be a string - which is a different question.
    (testcase "validname" #(runsetflags (group "validname") {:null false} VALIDNAME))

    (testcase "envkey" #(runset (group "envkey") ENVKEY))
    (testcase "vaultref" #(runset (group "vaultref") VAULTREF))
    (testcase "flatname" #(runset (group "flatname") FLATNAME))
    (testcase "awsparam" #(runset (group "awsparam") AWSPARAM))
    (testcase "parsedotenv" #(runset (group "parsedotenv") PARSEDOTENV))
    (testcase "resolve" #(runset (group "resolve") RESOLVE))
    (testcase "trysecret" #(runset (group "trysecret") TRYSECRET))
    (testcase "sources" #(runset (group "sources") SOURCES))
    (testcase "stores" #(runset (group "stores") STORES))
    (testcase "getfrom" #(runset (group "getfrom") GETFROM))
    (testcase "tryfrom" #(runset (group "tryfrom") TRYFROM))
    (testcase "sigv4" #(runset (group "sigv4") SIGV4))
    (testcase "redact" #(runset (group "redact") REDACT))

    (println (str "\n" @PASSCOUNT " passed, " @FAILCOUNT " failed"))

    (System/exit (if (zero? @FAILCOUNT) 0 1))))
