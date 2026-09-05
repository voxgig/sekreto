;; RUN: make test
;; RUN-SOME: java -cp "$(clojure -Spath):$PLUGIN/clojure/src:test" \
;;             clojure.main -m voxgig.sekreto.test.plugins unknownkind
;;
;; THE PLUGIN SEAM, from both sides.
;;
;; Moving the provider kinds that open sockets and spawn processes out of
;; the core made a consumer's PLUGIN LIST load-bearing: a kind nobody passed
;; in is not in the catalog, and a chain naming it is refused. That is the
;; intended behaviour, and it means a consumer can be broken without a
;; single conformance test noticing - the conformance suite passes every
;; plugin to every chain it builds, so it can never see a missing one. So
;; the full set is pinned here: it holds every kind, every kind builds, and
;; the CLI passes it.
;;
;; The other half is the boundary itself, and in Clojure that is the
;; classpath and the require graph. These tests read both in a FRESH JVM,
;; which no assertion inside this one could fake: a JVM whose classpath is
;; this one minus `plugins/` builds a chain of built-ins and cannot so much
;; as find a plugin namespace, and `loaded-libs` after a require is the
;; whole truth about what the process has read.
;;
;; A translation of python/tests/test_plugins.py, which is the model.

(ns voxgig.sekreto.test.plugins
  (:require [clojure.java.io :as io]
            [clojure.string :as string]
            [voxgig.plugin.catalog :as catalog]
            [voxgig.plugin.host :as host]
            [voxgig.plugin.types :as plugintypes]
            [voxgig.sekreto :as sekreto]
            [voxgig.sekreto.provider :as provider]
            [voxgig.sekreto.plugins :as plugins]
            [voxgig.sekreto.plugins.hashicorp :refer [hashicorp]]
            [voxgig.sekreto.plugins.proc :as proc])
  (:import [java.io File])
  (:gen-class))

(def PLUGINS
  ["awsparams" "awssecrets" "azuresecrets" "boru" "doppler" "gcpsecrets"
   "hashicorp" "infisical" "onepassword" "secretspec"])

(def EVERY (vec (sort (concat ["dotenv" "env" "file" "memory"] PLUGINS))))

(def ONLY (atom nil))
(def PASSCOUNT (atom 0))
(def FAILCOUNT (atom 0))

;; --------------------------------------------------------------- the checks

(defn same [want got what]
  (when-not (= want got)
    (throw (ex-info (str what ":\n  want: " (pr-str want) "\n  got:  " (pr-str got)) {}))))

(defn holds [got want what]
  (when-not (and (string? got) (string/includes? got want))
    (throw (ex-info (str what ":\n  want to contain: " want "\n  got: " (pr-str got)) {}))))

(defn refused
  "The message a sekreto error refused a construction with."
  [body]
  (try
    (body)
    (throw (ex-info "nothing refused" {}))
    (catch clojure.lang.ExceptionInfo err
      (when-not (sekreto/sekretoerror? err)
        (throw (ex-info (str "not a sekreto error: " (ex-message err)) {})))
      (ex-message err))))

(defn here
  "This port's own directory, wherever the suite was started from."
  []
  (loop [dir (.getAbsoluteFile (File. (System/getProperty "user.dir")))
         step 0]
    (cond
      (or (nil? dir) (<= 8 step)) (throw (ex-info "sekreto: clojure port directory not found" {}))
      (.exists (File. dir "cli/sekreto/cli.clj")) dir
      :else (recur (.getParentFile dir) (inc step)))))

;; --------------------------------------------------------------- the full set

(defn thefullsetholdseverykind []
  (same PLUGINS (vec (sort (map (fn [d] (get d "name")) plugins/ALL))) "ALL")

  ;; Two kinds, one plugin: aws ships both stores because they share a
  ;; signer, so the list is ten definitions from nine namespaces.
  (same 10 (count plugins/ALL) "(count ALL)")

  (same (:builtin sekreto/KINDS) (mapv (fn [d] (get d "name")) sekreto/BUILTINS) "BUILTINS")
  (same PLUGINS (vec (sort (:plugin sekreto/KINDS))) "KINDS"))

;; Naming a kind is not enough: a kind can be in the catalog and still fail
;; to build. Construction is what the CLI does before any network.
(defn everykindbuildsfromaspec []
  (let [chain (mapv (fn [kind] {:kind kind :addr "http://127.0.0.1:8200" :token "t"
                                :dir "/tmp" :file "/tmp/.env" :values {}})
                    EVERY)
        secrets (sekreto/sekreto chain {:plugins plugins/ALL})]

    (same EVERY (sekreto/stores secrets) "stores")
    (same EVERY (vec (sort (keys (host/list (:host secrets))))) "host list")
    (same #{"live"} (set (vals (host/list (:host secrets)))) "instance statuses")
    (same EVERY (catalog/definition-names (:catalog secrets)) "catalog names")))

(defn theclipassesthefullset []
  (let [src (slurp (io/file (here) "cli/sekreto/cli.clj"))]
    (holds src "[voxgig.sekreto.plugins :as plugins]" "cli.clj")
    (holds src "{:plugins plugins/ALL}" "cli.clj")))

;; ------------------------------------------------------- what a consumer sees

(defn onepluginisenoughforachainthatnamesonlyit []
  (let [secrets (sekreto/sekreto
                 [{:kind "memory" :values {"API_TOKEN" "tok01"}}
                  {:kind "hashicorp" :name "prod" :addr "https://vault.example.com" :token "t"}]
                 {:plugins [hashicorp]})]

    (same ["memory" "prod"] (sekreto/stores secrets) "stores")
    (same ["memory" "hashicorp:https://vault.example.com/secret"]
          (sekreto/sources secrets) "sources")
    (same "tok01" (sekreto/get secrets "api.token") "get")

    ;; The plugin host is what the chain is made of, and it reads like the
    ;; chain: the kind, or kind$store for a named store.
    (same {"memory" "live" "hashicorp$prod" "live"} (host/list (:host secrets)) "host list")
    (same ["dotenv" "env" "file" "hashicorp" "memory"]
          (catalog/definition-names (:catalog secrets)) "catalog names")))

(defn akindthatwasnotpassedinisrefusednamingthefix []
  (same (str "sekreto: unknown provider kind: doppler"
             " (available: dotenv, env, file, hashicorp, memory)"
             " - doppler is a sekreto plugin, not built in: pass it in the plugins option")
        (refused #(sekreto/sekreto [{:kind "doppler" :token "t"}] {:plugins [hashicorp]}))
        "a plugin that was not passed in")

  ;; A kind nobody ships is a typo, and gets no such hint.
  (same "sekreto: unknown provider kind: vualt (available: dotenv, env, file, memory)"
        (refused #(sekreto/sekreto [{:kind "vualt"}]))
        "a kind nobody ships"))

;; Two providers MAY share a store name - a directed read walks both, and
;; the spec pins it - but an instance ref may not, so the second gets a
;; numbered tag from the host and keeps its store name.
(defn arepeatedstorenamekeepsthestoreandnumberstheinstance []
  (let [secrets (sekreto/sekreto [{:kind "memory" :values {}}
                                  {:kind "memory" :values {"API_TOKEN" "second"}}
                                  {:kind "memory" :name "pair" :values {}}
                                  {:kind "memory" :name "pair" :values {"API_TOKEN" "pair2"}}])]

    (same ["memory" "pair"] (sekreto/stores secrets) "stores")
    (same ["memory" "memory$1" "memory$2" "memory$pair"]
          (vec (sort (keys (host/list (:host secrets))))) "host list")
    (same "second" (sekreto/getfrom secrets "memory" "api.token") "getfrom memory")
    (same "pair2" (sekreto/getfrom secrets "pair" "api.token") "getfrom pair")))

(defn astorenamemustbeavalidtag []
  (same "sekreto: invalid store name: my store"
        (refused #(sekreto/sekreto [{:kind "memory" :name "my store" :values {}}]))
        "an invalid store name"))

;; A provider that refuses its own configuration raises a sekreto error from
;; inside the plugin's `define`. The spec pins that message byte for byte,
;; so it must come back out of the host as itself - not wrapped as
;; plugin_define_failed, and not as a plugin error.
(defn asekretoerrorraisedindefinecomesbackoutasitself []
  (same "sekreto: hashicorp: unsupported kv version: 3"
        (refused #(sekreto/sekreto
                   [{:kind "hashicorp" :addr "http://127.0.0.1:1" :token "t" :kv 3}]
                   {:plugins [hashicorp]}))
        "a provider refusing its own configuration"))

;; ...and any other error is not sekreto's to rewrite: it surfaces as the
;; host reports it, naming the instance and the cause.
(defn anyothererrorraisedindefineisthehostsreportofit []
  (let [broken (sekreto/providerplugin "broken" (fn [_spec] (throw (RuntimeException. "boom"))))
        caught (try
                 (sekreto/sekreto [{:kind "broken"}] {:plugins [broken]})
                 nil
                 (catch Exception err err))]

    (when (nil? caught) (throw (ex-info "nothing raised" {})))
    (when (sekreto/sekretoerror? caught)
      (throw (ex-info (str "rewritten as a sekreto error: " (ex-message caught)) {})))
    (same "plugin_define_failed" (plugintypes/code-of caught) "the host's code")
    (holds (ex-message caught) "boom" "the host's report")))

(defrecord Shouty [values]
  provider/Provider
  (lookup [_ name] (get values (.toUpperCase ^String name)))
  (describe [_] "shouty"))

(defn acustomkindisoneproviderplugincall []
  (let [shouty (sekreto/providerplugin "shouty" (fn [spec] (->Shouty (or (:values spec) {}))))
        secrets (sekreto/sekreto [{:kind "shouty" :values {"API.TOKEN" "loud"}}]
                                 {:plugins [shouty]})]

    (same "loud" (sekreto/get secrets "api.token") "a custom kind")
    (same {"shouty" "live"} (host/list (:host secrets)) "host list")))

(defrecord Replaced []
  provider/Provider
  (lookup [_ _name] "replaced")
  (describe [_] "memory"))

;; A plugin that names a built-in kind replaces it: that is how a host
;; substitutes an implementation, and never an accident, because the four
;; names are documented.
(defn apluginmayreplaceabuiltinkind []
  (let [secrets (sekreto/sekreto
                 [{:kind "memory" :values {"API_TOKEN" "original"}}]
                 {:plugins [(sekreto/providerplugin "memory" (fn [_spec] (->Replaced)))]})]

    (same "replaced" (sekreto/get secrets "api.token") "the replacement")
    (same ["dotenv" "env" "file" "memory"]
          (catalog/definition-names (:catalog secrets)) "catalog names")))

(defn closetearsthechaindownandkeepsredaction []
  (let [secrets (sekreto/sekreto [{:kind "memory" :values {"API_TOKEN" "tok01"}}])]
    (same "tok01" (sekreto/get secrets "api.token") "get")

    (sekreto/close secrets)

    (same {} (host/list (:host secrets)) "host list")
    (same [] (sekreto/stores secrets) "stores")
    (same nil (sekreto/tryget secrets "api.token") "tryget after close")
    (same "token=[redacted]" (sekreto/redactall secrets "token=tok01") "redact after close")))

;; ---------------------------------------------------------- the boundary

(defn classpath
  "This suite's own classpath, entry by entry."
  []
  (vec (string/split (System/getProperty "java.class.path") (re-pattern File/pathSeparator))))

(defn corepath
  "The same classpath MINUS the plugins source root, so a JVM started on it
  can reach the core and voxgig/plugin and no plugin at all."
  []
  (string/join File/pathSeparator
               (remove (fn [entry] (or (= "plugins" entry)
                                       (string/ends-with? entry "/plugins")))
                       (classpath))))

(defn fresh
  "Run one form in a FRESH JVM and answer what it printed on stdout.
  Measured in a new process because this one has required everything
  (above) on purpose.

  Through the port's own child-process helper, which drains both streams:
  stderr is kept apart rather than folded in, because a JVM writes its own
  notices there and a probe that read them as its answer would be measuring
  the launcher."
  [path code]
  (let [java (str (System/getProperty "java.home") "/bin/java")
        ran (proc/runcmd (proc/command [java "-cp" path "clojure.main" "-e" code]) java)]
    (when-not (zero? (:status ran))
      (throw (ex-info (str "sekreto: probe failed:\n" (:why ran) "\n" (:out ran)) {})))
    (string/trim (:out ran))))

(defn loaded
  "The sekreto namespaces a require pulled into a fresh JVM."
  [path code]
  (fresh path (str code
                   " (println (clojure.string/join \" \""
                   " (sort (filter (fn [n] (clojure.string/starts-with? (str n) \"voxgig.sekreto\"))"
                   " (loaded-libs)))))")))

;; THE CORE REQUIRES NO PLUGIN. Requiring voxgig.sekreto brings in the
;; chain, the built-ins, the address guard and voxgig/plugin, and not one
;; namespace under plugins/ - and a JVM whose classpath does not carry
;; plugins/ at all proves it, because a core namespace that required one
;; could not have loaded.
(defn thecorerequiresnoplugin []
  (let [path (corepath)]
    (same (str "voxgig.sekreto voxgig.sekreto.addr voxgig.sekreto.chain"
               " voxgig.sekreto.core voxgig.sekreto.json"
               " voxgig.sekreto.provider voxgig.sekreto.providers")
          (loaded path "(require 'voxgig.sekreto)")
          "what requiring the core loads")

    ;; ...and the core alone still answers, with no plugin on the classpath.
    (same "tok01"
          (fresh path (str "(require 'voxgig.sekreto)"
                           " (print (voxgig.sekreto/get"
                           " (voxgig.sekreto/sekreto [{:kind \"memory\""
                           " :values {\"API_TOKEN\" \"tok01\"}} {:kind \"env\"}"
                           " {:kind \"dotenv\" :file \"/nonexistent-sekreto-test/.env\"}"
                           " {:kind \"file\" :dir \"/nonexistent-sekreto-test\"}])"
                           " \"api.token\"))"))
          "a chain of built-ins, with no plugin on the classpath")

    ;; ...and it cannot so much as find one.
    (holds (fresh path (str "(try (require 'voxgig.sekreto.plugins.hashicorp)"
                            " (print \"REACHED\")"
                            " (catch java.io.FileNotFoundException _ (print \"absent\")))"))
           "absent"
           "a plugin namespace, from a core-only classpath")))

;; ...and one plugin requires only itself and the shared edges it needs.
;; Python's plugins package had to arrange this deliberately - its
;; initializer once imported all ten so it could re-export them, which made
;; a single-plugin import load every network client behind it. Clojure has
;; no package initializer, so a directory of namespaces gets it for free;
;; this pins that it stays true.
(defn onepluginrequiresonlyitself []
  (same (str "voxgig.sekreto.addr voxgig.sekreto.core voxgig.sekreto.json"
             " voxgig.sekreto.plugins.hashicorp voxgig.sekreto.plugins.httpjson"
             " voxgig.sekreto.provider voxgig.sekreto.providers")
        (loaded (string/join File/pathSeparator (classpath))
                "(require 'voxgig.sekreto.plugins.hashicorp)")
        "what requiring one plugin loads"))

;; The full set is loaded on demand, and reaching it loads everything.
(defn thefullsetisloadedondemand []
  (let [path (string/join File/pathSeparator (classpath))
        before (loaded path "(require 'voxgig.sekreto.plugins.hashicorp)")
        after (loaded path "(require 'voxgig.sekreto.plugins)")]

    (when (string/includes? before "plugins.doppler")
      (throw (ex-info "one plugin reached another" {})))
    (when (string/includes? before "plugins.sigv4")
      (throw (ex-info "one plugin reached the signer" {})))

    (doseq [name ["hashicorp" "boru" "aws" "gcpsecrets" "azuresecrets" "onepassword"
                  "doppler" "infisical" "secretspec" "sigv4" "httpjson" "proc"]]
      (holds after (str "voxgig.sekreto.plugins." name) "the full set"))))

;; A namespace is the container, not the thing inside it, and both it and a
;; symbol naming it are refused by name, saying what to pass instead.
(defn anamespacepassedasapluginisrefused []
  (same (str "sekreto: not a plugin definition:"
             " the namespace voxgig.sekreto.plugins.hashicorp"
             " - a plugin is a definition in it, such as"
             " voxgig.sekreto.plugins.hashicorp/hashicorp,"
             " or voxgig.sekreto.plugins/ALL for every one")
        (refused #(sekreto/sekreto [] {:plugins [(find-ns 'voxgig.sekreto.plugins.hashicorp)]}))
        "a namespace")

  (holds (refused #(sekreto/sekreto [] {:plugins ['voxgig.sekreto.plugins.doppler]}))
         "voxgig.sekreto.plugins.doppler/doppler"
         "a symbol naming a namespace")

  (holds (refused #(sekreto/sekreto [] {:plugins [true]}))
         "sekreto: not a plugin definition: true"
         "a value that is not a definition")

  ;; A definition that exports no provider is a definition all the same,
  ;; and voxgig/plugin has no opinion about it - so this port does.
  (holds (refused #(sekreto/sekreto [{:kind "bare"}]
                                    {:plugins [{"name" "bare" "define" (fn [_i] nil)}]}))
         "sekreto: not a provider plugin: bare"
         "a definition that exports no provider"))

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
        (println (str "  " (ex-message err)))))))

(defn -main [& args]
  (when (seq args) (reset! ONLY (first args)))

  (testcase "fullset" thefullsetholdseverykind)
  (testcase "everykindbuilds" everykindbuildsfromaspec)
  (testcase "clipassesfullset" theclipassesthefullset)
  (testcase "oneplugin" onepluginisenoughforachainthatnamesonlyit)
  (testcase "unknownkind" akindthatwasnotpassedinisrefusednamingthefix)
  (testcase "repeatedstore" arepeatedstorenamekeepsthestoreandnumberstheinstance)
  (testcase "storenametag" astorenamemustbeavalidtag)
  (testcase "sekretoerror" asekretoerrorraisedindefinecomesbackoutasitself)
  (testcase "othererror" anyothererrorraisedindefineisthehostsreportofit)
  (testcase "customkind" acustomkindisoneproviderplugincall)
  (testcase "replacebuiltin" apluginmayreplaceabuiltinkind)
  (testcase "close" closetearsthechaindownandkeepsredaction)
  (testcase "corerequiresnoplugin" thecorerequiresnoplugin)
  (testcase "onepluginrequiresitself" onepluginrequiresonlyitself)
  (testcase "fullsetondemand" thefullsetisloadedondemand)
  (testcase "namespaceasplugin" anamespacepassedasapluginisrefused)

  (println (str "\n" @PASSCOUNT " passed, " @FAILCOUNT " failed"))

  (System/exit (if (zero? @FAILCOUNT) 0 1)))
