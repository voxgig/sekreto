;; The mini vault, from both sides: the store a chain reads, and the
;; programmatic API a plugin definition can publish beside it.
;;
;; The vault is not in spec/sekreto.json and cannot be until every port
;; ships the kind. The spec runs against all twenty-three of them, so an
;; entry naming `minivault` would fail the ports that have no such
;; provider. What the shared corpus would have carried is here instead,
;; plus the one thing it could not carry either way: a file written by this
;; port and read by another, pinned by test/fixture/*.skmv.

(ns voxgig.sekreto.test.minivault
  (:require [clojure.string :as string]
            [voxgig.sekreto :as sekreto]
            [voxgig.sekreto.plugins.minivault :as mv])
  (:import [java.io File FilenameFilter]
           [java.nio.charset StandardCharsets]
           [java.nio.file Files Path StandardCopyOption]))

(def MASTER "master-passphrase")

;; The rounds every test here uses. The library default is 210000, which is
;; the point of PBKDF2 and the wrong thing to pay per assertion.
(def ROUNDS 1000)

(def ONLY (atom nil))
(def PASSCOUNT (atom 0))
(def FAILCOUNT (atom 0))
(def WORK (atom nil))
(def COUNT (atom 0))

(defn same [want got what]
  (when-not (= want got)
    (throw (ex-info (str what ":\n  want: " (pr-str want) "\n  got:  " (pr-str got)) {}))))

(defn holds [got want what]
  (when-not (and (string? got) (string/includes? got want))
    (throw (ex-info (str what ":\n  want to contain: " want "\n  got: " (pr-str got)) {}))))

(defn refused
  "The message a sekreto error refused with."
  [body]
  (try
    (body)
    (throw (ex-info "nothing refused" {}))
    (catch clojure.lang.ExceptionInfo err
      (when-not (sekreto/sekretoerror? err)
        (throw (ex-info (str "not a sekreto error: " (ex-message err)) {})))
      (ex-message err))))

(defn vaultpath []
  (swap! COUNT inc)
  (.getPath (File. ^File @WORK (str "vault" @COUNT ".skmv"))))

(defn fresh []
  (mv/createvault {:file (vaultpath) :passphrase MASTER :iterations ROUNDS}))

(defn openas [file key phrase]
  (mv/openvault {:file file :key key :passphrase phrase}))

(defn fixturedir
  "Where the committed vaults live, found by walking up."
  []
  (loop [dir (.getAbsoluteFile (File. ".")) step 0]
    (cond
      (or (nil? dir) (< 8 step))
      (throw (ex-info "sekreto: fixture directory not found" {}))

      (.exists (File. (File. (File. dir "test") "fixture") "minivault.skmv"))
      (File. (File. dir "test") "fixture")

      :else (recur (.getParentFile dir) (inc step)))))

(defn fixtures
  "EVERY committed vault, read off disk rather than listed here. A
  hard-coded list is one more place to edit when a port lands, and the edit
  that gets forgotten is the one that makes this suite stop checking the
  port that just arrived."
  []
  (vec (sort (map #(.getName ^File %)
                  (seq (.listFiles ^File (fixturedir)
                                   (reify FilenameFilter
                                     (accept [_ _ n] (.endsWith ^String n ".skmv")))))))))

(defn fixture
  "A committed vault, copied so that a test which writes cannot edit the
  bytes the format contract is made of."
  [name]
  (let [mine (vaultpath)]
    (Files/copy (.toPath (File. ^File (fixturedir) ^String name))
                (Path/of ^String mine (into-array String []))
                (into-array StandardCopyOption [StandardCopyOption/REPLACE_EXISTING]))
    mine))

(defn thechain [& providers]
  (sekreto/sekreto (vec providers) {:plugins [mv/minivault]}))

;; --- the file --------------------------------------------------------

(defn anewvaultholdsnothing []
  (let [vault (fresh)]
    (same [] (mv/vaultlist vault) "list")
    (same "master" (mv/vaultkey vault) "key")
    (same {"key" "master" "master" true "write" true "grants" []}
          (mv/vaultopen vault) "open")))

(defn awrittensecretcomesback []
  (let [vault (fresh)]
    (mv/vaultset vault "api.token" "tok01")
    (mv/vaultset vault "db.pass" "hunter2")

    (same "tok01" (mv/vaultget vault "api.token") "get")
    (same ["api.token" "db.pass"] (mv/vaultlist vault) "list")
    (same true (mv/vaulthas? vault "api.token") "has?")
    (same false (mv/vaulthas? vault "nope") "has? nope")
    (same nil (mv/vaultget vault "nope") "get nope")

    (same "tok01" (mv/vaultget (openas (mv/vaultfile vault) nil MASTER) "api.token")
          "a new handle")))

(defn thefileisbinary []
  (let [vault (fresh)]
    (mv/vaultset vault "api.token" "tok01")
    (let [raw (String. (Files/readAllBytes
                        (Path/of ^String (mv/vaultfile vault) (into-array String [])))
                       StandardCharsets/ISO_8859_1)]
      (same "SKMV" (subs raw 0 4) "magic")
      ;; The key ids are plaintext and documented as such; a secret name is
      ;; not, and neither is a value.
      (same true (string/includes? raw "master") "the key id is plaintext")
      (same false (string/includes? raw "api.token") "the name is not")
      (same false (string/includes? raw "tok01") "the value is not"))))

(defn rewritinganamereplacesit []
  (let [vault (fresh)]
    (mv/vaultset vault "api.token" "one")
    (mv/vaultset vault "api.token" "two")
    (same "two" (mv/vaultget vault "api.token") "get")
    (same ["api.token"] (mv/vaultlist vault) "list")))

(defn removedropsaname []
  (let [vault (fresh)]
    (mv/vaultset vault "api.token" "tok01")
    (mv/vaultremove vault "api.token")
    (same [] (mv/vaultlist vault) "list")
    (same nil (mv/vaultget vault "api.token") "get")
    (holds (refused #(mv/vaultremove vault "api.token")) "no such secret" "remove again")))

(defn abadnameisrefused []
  (let [vault (fresh)]
    (refused #(mv/vaultget vault ""))
    (refused #(mv/vaultset vault "bad name" "x"))))

;; --- the keys --------------------------------------------------------

(defn arestrictedkeyreadsitsgrants []
  (let [vault (fresh)]
    (mv/vaultset vault "api.token" "tok01")
    (mv/vaultset vault "db.pass" "hunter2")
    (mv/vaultgrant vault {:key "ci" :passphrase "ci-phrase" :names ["api.token"]
                          :iterations ROUNDS})

    (let [ci (openas (mv/vaultfile vault) "ci" "ci-phrase")]
      (same ["api.token"] (mv/vaultlist ci) "list")
      (same "tok01" (mv/vaultget ci "api.token") "the grant")
      ;; Not an error: the vault answers as the key that opened it, so a
      ;; name outside the grant is a miss.
      (same nil (mv/vaultget ci "db.pass") "outside the grant")
      (same {"key" "ci" "master" false "write" false "grants" ["api.token"]}
            (mv/vaultopen ci) "open"))))

(defn areadonlykeyrefusestowrite []
  (let [vault (fresh)]
    (mv/vaultset vault "db.pass" "hunter2")
    (mv/vaultgrant vault {:key "ro" :passphrase "ro-phrase" :names ["db.pass"]
                          :iterations ROUNDS})
    (mv/vaultgrant vault {:key "rw" :passphrase "rw-phrase" :names ["db.pass"]
                          :write true :iterations ROUNDS})

    (holds (refused #(mv/vaultset (openas (mv/vaultfile vault) "ro" "ro-phrase")
                                  "db.pass" "nope"))
           "read-only" "a read-only key")

    (mv/vaultset (openas (mv/vaultfile vault) "rw" "rw-phrase") "db.pass" "changed")
    (same "changed" (mv/vaultget vault "db.pass") "a write key")))

(defn arestrictedkeycannotwriteanungrantedname []
  (let [vault (fresh)]
    (mv/vaultset vault "db.pass" "hunter2")
    (mv/vaultgrant vault {:key "rw" :passphrase "rw-phrase" :names ["db.pass"]
                          :write true :iterations ROUNDS})
    (holds (refused #(mv/vaultset (openas (mv/vaultfile vault) "rw" "rw-phrase")
                                  "other.name" "x"))
           "was not granted" "ungranted")))

(defn agrantednamethatdoesnotexistyet []
  (let [vault (fresh)]
    (mv/vaultgrant vault {:key "ci" :passphrase "ci-phrase" :names ["later.name"]
                          :iterations ROUNDS})
    (let [ci (openas (mv/vaultfile vault) "ci" "ci-phrase")]
      (same [] (mv/vaultlist ci) "before")
      (same nil (mv/vaultget ci "later.name") "before")

      (mv/vaultset vault "later.name" "here now")

      (same "here now" (mv/vaultget ci "later.name") "after")
      (same ["later.name"] (mv/vaultlist ci) "after"))))

(defn themasterlistseverykey []
  (let [vault (fresh)]
    (mv/vaultgrant vault {:key "ro" :passphrase "p1" :names ["a.one"] :iterations ROUNDS})
    (mv/vaultgrant vault {:key "rw" :passphrase "p2" :names ["a.one" "b.two"]
                          :write true :iterations ROUNDS})

    (same [{"key" "master" "master" true "write" true "grants" []}
           {"key" "ro" "master" false "write" false "grants" ["a.one"]}
           {"key" "rw" "master" false "write" true "grants" ["a.one" "b.two"]}]
          (mv/vaultkeys vault) "keys")))

(defn themasteronlymethodsrefusearestrictedkey []
  (let [vault (fresh)]
    (mv/vaultset vault "a.one" "x")
    (mv/vaultgrant vault {:key "ci" :passphrase "ci-phrase" :names ["a.one"]
                          :write true :iterations ROUNDS})

    (let [ci (openas (mv/vaultfile vault) "ci" "ci-phrase")]
      (doseq [call [#(mv/vaultkeys ci)
                    #(mv/vaultremove ci "a.one")
                    #(mv/vaultrotate ci)
                    #(mv/vaultrevoke ci "master")
                    #(mv/vaultgrant ci {:key "x" :passphrase "y" :names []})]]
        (holds (refused call) "master key" "a master-only method")))))

(defn arepeatedkeyidisrefused []
  (let [vault (fresh)]
    (mv/vaultgrant vault {:key "ci" :passphrase "one" :names [] :iterations ROUNDS})
    (holds (refused #(mv/vaultgrant vault {:key "ci" :passphrase "two" :names []
                                           :iterations ROUNDS}))
           "key already exists" "a repeated id")))

(defn revokedropsakey []
  (let [vault (fresh)]
    (mv/vaultset vault "a.one" "x")
    (mv/vaultgrant vault {:key "ci" :passphrase "ci-phrase" :names ["a.one"]
                          :iterations ROUNDS})

    (let [ci (openas (mv/vaultfile vault) "ci" "ci-phrase")]
      (same "x" (mv/vaultget ci "a.one") "before")
      (mv/vaultrevoke vault "ci")
      (holds (refused #(mv/vaultget ci "a.one")) "no such key" "after")
      (holds (refused #(mv/vaultrevoke vault "master")) "cannot revoke itself" "itself"))))

(defn rotatekeepsthesecrets []
  (let [vault (fresh)]
    (mv/vaultset vault "api.token" "tok01")
    (mv/vaultset vault "db.pass" "hunter2")
    (mv/vaultgrant vault {:key "ci" :passphrase "ci-phrase" :names ["api.token"]
                          :iterations ROUNDS})

    (mv/vaultrotate vault)

    (same ["api.token" "db.pass"] (mv/vaultlist vault) "list")
    (same "tok01" (mv/vaultget vault "api.token") "api.token")
    (same "hunter2" (mv/vaultget vault "db.pass") "db.pass")
    (same ["master"] (mapv #(get % "key") (mv/vaultkeys vault)) "keys")

    (refused #(mv/vaultget (openas (mv/vaultfile vault) "ci" "ci-phrase") "api.token"))))

;; --- refusals --------------------------------------------------------

(defn awrongpassphraseandamissingfilerefuse []
  (let [vault (fresh)]
    (mv/vaultset vault "a.one" "x")

    (holds (refused #(mv/vaultget (openas (mv/vaultfile vault) nil "wrong") "a.one"))
           "wrong passphrase" "a wrong passphrase")
    (refused #(mv/vaultget (openas (mv/vaultfile vault) "nope" MASTER) "a.one"))
    (holds (refused #(mv/vaultget
                      (openas (.getPath (File. ^File @WORK "nothing.skmv")) nil MASTER)
                      "a.one"))
           "no vault file" "a missing file")))

(defn adamagedfileisrefused []
  (let [vault (fresh)]
    (mv/vaultset vault "a.one" "x")
    (let [raw (Files/readAllBytes (Path/of ^String (mv/vaultfile vault)
                                           (into-array String [])))
          short (vaultpath)
          trailing (vaultpath)
          notvault (vaultpath)]

      (Files/write (Path/of ^String short (into-array String []))
                   ^bytes (java.util.Arrays/copyOf raw (- (alength raw) 10))
                   (into-array java.nio.file.OpenOption []))
      (holds (refused #(mv/vaultget (openas short nil MASTER) "a.one")) "truncated" "short")

      (Files/write (Path/of ^String trailing (into-array String []))
                   ^bytes (byte-array (concat (seq raw)
                                              (seq (.getBytes "junk"
                                                              StandardCharsets/ISO_8859_1))))
                   (into-array java.nio.file.OpenOption []))
      (holds (refused #(mv/vaultget (openas trailing nil MASTER) "a.one"))
             "trailing bytes" "trailing")

      (Files/write (Path/of ^String notvault (into-array String []))
                   ^bytes (byte-array (concat (seq (.getBytes "NOPE"
                                                              StandardCharsets/ISO_8859_1))
                                              (drop 4 (seq raw))))
                   (into-array java.nio.file.OpenOption []))
      (holds (refused #(mv/vaultget (openas notvault nil MASTER) "a.one"))
             "not a vault file" "magic"))))

(defn creatingoveranexistingvaultisrefused []
  (let [vault (fresh)]
    (holds (refused #(mv/createvault {:file (mv/vaultfile vault) :passphrase MASTER
                                      :iterations ROUNDS}))
           "already exists" "createvault over one")))

(defn avaultneedsafileandapassphrase []
  (refused #(mv/openvault {:file "" :passphrase MASTER}))
  (refused #(mv/openvault {:file (vaultpath) :passphrase ""})))

;; An EMPTY key is no key, so it means `master`. It is not a contrived
;; case: the CLI reads SEKRETO_VAULT_KEY, and an unset shell variable
;; expands to the empty string rather than to nothing at all - and
;; clojure's `or` answers for nil alone, because "" is truthy.
(defn anemptykeymeansthemasterkey []
  (let [vault (fresh)]
    (mv/vaultset vault "api.token" "tok01")

    (let [opened (mv/openvault {:file (mv/vaultfile vault) :key "" :passphrase MASTER})]
      (same "tok01" (mv/vaultget opened "api.token") "api.token")
      (same "master" (get (mv/vaultopen opened) "key") "key"))))

(defn createmakesthefileonlywhenasked []
  (let [path (vaultpath)
        refuses (mv/openvault {:file path :passphrase MASTER :iterations ROUNDS})]
    (refused #(mv/vaultlist refuses))
    (same false (.exists (File. ^String path)) "no file")

    (let [makes (mv/openvault {:file path :passphrase MASTER :iterations ROUNDS
                               :create true})]
      (same [] (mv/vaultlist makes) "created")
      (same true (.exists (File. ^String path)) "the file"))))

(defn akeyidlongerthantheformatallowsisrefused []
  (let [vault (fresh)]
    (holds (refused #(mv/vaultgrant vault {:key (apply str (repeat 256 "k"))
                                           :passphrase "p" :names []
                                           :iterations ROUNDS}))
           "longer than 255" "a long key id")
    (same ["master"] (mapv #(get % "key") (mv/vaultkeys vault)) "unchanged")))

;; --- the handle ------------------------------------------------------

(defn theinfoacallergetscannotchangewhatthekeymaydo []
  (let [vault (fresh)]
    (mv/vaultset vault "a.one" "x")
    (mv/vaultgrant vault {:key "ro" :passphrase "ro-phrase" :names ["a.one"]
                          :iterations ROUNDS})

    (let [ro (openas (mv/vaultfile vault) "ro" "ro-phrase")]
      ;; A map is a value here, so what a caller changes is its own copy -
      ;; the defect the review round found in the canonical cannot happen in
      ;; a language with no shared mutable map.
      (assoc (mv/vaultopen ro) "write" true "grants" ["a.one" "b.two"])

      (holds (refused #(mv/vaultset ro "a.one" "nope")) "read-only" "still read-only")
      (same ["a.one"] (get (mv/vaultopen ro) "grants") "still one grant"))))

(defn arevokedkeystopsreading []
  (let [vault (fresh)]
    (mv/vaultset vault "a.one" "x")
    (mv/vaultgrant vault {:key "ci" :passphrase "ci-phrase" :names ["a.one"]
                          :iterations ROUNDS})

    (let [ci (openas (mv/vaultfile vault) "ci" "ci-phrase")]
      (same "x" (mv/vaultget ci "a.one") "before")
      (mv/vaultrevoke vault "ci")
      (refused #(mv/vaultget ci "a.one")))))

(defn aregrantedkeyid []
  (let [vault (fresh)]
    (mv/vaultset vault "a.one" "x")
    (mv/vaultgrant vault {:key "ci" :passphrase "first" :names ["a.one"]
                          :iterations ROUNDS})

    (let [ci (openas (mv/vaultfile vault) "ci" "first")]
      (same "x" (mv/vaultget ci "a.one") "before")

      (mv/vaultrevoke vault "ci")
      (mv/vaultgrant vault {:key "ci" :passphrase "second" :names ["a.one"]
                            :iterations ROUNDS})

      (holds (refused #(mv/vaultget ci "a.one")) "wrong passphrase" "the old passphrase")
      (same "x" (mv/vaultget (openas (mv/vaultfile vault) "ci" "second") "a.one")
            "the new one"))))

(defn closeforgetsthederivedkeys []
  (let [vault (fresh)]
    (mv/vaultset vault "a.one" "x")
    (same "x" (mv/vaultget vault "a.one") "before")
    (mv/vaultclose vault)
    (same "x" (mv/vaultget vault "a.one") "after")))

;; --- the format, across ports ----------------------------------------

;; EVERY COMMITTED VAULT, not only this port's. A suite that reads only the
;; vault its own port wrote proves the reader agrees with the writer beside
;; it - which a port whose serializer and parser share a mistake satisfies
;; perfectly.
(defn readsfixture [name]
  (fn []
    (let [file (fixture name)
          master (openas file nil "fixture-master")]

      (same ["api.token" "db.pass" "deep.nested.name"] (mv/vaultlist master) "list")
      (same "fixture-token" (mv/vaultget master "api.token") "api.token")
      (same "fixture-pass" (mv/vaultget master "db.pass") "db.pass")
      (same "fixture-deep" (mv/vaultget master "deep.nested.name") "deep")

      (same [{"key" "master" "master" true "write" true "grants" []}
             {"key" "reader" "master" false "write" false "grants" ["api.token"]}
             {"key" "writer" "master" false "write" true "grants" ["db.pass"]}]
            (mv/vaultkeys master) "keys")

      (let [reader (openas file "reader" "fixture-reader")]
        (same ["api.token"] (mv/vaultlist reader) "reader list")
        (same "fixture-token" (mv/vaultget reader "api.token") "reader grant")
        (same nil (mv/vaultget reader "db.pass") "reader miss"))

      (mv/vaultset (openas file "writer" "fixture-writer") "db.pass" "written by this port")
      (same "written by this port" (mv/vaultget master "db.pass") "writer"))))

;; --- the chain -------------------------------------------------------

(defn avaultisonestoreinachain []
  (let [vault (fresh)]
    (mv/vaultset vault "api.token" "from the vault")

    (let [secrets (thechain {:kind "memory" :values {"DB_PASS" "from memory"}}
                            {:kind "minivault" :file (mv/vaultfile vault)
                             :passphrase MASTER})]
      (same "from the vault" (sekreto/get secrets "api.token") "the vault")
      (same "from memory" (sekreto/get secrets "db.pass") "memory"))))

(defn arestrictedkeyinachainfallsthrough []
  (let [vault (fresh)]
    (mv/vaultset vault "api.token" "from the vault")
    (mv/vaultset vault "db.pass" "in the vault, not granted")
    (mv/vaultgrant vault {:key "ci" :passphrase "ci-phrase" :names ["api.token"]
                          :iterations ROUNDS})

    (let [secrets (thechain {:kind "minivault" :file (mv/vaultfile vault)
                             :vaultkey "ci" :passphrase "ci-phrase"}
                            {:kind "memory" :values {"DB_PASS" "from memory"}})]
      (same "from the vault" (sekreto/get secrets "api.token") "the grant")
      (same "from memory" (sekreto/get secrets "db.pass") "falls through"))))

(defn thevaultbehindastoreisreachable []
  (let [vault (fresh)]
    (mv/vaultset vault "api.token" "tok01")

    (let [secrets (thechain {:kind "minivault" :file (mv/vaultfile vault)
                             :passphrase MASTER})
          api (mv/vaultof secrets)]
      (same ["api.token"] (mv/vaultlist api) "list")
      (mv/vaultset api "db.pass" "written through the api")
      (same "written through the api" (sekreto/get secrets "db.pass") "the chain"))))

(defn anamedstoreisreachedbyname []
  (let [vault (fresh)]
    (mv/vaultset vault "api.token" "tok01")

    (let [secrets (thechain {:kind "minivault" :name "app" :file (mv/vaultfile vault)
                             :passphrase MASTER})]
      (same ["api.token"] (mv/vaultlist (mv/vaultof secrets "app")) "by name")
      (same ["api.token"] (mv/vaultlist (mv/vaultof secrets)) "by alias")
      (holds (refused #(mv/vaultof secrets "minivault")) "no minivault store named"
             "a name that is not there"))))

(defn achainwithnovaultsaysso []
  (let [secrets (thechain {:kind "memory" :values {}})]
    (holds (refused #(mv/vaultof secrets)) "no minivault store" "no vault")))

(defn achainmissingthefileisrefused []
  (holds (refused #(thechain {:kind "minivault" :passphrase MASTER}))
         "a vault needs a file" "no file")
  (holds (refused #(thechain {:kind "minivault" :file (vaultpath)}))
         "a vault needs a passphrase" "no passphrase"))

(defn thefileisreachedatthefirstlookup []
  ;; No file, and construction still succeeds: the handle is lazy.
  (let [secrets (thechain {:kind "minivault" :file (vaultpath) :passphrase MASTER})]
    (holds (refused #(sekreto/get secrets "api.token")) "no vault file"
           "at the first lookup")))

;; --- the run ---------------------------------------------------------

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
  (reset! WORK (.toFile (Files/createTempDirectory "sekreto-minivault"
                                                   (into-array java.nio.file.attribute.FileAttribute []))))

  (testcase "newvault" anewvaultholdsnothing)
  (testcase "written" awrittensecretcomesback)
  (testcase "binary" thefileisbinary)
  (testcase "rewrite" rewritinganamereplacesit)
  (testcase "remove" removedropsaname)
  (testcase "badname" abadnameisrefused)
  (testcase "restricted" arestrictedkeyreadsitsgrants)
  (testcase "readonly" areadonlykeyrefusestowrite)
  (testcase "ungranted" arestrictedkeycannotwriteanungrantedname)
  (testcase "laternamed" agrantednamethatdoesnotexistyet)
  (testcase "keys" themasterlistseverykey)
  (testcase "masteronly" themasteronlymethodsrefusearestrictedkey)
  (testcase "repeatedid" arepeatedkeyidisrefused)
  (testcase "revoke" revokedropsakey)
  (testcase "rotate" rotatekeepsthesecrets)
  (testcase "wrongphrase" awrongpassphraseandamissingfilerefuse)
  (testcase "damaged" adamagedfileisrefused)
  (testcase "createover" creatingoveranexistingvaultisrefused)
  (testcase "needsfile" avaultneedsafileandapassphrase)
  (testcase "emptykey" anemptykeymeansthemasterkey)
  (testcase "createflag" createmakesthefileonlywhenasked)
  (testcase "longkeyid" akeyidlongerthantheformatallowsisrefused)
  (testcase "infocopy" theinfoacallergetscannotchangewhatthekeymaydo)
  (testcase "revokedcached" arevokedkeystopsreading)
  (testcase "regranted" aregrantedkeyid)
  (testcase "close" closeforgetsthederivedkeys)

  (doseq [name (fixtures)]
    (testcase (str "fixture:" name) (readsfixture name)))

  (testcase "chain" avaultisonestoreinachain)
  (testcase "chainfallthrough" arestrictedkeyinachainfallsthrough)
  (testcase "api" thevaultbehindastoreisreachable)
  (testcase "namedstore" anamedstoreisreachedbyname)
  (testcase "novault" achainwithnovaultsaysso)
  (testcase "badconfig" achainmissingthefileisrefused)
  (testcase "lazy" thefileisreachedatthefirstlookup)

  (println)
  (println (str @PASSCOUNT " passed, " @FAILCOUNT " failed"))
  (System/exit (if (zero? @FAILCOUNT) 0 1)))
