;; sekreto: one interface for secrets, wherever they live.
;;
;; This is the namespace a consumer requires. Everything below it is split
;; by subject rather than by audience: the facade and the name helpers in
;; `voxgig.sekreto.core`, the fourteen provider kinds in
;; `voxgig.sekreto.providers`, request signing in `voxgig.sekreto.sigv4`,
;; and just enough JSON in `voxgig.sekreto.json`.
;;
;; The split is not a matter of taste. The provider kinds need the name
;; helpers, so the namespace that defines those cannot be the one that
;; builds a chain out of kinds - a namespace cycle is a load error in
;; Clojure, not a warning. `carry` below republishes the two halves as one
;; API.
;;
;;   (require '[voxgig.sekreto :as sekreto])
;;
;;   (def secrets
;;     (sekreto/sekreto [{:kind "env"}
;;                       {:kind "dotenv" :file ".env"}
;;                       {:kind "hashicorp" :addr vaultaddr :token vaulttoken}]))
;;
;;   (sekreto/get secrets "api.token")                  ; the chain answers
;;   (sekreto/getfrom secrets "hashicorp" "api.token")  ; one named store

(ns voxgig.sekreto
  (:refer-clojure :exclude [get])
  (:require [voxgig.sekreto.core :as core]
            [voxgig.sekreto.providers :as providers]
            [voxgig.sekreto.sigv4 :as sigv4]))

(defmacro ^:private carry
  "Republish another namespace's var here, under the same name and with its
  own docstring and argument lists, so that `doc` and every editor find them
  through this namespace."
  [source]
  `(doto (def ~(symbol (name source)) ~source)
     (alter-meta! merge (select-keys (meta (var ~source)) [:doc :arglists]))))

;; The names.
(carry core/validname)
(carry core/checkname)
(carry core/envkey)
(carry core/vaultref)
(carry core/flatname)
(carry core/awsparam)

;; The text helpers.
(carry core/parsedotenv)
(carry core/redact)

;; Errors: one type, asked about rather than caught by class.
(carry core/sekretoerror)
(carry core/sekretoerror?)

;; A chain, and the two ways to read it.
(carry core/make)
(carry core/get)
(carry core/tryget)
(carry core/getfrom)
(carry core/tryfrom)
(carry core/has)
(carry core/hasin)
(carry core/all)
(carry core/sources)
(carry core/stores)
(carry core/storename)
(carry core/redactall)
(carry core/refresh)

;; The kinds, and AWS request signing.
(carry providers/makeprovider)
(carry sigv4/sigv4)

(defn sekreto
  "A Sekreto from declarative provider specs - the same shape the shared
  spec and an app's config file use.

  Each spec is a map whose `:kind` picks the provider; `:name` gives the
  store name `getfrom` addresses, and defaults to the kind. `:cache false`
  in the options turns the read cache off.

    (sekreto [{:kind \"memory\" :name \"local\" :values {\"API_TOKEN\" \"T\"}}
              {:kind \"hashicorp\" :addr addr :token token}])"
  ([specs] (sekreto specs nil))
  ([specs opts]
   (core/make (mapv providers/makeprovider specs)
              (assoc opts :names (mapv :name specs)))))
