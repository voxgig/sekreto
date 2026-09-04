;; A tiny app that needs a secret.
;;
;; It asks sekreto for `api.token` and calls the token-protected API with
;; it. Every port ships this same CLI, and test/integration.sh runs all of
;; them against the same server from every secret source - which is what
;; proves the library, rather than the spec alone.
;;
;; Usage: java -cp build/sekreto-cli.jar sekreto.Cli <api-url>
;;            [--source <source>] [--store <name>]
;;
;; Sources: env dotenv file hashicorp boru boruwire awssecrets awsparams
;;          gcpsecrets azuresecrets onepassword doppler infisical
;;          secretspec chain
;;
;; Each source's configuration arrives in the environment variables its own
;; ecosystem already uses (VAULT_*, AWS_*, OP_CONNECT_*, ...), listed in
;; `chainfor` below.
;;
;; AOT-compiled into a jar that carries the Clojure runtime with it, because
;; the integration suite runs every port's CLI from an EMPTY directory: a
;; CLI that needed a deps.edn, or anything else in the working directory,
;; would be reading the very files a stray .env must not be able to supply.

(ns sekreto.cli
  (:require [voxgig.sekreto :as sekreto]
            [voxgig.sekreto.json :as json])
  (:import [java.net URI]
           [java.net.http HttpClient HttpClient$Version
            HttpRequest HttpResponse HttpResponse$BodyHandlers])
  (:gen-class :name sekreto.Cli))

(def ^:private LANG "clojure")

(defn- env [name] (System/getenv name))

(defn- envor [name fallback]
  (let [value (env name)]
    (if (or (nil? value) (= "" value)) fallback value)))

(defn- chainfor [source]
  (let [envspec {:kind "env" :prefix (env "SEKRETO_PREFIX")}
        dotenvspec {:kind "dotenv" :file (envor "SEKRETO_DOTENV" ".env")}
        filespec {:kind "file" :dir (envor "SEKRETO_FILEDIR" "/run/secrets")}

        hashicorpspec {:kind "hashicorp"
                       :addr (envor "VAULT_ADDR" "")
                       :token (envor "VAULT_TOKEN" "")
                       :mount (env "VAULT_MOUNT")
                       :kv (some-> (env "VAULT_KV") parse-long)
                       :vaultnamespace (env "VAULT_NAMESPACE")
                       :auth (when-let [method (env "VAULT_AUTH")]
                               (when (not= "" method)
                                 {:method method
                                  :role (env "VAULT_ROLE")
                                  :jwtfile (env "VAULT_JWT_FILE")
                                  :roleid (env "VAULT_ROLE_ID")
                                  :secretid (env "VAULT_SECRET_ID")}))}

        boruspec {:kind "boru"
                  :command (envor "BORU_COMMAND" "boru")
                  :namespace (env "BORU_NAMESPACE")
                  :home (env "BORU_HOME")}

        ;; The same vault over its wire protocol (`boru vault serve`)
        ;; instead of the CLI: an address plus a capability token from
        ;; `vault grant`.
        boruwirespec {:kind "boru"
                      :addr (envor "BORU_ADDR" "")
                      :token (envor "BORU_TOKEN" "")
                      :namespace (env "BORU_NAMESPACE")}

        awssecretsspec {:kind "awssecrets"
                        :region (env "AWS_REGION")
                        :addr (env "AWS_ENDPOINT")}

        awsparamsspec {:kind "awsparams"
                       :region (env "AWS_REGION")
                       :addr (env "AWS_ENDPOINT")
                       :prefix (env "AWS_PARAM_PREFIX")}

        gcpspec {:kind "gcpsecrets"
                 :project (env "GCP_PROJECT")
                 :addr (env "GCP_ADDR")
                 :metadataaddr (env "GCP_METADATA_ADDR")}

        azurespec {:kind "azuresecrets"
                   :vault (env "AZURE_VAULT")
                   :token (env "AZURE_TOKEN")
                   :tenant (env "AZURE_TENANT")
                   :clientid (env "AZURE_CLIENT_ID")
                   :clientsecret (env "AZURE_CLIENT_SECRET")
                   :loginaddr (env "AZURE_LOGIN_ADDR")
                   :imdsaddr (env "AZURE_IMDS_ADDR")}

        onepasswordspec {:kind "onepassword"
                         :addr (env "OP_CONNECT_HOST")
                         :token (env "OP_CONNECT_TOKEN")
                         :vault (env "OP_VAULT")}

        dopplerspec {:kind "doppler"
                     :token (env "DOPPLER_TOKEN")
                     :project (env "DOPPLER_PROJECT")
                     :config (env "DOPPLER_CONFIG")
                     :addr (env "DOPPLER_ADDR")}

        ;; SecretSpec's own environment variables where it has them
        ;; (SECRETSPEC_FILE, _PROFILE, _PROVIDER, _REASON are read by the
        ;; secretspec CLI itself), so a shell already set up for secretspec
        ;; needs nothing further.
        secretspecspec {:kind "secretspec"
                        :command (envor "SECRETSPEC_COMMAND" "secretspec")
                        :file (env "SECRETSPEC_FILE")
                        :profile (env "SECRETSPEC_PROFILE")
                        :backend (env "SECRETSPEC_PROVIDER")
                        :reason (env "SECRETSPEC_REASON")}

        infisicalspec {:kind "infisical"
                       :addr (env "INFISICAL_ADDR")
                       :token (env "INFISICAL_TOKEN")
                       :clientid (env "INFISICAL_CLIENT_ID")
                       :clientsecret (env "INFISICAL_CLIENT_SECRET")
                       :project (env "INFISICAL_PROJECT")
                       :environment (env "INFISICAL_ENV")
                       :path (env "INFISICAL_PATH")}]

    (case source
      "env" [envspec]
      "dotenv" [dotenvspec]
      "file" [filespec]
      "hashicorp" [hashicorpspec]
      "boru" [boruspec]
      "boruwire" [boruwirespec]
      "awssecrets" [awssecretsspec]
      "awsparams" [awsparamsspec]
      "gcpsecrets" [gcpspec]
      "azuresecrets" [azurespec]
      "onepassword" [onepasswordspec]
      "doppler" [dopplerspec]
      "infisical" [infisicalspec]
      "secretspec" [secretspecspec]
      ;; The default: the chain an app would actually ship with - local
      ;; overrides first, shared vaults last.
      [envspec dotenvspec hashicorpspec boruspec])))

(defn- flag
  "The value of a `--flag value` pair, or \"\" when the flag is absent."
  [args name]
  (let [at (.indexOf ^java.util.List (vec args) name)]
    (if (or (= -1 at) (<= (count args) (inc at))) "" (nth args (inc at)))))

(defn- run [args]
  (let [url (if (seq args) (first args) "http://127.0.0.1:8099/whoami")
        source (let [given (flag args "--source")] (if (= "" given) "chain" given))

        ;; --store names a store outright: the secret must come from that
        ;; one, not from whichever provider happens to answer first.
        store (flag args "--store")

        secrets (sekreto/sekreto (chainfor source))

        token (try
                (if (= "" store)
                  (sekreto/get secrets "api.token")
                  (sekreto/getfrom secrets store "api.token"))
                (catch Exception err
                  (binding [*out* *err*] (println (str "sekreto-cli: " (ex-message err))))
                  ::failed))]

    (if (= ::failed token)
      2
      (let [request (-> (HttpRequest/newBuilder)
                        (.uri (URI/create url))
                        (.header "Authorization" (str "Bearer " token))
                        (.header "X-Sekreto-Lang" LANG)
                        (.GET)
                        (.build))

            response (try
                       (.send (-> (HttpClient/newBuilder)
                                  (.version HttpClient$Version/HTTP_1_1)
                                  (.build))
                              request
                              (HttpResponse$BodyHandlers/ofString))
                       (catch Exception err
                         (binding [*out* *err*]
                           (println (str "sekreto-cli: "
                                         (sekreto/redactall
                                          secrets
                                          (or (ex-message err) (str err))))))
                         nil))]

        (cond
          (nil? response) 1

          (not= 200 (.statusCode ^HttpResponse response))
          ;; Never print the token itself, even when the call fails.
          (do (binding [*out* *err*]
                (println (str "sekreto-cli: "
                              (sekreto/redactall secrets (.body ^HttpResponse response)))))
              1)

          :else
          (let [caller (json/dig (json/parse (.body ^HttpResponse response)) "caller")]
            ;; Assembled field by field, in the spec's order. Printing a map
            ;; here is what has bitten port after port: the language's own
            ;; key order is not the one every other port prints.
            (println (str "{\"ok\":true"
                          ",\"lang\":" (json/quotestr LANG)
                          ",\"source\":" (json/quotestr source)
                          ",\"store\":" (json/quotestr store)
                          ",\"caller\":" (json/stringify caller)
                          "}"))
            0))))))

(defn -main [& args]
  (System/exit (run args)))
