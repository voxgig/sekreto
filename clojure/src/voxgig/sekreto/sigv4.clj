;; AWS Signature Version 4, hand-rolled.
;;
;; The AWS providers need exactly one thing from the AWS SDK - request
;; signing - and taking the SDK for it would break the no-dependency rule
;; that keeps the ports honest. SigV4 is a stable, published algorithm built
;; from HMAC-SHA256, which the JDK already has.
;;
;; `sigv4` is pure: the caller passes the timestamp, so the same input
;; yields the same signature everywhere. That is what lets the shared spec
;; carry known-answer cases that all ports must reproduce bit-for-bit, and
;; lets the integration mock recompute the signature server-side.
;;
;; A port of typescript/src/Sigv4.ts, which is canonical.

(ns voxgig.sekreto.sigv4
  (:require [clojure.string :as string]
            [voxgig.sekreto.core :as core]
            [voxgig.sekreto.json :as json])
  (:import [java.io ByteArrayOutputStream]
           [java.net URI]
           [java.nio.charset StandardCharsets]
           [java.security GeneralSecurityException MessageDigest NoSuchAlgorithmException]
           [java.util Locale]
           [javax.crypto Mac]
           [javax.crypto.spec SecretKeySpec]))

(defn hex [^bytes bytes]
  (let [out (StringBuilder.)]
    (doseq [byte bytes]
      (.append out (format "%02x" (bit-and (int byte) 0xff))))
    (.toString out)))

(defn sha256hex [^String text]
  (try
    (hex (.digest (MessageDigest/getInstance "SHA-256") (.getBytes text StandardCharsets/UTF_8)))
    ;; Every JDK ships SHA-256; a JVM without it cannot sign anything.
    (catch NoSuchAlgorithmException err
      (throw (core/sekretoerror (str "sekreto: sigv4: no SHA-256: " (.getMessage err)))))))

(defn hmac ^bytes [^bytes key ^String text]
  (try
    (let [mac (Mac/getInstance "HmacSHA256")]
      (.init mac (SecretKeySpec. key "HmacSHA256"))
      (.doFinal mac (.getBytes text StandardCharsets/UTF_8)))
    (catch GeneralSecurityException err
      (throw (core/sekretoerror (str "sekreto: sigv4: no HmacSHA256: " (.getMessage err)))))))

(defn uriescape
  "RFC 3986 escaping, which is stricter than the usual URL encoder: AWS
  wants everything but unreserved characters escaped, with uppercase hex."
  [^String text]
  (let [out (StringBuilder.)]
    (doseq [byte (.getBytes text StandardCharsets/UTF_8)]
      (let [ch (bit-and (int byte) 0xff)]
        (if (or (<= (int \A) ch (int \Z))
                (<= (int \a) ch (int \z))
                (<= (int \0) ch (int \9))
                (= (int \-) ch) (= (int \_) ch) (= (int \.) ch) (= (int \~) ch))
          (.append out (char ch))
          (.append out (format "%%%02X" ch)))))
    (.toString out)))

(defn- hexbyte
  "Two hex digits as a byte, or nil. The usual number reads are decimal."
  [^String text]
  (try (Integer/parseInt text 16) (catch NumberFormatException _ nil)))

(defn uridecode
  "Percent-decode, and nothing else: `+` stays `+`, as on the wire."
  [^String text]
  (let [out (ByteArrayOutputStream.)]
    (loop [index 0]
      (if (<= (count text) index)
        (String. (.toByteArray out) StandardCharsets/UTF_8)
        (let [head (.charAt text index)
              code (when (and (= \% head) (> (count text) (+ index 2)))
                     (hexbyte (subs text (inc index) (+ index 3))))]
          (if (some? code)
            (do (.write out (int code))
                (recur (+ index 3)))
            ;; A stray % is kept as-is, the way a browser would.
            (do (.write out (.getBytes (str head) StandardCharsets/UTF_8))
                (recur (inc index)))))))))

(defn canonicalquery
  "The canonical query string: each pair RFC 3986-escaped, sorted by escaped
  key then escaped value."
  [^String query]
  (if (= "" query)
    ""
    (->> (string/split query #"&" -1)
         (map (fn [pair]
                (let [eq (string/index-of pair "=")
                      key (if (nil? eq) pair (subs pair 0 eq))
                      value (if (nil? eq) "" (subs pair (inc eq)))]
                  [(uriescape (uridecode key)) (uriescape (uridecode value))])))
         (sort)
         (map (fn [[key value]] (str key "=" value)))
         (string/join "&"))))

(defn sigv4
  "Sign one request. Answers the headers to attach: authorization,
  x-amz-date, and x-amz-security-token when a session token was given, in
  that order - the spec compares the result as a JSON object, and callers
  print it field by field.

  The input is the same declarative shape the shared spec uses: `:method`,
  `:url`, `:service`, `:region`, `:keyid`, `:secret`, `:datetime`
  (`YYYYMMDDTHHMMSSZ`, and it is the caller's, so that signing is a pure
  function of its input), and optionally `:headers`, `:body`, `:session`."
  [{:keys [method url service region keyid secret datetime headers body session]}]
  (let [uri (URI/create url)
        date (subs datetime 0 8)
        body (or body "")
        session (core/notempty session)

        ;; Every header that will be signed: the caller's extras, plus host
        ;; and x-amz-date (and the session token when present), lower-cased
        ;; and trimmed the way the canonical form requires. A sorted map
        ;; keeps them in the canonical order, which is by name.
        ;;
        ;; Canonical header values are trimmed AND internally collapsed -
        ;; AWS folds sequential whitespace to one space before signing, so a
        ;; header like "a  b" must sign as "a b" or the service refuses it.
        signheaders (cond-> (reduce-kv
                             (fn [out key value]
                               (assoc out
                                      (.toLowerCase ^String key Locale/ROOT)
                                      (string/replace (string/trim value) #"\s+" " ")))
                             (sorted-map)
                             (or headers {}))
                      true (assoc "host" (str (.getHost uri)
                                              (when (not= -1 (.getPort uri))
                                                (str ":" (.getPort uri)))))
                      true (assoc "x-amz-date" datetime)
                      session (assoc "x-amz-security-token" session))

        canonicalheaders (apply str (map (fn [[key value]] (str key ":" value "\n")) signheaders))
        signedheaders (string/join ";" (keys signheaders))

        rawpath (.getRawPath uri)
        path (if (or (nil? rawpath) (= "" rawpath)) "/" rawpath)

        canonicalrequest (string/join
                          "\n"
                          [(.toUpperCase ^String method Locale/ROOT)
                           path
                           (canonicalquery (or (.getRawQuery uri) ""))
                           canonicalheaders
                           signedheaders
                           (sha256hex body)])

        scope (str date "/" region "/" service "/aws4_request")

        stringtosign (string/join "\n" ["AWS4-HMAC-SHA256"
                                        datetime
                                        scope
                                        (sha256hex canonicalrequest)])

        kdate (hmac (.getBytes (str "AWS4" secret) StandardCharsets/UTF_8) date)
        kregion (hmac kdate region)
        kservice (hmac kregion service)
        ksigning (hmac kservice "aws4_request")
        signature (hex (hmac ksigning stringtosign))]

    (json/omap
     (cond-> [["authorization" (str "AWS4-HMAC-SHA256 Credential=" keyid "/" scope
                                    ", SignedHeaders=" signedheaders
                                    ", Signature=" signature)]
              ["x-amz-date" datetime]]
       session (conj ["x-amz-security-token" session])))))
