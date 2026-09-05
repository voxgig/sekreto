;; THE FULL SET - every plugin this library ships, in one require.
;;
;; It exists for the callers that genuinely want all ten kinds: the CLI,
;; the conformance suite, an app whose chain is decided at run time.
;;
;;   (require '[voxgig.sekreto :as sekreto]
;;            '[voxgig.sekreto.plugins :as plugins])
;;
;;   (sekreto/sekreto specs {:plugins plugins/ALL})
;;
;; IT IS ALSO THE THING TO AVOID IF YOU CARE ABOUT WHAT GETS LOADED.
;; Reaching one plugin through this namespace loads every other one - AWS
;; request signing and seven HTTP vault clients included - which is the
;; cost the core/plugin split exists to remove. A lean consumer requires
;; the kinds it actually configures, each its own namespace:
;;
;;   (require '[voxgig.sekreto.plugins.hashicorp :refer [hashicorp]])
;;
;; Nothing here is loaded by requiring `voxgig.sekreto`, and requiring one
;; plugin loads one plugin: Clojure has no package initializer to run, so
;; the laziness python's plugins package has to arrange with a module
;; `__getattr__` is what a directory of namespaces already does.
;;
;; See docs/design/plugin-providers.md.

(ns voxgig.sekreto.plugins
  (:require [voxgig.sekreto.plugins.hashicorp :as hashicorp]
            [voxgig.sekreto.plugins.boru :as boru]
            [voxgig.sekreto.plugins.aws :as aws]
            [voxgig.sekreto.plugins.gcpsecrets :as gcpsecrets]
            [voxgig.sekreto.plugins.azuresecrets :as azuresecrets]
            [voxgig.sekreto.plugins.onepassword :as onepassword]
            [voxgig.sekreto.plugins.doppler :as doppler]
            [voxgig.sekreto.plugins.infisical :as infisical]
            [voxgig.sekreto.plugins.secretspec :as secretspec]))

(def ALL
  "Every plugin kind this library ships, in one vector."
  [hashicorp/hashicorp
   boru/boru
   aws/awssecrets
   aws/awsparams
   gcpsecrets/gcpsecrets
   azuresecrets/azuresecrets
   onepassword/onepassword
   doppler/doppler
   infisical/infisical
   secretspec/secretspec])
