(* THE FULL SET - every plugin this library ships, in one module.

   It exists for the callers that genuinely want all ten kinds: the CLI,
   the conformance suite, an app whose chain is decided at run time.

     let secrets = Sekreto.sekreto ~plugins:(Allplugins.all ()) chain

   IT IS ALSO THE THING TO AVOID IF YOU CARE ABOUT SIZE. Naming this module
   links every plugin - AWS request signing, seven HTTP vault clients, the
   TLS binding and the OpenSSL beneath it - which is the cost the
   core/plugin split exists to remove. A lean consumer names the kinds it
   actually configures, each from its own module:

     let secrets = Sekreto.sekreto ~plugins:[ Hashicorp.plugin () ] chain

   ocamlopt links a compilation unit only when something references it, so
   the difference is in the binary and not merely in the source. *)

(* Built, not held: every entry is a fresh definition, so two chains never
   share one and nothing is built at load time. *)
let all () : Defs.definition list =
  [
    Hashicorp.plugin ();
    Boru.plugin ();
    Aws.secretsplugin ();
    Aws.paramsplugin ();
    Gcpsecrets.plugin ();
    Azuresecrets.plugin ();
    Onepassword.plugin ();
    Doppler.plugin ();
    Infisical.plugin ();
    Secretspec.plugin ();
  ]
