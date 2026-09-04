import Sekreto.Sigv4
import Sekreto.Core
open Sekreto
def render (pairs : Pairs String) : String :=
  Json.stringify (Json.obj (pairs.map (fun kv => (kv.1, Json.str kv.2))))
def main : IO Unit := do
  let a : Signing := {
    method := "GET", url := "https://example.amazonaws.com/",
    service := "service", region := "us-east-1", keyid := "AKIDEXAMPLE",
    secret := "wJalrXUtnFEMI/K7MDENG+bPxRfiCYEXAMPLEKEY", datetime := "20150830T123600Z" }
  IO.println (render (sigv4 a))
  let b : Signing := { a with url := "https://example.amazonaws.com/path/to?b=2&a=1" }
  IO.println ((Pairs.find? (sigv4 b) "authorization").getD "?")
  let c : Signing := { a with method := "POST", headers := [("x-amz-target", "a  b\tc")] }
  IO.println ((Pairs.find? (sigv4 c) "authorization").getD "?")
  IO.println (render (parsedotenv "export A = \"x\\ny\" \n#c\nNOEQ\nB='q'\r\n=bad\n"))
  IO.println (redact "token=abcd1234" ["abcd", "abcd1234"])
  IO.println (toString (validname "api.token\n", validname "api.token", validname "A.B"))
  IO.println (toString ((envkey "api.token" "app").toOption, (awsparam "api.token" "app/").toOption))
