import Sekreto.Curl
import Sekreto.Clock
open Sekreto
def main : IO Unit := do
  IO.println (← awsnow)
  IO.println (awsstamp 1440938160)
  let a ← fetchjson "GET" "http://127.0.0.1:9150/hello" [("X-Test", "1")]
  IO.println (toString a.status ++ " " ++ (a.body.map Json.stringify).getD "-")
  let b ← fetchjson "POST" "http://127.0.0.1:9150/echo" [("content-type","application/json")] (some "{\"a\":1}")
  IO.println (toString b.status ++ " " ++ (b.body.map Json.stringify).getD "-")
  try
    let _ ← fetchjson "GET" "http://127.0.0.1:9151/nope?q=secret" []
    IO.println "UNREACHED"
  catch e => IO.println (toString e)
  try
    let _ ← fetchjson "GET" "https://vault.example.invalid/v1/x" []
    IO.println "UNREACHED"
  catch e => IO.println (toString e)
