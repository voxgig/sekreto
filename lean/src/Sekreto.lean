/-
sekreto - one interface for secrets, wherever they live.

The whole public surface, in one import. Everything below is in the
`Sekreto` namespace, so a consumer writes `import Sekreto` and either
`open Sekreto` or qualifies.

    let secrets ← sekreto [
      { kind := "env" },
      { kind := "dotenv", file := ".env" },
      { kind := "hashicorp", addr := "https://vault.example.com:8200" }]

    let token ← secrets.get "api.token"

Two ways to read. `get` is transparent - it walks the chain and takes the
first hit. `getfrom` is directed - it names the store, and only that
store is asked.

Nothing here reaches the network until the first lookup: construction
validates, and contacts nothing.
-/

import Sekreto.Text
import Sekreto.Json
import Sekreto.Crypto
import Sekreto.Provider
import Sekreto.Core
import Sekreto.Sigv4
import Sekreto.Clock
import Sekreto.Addr
import Sekreto.Curl
import Sekreto.Providers
