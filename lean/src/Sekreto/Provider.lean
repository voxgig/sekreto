/-
A source of secrets.

A provider answers one question: "do you have this secret?" It returns
the value, or `none` to mean "ask the next one". Nothing else about a
provider is visible to the caller - which is the point: an app reads
`api.token` and never learns whether it came from the environment, a
.env file, HashiCorp Vault or a boru vault.
-/

namespace Sekreto

/-- A source of secrets: two functions and no lifecycle.

A record of functions rather than a class, so the provider set stays open
- a caller can put its own provider in a chain without this library
knowing the type. `lookup` is in `IO` because the four built-in kinds
already read the environment and the filesystem; `describe` is not,
because it is fixed when the provider is built and the facade calls it at
construction to derive a default store name. -/
structure Provider where
  /-- The value, or `none` if this provider does not have it. A store
  that could not ANSWER throws instead: the two are never the same. -/
  lookup : String → IO (Option String)
  /-- A short description, shown by `Sekreto.sources`. It opens with the
  provider's kind, because `storename` is everything before the first
  `:`. -/
  describe : String

end Sekreto
