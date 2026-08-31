# Provider plugins: sekreto on voxgig/plugin

**Status:** design agreed, TypeScript in progress, nine ports pending.

## Why

sekreto ships thirteen provider kinds in one 1,279-line `Providers.ts`,
reachable from a `makeprovider` switch. Every consumer gets all
thirteen, so an SDK whose chain is `[dotenv, env]` still carries AWS
SigV4 request signing, seven HTTP vault clients, and the `node:crypto`
edge that comes with them.

`nodemod()` already defers the *platform module* to first use, and that
was worth doing — importing sekreto is now safe on a runtime with no
`node:fs`. But it does not make the code absent, and its own comment
says so: a bundler still resolves a `require` it can see. Leanness needs
the provider to not be there at all.

The goal, stated by the consumer that forced it: **baseline sekreto has
no platform dependencies in any language port, and everything else is a
matter of choice or of what the API actually needs.**

## The shape

| layer | holds |
|---|---|
| **core** | the chain (`get`/`try`/`getfrom`/`tryfrom`), cache, redaction, `Provider`, `SekretoError`, and the two providers that import nothing: `env` and `memory` |
| **plugins** | the other eleven, each declaring what it needs: `dotenv` `file` `hashicorp` (fs), `boru` `gcpsecrets` `azuresecrets` `onepassword` `doppler` `infisical` (fetch), `awssecrets` `awsparams` (fetch + crypto, via `sigv4`) |

A chain needs somewhere to read from, so `env` and `memory` stay in
core: they make the library usable and testable standalone, and neither
imports anything.

## Providers are voxgig/plugin definitions

[`voxgig/plugin`](https://github.com/voxgig/plugin) is the general-purpose
plugin architecture for the stack — zero dependencies, one model across
every language. sekreto does not invent a second registry.

- A **provider kind** is a plugin `Definition` (`name`, `shape`,
  `define`, `activate`, `deactivate`).
- A **configured provider** is a plugin instance addressed by name+tag —
  `awssecrets$prod` and `awssecrets$test` coexist and are individually
  addressable. This is sekreto's `store` naming, and `getfrom(store,
  name)` becomes instance addressing rather than a filtered scan.
- Lifecycle is plugin's: declared (config only, nothing loaded) → loaded
  (defined, inert) → live (holding resources). A provider that opens a
  client acquires in `activate`, and plugin unwinds it.

## The one seam that is NOT plugin's: async lookup

**voxgig/plugin has no async surface.** `compose()` is synchronous, and
the only mention of asynchrony in the library is a comment in `Point.ts`
explaining why the fan-out modes exist at all. That is deliberate — the
§18 portability budget spans twenty languages, many with no
async/await — and it is not a gap to be filled.

sekreto's `Provider.lookup` is inherently async: seven of the thirteen
kinds are HTTP clients.

So the boundary is:

- **plugin owns** the catalog, instances, name+tag addressing,
  lifecycle, config normalisation and shape checking, and resolved
  ORDER.
- **sekreto owns** the walk. It asks plugin for the ordered live
  instances and iterates them in its own language's idiom.

Two things this deliberately avoids:

1. **`bail` mode cannot express first-hit here.** `bail` stops at the
   first binding that returns a value; an async lookup returns a
   Promise, which is always a value, so every chain would stop at its
   first provider whether or not it found the secret.
2. **A `chain` point would work in TypeScript and mislead nine ports.**
   `compose` builds `fn(inner, ...args)`, which composes correctly when
   the bindings are async — *in JavaScript*, because promises compose.
   Relying on that would make the canonical port pass while giving the
   other nine a construct their languages do not have. The portability
   budget is the whole reason plugin is sync; borrowing JS semantics
   through it would be using the library against its own design.

## Consequences accepted

- **Port coverage gates propagation.** plugin has five ports
  (typescript, go, javascript, python, ruby); sekreto has ten. The five
  without one — csharp, java, perl, php, rust — cannot adopt this until
  plugin lands there. They keep the switch until then, which is why the
  core/plugin *file split* is worth doing independently of the plugin
  dependency: the split delivers leanness to all ten, and the plugin
  model replaces the registry underneath it port by port.
- **Vendoring cost is real and is paid once.** plugin's TypeScript is
  3,184 lines. Vendoring that into an SDK to avoid a 5,153-byte
  `Sigv4.ts` is a bad trade *in isolation* and a good one only because
  the same host serves station, sdkgen's features and these providers.
  An SDK that wants none of them should not carry it, which is what the
  sdkgen-side trim decides.
- **The spec contract moves.** `spec/sekreto.aon` is the contract for
  all ten ports. Provider construction and store naming change shape,
  so the affected groups change with them — deliberately, and in one
  edit, because ten ports read it.

## Propagation order

typescript (canonical) → go, python, javascript, ruby (plugin ports
exist) → csharp, java, perl, php, rust (file split only, until plugin
lands).
