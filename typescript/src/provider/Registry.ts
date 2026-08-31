/* Copyright (c) 2025 Voxgig Ltd, MIT License */

// THE PROVIDER REGISTRY — the seam that replaced the `makeprovider`
// switch, and the reason an SDK no longer carries thirteen providers to
// use two.
//
// The switch named every kind in one function, so every kind was
// statically reachable from `Sekreto` and no bundler could drop one. Its
// replacement is a map that a provider ADDS ITSELF to. A kind that is
// never imported is never registered, is never reachable, and is not in
// the build — which is the whole point.
//
// The vocabulary is voxgig/plugin's (docs/design/plugin-providers.md): a
// provider kind is a plugin `Definition`, a configured provider is an
// instance addressed by name+tag. What sekreto does NOT route through
// plugin is the lookup itself: `Provider.lookup` is async, and plugin's
// dispatch is synchronous by design — twenty ports, many with no
// async/await. So plugin owns the catalog, the instances and their
// order; sekreto walks them in each language's own idiom.
//
// `define` is the definition's factory: spec in, Provider out. It is
// separate from the plugin `Definition.define` callback on purpose —
// this one runs at construction and returns a value, while plugin's runs
// at load and binds. They are bridged in Catalog.ts.

import { Provider, ProviderSpec, SekretoError } from './support'

export type ProviderDefinition = {
  /** The `kind` a ProviderSpec names. */
  name: string
  /** What this provider needs of its runtime, so a host can refuse or
   * report before a lookup fails: 'fs', 'fetch', 'crypto', 'process'. */
  needs?: string[]
  /** Build the provider from its declarative spec. */
  define: (spec: ProviderSpec) => Provider
}

const registry: { [kind: string]: ProviderDefinition } = {}

/** Register a provider kind. Called by each provider module at import,
 * so importing the module IS installing it. Re-registering the same name
 * replaces it, which is how a host substitutes an implementation. */
export function register(def: ProviderDefinition): void {
  if (null == def || 'string' !== typeof def.name || '' === def.name) {
    throw new SekretoError('sekreto: invalid provider definition')
  }
  registry[def.name] = def
}

export function registered(kind: string): ProviderDefinition | undefined {
  return registry[kind]
}

export function kinds(): string[] {
  return Object.keys(registry).sort()
}

/** Build a provider from its spec.
 *
 * An UNREGISTERED kind is not the same failure as an unknown one, and the
 * message says which: a kind sekreto has never heard of is a typo, while
 * a known kind that was not imported is the leanness mechanism working as
 * designed and telling you to import it. Collapsing the two was the first
 * thing that made the split confusing to use. */
export function makeprovider(spec: ProviderSpec): Provider {
  const kind = null == spec ? undefined : (spec as any).kind
  const def = registry[kind as string]

  if (null == def) {
    throw new SekretoError(
      'sekreto: unknown provider kind: ' + String(kind) +
      ' (registered: ' + (kinds().join(', ') || 'none') + ')' +
      (KNOWN.indexOf(String(kind)) < 0 ? '' :
        " - that kind exists but its module was not imported; import" +
        " '@voxgig/sekreto/provider/" + String(kind) + "' to register it"))
  }

  return def.define(spec)
}

/** Every kind this library ships, registered or not. Used only to tell a
 * typo from a module that was not imported. */
const KNOWN = [
  'env', 'memory', 'dotenv', 'file', 'hashicorp', 'boru',
  'awssecrets', 'awsparams', 'gcpsecrets', 'azuresecrets',
  'onepassword', 'doppler', 'infisical',
]
