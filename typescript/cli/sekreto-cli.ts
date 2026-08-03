// A tiny app that needs a secret.
//
// It asks sekreto for `api.token` and calls the token-protected API with
// it. Every port ships this same CLI, and test/integration.sh runs all of
// them against the same server from all four secret sources - which is
// what proves the library, rather than the spec alone.
//
// Usage: sekreto-cli <api-url> [--source env|dotenv|hashicorp|boru|chain]
//                              [--store <name>]   directed read

import { Sekreto } from '../src'
import { ProviderSpec } from '../src/Providers'

function chainfor(source: string): ProviderSpec[] {
  const env = process.env

  const envspec: ProviderSpec = { kind: 'env', prefix: env.SEKRETO_PREFIX }
  const dotenvspec: ProviderSpec = { kind: 'dotenv', file: env.SEKRETO_DOTENV || '.env' }
  const hashicorpspec: ProviderSpec = {
    kind: 'hashicorp',
    addr: env.VAULT_ADDR || '',
    token: env.VAULT_TOKEN || '',
    mount: env.VAULT_MOUNT,
  }
  const boruspec: ProviderSpec = {
    kind: 'boru',
    command: env.BORU_COMMAND || 'boru',
    namespace: env.BORU_NAMESPACE,
    home: env.BORU_HOME,
  }

  if ('env' === source) {
    return [envspec]
  }
  if ('dotenv' === source) {
    return [dotenvspec]
  }
  if ('hashicorp' === source) {
    return [hashicorpspec]
  }
  if ('boru' === source) {
    return [boruspec]
  }

  // The default: the chain an app would actually ship with - local
  // overrides first, shared vaults last.
  return [envspec, dotenvspec, hashicorpspec, boruspec]
}

async function main(): Promise<number> {
  const args = process.argv.slice(2)
  const url = args[0] || 'http://127.0.0.1:8099/whoami'

  const flag = args.indexOf('--source')
  const source = -1 === flag ? 'chain' : args[flag + 1]

  // --store names a store outright: the secret must come from that one,
  // not from whichever provider happens to answer first.
  const storeflag = args.indexOf('--store')
  const store = -1 === storeflag ? '' : args[storeflag + 1]

  const secrets = new Sekreto({ providers: chainfor(source) })

  let token: string
  try {
    token = store ? await secrets.getfrom(store, 'api.token') : await secrets.get('api.token')
  } catch (err: any) {
    console.error('sekreto-cli: ' + err.message)
    return 2
  }

  const res = await fetch(url, {
    headers: { authorization: 'Bearer ' + token, 'x-sekreto-lang': 'typescript' },
  })
  const body: any = await res.json()

  if (200 !== res.status) {
    // Never print the token itself, even when the call fails.
    console.error('sekreto-cli: ' + secrets.redact(JSON.stringify(body)))
    return 1
  }

  console.log(
    JSON.stringify({ ok: true, lang: 'typescript', source, store, caller: body.caller }),
  )

  return 0
}

main().then((code) => process.exit(code))
