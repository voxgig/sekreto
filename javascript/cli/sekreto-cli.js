// A tiny app that needs a secret.
//
// It asks sekreto for `api.token` and calls the token-protected API with
// it. Every port ships this same CLI, and test/integration.sh runs all of
// them against the same server from all four secret sources - which is
// what proves the library, rather than the spec alone.
//
// Usage: sekreto-cli <api-url> [--source env|dotenv|vault|boru|chain]

const { Sekreto } = require('../src')

const LANG = 'javascript'

function chainfor(source) {
  const env = process.env

  const envspec = { kind: 'env', prefix: env.SEKRETO_PREFIX }
  const dotenvspec = { kind: 'dotenv', file: env.SEKRETO_DOTENV || '.env' }
  const vaultspec = {
    kind: 'vault',
    addr: env.VAULT_ADDR || '',
    token: env.VAULT_TOKEN || '',
    mount: env.VAULT_MOUNT,
  }
  const boruspec = {
    kind: 'boru',
    addr: env.BORU_VAULT_ADDR || '',
    token: env.BORU_VAULT_TOKEN || '',
  }

  if ('env' === source) {
    return [envspec]
  }
  if ('dotenv' === source) {
    return [dotenvspec]
  }
  if ('vault' === source) {
    return [vaultspec]
  }
  if ('boru' === source) {
    return [boruspec]
  }

  // The default: the chain an app would actually ship with - local
  // overrides first, shared vaults last.
  return [envspec, dotenvspec, vaultspec, boruspec]
}

async function main() {
  const args = process.argv.slice(2)
  const url = args[0] || 'http://127.0.0.1:8099/whoami'

  const flag = args.indexOf('--source')
  const source = -1 === flag ? 'chain' : args[flag + 1]

  const secrets = new Sekreto({ providers: chainfor(source) })

  let token
  try {
    token = await secrets.get('api.token')
  } catch (err) {
    console.error('sekreto-cli: ' + err.message)
    return 2
  }

  const res = await fetch(url, {
    headers: { authorization: 'Bearer ' + token, 'x-sekreto-lang': LANG },
  })
  const body = await res.json()

  if (200 !== res.status) {
    // Never print the token itself, even when the call fails.
    console.error('sekreto-cli: ' + secrets.redact(JSON.stringify(body)))
    return 1
  }

  console.log(JSON.stringify({ ok: true, lang: LANG, source, caller: body.caller }))

  return 0
}

main().then((code) => process.exit(code))
