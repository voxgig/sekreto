// A tiny app that needs a secret.
//
// It asks sekreto for `api.token` and calls the token-protected API with
// it. Every port ships this same CLI, and test/integration.sh runs all of
// them against the same server from every secret source - which is
// what proves the library, rather than the spec alone.
//
// Usage: sekreto-cli <api-url> [--source <source>] [--store <name>]
//
// Sources: env dotenv file hashicorp boru boruwire awssecrets awsparams
//          gcpsecrets azuresecrets onepassword doppler infisical
//          secretspec chain
//
// Each source's configuration arrives in the environment variables its
// own ecosystem already uses (VAULT_*, AWS_*, OP_CONNECT_*, ...), listed
// in chainfor below.

const { Sekreto } = require('../src')

// THE FULL SET, passed to Sekreto. The CLI is asked for any provider
// kind on the command line, so it is the one consumer that legitimately
// wants all ten plugins; an app passes the one or two it configures.
//
// It must be passed as a VALUE. An earlier shape of this split
// registered kinds as a side effect of requiring them, and the canonical
// port's only import of the full set named a TYPE, which the compiler
// erased: every kind but env and memory failed as `unknown provider
// kind`, caught by the integration suite while `make test` stayed green.
// Handing the list to the constructor is what makes that impossible.
const { allplugins } = require('../plugins')

const LANG = 'javascript'

function chainfor(source) {
  const env = process.env

  const envspec = { kind: 'env', prefix: env.SEKRETO_PREFIX }
  const dotenvspec = { kind: 'dotenv', file: env.SEKRETO_DOTENV || '.env' }
  const filespec = { kind: 'file', dir: env.SEKRETO_FILEDIR || '/run/secrets' }

  const hashicorpspec = {
    kind: 'hashicorp',
    addr: env.VAULT_ADDR || '',
    token: env.VAULT_TOKEN || '',
    mount: env.VAULT_MOUNT,
    kv: env.VAULT_KV ? parseInt(env.VAULT_KV, 10) : undefined,
    vaultnamespace: env.VAULT_NAMESPACE,
    auth: env.VAULT_AUTH
      ? {
          method: env.VAULT_AUTH,
          role: env.VAULT_ROLE,
          jwtfile: env.VAULT_JWT_FILE,
          roleid: env.VAULT_ROLE_ID,
          secretid: env.VAULT_SECRET_ID,
        }
      : undefined,
  }

  const boruspec = {
    kind: 'boru',
    command: env.BORU_COMMAND || 'boru',
    namespace: env.BORU_NAMESPACE,
    home: env.BORU_HOME,
  }

  // The same vault over its wire protocol (`boru vault serve`) instead
  // of the CLI: an address plus a capability token from `vault grant`.
  const boruwirespec = {
    kind: 'boru',
    addr: env.BORU_ADDR || '',
    token: env.BORU_TOKEN || '',
    namespace: env.BORU_NAMESPACE,
  }

  const awssecretsspec = {
    kind: 'awssecrets',
    region: env.AWS_REGION,
    addr: env.AWS_ENDPOINT,
  }

  const awsparamsspec = {
    kind: 'awsparams',
    region: env.AWS_REGION,
    addr: env.AWS_ENDPOINT,
    prefix: env.AWS_PARAM_PREFIX,
  }

  const gcpspec = {
    kind: 'gcpsecrets',
    project: env.GCP_PROJECT,
    addr: env.GCP_ADDR,
    metadataaddr: env.GCP_METADATA_ADDR,
  }

  const azurespec = {
    kind: 'azuresecrets',
    vault: env.AZURE_VAULT,
    token: env.AZURE_TOKEN,
    tenant: env.AZURE_TENANT,
    clientid: env.AZURE_CLIENT_ID,
    clientsecret: env.AZURE_CLIENT_SECRET,
    loginaddr: env.AZURE_LOGIN_ADDR,
    imdsaddr: env.AZURE_IMDS_ADDR,
  }

  const onepasswordspec = {
    kind: 'onepassword',
    addr: env.OP_CONNECT_HOST,
    token: env.OP_CONNECT_TOKEN,
    vault: env.OP_VAULT,
  }

  const dopplerspec = {
    kind: 'doppler',
    token: env.DOPPLER_TOKEN,
    project: env.DOPPLER_PROJECT,
    config: env.DOPPLER_CONFIG,
    addr: env.DOPPLER_ADDR,
  }

  // SecretSpec's own environment variables where it has them, so a
  // shell already set up for secretspec needs nothing further.
  const secretspecspec = {
    kind: 'secretspec',
    command: env.SECRETSPEC_COMMAND || 'secretspec',
    file: env.SECRETSPEC_FILE,
    profile: env.SECRETSPEC_PROFILE,
    backend: env.SECRETSPEC_PROVIDER,
    reason: env.SECRETSPEC_REASON,
  }

  const infisicalspec = {
    kind: 'infisical',
    addr: env.INFISICAL_ADDR,
    token: env.INFISICAL_TOKEN,
    clientid: env.INFISICAL_CLIENT_ID,
    clientsecret: env.INFISICAL_CLIENT_SECRET,
    project: env.INFISICAL_PROJECT,
    environment: env.INFISICAL_ENV,
    path: env.INFISICAL_PATH,
  }

  const bysource = {
    env: [envspec],
    dotenv: [dotenvspec],
    file: [filespec],
    hashicorp: [hashicorpspec],
    boru: [boruspec],
    boruwire: [boruwirespec],
    awssecrets: [awssecretsspec],
    awsparams: [awsparamsspec],
    gcpsecrets: [gcpspec],
    azuresecrets: [azurespec],
    onepassword: [onepasswordspec],
    doppler: [dopplerspec],
    infisical: [infisicalspec],
    secretspec: [secretspecspec],
  }

  const found = bysource[source]
  if (undefined !== found) {
    return found
  }

  // The default: the chain an app would actually ship with - local
  // overrides first, shared vaults last.
  return [envspec, dotenvspec, hashicorpspec, boruspec]
}

async function main() {
  const args = process.argv.slice(2)
  const url = args[0] || 'http://127.0.0.1:8099/whoami'

  const flag = args.indexOf('--source')
  const source = -1 === flag ? 'chain' : args[flag + 1]

  // --store names a store outright: the secret must come from that one,
  // not from whichever provider happens to answer first.
  const storeflag = args.indexOf('--store')
  const store = -1 === storeflag ? '' : args[storeflag + 1]

  const secrets = new Sekreto({ plugins: allplugins, providers: chainfor(source) })

  let token
  try {
    token = store ? await secrets.getfrom(store, 'api.token') : await secrets.get('api.token')
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

  console.log(JSON.stringify({ ok: true, lang: LANG, source, store, caller: body.caller }))

  return 0
}

main().then((code) => process.exit(code))
