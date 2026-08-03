// Stand-in vault servers for the integration test.
//
// Two protocols, one process:
//
//   HashiCorp Vault KV v2   GET /v1/{mount}/data/{path}   X-Vault-Token
//                           -> {"data":{"data":{field:value}}}
//
//   boru vault              GET /vault/{path}?field=...   X-Boru-Token
//                           -> {"ok":true,"value":"..."}
//
// These are the two shapes sekreto's providers speak. They are small on
// purpose: the point is to prove the providers talk the protocol, not to
// reimplement a vault.
//
// Usage: node mockvault.js <kind: vault|boru> <port> <token> <name=value>...

const http = require('node:http')

const kind = process.argv[2] || 'vault'
const port = parseInt(process.argv[3] || '8200', 10)
const token = process.argv[4] || 'vault-root'

// Secrets arrive as dotted names, exactly as an app asks for them:
//   api.token=s3cr3t  ->  path "api", field "token"
const secrets = {}
for (const pair of process.argv.slice(5)) {
  const eq = pair.indexOf('=')
  if (0 < eq) {
    secrets[pair.slice(0, eq)] = pair.slice(eq + 1)
  }
}

// The same name split sekreto's `vaultref` performs, so that the mock and
// the library agree without sharing code.
function vaultref(name) {
  const parts = name.split('.')
  if (1 === parts.length) {
    return { path: parts[0], field: 'value' }
  }
  return { path: parts.slice(0, -1).join('/'), field: parts[parts.length - 1] }
}

function lookup(path, field) {
  for (const name of Object.keys(secrets)) {
    const ref = vaultref(name)
    if (ref.path === path && ref.field === field) {
      return secrets[name]
    }
  }
  return undefined
}

// Every field stored under one path, for the KV v2 shape.
function pathdata(path) {
  const data = {}
  let found = false

  for (const name of Object.keys(secrets)) {
    const ref = vaultref(name)
    if (ref.path === path) {
      data[ref.field] = secrets[name]
      found = true
    }
  }

  return found ? data : undefined
}

function send(res, code, body) {
  const text = JSON.stringify(body)
  res.writeHead(code, { 'content-type': 'application/json' })
  res.end(text)
}

const server = http.createServer((req, res) => {
  const url = new URL(req.url, 'http://localhost')

  if ('vault' === kind) {
    if (token !== req.headers['x-vault-token']) {
      return send(res, 403, { errors: ['permission denied'] })
    }

    const match = url.pathname.match(/^\/v1\/([^/]+)\/data\/(.+)$/)
    if (!match) {
      return send(res, 404, { errors: [] })
    }

    const data = pathdata(match[2])
    if (undefined === data) {
      return send(res, 404, { errors: [] })
    }

    return send(res, 200, { data: { data, metadata: { version: 1 } } })
  }

  if (token !== req.headers['x-boru-token']) {
    return send(res, 403, { ok: false, why: 'bad token' })
  }

  const match = url.pathname.match(/^\/vault\/(.+)$/)
  if (!match) {
    return send(res, 404, { ok: false })
  }

  const value = lookup(match[1], url.searchParams.get('field') || 'value')
  if (undefined === value) {
    return send(res, 404, { ok: false })
  }

  return send(res, 200, { ok: true, value })
})

server.listen(port, '127.0.0.1', () =>
  console.log('mockvault(' + kind + '): listening on http://127.0.0.1:' + port),
)
