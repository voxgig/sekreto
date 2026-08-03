// A stand-in HashiCorp Vault for the integration test.
//
//   KV v2   GET /v1/{mount}/data/{path}   X-Vault-Token
//           -> {"data":{"data":{field:value}}}
//
// That is HashiCorp's published wire protocol, so this mock is a genuine
// stand-in: the provider talks to it exactly as it would to a real Vault.
//
// There is deliberately no boru mock here. boru has no read-a-secret wire
// protocol to imitate - its vault is read through the `boru` CLI - so the
// boru provider is tested against the real binary, or not at all.
//
// Usage: node mockhashicorp.js <port> <token> <name=value>...

const http = require('node:http')

const port = parseInt(process.argv[2] || '8200', 10)
const token = process.argv[3] || 'vault-root'

// Secrets arrive as dotted names, exactly as an app asks for them:
//   api.token=s3cr3t  ->  path "api", field "token"
const secrets = {}
for (const pair of process.argv.slice(4)) {
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
  if (token !== req.headers['x-vault-token']) {
    return send(res, 403, { errors: ['permission denied'] })
  }

  const match = req.url.match(/^\/v1\/([^/]+)\/data\/([^?]+)/)
  if (!match) {
    return send(res, 404, { errors: [] })
  }

  const data = pathdata(match[2])
  if (undefined === data) {
    return send(res, 404, { errors: [] })
  }

  return send(res, 200, { data: { data, metadata: { version: 1 } } })
})

server.listen(port, '127.0.0.1', () =>
  console.log('mockhashicorp: listening on http://127.0.0.1:' + port),
)
