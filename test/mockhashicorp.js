// A stand-in HashiCorp Vault for the integration test.
//
//   KV v2   GET  /v1/{mount}/data/{path}        X-Vault-Token
//           -> {"data":{"data":{field:value}}}
//   KV v1   GET  /v1/{mount}/{path}             X-Vault-Token
//           -> {"data":{field:value}}
//   auth    POST /v1/auth/kubernetes/login      {"role","jwt"}
//           POST /v1/auth/approle/login         {"role_id","secret_id"}
//           -> {"auth":{"client_token":...}}
//
// That is HashiCorp's published wire protocol, so this mock is a genuine
// stand-in: the provider talks to it exactly as it would to a real Vault.
//
// With --namespace=<ns>, every request (logins included) must carry
// X-Vault-Namespace: <ns> - which is how a port's namespace support is
// proven end to end, the way Vault Enterprise would demand it.
//
// There is deliberately no boru mock here. boru's provision protocol
// (`boru vault serve`) is served by the real binary in the integration
// run; imitating it would test the imitation, not the integration.
//
// Usage: node mockhashicorp.js <port> <token>
//          [--namespace=NS] [--jwt=JWT --role=ROLE]
//          [--roleid=ID --secretid=ID] <name=value>...

const http = require('node:http')

const args = process.argv.slice(2)
const flags = {}
const rest = []

for (const arg of args) {
  const match = arg.match(/^--([a-z]+)=(.*)$/)
  if (match) {
    flags[match[1]] = match[2]
  } else {
    rest.push(arg)
  }
}

const port = parseInt(rest[0] || '8200', 10)
const token = rest[1] || 'vault-root'

// Secrets arrive as dotted names, exactly as an app asks for them:
//   api.token=s3cr3t  ->  path "api", field "token"
const secrets = {}
for (const pair of rest.slice(2)) {
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

// Every field stored under one path, for the KV shapes.
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

function readbody(req) {
  return new Promise((resolve) => {
    let text = ''
    req.on('data', (chunk) => (text += chunk))
    req.on('end', () => resolve(text))
  })
}

const server = http.createServer(async (req, res) => {
  // Vault Enterprise scopes everything by namespace; when this mock is
  // told to demand one, a request without it is a hard failure - which
  // is exactly how a port that forgets the header gets caught.
  if (flags.namespace && flags.namespace !== req.headers['x-vault-namespace']) {
    return send(res, 400, { errors: ['missing or wrong X-Vault-Namespace'] })
  }

  const login = req.url.match(/^\/v1\/auth\/(kubernetes|approle)\/login$/)
  if (login && 'POST' === req.method) {
    let body = {}
    try {
      body = JSON.parse(await readbody(req))
    } catch (err) {
      return send(res, 400, { errors: ['bad json'] })
    }

    if ('kubernetes' === login[1]) {
      if (flags.jwt && flags.jwt === body.jwt && (!flags.role || flags.role === body.role)) {
        return send(res, 200, { auth: { client_token: token } })
      }
    } else {
      if (flags.roleid === body.role_id && flags.secretid === body.secret_id) {
        return send(res, 200, { auth: { client_token: token } })
      }
    }

    return send(res, 403, { errors: ['login denied'] })
  }

  if (token !== req.headers['x-vault-token']) {
    return send(res, 403, { errors: ['permission denied'] })
  }

  const kv2 = req.url.match(/^\/v1\/([^/]+)\/data\/([^?]+)/)
  if (kv2) {
    const data = pathdata(kv2[2])
    if (undefined === data) {
      return send(res, 404, { errors: [] })
    }
    return send(res, 200, { data: { data, metadata: { version: 1 } } })
  }

  const kv1 = req.url.match(/^\/v1\/([^/]+)\/([^?]+)/)
  if (kv1) {
    const data = pathdata(kv1[2])
    if (undefined === data) {
      return send(res, 404, { errors: [] })
    }
    return send(res, 200, { data })
  }

  return send(res, 404, { errors: [] })
})

server.listen(port, '127.0.0.1', () =>
  console.log('mockhashicorp: listening on http://127.0.0.1:' + port),
)
