// A stand-in Azure for the integration test: the Entra client-credential
// token endpoint, the IMDS managed-identity endpoint, and Key Vault's
// secrets endpoint, on one port - the provider is pointed at it for all
// three roles.
//
//   login  POST /{tenant}/oauth2/v2.0/token       (form; client id+secret)
//   imds   GET  /metadata/identity/oauth2/token   (requires Metadata: true)
//   vault  GET  /secrets/{name}?api-version=...   (requires the Bearer token)
//
// All three are Microsoft's published protocols.
//
// Usage: node mockazure.js <port> <tenant> <clientid> <clientsecret>
//          <token> <name=value>...
//
// Secret names are dotted names flattened with dashes: api.token is
// served as secret "api-token".

const http = require('node:http')

const port = parseInt(process.argv[2] || '8204', 10)
const tenant = process.argv[3] || 'tenant1'
const clientid = process.argv[4] || 'client1'
const clientsecret = process.argv[5] || 'clientsecret1'
const token = process.argv[6] || 'azure-access-token'

const secrets = {}
for (const pair of process.argv.slice(7)) {
  const eq = pair.indexOf('=')
  if (0 < eq) {
    secrets[pair.slice(0, eq).split('.').join('-')] = pair.slice(eq + 1)
  }
}

function send(res, code, body) {
  res.writeHead(code, { 'content-type': 'application/json' })
  res.end(JSON.stringify(body))
}

const server = http.createServer((req, res) => {
  const url = new URL(req.url, 'http://localhost')

  if ('/' + tenant + '/oauth2/v2.0/token' === url.pathname && 'POST' === req.method) {
    let body = ''
    req.on('data', (chunk) => (body += chunk))
    req.on('end', () => {
      const form = new URLSearchParams(body)
      if (
        'client_credentials' === form.get('grant_type') &&
        clientid === form.get('client_id') &&
        clientsecret === form.get('client_secret')
      ) {
        return send(res, 200, { access_token: token, token_type: 'Bearer', expires_in: 3599 })
      }
      return send(res, 401, { error: 'invalid_client' })
    })
    return
  }

  if ('/metadata/identity/oauth2/token' === url.pathname) {
    if ('true' !== req.headers['metadata']) {
      return send(res, 400, { error: 'missing Metadata: true' })
    }
    return send(res, 200, { access_token: token, token_type: 'Bearer', expires_in: '3599' })
  }

  if ('Bearer ' + token !== req.headers['authorization']) {
    return send(res, 401, { error: { code: 'Unauthorized' } })
  }

  const match = url.pathname.match(/^\/secrets\/([^/]+)$/)
  if (match && url.searchParams.get('api-version')) {
    const value = secrets[match[1]]
    if (undefined === value) {
      return send(res, 404, { error: { code: 'SecretNotFound' } })
    }
    return send(res, 200, {
      value,
      id: 'http://127.0.0.1:' + port + '/secrets/' + match[1] + '/1',
    })
  }

  return send(res, 404, { error: { code: 'NotFound' } })
})

server.listen(port, '127.0.0.1', () =>
  console.log('mockazure: listening on http://127.0.0.1:' + port),
)
