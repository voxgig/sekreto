// A stand-in Infisical API for the integration test.
//
//   login   POST /api/v1/auth/universal-auth/login {clientId,clientSecret}
//           -> {accessToken}
//   secret  GET  /api/v3/secrets/raw/{key}?workspaceId=&environment=&secretPath=
//           (requires the Bearer token above) -> {secret:{secretValue}}
//
// Both are Infisical's published API. The access token is handed out only
// by the login endpoint, so a passing run proves the machine-identity
// path end to end.
//
// Usage: node mockinfisical.js <port> <clientid> <clientsecret>
//          <workspace> <environment> <name=value>...
//
// Keys are environment-style (api.token -> API_TOKEN), Infisical's own
// convention.

const http = require('node:http')

const port = parseInt(process.argv[2] || '8207', 10)
const clientid = process.argv[3] || 'machine1'
const clientsecret = process.argv[4] || 'machinesecret1'
const workspace = process.argv[5] || 'w1'
const environment = process.argv[6] || 'prod'
const accesstoken = 'infisical-access-' + clientid

const values = {}
for (const pair of process.argv.slice(7)) {
  const eq = pair.indexOf('=')
  if (0 < eq) {
    values[pair.slice(0, eq).split('.').join('_').toUpperCase()] = pair.slice(eq + 1)
  }
}

function send(res, code, body) {
  res.writeHead(code, { 'content-type': 'application/json' })
  res.end(JSON.stringify(body))
}

const server = http.createServer((req, res) => {
  const url = new URL(req.url, 'http://localhost')

  if ('/api/v1/auth/universal-auth/login' === url.pathname && 'POST' === req.method) {
    let body = ''
    req.on('data', (chunk) => (body += chunk))
    req.on('end', () => {
      let payload = {}
      try {
        payload = JSON.parse(body)
      } catch (err) {
        return send(res, 400, { message: 'bad json' })
      }
      if (clientid === payload.clientId && clientsecret === payload.clientSecret) {
        return send(res, 200, { accessToken: accesstoken, expiresIn: 3600 })
      }
      return send(res, 401, { message: 'invalid credentials' })
    })
    return
  }

  if ('Bearer ' + accesstoken !== req.headers['authorization']) {
    return send(res, 401, { message: 'unauthorized' })
  }

  const match = url.pathname.match(/^\/api\/v3\/secrets\/raw\/([^/]+)$/)
  if (match) {
    if (
      workspace !== url.searchParams.get('workspaceId') ||
      environment !== url.searchParams.get('environment')
    ) {
      return send(res, 404, { message: 'no such workspace/environment' })
    }
    const value = values[match[1]]
    if (undefined === value) {
      return send(res, 404, { message: 'secret not found' })
    }
    return send(res, 200, {
      secret: { secretKey: match[1], secretValue: value },
    })
  }

  return send(res, 404, { message: 'not found' })
})

server.listen(port, '127.0.0.1', () =>
  console.log('mockinfisical: listening on http://127.0.0.1:' + port),
)
