// A stand-in GCP for the integration test: the GCE metadata server's
// token endpoint plus Secret Manager's access endpoint, on one port.
//
//   metadata  GET /computeMetadata/v1/instance/service-accounts/default/token
//             (requires Metadata-Flavor: Google) -> {access_token}
//   secrets   GET /v1/projects/{project}/secrets/{id}/versions/latest:access
//             (requires the Bearer token above) -> {payload:{data:base64}}
//
// Both are Google's published protocols. The provider must fetch its
// token from the metadata endpoint first - the mock hands the token out
// nowhere else - so a passing run proves the whole on-platform auth path.
//
// Usage: node mockgcp.js <port> <project> <token> <name=value>...
//
// Secret ids are dotted names flattened with underscores: api.token is
// served as secret "api_token".

const http = require('node:http')

const port = parseInt(process.argv[2] || '8203', 10)
const project = process.argv[3] || 'proj1'
const token = process.argv[4] || 'gcp-access-token'

const secrets = {}
for (const pair of process.argv.slice(5)) {
  const eq = pair.indexOf('=')
  if (0 < eq) {
    secrets[pair.slice(0, eq).split('.').join('_')] = pair.slice(eq + 1)
  }
}

function send(res, code, body) {
  res.writeHead(code, { 'content-type': 'application/json' })
  res.end(JSON.stringify(body))
}

const server = http.createServer((req, res) => {
  const url = new URL(req.url, 'http://localhost')

  if ('/computeMetadata/v1/instance/service-accounts/default/token' === url.pathname) {
    if ('Google' !== req.headers['metadata-flavor']) {
      return send(res, 403, { error: 'missing Metadata-Flavor: Google' })
    }
    return send(res, 200, { access_token: token, expires_in: 3599, token_type: 'Bearer' })
  }

  if ('Bearer ' + token !== req.headers['authorization']) {
    return send(res, 401, { error: { code: 401, message: 'unauthenticated' } })
  }

  const match = url.pathname.match(/^\/v1\/projects\/([^/]+)\/secrets\/([^/]+)\/versions\/latest:access$/)
  if (match && project === match[1]) {
    const value = secrets[match[2]]
    if (undefined === value) {
      return send(res, 404, { error: { code: 404, message: 'not found' } })
    }
    return send(res, 200, {
      name: 'projects/' + project + '/secrets/' + match[2] + '/versions/1',
      payload: { data: Buffer.from(value, 'utf8').toString('base64') },
    })
  }

  return send(res, 404, { error: { code: 404, message: 'not found' } })
})

server.listen(port, '127.0.0.1', () =>
  console.log('mockgcp: listening on http://127.0.0.1:' + port),
)
