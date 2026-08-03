// A stand-in Doppler API for the integration test.
//
//   GET /v3/configs/config/secrets/download?format=json
//   -> {"API_TOKEN":"...", ...}
//
// Doppler's own bulk endpoint, the one the provider downloads a config
// through. The service token rides as a Bearer credential.
//
// Usage: node mockdoppler.js <port> <token> <name=value>...
//
// Names arrive dotted and are served under their environment-style keys:
// api.token becomes API_TOKEN, which is Doppler's own convention.

const http = require('node:http')

const port = parseInt(process.argv[2] || '8206', 10)
const token = process.argv[3] || 'dp.st.token'

const values = {}
for (const pair of process.argv.slice(4)) {
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
  if ('Bearer ' + token !== req.headers['authorization']) {
    return send(res, 401, { messages: ['Invalid Auth token'], success: false })
  }

  const url = new URL(req.url, 'http://localhost')

  if (
    '/v3/configs/config/secrets/download' === url.pathname &&
    'json' === url.searchParams.get('format')
  ) {
    return send(res, 200, values)
  }

  return send(res, 404, { messages: ['not found'], success: false })
})

server.listen(port, '127.0.0.1', () =>
  console.log('mockdoppler: listening on http://127.0.0.1:' + port),
)
