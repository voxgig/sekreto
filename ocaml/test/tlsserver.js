// A HashiCorp-shaped KV v2 endpoint over real TLS, and an SNI recorder.
//
// It exists to prove one thing the rest of the repository cannot: that this
// port's OpenSSL binding verifies what it is supposed to verify. Nothing in
// `make test` or `make integration` speaks TLS at all, and `make realstores`
// has no negative hostname case.
//
// Usage: node tlsserver.js <port> <cert> <key> <snilog>

const https = require('node:https')
const fs = require('node:fs')
const tls = require('node:tls')

const [, , port, cert, key, snifile] = process.argv
const seen = []

fs.writeFileSync(snifile, JSON.stringify(seen))

const secure = () =>
  tls.createSecureContext({ cert: fs.readFileSync(cert), key: fs.readFileSync(key) })

https
  .createServer(
    {
      cert: fs.readFileSync(cert),
      key: fs.readFileSync(key),
      // Only called when the client actually sent the extension, which is
      // what makes this a test of obligation 3 in both directions.
      SNICallback: (servername, cb) => {
        seen.push(String(servername))
        fs.writeFileSync(snifile, JSON.stringify(seen))
        cb(null, secure())
      },
    },
    (req, res) => {
      res.setHeader('content-type', 'application/json')
      if (req.url.startsWith('/v1/secret/data/api')) {
        return res.end(JSON.stringify({ data: { data: { token: 'over-real-tls' } } }))
      }
      res.statusCode = 404
      res.end('{"errors":[]}')
    }
  )
  .listen(parseInt(port, 10), '127.0.0.1')
