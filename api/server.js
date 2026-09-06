// The API that sekreto exists to reach.
//
// One rule: every request must carry `Authorization: Bearer <token>`, and
// the token must match the one the server was started with. A CLI in any
// language passes this only if sekreto really fetched the secret.
//
// Usage: API_TOKEN=... PORT=8099 node server.js

const Fastify = require('fastify')

const TOKEN = process.env.API_TOKEN || 'no-token-configured'
const PORT = parseInt(process.env.PORT || '8099', 10)
const HOST = process.env.HOST || '127.0.0.1'

const app = Fastify({ logger: false })

// Authentication is deliberately the only middleware: this server is a
// test of the caller's secret handling, not of anything else.
app.addHook('onRequest', async (req, reply) => {
  if ('/health' === req.url) {
    return
  }

  const header = req.headers.authorization || ''
  const match = header.match(/^Bearer (.+)$/)

  if (!match) {
    return reply.code(401).send({ ok: false, why: 'missing bearer token' })
  }

  if (match[1] !== TOKEN) {
    return reply.code(403).send({ ok: false, why: 'bad token' })
  }
})

app.get('/health', async () => ({ ok: true }))

app.get('/whoami', async (req) => ({
  ok: true,
  caller: req.headers['x-sekreto-lang'] || 'unknown',
  when: 'now',
}))

// The same answer, but with a caller that exercises every escaper: the
// three characters Go's encoding/json escapes by default, the slash PHP
// escapes, a control character with no short escape, and non-ASCII in the
// BMP and beyond it. Built from code points so this file stays ASCII and
// the intent of each character is legible.
//
// A port's JSON writer and its stdout encoding both have to be right for
// the line to come back byte-identical, and neither is reachable from the
// conformance corpus: the spec has no entry whose subject is the writer,
// and a chain never prints. test/integration.sh compares the whole line
// across every port, which is what makes this a cross-port contract
// rather than 23 separate opinions.
const ESCAPES = [
  0x61, 0x3c, 0x62, 0x3e, 0x63, 0x26,  // a < b > c &
  0x64, 0x22, 0x65, 0x5c, 0x66,        // d " e backslash f
  0x2f, 0x67,                          // / g
  0x1f, 0x68,                          // U+001F h
  0xe9, 0x69,                          // U+00E9 i
  0x2603, 0x6a,                        // U+2603 j
  0x1f600, 0x6b,                       // U+1F600 k
].map((code) => String.fromCodePoint(code)).join('')

app.get('/whoami-escapes', async () => ({
  ok: true,
  caller: ESCAPES,
  when: 'now',
}))

app.listen({ port: PORT, host: HOST }).then(
  () => console.log('sekreto-api: listening on http://' + HOST + ':' + PORT),
  (err) => {
    console.error('sekreto-api: ' + err.message)
    process.exit(1)
  },
)
