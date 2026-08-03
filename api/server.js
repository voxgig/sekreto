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

app.listen({ port: PORT, host: HOST }).then(
  () => console.log('sekreto-api: listening on http://' + HOST + ':' + PORT),
  (err) => {
    console.error('sekreto-api: ' + err.message)
    process.exit(1)
  },
)
