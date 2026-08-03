// A stand-in 1Password Connect server for the integration test.
//
//   GET /v1/vaults                       -> [{id,name}]
//   GET /v1/vaults/{id}/items?filter=... -> [{id,title}]
//   GET /v1/vaults/{id}/items/{itemid}   -> {fields:[{purpose,value}]}
//
// That is the Connect REST API 1Password publishes for exactly this kind
// of machine access. Every request needs the Connect bearer token.
//
// Usage: node mockonepassword.js <port> <token> <vaultname> <name=value>...
//
// Item titles are the dotted names themselves; the value is the field
// with purpose PASSWORD, which is where the provider looks first.

const http = require('node:http')

const port = parseInt(process.argv[2] || '8205', 10)
const token = process.argv[3] || 'op-connect-token'
const vaultname = process.argv[4] || 'dev'
const vaultid = 'v-' + vaultname

const secrets = {}
for (const pair of process.argv.slice(5)) {
  const eq = pair.indexOf('=')
  if (0 < eq) {
    secrets[pair.slice(0, eq)] = pair.slice(eq + 1)
  }
}

const titles = Object.keys(secrets)

function send(res, code, body) {
  res.writeHead(code, { 'content-type': 'application/json' })
  res.end(JSON.stringify(body))
}

const server = http.createServer((req, res) => {
  if ('Bearer ' + token !== req.headers['authorization']) {
    return send(res, 401, { status: 401, message: 'Invalid bearer token' })
  }

  const url = new URL(req.url, 'http://localhost')

  if ('/v1/vaults' === url.pathname) {
    return send(res, 200, [{ id: vaultid, name: vaultname }])
  }

  if ('/v1/vaults/' + vaultid + '/items' === url.pathname) {
    const filter = url.searchParams.get('filter') || ''
    const match = filter.match(/^title eq "(.+)"$/)
    const out = []
    for (const title of titles) {
      if (!match || match[1] === title) {
        out.push({ id: 'i-' + titles.indexOf(title), title, vault: { id: vaultid } })
      }
    }
    return send(res, 200, out)
  }

  const item = url.pathname.match(/^\/v1\/vaults\/([^/]+)\/items\/i-(\d+)$/)
  if (item && vaultid === item[1]) {
    const title = titles[parseInt(item[2], 10)]
    if (undefined === title) {
      return send(res, 404, { status: 404, message: 'item not found' })
    }
    return send(res, 200, {
      id: 'i-' + item[2],
      title,
      vault: { id: vaultid },
      fields: [
        { id: 'username', purpose: 'USERNAME', label: 'username', value: 'svc' },
        { id: 'password', purpose: 'PASSWORD', label: 'password', value: secrets[title] },
      ],
    })
  }

  return send(res, 404, { status: 404, message: 'not found' })
})

server.listen(port, '127.0.0.1', () =>
  console.log('mockonepassword: listening on http://127.0.0.1:' + port),
)
