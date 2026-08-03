// A stand-in AWS endpoint for the integration test: Secrets Manager and
// SSM Parameter Store, dispatched by X-Amz-Target the way AWS's JSON-1.1
// protocol really works.
//
// The point of this mock is the signature. It re-derives the SigV4
// signature of every request from scratch - same canonical request, same
// key derivation - and refuses anything that does not match. A port
// whose signing is wrong in any byte fails here exactly as it would
// against real AWS, but with a readable error instead of a 403 from
// Virginia.
//
//   Secrets Manager  secretsmanager.GetSecretValue {SecretId}
//                    -> {SecretString} (a JSON map of fields)
//   Parameter Store  AmazonSSM.GetParameter {Name}
//                    -> {Parameter:{Value}}
//
// Usage: node mockaws.js <port> <keyid> <secretkey> <name=value>...
//
// Secrets arrive as dotted names. `api.token=s3cr3t` is served both as
// Secrets Manager secret "api" (field "token" of its JSON) and as SSM
// parameter "/api/token".

const http = require('node:http')
const { createHash, createHmac } = require('node:crypto')

const port = parseInt(process.argv[2] || '8202', 10)
const keyid = process.argv[3] || 'AKIDEXAMPLE'
const secretkey = process.argv[4] || 'wJalrXUtnFEMI/K7MDENG+bPxRfiCYEXAMPLEKEY'

const secrets = {}
for (const pair of process.argv.slice(5)) {
  const eq = pair.indexOf('=')
  if (0 < eq) {
    secrets[pair.slice(0, eq)] = pair.slice(eq + 1)
  }
}

function vaultref(name) {
  const parts = name.split('.')
  if (1 === parts.length) {
    return { path: parts[0], field: 'value' }
  }
  return { path: parts.slice(0, -1).join('/'), field: parts[parts.length - 1] }
}

function sha256hex(text) {
  return createHash('sha256').update(text, 'utf8').digest('hex')
}

function hmac(key, text) {
  return createHmac('sha256', key).update(text, 'utf8').digest()
}

// Recompute the signature of a received request, from the pieces the
// Authorization header says were signed.
function verify(req, body) {
  const auth = req.headers['authorization'] || ''
  const match = auth.match(
    /^AWS4-HMAC-SHA256 Credential=([^/]+)\/(\d{8})\/([^/]+)\/([^/]+)\/aws4_request, SignedHeaders=([^,]+), Signature=([0-9a-f]{64})$/,
  )
  if (!match) {
    return 'malformed authorization header'
  }

  const [, gotkeyid, date, region, service, signedheaders, signature] = match

  if (keyid !== gotkeyid) {
    return 'unknown key id'
  }

  const datetime = req.headers['x-amz-date'] || ''
  if (date !== datetime.slice(0, 8)) {
    return 'x-amz-date does not match the credential scope'
  }

  const names = signedheaders.split(';')
  const canonicalheaders = names
    .map((name) => name + ':' + String(req.headers[name] || '').trim() + '\n')
    .join('')

  const url = new URL(req.url, 'http://localhost')

  const canonicalrequest = [
    req.method,
    url.pathname || '/',
    url.search.replace(/^\?/, ''),
    canonicalheaders,
    signedheaders,
    sha256hex(body),
  ].join('\n')

  const scope = date + '/' + region + '/' + service + '/aws4_request'
  const stringtosign = [
    'AWS4-HMAC-SHA256',
    datetime,
    scope,
    sha256hex(canonicalrequest),
  ].join('\n')

  const kdate = hmac('AWS4' + secretkey, date)
  const kregion = hmac(kdate, region)
  const kservice = hmac(kregion, service)
  const ksigning = hmac(kservice, 'aws4_request')
  const want = createHmac('sha256', ksigning).update(stringtosign, 'utf8').digest('hex')

  if (want !== signature) {
    return 'signature mismatch'
  }

  return undefined
}

function send(res, code, body) {
  res.writeHead(code, { 'content-type': 'application/x-amz-json-1.1' })
  res.end(JSON.stringify(body))
}

const server = http.createServer((req, res) => {
  let body = ''
  req.on('data', (chunk) => (body += chunk))
  req.on('end', () => {
    const why = verify(req, body)
    if (undefined !== why) {
      return send(res, 403, { __type: 'InvalidSignatureException', message: why })
    }

    let payload = {}
    try {
      payload = JSON.parse(body)
    } catch (err) {
      return send(res, 400, { __type: 'SerializationException' })
    }

    const target = req.headers['x-amz-target'] || ''

    if ('secretsmanager.GetSecretValue' === target) {
      const fields = {}
      let found = false
      for (const name of Object.keys(secrets)) {
        const ref = vaultref(name)
        if (ref.path === payload.SecretId) {
          fields[ref.field] = secrets[name]
          found = true
        }
      }
      if (!found) {
        return send(res, 400, {
          __type: 'ResourceNotFoundException',
          message: 'Secrets Manager can not find the specified secret.',
        })
      }
      return send(res, 200, {
        Name: payload.SecretId,
        SecretString: JSON.stringify(fields),
      })
    }

    if ('AmazonSSM.GetParameter' === target) {
      for (const name of Object.keys(secrets)) {
        if ('/' + name.split('.').join('/') === payload.Name) {
          return send(res, 200, {
            Parameter: { Name: payload.Name, Value: secrets[name], Type: 'SecureString' },
          })
        }
      }
      return send(res, 400, { __type: 'ParameterNotFound' })
    }

    return send(res, 400, { __type: 'UnknownOperationException', message: target })
  })
})

server.listen(port, '127.0.0.1', () =>
  console.log('mockaws: listening on http://127.0.0.1:' + port),
)
