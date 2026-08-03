// AWS Signature Version 4, hand-rolled.
//
// The AWS providers need exactly one thing from the AWS SDK - request
// signing - and taking the SDK for it would break the no-dependency rule
// that keeps ten ports honest. SigV4 is a stable, published algorithm
// built from HMAC-SHA256, which node's own crypto already has.
//
// `sigv4` is pure: the caller passes the timestamp, so the same input
// yields the same signature everywhere. That is what lets the shared spec
// carry known-answer cases that all ten ports must reproduce bit-for-bit,
// and lets the integration mock recompute the signature server-side.
//
// A port of typescript/src/Sigv4.ts, which is canonical.

const { createHash, createHmac } = require('node:crypto')

function sha256hex(text) {
  return createHash('sha256').update(text, 'utf8').digest('hex')
}

function hmac(key, text) {
  return createHmac('sha256', key).update(text, 'utf8').digest()
}

/** RFC 3986 escaping, which is stricter than encodeURIComponent: AWS
 * wants `!`, `'`, `(`, `)` and `*` escaped too. */
function uriescape(text) {
  return encodeURIComponent(text).replace(
    /[!'()*]/g,
    (ch) => '%' + ch.charCodeAt(0).toString(16).toUpperCase(),
  )
}

/** The canonical query string: each pair RFC 3986-escaped, sorted by
 * escaped key then escaped value. */
function canonicalquery(query) {
  if ('' === query) {
    return ''
  }

  const pairs = query.split('&').map((pair) => {
    const eq = pair.indexOf('=')
    const key = -1 === eq ? pair : pair.slice(0, eq)
    const value = -1 === eq ? '' : pair.slice(eq + 1)
    return [uriescape(decodeURIComponent(key)), uriescape(decodeURIComponent(value))]
  })

  pairs.sort((left, right) => {
    if (left[0] !== right[0]) {
      return left[0] < right[0] ? -1 : 1
    }
    return left[1] < right[1] ? -1 : left[1] > right[1] ? 1 : 0
  })

  return pairs.map((pair) => pair[0] + '=' + pair[1]).join('&')
}

/** Sign one request. Returns the headers to attach: authorization,
 * x-amz-date, and x-amz-security-token when a session token was given. */
function sigv4(input) {
  const url = new URL(input.url)

  const date = input.datetime.slice(0, 8)
  const body = input.body || ''

  // Every header that will be signed: the caller's extras, plus host and
  // x-amz-date (and the session token when present), lower-cased and
  // trimmed the way the canonical form requires.
  // Canonical header values are trimmed AND internally collapsed -
  // AWS folds sequential whitespace to one space before signing, so a
  // header like "a  b" must sign as "a b" or the service refuses it.
  const headers = {}
  for (const [key, value] of Object.entries(input.headers || {})) {
    headers[key.toLowerCase()] = String(value).trim().replace(/\s+/g, ' ')
  }
  headers['host'] = url.host
  headers['x-amz-date'] = input.datetime
  if (input.session) {
    headers['x-amz-security-token'] = input.session
  }

  const names = Object.keys(headers).sort()
  const canonicalheaders = names.map((name) => name + ':' + headers[name] + '\n').join('')
  const signedheaders = names.join(';')

  const canonicalrequest = [
    input.method.toUpperCase(),
    url.pathname || '/',
    canonicalquery(url.search.replace(/^\?/, '')),
    canonicalheaders,
    signedheaders,
    sha256hex(body),
  ].join('\n')

  const scope = date + '/' + input.region + '/' + input.service + '/aws4_request'

  const stringtosign = [
    'AWS4-HMAC-SHA256',
    input.datetime,
    scope,
    sha256hex(canonicalrequest),
  ].join('\n')

  const kdate = hmac('AWS4' + input.secret, date)
  const kregion = hmac(kdate, input.region)
  const kservice = hmac(kregion, input.service)
  const ksigning = hmac(kservice, 'aws4_request')
  const signature = createHmac('sha256', ksigning).update(stringtosign, 'utf8').digest('hex')

  const out = {
    authorization:
      'AWS4-HMAC-SHA256 Credential=' +
      input.keyid +
      '/' +
      scope +
      ', SignedHeaders=' +
      signedheaders +
      ', Signature=' +
      signature,
    'x-amz-date': input.datetime,
  }

  if (input.session) {
    out['x-amz-security-token'] = input.session
  }

  return out
}

module.exports = { sigv4 }
