// AWS Signature Version 4, hand-rolled.
//
// The AWS providers need exactly one thing from the AWS SDK - request
// signing - and taking the SDK for it would break the no-dependency rule
// that keeps the ports honest. SigV4 is a stable, published algorithm built
// from HMAC-SHA256, which `crypto.dart` supplies.
//
// `sigv4` is pure: the caller passes the timestamp, so the same input
// yields the same signature everywhere. That is what lets the shared spec
// carry known-answer cases that all ports must reproduce bit-for-bit, and
// lets the integration mock recompute the signature server-side.
//
// A port of typescript/plugins/sigv4.ts, which is canonical.

import 'dart:convert';

import 'crypto.dart';

/// One request to sign - the same declarative shape the shared spec uses.
/// `datetime` is `YYYYMMDDTHHMMSSZ`, and it is the caller's, so that signing
/// is a pure function of its input.
class Signing {
  final String method;
  final String url;
  final String service;
  final String region;
  final String keyid;
  final String secret;
  final String datetime;
  final Map<String, String> headers;
  final String body;
  final String? session;

  const Signing({
    required this.method,
    required this.url,
    required this.service,
    required this.region,
    required this.keyid,
    required this.secret,
    required this.datetime,
    this.headers = const {},
    this.body = '',
    this.session,
  });
}

/// The index of the first character of [chars], or -1.
int stopat(String text, String chars) {
  for (var at = 0; at < text.length; at++) {
    if (chars.contains(text[at])) {
      return at;
    }
  }
  return -1;
}

/// The three pieces of a URL that signing needs, split by hand.
///
/// Not `Uri.parse`: the `host` header AWS signs is the WHATWG one - the
/// hostname lowercased, userinfo stripped, and the port present only when
/// it is not the scheme's default - and no platform URL type answers
/// exactly that. A signature over a host the service computes differently
/// is refused with no useful diagnostic.
class _Parts {
  final String host;
  final String path;
  final String query;
  const _Parts(this.host, this.path, this.query);
}

_Parts _split(String url) {
  final mark = url.indexOf('://');
  final scheme = -1 == mark ? '' : url.substring(0, mark).toLowerCase();
  final rest = -1 == mark ? url : url.substring(mark + 3);

  final stop = stopat(rest, '/?#');
  var authority = -1 == stop ? rest : rest.substring(0, stop);
  var tail = -1 == stop ? '' : rest.substring(stop);

  // Userinfo is not part of the signed host.
  final at = authority.lastIndexOf('@');
  if (-1 != at) {
    authority = authority.substring(at + 1);
  }

  String host;
  var port = '';

  if (authority.startsWith('[')) {
    // An IPv6 literal keeps its brackets and carries colons of its own.
    final close = authority.indexOf(']');
    if (-1 == close) {
      host = authority;
    } else {
      host = authority.substring(0, close + 1);
      final after = authority.substring(close + 1);
      if (after.startsWith(':')) {
        port = after.substring(1);
      }
    }
  } else {
    final colon = authority.lastIndexOf(':');
    if (-1 == colon) {
      host = authority;
    } else {
      host = authority.substring(0, colon);
      port = authority.substring(colon + 1);
    }
  }

  host = host.toLowerCase();

  // A default port is implicit, and signing it would not match what the
  // service reconstructs from the request line.
  if (port.isNotEmpty &&
      !('https' == scheme && '443' == port) &&
      !('http' == scheme && '80' == port)) {
    host = '$host:$port';
  }

  final hash = tail.indexOf('#');
  if (-1 != hash) {
    tail = tail.substring(0, hash);
  }

  final mark2 = tail.indexOf('?');
  final path = -1 == mark2 ? tail : tail.substring(0, mark2);
  final query = -1 == mark2 ? '' : tail.substring(mark2 + 1);

  return _Parts(host, path.isEmpty ? '/' : path, query);
}

/// RFC 3986 escaping, which is stricter than the usual URL encoder: AWS
/// wants everything but unreserved characters escaped, with uppercase hex.
String uriescape(String text) {
  final out = StringBuffer();

  for (final byte in utf8.encode(text)) {
    final ch = byte & 0xff;
    final unreserved = (0x41 <= ch && 0x5a >= ch) ||
        (0x61 <= ch && 0x7a >= ch) ||
        (0x30 <= ch && 0x39 >= ch) ||
        0x2d == ch ||
        0x5f == ch ||
        0x2e == ch ||
        0x7e == ch;

    if (unreserved) {
      out.writeCharCode(ch);
    } else {
      out.write('%');
      out.write(ch.toRadixString(16).toUpperCase().padLeft(2, '0'));
    }
  }

  return out.toString();
}

/// Two hex digits as a byte, or nothing.
int? _hexbyte(String text) {
  var value = 0;

  for (final unit in text.codeUnits) {
    final digit = _HEX.indexOf(String.fromCharCode(unit).toLowerCase());
    if (-1 == digit) {
      return null;
    }
    value = value * 16 + digit;
  }

  return value;
}

const String _HEX = '0123456789abcdef';

/// Percent-decode, and nothing else: `+` stays `+`, as on the wire.
String uridecode(String text) {
  final out = <int>[];
  var index = 0;

  while (index < text.length) {
    var taken = false;

    if ('%' == text[index] && index + 2 < text.length) {
      final code = _hexbyte(text.substring(index + 1, index + 3));
      if (null != code) {
        out.add(code);
        index += 3;
        taken = true;
      }
    }

    if (!taken) {
      // A stray % is kept as-is, the way a browser would.
      out.addAll(utf8.encode(text[index]));
      index += 1;
    }
  }

  return utf8.decode(out, allowMalformed: true);
}

/// The canonical query string: each pair RFC 3986-escaped, sorted by escaped
/// key then escaped value.
String canonicalquery(String query) {
  if (query.isEmpty) {
    return '';
  }

  final pairs = <List<String>>[];

  for (final pair in query.split('&')) {
    final eq = pair.indexOf('=');
    final key = -1 == eq ? pair : pair.substring(0, eq);
    final value = -1 == eq ? '' : pair.substring(eq + 1);
    pairs.add([uriescape(uridecode(key)), uriescape(uridecode(value))]);
  }

  pairs.sort((left, right) {
    final bykey = left[0].compareTo(right[0]);
    return 0 != bykey ? bykey : left[1].compareTo(right[1]);
  });

  return pairs.map((pair) => '${pair[0]}=${pair[1]}').join('&');
}

/// Sign one request. Returns the headers to attach: authorization,
/// x-amz-date, and x-amz-security-token when a session token was given, in
/// that order - the spec compares the result as a JSON object, and callers
/// print it field by field.
Map<String, String> sigv4(Signing input) {
  final parts = _split(input.url);
  final date = input.datetime.substring(0, 8);
  final session =
      (null == input.session || input.session!.isEmpty) ? null : input.session;

  // Every header that will be signed: the caller's extras, plus host and
  // x-amz-date (and the session token when present), lower-cased and
  // trimmed the way the canonical form requires.
  //
  // Canonical header values are trimmed AND internally collapsed - AWS
  // folds every run of whitespace, tabs included, to one space before
  // signing, so a header like "a  b" must sign as "a b" or the service
  // refuses it.
  final headers = <String, String>{};

  input.headers.forEach((key, value) {
    headers[key.toLowerCase()] = value.trim().replaceAll(RegExp(r'\s+'), ' ');
  });

  // Inserted after the caller's, so they win.
  headers['host'] = parts.host;
  headers['x-amz-date'] = input.datetime;
  if (null != session) {
    headers['x-amz-security-token'] = session;
  }

  final names = headers.keys.toList()..sort();
  final canonicalheaders =
      names.map((name) => '$name:${headers[name]}\n').join();
  final signedheaders = names.join(';');

  final canonicalrequest = [
    input.method.toUpperCase(),
    parts.path,
    canonicalquery(parts.query),
    canonicalheaders,
    signedheaders,
    sha256hex(input.body),
  ].join('\n');

  final scope = '$date/${input.region}/${input.service}/aws4_request';

  final stringtosign = [
    'AWS4-HMAC-SHA256',
    input.datetime,
    scope,
    sha256hex(canonicalrequest),
  ].join('\n');

  final kdate = hmacsha256(utf8.encode('AWS4${input.secret}'), utf8.encode(date));
  final kregion = hmacsha256(kdate, utf8.encode(input.region));
  final kservice = hmacsha256(kregion, utf8.encode(input.service));
  final ksigning = hmacsha256(kservice, utf8.encode('aws4_request'));
  final signature = hex(hmacsha256(ksigning, utf8.encode(stringtosign)));

  final out = <String, String>{};

  out['authorization'] = 'AWS4-HMAC-SHA256 Credential=${input.keyid}/$scope'
      ', SignedHeaders=$signedheaders'
      ', Signature=$signature';
  out['x-amz-date'] = input.datetime;

  if (null != session) {
    out['x-amz-security-token'] = session;
  }

  return out;
}
