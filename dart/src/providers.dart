// The providers a Sekreto chains together.
//
// A provider answers one question: "do you have this secret?" It returns
// the value, or null to mean "ask the next one". Nothing else about a
// provider is visible to the caller - which is the point: an app reads
// `api.token` and never learns whether it came from the environment, a
// .env file, HashiCorp Vault, AWS, GCP, Azure or a boru vault.
//
// Two failure shapes, and they are never interchangeable. A store that does
// not hold the secret is a MISS (null) - the chain carries on. A store that
// could not answer - bad credentials, unreachable host, missing
// configuration - is an ERROR: falling through there would quietly reach
// for a weaker store.
//
// A port of typescript/src/Providers.ts, which is canonical.

import 'dart:async';
import 'dart:convert';
import 'dart:io';

import 'json.dart';
import 'provider.dart';
import 'sekreto.dart';
import 'sigv4.dart';

/// How long any single vault round-trip may take before it is treated as
/// unreachable. Ports carry the same bound.
const Duration TIMEOUT = Duration(seconds: 10);

/// How much of a response body will be read before the store is treated as
/// having answered incoherently. Ports carry the same bound.
///
/// Far above anything real - the largest legitimate payload this library
/// fetches is Doppler's whole-config download, measured in kilobytes. A
/// bound is needed because the TIMEOUT is not one: ten seconds on a loopback
/// or datacentre link is gigabytes, and the body is accumulated in memory
/// before it is parsed. This runs on an application's startup path, so the
/// failure is the application never starting.
const int MAXBODY = 8 * 1024 * 1024;

/// A deadline that never arrives: a configured token is never renewed.
const int NEVER = 0x7fffffffffffffff;

/// Logging in to a vault instead of being handed a token. `method` is
/// `kubernetes` or `approle`; `mount` defaults to the method name.
class AuthSpec {
  final String method;
  final String? mount;

  /// kubernetes: the Vault role to log in as.
  final String? role;

  /// kubernetes: the service-account JWT itself (tests).
  final String? jwt;

  /// kubernetes: where the JWT lives; the conventional pod path by default.
  final String? jwtfile;

  /// approle: the role and secret ids.
  final String? roleid;
  final String? secretid;

  const AuthSpec({
    required this.method,
    this.mount,
    this.role,
    this.jwt,
    this.jwtfile,
    this.roleid,
    this.secretid,
  });

  /// Printed without its credentials.
  ///
  /// A printer that walked every field would put the service-account JWT and
  /// the AppRole secret id into `print('bad chain: $specs')` - which is what
  /// someone writes when a chain will not build. Fields that hold a
  /// credential report whether they are set, never what they are.
  @override
  String toString() => 'AuthSpec(method: $method, mount: $mount, role: $role, '
      'jwtfile: $jwtfile, roleid: $roleid, jwt: ${setornot(jwt)}, '
      'secretid: ${setornot(secretid)})';
}

/// What a credential field reports about itself.
String setornot(String? value) =>
    (null != value && value.isNotEmpty) ? '[set]' : '[unset]';

/// The declarative form of a provider, as used in config and in the shared
/// spec. `kind` picks the provider; everything else is that kind's own.
class ProviderSpec {
  final String kind;

  /// The store name `Sekreto.getfrom` addresses. Defaults to `kind`.
  final String? name;
  final String? prefix;

  /// dotenv: the file to read. secretspec: the declaration to read.
  final String? file;

  /// memory: literal values, keyed like environment variables. Insertion
  /// ordered, because the spec compares whole maps.
  final Map<String, String>? values;

  /// file: the directory of one-secret-per-file entries.
  final String? dir;

  /// hashicorp / boru (wire) / gcp / 1password / doppler / infisical: the
  /// base URL.
  final String? addr;

  /// hashicorp / boru (wire) / gcp / azure / 1password / doppler /
  /// infisical: the token.
  final String? token;

  /// hashicorp / boru (wire): the KV mount (default `secret`).
  final String? mount;

  /// hashicorp: KV engine version, 1 or 2 (default 2).
  final int? kv;

  /// hashicorp: Vault Enterprise namespace (X-Vault-Namespace).
  final String? vaultnamespace;

  /// hashicorp: log in for a token instead of being handed one.
  final AuthSpec? auth;

  /// boru / secretspec: the executable to run (default: the kind's name).
  final String? command;

  /// secretspec: the profile to read (`--profile`).
  final String? profile;

  /// secretspec: which of ITS backends to read from (`--provider`), e.g.
  /// `keyring` or `dotenv://.env`. Named `backend` here because `provider`
  /// already means a sekreto provider.
  final String? backend;

  /// secretspec: the audit reason recorded for the read (`--reason`).
  /// SecretSpec refuses to read without one.
  final String? reason;

  /// boru: the namespace qualifying the alias.
  final String? namespace;

  /// boru: the vault home, passed as BORU_HOME.
  final String? home;

  /// aws: region and credentials; the standard AWS_* variables fill the
  /// rest.
  final String? region;
  final String? keyid;
  final String? secret;
  final String? session;

  /// gcp / doppler / infisical: the project, however that store names it.
  final String? project;

  /// azure: the Key Vault name or full URL. 1password: the vault name or id.
  final String? vault;

  /// azure: client-credential login. infisical: universal-auth login.
  final String? tenant;
  final String? clientid;
  final String? clientsecret;

  /// azure: where to log in / where IMDS answers. gcp: the metadata server.
  final String? loginaddr;
  final String? imdsaddr;
  final String? metadataaddr;

  /// azure: the Key Vault API version (default 7.4).
  final String? apiversion;

  /// doppler: the config slug (with `project`).
  final String? config;

  /// infisical: the environment slug and secret path.
  final String? environment;
  final String? path;

  const ProviderSpec({
    required this.kind,
    this.name,
    this.prefix,
    this.file,
    this.values,
    this.dir,
    this.addr,
    this.token,
    this.mount,
    this.kv,
    this.vaultnamespace,
    this.auth,
    this.command,
    this.profile,
    this.backend,
    this.reason,
    this.namespace,
    this.home,
    this.region,
    this.keyid,
    this.secret,
    this.session,
    this.project,
    this.vault,
    this.tenant,
    this.clientid,
    this.clientsecret,
    this.loginaddr,
    this.imdsaddr,
    this.metadataaddr,
    this.apiversion,
    this.config,
    this.environment,
    this.path,
  });

  /// Printed without its credentials. See AuthSpec.toString: a printer that
  /// walked every field would put the Vault token, the AWS secret access key
  /// and the Azure client secret into whatever formatted it.
  @override
  String toString() => 'ProviderSpec(kind: $kind, name: $name, addr: $addr, '
      'token: ${setornot(token)}, secret: ${setornot(secret)}, '
      'clientsecret: ${setornot(clientsecret)}, auth: $auth)';
}

/// An environment variable, or null.
String? getenv(String name) => Platform.environment[name];

/// The first candidate that is set and non-empty, or the empty string.
String first(List<String?> candidates) {
  for (final candidate in candidates) {
    if (null != candidate && candidate.isNotEmpty) {
      return candidate;
    }
  }
  return '';
}

/// Drop one trailing slash.
String trimslash(String text) => dropsuffix(text, '/');

/// A URL without its query string, for a message that must not leak one.
String bare(String url) {
  final mark = url.indexOf('?');
  return -1 == mark ? url : url.substring(0, mark);
}

/// What a failure has to say for itself, never the empty string.
String why(Object err) {
  if (err is FileSystemException) {
    final os = err.osError;
    return null != os ? os.message : err.message;
  }
  if (err is SocketException) {
    final os = err.osError;
    return null != os ? os.message : err.message;
  }
  final text = '$err';
  return text.isEmpty ? '$err.runtimeType' : text;
}

// The two errno values that mean "no secrets here" rather than "I could not
// answer". A path that is not there, and a path whose parent is a plain
// file, are both absence; permission denied (EACCES) and "is a directory"
// (EISDIR) are not, and must raise rather than fall through to a weaker
// store.
const int _ENOENT = 2;
const int _ENOTDIR = 20;

bool absent(FileSystemException err) {
  final code = err.osError?.errorCode;
  return _ENOENT == code || _ENOTDIR == code;
}

/// `<dir>/<name>`, with an empty dir meaning the working directory.
String joinpath(String dir, String name) {
  if (dir.isEmpty) {
    return name;
  }
  return dir.endsWith('/') ? '$dir$name' : '$dir/$name';
}

/// What a finished child process left behind.
class Ran {
  final String out;
  final String why;
  final int status;
  const Ran(this.out, this.why, this.status);
}

/// Run a child to completion and collect both its streams.
///
/// `Process.runSync` closes the child's stdin and drains stdout and stderr
/// together. Both matter. A CLI that prompts for a passphrase when its
/// environment variable is absent sees EOF and gives up rather than waiting
/// forever; and draining one stream to EOF before starting on the other
/// would deadlock the moment the child writes more than one pipe buffer
/// (64 KiB on Linux) to stderr - secretspec's box-drawn diagnostics reach
/// that size easily, and nothing here sets a timeout, so that hang would be
/// permanent.
///
/// The argument list is passed as a list, never through a shell, and no
/// secret is ever put on it: the process table is public.
Ran runcmd(List<String> argv, String command, {Map<String, String>? extraenv}) {
  try {
    final result = Process.runSync(
      argv.first,
      argv.sublist(1),
      environment: extraenv,
      stdoutEncoding: utf8,
      stderrEncoding: utf8,
    );

    return Ran(
      result.stdout as String,
      (result.stderr as String).trim(),
      result.exitCode,
    );
  } on ProcessException catch (err) {
    throw SekretoError('sekreto: cannot run $command: ${err.message}');
  }
}

/// One JSON round-trip's result: the status, and the parsed body.
class Answer {
  final int status;
  final Json? body;
  const Answer(this.status, this.body);
}

/// An address with any userinfo replaced by `[redacted]`, for messages.
///
/// Every refusal below names the address it refused, and one of them fires
/// precisely because the address carries a credential - so printing it
/// verbatim would write the password to stderr and into the logs. It cannot
/// be cleaned up afterwards either: that password was never resolved as a
/// secret, so redact() has never seen it and never will. The host is what a
/// reader needs to identify which chain entry is at fault; the userinfo is
/// not.
String safeaddr(String addr) {
  final mark = addr.indexOf('://');
  if (-1 == mark) {
    return addr;
  }

  final rest = addr.substring(mark + 3);
  final stop = stopat(rest, '/?#');
  final authority = -1 == stop ? rest : rest.substring(0, stop);

  final at = authority.lastIndexOf('@');
  if (-1 == at) {
    return addr;
  }

  return '${addr.substring(0, mark + 3)}[redacted]${addr.substring(mark + 3 + at)}';
}

/// Refuse to send a secret-bearing credential in the clear.
///
/// A vault API is HTTPS in any real deployment; plaintext is a dev-mode
/// convenience. Sending a token over http to anything but the local machine
/// puts both the token and the secret it fetches on the wire for anyone on
/// the path, so sekreto will not do it. Loopback stays allowed: that is
/// `vault server -dev`, `boru vault serve`, and this repo's own test
/// harness.
///
/// The address is read by hand, in the same handful of steps in every port,
/// rather than by `Uri.parse`. That is deliberate. A dozen parsers disagree
/// about malformed input - where userinfo ends, whether `0177.0.0.1` is
/// loopback, what an unclosed bracket means - and a check that answers
/// differently in different ports is not a check.
///
/// The rule this parse obeys, and the reason it can be trusted: it is never
/// more permissive than the HTTP client that will dial the address. It ends
/// the authority at `/`, `?` or `#` only, so a client that also breaks on
/// `\` (WHATWG does) can only ever see a SHORTER host than this does. It
/// refuses userinfo outright rather than locating its end. It compares the
/// host literally, so a numeric form no parser here agrees on is refused
/// rather than guessed at.
void checkaddr(String addr) {
  final String scheme;

  if (addr.startsWith('https://')) {
    scheme = 'https://';
  } else if (addr.startsWith('http://')) {
    scheme = 'http://';
  } else {
    throw SekretoError('sekreto: not an http(s) address: ${safeaddr(addr)}');
  }

  final rest = addr.substring(scheme.length);
  final end = stopat(rest, '/?#');
  final authority = -1 == end ? rest : rest.substring(0, end);

  // Userinfo is refused outright rather than parsed around, and on https as
  // well as http. No store this library speaks authenticates by userinfo -
  // they take a token or a signature - so an address carrying one is a
  // mistake at best. At worst it is the attack this whole function exists to
  // stop: `http://localhost:8200@evil.example.com/` is a request to
  // evil.example.com that reads, to anything that splits the authority on
  // ':', as loopback.
  if (authority.contains('@')) {
    throw SekretoError(
      'sekreto: refusing an address with embedded credentials: ${safeaddr(addr)}',
    );
  }

  // An opening bracket with no closing one is not an address at all.
  if (authority.startsWith('[') && !authority.contains(']')) {
    throw SekretoError(
      'sekreto: not a valid http(s) address: ${safeaddr(addr)}',
    );
  }

  if ('https://' == scheme) {
    return;
  }

  // A bracketed IPv6 literal keeps its brackets. Splitting the authority on
  // the first colon yields '[', so `http://[::1]:8200` could never match -
  // which would make the '[::1]' entry below unreachable, and refuse a
  // legitimate local vault.
  final String host;
  if (authority.startsWith('[')) {
    host = authority.substring(0, authority.indexOf(']') + 1).toLowerCase();
  } else {
    final colon = authority.indexOf(':');
    host = (-1 == colon ? authority : authority.substring(0, colon))
        .toLowerCase();
  }

  // Literal, and exactly four. Nothing is normalised: `0177.0.0.1`,
  // `2130706433` and `[::ffff:127.0.0.1]` are loopback to some resolvers and
  // not to others, and a check that has to guess is not a check.
  if ('localhost' != host &&
      '127.0.0.1' != host &&
      '::1' != host &&
      '[::1]' != host) {
    throw SekretoError(
      'sekreto: refusing to send a token in plaintext to ${safeaddr(addr)} (use https)',
    );
  }
}

// The one HTTP client, built once.
//
// Redirects are never followed: a vault API does not legitimately redirect,
// and a followed redirect would carry X-Vault-Token to the redirect's host
// (and could downgrade https to http), which checkaddr - it only validates
// the configured address - cannot see.
//
// Proxies are ignored. The GCP and Azure metadata endpoints are not
// loopback, and an `http_proxy` in the environment has sent a Vault token in
// the clear before now. Dart's HttpClient does not read the proxy
// environment unless asked; saying so explicitly makes it auditable rather
// than merely true.
HttpClient? _client;

HttpClient http() {
  final existing = _client;
  if (null != existing) {
    return existing;
  }

  // Additive, never a replacement: the platform roots are loaded first and
  // unconditionally, and SEKRETO_CA_BUNDLE adds to them. It fails open and
  // silently - an unreadable file or a certificate the store rejects adds no
  // roots and raises nothing, so a wrong path cannot turn into a refusal
  // that looks like a network fault.
  final context = SecurityContext(withTrustedRoots: true);
  final extra = getenv('SEKRETO_CA_BUNDLE');

  if (null != extra && extra.isNotEmpty) {
    try {
      context.setTrustedCertificates(extra);
    } catch (_) {
      // Fails open by design.
    }
  }

  final client = HttpClient(context: context);
  client.connectionTimeout = TIMEOUT;
  client.findProxy = (uri) => 'DIRECT';

  _client = client;
  return client;
}

Future<(int, String)> _roundtrip(
  String method,
  String url,
  Map<String, String> headers,
  String? body,
) async {
  final request = await http().openUrl(method, Uri.parse(url));

  request.followRedirects = false;

  headers.forEach((key, value) => request.headers.set(key, value));

  if (null == body) {
    request.contentLength = 0;
  } else {
    final bytes = utf8.encode(body);
    request.contentLength = bytes.length;
    request.add(bytes);
  }

  final response = await request.close();

  // One byte over the bound is enough to know it was exceeded. An endless
  // body is a store that could not answer, so this raises rather than
  // returning a miss - the latter would fall through to a weaker store on an
  // attacker's cue.
  final chunks = <int>[];

  await for (final chunk in response) {
    chunks.addAll(chunk);
    if (MAXBODY < chunks.length) {
      throw SekretoError('sekreto: oversized response from ${bare(url)}');
    }
  }

  return (response.statusCode, utf8.decode(chunks, allowMalformed: true));
}

/// One JSON round-trip. Network failure is always an error - an unreachable
/// store is a store that could not answer, never a store that does not hold
/// the secret.
Future<Answer> fetchjson(
  String method,
  String url, {
  Map<String, String> headers = const {},
  String? body,
}) async {
  final int status;
  final String text;

  try {
    final answered = await _roundtrip(method, url, headers, body).timeout(TIMEOUT);
    status = answered.$1;
    text = answered.$2;
  } on SekretoError {
    // The body bound above; already the message it should be.
    rethrow;
  } catch (err) {
    throw SekretoError('sekreto: cannot reach ${bare(url)}: ${why(err)}');
  }

  // A success status promised JSON; a body that does not parse means the
  // store could not answer coherently, and treating it as a miss would fall
  // through to a weaker store. Error statuses may carry any body - they are
  // decided on status alone.
  final parsed = jsonparse(text);
  if (200 == status && null == parsed) {
    throw SekretoError('sekreto: malformed response from ${bare(url)}');
  }

  return Answer(status, parsed);
}

/// When a logged-in token must be renewed, from its expiry in seconds (a
/// JSON number, or a string as Azure IMDS sends it): now + max(seconds - 60,
/// 1). A missing or zero expiry means never renew.
int renewtime(Json? expires) {
  var seconds = 0.0;

  final number = expires.asnum;
  if (null != number) {
    seconds = number;
  } else {
    final text = expires.asstr;
    if (null != text) {
      seconds = double.tryParse(text) ?? 0.0;
    }
  }

  if (seconds.isNaN || 0 >= seconds) {
    return NEVER;
  }

  final lead = seconds - 60 < 1 ? 1.0 : seconds - 60;
  return DateTime.now().millisecondsSinceEpoch + (lead * 1000).toInt();
}

/// Now, as the `YYYYMMDDTHHMMSSZ` timestamp SigV4 wants.
String awsnow() {
  final now = DateTime.now().toUtc();
  String two(int value) => value.toString().padLeft(2, '0');

  return '${now.year.toString().padLeft(4, '0')}${two(now.month)}'
      '${two(now.day)}T${two(now.hour)}${two(now.minute)}'
      '${two(now.second)}Z';
}

/// Decode standard base64, strictly.
///
/// Nothing is skipped and nothing is guessed: a lenient decoder silently
/// drops bytes outside the alphabet and hands back plausible bytes for a
/// corrupted payload - which then get returned as the secret. Whitespace is
/// stripped first, because the canonical function accepts a payload wrapped
/// across lines; everything else outside the alphabet is a refusal, and a
/// refusal is an error, never a miss.
String? unbase64(String text) {
  final cleaned = text.replaceAll(RegExp(r'\s'), '');

  if (cleaned.isEmpty || 0 != cleaned.length % 4) {
    return null;
  }

  var end = cleaned.length;
  var pad = 0;
  while (0 < end && '=' == cleaned[end - 1] && 2 > pad) {
    end--;
    pad++;
  }

  for (var at = 0; at < end; at++) {
    if (!_B64.contains(cleaned[at])) {
      return null;
    }
  }

  try {
    return utf8.decode(base64.decode(cleaned), allowMalformed: true);
  } catch (_) {
    return null;
  }
}

const String _B64 =
    'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/';

// ------------------------------------------------------------ the kinds

/// Environment variables: `api.token` from `API_TOKEN`.
class Env extends Provider {
  final String? prefix;

  /// An injected environment, for tests. The spec never passes one.
  final Map<String, String>? source;

  Env({this.prefix, this.source});

  @override
  String? lookup(String name) {
    final key = envkey(name, prefix);
    return null == source ? getenv(key) : source![key];
  }

  @override
  String describe() =>
      'env${(null != prefix && prefix!.isNotEmpty) ? ':$prefix' : ''}';
}

/// A `.env` file, read once, keyed exactly like the environment.
class Dotenv extends Provider {
  final String file;
  final String? prefix;

  // Read LAZILY, on the first lookup. An eager read would open whatever
  // `.env` happens to sit in the working directory just because a dotenv
  // provider is in a chain that is never read from.
  Map<String, String>? _values;

  Dotenv(this.file, {this.prefix});

  Map<String, String> _load() {
    final loaded = _values;
    if (null != loaded) {
      return loaded;
    }

    Map<String, String> values;

    try {
      values = parsedotenv(File(file).readAsStringSync());
    } on FileSystemException catch (err) {
      // An absent file - or an absent directory - means "no secrets here",
      // exactly like the file provider. Anything else (permission denied, an
      // unreadable mount) is a store that could not answer.
      if (!absent(err)) {
        throw SekretoError(
          'sekreto: dotenv provider cannot read $file: ${why(err)}',
        );
      }
      values = <String, String>{};
    }

    _values = values;
    return values;
  }

  @override
  String? lookup(String name) => _load()[envkey(name, prefix)];

  @override
  String describe() => 'dotenv:$file';
}

/// Literal values, keyed like environment variables. The spec uses this to
/// test chain behaviour without touching the outside world.
class Memory extends Provider {
  final Map<String, String> values;
  final String? prefix;

  Memory({Map<String, String>? source, this.prefix})
      : values = source ?? const {};

  @override
  String? lookup(String name) => values[envkey(name, prefix)];

  @override
  String describe() =>
      'memory${(null != prefix && prefix!.isNotEmpty) ? ':$prefix' : ''}';
}

/// A directory of one-secret-per-file entries, keyed like the environment:
/// `api.token` reads `<dir>/API_TOKEN`.
///
/// This is the shape of a mounted Kubernetes Secret, a Docker or Swarm
/// secret, and a systemd credentials directory, so those all work with no
/// further configuration. Read on every lookup and never cached: a mounted
/// secret is rotated underneath a running process.
///
/// One trailing newline is stripped - tools that write these files disagree
/// about it, and a newline is never part of a secret on purpose.
class SecretFile extends Provider {
  final String dir;
  final String? prefix;

  SecretFile(this.dir, {this.prefix});

  @override
  String? lookup(String name) {
    final path = joinpath(dir, envkey(name, prefix));

    final String body;

    try {
      body = File(path).readAsStringSync();
    } on FileSystemException catch (err) {
      if (absent(err)) {
        return null;
      }
      throw SekretoError(
        'sekreto: file provider cannot read $path: ${why(err)}',
      );
    }

    if (body.endsWith('\r\n')) {
      return body.substring(0, body.length - 2);
    }
    if (body.endsWith('\n')) {
      return body.substring(0, body.length - 1);
    }
    return body;
  }

  @override
  String describe() => 'file:$dir';
}

/// HashiCorp Vault.
///
/// KV v2 (the default): `api.token` reads `{addr}/v1/{mount}/data/api` and
/// takes the `token` field of `data.data`. KV v1 (`kv: 1`) reads
/// `{addr}/v1/{mount}/api` and takes the field of `data`. A 404 means "not
/// here" - a miss - so a vault can sit in a chain with fallbacks.
///
/// A Vault Enterprise namespace rides the X-Vault-Namespace header, on
/// logins as well as reads.
///
/// Instead of being handed a token, the provider can log in: Kubernetes auth
/// (the pod's service-account JWT, from its conventional path) or AppRole. A
/// failed login is an error, never a miss - it means this store could not
/// answer at all.
class Hashicorp extends Provider {
  final String addr;
  final String mount;
  final int kv;
  final String? vaultnamespace;
  final AuthSpec? auth;

  // The working token: a configured token is kept forever, a logged-in token
  // is renewed shortly before its lease runs out - a long-running process
  // must not keep presenting a token the vault already expired.
  String? _livetoken;
  int _renewat = NEVER;

  Hashicorp(
    this.addr, {
    String? token,
    String? mount,
    int? kv,
    this.vaultnamespace,
    this.auth,
  })  : mount = (null == mount || mount.isEmpty) ? 'secret' : mount,
        kv = kv ?? 2,
        _livetoken = (null == token || token.isEmpty) ? null : token {
    // A version typo like kv: 3 must not quietly behave as v2 and turn its
    // 404s into misses; there is nothing safe to assume it meant.
    if (1 != this.kv && 2 != this.kv) {
      throw SekretoError('sekreto: hashicorp: unsupported kv version: ${this.kv}');
    }
  }

  Map<String, String> _baseheaders() {
    if (null != vaultnamespace && vaultnamespace!.isNotEmpty) {
      return {'X-Vault-Namespace': vaultnamespace!};
    }
    return {};
  }

  Future<String> _login() async {
    final use = auth;
    if (null == use) {
      throw SekretoError('sekreto: hashicorp: no token and no auth method');
    }

    final authmount = first([use.mount, use.method]);
    final url = '${trimslash(addr)}/v1/auth/$authmount/login';

    final Json body;

    switch (use.method) {
      case 'kubernetes':
        String jwt;
        final given = use.jwt;

        if (null != given) {
          jwt = given;
        } else {
          final file = use.jwtfile ??
              '/var/run/secrets/kubernetes.io/serviceaccount/token';
          try {
            jwt = File(file).readAsStringSync().trim();
          } on FileSystemException {
            throw SekretoError(
              'sekreto: hashicorp: cannot read jwt file $file',
            );
          }
        }

        body = JsonObj({
          'role': JsonStr(use.role ?? ''),
          'jwt': JsonStr(jwt),
        });

      case 'approle':
        body = JsonObj({
          'role_id': JsonStr(use.roleid ?? ''),
          'secret_id': JsonStr(use.secretid ?? ''),
        });

      default:
        throw SekretoError(
          'sekreto: hashicorp: unknown auth method: ${use.method}',
        );
    }

    final res = await fetchjson(
      'POST',
      url,
      headers: _baseheaders(),
      body: jsonstringify(body),
    );

    final got = res.body.dig('auth', 'client_token').text;
    if (200 != res.status || null == got || got.isEmpty) {
      throw SekretoError('sekreto: hashicorp login failed: ${res.status}: $url');
    }

    _renewat = renewtime(res.body.dig('auth', 'lease_duration'));

    return got;
  }

  @override
  FutureOr<String?> lookup(String name) {
    // Refused before anything is dialled, and synchronously, so a misspelled
    // address is a configuration error rather than a network one.
    checkaddr(addr);
    return _read(name);
  }

  Future<String?> _read(String name) async {
    if (null == _livetoken || DateTime.now().millisecondsSinceEpoch >= _renewat) {
      _livetoken = await _login();
    }

    final ref = vaultref(name);
    final base = '${trimslash(addr)}/v1/$mount';
    final url = 1 == kv ? '$base/${ref.path}' : '$base/data/${ref.path}';

    final headers = _baseheaders();
    headers['X-Vault-Token'] = _livetoken ?? '';

    final res = await fetchjson('GET', url, headers: headers);

    if (404 == res.status) {
      return null;
    }
    if (200 != res.status) {
      throw SekretoError('sekreto: hashicorp error: ${res.status}: $url');
    }

    final data =
        1 == kv ? res.body.dig('data') : res.body.dig('data', 'data');

    return data.dig(ref.field).text;
  }

  @override
  String describe() => 'hashicorp:$addr/$mount';
}

/// Does this boru failure mean "no such secret" rather than "I could not
/// answer"? Matched on boru's own wording for a missing alias.
bool borumiss(String reason) => reason.contains('no alias named');

/// A boru vault (https://github.com/boru-lang/boru).
///
/// Two ways in, both boru's own.
///
/// With no `addr`, the CLI: `boru vault get --reveal <alias>` prints the
/// secret on stdout and nothing else. The passphrase is read by boru itself
/// from `BORU_VAULT_PASSPHRASE`; sekreto never accepts it as config and
/// never puts it on a command line, where it would show up in the process
/// table.
///
/// With an `addr`, boru's wire protocol: `boru vault serve` publishes a
/// read-only, HashiCorp-shaped provision API, authenticated by a capability
/// token from `boru vault grant`. A sekreto name is already a valid boru
/// alias, and boru aliases keep their dots, so `api.token` is the single
/// path segment `api.token` - not the `api`/`token` split a HashiCorp KV
/// gets. The value is the `value` field. A 404 is a miss; anything else the
/// server refuses (a revoked capability, a sealed vault) is an error.
class Boru extends Provider {
  final String command;
  final String? namespace;
  final String? home;
  final String addr;
  final String token;
  final String mount;

  Boru({
    String? command,
    this.namespace,
    this.home,
    String? addr,
    String? token,
    String? mount,
  })  : command = (null == command || command.isEmpty) ? 'boru' : command,
        addr = null == addr ? '' : trimslash(addr),
        token = token ?? '',
        mount = (null == mount || mount.isEmpty) ? 'secret' : mount;

  @override
  FutureOr<String?> lookup(String name) {
    checkname(name);

    if (addr.isNotEmpty) {
      checkaddr(addr);
      return _wire(name);
    }

    final space = namespace;
    final alias =
        (null != space && space.isNotEmpty) ? '$space:$name' : name;

    final ran = runcmd(
      [command, 'vault', 'get', '--reveal', alias],
      command,
      // Merged over the parent environment, not replacing it: boru needs
      // the rest of it, BORU_VAULT_PASSPHRASE included.
      extraenv: (null != home && home!.isNotEmpty)
          ? {'BORU_HOME': home!}
          : null,
    );

    if (0 == ran.status) {
      // boru prints the value and one newline, and nothing else.
      return dropsuffix(ran.out, '\n');
    }

    // "no alias named" is boru saying it does not hold this secret, which is
    // a miss: the chain carries on to the next provider. A locked vault or a
    // wrong passphrase is not a miss - treating it as one would fall through
    // to a weaker store without saying so.
    if (borumiss(ran.why)) {
      return null;
    }

    throw SekretoError(
      'sekreto: boru vault error: '
      '${ran.why.isEmpty ? 'exit ${ran.status}' : ran.why}',
    );
  }

  Future<String?> _wire(String name) async {
    // The dotted name stays one path segment: boru aliases keep dots.
    final space = namespace;
    final alias =
        (null != space && space.isNotEmpty) ? '$space/$name' : name;
    final url = '$addr/v1/$mount/data/$alias';

    final res = await fetchjson('GET', url, headers: {'X-Vault-Token': token});

    if (404 == res.status) {
      return null;
    }
    if (200 != res.status) {
      throw SekretoError('sekreto: boru serve error: ${res.status}: $url');
    }

    return res.body.dig('data', 'data', 'value').text;
  }

  @override
  String describe() {
    if (addr.isNotEmpty) {
      return 'boru:$addr';
    }
    return 'boru${(null != namespace && namespace!.isNotEmpty) ? ':$namespace' : ''}';
  }
}

/// Does this SecretSpec failure mean "no such secret" rather than "I could
/// not answer"?
///
/// SecretSpec says `Secret 'API_TOKEN' not found` for both a name it does
/// not declare and one declared with no value, and both are misses: this
/// store does not hold it, so the chain carries on.
///
/// MATCHED ON THE WHOLE PHRASE, NOT ON "not found". SecretSpec also says
/// `Provider backend 'keyring' not found`, which is a store that could not
/// answer at all - and reading that as a miss is the worst failure this
/// library has, because the chain then falls through to a weaker store
/// without saying so. The key is required to appear, so the two cannot be
/// confused.
bool secretspecmiss(String reason, String key) =>
    reason.contains("Secret '$key' not found");

/// SecretSpec (https://secretspec.dev).
///
/// SecretSpec is a declaration - a `secretspec.toml` naming the secrets a
/// project needs - plus a chain of its own backends to satisfy them from.
/// That makes it the same shape as sekreto one level down, and the reason to
/// support it is the same reason sekreto exists: a project that has already
/// declared its secrets there should not have to declare them again here.
///
/// A reason is required, not optional: SecretSpec records every read in an
/// audit log and refuses to read at all without one. sekreto sends `sekreto`
/// unless told otherwise, so the audit trail says which tool asked.
class Secretspec extends Provider {
  final String command;
  final String? file;
  final String? profile;
  final String? backend;
  final String? reason;
  final String? prefix;

  Secretspec({
    String? command,
    this.file,
    this.profile,
    this.backend,
    this.reason,
    this.prefix,
  }) : command = (null == command || command.isEmpty) ? 'secretspec' : command;

  @override
  String? lookup(String name) {
    final key = envkey(name, prefix);

    // The order is SecretSpec's: --file belongs to the program, before the
    // subcommand; everything else belongs to `get`.
    final argv = <String>[command];
    if (null != file && file!.isNotEmpty) {
      argv.addAll(['--file', file!]);
    }
    argv.addAll(['get', key]);
    if (null != backend && backend!.isNotEmpty) {
      argv.addAll(['--provider', backend!]);
    }
    if (null != profile && profile!.isNotEmpty) {
      argv.addAll(['--profile', profile!]);
    }
    argv.addAll(['--reason', first([reason, 'sekreto'])]);

    final ran = runcmd(argv, command);

    if (0 == ran.status) {
      // The value and one newline, and nothing else.
      return dropsuffix(ran.out, '\n');
    }

    if (secretspecmiss(ran.why, key)) {
      return null;
    }

    throw SekretoError(
      'sekreto: secretspec error: '
      '${ran.why.isEmpty ? 'exit ${ran.status}' : ran.why}',
    );
  }

  @override
  String describe() =>
      'secretspec${(null != backend && backend!.isNotEmpty) ? ':$backend' : ''}';
}

/// One signed AWS call, prepared without touching the network.
class _Awscall {
  final String url;
  final Map<String, String> headers;
  final String payload;
  const _Awscall(this.url, this.headers, this.payload);
}

/// Region and credentials, from config first and the standard AWS_*
/// environment variables second - those are AWS's own convention, and a pod
/// or CI job that has them set should just work. Missing either is an error:
/// an AWS store with no credentials could not answer.
///
/// Resolved, checked and signed synchronously, so a chain with no
/// credentials fails where it is configured rather than somewhere inside a
/// network call.
_Awscall awsprep({
  String? region,
  String? keyid,
  String? secret,
  String? session,
  String? addr,
  required String service,
  required String target,
  required String payload,
}) {
  final useregion =
      first([region, getenv('AWS_REGION'), getenv('AWS_DEFAULT_REGION')]);
  final usekeyid = first([keyid, getenv('AWS_ACCESS_KEY_ID')]);
  final usesecret = first([secret, getenv('AWS_SECRET_ACCESS_KEY')]);
  final usesession = first([session, getenv('AWS_SESSION_TOKEN')]);

  if (useregion.isEmpty) {
    throw SekretoError('sekreto: aws: no region (set region or AWS_REGION)');
  }

  if (usekeyid.isEmpty || usesecret.isEmpty) {
    throw SekretoError(
      'sekreto: aws: no credentials'
      ' (set keyid/secret or AWS_ACCESS_KEY_ID/AWS_SECRET_ACCESS_KEY)',
    );
  }

  // The China partition lives under its own suffix; every other commercial
  // region is plain amazonaws.com.
  final suffix =
      useregion.startsWith('cn-') ? '.amazonaws.com.cn' : '.amazonaws.com';
  final useaddr = first([addr, 'https://$service.$useregion$suffix']);
  checkaddr(useaddr);

  final url = '${trimslash(useaddr)}/';

  final extras = <String, String>{
    'content-type': 'application/x-amz-json-1.1',
    'x-amz-target': target,
  };

  final signed = sigv4(Signing(
    method: 'POST',
    url: url,
    service: service,
    region: useregion,
    keyid: usekeyid,
    secret: usesecret,
    datetime: awsnow(),
    headers: extras,
    body: payload,
    session: usesession.isEmpty ? null : usesession,
  ));

  final headers = <String, String>{...extras, ...signed};

  return _Awscall(url, headers, payload);
}

/// Does this AWS error body name one of the not-found types? Those are a
/// miss; every other failure is a store that could not answer.
///
/// A containment test, because AWS sends the type fully qualified:
/// `com.amazonaws.service#ResourceNotFoundException`.
bool awsmiss(Json? body, String type) {
  final errtype = body.dig('__type').asstr;
  return null != errtype && errtype.contains(type);
}

/// AWS Secrets Manager.
///
/// `api.token` reads the secret named `api` (the vaultref path, so
/// `db.pass.main` reads `db/pass`) and takes the `token` field of its JSON
/// SecretString - the AWS idiom of one JSON map per secret. A SecretString
/// that is not JSON is the value itself, under the conventional field
/// `value`. Requests are SigV4-signed in-tree; see sigv4.dart.
class Awssecrets extends Provider {
  final String? region;
  final String? keyid;
  final String? secret;
  final String? session;
  final String? addr;

  Awssecrets({this.region, this.keyid, this.secret, this.session, this.addr});

  @override
  FutureOr<String?> lookup(String name) {
    final ref = vaultref(name);

    final call = awsprep(
      region: region,
      keyid: keyid,
      secret: secret,
      session: session,
      addr: addr,
      service: 'secretsmanager',
      target: 'secretsmanager.GetSecretValue',
      payload: jsonstringify(JsonObj({'SecretId': JsonStr(ref.path)})),
    );

    return _read(call, ref);
  }

  Future<String?> _read(_Awscall call, VaultRef ref) async {
    final res = await fetchjson('POST', call.url,
        headers: call.headers, body: call.payload);

    if (400 == res.status && awsmiss(res.body, 'ResourceNotFoundException')) {
      return null;
    }
    if (200 != res.status) {
      throw SekretoError('sekreto: aws secretsmanager error: ${res.status}');
    }

    final text = res.body.dig('SecretString').asstr;

    if (null == text) {
      // A binary secret has no fields to address; only the conventional
      // `value` field can mean "the bytes themselves".
      final binary = res.body.dig('SecretBinary').asstr;

      if (null == binary || 'value' != ref.field) {
        return null;
      }

      final decoded = unbase64(binary);
      if (null == decoded) {
        throw SekretoError('sekreto: aws secretsmanager: undecodable secret');
      }
      return decoded;
    }

    final parsed = jsonparse(text);
    final fields = parsed.asobj;

    if (null != fields) {
      return fields[ref.field].text;
    }

    // A plain-string secret is the whole value; it has no named fields.
    return 'value' == ref.field ? text : null;
  }

  // Config only, never the environment: describe() feeds the spec's sources
  // group, which must answer the same everywhere.
  @override
  String describe() => 'awssecrets:${region ?? ''}';
}

/// AWS SSM Parameter Store.
///
/// `db.pass.main` reads the parameter `/db/pass/main` (under an optional
/// prefix path), decrypted. Parameter Store carries flat strings, so there
/// is no field indirection.
class Awsparams extends Provider {
  final String? region;
  final String? keyid;
  final String? secret;
  final String? session;
  final String? addr;
  final String? prefix;

  Awsparams({
    this.region,
    this.keyid,
    this.secret,
    this.session,
    this.addr,
    this.prefix,
  });

  @override
  FutureOr<String?> lookup(String name) {
    final call = awsprep(
      region: region,
      keyid: keyid,
      secret: secret,
      session: session,
      addr: addr,
      service: 'ssm',
      target: 'AmazonSSM.GetParameter',
      payload: jsonstringify(JsonObj({
        'Name': JsonStr(awsparam(name, prefix)),
        'WithDecryption': const JsonBool(true),
      })),
    );

    return _read(call);
  }

  Future<String?> _read(_Awscall call) async {
    final res = await fetchjson('POST', call.url,
        headers: call.headers, body: call.payload);

    if (400 == res.status && awsmiss(res.body, 'ParameterNotFound')) {
      return null;
    }
    if (200 != res.status) {
      throw SekretoError('sekreto: aws ssm error: ${res.status}');
    }

    return res.body.dig('Parameter', 'Value').text;
  }

  @override
  String describe() => 'awsparams:${region ?? ''}${prefix ?? ''}';
}

/// GCP Secret Manager.
///
/// `api.token` reads secret `api_token` (dots flattened to `_`; Secret
/// Manager ids have no hierarchy and reject dots), latest version. The token
/// comes from config, then `GOOGLE_OAUTH_ACCESS_TOKEN`, then the GCE/GKE
/// metadata server - so on Google's own platform no credential configuration
/// is needed at all.
///
/// The metadata call itself is plain http to a link-local host by platform
/// design; no credential rides on it, so `checkaddr` guards the Secret
/// Manager address instead.
class Gcpsecrets extends Provider {
  final String? project;
  final String? token;
  final String? addr;
  final String? metadataaddr;

  // A configured token is kept forever; a metadata-server token carries
  // expires_in and is renewed shortly before it runs out.
  String? _livetoken;
  int _renewat = NEVER;

  Gcpsecrets({this.project, this.token, this.addr, this.metadataaddr});

  String _metadataaddr() {
    if (null != metadataaddr && metadataaddr!.isNotEmpty) {
      return metadataaddr!;
    }

    final host = getenv('GCE_METADATA_HOST');
    if (null != host && host.isNotEmpty) {
      return 'http://$host';
    }

    return 'http://metadata.google.internal';
  }

  Future<String> _login() async {
    final configured = first([token, getenv('GOOGLE_OAUTH_ACCESS_TOKEN')]);
    if (configured.isNotEmpty) {
      return configured;
    }

    final url = '${trimslash(_metadataaddr())}'
        '/computeMetadata/v1/instance/service-accounts/default/token';

    final res =
        await fetchjson('GET', url, headers: {'Metadata-Flavor': 'Google'});

    final got = res.body.dig('access_token').text;
    if (200 != res.status || null == got || got.isEmpty) {
      throw SekretoError(
        'sekreto: gcp: no token and metadata server did not answer',
      );
    }

    _renewat = renewtime(res.body.dig('expires_in'));

    return got;
  }

  @override
  FutureOr<String?> lookup(String name) {
    final useproject = project ?? '';
    if (useproject.isEmpty) {
      throw SekretoError('sekreto: gcp: no project');
    }

    final useaddr = first([addr, 'https://secretmanager.googleapis.com']);
    checkaddr(useaddr);

    return _read(useproject, useaddr, name);
  }

  Future<String?> _read(String useproject, String useaddr, String name) async {
    if (null == _livetoken || DateTime.now().millisecondsSinceEpoch >= _renewat) {
      _livetoken = await _login();
    }

    final url = '${trimslash(useaddr)}/v1/projects/$useproject/secrets/'
        '${flatname(name, '_')}/versions/latest:access';

    final res = await fetchjson('GET', url,
        headers: {'authorization': 'Bearer ${_livetoken ?? ''}'});

    if (404 == res.status) {
      return null;
    }
    if (200 != res.status) {
      throw SekretoError('sekreto: gcp error: ${res.status}: $url');
    }

    final data = res.body.dig('payload', 'data').asstr;
    if (null == data) {
      return null;
    }

    final decoded = unbase64(data);
    if (null == decoded) {
      throw SekretoError('sekreto: gcp: undecodable secret');
    }

    return decoded;
  }

  @override
  String describe() => 'gcpsecrets:${project ?? ''}';
}

/// The Key Vault audience an Azure token is minted for.
const String RESOURCE = 'https://vault.azure.net';

/// Azure Key Vault.
///
/// `api.token` reads secret `api-token` (dots flattened to `-`; Key Vault
/// names allow nothing else), current version. The token comes from config,
/// then a client-credentials login when tenant/clientid/clientsecret are
/// given, then the IMDS managed-identity endpoint - so on Azure's own
/// platform no credential configuration is needed.
///
/// As with GCP, the IMDS call is plain http to a link-local host by platform
/// design and carries no credential; the login and vault addresses are
/// `checkaddr`-guarded.
class Azuresecrets extends Provider {
  final String? vault;
  final String? token;
  final String? tenant;
  final String? clientid;
  final String? clientsecret;
  final String? loginaddr;
  final String? imdsaddr;
  final String? apiversion;

  // A configured token is kept forever; logged-in and IMDS tokens carry
  // expires_in and are renewed shortly before they run out.
  String? _livetoken;
  int _renewat = NEVER;

  Azuresecrets({
    this.vault,
    this.token,
    this.tenant,
    this.clientid,
    this.clientsecret,
    this.loginaddr,
    this.imdsaddr,
    this.apiversion,
  });

  bool get _hasclient =>
      null != tenant &&
      tenant!.isNotEmpty &&
      null != clientid &&
      clientid!.isNotEmpty &&
      null != clientsecret &&
      clientsecret!.isNotEmpty;

  Future<String> _login() async {
    if (null != token && token!.isNotEmpty) {
      return token!;
    }

    if (_hasclient) {
      final useloginaddr =
          first([loginaddr, 'https://login.microsoftonline.com']);
      checkaddr(useloginaddr);

      final url = '${trimslash(useloginaddr)}/${tenant!}/oauth2/v2.0/token';
      final form = 'grant_type=client_credentials'
          '&client_id=${uriescape(clientid!)}'
          '&client_secret=${uriescape(clientsecret!)}'
          '&scope=${uriescape('$RESOURCE/.default')}';

      final res = await fetchjson(
        'POST',
        url,
        headers: {'content-type': 'application/x-www-form-urlencoded'},
        body: form,
      );

      final got = res.body.dig('access_token').text;
      if (200 != res.status || null == got || got.isEmpty) {
        throw SekretoError('sekreto: azure login failed: ${res.status}');
      }

      _renewat = renewtime(res.body.dig('expires_in'));
      return got;
    }

    final imds = '${trimslash(first([imdsaddr, 'http://169.254.169.254']))}'
        '/metadata/identity/oauth2/token?api-version=2018-02-01'
        '&resource=${uriescape(RESOURCE)}';

    final res = await fetchjson('GET', imds, headers: {'Metadata': 'true'});

    final got = res.body.dig('access_token').text;
    if (200 != res.status || null == got || got.isEmpty) {
      throw SekretoError(
        'sekreto: azure: no token, no client credentials, and IMDS did not answer',
      );
    }

    // IMDS sends expires_in as a STRING, where everyone else sends a number.
    _renewat = renewtime(res.body.dig('expires_in'));
    return got;
  }

  @override
  FutureOr<String?> lookup(String name) {
    final usevault = vault ?? '';
    if (usevault.isEmpty) {
      throw SekretoError('sekreto: azure: no vault');
    }

    // Only an explicit scheme is a URL; a vault NAMED httpvault must still
    // become https://httpvault.vault.azure.net.
    final vaulturl =
        (usevault.startsWith('http://') || usevault.startsWith('https://'))
            ? usevault
            : 'https://$usevault.vault.azure.net';
    checkaddr(vaulturl);

    return _read(vaulturl, name);
  }

  Future<String?> _read(String vaulturl, String name) async {
    if (null == _livetoken || DateTime.now().millisecondsSinceEpoch >= _renewat) {
      _livetoken = await _login();
    }

    final url = '${trimslash(vaulturl)}/secrets/${flatname(name, '-')}'
        '?api-version=${first([apiversion, '7.4'])}';

    final res = await fetchjson('GET', url,
        headers: {'authorization': 'Bearer ${_livetoken ?? ''}'});

    if (404 == res.status) {
      return null;
    }
    if (200 != res.status) {
      throw SekretoError('sekreto: azure error: ${res.status}: ${bare(url)}');
    }

    return res.body.dig('value').text;
  }

  @override
  String describe() => 'azuresecrets:${vault ?? ''}';
}

/// 1Password, through a Connect server.
///
/// The item titled `api.token` (titles keep their dots), in the named vault.
/// The value is the field with purpose PASSWORD, or the field labelled
/// `value`. A vault that cannot be found is an error - config names it, so
/// its absence is a broken store, not a missing secret.
class Onepassword extends Provider {
  final String? addr;
  final String? token;
  final String? vault;

  String? _vaultid;

  Onepassword({this.addr, this.token, this.vault});

  Map<String, String> _auth() => {'authorization': 'Bearer ${token ?? ''}'};

  Future<String> _resolvevault(String useaddr) async {
    final want = vault ?? '';
    if (want.isEmpty) {
      throw SekretoError('sekreto: onepassword: no vault');
    }

    final res = await fetchjson('GET', '$useaddr/v1/vaults', headers: _auth());

    final list = res.body.asarr;
    if (200 != res.status || null == list) {
      throw SekretoError(
        'sekreto: onepassword error: ${res.status}: listing vaults',
      );
    }

    for (final entry in list) {
      if (want == entry.dig('id').text || want == entry.dig('name').text) {
        return entry.dig('id').text ?? '';
      }
    }

    throw SekretoError('sekreto: onepassword: no vault named $want');
  }

  @override
  FutureOr<String?> lookup(String name) {
    checkname(name);

    final useaddr = trimslash(addr ?? '');
    if (useaddr.isEmpty) {
      throw SekretoError('sekreto: onepassword: no addr');
    }
    checkaddr(useaddr);

    return _read(useaddr, name);
  }

  Future<String?> _read(String useaddr, String name) async {
    var id = _vaultid;
    if (null == id) {
      id = await _resolvevault(useaddr);
      _vaultid = id;
    }

    final filter = uriescape('title eq "$name"');
    final found = await fetchjson(
      'GET',
      '$useaddr/v1/vaults/$id/items?filter=$filter',
      headers: _auth(),
    );

    final items = found.body.asarr;
    if (200 != found.status || null == items) {
      throw SekretoError(
        'sekreto: onepassword error: ${found.status}: finding $name',
      );
    }

    // An empty list is a miss: the vault is fine, the item is not there.
    if (items.isEmpty) {
      return null;
    }

    final itemid = items.first.dig('id').text ?? '';
    final item = await fetchjson(
      'GET',
      '$useaddr/v1/vaults/$id/items/$itemid',
      headers: _auth(),
    );

    if (200 != item.status) {
      throw SekretoError(
        'sekreto: onepassword error: ${item.status}: reading $name',
      );
    }

    final fields = item.body.dig('fields').asarr ?? const <Json>[];

    for (final field in fields) {
      if ('PASSWORD' == field.dig('purpose').asstr) {
        return field.dig('value').text;
      }
    }

    for (final field in fields) {
      if ('value' == field.dig('label').asstr) {
        return field.dig('value').text;
      }
    }

    return null;
  }

  @override
  String describe() => 'onepassword:${vault ?? ''}';
}

/// Doppler.
///
/// The whole config is downloaded once - Doppler's own bulk endpoint - and
/// answered from memory, like a remote .env: `api.token` is the `API_TOKEN`
/// entry. A service token is config-scoped, so project and config are only
/// needed with broader tokens.
class Doppler extends Provider {
  final String? token;
  final String? project;
  final String? config;
  final String? addr;

  Map<String, String>? _values;

  Doppler({this.token, this.project, this.config, this.addr});

  @override
  FutureOr<String?> lookup(String name) {
    final loaded = _values;
    if (null != loaded) {
      return loaded[envkey(name)];
    }

    final useaddr = trimslash(first([addr, 'https://api.doppler.com']));
    checkaddr(useaddr);

    return _load(useaddr).then((values) => values[envkey(name)]);
  }

  Future<Map<String, String>> _load(String useaddr) async {
    var url = '$useaddr/v3/configs/config/secrets/download?format=json';
    if (null != project && project!.isNotEmpty) {
      url += '&project=${uriescape(project!)}';
    }
    if (null != config && config!.isNotEmpty) {
      url += '&config=${uriescape(config!)}';
    }

    final res = await fetchjson('GET', url,
        headers: {'authorization': 'Bearer ${token ?? ''}'});

    final body = res.body.asobj;
    if (200 != res.status || null == body) {
      throw SekretoError('sekreto: doppler error: ${res.status}');
    }

    final loaded = <String, String>{};
    body.forEach((key, value) {
      // A null value is not a secret; it is a declared name with nothing
      // behind it.
      final text = value.text;
      if (null != text) {
        loaded[key] = text;
      }
    });

    // Only a successful load is remembered, so a failure retries.
    _values = loaded;
    return loaded;
  }

  @override
  String describe() {
    if (null != project && project!.isNotEmpty) {
      return 'doppler:$project/${config ?? ''}';
    }
    return 'doppler';
  }
}

/// Infisical.
///
/// `api.token` reads the secret keyed `API_TOKEN` (Infisical's own
/// convention is environment-style keys) at a secret path in one environment
/// of a project. Auth is a token, or a universal-auth (machine identity)
/// login with clientid/clientsecret.
class Infisical extends Provider {
  final String? addr;
  final String? token;
  final String? clientid;
  final String? clientsecret;
  final String? project;
  final String? environment;
  final String? path;

  // A configured token is kept forever; a universal-auth token carries
  // expiresIn and is renewed shortly before it runs out.
  String? _livetoken;
  int _renewat = NEVER;

  Infisical({
    this.addr,
    this.token,
    this.clientid,
    this.clientsecret,
    this.project,
    this.environment,
    this.path,
  });

  Future<String> _login(String useaddr) async {
    if (null != token && token!.isNotEmpty) {
      return token!;
    }

    if (null == clientid ||
        clientid!.isEmpty ||
        null == clientsecret ||
        clientsecret!.isEmpty) {
      throw SekretoError(
        'sekreto: infisical: no token and no client credentials',
      );
    }

    final body = JsonObj({
      'clientId': JsonStr(clientid!),
      'clientSecret': JsonStr(clientsecret!),
    });

    final res = await fetchjson(
      'POST',
      '$useaddr/api/v1/auth/universal-auth/login',
      headers: {'content-type': 'application/json'},
      body: jsonstringify(body),
    );

    final got = res.body.dig('accessToken').text;
    if (200 != res.status || null == got || got.isEmpty) {
      throw SekretoError('sekreto: infisical login failed: ${res.status}');
    }

    // camelCase, unlike everyone else's expires_in.
    _renewat = renewtime(res.body.dig('expiresIn'));

    return got;
  }

  @override
  FutureOr<String?> lookup(String name) {
    final useaddr = trimslash(first([addr, 'https://app.infisical.com']));
    checkaddr(useaddr);

    final useproject = project ?? '';
    final useenvironment = environment ?? '';
    if (useproject.isEmpty || useenvironment.isEmpty) {
      throw SekretoError('sekreto: infisical: no project/environment');
    }

    return _read(useaddr, useproject, useenvironment, name);
  }

  Future<String?> _read(
    String useaddr,
    String useproject,
    String useenvironment,
    String name,
  ) async {
    if (null == _livetoken || DateTime.now().millisecondsSinceEpoch >= _renewat) {
      _livetoken = await _login(useaddr);
    }

    final url = '$useaddr/api/v3/secrets/raw/${envkey(name)}'
        '?workspaceId=${uriescape(useproject)}'
        '&environment=${uriescape(useenvironment)}'
        '&secretPath=${uriescape(first([path, '/']))}';

    final res = await fetchjson('GET', url,
        headers: {'authorization': 'Bearer ${_livetoken ?? ''}'});

    if (404 == res.status) {
      return null;
    }
    if (200 != res.status) {
      throw SekretoError('sekreto: infisical error: ${res.status}');
    }

    return res.body.dig('secret', 'secretValue').text;
  }

  @override
  String describe() => 'infisical:${project ?? ''}/${environment ?? ''}';
}

/// Build a provider from its declarative form - the same shape the shared
/// spec and an app's config file use.
Provider makeprovider(ProviderSpec spec) {
  switch (spec.kind) {
    case 'env':
      return Env(prefix: spec.prefix);

    case 'dotenv':
      return Dotenv(spec.file ?? '.env', prefix: spec.prefix);

    case 'memory':
      return Memory(source: spec.values, prefix: spec.prefix);

    case 'file':
      return SecretFile(spec.dir ?? '', prefix: spec.prefix);

    case 'hashicorp':
      return Hashicorp(
        spec.addr ?? '',
        token: spec.token,
        mount: spec.mount,
        kv: spec.kv,
        vaultnamespace: spec.vaultnamespace,
        auth: spec.auth,
      );

    case 'boru':
      return Boru(
        command: spec.command,
        namespace: spec.namespace,
        home: spec.home,
        addr: spec.addr,
        token: spec.token,
        mount: spec.mount,
      );

    case 'awssecrets':
      return Awssecrets(
        region: spec.region,
        keyid: spec.keyid,
        secret: spec.secret,
        session: spec.session,
        addr: spec.addr,
      );

    case 'awsparams':
      return Awsparams(
        region: spec.region,
        keyid: spec.keyid,
        secret: spec.secret,
        session: spec.session,
        addr: spec.addr,
        prefix: spec.prefix,
      );

    case 'gcpsecrets':
      return Gcpsecrets(
        project: spec.project,
        token: spec.token,
        addr: spec.addr,
        metadataaddr: spec.metadataaddr,
      );

    case 'azuresecrets':
      return Azuresecrets(
        vault: spec.vault,
        token: spec.token,
        tenant: spec.tenant,
        clientid: spec.clientid,
        clientsecret: spec.clientsecret,
        loginaddr: spec.loginaddr,
        imdsaddr: spec.imdsaddr,
        apiversion: spec.apiversion,
      );

    case 'onepassword':
      return Onepassword(
        addr: spec.addr,
        token: spec.token,
        vault: spec.vault,
      );

    case 'doppler':
      return Doppler(
        token: spec.token,
        project: spec.project,
        config: spec.config,
        addr: spec.addr,
      );

    case 'infisical':
      return Infisical(
        addr: spec.addr,
        token: spec.token,
        clientid: spec.clientid,
        clientsecret: spec.clientsecret,
        project: spec.project,
        environment: spec.environment,
        path: spec.path,
      );

    case 'secretspec':
      return Secretspec(
        command: spec.command,
        file: spec.file,
        profile: spec.profile,
        backend: spec.backend,
        reason: spec.reason,
        prefix: spec.prefix,
      );

    default:
      throw SekretoError('sekreto: unknown provider kind: ${spec.kind}');
  }
}
