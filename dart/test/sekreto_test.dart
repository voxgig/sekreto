// RUN: make test
// RUN-SOME: dart run --packages=build/package_config.json \
//               test/sekreto_test.dart envkey
//
// The sekreto conformance suite. Every port runs these same groups, from
// the same spec/sekreto.json, through its own voxgig/omni runner.
//
// No third-party test framework: a failing omni check throws OmniError, and
// the forty lines below are all the harness that needs, which is what keeps
// `make test` dependency-free. This is the only file in the port that may
// name voxgig/omni; the library and the CLI never do.

import 'dart:async';
import 'dart:io';

import 'package:voxgig_omni/omni.dart';

import '../src/sekreto.dart';
import '../src/spec.dart';

// THE FULL SET, and the AWS signer with it. A conformance suite is exactly
// the caller the full set exists for: the spec's chain groups name kinds
// this file does not choose, so every chain it builds is handed every
// plugin. That is also why this suite CANNOT SEE the split - it is only
// ever exercising the one consumer that gets the plugin list right - and
// why test/plugins_test.dart exists.
import '../plugins/plugins.dart';

String? only;
int passcount = 0;
int failcount = 0;

/// Find the shared spec directory by walking up from the working directory.
String specfile(String name) {
  var dir = Directory.current.absolute.path;

  for (var step = 0; step < 8; step++) {
    final candidate = '$dir/spec/$name';
    if (File(candidate).existsSync()) {
      return candidate;
    }

    final parent = Directory(dir).parent.path;
    if (parent == dir) {
      break;
    }
    dir = parent;
  }

  throw OmniError('sekreto: spec not found: $name');
}

// ------------------------------------------------------------ the bridge

/// The chain groups are all local stores, so every read completes without
/// yielding. A Future here would mean a subject reached the network, which
/// no spec entry does - so it is reported as a failure rather than silently
/// compared as an object.
T settled<T>(FutureOr<T> value) {
  if (value is Future) {
    throw OmniError('sekreto: chain answered asynchronously');
  }
  return value;
}

String? asstr(dynamic value) => value is String ? value : null;

/// A `values` map, with every value as the text the store would hold.
Map<String, String>? valuesof(dynamic value) {
  if (value is! Map) {
    return null;
  }

  final out = <String, String>{};
  value.forEach((key, entry) => out['$key'] = stringify(entry));
  return out;
}

/// One provider spec, out of the spec's declarative chain description.
ProviderSpec specof(dynamic entry) {
  final source = entry is Map ? entry : const {};

  final rawauth = source['auth'];
  final auth = rawauth is Map
      ? AuthSpec(
          method: asstr(rawauth['method']) ?? '',
          mount: asstr(rawauth['mount']),
          role: asstr(rawauth['role']),
          jwt: asstr(rawauth['jwt']),
          jwtfile: asstr(rawauth['jwtfile']),
          roleid: asstr(rawauth['roleid']),
          secretid: asstr(rawauth['secretid']),
        )
      : null;

  final kv = source['kv'];

  return ProviderSpec(
    kind: asstr(source['kind']) ?? '',
    name: asstr(source['name']),
    prefix: asstr(source['prefix']),
    file: asstr(source['file']),
    values: valuesof(source['values']),
    dir: asstr(source['dir']),
    addr: asstr(source['addr']),
    token: asstr(source['token']),
    mount: asstr(source['mount']),
    kv: isnum(kv) ? (kv as num).toInt() : null,
    vaultnamespace: asstr(source['vaultnamespace']),
    auth: auth,
    command: asstr(source['command']),
    profile: asstr(source['profile']),
    backend: asstr(source['backend']),
    reason: asstr(source['reason']),
    namespace: asstr(source['namespace']),
    home: asstr(source['home']),
    region: asstr(source['region']),
    keyid: asstr(source['keyid']),
    secret: asstr(source['secret']),
    session: asstr(source['session']),
    project: asstr(source['project']),
    vault: asstr(source['vault']),
    tenant: asstr(source['tenant']),
    clientid: asstr(source['clientid']),
    clientsecret: asstr(source['clientsecret']),
    loginaddr: asstr(source['loginaddr']),
    imdsaddr: asstr(source['imdsaddr']),
    metadataaddr: asstr(source['metadataaddr']),
    apiversion: asstr(source['apiversion']),
    config: asstr(source['config']),
    environment: asstr(source['environment']),
    path: asstr(source['path']),
  );
}

/// Build a Sekreto from the spec's declarative chain description.
///
/// Built INSIDE the subject, deliberately. Four entries expect
/// `unsupported kv version`, which a constructor raises, and only a chain
/// built here delivers that to omni as a subject error rather than as a
/// crash before the run starts.
///
/// EVERY PLUGIN IS HANDED TO EVERY CHAIN. The spec's chain groups name
/// hashicorp, boru and eight more as well as the four built-in kinds, and a
/// conformance suite may not choose which of them a case gets - so it
/// passes the full set. That is exactly why the split is invisible here:
/// the CLI's own plugin list, the refusal a consumer meets, and the import
/// graph are all somebody else's, and test/plugins_test.dart pins them.
///
/// Caching off: each entry is its own chain, and a cache would only hide a
/// provider that was asked twice.
Sekreto chainof(dynamic entry) {
  final source = entry is Map ? entry : const {};
  final chain = source['chain'];

  final specs = <ProviderSpec>[];
  if (chain is List) {
    for (final spec in chain) {
      specs.add(specof(spec));
    }
  }

  return sekreto(specs, plugins: allplugins, cache: false);
}

String nameof(dynamic entry) =>
    asstr(entry is Map ? entry['name'] : null) ?? '';

String storeof(dynamic entry) =>
    asstr(entry is Map ? entry['store'] : null) ?? '';

// ----------------------------------------------------------- the subjects

// `validname` answers whatever the language calls true; the spec says JSON
// true, and in Dart those are the same value - so the adaptation is nothing
// here, but it still belongs in the test rather than in the library.
dynamic VALIDNAME(List<dynamic> args) => validname(args[0]);

dynamic ENVKEY(List<dynamic> args) {
  final entry = args[0] as Map;
  return envkey(entry['name'], asstr(entry['prefix']));
}

dynamic VAULTREF(List<dynamic> args) {
  final ref = vaultref(args[0]);
  return {'path': ref.path, 'field': ref.field};
}

dynamic FLATNAME(List<dynamic> args) {
  final entry = args[0] as Map;
  return flatname(entry['name'], asstr(entry['sep']) ?? '');
}

dynamic AWSPARAM(List<dynamic> args) {
  final entry = args[0] as Map;
  return awsparam(entry['name'], asstr(entry['prefix']));
}

dynamic PARSEDOTENV(List<dynamic> args) => parsedotenv(args[0]);

dynamic RESOLVE(List<dynamic> args) =>
    settled(chainof(args[0]).get(nameof(args[0])));

dynamic TRYSECRET(List<dynamic> args) =>
    settled(chainof(args[0]).tryget(nameof(args[0])));

dynamic SOURCES(List<dynamic> args) => chainof(args[0]).sources();

dynamic STORES(List<dynamic> args) => chainof(args[0]).stores();

dynamic GETFROM(List<dynamic> args) =>
    settled(chainof(args[0]).getfrom(storeof(args[0]), nameof(args[0])));

dynamic TRYFROM(List<dynamic> args) =>
    settled(chainof(args[0]).tryfrom(storeof(args[0]), nameof(args[0])));

// Answers the ordered output map itself, which omni compares as a JSON
// object against the spec's known-answer signatures.
dynamic SIGV4(List<dynamic> args) {
  final entry = args[0] as Map;
  final headers = <String, String>{};

  final given = entry['headers'];
  if (given is Map) {
    given.forEach((key, value) => headers['$key'] = stringify(value));
  }

  return sigv4(Signing(
    method: asstr(entry['method']) ?? '',
    url: asstr(entry['url']) ?? '',
    service: asstr(entry['service']) ?? '',
    region: asstr(entry['region']) ?? '',
    keyid: asstr(entry['keyid']) ?? '',
    secret: asstr(entry['secret']) ?? '',
    datetime: asstr(entry['datetime']) ?? '',
    headers: headers,
    body: asstr(entry['body']) ?? '',
    session: asstr(entry['session']),
  ));
}

dynamic REDACT(List<dynamic> args) {
  final entry = args[0] as Map;
  final values = entry['values'];
  return redact(entry['text'], values is List ? values : null);
}

// ------------------------------------------------------------ the runner

void testcase(String name, void Function() body) {
  if (null != only && name != only) {
    return;
  }

  try {
    body();
    passcount++;
    print('ok   - $name');
  } catch (err) {
    failcount++;
    print('FAIL - $name');
    print(errmessage(err));
  }
}

void main(List<String> args) {
  if (args.isNotEmpty) {
    only = args[0];
  }

  final R = makeRunner(specfile('sekreto.json')).runner('sekreto');

  testcase('validname',
      () => R.runsetflags(R.set('validname'), Flags.nonull, VALIDNAME));
  testcase('envkey', () => R.runset(R.set('envkey'), ENVKEY));
  testcase('vaultref', () => R.runset(R.set('vaultref'), VAULTREF));
  testcase('flatname', () => R.runset(R.set('flatname'), FLATNAME));
  testcase('awsparam', () => R.runset(R.set('awsparam'), AWSPARAM));
  testcase('parsedotenv', () => R.runset(R.set('parsedotenv'), PARSEDOTENV));
  testcase('resolve', () => R.runset(R.set('resolve'), RESOLVE));
  testcase('trysecret', () => R.runset(R.set('trysecret'), TRYSECRET));
  testcase('sources', () => R.runset(R.set('sources'), SOURCES));
  testcase('stores', () => R.runset(R.set('stores'), STORES));
  testcase('getfrom', () => R.runset(R.set('getfrom'), GETFROM));
  testcase('tryfrom', () => R.runset(R.set('tryfrom'), TRYFROM));
  testcase('sigv4', () => R.runset(R.set('sigv4'), SIGV4));
  testcase('redact', () => R.runset(R.set('redact'), REDACT));

  print('\n$passcount passed, $failcount failed');

  exit(0 == failcount ? 0 : 1);
}
