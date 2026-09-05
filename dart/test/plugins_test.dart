// RUN: make seam
// RUN-SOME: dart run --packages=build/package_config.json \
//               test/plugins_test.dart "a store name must be a valid tag"
//
// THE PLUGIN SEAM, from both sides.
//
// Moving the provider kinds that open sockets and spawn processes out of
// the core made a consumer's PLUGIN LIST load-bearing: a kind nobody passed
// in is not in the catalog, and a chain naming it is refused. That is the
// intended behaviour, and it means a CONSUMER can be broken without a
// single conformance test noticing - the conformance suite hands the full
// set to every chain it builds, so it is only ever testing the one
// consumer that gets it right. So the full set is pinned here: it holds
// every kind, every kind builds, and the CLI passes it.
//
// It happened immediately, in the previous shape of this split: the
// canonical CLI's only reference to the full set was a TYPE import, which
// the compiler erased, and every kind but env and memory failed in the
// integration suite while `make test` stayed green.
//
// THE DART HALF OF THE SEAM IS THE IMPORT GRAPH, so the four boundary tests
// below work on the COMPILER'S OWN DEPENDENCY LISTING rather than on the
// source. `dart compile kernel --depfile` writes a ninja depfile naming
// every file that went into a compilation - this language's link map - and
// a probe entry point is compiled for the core, for one plugin, for the aws
// plugin and for the full set. A relative import, a package import, an
// export: anything the compiler follows is in that list, which is what
// makes these statements about the artifact rather than about the source.
//
// A translation of python/tests/test_plugins.py, which is the model.

import 'dart:async';
import 'dart:io';

import '../src/providers.dart';
import '../src/provider.dart';
import '../src/sekreto.dart';
import '../src/spec.dart';
import '../src/support.dart';

import 'package:voxgig_plugin/plugin.dart' show PluginError;

// BOTH SPELLINGS ON PURPOSE. `plugins.dart` is the full set, which a CLI or
// a harness takes; `hashicorp.dart` is one plugin, which a lean consumer
// takes - and the boundary tests below compile a probe for each and compare
// what the compiler actually pulled in.
import '../plugins/hashicorp.dart' show hashicorp;
import '../plugins/plugins.dart' show allplugins;

const List<String> PLUGINS = [
  'awsparams', 'awssecrets', 'azuresecrets', 'boru', 'doppler', 'gcpsecrets',
  'hashicorp', 'infisical', 'onepassword', 'secretspec',
];

final List<String> EVERY =
    ([...KINDS.builtin, ...PLUGINS]..sort()).toList(growable: false);

/// The package map `make` wrote for the LIBRARY: voxgig/plugin, and nothing
/// else. The probe compilations below are given the same one, because the
/// port's own files reach each other by relative import - so a probe needs
/// no more of a classpath than the library does.
const String PKG = 'build/package_config.json';

// --------------------------------------------------------- the harness

String? only;
int passcount = 0;
int failcount = 0;

class Failed implements Exception {
  final String message;
  Failed(this.message);
  @override
  String toString() => message;
}

void testcase(String name, void Function() body) {
  final filter = only;
  if (null != filter && name != filter) {
    return;
  }

  try {
    body();
    passcount++;
    print('ok   - $name');
  } catch (err) {
    failcount++;
    print('FAIL - $name');
    print('       ${'$err'.replaceAll('\n', '\n       ')}');
  }
}

void eq(Object? want, Object? got, [String what = '']) {
  if ('$want' != '$got') {
    throw Failed('$what\n  want: $want\n  got:  $got');
  }
}

void ok(String what, bool condition) {
  if (!condition) {
    throw Failed(what);
  }
}

/// The message of the SekretoError [body] must raise.
String refusal(void Function() body) {
  try {
    body();
  } on SekretoError catch (err) {
    return err.message;
  }

  throw Failed('no SekretoError was raised');
}

/// A chain of local stores answers without yielding. A Future here would
/// mean a subject reached the network, which nothing below does.
T settled<T>(FutureOr<T> value) {
  if (value is Future) {
    throw Failed('the chain answered asynchronously');
  }
  return value;
}

// -------------------------------------------------- the dependency graph

/// What compiling [source] actually pulls in, as the compiler reports it.
///
/// The probe is written into `build/probe/`, compiled to a kernel, and the
/// `--depfile` it is asked for is read back: a ninja depfile whose one rule
/// names the output and then every source that went into it. Only this
/// port's own files are kept - the SDK's and voxgig/plugin's are not what is
/// being asked about - and the probe itself is dropped.
List<String> graph(String label, String source) {
  final root = Directory.current.path;
  final dir = Directory('build/probe')..createSync(recursive: true);

  final entry = '${dir.path}/$label.dart';
  File(entry).writeAsStringSync(source);

  final dep = '${dir.path}/$label.d';

  final ran = Process.runSync(Platform.resolvedExecutable, [
    'compile', 'kernel', '--packages=$PKG', entry,
    '-o', '${dir.path}/$label.dill', '--depfile=$dep',
  ]);

  if (0 != ran.exitCode) {
    throw Failed('the probe did not compile:\n${ran.stdout}\n${ran.stderr}');
  }

  final listing = File(dep).readAsStringSync().split(RegExp(r'\s+'));
  final out = <String>[];

  for (final raw in listing) {
    if (!raw.startsWith('$root/') || !raw.endsWith('.dart')) {
      continue;
    }
    final file = raw.substring(root.length + 1);
    if (file.startsWith('build/')) {
      continue;
    }
    out.add(file);
  }

  out.sort();
  return out;
}

List<String> under(List<String> files, String dir) =>
    files.where((file) => file.startsWith('$dir/')).toList();

// --------------------------------------------------------- a custom kind

/// A provider kind an application might write for itself: everything a
/// custom kind needs is a class and one `providerplugin` call.
class Shouty extends Provider {
  final Map<String, String> values;
  Shouty(this.values);

  @override
  String? lookup(String name) => values[name.toUpperCase()];

  @override
  String describe() => 'shouty';
}

class Replaced extends Provider {
  @override
  String lookup(String name) => 'replaced';

  @override
  String describe() => 'memory';
}

// ----------------------------------------------------------- the subjects

void main(List<String> args) {
  if (args.isNotEmpty) {
    only = args[0];
  }

  // ------------------------------------------------------- the full set

  testcase('the full set holds every kind', () {
    eq(PLUGINS, (allplugins.map((d) => d['name'] as String).toList()..sort()),
        'allplugins');
    eq(KINDS.builtin, BUILTINS.map((d) => d['name'] as String).toList(),
        'BUILTINS');
    eq(PLUGINS, ([...KINDS.plugin]..sort()), 'KINDS.plugin');
    eq(10, allplugins.length, 'ten plugins');
  });

  // Naming a kind is not enough: a kind can be in the catalog and still fail
  // to build. Construction is what the CLI does before any network.
  testcase('every kind builds from a spec', () {
    final chain = EVERY
        .map((kind) => ProviderSpec(
              kind: kind,
              addr: 'http://127.0.0.1:8200',
              token: 't',
              dir: '/tmp',
              file: '/tmp/.env',
              values: const {},
            ))
        .toList();

    final secrets = sekreto(chain, plugins: allplugins);

    eq(EVERY, secrets.stores(), 'stores');
    eq(EVERY, (secrets.host.list().keys.toList()..sort()), 'host.list');
    eq({'live'}, secrets.host.list().values.toSet(), 'every instance live');
    secrets.close();
  });

  testcase('the CLI passes the full set', () {
    final source = File('cli/cli.dart').readAsStringSync();

    ok('cli.dart imports the full set',
        source.contains("import '../plugins/plugins.dart';"));
    // THE CALL SITE, closing bracket included. `contains('plugins:
    // allplugins')` is satisfied by `plugins: allplugins.sublist(0, 1)`,
    // which is a CLI carrying one kind - the exact failure this file
    // exists to catch, passing the test meant to catch it.
    ok('cli.dart passes the full set',
        source.contains('plugins: allplugins)'));
  });

  // --------------------------------------------------- what a consumer sees

  testcase('one plugin is enough for a chain that names only it', () {
    final secrets = sekreto(
      [
        ProviderSpec(kind: 'memory', values: {'API_TOKEN': 'tok01'}),
        ProviderSpec(
          kind: 'hashicorp',
          name: 'prod',
          addr: 'https://vault.example.com',
          token: 't',
        ),
      ],
      plugins: [hashicorp],
    );

    eq(['memory', 'prod'], secrets.stores(), 'stores');
    eq(['memory', 'hashicorp:https://vault.example.com/secret'],
        secrets.sources(), 'sources');
    eq('tok01', settled(secrets.get('api.token')), 'the chain answers');

    // The plugin host is what the chain is made of, and it reads like the
    // chain: the kind, or kind$store for a named store.
    eq({r'hashicorp$prod': 'live', 'memory': 'live'}, secrets.host.list(),
        'host.list');
    eq(['dotenv', 'env', 'file', 'hashicorp', 'memory'],
        secrets.catalog.names(), 'catalog');
    secrets.close();
  });

  // ONE CATALOG, HELD TWICE. `Sekreto` is a factory rather than a
  // generative constructor precisely because an initializer list cannot
  // share a value between two fields: `catalog` and the host's catalog
  // would be built separately, agree at construction, and diverge the
  // moment either gained a definition. Nothing else in this file can see
  // the difference - two catalogs built from the same list answer every
  // other question identically - so it is asserted directly.
  testcase('the catalog the host loads from is the catalog Sekreto checks',
      () {
    final secrets = sekreto([], plugins: [hashicorp]);

    ok('Sekreto.catalog and host.catalog are one object',
        identical(secrets.catalog, secrets.host.catalog));

    // ...and the observable consequence: a definition added to the host
    // after construction is a kind this Sekreto can build.
    secrets.host.define(providerplugin('late', (spec) => Shouty(const {})));
    ok('a late definition is in Sekreto.catalog: ${secrets.catalog.names()}',
        secrets.catalog.has('late'));
    secrets.close();
  });

  testcase('a kind that was not passed in is refused, naming the fix', () {
    eq(
      'sekreto: unknown provider kind: doppler'
          ' (available: dotenv, env, file, hashicorp, memory)'
          ' - doppler is a sekreto plugin, not built in:'
          ' pass it in the plugins option',
      refusal(() => sekreto([ProviderSpec(kind: 'doppler', token: 't')],
          plugins: [hashicorp])),
      'a plugin that was not passed',
    );

    // A kind nobody ships is a typo, and gets no such hint.
    eq(
      'sekreto: unknown provider kind: vualt'
          ' (available: dotenv, env, file, memory)',
      refusal(() => sekreto([ProviderSpec(kind: 'vualt')])),
      'a typo',
    );
  });

  // Two providers MAY share a store name - a directed read walks both, and
  // the spec pins it - but an instance ref may not, so the second gets a
  // numbered tag from the host and keeps its store name.
  testcase('a repeated store name keeps the store and numbers the instance',
      () {
    final secrets = sekreto([
      ProviderSpec(kind: 'memory', values: const {}),
      ProviderSpec(kind: 'memory', values: {'API_TOKEN': 'second'}),
      ProviderSpec(kind: 'memory', name: 'pair', values: const {}),
      ProviderSpec(kind: 'memory', name: 'pair', values: {'API_TOKEN': 'pair2'}),
    ]);

    eq(['memory', 'pair'], secrets.stores(), 'stores');
    eq([r'memory', r'memory$1', r'memory$2', r'memory$pair'],
        secrets.host.list().keys.toList(), 'host.list');
    eq('second', settled(secrets.getfrom('memory', 'api.token')),
        'the second memory answers');
    eq('pair2', settled(secrets.getfrom('pair', 'api.token')),
        'the second pair answers');
    secrets.close();
  });

  testcase('a store name must be a valid tag', () {
    eq(
      'sekreto: invalid store name: my store',
      refusal(() => sekreto([
            ProviderSpec(kind: 'memory', name: 'my store', values: const {}),
          ])),
    );
  });

  // A provider that refuses its own configuration raises a SekretoError from
  // inside the plugin's `define`. The spec pins that message byte for byte,
  // so it must come back out of the host as itself - not wrapped as
  // plugin_define_failed, and not as a PluginError.
  testcase('a SekretoError raised in define comes back out as itself', () {
    eq(
      'sekreto: hashicorp: unsupported kv version: 3',
      refusal(() => sekreto(
            [
              ProviderSpec(
                kind: 'hashicorp',
                addr: 'http://127.0.0.1:1',
                token: 't',
                kv: 3,
              ),
            ],
            plugins: [hashicorp],
          )),
    );
  });

  // ...and any other error is not sekreto's to rewrite: it surfaces as the
  // host reports it, naming the instance and the cause.
  testcase("any other error raised in define is the host's report of it", () {
    final broken =
        providerplugin('broken', (spec) => throw StateError('boom'));

    Object? caught;
    try {
      sekreto([ProviderSpec(kind: 'broken')], plugins: [broken]);
    } catch (err) {
      caught = err;
    }

    ok('a PluginError was raised, not $caught', caught is PluginError);
    final err = caught as PluginError;
    eq('plugin_define_failed', err.code, 'code');
    ok('names the cause: ${err.message}', err.message.contains('boom'));
    ok('names the instance: ${err.message}', err.message.contains('broken'));
  });

  testcase('a custom kind is one providerplugin call', () {
    final shouty =
        providerplugin('shouty', (spec) => Shouty(spec.values ?? const {}));

    final secrets = sekreto(
      [ProviderSpec(kind: 'shouty', values: {'API.TOKEN': 'loud'})],
      plugins: [shouty],
    );

    eq('loud', settled(secrets.get('api.token')), 'the custom kind answers');
    eq({'shouty': 'live'}, secrets.host.list(), 'host.list');
    secrets.close();
  });

  // A plugin that names a built-in kind replaces it: that is how a host
  // substitutes an implementation, and never an accident, because the four
  // names are documented.
  testcase('a plugin may replace a built-in kind', () {
    final secrets = sekreto(
      [ProviderSpec(kind: 'memory', values: {'API_TOKEN': 'original'})],
      plugins: [providerplugin('memory', (spec) => Replaced())],
    );

    eq('replaced', settled(secrets.get('api.token')));
    eq(4, secrets.catalog.names().length, 'still four kinds');
    secrets.close();
  });

  testcase('close tears the chain down and keeps redaction', () {
    final secrets = sekreto(
      [ProviderSpec(kind: 'memory', values: {'API_TOKEN': 'tok01'})],
    );

    eq('tok01', settled(secrets.get('api.token')));

    secrets.close();

    eq(0, secrets.host.list().length, 'the host is empty');
    eq(<String>[], secrets.stores(), 'no stores');
    eq(null, settled(secrets.tryget('api.token')), 'nothing answers');
    eq('token=[redacted]', secrets.redact('token=tok01'),
        'redaction survives');
  });

  // Dart's shape of python's "a module passed as a plugin is refused": a
  // library is not a value here, so the mistake a consumer actually makes is
  // passing the provider, the factory, or the kind's NAME where the
  // definition belongs. Refused by sekreto rather than deep inside
  // voxgig/plugin, which would report it as `plugin_definition_name`.
  testcase('a plugin that is not a definition is refused', () {
    eq('sekreto: not a plugin definition: hashicorp',
        refusal(() => sekreto([], plugins: ['hashicorp'])), 'a name');

    // The mistake dart actually invites: each plugin file exports the
    // provider AND the definition, one letter apart.
    eq(
        'sekreto: not a plugin definition: a provider (shouty)'
            ' - a definition builds a provider rather than being one:'
            ' pass the definition instead',
        refusal(() => sekreto([], plugins: [Shouty(const {})])), 'a provider');

    // A map that is a map and nothing else: no `name`, so no kind.
    eq('sekreto: not a plugin definition: {define: null}',
        refusal(() => sekreto([], plugins: [
              <String, dynamic>{'define': null}
            ])),
        'a map with no name');
  });

  // A definition that is not a `providerplugin` - one whose `define` exports
  // no provider. plugin runs a `define` that is not a function SILENTLY (its
  // `_run` returns when the callback is not a Function), so without this
  // check the chain would carry a hole and the first lookup would blame the
  // wrong thing.
  testcase('a definition that exports no provider is refused', () {
    eq(
      'sekreto: plugin shouty exported no provider',
      refusal(() => sekreto([ProviderSpec(kind: 'shouty')], plugins: [
            <String, dynamic>{'name': 'shouty'}
          ])),
    );
  });

  // The spec crosses the boundary as plugin's own value model - a map of
  // strings to null, num, String and Map - and comes back typed. A field
  // added to `optionsof` and forgotten in `specof` would be lost in silence,
  // and only for the kinds no conformance case exercises.
  testcase('a provider spec survives the plugin boundary', () {
    final full = ProviderSpec(
      kind: 'hashicorp', name: 'prod', prefix: 'P_', file: 'f', dir: 'd',
      values: const {'A': '1'}, addr: 'https://a', token: 't', mount: 'm',
      kv: 1, vaultnamespace: 'ns',
      auth: AuthSpec(
        method: 'approle', mount: 'am', role: 'r', jwt: 'j',
        jwtfile: 'jf', roleid: 'ri', secretid: 'si',
      ),
      command: 'c', profile: 'pr', backend: 'b', reason: 're',
      namespace: 'n', home: 'h', region: 'eu', keyid: 'k', secret: 's',
      session: 'se', project: 'pj', vault: 'v', tenant: 'tn',
      clientid: 'ci', clientsecret: 'cs', loginaddr: 'la', imdsaddr: 'ia',
      metadataaddr: 'ma', apiversion: '7.4', config: 'cf',
      environment: 'dev', path: '/p',
    );

    final crossed = optionsof(full);
    final back = specof(crossed);

    // Field by field, because ProviderSpec.toString() deliberately hides the
    // credentials - so comparing the printed form would compare `[set]` with
    // `[set]` and pass whatever the token became.
    eq(optionsof(full).toString(), optionsof(back).toString(),
        'the round trip');

    // Every field is set above, so nothing may be missing from the options
    // either - a field dropped from BOTH sides would round trip and still be
    // gone.
    eq(34, crossed.length, 'every ProviderSpec field crossed');
    eq(7, (crossed['auth'] as Map).length, 'every AuthSpec field crossed');
  });

  // ------------------------------------------------------- the boundary

  // THE CORE IMPORTS NO PLUGIN. Not the module, not the full set, not a name
  // the compiler would follow: compiling the core pulls in the chain, the
  // built-ins and voxgig/plugin, and not one file under plugins/.
  testcase('the core imports no plugin', () {
    final loaded = graph('core', "import '../../src/sekreto.dart';\n"
        "void main() { sekreto(const []); }\n");

    eq(<String>[], under(loaded, 'plugins'), 'the core reached a plugin');
    eq([
      'src/provider.dart',
      'src/providers.dart',
      'src/sekreto.dart',
      'src/spec.dart',
      'src/support.dart',
    ], loaded, 'what compiling the core pulls in');
  });

  // ...and one plugin imports only itself. The full set is one file, and a
  // single-plugin import must not reach it: through that file, one plugin
  // makes every other reachable too - AWS request signing, SHA-256 and eight
  // HTTP vault clients, for a consumer that named exactly one.
  testcase('one plugin imports only itself', () {
    final loaded = graph('one', "import '../../plugins/hashicorp.dart';\n"
        'void main() { print(hashicorp["name"]); }\n');

    eq(['plugins/hashicorp.dart', 'plugins/httpjson.dart'],
        under(loaded, 'plugins'), 'the plugin files reached');

    for (final other in [
      'plugins', 'aws', 'sigv4', 'crypto', 'boru', 'doppler', 'gcpsecrets',
      'azuresecrets', 'onepassword', 'infisical', 'secretspec',
    ]) {
      ok('importing one plugin reached plugins/$other.dart',
          !loaded.contains('plugins/$other.dart'));
    }
  });

  // ...and the signer is the aws plugin's own business. Percent-escaping
  // lives with the transport rather than in `sigv4.dart` precisely so that
  // the four kinds which only escape a query parameter do not compile a
  // hash function to get one - a claim about the artifact, so the compiler
  // is asked rather than the reader.
  testcase('only the aws plugin compiles the signer', () {
    final azure = graph('azure', "import '../../plugins/azuresecrets.dart';\n"
        'void main() { print(azuresecrets["name"]); }\n');

    eq(['plugins/azuresecrets.dart', 'plugins/httpjson.dart'],
        under(azure, 'plugins'), 'azuresecrets');

    final aws = graph('aws', "import '../../plugins/aws.dart';\n"
        'void main() { print(awssecrets["name"]); }\n');

    eq([
      'plugins/aws.dart',
      'plugins/crypto.dart',
      'plugins/httpjson.dart',
      'plugins/sigv4.dart',
    ], under(aws, 'plugins'), 'aws');
  });

  // The full set is what pulls all ten in, and reaching for it is the
  // deliberate act of a CLI or a test harness rather than a side effect of
  // importing the library.
  testcase('the full set is built on demand', () {
    final loaded = graph('all', "import '../../plugins/plugins.dart';\n"
        'void main() { print(allplugins.length); }\n');

    eq([
      'plugins/aws.dart',
      'plugins/azuresecrets.dart',
      'plugins/boru.dart',
      'plugins/crypto.dart',
      'plugins/doppler.dart',
      'plugins/gcpsecrets.dart',
      'plugins/hashicorp.dart',
      'plugins/httpjson.dart',
      'plugins/infisical.dart',
      'plugins/onepassword.dart',
      'plugins/plugins.dart',
      'plugins/secretspec.dart',
      'plugins/sigv4.dart',
    ], under(loaded, 'plugins'), 'the full set pulls in every plugin file');
  });

  print('\n$passcount passed, $failcount failed');

  exit(0 == failcount ? 0 : 1);
}
