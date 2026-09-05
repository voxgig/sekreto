// RUN: make check-core
//
// THE CORE, COMPILED AND RUN WITH THE PLUGINS ABSENT.
//
// This file is compiled against `build/core_config.json`, a package map
// holding voxgig/plugin and NOTHING ELSE, and the compiler is asked for its
// own dependency listing while it does it. So the proof is the compiler's
// rather than a reviewer's:
//
//   - a chain of the four built-in kinds must work with no plugin imported
//     anywhere, which is the promise the split makes to an app whose chain
//     is [dotenv, env];
//   - the listing `--depfile` writes names every source that went into the
//     binary, and `corecheck.sh` fails if one of them is under `plugins/`;
//   - and a plugin kind is refused HERE TOO, naming the fix - the core
//     knows the ten plugin names without importing one of them, because
//     KINDS.plugin is a list of strings.
//
// It is the dart analogue of python's `test_the_core_imports_no_plugin` (a
// fresh interpreter listing sys.modules), of javascript's require.cache
// graph, and of go's linking boundary.

import 'dart:io';

import '../src/providers.dart';
import '../src/sekreto.dart';
import '../src/spec.dart';

int failed = 0;

void check(String what, bool ok) {
  if (ok) {
    print('ok   - $what');
  } else {
    failed++;
    print('FAIL - $what');
  }
}

void checkeq(String what, Object? want, Object? got) {
  final ok = '$want' == '$got';
  check(ok ? what : '$what (want $want, got $got)', ok);
}

void main() {
  final dir = Directory('${Directory.systemTemp.path}/sekreto-coreonly');
  dir.createSync(recursive: true);
  File('${dir.path}/.env').writeAsStringSync('API_TOKEN=fromdotenv\n');
  File('${dir.path}/DB_PASS').writeAsStringSync('fromfile\n');

  // The four built-in kinds, in one chain, with no plugin file anywhere in
  // the compilation. If the core reached a plugin to build any of them, the
  // dependency listing beside this binary would say so.
  final secrets = sekreto([
    ProviderSpec(kind: 'memory', values: {'API_KEY': 'frommemory'}),
    ProviderSpec(kind: 'dotenv', file: '${dir.path}/.env'),
    ProviderSpec(kind: 'file', dir: dir.path),
    ProviderSpec(kind: 'env', prefix: 'SEKRETO_CORE_'),
  ]);

  checkeq('the four built-in kinds are the catalog',
      [...KINDS.builtin]..sort(), secrets.catalog.names());
  checkeq('the built-in definitions are four', 4, BUILTINS.length);
  checkeq('memory answers', 'frommemory', secrets.get('api.key'));
  checkeq('dotenv answers', 'fromdotenv', secrets.get('api.token'));
  checkeq('file answers', 'fromfile', secrets.get('db.pass'));
  checkeq('the chain is four stores', ['memory', 'dotenv', 'file', 'env'],
      secrets.stores());
  checkeq('redaction still works', 't=[redacted]',
      secrets.redact('t=fromdotenv'));

  // ...and a plugin kind is refused, naming the fix.
  String refused;
  try {
    sekreto([ProviderSpec(kind: 'hashicorp', addr: 'https://v', token: 't')]);
    refused = 'no error';
  } on SekretoError catch (err) {
    refused = err.message;
  }

  checkeq(
    'a plugin kind is refused, naming the fix',
    'sekreto: unknown provider kind: hashicorp'
        ' (available: dotenv, env, file, memory)'
        ' - hashicorp is a sekreto plugin, not built in:'
        ' pass it in the plugins option',
    refused,
  );

  secrets.close();
  checkeq('close empties the host', 0, secrets.host.list().length);

  print(0 == failed
      ? '\ncore: the core runs with the plugins absent'
      : '\ncore: $failed failed');

  exit(0 == failed ? 0 : 1);
}
