// A tiny app that needs a secret.
//
// It asks sekreto for `api.token` and calls the token-protected API with
// it. Every port ships this same CLI, and test/integration.sh runs all of
// them against the same server from every secret source - which is what
// proves the library, rather than the spec alone.
//
// Usage: build/sekreto-cli <api-url> [--source <source>] [--store <name>]
//
// Sources: env dotenv file hashicorp boru boruwire awssecrets awsparams
//          gcpsecrets azuresecrets onepassword doppler infisical
//          secretspec chain
//
// Each source's configuration arrives in the environment variables its own
// ecosystem already uses (VAULT_*, AWS_*, OP_CONNECT_*, ...), listed in
// chainfor below.
//
// Compiled to a self-contained native binary, because the suite runs it
// from an empty working directory with a wiped environment: nothing may be
// resolved relative to where it is started.
//
// It passes `allplugins`, because a CLI whose `--source` is chosen at run
// time needs every kind. An app that knows its chain imports the two or
// three it configures instead.

import 'dart:convert';
import 'dart:io';

import '../src/json.dart';
import '../src/sekreto.dart';
import '../src/spec.dart';

// THE FULL SET, IMPORTED AS A VALUE and passed to the constructor below.
//
// A CLI genuinely wants all ten kinds - `--source` picks one at run time -
// so this is the caller the full set exists for. It is a LIST HANDED TO A
// CONSTRUCTOR, not a side effect of importing: an earlier shape registered
// kinds at import, this file's only reference to the set was a type, the
// compiler erased it, and every kind but two failed in the integration
// suite while `make test` stayed green. See docs/design/plugin-providers.md.
import '../plugins/plugins.dart';

const String LANG = 'dart';

/// An environment variable, or null. An empty value counts as absent: the
/// suite starts the CLI with `env -i`, and a variable set to nothing is a
/// variable that was not set.
String? env(String name) {
  final value = Platform.environment[name];
  return (null == value || value.isEmpty) ? null : value;
}

String envor(String name, String fallback) => env(name) ?? fallback;

List<ProviderSpec> chainfor(String source) {
  final envspec = ProviderSpec(kind: 'env', prefix: env('SEKRETO_PREFIX'));

  final dotenvspec =
      ProviderSpec(kind: 'dotenv', file: envor('SEKRETO_DOTENV', '.env'));

  final filespec =
      ProviderSpec(kind: 'file', dir: envor('SEKRETO_FILEDIR', '/run/secrets'));

  final vaultauth = env('VAULT_AUTH');

  final hashicorpspec = ProviderSpec(
    kind: 'hashicorp',
    addr: envor('VAULT_ADDR', ''),
    token: envor('VAULT_TOKEN', ''),
    mount: env('VAULT_MOUNT'),
    kv: int.tryParse(envor('VAULT_KV', '')),
    vaultnamespace: env('VAULT_NAMESPACE'),
    auth: null == vaultauth
        ? null
        : AuthSpec(
            method: vaultauth,
            role: env('VAULT_ROLE'),
            jwtfile: env('VAULT_JWT_FILE'),
            roleid: env('VAULT_ROLE_ID'),
            secretid: env('VAULT_SECRET_ID'),
          ),
  );

  final boruspec = ProviderSpec(
    kind: 'boru',
    command: envor('BORU_COMMAND', 'boru'),
    namespace: env('BORU_NAMESPACE'),
    home: env('BORU_HOME'),
  );

  // The same vault over its wire protocol (`boru vault serve`) instead of
  // the CLI: an address plus a capability token from `vault grant`.
  final boruwirespec = ProviderSpec(
    kind: 'boru',
    addr: envor('BORU_ADDR', ''),
    token: envor('BORU_TOKEN', ''),
    namespace: env('BORU_NAMESPACE'),
  );

  final awssecretsspec = ProviderSpec(
    kind: 'awssecrets',
    region: env('AWS_REGION'),
    addr: env('AWS_ENDPOINT'),
  );

  final awsparamsspec = ProviderSpec(
    kind: 'awsparams',
    region: env('AWS_REGION'),
    addr: env('AWS_ENDPOINT'),
    prefix: env('AWS_PARAM_PREFIX'),
  );

  final gcpspec = ProviderSpec(
    kind: 'gcpsecrets',
    project: env('GCP_PROJECT'),
    addr: env('GCP_ADDR'),
    metadataaddr: env('GCP_METADATA_ADDR'),
  );

  final azurespec = ProviderSpec(
    kind: 'azuresecrets',
    vault: env('AZURE_VAULT'),
    token: env('AZURE_TOKEN'),
    tenant: env('AZURE_TENANT'),
    clientid: env('AZURE_CLIENT_ID'),
    clientsecret: env('AZURE_CLIENT_SECRET'),
    loginaddr: env('AZURE_LOGIN_ADDR'),
    imdsaddr: env('AZURE_IMDS_ADDR'),
  );

  final onepasswordspec = ProviderSpec(
    kind: 'onepassword',
    addr: env('OP_CONNECT_HOST'),
    token: env('OP_CONNECT_TOKEN'),
    vault: env('OP_VAULT'),
  );

  final dopplerspec = ProviderSpec(
    kind: 'doppler',
    token: env('DOPPLER_TOKEN'),
    project: env('DOPPLER_PROJECT'),
    config: env('DOPPLER_CONFIG'),
    addr: env('DOPPLER_ADDR'),
  );

  // SecretSpec's own environment variables where it has them
  // (SECRETSPEC_FILE, _PROFILE, _PROVIDER, _REASON are read by the
  // secretspec CLI itself), so a shell already set up for secretspec needs
  // nothing further.
  final secretspecspec = ProviderSpec(
    kind: 'secretspec',
    command: envor('SECRETSPEC_COMMAND', 'secretspec'),
    file: env('SECRETSPEC_FILE'),
    profile: env('SECRETSPEC_PROFILE'),
    backend: env('SECRETSPEC_PROVIDER'),
    reason: env('SECRETSPEC_REASON'),
  );

  final infisicalspec = ProviderSpec(
    kind: 'infisical',
    addr: env('INFISICAL_ADDR'),
    token: env('INFISICAL_TOKEN'),
    clientid: env('INFISICAL_CLIENT_ID'),
    clientsecret: env('INFISICAL_CLIENT_SECRET'),
    project: env('INFISICAL_PROJECT'),
    environment: env('INFISICAL_ENV'),
    path: env('INFISICAL_PATH'),
  );

  switch (source) {
    case 'env':
      return [envspec];
    case 'dotenv':
      return [dotenvspec];
    case 'file':
      return [filespec];
    case 'hashicorp':
      return [hashicorpspec];
    case 'boru':
      return [boruspec];
    case 'boruwire':
      return [boruwirespec];
    case 'awssecrets':
      return [awssecretsspec];
    case 'awsparams':
      return [awsparamsspec];
    case 'gcpsecrets':
      return [gcpspec];
    case 'azuresecrets':
      return [azurespec];
    case 'onepassword':
      return [onepasswordspec];
    case 'doppler':
      return [dopplerspec];
    case 'infisical':
      return [infisicalspec];
    case 'secretspec':
      return [secretspecspec];
    default:
      // The chain an app would actually ship with - local overrides first,
      // shared vaults last.
      return [envspec, dotenvspec, hashicorpspec, boruspec];
  }
}

/// The value of a `--flag value` pair, or "" when the flag is absent. Found
/// positionally: no argument-parsing library, in any port.
String flag(List<String> args, String name) {
  final at = args.indexOf(name);
  return (-1 == at || at + 1 >= args.length) ? '' : args[at + 1];
}

Future<int> run(List<String> args) async {
  final url = args.isNotEmpty ? args[0] : 'http://127.0.0.1:8099/whoami';

  final wanted = flag(args, '--source');
  final source = wanted.isEmpty ? 'chain' : wanted;

  // --store names a store outright: the secret must come from that one, not
  // from whichever provider happens to answer first. An unknown store is an
  // error, which is what one of the checks asserts.
  final store = flag(args, '--store');

  Sekreto secrets;
  String token;

  try {
    secrets = sekreto(chainfor(source), plugins: allplugins);
    token = store.isEmpty
        ? await secrets.get('api.token')
        : await secrets.getfrom(store, 'api.token');
  } catch (err) {
    stderr.writeln('sekreto-cli: $err');
    return 2;
  }

  final client = HttpClient();
  client.connectionTimeout = const Duration(seconds: 10);
  client.findProxy = (uri) => 'DIRECT';

  final int status;
  final String body;

  try {
    final request = await client.getUrl(Uri.parse(url));
    request.followRedirects = false;
    request.headers.set('Authorization', 'Bearer $token');
    request.headers.set('X-Sekreto-Lang', LANG);

    final response = await request.close();
    status = response.statusCode;
    body = await response.transform(utf8.decoder).join();
  } catch (err) {
    // Never print the token itself, even when the call fails.
    stderr.writeln('sekreto-cli: ${secrets.redact('$err')}');
    return 1;
  } finally {
    client.close(force: true);
  }

  if (200 != status) {
    stderr.writeln('sekreto-cli: ${secrets.redact(body)}');
    return 1;
  }

  final caller = jsonparse(body).dig('caller');

  // Assembled field by field, in the spec's order. Printing a map here is
  // what has bitten port after port: the language's own key order is not the
  // one every other port prints.
  final line = StringBuffer('{"ok":true');
  line.write(',"lang":${jsonquote(LANG)}');
  line.write(',"source":${jsonquote(source)}');
  line.write(',"store":${jsonquote(store)}');
  line.write(',"caller":${null == caller ? 'null' : jsonstringify(caller)}');
  line.write('}');

  stdout.writeln(line.toString());

  return 0;
}

Future<void> main(List<String> args) async {
  exitCode = await run(args);
}
