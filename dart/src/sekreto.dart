// sekreto: one interface for secrets, wherever they live.
//
// A Sekreto is an ordered chain of providers. `get` asks each in turn and
// returns the first hit, so an app can be configured from environment
// variables in development and a vault in production without changing a
// line of its own code.
//
// A port of typescript/src/Sekreto.ts, which is canonical.

import 'dart:async';

import 'provider.dart';
import 'providers.dart';

/// A secret name: dot-separated lowercase segments, e.g. `api.token`.
typedef Name = String;

/// Anything sekreto refuses to do: a bad name, a missing secret, a provider
/// that could not be reached.
///
/// The message is the whole contract - there is no code and no cause, and
/// the shared spec pins the text of every one of them byte for byte.
class SekretoError implements Exception {
  final String message;

  SekretoError(this.message);

  @override
  String toString() => message;
}

/// Drop a suffix if it is there. `.` and `_` both appear in names, so this
/// is spelled out rather than reached for through a regex.
String dropsuffix(String text, String suffix) =>
    text.endsWith(suffix) ? text.substring(0, text.length - suffix.length) : text;

/// Split on the literal dot, KEEPING trailing empties, which Dart's `split`
/// does: `a.` is two segments, the second empty, so it is not a valid
/// one-segment name.
List<String> segments(String name) => name.split('.');

/// Is this a well-formed secret name?
///
/// A character scan, not a regex. The obvious `^[a-z0-9_]+$` is not the
/// check it looks like: in several regex flavours `$` also matches before a
/// final newline, and `api.token\n` is a spec case that must be false.
bool validname(Object? name) {
  if (name is! String || name.isEmpty) {
    return false;
  }

  for (final part in segments(name)) {
    if (part.isEmpty) {
      return false;
    }

    for (final unit in part.codeUnits) {
      final ok = (0x61 <= unit && 0x7a >= unit) ||
          (0x30 <= unit && 0x39 >= unit) ||
          0x5f == unit;
      if (!ok) {
        return false;
      }
    }
  }

  return true;
}

/// The name, or a SekretoError. Every entry point checks its name here.
Name checkname(Object? name) {
  if (!validname(name)) {
    throw SekretoError('sekreto: invalid name: ${null == name ? '' : name}');
  }

  return name as String;
}

/// Uppercase the ASCII letters and nothing else.
///
/// Not `toUpperCase`: a locale-sensitive uppercase turns `i` into a dotted
/// capital in Turkish, and `api.token` would key `API_TOKEN` on one machine
/// and something else on another.
String _upper(String text) {
  final out = StringBuffer();

  for (final unit in text.codeUnits) {
    out.writeCharCode(0x61 <= unit && 0x7a >= unit ? unit - 32 : unit);
  }

  return out.toString();
}

/// The environment-variable key for a name: `api.token` -> `API_TOKEN`.
///
/// The prefix is NOT uppercased: it is written the way the caller wants it
/// to appear.
String envkey(Object? name, [String? prefix]) =>
    (prefix ?? '') + _upper(segments(checkname(name)).join('_'));

/// Where a name lives in a KV vault.
class VaultRef {
  final String path;
  final String field;
  const VaultRef(this.path, this.field);
}

/// Where a name lives in a KV vault: `api.token` -> `api` / `token`.
///
/// A single-segment name has no path of its own, so it becomes a secret of
/// that name with the conventional field `value`.
VaultRef vaultref(Object? name) {
  final parts = segments(checkname(name));

  if (1 == parts.length) {
    return VaultRef(parts[0], 'value');
  }

  return VaultRef(parts.sublist(0, parts.length - 1).join('/'), parts.last);
}

/// A name flattened to one segment: `api.token` -> `api_token` (GCP Secret
/// Manager, `_`) or `api-token` (Azure Key Vault, `-`).
///
/// Those stores have no path hierarchy and reject dots in ids, so the dots
/// become the store's conventional separator. With `-` as the separator,
/// underscores flatten too: Azure Key Vault's alphabet is letters, digits
/// and hyphens only, and a valid sekreto name like `with_underscore` must
/// still be representable there.
String flatname(Object? name, String sep) {
  final flat = segments(checkname(name)).join(sep);
  return '-' == sep ? flat.replaceAll('_', '-') : flat;
}

/// The AWS SSM Parameter Store name for a name: dots become the path
/// hierarchy, rooted at `/` (or at a prefix): `db.pass.main` ->
/// `/db/pass/main`, or `/app/db/pass/main` under prefix `/app`.
String awsparam(Object? name, [String? prefix]) {
  final checked = checkname(name);

  var base = prefix ?? '';
  if (base.isNotEmpty && !base.startsWith('/')) {
    base = '/$base';
  }
  base = dropsuffix(base, '/');

  return '$base/${segments(checked).join('/')}';
}

/// Parse `.env` text into a map of raw keys to values.
///
/// There is no `.env` standard, so this function is the specification.
/// Deliberately small: `KEY=value`, optional `export`, `#` comments on their
/// own line, and single- or double-quoted values (double quotes also
/// unescape `\n`, `\r`, `\t`, `\\` and `\"`). A line with no `=`, or with an
/// empty key, is skipped rather than refused - one malformed line must not
/// cost the rest of the file.
Map<String, String> parsedotenv(Object? text) {
  final out = <String, String>{};

  if (text is! String) {
    return out;
  }

  for (final rawline in text.split('\n')) {
    final line = dropsuffix(rawline, '\r').trim();

    if (line.isEmpty || line.startsWith('#')) {
      continue;
    }

    final entry =
        line.startsWith('export ') ? line.substring(7).trim() : line;
    final eq = entry.indexOf('=');

    if (0 >= eq) {
      continue;
    }

    final key = entry.substring(0, eq).trim();
    var value = entry.substring(eq + 1).trim();

    if (2 <= value.length && value.startsWith('"') && value.endsWith('"')) {
      value = unescape(value.substring(1, value.length - 1));
    } else if (2 <= value.length &&
        value.startsWith("'") &&
        value.endsWith("'")) {
      value = value.substring(1, value.length - 1);
    }

    out[key] = value;
  }

  return out;
}

/// The escapes a double-quoted `.env` value may carry. A scan, not a chain
/// of replacements: an unknown escape is kept whole, backslash and all, and
/// a trailing backslash is literal.
String unescape(String text) {
  final out = StringBuffer();
  var index = 0;

  while (index < text.length) {
    if (r'\' == text[index] && index + 1 < text.length) {
      final next = text[index + 1];
      index += 2;

      switch (next) {
        case 'n':
          out.write('\n');
        case 'r':
          out.write('\r');
        case 't':
          out.write('\t');
        case r'\':
          out.write(r'\');
        case '"':
          out.write('"');
        default:
          out.write(r'\');
          out.write(next);
      }
    } else {
      out.write(text[index]);
      index += 1;
    }
  }

  return out.toString();
}

/// Replace known secret values in text with `[redacted]`.
///
/// Only values of four characters or more are replaced: shorter ones are too
/// likely to appear in ordinary text, and redacting them would make logs
/// unreadable without making them safer.
String redact(Object? text, List<Object?>? values) {
  var out = text is String ? text : '';

  // A COPY is sorted: `values` belongs to the caller (it is the resolved
  // history when called through Sekreto.redact), and sorting in place would
  // reorder it. Longest first, so a value that contains a shorter one is
  // replaced whole rather than left with a redacted fragment inside it.
  final usable = values
          ?.whereType<String>()
          .where((value) => 4 <= value.length)
          .toList() ??
      <String>[];

  usable.sort((left, right) => right.length - left.length);

  // A literal replace, never a regex: a secret containing metacharacters
  // must not be interpreted as a pattern.
  for (final value in usable) {
    out = out.split(value).join('[redacted]');
  }

  return out;
}

/// The store name a provider answers to when nothing says otherwise.
///
/// `describe()` opens with the provider's kind - `hashicorp:...`,
/// `dotenv:...`, plain `env` - so the kind is the natural default, and a
/// custom provider gets a sensible name without implementing anything extra.
String storename(Provider provider) {
  final described = provider.describe();
  final mark = described.indexOf(':');
  return -1 == mark ? described : described.substring(0, mark);
}

/// One provider in the chain, under the store name it answers to.
class _Entry {
  final String store;
  final Provider provider;
  const _Entry(this.store, this.provider);
}

/// One resolved value, with the store it came from.
class _Cached {
  final String store;
  final String name;
  final String value;
  const _Cached(this.store, this.name, this.value);
}

/// The secrets facade: a chain of providers plus a cache.
///
/// Two ways to read. `get` is transparent - it walks the chain and takes the
/// first hit, and the caller never learns which store answered. `getfrom` is
/// directed - it names the store, and only that store is asked. Use the
/// first for ordinary configuration, the second when *which* store holds a
/// secret is part of what you mean.
///
/// `names` gives the store names, positionally; an entry left null or empty
/// falls back to the provider's kind.
class Sekreto {
  final List<_Entry> _entries = [];

  // A list, not a map: the store a value came from stays attached, and
  // redaction order does not vary between runs.
  final List<_Cached> _cache = [];

  // Every value ever resolved, for redact(). Kept independently of the read
  // cache so that redaction still works when caching is off - otherwise an
  // uncached Sekreto would silently disable redact() and leak secrets to
  // logs. Append-only for the object's life: neither refresh() nor close()
  // clears it, because a value that has been in a log is still in that log.
  final List<String> _seen = [];

  final bool _docache;

  Sekreto({
    List<Provider> providers = const [],
    List<String?> names = const [],
    bool cache = true,
  }) : _docache = cache {
    for (var at = 0; at < providers.length; at++) {
      final given = at < names.length ? names[at] : null;
      final store = (null == given || given.isEmpty)
          ? storename(providers[at])
          : given;
      _entries.add(_Entry(store, providers[at]));
    }
  }

  /// The secret, or a SekretoError if no provider has it.
  FutureOr<String> get(Name name) {
    final found = tryget(name);

    if (found is Future<String?>) {
      return found.then((value) => value ?? _nosecret(name));
    }

    return found ?? _nosecret(name);
  }

  /// The secret, or null if no provider has it. Named `tryget` because
  /// `try` is a Dart keyword.
  FutureOr<String?> tryget(Name name) => _resolve('', name, _entries);

  /// The secret from one named store, or a SekretoError if that store does
  /// not have it.
  FutureOr<String> getfrom(String store, Name name) {
    final found = tryfrom(store, name);

    if (found is Future<String?>) {
      return found.then((value) => value ?? _nosecret('$store:$name'));
    }

    return found ?? _nosecret('$store:$name');
  }

  /// The secret from one named store, or null if that store does not have
  /// it.
  ///
  /// Naming a store that is not in the chain is an error, not a miss:
  /// `tryget` already means "this store may not have it", so it cannot also
  /// mean "this store may not exist" without hiding a typo. Raised before
  /// the name is validated, because a chain that cannot answer at all is the
  /// larger mistake.
  FutureOr<String?> tryfrom(String store, Name name) {
    final matching =
        _entries.where((entry) => store == entry.store).toList();

    if (matching.isEmpty) {
      throw SekretoError('sekreto: unknown store: $store');
    }

    return _resolve(store, name, matching);
  }

  Never _nosecret(String what) =>
      throw SekretoError('sekreto: unknown secret: $what');

  FutureOr<String?> _resolve(
      String store, Name name, List<_Entry> useentries) {
    // Validated first: before the cache, and before any provider is asked.
    checkname(name);

    if (_docache) {
      for (final entry in _cache) {
        if (store == entry.store && name == entry.name) {
          return entry.value;
        }
      }
    }

    return _walk(store, name, useentries, 0);
  }

  /// Walk the chain from [at], staying synchronous for as long as the
  /// providers do. The first provider that answers with a Future hands the
  /// rest of the walk to a continuation; a chain of purely local stores
  /// never builds one.
  FutureOr<String?> _walk(
      String store, Name name, List<_Entry> entries, int at) {
    var index = at;

    while (index < entries.length) {
      final found = entries[index].provider.lookup(name);

      if (found is Future<String?>) {
        final next = index + 1;
        return found.then((value) => null != value
            ? _hit(store, name, value)
            : _walk(store, name, entries, next));
      }

      // The empty string is a hit. Only null means "ask the next one".
      if (null != found) {
        return _hit(store, name, found);
      }

      index++;
    }

    // A miss is never cached: the next read asks again.
    return null;
  }

  String _hit(String store, Name name, String value) {
    if (_docache) {
      _cache.add(_Cached(store, name, value));
    }
    _seen.add(value);
    return value;
  }

  /// Does any provider have this secret?
  FutureOr<bool> has(Name name) {
    final found = tryget(name);

    if (found is Future<String?>) {
      return found.then((value) => null != value);
    }

    return null != found;
  }

  /// Does this named store have this secret?
  FutureOr<bool> hasin(String store, Name name) {
    final found = tryfrom(store, name);

    if (found is Future<String?>) {
      return found.then((value) => null != value);
    }

    return null != found;
  }

  /// Every named secret at once, read in order. A missing one is an error.
  Future<Map<String, String>> all(List<Name> names) async {
    final out = <String, String>{};

    for (final name in names) {
      out[name] = await get(name);
    }

    return out;
  }

  /// A description of each provider, in resolution order. Repeats are kept:
  /// two entries of the same kind are two entries.
  List<String> sources() =>
      _entries.map((entry) => entry.provider.describe()).toList();

  /// The name of each store that can be named by `getfrom`, in resolution
  /// order and without repeats.
  List<String> stores() {
    final out = <String>[];

    for (final entry in _entries) {
      if (!out.contains(entry.store)) {
        out.add(entry.store);
      }
    }

    return out;
  }

  /// Replace every value this Sekreto has resolved with `[redacted]`.
  ///
  /// Works whether or not caching is enabled: the redaction list is kept
  /// independently of the read cache.
  String redact(String text) =>
      // The library function of the same name, which this method shadows.
      _redactall(text, _seen);

  /// Drop cached values, so the next read asks the providers again. The
  /// redaction history is not touched.
  void refresh() => _cache.clear();

  /// Tear the chain down. Afterwards there are no stores, no sources and
  /// nothing to read - but redaction still knows every value ever resolved,
  /// because those values are still in whatever they were printed into.
  void close() {
    _entries.clear();
    _cache.clear();
  }

  /// Serialised without reaching a value: `cache` and `seen` are ordinary
  /// fields, so anything deriving this from them would emit every secret
  /// the process has read.
  Map<String, Object?> toJson() => {'stores': stores()};

  @override
  String toString() => 'Sekreto { stores: [ ${stores().join(', ')} ] }';
}

String _redactall(String text, List<String> values) => redact(text, values);

/// Make a Sekreto from declarative provider specs - the same shape the
/// shared spec and an app's config file use.
Sekreto sekreto(List<ProviderSpec> specs, {bool cache = true}) => Sekreto(
      providers: specs.map(makeprovider).toList(),
      names: specs.map((spec) => spec.name).toList(),
      cache: cache,
    );
