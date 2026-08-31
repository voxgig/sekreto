// sekreto: one interface for secrets, wherever they live.
//
// A Sekreto is an ordered chain of providers. `get` asks each in turn and
// returns the first hit, so an app can be configured from environment
// variables in development and a vault in production without changing a
// line of its own code.
//
// A port of typescript/src/Sekreto.ts, which is canonical.

package com.voxgig.sekreto

/** A secret name: dot-separated lowercase segments, e.g. `api.token`. */
typealias Name = String

/**
 * Anything sekreto refuses to do: a bad name, a missing secret, a provider
 * that could not be reached.
 */
class SekretoError(message: String) : RuntimeException(message)

private val NAMEPART = Regex("^[a-z0-9_]+$")

/** Is this a well-formed secret name? */
fun validname(name: Any?): Boolean {
    if (name !is String || name.isEmpty()) {
        return false
    }

    return name.split(".").all { NAMEPART.matches(it) }
}

/** The name, or a SekretoError. Every entry point checks its name here. */
fun checkname(name: Any?): Name {
    if (!validname(name)) {
        throw SekretoError("sekreto: invalid name: " + (name ?: ""))
    }

    return name as String
}

/** The environment-variable key for a name: `api.token` -> `API_TOKEN`. */
fun envkey(name: Any?, prefix: String? = null): String =
    (prefix ?: "") + checkname(name).split(".").joinToString("_").uppercase()

/** Where a name lives in a KV vault. */
data class VaultRef(val path: String, val field: String)

/**
 * Where a name lives in a KV vault: `api.token` -> `api` / `token`.
 *
 * A single-segment name has no path of its own, so it becomes a secret of
 * that name with the conventional field `value`.
 */
fun vaultref(name: Any?): VaultRef {
    val parts = checkname(name).split(".")

    if (1 == parts.size) {
        return VaultRef(parts[0], "value")
    }

    return VaultRef(parts.dropLast(1).joinToString("/"), parts.last())
}

/**
 * A name flattened to one segment: `api.token` -> `api_token` (GCP Secret
 * Manager, `_`) or `api-token` (Azure Key Vault, `-`).
 *
 * Those stores have no path hierarchy and reject dots in ids, so the dots
 * become the store's conventional separator. With `-` as the separator,
 * underscores flatten too: Azure Key Vault's alphabet is letters, digits
 * and hyphens only, and a valid sekreto name like `with_underscore` must
 * still be representable there. (The resulting `.`/`_` collision mirrors
 * the documented envkey behaviour, where both already map to `_`.)
 */
fun flatname(name: Any?, sep: String): String {
    val flat = checkname(name).split(".").joinToString(sep)
    return if ("-" == sep) flat.replace("_", "-") else flat
}

/**
 * The AWS SSM Parameter Store name for a name: dots become the path
 * hierarchy, rooted at `/` (or at a prefix): `db.pass.main` ->
 * `/db/pass/main`, or `/app/db/pass/main` under prefix `/app`.
 */
fun awsparam(name: Any?, prefix: String? = null): String {
    val checked = checkname(name)

    var base = prefix ?: ""
    if (base.isNotEmpty() && !base.startsWith("/")) {
        base = "/$base"
    }
    base = base.removeSuffix("/")

    return base + "/" + checked.split(".").joinToString("/")
}

/**
 * Parse `.env` text into a map of raw keys to values.
 *
 * Deliberately small: `KEY=value`, optional `export`, `#` comments on their
 * own line, and single- or double-quoted values (double quotes also
 * unescape `\n`, `\r`, `\t` and `\\`). A line with no `=` is skipped.
 */
fun parsedotenv(text: Any?): Map<String, String> {
    val out = LinkedHashMap<String, String>()

    if (text !is String) {
        return out
    }

    for (rawline in text.split("\n")) {
        val line = rawline.removeSuffix("\r").trim()

        if (line.isEmpty() || line.startsWith("#")) {
            continue
        }

        val body = if (line.startsWith("export ")) line.substring(7).trim() else line

        val eq = body.indexOf('=')
        if (0 >= eq) {
            continue
        }

        val key = body.substring(0, eq).trim()
        var value = body.substring(eq + 1).trim()

        if (2 <= value.length && value.startsWith("\"") && value.endsWith("\"")) {
            value = unescape(value.substring(1, value.length - 1))
        } else if (2 <= value.length && value.startsWith("'") && value.endsWith("'")) {
            value = value.substring(1, value.length - 1)
        }

        out[key] = value
    }

    return out
}

private fun unescape(text: String): String {
    val out = StringBuilder()
    var index = 0

    while (index < text.length) {
        if ('\\' == text[index] && index + 1 < text.length) {
            val next = text[index + 1]
            index += 2
            when (next) {
                'n' -> out.append('\n')
                'r' -> out.append('\r')
                't' -> out.append('\t')
                '\\' -> out.append('\\')
                '"' -> out.append('"')
                else -> out.append('\\').append(next)
            }
        } else {
            out.append(text[index])
            index++
        }
    }

    return out.toString()
}

/**
 * Replace known secret values in text with `[redacted]`.
 *
 * Only values of four characters or more are replaced: shorter ones are too
 * likely to appear in ordinary text, and redacting them would make logs
 * unreadable without making them safer.
 */
fun redact(text: Any?, values: List<Any?>?): String {
    var out = if (text is String) text else ""

    for (value in values ?: emptyList()) {
        if (value !is String || 4 > value.length) {
            continue
        }
        out = out.replace(value, "[redacted]")
    }

    return out
}

/**
 * The store name a provider answers to when nothing says otherwise.
 *
 * `describe()` opens with the provider's kind - `hashicorp:...`,
 * `dotenv:...`, plain `env` - so the kind is the natural default, and a
 * custom provider gets a sensible name without implementing anything extra.
 */
fun storename(provider: Provider): String = provider.describe().substringBefore(':')

/**
 * The secrets facade: a chain of providers plus a cache.
 *
 * Two ways to read. `get` is transparent - it walks the chain and takes the
 * first hit, and the caller never learns which store answered. `getfrom` is
 * directed - it names the store, and only that store is asked. Use the
 * first for ordinary configuration, the second when *which* store holds a
 * secret is part of what you mean.
 *
 * `names` gives the store names, positionally; an entry left null or empty
 * falls back to the provider's kind.
 */
class Sekreto(
    providers: List<Provider> = emptyList(),
    names: List<String?> = emptyList(),
    private val docache: Boolean = true,
) {

    /** One provider in the chain, under the store name it answers to. */
    private data class Entry(val store: String, val provider: Provider)

    /** One resolved value, with the store it came from. */
    private data class Cached(val store: String, val name: Name, val value: String)

    private val entries: List<Entry> = providers.mapIndexed { index, provider ->
        val given = names.getOrNull(index)
        Entry(if (given.isNullOrEmpty()) storename(provider) else given, provider)
    }

    // A list, not a map: the store a value came from stays attached, and
    // redaction order does not vary between runs.
    private val cache = mutableListOf<Cached>()

    // Every value ever resolved, for redact(). Kept independently of the
    // read cache so that redaction still works when cache is off - otherwise
    // an uncached Sekreto would silently disable redact() and leak secrets
    // to logs.
    private val seen = mutableListOf<String>()

    /** The secret, or a SekretoError if no provider has it. */
    fun get(name: Name): String =
        tryget(name) ?: throw SekretoError("sekreto: unknown secret: $name")

    /**
     * The secret, or null if no provider has it. Named `tryget` because
     * `try` is a Kotlin keyword.
     */
    fun tryget(name: Name): String? = resolve("", name, entries)

    /** Canonical's own name for `tryget`, for callers translating from it. */
    fun `try`(name: Name): String? = tryget(name)

    /**
     * The secret from one named store, or a SekretoError if that store does
     * not have it.
     */
    fun getfrom(store: String, name: Name): String =
        tryfrom(store, name) ?: throw SekretoError("sekreto: unknown secret: $store:$name")

    /**
     * The secret from one named store, or null if that store does not have
     * it.
     *
     * Naming a store that is not in the chain is an error, not a miss:
     * `tryget` already means "this store may not have it", so it cannot also
     * mean "this store may not exist" without hiding a typo.
     */
    fun tryfrom(store: String, name: Name): String? {
        val matching = entries.filter { store == it.store }

        if (matching.isEmpty()) {
            throw SekretoError("sekreto: unknown store: $store")
        }

        return resolve(store, name, matching)
    }

    private fun resolve(store: String, name: Name, useentries: List<Entry>): String? {
        checkname(name)

        if (docache) {
            val hit = cache.find { store == it.store && name == it.name }
            if (null != hit) {
                return hit.value
            }
        }

        for (entry in useentries) {
            val found = entry.provider.lookup(name)

            if (null != found) {
                if (docache) {
                    cache.add(Cached(store, name, found))
                }
                seen.add(found)
                return found
            }
        }

        return null
    }

    /** Does any provider have this secret? */
    fun has(name: Name): Boolean = null != tryget(name)

    /** Does this named store have this secret? */
    fun hasin(store: String, name: Name): Boolean = null != tryfrom(store, name)

    /** Every named secret at once. Missing ones are an error. */
    fun all(names: List<Name>): Map<String, String> {
        val out = LinkedHashMap<String, String>()

        for (name in names) {
            out[name] = get(name)
        }

        return out
    }

    /** A description of each provider, in resolution order. */
    fun sources(): List<String> = entries.map { it.provider.describe() }

    /**
     * The name of each store that can be named by `getfrom`, in resolution
     * order and without repeats.
     */
    fun stores(): List<String> = entries.map { it.store }.distinct()

    /**
     * Replace every value this Sekreto has resolved with `[redacted]`.
     *
     * Works whether or not caching is enabled: the redaction list is kept
     * independently of the read cache.
     */
    fun redact(text: String): String = redact(text, seen)

    /** Drop cached values, so the next `get` asks the providers again. */
    fun refresh() {
        cache.clear()
    }
}

/**
 * Make a Sekreto from declarative provider specs - the same shape the
 * shared spec and an app's config file use.
 */
fun sekreto(specs: List<ProviderSpec>, cache: Boolean = true): Sekreto =
    Sekreto(specs.map { Providers.makeprovider(it) }, specs.map { it.name }, cache)
