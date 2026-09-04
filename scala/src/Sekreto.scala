// sekreto: one interface for secrets, wherever they live.
//
// A Sekreto is an ordered chain of providers. `get` asks each in turn and
// returns the first hit, so an app can be configured from environment
// variables in development and a vault in production without changing a
// line of its own code.
//
// A port of typescript/src/Sekreto.ts, which is canonical.

package com.voxgig.sekreto

import java.util.Locale
import scala.collection.immutable.ListMap
import scala.collection.mutable.ListBuffer
import scala.util.matching.Regex

/** A secret name: dot-separated lowercase segments, e.g. `api.token`. */
type Name = String

/** Anything sekreto refuses to do: a bad name, a missing secret, a provider
  * that could not be reached.
  */
class SekretoError(message: String) extends RuntimeException(message)

// `matches` anchors at both ends of the whole input. The obvious `^...$`
// with a find would not: in java.util.regex `$` also matches BEFORE a final
// newline, so `token\n` would pass - and the spec has that exact case.
private val NAMEPART: Regex = "[a-z0-9_]+".r

/** Drop a suffix if it is there. `.` and `_` both appear in names, so this
  * is spelled out rather than reached for through a regex.
  */
private[sekreto] def dropsuffix(text: String, suffix: String): String =
  if text.endsWith(suffix) then text.dropRight(suffix.length) else text

/** Split on the literal dot, KEEPING trailing empties: `String.split` drops
  * them, which would make `a.` a valid one-segment name.
  */
private[sekreto] def segments(name: String): Array[String] = name.split("\\.", -1)

/** Is this a well-formed secret name? */
def validname(name: Any): Boolean = name match
  case text: String => text.nonEmpty && segments(text).forall(NAMEPART.matches)
  case _            => false

/** The name, or a SekretoError. Every entry point checks its name here. */
def checkname(name: Any): Name =
  if !validname(name) then
    throw SekretoError("sekreto: invalid name: " + (if null == name then "" else name.toString))

  name.asInstanceOf[String]

/** The environment-variable key for a name: `api.token` -> `API_TOKEN`. */
def envkey(name: Any, prefix: Option[String] = None): String =
  prefix.getOrElse("") + segments(checkname(name)).mkString("_").toUpperCase(Locale.ROOT)

/** Where a name lives in a KV vault. */
case class VaultRef(path: String, field: String)

/** Where a name lives in a KV vault: `api.token` -> `api` / `token`.
  *
  * A single-segment name has no path of its own, so it becomes a secret of
  * that name with the conventional field `value`.
  */
def vaultref(name: Any): VaultRef =
  val parts = segments(checkname(name))

  if 1 == parts.length then VaultRef(parts(0), "value")
  else VaultRef(parts.dropRight(1).mkString("/"), parts.last)

/** A name flattened to one segment: `api.token` -> `api_token` (GCP Secret
  * Manager, `_`) or `api-token` (Azure Key Vault, `-`).
  *
  * Those stores have no path hierarchy and reject dots in ids, so the dots
  * become the store's conventional separator. With `-` as the separator,
  * underscores flatten too: Azure Key Vault's alphabet is letters, digits
  * and hyphens only, and a valid sekreto name like `with_underscore` must
  * still be representable there. (The resulting `.`/`_` collision mirrors
  * the documented envkey behaviour, where both already map to `_`.)
  */
def flatname(name: Any, sep: String): String =
  val flat = segments(checkname(name)).mkString(sep)
  if "-" == sep then flat.replace("_", "-") else flat

/** The AWS SSM Parameter Store name for a name: dots become the path
  * hierarchy, rooted at `/` (or at a prefix): `db.pass.main` ->
  * `/db/pass/main`, or `/app/db/pass/main` under prefix `/app`.
  */
def awsparam(name: Any, prefix: Option[String] = None): String =
  val checked = checkname(name)

  var base = prefix.getOrElse("")
  if base.nonEmpty && !base.startsWith("/") then base = "/" + base
  base = dropsuffix(base, "/")

  base + "/" + segments(checked).mkString("/")

/** Parse `.env` text into a map of raw keys to values.
  *
  * Deliberately small: `KEY=value`, optional `export`, `#` comments on their
  * own line, and single- or double-quoted values (double quotes also
  * unescape `\n`, `\r`, `\t` and `\\`). A line with no `=` is skipped.
  */
def parsedotenv(text: Any): ListMap[String, String] =
  text match
    case body: String =>
      var out = ListMap.empty[String, String]

      for rawline <- body.split("\n", -1) do
        val line = dropsuffix(rawline, "\r").trim

        if line.nonEmpty && !line.startsWith("#") then
          val entry = if line.startsWith("export ") then line.substring(7).trim else line
          val eq = entry.indexOf('=')

          if 0 < eq then
            val key = entry.substring(0, eq).trim
            var value = entry.substring(eq + 1).trim

            if 2 <= value.length && value.startsWith("\"") && value.endsWith("\"") then
              value = unescape(value.substring(1, value.length - 1))
            else if 2 <= value.length && value.startsWith("'") && value.endsWith("'") then
              value = value.substring(1, value.length - 1)

            out = out.updated(key, value)

      out

    case _ => ListMap.empty[String, String]

private def unescape(text: String): String =
  val out = StringBuilder()
  var index = 0

  while index < text.length do
    if '\\' == text(index) && index + 1 < text.length then
      val next = text(index + 1)
      index += 2
      next match
        case 'n'  => out.append('\n')
        case 'r'  => out.append('\r')
        case 't'  => out.append('\t')
        case '\\' => out.append('\\')
        case '"'  => out.append('"')
        case _    => out.append('\\').append(next)
    else
      out.append(text(index))
      index += 1

  out.toString

/** Replace known secret values in text with `[redacted]`.
  *
  * Only values of four characters or more are replaced: shorter ones are too
  * likely to appear in ordinary text, and redacting them would make logs
  * unreadable without making them safer.
  */
def redact(text: Any, values: Option[List[Any]]): String =
  var out = text match
    case body: String => body
    case _            => ""

  // sortBy returns a new list: `values` belongs to the caller (it is `seen`
  // when called through Sekreto.redact), and sorting in place would reorder
  // it. sortBy is stable, so equal lengths keep the caller's order.
  val usable = values
    .getOrElse(List.empty)
    .collect { case value: String => value }
    .filter(value => 4 <= value.length)
    .sortBy(value => -value.length)

  for value <- usable do out = out.replace(value, "[redacted]")

  out

/** The store name a provider answers to when nothing says otherwise.
  *
  * `describe()` opens with the provider's kind - `hashicorp:...`,
  * `dotenv:...`, plain `env` - so the kind is the natural default, and a
  * custom provider gets a sensible name without implementing anything extra.
  */
def storename(provider: Provider): String = provider.describe().takeWhile(_ != ':')

/** The secrets facade: a chain of providers plus a cache.
  *
  * Two ways to read. `get` is transparent - it walks the chain and takes the
  * first hit, and the caller never learns which store answered. `getfrom` is
  * directed - it names the store, and only that store is asked. Use the
  * first for ordinary configuration, the second when *which* store holds a
  * secret is part of what you mean.
  *
  * `names` gives the store names, positionally; an entry left None or empty
  * falls back to the provider's kind.
  */
class Sekreto(
    providers: List[Provider] = List.empty,
    names: List[Option[String]] = List.empty,
    docache: Boolean = true,
):

  /** One provider in the chain, under the store name it answers to. */
  private case class Entry(store: String, provider: Provider)

  /** One resolved value, with the store it came from. */
  private case class Cached(store: String, name: Name, value: String)

  private val entries: List[Entry] = providers.zipWithIndex.map: (provider, index) =>
    val given = names.lift(index).flatten
    Entry(given.filter(_.nonEmpty).getOrElse(storename(provider)), provider)

  // A buffer, not a map: the store a value came from stays attached, and
  // redaction order does not vary between runs.
  private val cache = ListBuffer.empty[Cached]

  // Every value ever resolved, for redact(). Kept independently of the read
  // cache so that redaction still works when cache is off - otherwise an
  // uncached Sekreto would silently disable redact() and leak secrets to
  // logs.
  private val seen = ListBuffer.empty[String]

  /** The secret, or a SekretoError if no provider has it. */
  def get(name: Name): String =
    tryget(name).getOrElse(throw SekretoError(s"sekreto: unknown secret: $name"))

  /** The secret, or None if no provider has it. Named `tryget` because `try`
    * is a Scala keyword.
    */
  def tryget(name: Name): Option[String] = resolve("", name, entries)

  /** The secret from one named store, or a SekretoError if that store does
    * not have it.
    */
  def getfrom(store: String, name: Name): String =
    tryfrom(store, name).getOrElse(
      throw SekretoError(s"sekreto: unknown secret: $store:$name"),
    )

  /** The secret from one named store, or None if that store does not have
    * it.
    *
    * Naming a store that is not in the chain is an error, not a miss:
    * `tryget` already means "this store may not have it", so it cannot also
    * mean "this store may not exist" without hiding a typo.
    */
  def tryfrom(store: String, name: Name): Option[String] =
    val matching = entries.filter(entry => store == entry.store)

    if matching.isEmpty then throw SekretoError(s"sekreto: unknown store: $store")

    resolve(store, name, matching)

  private def resolve(store: String, name: Name, useentries: List[Entry]): Option[String] =
    checkname(name)

    val hit =
      if docache then cache.find(entry => store == entry.store && name == entry.name)
      else None

    if hit.isDefined then hit.map(_.value)
    else
      var found: Option[String] = None
      val rest = useentries.iterator

      while found.isEmpty && rest.hasNext do found = rest.next().provider.lookup(name)

      found.foreach: value =>
        if docache then cache += Cached(store, name, value)
        seen += value

      found

  /** Does any provider have this secret? */
  def has(name: Name): Boolean = tryget(name).isDefined

  /** Does this named store have this secret? */
  def hasin(store: String, name: Name): Boolean = tryfrom(store, name).isDefined

  /** Every named secret at once. Missing ones are an error. */
  def all(names: List[Name]): ListMap[String, String] =
    ListMap.from(names.map(name => (name, get(name))))

  /** A description of each provider, in resolution order. */
  def sources(): List[String] = entries.map(_.provider.describe())

  /** The name of each store that can be named by `getfrom`, in resolution
    * order and without repeats.
    */
  def stores(): List[String] = entries.map(_.store).distinct

  /** Replace every value this Sekreto has resolved with `[redacted]`.
    *
    * Works whether or not caching is enabled: the redaction list is kept
    * independently of the read cache.
    */
  def redact(text: String): String =
    // Qualified: the member below shadows the package-level function of the
    // same name, which is the one wanted here.
    com.voxgig.sekreto.redact(text, Some(seen.toList))

  /** Drop cached values, so the next `get` asks the providers again. */
  def refresh(): Unit = cache.clear()

/** Make a Sekreto from declarative provider specs - the same shape the
  * shared spec and an app's config file use.
  */
def sekreto(specs: List[ProviderSpec], cache: Boolean = true): Sekreto =
  Sekreto(specs.map(Providers.makeprovider), specs.map(_.name), cache)
