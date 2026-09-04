# sekreto: one interface for secrets, wherever they live.
#
# A Sekreto is an ordered chain of providers. `get` asks each in turn and
# returns the first hit, so an app can be configured from environment
# variables in development and a vault in production without changing a
# line of its own code.
#
# A port of typescript/src/Sekreto.ts, which is canonical.

defmodule Sekreto.Error do
  @moduledoc """
  Anything sekreto refuses to do: a bad name, a missing secret, a provider
  that could not be reached.

  The message is the whole contract - there is no code and no cause, in any
  port.
  """
  defexception [:message]
end

defmodule Sekreto do
  @moduledoc """
  The secrets facade: a chain of providers plus a cache.

  Two ways to read. `get` is transparent - it walks the chain and takes the
  first hit, and the caller never learns which store answered. `getfrom` is
  directed - it names the store, and only that store is asked. Use the
  first for ordinary configuration, the second when *which* store holds a
  secret is part of what you mean.
  """

  alias Sekreto.Error
  alias Sekreto.Provider
  alias Sekreto.Providers
  alias Sekreto.ProviderSpec

  @typedoc "A secret name: dot-separated lowercase segments, e.g. `api.token`."
  @type name :: binary

  defstruct [:state]

  # ------------------------------------------------------ name functions

  @doc """
  Is this a well-formed secret name?

  Scanned byte by byte rather than matched against `^[a-z0-9_]+$`: in four
  of the twelve regex flavours these ports use, `$` also matches before a
  final newline, so `api.token\\n` passed - and the spec pins that exact
  case as false.
  """
  def validname(name) when is_binary(name) do
    "" != name and Enum.all?(String.split(name, "."), &segment?/1)
  end

  def validname(_other), do: false

  defp segment?(""), do: false

  defp segment?(segment) do
    Enum.all?(:binary.bin_to_list(segment), fn ch ->
      (?a <= ch and ?z >= ch) or (?0 <= ch and ?9 >= ch) or ?_ == ch
    end)
  end

  @doc "The name, or a `Sekreto.Error`. Every entry point checks its name here."
  def checkname(name) do
    if not validname(name) do
      raise Error, message: "sekreto: invalid name: " <> nametext(name)
    end

    name
  end

  # A name that is not a name still has to be printable. Absence renders as
  # the empty string, so the message ends with a trailing space - which the
  # spec pins.
  defp nametext(name) when is_binary(name), do: name
  defp nametext(nil), do: ""
  defp nametext(other), do: inspect(other)

  @doc """
  The environment-variable key for a name: `api.token` -> `API_TOKEN`.

  The prefix is NOT uppercased: it is written as it is meant to appear.
  Uppercasing is ASCII-only, because a Turkish locale turns `i` into `İ`
  and `API_TOKEN` into something no environment holds.
  """
  def envkey(name, prefix \\ "") do
    prefix <> String.upcase(Enum.join(String.split(checkname(name), "."), "_"), :ascii)
  end

  @doc """
  Where a name lives in a KV vault: `api.token` -> `api` / `token`.

  A single-segment name has no path of its own, so it becomes a secret of
  that name with the conventional field `value`.
  """
  def vaultref(name) do
    parts = String.split(checkname(name), ".")

    if 1 == length(parts) do
      %{path: hd(parts), field: "value"}
    else
      %{path: Enum.join(Enum.drop(parts, -1), "/"), field: List.last(parts)}
    end
  end

  @doc """
  A name flattened to one segment: `api.token` -> `api_token` (GCP Secret
  Manager, `_`) or `api-token` (Azure Key Vault, `-`).

  Those stores have no path hierarchy and reject dots in ids, so the dots
  become the store's conventional separator. With `-` as the separator,
  underscores flatten too: Azure Key Vault's alphabet is letters, digits
  and hyphens only, and a valid sekreto name like `with_underscore` must
  still be representable there.
  """
  def flatname(name, sep) do
    flat = Enum.join(String.split(checkname(name), "."), sep)
    if "-" == sep, do: String.replace(flat, "_", "-"), else: flat
  end

  @doc """
  The AWS SSM Parameter Store name for a name: dots become the path
  hierarchy, rooted at `/` (or at a prefix): `db.pass.main` ->
  `/db/pass/main`, or `/app/db/pass/main` under prefix `/app`.
  """
  def awsparam(name, prefix \\ "") do
    checked = checkname(name)

    base = prefix || ""
    base = if "" != base and not String.starts_with?(base, "/"), do: "/" <> base, else: base
    base = dropsuffix(base, "/")

    base <> "/" <> Enum.join(String.split(checked, "."), "/")
  end

  @doc "Drop a suffix if it is there."
  def dropsuffix(text, suffix) do
    if String.ends_with?(text, suffix) and byte_size(text) >= byte_size(suffix) do
      binary_part(text, 0, byte_size(text) - byte_size(suffix))
    else
      text
    end
  end

  @doc """
  Parse `.env` text into an ORDERED list of `{key, value}` pairs.

  A list rather than a map because the order a file declares its keys in is
  the order this answers them in, in every port; an Elixir map has no order
  at all once it grows past a handful of keys.

  Deliberately small: `KEY=value`, optional `export`, `#` comments on their
  own line, and single- or double-quoted values (double quotes also
  unescape `\\n`, `\\r`, `\\t` and `\\\\`). A line with no `=`, or with an
  empty key, is skipped rather than failing the file.
  """
  def parsedotenv(text) when is_binary(text) do
    text
    |> String.split("\n")
    |> Enum.reduce([], fn rawline, out ->
      line = String.trim(dropsuffix(rawline, "\r"))

      if "" == line or String.starts_with?(line, "#") do
        out
      else
        entry =
          if String.starts_with?(line, "export "),
            do: String.trim(binary_part(line, 7, byte_size(line) - 7)),
            else: line

        case :binary.match(entry, "=") do
          # Both "no `=`" and "empty key", silently, without abandoning the
          # lines below.
          :nomatch ->
            out

          {0, _len} ->
            out

          {at, _len} ->
            key = String.trim(binary_part(entry, 0, at))
            value = String.trim(binary_part(entry, at + 1, byte_size(entry) - at - 1))
            pairput(out, key, unquote_value(value))
        end
      end
    end)
  end

  def parsedotenv(_other), do: []

  defp unquote_value(value) do
    inner = fn -> binary_part(value, 1, byte_size(value) - 2) end

    cond do
      2 <= byte_size(value) and String.starts_with?(value, "\"") and String.ends_with?(value, "\"") ->
        unescape(inner.())

      2 <= byte_size(value) and String.starts_with?(value, "'") and String.ends_with?(value, "'") ->
        inner.()

      true ->
        value
    end
  end

  # A scan, not a chain of replacements: an unknown escape is kept as
  # backslash plus character, and a trailing backslash is literal.
  defp unescape(text), do: unescape(text, [])

  defp unescape(<<>>, acc), do: acc |> Enum.reverse() |> IO.iodata_to_binary()

  defp unescape(<<?\\, next, rest::binary>>, acc) do
    piece =
      case next do
        ?n -> "\n"
        ?r -> "\r"
        ?t -> "\t"
        ?\\ -> "\\"
        ?" -> "\""
        other -> <<?\\, other>>
      end

    unescape(rest, [piece | acc])
  end

  defp unescape(<<ch, rest::binary>>, acc), do: unescape(rest, [<<ch>> | acc])

  @doc """
  Put a key into an ordered pair list, keeping its first position: a later
  duplicate overwrites the value, not the order.
  """
  def pairput(pairs, key, value) do
    if List.keymember?(pairs, key, 0) do
      List.keyreplace(pairs, key, 0, {key, value})
    else
      pairs ++ [{key, value}]
    end
  end

  @doc "The value for a key in an ordered pair list, or nil."
  def pairget(pairs, key) do
    case List.keyfind(pairs, key, 0) do
      {^key, value} -> value
      nil -> nil
    end
  end

  @doc """
  Replace known secret values in text with `[redacted]`.

  Only values of four characters or more are replaced: shorter ones are too
  likely to appear in ordinary text, and redacting them would make logs
  unreadable without making them safer.

  Longest first, always, so that a value which contains a shorter one is
  redacted whole. Literal substring replacement, never a regex: a secret
  full of metacharacters must not be interpreted.
  """
  def redact(text, values) do
    out = if is_binary(text), do: text, else: ""

    (values || [])
    |> Enum.filter(fn value -> is_binary(value) and 4 <= String.length(value) end)
    |> Enum.sort_by(&String.length/1, :desc)
    |> Enum.reduce(out, fn value, acc -> String.replace(acc, value, "[redacted]") end)
  end

  @doc """
  The store name a provider answers to when nothing says otherwise.

  `describe()` opens with the provider's kind - `hashicorp:...`,
  `dotenv:...`, plain `env` - so the kind is the natural default, and a
  custom provider gets a sensible name without implementing anything extra.
  """
  def storename(provider) do
    provider |> Provider.describe() |> String.split(":") |> hd()
  end

  # ------------------------------------------------------------ the chain

  @doc """
  Build a chain from provider specs, live providers, or a mix of the two.

  Options: `cache: false` turns the read cache off. Only an exact `false`
  does; anything else leaves it on.

  Construction contacts nothing. The first network call is the first
  lookup - but a spec that cannot be built at all (an unknown kind, an
  unsupported KV version) raises here, in chain order.
  """
  def new(entries \\ [], opts \\ []) do
    built =
      Enum.map(entries, fn entry ->
        if Provider.provider?(entry) do
          %{store: storename(entry), provider: entry}
        else
          %{store: storeof(entry), provider: Providers.makeprovider(entry)}
        end
      end)

    %Sekreto{
      state:
        Sekreto.Cell.new(%{
          entries: built,
          cache: [],
          seen: [],
          docache: false != Keyword.get(opts, :cache, true)
        })
    }
  end

  # An empty name falls back to the kind, so a chain of two unnamed vaults
  # is addressable as `hashicorp` rather than as nothing.
  defp storeof(%ProviderSpec{} = spec) do
    if "" == spec.name, do: spec.kind, else: spec.name
  end

  @doc "The secret, or a `Sekreto.Error` if no provider has it."
  def get(%Sekreto{} = sek, name) do
    case tryget(sek, name) do
      nil -> raise Error, message: "sekreto: unknown secret: " <> name
      value -> value
    end
  end

  @doc """
  The secret, or nil if no provider has it.

  Named `tryget` because `try` is an Elixir special form.
  """
  def tryget(%Sekreto{} = sek, name), do: resolve(sek, "", name, entries(sek))

  @doc "The secret from one named store, or a `Sekreto.Error`."
  def getfrom(%Sekreto{} = sek, store, name) do
    case tryfrom(sek, store, name) do
      nil -> raise Error, message: "sekreto: unknown secret: " <> store <> ":" <> name
      value -> value
    end
  end

  @doc """
  The secret from one named store, or nil if that store does not have it.

  Naming a store that is not in the chain is an error, not a miss:
  `tryget` already means "this store may not have it", so it cannot also
  mean "this store may not exist" without hiding a typo. That check comes
  before the name is validated.
  """
  def tryfrom(%Sekreto{} = sek, store, name) do
    matching = Enum.filter(entries(sek), fn entry -> store == entry.store end)

    if [] == matching do
      raise Error, message: "sekreto: unknown store: " <> store
    end

    resolve(sek, store, name, matching)
  end

  defp resolve(%Sekreto{state: state}, store, name, useentries) do
    checkname(name)

    held = Sekreto.Cell.get(state)

    hit =
      if held.docache do
        Enum.find(held.cache, fn entry -> store == entry.store and name == entry.name end)
      end

    cond do
      nil != hit ->
        hit.value

      true ->
        # Sequentially, in chain order, short-circuiting on the first hit.
        # A provider that raises is not caught: a store that could not
        # answer must not read as a store that did not have it.
        found =
          Enum.reduce_while(useentries, nil, fn entry, _acc ->
            case Provider.lookup(entry.provider, name) do
              nil -> {:cont, nil}
              value -> {:halt, value}
            end
          end)

        if nil != found do
          later = Sekreto.Cell.get(state)

          Sekreto.Cell.put(state, %{
            later
            | cache:
                if(later.docache,
                  do: later.cache ++ [%{store: store, name: name, value: found}],
                  else: later.cache
                ),
              # Kept whether or not the cache is on, so that `cache: false`
              # cannot silently disable redaction.
              seen: later.seen ++ [found]
          })
        end

        found
    end
  end

  @doc "Does any provider have this secret?"
  def has(%Sekreto{} = sek, name), do: nil != tryget(sek, name)

  @doc "Does this named store have this secret?"
  def hasin(%Sekreto{} = sek, store, name), do: nil != tryfrom(sek, store, name)

  @doc "Every named secret at once. Missing ones are an error."
  def all(%Sekreto{} = sek, names) do
    Map.new(names, fn name -> {name, get(sek, name)} end)
  end

  @doc "A description of each provider, in resolution order."
  def sources(%Sekreto{} = sek) do
    Enum.map(entries(sek), fn entry -> Provider.describe(entry.provider) end)
  end

  @doc """
  The name of each store that can be named by `getfrom`, in resolution
  order and without repeats.
  """
  def stores(%Sekreto{} = sek) do
    entries(sek) |> Enum.map(& &1.store) |> Enum.uniq()
  end

  @doc """
  Replace every value this Sekreto has resolved with `[redacted]`.

  Named `redactall` because the module-level `redact/2` - the pure
  function over an explicit list of values - takes two arguments too. Works
  whether or not caching is enabled: the redaction list is kept
  independently of the read cache.
  """
  def redactall(%Sekreto{state: state}, text) do
    redact(text, Sekreto.Cell.get(state).seen)
  end

  @doc "Drop cached values, so the next `get` asks the providers again."
  def refresh(%Sekreto{state: state}) do
    Sekreto.Cell.put(state, %{Sekreto.Cell.get(state) | cache: []})
    :ok
  end

  @doc """
  Tear the chain down: no stores, no cache, no further reads.

  What survives is redaction - every value this Sekreto ever resolved is
  still replaced in text afterwards, because a log line written after
  shutdown is exactly as public as one written before it.
  """
  def close(%Sekreto{state: state}) do
    Sekreto.Cell.put(state, %{Sekreto.Cell.get(state) | entries: [], cache: []})
    :ok
  end

  defp entries(%Sekreto{state: state}), do: Sekreto.Cell.get(state).entries
end

defimpl Inspect, for: Sekreto do
  @moduledoc """
  The cache and the resolved-value list are ordinary fields, so the default
  struct inspection would print every secret this chain has ever read. This
  one reaches the store names and nothing else.
  """

  def inspect(sek, _opts) do
    Inspect.Algebra.concat(["Sekreto { stores: [ ", Enum.join(Sekreto.stores(sek), ", "), " ] }"])
  end
end
