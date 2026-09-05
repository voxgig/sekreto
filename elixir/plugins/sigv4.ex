# AWS Signature Version 4, hand-rolled - and OUTSIDE THE CORE, because it
# is the library's one cryptographic edge. Only the two aws kinds sign
# anything, which is why the core of no port imports a hash function:
# `:crypto` is reached from here and from nowhere else.
#
# The AWS providers need exactly one thing from the AWS SDK - request
# signing - and taking the SDK for it would break the no-dependency rule
# that keeps the ports honest. SigV4 is a stable, published algorithm built
# from HMAC-SHA256, which OTP's `:crypto` already has.
#
# `sigv4` is pure: the caller passes the timestamp, so the same input
# yields the same signature everywhere. That is what lets the shared spec
# carry known-answer cases that all ports must reproduce bit-for-bit, and
# lets the integration mock recompute the signature server-side.
#
# A port of typescript/plugins/sigv4.ts, which is canonical.

defmodule Sekreto.Plugins.Signing do
  @moduledoc """
  One request to sign - the same declarative shape the shared spec uses.

  `datetime` is `YYYYMMDDTHHMMSSZ`, and it is the caller's, so that signing
  is a pure function of its input.
  """

  defstruct method: "",
            url: "",
            service: "",
            region: "",
            keyid: "",
            secret: "",
            datetime: "",
            headers: [],
            body: "",
            session: ""
end

defmodule Sekreto.Plugins.Sigv4 do
  @moduledoc """
  AWS Signature Version 4.

  A plugin module: nothing under `src/` names it, and `:crypto` is
  reached from here alone. See docs/design/plugin-providers.md.
  """

  alias Sekreto.Plugins.Signing

  @doc "Lowercase hex, two digits a byte."
  def hex(bytes), do: Base.encode16(bytes, case: :lower)

  @doc "SHA-256 of the UTF-8 text, as lowercase hex."
  def sha256hex(text), do: hex(:crypto.hash(:sha256, text))

  @doc "HMAC-SHA256, key first - PHP and Perl's stdlib take them the other way."
  def hmac(key, text), do: :crypto.mac(:hmac, :sha256, key, text)

  @doc """
  RFC 3986 escaping, which is stricter than the usual URL encoder: AWS
  wants everything but unreserved characters escaped, with uppercase hex.
  """
  def uriescape(text) do
    text
    |> :binary.bin_to_list()
    |> Enum.map_join("", fn ch ->
      if (?A <= ch and ?Z >= ch) or (?a <= ch and ?z >= ch) or (?0 <= ch and ?9 >= ch) or
           ch in [?-, ?_, ?., ?~] do
        <<ch>>
      else
        # UPPERCASE hex, deliberately: AWS SigV4 specifies uppercase
        # percent-escapes, and Integer.to_string/2 already gives that.
        # src/json.ex uses the same call and must LOWERCASE it -- the two
        # are opposite requirements, which is exactly how one gets copied
        # onto the other by mistake. The split moved this file to
        # plugins/ and left that one in the core, so the two now sit in
        # different directories; the asymmetry is unchanged, and each
        # file names the other.
        "%" <> String.pad_leading(Integer.to_string(ch, 16), 2, "0")
      end
    end)
  end

  @doc "Percent-decode, and nothing else: `+` stays `+`, as on the wire."
  def uridecode(text), do: uridecode(text, [])

  defp uridecode(<<>>, acc), do: acc |> Enum.reverse() |> IO.iodata_to_binary()

  defp uridecode(<<?%, hi, lo, rest::binary>> = text, acc) do
    case Integer.parse(<<hi, lo>>, 16) do
      {code, ""} ->
        uridecode(rest, [<<code>> | acc])

      # A stray % is kept as-is, the way a browser would.
      _other ->
        <<head, more::binary>> = text
        uridecode(more, [<<head>> | acc])
    end
  end

  defp uridecode(<<head, rest::binary>>, acc), do: uridecode(rest, [<<head>> | acc])

  @doc """
  The canonical query string: each pair RFC 3986-escaped, sorted by escaped
  key then escaped value.
  """
  def canonicalquery(""), do: ""

  def canonicalquery(query) do
    query
    |> String.split("&")
    |> Enum.map(fn pair ->
      {key, value} =
        case :binary.split(pair, "=") do
          [only] -> {only, ""}
          [head, tail] -> {head, tail}
        end

      {uriescape(uridecode(key)), uriescape(uridecode(value))}
    end)
    |> Enum.sort()
    |> Enum.map_join("&", fn {key, value} -> key <> "=" <> value end)
  end

  @doc """
  The `host` header value for a URL: the WHATWG `URL.host` - hostname
  lowercased, userinfo stripped, and the port appended only when it is not
  the scheme's default.

  Hand-split, like `checkaddr`: a platform URL type is free to disagree,
  and `Host: example.com:443` is not what a signature covering `host`
  was computed over.
  """
  def urlhost(url) do
    {scheme, authority, _path, _query} = urlparts(url)

    authority =
      case String.split(authority, "@") do
        [only] -> only
        many -> List.last(many)
      end

    {host, port} =
      if String.starts_with?(authority, "[") do
        case :binary.match(authority, "]") do
          {at, _len} ->
            {binary_part(authority, 0, at + 1),
             binary_part(authority, at + 1, byte_size(authority) - at - 1)}

          :nomatch ->
            {authority, ""}
        end
      else
        case :binary.split(authority, ":") do
          [only] -> {only, ""}
          [head, tail] -> {head, ":" <> tail}
        end
      end

    port =
      cond do
        ":" == port -> ""
        "https://" == scheme and ":443" == port -> ""
        "http://" == scheme and ":80" == port -> ""
        true -> port
      end

    String.downcase(host, :ascii) <> port
  end

  @doc """
  A URL split into scheme, authority, raw path and raw query - by hand, so
  that every port cuts it in the same place.
  """
  def urlparts(url) do
    {scheme, rest} =
      cond do
        String.starts_with?(url, "https://") -> {"https://", binary_part(url, 8, byte_size(url) - 8)}
        String.starts_with?(url, "http://") -> {"http://", binary_part(url, 7, byte_size(url) - 7)}
        true -> {"", url}
      end

    {authority, tail} =
      case cutat(rest, [?/, ??, ?#]) do
        nil -> {rest, ""}
        at -> {binary_part(rest, 0, at), binary_part(rest, at, byte_size(rest) - at)}
      end

    {tail, _fragment} =
      case cutat(tail, [?#]) do
        nil -> {tail, ""}
        at -> {binary_part(tail, 0, at), binary_part(tail, at, byte_size(tail) - at)}
      end

    {path, query} =
      case :binary.split(tail, "?") do
        [only] -> {only, ""}
        [head, more] -> {head, more}
      end

    {scheme, authority, path, query}
  end

  defp cutat(text, chars), do: cutat(text, chars, 0)

  defp cutat(text, chars, at) do
    case text do
      <<_::binary-size(at), ch, _::binary>> ->
        if ch in chars, do: at, else: cutat(text, chars, at + 1)

      _other ->
        nil
    end
  end

  @doc """
  Sign one request. Answers the headers to attach: `authorization`,
  `x-amz-date`, and `x-amz-security-token` when a session token was given,
  in that order - the spec compares the result as a JSON object, and
  callers print it field by field.
  """
  def sigv4(%Signing{} = input) do
    date = binary_part(input.datetime, 0, 8)
    session = input.session || ""

    # Every header that will be signed: the caller's extras, plus host and
    # x-amz-date (and the session token when present), lower-cased and
    # trimmed the way the canonical form requires - AWS folds sequential
    # whitespace, spaces AND tabs, to one space before signing, so a header
    # like "a  b" must sign as "a b" or the service refuses it.
    #
    # The inserted three come last, so they win over a caller that named
    # one of them.
    folded =
      Enum.map(input.headers, fn {key, value} ->
        {String.downcase(key, :ascii), String.replace(String.trim(value), ~r/\s+/, " ")}
      end)

    folded = putheader(folded, "host", urlhost(input.url))
    folded = putheader(folded, "x-amz-date", input.datetime)

    folded =
      if "" == session, do: folded, else: putheader(folded, "x-amz-security-token", session)

    headers = Enum.sort_by(folded, fn {key, _value} -> key end)

    canonicalheaders = Enum.map_join(headers, "", fn {key, value} -> key <> ":" <> value <> "\n" end)
    signedheaders = Enum.map_join(headers, ";", fn {key, _value} -> key end)

    {_scheme, _authority, rawpath, rawquery} = urlparts(input.url)
    path = if "" == rawpath, do: "/", else: rawpath

    canonicalrequest =
      Enum.join(
        [
          String.upcase(input.method, :ascii),
          path,
          canonicalquery(rawquery),
          canonicalheaders,
          signedheaders,
          sha256hex(input.body)
        ],
        "\n"
      )

    scope = date <> "/" <> input.region <> "/" <> input.service <> "/aws4_request"

    stringtosign =
      Enum.join(
        ["AWS4-HMAC-SHA256", input.datetime, scope, sha256hex(canonicalrequest)],
        "\n"
      )

    kdate = hmac("AWS4" <> input.secret, date)
    kregion = hmac(kdate, input.region)
    kservice = hmac(kregion, input.service)
    ksigning = hmac(kservice, "aws4_request")
    signature = hex(hmac(ksigning, stringtosign))

    out = [
      {"authorization",
       "AWS4-HMAC-SHA256 Credential=" <>
         input.keyid <>
         "/" <> scope <> ", SignedHeaders=" <> signedheaders <> ", Signature=" <> signature},
      {"x-amz-date", input.datetime}
    ]

    if "" == session, do: out, else: out ++ [{"x-amz-security-token", session}]
  end

  # Replace in place if the key is there, else append: the caller's own
  # order is kept, and an inserted header wins over a caller's.
  defp putheader(pairs, key, value) do
    if List.keymember?(pairs, key, 0) do
      List.keyreplace(pairs, key, 0, {key, value})
    else
      pairs ++ [{key, value}]
    end
  end
end
