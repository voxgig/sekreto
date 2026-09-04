# The providers a Sekreto chains together.
#
# A provider answers one question: "do you have this secret?" It returns
# the value, or nil to mean "ask the next one". Nothing else about a
# provider is visible to the caller - which is the point: an app reads
# `api.token` and never learns whether it came from the environment, a
# .env file, HashiCorp Vault, AWS, GCP, Azure or a boru vault.
#
# Two failure shapes, and they are never interchangeable. A store that does
# not hold the secret is a MISS (nil) - the chain carries on. A store that
# could not answer - bad credentials, unreachable host, missing
# configuration - is an ERROR: falling through there would quietly reach
# for a weaker store.
#
# A port of typescript/src/Providers.ts, which is canonical.

defmodule Sekreto.AuthSpec do
  @moduledoc """
  Logging in to a vault instead of being handed a token. `method` is
  `kubernetes` or `approle`; `mount` defaults to the method name.
  """

  defstruct method: "",
            mount: "",
            # kubernetes: the Vault role to log in as.
            role: "",
            # kubernetes: the service-account JWT itself (tests).
            jwt: "",
            # kubernetes: where the JWT lives; the pod path by default.
            jwtfile: "",
            # approle: the role and secret ids.
            roleid: "",
            secretid: ""
end

# Printed without its credentials.
#
# The derived inspection prints every field, so `Logger.error("bad chain:
# #{inspect(specs)}")` - which is what someone writes when a chain will not
# build - would put the service-account JWT and the AppRole secret id in
# the log. Fields that hold a credential report whether they are set, never
# what they are.
defimpl Inspect, for: Sekreto.AuthSpec do
  def inspect(spec, _opts) do
    Inspect.Algebra.concat([
      "AuthSpec(method=#{spec.method}, mount=#{spec.mount}, role=#{spec.role}",
      ", jwtfile=#{spec.jwtfile}, roleid=#{spec.roleid}",
      ", jwt=#{Sekreto.Providers.setornot(spec.jwt)}",
      ", secretid=#{Sekreto.Providers.setornot(spec.secretid)})"
    ])
  end
end

defmodule Sekreto.ProviderSpec do
  @moduledoc """
  The declarative form of a provider, as used in config and in the shared
  spec. `kind` picks the provider; everything else is that kind's own.

  Every text field defaults to the empty string: "not configured" and
  "configured empty" mean the same thing everywhere in this library.
  """

  defstruct kind: "",
            # The store name `Sekreto.getfrom` addresses. Defaults to `kind`.
            name: "",
            prefix: "",
            # dotenv: the file to read. secretspec: the declaration to read.
            file: "",
            # memory: literal values, keyed like environment variables, in
            # order - a list of {key, value} pairs, not a map.
            values: [],
            # file: the directory of one-secret-per-file entries.
            dir: "",
            # hashicorp / boru (wire) / gcp / 1password / doppler /
            # infisical: the base URL.
            addr: "",
            # hashicorp / boru (wire) / gcp / azure / 1password / doppler /
            # infisical: the token.
            token: "",
            # hashicorp / boru (wire): the KV mount (default `secret`).
            mount: "",
            # hashicorp: KV engine version, 1 or 2 (default 2).
            kv: nil,
            # hashicorp: Vault Enterprise namespace (X-Vault-Namespace).
            vaultnamespace: "",
            # hashicorp: log in for a token instead of being handed one.
            auth: nil,
            # boru / secretspec: the executable to run.
            command: "",
            # secretspec: the profile to read (`--profile`).
            profile: "",
            # secretspec: which of ITS backends to read from (`--provider`),
            # e.g. `keyring` or `dotenv://.env`. Named `backend` here
            # because `provider` already means a sekreto provider.
            backend: "",
            # secretspec: the audit reason recorded for the read
            # (`--reason`). SecretSpec refuses to read without one.
            reason: "",
            # boru: the namespace qualifying the alias.
            namespace: "",
            # boru: the vault home, passed as BORU_HOME.
            home: "",
            # aws: region and credentials; the standard AWS_* variables
            # fill the rest.
            region: "",
            keyid: "",
            secret: "",
            session: "",
            # gcp / doppler / infisical: the project, however that store
            # names it.
            project: "",
            # azure: the Key Vault name or full URL. 1password: the vault
            # name or id.
            vault: "",
            # azure: client-credential login. infisical: universal-auth.
            tenant: "",
            clientid: "",
            clientsecret: "",
            # azure: where to log in / where IMDS answers. gcp: the
            # metadata server.
            loginaddr: "",
            imdsaddr: "",
            metadataaddr: "",
            # azure: the Key Vault API version (default 7.4).
            apiversion: "",
            # doppler: the config slug (with `project`).
            config: "",
            # infisical: the environment slug and secret path.
            environment: "",
            path: ""
end

# Printed without its credentials. See the AuthSpec implementation: the
# derived one would put the Vault token, the AWS secret access key and the
# Azure client secret into whatever formatted it.
defimpl Inspect, for: Sekreto.ProviderSpec do
  def inspect(spec, opts) do
    Inspect.Algebra.concat([
      "ProviderSpec(kind=#{spec.kind}, name=#{spec.name}, addr=#{spec.addr}",
      ", token=#{Sekreto.Providers.setornot(spec.token)}",
      ", secret=#{Sekreto.Providers.setornot(spec.secret)}",
      ", clientsecret=#{Sekreto.Providers.setornot(spec.clientsecret)}",
      ", auth=",
      if(nil == spec.auth, do: "nil", else: Inspect.inspect(spec.auth, opts)),
      ")"
    ])
  end
end

defmodule Sekreto.Providers do
  @moduledoc "The fourteen provider kinds, and the factory that builds them."

  alias Sekreto.AuthSpec
  alias Sekreto.Cell
  alias Sekreto.Error
  alias Sekreto.Http
  alias Sekreto.Json
  alias Sekreto.ProviderSpec
  alias Sekreto.Sigv4
  alias Sekreto.Signing

  # The Key Vault audience an Azure token is minted for.
  @resource "https://vault.azure.net"

  # A token with no expiry is never renewed.
  @never 9_223_372_036_854_775_807

  @doc "What a credential field reports about itself."
  def setornot(value), do: if("" == value or nil == value, do: "[unset]", else: "[set]")

  @doc "An environment variable, or the empty string."
  def getenv(name), do: System.get_env(name) || ""

  @doc "The first candidate that is set and non-empty, or the empty string."
  def first(candidates), do: Enum.find(candidates, "", fn value -> is_binary(value) and "" != value end)

  defp trimslash(text), do: Sekreto.dropsuffix(text, "/")

  # ------------------------------------------------------------ addresses

  @doc """
  An address with any userinfo replaced by `[redacted]`, for messages.

  Every refusal below names the address it refused, and one of them fires
  precisely because the address carries a credential - so printing it
  verbatim would write the password to stderr and into the logs. It cannot
  be cleaned up afterwards either: that password was never resolved as a
  secret, so `redact` has never seen it and never will. The host is what a
  reader needs to identify which chain entry is at fault; the userinfo is
  not.
  """
  def safeaddr(addr) do
    case :binary.match(addr, "://") do
      :nomatch ->
        addr

      {mark, _len} ->
        rest = binary_part(addr, mark + 3, byte_size(addr) - mark - 3)
        authority = authorityof(rest)

        case :binary.matches(authority, "@") do
          [] ->
            addr

          found ->
            {at, _len} = List.last(found)

            binary_part(addr, 0, mark + 3) <>
              "[redacted]" <>
              binary_part(addr, mark + 3 + at, byte_size(addr) - mark - 3 - at)
        end
    end
  end

  # The authority ends at `/`, `?` or `#` - and NOT at `\`, so a client
  # that also breaks on a backslash (WHATWG does) can only ever see a
  # SHORTER host than this does.
  defp authorityof(rest) do
    case cutat(rest, [?/, ??, ?#], 0) do
      nil -> rest
      at -> binary_part(rest, 0, at)
    end
  end

  defp cutat(text, chars, at) do
    case text do
      <<_::binary-size(at), ch, _::binary>> ->
        if ch in chars, do: at, else: cutat(text, chars, at + 1)

      _other ->
        nil
    end
  end

  @doc """
  Refuse to send a secret-bearing credential in the clear.

  A vault API is HTTPS in any real deployment; plaintext is a dev-mode
  convenience. Sending a token over http to anything but the local machine
  puts both the token and the secret it fetches on the wire for anyone on
  the path, so sekreto will not do it. Loopback stays allowed: that is
  `vault server -dev`, `boru vault serve`, and this repository's own test
  harness.

  The address is read by hand, in the same handful of steps in every port,
  rather than by each platform's URL parser. A dozen parsers disagree about
  malformed input - where userinfo ends, whether `0177.0.0.1` is loopback,
  what an unclosed bracket means - and a check that answers differently in
  different ports is not a check.
  """
  def checkaddr(addr) do
    scheme =
      cond do
        String.starts_with?(addr, "https://") -> "https://"
        String.starts_with?(addr, "http://") -> "http://"
        true -> raise Error, message: "sekreto: not an http(s) address: " <> safeaddr(addr)
      end

    rest = binary_part(addr, byte_size(scheme), byte_size(addr) - byte_size(scheme))
    authority = authorityof(rest)

    # Userinfo is refused outright rather than parsed around, and on https
    # as well as http. No store this library speaks authenticates by
    # userinfo - they take a token or a signature - so an address carrying
    # one is a mistake at best. At worst it is the attack this whole
    # function exists to stop: `http://localhost:8200@evil.example.com/` is
    # a request to evil.example.com that reads, to anything that splits the
    # authority on ':', as loopback.
    if String.contains?(authority, "@") do
      raise Error,
        message: "sekreto: refusing an address with embedded credentials: " <> safeaddr(addr)
    end

    # An opening bracket with no closing one is not an address at all.
    if String.starts_with?(authority, "[") and not String.contains?(authority, "]") do
      raise Error, message: "sekreto: not a valid http(s) address: " <> safeaddr(addr)
    end

    if "https://" != scheme do
      # A bracketed IPv6 literal keeps its brackets. Splitting the
      # authority on the first colon yields '[', so `http://[::1]:8200`
      # could never match - which made the '[::1]' entry below unreachable,
      # and refused a legitimate local vault.
      host =
        if String.starts_with?(authority, "[") do
          {at, _len} = :binary.match(authority, "]")
          binary_part(authority, 0, at + 1)
        else
          authority |> :binary.split(":") |> hd()
        end

      # Nothing is normalised: `0177.0.0.1`, `2130706433` and
      # `[::ffff:127.0.0.1]` are refused rather than guessed at.
      if String.downcase(host, :ascii) not in ["localhost", "127.0.0.1", "::1", "[::1]"] do
        raise Error,
          message:
            "sekreto: refusing to send a token in plaintext to " <>
              safeaddr(addr) <> " (use https)"
      end
    end

    :ok
  end

  # ---------------------------------------------------------- round-trips

  @doc """
  One JSON round-trip. Answers `%{status: integer, body: json | :none}`.

  Network failure is always an error - an unreachable store is a store that
  could not answer. A success status promised JSON, so a 200 whose body
  does not parse is a store that answered incoherently, and treating that
  as a miss would fall through to a weaker store. Error statuses may carry
  any body at all: they are decided on status alone.
  """
  def fetchjson(method, url, headers \\ [], body \\ nil) do
    answer = Http.fetch(method, url, headers, body)

    parsed =
      case Json.parse(answer.body) do
        {:ok, value} -> value
        :error -> :none
      end

    if 200 == answer.status and :none == parsed do
      raise Error, message: "sekreto: malformed response from " <> Http.bare(url)
    end

    %{status: answer.status, body: parsed}
  end

  @doc """
  Run a child to completion and collect both its streams.

  The BEAM's ports cannot give a parent the child's stderr on a channel of
  its own - and boru's and SecretSpec's miss detection is a phrase they
  print THERE, so merging it into stdout would put a diagnostic where a
  secret is supposed to be. The child is therefore started through `sh`
  with its stderr redirected to a file and its stdin taken from
  `/dev/null`, which also delivers the other two obligations: a CLI that
  prompts for a passphrase sees EOF rather than hanging, and a child that
  writes more than one 64 KiB pipe buffer to stderr cannot deadlock,
  because nothing is draining a pipe.

  The arguments go through `$0` and `$@`, so nothing is ever parsed by the
  shell, and the redirect target arrives in the environment rather than
  spliced into the script text.
  """
  def runcmd(command, args, env \\ []) do
    exe = System.find_executable(command)

    if nil == exe do
      raise Error, message: "sekreto: cannot run " <> command <> ": no such file or directory"
    end

    errfile =
      Path.join(
        System.tmp_dir() || "/tmp",
        "sekreto-stderr-#{:erlang.unique_integer([:positive])}"
      )

    script = ~s|exec "$0" "$@" </dev/null 2>"$SEKRETO_STDERR_FILE"|

    try do
      {out, status} =
        System.cmd("/bin/sh", ["-c", script, exe | args],
          env: [{"SEKRETO_STDERR_FILE", errfile} | env],
          stderr_to_stdout: false
        )

      why =
        case File.read(errfile) do
          {:ok, text} -> String.trim(text)
          {:error, _why} -> ""
        end

      %{out: out, why: why, status: status}
    rescue
      err in [ErlangError, ArgumentError] ->
        raise Error, message: "sekreto: cannot run " <> command <> ": " <> Exception.message(err)
    after
      File.rm(errfile)
    end
  end

  @doc """
  When a logged-in token must be renewed, from its expiry in seconds (a
  JSON number, or a string as Azure IMDS sends it): now + max(seconds - 60,
  1). A missing or zero expiry means never renew.
  """
  def renewtime(expires) do
    seconds =
      case expires do
        {:num, value} ->
          value

        {:str, value} ->
          case Float.parse(value) do
            {value, _rest} -> value
            :error -> 0.0
          end

        _other ->
          0.0
      end

    if 0 >= seconds do
      @never
    else
      System.system_time(:millisecond) + trunc(max(seconds - 60, 1.0) * 1000)
    end
  end

  defp expired?(cell) do
    held = Cell.get(cell)
    "" == held.token or System.system_time(:millisecond) >= held.renewat
  end

  # --------------------------------------------------------- the built-in
  #
  # "Built in" means: needs nothing of the platform beyond reading a local
  # file - no socket, no TLS, no crypto, no child process.

  @doc "Environment variables: `api.token` from `API_TOKEN`."
  def env(prefix \\ "", source \\ nil) do
    %{
      lookup: fn name ->
        key = Sekreto.envkey(name, prefix)
        if nil == source, do: System.get_env(key), else: Sekreto.pairget(source, key)
      end,
      describe: fn -> if "" == prefix, do: "env", else: "env:" <> prefix end
    }
  end

  @doc """
  Literal values, keyed like environment variables. The spec uses this to
  test chain behaviour without touching the outside world.
  """
  def memory(values \\ [], prefix \\ "") do
    %{
      lookup: fn name -> Sekreto.pairget(values, Sekreto.envkey(name, prefix)) end,
      describe: fn -> if "" == prefix, do: "memory", else: "memory:" <> prefix end
    }
  end

  @doc """
  A `.env` file, read once, keyed exactly like the environment.

  Read LAZILY: the `stores` corpus group puts a dotenv provider in a chain
  and never looks anything up, so an eager constructor would read whatever
  `.env` happened to sit in the working directory.
  """
  def dotenv(file, prefix \\ "") do
    cell = Cell.new(:unloaded)

    %{
      lookup: fn name ->
        values =
          case Cell.get(cell) do
            :unloaded ->
              loaded = loaddotenv(file)
              Cell.put(cell, loaded)
              loaded

            loaded ->
              loaded
          end

        Sekreto.pairget(values, Sekreto.envkey(name, prefix))
      end,
      describe: fn -> "dotenv:" <> file end
    }
  end

  defp loaddotenv(file) do
    case File.read(file) do
      {:ok, text} ->
        Sekreto.parsedotenv(text)

      # An absent file - or an absent directory - means "no secrets here",
      # exactly like the file provider. Anything else - permission denied,
      # an unreadable mount - is an error, because answering a miss there
      # falls silently through to a weaker store.
      {:error, why} when why in [:enoent, :enotdir] ->
        []

      {:error, why} ->
        raise Error,
          message: "sekreto: dotenv provider cannot read " <> file <> ": " <> errtext(why)
    end
  end

  defp errtext(why), do: to_string(:file.format_error(why))

  @doc """
  A directory of one-secret-per-file entries, keyed like the environment:
  `api.token` reads `<dir>/API_TOKEN`.

  This is the shape of a mounted Kubernetes Secret, a Docker or Swarm
  secret, and a systemd credentials directory, so those all work with no
  further configuration. Read on every lookup, never cached. One trailing
  newline is stripped - tools that write these files disagree about it, and
  a newline is never part of a secret on purpose.
  """
  def file(dir, prefix \\ "") do
    %{
      lookup: fn name ->
        path = Path.join(dir, Sekreto.envkey(name, prefix))

        case File.read(path) do
          {:ok, text} ->
            cond do
              String.ends_with?(text, "\r\n") -> Sekreto.dropsuffix(text, "\r\n")
              String.ends_with?(text, "\n") -> Sekreto.dropsuffix(text, "\n")
              true -> text
            end

          {:error, why} when why in [:enoent, :enotdir] ->
            nil

          {:error, why} ->
            raise Error,
              message: "sekreto: file provider cannot read " <> path <> ": " <> errtext(why)
        end
      end,
      describe: fn -> "file:" <> dir end
    }
  end

  # ------------------------------------------------------------ hashicorp

  @doc """
  HashiCorp Vault.

  KV v2 (the default): `api.token` reads `{addr}/v1/{mount}/data/api` and
  takes the `token` field of `data.data`. KV v1 reads
  `{addr}/v1/{mount}/api` and takes the field of `data`. A 404 means "not
  here" - a miss - so a vault can sit in a chain with fallbacks.

  A Vault Enterprise namespace rides the `X-Vault-Namespace` header, on
  logins as well as reads.

  Instead of being handed a token, the provider can log in: Kubernetes auth
  (the pod's service-account JWT, from its conventional path) or AppRole. A
  failed login is an error, never a miss - it means this store could not
  answer at all.
  """
  def hashicorp(addr, token, mountgiven, kvgiven, vaultnamespace, auth) do
    mount = first([mountgiven, "secret"])
    kv = kvgiven || 2

    # A version typo like kv: 3 must not quietly behave as v2 and turn its
    # 404s into misses; there is nothing safe to assume it meant.
    if 1 != kv and 2 != kv do
      raise Error, message: "sekreto: hashicorp: unsupported kv version: " <> tostr(kv)
    end

    # A configured token is kept forever; a logged-in token is renewed
    # shortly before its lease runs out - a long-running process must not
    # keep presenting a token the vault already expired.
    cell = Cell.new(%{token: token, renewat: @never})

    base = fn -> if "" == vaultnamespace, do: [], else: [{"X-Vault-Namespace", vaultnamespace}] end

    login = fn ->
      if nil == auth do
        raise Error, message: "sekreto: hashicorp: no token and no auth method"
      end

      authmount = first([auth.mount, auth.method])
      url = trimslash(addr) <> "/v1/auth/" <> authmount <> "/login"

      body =
        case auth.method do
          "kubernetes" ->
            jwt =
              if "" != auth.jwt do
                auth.jwt
              else
                jwtfile =
                  first([auth.jwtfile, "/var/run/secrets/kubernetes.io/serviceaccount/token"])

                case File.read(jwtfile) do
                  {:ok, text} ->
                    String.trim(text)

                  {:error, _why} ->
                    raise Error,
                      message: "sekreto: hashicorp: cannot read jwt file " <> jwtfile
                end
              end

            Json.obj([{"role", Json.str(auth.role)}, {"jwt", Json.str(jwt)}])

          "approle" ->
            Json.obj([
              {"role_id", Json.str(auth.roleid)},
              {"secret_id", Json.str(auth.secretid)}
            ])

          other ->
            raise Error, message: "sekreto: hashicorp: unknown auth method: " <> other
        end

      res = fetchjson("POST", url, base.(), Json.stringify(body))
      got = Json.text(Json.dig(res.body, ["auth", "client_token"]))

      if 200 != res.status or :none == got or "" == got do
        raise Error,
          message: "sekreto: hashicorp login failed: " <> tostr(res.status) <> ": " <> url
      end

      Cell.put(cell, %{
        token: got,
        renewat: renewtime(Json.dig(res.body, ["auth", "lease_duration"]))
      })
    end

    %{
      lookup: fn name ->
        checkaddr(addr)

        if expired?(cell), do: login.()

        ref = Sekreto.vaultref(name)
        stem = trimslash(addr) <> "/v1/" <> mount
        url = if 1 == kv, do: stem <> "/" <> ref.path, else: stem <> "/data/" <> ref.path

        headers = base.() ++ [{"X-Vault-Token", Cell.get(cell).token}]
        res = fetchjson("GET", url, headers)

        cond do
          404 == res.status ->
            nil

          200 != res.status ->
            raise Error,
              message: "sekreto: hashicorp error: " <> tostr(res.status) <> ": " <> url

          true ->
            data =
              if 1 == kv,
                do: Json.dig(res.body, ["data"]),
                else: Json.dig(res.body, ["data", "data"])

            nonone(Json.text(Json.dig(data, [ref.field])))
        end
      end,
      describe: fn -> "hashicorp:" <> addr <> "/" <> mount end
    }
  end

  # ----------------------------------------------------------------- boru

  @doc """
  A boru vault.

  Two ways in, both boru's own.

  With no `addr`, the CLI: `boru vault get --reveal <alias>` prints the
  secret on stdout and nothing else. The passphrase is read by boru itself
  from `BORU_VAULT_PASSPHRASE`; sekreto never accepts it as config and
  never puts it on a command line, where it would show up in the process
  table.

  With an `addr`, boru's wire protocol: a read-only, HashiCorp-shaped
  provision API authenticated by a capability token. A sekreto name is
  already a valid boru alias, and boru aliases keep their dots, so
  `api.token` is the single path segment `api.token` - not the `api`/`token`
  split a HashiCorp KV gets. The value is the `value` field.
  """
  def boru(commandgiven, namespace, home, addrgiven, token, mountgiven) do
    command = first([commandgiven, "boru"])
    addr = trimslash(addrgiven)
    mount = first([mountgiven, "secret"])

    %{
      lookup: fn name ->
        Sekreto.checkname(name)

        if "" != addr do
          checkaddr(addr)

          # The dotted name stays one path segment: boru aliases keep dots.
          alias_ = if "" == namespace, do: name, else: namespace <> "/" <> name
          url = addr <> "/v1/" <> mount <> "/data/" <> alias_

          res = fetchjson("GET", url, [{"X-Vault-Token", token}])

          cond do
            404 == res.status ->
              nil

            200 != res.status ->
              raise Error,
                message: "sekreto: boru serve error: " <> tostr(res.status) <> ": " <> url

            true ->
              nonone(Json.text(Json.dig(res.body, ["data", "data", "value"])))
          end
        else
          alias_ = if "" == namespace, do: name, else: namespace <> ":" <> name
          env = if "" == home, do: [], else: [{"BORU_HOME", home}]

          ran = runcmd(command, ["vault", "get", "--reveal", alias_], env)

          cond do
            # boru prints the value and one newline, and nothing else.
            0 == ran.status ->
              Sekreto.dropsuffix(ran.out, "\n")

            # "no alias named" is boru saying it does not hold this secret,
            # which is a miss. A locked vault or a wrong passphrase is not:
            # treating it as one would fall through to a weaker store
            # without saying so.
            borumiss(ran.why) ->
              nil

            true ->
              raise Error,
                message:
                  "sekreto: boru vault error: " <>
                    if("" == ran.why, do: "exit " <> tostr(ran.status), else: ran.why)
          end
        end
      end,
      describe: fn ->
        cond do
          "" != addr -> "boru:" <> addr
          "" != namespace -> "boru:" <> namespace
          true -> "boru"
        end
      end
    }
  end

  @doc """
  Does this boru failure mean "no such secret" rather than "I could not
  answer"? Matched on boru's own wording for a missing alias.
  """
  def borumiss(why), do: String.contains?(why, "no alias named")

  # ----------------------------------------------------------- secretspec

  @doc """
  SecretSpec.

  SecretSpec is a declaration - a `secretspec.toml` naming the secrets a
  project needs - plus a chain of its own backends to satisfy them from.
  That makes it the same shape as sekreto one level down, and the reason to
  support it is the same reason sekreto exists: a project that has already
  declared its secrets there should not have to declare them again here.

  A reason is required, not optional: SecretSpec records every read in an
  audit log and refuses to read at all without one.
  """
  def secretspec(commandgiven, file, profile, backend, reason, prefix) do
    command = first([commandgiven, "secretspec"])

    %{
      lookup: fn name ->
        key = Sekreto.envkey(name, prefix)

        args =
          (if "" == file, do: [], else: ["--file", file]) ++
            ["get", key] ++
            (if "" == backend, do: [], else: ["--provider", backend]) ++
            (if "" == profile, do: [], else: ["--profile", profile]) ++
            ["--reason", first([reason, "sekreto"])]

        ran = runcmd(command, args)

        cond do
          0 == ran.status ->
            Sekreto.dropsuffix(ran.out, "\n")

          secretspecmiss(ran.why, key) ->
            nil

          true ->
            raise Error,
              message:
                "sekreto: secretspec error: " <>
                  if("" == ran.why, do: "exit " <> tostr(ran.status), else: ran.why)
        end
      end,
      describe: fn -> if "" == backend, do: "secretspec", else: "secretspec:" <> backend end
    }
  end

  @doc """
  Does this SecretSpec failure mean "no such secret" rather than "I could
  not answer"?

  SecretSpec says `Secret 'API_TOKEN' not found` for both a name it does
  not declare and one declared with no value, and both are misses.

  MATCHED ON THE WHOLE PHRASE, NOT ON "not found". SecretSpec also says
  `Provider backend 'keyring' not found`, which is a store that could not
  answer at all - and reading that as a miss is the worst failure this
  library has, because the chain then falls through to a weaker store
  without saying so.
  """
  def secretspecmiss(why, key), do: String.contains?(why, "Secret '" <> key <> "' not found")

  # ------------------------------------------------------------------ aws

  @doc "The `YYYYMMDDTHHMMSSZ` timestamp SigV4 wants, for now."
  def awsnow do
    {{year, month, day}, {hour, minute, second}} = :calendar.universal_time()

    pad = fn value, width ->
      value |> Integer.to_string() |> String.pad_leading(width, "0")
    end

    pad.(year, 4) <>
      pad.(month, 2) <>
      pad.(day, 2) <> "T" <> pad.(hour, 2) <> pad.(minute, 2) <> pad.(second, 2) <> "Z"
  end

  @doc """
  Region and credentials, from config first and the standard AWS_*
  environment variables second - those are AWS's own convention, and a pod
  or CI job that has them set should just work. Missing either is an error:
  an AWS store with no credentials could not answer.
  """
  def awsauth(region, keyid, secret, session) do
    useregion = first([region, getenv("AWS_REGION"), getenv("AWS_DEFAULT_REGION")])
    usekeyid = first([keyid, getenv("AWS_ACCESS_KEY_ID")])
    usesecret = first([secret, getenv("AWS_SECRET_ACCESS_KEY")])
    usesession = first([session, getenv("AWS_SESSION_TOKEN")])

    if "" == useregion do
      raise Error, message: "sekreto: aws: no region (set region or AWS_REGION)"
    end

    if "" == usekeyid or "" == usesecret do
      raise Error,
        message:
          "sekreto: aws: no credentials" <>
            " (set keyid/secret or AWS_ACCESS_KEY_ID/AWS_SECRET_ACCESS_KEY)"
    end

    %{region: useregion, keyid: usekeyid, secret: usesecret, session: usesession}
  end

  @doc "One signed call to an AWS JSON-1.1 API."
  def awscall(opts, service, target, payload) do
    auth = awsauth(opts.region, opts.keyid, opts.secret, opts.session)

    # The China partition lives under its own suffix; every other
    # commercial region is plain amazonaws.com.
    suffix =
      if String.starts_with?(auth.region, "cn-"),
        do: ".amazonaws.com.cn",
        else: ".amazonaws.com"

    useaddr = first([opts.addr, "https://" <> service <> "." <> auth.region <> suffix])
    checkaddr(useaddr)

    url = trimslash(useaddr) <> "/"

    extras = [
      {"content-type", "application/x-amz-json-1.1"},
      {"x-amz-target", target}
    ]

    signed =
      Sigv4.sigv4(%Signing{
        method: "POST",
        url: url,
        service: service,
        region: auth.region,
        keyid: auth.keyid,
        secret: auth.secret,
        datetime: awsnow(),
        headers: extras,
        body: payload,
        session: auth.session
      })

    fetchjson("POST", url, extras ++ signed, payload)
  end

  @doc """
  Does this AWS error body name one of the not-found types? Those are a
  miss; every other failure is a store that could not answer.
  """
  def awsmiss(body, types) do
    case Json.asstr(Json.dig(body, ["__type"])) do
      :none -> false
      errtype -> Enum.any?(types, fn want -> String.contains?(errtype, want) end)
    end
  end

  @doc """
  AWS Secrets Manager.

  `api.token` reads the secret named `api` (the vaultref path, so
  `db.pass.main` reads `db/pass`) and takes the `token` field of its JSON
  SecretString - the AWS idiom of one JSON map per secret. A SecretString
  that is not JSON is the value itself, under the conventional field
  `value`.
  """
  def awssecrets(opts) do
    %{
      lookup: fn name ->
        ref = Sekreto.vaultref(name)

        res =
          awscall(
            opts,
            "secretsmanager",
            "secretsmanager.GetSecretValue",
            Json.stringify(Json.obj([{"SecretId", Json.str(ref.path)}]))
          )

        cond do
          400 == res.status and awsmiss(res.body, ["ResourceNotFoundException"]) ->
            nil

          200 != res.status ->
            raise Error, message: "sekreto: aws secretsmanager error: " <> tostr(res.status)

          true ->
            case Json.asstr(Json.dig(res.body, ["SecretString"])) do
              :none ->
                # A binary secret has no fields to address; only the
                # conventional `value` field can mean "the bytes
                # themselves".
                bin = Json.asstr(Json.dig(res.body, ["SecretBinary"]))

                if :none != bin and "value" == ref.field do
                  case unbase64(bin) do
                    :error ->
                      raise Error, message: "sekreto: aws secretsmanager: undecodable secret"

                    text ->
                      text
                  end
                end

              text ->
                case Json.parse(text) do
                  {:ok, {:obj, _pairs} = parsed} ->
                    nonone(Json.text(Json.dig(parsed, [ref.field])))

                  # A plain-string secret is the whole value; it has no
                  # named fields.
                  _other ->
                    if "value" == ref.field, do: text
                end
            end
        end
      end,
      # Config only, never the environment: describe() feeds the spec's
      # sources group, which must answer the same everywhere.
      describe: fn -> "awssecrets:" <> opts.region end
    }
  end

  @doc """
  AWS SSM Parameter Store.

  `db.pass.main` reads the parameter `/db/pass/main` (under an optional
  prefix path), decrypted. Parameter Store carries flat strings, so there
  is no field indirection.
  """
  def awsparams(opts, prefix) do
    %{
      lookup: fn name ->
        payload =
          Json.obj([
            {"Name", Json.str(Sekreto.awsparam(name, prefix))},
            {"WithDecryption", Json.bool(true)}
          ])

        res = awscall(opts, "ssm", "AmazonSSM.GetParameter", Json.stringify(payload))

        cond do
          400 == res.status and awsmiss(res.body, ["ParameterNotFound"]) ->
            nil

          200 != res.status ->
            raise Error, message: "sekreto: aws ssm error: " <> tostr(res.status)

          true ->
            nonone(Json.text(Json.dig(res.body, ["Parameter", "Value"])))
        end
      end,
      describe: fn -> "awsparams:" <> opts.region <> prefix end
    }
  end

  # ------------------------------------------------------------------ gcp

  @doc """
  GCP Secret Manager.

  `api.token` reads secret `api_token` (dots flattened to `_`; Secret
  Manager ids have no hierarchy and reject dots), latest version. The token
  comes from config, then `GOOGLE_OAUTH_ACCESS_TOKEN`, then the GCE/GKE
  metadata server - so on Google's own platform no credential configuration
  is needed at all.

  The metadata call itself is plain http to a link-local host by platform
  design; no credential rides on it, so `checkaddr` guards the Secret
  Manager address instead.
  """
  def gcpsecrets(project, token, addr, metadataaddr) do
    cell = Cell.new(%{token: "", renewat: @never})

    usemetadataaddr = fn ->
      cond do
        "" != metadataaddr -> metadataaddr
        "" != getenv("GCE_METADATA_HOST") -> "http://" <> getenv("GCE_METADATA_HOST")
        true -> "http://metadata.google.internal"
      end
    end

    login = fn ->
      configured = first([token, getenv("GOOGLE_OAUTH_ACCESS_TOKEN")])

      if "" != configured do
        Cell.put(cell, %{token: configured, renewat: @never})
      else
        url =
          trimslash(usemetadataaddr.()) <>
            "/computeMetadata/v1/instance/service-accounts/default/token"

        res = fetchjson("GET", url, [{"Metadata-Flavor", "Google"}])
        got = Json.text(Json.dig(res.body, ["access_token"]))

        if 200 != res.status or :none == got or "" == got do
          raise Error, message: "sekreto: gcp: no token and metadata server did not answer"
        end

        Cell.put(cell, %{token: got, renewat: renewtime(Json.dig(res.body, ["expires_in"]))})
      end
    end

    %{
      lookup: fn name ->
        if "" == project, do: raise(Error, message: "sekreto: gcp: no project")

        useaddr = first([addr, "https://secretmanager.googleapis.com"])
        checkaddr(useaddr)

        if expired?(cell), do: login.()

        url =
          trimslash(useaddr) <>
            "/v1/projects/" <>
            project <> "/secrets/" <> Sekreto.flatname(name, "_") <> "/versions/latest:access"

        res =
          fetchjson("GET", url, [{"authorization", "Bearer " <> Cell.get(cell).token}])

        cond do
          404 == res.status ->
            nil

          200 != res.status ->
            raise Error, message: "sekreto: gcp error: " <> tostr(res.status) <> ": " <> url

          true ->
            case Json.asstr(Json.dig(res.body, ["payload", "data"])) do
              :none ->
                nil

              data ->
                case unbase64(data) do
                  :error -> raise Error, message: "sekreto: gcp: undecodable secret"
                  text -> text
                end
            end
        end
      end,
      describe: fn -> "gcpsecrets:" <> project end
    }
  end

  # ---------------------------------------------------------------- azure

  @doc """
  Azure Key Vault.

  `api.token` reads secret `api-token` (dots flattened to `-`; Key Vault
  names allow nothing else), current version. The token comes from config,
  then a client-credentials login when tenant/clientid/clientsecret are
  given, then the IMDS managed-identity endpoint - so on Azure's own
  platform no credential configuration is needed.
  """
  def azuresecrets(opts) do
    cell = Cell.new(%{token: "", renewat: @never})

    login = fn ->
      cond do
        "" != opts.token ->
          Cell.put(cell, %{token: opts.token, renewat: @never})

        "" != opts.tenant and "" != opts.clientid and "" != opts.clientsecret ->
          useloginaddr = first([opts.loginaddr, "https://login.microsoftonline.com"])
          checkaddr(useloginaddr)

          url = trimslash(useloginaddr) <> "/" <> opts.tenant <> "/oauth2/v2.0/token"

          form =
            "grant_type=client_credentials&client_id=" <>
              Sigv4.uriescape(opts.clientid) <>
              "&client_secret=" <>
              Sigv4.uriescape(opts.clientsecret) <>
              "&scope=" <> Sigv4.uriescape(@resource <> "/.default")

          res =
            fetchjson(
              "POST",
              url,
              [{"content-type", "application/x-www-form-urlencoded"}],
              form
            )

          got = Json.text(Json.dig(res.body, ["access_token"]))

          if 200 != res.status or :none == got or "" == got do
            raise Error, message: "sekreto: azure login failed: " <> tostr(res.status)
          end

          Cell.put(cell, %{token: got, renewat: renewtime(Json.dig(res.body, ["expires_in"]))})

        true ->
          imds =
            trimslash(first([opts.imdsaddr, "http://169.254.169.254"])) <>
              "/metadata/identity/oauth2/token?api-version=2018-02-01&resource=" <>
              Sigv4.uriescape(@resource)

          res = fetchjson("GET", imds, [{"Metadata", "true"}])
          got = Json.text(Json.dig(res.body, ["access_token"]))

          if 200 != res.status or :none == got or "" == got do
            raise Error,
              message: "sekreto: azure: no token, no client credentials, and IMDS did not answer"
          end

          # IMDS sends expires_in as a STRING, unlike everyone else.
          Cell.put(cell, %{token: got, renewat: renewtime(Json.dig(res.body, ["expires_in"]))})
      end
    end

    %{
      lookup: fn name ->
        if "" == opts.vault, do: raise(Error, message: "sekreto: azure: no vault")

        # Only an explicit scheme is a URL; a vault NAMED httpvault must
        # still become https://httpvault.vault.azure.net.
        vaulturl =
          if String.starts_with?(opts.vault, "http://") or
               String.starts_with?(opts.vault, "https://") do
            opts.vault
          else
            "https://" <> opts.vault <> ".vault.azure.net"
          end

        checkaddr(vaulturl)

        if expired?(cell), do: login.()

        url =
          trimslash(vaulturl) <>
            "/secrets/" <>
            Sekreto.flatname(name, "-") <> "?api-version=" <> first([opts.apiversion, "7.4"])

        res = fetchjson("GET", url, [{"authorization", "Bearer " <> Cell.get(cell).token}])

        cond do
          404 == res.status ->
            nil

          200 != res.status ->
            raise Error,
              message: "sekreto: azure error: " <> tostr(res.status) <> ": " <> Http.bare(url)

          true ->
            nonone(Json.text(Json.dig(res.body, ["value"])))
        end
      end,
      describe: fn -> "azuresecrets:" <> opts.vault end
    }
  end

  # ------------------------------------------------------------ 1password

  @doc """
  1Password, through a Connect server.

  The item titled `api.token` (titles keep their dots), in the named vault.
  The value is the field with purpose PASSWORD, or the field labelled
  `value`. A vault that cannot be found is an error - config names it, so
  its absence is a broken store, not a missing secret.
  """
  def onepassword(addr, token, vault) do
    cell = Cell.new(:unresolved)
    auth = [{"authorization", "Bearer " <> token}]

    resolvevault = fn useaddr ->
      if "" == vault, do: raise(Error, message: "sekreto: onepassword: no vault")

      res = fetchjson("GET", useaddr <> "/v1/vaults", auth)
      list = Json.asarr(res.body)

      if 200 != res.status or :none == list do
        raise Error,
          message: "sekreto: onepassword error: " <> tostr(res.status) <> ": listing vaults"
      end

      found =
        Enum.find(list, fn entry ->
          vault == Json.text(Json.dig(entry, ["id"])) or
            vault == Json.text(Json.dig(entry, ["name"]))
        end)

      if nil == found do
        raise Error, message: "sekreto: onepassword: no vault named " <> vault
      end

      case Json.text(Json.dig(found, ["id"])) do
        :none -> ""
        id -> id
      end
    end

    %{
      lookup: fn name ->
        Sekreto.checkname(name)

        useaddr = trimslash(addr)
        if "" == useaddr, do: raise(Error, message: "sekreto: onepassword: no addr")
        checkaddr(useaddr)

        id =
          case Cell.get(cell) do
            :unresolved ->
              resolved = resolvevault.(useaddr)
              Cell.put(cell, resolved)
              resolved

            resolved ->
              resolved
          end

        filter = Sigv4.uriescape(~s|title eq "| <> name <> ~s|"|)
        found = fetchjson("GET", useaddr <> "/v1/vaults/" <> id <> "/items?filter=" <> filter, auth)

        items = Json.asarr(found.body)

        if 200 != found.status or :none == items do
          raise Error,
            message: "sekreto: onepassword error: " <> tostr(found.status) <> ": finding " <> name
        end

        if [] == items do
          nil
        else
          itemid =
            case Json.text(Json.dig(hd(items), ["id"])) do
              :none -> ""
              value -> value
            end

          item = fetchjson("GET", useaddr <> "/v1/vaults/" <> id <> "/items/" <> itemid, auth)

          if 200 != item.status do
            raise Error,
              message:
                "sekreto: onepassword error: " <> tostr(item.status) <> ": reading " <> name
          end

          fields =
            case Json.asarr(Json.dig(item.body, ["fields"])) do
              :none -> []
              value -> value
            end

          # Two full passes, in order: purpose first, then label.
          chosen =
            Enum.find(fields, fn field ->
              "PASSWORD" == Json.asstr(Json.dig(field, ["purpose"]))
            end) ||
              Enum.find(fields, fn field ->
                "value" == Json.asstr(Json.dig(field, ["label"]))
              end)

          if nil == chosen, do: nil, else: nonone(Json.text(Json.dig(chosen, ["value"])))
        end
      end,
      describe: fn -> "onepassword:" <> vault end
    }
  end

  # -------------------------------------------------------------- doppler

  @doc """
  Doppler.

  The whole config is downloaded once - Doppler's own bulk endpoint - and
  answered from memory, like a remote .env: `api.token` is the `API_TOKEN`
  entry. A service token is config-scoped, so project and config are only
  needed with broader tokens.

  The `prefix` option is not consulted by this kind.
  """
  def doppler(token, project, config, addr) do
    cell = Cell.new(:unloaded)

    load = fn ->
      useaddr = trimslash(first([addr, "https://api.doppler.com"]))
      checkaddr(useaddr)

      url =
        useaddr <>
          "/v3/configs/config/secrets/download?format=json" <>
          if("" == project, do: "", else: "&project=" <> Sigv4.uriescape(project)) <>
          if("" == config, do: "", else: "&config=" <> Sigv4.uriescape(config))

      res = fetchjson("GET", url, [{"authorization", "Bearer " <> token}])
      body = Json.asobj(res.body)

      if 200 != res.status or :none == body do
        raise Error, message: "sekreto: doppler error: " <> tostr(res.status)
      end

      Enum.reduce(body, [], fn {key, value}, out ->
        case Json.text(value) do
          :none -> out
          text -> Sekreto.pairput(out, key, text)
        end
      end)
    end

    %{
      lookup: fn name ->
        values =
          case Cell.get(cell) do
            :unloaded ->
              # A failed load caches nothing, so the next lookup retries.
              loaded = load.()
              Cell.put(cell, loaded)
              loaded

            loaded ->
              loaded
          end

        Sekreto.pairget(values, Sekreto.envkey(name))
      end,
      describe: fn ->
        if "" == project, do: "doppler", else: "doppler:" <> project <> "/" <> config
      end
    }
  end

  # ------------------------------------------------------------ infisical

  @doc """
  Infisical.

  `api.token` reads the secret keyed `API_TOKEN` (Infisical's own
  convention is environment-style keys) at a secret path in one environment
  of a project. Auth is a token, or a universal-auth (machine identity)
  login with clientid/clientsecret.
  """
  def infisical(opts) do
    cell = Cell.new(%{token: "", renewat: @never})

    login = fn useaddr ->
      if "" != opts.token do
        Cell.put(cell, %{token: opts.token, renewat: @never})
      else
        if "" == opts.clientid or "" == opts.clientsecret do
          raise Error, message: "sekreto: infisical: no token and no client credentials"
        end

        body =
          Json.obj([
            {"clientId", Json.str(opts.clientid)},
            {"clientSecret", Json.str(opts.clientsecret)}
          ])

        res =
          fetchjson(
            "POST",
            useaddr <> "/api/v1/auth/universal-auth/login",
            [{"content-type", "application/json"}],
            Json.stringify(body)
          )

        got = Json.text(Json.dig(res.body, ["accessToken"]))

        if 200 != res.status or :none == got or "" == got do
          raise Error, message: "sekreto: infisical login failed: " <> tostr(res.status)
        end

        # camelCase, unlike everyone else's expires_in.
        Cell.put(cell, %{token: got, renewat: renewtime(Json.dig(res.body, ["expiresIn"]))})
      end
    end

    %{
      lookup: fn name ->
        useaddr = trimslash(first([opts.addr, "https://app.infisical.com"]))
        checkaddr(useaddr)

        if "" == opts.project or "" == opts.environment do
          raise Error, message: "sekreto: infisical: no project/environment"
        end

        if expired?(cell), do: login.(useaddr)

        url =
          useaddr <>
            "/api/v3/secrets/raw/" <>
            Sekreto.envkey(name) <>
            "?workspaceId=" <>
            Sigv4.uriescape(opts.project) <>
            "&environment=" <>
            Sigv4.uriescape(opts.environment) <>
            "&secretPath=" <> Sigv4.uriescape(first([opts.path, "/"]))

        res = fetchjson("GET", url, [{"authorization", "Bearer " <> Cell.get(cell).token}])

        cond do
          404 == res.status -> nil
          200 != res.status -> raise Error, message: "sekreto: infisical error: " <> tostr(res.status)
          true -> nonone(Json.text(Json.dig(res.body, ["secret", "secretValue"])))
        end
      end,
      describe: fn -> "infisical:" <> opts.project <> "/" <> opts.environment end
    }
  end

  # ---------------------------------------------------------------- shared

  @doc """
  Strict base64.

  Whitespace is stripped first - the canonical function accepts embedded
  newlines - and then anything outside the standard alphabet, or a length
  that is not a multiple of four, is REFUSED. A lenient decoder silently
  skips what it does not recognise and hands back plausible bytes for a
  corrupted payload, which then get returned as the secret.
  """
  def unbase64(text) do
    stripped = String.replace(text, ~r/\s/, "")

    case Base.decode64(stripped, padding: true) do
      {:ok, bytes} -> bytes
      :error -> :error
    end
  end

  defp nonone(:none), do: nil
  defp nonone(value), do: value

  defp tostr(value) when is_binary(value), do: value
  defp tostr(value) when is_integer(value), do: Integer.to_string(value)
  defp tostr(value) when is_float(value), do: Json.numstr(value)
  defp tostr(value), do: inspect(value)

  # --------------------------------------------------------- the factory

  @doc """
  Build a provider from its declarative form - the same shape the shared
  spec and an app's config file use.
  """
  def makeprovider(%ProviderSpec{} = spec) do
    awsopts = %{
      region: spec.region,
      keyid: spec.keyid,
      secret: spec.secret,
      session: spec.session,
      addr: spec.addr
    }

    case spec.kind do
      "env" ->
        env(spec.prefix)

      "dotenv" ->
        dotenv(first([spec.file, ".env"]), spec.prefix)

      "memory" ->
        memory(spec.values, spec.prefix)

      "file" ->
        file(spec.dir, spec.prefix)

      "hashicorp" ->
        hashicorp(spec.addr, spec.token, spec.mount, spec.kv, spec.vaultnamespace, spec.auth)

      "boru" ->
        boru(spec.command, spec.namespace, spec.home, spec.addr, spec.token, spec.mount)

      "awssecrets" ->
        awssecrets(awsopts)

      "awsparams" ->
        awsparams(awsopts, spec.prefix)

      "gcpsecrets" ->
        gcpsecrets(spec.project, spec.token, spec.addr, spec.metadataaddr)

      "azuresecrets" ->
        azuresecrets(%{
          vault: spec.vault,
          token: spec.token,
          tenant: spec.tenant,
          clientid: spec.clientid,
          clientsecret: spec.clientsecret,
          loginaddr: spec.loginaddr,
          imdsaddr: spec.imdsaddr,
          apiversion: spec.apiversion
        })

      "onepassword" ->
        onepassword(spec.addr, spec.token, spec.vault)

      "doppler" ->
        doppler(spec.token, spec.project, spec.config, spec.addr)

      "infisical" ->
        infisical(%{
          addr: spec.addr,
          token: spec.token,
          clientid: spec.clientid,
          clientsecret: spec.clientsecret,
          project: spec.project,
          environment: spec.environment,
          path: spec.path
        })

      "secretspec" ->
        secretspec(spec.command, spec.file, spec.profile, spec.backend, spec.reason, spec.prefix)

      other ->
        raise Error, message: "sekreto: unknown provider kind: " <> other
    end
  end

  @doc "An AuthSpec, for callers building one by hand."
  def authspec(fields \\ []), do: struct(AuthSpec, fields)
end
