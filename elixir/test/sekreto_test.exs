# RUN: make test
# RUN-SOME: elixir -pa build -pa $PLUGIN/elixir/build -pa $OMNI/elixir/build \
#             test/sekreto_test.exs envkey
#
# The sekreto conformance suite. Every port runs these same groups, from
# the same spec/sekreto.json, through its own voxgig/omni runner.
#
# THIS SUITE LOADS EVERY PLUGIN, deliberately. The spec is the contract for
# the whole library and exercises all fourteen provider kinds, so every
# Sekreto built here is handed the full set. That is the split working, not
# a leak of it: a CONSUMER passes the kinds it configures and needs nothing
# else, while the suite that proves all fourteen behave has to have all
# fourteen. What this suite therefore cannot see - a consumer's list, a
# kind that was not passed in, the core reaching a plugin - is pinned by
# test/plugins_test.exs.
#
# `sigv4` lives with the aws plugin now: it is the crypto edge, and only
# the two aws kinds use it (docs/design/plugin-providers.md).
#
# No third-party test framework: a failing omni check raises
# Voxgig.Omni.OmniError, so any host framework (ExUnit) reports it as a
# failure. This harness keeps `make test` dependency-free.
#
# Two value models meet here. omni's are plain Elixir values, with absence
# marked by an atom of its own; the library takes typed specs, ordered pair
# lists for anything whose order is signed, and `nil` for a miss. The
# bridge below converts between them explicitly, so nothing about absent,
# null and value is guessed.

alias Sekreto.AuthSpec
alias Sekreto.Plugins
alias Sekreto.Plugins.Signing
alias Sekreto.ProviderSpec
alias Voxgig.Omni.OmniError
alias Voxgig.Omni.Runner
alias Voxgig.Omni.Util, as: U

defmodule SekretoTest do
  @moduledoc "The sekreto conformance harness for the Elixir port."

  alias Sekreto.AuthSpec
  alias Sekreto.Plugins
  alias Sekreto.ProviderSpec
  alias Voxgig.Omni.OmniError
  alias Voxgig.Omni.Util, as: U

  @doc "Find the shared spec directory by walking up from the working dir."
  def specfile(name) do
    Enum.reduce_while(0..7, File.cwd!(), fn _step, dir ->
      cand = Path.join([dir, "spec", name])
      if File.exists?(cand), do: {:halt, cand}, else: {:cont, Path.dirname(dir)}
    end)
    |> case do
      path when is_binary(path) ->
        if String.ends_with?(path, name) do
          path
        else
          raise OmniError, message: "sekreto: spec not found: #{name}"
        end
    end
  end

  # ------------------------------------------------------------ the bridge

  @doc "omni's model -> a plain value: absent and null both read as nil."
  def plain(value), do: if(U.isnone(value), do: nil, else: value)

  @doc "A map entry as text, or the empty string - the library's own default."
  def str(entry, key) do
    case U.get(entry, key) do
      value when is_binary(value) -> value
      _other -> ""
    end
  end

  @doc "One provider spec, out of the spec's declarative chain description."
  def specof(entry) do
    values =
      case U.get(entry, "values") do
        source when is_map(source) ->
          Enum.map(source, fn {key, value} -> {key, U.stringify(value)} end)

        _other ->
          []
      end

    auth =
      case U.get(entry, "auth") do
        source when is_map(source) ->
          %AuthSpec{
            method: str(source, "method"),
            mount: str(source, "mount"),
            role: str(source, "role"),
            jwt: str(source, "jwt"),
            jwtfile: str(source, "jwtfile"),
            roleid: str(source, "roleid"),
            secretid: str(source, "secretid")
          }

        _other ->
          nil
      end

    kv =
      case U.get(entry, "kv") do
        value when is_number(value) -> trunc(value)
        _other -> nil
      end

    %ProviderSpec{
      kind: str(entry, "kind"),
      name: str(entry, "name"),
      prefix: str(entry, "prefix"),
      file: str(entry, "file"),
      values: values,
      dir: str(entry, "dir"),
      addr: str(entry, "addr"),
      token: str(entry, "token"),
      mount: str(entry, "mount"),
      kv: kv,
      vaultnamespace: str(entry, "vaultnamespace"),
      auth: auth,
      command: str(entry, "command"),
      profile: str(entry, "profile"),
      backend: str(entry, "backend"),
      reason: str(entry, "reason"),
      namespace: str(entry, "namespace"),
      home: str(entry, "home"),
      region: str(entry, "region"),
      keyid: str(entry, "keyid"),
      secret: str(entry, "secret"),
      session: str(entry, "session"),
      project: str(entry, "project"),
      vault: str(entry, "vault"),
      tenant: str(entry, "tenant"),
      clientid: str(entry, "clientid"),
      clientsecret: str(entry, "clientsecret"),
      loginaddr: str(entry, "loginaddr"),
      imdsaddr: str(entry, "imdsaddr"),
      metadataaddr: str(entry, "metadataaddr"),
      apiversion: str(entry, "apiversion"),
      config: str(entry, "config"),
      environment: str(entry, "environment"),
      path: str(entry, "path")
    }
  end

  @doc """
  Build a Sekreto from the spec's declarative chain description.

  Called INSIDE each subject, never before: four corpus entries expect
  `unsupported kv version`, which the constructor raises, and only a
  constructor call inside the subject reaches omni as a subject error.
  """
  def chainof(entry) do
    chain =
      case U.get(entry, "chain") do
        list when is_list(list) -> Enum.map(list, &specof/1)
        _other -> []
      end

    Sekreto.new(chain, plugins: Plugins.all(), cache: false)
  end

  @doc "The name a group's entry asks about."
  def namearg(entry), do: str(entry, "name")

  # ----------------------------------------------------------- the runner

  def testcase(name, body, {only, pass, fail}) do
    if nil != only and name != only do
      {only, pass, fail}
    else
      try do
        body.()
        IO.puts("ok   - #{name}")
        {only, pass + 1, fail}
      rescue
        err ->
          IO.puts("FAIL - #{name}")
          IO.puts(Exception.message(err))
          {only, pass, fail + 1}
      end
    end
  end
end

# ---------------------------------------------------------- the subjects

# `validname` answers whatever the language calls true; the spec says JSON
# true, so the adaptation happens here rather than in the library.
validname = fn args -> Sekreto.validname(SekretoTest.plain(hd(args))) end

envkey = fn args ->
  Sekreto.envkey(SekretoTest.plain(U.get(hd(args), "name")), SekretoTest.str(hd(args), "prefix"))
end

vaultref = fn args ->
  ref = Sekreto.vaultref(SekretoTest.plain(hd(args)))
  %{"path" => ref.path, "field" => ref.field}
end

flatname = fn args ->
  Sekreto.flatname(SekretoTest.plain(U.get(hd(args), "name")), SekretoTest.str(hd(args), "sep"))
end

awsparam = fn args ->
  Sekreto.awsparam(SekretoTest.plain(U.get(hd(args), "name")), SekretoTest.str(hd(args), "prefix"))
end

# The library answers an ORDERED pair list; the spec compares a JSON
# object, which omni holds as a map.
parsedotenv = fn args -> Map.new(Sekreto.parsedotenv(SekretoTest.plain(hd(args)))) end

resolve = fn args -> Sekreto.get(SekretoTest.chainof(hd(args)), SekretoTest.namearg(hd(args))) end

trysecret = fn args ->
  Sekreto.tryget(SekretoTest.chainof(hd(args)), SekretoTest.namearg(hd(args)))
end

sources = fn args -> Sekreto.sources(SekretoTest.chainof(hd(args))) end

stores = fn args -> Sekreto.stores(SekretoTest.chainof(hd(args))) end

getfrom = fn args ->
  Sekreto.getfrom(
    SekretoTest.chainof(hd(args)),
    SekretoTest.str(hd(args), "store"),
    SekretoTest.namearg(hd(args))
  )
end

tryfrom = fn args ->
  Sekreto.tryfrom(
    SekretoTest.chainof(hd(args)),
    SekretoTest.str(hd(args), "store"),
    SekretoTest.namearg(hd(args))
  )
end

# Answers the ordered output map itself, which omni compares as a JSON
# object against the spec's known-answer signatures.
sigv4 = fn args ->
  entry = hd(args)

  headers =
    case U.get(entry, "headers") do
      source when is_map(source) ->
        Enum.map(source, fn {key, value} -> {key, U.stringify(value)} end)

      _other ->
        []
    end

  Map.new(
    Sekreto.Plugins.Sigv4.sigv4(%Signing{
      method: SekretoTest.str(entry, "method"),
      url: SekretoTest.str(entry, "url"),
      service: SekretoTest.str(entry, "service"),
      region: SekretoTest.str(entry, "region"),
      keyid: SekretoTest.str(entry, "keyid"),
      secret: SekretoTest.str(entry, "secret"),
      datetime: SekretoTest.str(entry, "datetime"),
      headers: headers,
      body: SekretoTest.str(entry, "body"),
      session: SekretoTest.str(entry, "session")
    })
  )
end

redact = fn args ->
  values =
    case U.get(hd(args), "values") do
      list when is_list(list) -> Enum.map(list, &SekretoTest.plain/1)
      _other -> []
    end

  Sekreto.redact(SekretoTest.plain(U.get(hd(args), "text")), values)
end

# ------------------------------------------------------------- the spine

only = List.first(System.argv())

pack = Runner.make_runner(SekretoTest.specfile("sekreto.json")).("sekreto", nil)

state = {only, 0, 0}

# validname is the only group carrying real JSON nulls as inputs, so it is
# the only one that runs with null-normalisation off.
state =
  SekretoTest.testcase(
    "validname",
    fn -> pack.runsetflags.(pack.set.("validname"), %{null: false}, validname) end,
    state
  )

state = SekretoTest.testcase("envkey", fn -> pack.runset.(pack.set.("envkey"), envkey) end, state)

state =
  SekretoTest.testcase("vaultref", fn -> pack.runset.(pack.set.("vaultref"), vaultref) end, state)

state =
  SekretoTest.testcase("flatname", fn -> pack.runset.(pack.set.("flatname"), flatname) end, state)

state =
  SekretoTest.testcase("awsparam", fn -> pack.runset.(pack.set.("awsparam"), awsparam) end, state)

state =
  SekretoTest.testcase(
    "parsedotenv",
    fn -> pack.runset.(pack.set.("parsedotenv"), parsedotenv) end,
    state
  )

state =
  SekretoTest.testcase("resolve", fn -> pack.runset.(pack.set.("resolve"), resolve) end, state)

state =
  SekretoTest.testcase(
    "trysecret",
    fn -> pack.runset.(pack.set.("trysecret"), trysecret) end,
    state
  )

state =
  SekretoTest.testcase("sources", fn -> pack.runset.(pack.set.("sources"), sources) end, state)

state = SekretoTest.testcase("stores", fn -> pack.runset.(pack.set.("stores"), stores) end, state)

state =
  SekretoTest.testcase("getfrom", fn -> pack.runset.(pack.set.("getfrom"), getfrom) end, state)

state =
  SekretoTest.testcase("tryfrom", fn -> pack.runset.(pack.set.("tryfrom"), tryfrom) end, state)

state = SekretoTest.testcase("sigv4", fn -> pack.runset.(pack.set.("sigv4"), sigv4) end, state)

state = SekretoTest.testcase("redact", fn -> pack.runset.(pack.set.("redact"), redact) end, state)

{_only, passcount, failcount} = state

IO.puts("\n#{passcount} passed, #{failcount} failed")

System.halt(if 0 == failcount, do: 0, else: 1)
