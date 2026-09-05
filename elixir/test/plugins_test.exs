# RUN: make test
# RUN-SOME: elixir -pa build -pa $PLUGIN/elixir/build test/plugins_test.exs unknownkind
#
# THE PLUGIN SEAM, from both sides.
#
# Moving the provider kinds that open sockets and spawn processes out of
# the core made a consumer's PLUGIN LIST load-bearing: a kind nobody
# passed in is not in the catalog, and a chain naming it is refused. That
# is the intended behaviour, and it means a consumer can be broken without
# a single conformance test noticing - the conformance suite passes every
# plugin to every chain it builds, so it can never see a missing one. So
# the full set is pinned here: it holds every kind, every kind builds, and
# the CLI passes it.
#
# The other half is the boundary itself, and on the BEAM that is the
# MODULE REFERENCE GRAPH. Every beam carries an `imports` chunk - the
# exact {module, function, arity} of every remote call the compiler
# emitted - and the runtime loads a module the first time something calls
# into it, so that graph is not a proxy for what gets loaded, it is the
# thing itself. These tests read it, and then check the reading against a
# FRESH BEAM, which no assertion inside this one could fake: this process
# has loaded everything, on purpose, by running the tests above.
#
# A translation of python/tests/test_plugins.py, which is the model.

alias Sekreto.Plugins
alias Sekreto.Plugins.Hashicorp
alias Sekreto.ProviderSpec
alias Voxgig.Plugin.Catalog
alias Voxgig.Plugin.Host

defmodule PluginsTest do
  @moduledoc "The plugin-seam suite for the Elixir port."

  @plugins ~w(awsparams awssecrets azuresecrets boru doppler gcpsecrets
              hashicorp infisical onepassword secretspec)

  @builtin ~w(dotenv env file memory)

  @doc "The ten plugin kinds, sorted."
  def plugins, do: @plugins

  @doc "All fourteen kinds, sorted."
  def every, do: Enum.sort(@builtin ++ @plugins)

  # ------------------------------------------------------------ the checks

  def same(want, got, what) do
    if want != got do
      raise RuntimeError,
        message: "#{what}:\n  want: #{inspect(want)}\n  got:  #{inspect(got)}"
    end
  end

  def holds(got, want, what) do
    if not (is_binary(got) and String.contains?(got, want)) do
      raise RuntimeError,
        message: "#{what}:\n  want to contain: #{want}\n  got: #{excerpt(got)}"
    end
  end

  # A whole source file is a haystack, and printing one as the failure of a
  # one-line assertion buries the assertion.
  defp excerpt(text) when is_binary(text) and 400 < byte_size(text),
    do: inspect(binary_part(text, 0, 200)) <> " ... (#{byte_size(text)} bytes)"

  defp excerpt(text), do: inspect(text)

  def lacks(got, want, what) do
    if is_binary(got) and String.contains?(got, want) do
      raise RuntimeError, message: "#{what}:\n  want NOT to contain: #{want}\n  got: #{got}"
    end
  end

  @doc "The message a `Sekreto.Error` refused a construction with."
  def refused(body) do
    try do
      body.()
      raise RuntimeError, message: "nothing refused"
    rescue
      err in Sekreto.Error -> Exception.message(err)
    end
  end

  @doc "Whatever a construction raised, sekreto error or not."
  def raised(body) do
    try do
      body.()
      raise RuntimeError, message: "nothing raised"
    rescue
      err -> err
    end
  end

  # ------------------------------------------------------- the beam reader

  @doc """
  The modules one compiled module calls into: its `imports` chunk, which
  is this runtime's link map.

  It sees what a source grep cannot - a call through an alias, a capture
  or a macro is in here all the same - and what a require graph cannot,
  because elixir has no require graph to read.
  """
  def references(module) do
    {:ok, {^module, [imports: imports]}} =
      :beam_lib.chunks(:code.which(module), [:imports])

    imports |> Enum.map(fn {mod, _fun, _arity} -> mod end) |> Enum.uniq() |> Enum.sort()
  end

  @doc "Everything a module reaches, transitively, within this library."
  def closure(module), do: closure([module], MapSet.new())

  defp closure([], seen), do: seen |> MapSet.to_list() |> Enum.sort()

  defp closure([module | rest], seen) do
    if MapSet.member?(seen, module) do
      closure(rest, seen)
    else
      more =
        module
        |> references()
        |> Enum.filter(&String.starts_with?(Atom.to_string(&1), "Elixir.Sekreto"))

      closure(rest ++ more, MapSet.put(seen, module))
    end
  end

  # ------------------------------------------------------- the fresh probe

  @doc "This port's own directory, wherever the suite was started from."
  def here do
    Enum.reduce_while(0..7, File.cwd!(), fn _step, dir ->
      if File.exists?(Path.join(dir, "cli/cli.ex")),
        do: {:halt, dir},
        else: {:cont, Path.dirname(dir)}
    end)
  end

  @doc """
  Where voxgig/plugin's beams are, taken from THIS process's own code path
  rather than searched for: the Makefile put them there, and a probe has
  to run with the same dependency the suite is running with.
  """
  def pluginbuild do
    case Enum.find(:code.get_path(), fn dir ->
           File.exists?(Path.join(to_string(dir), "Elixir.Voxgig.Plugin.beam"))
         end) do
      nil -> raise RuntimeError, message: "sekreto: voxgig/plugin is not on the code path"
      dir -> to_string(dir)
    end
  end

  @doc """
  Run one expression in a FRESH BEAM on the given code path, and answer
  what it printed.

  A new process because this one has loaded every module in the library by
  running the tests above, and because a code path is fixed when a node
  starts: "what a build carries" is a question only a new node can answer.

  The child's stderr is folded into its stdout on purpose. A probe that
  answers a list of module names must answer nothing else, so a warning
  the child printed has to break the comparison rather than pass unread.
  """
  def fresh(paths, code) do
    args = Enum.flat_map(paths, fn path -> ["-pa", path] end) ++ ["-e", code]

    {out, status} = System.cmd(System.find_executable("elixir"), args, stderr_to_stdout: true)

    if 0 != status do
      raise RuntimeError, message: "sekreto: probe failed:\n#{out}"
    end

    String.trim(out)
  end

  @doc "The library's own modules a fresh BEAM has loaded, after `code`."
  def loaded(paths, code) do
    fresh(paths, code <> """
    ;IO.puts(:code.all_loaded()
      |> Enum.map(fn {m, _} -> Atom.to_string(m) end)
      |> Enum.filter(&String.starts_with?(&1, "Elixir.Sekreto"))
      |> Enum.map(&String.replace_prefix(&1, "Elixir.", ""))
      |> Enum.sort()
      |> Enum.join(" "))
    """)
  end

  # ------------------------------------------------------------ the runner

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
          IO.puts("  " <> Exception.message(err))
          {only, pass, fail + 1}
      end
    end
  end
end

# --------------------------------------------------------------- the tests

# A provider that shouts: the smallest custom kind there is.
shouty = fn values ->
  %{
    lookup: fn name -> Sekreto.pairget(values, String.upcase(name)) end,
    describe: fn -> "shouty" end
  }
end

fullset = fn ->
  PluginsTest.same(
    PluginsTest.plugins(),
    Enum.sort(Enum.map(Plugins.all(), & &1["name"])),
    "Plugins.all/0"
  )

  # Two kinds, one module: aws ships both stores because they share a
  # signer, so the list is ten definitions from nine modules.
  PluginsTest.same(10, length(Plugins.all()), "length(Plugins.all/0)")

  PluginsTest.same(Sekreto.kinds().builtin, Enum.map(Sekreto.builtins(), & &1["name"]), "builtins")
  PluginsTest.same(PluginsTest.plugins(), Enum.sort(Sekreto.kinds().plugin), "kinds().plugin")
end

# Naming a kind is not enough: a kind can be in the catalog and still fail
# to build. Construction is what the CLI does before any network.
everykindbuilds = fn ->
  chain =
    Enum.map(PluginsTest.every(), fn kind ->
      %ProviderSpec{
        kind: kind,
        addr: "http://127.0.0.1:8200",
        token: "t",
        dir: "/tmp",
        file: "/tmp/.env",
        values: []
      }
    end)

  secrets = Sekreto.new(chain, plugins: Plugins.all())

  PluginsTest.same(PluginsTest.every(), Sekreto.stores(secrets), "stores")
  PluginsTest.same(PluginsTest.every(), Enum.sort(Map.keys(Host.list(secrets.host))), "host list")
  PluginsTest.same(["live"], Enum.uniq(Map.values(Host.list(secrets.host))), "instance statuses")
  PluginsTest.same(PluginsTest.every(), Catalog.names(secrets.catalog), "catalog names")
end

# The one thing the conformance suite genuinely cannot see: it hands every
# plugin to every chain it builds, so a CLI passing one instead of ten
# leaves all fourteen groups green and fails nine integration checks.
#
# Pinned as the WHOLE call, closing bracket included: `Plugins.all()` alone
# is still a substring of `Enum.take(Plugins.all(), 1)`.
clipassesfullset = fn ->
  src = File.read!(Path.join(PluginsTest.here(), "cli/cli.ex"))

  PluginsTest.holds(src, "alias Sekreto.Plugins\n", "cli.ex")
  PluginsTest.holds(src, "Sekreto.new(chainfor(source), plugins: Plugins.all())", "cli.ex")
end

# ------------------------------------------------------- what a consumer sees

oneplugin = fn ->
  secrets =
    Sekreto.new(
      [
        %ProviderSpec{kind: "memory", values: [{"API_TOKEN", "tok01"}]},
        %ProviderSpec{
          kind: "hashicorp",
          name: "prod",
          addr: "https://vault.example.com",
          token: "t"
        }
      ],
      plugins: [Hashicorp.hashicorp()]
    )

  PluginsTest.same(["memory", "prod"], Sekreto.stores(secrets), "stores")
  PluginsTest.same(
    ["memory", "hashicorp:https://vault.example.com/secret"],
    Sekreto.sources(secrets),
    "sources"
  )
  PluginsTest.same("tok01", Sekreto.get(secrets, "api.token"), "get")

  # The plugin host is what the chain is made of, and it reads like the
  # chain: the kind, or kind$store for a named store.
  PluginsTest.same(
    %{"memory" => "live", "hashicorp$prod" => "live"},
    Host.list(secrets.host),
    "host list"
  )
  PluginsTest.same(
    ~w(dotenv env file hashicorp memory),
    Catalog.names(secrets.catalog),
    "catalog names"
  )
end

unknownkind = fn ->
  PluginsTest.same(
    "sekreto: unknown provider kind: doppler" <>
      " (available: dotenv, env, file, hashicorp, memory)" <>
      " - doppler is a sekreto plugin, not built in: pass it in the plugins option",
    PluginsTest.refused(fn ->
      Sekreto.new([%ProviderSpec{kind: "doppler", token: "t"}], plugins: [Hashicorp.hashicorp()])
    end),
    "a plugin that was not passed in"
  )

  # A kind nobody ships is a typo, and gets no such hint.
  PluginsTest.same(
    "sekreto: unknown provider kind: vualt (available: dotenv, env, file, memory)",
    PluginsTest.refused(fn -> Sekreto.new([%ProviderSpec{kind: "vualt"}]) end),
    "a kind nobody ships"
  )
end

# Two providers MAY share a store name - a directed read walks both, and
# the spec pins it - but an instance ref may not, so the second gets a
# numbered tag from the host and keeps its store name.
repeatedstore = fn ->
  secrets =
    Sekreto.new([
      %ProviderSpec{kind: "memory", values: []},
      %ProviderSpec{kind: "memory", values: [{"API_TOKEN", "second"}]},
      %ProviderSpec{kind: "memory", name: "pair", values: []},
      %ProviderSpec{kind: "memory", name: "pair", values: [{"API_TOKEN", "pair2"}]}
    ])

  PluginsTest.same(["memory", "pair"], Sekreto.stores(secrets), "stores")
  PluginsTest.same(
    ~w(memory memory$1 memory$2 memory$pair),
    Enum.sort(Map.keys(Host.list(secrets.host))),
    "host list"
  )
  PluginsTest.same("second", Sekreto.getfrom(secrets, "memory", "api.token"), "getfrom memory")
  PluginsTest.same("pair2", Sekreto.getfrom(secrets, "pair", "api.token"), "getfrom pair")
end

storenametag = fn ->
  PluginsTest.same(
    "sekreto: invalid store name: my store",
    PluginsTest.refused(fn -> Sekreto.new([%ProviderSpec{kind: "memory", name: "my store"}]) end),
    "an invalid store name"
  )
end

# A provider that refuses its own configuration raises a Sekreto.Error from
# inside the plugin's `define`. The spec pins that message byte for byte,
# so it must come back out of the host as itself - not wrapped as
# plugin_define_failed, and not as a Voxgig.Plugin.Error.
sekretoerror = fn ->
  PluginsTest.same(
    "sekreto: hashicorp: unsupported kv version: 3",
    PluginsTest.refused(fn ->
      Sekreto.new(
        [%ProviderSpec{kind: "hashicorp", addr: "http://127.0.0.1:1", token: "t", kv: 3}],
        plugins: [Hashicorp.hashicorp()]
      )
    end),
    "a provider refusing its own configuration"
  )
end

# ...and any other error is not sekreto's to rewrite: it surfaces as the
# host reports it, naming the instance and the cause.
othererror = fn ->
  broken = Sekreto.providerplugin("broken", fn _spec -> raise ArgumentError, "boom" end)

  err =
    PluginsTest.raised(fn -> Sekreto.new([%ProviderSpec{kind: "broken"}], plugins: [broken]) end)

  if is_struct(err, Sekreto.Error) do
    raise RuntimeError, message: "rewritten as a sekreto error: " <> Exception.message(err)
  end

  PluginsTest.same(Voxgig.Plugin.Error, err.__struct__, "the host's error type")
  PluginsTest.same("plugin_define_failed", err.code, "the host's code")
  PluginsTest.holds(Exception.message(err), "boom", "the host's report")
end

customkind = fn ->
  kind = Sekreto.providerplugin("shouty", fn spec -> shouty.(spec.values) end)

  secrets =
    Sekreto.new([%ProviderSpec{kind: "shouty", values: [{"API.TOKEN", "loud"}]}], plugins: [kind])

  PluginsTest.same("loud", Sekreto.get(secrets, "api.token"), "a custom kind")
  PluginsTest.same(%{"shouty" => "live"}, Host.list(secrets.host), "host list")
end

# A plugin that names a built-in kind replaces it: that is how a host
# substitutes an implementation, and never an accident, because the four
# names are documented.
replacebuiltin = fn ->
  replaced = %{lookup: fn _name -> "replaced" end, describe: fn -> "memory" end}

  secrets =
    Sekreto.new([%ProviderSpec{kind: "memory", values: [{"API_TOKEN", "original"}]}],
      plugins: [Sekreto.providerplugin("memory", fn _spec -> replaced end)]
    )

  PluginsTest.same("replaced", Sekreto.get(secrets, "api.token"), "the replacement")
  PluginsTest.same(~w(dotenv env file memory), Catalog.names(secrets.catalog), "catalog names")
end

close = fn ->
  secrets = Sekreto.new([%ProviderSpec{kind: "memory", values: [{"API_TOKEN", "tok01"}]}])
  PluginsTest.same("tok01", Sekreto.get(secrets, "api.token"), "get")

  Sekreto.close(secrets)

  PluginsTest.same(%{}, Host.list(secrets.host), "host list")
  PluginsTest.same([], Sekreto.stores(secrets), "stores")
  PluginsTest.same(nil, Sekreto.tryget(secrets, "api.token"), "tryget after close")
  PluginsTest.same(
    "token=[redacted]",
    Sekreto.redactall(secrets, "token=tok01"),
    "redact after close"
  )
end

# ----------------------------------------------------------- the boundary

# THE CORE REACHES NO PLUGIN, proved three ways.
#
# tool/checkcore.exs is the first two: `src/` compiles ALONE with only
# voxgig/plugin on the code path, which a core module naming a plugin
# could not do, and then every beam it produced is read back for a plugin
# module, a socket, a hash function or a child process.
#
# The third is here: a BEAM started on that core-only build still answers
# from a chain of the four built-ins, and cannot so much as find a plugin.
coreisreallycore = fn ->
  root = PluginsTest.here()
  {out, status} = System.cmd("make", ["check-core"], cd: root, stderr_to_stdout: true)

  if 0 != status do
    raise RuntimeError, message: "check-core failed:\n" <> out
  end

  PluginsTest.holds(out, "none of them a plugin", "check-core")

  core = [Path.join(root, "build/core"), PluginsTest.pluginbuild()]

  PluginsTest.same(
    "tok01",
    PluginsTest.fresh(core, """
    IO.write(Sekreto.get(Sekreto.new([
      %Sekreto.ProviderSpec{kind: "memory", values: [{"API_TOKEN", "tok01"}]},
      %Sekreto.ProviderSpec{kind: "env"},
      %Sekreto.ProviderSpec{kind: "dotenv", file: "/nonexistent-sekreto-test/.env"},
      %Sekreto.ProviderSpec{kind: "file", dir: "/nonexistent-sekreto-test"}
    ]), "api.token"))
    """),
    "a chain of built-ins, with no plugin on the code path"
  )

  PluginsTest.same(
    "absent",
    PluginsTest.fresh(core, """
    IO.write(if Code.ensure_loaded?(Sekreto.Plugins.Hashicorp), do: "REACHED", else: "absent")
    """),
    "a plugin module, from a core-only build"
  )

  # ...and the core-only build answers a chain that names one anyway with
  # the message that says what to pass.
  PluginsTest.holds(
    PluginsTest.fresh(core, """
    try do
      Sekreto.new([%Sekreto.ProviderSpec{kind: "hashicorp"}])
    rescue
      err -> IO.write(Exception.message(err))
    end
    """),
    "hashicorp is a sekreto plugin, not built in: pass it in the plugins option",
    "a plugin kind, from a core-only build"
  )
end

# ...and one plugin reaches only itself and the shared edges it needs.
# Python's plugins package had to arrange this deliberately - its
# initializer once imported all ten so it could re-export them, which made
# a single-plugin import load every network client behind it. The BEAM
# loads a module when something first calls into it, so a directory of
# modules gets it for free; this pins that it stays true.
onepluginreachesitself = fn ->
  PluginsTest.same(
    [
      Sekreto,
      Sekreto.Cell,
      Sekreto.Error,
      Sekreto.Json,
      Sekreto.Plugins.Hashicorp,
      Sekreto.Plugins.Http,
      Sekreto.Plugins.Httpjson,
      Sekreto.Provider,
      Sekreto.Providers
    ]
    |> Enum.sort(),
    PluginsTest.closure(Sekreto.Plugins.Hashicorp),
    "what one plugin reaches"
  )

  # It reaches no other kind, and no signer: SigV4 is the aws plugin's
  # alone, which is why `:crypto` is reached from one module in the whole
  # library.
  for name <- [Sekreto.Plugins.Sigv4, Sekreto.Plugins.Doppler, Sekreto.Plugins.Proc] do
    if name in PluginsTest.closure(Sekreto.Plugins.Hashicorp) do
      raise RuntimeError, message: "one plugin reached #{inspect(name)}"
    end
  end

  # ...and secretspec, the one kind that reaches no socket, reaches no HTTP
  # helper either. It needs the child-process helper and nothing else, and
  # calling `httpjson` for a one-line default would load a TLS stack into a
  # process that only ever runs a program.
  PluginsTest.same(
    [
      Sekreto,
      Sekreto.Cell,
      Sekreto.Error,
      Sekreto.Plugins.Proc,
      Sekreto.Plugins.Secretspec,
      Sekreto.Provider,
      Sekreto.Providers
    ]
    |> Enum.sort(),
    PluginsTest.closure(Sekreto.Plugins.Secretspec),
    "what the one socketless plugin reaches"
  )

  PluginsTest.same(
    [:crypto],
    Enum.filter(PluginsTest.references(Sekreto.Plugins.Sigv4), &(:crypto == &1)),
    "the signer"
  )
end

# The full set is built on demand, and reaching it reaches everything.
fullsetondemand = fn ->
  full = [Path.join(PluginsTest.here(), "build"), PluginsTest.pluginbuild()]

  # Building ONE plugin's definition loads that plugin and the core helper
  # that makes a definition. Not the other eight, and not the client under
  # it: the BEAM has not yet had to call into either.
  before = PluginsTest.loaded(full, "Sekreto.Plugins.Hashicorp.hashicorp()")

  PluginsTest.holds(before, "Sekreto.Plugins.Hashicorp", "one plugin")
  PluginsTest.lacks(before, "Sekreto.Plugins.Doppler", "one plugin")
  PluginsTest.lacks(before, "Sekreto.Plugins.Sigv4", "one plugin")

  # The full set loads every module that defines a kind.
  after_ = PluginsTest.loaded(full, "Sekreto.Plugins.all()")

  for name <- ~w(Hashicorp Boru Aws Gcpsecrets Azuresecrets Onepassword Doppler
                 Infisical Secretspec) do
    PluginsTest.holds(after_, "Sekreto.Plugins." <> name, "the full set")
  end

  # ...and reaching it reaches the shared edges behind them - the HTTP
  # client, the TLS binding, the signer and the child-process helper - as
  # soon as a lookup calls one. Read off the reference graph, because
  # loading is what a call does and the full set has not made one.
  reach = PluginsTest.closure(Sekreto.Plugins)

  for name <- [
        Sekreto.Plugins.Hashicorp,
        Sekreto.Plugins.Boru,
        Sekreto.Plugins.Aws,
        Sekreto.Plugins.Gcpsecrets,
        Sekreto.Plugins.Azuresecrets,
        Sekreto.Plugins.Onepassword,
        Sekreto.Plugins.Doppler,
        Sekreto.Plugins.Infisical,
        Sekreto.Plugins.Secretspec,
        Sekreto.Plugins.Sigv4,
        Sekreto.Plugins.Httpjson,
        Sekreto.Plugins.Http,
        Sekreto.Plugins.Proc
      ] do
    if name not in reach do
      raise RuntimeError, message: "the full set does not reach #{inspect(name)}"
    end
  end
end

# A plugin module is the container, not the definition inside it, and
# `plugins: [Sekreto.Plugins.Hashicorp]` is the elixir spelling of that
# mistake: a module alias is an atom, and an atom in the catalog would fail
# inside voxgig/plugin with a message about a definition name. Refused by
# name instead, saying what to call.
moduleasplugin = fn ->
  PluginsTest.same(
    "sekreto: not a plugin definition: the module Sekreto.Plugins.Hashicorp" <>
      " - a plugin is a definition a plugin module answers, such as" <>
      " Sekreto.Plugins.Hashicorp.hashicorp(), or Sekreto.Plugins.all() for every one",
    PluginsTest.refused(fn -> Sekreto.new([], plugins: [Sekreto.Plugins.Hashicorp]) end),
    "a module"
  )

  PluginsTest.holds(
    PluginsTest.refused(fn -> Sekreto.new([], plugins: [Sekreto.Plugins]) end),
    "Sekreto.Plugins.all() for every one",
    "the plugins module itself"
  )

  PluginsTest.holds(
    PluginsTest.refused(fn -> Sekreto.new([], plugins: [true]) end),
    "sekreto: not a plugin definition: true",
    "a value that is not a definition"
  )

  # A definition that exports no provider is a definition all the same, and
  # voxgig/plugin has no opinion about it - so this port does.
  PluginsTest.holds(
    PluginsTest.refused(fn ->
      Sekreto.new([%ProviderSpec{kind: "bare"}],
        plugins: [%{"name" => "bare", "define" => fn _inst -> :ok end}]
      )
    end),
    "sekreto: not a provider plugin: bare",
    "a definition that exports no provider"
  )
end

# THE SAME CALL, THE OPPOSITE ANSWER, IN TWO DIRECTORIES.
#
# `Integer.to_string(n, 16)` is UPPERCASE in Elixir. src/json.ex has to
# lowercase it, because every port emits `\u000b` and the writer is
# contract; plugins/http.ex must not, because RFC 3986 and SigV4 specify
# uppercase percent-escapes. `uriescape` has now moved twice - out of
# src/sigv4.ex to plugins/, then again to plugins/http.ex - and each file
# names the other in a comment, which is all that has ever held the two
# apart.
#
# A comment is not a test. Flipping either one passes all fourteen
# conformance groups AND all nineteen integration checks: the spec's
# sigv4 cases carry the query `b=2&a=1`, where nothing needs escaping, and
# no secret the CLI prints has ever held a control character. So the pair
# is pinned here, both directions, exhaustively - the whole control range
# for the writer and every byte for the escaper.
#
# The expected digits come from literal tables, never from
# `Integer.to_string/2`: an assertion that reaches for the same call it is
# checking would flip with it.
hexcase = fn ->
  lower = "0123456789abcdef"
  upper = "0123456789ABCDEF"

  digits = fn value, table ->
    binary_part(table, div(value, 16), 1) <> binary_part(table, rem(value, 16), 1)
  end

  # The writer: five short escapes, LOWERCASE \u00xx below 0x20, and every
  # other ASCII byte untouched - the whole range, so that "nothing else is
  # escaped" is pinned too.
  short = %{?" => "\\\"", ?\\ => "\\\\", ?\n => "\\n", ?\r => "\\r", ?\t => "\\t"}

  for ch <- 0..0x7F do
    want =
      cond do
        Map.has_key?(short, ch) -> Map.get(short, ch)
        0x20 > ch -> "\\u00" <> digits.(ch, lower)
        true -> <<ch>>
      end

    PluginsTest.same("\"" <> want <> "\"", Sekreto.Json.quotestr(<<ch>>), "json escape of byte #{ch}")
  end

  PluginsTest.same(
    ~s|"\\u000b\\u001b\\u001f"|,
    Sekreto.Json.quotestr(<<11, 27, 31>>),
    "json escapes a run of control bytes"
  )

  # The escaper: UPPERCASE %XX for every byte that is not unreserved.
  for byte <- 0..255 do
    unreserved =
      (?A <= byte and ?Z >= byte) or (?a <= byte and ?z >= byte) or
        (?0 <= byte and ?9 >= byte) or byte in [?-, ?_, ?., ?~]

    want = if unreserved, do: <<byte>>, else: "%" <> digits.(byte, upper)
    PluginsTest.same(want, Sekreto.Plugins.Http.uriescape(<<byte>>), "uriescape of byte #{byte}")
  end

  PluginsTest.same("a%20b%2Fc~d", Sekreto.Plugins.Http.uriescape("a b/c~d"), "uriescape")

  # ...and the pairing itself, on one byte, so a failure says which way
  # round it went wrong.
  PluginsTest.same(~s|"\\u001b"|, Sekreto.Json.quotestr(<<0x1B>>), "0x1B for the writer")
  PluginsTest.same("%1B", Sekreto.Plugins.Http.uriescape(<<0x1B>>), "0x1B for the escaper")
end

# ------------------------------------------------------------- the spine

state = {List.first(System.argv()), 0, 0}

state = PluginsTest.testcase("fullset", fullset, state)
state = PluginsTest.testcase("everykindbuilds", everykindbuilds, state)
state = PluginsTest.testcase("clipassesfullset", clipassesfullset, state)
state = PluginsTest.testcase("oneplugin", oneplugin, state)
state = PluginsTest.testcase("unknownkind", unknownkind, state)
state = PluginsTest.testcase("repeatedstore", repeatedstore, state)
state = PluginsTest.testcase("storenametag", storenametag, state)
state = PluginsTest.testcase("sekretoerror", sekretoerror, state)
state = PluginsTest.testcase("othererror", othererror, state)
state = PluginsTest.testcase("customkind", customkind, state)
state = PluginsTest.testcase("replacebuiltin", replacebuiltin, state)
state = PluginsTest.testcase("close", close, state)
state = PluginsTest.testcase("coreisreallycore", coreisreallycore, state)
state = PluginsTest.testcase("onepluginreachesitself", onepluginreachesitself, state)
state = PluginsTest.testcase("fullsetondemand", fullsetondemand, state)
state = PluginsTest.testcase("moduleasplugin", moduleasplugin, state)
state = PluginsTest.testcase("hexcase", hexcase, state)

{_only, passcount, failcount} = state

IO.puts("\n#{passcount} passed, #{failcount} failed")

System.halt(if 0 == failcount, do: 0, else: 1)
