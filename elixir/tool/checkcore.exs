# THE CORE REACHES NO PLUGIN, proved twice - by the compiler, and then by
# reading the beams it produced.
#
# Run by `make check-core`, and again from test/plugins_test.exs, which
# uses the core-only build this leaves in build/core.
#
#   THE COMPILER'S HALF. `src/*.ex` is compiled ALONE, with only
#   voxgig/plugin on the code path and nothing under plugins/ anywhere.
#   Elixir warns when a call names a module that is not available, and
#   --warnings-as-errors makes that warning fail the build - naming the
#   module and the line. So a core module that so much as mentioned
#   `Sekreto.Plugins.Hashicorp` could not compile here.
#
#   THE ARTIFACT'S HALF. Every beam carries an `imports` chunk: the exact
#   {module, function, arity} of every remote call the compiler emitted.
#   That is this runtime's link map, and it sees what a require graph
#   cannot - a call reached through an alias, a capture or a macro shows
#   up all the same. Nothing in it may be a plugin module, and nothing in
#   it may be the three things that make a kind a plugin: a socket, a hash
#   function, a child process.
#
# The equivalents elsewhere are clojure's `jdeps` over an AOT-compiled
# core and go's "an unimported package is not in the binary".

pluginbuild = List.first(System.argv())

if nil == pluginbuild or not File.dir?(pluginbuild) do
  IO.puts(:stderr, "sekreto: check-core needs the voxgig/plugin build directory")
  System.halt(1)
end

out = "build/core"
File.rm_rf!(out)
File.mkdir_p!(out)

# --- the compiler's half --------------------------------------------------

{text, status} =
  System.cmd(
    "elixirc",
    ["--warnings-as-errors", "-o", out] ++ Path.wildcard("src/*.ex"),
    env: [{"ELIXIR_ERL_OPTIONS", "-pa " <> pluginbuild}],
    stderr_to_stdout: true
  )

if 0 != status do
  IO.puts(:stderr, "sekreto: the core does not compile without the plugins\n" <> text)
  System.halt(1)
end

# --- the artifact's half --------------------------------------------------

# A plugin needs a socket, a signature or a child process. These are the
# calls that do each of those on this runtime, and no core module may
# carry one.
#
# EVERY SPELLING OTP HAS, not the ones the plugins happen to use. Listing
# only the latter is how swift's core came to hold a real POSIX socket
# while its own check printed "reaches no plugin": a boundary named after
# the implementation catches the implementation and nothing else. On this
# runtime `gen_tcp` and `inet` are the classic pair, `socket` is the OTP
# 22 API underneath them, `gen_udp` and `gen_sctp` are sockets too, and
# `prim_inet` is the driver below all of them - and each is a complete
# route to the network on its own. `erl_ddll` and `erlang:load_nif` are
# the other kind of route: native code that can then do anything at all.
forbidden = fn {mod, fun, _arity} ->
  cond do
    :crypto == mod -> "crypto"
    :ssl == mod -> "tls"
    :gen_tcp == mod -> "a socket"
    :gen_udp == mod -> "a socket"
    :gen_sctp == mod -> "a socket"
    :socket == mod -> "a socket"
    :inet == mod -> "a socket"
    :prim_inet == mod -> "a socket"
    :public_key == mod -> "trust roots"
    :httpc == mod -> "an http client"
    :os == mod and :cmd == fun -> "a child process"
    Port == mod -> "a child process"
    System == mod and fun in [:cmd, :find_executable, :shell] -> "a child process"
    :erlang == mod and fun in [:open_port, :port_command] -> "a child process"
    :erlang == mod and fun in [:md5, :md5_init, :md5_update, :md5_final] -> "a hash function"
    :erlang == mod and :load_nif == fun -> "native code"
    :erl_ddll == mod -> "native code"
    true -> nil
  end
end

beams = Path.wildcard(Path.join(out, "*.beam"))

if [] == beams do
  IO.puts(:stderr, "sekreto: nothing compiled into " <> out)
  System.halt(1)
end

bad =
  Enum.flat_map(beams, fn path ->
    {:ok, {module, [imports: imports]}} =
      :beam_lib.chunks(String.to_charlist(path), [:imports])

    Enum.flat_map(imports, fn {mod, fun, arity} = call ->
      name = Atom.to_string(mod)

      cond do
        String.starts_with?(name, "Elixir.Sekreto.Plugins") ->
          ["#{inspect(module)} reaches the plugin #{inspect(mod)}.#{fun}/#{arity}"]

        why = forbidden.(call) ->
          ["#{inspect(module)} reaches #{why}: #{inspect(mod)}.#{fun}/#{arity}"]

        true ->
          []
      end
    end)
  end)

if [] != bad do
  IO.puts(:stderr, "sekreto: the core is not core")
  Enum.each(bad, fn line -> IO.puts(:stderr, "  " <> line) end)
  System.halt(1)
end

reached =
  beams
  |> Enum.flat_map(fn path ->
    {:ok, {_module, [imports: imports]}} = :beam_lib.chunks(String.to_charlist(path), [:imports])
    Enum.map(imports, fn {mod, _fun, _arity} -> mod end)
  end)
  |> Enum.uniq()

IO.puts(
  "core: #{length(beams)} modules compile with no plugin present," <>
    " and reach #{length(reached)} modules, none of them a plugin"
)
