# Pack the compiled library and CLI into an escript.
#
# `mix escript.build` would do this, and would need a mix.exs - a project
# manifest whose only content would be the absence of dependencies. So the
# archive is assembled here instead, from `:escript.create/2`, which is
# OTP's own.
#
# Elixir's `ebin` goes in alongside: an escript runs under `escript`, which
# starts the Erlang runtime and nothing else, so the standard library the
# code calls has to travel with it. That is what makes the result a
# self-contained artifact - it needs nothing in the working directory, no
# manifest, and no code path.

beams =
  Path.wildcard("build/*.beam")
  |> Enum.map(fn path -> {String.to_charlist(Path.basename(path)), File.read!(path)} end)

if [] == beams do
  IO.puts(:stderr, "sekreto: nothing compiled in build/")
  System.halt(1)
end

ebin = to_string(:code.lib_dir(:elixir, :ebin))

runtime =
  (Path.wildcard(Path.join(ebin, "*.beam")) ++ Path.wildcard(Path.join(ebin, "*.app")))
  |> Enum.map(fn path -> {String.to_charlist(Path.basename(path)), File.read!(path)} end)

out = ~c"build/sekreto-cli"

:ok =
  :escript.create(out, [
    :shebang,
    {:emu_args, ~c"-escript main Elixir.Sekreto.Cli"},
    {:archive, beams ++ runtime, []}
  ])

File.chmod!("build/sekreto-cli", 0o755)
