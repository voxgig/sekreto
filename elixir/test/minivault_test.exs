# RUN: elixir -pa build -pa $PLUGINBUILD test/minivault_test.exs
# RUN-SOME: ... test/minivault_test.exs written
#
# The mini vault, from both sides: the store a chain reads, and the
# programmatic API a plugin definition can publish beside it.
#
# The vault is not in spec/sekreto.json and cannot be until every port
# ships the kind. The spec runs against all twenty-three of them, so an
# entry naming `minivault` would fail the ports that have no such
# provider. What the shared corpus would have carried is here instead,
# plus the one thing it could not carry either way: a file written by this
# port and read by another, pinned by test/fixture/*.skmv.

alias Sekreto.Plugins.Minivault, as: MV
alias Sekreto.ProviderSpec

defmodule MiniVaultTest do
  @master "master-passphrase"

  # The rounds every test here uses. The library default is 210000, which
  # is the point of PBKDF2 and the wrong thing to pay per assertion.
  @rounds 1000

  def master, do: @master
  def rounds, do: @rounds

  def same(want, got, what) do
    if want != got do
      raise RuntimeError,
        message: "#{what}:\n  want: #{inspect(want)}\n  got:  #{inspect(got)}"
    end
  end

  def holds(got, want, what) do
    if not (is_binary(got) and String.contains?(got, want)) do
      raise RuntimeError, message: "#{what}:\n  want to contain: #{want}\n  got: #{inspect(got)}"
    end
  end

  @doc "The message a `Sekreto.Error` refused with."
  def refused(body) do
    try do
      body.()
      raise RuntimeError, message: "nothing refused"
    rescue
      err in Sekreto.Error -> Exception.message(err)
    end
  end

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

work = Path.join(System.tmp_dir!(), "sekreto-minivault-#{:erlang.unique_integer([:positive])}")
File.mkdir_p!(work)
counter = :counters.new(1, [])

vaultpath = fn ->
  :counters.add(counter, 1, 1)
  Path.join(work, "vault#{:counters.get(counter, 1)}.skmv")
end

fresh = fn ->
  MV.createvault(%{
    "file" => vaultpath.(),
    "passphrase" => MiniVaultTest.master(),
    "iterations" => MiniVaultTest.rounds()
  })
end

openas = fn file, key, phrase ->
  MV.openvault(%{"file" => file, "key" => key, "passphrase" => phrase})
end

# Where the committed vaults live, found by walking up.
fixturedir = fn ->
  Enum.reduce_while(0..7, File.cwd!(), fn _step, dir ->
    cand = Path.join([dir, "test", "fixture"])
    if File.exists?(Path.join(cand, "minivault.skmv")),
      do: {:halt, cand},
      else: {:cont, Path.dirname(dir)}
  end)
end

# EVERY committed vault, read off disk rather than listed here. A
# hard-coded list is one more place to edit when a port lands, and the edit
# that gets forgotten is the one that makes this suite stop checking the
# port that just arrived.
fixtures = fn -> fixturedir.() |> Path.join("*.skmv") |> Path.wildcard() |> Enum.sort() end

# A committed vault, copied so that a test which writes cannot edit the
# bytes the format contract is made of.
fixture = fn name ->
  mine = vaultpath.()
  File.cp!(Path.join(fixturedir.(), name), mine)
  mine
end

chain = fn providers ->
  Sekreto.new(providers, plugins: [MV.minivault()], cache: false)
end

# --- the file --------------------------------------------------------

anewvault = fn ->
  vault = fresh.()

  MiniVaultTest.same([], MV.list(vault), "list")
  MiniVaultTest.same("master", MV.key(vault), "key")

  MiniVaultTest.same(
    %{"key" => "master", "master" => true, "write" => true, "grants" => []},
    MV.open(vault),
    "open"
  )
end

written = fn ->
  vault = fresh.()
  MV.set(vault, "api.token", "tok01")
  MV.set(vault, "db.pass", "hunter2")

  MiniVaultTest.same("tok01", MV.get(vault, "api.token"), "get")
  MiniVaultTest.same(["api.token", "db.pass"], MV.list(vault), "list")
  MiniVaultTest.same(true, MV.has?(vault, "api.token"), "has?")
  MiniVaultTest.same(false, MV.has?(vault, "nope"), "has? nope")
  MiniVaultTest.same(nil, MV.get(vault, "nope"), "get nope")

  again = openas.(MV.file(vault), nil, MiniVaultTest.master())
  MiniVaultTest.same("tok01", MV.get(again, "api.token"), "a new handle")
end

binaryfile = fn ->
  vault = fresh.()
  MV.set(vault, "api.token", "tok01")
  raw = File.read!(MV.file(vault))

  MiniVaultTest.same("SKMV", binary_part(raw, 0, 4), "magic")
  # The key ids are plaintext and documented as such; a secret name is
  # not, and neither is a value.
  MiniVaultTest.same(true, String.contains?(raw, "master"), "the key id is plaintext")
  MiniVaultTest.same(false, String.contains?(raw, "api.token"), "the name is not")
  MiniVaultTest.same(false, String.contains?(raw, "tok01"), "the value is not")
end

rewrite = fn ->
  vault = fresh.()
  MV.set(vault, "api.token", "one")
  MV.set(vault, "api.token", "two")

  MiniVaultTest.same("two", MV.get(vault, "api.token"), "get")
  MiniVaultTest.same(["api.token"], MV.list(vault), "list")
end

remove = fn ->
  vault = fresh.()
  MV.set(vault, "api.token", "tok01")
  MV.remove(vault, "api.token")

  MiniVaultTest.same([], MV.list(vault), "list")
  MiniVaultTest.same(nil, MV.get(vault, "api.token"), "get")

  MiniVaultTest.holds(
    MiniVaultTest.refused(fn -> MV.remove(vault, "api.token") end),
    "no such secret",
    "remove again"
  )
end

badname = fn ->
  vault = fresh.()
  MiniVaultTest.refused(fn -> MV.get(vault, "") end)
  MiniVaultTest.refused(fn -> MV.set(vault, "bad name", "x") end)
end

# --- the keys --------------------------------------------------------

restricted = fn ->
  vault = fresh.()
  MV.set(vault, "api.token", "tok01")
  MV.set(vault, "db.pass", "hunter2")

  MV.grant(vault, %{
    "key" => "ci",
    "passphrase" => "ci-phrase",
    "names" => ["api.token"],
    "iterations" => MiniVaultTest.rounds()
  })

  ci = openas.(MV.file(vault), "ci", "ci-phrase")

  MiniVaultTest.same(["api.token"], MV.list(ci), "list")
  MiniVaultTest.same("tok01", MV.get(ci, "api.token"), "the grant")
  # Not an error: the vault answers as the key that opened it, so a name
  # outside the grant is a miss.
  MiniVaultTest.same(nil, MV.get(ci, "db.pass"), "outside the grant")

  MiniVaultTest.same(
    %{"key" => "ci", "master" => false, "write" => false, "grants" => ["api.token"]},
    MV.open(ci),
    "open"
  )
end

readonly = fn ->
  vault = fresh.()
  MV.set(vault, "db.pass", "hunter2")

  MV.grant(vault, %{
    "key" => "ro",
    "passphrase" => "ro-phrase",
    "names" => ["db.pass"],
    "iterations" => MiniVaultTest.rounds()
  })

  MV.grant(vault, %{
    "key" => "rw",
    "passphrase" => "rw-phrase",
    "names" => ["db.pass"],
    "write" => true,
    "iterations" => MiniVaultTest.rounds()
  })

  ro = openas.(MV.file(vault), "ro", "ro-phrase")

  MiniVaultTest.holds(
    MiniVaultTest.refused(fn -> MV.set(ro, "db.pass", "nope") end),
    "read-only",
    "a read-only key"
  )

  rw = openas.(MV.file(vault), "rw", "rw-phrase")
  MV.set(rw, "db.pass", "changed")
  MiniVaultTest.same("changed", MV.get(vault, "db.pass"), "a write key")
end

ungranted = fn ->
  vault = fresh.()
  MV.set(vault, "db.pass", "hunter2")

  MV.grant(vault, %{
    "key" => "rw",
    "passphrase" => "rw-phrase",
    "names" => ["db.pass"],
    "write" => true,
    "iterations" => MiniVaultTest.rounds()
  })

  rw = openas.(MV.file(vault), "rw", "rw-phrase")

  MiniVaultTest.holds(
    MiniVaultTest.refused(fn -> MV.set(rw, "other.name", "x") end),
    "was not granted",
    "an ungranted name"
  )
end

laternamed = fn ->
  vault = fresh.()

  MV.grant(vault, %{
    "key" => "ci",
    "passphrase" => "ci-phrase",
    "names" => ["later.name"],
    "iterations" => MiniVaultTest.rounds()
  })

  ci = openas.(MV.file(vault), "ci", "ci-phrase")
  MiniVaultTest.same([], MV.list(ci), "before")
  MiniVaultTest.same(nil, MV.get(ci, "later.name"), "before")

  MV.set(vault, "later.name", "here now")

  MiniVaultTest.same("here now", MV.get(ci, "later.name"), "after")
  MiniVaultTest.same(["later.name"], MV.list(ci), "after")
end

keylist = fn ->
  vault = fresh.()

  MV.grant(vault, %{
    "key" => "ro",
    "passphrase" => "p1",
    "names" => ["a.one"],
    "iterations" => MiniVaultTest.rounds()
  })

  MV.grant(vault, %{
    "key" => "rw",
    "passphrase" => "p2",
    "names" => ["a.one", "b.two"],
    "write" => true,
    "iterations" => MiniVaultTest.rounds()
  })

  MiniVaultTest.same(
    [
      %{"key" => "master", "master" => true, "write" => true, "grants" => []},
      %{"key" => "ro", "master" => false, "write" => false, "grants" => ["a.one"]},
      %{"key" => "rw", "master" => false, "write" => true, "grants" => ["a.one", "b.two"]}
    ],
    MV.keys(vault),
    "keys"
  )
end

masteronly = fn ->
  vault = fresh.()
  MV.set(vault, "a.one", "x")

  MV.grant(vault, %{
    "key" => "ci",
    "passphrase" => "ci-phrase",
    "names" => ["a.one"],
    "write" => true,
    "iterations" => MiniVaultTest.rounds()
  })

  ci = openas.(MV.file(vault), "ci", "ci-phrase")

  [
    fn -> MV.keys(ci) end,
    fn -> MV.remove(ci, "a.one") end,
    fn -> MV.rotate(ci) end,
    fn -> MV.revoke(ci, "master") end,
    fn -> MV.grant(ci, %{"key" => "x", "passphrase" => "y", "names" => []}) end
  ]
  |> Enum.each(fn call ->
    MiniVaultTest.holds(MiniVaultTest.refused(call), "master key", "a master-only method")
  end)
end

repeatedid = fn ->
  vault = fresh.()

  MV.grant(vault, %{
    "key" => "ci",
    "passphrase" => "one",
    "names" => [],
    "iterations" => MiniVaultTest.rounds()
  })

  MiniVaultTest.holds(
    MiniVaultTest.refused(fn ->
      MV.grant(vault, %{
        "key" => "ci",
        "passphrase" => "two",
        "names" => [],
        "iterations" => MiniVaultTest.rounds()
      })
    end),
    "key already exists",
    "a repeated id"
  )
end

revoke = fn ->
  vault = fresh.()
  MV.set(vault, "a.one", "x")

  MV.grant(vault, %{
    "key" => "ci",
    "passphrase" => "ci-phrase",
    "names" => ["a.one"],
    "iterations" => MiniVaultTest.rounds()
  })

  ci = openas.(MV.file(vault), "ci", "ci-phrase")
  MiniVaultTest.same("x", MV.get(ci, "a.one"), "before")

  MV.revoke(vault, "ci")

  MiniVaultTest.holds(
    MiniVaultTest.refused(fn -> MV.get(ci, "a.one") end),
    "no such key",
    "after"
  )

  MiniVaultTest.holds(
    MiniVaultTest.refused(fn -> MV.revoke(vault, "master") end),
    "cannot revoke itself",
    "itself"
  )
end

rotate = fn ->
  vault = fresh.()
  MV.set(vault, "api.token", "tok01")
  MV.set(vault, "db.pass", "hunter2")

  MV.grant(vault, %{
    "key" => "ci",
    "passphrase" => "ci-phrase",
    "names" => ["api.token"],
    "iterations" => MiniVaultTest.rounds()
  })

  MV.rotate(vault)

  MiniVaultTest.same(["api.token", "db.pass"], MV.list(vault), "list")
  MiniVaultTest.same("tok01", MV.get(vault, "api.token"), "api.token")
  MiniVaultTest.same("hunter2", MV.get(vault, "db.pass"), "db.pass")
  MiniVaultTest.same(["master"], Enum.map(MV.keys(vault), & &1["key"]), "keys")

  ci = openas.(MV.file(vault), "ci", "ci-phrase")
  MiniVaultTest.refused(fn -> MV.get(ci, "api.token") end)
end

# --- refusals --------------------------------------------------------

wrongphrase = fn ->
  vault = fresh.()
  MV.set(vault, "a.one", "x")

  bad = openas.(MV.file(vault), nil, "wrong")

  MiniVaultTest.holds(
    MiniVaultTest.refused(fn -> MV.get(bad, "a.one") end),
    "wrong passphrase",
    "a wrong passphrase"
  )

  nokey = openas.(MV.file(vault), "nope", MiniVaultTest.master())
  MiniVaultTest.refused(fn -> MV.get(nokey, "a.one") end)

  missing = openas.(Path.join(work, "nothing.skmv"), nil, MiniVaultTest.master())

  MiniVaultTest.holds(
    MiniVaultTest.refused(fn -> MV.get(missing, "a.one") end),
    "no vault file",
    "a missing file"
  )
end

damaged = fn ->
  vault = fresh.()
  MV.set(vault, "a.one", "x")
  raw = File.read!(MV.file(vault))

  short = vaultpath.()
  File.write!(short, binary_part(raw, 0, byte_size(raw) - 10))

  MiniVaultTest.holds(
    MiniVaultTest.refused(fn -> MV.get(openas.(short, nil, MiniVaultTest.master()), "a.one") end),
    "truncated",
    "short"
  )

  trailing = vaultpath.()
  File.write!(trailing, raw <> "junk")

  MiniVaultTest.holds(
    MiniVaultTest.refused(fn ->
      MV.get(openas.(trailing, nil, MiniVaultTest.master()), "a.one")
    end),
    "trailing bytes",
    "trailing"
  )

  notvault = vaultpath.()
  File.write!(notvault, "NOPE" <> binary_part(raw, 4, byte_size(raw) - 4))

  MiniVaultTest.holds(
    MiniVaultTest.refused(fn ->
      MV.get(openas.(notvault, nil, MiniVaultTest.master()), "a.one")
    end),
    "not a vault file",
    "magic"
  )
end

createover = fn ->
  vault = fresh.()

  MiniVaultTest.holds(
    MiniVaultTest.refused(fn ->
      MV.createvault(%{
        "file" => MV.file(vault),
        "passphrase" => MiniVaultTest.master(),
        "iterations" => MiniVaultTest.rounds()
      })
    end),
    "already exists",
    "createvault over one"
  )
end

needsfile = fn ->
  MiniVaultTest.refused(fn ->
    MV.openvault(%{"file" => "", "passphrase" => MiniVaultTest.master()})
  end)

  MiniVaultTest.refused(fn ->
    MV.openvault(%{"file" => vaultpath.(), "passphrase" => ""})
  end)
end

createflag = fn ->
  path = vaultpath.()

  refuses =
    MV.openvault(%{
      "file" => path,
      "passphrase" => MiniVaultTest.master(),
      "iterations" => MiniVaultTest.rounds()
    })

  MiniVaultTest.refused(fn -> MV.list(refuses) end)
  MiniVaultTest.same(false, File.exists?(path), "no file")

  makes =
    MV.openvault(%{
      "file" => path,
      "passphrase" => MiniVaultTest.master(),
      "iterations" => MiniVaultTest.rounds(),
      "create" => true
    })

  MiniVaultTest.same([], MV.list(makes), "created")
  MiniVaultTest.same(true, File.exists?(path), "the file")
end

longkeyid = fn ->
  vault = fresh.()

  MiniVaultTest.holds(
    MiniVaultTest.refused(fn ->
      MV.grant(vault, %{
        "key" => String.duplicate("k", 256),
        "passphrase" => "p",
        "names" => [],
        "iterations" => MiniVaultTest.rounds()
      })
    end),
    "longer than 255",
    "a long key id"
  )

  MiniVaultTest.same(["master"], Enum.map(MV.keys(vault), & &1["key"]), "unchanged")
end

# --- the handle ------------------------------------------------------

infocopy = fn ->
  vault = fresh.()
  MV.set(vault, "a.one", "x")

  MV.grant(vault, %{
    "key" => "ro",
    "passphrase" => "ro-phrase",
    "names" => ["a.one"],
    "iterations" => MiniVaultTest.rounds()
  })

  ro = openas.(MV.file(vault), "ro", "ro-phrase")

  # A map is a value here, so what a caller changes is its own copy - the
  # defect the review round found in the canonical cannot happen in a
  # language with no shared mutable map.
  _mine = MV.open(ro) |> Map.put("write", true) |> Map.put("grants", ["a.one", "b.two"])

  MiniVaultTest.holds(
    MiniVaultTest.refused(fn -> MV.set(ro, "a.one", "nope") end),
    "read-only",
    "still read-only"
  )

  MiniVaultTest.same(["a.one"], MV.open(ro)["grants"], "still one grant")
end

revokedcached = fn ->
  vault = fresh.()
  MV.set(vault, "a.one", "x")

  MV.grant(vault, %{
    "key" => "ci",
    "passphrase" => "ci-phrase",
    "names" => ["a.one"],
    "iterations" => MiniVaultTest.rounds()
  })

  ci = openas.(MV.file(vault), "ci", "ci-phrase")
  MiniVaultTest.same("x", MV.get(ci, "a.one"), "before")

  MV.revoke(vault, "ci")
  MiniVaultTest.refused(fn -> MV.get(ci, "a.one") end)
end

regranted = fn ->
  vault = fresh.()
  MV.set(vault, "a.one", "x")

  MV.grant(vault, %{
    "key" => "ci",
    "passphrase" => "first",
    "names" => ["a.one"],
    "iterations" => MiniVaultTest.rounds()
  })

  ci = openas.(MV.file(vault), "ci", "first")
  MiniVaultTest.same("x", MV.get(ci, "a.one"), "before")

  MV.revoke(vault, "ci")

  MV.grant(vault, %{
    "key" => "ci",
    "passphrase" => "second",
    "names" => ["a.one"],
    "iterations" => MiniVaultTest.rounds()
  })

  MiniVaultTest.holds(
    MiniVaultTest.refused(fn -> MV.get(ci, "a.one") end),
    "wrong passphrase",
    "the old passphrase"
  )

  MiniVaultTest.same(
    "x",
    MV.get(openas.(MV.file(vault), "ci", "second"), "a.one"),
    "the new one"
  )
end

closehandle = fn ->
  vault = fresh.()
  MV.set(vault, "a.one", "x")
  MiniVaultTest.same("x", MV.get(vault, "a.one"), "before")

  MV.close(vault)
  MiniVaultTest.same("x", MV.get(vault, "a.one"), "after")
end

# --- the format, across ports ----------------------------------------

# EVERY COMMITTED VAULT, not only this port's. A suite that reads only the
# vault its own port wrote proves the reader agrees with the writer beside
# it - which a port whose serializer and parser share a mistake satisfies
# perfectly.
fixturecases =
  Enum.map(fixtures.(), fn path ->
    name = Path.basename(path)

    {"fixture:" <> name,
     fn ->
       file = fixture.(name)

       master = openas.(file, nil, "fixture-master")

       MiniVaultTest.same(
         ["api.token", "db.pass", "deep.nested.name"],
         MV.list(master),
         "list"
       )

       MiniVaultTest.same("fixture-token", MV.get(master, "api.token"), "api.token")
       MiniVaultTest.same("fixture-pass", MV.get(master, "db.pass"), "db.pass")
       MiniVaultTest.same("fixture-deep", MV.get(master, "deep.nested.name"), "deep")

       MiniVaultTest.same(
         [
           %{"key" => "master", "master" => true, "write" => true, "grants" => []},
           %{
             "key" => "reader",
             "master" => false,
             "write" => false,
             "grants" => ["api.token"]
           },
           %{"key" => "writer", "master" => false, "write" => true, "grants" => ["db.pass"]}
         ],
         MV.keys(master),
         "keys"
       )

       reader = openas.(file, "reader", "fixture-reader")
       MiniVaultTest.same(["api.token"], MV.list(reader), "reader list")
       MiniVaultTest.same("fixture-token", MV.get(reader, "api.token"), "reader grant")
       MiniVaultTest.same(nil, MV.get(reader, "db.pass"), "reader miss")

       writer = openas.(file, "writer", "fixture-writer")
       MV.set(writer, "db.pass", "written by this port")
       MiniVaultTest.same("written by this port", MV.get(master, "db.pass"), "writer")
     end}
  end)

# --- the chain -------------------------------------------------------

inachain = fn ->
  vault = fresh.()
  MV.set(vault, "api.token", "from the vault")

  secrets =
    chain.([
      %ProviderSpec{kind: "memory", values: [{"DB_PASS", "from memory"}]},
      %ProviderSpec{
        kind: "minivault",
        file: MV.file(vault),
        passphrase: MiniVaultTest.master()
      }
    ])

  MiniVaultTest.same("from the vault", Sekreto.get(secrets, "api.token"), "the vault")
  MiniVaultTest.same("from memory", Sekreto.get(secrets, "db.pass"), "memory")
end

fallthrough = fn ->
  vault = fresh.()
  MV.set(vault, "api.token", "from the vault")
  MV.set(vault, "db.pass", "in the vault, not granted")

  MV.grant(vault, %{
    "key" => "ci",
    "passphrase" => "ci-phrase",
    "names" => ["api.token"],
    "iterations" => MiniVaultTest.rounds()
  })

  secrets =
    chain.([
      %ProviderSpec{
        kind: "minivault",
        file: MV.file(vault),
        vaultkey: "ci",
        passphrase: "ci-phrase"
      },
      %ProviderSpec{kind: "memory", values: [{"DB_PASS", "from memory"}]}
    ])

  MiniVaultTest.same("from the vault", Sekreto.get(secrets, "api.token"), "the grant")
  MiniVaultTest.same("from memory", Sekreto.get(secrets, "db.pass"), "falls through")
end

asapi = fn ->
  vault = fresh.()
  MV.set(vault, "api.token", "tok01")

  secrets =
    chain.([
      %ProviderSpec{
        kind: "minivault",
        file: MV.file(vault),
        passphrase: MiniVaultTest.master()
      }
    ])

  api = MV.vaultof(secrets)
  MiniVaultTest.same(["api.token"], MV.list(api), "list")

  MV.set(api, "db.pass", "written through the api")
  MiniVaultTest.same("written through the api", Sekreto.get(secrets, "db.pass"), "the chain")
end

namedstore = fn ->
  vault = fresh.()
  MV.set(vault, "api.token", "tok01")

  secrets =
    chain.([
      %ProviderSpec{
        kind: "minivault",
        name: "app",
        file: MV.file(vault),
        passphrase: MiniVaultTest.master()
      }
    ])

  MiniVaultTest.same(["api.token"], MV.list(MV.vaultof(secrets, "app")), "by name")
  MiniVaultTest.same(["api.token"], MV.list(MV.vaultof(secrets)), "by alias")

  MiniVaultTest.holds(
    MiniVaultTest.refused(fn -> MV.vaultof(secrets, "minivault") end),
    "no minivault store named",
    "a name that is not there"
  )
end

novault = fn ->
  secrets = chain.([%ProviderSpec{kind: "memory", values: []}])

  MiniVaultTest.holds(
    MiniVaultTest.refused(fn -> MV.vaultof(secrets) end),
    "no minivault store",
    "no vault"
  )
end

badconfig = fn ->
  MiniVaultTest.holds(
    MiniVaultTest.refused(fn ->
      chain.([%ProviderSpec{kind: "minivault", passphrase: MiniVaultTest.master()}])
    end),
    "a vault needs a file",
    "no file"
  )

  MiniVaultTest.holds(
    MiniVaultTest.refused(fn ->
      chain.([%ProviderSpec{kind: "minivault", file: vaultpath.()}])
    end),
    "a vault needs a passphrase",
    "no passphrase"
  )
end

lazy = fn ->
  # No file, and construction still succeeds: the handle is lazy.
  secrets =
    chain.([
      %ProviderSpec{
        kind: "minivault",
        file: vaultpath.(),
        passphrase: MiniVaultTest.master()
      }
    ])

  MiniVaultTest.holds(
    MiniVaultTest.refused(fn -> Sekreto.get(secrets, "api.token") end),
    "no vault file",
    "at the first lookup"
  )
end

# --- the run ---------------------------------------------------------

state = {List.first(System.argv()), 0, 0}

state = MiniVaultTest.testcase("newvault", anewvault, state)
state = MiniVaultTest.testcase("written", written, state)
state = MiniVaultTest.testcase("binary", binaryfile, state)
state = MiniVaultTest.testcase("rewrite", rewrite, state)
state = MiniVaultTest.testcase("remove", remove, state)
state = MiniVaultTest.testcase("badname", badname, state)
state = MiniVaultTest.testcase("restricted", restricted, state)
state = MiniVaultTest.testcase("readonly", readonly, state)
state = MiniVaultTest.testcase("ungranted", ungranted, state)
state = MiniVaultTest.testcase("laternamed", laternamed, state)
state = MiniVaultTest.testcase("keys", keylist, state)
state = MiniVaultTest.testcase("masteronly", masteronly, state)
state = MiniVaultTest.testcase("repeatedid", repeatedid, state)
state = MiniVaultTest.testcase("revoke", revoke, state)
state = MiniVaultTest.testcase("rotate", rotate, state)
state = MiniVaultTest.testcase("wrongphrase", wrongphrase, state)
state = MiniVaultTest.testcase("damaged", damaged, state)
state = MiniVaultTest.testcase("createover", createover, state)
state = MiniVaultTest.testcase("needsfile", needsfile, state)
state = MiniVaultTest.testcase("createflag", createflag, state)
state = MiniVaultTest.testcase("longkeyid", longkeyid, state)
state = MiniVaultTest.testcase("infocopy", infocopy, state)
state = MiniVaultTest.testcase("revokedcached", revokedcached, state)
state = MiniVaultTest.testcase("regranted", regranted, state)
state = MiniVaultTest.testcase("close", closehandle, state)

state =
  Enum.reduce(fixturecases, state, fn {name, body}, acc ->
    MiniVaultTest.testcase(name, body, acc)
  end)

state = MiniVaultTest.testcase("chain", inachain, state)
state = MiniVaultTest.testcase("chainfallthrough", fallthrough, state)
state = MiniVaultTest.testcase("api", asapi, state)
state = MiniVaultTest.testcase("namedstore", namedstore, state)
state = MiniVaultTest.testcase("novault", novault, state)
state = MiniVaultTest.testcase("badconfig", badconfig, state)
state = MiniVaultTest.testcase("lazy", lazy, state)

{_only, passcount, failcount} = state

File.rm_rf!(work)

IO.puts("\n#{passcount} passed, #{failcount} failed")

System.halt(if 0 == failcount, do: 0, else: 1)
