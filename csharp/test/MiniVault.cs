// The mini vault, from both sides: the store a chain reads, and the
// programmatic API a plugin definition can publish beside it.
//
// The vault is not in spec/sekreto.json and cannot be until every port
// ships the kind. The spec runs against all twenty-three of them, so an
// entry naming `minivault` would fail the ports that have no such
// provider. What the shared corpus would have carried is here instead,
// plus the one thing it could not carry either way: a file written by
// this port and read by another, pinned by test/fixture/*.skmv.

using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text;

using Voxgig.Sekreto;
using Voxgig.Sekreto.Plugins;

using Definition = Voxgig.Plugin.Definition;

internal static class MiniVaultSeam
{
    private const string MASTER = "master-passphrase";

    /// <summary>
    /// The rounds every test here uses. The library default is 210000,
    /// which is the point of PBKDF2 and the wrong thing to pay per
    /// assertion.
    /// </summary>
    private const int ROUNDS = 1000;

    private static string work;
    private static int count;

    // --- the harness ------------------------------------------------

    private static string Show(object value)
    {
        if (null == value)
        {
            return "null";
        }

        if (value is string text)
        {
            return text;
        }

        if (value is System.Collections.IEnumerable many && !(value is string))
        {
            var parts = new List<string>();

            foreach (object one in many)
            {
                parts.Add(Show(one));
            }

            return "[" + string.Join(", ", parts) + "]";
        }

        return Convert.ToString(value);
    }

    private static void Eq(object got, object want, string what)
    {
        string gottext = Show(got);
        string wanttext = Show(want);

        if (gottext != wanttext)
        {
            throw new Exception(what + ":\n  got  " + gottext + "\n  want " + wanttext);
        }
    }

    private static void True(bool got, string what)
    {
        if (!got)
        {
            throw new Exception(what);
        }
    }

    /// <summary>The message of the SekretoError the body raised.</summary>
    private static string Threw(Action body)
    {
        try
        {
            body();
        }
        catch (SekretoError err)
        {
            return err.Message;
        }

        throw new Exception("want a SekretoError, nothing was thrown");
    }

    private static void Has(string got, string want, string what)
    {
        if (null == got || !got.Contains(want))
        {
            throw new Exception(what + ":\n  want to contain: " + want + "\n  got: " + got);
        }
    }

    // --- the fixtures -----------------------------------------------

    private static string VaultPath()
    {
        count++;
        return Path.Combine(work, "vault" + count + ".skmv");
    }

    private static MiniVault.Vault Fresh()
    {
        return MiniVault.CreateVault(new MiniVault.Options
        {
            File = VaultPath(), Passphrase = MASTER, Iterations = ROUNDS,
        });
    }

    private static MiniVault.Vault Open(string file, string key, string phrase)
    {
        return MiniVault.OpenVault(new MiniVault.Options
        {
            File = file, Key = key ?? MiniVault.MasterKey, Passphrase = phrase,
        });
    }

    /// <summary>Where the committed vaults live, found by walking up.</summary>
    private static string FixtureDir()
    {
        string dir = Directory.GetCurrentDirectory();

        for (int step = 0; step < 8 && null != dir; step++)
        {
            string cand = Path.Combine(dir, "test", "fixture");

            if (File.Exists(Path.Combine(cand, "minivault.skmv")))
            {
                return cand;
            }

            dir = Path.GetDirectoryName(dir);
        }

        throw new Exception("sekreto: fixture directory not found");
    }

    /// <summary>
    /// EVERY committed vault, read off disk rather than listed here. A
    /// hard-coded list is one more place to edit when a port lands, and
    /// the edit that gets forgotten is the one that makes this suite stop
    /// checking the port that just arrived.
    /// </summary>
    private static List<string> Fixtures()
    {
        var out_ = Directory.GetFiles(FixtureDir(), "*.skmv")
            .Select(Path.GetFileName).ToList();
        out_.Sort(StringComparer.Ordinal);
        return out_;
    }

    /// <summary>
    /// A committed vault, copied so that a test which writes cannot edit
    /// the bytes the format contract is made of.
    /// </summary>
    private static string Fixture(string name)
    {
        string mine = VaultPath();
        File.Copy(Path.Combine(FixtureDir(), name), mine, true);
        return mine;
    }

    private static Dictionary<string, object> Spec(params object[] pairs)
    {
        var out_ = new Dictionary<string, object>();

        for (int index = 0; index + 1 < pairs.Length; index += 2)
        {
            out_[Convert.ToString(pairs[index])] = pairs[index + 1];
        }

        return out_;
    }

    private static Sekreto Chain(params object[] providers)
    {
        return new Sekreto(new SekretoOptions
        {
            Plugins = new List<Definition> { MiniVault.Plugin },
            Providers = providers.ToList(),
            Cache = false,
        });
    }

    // --- the cases ----------------------------------------------------

    internal static List<KeyValuePair<string, Action>> Cases()
    {
        work = Path.Combine(Path.GetTempPath(),
            "sekreto-minivault-" + Guid.NewGuid().ToString("N").Substring(0, 12));
        Directory.CreateDirectory(work);
        count = 0;

        var cases = new List<KeyValuePair<string, Action>>();

        void Case(string name, Action body)
        {
            cases.Add(new KeyValuePair<string, Action>(name, body));
        }

        // --- the file ---------------------------------------------------

        Case("a new vault holds nothing", () =>
        {
            var vault = Fresh();

            Eq(vault.List(), new string[0], "List()");
            Eq(vault.Key(), "master", "Key()");
            Eq(vault.Open().ToString(), "master/true/true/[]", "Open()");
        });

        Case("a written secret comes back", () =>
        {
            var vault = Fresh();
            vault.Set("api.token", "tok01");
            vault.Set("db.pass", "hunter2");

            Eq(vault.Get("api.token"), "tok01", "Get()");
            Eq(vault.List(), new[] { "api.token", "db.pass" }, "List()");
            True(vault.Has("api.token"), "Has()");
            True(!vault.Has("nope"), "Has(nope)");
            Eq(vault.Get("nope"), null, "Get(nope)");

            Eq(Open(vault.File(), null, MASTER).Get("api.token"), "tok01", "a new handle");
        });

        Case("the file is binary and names nothing in plaintext", () =>
        {
            var vault = Fresh();
            vault.Set("api.token", "tok01");

            string raw = Encoding.Latin1.GetString(File.ReadAllBytes(vault.File()));

            Eq(raw.Substring(0, 4), "SKMV", "magic");
            // The key ids are plaintext and documented as such; a secret
            // name is not, and neither is a value.
            True(raw.Contains("master"), "the key id is plaintext");
            True(!raw.Contains("api.token"), "the name is not");
            True(!raw.Contains("tok01"), "the value is not");
        });

        Case("rewriting a name replaces it", () =>
        {
            var vault = Fresh();
            vault.Set("api.token", "one");
            vault.Set("api.token", "two");

            Eq(vault.Get("api.token"), "two", "Get()");
            Eq(vault.List(), new[] { "api.token" }, "List()");
        });

        Case("remove drops a name", () =>
        {
            var vault = Fresh();
            vault.Set("api.token", "tok01");
            vault.Remove("api.token");

            Eq(vault.List(), new string[0], "List()");
            Eq(vault.Get("api.token"), null, "Get()");
            Has(Threw(() => vault.Remove("api.token")), "no such secret", "remove() again");
        });

        Case("a bad name is refused", () =>
        {
            var vault = Fresh();

            Threw(() => vault.Get(""));
            Threw(() => vault.Set("bad name", "x"));
        });

        // --- the keys ---------------------------------------------------

        Case("a restricted key reads its grants", () =>
        {
            var vault = Fresh();
            vault.Set("api.token", "tok01");
            vault.Set("db.pass", "hunter2");
            vault.Grant(new MiniVault.Grant
            {
                Key = "ci", Passphrase = "ci-phrase",
                Names = new List<string> { "api.token" }, Iterations = ROUNDS,
            });

            var ci = Open(vault.File(), "ci", "ci-phrase");

            Eq(ci.List(), new[] { "api.token" }, "List()");
            Eq(ci.Get("api.token"), "tok01", "the grant");
            // Not an error: the vault answers as the key that opened it,
            // so a name outside the grant is a miss.
            Eq(ci.Get("db.pass"), null, "outside the grant");
            Eq(ci.Open().ToString(), "ci/false/false/[api.token]", "Open()");
        });

        Case("a read-only key refuses to write", () =>
        {
            var vault = Fresh();
            vault.Set("db.pass", "hunter2");
            vault.Grant(new MiniVault.Grant
            {
                Key = "ro", Passphrase = "ro-phrase",
                Names = new List<string> { "db.pass" }, Iterations = ROUNDS,
            });
            vault.Grant(new MiniVault.Grant
            {
                Key = "rw", Passphrase = "rw-phrase",
                Names = new List<string> { "db.pass" }, Write = true, Iterations = ROUNDS,
            });

            var ro = Open(vault.File(), "ro", "ro-phrase");
            Has(Threw(() => ro.Set("db.pass", "nope")), "read-only", "a read-only key");

            Open(vault.File(), "rw", "rw-phrase").Set("db.pass", "changed");
            Eq(vault.Get("db.pass"), "changed", "a write key");
        });

        Case("a restricted key cannot write an ungranted name", () =>
        {
            var vault = Fresh();
            vault.Set("db.pass", "hunter2");
            vault.Grant(new MiniVault.Grant
            {
                Key = "rw", Passphrase = "rw-phrase",
                Names = new List<string> { "db.pass" }, Write = true, Iterations = ROUNDS,
            });

            var rw = Open(vault.File(), "rw", "rw-phrase");
            Has(Threw(() => rw.Set("other.name", "x")), "was not granted", "ungranted");
        });

        Case("a granted name that does not exist yet", () =>
        {
            var vault = Fresh();
            vault.Grant(new MiniVault.Grant
            {
                Key = "ci", Passphrase = "ci-phrase",
                Names = new List<string> { "later.name" }, Iterations = ROUNDS,
            });

            var ci = Open(vault.File(), "ci", "ci-phrase");
            Eq(ci.List(), new string[0], "before");
            Eq(ci.Get("later.name"), null, "before");

            vault.Set("later.name", "here now");

            Eq(ci.Get("later.name"), "here now", "after");
            Eq(ci.List(), new[] { "later.name" }, "after");
        });

        Case("the master lists every key", () =>
        {
            var vault = Fresh();
            vault.Grant(new MiniVault.Grant
            {
                Key = "ro", Passphrase = "p1",
                Names = new List<string> { "a.one" }, Iterations = ROUNDS,
            });
            vault.Grant(new MiniVault.Grant
            {
                Key = "rw", Passphrase = "p2",
                Names = new List<string> { "a.one", "b.two" }, Write = true,
                Iterations = ROUNDS,
            });

            Eq(vault.Keys().Select(k => k.ToString()), new[]
            {
                "master/true/true/[]", "ro/false/false/[a.one]",
                "rw/false/true/[a.one, b.two]",
            }, "Keys()");
        });

        Case("the master-only methods refuse a restricted key", () =>
        {
            var vault = Fresh();
            vault.Set("a.one", "x");
            vault.Grant(new MiniVault.Grant
            {
                Key = "ci", Passphrase = "ci-phrase",
                Names = new List<string> { "a.one" }, Write = true, Iterations = ROUNDS,
            });

            var ci = Open(vault.File(), "ci", "ci-phrase");

            Has(Threw(() => ci.Keys()), "master key", "Keys()");
            Has(Threw(() => ci.Remove("a.one")), "master key", "Remove()");
            Has(Threw(() => ci.Rotate()), "master key", "Rotate()");
            Has(Threw(() => ci.Revoke("master")), "master key", "Revoke()");
            Has(Threw(() => ci.Grant(new MiniVault.Grant { Key = "x", Passphrase = "y" })),
                "master key", "Grant()");
        });

        Case("a repeated key id is refused", () =>
        {
            var vault = Fresh();
            vault.Grant(new MiniVault.Grant
            {
                Key = "ci", Passphrase = "one", Iterations = ROUNDS,
            });

            Has(Threw(() => vault.Grant(new MiniVault.Grant
            {
                Key = "ci", Passphrase = "two", Iterations = ROUNDS,
            })), "key already exists", "a repeated id");
        });

        Case("revoke drops a key", () =>
        {
            var vault = Fresh();
            vault.Set("a.one", "x");
            vault.Grant(new MiniVault.Grant
            {
                Key = "ci", Passphrase = "ci-phrase",
                Names = new List<string> { "a.one" }, Iterations = ROUNDS,
            });

            var ci = Open(vault.File(), "ci", "ci-phrase");
            Eq(ci.Get("a.one"), "x", "before");

            vault.Revoke("ci");

            Has(Threw(() => ci.Get("a.one")), "no such key", "after");
            Has(Threw(() => vault.Revoke("master")), "cannot revoke itself", "itself");
        });

        Case("rotate keeps the secrets", () =>
        {
            var vault = Fresh();
            vault.Set("api.token", "tok01");
            vault.Set("db.pass", "hunter2");
            vault.Grant(new MiniVault.Grant
            {
                Key = "ci", Passphrase = "ci-phrase",
                Names = new List<string> { "api.token" }, Iterations = ROUNDS,
            });

            vault.Rotate();

            Eq(vault.List(), new[] { "api.token", "db.pass" }, "List()");
            Eq(vault.Get("api.token"), "tok01", "api.token");
            Eq(vault.Get("db.pass"), "hunter2", "db.pass");
            Eq(vault.Keys().Select(k => k.Key), new[] { "master" }, "Keys()");

            Threw(() => Open(vault.File(), "ci", "ci-phrase").Get("api.token"));
        });

        // --- refusals -----------------------------------------------------

        Case("a wrong passphrase and a missing file refuse", () =>
        {
            var vault = Fresh();
            vault.Set("a.one", "x");

            Has(Threw(() => Open(vault.File(), null, "wrong").Get("a.one")),
                "wrong passphrase", "a wrong passphrase");
            Threw(() => Open(vault.File(), "nope", MASTER).Get("a.one"));
            Has(Threw(() => Open(Path.Combine(work, "nothing.skmv"), null, MASTER)
                .Get("a.one")), "no vault file", "a missing file");
        });

        Case("a damaged file is refused", () =>
        {
            var vault = Fresh();
            vault.Set("a.one", "x");
            byte[] raw = File.ReadAllBytes(vault.File());

            string short1 = VaultPath();
            File.WriteAllBytes(short1, raw.Take(raw.Length - 10).ToArray());
            Has(Threw(() => Open(short1, null, MASTER).Get("a.one")), "truncated", "short");

            string trailing = VaultPath();
            File.WriteAllBytes(trailing,
                raw.Concat(Encoding.Latin1.GetBytes("junk")).ToArray());
            Has(Threw(() => Open(trailing, null, MASTER).Get("a.one")),
                "trailing bytes", "trailing");

            string notvault = VaultPath();
            File.WriteAllBytes(notvault,
                Encoding.Latin1.GetBytes("NOPE").Concat(raw.Skip(4)).ToArray());
            Has(Threw(() => Open(notvault, null, MASTER).Get("a.one")),
                "not a vault file", "magic");
        });

        Case("creating over an existing vault is refused", () =>
        {
            var vault = Fresh();

            Has(Threw(() => MiniVault.CreateVault(new MiniVault.Options
            {
                File = vault.File(), Passphrase = MASTER, Iterations = ROUNDS,
            })), "already exists", "createvault over one");
        });

        Case("a vault needs a file and a passphrase", () =>
        {
            Threw(() => MiniVault.OpenVault(new MiniVault.Options
            {
                File = "", Passphrase = MASTER,
            }));
            Threw(() => MiniVault.OpenVault(new MiniVault.Options
            {
                File = VaultPath(), Passphrase = "",
            }));
        });

        Case("create makes the file only when asked", () =>
        {
            string path = VaultPath();

            var refuses = MiniVault.OpenVault(new MiniVault.Options
            {
                File = path, Passphrase = MASTER, Iterations = ROUNDS,
            });
            Threw(() => refuses.List());
            True(!File.Exists(path), "no file");

            var makes = MiniVault.OpenVault(new MiniVault.Options
            {
                File = path, Passphrase = MASTER, Iterations = ROUNDS, Create = true,
            });
            Eq(makes.List(), new string[0], "created");
            True(File.Exists(path), "the file");
        });

        Case("a key id longer than the format allows is refused", () =>
        {
            var vault = Fresh();

            Has(Threw(() => vault.Grant(new MiniVault.Grant
            {
                Key = new string('k', 256), Passphrase = "p", Iterations = ROUNDS,
            })), "longer than 255", "a long key id");
            Eq(vault.Keys().Select(k => k.Key), new[] { "master" }, "unchanged");
        });

        // --- the handle ----------------------------------------------------

        Case("the key information a caller gets cannot change what the key may do", () =>
        {
            var vault = Fresh();
            vault.Set("a.one", "x");
            vault.Grant(new MiniVault.Grant
            {
                Key = "ro", Passphrase = "ro-phrase",
                Names = new List<string> { "a.one" }, Iterations = ROUNDS,
            });

            var ro = Open(vault.File(), "ro", "ro-phrase");

            // KeyInfo's properties have no setter and `Grants` is a
            // read-only view, so the defect the review round found - a
            // caller flipping its own `write` bit - does not compile here.
            var got = ro.Open();
            bool refused = false;

            try
            {
                ((IList<string>)got.Grants).Add("b.two");
            }
            catch (NotSupportedException)
            {
                refused = true;
            }

            True(refused, "Grants is read-only");
            Has(Threw(() => ro.Set("a.one", "nope")), "read-only", "still read-only");
            Eq(ro.Open().Grants, new[] { "a.one" }, "still one grant");
        });

        Case("a revoked key stops reading from a cached handle", () =>
        {
            var vault = Fresh();
            vault.Set("a.one", "x");
            vault.Grant(new MiniVault.Grant
            {
                Key = "ci", Passphrase = "ci-phrase",
                Names = new List<string> { "a.one" }, Iterations = ROUNDS,
            });

            var ci = Open(vault.File(), "ci", "ci-phrase");
            Eq(ci.Get("a.one"), "x", "before");

            vault.Revoke("ci");
            Threw(() => ci.Get("a.one"));
        });

        Case("a re-granted key id does not keep the old passphrase working", () =>
        {
            var vault = Fresh();
            vault.Set("a.one", "x");
            vault.Grant(new MiniVault.Grant
            {
                Key = "ci", Passphrase = "first",
                Names = new List<string> { "a.one" }, Iterations = ROUNDS,
            });

            var ci = Open(vault.File(), "ci", "first");
            Eq(ci.Get("a.one"), "x", "before");

            vault.Revoke("ci");
            vault.Grant(new MiniVault.Grant
            {
                Key = "ci", Passphrase = "second",
                Names = new List<string> { "a.one" }, Iterations = ROUNDS,
            });

            Has(Threw(() => ci.Get("a.one")), "wrong passphrase", "the old passphrase");
            Eq(Open(vault.File(), "ci", "second").Get("a.one"), "x", "the new one");
        });

        Case("close forgets the derived keys", () =>
        {
            var vault = Fresh();
            vault.Set("a.one", "x");
            Eq(vault.Get("a.one"), "x", "before");

            vault.Close();
            Eq(vault.Get("a.one"), "x", "after");
        });

        // --- the format, across ports ---------------------------------------

        // EVERY COMMITTED VAULT, not only this port's. A suite that reads
        // only the vault its own port wrote proves the reader agrees with
        // the writer beside it - which a port whose serializer and parser
        // share a mistake satisfies perfectly.
        foreach (string name in Fixtures())
        {
            string which = name;

            Case("the committed fixture reads, key by key: " + which, () =>
            {
                string file = Fixture(which);

                var master = Open(file, null, "fixture-master");

                Eq(master.List(), new[] { "api.token", "db.pass", "deep.nested.name" },
                    "List()");
                Eq(master.Get("api.token"), "fixture-token", "api.token");
                Eq(master.Get("db.pass"), "fixture-pass", "db.pass");
                Eq(master.Get("deep.nested.name"), "fixture-deep", "deep");

                Eq(master.Keys().Select(k => k.ToString()), new[]
                {
                    "master/true/true/[]", "reader/false/false/[api.token]",
                    "writer/false/true/[db.pass]",
                }, "Keys()");

                var reader = Open(file, "reader", "fixture-reader");
                Eq(reader.List(), new[] { "api.token" }, "reader List()");
                Eq(reader.Get("api.token"), "fixture-token", "reader grant");
                Eq(reader.Get("db.pass"), null, "reader miss");

                Open(file, "writer", "fixture-writer").Set("db.pass", "written by this port");
                Eq(master.Get("db.pass"), "written by this port", "writer");
            });
        }

        // --- the chain --------------------------------------------------------

        Case("a vault is one store in a chain", () =>
        {
            var vault = Fresh();
            vault.Set("api.token", "from the vault");

            var secrets = Chain(
                Spec("kind", "memory", "values",
                    new Dictionary<string, object> { { "DB_PASS", "from memory" } }),
                Spec("kind", "minivault", "file", vault.File(), "passphrase", MASTER));

            Eq(secrets.Get("api.token"), "from the vault", "the vault");
            Eq(secrets.Get("db.pass"), "from memory", "memory");
        });

        Case("a restricted key in a chain falls through", () =>
        {
            var vault = Fresh();
            vault.Set("api.token", "from the vault");
            vault.Set("db.pass", "in the vault, not granted");
            vault.Grant(new MiniVault.Grant
            {
                Key = "ci", Passphrase = "ci-phrase",
                Names = new List<string> { "api.token" }, Iterations = ROUNDS,
            });

            var secrets = Chain(
                Spec("kind", "minivault", "file", vault.File(), "vaultkey", "ci",
                    "passphrase", "ci-phrase"),
                Spec("kind", "memory", "values",
                    new Dictionary<string, object> { { "DB_PASS", "from memory" } }));

            Eq(secrets.Get("api.token"), "from the vault", "the grant");
            Eq(secrets.Get("db.pass"), "from memory", "falls through");
        });

        Case("the vault behind a store is reachable as an API", () =>
        {
            var vault = Fresh();
            vault.Set("api.token", "tok01");

            var secrets = Chain(
                Spec("kind", "minivault", "file", vault.File(), "passphrase", MASTER));

            var api = MiniVault.VaultOf(secrets);
            Eq(api.List(), new[] { "api.token" }, "List()");

            api.Set("db.pass", "written through the api");
            Eq(secrets.Get("db.pass"), "written through the api", "the chain sees it");
        });

        Case("a named store is reached by name", () =>
        {
            var vault = Fresh();
            vault.Set("api.token", "tok01");

            var secrets = Chain(
                Spec("kind", "minivault", "name", "app", "file", vault.File(),
                    "passphrase", MASTER));

            Eq(MiniVault.VaultOf(secrets, "app").List(), new[] { "api.token" }, "by name");
            Eq(MiniVault.VaultOf(secrets).List(), new[] { "api.token" }, "by alias");
            Has(Threw(() => MiniVault.VaultOf(secrets, "minivault")),
                "no minivault store named", "a name that is not there");
        });

        Case("a chain with no vault says so", () =>
        {
            var secrets = Chain(
                Spec("kind", "memory", "values", new Dictionary<string, object>()));

            Has(Threw(() => MiniVault.VaultOf(secrets)), "no minivault store", "no vault");
        });

        Case("a chain missing the file is refused at construction", () =>
        {
            Has(Threw(() => Chain(Spec("kind", "minivault", "passphrase", MASTER))),
                "a vault needs a file", "no file");
            Has(Threw(() => Chain(Spec("kind", "minivault", "file", VaultPath()))),
                "a vault needs a passphrase", "no passphrase");
        });

        Case("the file is reached at the first lookup", () =>
        {
            // No file, and construction still succeeds: the handle is lazy.
            var secrets = Chain(
                Spec("kind", "minivault", "file", VaultPath(), "passphrase", MASTER));

            Has(Threw(() => secrets.Get("api.token")), "no vault file", "at first lookup");
        });

        return cases;
    }
}
