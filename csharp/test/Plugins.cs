// RUN: make test-plugins
// RUN-SOME: ./test/bin/Debug/net8.0/sekretotest plugins
//
// THE PLUGIN SEAM, from both sides.
//
// Moving the provider kinds that open sockets and spawn processes out of
// the core made a consumer's PLUGIN LIST load-bearing: a kind nobody
// passed in is not in the catalog, and a chain naming it is refused. That
// is the intended behaviour, and it means a consumer can be broken
// without a single conformance check noticing - the conformance suite
// passes every plugin to every chain it builds, so it can never see a
// missing one. So the full set is pinned here: it holds every kind, every
// kind builds, and the CLI passes it.
//
// And from the other side: the core assembly must not be able to REACH a
// plugin. In csharp that is not a convention, it is the assembly
// reference graph, and the last three cases read it out of the compiled
// artifact.

using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Reflection;
using Voxgig.Plugin;
using Voxgig.Sekreto;
using Voxgig.Sekreto.Plugins;

internal static class Seam
{
    private static readonly string[] PLUGINS =
    {
        "awsparams", "awssecrets", "azuresecrets", "boru", "doppler", "gcpsecrets",
        "hashicorp", "infisical", "onepassword", "secretspec",
    };

    // Every kind this library ships, built in or plugged in, in one sorted
    // list - which is also the order a chain of all of them reports.
    private static readonly string[] EVERY =
        new[] { "dotenv", "env", "file", "memory" }.Concat(PLUGINS).OrderBy(n => n, StringComparer.Ordinal).ToArray();

    // --- assertions -------------------------------------------------------

    private static void Eq(object got, object want, string what)
    {
        string gottext = Show(got);
        string wanttext = Show(want);

        if (gottext != wanttext)
        {
            throw new Exception(what + ":\n  got  " + gottext + "\n  want " + wanttext);
        }
    }

    private static string Show(object value)
    {
        if (value is IEnumerable<string> texts)
        {
            return "[" + string.Join(", ", texts) + "]";
        }

        if (value is IEnumerable<object> items)
        {
            return "[" + string.Join(", ", items.Select(Show)) + "]";
        }

        return null == value ? "<null>" : Convert.ToString(value);
    }

    private static void True(bool got, string what)
    {
        if (!got)
        {
            throw new Exception(what);
        }
    }

    private static Exception Caught(Action body, string what)
    {
        try
        {
            body();
        }
        catch (Exception err)
        {
            return err;
        }

        throw new Exception(what + ": nothing was thrown");
    }

    private static string Refused(Action body, string what)
    {
        Exception err = Caught(body, what);

        if (!(err is SekretoError))
        {
            throw new Exception(what + ": " + err.GetType().Name + " - " + err.Message);
        }

        return err.Message;
    }

    // --- helpers ----------------------------------------------------------

    private static Dictionary<string, object> Spec(params object[] pairs)
    {
        var out_ = new Dictionary<string, object>();

        for (int index = 0; index + 1 < pairs.Length; index += 2)
        {
            out_[Convert.ToString(pairs[index])] = pairs[index + 1];
        }

        return out_;
    }

    private static List<string> Names(IEnumerable<Definition> definitions)
    {
        return definitions.Select(d => d.Name).ToList();
    }

    private static string Here(params string[] parts)
    {
        string dir = Path.GetDirectoryName(typeof(Seam).Assembly.Location);

        for (int step = 0; step < 8 && null != dir; step++)
        {
            string cand = Path.Combine(new[] { dir }.Concat(parts).ToArray());

            if (File.Exists(cand))
            {
                return cand;
            }

            dir = Path.GetDirectoryName(dir);
        }

        throw new Exception("seam: file not found: " + string.Join("/", parts));
    }

    /// <summary>A provider kind a consumer wrote, not this library.</summary>
    private sealed class Shouty : IProvider
    {
        private readonly Dictionary<string, object> values;

        internal Shouty(Dictionary<string, object> values)
        {
            this.values = values ?? new Dictionary<string, object>();
        }

        public string Lookup(string name)
        {
            return values.TryGetValue(name.ToUpperInvariant(), out object found)
                ? Convert.ToString(found)
                : null;
        }

        public string Describe()
        {
            return "shouty";
        }
    }

    private sealed class Replaced : IProvider
    {
        public string Lookup(string name)
        {
            return "replaced";
        }

        public string Describe()
        {
            return "memory";
        }
    }

    // --- the cases --------------------------------------------------------

    internal static List<KeyValuePair<string, Action>> Cases()
    {
        var cases = new List<KeyValuePair<string, Action>>();

        void Case(string name, Action body)
        {
            cases.Add(new KeyValuePair<string, Action>(name, body));
        }

        Case("the full set holds every kind", () =>
        {
            Eq(Names(SekretoPlugins.All()).OrderBy(n => n, StringComparer.Ordinal), PLUGINS,
                "SekretoPlugins.All()");
            Eq(Names(Providers.Builtins()), Providers.BuiltinKinds, "Providers.Builtins()");
            Eq(Providers.PluginKinds.OrderBy(n => n, StringComparer.Ordinal), PLUGINS,
                "Providers.PluginKinds");
        });

        // Naming a kind is not enough: a kind can be in the catalog and
        // still fail to build. Construction is what the CLI does before any
        // network.
        Case("every kind builds from a spec", () =>
        {
            var chain = new List<object>();

            foreach (string kind in EVERY)
            {
                chain.Add(Spec(
                    "kind", kind, "addr", "http://127.0.0.1:8200", "token", "t",
                    "dir", "/tmp", "file", "/tmp/.env", "values", new Dictionary<string, object>()));
            }

            var secrets = new Sekreto(new SekretoOptions
            {
                Providers = chain, Plugins = SekretoPlugins.All(), Cache = false,
            });

            Eq(secrets.Stores(), EVERY, "stores");
            Eq(secrets.Host.List().Keys, EVERY, "host refs");
            Eq(secrets.Host.List().Values.Distinct(), new[] { "live" }, "host statuses");
        });

        Case("the cli passes the full set", () =>
        {
            string source = File.ReadAllText(Here("cli", "Program.cs"));
            True(source.Contains("using Voxgig.Sekreto.Plugins;"), "the CLI names the plugin assembly");
            True(source.Contains("Plugins = SekretoPlugins.All(),"), "the CLI passes the full set");

            string project = File.ReadAllText(Here("cli", "SekretoCli.csproj"));
            True(project.Contains("../plugins/SekretoPlugins.csproj"), "the CLI references the plugin assembly");
        });

        // --- what a consumer sees -----------------------------------------

        Case("one plugin is enough for a chain that names only it", () =>
        {
            var secrets = new Sekreto(new SekretoOptions
            {
                Plugins = new List<Definition> { Hashicorp.Plugin },
                Providers = new List<object>
                {
                    Spec("kind", "memory", "values", Spec("API_TOKEN", "tok01")),
                    Spec("kind", "hashicorp", "name", "prod",
                         "addr", "https://vault.example.com", "token", "t"),
                },
            });

            Eq(secrets.Stores(), new[] { "memory", "prod" }, "stores");
            Eq(secrets.Sources(),
                new[] { "memory", "hashicorp:https://vault.example.com/secret" }, "sources");
            Eq(secrets.Get("api.token"), "tok01", "get");

            // The plugin host is what the chain is made of, and it reads
            // like the chain: the kind, or kind$store for a named store.
            Eq(secrets.Host.List().Keys, new[] { "hashicorp$prod", "memory" }, "host refs");
            Eq(secrets.Catalog.Names(),
                new[] { "dotenv", "env", "file", "hashicorp", "memory" }, "catalog");
        });

        Case("a kind that was not passed in is refused, naming the fix", () =>
        {
            Eq(Refused(() => new Sekreto(new SekretoOptions
            {
                Plugins = new List<Definition> { Hashicorp.Plugin },
                Providers = new List<object> { Spec("kind", "doppler", "token", "t") },
            }), "an unloaded plugin kind"),
                "sekreto: unknown provider kind: doppler"
                + " (available: dotenv, env, file, hashicorp, memory)"
                + " - doppler is a sekreto plugin, not built in: pass it in the plugins option",
                "the message names the fix");

            // A kind nobody ships is a typo, and gets no such hint.
            Eq(Refused(() => new Sekreto(new SekretoOptions
            {
                Providers = new List<object> { Spec("kind", "vualt") },
            }), "a kind nobody ships"),
                "sekreto: unknown provider kind: vualt (available: dotenv, env, file, memory)",
                "a typo gets no hint");
        });

        // Two providers MAY share a store name - a directed read walks both,
        // and the spec pins it - but an instance ref may not, so the second
        // gets a numbered tag from the host and keeps its store name.
        Case("a repeated store name keeps the store and numbers the instance", () =>
        {
            var secrets = new Sekreto(new SekretoOptions
            {
                Providers = new List<object>
                {
                    Spec("kind", "memory", "values", Spec()),
                    Spec("kind", "memory", "values", Spec("API_TOKEN", "second")),
                    Spec("kind", "memory", "name", "pair", "values", Spec()),
                    Spec("kind", "memory", "name", "pair", "values", Spec("API_TOKEN", "pair2")),
                },
            });

            Eq(secrets.Stores(), new[] { "memory", "pair" }, "stores");
            Eq(secrets.Host.List().Keys,
                new[] { "memory", "memory$1", "memory$2", "memory$pair" }, "host refs");
            Eq(secrets.GetFrom("memory", "api.token"), "second", "getfrom memory");
            Eq(secrets.GetFrom("pair", "api.token"), "pair2", "getfrom pair");
        });

        Case("a store name must be a valid tag", () =>
        {
            Eq(Refused(() => new Sekreto(new SekretoOptions
            {
                Providers = new List<object>
                {
                    Spec("kind", "memory", "name", "my store", "values", Spec()),
                },
            }), "a store name with a space"),
                "sekreto: invalid store name: my store", "the message");
        });

        // A provider that refuses its own configuration raises a
        // SekretoError from inside the plugin's define. The spec pins that
        // message byte for byte, so it must come back out of the host as
        // itself - not wrapped as plugin_define_failed, and not as a
        // PluginException.
        Case("a sekreto error raised in define comes back out as itself", () =>
        {
            Eq(Refused(() => new Sekreto(new SekretoOptions
            {
                Plugins = new List<Definition> { Hashicorp.Plugin },
                Providers = new List<object>
                {
                    Spec("kind", "hashicorp", "addr", "http://127.0.0.1:1", "token", "t", "kv", 3),
                },
            }), "a hashicorp kv version that does not exist"),
                "sekreto: hashicorp: unsupported kv version: 3", "the message, byte for byte");
        });

        // ...and any other error is not sekreto's to rewrite: it surfaces as
        // the host reports it, naming the instance and the cause.
        Case("any other error raised in define is the host's report of it", () =>
        {
            Definition broken = Providers.ProviderPlugin("broken",
                spec => throw new InvalidOperationException("boom"));

            Exception err = Caught(() => new Sekreto(new SekretoOptions
            {
                Plugins = new List<Definition> { broken },
                Providers = new List<object> { Spec("kind", "broken") },
            }), "a definition that raises");

            Eq(Plugin.CodeOf(err), "plugin_define_failed", "the host's code");
            True(err.Message.Contains("boom"), "the cause survives: " + err.Message);
            True(!(err is SekretoError), "it is not rewritten as a SekretoError");
        });

        Case("a custom kind is one providerplugin call", () =>
        {
            Definition shouty = Providers.ProviderPlugin("shouty",
                spec => new Shouty(spec.GetValueOrDefault("values") as Dictionary<string, object>));

            var secrets = new Sekreto(new SekretoOptions
            {
                Plugins = new List<Definition> { shouty },
                Providers = new List<object>
                {
                    Spec("kind", "shouty", "values", Spec("API.TOKEN", "loud")),
                },
            });

            Eq(secrets.Get("api.token"), "loud", "get");
            Eq(secrets.Host.List().Keys, new[] { "shouty" }, "host refs");
        });

        // A plugin that names a built-in kind replaces it: that is how a
        // host substitutes an implementation, and never an accident,
        // because the four names are documented.
        Case("a plugin may replace a built-in kind", () =>
        {
            var secrets = new Sekreto(new SekretoOptions
            {
                Plugins = new List<Definition>
                {
                    Providers.ProviderPlugin("memory", spec => new Replaced()),
                },
                Providers = new List<object>
                {
                    Spec("kind", "memory", "values", Spec("API_TOKEN", "original")),
                },
            });

            Eq(secrets.Get("api.token"), "replaced", "the substitute answered");
        });

        Case("close tears the chain down and keeps redaction", () =>
        {
            var secrets = new Sekreto(new SekretoOptions
            {
                Providers = new List<object>
                {
                    Spec("kind", "memory", "values", Spec("API_TOKEN", "tok01")),
                },
            });

            Eq(secrets.Get("api.token"), "tok01", "get");

            secrets.Close();

            Eq(secrets.Host.List().Keys, new string[0], "host refs");
            Eq(secrets.Stores(), new string[0], "stores");
            Eq(secrets.TryGet("api.token"), null, "try");
            Eq(secrets.Redact("token=tok01"), "token=[redacted]", "redact");
        });

        // --- what the artifact says ---------------------------------------

        // THE CORE REFERENCES NO PLUGIN. A .NET assembly names every
        // assembly it references in its own metadata, and a type in an
        // assembly that is not named there cannot be resolved at run time -
        // so this is the linking boundary itself, read back, not a
        // convention anyone has to keep.
        Case("the core references no plugin", () =>
        {
            var refs = typeof(Sekreto).Assembly.GetReferencedAssemblies()
                .Select(a => a.Name).OrderBy(n => n, StringComparer.Ordinal).ToList();

            True(!refs.Contains("VoxgigSekretoPlugins"),
                "the core references the plugin assembly: " + Show(refs));

            // ...and none of the three platform assemblies only a plugin
            // needs. A socket, a signature and a child process, in that
            // order.
            foreach (string platform in new[]
            {
                "System.Net.Http", "System.Security.Cryptography", "System.Diagnostics.Process",
            })
            {
                True(!refs.Contains(platform),
                    "the core references " + platform + ": " + Show(refs));
            }

            // The reference points the other way, which is what makes the
            // absence structural: a reference back would be a build cycle.
            var back = typeof(Hashicorp).Assembly.GetReferencedAssemblies()
                .Select(a => a.Name).ToList();

            True(back.Contains("VoxgigSekreto"), "the plugins reference the core: " + Show(back));
        });

        // sigv4 moved with the aws plugin, and that is the sharpest
        // instance of the rule: THE CORE OF NO PORT IMPORTS A HASH
        // FUNCTION.
        Case("sigv4 lives with the aws plugin, not in the core", () =>
        {
            Eq(typeof(Sigv4).Assembly.GetName().Name, "VoxgigSekretoPlugins", "sigv4's assembly");
            Eq(typeof(Sekreto).Assembly.GetName().Name, "VoxgigSekreto", "the core's assembly");

            True(!Directory.EnumerateFiles(
                    Path.GetDirectoryName(Here("src", "Sekreto.csproj")), "*.cs")
                .Any(f => File.ReadAllText(f).Contains("System.Security.Cryptography")),
                "the core's source names a crypto namespace");
        });

        // The full set is built on demand: All() hands back a fresh list
        // every time, so a caller cannot mutate the catalog every other
        // caller will get. It is also the ONLY name that reaches all ten -
        // a consumer that wants one takes one.
        Case("the full set is built on demand", () =>
        {
            List<Definition> first = SekretoPlugins.All();
            List<Definition> second = SekretoPlugins.All();

            True(!ReferenceEquals(first, second), "All() returns a shared list");
            Eq(first.Count, 10, "the full set");
            Eq(Names(first), Names(second), "the same definitions");

            Eq(Names(new List<Definition> { Hashicorp.Plugin }), new[] { "hashicorp" },
                "one plugin is one definition");
        });

        // Python refuses a MODULE handed in where a definition belongs.
        // csharp's type system refuses that at compile time - Plugins is a
        // List<Definition> and a namespace is not a value - so what is left
        // to check is the one non-definition the type does admit.
        Case("a non-definition passed as a plugin is refused", () =>
        {
            Exception err = Caught(() => new Sekreto(new SekretoOptions
            {
                Plugins = new List<Definition> { null },
                Providers = new List<object>(),
            }), "a null plugin");

            // A SEKRETO refusal, not the plugin library's. The message
            // names the fix, and it matches java and python byte for byte.
            Eq(err.GetType().Name, "SekretoError", "refused by sekreto, not the catalog");
            Eq(
                err.Message,
                "sekreto: not a plugin definition: null"
                + " - a plugin is what Support.ProviderPlugin(kind, make) returns",
                "the message names the fix");
        });

        return cases;
    }
}
