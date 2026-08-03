// RUN: make test
// RUN-SOME: ./test/bin/Debug/net8.0/sekretotest envkey
//
// The sekreto conformance suite. Every port runs these same groups, from
// the same spec/sekreto.json, through its own voxgig/omni runner.
//
// No third-party test framework: a failing omni check throws OmniError, so
// any host framework (xUnit, NUnit, MSTest) reports it as a failure. This
// harness keeps `make test` dependency-free.

using System;
using System.Collections.Generic;
using System.IO;
using Voxgig.Omni;
using Voxgig.Sekreto;

internal static class Program
{
    private static string only;
    private static int passcount;
    private static int failcount;

    // Find the shared spec directory by walking up from the working dir.
    private static string SpecFile(string name)
    {
        var dir = new DirectoryInfo(Directory.GetCurrentDirectory());

        for (int step = 0; step < 8 && null != dir; step++)
        {
            string cand = Path.Combine(dir.FullName, "spec", name);
            if (File.Exists(cand))
            {
                return cand;
            }
            dir = dir.Parent;
        }

        throw new SekretoError("sekreto: spec not found: " + name);
    }

    private static Dictionary<string, object> Entry(object value)
    {
        return value as Dictionary<string, object>;
    }

    private static string Text(object value)
    {
        return null == value ? null : Convert.ToString(value);
    }

    // Build a Sekreto from the spec's declarative chain description.
    private static Sekreto ChainOf(object value)
    {
        object chain = Entry(value)["chain"];
        return new Sekreto(Providers.MakeChain(chain), Providers.ChainNames(chain), false);
    }

    private static readonly Subject VALIDNAME = args => Names.ValidName(args[0]);

    private static readonly Subject ENVKEY =
        args => Names.EnvKey(Entry(args[0])["name"], Text(Entry(args[0]).GetValueOrDefault("prefix")));

    private static readonly Subject VAULTREF = args => Names.VaultRef(args[0]);

    private static readonly Subject FLATNAME =
        args => Names.FlatName(Entry(args[0])["name"], Text(Entry(args[0])["sep"]));

    private static readonly Subject AWSPARAM =
        args => Names.AwsParam(Entry(args[0])["name"], Text(Entry(args[0]).GetValueOrDefault("prefix")));

    private static readonly Subject PARSEDOTENV = args => Dotenv.Parse(args[0]);

    private static readonly Subject RESOLVE =
        args => ChainOf(args[0]).Get(Text(Entry(args[0])["name"]));

    private static readonly Subject TRYSECRET =
        args => ChainOf(args[0]).TryGet(Text(Entry(args[0])["name"]));

    private static readonly Subject SOURCES = args => ChainOf(args[0]).Sources();

    private static readonly Subject STORES = args => ChainOf(args[0]).Stores();

    private static readonly Subject GETFROM = args => ChainOf(args[0]).GetFrom(
        Text(Entry(args[0])["store"]), Text(Entry(args[0])["name"]));

    private static readonly Subject TRYFROM = args => ChainOf(args[0]).TryFrom(
        Text(Entry(args[0])["store"]), Text(Entry(args[0])["name"]));

    // The answer is an insertion-ordered map, compared as a JSON object.
    private static readonly Subject SIGV4 = args => Sigv4.Sign(Entry(args[0]));

    private static readonly Subject REDACT = args => Sekreto.Redact(
        Entry(args[0])["text"], Entry(args[0])["values"] as List<object>);

    private static void TestCase(string name, Action body)
    {
        if (null != only && name != only)
        {
            return;
        }

        try
        {
            body();
            passcount++;
            Console.WriteLine("ok   - " + name);
        }
        catch (Exception err)
        {
            failcount++;
            Console.WriteLine("FAIL - " + name);
            Console.WriteLine(err.Message);
        }
    }

    private static int Main(string[] args)
    {
        if (0 < args.Length)
        {
            only = args[0];
        }

        RunPack R = Runner.MakeRunner(SpecFile("sekreto.json")).Run("sekreto");

        TestCase("validname", () => R.RunSetFlags(R.Set("validname"), Flags.NoNull(), VALIDNAME));
        TestCase("envkey", () => R.RunSet(R.Set("envkey"), ENVKEY));
        TestCase("vaultref", () => R.RunSet(R.Set("vaultref"), VAULTREF));
        TestCase("flatname", () => R.RunSet(R.Set("flatname"), FLATNAME));
        TestCase("awsparam", () => R.RunSet(R.Set("awsparam"), AWSPARAM));
        TestCase("parsedotenv", () => R.RunSet(R.Set("parsedotenv"), PARSEDOTENV));
        TestCase("resolve", () => R.RunSet(R.Set("resolve"), RESOLVE));
        TestCase("trysecret", () => R.RunSet(R.Set("trysecret"), TRYSECRET));
        TestCase("sources", () => R.RunSet(R.Set("sources"), SOURCES));
        TestCase("stores", () => R.RunSet(R.Set("stores"), STORES));
        TestCase("getfrom", () => R.RunSet(R.Set("getfrom"), GETFROM));
        TestCase("tryfrom", () => R.RunSet(R.Set("tryfrom"), TRYFROM));
        TestCase("sigv4", () => R.RunSet(R.Set("sigv4"), SIGV4));
        TestCase("redact", () => R.RunSet(R.Set("redact"), REDACT));

        Console.WriteLine("\n" + passcount + " passed, " + failcount + " failed");

        return 0 == failcount ? 0 : 1;
    }
}
