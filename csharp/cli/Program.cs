// A tiny app that needs a secret.
//
// It asks sekreto for `api.token` and calls the token-protected API with
// it. Every port ships this same CLI, and test/integration.sh runs all of
// them against the same server from all four secret sources - which is what
// proves the library, rather than the spec alone.
//
// Usage: dotnet SekretoCli.dll <api-url> [--source env|dotenv|hashicorp|boru|chain]
//                                        [--store <name>]   directed read

using System;
using System.Collections.Generic;
using System.Net;
using System.Net.Http;
using Voxgig.Sekreto;

internal static class Program
{
    private const string Lang = "csharp";

    private static string EnvOr(string name, string fallback)
    {
        string value = Environment.GetEnvironmentVariable(name);
        return string.IsNullOrEmpty(value) ? fallback : value;
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

    private static List<object> ChainSpecs(string source)
    {
        var envspec = Spec("kind", "env", "prefix", Environment.GetEnvironmentVariable("SEKRETO_PREFIX"));
        var dotenvspec = Spec("kind", "dotenv", "file", EnvOr("SEKRETO_DOTENV", ".env"));
        var hashicorpspec = Spec(
            "kind", "hashicorp",
            "addr", EnvOr("VAULT_ADDR", ""),
            "token", EnvOr("VAULT_TOKEN", ""),
            "mount", Environment.GetEnvironmentVariable("VAULT_MOUNT"));
        var boruspec = Spec(
            "kind", "boru",
            "command", EnvOr("BORU_COMMAND", "boru"),
            "namespace", Environment.GetEnvironmentVariable("BORU_NAMESPACE"),
            "home", Environment.GetEnvironmentVariable("BORU_HOME"));

        var chain = new List<object>();

        switch (source)
        {
            case "env": chain.Add(envspec); break;
            case "dotenv": chain.Add(dotenvspec); break;
            case "hashicorp": chain.Add(hashicorpspec); break;
            case "boru": chain.Add(boruspec); break;
            default:
                // The default: the chain an app would actually ship with -
                // local overrides first, shared vaults last.
                chain.AddRange(new object[] { envspec, dotenvspec, hashicorpspec, boruspec });
                break;
        }

        return chain;
    }

    private static int Main(string[] args)
    {
        string url = 0 < args.Length ? args[0] : "http://127.0.0.1:8099/whoami";

        string source = "chain";
        for (int index = 0; index < args.Length; index++)
        {
            if ("--source" == args[index] && index + 1 < args.Length)
            {
                source = args[index + 1];
            }
        }

        // --store names a store outright: the secret must come from that one,
        // not from whichever provider happens to answer first.
        string store = "";
        for (int index = 0; index < args.Length; index++)
        {
            if ("--store" == args[index] && index + 1 < args.Length)
            {
                store = args[index + 1];
            }
        }

        object chain = ChainSpecs(source);
        var secrets = new Sekreto(Providers.MakeChain(chain), Providers.ChainNames(chain), true);

        string token;
        try
        {
            token = 0 == store.Length
                ? secrets.Get("api.token")
                : secrets.GetFrom(store, "api.token");
        }
        catch (Exception err)
        {
            Console.Error.WriteLine("sekreto-cli: " + err.Message);
            return 2;
        }

        using var client = new HttpClient { Timeout = TimeSpan.FromSeconds(10) };

        var request = new HttpRequestMessage(HttpMethod.Get, url);
        request.Headers.TryAddWithoutValidation("Authorization", "Bearer " + token);
        request.Headers.TryAddWithoutValidation("X-Sekreto-Lang", Lang);

        HttpResponseMessage response;
        string body;
        try
        {
            response = client.Send(request);
            body = response.Content.ReadAsStringAsync().GetAwaiter().GetResult();
        }
        catch (Exception err)
        {
            Console.Error.WriteLine("sekreto-cli: " + secrets.Redact(err.Message));
            return 1;
        }

        if (HttpStatusCode.OK != response.StatusCode)
        {
            // Never print the token itself, even when the call fails.
            Console.Error.WriteLine("sekreto-cli: " + secrets.Redact(body));
            return 1;
        }

        object caller = (Json.Parse(body) as Dictionary<string, object>)?.GetValueOrDefault("caller");

        Console.WriteLine(Json.Stringify(
            Spec("ok", true, "lang", Lang, "source", source, "store", store, "caller", caller)));

        return 0;
    }
}
