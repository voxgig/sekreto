// A tiny app that needs a secret.
//
// It asks sekreto for `api.token` and calls the token-protected API with
// it. Every port ships this same CLI, and test/integration.sh runs all of
// them against the same server from every secret source - which is what
// proves the library, rather than the spec alone.
//
// Usage: dotnet SekretoCli.dll <api-url> [--source <source>] [--store <name>]
//
// Sources: env dotenv file hashicorp boru boruwire awssecrets awsparams
//          gcpsecrets azuresecrets onepassword doppler infisical chain
//
// Each source's configuration arrives in the environment variables its
// own ecosystem already uses (VAULT_*, AWS_*, OP_CONNECT_*, ...), listed
// in ChainSpecs below.

using System;
using System.Collections.Generic;
using System.Globalization;
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
        var filespec = Spec("kind", "file", "dir", EnvOr("SEKRETO_FILEDIR", "/run/secrets"));

        string vaultkv = Environment.GetEnvironmentVariable("VAULT_KV");
        string vaultauth = Environment.GetEnvironmentVariable("VAULT_AUTH");

        var hashicorpspec = Spec(
            "kind", "hashicorp",
            "addr", EnvOr("VAULT_ADDR", ""),
            "token", EnvOr("VAULT_TOKEN", ""),
            "mount", Environment.GetEnvironmentVariable("VAULT_MOUNT"),
            "kv", string.IsNullOrEmpty(vaultkv)
                ? null
                : (object)int.Parse(vaultkv, CultureInfo.InvariantCulture),
            "vaultnamespace", Environment.GetEnvironmentVariable("VAULT_NAMESPACE"),
            "auth", string.IsNullOrEmpty(vaultauth) ? null : Spec(
                "method", vaultauth,
                "role", Environment.GetEnvironmentVariable("VAULT_ROLE"),
                "jwtfile", Environment.GetEnvironmentVariable("VAULT_JWT_FILE"),
                "roleid", Environment.GetEnvironmentVariable("VAULT_ROLE_ID"),
                "secretid", Environment.GetEnvironmentVariable("VAULT_SECRET_ID")));

        var boruspec = Spec(
            "kind", "boru",
            "command", EnvOr("BORU_COMMAND", "boru"),
            "namespace", Environment.GetEnvironmentVariable("BORU_NAMESPACE"),
            "home", Environment.GetEnvironmentVariable("BORU_HOME"));

        // The same vault over its wire protocol (`boru vault serve`) instead
        // of the CLI: an address plus a capability token from `vault grant`.
        var boruwirespec = Spec(
            "kind", "boru",
            "addr", EnvOr("BORU_ADDR", ""),
            "token", EnvOr("BORU_TOKEN", ""),
            "namespace", Environment.GetEnvironmentVariable("BORU_NAMESPACE"));

        var awssecretsspec = Spec(
            "kind", "awssecrets",
            "region", Environment.GetEnvironmentVariable("AWS_REGION"),
            "addr", Environment.GetEnvironmentVariable("AWS_ENDPOINT"));

        var awsparamsspec = Spec(
            "kind", "awsparams",
            "region", Environment.GetEnvironmentVariable("AWS_REGION"),
            "addr", Environment.GetEnvironmentVariable("AWS_ENDPOINT"),
            "prefix", Environment.GetEnvironmentVariable("AWS_PARAM_PREFIX"));

        var gcpspec = Spec(
            "kind", "gcpsecrets",
            "project", Environment.GetEnvironmentVariable("GCP_PROJECT"),
            "addr", Environment.GetEnvironmentVariable("GCP_ADDR"),
            "metadataaddr", Environment.GetEnvironmentVariable("GCP_METADATA_ADDR"));

        var azurespec = Spec(
            "kind", "azuresecrets",
            "vault", Environment.GetEnvironmentVariable("AZURE_VAULT"),
            "token", Environment.GetEnvironmentVariable("AZURE_TOKEN"),
            "tenant", Environment.GetEnvironmentVariable("AZURE_TENANT"),
            "clientid", Environment.GetEnvironmentVariable("AZURE_CLIENT_ID"),
            "clientsecret", Environment.GetEnvironmentVariable("AZURE_CLIENT_SECRET"),
            "loginaddr", Environment.GetEnvironmentVariable("AZURE_LOGIN_ADDR"),
            "imdsaddr", Environment.GetEnvironmentVariable("AZURE_IMDS_ADDR"));

        var onepasswordspec = Spec(
            "kind", "onepassword",
            "addr", Environment.GetEnvironmentVariable("OP_CONNECT_HOST"),
            "token", Environment.GetEnvironmentVariable("OP_CONNECT_TOKEN"),
            "vault", Environment.GetEnvironmentVariable("OP_VAULT"));

        var dopplerspec = Spec(
            "kind", "doppler",
            "token", Environment.GetEnvironmentVariable("DOPPLER_TOKEN"),
            "project", Environment.GetEnvironmentVariable("DOPPLER_PROJECT"),
            "config", Environment.GetEnvironmentVariable("DOPPLER_CONFIG"),
            "addr", Environment.GetEnvironmentVariable("DOPPLER_ADDR"));

        var infisicalspec = Spec(
            "kind", "infisical",
            "addr", Environment.GetEnvironmentVariable("INFISICAL_ADDR"),
            "token", Environment.GetEnvironmentVariable("INFISICAL_TOKEN"),
            "clientid", Environment.GetEnvironmentVariable("INFISICAL_CLIENT_ID"),
            "clientsecret", Environment.GetEnvironmentVariable("INFISICAL_CLIENT_SECRET"),
            "project", Environment.GetEnvironmentVariable("INFISICAL_PROJECT"),
            "environment", Environment.GetEnvironmentVariable("INFISICAL_ENV"),
            "path", Environment.GetEnvironmentVariable("INFISICAL_PATH"));

        var chain = new List<object>();

        switch (source)
        {
            case "env": chain.Add(envspec); break;
            case "dotenv": chain.Add(dotenvspec); break;
            case "file": chain.Add(filespec); break;
            case "hashicorp": chain.Add(hashicorpspec); break;
            case "boru": chain.Add(boruspec); break;
            case "boruwire": chain.Add(boruwirespec); break;
            case "awssecrets": chain.Add(awssecretsspec); break;
            case "awsparams": chain.Add(awsparamsspec); break;
            case "gcpsecrets": chain.Add(gcpspec); break;
            case "azuresecrets": chain.Add(azurespec); break;
            case "onepassword": chain.Add(onepasswordspec); break;
            case "doppler": chain.Add(dopplerspec); break;
            case "infisical": chain.Add(infisicalspec); break;
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
