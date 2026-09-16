# sekreto — C#

The C# port of [sekreto](../README.md): one interface for secrets,
wherever they live.

```sh
make test                     # the conformance suite, then the plugin seam
make test-plugins             # the plugin seam alone
make check-core               # the core, built alone, reaches no plugin
```

`System.Text.Json` and `HttpClient` are both base class library, not
packages, so this port takes no NuGet dependency. `Json.cs` is a thin
adapter turning `System.Text.Json` into the plain
`Dictionary`/`List`/`string`/`double` model the rest of the code uses.

The one dependency is [voxgig/plugin](https://github.com/voxgig/plugin),
which has no NuGet package either, so it comes from a checkout: `make`
finds it the way it finds voxgig/omni — `PLUGIN_HOME`, then the usual
places — and passes the path as `-p:PluginPath=`, so no project file
names a machine-specific location. `make deps` fetches a shallow clone
when there is none.

The optional lookup is `TryGet`. The cache is an insertion-ordered list so
that `Redact` does not vary between runs.

## Two assemblies, and why

Four provider kinds are built in — `env`, `memory`, `dotenv`, `file` —
and the line is *reads at most a local file*. Every kind that opens a
socket, signs a request or spawns a process is a voxgig/plugin
definition in a **separate assembly**, and the calling project passes
the ones it wants:

```csharp
var secrets = new Sekreto(new SekretoOptions
{
    Plugins = new List<Definition> { Hashicorp.Plugin },
    Providers = chain,
});
```

`SekretoPlugins.All()` is the whole set, for a caller whose chain is
decided at run time — the CLI and the conformance suite both take it.

The boundary is the assembly reference graph, not a convention:
`plugins/SekretoPlugins.csproj` references `src/Sekreto.csproj`, and
the core references nothing back — a reference the other way is a cycle
`msbuild` refuses to build. So `VoxgigSekreto.dll` cannot name a type in
`VoxgigSekretoPlugins.dll`, and it names none of the three platform
assemblies a plugin needs either. `make check-core` reads that out of
the compiled artifact.

## The mini vault

`plugins/MiniVault.cs` is a store this port owns outright rather than a
client for a server somebody else runs: every secret, encrypted, in one
binary file. It has a master key and restricted keys, and it is the port's
worked example of a definition publishing an API beside its provider.

```csharp
var vault = MiniVault.CreateVault(new MiniVault.Options {
    File = "app.skmv", Passphrase = master });
vault.Set("api.token", "tok01");
vault.Grant(new MiniVault.Grant {
    Key = "ci", Passphrase = ci, Names = new List<string> { "api.token" } });

var secrets = new Sekreto(new SekretoOptions {
    Plugins = new List<Definition> { MiniVault.Plugin },
    Providers = new List<object> { new Dictionary<string, object> {
        { "kind", "minivault" }, { "file", "app.skmv" },
        { "vaultkey", "ci" }, { "passphrase", ci } } } });

secrets.Get("api.token");            // the chain reads
MiniVault.VaultOf(secrets).List();   // ['api.token'] — as the `ci` key sees it
```

A chain reads; writing is a deliberate act with an API of its own, so the
definition exports `vault` beside `provider` and `VaultOf` reads it back
off `secrets.Host`. `System.Security.Cryptography` carries all four
primitives — `AesGcm`, `Rfc2898DeriveBytes.Pbkdf2`, `HMACSHA256` and
`RandomNumberGenerator` — so nothing here is hand-rolled. What each key
may do, what the file holds, and what the whole thing does and does not
protect are in
[DOCS.md](../DOCS.md#minivault--a-local-mini-vault--plugin-minivault).

`KeyInfo` has get-only properties and a read-only `Grants`, which is how
this port answers the defect the review round found in the canonical: a
caller handed the live permission record could flip its own `Write` bit.
Here that does not compile.

Ports carrying this kind read each other's files, which
`test/MiniVault.cs` checks against every committed vault in
`test/fixture/`, including the one this port wrote.

## Layout

| | |
|---|---|
| `src/Sekreto.cs` | the facade, `Names`, `Dotenv`, `Redact`, `SekretoOptions` |
| `src/Providers.cs` | `IProvider`, the four built-in kinds, `Addr`, `ProviderPlugin` |
| `src/Json.cs` | the JSON adapter |
| `plugins/*.cs` | the eleven plugin kinds, one file each, and `Sigv4.cs` with the AWS pair |
| `plugins/HttpJson.cs` | the shared HTTP-JSON client, `plugins/Child.cs` the child process |
| `plugins/MiniVault.cs` | the mini vault: the format, the keys, the API, the definition |
| `plugins/SekretoPlugins.cs` | the full set |
| `test/Program.cs` | the conformance suite |
| `test/Plugins.cs` | the plugin seam — what the conformance suite cannot see |
| `test/MiniVault.cs` | the mini vault, and the committed files every port reads |
| `cli/Program.cs` | the app that needs a secret |

## Testing

The conformance suite runs [`spec/sekreto.json`](../spec/sekreto.json) —
the same file every port runs — through the C#
[voxgig/omni](https://github.com/voxgig/omni) runner. Set `OMNI_HOME` if
your omni checkout is not a sibling of this repository.

That suite hands every plugin to every chain it builds, so it can never
see a missing one. `test/Plugins.cs` pins that half: the full set holds
every kind, every kind builds, the CLI passes the full set, a kind that
was not passed in is refused with a message naming the fix, a
`SekretoError` raised inside a definition comes back out as itself, and
the core assembly references no plugin.

Together they prove this port computes the same answers as the others.
What proves it can actually *fetch* a secret is the integration run, from the
repository root:

```sh
make integration              # every port
./test/integration.sh csharp  # just this one
```

It starts a token-protected API, mock HashiCorp/AWS/GCP/Azure/1Password/
Doppler/Infisical servers and a real boru vault, then runs this port's
CLI against them from each secret source in turn:

```sh
make build
dotnet cli/bin/Release/net8.0/SekretoCli.dll http://127.0.0.1:8099/whoami --source hashicorp
```

## API

See [DOCS.md](../DOCS.md) for the full API. Anything named differently in
C# is listed there.
