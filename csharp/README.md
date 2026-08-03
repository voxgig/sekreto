# sekreto — C#

The C# port of [sekreto](../README.md): one interface for secrets,
wherever they live.

```sh
make test                     # the conformance suite
```

`System.Text.Json` and `HttpClient` are both base class library, not
packages, so this port takes no NuGet dependency. `Json.cs` is a thin
adapter turning `System.Text.Json` into the plain
`Dictionary`/`List`/`string`/`double` model the rest of the code uses.

The optional lookup is `TryGet`. The cache is an insertion-ordered list so
that `Redact` does not vary between runs.

`make test` passes the voxgig/omni path as `-p:OmniPath=`, so the test
project file names no machine-specific location.

## Layout

| | |
|---|---|
| `src/Sekreto.cs` | the facade, `Names`, `Dotenv`, `Redact` |
| `src/Providers.cs` | the five providers |
| `src/Json.cs` | the JSON adapter |
| `test/Program.cs` | the conformance suite |
| `cli/Program.cs` | the app that needs a secret |

## Testing

The conformance suite runs [`spec/sekreto.json`](../spec/sekreto.json) —
the same file every port runs — through the C#
[voxgig/omni](https://github.com/voxgig/omni) runner. Set `OMNI_HOME` if
your omni checkout is not a sibling of this repository.

That suite proves this port computes the same answers as the others. What
proves it can actually *fetch* a secret is the integration run, from the
repository root:

```sh
make integration              # every port
./test/integration.sh csharp  # just this one
```

It starts a token-protected API and stand-in HashiCorp and boru vaults,
then runs this port's CLI against them from each secret source in turn:

```sh
make build
dotnet cli/bin/Release/net8.0/SekretoCli.dll http://127.0.0.1:8099/whoami --source vault
```

## API

See [DOCS.md](../DOCS.md) for the full API. Anything named differently in
C# is listed there.
