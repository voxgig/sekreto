# A tiny app that needs a secret.
#
# It asks sekreto for `api.token` and calls the token-protected API with
# it. Every port ships this same CLI, and test/integration.sh runs all of
# them against the same server from every secret source - which is what
# proves the library, rather than the spec alone.
#
# Usage: build/sekreto-cli <api-url> [--source <source>] [--store <name>]
#
# Sources: env dotenv file hashicorp boru boruwire awssecrets awsparams
#          gcpsecrets azuresecrets onepassword doppler infisical
#          secretspec chain
#
# Each source's configuration arrives in the environment variables its own
# ecosystem already uses (VAULT_*, AWS_*, OP_CONNECT_*, ...), listed in
# chainfor below.

defmodule Sekreto.Cli do
  @moduledoc "The integration CLI: the app that needs a secret."

  alias Sekreto.AuthSpec
  alias Sekreto.Http
  alias Sekreto.Json
  alias Sekreto.ProviderSpec

  @lang "elixir"

  defp env(name), do: System.get_env(name) || ""

  defp envor(name, fallback) do
    case env(name) do
      "" -> fallback
      value -> value
    end
  end

  defp chainfor(source) do
    envspec = %ProviderSpec{kind: "env", prefix: env("SEKRETO_PREFIX")}
    dotenvspec = %ProviderSpec{kind: "dotenv", file: envor("SEKRETO_DOTENV", ".env")}
    filespec = %ProviderSpec{kind: "file", dir: envor("SEKRETO_FILEDIR", "/run/secrets")}

    hashicorpspec = %ProviderSpec{
      kind: "hashicorp",
      addr: env("VAULT_ADDR"),
      token: env("VAULT_TOKEN"),
      mount: env("VAULT_MOUNT"),
      kv:
        case Integer.parse(env("VAULT_KV")) do
          {value, ""} -> value
          _other -> nil
        end,
      vaultnamespace: env("VAULT_NAMESPACE"),
      auth:
        case env("VAULT_AUTH") do
          "" ->
            nil

          method ->
            %AuthSpec{
              method: method,
              role: env("VAULT_ROLE"),
              jwtfile: env("VAULT_JWT_FILE"),
              roleid: env("VAULT_ROLE_ID"),
              secretid: env("VAULT_SECRET_ID")
            }
        end
    }

    boruspec = %ProviderSpec{
      kind: "boru",
      command: envor("BORU_COMMAND", "boru"),
      namespace: env("BORU_NAMESPACE"),
      home: env("BORU_HOME")
    }

    # The same vault over its wire protocol (`boru vault serve`) instead of
    # the CLI: an address plus a capability token from `vault grant`.
    boruwirespec = %ProviderSpec{
      kind: "boru",
      addr: env("BORU_ADDR"),
      token: env("BORU_TOKEN"),
      namespace: env("BORU_NAMESPACE")
    }

    awssecretsspec = %ProviderSpec{
      kind: "awssecrets",
      region: env("AWS_REGION"),
      addr: env("AWS_ENDPOINT")
    }

    awsparamsspec = %ProviderSpec{
      kind: "awsparams",
      region: env("AWS_REGION"),
      addr: env("AWS_ENDPOINT"),
      prefix: env("AWS_PARAM_PREFIX")
    }

    gcpspec = %ProviderSpec{
      kind: "gcpsecrets",
      project: env("GCP_PROJECT"),
      addr: env("GCP_ADDR"),
      metadataaddr: env("GCP_METADATA_ADDR")
    }

    azurespec = %ProviderSpec{
      kind: "azuresecrets",
      vault: env("AZURE_VAULT"),
      token: env("AZURE_TOKEN"),
      tenant: env("AZURE_TENANT"),
      clientid: env("AZURE_CLIENT_ID"),
      clientsecret: env("AZURE_CLIENT_SECRET"),
      loginaddr: env("AZURE_LOGIN_ADDR"),
      imdsaddr: env("AZURE_IMDS_ADDR")
    }

    onepasswordspec = %ProviderSpec{
      kind: "onepassword",
      addr: env("OP_CONNECT_HOST"),
      token: env("OP_CONNECT_TOKEN"),
      vault: env("OP_VAULT")
    }

    dopplerspec = %ProviderSpec{
      kind: "doppler",
      token: env("DOPPLER_TOKEN"),
      project: env("DOPPLER_PROJECT"),
      config: env("DOPPLER_CONFIG"),
      addr: env("DOPPLER_ADDR")
    }

    # SecretSpec's own environment variables where it has them
    # (SECRETSPEC_FILE, _PROFILE, _PROVIDER, _REASON are read by the
    # secretspec CLI itself), so a shell already set up for secretspec needs
    # nothing further.
    secretspecspec = %ProviderSpec{
      kind: "secretspec",
      command: envor("SECRETSPEC_COMMAND", "secretspec"),
      file: env("SECRETSPEC_FILE"),
      profile: env("SECRETSPEC_PROFILE"),
      backend: env("SECRETSPEC_PROVIDER"),
      reason: env("SECRETSPEC_REASON")
    }

    infisicalspec = %ProviderSpec{
      kind: "infisical",
      addr: env("INFISICAL_ADDR"),
      token: env("INFISICAL_TOKEN"),
      clientid: env("INFISICAL_CLIENT_ID"),
      clientsecret: env("INFISICAL_CLIENT_SECRET"),
      project: env("INFISICAL_PROJECT"),
      environment: env("INFISICAL_ENV"),
      path: env("INFISICAL_PATH")
    }

    case source do
      "env" -> [envspec]
      "dotenv" -> [dotenvspec]
      "file" -> [filespec]
      "hashicorp" -> [hashicorpspec]
      "boru" -> [boruspec]
      "boruwire" -> [boruwirespec]
      "awssecrets" -> [awssecretsspec]
      "awsparams" -> [awsparamsspec]
      "gcpsecrets" -> [gcpspec]
      "azuresecrets" -> [azurespec]
      "onepassword" -> [onepasswordspec]
      "doppler" -> [dopplerspec]
      "infisical" -> [infisicalspec]
      "secretspec" -> [secretspecspec]
      # The default: the chain an app would actually ship with - local
      # overrides first, shared vaults last.
      _other -> [envspec, dotenvspec, hashicorpspec, boruspec]
    end
  end

  # The value of a `--flag value` pair, or "" when the flag is absent.
  # Positional, by index-of: no argument-parsing library.
  defp flag(args, name) do
    case Enum.find_index(args, fn arg -> name == arg end) do
      nil -> ""
      at -> Enum.at(args, at + 1, "")
    end
  end

  defp fail(message, code) do
    IO.puts(:stderr, "sekreto-cli: " <> message)
    code
  end

  defp run(args) do
    url = List.first(args) || "http://127.0.0.1:8099/whoami"

    source =
      case flag(args, "--source") do
        "" -> "chain"
        value -> value
      end

    # --store names a store outright: the secret must come from that one,
    # not from whichever provider happens to answer first. An unknown store
    # is an error, not a miss.
    store = flag(args, "--store")

    secrets =
      try do
        Sekreto.new(chainfor(source))
      rescue
        err -> throw({:fail, fail(Exception.message(err), 2)})
      end

    token =
      try do
        if "" == store do
          Sekreto.get(secrets, "api.token")
        else
          Sekreto.getfrom(secrets, store, "api.token")
        end
      rescue
        err -> throw({:fail, fail(Sekreto.redactall(secrets, Exception.message(err)), 2)})
      end

    answer =
      try do
        Http.fetch("GET", url, [
          {"Authorization", "Bearer " <> token},
          {"X-Sekreto-Lang", @lang}
        ])
      rescue
        err -> throw({:fail, fail(Sekreto.redactall(secrets, Exception.message(err)), 1)})
      end

    if 200 != answer.status do
      # Never print the token itself, even when the call fails.
      throw({:fail, fail(Sekreto.redactall(secrets, answer.body), 1)})
    end

    caller =
      case Json.parse(answer.body) do
        {:ok, body} -> Json.dig(body, ["caller"])
        :error -> :none
      end

    # Assembled field by field, in the spec's order. Printing a map here is
    # what has bitten port after port: the language's own key order is not
    # the one every other port prints.
    IO.puts(
      "{\"ok\":true" <>
        ",\"lang\":" <>
        Json.quotestr(@lang) <>
        ",\"source\":" <>
        Json.quotestr(source) <>
        ",\"store\":" <>
        Json.quotestr(store) <>
        ",\"caller\":" <> Json.stringify(caller) <> "}"
    )

    0
  end

  @doc "The escript entry point. Arguments arrive as charlists."
  def main(args) do
    code =
      try do
        run(Enum.map(args, &to_string/1))
      catch
        {:fail, code} -> code
      end

    System.halt(code)
  end
end
