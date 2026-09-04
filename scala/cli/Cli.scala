// A tiny app that needs a secret.
//
// It asks sekreto for `api.token` and calls the token-protected API with
// it. Every port ships this same CLI, and test/integration.sh runs all of
// them against the same server from every secret source - which is what
// proves the library, rather than the spec alone.
//
// Usage: java -cp build/sekreto-cli.jar sekreto.Cli <api-url>
//            [--source <source>] [--store <name>]
//
// Sources: env dotenv file hashicorp boru boruwire awssecrets awsparams
//          gcpsecrets azuresecrets onepassword doppler infisical
//          secretspec chain
//
// Each source's configuration arrives in the environment variables its own
// ecosystem already uses (VAULT_*, AWS_*, OP_CONNECT_*, ...), listed in
// chainfor below.

package sekreto

import java.net.URI
import java.net.http.HttpClient
import java.net.http.HttpRequest
import java.net.http.HttpResponse
import scala.util.control.NonFatal

// Renamed on import: this file's own package is called `sekreto` too, and
// the builder function would otherwise be read as the package.
import com.voxgig.sekreto.{AuthSpec, Json, ProviderSpec, dig, sekreto as makesekreto}

object Cli:

  private val LANG = "scala"

  private def env(name: String): Option[String] = Option(System.getenv(name))

  private def envor(name: String, fallback: String): String =
    env(name).filter(_.nonEmpty).getOrElse(fallback)

  private def chainfor(source: String): List[ProviderSpec] =
    val envspec = ProviderSpec(kind = "env", prefix = env("SEKRETO_PREFIX"))
    val dotenvspec =
      ProviderSpec(kind = "dotenv", file = Some(envor("SEKRETO_DOTENV", ".env")))
    val filespec =
      ProviderSpec(kind = "file", dir = Some(envor("SEKRETO_FILEDIR", "/run/secrets")))

    val hashicorpspec = ProviderSpec(
      kind = "hashicorp",
      addr = Some(envor("VAULT_ADDR", "")),
      token = Some(envor("VAULT_TOKEN", "")),
      mount = env("VAULT_MOUNT"),
      kv = env("VAULT_KV").flatMap(_.toIntOption),
      vaultnamespace = env("VAULT_NAMESPACE"),
      auth = env("VAULT_AUTH")
        .filter(_.nonEmpty)
        .map: method =>
          AuthSpec(
            method = method,
            role = env("VAULT_ROLE"),
            jwtfile = env("VAULT_JWT_FILE"),
            roleid = env("VAULT_ROLE_ID"),
            secretid = env("VAULT_SECRET_ID"),
          ),
    )

    val boruspec = ProviderSpec(
      kind = "boru",
      command = Some(envor("BORU_COMMAND", "boru")),
      namespace = env("BORU_NAMESPACE"),
      home = env("BORU_HOME"),
    )

    // The same vault over its wire protocol (`boru vault serve`) instead of
    // the CLI: an address plus a capability token from `vault grant`.
    val boruwirespec = ProviderSpec(
      kind = "boru",
      addr = Some(envor("BORU_ADDR", "")),
      token = Some(envor("BORU_TOKEN", "")),
      namespace = env("BORU_NAMESPACE"),
    )

    val awssecretsspec = ProviderSpec(
      kind = "awssecrets",
      region = env("AWS_REGION"),
      addr = env("AWS_ENDPOINT"),
    )

    val awsparamsspec = ProviderSpec(
      kind = "awsparams",
      region = env("AWS_REGION"),
      addr = env("AWS_ENDPOINT"),
      prefix = env("AWS_PARAM_PREFIX"),
    )

    val gcpspec = ProviderSpec(
      kind = "gcpsecrets",
      project = env("GCP_PROJECT"),
      addr = env("GCP_ADDR"),
      metadataaddr = env("GCP_METADATA_ADDR"),
    )

    val azurespec = ProviderSpec(
      kind = "azuresecrets",
      vault = env("AZURE_VAULT"),
      token = env("AZURE_TOKEN"),
      tenant = env("AZURE_TENANT"),
      clientid = env("AZURE_CLIENT_ID"),
      clientsecret = env("AZURE_CLIENT_SECRET"),
      loginaddr = env("AZURE_LOGIN_ADDR"),
      imdsaddr = env("AZURE_IMDS_ADDR"),
    )

    val onepasswordspec = ProviderSpec(
      kind = "onepassword",
      addr = env("OP_CONNECT_HOST"),
      token = env("OP_CONNECT_TOKEN"),
      vault = env("OP_VAULT"),
    )

    val dopplerspec = ProviderSpec(
      kind = "doppler",
      token = env("DOPPLER_TOKEN"),
      project = env("DOPPLER_PROJECT"),
      config = env("DOPPLER_CONFIG"),
      addr = env("DOPPLER_ADDR"),
    )

    // SecretSpec's own environment variables where it has them
    // (SECRETSPEC_FILE, _PROFILE, _PROVIDER, _REASON are read by the
    // secretspec CLI itself), so a shell already set up for secretspec needs
    // nothing further.
    val secretspecspec = ProviderSpec(
      kind = "secretspec",
      command = Some(envor("SECRETSPEC_COMMAND", "secretspec")),
      file = env("SECRETSPEC_FILE"),
      profile = env("SECRETSPEC_PROFILE"),
      backend = env("SECRETSPEC_PROVIDER"),
      reason = env("SECRETSPEC_REASON"),
    )

    val infisicalspec = ProviderSpec(
      kind = "infisical",
      addr = env("INFISICAL_ADDR"),
      token = env("INFISICAL_TOKEN"),
      clientid = env("INFISICAL_CLIENT_ID"),
      clientsecret = env("INFISICAL_CLIENT_SECRET"),
      project = env("INFISICAL_PROJECT"),
      environment = env("INFISICAL_ENV"),
      path = env("INFISICAL_PATH"),
    )

    source match
      case "env"          => List(envspec)
      case "dotenv"       => List(dotenvspec)
      case "file"         => List(filespec)
      case "hashicorp"    => List(hashicorpspec)
      case "boru"         => List(boruspec)
      case "boruwire"     => List(boruwirespec)
      case "awssecrets"   => List(awssecretsspec)
      case "awsparams"    => List(awsparamsspec)
      case "gcpsecrets"   => List(gcpspec)
      case "azuresecrets" => List(azurespec)
      case "onepassword"  => List(onepasswordspec)
      case "doppler"      => List(dopplerspec)
      case "infisical"    => List(infisicalspec)
      case "secretspec"   => List(secretspecspec)
      // The default: the chain an app would actually ship with - local
      // overrides first, shared vaults last.
      case _ => List(envspec, dotenvspec, hashicorpspec, boruspec)

  /** The value of a `--flag value` pair, or "" when the flag is absent. */
  private def flag(args: Array[String], name: String): String =
    val at = args.indexOf(name)
    if -1 == at || at + 1 >= args.length then "" else args(at + 1)

  private def run(args: Array[String]): Int =
    val url = if args.nonEmpty then args(0) else "http://127.0.0.1:8099/whoami"

    val source = Some(flag(args, "--source")).filter(_.nonEmpty).getOrElse("chain")

    // --store names a store outright: the secret must come from that one,
    // not from whichever provider happens to answer first.
    val store = flag(args, "--store")

    val secrets = makesekreto(chainfor(source))

    val token =
      try
        if store.isEmpty then secrets.get("api.token")
        else secrets.getfrom(store, "api.token")
      catch
        case NonFatal(err) =>
          System.err.println(s"sekreto-cli: ${err.getMessage}")
          return 2

    val request = HttpRequest
      .newBuilder()
      .uri(URI.create(url))
      .header("Authorization", s"Bearer $token")
      .header("X-Sekreto-Lang", LANG)
      .GET()
      .build()

    val response: HttpResponse[String] =
      try
        HttpClient
          .newBuilder()
          .version(HttpClient.Version.HTTP_1_1)
          .build()
          .send(request, HttpResponse.BodyHandlers.ofString())
      catch
        case NonFatal(err) =>
          System.err.println(
            "sekreto-cli: " + secrets.redact(Option(err.getMessage).getOrElse(err.toString)),
          )
          return 1

    if 200 != response.statusCode() then
      // Never print the token itself, even when the call fails.
      System.err.println("sekreto-cli: " + secrets.redact(response.body()))
      return 1

    val caller = Json.parse(response.body()).dig("caller")

    // Assembled field by field, in the spec's order. Printing a map here is
    // what has bitten port after port: the language's own key order is not
    // the one every other port prints.
    val line = StringBuilder("{\"ok\":true")
    line.append(",\"lang\":").append(Json.quote(LANG))
    line.append(",\"source\":").append(Json.quote(source))
    line.append(",\"store\":").append(Json.quote(store))
    line.append(",\"caller\":").append(caller.map(Json.stringify).getOrElse("null"))
    line.append("}")

    println(line.toString)

    0

  def main(args: Array[String]): Unit = System.exit(run(args))
