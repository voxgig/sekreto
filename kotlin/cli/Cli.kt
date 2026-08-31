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

@file:JvmName("Cli")

package sekreto

import com.voxgig.sekreto.Json
import com.voxgig.sekreto.ProviderSpec
import com.voxgig.sekreto.AuthSpec
import com.voxgig.sekreto.sekreto
import java.net.URI
import java.net.http.HttpClient
import java.net.http.HttpRequest
import java.net.http.HttpResponse
import kotlin.system.exitProcess

private const val LANG = "kotlin"

private fun envor(name: String, fallback: String): String {
    val value = System.getenv(name)
    return if (value.isNullOrEmpty()) fallback else value
}

private fun chainfor(source: String): List<ProviderSpec> {
    val envspec = ProviderSpec(kind = "env", prefix = System.getenv("SEKRETO_PREFIX"))
    val dotenvspec = ProviderSpec(kind = "dotenv", file = envor("SEKRETO_DOTENV", ".env"))
    val filespec = ProviderSpec(kind = "file", dir = envor("SEKRETO_FILEDIR", "/run/secrets"))

    val vaultauth = System.getenv("VAULT_AUTH")
    val hashicorpspec = ProviderSpec(
        kind = "hashicorp",
        addr = envor("VAULT_ADDR", ""),
        token = envor("VAULT_TOKEN", ""),
        mount = System.getenv("VAULT_MOUNT"),
        kv = System.getenv("VAULT_KV")?.toIntOrNull(),
        vaultnamespace = System.getenv("VAULT_NAMESPACE"),
        auth = if (vaultauth.isNullOrEmpty()) {
            null
        } else {
            AuthSpec(
                method = vaultauth,
                role = System.getenv("VAULT_ROLE"),
                jwtfile = System.getenv("VAULT_JWT_FILE"),
                roleid = System.getenv("VAULT_ROLE_ID"),
                secretid = System.getenv("VAULT_SECRET_ID"),
            )
        },
    )

    val boruspec = ProviderSpec(
        kind = "boru",
        command = envor("BORU_COMMAND", "boru"),
        namespace = System.getenv("BORU_NAMESPACE"),
        home = System.getenv("BORU_HOME"),
    )

    // The same vault over its wire protocol (`boru vault serve`) instead of
    // the CLI: an address plus a capability token from `vault grant`.
    val boruwirespec = ProviderSpec(
        kind = "boru",
        addr = envor("BORU_ADDR", ""),
        token = envor("BORU_TOKEN", ""),
        namespace = System.getenv("BORU_NAMESPACE"),
    )

    val awssecretsspec = ProviderSpec(
        kind = "awssecrets",
        region = System.getenv("AWS_REGION"),
        addr = System.getenv("AWS_ENDPOINT"),
    )

    val awsparamsspec = ProviderSpec(
        kind = "awsparams",
        region = System.getenv("AWS_REGION"),
        addr = System.getenv("AWS_ENDPOINT"),
        prefix = System.getenv("AWS_PARAM_PREFIX"),
    )

    val gcpspec = ProviderSpec(
        kind = "gcpsecrets",
        project = System.getenv("GCP_PROJECT"),
        addr = System.getenv("GCP_ADDR"),
        metadataaddr = System.getenv("GCP_METADATA_ADDR"),
    )

    val azurespec = ProviderSpec(
        kind = "azuresecrets",
        vault = System.getenv("AZURE_VAULT"),
        token = System.getenv("AZURE_TOKEN"),
        tenant = System.getenv("AZURE_TENANT"),
        clientid = System.getenv("AZURE_CLIENT_ID"),
        clientsecret = System.getenv("AZURE_CLIENT_SECRET"),
        loginaddr = System.getenv("AZURE_LOGIN_ADDR"),
        imdsaddr = System.getenv("AZURE_IMDS_ADDR"),
    )

    val onepasswordspec = ProviderSpec(
        kind = "onepassword",
        addr = System.getenv("OP_CONNECT_HOST"),
        token = System.getenv("OP_CONNECT_TOKEN"),
        vault = System.getenv("OP_VAULT"),
    )

    val dopplerspec = ProviderSpec(
        kind = "doppler",
        token = System.getenv("DOPPLER_TOKEN"),
        project = System.getenv("DOPPLER_PROJECT"),
        config = System.getenv("DOPPLER_CONFIG"),
        addr = System.getenv("DOPPLER_ADDR"),
    )

    // SecretSpec's own environment variables where it has them
    // (SECRETSPEC_FILE, _PROFILE, _PROVIDER, _REASON are read by the
    // secretspec CLI itself), so a shell already set up for secretspec needs
    // nothing further.
    val secretspecspec = ProviderSpec(
        kind = "secretspec",
        command = envor("SECRETSPEC_COMMAND", "secretspec"),
        file = System.getenv("SECRETSPEC_FILE"),
        profile = System.getenv("SECRETSPEC_PROFILE"),
        backend = System.getenv("SECRETSPEC_PROVIDER"),
        reason = System.getenv("SECRETSPEC_REASON"),
    )

    val infisicalspec = ProviderSpec(
        kind = "infisical",
        addr = System.getenv("INFISICAL_ADDR"),
        token = System.getenv("INFISICAL_TOKEN"),
        clientid = System.getenv("INFISICAL_CLIENT_ID"),
        clientsecret = System.getenv("INFISICAL_CLIENT_SECRET"),
        project = System.getenv("INFISICAL_PROJECT"),
        environment = System.getenv("INFISICAL_ENV"),
        path = System.getenv("INFISICAL_PATH"),
    )

    return when (source) {
        "env" -> listOf(envspec)
        "dotenv" -> listOf(dotenvspec)
        "file" -> listOf(filespec)
        "hashicorp" -> listOf(hashicorpspec)
        "boru" -> listOf(boruspec)
        "boruwire" -> listOf(boruwirespec)
        "awssecrets" -> listOf(awssecretsspec)
        "awsparams" -> listOf(awsparamsspec)
        "gcpsecrets" -> listOf(gcpspec)
        "azuresecrets" -> listOf(azurespec)
        "onepassword" -> listOf(onepasswordspec)
        "doppler" -> listOf(dopplerspec)
        "infisical" -> listOf(infisicalspec)
        "secretspec" -> listOf(secretspecspec)
        // The default: the chain an app would actually ship with - local
        // overrides first, shared vaults last.
        else -> listOf(envspec, dotenvspec, hashicorpspec, boruspec)
    }
}

/** The value of a `--flag value` pair, or "" when the flag is absent. */
private fun flag(args: Array<String>, name: String): String {
    val at = args.indexOf(name)
    return if (-1 == at || at + 1 >= args.size) "" else args[at + 1]
}

private fun run(args: Array<String>): Int {
    val url = if (args.isNotEmpty()) args[0] else "http://127.0.0.1:8099/whoami"

    val source = flag(args, "--source").ifEmpty { "chain" }

    // --store names a store outright: the secret must come from that one, not
    // from whichever provider happens to answer first.
    val store = flag(args, "--store")

    val secrets = sekreto(chainfor(source))

    val token = try {
        if (store.isEmpty()) secrets.get("api.token") else secrets.getfrom(store, "api.token")
    } catch (err: RuntimeException) {
        System.err.println("sekreto-cli: ${err.message}")
        return 2
    }

    val request = HttpRequest.newBuilder()
        .uri(URI.create(url))
        .header("Authorization", "Bearer $token")
        .header("X-Sekreto-Lang", LANG)
        .GET()
        .build()

    val response: HttpResponse<String> = try {
        HttpClient.newBuilder()
            .version(HttpClient.Version.HTTP_1_1)
            .build()
            .send(request, HttpResponse.BodyHandlers.ofString())
    } catch (err: Exception) {
        System.err.println("sekreto-cli: " + secrets.redact(err.message ?: err.toString()))
        return 1
    }

    if (200 != response.statusCode()) {
        // Never print the token itself, even when the call fails.
        System.err.println("sekreto-cli: " + secrets.redact(response.body()))
        return 1
    }

    val caller = Json.parse(response.body())?.dig("caller")

    // Assembled field by field, in the spec's order. Printing a map here is
    // what has bitten port after port: the language's own key order is not
    // the one every other port prints.
    val line = StringBuilder("{\"ok\":true")
    line.append(",\"lang\":").append(Json.quote(LANG))
    line.append(",\"source\":").append(Json.quote(source))
    line.append(",\"store\":").append(Json.quote(store))
    line.append(",\"caller\":").append(if (null == caller) "null" else Json.stringify(caller))
    line.append("}")

    println(line)

    return 0
}

fun main(args: Array<String>) {
    exitProcess(run(args))
}
