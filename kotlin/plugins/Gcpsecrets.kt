// GCP Secret Manager, as a voxgig/plugin definition.

package com.voxgig.sekreto.plugins

import com.voxgig.sekreto.Definition
import com.voxgig.sekreto.Provider
import com.voxgig.sekreto.Providers.checkaddr
import com.voxgig.sekreto.SekretoError
import com.voxgig.sekreto.flatname
import com.voxgig.sekreto.providerplugin

import java.nio.charset.StandardCharsets
import java.util.Base64

/**
 * GCP Secret Manager.
 *
 * `api.token` reads secret `api_token` (dots flattened to `_`; Secret
 * Manager ids have no hierarchy and reject dots), latest version. The
 * token comes from config, then `GOOGLE_OAUTH_ACCESS_TOKEN`, then the
 * GCE/GKE metadata server - so on Google's own platform no credential
 * configuration is needed at all.
 *
 * The metadata call itself is plain http to a link-local host by platform
 * design; no credential rides on it, so `checkaddr` guards the Secret
 * Manager address instead.
 */
class Gcpsecrets(
    private val project: String? = null,
    private val token: String? = null,
    private val addr: String? = null,
    private val metadataaddr: String? = null,
) : Provider {

    // A configured token is kept forever; a metadata-server token carries
    // expires_in and is renewed shortly before it runs out.
    private var livetoken: String? = null
    private var renewat: Long = Long.MAX_VALUE

    private fun usemetadataaddr(): String {
        if (!metadataaddr.isNullOrEmpty()) {
            return metadataaddr
        }

        val host = System.getenv("GCE_METADATA_HOST")
        return if (host.isNullOrEmpty()) "http://metadata.google.internal" else "http://$host"
    }

    private fun login(): String {
        val configured = first(token, System.getenv("GOOGLE_OAUTH_ACCESS_TOKEN"))
        if (configured.isNotEmpty()) {
            return configured
        }

        val url = trimslash(usemetadataaddr()) +
            "/computeMetadata/v1/instance/service-accounts/default/token"

        val res = fetchjson("GET", url, mapOf("Metadata-Flavor" to "Google"))

        val got = res.body?.dig("access_token")?.text
        if (200 != res.status || got.isNullOrEmpty()) {
            throw SekretoError("sekreto: gcp: no token and metadata server did not answer")
        }

        renewat = renewtime(res.body?.dig("expires_in"))

        return got
    }

    override fun lookup(name: String): String? {
        val useproject = project ?: ""
        if (useproject.isEmpty()) {
            throw SekretoError("sekreto: gcp: no project")
        }

        val useaddr = first(addr, "https://secretmanager.googleapis.com")
        checkaddr(useaddr)

        if (null == livetoken || System.currentTimeMillis() >= renewat) {
            livetoken = login()
        }

        val url = trimslash(useaddr) + "/v1/projects/" + useproject + "/secrets/" +
            flatname(name, "_") + "/versions/latest:access"

        val res = fetchjson("GET", url, mapOf("authorization" to "Bearer $livetoken"))

        if (404 == res.status) {
            return null
        }

        if (200 != res.status) {
            throw SekretoError("sekreto: gcp error: ${res.status}: $url")
        }

        val data = res.body?.dig("payload", "data")?.asstr ?: return null

        // See the aws provider: an undecodable payload is a SekretoError.
        return try {
            String(Base64.getDecoder().decode(data), StandardCharsets.UTF_8)
        } catch (err: IllegalArgumentException) {
            throw SekretoError("sekreto: gcp: undecodable secret")
        }
    }

    override fun describe(): String = "gcpsecrets:${project ?: ""}"
}

/** The `gcpsecrets` provider kind, as a voxgig/plugin definition. A
 * consumer imports this and hands it to `Sekreto`; a consumer that does
 * not is a `Sekreto` that cannot build a `gcpsecrets` chain entry. */
val gcpsecrets: Definition = providerplugin("gcpsecrets") { spec ->
    Gcpsecrets(
        spec.project, spec.token, spec.addr, spec.metadataaddr,
    )
}
