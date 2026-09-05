// GCP Secret Manager, as a voxgig/plugin definition.
//
// A PLUGIN, NOT PART OF THE CORE: it opens a socket, and the core reads
// at most a local file. A chain that does not name this kind must not
// carry it, so the calling project imports this definition and hands it
// to Sekreto in the `plugins` option.
// See docs/design/plugin-providers.md.

package com.voxgig.sekreto.plugins;

import static com.voxgig.sekreto.Addr.checkaddr;
import static com.voxgig.sekreto.plugins.Httpjson.dig;
import static com.voxgig.sekreto.plugins.Httpjson.fetchjson;
import static com.voxgig.sekreto.plugins.Httpjson.first;
import static com.voxgig.sekreto.plugins.Httpjson.headers;
import static com.voxgig.sekreto.plugins.Httpjson.renewtime;
import static com.voxgig.sekreto.plugins.Httpjson.trimslash;

import com.voxgig.sekreto.Provider;
import com.voxgig.sekreto.Sekreto;
import com.voxgig.sekreto.Sekreto.SekretoError;
import com.voxgig.sekreto.Support;
import com.voxgig.sekreto.plugins.Httpjson.Answer;
import java.nio.charset.StandardCharsets;
import java.util.Base64;
import voxgig.plugin.Definition;

/**
 * GCP Secret Manager.
 *
 * <p>`api.token` reads secret `api_token` (dots flattened to `_`; Secret
 * Manager ids have no hierarchy and reject dots), latest version. The
 * token comes from config, then `GOOGLE_OAUTH_ACCESS_TOKEN`, then the
 * GCE/GKE metadata server - so on Google's own platform no credential
 * configuration is needed at all.
 *
 * <p>The metadata call itself is plain http to a link-local host by
 * platform design; no credential rides on it, so `checkaddr` guards the
 * Secret Manager address instead.
 */
public final class Gcpsecrets implements Provider {

  /** The `gcpsecrets` kind: what `plugins` hands to Sekreto. */
  public static final Definition PLUGIN = Support.providerplugin("gcpsecrets", spec ->
      new Gcpsecrets(
          Support.text(spec.get("project")), Support.text(spec.get("token")),
          Support.text(spec.get("addr")), Support.text(spec.get("metadataaddr"))));
  private final String project;
  private final String token;
  private final String addr;
  private final String metadataaddr;

  // A configured token is kept forever; a metadata-server token carries
  // expires_in and is renewed shortly before it runs out.
  private String livetoken;
  private long renewat = Long.MAX_VALUE;

  public Gcpsecrets(String project, String token, String addr, String metadataaddr) {
    this.project = project;
    this.token = token;
    this.addr = addr;
    this.metadataaddr = metadataaddr;
  }

  private String usemetadataaddr() {
    if (null != metadataaddr && !metadataaddr.isEmpty()) {
      return metadataaddr;
    }
    String host = System.getenv("GCE_METADATA_HOST");
    return null == host || host.isEmpty()
        ? "http://metadata.google.internal" : "http://" + host;
  }

  private String login() {
    String configured = first(token, System.getenv("GOOGLE_OAUTH_ACCESS_TOKEN"));
    if (!configured.isEmpty()) {
      return configured;
    }

    String url = trimslash(usemetadataaddr())
        + "/computeMetadata/v1/instance/service-accounts/default/token";

    Answer res = fetchjson("GET", url, headers("Metadata-Flavor", "Google"), null);

    Object got = dig(res.body, "access_token");
    if (200 != res.status || null == got || String.valueOf(got).isEmpty()) {
      throw new SekretoError("sekreto: gcp: no token and metadata server did not answer");
    }

    renewat = renewtime(dig(res.body, "expires_in"));

    return String.valueOf(got);
  }

  @Override
  public String lookup(String name) {
    String useproject = null == project ? "" : project;
    if (useproject.isEmpty()) {
      throw new SekretoError("sekreto: gcp: no project");
    }

    String useaddr = first(addr, "https://secretmanager.googleapis.com");
    checkaddr(useaddr);

    if (null == livetoken || System.currentTimeMillis() >= renewat) {
      livetoken = login();
    }

    String url = trimslash(useaddr) + "/v1/projects/" + useproject + "/secrets/"
        + Sekreto.flatname(name, "_") + "/versions/latest:access";

    Answer res = fetchjson("GET", url, headers("authorization", "Bearer " + livetoken), null);

    if (404 == res.status) {
      return null;
    }

    if (200 != res.status) {
      throw new SekretoError("sekreto: gcp error: " + res.status + ": " + url);
    }

    Object data = dig(res.body, "payload", "data");
    if (!(data instanceof String)) {
      return null;
    }

    // See the aws provider: an undecodable payload is a SekretoError.
    try {
      return new String(
          Base64.getDecoder().decode((String) data), StandardCharsets.UTF_8);
    } catch (IllegalArgumentException err) {
      throw new SekretoError("sekreto: gcp: undecodable secret");
    }
  }

  @Override
  public String describe() {
    return "gcpsecrets:" + (null == project ? "" : project);
  }
}
