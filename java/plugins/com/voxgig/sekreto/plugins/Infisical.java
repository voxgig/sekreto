// Infisical, as a voxgig/plugin definition.
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

import com.voxgig.sekreto.Json;
import com.voxgig.sekreto.Provider;
import com.voxgig.sekreto.Sekreto;
import com.voxgig.sekreto.Sekreto.SekretoError;
import com.voxgig.sekreto.Support;
import com.voxgig.sekreto.plugins.Httpjson.Answer;
import java.util.LinkedHashMap;
import java.util.Map;
import voxgig.plugin.Definition;

/**
 * Infisical.
 *
 * <p>`api.token` reads the secret keyed `API_TOKEN` (Infisical's own
 * convention is environment-style keys) at a secret path in one
 * environment of a project. Auth is a token, or a universal-auth (machine
 * identity) login with clientid/clientsecret.
 */
public final class Infisical implements Provider {

  /** The `infisical` kind: what `plugins` hands to Sekreto. */
  public static final Definition PLUGIN = Support.providerplugin("infisical", spec ->
      new Infisical(
          Support.text(spec.get("addr")), Support.text(spec.get("token")),
          Support.text(spec.get("clientid")), Support.text(spec.get("clientsecret")),
          Support.text(spec.get("project")), Support.text(spec.get("environment")),
          Support.text(spec.get("path"))));
  private final String addr;
  private final String token;
  private final String clientid;
  private final String clientsecret;
  private final String project;
  private final String environment;
  private final String path;

  // A configured token is kept forever; a universal-auth token carries
  // expiresIn and is renewed shortly before it runs out.
  private String livetoken;
  private long renewat = Long.MAX_VALUE;

  public Infisical(String addr, String token, String clientid, String clientsecret,
      String project, String environment, String path) {
    this.addr = addr;
    this.token = token;
    this.clientid = clientid;
    this.clientsecret = clientsecret;
    this.project = project;
    this.environment = environment;
    this.path = path;
  }

  private String login(String useaddr) {
    if (null != token && !token.isEmpty()) {
      return token;
    }

    if (null == clientid || clientid.isEmpty()
        || null == clientsecret || clientsecret.isEmpty()) {
      throw new SekretoError("sekreto: infisical: no token and no client credentials");
    }

    Map<String, Object> body = new LinkedHashMap<>();
    body.put("clientId", clientid);
    body.put("clientSecret", clientsecret);

    Answer res = fetchjson("POST", useaddr + "/api/v1/auth/universal-auth/login",
        headers("content-type", "application/json"), Json.stringify(body));

    Object got = dig(res.body, "accessToken");
    if (200 != res.status || null == got || String.valueOf(got).isEmpty()) {
      throw new SekretoError("sekreto: infisical login failed: " + res.status);
    }

    renewat = renewtime(dig(res.body, "expiresIn"));

    return String.valueOf(got);
  }

  @Override
  public String lookup(String name) {
    String useaddr = trimslash(first(addr, "https://app.infisical.com"));
    checkaddr(useaddr);

    String useproject = null == project ? "" : project;
    String useenvironment = null == environment ? "" : environment;
    if (useproject.isEmpty() || useenvironment.isEmpty()) {
      throw new SekretoError("sekreto: infisical: no project/environment");
    }

    if (null == livetoken || System.currentTimeMillis() >= renewat) {
      livetoken = login(useaddr);
    }

    String url = useaddr + "/api/v3/secrets/raw/" + Sekreto.envkey(name, null)
        + "?workspaceId=" + Sigv4.uriescape(useproject)
        + "&environment=" + Sigv4.uriescape(useenvironment)
        + "&secretPath=" + Sigv4.uriescape(first(path, "/"));

    Answer res = fetchjson("GET", url, headers("authorization", "Bearer " + livetoken), null);

    if (404 == res.status) {
      return null;
    }

    if (200 != res.status) {
      throw new SekretoError("sekreto: infisical error: " + res.status);
    }

    Object value = dig(res.body, "secret", "secretValue");
    return null == value ? null : String.valueOf(value);
  }

  @Override
  public String describe() {
    return "infisical:" + (null == project ? "" : project)
        + "/" + (null == environment ? "" : environment);
  }
}
