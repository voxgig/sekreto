/* THE FULL SET - every plugin this library ships, in one call.
 *
 * It exists for the callers that genuinely want all ten kinds: the CLI,
 * the conformance suite, an app whose chain is decided at run time.
 *
 *     Definition **plugins;
 *     sek_options opts = {0};
 *     opts.plugincount = sek_allplugins(&plugins);
 *     opts.plugins = plugins;
 *
 * IT IS ALSO THE THING TO AVOID IF YOU CARE ABOUT SIZE, and in C the cost
 * is exactly visible: this object references all ten `sek_plugin_*`
 * symbols, so a link that pulls `all.o` in pulls every plugin object,
 * every HTTP client, the TLS binding, the child-process launcher and AWS
 * request signing with them. A lean consumer never names this file. It
 * links the plugin objects it configures and passes their definitions:
 *
 *     Definition *chain[] = {sek_plugin_hashicorp()};
 *
 * and its binary contains one vault client.
 *
 * The order is the order every port lists them in, which is the order the
 * design document does.
 */

#include "sekretoplugins.h"

static Definition *ALL[10];

size_t sek_allplugins(Definition ***out) {
  ALL[0] = sek_plugin_hashicorp();
  ALL[1] = sek_plugin_boru();
  ALL[2] = sek_plugin_awssecrets();
  ALL[3] = sek_plugin_awsparams();
  ALL[4] = sek_plugin_gcpsecrets();
  ALL[5] = sek_plugin_azuresecrets();
  ALL[6] = sek_plugin_onepassword();
  ALL[7] = sek_plugin_doppler();
  ALL[8] = sek_plugin_infisical();
  ALL[9] = sek_plugin_secretspec();

  *out = ALL;

  return 10;
}
