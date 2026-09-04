/* One HTTPS round-trip, and nothing else.
 *
 * test/tlscheck.sh drives this against a local TLS server to prove the
 * four obligations a TLS binding in this repository has: chain
 * verification, HOSTNAME verification, SNI, and additive extra roots from
 * SEKRETO_CA_BUNDLE.
 *
 * The hostname half needs its own proof and cannot borrow anyone else's:
 * `make integration` contains no https URL at all, and `test/realstores.sh`
 * has no NEGATIVE hostname case - so nothing in either suite would notice
 * a port that verified the chain and then accepted a certificate issued
 * for somebody else. That case is number 4 in tlscheck.sh.
 *
 * Prints one line - `status=<code>` or `error=<message>` - so the shell
 * driver can assert on it.
 */

#define _POSIX_C_SOURCE 200809L

#include <stdio.h>

#include "sekreto.h"

int main(int argc, char **argv) {
  sek_pool *pool = sek_pool_new();
  int status = 0;
  char *body = NULL;
  sek_err err;

  if (2 > argc) {
    printf("error=usage: tlsprobe <url>\n");
    sek_pool_free(pool);
    return 2;
  }

  err = sek_fetch(pool, "GET", argv[1], NULL, NULL, &status, &body);

  if (NULL != err) {
    printf("error=%s\n", err);
    sek_pool_free(pool);
    return 1;
  }

  printf("status=%d\n", status);

  sek_pool_free(pool);

  return 0;
}
