/* ares_dns_write_fuzzer.c
 *
 * Fuzz target for c-ares DNS record serialisation path.
 * The existing OSS-Fuzz coverage exercises the parse path (ares_dns_parse).
 * This harness targets ares_dns_write() in src/lib/record/ares_dns_write.c
 * via a parse→write round-trip, exercising every record type that
 * ares_dns_parse successfully decodes from fuzz input.
 */
#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include "ares.h"
#include "ares_dns.h"

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    if (size < 12) return 0;   /* minimum DNS header */

    ares_dns_record_t *rec = NULL;
    unsigned char     *out = NULL;
    size_t             out_len = 0;

    /* Parse the fuzz input as a DNS message */
    ares_status_t st = ares_dns_parse(data, size, 0, &rec);
    if (st != ARES_SUCCESS || rec == NULL) return 0;

    /* Re-serialise – exercises ares_dns_write */
    st = ares_dns_write(rec, &out, &out_len);
    if (st == ARES_SUCCESS && out != NULL) {
        /* Parse the re-serialised output for round-trip fidelity */
        ares_dns_record_t *rec2 = NULL;
        ares_dns_parse(out, out_len, 0, &rec2);
        if (rec2) ares_dns_record_destroy(rec2);
        ares_free(out);
    }

    ares_dns_record_destroy(rec);
    return 0;
}
