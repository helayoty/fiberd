/* fuzz_identity delivers one message on a handoff fiber's channel, as the
 * agent queues it before the CLONE, and lets read_identity take it apart
 * ('k' then three NUL-ended fields), with descriptors it must not keep.
 *
 * The input is [descriptor count][message bytes]. An empty message is a
 * closed channel instead. */
#include "common.h"
#include "../libfiberzygote.c"

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    if (size < 1) return 0;
    size_t nfds = data[0] % 4;
    data++; size--;

    int s[2];
    stream_pair(SOCK_SEQPACKET, s);
    if (size) send_scratch_fds(s[1], data, size, nfds);
    close(s[1]);

    have_identity = 0;
    memset(&identity, 0, sizeof identity);
    const char *why = NULL;
    int rc = read_identity(s[0], &why);
    if (rc == 0) {
        /* Three fields, each non-empty and NUL-ended, back to back after
         * the 'k', and together they are the whole message. */
        if (!have_identity || identity.key_pem != identity_buf + 1) abort();
        if (identity.cert_pem != identity.key_pem + strlen(identity.key_pem) + 1) abort();
        if (identity.caller != identity.cert_pem + strlen(identity.cert_pem) + 1) abort();
        if (!*identity.key_pem || !*identity.cert_pem || !*identity.caller) abort();
        size_t end = (size_t)(identity.caller - identity_buf) + strlen(identity.caller) + 1;
        if (end != size) abort();
    } else if (!why) {
        abort();
    }
    close(s[0]);
    return 0;
}
