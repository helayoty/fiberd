/* fuzz_poll drives fz_incarnation_poll and fz_accept over a real pair,
 * as a resumed fiber reads the record fiberd wrote on its channel. The
 * input is [served generation][packet lengths...][bytes], cut into
 * packets as fiberd's sendmsg would frame them, each with a descriptor
 * riding along when its first byte is even. Whatever arrives, a poll
 * hands over only a record above the served generation, every other
 * message is refused or kept for fz_accept, and the next call zeroes
 * the seed. */
#include "common.h"
#include "../libfiberzygote.c"

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    if (size < 2) return 0;
    served_generation = data[0];
    size_t npk = data[1] % 8;
    data += 2; size -= 2;
    if (size < npk) return 0;
    const uint8_t *lens = data;
    data += npk; size -= npk;

    int s[2];
    stream_pair(SOCK_SEQPACKET, s);
    channel_fd = s[0];
    polled_pending = 0;
    stashed_conn = -1;
    memset(&polled, 0, sizeof polled);
    for (size_t i = 0; i < npk && size; i++) {
        size_t n = lens[i] + 1;
        if (n > size) n = size;
        send_scratch_fds(s[1], data, n, data[0] % 2 == 0);
        data += n; size -= n;
    }
    if (size) send_scratch_fds(s[1], data, size, 0);
    /* The peer stays open, as the fiber's own end would, so a poll
     * never sees EOF here. */

    unsigned before = served_generation;
    for (int round = 0; round < 10; round++) {
        fz_incarnation_t inc;
        memset(&inc, 0, sizeof inc);
        errno = 0;
        int rc = fz_incarnation_poll(&inc);
        if (rc > 0) {
            /* A record the fiber had not served: above the generation
             * before this call, now the one served, with a 32-byte seed
             * in the polled store. */
            if (inc.generation <= before || served_generation != inc.generation) abort();
            if (strcmp(inc.kind, polled.inc.kind) != 0 || inc.seed != polled.seed || inc.seed_len != SEED_LEN) abort();
            if (!*inc.fence || strlen(inc.fence) >= FENCE_MAX || !*inc.endpoint) abort();
            before = inc.generation;
        } else if (rc < 0) {
            if (errno != EPROTO && errno != ECONNRESET) abort();
        } else if (rc != 0) {
            abort();
        }
        /* The seed handed over last time is gone at the next call. */
        for (size_t i = 0; i < SEED_LEN; i++) if (rc <= 0 && polled.seed[i]) abort();
        if (rc <= 0 && polled.inc.seed_len != 0) abort();
        /* A connection kept aside comes out of fz_accept, once. */
        if (stashed_conn >= 0) {
            int fd = fz_accept();
            if (fd < 0 || stashed_conn >= 0) abort();
            close(fd);
        }
        if (rc == 0 && errno == 0 && stashed_conn < 0) break;
    }
    fz_seed_forget();
    for (size_t i = 0; i < SEED_LEN; i++) if (polled.seed[i] || born.seed[i]) abort();
    close(s[0]); close(s[1]);
    channel_fd = -1;
    return 0;
}
