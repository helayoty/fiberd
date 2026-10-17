/* fuzz_wait drives fz_incarnation_wait, fz_fiber_ready and fz_accept
 * over a real pair, as a fiber in a park's wait reads what fiberd wrote
 * on its channel. The input is [served generation][packet
 * lengths...][bytes], cut into packets as fiberd's sendmsg would frame
 * them, each with a descriptor riding along when its first byte is
 * even. Whatever arrives, a wait hands over only a record above the
 * served generation, answers 0 to a 'c' naming the park round the fiber
 * answers (set by a 'p' before it) and drops any other, closes any
 * descriptor, refuses anything else, and the ack that follows a record
 * names its fence. The seed handed over is zeroed by the ack or the
 * next call. The entries and their state are the Rust core's
 * (core/src/fiber.rs), which the fuzzshim archive hands out, so the
 * harness sets the state up and checks it as it did the C's statics. */
#include "common.h"
#include "../libfiberzygote.c"

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    if (size < 2) return 0;
    struct fz_rs_fiber_state *F = fz_rs_fuzz_state();
    struct record_store *polled = fz_rs_fuzz_polled(), *born = fz_rs_fuzz_born();
    F->served_generation = data[0];
    F->park_round = data[0];
    F->park_over = 0;
    size_t npk = data[1] % 8;
    data += 2; size -= 2;
    if (size < npk) return 0;
    const uint8_t *lens = data;
    data += npk; size -= npk;

    int s[2];
    stream_pair(SOCK_SEQPACKET, s);
    F->channel_fd = s[0];
    F->ack_pending = 0;
    F->ready_fd = -1;
    memset(polled, 0, sizeof *polled);
    for (size_t i = 0; i < npk && size; i++) {
        size_t n = lens[i] + 1;
        if (n > size) n = size;
        send_scratch_fds(s[1], data, n, data[0] % 2 == 0);
        data += n; size -= n;
    }
    if (size) send_scratch_fds(s[1], data, size, 0);
    /* fiberd's end sends nothing more, so every wait ends with EOF once
     * the queue is taken, while the fiber's answers still land there. */
    shutdown(s[1], SHUT_WR);

    unsigned before = F->served_generation;
    for (int round = 0; round < 10; round++) {
        fz_incarnation_t inc;
        memset(&inc, 0, sizeof inc);
        errno = 0;
        int rc = fz_incarnation_wait(&inc);
        if (rc > 0) {
            /* A record the fiber had not served: above the generation
             * before this call, now the one served, with a 32-byte seed
             * in the store, and an ack pending that names its fence. */
            if (inc.generation <= before || F->served_generation != inc.generation) abort();
            if (strcmp(inc.kind, polled->inc.kind) != 0 || inc.seed != polled->seed || inc.seed_len != SEED_LEN) abort();
            if (!*inc.fence || strlen(inc.fence) >= FENCE_MAX || !*inc.endpoint) abort();
            if (!F->ack_pending) abort();
            before = inc.generation;
            fz_fiber_ready();
            char ack[FENCE_MAX + 2];
            ssize_t n = recv(s[1], ack, sizeof ack, MSG_DONTWAIT);
            if (n != (ssize_t)(strlen(inc.fence) + 2) || ack[0] != 'a' || strcmp(ack + 1, inc.fence) != 0) abort();
            if (F->ack_pending || polled->inc.seed_len != 0) abort();
            for (size_t i = 0; i < sizeof F->ack_fence; i++) if (F->ack_fence[i]) abort(); /* wiped once acked */
        } else if (rc < 0) {
            if (errno != EPROTO && errno != ECONNRESET) abort();
        } else if (rc != 0) {
            abort();
        } else if (F->park_over) {
            abort(); /* a carry-on honoured is a round over */
        }
        /* No seed stays behind after a refusal or a carry-on. */
        for (size_t i = 0; i < SEED_LEN; i++) if (rc <= 0 && polled->seed[i]) abort();
        if (rc <= 0 && polled->inc.seed_len != 0) abort();
        if (F->ack_pending && rc <= 0) abort();
    }
    /* Whatever is left comes out of fz_accept as a descriptor or not at
     * all, then the EOF. */
    for (int round = 0; round < 10; round++) {
        int fd = fz_accept();
        if (fd < 0) {
            if (errno == EINTR) continue; /* a park's round, for the loop's flag */
            if (errno != ECONNRESET && errno != EPROTO) abort();
            break;
        }
        close(fd);
    }
    fz_seed_forget();
    for (size_t i = 0; i < SEED_LEN; i++) if (polled->seed[i] || born->seed[i]) abort();
    close(s[0]); close(s[1]);
    F->channel_fd = -1;
    return 0;
}
