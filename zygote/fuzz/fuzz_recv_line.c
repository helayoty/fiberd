/* fuzz_recv_line feeds recv_line, the control line reader, a stream cut
 * into chunks as an agent's socket may deliver it, with descriptors riding
 * on some of the chunks. The kernel returns a chunk that carries
 * descriptors on its own, so this exercises the reader's buffering. A
 * line split over several reads, a partial line at EOF, and one longer
 * than the buffer.
 *
 * The input is [cap selector][chunk count and descriptor mask][stream
 * bytes]. */
#include "common.h"
#include "../libfiberzygote.c"

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    if (size < 2) return 0;
    static const size_t caps[] = { 2, 16, 64, 256, 4096, MAX_LINE };
    size_t cap = caps[data[0] % (sizeof caps / sizeof caps[0])];
    unsigned chunks = 1 + (data[1] & 7), mask = data[1] >> 3;
    data += 2; size -= 2;

    int s[2];
    stream_pair(SOCK_STREAM, s);
    size_t each = size / chunks, off = 0;
    for (unsigned i = 0; i < chunks && off < size; i++) {
        size_t n = i + 1 == chunks ? size - off : each;
        if (n == 0) continue;
        /* Chunk i carries one to three descriptors when its mask bit is
         * set, so the reader also sees more than MAX_PASSED at once. */
        send_scratch_fds(s[1], data + off, n, (mask >> i) & 1 ? 1 + i % 3 : 0);
        off += n;
    }
    if (shutdown(s[1], SHUT_WR) < 0) abort();

    static char buf[MAX_LINE];
    int fds[MAX_PASSED];
    for (;;) {
        ssize_t n = recv_line(s[0], buf, cap, fds);
        /* Whatever it handed over must be a live descriptor of ours. */
        for (int i = 0; i < MAX_PASSED; i++)
            if (fds[i] >= 0 && close(fds[i]) < 0) abort();
        if (n <= 0) break;
        /* The line is NUL-terminated inside the buffer and no longer than
         * the bytes it says it consumed. */
        if ((size_t)n > cap || strlen(buf) >= cap || strlen(buf) > (size_t)n) abort();
    }
    close(s[0]);
    close(s[1]);
    return 0;
}
