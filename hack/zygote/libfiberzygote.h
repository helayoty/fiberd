/* libfiberzygote: the zygote side of fiberd's process runtime.
 *
 * An application becomes a zygote by doing its expensive initialization
 * once and then calling fz_serve() on the control descriptor fiberd handed
 * it (fd 3). fiberd then asks it to fork; each child is a fiber. The
 * library does the part the protocol requires and the application must not
 * get wrong:
 *
 *   - the child is born inside the cgroup fiberd chose (clone3 with
 *     CLONE_INTO_CGROUP, so not one page is charged elsewhere);
 *   - the child is scrubbed before it runs any application code: every
 *     inherited descriptor closed (the standard three go to /dev/null),
 *     the environment emptied, a new session, and a fresh random seed;
 *   - identity (the fence) is handed to the child AFTER the fork, never
 *     baked into the template;
 *   - readiness is reported when the application says so, under the
 *     deadline fiberd set; a late child is killed, not delivered;
 *   - clones are forked back to back: the loop polls every pending
 *     child's readiness pipe at once, so under a storm each request is
 *     acknowledged when its own child is ready, never behind the others.
 *
 * Wire protocol on the control descriptor (one line per message):
 *
 *   zygote -> agent   READY
 *   agent  -> zygote  CLONE <fence> <endpoint> <deadline_ms> <hex-payload|-> [pidns]
 *                     (the fiber's cgroup directory fd rides along via
 *                     SCM_RIGHTS on the same message; "pidns" asks for the
 *                     child to be the init of its own pid namespace)
 *   zygote -> agent   CLONED <fence> <pid> pidns=<0|1>
 *   zygote -> agent   ERROR <fence> <reason>
 *   zygote -> agent   EXITED <pid> exit:<code>|signal:<num>
 *
 * An engine zygote (one that owns device state its fibers use over IPC)
 * adds, unsolicited, from any thread:
 *
 *   zygote -> agent   DEVICE <fence> <bytes> 0        one fiber's slice
 *   zygote -> agent   DEVICE - <used> <capacity>      the whole engine
 *
 * and receives, before a fiber is parked:
 *
 *   agent  -> zygote  EVICT <fence>                   drop that slice
 */
#ifndef FIBERZYGOTE_H
#define FIBERZYGOTE_H

#include <stddef.h>

typedef struct {
    const char *fence;            /* "grant/epoch/seq": the fiber's identity */
    const char *endpoint;         /* unix socket path or tcp://host:port the fiber must serve on */
    const unsigned char *payload; /* opaque data delivered at birth */
    size_t payload_len;
} fz_fiber_t;

/* Runs in the CHILD after the scrub. Serve on f->endpoint, call
 * fz_fiber_ready() once listening, then do the fiber's work. The return
 * value becomes the process exit code. */
typedef int (*fz_on_fiber)(const fz_fiber_t *f);

/* Runs in the ZYGOTE for every control line that is not CLONE or PING
 * (EVICT <fence>, and whatever a runtime and its engine agree on). */
typedef void (*fz_on_control)(const char *line);

/* Call first thing in main(), before any allocation. It makes the zygote's
 * memory layout reproducible: if address-space randomisation is on it
 * turns it off for this process and re-execs argv. Reproducible layout is
 * what lets a fiber's checkpoint be expressed as a delta over the zygote's
 * pages, on this home or another one warmed from the same artifact. */
void fz_init(int argc, char **argv);

/* Zygote main loop. Returns 0 when the agent closes the channel, -1 on a
 * protocol or system error (errno set). */
int fz_serve(int ctl_fd, fz_on_fiber on_fiber);

/* Called by on_fiber in the child once its endpoint accepts connections.
 * Until this is called the agent has not acknowledged the clone. */
void fz_fiber_ready(void);

/* Engine support. fz_set_engine names the engine's IPC endpoint; every
 * fiber finds it as FIBERD_ENGINE in its scrubbed environment. fz_report
 * sends one line to the agent from any thread (a DEVICE report); it
 * fails with -1 before fz_serve has the channel. fz_set_control installs
 * the handler for lines such as EVICT. */
void fz_set_engine(const char *endpoint);
int fz_report(const char *fmt, ...) __attribute__((format(printf, 1, 2)));
void fz_set_control(fz_on_control handler);

#endif
