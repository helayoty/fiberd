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
 *     inherited descriptor closed (the standard three go to /dev/null,
 *     stderr once the child is ready), the environment emptied, a new
 *     session, and libc's random() reseeded from getrandom;
 *   - when asked, the child gets a private mount namespace with the
 *     agent's paths covered, a /proc of its own pid namespace, and no
 *     capabilities under no_new_privs;
 *   - identity (the fence) is handed to the child AFTER the fork, never
 *     baked into the template;
 *   - readiness is reported when the application says so, under the
 *     deadline fiberd set; a late child is killed, not delivered;
 *   - clones are forked back to back: the loop polls every pending
 *     child's readiness pipe at once, so under a storm each request is
 *     acknowledged when its own child is ready, never behind the others.
 *
 * With FIBERD_CTL_REBIND set in its environment, fz_serve first reads a
 * REBIND message carrying a socket on the control descriptor and serves
 * on that socket instead (the agent made it in the zygote's network
 * namespace, where a checkpoint of the zygote finds it).
 *
 * With FIBERD_USERNS_NESTED=deny in its environment, fz_serve first sets
 * user.max_user_namespaces to 0 in the zygote's own user namespace and
 * drops CAP_SYS_RESOURCE, so no fiber can make a namespace in which it
 * would be capable again. It refuses to do so in the initial user
 * namespace, and it does not serve when the limit cannot be set. Every
 * fiber also gets a seccomp filter refusing unshare, clone and setns
 * with a user namespace (and clone3, with ENOSYS), which a checkpoint
 * carries into the new user namespace a restore puts the fiber in.
 *
 * Wire protocol on the control descriptor (one line per message):
 *
 *   zygote -> agent   READY
 *   agent  -> zygote  HIDE <dir>      cover dir with an empty tmpfs in
 *                                     every mntns fiber (before any CLONE)
 *   agent  -> zygote  DROP <path>     unmount path in every mntns fiber
 *   agent  -> zygote  RUNDIR <parent> <own>
 *                                     in every mntns fiber, cover parent
 *                                     (the agent's run directory, holding
 *                                     one directory per grant) with an
 *                                     empty read-only tmpfs and bind only
 *                                     own, this grant's directory, back
 *                                     at its place (before any CLONE)
 *   agent  -> zygote  CLONE <fence> <endpoint> <deadline_ms> <hex-payload|-> [opts]
 *                     (the fiber's cgroup directory fd rides along via
 *                     SCM_RIGHTS on the same message; opts is a comma
 *                     list: "pidns" makes the child the init of its own
 *                     pid namespace, "mntns" gives it a private mount
 *                     namespace, "nocaps" drops every capability under
 *                     no_new_privs, and "handoff" means the last
 *                     descriptor on the message is the fiber's end of a
 *                     SOCK_SEQPACKET pair the agent passes connections
 *                     over: the child keeps it at FZ_HANDOFF_FD, see
 *                     fz_accept. A child that cannot get what it was
 *                     asked for ends before it runs, and the CLONE is
 *                     answered with an ERROR. So is a mntns CLONE after
 *                     a refused HIDE, DROP or RUNDIR.)
 *   zygote -> agent   CLONED <fence> <pid>
 *
 * On a fresh handoff fiber's channel the first message, queued by the
 * agent before the CLONE, is the grant's TLS identity:
 *
 *   agent  -> fiber   'k' <key PEM> NUL <cert PEM> NUL <caller> NUL
 *
 * The library reads it in the child before the application runs (see
 * fz_handoff_identity) and every message after it carries one connected
 * socket in SCM_RIGHTS (see fz_accept). A fiber restored from a
 * checkpoint keeps the identity it was born with and is sent no new one.
 * The identity is never a file: every grant's fibers run as the agent's
 * user, so no file mode would keep one grant's fibers out of another's
 * key.
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
    const char *endpoint;         /* unix socket path or tcp://host:port the fiber must serve on;
                                     "handoff" when it serves fz_accept() instead */
    const unsigned char *payload; /* opaque data delivered at birth */
    size_t payload_len;
} fz_fiber_t;

/* Runs in the CHILD after the scrub. Serve on f->endpoint, call
 * fz_fiber_ready() once listening, then do the fiber's work. The return
 * value becomes the process exit code.
 *
 * Every fiber starts as a copy of the zygote's memory, including any
 * random generator the application seeded during its initialization (a
 * TLS library's DRBG, a language runtime's hash seed, a UUID generator).
 * The library reseeds only libc's random(). Reseed the others here from
 * getrandom(2), before they are used. Fibers restored from one checkpoint
 * also share that state, so a generator that makes keys is best reseeded
 * before each use, as refzygote does before every TLS handshake. */
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
 * Until this is called the agent has not acknowledged the clone, and the
 * child's stderr is the zygote's log, for saying why it could not start;
 * after it, stderr is /dev/null. The readiness pipe is fd 3 and is not
 * the fiber's to use: a fiber that writes anything else on it, or closes
 * it without calling this, is killed and its CLONE answered with ERROR. */
void fz_fiber_ready(void);

/* Where a handoff fiber's channel to the agent lives. FIBERD_HANDOFF_FD
 * names it in the fiber's environment; it is unset for other fibers. */
#define FZ_HANDOFF_FD 4

/* A handoff fiber terminates TLS itself with the grant's identity, which
 * the agent sends down the channel at birth and the library holds in the
 * fiber's memory (never the zygote's, so no key ends up in a template
 * checkpoint). key_pem and cert_pem are the grant's PKCS #8 private key
 * and self-signed certificate; caller is the thumbprint (x5t#S256,
 * base64url) of the one client certificate the fiber may accept. */
typedef struct {
    const char *key_pem;
    const char *cert_pem;
    const char *caller;
} fz_identity_t;

/* The identity of the fiber calling, valid for its lifetime (a restored
 * fiber keeps the one it was born with); NULL when the fiber is not a
 * handoff fiber. Load it into the TLS library in on_fiber, before
 * fz_fiber_ready. */
const fz_identity_t *fz_handoff_identity(void);

/* Handoff fibers do not listen: the agent accepts on their behalf and
 * passes each connected socket here. fz_accept blocks until the next one
 * and returns it (close-on-exec set), or -1 with errno set: EBADF when
 * the fiber is not a handoff fiber, ECONNRESET once the agent has closed
 * the channel (the fiber is being released). */
int fz_accept(void);

/* Engine support. fz_set_engine names the engine's IPC endpoint; every
 * fiber finds it as FIBERD_ENGINE in its scrubbed environment. fz_report
 * sends one line to the agent from any thread (a DEVICE report); it
 * fails with -1 before fz_serve has the channel, and always in a fiber,
 * which has no channel to the agent. fz_set_control installs the handler
 * for lines such as EVICT. */
void fz_set_engine(const char *endpoint);
int fz_report(const char *fmt, ...) __attribute__((format(printf, 1, 2)));
void fz_set_control(fz_on_control handler);

#endif
