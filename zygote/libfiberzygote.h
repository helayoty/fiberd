/* libfiberzygote is the zygote side of fiberd's process runtime.
 *
 * An application becomes a zygote by doing its expensive initialization
 * once and then calling fz_serve() on the control descriptor fiberd handed
 * it (fd 3). fiberd then asks it to fork, and each child is a fiber. The
 * library does the part the protocol requires and the application must
 * not get wrong.
 *
 *   - The child is born inside the cgroup fiberd chose, through clone3
 *     with CLONE_INTO_CGROUP, so not one page is charged elsewhere. On a
 *     kernel without it the legacy clone runs with the same namespace
 *     flags, and the child joins its leaf as its first act or ends.
 *   - The child is scrubbed before any application code runs. Every
 *     inherited descriptor is closed, the standard three point at
 *     /dev/null (stderr once the child is ready), the environment is
 *     emptied and the child gets a new session.
 *   - When asked, the child gets a private mount namespace with the
 *     agent's paths covered, a /proc of its own pid namespace, and no
 *     capabilities under no_new_privs. The grant-wide part of that
 *     namespace (read-only /sys, the run directory narrowed, the HIDE
 *     directories covered) is made once, in a mount namespace the
 *     zygote takes for itself in fz_init and fills before READY, so a
 *     fiber's namespace is a copy and its birth pays only for what is
 *     its own.
 *   - Identity (the fence) is handed to the child after the fork and is
 *     never baked into the template.
 *   - Readiness is reported when the application says so, under the
 *     deadline fiberd set. A late child is killed, not delivered.
 *   - Clones are forked back to back. The loop polls every pending
 *     child's readiness pipe at once, so under a storm each request is
 *     acknowledged when its own child is ready, never behind the others.
 *
 * With FIBERD_CTL_REBIND set in its environment, fz_serve first reads a
 * REBIND message carrying a socket on the control descriptor and serves
 * on that socket instead. The agent made it in the zygote's network
 * namespace, where a checkpoint of the zygote finds it.
 *
 * With FIBERD_OWN_MNTNS set in its environment, fz_init moves the zygote
 * into a private mount namespace of its own, and fz_serve fills it
 * before READY with what every mntns fiber must see (PREPARE mntns
 * below), so a fiber's namespace is a copy. The agent sets it when its
 * fibers will ask for a mount namespace. Without it a mntns CLONE is
 * refused.
 *
 * With FIBERD_USERNS_NESTED=deny in its environment, fz_serve first sets
 * user.max_user_namespaces to 0 in the zygote's own user namespace and
 * drops CAP_SYS_RESOURCE, so no fiber can make a namespace in which it
 * would be capable again. It refuses to do so in the initial user
 * namespace, and it does not serve when the limit cannot be set. Every
 * fiber also gets a seccomp filter that refuses unshare, clone and setns
 * with a user namespace, and answers clone3 with ENOSYS. A checkpoint
 * carries the filter into the new user namespace a restore puts the
 * fiber in.
 *
 * Wire protocol on the control descriptor, one line per message. The
 * agent speaks first. Its setup lines, ended by PREPARE, come before
 * READY, because the zygote prepares what every mntns fiber's namespace
 * must have once, in a namespace of its own, and answers READY from it.
 *
 *   agent  -> zygote  HIDE <dir>
 *                     Cover dir with an empty tmpfs in every mntns fiber.
 *   agent  -> zygote  DROP <path>
 *                     Unmount path in every mntns fiber.
 *   agent  -> zygote  RUNDIR <parent> <own>
 *                     In every mntns fiber, cover parent (the agent's run
 *                     directory, one directory per grant) with an empty
 *                     read-only tmpfs and bind only own, this grant's
 *                     directory, back at its place.
 *   agent  -> zygote  PREPARE mntns|none
 *                     Ends the setup lines. With mntns, the zygote makes
 *                     every mount under /sys read-only, unmounts the DROP
 *                     paths, narrows the run directory and covers the
 *                     HIDE directories in its own mount namespace (the
 *                     one FIBERD_OWN_MNTNS had fz_init take), and every
 *                     mntns fiber starts from a copy. With none, no fiber
 *                     will ask for a mount namespace, and a mntns CLONE
 *                     is refused. A setup line refused, or a step of
 *                     PREPARE that fails, gets an ERROR ? line naming the
 *                     reason instead of READY, and the zygote ends, since
 *                     a plain proc grant's fibers all ask for a mount
 *                     namespace and the agent fails the warm. Any other
 *                     line before PREPARE, or a setup line after READY,
 *                     is a protocol error. The first ends the zygote and
 *                     the second refuses every mntns CLONE.
 *   zygote -> agent   READY
 *   agent  -> zygote  CLONE <fence> <endpoint> <deadline_ms> <hex-payload|-> [opts]
 *                     The fence is at most 127 characters and the endpoint
 *                     at most 1023. The fiber's cgroup directory fd rides
 *                     along in SCM_RIGHTS on the same message. opts is a
 *                     comma list. "pidns" makes the child the init of its
 *                     own pid namespace. "mntns" gives it a private mount
 *                     namespace. "nocaps" drops every capability under
 *                     no_new_privs. "handoff" means the last descriptor on
 *                     the message is the fiber's end of a SOCK_SEQPACKET
 *                     pair the agent passes connections over, kept at
 *                     FZ_HANDOFF_FD (see fz_accept). A child that cannot
 *                     get what it was asked for ends before it runs, and
 *                     the CLONE is answered with an ERROR. So is a mntns
 *                     CLONE after a refused HIDE, DROP, RUNDIR or
 *                     PREPARE, or after PREPARE none.
 *   zygote -> agent   CLONED <fence> <pid>
 *   zygote -> agent   ERROR <fence> <reason>
 *                     For a child that ended before ready, the reason is
 *                     "died before ready: exit:<code>", followed by what
 *                     the code stands for when the library assigned it.
 *                     110-115 and 117 are the confinement steps (116 is
 *                     retired, since the zygote narrows the run directory
 *                     at PREPARE), 120 the descriptors, 121 the handoff
 *                     identity and 125 the cgroup leaf on the legacy clone.
 *   zygote -> agent   EXITED <pid> exit:<code>|signal:<num>
 *
 * On a fresh handoff fiber's channel the first message, queued by the
 * agent before the CLONE, is the grant's TLS identity.
 *
 *   agent  -> fiber   'k' <key PEM> NUL <cert PEM> NUL <caller> NUL
 *
 * The library reads it in the child before the application runs (see
 * fz_handoff_identity). Every message after it carries one connected
 * socket in SCM_RIGHTS (see fz_accept). A fiber restored from a
 * checkpoint keeps the identity it was born with and is sent no new one.
 * The identity is never a file. Every grant's fibers run as the agent's
 * user, so no file mode would keep one grant's fibers out of another's
 * key.
 *
 * An engine zygote, one that owns device state its fibers use over IPC,
 * adds these lines, unsolicited, from any thread.
 *
 *   zygote -> agent   DEVICE <fence> <bytes> 0        one fiber's slice
 *   zygote -> agent   DEVICE - <used> <capacity>      the whole engine
 *
 * It receives this one before a fiber is parked.
 *
 *   agent  -> zygote  EVICT <fence>                   drop that slice
 */
#ifndef FIBERZYGOTE_H
#define FIBERZYGOTE_H

#include <stddef.h>

typedef struct {
    const char *fence;            /* the fiber's identity, "grant/epoch/seq" */
    const char *endpoint;         /* unix socket path or tcp://host:port the fiber serves on,
                                     or "handoff" when it serves fz_accept() instead */
    const unsigned char *payload; /* opaque data delivered at birth */
    size_t payload_len;
} fz_fiber_t;

/* Runs in the CHILD after the scrub. Serve on f->endpoint, call
 * fz_fiber_ready() once listening, then do the fiber's work. The return
 * value becomes the process exit code.
 *
 * Every fiber starts as a copy of the zygote's memory, including every
 * random generator the application seeded during its initialization
 * (libc's random(), a TLS library's DRBG, a language runtime's hash
 * seed, a UUID generator). The library reseeds none of them, because it
 * takes no lock between the clone and this call, and srandom takes one.
 * Reseed each of them here from getrandom(2), before it is used. A fork
 * is not the only copy. A sandbox restored from a checkpoint and a fiber
 * resumed from a park (CRIU keeps the pid, so a pid check sees no copy)
 * hold that state too. Reseed again in every new incarnation, which is
 * when a restore returns and when the fence beside the endpoint changes,
 * as refzygote does. A generator that makes keys is best reseeded before
 * each use as well, as refzygote does before every TLS handshake.
 *
 * The child is a copy of the one thread that called fz_serve. A lock
 * another thread of the zygote (an engine) held at the clone stays held
 * in the copy, malloc's and a stream's included, since the raw clone
 * runs no atfork handlers. A template with threads of its own keeps
 * their allocation and stdio rare, or stops them around clones. */
typedef int (*fz_on_fiber)(const fz_fiber_t *f);

/* Runs in the ZYGOTE for every control line that is not CLONE, HIDE,
 * DROP or RUNDIR. That is EVICT <fence>, and whatever a runtime and its
 * engine agree on. */
typedef void (*fz_on_control)(const char *line);

/* Call first thing in main(), before any allocation and before any
 * thread. It makes the zygote's memory layout reproducible. If
 * address-space randomisation is on it turns it off for this process and
 * re-execs argv. A reproducible layout is what lets a fiber's checkpoint
 * be expressed as a delta over the zygote's pages, on this home or
 * another one warmed from the same artifact. It also blocks SIGCHLD,
 * which fz_serve reads from a descriptor so a fiber's exit wakes its
 * loop. Every thread made after it inherits the block. A fiber starts
 * with the signal unblocked. With FIBERD_OWN_MNTNS set it also moves the
 * zygote into a private mount namespace of its own, which fz_serve fills
 * before READY with what every mntns fiber must see, so a fiber's
 * namespace is a copy. That needs CAP_SYS_ADMIN and no thread yet. With
 * a thread already made, only the calling thread would move, so the
 * namespace is not taken, and fz_serve then refuses every mntns CLONE
 * with that reason (fail closed) while serving the rest. */
void fz_init(int argc, char **argv);

/* Zygote main loop. Returns 0 when the agent closes the channel, -1 on a
 * protocol or system error (errno set). It refuses to serve, with EINVAL
 * and a line on stderr, when SIGCHLD is not blocked, which means fz_init
 * was skipped. */
int fz_serve(int ctl_fd, fz_on_fiber on_fiber);

/* Called by on_fiber in the child once its endpoint accepts connections.
 * Until then the agent has not acknowledged the clone, and the child's
 * stderr is the zygote's log, for saying why it could not start. After
 * it, stderr is /dev/null. The readiness pipe is fd 3 and is not the
 * fiber's to use. A fiber that writes anything else on it, or closes it
 * without calling this, is killed and its CLONE answered with ERROR. */
void fz_fiber_ready(void);

/* Where a handoff fiber's channel to the agent lives. FIBERD_HANDOFF_FD
 * names it in the fiber's environment and is unset for other fibers. */
#define FZ_HANDOFF_FD 4

/* A handoff fiber terminates TLS itself with the grant's identity, which
 * the agent sends down the channel at birth and the library holds in the
 * fiber's memory, never the zygote's, so no key ends up in a template
 * checkpoint. key_pem and cert_pem are the grant's PKCS #8 private key
 * and self-signed certificate. caller is the thumbprint (x5t#S256,
 * base64url) of the one client certificate the fiber may accept. */
typedef struct {
    const char *key_pem;
    const char *cert_pem;
    const char *caller;
} fz_identity_t;

/* The identity of the fiber calling, valid for its lifetime. A restored
 * fiber keeps the one it was born with. NULL when the fiber is not a
 * handoff fiber. Load it into the TLS library in on_fiber, before
 * fz_fiber_ready. */
const fz_identity_t *fz_handoff_identity(void);

/* Handoff fibers do not listen. The agent accepts on their behalf and
 * passes each connected socket here. fz_accept blocks until the next one
 * and returns it with close-on-exec set, or -1 with errno set. EBADF
 * means the fiber is not a handoff fiber. ECONNRESET means the agent has
 * closed the channel and the fiber is being released. */
int fz_accept(void);

/* Engine support. fz_set_engine names the engine's IPC endpoint, which
 * every fiber finds as FIBERD_ENGINE in its scrubbed environment.
 * fz_report sends one line to the agent from any thread (a DEVICE
 * report). It fails with -1 before fz_serve has the channel, and always
 * in a fiber, which has no channel to the agent. fz_set_control installs
 * the handler for lines such as EVICT. Bind a unix endpoint under the
 * run directory before fz_serve, which remounts that directory. */
void fz_set_engine(const char *endpoint);
int fz_report(const char *fmt, ...) __attribute__((format(printf, 1, 2)));
void fz_set_control(fz_on_control handler);

#endif
