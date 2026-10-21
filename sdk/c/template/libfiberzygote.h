/* libfiberzygote is the zygote side of fiberd's process runtime.
 *
 * An application becomes a zygote by doing its expensive initialization
 * once and then calling fz_serve() on the control descriptor fiberd
 * handed it (fd 3). fiberd then asks it to fork, and each child is a
 * fiber. The library does the part the application must not get wrong.
 *
 *   - The child is born inside the cgroup fiberd chose, so not one page
 *     is charged elsewhere.
 *   - The child is scrubbed before any application code runs. Inherited
 *     descriptors are closed, the standard three point at /dev/null
 *     (stderr once the child is ready), the environment is emptied and
 *     the child gets a new session.
 *   - When asked, the child gets a private mount namespace, a /proc of
 *     its own pid namespace, and no capabilities.
 *   - The zygote and every child run under no_new_privs and the fiber
 *     filter, a seccomp program fz_serve installs before READY. A
 *     zygote that cannot install it never says READY. Each child adds a
 *     filter that refuses clone3 before any application code runs.
 *   - Identity (the fence, the seed, a handoff fiber's key) reaches the
 *     child after the fork, on its channel, and is never baked into the
 *     template.
 *   - Readiness is reported when the application says so, under the
 *     deadline fiberd set. A late child is killed, not delivered.
 *
 * fiberd may set these in the zygote's environment.
 *
 *   FIBERD_CTL_REBIND    fz_serve first reads a REBIND message carrying
 *                        a socket and serves on that socket. fiberd made
 *                        it in the zygote's network namespace, where a
 *                        checkpoint of the zygote finds it.
 *   FIBERD_OWN_MNTNS     fz_init takes a private mount namespace, which
 *                        fz_serve fills at PREPARE, so a mntns fiber's
 *                        namespace is a copy. Without it a mntns CLONE
 *                        is refused.
 *   FIBERD_USERNS_NESTED=deny
 *                        fz_serve sets user.max_user_namespaces to 0 in
 *                        the zygote's user namespace, keeps CAP_SYS_ADMIN
 *                        alone on the serving thread, and installs the
 *                        fiber filter with the mount family refused too.
 *                        It does not serve in the initial user namespace
 *                        or when any step is refused.
 *
 * Wire protocol on the control descriptor, one line per message. fiberd
 * speaks first, and its setup lines, ended by PREPARE, come before READY.
 *
 *   fiberd -> zygote  HIDE <dir>
 *                     Cover dir with an empty tmpfs in every mntns fiber.
 *   fiberd -> zygote  DROP <path>
 *                     Unmount path in every mntns fiber.
 *   fiberd -> zygote  RUNDIR <parent> <own>
 *                     In every mntns fiber, cover parent (fiberd's run
 *                     directory) with an empty read-only tmpfs and bind
 *                     only own, this grant's directory, back in place.
 *   fiberd -> zygote  PREPARE mntns|none
 *                     Ends the setup lines. With mntns the zygote builds,
 *                     once in its own namespace, what every mntns fiber
 *                     sees (read-only /sys, the DROP, RUNDIR and HIDE
 *                     steps, and every mount another fiberd home made
 *                     detached). With none a mntns CLONE is refused. A
 *                     refused setup line or a failed PREPARE step gets
 *                     ERROR ? <reason> instead of READY and the zygote
 *                     ends. Any other line before PREPARE ends the
 *                     zygote too, and a setup line after READY refuses
 *                     every later mntns CLONE.
 *   zygote -> fiberd  READY
 *   fiberd -> zygote  CLONE <fence> <endpoint> <deadline_ms> <hex-payload|-> <hex-session|-> [opts]
 *                     The fence is at most 127 characters and the endpoint
 *                     at most 1023. The session is hex, "-" when
 *                     anonymous, at most 1023 bytes decoded with no NUL,
 *                     and the fiber finds it as FIBERD_SESSION. The
 *                     fiber's cgroup directory fd, when fiberd has one,
 *                     and then the fiber's channel ride in SCM_RIGHTS on
 *                     the same message. opts is a comma list of "pidns",
 *                     "mntns" and "nocaps". A child that cannot get what
 *                     it asked for ends before it runs and the CLONE is
 *                     answered with ERROR, as is a CLONE without a
 *                     channel.
 *   zygote -> fiberd  CLONED <fence> <pid>
 *   zygote -> fiberd  ERROR <fence> <reason>
 *                     A child that ended before ready gets "died before
 *                     ready: exit:<code>". Codes 110-126 are the
 *                     library's own (confinement, the child's filter,
 *                     descriptors, the incarnation record, the cgroup
 *                     leaf), and the reason then says which.
 *   zygote -> fiberd  EXITED <pid> exit:<code>|signal:<num>
 *
 * On every fiber's channel the first message, queued by fiberd before
 * the CLONE, is the fiber's incarnation record, the same record a gVisor
 * sandbox reads (fz_gvisor_identity below).
 *
 *   fiberd -> fiber   'i' <generation> NUL <kind> NUL <fence> NUL <endpoint> NUL <payload-hex|-> NUL
 *                     <session-hex|-> NUL <key PEM|-> NUL <cert PEM|-> NUL <caller|-> NUL <caller cert PEM|-> NUL <seed-hex> NUL
 *
 * The library reads it in the child, never the zygote, and hands it to
 * on_fiber. A handoff fiber's record carries the grant's TLS identity,
 * and every later message carries one connected socket (see fz_accept).
 * Any other fiber has "-" in those four fields and gets a SOCK_SEQPACKET
 * pair of its own, at FZ_CHANNEL_FD and FZ_CHANNEL_PEER_FD, so a park
 * dumps the pair whole. The identity is never a file, since every
 * grant's fibers run as fiberd's user and no file mode would keep them
 * apart.
 *
 * A park is cooperative. fiberd queues the park's round on the channel
 * and sends the fiber SIGUSR1. The template stops serving, closes its
 * listener and every connection, calls fz_quiesce and then
 * fz_incarnation_wait. A fiber that does not answer in time is not
 * parked and gets a carry-on for that round. A resume restores the tree
 * and sends a record of kind "resume". The template reseeds, listens
 * again and calls fz_fiber_ready, and fiberd routes it only after that
 * ack.
 *
 *   fiberd -> fiber   'p' <round> NUL     a park, before the signal
 *   fiber  -> fiberd  'q' <round> NUL     the fiber serves nothing, dump it
 *   fiberd -> fiber   'i' ... (kind "resume"), after the restore
 *   fiberd -> fiber   'c' <round> NUL     that park failed, serve on as you were
 *   fiber  -> fiberd  'a' <fence> NUL     listening again under the new fence
 *
 * An engine zygote, one that owns device state its fibers use over IPC,
 * adds these lines, unsolicited, from any thread.
 *
 *   zygote -> fiberd  DEVICE <fence> <bytes> 0        one fiber's slice
 *   zygote -> fiberd  DEVICE - <used> <capacity>      the whole engine
 *
 * It receives this one before a fiber is parked.
 *
 *   fiberd -> zygote  EVICT <fence>                   drop that slice
 */
#ifndef FIBERZYGOTE_H
#define FIBERZYGOTE_H

/* The ABI this header describes, which every binding checks at build
 * time. */
#define FZ_ABI_VERSION 10

#include <stddef.h>

/* A handoff fiber's TLS identity, held in the fiber's memory only, so no
 * key lands in a template checkpoint. key_pem and cert_pem are the
 * grant's PKCS #8 key and self-signed certificate. caller is the
 * thumbprint (x5t#S256, base64url) of the one client certificate the
 * fiber may accept, and caller_pem is that certificate, for a TLS
 * library that trusts it alone. */
typedef struct {
    const char *key_pem;
    const char *cert_pem;
    const char *caller;
    const char *caller_pem;
} fz_identity_t;

/* What a fiber learns at birth or resume, from its incarnation record.
 * The generation counts the lineage. A fiber from the warm template is
 * 1, and a resumed fiber is the parked one's plus one. The seed is
 * zeroed at fz_fiber_ready, fz_gvisor_ack and fz_seed_forget, so a
 * checkpoint holds no seed. */
typedef struct {
    const char *fence;            /* the fiber's identity, "grant/epoch/seq" */
    const char *endpoint;         /* unix socket path or tcp://host:port the fiber serves on,
                                     or "handoff" when it serves fz_accept() instead */
    const unsigned char *payload; /* opaque data delivered at birth */
    size_t payload_len;
    const char *session;          /* the session the caller named, "" for an anonymous fiber */
    unsigned generation;          /* 1: a fork of the warm template starts a lineage */
    const char *kind;             /* "fork" (proc, runc), "clone" (a gVisor restore of the image) or "resume" (a park brought back) */
    const unsigned char *seed;    /* 32 bytes of fresh entropy from the host, zeroed once ready */
    size_t seed_len;
    const fz_identity_t *identity; /* a handoff fiber's TLS identity, NULL on every other fiber */
} fz_incarnation_t;

/* Runs in the CHILD after the scrub. Serve on f->endpoint, call
 * fz_fiber_ready() once listening, then do the fiber's work. The return
 * value becomes the exit code.
 *
 * Every fiber is a copy of the zygote's memory, random generators
 * included, and the library reseeds none of them. Reseed each one here
 * from f->seed mixed with getrandom(2), and again in every new
 * incarnation (a restore, a resume), as refzygote's reseed_rngs_from
 * does. CRIU keeps the pid, so a pid check sees no copy.
 *
 * The child copies only the thread that called fz_serve, and no atfork
 * handler runs. A lock another zygote thread held at the clone, malloc's
 * or a stream's, stays held, so such threads keep allocation and stdio
 * rare. */
typedef int (*fz_on_fiber)(const fz_incarnation_t *f);

/* Runs in the ZYGOTE for every control line that is not CLONE, HIDE,
 * DROP or RUNDIR, such as EVICT <fence>. */
typedef void (*fz_on_control)(const char *line);

/* Call first thing in main(), before any allocation and any thread. It
 * turns off address-space randomisation and re-execs argv, so the
 * layout is reproducible and a fiber's checkpoint is a delta over the
 * zygote's pages. It blocks SIGCHLD for fz_serve's loop (a fiber starts
 * with it unblocked). With FIBERD_OWN_MNTNS it also takes a private
 * mount namespace, which needs CAP_SYS_ADMIN and no thread yet.
 * Otherwise fz_serve refuses every mntns CLONE and serves the rest. */
void fz_init(int argc, char **argv);

/* Zygote main loop. Returns 0 when fiberd closes the channel, -1 on a
 * protocol or system error (errno set). It refuses to serve, with EINVAL
 * and a line on stderr, when SIGCHLD is not blocked, which means fz_init
 * was skipped. */
int fz_serve(int ctl_fd, fz_on_fiber on_fiber);

/* Called by on_fiber in the child once its endpoint accepts connections,
 * in every incarnation. At birth it reports on the readiness pipe (fd
 * 3, not the fiber's to use), then points stderr at /dev/null and zeroes
 * the seed. Until then stderr is the zygote's log. A child that closes
 * or misuses the pipe is killed and its CLONE answered with ERROR. After
 * a resume it acks on the channel instead, and fiberd routes the fiber
 * only after that ack. */
void fz_fiber_ready(void);

/* A fiber's channel, named by FIBERD_CHANNEL_FD in its environment, and
 * its peer, the end fiberd borrows when the fiber serves its own
 * endpoint. Neither is the fiber's to read, write or close.
 *
 * The fiber-side calls (fz_fiber_ready, fz_accept, fz_quiesce,
 * fz_incarnation_wait, fz_seed_forget, fz_gvisor_identity and
 * fz_gvisor_ack) share state, so they must never overlap. Make one at a
 * time, never from a signal handler. Any thread may make the next. */
#define FZ_CHANNEL_FD 4
#define FZ_CHANNEL_PEER_FD 5

/* Answers a park's SIGUSR1 for the round fiberd queued. Call it with the
 * listener and every connection closed and nothing in flight, since the
 * dump keeps what it finds. Returns 0, or -1 with errno set (EBADF with
 * no channel, as in a gVisor sandbox). Then call fz_incarnation_wait. */
int fz_quiesce(void);

/* Blocks for fiberd's answer to fz_quiesce.
 *
 *   1   the fiber was dumped and restored, and *inc is the resume's
 *       record, valid until the next call. Reseed, listen again on
 *       inc->endpoint and call fz_fiber_ready.
 *   0   the park failed or gave up. Listen again and serve on.
 *   -1  with errno EINTR (a handler ran, call again), EBADF (no
 *       channel), EPROTO (not a record) or ECONNRESET (fiberd closed a
 *       handoff fiber's channel).
 *
 * A record of a generation already served is dropped, and a connection
 * handed to a handoff fiber meanwhile is closed. Each call zeroes the
 * seed the previous one handed over. */
int fz_incarnation_wait(fz_incarnation_t *inc);

/* Zeroes every seed the library holds. Call it once the generators are
 * reseeded, so no seed is in memory when the fiber is parked. */
void fz_seed_forget(void);

/* Blocks for the next connected socket fiberd accepted for a handoff
 * fiber and returns it with close-on-exec set, or -1 with errno set.
 * EBADF means not a handoff fiber, ECONNRESET that fiberd closed the
 * channel. EINTR means a signal handler ran or a park's round arrived,
 * so the template's loop checks its park flag before calling again. */
int fz_accept(void);

/* gVisor templates. Nothing forks on gVisor. Every fiber is a sandbox
 * restored from the template's checkpoint. Once restored, the template
 * calls fz_gvisor_identity, which hands the spec's one-shot FIBERD_TOKEN
 * to fiberd at /fiberd/channel/pool.sock and blocks for the incarnation
 * record. It then reseeds, binds the endpoint and calls fz_gvisor_ack.
 *
 *   sandbox -> fiberd  't' <token> NUL
 *   fiberd  -> sandbox 'i' ... (the record above, kind "clone" or "resume", no identity)
 *   sandbox -> fiberd  'a' <fence> NUL
 */

/* Blocks for this sandbox's record, valid until the next call. The
 * endpoint is the unix socket path to serve, under /host. -1 with
 * errno set on failure, and the template then exits with 122. */
int fz_gvisor_identity(fz_incarnation_t *id);

/* Tells fiberd the endpoint is bound, closes the channel and zeroes the
 * seed. */
int fz_gvisor_ack(void);

/* Engine support. fz_set_engine names the engine's IPC endpoint, which
 * every fiber finds as FIBERD_ENGINE. fz_set_control installs the
 * handler for lines such as EVICT. Bind a unix endpoint under the run
 * directory before fz_serve, which remounts that directory.
 *
 * fz_report_line sends one line the template formatted, without its
 * newline, to fiberd from any thread (a DEVICE report). The library
 * appends the newline and writes it whole, never interleaved. It
 * returns 0, or -1 with errno set.
 *
 *   EMSGSIZE  the line is FZ_REPORT_MAX characters or longer. It is
 *             refused whole, never cut.
 *   EINVAL    the line is NULL or holds a newline.
 *   EBADF     no channel yet, and always in a fiber.
 *   other     the write to fiberd failed. */
#define FZ_REPORT_MAX 1024
void fz_set_engine(const char *endpoint);
int fz_report_line(const char *line);
void fz_set_control(fz_on_control handler);

#endif
