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
 *     fiberd's paths covered, a /proc of its own pid namespace, and no
 *     capabilities under no_new_privs. The grant-wide part of that
 *     namespace (read-only /sys, the run directory narrowed, the HIDE
 *     directories covered) is made once, in a mount namespace the
 *     zygote takes for itself in fz_init and fills before READY, so a
 *     fiber's namespace is a copy and its birth pays only for what is
 *     its own.
 *   - Identity (the fence, the seed, a handoff fiber's key) is handed to
 *     the child after the fork, on its channel, and is never baked into
 *     the template.
 *   - Readiness is reported when the application says so, under the
 *     deadline fiberd set. A late child is killed, not delivered.
 *   - Clones are forked back to back. The loop polls every pending
 *     child's readiness pipe at once, so under a storm each request is
 *     acknowledged when its own child is ready, never behind the others.
 *
 * With FIBERD_CTL_REBIND set in its environment, fz_serve first reads a
 * REBIND message carrying a socket on the control descriptor and serves
 * on that socket instead. fiberd made it in the zygote's network
 * namespace, where a checkpoint of the zygote finds it.
 *
 * With FIBERD_OWN_MNTNS set in its environment, fz_init moves the zygote
 * into a private mount namespace of its own, and fz_serve fills it
 * before READY with what every mntns fiber must see (PREPARE mntns
 * below), so a fiber's namespace is a copy. fiberd sets it when its
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
 * fiberd speaks first. Its setup lines, ended by PREPARE, come before
 * READY, because the zygote prepares what every mntns fiber's namespace
 * must have once, in a namespace of its own, and answers READY from it.
 *
 *   fiberd -> zygote  HIDE <dir>
 *                     Cover dir with an empty tmpfs in every mntns fiber.
 *   fiberd -> zygote  DROP <path>
 *                     Unmount path in every mntns fiber.
 *   fiberd -> zygote  RUNDIR <parent> <own>
 *                     In every mntns fiber, cover parent (fiberd's run
 *                     directory, one directory per grant) with an empty
 *                     read-only tmpfs and bind only own, this grant's
 *                     directory, back at its place.
 *   fiberd -> zygote  PREPARE mntns|none
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
 *                     namespace and fiberd fails the warm. Any other
 *                     line before PREPARE, or a setup line after READY,
 *                     is a protocol error. The first ends the zygote and
 *                     the second refuses every mntns CLONE.
 *   zygote -> fiberd  READY
 *   fiberd -> zygote  CLONE <fence> <endpoint> <deadline_ms> <hex-payload|-> <hex-session|-> [opts]
 *                     The fence is at most 127 characters and the endpoint
 *                     at most 1023. The session is the name the caller
 *                     gave the Clone, hex so it may hold any character,
 *                     "-" for an anonymous fiber, and at most 1023 bytes
 *                     decoded with no NUL in them. The fiber also finds
 *                     it as FIBERD_SESSION in its environment, unset
 *                     when anonymous. The fiber's cgroup directory fd,
 *                     when fiberd has one, and then the fiber's channel
 *                     ride along in SCM_RIGHTS on the same message. The
 *                     channel is the last descriptor, the fiber's end of
 *                     a SOCK_SEQPACKET pair, kept at FZ_CHANNEL_FD. opts
 *                     is a comma list. "pidns" makes the child the init
 *                     of its own pid namespace. "mntns" gives it a
 *                     private mount namespace. "nocaps" drops every
 *                     capability under no_new_privs. A child that cannot
 *                     get what it was asked for ends before it runs, and
 *                     the CLONE is answered with an ERROR. So is a mntns
 *                     CLONE after a refused HIDE, DROP, RUNDIR or
 *                     PREPARE, or after PREPARE none, or a CLONE without
 *                     a channel.
 *   zygote -> fiberd  CLONED <fence> <pid>
 *   zygote -> fiberd  ERROR <fence> <reason>
 *                     For a child that ended before ready, the reason is
 *                     "died before ready: exit:<code>", followed by what
 *                     the code stands for when the library assigned it.
 *                     110-115 and 117 are the confinement steps (116 is
 *                     retired, since the zygote narrows the run directory
 *                     at PREPARE), 120 the descriptors, 121 the
 *                     incarnation record and 125 the cgroup leaf on the
 *                     legacy clone.
 *   zygote -> fiberd  EXITED <pid> exit:<code>|signal:<num>
 *
 * On every fiber's channel the first message, queued by fiberd before
 * the CLONE, is the fiber's incarnation record, the same record a
 * gVisor sandbox reads (fz_gvisor_identity below).
 *
 *   fiberd -> fiber   'i' <generation> NUL <kind> NUL <fence> NUL <endpoint> NUL <payload-hex|-> NUL
 *                     <session-hex|-> NUL <key PEM|-> NUL <cert PEM|-> NUL <caller|-> NUL <caller cert PEM|-> NUL <seed-hex> NUL
 *
 * The library reads it in the child before the application runs, into
 * the child's memory and never the zygote's, and hands it to on_fiber as
 * fz_incarnation_t. On a handoff fiber the record carries the grant's
 * TLS identity, the channel stays open at FZ_CHANNEL_FD and every
 * message after it carries one connected socket in SCM_RIGHTS (see
 * fz_accept). Any other fiber's record has "-" in those four fields,
 * and the library then closes fiberd's end and makes the fiber a
 * SOCK_SEQPACKET pair of its own, the end it reads at FZ_CHANNEL_FD
 * and the peer at FZ_CHANNEL_PEER_FD. The fiber holds both, so a park
 * dumps the pair whole and a restore remakes it inside the fiber's own
 * namespaces. A fiber resumed from a park is sent a second record on
 * that channel, kind "resume", with the new fence, the next generation
 * and a fresh seed: fiberd borrows the peer end of the restored tree
 * with pidfd_getfd(2), writes the record and closes its copy. A handoff
 * fiber gets it on the fresh channel end the restore hands it, ahead
 * of any connection. The template reads it with fz_incarnation_poll.
 * The identity is never a file.
 * Every grant's fibers run as fiberd's user, so no file mode would keep
 * one grant's fibers out of another's key. The caller cert is the
 * certificate the clone arrived under, the one the thumbprint is of, so
 * a TLS library can trust that certificate alone and refuse every other
 * during the handshake.
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

/* The ABI this header describes, which every binding checks at build time.
 * 3 added session to the gVisor identity. 4 added a fourth field to
 * fz_identity_t, which 5 made the caller's certificate (caller_pem). 6
 * added generation and kind. 7 made fz_incarnation_t the one record on
 * every backend, with the seed and the identity in it, and gave every
 * fiber a channel at FZ_CHANNEL_FD. 8 made that channel a pair the
 * fiber keeps across parks, delivered a resume's record on it and added
 * fz_incarnation_poll and fz_seed_forget. */
#define FZ_ABI_VERSION 8

#include <stddef.h>

/* A handoff fiber terminates TLS itself with the grant's identity, which
 * rides on its incarnation record and the library holds in the fiber's
 * memory, never the zygote's, so no key ends up in a template
 * checkpoint. key_pem and cert_pem are the grant's PKCS #8 private key
 * and self-signed certificate. caller is the thumbprint (x5t#S256,
 * base64url) of the one client certificate the fiber may accept, and
 * caller_pem is that certificate, for a TLS library that trusts one
 * certificate as its anchor and so refuses every other in the
 * handshake. */
typedef struct {
    const char *key_pem;
    const char *cert_pem;
    const char *caller;
    const char *caller_pem;
} fz_identity_t;

/* What a fiber learns at birth, from the incarnation record on its
 * channel. The generation is fiberd's count of the lineage. A fiber born
 * from the warm template, forked or restored from its image, is 1. A
 * fiber resumed from a park is the parked one's plus one, on whichever
 * home resumes it. A template that counts its own incarnations can tell
 * a missed one from the number. The seed is 32 bytes of fresh entropy
 * from the host, to mix into every generator the template owns (see
 * fz_on_fiber). It is zeroed at fz_fiber_ready, at fz_gvisor_ack and at
 * fz_seed_forget, so a checkpoint holds no seed. */
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
 * value becomes the process exit code.
 *
 * Every fiber starts as a copy of the zygote's memory, including every
 * random generator the application seeded during its initialization
 * (libc's random(), a TLS library's DRBG, a language runtime's hash
 * seed, a UUID generator). The library reseeds none of them, because it
 * takes no lock between the clone and this call, and srandom takes one.
 * Reseed each of them here from f->seed mixed with getrandom(2), before
 * it is used, as refzygote's reseed_rngs_from does. A fork is not the
 * only copy. A sandbox restored from a checkpoint and a fiber resumed
 * from a park (CRIU keeps the pid, so a pid check sees no copy) hold
 * that state too. Reseed again in every new incarnation, which is when
 * a restore returns and when fz_incarnation_poll hands over a resume's
 * record, as refzygote does. A generator that makes keys is best
 * reseeded before each use as well, as refzygote does before every TLS
 * handshake.
 *
 * The child is a copy of the one thread that called fz_serve. A lock
 * another thread of the zygote (an engine) held at the clone stays held
 * in the copy, malloc's and a stream's included, since the raw clone
 * runs no atfork handlers. A template with threads of its own keeps
 * their allocation and stdio rare, or stops them around clones. */
typedef int (*fz_on_fiber)(const fz_incarnation_t *f);

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

/* Zygote main loop. Returns 0 when fiberd closes the channel, -1 on a
 * protocol or system error (errno set). It refuses to serve, with EINVAL
 * and a line on stderr, when SIGCHLD is not blocked, which means fz_init
 * was skipped. */
int fz_serve(int ctl_fd, fz_on_fiber on_fiber);

/* Called by on_fiber in the child once its endpoint accepts connections.
 * Until then fiberd has not acknowledged the clone, and the child's
 * stderr is the zygote's log, for saying why it could not start. After
 * it, stderr is /dev/null, and the record's seed is zeroed. The
 * readiness pipe is fd 3 and is not the fiber's to use. A fiber that
 * writes anything else on it, or closes it without calling this, is
 * killed and its CLONE answered with ERROR. */
void fz_fiber_ready(void);

/* Where a fiber's channel lives, named by FIBERD_CHANNEL_FD in its
 * environment. Every fiber reads its birth record off it, a handoff
 * fiber then takes its connections from it through fz_accept, and every
 * fiber takes a resume's record from it through fz_incarnation_poll. A
 * fiber that serves an endpoint of its own holds the channel's peer at
 * FZ_CHANNEL_PEER_FD too, the end fiberd borrows after a restore.
 * Neither is the fiber's to read, write or close. */
#define FZ_CHANNEL_FD 4
#define FZ_CHANNEL_PEER_FD 5

/* A resume's record, when one has arrived on the channel since the last
 * call: 1 with *inc filled, valid until the next call. 0 when none has.
 * -1 with errno set: EBADF in a process with no channel (a gVisor
 * sandbox), EPROTO for a message that is not a well-formed record, and
 * ECONNRESET once fiberd has closed a handoff fiber's channel. It never
 * blocks, so a template calls it before each connection it serves, as
 * refzygote does, and reseeds from inc->seed when it answers 1. A
 * record of a generation the fiber has already served is dropped. On a
 * handoff fiber a connection that arrives meanwhile is kept for the
 * next fz_accept. Each call zeroes the seed the previous one handed
 * over, and fz_seed_forget zeroes it sooner. */
int fz_incarnation_poll(fz_incarnation_t *inc);

/* Zeroes every copy of a seed the library holds, the birth record's and
 * the last polled record's. Call it once the generators are reseeded,
 * so no seed is in memory when the fiber is parked. fz_fiber_ready and
 * fz_gvisor_ack do it for the birth record. */
void fz_seed_forget(void);

/* Handoff fibers do not listen. fiberd accepts on their behalf and
 * passes each connected socket here. fz_accept blocks until the next one
 * and returns it with close-on-exec set, or -1 with errno set. EBADF
 * means the fiber is not a handoff fiber. ECONNRESET means fiberd has
 * closed the channel and the fiber is being released. */
int fz_accept(void);

/* gVisor templates. Nothing forks on gVisor. Every fiber is a sandbox
 * restored from the template's checkpoint. After its checkpoint read
 * answers "restore", the template calls fz_gvisor_identity, which hands
 * the spec's one-shot FIBERD_TOKEN to fiberd at
 * /fiberd/channel/pool.sock and blocks for the incarnation record, the
 * 'i' record above. It then reseeds, binds the endpoint and calls
 * fz_gvisor_ack, which zeroes the seed.
 *
 *   sandbox -> fiberd  't' <token> NUL
 *   fiberd  -> sandbox 'i' ... (the record above, kind "clone" or "resume", no identity)
 *   sandbox -> fiberd  'a' <fence> NUL
 *
 * The session is hex so a name may hold any character, "-" for an
 * anonymous fiber, and at most 1023 bytes decoded with no NUL in them,
 * as on the CLONE line. The generation is decimal, 1 or more, as
 * fz_incarnation_t describes it.
 */

/* Blocks for this sandbox's record, valid until the next call. The
 * endpoint is the unix socket path to serve, under /host. -1 with
 * errno set on failure, and the template then exits with 122. */
int fz_gvisor_identity(fz_incarnation_t *id);

/* Tells fiberd the endpoint is bound, closes the channel and zeroes the
 * seed. */
int fz_gvisor_ack(void);

/* Engine support. fz_set_engine names the engine's IPC endpoint, which
 * every fiber finds as FIBERD_ENGINE in its scrubbed environment.
 * fz_report sends one line to fiberd from any thread (a DEVICE
 * report). It fails with -1 before fz_serve has the channel, and always
 * in a fiber, which has no channel to fiberd. fz_set_control installs
 * the handler for lines such as EVICT. Bind a unix endpoint under the
 * run directory before fz_serve, which remounts that directory. */
void fz_set_engine(const char *endpoint);
int fz_report(const char *fmt, ...) __attribute__((format(printf, 1, 2)));
void fz_set_control(fz_on_control handler);

#endif
