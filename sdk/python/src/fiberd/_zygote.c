/* _zygote is the CPython binding of libfiberzygote (sdk/c/template), the one part
 * of fiberd.template that must be C. It is built against the limited API
 * so one wheel serves every CPython from 3.14, compiled under the
 * Makefile's ZYGOTE_CFLAGS, and linked with the library's archive (see
 * setup.py).
 *
 * What it does that Python cannot. The library forks a fiber with a raw
 * clone and runs no atfork handler, so the child starts as a byte copy
 * of the one thread that called fz_serve with the GIL released. serve()
 * runs PyOS_BeforeFork once in the zygote, lets go of the GIL and blocks
 * in fz_serve. The trampoline below is the first thing that runs in a
 * child. It takes the GIL back with the zygote's thread state, runs
 * PyOS_AfterFork_Child, which reinitialises the GIL and the runtime
 * locks, resets the main thread and runs every os.register_at_fork
 * after_in_child hook, and only then calls the Python callback with the
 * fiber's record (its seed as a bytearray the SDK zeroes after the
 * hooks, its identity as a tuple or None) and the C environ, which the
 * scrub has replaced. A park's wait (incarnation_wait) blocks in C
 * without the GIL, so the SDK waits in slices of its own first.
 * Everything else, the rules, the incarnation hooks and the accept loop,
 * is fiberd.template. */
#define PY_SSIZE_T_CLEAN
#define Py_LIMITED_API 0x030E0000
#include <Python.h>

#include <errno.h>
#include <stdlib.h>
#include <string.h>

#include "libfiberzygote.h"

#if FZ_ABI_VERSION != 10
#error "fiberd._zygote binds FZ_ABI_VERSION 10; rebuild it against this header"
#endif
#ifdef Py_GIL_DISABLED
#error "fiberd._zygote needs the GIL; the fork rules assume it and abi3 does not cover a free-threaded build"
#endif

extern char **environ;

/* The callback serve() was given, and the zygote's thread state while
 * fz_serve runs without the GIL. Both are read in the child. */
static PyObject *on_fiber_cb;
static PyThreadState *serve_ts;

/* environ_dict is the C environ as a dict of str, which in the child is
 * the fiber's scrubbed FIBERD_ entries. Undecodable bytes take the
 * filesystem encoding's escape, as os.environ does. */
static PyObject *environ_dict(void) {
    PyObject *d = PyDict_New();
    if (!d) return NULL;
    for (char **e = environ; e && *e; e++) {
        const char *eq = strchr(*e, '=');
        if (!eq) continue;
        PyObject *k = PyUnicode_DecodeFSDefaultAndSize(*e, (Py_ssize_t)(eq - *e));
        PyObject *v = PyUnicode_DecodeFSDefault(eq + 1);
        int rc = k && v ? PyDict_SetItem(d, k, v) : -1;
        Py_XDECREF(k);
        Py_XDECREF(v);
        if (rc < 0) { Py_DECREF(d); return NULL; }
    }
    return d;
}

/* identity_tuple is a record's handoff identity as (key_pem, cert_pem,
 * caller, caller_pem), or None on a fiber that has none. */
static PyObject *identity_tuple(const fz_identity_t *id) {
    if (!id) Py_RETURN_NONE;
    return Py_BuildValue("(ssss)", id->key_pem, id->cert_pem, id->caller, id->caller_pem);
}

/* seed_bytearray is a record's seed as a bytearray, which the SDK zeroes
 * once the incarnation hooks have run. */
static PyObject *seed_bytearray(const fz_incarnation_t *f) {
    return PyByteArray_FromStringAndSize((const char *)f->seed, (Py_ssize_t)f->seed_len);
}

/* trampoline runs in the child before any Python. Its return value is the
 * fiber's exit code, as the library ends the process with it. A callback
 * that raised is a fiber that failed to start, written to stderr, which
 * is still the zygote's log until the fiber reports ready. */
static int trampoline(const fz_incarnation_t *f) {
    PyEval_RestoreThread(serve_ts);
    PyOS_AfterFork_Child();
    PyObject *env = environ_dict();
    PyObject *seed = seed_bytearray(f);
    PyObject *identity = identity_tuple(f->identity);
    PyObject *res = NULL;
    if (env && seed && identity) {
        res = PyObject_CallFunction(on_fiber_cb, "ssy#sOIsOO", f->fence, f->endpoint,
                                    (const char *)f->payload, (Py_ssize_t)f->payload_len, f->session, env,
                                    f->generation, f->kind, seed, identity);
    }
    Py_XDECREF(env);
    Py_XDECREF(seed);
    Py_XDECREF(identity);
    int rc = 1;
    if (!res) {
        PyErr_Print();
    } else {
        long code = PyLong_AsLong(res);
        if (code == -1 && PyErr_Occurred()) {
            PyErr_Print();
        } else {
            rc = (int)(code & 0xff);
        }
        Py_DECREF(res);
    }
    return rc;
}

static PyObject *py_init(PyObject *self, PyObject *arg) {
    (void)self;
    if (!PyList_Check(arg)) {
        PyErr_SetString(PyExc_TypeError, "init() takes a list of str, sys.orig_argv");
        return NULL;
    }
    Py_ssize_t n = PyList_Size(arg);
    PyObject **encoded = PyMem_Calloc((size_t)n + 1, sizeof *encoded);
    char **argv = PyMem_Calloc((size_t)n + 1, sizeof *argv);
    if (!encoded || !argv) {
        PyMem_Free(encoded);
        PyMem_Free(argv);
        return PyErr_NoMemory();
    }
    int ok = 1;
    for (Py_ssize_t i = 0; i < n && ok; i++) {
        encoded[i] = PyUnicode_EncodeFSDefault(PyList_GetItem(arg, i));
        if (!encoded[i] || PyBytes_AsStringAndSize(encoded[i], &argv[i], NULL) < 0) ok = 0;
    }
    /* Returns only when address-space randomisation was already off, or
     * the re-exec failed. Otherwise the process is replaced here. */
    if (ok) fz_init((int)n, argv);
    for (Py_ssize_t i = 0; i < n; i++) Py_XDECREF(encoded[i]);
    PyMem_Free(encoded);
    PyMem_Free(argv);
    if (!ok) return NULL;
    Py_RETURN_NONE;
}

static PyObject *py_serve(PyObject *self, PyObject *args) {
    (void)self;
    PyObject *cb;
    int ctl_fd = 3;
    if (!PyArg_ParseTuple(args, "O|i:serve", &cb, &ctl_fd)) return NULL;
    if (!PyCallable_Check(cb)) {
        PyErr_SetString(PyExc_TypeError, "serve() takes a callable");
        return NULL;
    }
    Py_INCREF(cb);
    Py_XDECREF(on_fiber_cb);
    on_fiber_cb = cb;
    /* The fork hooks around fz_serve, which os.fork would run around its
     * one fork. The parent half runs once, when fiberd closes the channel. */
    PyOS_BeforeFork();
    serve_ts = PyEval_SaveThread();
    int rc = fz_serve(ctl_fd, trampoline);
    int e = errno;
    PyEval_RestoreThread(serve_ts);
    PyOS_AfterFork_Parent();
    if (rc < 0) {
        errno = e;
        return PyErr_SetFromErrno(PyExc_OSError);
    }
    return PyLong_FromLong(rc);
}

static PyObject *py_fiber_ready(PyObject *self, PyObject *unused) {
    (void)self; (void)unused;
    fz_fiber_ready();
    Py_RETURN_NONE;
}

static PyObject *py_accept(PyObject *self, PyObject *unused) {
    (void)self; (void)unused;
    int fd;
    Py_BEGIN_ALLOW_THREADS
    fd = fz_accept();
    Py_END_ALLOW_THREADS
    if (fd < 0) return PyErr_SetFromErrno(PyExc_OSError);
    return PyLong_FromLong(fd);
}

static PyObject *py_gvisor_identity(PyObject *self, PyObject *unused) {
    (void)self; (void)unused;
    fz_incarnation_t id;
    int rc;
    Py_BEGIN_ALLOW_THREADS
    rc = fz_gvisor_identity(&id);
    Py_END_ALLOW_THREADS
    if (rc < 0) return PyErr_SetFromErrno(PyExc_OSError);
    PyObject *seed = seed_bytearray(&id);
    if (!seed) return NULL;
    PyObject *out = Py_BuildValue("(sssy#OsI)", id.kind, id.fence, id.endpoint,
                                  (const char *)id.payload, (Py_ssize_t)id.payload_len, seed, id.session, id.generation);
    Py_DECREF(seed);
    return out;
}

/* py_quiesce is fz_quiesce: the fiber's word that it serves nothing. */
static PyObject *py_quiesce(PyObject *self, PyObject *unused) {
    (void)self; (void)unused;
    if (fz_quiesce() < 0) return PyErr_SetFromErrno(PyExc_OSError);
    Py_RETURN_NONE;
}

/* py_incarnation_wait is fz_incarnation_wait: the resume's record as
 * gvisor_identity returns one, with the library's copy of the seed
 * zeroed once the bytearray holds it, or None when fiberd says the
 * park failed and the fiber serves on. It blocks without the GIL, so
 * the SDK calls it once the channel is readable, in slices it waits
 * out in select with the stop flag checked. A signal's EINTR runs the
 * Python handler and comes back as InterruptedError when it raised
 * nothing. */
static PyObject *py_incarnation_wait(PyObject *self, PyObject *unused) {
    (void)self; (void)unused;
    fz_incarnation_t inc;
    int rc;
    Py_BEGIN_ALLOW_THREADS
    rc = fz_incarnation_wait(&inc);
    Py_END_ALLOW_THREADS
    if (rc < 0) {
        if (errno == EINTR && PyErr_CheckSignals() < 0) return NULL;
        return PyErr_SetFromErrno(PyExc_OSError);
    }
    if (rc == 0) Py_RETURN_NONE;
    PyObject *seed = seed_bytearray(&inc);
    fz_seed_forget();
    if (!seed) return NULL;
    PyObject *out = Py_BuildValue("(sssy#OsI)", inc.kind, inc.fence, inc.endpoint,
                                  (const char *)inc.payload, (Py_ssize_t)inc.payload_len, seed, inc.session, inc.generation);
    Py_DECREF(seed);
    return out;
}

static PyObject *py_gvisor_ack(PyObject *self, PyObject *unused) {
    (void)self; (void)unused;
    if (fz_gvisor_ack() < 0) return PyErr_SetFromErrno(PyExc_OSError);
    Py_RETURN_NONE;
}

static PyMethodDef methods[] = {
    {"init", py_init, METH_O, "init(argv): fz_init, which re-execs argv once with address-space randomisation off."},
    {"serve", py_serve, METH_VARARGS, "serve(on_fiber, ctl_fd=3): fz_serve with the fork hooks; on_fiber(fence, endpoint, payload, session, env, generation, kind, seed, identity) runs in each child."},
    {"fiber_ready", py_fiber_ready, METH_NOARGS, "fz_fiber_ready, which zeroes the library's copy of the seed and acks a resume."},
    {"accept", py_accept, METH_NOARGS, "fz_accept: the next handed-off connection's descriptor."},
    {"gvisor_identity", py_gvisor_identity, METH_NOARGS, "fz_gvisor_identity as (kind, fence, endpoint, payload, seed, session, generation)."},
    {"gvisor_ack", py_gvisor_ack, METH_NOARGS, "fz_gvisor_ack."},
    {"quiesce", py_quiesce, METH_NOARGS, "fz_quiesce: the fiber serves nothing and may be dumped."},
    {"incarnation_wait", py_incarnation_wait, METH_NOARGS, "fz_incarnation_wait: a resume's record as gvisor_identity shapes one, or None when the park failed."},
    {NULL, NULL, 0, NULL}
};

static struct PyModuleDef module = {
    PyModuleDef_HEAD_INIT, "fiberd._zygote", "The libfiberzygote binding. Use fiberd.template.", -1, methods,
    NULL, NULL, NULL, NULL
};

PyMODINIT_FUNC PyInit__zygote(void) {
    PyObject *m = PyModule_Create(&module);
    if (!m) return NULL;
    if (PyModule_AddIntConstant(m, "ABI_VERSION", FZ_ABI_VERSION) < 0 ||
        PyModule_AddIntConstant(m, "CHANNEL_FD", FZ_CHANNEL_FD) < 0) {
        Py_DECREF(m);
        return NULL;
    }
    return m;
}
