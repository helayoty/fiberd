/* fakecuda: a stand-in libcuda.so.1 so the engine's CUDA path runs in CI
 * with no GPU.
 *
 * It exports the subset of the CUDA driver API the engine calls, under the
 * real names. Where the real driver exports a _v2 entry point (the 64-bit
 * CUdeviceptr and size_t ABI), only the _v2 name is here. The CUresult
 * codes and device attributes carry the values cuda.h gives them.
 *
 * There is one device at most. Its memory is host memory from mmap. A
 * CUdeviceptr is an opaque handle into a fake address space that the
 * library never dereferences. Every copy and memset looks the handle up,
 * so an unknown or freed pointer, or a range that runs past its
 * allocation, is CUDA_ERROR_INVALID_VALUE. Freed addresses are never
 * handed out again. One mutex guards all of it, and the current context
 * is per thread, as in the real driver.
 *
 * Every call but cuDriverGetVersion, cuGetErrorName and cuGetErrorString
 * returns CUDA_ERROR_NOT_INITIALIZED before cuInit. Those three work
 * without it in the real driver too, and an engine needs the names to
 * report a failed cuInit.
 *
 * The environment is read once, at the first cuInit.
 *
 *   FAKECUDA_NAME          the device name (default "fakecuda")
 *   FAKECUDA_CC            compute capability "major.minor" (default 8.0)
 *   FAKECUDA_MEM_MB        total device memory in MiB (default 1024)
 *   FAKECUDA_UUID          the device UUID, GPU-xxxxxxxx-xxxx-xxxx-xxxx-
 *                          xxxxxxxxxxxx (a fixed default otherwise)
 *   FAKECUDA_MIG_UUID      a MIG- UUID in the same form. When the first
 *                          CUDA_VISIBLE_DEVICES entry names it, the device
 *                          is that MIG instance. Its name ends in " MIG"
 *                          and cuDeviceGetUuid_v2 returns the MIG UUID.
 *   FAKECUDA_STICKY_AFTER  N > 0 makes the Nth memory call (alloc, free,
 *                          memset, either copy) and every later context
 *                          call fail with CUDA_ERROR_ILLEGAL_ADDRESS, a
 *                          sticky error. Unset or 0 is off.
 *   FAKECUDA_DRIVER        what cuDriverGetVersion reports (default 13000)
 *
 * CUDA_VISIBLE_DEVICES is honored as the real driver honors its first
 * entry. Unset shows the device. An ordinal 0, the device's GPU- UUID or
 * the FAKECUDA_MIG_UUID shows it. Anything else, the empty string
 * included, shows zero devices, and cuInit returns CUDA_ERROR_NO_DEVICE.
 * UUIDs must match in full, without the real driver's prefix match.
 *
 * A malformed knob makes cuInit fail with CUDA_ERROR_INVALID_VALUE and
 * name the knob on stderr, so a typo in a test never runs on defaults.
 *
 * Build: make fakecuda (bin/fakecuda/libcuda.so.1, Linux only)
 * Run:   LD_LIBRARY_PATH=bin/fakecuda FAKECUDA_MEM_MB=64 <engine>
 */
#define _GNU_SOURCE

#include <limits.h>
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <unistd.h>

#define API __attribute__((visibility("default")))

/* CUresult (enum cudaError_enum in cuda.h). Only the codes used here. */
typedef enum cudaError_enum {
    CUDA_SUCCESS = 0,
    CUDA_ERROR_INVALID_VALUE = 1,
    CUDA_ERROR_OUT_OF_MEMORY = 2,
    CUDA_ERROR_NOT_INITIALIZED = 3,
    CUDA_ERROR_NO_DEVICE = 100,
    CUDA_ERROR_INVALID_DEVICE = 101,
    CUDA_ERROR_INVALID_CONTEXT = 201,
    CUDA_ERROR_ILLEGAL_ADDRESS = 700,
    CUDA_ERROR_UNKNOWN = 999,
} CUresult;

/* CUdevice_attribute (enum CUdevice_attribute_enum in cuda.h). */
typedef enum CUdevice_attribute_enum {
    CU_DEVICE_ATTRIBUTE_COMPUTE_CAPABILITY_MAJOR = 75,
    CU_DEVICE_ATTRIBUTE_COMPUTE_CAPABILITY_MINOR = 76,
} CUdevice_attribute;

/* CUdevice_v1, CUdeviceptr_v2 and struct CUuuid_st, as cuda.h has them. */
typedef int CUdevice;
typedef unsigned long long CUdeviceptr;
typedef struct CUuuid_st {
    char bytes[16];
} CUuuid;

/* The primary context. cuda.h leaves struct CUctx_st opaque. */
struct CUctx_st {
    int refs;
};
typedef struct CUctx_st *CUcontext;

/* One live allocation. va is the handle's base in the fake address
 * space, host is where the bytes are, size is what the caller asked for
 * and mapped is what mmap took. */
struct alloc {
    CUdeviceptr va;
    void *host;
    size_t size;
    size_t mapped;
};

/* Fake device addresses start here and only grow. A 2 MiB gap after
 * every allocation keeps a pointer one past the end from landing in the
 * next one. */
#define VA_BASE 0x200000000ULL
#define VA_ALIGN (2ULL << 20)

#define NAME_MAX_LEN 256

static pthread_mutex_t mu = PTHREAD_MUTEX_INITIALIZER;

/* Set by the first cuInit, under mu. */
static int inited;
static CUresult init_rc = CUDA_ERROR_NOT_INITIALIZED;
static int ndev;
static char dev_name[NAME_MAX_LEN];
static int cc_major = 8, cc_minor = 0;
static size_t total_mem = 1024ULL << 20;
static unsigned char gpu_uuid[16] = {
    0xfa, 0x4e, 0xc0, 0xda, 0x00, 0x00, 0x40, 0x00,
    0x80, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
};
static unsigned char mig_uuid[16];
static int have_mig, is_mig;
static int driver_version = 13000;
static unsigned long sticky_after;

/* The device and context state, under mu. */
static struct CUctx_st primary;
static struct alloc *allocs;
static size_t nallocs, cap_allocs;
static size_t used_mem;
static CUdeviceptr next_va = VA_BASE;
static unsigned long memcalls;
static int sticky;

static __thread CUcontext current;

/* Knob parsing. Each parser leaves its output alone on failure. */

static CUresult bad(const char *knob) {
    fprintf(stderr, "fakecuda: malformed %s\n", knob);
    return CUDA_ERROR_INVALID_VALUE;
}

/* A decimal number in [0, max], digits only. */
static int parse_ulong(const char *s, unsigned long max, unsigned long *out) {
    unsigned long v = 0;
    if (!*s) return -1;
    for (; *s; s++) {
        if (*s < '0' || *s > '9') return -1;
        unsigned long d = (unsigned long)(*s - '0');
        if (v > (max - d) / 10) return -1;
        v = v * 10 + d;
    }
    *out = v;
    return 0;
}

static int hexval(char c) {
    if (c >= '0' && c <= '9') return c - '0';
    if (c >= 'a' && c <= 'f') return c - 'a' + 10;
    if (c >= 'A' && c <= 'F') return c - 'A' + 10;
    return -1;
}

/* prefix followed by xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx, exactly n
 * bytes long, as nvidia-smi -L prints a GPU- or MIG- UUID. */
static int parse_uuid(const char *s, size_t n, const char *prefix, unsigned char out[16]) {
    static const int dash[] = {8, 13, 18, 23};
    unsigned char u[16];
    int b = 0, d = 0;
    if (n != 40 || strncmp(s, prefix, 4) != 0) return -1;
    s += 4;
    for (int i = 0; i < 36;) {
        if (d < 4 && i == dash[d]) {
            if (s[i] != '-') return -1;
            d++;
            i++;
            continue;
        }
        int hi = hexval(s[i]), lo = hexval(s[i + 1]);
        if (hi < 0 || lo < 0) return -1;
        u[b++] = (unsigned char)(hi << 4 | lo);
        i += 2;
    }
    memcpy(out, u, sizeof u);
    return 0;
}

static CUresult driver_from_env(int *out) {
    const char *s = getenv("FAKECUDA_DRIVER");
    unsigned long v;
    if (!s) return CUDA_SUCCESS;
    if (parse_ulong(s, INT_MAX, &v) || v == 0) return bad("FAKECUDA_DRIVER");
    *out = (int)v;
    return CUDA_SUCCESS;
}

/* Whether the first CUDA_VISIBLE_DEVICES entry shows the device. The real
 * driver stops at the first entry that names no device, and later
 * entries could only repeat this one, so the first decides. */
static int visible(void) {
    const char *v = getenv("CUDA_VISIBLE_DEVICES");
    unsigned char u[16];
    char ord[16];
    unsigned long o = 0;
    if (!v) return 1;
    size_t n = strcspn(v, ",");
    if (n > 0 && n < sizeof ord && v[0] >= '0' && v[0] <= '9') {
        memcpy(ord, v, n);
        ord[n] = 0;
        return parse_ulong(ord, INT_MAX, &o) == 0 && o == 0;
    }
    if (parse_uuid(v, n, "GPU-", u) == 0) return memcmp(u, gpu_uuid, 16) == 0;
    if (have_mig && parse_uuid(v, n, "MIG-", u) == 0 && memcmp(u, mig_uuid, 16) == 0) {
        is_mig = 1;
        return 1;
    }
    return 0;
}

/* Reads every knob once, at the first cuInit, with mu held. */
static CUresult load_env(void) {
    const char *s, *name = "fakecuda";
    unsigned long v, w;
    char major[8];

    if ((s = getenv("FAKECUDA_NAME"))) name = s;
    if (!*name || strlen(name) + sizeof " MIG" > NAME_MAX_LEN) return bad("FAKECUDA_NAME");
    if ((s = getenv("FAKECUDA_CC"))) {
        const char *dot = strchr(s, '.');
        if (!dot || dot == s || (size_t)(dot - s) >= sizeof major) return bad("FAKECUDA_CC");
        memcpy(major, s, (size_t)(dot - s));
        major[dot - s] = 0;
        if (parse_ulong(major, 99, &v) || parse_ulong(dot + 1, 99, &w) || v == 0)
            return bad("FAKECUDA_CC");
        cc_major = (int)v;
        cc_minor = (int)w;
    }
    if ((s = getenv("FAKECUDA_MEM_MB"))) {
        if (parse_ulong(s, 1UL << 20, &v) || v == 0) return bad("FAKECUDA_MEM_MB");
        total_mem = (size_t)v << 20;
    }
    if ((s = getenv("FAKECUDA_UUID")) && parse_uuid(s, strlen(s), "GPU-", gpu_uuid))
        return bad("FAKECUDA_UUID");
    if ((s = getenv("FAKECUDA_MIG_UUID"))) {
        if (parse_uuid(s, strlen(s), "MIG-", mig_uuid)) return bad("FAKECUDA_MIG_UUID");
        have_mig = 1;
    }
    if ((s = getenv("FAKECUDA_STICKY_AFTER")) && parse_ulong(s, ULONG_MAX, &sticky_after))
        return bad("FAKECUDA_STICKY_AFTER");
    if (driver_from_env(&driver_version) != CUDA_SUCCESS) return CUDA_ERROR_INVALID_VALUE;

    ndev = visible();
    snprintf(dev_name, sizeof dev_name, "%s%s", name, is_mig ? " MIG" : "");
    return ndev ? CUDA_SUCCESS : CUDA_ERROR_NO_DEVICE;
}

/* Gates, all with mu held. */

/* A cuInit that found no device still leaves the library up, showing
 * zero devices. One that hit a malformed knob does not. */
static CUresult ready(void) {
    if (!inited || (init_rc != CUDA_SUCCESS && init_rc != CUDA_ERROR_NO_DEVICE))
        return CUDA_ERROR_NOT_INITIALIZED;
    return CUDA_SUCCESS;
}

static CUresult check_dev(CUdevice dev) {
    return ndev && dev == 0 ? CUDA_SUCCESS : CUDA_ERROR_INVALID_DEVICE;
}

/* The calling thread must have the live primary context current. */
static CUresult need_ctx(void) {
    if (current != &primary || primary.refs == 0) return CUDA_ERROR_INVALID_CONTEXT;
    if (sticky) return CUDA_ERROR_ILLEGAL_ADDRESS;
    return CUDA_SUCCESS;
}

/* Every memory call counts toward FAKECUDA_STICKY_AFTER. */
static CUresult mem_enter(void) {
    CUresult rc = ready();
    if (rc != CUDA_SUCCESS) return rc;
    memcalls++;
    if (sticky_after && memcalls >= sticky_after) sticky = 1;
    return need_ctx();
}

/* Finds the allocation holding [p, p+n). An unknown handle, or a range
 * past the allocation's end, is CUDA_ERROR_INVALID_VALUE. */
static CUresult find(CUdeviceptr p, size_t n, void **host) {
    for (size_t i = 0; i < nallocs; i++) {
        struct alloc *a = &allocs[i];
        if (p < a->va || p - a->va >= a->size) continue;
        size_t off = (size_t)(p - a->va);
        if (n > a->size - off) return CUDA_ERROR_INVALID_VALUE;
        *host = (char *)a->host + off;
        return CUDA_SUCCESS;
    }
    return CUDA_ERROR_INVALID_VALUE;
}

/* Drops every allocation, as the real driver does when the primary
 * context's last reference goes. Their addresses stay retired. */
static void drop_all(void) {
    for (size_t i = 0; i < nallocs; i++) munmap(allocs[i].host, allocs[i].mapped);
    nallocs = 0;
    used_mem = 0;
}

/* Initialization and version. */

API CUresult cuInit(unsigned int flags) {
    if (flags != 0) return CUDA_ERROR_INVALID_VALUE;
    pthread_mutex_lock(&mu);
    if (!inited) {
        init_rc = load_env();
        inited = 1;
    }
    CUresult rc = init_rc;
    pthread_mutex_unlock(&mu);
    return rc;
}

/* Works before cuInit, as the real one does, reading FAKECUDA_DRIVER on
 * the spot until cuInit has read it for good. */
API CUresult cuDriverGetVersion(int *version) {
    if (!version) return CUDA_ERROR_INVALID_VALUE;
    pthread_mutex_lock(&mu);
    int v = driver_version;
    CUresult rc = inited ? CUDA_SUCCESS : driver_from_env(&v);
    pthread_mutex_unlock(&mu);
    if (rc == CUDA_SUCCESS) *version = v;
    return rc;
}

/* Devices. */

API CUresult cuDeviceGetCount(int *count) {
    pthread_mutex_lock(&mu);
    CUresult rc = ready();
    if (rc == CUDA_SUCCESS && !count) rc = CUDA_ERROR_INVALID_VALUE;
    if (rc == CUDA_SUCCESS) *count = ndev;
    pthread_mutex_unlock(&mu);
    return rc;
}

API CUresult cuDeviceGet(CUdevice *device, int ordinal) {
    pthread_mutex_lock(&mu);
    CUresult rc = ready();
    if (rc == CUDA_SUCCESS && !device) rc = CUDA_ERROR_INVALID_VALUE;
    if (rc == CUDA_SUCCESS && (ordinal < 0 || ordinal >= ndev)) rc = CUDA_ERROR_INVALID_DEVICE;
    if (rc == CUDA_SUCCESS) *device = ordinal;
    pthread_mutex_unlock(&mu);
    return rc;
}

API CUresult cuDeviceGetName(char *name, int len, CUdevice dev) {
    pthread_mutex_lock(&mu);
    CUresult rc = ready();
    if (rc == CUDA_SUCCESS && (!name || len <= 0)) rc = CUDA_ERROR_INVALID_VALUE;
    if (rc == CUDA_SUCCESS) rc = check_dev(dev);
    if (rc == CUDA_SUCCESS) snprintf(name, (size_t)len, "%s", dev_name);
    pthread_mutex_unlock(&mu);
    return rc;
}

/* Only the compute capability. Any other attribute is
 * CUDA_ERROR_INVALID_VALUE, so an engine that asks for more fails
 * loudly here rather than on a real GPU. */
API CUresult cuDeviceGetAttribute(int *pi, CUdevice_attribute attrib, CUdevice dev) {
    pthread_mutex_lock(&mu);
    CUresult rc = ready();
    if (rc == CUDA_SUCCESS && !pi) rc = CUDA_ERROR_INVALID_VALUE;
    if (rc == CUDA_SUCCESS) rc = check_dev(dev);
    if (rc == CUDA_SUCCESS) {
        switch (attrib) {
        case CU_DEVICE_ATTRIBUTE_COMPUTE_CAPABILITY_MAJOR: *pi = cc_major; break;
        case CU_DEVICE_ATTRIBUTE_COMPUTE_CAPABILITY_MINOR: *pi = cc_minor; break;
        default: rc = CUDA_ERROR_INVALID_VALUE; break;
        }
    }
    pthread_mutex_unlock(&mu);
    return rc;
}

static CUresult get_uuid(CUuuid *uuid, CUdevice dev, int v2) {
    pthread_mutex_lock(&mu);
    CUresult rc = ready();
    if (rc == CUDA_SUCCESS && !uuid) rc = CUDA_ERROR_INVALID_VALUE;
    if (rc == CUDA_SUCCESS) rc = check_dev(dev);
    if (rc == CUDA_SUCCESS) memcpy(uuid->bytes, v2 && is_mig ? mig_uuid : gpu_uuid, 16);
    pthread_mutex_unlock(&mu);
    return rc;
}

/* The first version names the parent GPU even on a MIG instance. The
 * _v2 one names the MIG instance, which is why CUDA 11.4 added it. */
API CUresult cuDeviceGetUuid(CUuuid *uuid, CUdevice dev) {
    return get_uuid(uuid, dev, 0);
}

API CUresult cuDeviceGetUuid_v2(CUuuid *uuid, CUdevice dev) {
    return get_uuid(uuid, dev, 1);
}

API CUresult cuDeviceTotalMem_v2(size_t *bytes, CUdevice dev) {
    pthread_mutex_lock(&mu);
    CUresult rc = ready();
    if (rc == CUDA_SUCCESS && !bytes) rc = CUDA_ERROR_INVALID_VALUE;
    if (rc == CUDA_SUCCESS) rc = check_dev(dev);
    if (rc == CUDA_SUCCESS) *bytes = total_mem;
    pthread_mutex_unlock(&mu);
    return rc;
}

/* Contexts. Only the primary context exists. */

API CUresult cuDevicePrimaryCtxRetain(CUcontext *pctx, CUdevice dev) {
    pthread_mutex_lock(&mu);
    CUresult rc = ready();
    if (rc == CUDA_SUCCESS && !pctx) rc = CUDA_ERROR_INVALID_VALUE;
    if (rc == CUDA_SUCCESS) rc = check_dev(dev);
    if (rc == CUDA_SUCCESS && sticky) rc = CUDA_ERROR_ILLEGAL_ADDRESS;
    if (rc == CUDA_SUCCESS && primary.refs == INT_MAX) rc = CUDA_ERROR_UNKNOWN;
    if (rc == CUDA_SUCCESS) {
        primary.refs++;
        *pctx = &primary;
    }
    pthread_mutex_unlock(&mu);
    return rc;
}

/* Release works even after a sticky error, so an engine can tear down
 * on its way out. The last reference drops every allocation. */
API CUresult cuDevicePrimaryCtxRelease_v2(CUdevice dev) {
    pthread_mutex_lock(&mu);
    CUresult rc = ready();
    if (rc == CUDA_SUCCESS) rc = check_dev(dev);
    if (rc == CUDA_SUCCESS && primary.refs == 0) rc = CUDA_ERROR_INVALID_CONTEXT;
    if (rc == CUDA_SUCCESS && --primary.refs == 0) drop_all();
    pthread_mutex_unlock(&mu);
    return rc;
}

API CUresult cuCtxSetCurrent(CUcontext ctx) {
    pthread_mutex_lock(&mu);
    CUresult rc = ready();
    if (rc == CUDA_SUCCESS && ctx) {
        if (ctx != &primary || primary.refs == 0) rc = CUDA_ERROR_INVALID_CONTEXT;
        else if (sticky) rc = CUDA_ERROR_ILLEGAL_ADDRESS;
    }
    if (rc == CUDA_SUCCESS) current = ctx;
    pthread_mutex_unlock(&mu);
    return rc;
}

/* Every call runs to completion, so there is nothing to wait for. It
 * still reports a sticky error, as the real one does. */
API CUresult cuCtxSynchronize(void) {
    pthread_mutex_lock(&mu);
    CUresult rc = ready();
    if (rc == CUDA_SUCCESS) rc = need_ctx();
    pthread_mutex_unlock(&mu);
    return rc;
}

/* Memory. */

API CUresult cuMemAlloc_v2(CUdeviceptr *dptr, size_t bytesize) {
    size_t page = (size_t)sysconf(_SC_PAGESIZE);
    pthread_mutex_lock(&mu);
    CUresult rc = mem_enter();
    if (rc == CUDA_SUCCESS && (!dptr || bytesize == 0)) rc = CUDA_ERROR_INVALID_VALUE;
    size_t mapped = 0;
    unsigned long long span = 0;
    if (rc == CUDA_SUCCESS) {
        /* total_mem is whole pages, so checking it first keeps the
         * rounding from overflowing. */
        if (bytesize > total_mem) rc = CUDA_ERROR_OUT_OF_MEMORY;
        else mapped = (bytesize + page - 1) / page * page;
        if (rc == CUDA_SUCCESS && mapped > total_mem - used_mem) rc = CUDA_ERROR_OUT_OF_MEMORY;
    }
    if (rc == CUDA_SUCCESS) {
        span = (mapped + VA_ALIGN - 1) / VA_ALIGN * VA_ALIGN + VA_ALIGN;
        if (next_va > ~0ULL - span) rc = CUDA_ERROR_OUT_OF_MEMORY;
    }
    if (rc == CUDA_SUCCESS && nallocs == cap_allocs) {
        size_t cap = cap_allocs ? cap_allocs * 2 : 16;
        struct alloc *grown = realloc(allocs, cap * sizeof *grown);
        if (!grown) rc = CUDA_ERROR_OUT_OF_MEMORY;
        else {
            allocs = grown;
            cap_allocs = cap;
        }
    }
    void *host = MAP_FAILED;
    if (rc == CUDA_SUCCESS) {
        host = mmap(NULL, mapped, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS | MAP_NORESERVE, -1, 0);
        if (host == MAP_FAILED) rc = CUDA_ERROR_OUT_OF_MEMORY;
    }
    if (rc == CUDA_SUCCESS) {
        allocs[nallocs++] = (struct alloc){.va = next_va, .host = host, .size = bytesize, .mapped = mapped};
        *dptr = next_va;
        next_va += span;
        used_mem += mapped;
    }
    pthread_mutex_unlock(&mu);
    return rc;
}

/* Only an allocation's base address frees it. */
API CUresult cuMemFree_v2(CUdeviceptr dptr) {
    pthread_mutex_lock(&mu);
    CUresult rc = mem_enter();
    if (rc == CUDA_SUCCESS) {
        size_t i = 0;
        while (i < nallocs && allocs[i].va != dptr) i++;
        if (i == nallocs) rc = CUDA_ERROR_INVALID_VALUE;
        else {
            munmap(allocs[i].host, allocs[i].mapped);
            used_mem -= allocs[i].mapped;
            allocs[i] = allocs[--nallocs];
        }
    }
    pthread_mutex_unlock(&mu);
    return rc;
}

API CUresult cuMemsetD8_v2(CUdeviceptr dst, unsigned char uc, size_t n) {
    void *host = NULL;
    pthread_mutex_lock(&mu);
    CUresult rc = mem_enter();
    if (rc == CUDA_SUCCESS) rc = find(dst, n, &host);
    if (rc == CUDA_SUCCESS) memset(host, uc, n);
    pthread_mutex_unlock(&mu);
    return rc;
}

API CUresult cuMemcpyHtoD_v2(CUdeviceptr dst, const void *src, size_t n) {
    void *host = NULL;
    pthread_mutex_lock(&mu);
    CUresult rc = mem_enter();
    if (rc == CUDA_SUCCESS && !src && n) rc = CUDA_ERROR_INVALID_VALUE;
    if (rc == CUDA_SUCCESS) rc = find(dst, n, &host);
    if (rc == CUDA_SUCCESS && n) memcpy(host, src, n);
    pthread_mutex_unlock(&mu);
    return rc;
}

API CUresult cuMemcpyDtoH_v2(void *dst, CUdeviceptr src, size_t n) {
    void *host = NULL;
    pthread_mutex_lock(&mu);
    CUresult rc = mem_enter();
    if (rc == CUDA_SUCCESS && !dst && n) rc = CUDA_ERROR_INVALID_VALUE;
    if (rc == CUDA_SUCCESS) rc = find(src, n, &host);
    if (rc == CUDA_SUCCESS && n) memcpy(dst, host, n);
    pthread_mutex_unlock(&mu);
    return rc;
}

/* Free and total memory. Not a memory call for FAKECUDA_STICKY_AFTER,
 * so a start-up query never shifts the count a test sets. */
API CUresult cuMemGetInfo_v2(size_t *free_bytes, size_t *total_bytes) {
    pthread_mutex_lock(&mu);
    CUresult rc = ready();
    if (rc == CUDA_SUCCESS) rc = need_ctx();
    if (rc == CUDA_SUCCESS && (!free_bytes || !total_bytes)) rc = CUDA_ERROR_INVALID_VALUE;
    if (rc == CUDA_SUCCESS) {
        *free_bytes = total_mem - used_mem;
        *total_bytes = total_mem;
    }
    pthread_mutex_unlock(&mu);
    return rc;
}

/* Errors. The names and strings are the real driver's. Both work before
 * cuInit. An unknown code sets *pstr to NULL and is
 * CUDA_ERROR_INVALID_VALUE, as in the real driver. */

static const struct {
    CUresult rc;
    const char *name;
    const char *text;
} errors[] = {
    {CUDA_SUCCESS, "CUDA_SUCCESS", "no error"},
    {CUDA_ERROR_INVALID_VALUE, "CUDA_ERROR_INVALID_VALUE", "invalid argument"},
    {CUDA_ERROR_OUT_OF_MEMORY, "CUDA_ERROR_OUT_OF_MEMORY", "out of memory"},
    {CUDA_ERROR_NOT_INITIALIZED, "CUDA_ERROR_NOT_INITIALIZED", "initialization error"},
    {CUDA_ERROR_NO_DEVICE, "CUDA_ERROR_NO_DEVICE", "no CUDA-capable device is detected"},
    {CUDA_ERROR_INVALID_DEVICE, "CUDA_ERROR_INVALID_DEVICE", "invalid device ordinal"},
    {CUDA_ERROR_INVALID_CONTEXT, "CUDA_ERROR_INVALID_CONTEXT", "invalid device context"},
    {CUDA_ERROR_ILLEGAL_ADDRESS, "CUDA_ERROR_ILLEGAL_ADDRESS", "an illegal memory access was encountered"},
    {CUDA_ERROR_UNKNOWN, "CUDA_ERROR_UNKNOWN", "unknown error"},
};

static CUresult error_field(CUresult error, const char **pstr, int text) {
    if (!pstr) return CUDA_ERROR_INVALID_VALUE;
    for (size_t i = 0; i < sizeof errors / sizeof errors[0]; i++) {
        if (errors[i].rc == error) {
            *pstr = text ? errors[i].text : errors[i].name;
            return CUDA_SUCCESS;
        }
    }
    *pstr = NULL;
    return CUDA_ERROR_INVALID_VALUE;
}

API CUresult cuGetErrorName(CUresult error, const char **pstr) {
    return error_field(error, pstr, 0);
}

API CUresult cuGetErrorString(CUresult error, const char **pstr) {
    return error_field(error, pstr, 1);
}
