/* noclone3 runs its arguments as if the kernel had no clone3. A seccomp
 * filter answers __NR_clone3 with ENOSYS and lets every other syscall
 * through. The filter is inherited across fork and exec, so a zygote
 * started this way, and every fiber it forks, takes libfiberzygote's fork
 * fallback.
 *
 *   noclone3 <command> [args...]
 *
 * Built by the tests in tests/proc (see noclone3_linux_test.go). */
#define _GNU_SOURCE
#include <errno.h>
#include <linux/audit.h>
#include <linux/filter.h>
#include <linux/seccomp.h>
#include <stddef.h>
#include <stdio.h>
#include <sys/prctl.h>
#include <sys/syscall.h>
#include <unistd.h>

#if defined(__x86_64__)
#define NOCLONE3_ARCH AUDIT_ARCH_X86_64
#elif defined(__aarch64__)
#define NOCLONE3_ARCH AUDIT_ARCH_AARCH64
#else
#error "noclone3: add this architecture's AUDIT_ARCH"
#endif

int main(int argc, char **argv) {
    if (argc < 2) {
        fprintf(stderr, "usage: noclone3 <command> [args...]\n");
        return 2;
    }
    struct sock_filter filter[] = {
        /* A process of another architecture, such as a 32-bit binary, has
         * other syscall numbers. None is expected here, so one is killed. */
        BPF_STMT(BPF_LD | BPF_W | BPF_ABS, offsetof(struct seccomp_data, arch)),
        BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, NOCLONE3_ARCH, 1, 0),
        BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_KILL_PROCESS),
        BPF_STMT(BPF_LD | BPF_W | BPF_ABS, offsetof(struct seccomp_data, nr)),
        BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, __NR_clone3, 0, 1),
        BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ERRNO | (ENOSYS & SECCOMP_RET_DATA)),
        BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ALLOW),
    };
    struct sock_fprog prog = { .len = sizeof filter / sizeof filter[0], .filter = filter };
    if (prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) < 0) {
        perror("noclone3: PR_SET_NO_NEW_PRIVS");
        return 2;
    }
    if (prctl(PR_SET_SECCOMP, SECCOMP_MODE_FILTER, &prog) < 0) {
        perror("noclone3: PR_SET_SECCOMP");
        return 2;
    }
    execv(argv[1], argv + 1);
    perror("noclone3: exec");
    return 127;
}
