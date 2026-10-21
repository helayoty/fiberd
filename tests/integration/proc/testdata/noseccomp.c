/* noseccomp runs its command as if the kernel refused every seccomp
 * filter. A filter answers seccomp(2) and prctl(PR_SET_SECCOMP) with the
 * given errno and lets every other syscall through. It is inherited
 * across exec, so a zygote started this way cannot install the fiber
 * filter.
 *
 *   noseccomp <errno> <command> [args...]
 *
 * Built by the tests in tests/integration/proc (see seccomp_linux_test.go). */
#define _GNU_SOURCE
#include <linux/audit.h>
#include <linux/filter.h>
#include <linux/seccomp.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/prctl.h>
#include <sys/syscall.h>
#include <unistd.h>

#if defined(__x86_64__)
#define NOSECCOMP_ARCH AUDIT_ARCH_X86_64
#elif defined(__aarch64__)
#define NOSECCOMP_ARCH AUDIT_ARCH_AARCH64
#else
#error "noseccomp: add this architecture's AUDIT_ARCH"
#endif

int main(int argc, char **argv) {
    if (argc < 3) {
        fprintf(stderr, "usage: noseccomp <errno> <command> [args...]\n");
        return 2;
    }
    unsigned e = (unsigned)atoi(argv[1]);
    struct sock_filter filter[] = {
        BPF_STMT(BPF_LD | BPF_W | BPF_ABS, offsetof(struct seccomp_data, arch)),
        BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, NOSECCOMP_ARCH, 1, 0),
        BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_KILL_PROCESS),
        BPF_STMT(BPF_LD | BPF_W | BPF_ABS, offsetof(struct seccomp_data, nr)),
        BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, __NR_seccomp, 4, 0),
        BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, __NR_prctl, 0, 2),
        BPF_STMT(BPF_LD | BPF_W | BPF_ABS, offsetof(struct seccomp_data, args[0])),
        BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, PR_SET_SECCOMP, 1, 0),
        BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ALLOW),
        BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ERRNO | (e & SECCOMP_RET_DATA)),
    };
    struct sock_fprog prog = { .len = sizeof filter / sizeof filter[0], .filter = filter };
    if (prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) < 0) {
        perror("noseccomp: PR_SET_NO_NEW_PRIVS");
        return 2;
    }
    if (prctl(PR_SET_SECCOMP, SECCOMP_MODE_FILTER, &prog) < 0) {
        perror("noseccomp: PR_SET_SECCOMP");
        return 2;
    }
    execv(argv[2], argv + 2);
    perror("noseccomp: exec");
    return 127;
}
