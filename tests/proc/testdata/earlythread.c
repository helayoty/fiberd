/* earlythread is a template that breaks libfiberzygote's contract by
 * starting a thread before fz_init. With a thread already made, unshare
 * would move the calling thread alone, so the library takes no mount
 * namespace of its own and must refuse every mntns CLONE (fail closed)
 * while still saying READY and serving the rest. The thread sleeps
 * forever. on_fiber is the least a fiber can do, since no mntns fiber is
 * ever born from here.
 *
 *   earlythread
 *
 * Built by the tests in tests/proc (see prepare_linux_test.go), linked
 * with the library like refzygote. */
#define _GNU_SOURCE
#include "../../../zygote/libfiberzygote.h"

#include <pthread.h>
#include <stdio.h>
#include <unistd.h>

static void *sleeper(void *arg) {
    (void)arg;
    for (;;) pause();
    return NULL;
}

static int on_fiber(const fz_fiber_t *f) {
    (void)f;
    fz_fiber_ready();
    for (;;) pause();
    return 0;
}

int main(int argc, char **argv) {
    pthread_t t;
    if (pthread_create(&t, NULL, sleeper, NULL) != 0) {
        perror("earlythread: pthread_create");
        return 2;
    }
    fz_init(argc, argv); /* too late: a thread exists */
    if (fz_serve(3, on_fiber) < 0) {
        perror("earlythread: fz_serve");
        return 1;
    }
    return 0;
}
