/* fuzz_rundir hands set_rundir a RUNDIR line and checks what it kept.
 * Two absolute, clean paths, own a direct child of parent, both short
 * enough for the child's static storage.
 *
 * The input is the bytes after "RUNDIR ". */
#include "common.h"
#include "../libfiberzygote.c"

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    static const char prefix[] = "RUNDIR ";
    char *line = malloc(sizeof prefix + size);
    if (!line) abort();
    memcpy(line, prefix, sizeof prefix - 1);
    memcpy(line + sizeof prefix - 1, data, size);
    line[sizeof prefix - 1 + size] = 0;

    rundir_parent[0] = rundir_own[0] = 0;
    const char *why = NULL;
    int rc = set_rundir(line, &why);
    free(line);
    if (rc < 0) {
        if (!why || rundir_parent[0] || rundir_own[0]) abort();
        return 0;
    }
    size_t pl = strnlen(rundir_parent, RUNDIR_MAX), ol = strnlen(rundir_own, RUNDIR_MAX);
    if (pl >= RUNDIR_MAX || ol >= RUNDIR_MAX || pl < 2 || ol <= pl + 1) abort();
    if (rundir_parent[0] != '/' || rundir_parent[pl - 1] == '/' || strstr(rundir_parent, "//")) abort();
    if (strncmp(rundir_own, rundir_parent, pl) != 0 || rundir_own[pl] != '/') abort();
    const char *name = rundir_own + pl + 1;
    if (!*name || strchr(name, '/') || strcmp(name, ".") == 0 || strcmp(name, "..") == 0) abort();
    if (strchr(rundir_parent, ' ') || strchr(rundir_own, ' ')) abort();
    return 0;
}
