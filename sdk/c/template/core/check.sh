#!/usr/bin/env bash
# Checks the zygote library's archive for what the link cannot. It must
# need nothing from libc beyond its allowlist, so no allocator creeps in,
# and carry no pointer authentication instruction on aarch64, since a
# checkpoint restored on a FEAT_FPAC CPU would trap on one.
#
#   sdk/c/template/core/check.sh sdk/c/template/core/target/release/libfiberzygote_core.a
#
# OBJDUMP names the objdump to disassemble with. An x86_64 host's own
# objdump cannot read aarch64 code, so the release checks the arm64
# archive with OBJDUMP=aarch64-linux-gnu-objdump.
set -euo pipefail

archive=${1:?usage: check.sh <libfiberzygote_core.a>}
objdump=${OBJDUMP:-objdump}
[ -r "$archive" ] || { echo "check.sh: $archive: not readable" >&2; exit 1; }
for tool in readelf "$objdump"; do
  command -v "$tool" >/dev/null || { echo "check.sh: $tool is needed" >&2; exit 1; }
done

# What the archive may take from libc and libgcc. Everything else is a
# finding, and an allocator is one by name even if it were on this list.
allow="abort getauxval memchr memcpy memset memcmp bcmp strlen write __errno_location"
allow="$allow __addtf3 __multf3 __subtf3 __unordtf2 __udivti3"
# memmove is copy_within, which lock_sys uses on mountinfo.
allow="$allow memmove"
# The child's path (child.rs, mounts.rs) and the sys seam.
allow="$allow syscall prctl openat close _exit mount umount2 mkdir open"
allow="$allow stat chdir dup2 fcntl socketpair recvmsg setsid signal sigemptyset sigprocmask strcmp"
# The fiber side and the gVisor side (fiber.rs).
allow="$allow poll send socket connect usleep read"
# The zygote side (zygote.rs, prepare.rs, ctl.rs). __xpg_strerror_r is
# glibc's strerror_r, and environ is what the child points at the fiber's
# environment.
allow="$allow pthread_mutex_lock pthread_mutex_unlock pthread_sigmask sigaddset sigismember signalfd"
allow="$allow personality execv getenv clock_gettime nanosleep waitpid kill pipe2 readlink realpath"
allow="$allow mkdtemp rmdir __xpg_strerror_r environ"
deny_re='^(malloc|calloc|realloc|free|__rust_alloc.*)$'

# readelf rather than nm, because GNU nm hands a member with an .llvmbc
# section to the gold plugin, which then reports no symbols for it.
# Column 7 is the section index (UND when undefined), column 8 the name.
syms=$(readelf -sW "$archive")
undefined=$(printf '%s\n' "$syms" | awk '$7 == "UND" && $8 != "" {print $8}' | sort -u)
defined=$(printf '%s\n' "$syms" | awk '$7 != "UND" && $7 ~ /^[0-9]+$/ && $8 != "" {print $8}' | sort -u)

rc=0
# An allocator anywhere, referenced or defined, fails on its own.
bad=$(printf '%s\n%s\n' "$undefined" "$defined" | grep -E "$deny_re" || true)
if [ -n "$bad" ]; then
  echo "check.sh: $archive names an allocator:" >&2
  printf '  %s\n' $bad >&2
  rc=1
fi

# What no member of the archive defines must be on the allowlist.
external=$(comm -23 <(printf '%s\n' "$undefined") <(printf '%s\n' "$defined"))
unknown=()
for s in $external; do
  case " $allow " in *" $s "*) ;; *) unknown+=("$s") ;; esac
done
if [ ${#unknown[@]} -gt 0 ]; then
  echo "check.sh: $archive needs symbols outside the allowlist:" >&2
  printf '  %s\n' "${unknown[@]}" >&2
  rc=1
fi

# Pointer authentication, counted over every member with no exemption.
machine=$(readelf -h "$archive" | awk -F: '/Machine:/ && !seen {seen = 1; gsub(/^[ \t]+/, "", $2); print $2}')
case "$machine" in
  AArch64)
    n=$("$objdump" -d "$archive" | awk '$3 ~ /^(pac|aut|reta|bra|blra)/ {n++} END {print n+0}')
    if [ "$n" != 0 ]; then
      echo "check.sh: $n PAC instructions in $archive; a restore would trap on a FEAT_FPAC CPU" >&2
      rc=1
    fi
    ;;
  *) n="n/a ($machine)" ;;
esac

if [ $rc = 0 ]; then
  echo "check.sh: $archive: externals [$(echo $external)], PAC $n"
fi
exit $rc
