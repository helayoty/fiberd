#!/usr/bin/env bash
# Checks the Rust core's archive for what the link cannot. The archive
# must need nothing from libc beyond the few calls on its allowlist, so no
# allocator can have crept in, and it must carry no pointer authentication
# instruction on aarch64, since a checkpoint restored on a FEAT_FPAC CPU
# would trap on one (hack/gvisor/rootfs.sh counts the same way, with one
# exemption for libgcc's unwinder that does not apply here).
#
#   sdk/c/template/core/check.sh sdk/c/template/core/target/release/libfiberzygote_core.a
set -euo pipefail

archive=${1:?usage: check.sh <libfiberzygote_core.a>}
[ -r "$archive" ] || { echo "check.sh: $archive: not readable" >&2; exit 1; }
for tool in readelf objdump; do
  command -v "$tool" >/dev/null || { echo "check.sh: $tool is needed" >&2; exit 1; }
done

# What the archive may take from libc and libgcc. Everything else is a
# finding, and an allocator is one by name even if it were on this list.
allow="abort getauxval memchr memcpy memset memcmp bcmp strlen write __errno_location"
allow="$allow __addtf3 __multf3 __subtf3 __unordtf2 __udivti3"
# memmove is copy_within, which moves mountinfo's partial line to the
# front and an unescaped mount point down, as lock_sys did in C.
allow="$allow memmove"
# The child's path (child.rs, mounts.rs) and the sys seam make the system
# calls the C made there: the raw syscall for clone3, clone, capset and
# close_range, prctl for the filter and the capability drop, openat,
# write, close and _exit in the legacy clone's child, mount, umount2,
# mkdir and open behind the seam, stat and chdir for the mount steps,
# dup2, fcntl, socketpair and recvmsg for the descriptors and the record,
# setsid, signal, sigemptyset and sigprocmask for the session and the
# mask, and strcmp for the fence check.
allow="$allow syscall prctl openat close _exit mount umount2 mkdir open"
allow="$allow stat chdir dup2 fcntl socketpair recvmsg setsid signal sigemptyset sigprocmask strcmp"
deny_re='^(malloc|calloc|realloc|free|__rust_alloc.*)$'

# The symbol tables of every member. readelf rather than nm, because GNU
# nm hands any member with an embedded .llvmbc section to the LLVM gold
# plugin, which cannot read rustc's bitcode and then reports no symbols
# for that member. Column 7 is the section index, UND for an undefined
# symbol, and column 8 the name.
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
    n=$(objdump -d "$archive" | awk '$3 ~ /^(pac|aut|reta|bra|blra)/ {n++} END {print n+0}')
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
