#!/usr/bin/env bash
# Fail when an aarch64 shared object of ours holds pointer authentication
# (PAC) instructions, which trap after a CRIU restore on a FEAT_FPAC CPU.
# A wheel is opened and each .so in it checked. The count is the one
# hack/python/rootfs.sh takes of fiberd._zygote. Needs objdump.
#
#   hack/python/pac.sh <file.whl | file.so>...
set -euo pipefail
work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT
pac() { objdump -d "$1" | awk '$3 ~ /^(pac|aut|reta|bra|blra)/ {n++} END{print n+0}'; }
bad=0
for f in "$@"; do
  objs=("$f")
  if [[ "$f" == *.whl ]]; then
    dir="$work/$(basename "$f")"
    python3 -c 'import sys, zipfile; z = zipfile.ZipFile(sys.argv[1]); [z.extract(n, sys.argv[2]) for n in z.namelist() if n.endswith(".so")]' "$f" "$dir"
    mapfile -t objs < <(find "$dir" -name '*.so')
    [[ ${#objs[@]} -gt 0 ]] || { echo "pac.sh: no .so in $f" >&2; exit 1; }
  fi
  for o in "${objs[@]}"; do
    n=$(pac "$o")
    echo "pac.sh: ${o#"$work/"}: $n PAC instructions"
    [[ "$n" == 0 ]] || bad=1
  done
done
exit "$bad"
