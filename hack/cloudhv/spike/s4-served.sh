#!/usr/bin/env bash
# S4. How long from starting a VMM on a snapshot to the guest's served line?
#
#   sudo bash hack/cloudhv/spike/s4-served.sh
#
# Each run starts a fresh VMM with --restore, waits for vm.info to say
# Paused, calls vm.resume, then sends "incarnate <n>" over vsock port 1024
# until the guest answers "served <n>". Times are taken in hostctl.py from
# the VMM's start. One VMM at a time, S4_RUNS runs (20) per restore mode.
# These are logged numbers from one host, not claims.
set -euo pipefail
. "$(dirname "$0")/lib.sh"
prereqs

RUNS=${S4_RUNS:-20}
MODES=${S4_MODES:-copy ondemand file-private}
OUT=$SPIKE_DIR/s4
trap cleanup EXIT
rm -rf "$OUT"
mkdir -p "$OUT"

span() { hc stats | sed -n 's/n=[0-9]* min=\([^ ]*\) median=\([^ ]*\) max=\([^ ]*\)/\1 \/ \2 \/ \3/p'; }

warm_snapshot "$OUT/warm-anon"
case " $MODES " in *" file-private "*) warm_snapshot "$OUT/warm-file" file ;; esac

summary=$OUT/summary.txt
printf '%-13s %4s  %-26s %-26s %-26s  %s\n' mode runs "restored ms min/med/max" "resumed ms min/med/max" \
  "served ms min/med/max" "(from VMM start)" >"$summary"
for mode in $MODES; do
  case $mode in
    copy) src=$OUT/warm-anon/snap; args=(--mode copy) ;;
    ondemand) src=$OUT/warm-anon/snap; args=(--mode ondemand) ;;
    file-private) src=$OUT/warm-file/snap; args=(--mode copy --private-zones) ;;
    *) fail "unknown mode $mode" ;;
  esac
  dir=$OUT/$mode
  mkdir -p "$dir"
  err=""
  for i in $(seq 1 "$RUNS"); do
    if line=$(hc restore --ch "$CH" --run "$dir/vm" --source "$src" "${args[@]}" --incarnate "$i" 2>"$dir/err.txt"); then
      echo "$line" >>"$dir/runs.txt"
    else
      err=$(tail -1 "$dir/err.txt")
    fi
    hc shutdown --run "$dir/vm"
    rm -f "$dir/vm/pid"
    [ -z "$err" ] || break
  done
  if [ ! -s "$dir/runs.txt" ]; then
    printf '%-13s %4s  unsupported or failed: %s\n' "$mode" 0 "$err" >>"$summary"
    continue
  fi
  printf '%-13s %4s  %-26s %-26s %-26s  %s\n' "$mode" "$(wc -l <"$dir/runs.txt")" \
    "$(field restored_ms <"$dir/runs.txt" | span)" \
    "$(field resumed_ms <"$dir/runs.txt" | span)" \
    "$(field served_ms <"$dir/runs.txt" | span)" \
    "${err:+stopped early: $err}" >>"$summary"
done

echo
echo "S4 on $(hostname), cloud-hypervisor $CH_VERSION, guest ${SPIKE_MEM_MB} MiB"
echo "cold boot of the warm guest: $(cat "$OUT/warm-anon/boot.txt")"
cat "$summary"
echo
echo "Raw numbers: $OUT/*/runs.txt"
