#!/usr/bin/env bash
# S1. Can a restore share the warm snapshot's memory copy-on-write, and what
# does a Clone cost in time and in private memory?
#
#   sudo bash hack/cloudhv/spike/s1-cow.sh
#
# One warm guest is snapshotted, then restored S1_COUNT times (64), all left
# running together. Each clone answers its incarnation, then dirties
# SPIKE_DIRTY_MB like a fiber would. Then every VMM's smaps_rollup is read.
# Four ways to restore, each as v54.0 has it.
#   copy          the default, memory-ranges copied into fresh anonymous RAM
#   ondemand      memory_restore_mode=ondemand, pages faulted in by userfaultfd
#   copyonwrite   memory_restore_mode=copyonwrite, memory-ranges mapped private
#   file-private  guest RAM is a file. The warm VM maps it shared, so the
#                 snapshot skips it. Each restore maps it private instead
# A mode that fails to restore is reported as such, and the next one runs.
set -euo pipefail
. "$(dirname "$0")/lib.sh"
prereqs

COUNT=${S1_COUNT:-64}
MODES=${S1_MODES:-copy ondemand copyonwrite file-private}
OUT=$SPIKE_DIR/s1
trap cleanup EXIT
rm -rf "$OUT"
mkdir -p "$OUT"

avail_mb() { awk '/^MemAvailable:/ { print int($2 / 1024) }' /proc/meminfo; }
# A full copy costs the whole guest per clone. Stay under 80% of what is free.
fit=$(($(avail_mb) * 8 / 10 / (SPIKE_MEM_MB + 64)))
[ "$fit" -ge 1 ] || fit=1
# Unit conversion and the min / median / max of a column of numbers.
mib() { awk '{ printf "%.1f\n", $1 / 1024 }'; }
med() { hc stats | sed -n 's/.*median=\([^ ]*\).*/\1/p'; }
span() { hc stats | sed -n 's/n=[0-9]* min=\([^ ]*\) median=\([^ ]*\) max=\([^ ]*\)/\1 \/ \2 \/ \3/p'; }

warm_snapshot "$OUT/warm-anon"
case " $MODES " in *" file-private "*) warm_snapshot "$OUT/warm-file" file ;; esac

summary=$OUT/summary.txt
printf '%-13s %5s  %-28s %-28s %10s %9s %9s %10s  %s\n' mode clones "resumed ms min/med/max" "served ms min/med/max" \
  "privdirty" "rss" "pss" "host used" "(MiB, medians per VMM, host used is the drop in MemAvailable)" >"$summary"

for mode in $MODES; do
  case $mode in
    copy) src=$OUT/warm-anon/snap; args=(--mode copy) ;;
    ondemand) src=$OUT/warm-anon/snap; args=(--mode ondemand) ;;
    copyonwrite) src=$OUT/warm-anon/snap; args=(--mode copyonwrite) ;;
    file-private) src=$OUT/warm-file/snap; args=(--mode copy --private-zones) ;;
    *) fail "unknown mode $mode" ;;
  esac
  n=$COUNT
  if [ "$mode" = copy ] && [ "$n" -gt "$fit" ]; then
    echo "note  copy mode: $n full copies would not fit, running $fit"
    n=$fit
  fi
  dir=$OUT/$mode
  mkdir -p "$dir"
  before=$(avail_mb)
  done_n=0
  err=""
  for i in $(seq 1 "$n"); do
    if ! line=$(hc restore --ch "$CH" --run "$dir/vm-$i" --source "$src" "${args[@]}" --incarnate "$i" 2>"$dir/vm-$i.err"); then
      err=$(tail -1 "$dir/vm-$i.err")
      hc shutdown --run "$dir/vm-$i"
      rm -f "$dir/vm-$i/pid"
      break
    fi
    echo "$line" >>"$dir/restores.txt"
    hc call "$dir/vm-$i/vsock.sock" 1024 "touch $SPIKE_DIRTY_MB" >/dev/null || { err="touch failed on clone $i"; break; }
    done_n=$i
  done
  if [ "$done_n" = 0 ]; then
    printf '%-13s %5s  unsupported or failed: %s\n' "$mode" 0 "$err" >>"$summary"
    continue
  fi
  for i in $(seq 1 "$done_n"); do
    echo "vm-$i $(hc smaps "$(cat "$dir/vm-$i/pid")")" >>"$dir/smaps.txt"
  done
  used=$((before - $(avail_mb)))
  printf '%-13s %5s  %-28s %-28s %10s %9s %9s %10s  %s\n' "$mode" "$done_n" \
    "$(field resumed_ms <"$dir/restores.txt" | span)" \
    "$(field served_ms <"$dir/restores.txt" | span)" \
    "$(field private_dirty_kb <"$dir/smaps.txt" | mib | med)" \
    "$(field rss_kb <"$dir/smaps.txt" | mib | med)" \
    "$(field pss_kb <"$dir/smaps.txt" | mib | med)" \
    "$used" "${err:+stopped early: $err}" >>"$summary"
  for i in $(seq 1 "$done_n"); do hc shutdown --run "$dir/vm-$i"; rm -f "$dir/vm-$i/pid"; done
done

echo
echo "S1 on $(hostname), cloud-hypervisor $CH_VERSION, guest ${SPIKE_MEM_MB} MiB, warm dirtied ${SPIKE_WARM_MB} MiB, each clone ${SPIKE_DIRTY_MB} MiB"
cat "$summary"
echo
echo "Raw numbers: $OUT/*/restores.txt and $OUT/*/smaps.txt"
