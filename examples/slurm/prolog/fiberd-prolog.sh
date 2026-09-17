#!/usr/bin/env bash
# Slurm prolog for fiberd (PrologFlags=Alloc: runs once per allocation on
# each node, as root, before the job). It stages the grants the issuer
# left for this job in the node's spool into the job's grants directory,
# where fiberd-slurm's lane picks them up. Verification happens in
# fiberd-slurm itself, offline against the issuer's keys, before the agent
# serves anything; the prolog only moves files.
#
# Spool layout: /var/spool/fiberd/grants/<job id>/*.jwt, or
# /var/spool/fiberd/grants/<user>/*.jwt for grants minted per user.
set -eu
: "${SLURM_JOB_ID:?}"
dst="/run/fiberd/job-$SLURM_JOB_ID/grants"
mkdir -p "$dst"
for src in "/var/spool/fiberd/grants/$SLURM_JOB_ID" "/var/spool/fiberd/grants/${SLURM_JOB_USER:-}"; do
  [ -d "$src" ] || continue
  for f in "$src"/*.jwt; do
    [ -f "$f" ] && install -m 0600 "$f" "$dst/"
  done
done
exit 0
