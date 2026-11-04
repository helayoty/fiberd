#!/usr/bin/env bash
# Print the dev image's tag, a hash of every file its build reads: the
# Dockerfile, which pins every download, and the sources of its COPY lines.
# Those lines are read rather than listed here, so a new COPY joins the
# hash as long as it stays on one line. hack/dev/run.sh and
# .github/workflows/dev-image.yml both call this, so what is published and
# what is pulled carry the same tag.
set -euo pipefail
cd "$(dirname "$0")/../.."

{
  echo docker/dev/Dockerfile
  awk '$1 == "COPY" && !/--from=/ { for (i = 2; i < NF; i++) if ($i !~ /^--/) print $i }' docker/dev/Dockerfile
} | LC_ALL=C sort | xargs cat | shasum -a 256 | cut -c1-16
