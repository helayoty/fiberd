#!/usr/bin/env bash
# Print the license and NOTICE files of the third-party code the given Go
# packages link, for a THIRD_PARTY_NOTICES file. That is Go's standard
# library and every module the packages import, as found at the module's
# root. GOOS, GOARCH and CGO_ENABLED pick the build, since each platform
# links only its own dependencies.
#
#   hack/release/third-party-notices.sh ./cmd/fiberd > THIRD_PARTY_NOTICES
set -euo pipefail

section() { # section <title> <file>
  printf '%s\n%s\n%s\n\n' "================================================================" "$1" \
    "================================================================"
  cat "$2"
  printf '\n'
}

echo "These programs include the third-party software below, each under its own license."
echo
section "Go standard library, $(go env GOVERSION)" "$(go env GOROOT)/LICENSE"
go list -deps -f '{{with .Module}}{{if not .Main}}{{.Path}} {{.Version}} {{.Dir}}{{end}}{{end}}' "$@" |
  sort -u | while read -r path version dir; do
    found=""
    for file in "$dir"/LICENSE* "$dir"/LICENCE* "$dir"/COPYING* "$dir"/NOTICE*; do
      [[ -f "$file" ]] || continue
      section "$path $version, ${file##*/}" "$file"
      found=1
    done
    if [[ -z "$found" ]]; then
      echo "third-party-notices: $path has no license file in $dir" >&2
      exit 1
    fi
  done
