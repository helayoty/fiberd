# Security policy

## Reporting a vulnerability

Report a vulnerability privately through GitHub's private vulnerability reporting. Open the repository's Security tab and choose "Report a vulnerability". Do not open a public issue, pull request or discussion for it.

Include the version, the backend, how to reproduce it and the impact.

## Scope

In scope is the code in this repository and what the releases ship. That is the binaries, the libfiberzygote library and the `ghcr.io/helayoty/fiberd` image. Bugs in dependencies such as criu, runc or gVisor belong to their projects, unless fiberd uses them unsafely.

fiberd is a reference implementation and not yet production-ready. The gaps that [docs/production-readiness.md](docs/production-readiness.md) lists are known and need no report. [docs/security.md](docs/security.md) states the trust boundaries, and a way across one is a vulnerability.

## What to expect

A maintainer acknowledges the report within a week. Fixes ship in a new release with an advisory that credits you, unless you ask otherwise. Only the latest release gets fixes.
