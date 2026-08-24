#!/usr/bin/env bash
# Audit the project's locked dependencies for known CVEs (issue #697).
#
# The project's third-party dependency graph lives in uv.lock. Exporting it to a
# requirements file and running `pip-audit -r` on that file audits exactly the
# packages that get deployed — and keeps the scanner tooling (pip-audit/bandit)
# out of the audited set, so a project CVE can never pass CI silently.
set -euo pipefail

REQ_FILE="${REQ_FILE:-/tmp/requirements-audit.txt}"

uv export --locked --no-hashes --no-emit-project -o "$REQ_FILE"
exec pip-audit -r "$REQ_FILE" --desc on
