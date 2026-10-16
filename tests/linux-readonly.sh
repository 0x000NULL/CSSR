#!/usr/bin/env bash
# Smoke test for audit/linux/cssr-audit.sh. Run as root (CI uses sudo).
# Checks that the audit runs, exits 0 or 1, writes valid JSON with one result per check,
# and leaves every file under /etc byte-for-byte unchanged.
set -euo pipefail

here=$(cd "$(dirname "$0")/.." && pwd)
audit="$here/audit/linux/cssr-audit.sh"
work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT

snapshot() { find /etc -xdev -type f -readable -print0 2>/dev/null | sort -z | xargs -0 sha256sum 2>/dev/null; }

snapshot >"$work/before"
set +e
"$audit" --no-color --users "$here/audit/examples/users.txt" \
  --admins "$here/audit/examples/admins.txt" --json "$work/report.json" >"$work/out.txt"
status=$?
set -e
snapshot >"$work/after"

cat "$work/out.txt"
echo "exit code: $status"
if [ "$status" -gt 1 ]; then
  echo "FAIL: unexpected exit code $status" >&2
  exit 1
fi

if ! diff -u "$work/before" "$work/after"; then
  echo "FAIL: the audit changed files under /etc" >&2
  exit 1
fi
echo "OK: /etc is unchanged"

expected=$("$audit" --list-checks | wc -l)
python3 - "$work/report.json" "$expected" <<'EOF'
import json, sys
report = json.load(open(sys.argv[1], encoding="utf-8"))
expected = int(sys.argv[2])
results = report["results"]
assert len(results) == expected, f"{len(results)} results, expected {expected}"
assert all(r["status"] in {"PASS", "FAIL", "WARN", "INFO", "SKIP"} for r in results)
assert len({r["id"] for r in results}) == expected, "duplicate check IDs"
print(f"OK: JSON report has {expected} results; summary {report['summary']}")
EOF
