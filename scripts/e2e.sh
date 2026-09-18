#!/usr/bin/env bash
# The end-to-end run, and the HTML report it produces.
#
# Three suites, in increasing order of what they can prove:
#
#   1. TestRealDNS01Lifecycle  -- a real ACME server, a real authoritative DNS server on port 53,
#                                 the real solver writing real records, the real propagation check
#                                 reading them back over the wire, a real certificate over the wire.
#   2. TestPebble*             -- the order protocol against the same real ACME server, for the
#                                 parts DNS-01 does not touch (account/key binding, CSR finalize,
#                                 chain download).
#   3. test-e2e-wildcard.sh    -- the shared apex/wildcard challenge name, against a canned
#                                 resolver, so it runs with no network at all.
#
# What it deliberately does NOT do is pretend: the cloud deploy and the Let's Encrypt staging run
# both need credentials this script does not have, and they appear in the report as "not run" with
# the exact command that would run them.
#
# Usage: scripts/e2e.sh [--out HTML]
set -uo pipefail

cd "$(dirname "$0")/.." || exit 1

GO="${GO:-go}"
export GOCACHE="${GOCACHE:-$HOME/.cache/go-build}"
export GOPATH="${GOPATH:-$HOME/go}"
PATH="$GOPATH/bin:$PATH"

OUT="docs/e2e-run-$(date +%Y-%m-%d).html"
while [[ $# -gt 0 ]]; do
	case "$1" in
	--out) OUT="$2"; shift 2 ;;
	*) echo "unknown argument: $1" >&2; exit 2 ;;
	esac
done

mkdir -p dist
# Absolute: `go test` runs the binary with the package directory as its working directory, so a
# relative path handed to the test lands under internal/acme/ instead of the repository root.
ROOT="$(pwd)"
GORESULT="$ROOT/dist/e2e-go.json"
EXTRAS="$ROOT/dist/e2e-extras.json"
LOG="$ROOT/dist/e2e.log"
: >"$LOG"

echo "==> 1/3 real DNS-01 lifecycle (pebble + authoritative DNS on :53 + real solver)"
start=$(date +%s)
if WECERT_E2E_REPORT="$GORESULT" "$GO" test -tags "pebble lego_dns" -count=1 -timeout 15m \
	./internal/acme/ -run TestRealDNS01Lifecycle -v >>"$LOG" 2>&1; then
	go_status=pass
else
	go_status=fail
fi
go_seconds=$(( $(date +%s) - start ))
echo "    $go_status in ${go_seconds}s (log: $LOG)"

echo "==> 2/3 ACME order protocol against pebble"
start=$(date +%s)
if "$GO" test -tags pebble -count=1 -timeout 10m ./internal/acme/ -run TestPebble -v >>"$LOG" 2>&1; then
	pebble_status=pass
else
	pebble_status=fail
fi
pebble_seconds=$(( $(date +%s) - start ))
echo "    $pebble_status in ${pebble_seconds}s"

echo "==> 3/3 wildcard/apex shared-name logic (canned resolver, no network)"
start=$(date +%s)
if bash scripts/test-e2e-wildcard.sh >>"$LOG" 2>&1; then
	wild_status=pass
else
	wild_status=fail
fi
wild_seconds=$(( $(date +%s) - start ))
echo "    $wild_status in ${wild_seconds}s"

python3 - "$EXTRAS" "$go_status" "$go_seconds" "$pebble_status" "$pebble_seconds" "$wild_status" "$wild_seconds" <<'PY'
import json, platform, subprocess, sys

out, *rest = sys.argv[1:]
def gokey(k):
    try:
        return subprocess.run(["go", "version"], capture_output=True, text=True).stdout.strip()
    except Exception:
        return "unknown"

payload = {
    "suites": [
        {"name": "TestRealDNS01Lifecycle", "what": "real ACME server + real authoritative DNS on :53 + real solver + real propagation check",
         "verdict": rest[0], "seconds": int(rest[1])},
        {"name": "TestPebble (order protocol)", "what": "account/key binding, authorization polling, CSR finalize, chain download against the same real ACME server",
         "verdict": rest[2], "seconds": int(rest[3])},
        {"name": "test-e2e-wildcard.sh", "what": "the shared apex/wildcard _acme-challenge name, against a canned resolver",
         "verdict": rest[4], "seconds": int(rest[5])},
    ],
    "host": platform.platform(),
    "go": gokey("go"),
}
open(out, "w").write(json.dumps(payload, indent=2))
PY

echo "==> report"
python3 scripts/e2e-report.py --go-report "$GORESULT" --extras "$EXTRAS" --out "$OUT"
echo "    $OUT"

if [[ "$go_status" != pass || "$pebble_status" != pass || "$wild_status" != pass ]]; then
	exit 1
fi
