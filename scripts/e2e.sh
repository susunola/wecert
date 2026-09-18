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
# A SKIP is not a pass.
#
# This suite binds port 53 to be a real authoritative server, so on a machine where something
# already holds :53 (a local resolver, a VM's DNS proxy) it skips itself -- and `go test` exits 0
# for a skipped test, so the whole gate reported "pass in 0s" for a suite that never ran. That is
# the one thing an e2e gate must not do: the suites are the evidence, and "we could not run it" is
# not evidence. The skip is detected from the output and reported as such; set
# WECERT_E2E_ALLOW_SKIP=1 to run the rest anyway (the report then says the suite did not run).
start=$(date +%s)
skip_from=$(( $(wc -l <"$LOG") + 1 ))
if WECERT_E2E_REPORT="$GORESULT" "$GO" test -tags "pebble lego_dns" -count=1 -timeout 15m \
	./internal/acme/ -run TestRealDNS01Lifecycle -v >>"$LOG" 2>&1; then
	go_status=pass
else
	go_status=fail
fi
if [[ "$go_status" == pass ]] && tail -n +"$skip_from" "$LOG" | grep -qE '^--- SKIP: TestRealDNS01Lifecycle'; then
	go_status=skip
fi
go_seconds=$(( $(date +%s) - start ))
if [[ "$go_status" == skip ]]; then
	echo "    SKIPPED in ${go_seconds}s: something already holds port 53, so the suite could not run"
	echo "    (it needs to bind :53; see the log for the exact message) -- log: $LOG"
	grep -m1 'cannot bind' "$LOG" | sed 's/^/    /' || true
	if [[ "${WECERT_E2E_ALLOW_SKIP:-0}" != 1 ]]; then
		echo "    this is a failed gate, not a pass; set WECERT_E2E_ALLOW_SKIP=1 to run the rest anyway" >&2
	fi
else
	echo "    $go_status in ${go_seconds}s (log: $LOG)"
fi

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

# With the override set, "skipped" is an accepted outcome for the first suite only -- and it is
# recorded on the page, so a report generated this way cannot be mistaken for a full run.
if [[ "$go_status" == skip && "${WECERT_E2E_ALLOW_SKIP:-0}" == 1 ]]; then
	echo "note: the real DNS-01 suite did not run (WECERT_E2E_ALLOW_SKIP=1); the report says so" >&2
	go_status=skipped
fi
if [[ "$go_status" != pass && "$go_status" != skipped ]]; then
	exit 1
fi
if [[ "$pebble_status" != pass || "$wild_status" != pass ]]; then
	exit 1
fi
