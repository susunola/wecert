#!/usr/bin/env bash
#
# SNI multi-certificate end-to-end check: renewing one certificate on a shared
# listener must not disturb the other.
#
#   ./scripts/e2e-sni.sh <region> <clb-id> <listener-id> <cert-id-A> <cert-id-B> [--yes] [--wait <seconds>]
#
# Example:
#   ./scripts/e2e-sni.sh ap-guangzhou lb-xxxx lbl-yyyy apJdfyPa apJRqDsC --yes
#
# What it does NOT do: it never renews anything itself. It reads the listener,
# asserts the starting shape, hands control back to the operator for the renewal,
# and then re-reads. Driving the renewal is deliberately a human step -- it
# consumes real CA quota and depends on the deployment under test (a SAN added to
# /etc/wecert/config.yaml, or the ARI window opening), and a script that tried to
# force it would be guessing at someone else's configuration.
#
# The claim under test
# --------------------
# README.reference.md says of UpdateCertificateInstance: "There is no listener
# inventory to maintain here, and other certificates on the same listener (SNI)
# are not disturbed." That sentence is a *claim about server behaviour*, and it
# is on the roadmap as an outstanding item ("Test the SNI multi-certificate case
# with multi_cert_info"). This script is what turns it into an observation.
#
# The SDK documents UpdateCertificateInstance as a "one-click update of the old
# certificate's resources": the request carries OldCertificateId, documented as
# "the old certificate ID to update in one click -- the cloud resources that this
# certificate ID is bound to are looked up, and the new certificate is then used
# to update those cloud resources" (ssl/v20191205 models.go; the field comments
# are quoted verbatim in docs/sni-multicert.md, which is why they are not repeated
# here). Neither that request type nor its response type says anything about the
# listener's *other* certificates, so preservation of B is NOT something the SDK
# documentation promises. Read the raw dump; do not take our word for it.
#
# Read path versus write path
# ---------------------------
# On the write side the multi-certificate parameter is `MultiCertInfo.CertList`
# (clb/v20180317 models.go, CreateListener/ModifyListener). On the READ side,
# DescribeListeners returns `Listener.Certificate`, whose `CertId` is documented as
# the ID of the server certificate and whose `ExtCertIds` is documented as the
# extension server certificate IDs of the multi-server-certificate case. So "B is
# present in multi_cert_info" is read back as "B is in Certificate.CertId or
# Certificate.ExtCertIds". The field comments themselves are quoted, in the
# original, in docs/sni-multicert.md.
#
# Usage notes
#   --yes            actually talk to Tencent Cloud. Without it the script prints
#                    the plan and exits 0 without a single API call.
#   --wait <seconds> how long to poll after the renewal for the primary to change
#                    (default 180). UpdateCertificateInstance is asynchronous --
#                    the README measured the rebind at ~15s, with a 30s-2min range.
#   WECERT_CREDS     credentials file, default ~/.wecert/tencent.env, same
#                    variable and format as scripts/run-stage-ab.sh.
#
# Exit codes: 0 = every assertion passed; 1 = assertion failed, or a precondition
# was missing. There is no "skip": this is a procedure an operator runs
# deliberately, so an unusable environment must fail loudly rather than report a
# green that means nothing.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
# WECERT_CLBVERIFY exists so this script's own assertion logic can be exercised
# against a canned DescribeListeners response without a cloud account. It is
# echoed in the plan and in the evidence header, so a run always says which binary
# produced the evidence it is asserting on.
CLBVERIFY="${WECERT_CLBVERIFY:-${ROOT}/bin/wecert-clbverify}"

# ── evidence helpers ────────────────────────────────────────────────────────
#
# Defined before the operator procedure below, and before the argument parsing
# starts, so that scripts/test-e2e-sni.sh can source this file for them. The
# parsing helpers are the part of this script that reads the -raw dump, and they
# were wrong once in a way no run could reveal from the outside (json.load over a
# dump that ends with a human report); the self-test is what keeps them pinned.

SNAPSHOT_FILE=""
# SNAPSHOT_FILTERED records whether the dump came from a listener-filtered query.
# wecert-clbverify's own note says a filtered query can return entries without the
# Certificate field, and its assertions read Listeners[0] -- so when the filter
# comes back empty of certificates we fall back to the unfiltered query for the
# raw evidence, and skip the assertion-shaped calls that would then be looking at
# the wrong listener.
SNAPSHOT_FILTERED=""

snapshot() {
	local label="$1"
	SNAPSHOT_FILE="${EVIDENCE_DIR}/listener-${label}.json"
	SNAPSHOT_FILTERED="yes"

	"${CLBVERIFY}" -region "${REGION}" -clb "${CLB}" -listener "${LISTENER}" -raw >"${SNAPSHOT_FILE}.full"
	# -raw prints the raw DescribeListeners JSON *and then* the human report (added in 6c2057b), so
	# that file is not JSON on its own. Keeping only the first JSON document is what makes
	# listener_field (json.load) able to read it at all: against a real CLB the script used to die
	# with "Extra data: line 121 column 1 (char 3414)" -- the stub table passed only because a stub
	# printed pure JSON. Found by the round-11 verification pass (U98).
	keep_first_json "${SNAPSHOT_FILE}.full" "${SNAPSHOT_FILE}"
	rm -f -- "${SNAPSHOT_FILE}.full"

	if ! listener_field "${SNAPSHOT_FILE}" has-certificate >/dev/null 2>&1; then
		echo "WARN: the listener-filtered DescribeListeners response carries no Certificate field" >&2
		echo "      (wecert-clbverify notes this can happen when filtering by ListenerIds)." >&2
		echo "      Re-reading the whole CLB and selecting ${LISTENER} from it." >&2
		SNAPSHOT_FILTERED="no"
		"${CLBVERIFY}" -region "${REGION}" -clb "${CLB}" -raw >"${SNAPSHOT_FILE}.full"
		keep_first_json "${SNAPSHOT_FILE}.full" "${SNAPSHOT_FILE}"
		rm -f -- "${SNAPSHOT_FILE}.full"
	fi

	echo "--- raw evidence (${label}) -> ${SNAPSHOT_FILE}"
}

show_raw() {
	cat -- "${SNAPSHOT_FILE}"
	echo
}

# keep_first_json <in> <out>
#
# Copies the first complete JSON document from <in> into <out>, discarding whatever follows it.
# wecert-clbverify -raw ends its raw dump with a human-readable report, so a plain json.load on the
# file fails with "Extra data"; raw_decode stops at the end of the first document instead.
keep_first_json() {
	python3 - "$1" "$2" <<'PYEOF'
import json
import sys

src, dst = sys.argv[1], sys.argv[2]
with open(src, encoding="utf-8") as fh:
    text = fh.read()
try:
    value, _ = json.JSONDecoder().raw_decode(text.lstrip())
except ValueError as exc:
    sys.exit("could not find a JSON document in %s: %s" % (src, exc))
with open(dst, "w", encoding="utf-8") as fh:
    json.dump(value, fh)
PYEOF
}

# listener_field <file> <mode>
#   modes: primary | ext | bound | has-certificate | sni-switch
# Reads the -raw DescribeListeners dump. Selects the listener by ListenerId when
# the dump contains it, otherwise the first listener that carries a Certificate.
listener_field() {
	python3 - "$1" "$2" "$LISTENER" <<'PY'
import json
import sys

path, mode, want = sys.argv[1], sys.argv[2], sys.argv[3]

try:
    with open(path, encoding="utf-8") as fh:
        body = json.load(fh)
except (OSError, ValueError) as exc:
    sys.exit("could not parse the raw dump %s: %s" % (path, exc))

listeners = body.get("Listeners") or []
chosen = None
for l in listeners:
    if want and l.get("ListenerId") == want:
        chosen = l
        break
if chosen is None:
    for l in listeners:
        if l.get("Certificate"):
            chosen = l
            break
if chosen is None:
    sys.exit("no listener in %s carries a Certificate field; if this was a "
             "listener-filtered query, cross-check with an unfiltered -raw run" % path)

cert = chosen.get("Certificate") or {}
primary = cert.get("CertId") or ""
ext = [c for c in (cert.get("ExtCertIds") or []) if c]

if mode == "has-certificate":
    # Exit non-zero when the selected listener carries nothing: the caller uses the
    # exit status to decide whether to fall back to an unfiltered query.
    if primary or ext:
        sys.stdout.write("yes\n")
        sys.exit(0)
    sys.exit("the selected listener (%s) carries no Certificate field" % (chosen.get("ListenerId") or "?"))
elif mode == "primary":
    out = [primary] if primary else []
elif mode == "ext":
    out = ext
elif mode == "bound":
    out = ([primary] if primary else []) + ext
elif mode == "sni-switch":
    out = [str(chosen.get("SniSwitch", ""))]
else:
    sys.exit("unknown mode %r" % mode)

sys.stdout.write("\n".join(out) + ("\n" if out else ""))
PY
}

primary_of() { listener_field "$1" primary; }
ext_of() { listener_field "$1" ext; }
bound_of() { listener_field "$1" bound; }

# bound_certs_are <id> <file> -- is the id among the listener's certificates?
bound_certs_are() {
	local id="$1" file="$2" bound
	bound="$(bound_of "${file}")"
	[[ -n "${bound}" ]] || return 1
	printf '%s\n' "${bound}" | grep -qxF -- "${id}"
}

# Sourced for those helpers by scripts/test-e2e-sni.sh: everything below is the
# operator procedure, which must not run there -- it parses its own argv, requires
# cloud credentials and talks to the API. `return` is valid precisely when the file
# was sourced, which is what the guard detects.
if [[ "${BASH_SOURCE[0]}" != "${0}" ]]; then
	return 0
fi

usage() {
	cat >&2 <<'EOF'
Usage: ./scripts/e2e-sni.sh <region> <clb-id> <listener-id> <cert-id-A> <cert-id-B> [--yes] [--wait <seconds>]

  region       e.g. ap-guangzhou
  clb-id       CLB instance ID, e.g. lb-xxxx
  listener-id  HTTPS listener ID carrying both certificates, e.g. lbl-yyyy
  cert-id-A    the certificate wecert manages and will renew (currently primary)
  cert-id-B    the other certificate on the same listener, which must survive

  --yes          perform the run; without it only the plan is printed
  --wait <secs>  poll this long for the primary to change (default 180)

Without --yes nothing is sent to Tencent Cloud at all. This script is read-only
against the API: it calls DescribeListeners through wecert-clbverify, and never
Create/Modify/Delete anything.
EOF
}

REGION=""
CLB=""
LISTENER=""
CERT_A=""
CERT_B=""
CONFIRM=""
WAIT_SECONDS=180

positional=()
while [[ $# -gt 0 ]]; do
	case "$1" in
	--yes)
		CONFIRM="--yes"
		shift
		;;
	--wait)
		if [[ $# -lt 2 ]]; then
			echo "Error: --wait needs a value in seconds" >&2
			exit 1
		fi
		WAIT_SECONDS="$2"
		shift 2
		;;
	-h | --help)
		usage
		exit 0
		;;
	-*)
		echo "Error: unknown argument: $1" >&2
		usage
		exit 1
		;;
	*)
		positional+=("$1")
		shift
		;;
	esac
done

if [[ "${#positional[@]}" -ne 5 ]]; then
	echo "Error: expected 5 positional arguments, got ${#positional[@]}" >&2
	usage
	exit 1
fi

REGION="${positional[0]}"
CLB="${positional[1]}"
LISTENER="${positional[2]}"
CERT_A="${positional[3]}"
CERT_B="${positional[4]}"

if [[ ! "${WAIT_SECONDS}" =~ ^[0-9]+$ ]]; then
	echo "Error: --wait takes a whole number of seconds, got: ${WAIT_SECONDS}" >&2
	exit 1
fi

if [[ "${CERT_A}" == "${CERT_B}" ]]; then
	echo "Error: cert-id-A and cert-id-B are both ${CERT_A}; this check is about two distinct certificates." >&2
	exit 1
fi

# ── credentials ─────────────────────────────────────────────────────────────
#
# Checked before the --yes gate on purpose: "this script cannot run here" is a
# more useful answer than a printed plan, and it must be non-zero rather than a
# silent skip. The test suites skip when credentials are absent; an operator
# procedure must not, because a skipped procedure is indistinguishable from a
# passing one in a release record.

CREDS="${WECERT_CREDS:-${HOME}/.wecert/tencent.env}"

# Same extraction as scripts/run-stage-ab.sh: read only the two variables this
# script needs, never `source` a file that usually holds unrelated secrets too.
# Both `KEY=value` and `export KEY=value` are accepted, quotes are stripped the
# way a shell would, and a trailing comment only counts outside quotes.
cred_value() {
	local raw
	raw="$(sed -n \
		-e "s/^[[:space:]]*export[[:space:]][[:space:]]*$1=\(.*\)/\1/p" \
		-e "s/^[[:space:]]*$1=\(.*\)/\1/p" \
		"${CREDS}" | tail -n 1)"
	raw="${raw#"${raw%%[![:space:]]*}"}"
	raw="${raw%"${raw##*[![:space:]]}"}"
	case "${raw}" in
	\"*)
		raw="${raw#\"}"
		raw="${raw%%\"*}"
		;;
	\'*)
		raw="${raw#\'}"
		raw="${raw%%\'*}"
		;;
	*)
		raw="$(printf '%s' "${raw}" | sed 's/[[:space:]][[:space:]]*#.*$//')"
		;;
	esac
	printf '%s' "${raw}"
}

if [[ -n "${CREDS}" && -f "${CREDS}" ]]; then
	[[ -n "${TENCENTCLOUD_SECRET_ID:-}" ]] || TENCENTCLOUD_SECRET_ID="$(cred_value TENCENTCLOUD_SECRET_ID)"
	[[ -n "${TENCENTCLOUD_SECRET_KEY:-}" ]] || TENCENTCLOUD_SECRET_KEY="$(cred_value TENCENTCLOUD_SECRET_KEY)"
fi

missing=()
[[ -n "${TENCENTCLOUD_SECRET_ID:-}" ]] || missing+=("TENCENTCLOUD_SECRET_ID")
[[ -n "${TENCENTCLOUD_SECRET_KEY:-}" ]] || missing+=("TENCENTCLOUD_SECRET_KEY")
if [[ "${#missing[@]}" -gt 0 ]]; then
	echo "Error: refusing to run: missing cloud credentials: ${missing[*]}" >&2
	echo "       wecert-clbverify calls clb:DescribeListeners, which needs a CAM credential pair." >&2
	if [[ -f "${CREDS}" ]]; then
		echo "       ${CREDS} exists but does not define ${missing[*]}." >&2
	else
		echo "       ${CREDS} does not exist." >&2
	fi
	echo "       Either export TENCENTCLOUD_SECRET_ID and TENCENTCLOUD_SECRET_KEY, or write them" >&2
	echo "       (one per line, with or without 'export ') into ${CREDS}, or point WECERT_CREDS at" >&2
	echo "       another file." >&2
	exit 1
fi
export TENCENTCLOUD_SECRET_ID TENCENTCLOUD_SECRET_KEY

# ── tools ───────────────────────────────────────────────────────────────────

# Checked after the --yes gate, so the plan above is printable without a build.
if [[ "${CONFIRM}" == "--yes" ]]; then
	if [[ ! -x "${CLBVERIFY}" ]]; then
		echo "Error: ${CLBVERIFY} is missing or not executable. Run: make tools" >&2
		exit 1
	fi

	if ! command -v python3 >/dev/null 2>&1; then
		echo "Error: python3 is required to read the raw DescribeListeners JSON (the -raw dump is JSON, not a stable CLI contract)." >&2
		exit 1
	fi
fi

# ── the plan ────────────────────────────────────────────────────────────────

cat <<EOF
==============================================
 wecert SNI multi-certificate check

 region        : ${REGION}
 CLB           : ${CLB}
 listener      : ${LISTENER}
 certificate A : ${CERT_A}   (managed by wecert, will be renewed)
 certificate B : ${CERT_B}   (must survive the renewal untouched)
 wait after    : ${WAIT_SECONDS}s
 clbverify     : ${CLBVERIFY}

 Assertions, in order:
   1. the listener's PRIMARY certificate is A
   2. B is present among the listener's certificates (multi_cert_info)
   3. after you renew A: the primary is a NEW certificate id
   4. after you renew A: B is still bound, with the same certificate id
   5. after you renew A: A is no longer bound anywhere on the listener
==============================================
EOF

if [[ "${CONFIRM}" != "--yes" ]]; then
	cat <<EOF

Not running. Nothing has been sent to Tencent Cloud.

This step reads a real listener and then waits for you to renew a real
certificate, so it needs a deliberate confirmation. When you are ready:

    $0 ${REGION} ${CLB} ${LISTENER} ${CERT_A} ${CERT_B} --yes

EOF
	exit 0
fi

EVIDENCE_DIR="${EVIDENCE_DIR:-${ROOT}/dist/sni-$(date +%Y%m%dT%H%M%S)-$$}"
mkdir -p "${EVIDENCE_DIR}"

# clbverify_assert <args...> -- run the tool's own assertion path, so the verdict
# is not only this script's parsing. Skipped when the dump had to fall back to the
# unfiltered query, because the tool then reads a listener we did not choose.
clbverify_assert() {
	if [[ "${SNAPSHOT_FILTERED}" != "yes" ]]; then
		echo "NOTE: skipping the wecert-clbverify assertion below: the evidence came from an"
		echo "      unfiltered query, and the tool would assert against Listeners[0]."
		return 0
	fi
	"${CLBVERIFY}" -region "${REGION}" -clb "${CLB}" -listener "${LISTENER}" "$@"
}

fail() {
	echo >&2
	echo "FAIL: $*" >&2
	echo "The raw dumps are in ${EVIDENCE_DIR}." >&2
	exit 1
}

# ── 1. the starting shape ───────────────────────────────────────────────────

echo
echo "=== [1/4] read the listener before the renewal ==="
snapshot before
show_raw
BEFORE_FILE="${SNAPSHOT_FILE}"

BEFORE_PRIMARY="$(primary_of "${BEFORE_FILE}")"
BEFORE_EXT="$(ext_of "${BEFORE_FILE}")"
BEFORE_SNI="$(listener_field "${BEFORE_FILE}" sni-switch)"

echo "SniSwitch        : ${BEFORE_SNI:-<absent>}"
echo "primary          : ${BEFORE_PRIMARY:-<none>}"
echo "extension certs  : ${BEFORE_EXT:-<none>}"
echo

[[ -n "${BEFORE_PRIMARY}" ]] ||
	fail "the listener has no primary certificate (Certificate.CertId is absent or empty), so there is no A to swap. Two known shapes produce this: an SNI listener that was created with certificate_id instead of multi_cert_info (README.reference.md: CLB silently ignores the primary certificate then), or a listener whose certificates are ALL reported as extension certificate ids. Read the raw dump above: if ExtCertIds lists ${CERT_A} and ${CERT_B}, the check's model of 'A is primary, B is an extension' does not match how this listener reports itself, and that mismatch is itself worth writing down before trusting anything else."

[[ "${BEFORE_PRIMARY}" == "${CERT_A}" ]] ||
	fail "the listener's primary certificate is ${BEFORE_PRIMARY}, but A was given as ${CERT_A}. Either A already moved (an earlier renewal), the two ids were swapped on the command line, or the two certificates live on different listeners. Nothing has been changed by this script."

if ! bound_certs_are "${CERT_B}" "${BEFORE_FILE}"; then
	fail "B=${CERT_B} is not bound to listener ${LISTENER} (bound: ${BEFORE_PRIMARY} ${BEFORE_EXT}). This check needs both certificates on one listener before it starts."
fi

# B is in the bound set and the primary is A, so B has to be one of the extension
# certificate ids -- that is the read-side shape of "B is in multi_cert_info". The
# raw dump above is what a reviewer wants next to this line.
echo "OK: A is the primary certificate and B is an extension certificate (ExtCertIds) -- the shape this check is for."

echo
echo "--- wecert-clbverify's own assertion: B must be present ---"
clbverify_assert -expect "${CERT_B}"

# ── 2. the renewal, performed by the operator ───────────────────────────────

echo
echo "=== [2/4] renew A -- this is your step ==="
cat <<EOF

Renew certificate A (${CERT_A}) now, on the host that runs wecert. Two ways this
normally happens:

  a) a domain-set change forces an immediate reissue: add a SAN to the
     certificate's domains in /etc/wecert/config.yaml, then
         sudo systemctl restart wecert
     ("the live certificate's SANs no longer match the config; reissuing now")

  b) the ARI window has opened, so the ordinary pass renews it:
         sudo systemctl start wecert-once.service     # timer mode
     or wait for the daemon's hourly pass. Running a pass by hand with
     "wecert -once" only works while the daemon is stopped: it takes the same
     state lock, and a second process is refused with "the state database is
     already held by another wecert process".

Wait for this line in journalctl before continuing:

    certificate renewed and live cert=... deployedCertId=<the new id>

Then type "renewed" below. The new certificate id is read from the listener, so
you do not need to know it in advance.

Evidence so far: ${EVIDENCE_DIR}
EOF
printf 'Type "renewed" once the renewal has finished: '
if ! read -r answer; then
	fail "stdin closed before confirmation. This step is interactive on purpose: renewing a certificate consumes real CA quota, so it is never started by the script and never assumed."
fi
if [[ "${answer}" != "renewed" ]]; then
	fail "aborted: expected exactly \"renewed\", got \"${answer}\". Nothing was changed by this script."
fi

# ── 3. wait for the rebind ──────────────────────────────────────────────────

echo
echo "=== [3/4] wait for the rebind (asynchronous, up to ${WAIT_SECONDS}s) ==="

deadline=$((SECONDS + WAIT_SECONDS))
AFTER_FILE=""
AFTER_PRIMARY=""
while :; do
	snapshot after
	AFTER_FILE="${SNAPSHOT_FILE}"
	AFTER_PRIMARY="$(primary_of "${AFTER_FILE}")"
	if [[ -n "${AFTER_PRIMARY}" && "${AFTER_PRIMARY}" != "${CERT_A}" ]]; then
		break
	fi
	if ((SECONDS >= deadline)); then
		break
	fi
	printf '  primary is still %s; re-reading in 5s (%ss left)\n' "${AFTER_PRIMARY:-<none>}" "$((deadline - SECONDS))"
	sleep 5
done

echo
show_raw

# ── 4. the assertions ───────────────────────────────────────────────────────

echo
echo "=== [4/4] assertions after the renewal ==="

AFTER_EXT="$(ext_of "${AFTER_FILE}")"
echo "primary          : ${AFTER_PRIMARY:-<none>}"
echo "extension certs  : ${AFTER_EXT:-<none>}"
echo

[[ -n "${AFTER_PRIMARY}" ]] ||
	fail "after ${WAIT_SECONDS}s the listener has no primary certificate at all. That is worse than 'not switched': check the raw dump for a listener whose certificate binding was dropped."

[[ "${AFTER_PRIMARY}" != "${CERT_A}" ]] ||
	fail "after ${WAIT_SECONDS}s the primary is still A=${CERT_A}. The renewal did not reach this listener. Check: did the renewal actually finish (journalctl), and is ${CLB}/${LISTENER} in tencent.regions and bound to the OLD certificate id the state store recorded? UpdateCertificateInstance only updates resources bound to that old id."

[[ "${AFTER_PRIMARY}" != "${CERT_B}" ]] ||
	fail "after the renewal the primary is B=${CERT_B}. A's replacement should have taken A's place; B becoming primary means the listener's certificate set was rewritten rather than one entry replaced -- exactly the failure this check exists to catch."

bound_certs_are "${CERT_B}" "${AFTER_FILE}" ||
	fail "B=${CERT_B} was bound before the renewal and is not bound now (bound: ${AFTER_PRIMARY} ${AFTER_EXT}). Renewing A disturbed B."

echo "OK: primary is ${AFTER_PRIMARY} (a new certificate id, not A=${CERT_A})"
echo "OK: B=${CERT_B} is still bound with the same certificate id"

# Assertion 5 ("A is no longer bound anywhere on the listener") reads the STORED dump, not
# a fresh query: clbverify_assert below re-asks the API, so it would pass against a state
# the evidence in ${EVIDENCE_DIR} does not show (and it skips entirely on the unfiltered
# fallback). This check is what the saved dump is asserted to show.
if bound_certs_are "${CERT_A}" "${AFTER_FILE}"; then
	fail "A=${CERT_A} is still bound to listener ${LISTENER} after the renewal (bound: ${AFTER_PRIMARY} ${AFTER_EXT}). The old certificate id should be gone from the listener once the rebind lands."
fi
echo "OK: A=${CERT_A} is no longer bound anywhere on the listener"

# Anything else on the listener that changed is reported, not asserted on: the
# pair (primary + ExtCertIds) is not a documented, stable representation of a
# multi-certificate listener, so a strict set comparison here would produce false
# failures. A human reads this. A, B and the new primary are removed from both
# sides first, so the expected swap does not show up as a difference.
before_others="$(printf '%s\n' "${BEFORE_EXT}" | grep -vxF -e "${CERT_A}" -e "${CERT_B}" | sed '/^$/d' | sort || true)"
after_others="$(printf '%s\n' "${AFTER_EXT}" | grep -vxF -e "${CERT_A}" -e "${CERT_B}" -e "${AFTER_PRIMARY}" | sed '/^$/d' | sort || true)"
if [[ "${before_others}" != "${after_others}" ]]; then
	echo
	echo "WARN: certificates other than A and B differ between the two reads:"
	printf '  before: %s\n' "${before_others:-<none>}"
	printf '  after : %s\n' "${after_others:-<none>}"
	echo "      Read the two raw dumps before signing this off: B survived, but something"
	echo "      else on the listener may not have."
fi

echo
echo "--- wecert-clbverify's own assertion: the old A must be gone ---"
# A live re-query, so it confirms the CURRENT state; the script-side check above is the one
# tied to the stored evidence, and the only one of the two that runs on the unfiltered
# fallback (see clbverify_assert).
clbverify_assert -not-expect "${CERT_A}"

cat <<EOF

==============================================
 PASS (mechanical assertions)

   primary before : ${CERT_A}
   primary after  : ${AFTER_PRIMARY}
   B before/after : ${CERT_B} / unchanged certificate id

 Raw evidence for independent review:
   ${EVIDENCE_DIR}

 What this does NOT prove:
   - that the certificate now primary is actually SERVED. The control plane can
     report a binding that a TLS handshake does not see. Prove that separately,
     with a real handshake against the VIP:
       openssl s_client -connect <clb-vip>:443 -servername <host> -showcerts
     or: ./bin/wecert-probe -host <host>
   - that B still serves on its own hostname. Do the same handshake with B's
     SNI name.
   - anything about other listeners: this check reads exactly one.
   - that the renewal was a renewal: if A's old id was replaced by a fresh
     issuance rather than a rebind, these assertions still pass. journalctl is
     where "certificate renewed and live" proves the path that ran.
==============================================
EOF
