# Staging checklist

What cannot be tested automatically, and how to test it by hand.

Every other layer has a home in CI: unit and contract tests cover the SDK boundary, `make
test-pebble` covers the ACME protocol against a real server, `scripts/e2e-wildcard.sh` covers the
wildcard challenge against real DNS. This file is for the things that need a real Tencent Cloud
account, a real CLB, or a certificate issued by a real CA — the parts where a mistake costs quota
or an outage, and where the answer is a person running commands rather than a test suite.

Run it before a release that touches the deployer, the CAM policy, or the provisioning flow.
Everything here uses the **staging** ACME directory and a **test** domain. Nothing here should be
run against production certificates or a production CLB.

---

## 0. Before you start

```sh
# Staging ACME directory, and a domain whose DNS you control.
grep -E '^\s*directory:' /etc/wecert/config.yaml   # must be acme-staging-v02...
export WECERT_DOMAIN=test1.example.com
export WECERT_REGION=ap-guangzhou
```

Checklist-wide: every step below assumes you are looking at `journalctl -u wecert -f` in another
terminal, and that `statePath` points at a **throwaway** database as in `e2e-config.example.yaml`.

---

## 1. First issuance, manual bind, then automatic rebind

The one flow a human is part of, and the one that is hardest to fake.

| # | Do | Expect |
|---|---|---|
| 1.1 | `sudo -u wecert wecert -config … -once` on a fresh state store, **with the daemon stopped** (the state database is locked by a running process, and the refusal is by design) | uploads, prints the uploaded CertId, logs "waiting for a one-time manual bind in the CLB console"; issuance succeeds and `wecert_certificate_deployed` stays **0** |
| 1.2 | Bind that certificate to a CLB listener in the console (an **SNI** listener needs `multi_cert_info`; the primary `certificate_id` is silently ignored) | — |
| 1.3 | Wait one reconcile pass, or POST `/hook/reconcile` | logs "confirmed the certificate is bound"; `wecert_certificate_deployed{cert}` becomes **1** |
| 1.4 | Force the next renewal window (`renewBefore` shorter, or a second staging cert), run a pass | `UpdateCertificateInstance` runs, the listener moves to the new CertId **without** console work |
| 1.5 | `wecert-clbverify -region $WECERT_REGION -clb <id> -expect <newCertId>` | exit 0; the assertion sees SNI extension certificates too |
| 1.6 | `wecert-probe -host $WECERT_DOMAIN -expect-not-after <the new notAfter>` | `ok`, and `notBefore` is recent — the endpoint serves the certificate wecert deployed |

**Failure worth recognising:** if 1.4's rebind reports "found no resource bound to the old
certificate" while the listener is plainly bound, the old certificate was bound as an SNI
extension certificate and `bindingsWith` did not see it. That is the case the `deploy` contract
tests cover on the fake side; here you are confirming the cloud really reports it.

## 2. The async delete, including the refusal that matters

`DeleteCertificate` with `IsCheckResource=true` is asynchronous, and status 4 means "a resource
still references this certificate". Both halves need to be seen once.

| # | Do | Expect |
|---|---|---|
| 2.1 | With a certificate **bound** and past retention (`retention` is 7 days; move `retired_at` back with sqlite3 to force it), run a pass | `Delete` fails, `ReapRetired` logs a warning, and the `retired_certificates` row **stays** |
| 2.2 | Unbind it in the console, run another pass | the delete task reports success, the row goes, and `wecert-preflight -list-certs` no longer shows it |
| 2.3 | Confirm the async task was actually polled | the log shows the task accepted and then the outcome, not an immediate "reclaimed" |

**This is the check for the review's P1-5.** Before that fix, 2.1's row was deleted on the
*accepted* call and the certificate leaked in the account forever.

## 3. CAM policy is minimal and sufficient

The policy files were wrong once: they omitted four `ssl:*` actions the runtime calls, so a role
built from them failed every rebind. Reading the JSON cannot catch a recurrence; running it can.

| # | Do | Expect |
|---|---|---|
| 3.1 | Create a role with **only** `deploy/cam-policy-runtime.json` attached | — |
| 3.2 | Attach it to a CVM (or use its keys), run a full issue → rebind cycle | **no `AuthFailure` / `UnauthorizedOperation`** anywhere in the log |
| 3.3 | Grep the log for the actions that were missing | `DescribeHostUpdateRecordDetail`, `CreateCertificateBindResourceSyncTask` and `DescribeCertificateBindResourceTaskResult` all succeeded |
| 3.4 | Deny one of them deliberately (a second policy with `effect: deny`) | the failure names the action, and the round backs off rather than silently reporting success |

If 3.4 reports success, the code is not reading that response — which is exactly the failure mode
the unread-field test in `internal/deploy` exists to prevent.

## 4. SNI: two certificates on one listener

| # | Do | Expect |
|---|---|---|
| 4.1 | Bind two tested certificates to one SNI listener, then renew one | the other is **untouched**; `wecert-clbverify -not-expect <renewed old id>` passes |
| 4.2 | Run `wecert-clbverify -raw` on the listener | every certificate in `ExtCertIds` is accounted for by some wecert certificate or a known manual one |

## 5. Quota behaviour under a real failure

Deliberately break DNS for one name, and watch wecert not burn the account.

| # | Do | Expect |
|---|---|---|
| 5.1 | Remove the challenge record's zone delegation for one SAN | the authorization fails, and the failure is booked against **that identifier** (`identifier_failures` has one row) |
| 5.2 | Leave it failing, with `failureFallback` **off**, for a day | orders stop being placed for the window, and the backoff caps at 6h — count the orders in the log and compare against "5 per exact set per 7 days" |
| 5.3 | Repeat with `failureFallback` **on**, near expiry | exactly one degraded issuance, then the full set is retried at the **renewal window** — not on every pass, and not merely when the failure evidence ages out (the evidence expiring stops the reduction being forced; the renewal window is what orders; the review's P1-3) |
| 5.4 | Restore the delegation | the next round succeeds with the full set, and the ledger is cleared |

## 6. Crash recovery, for real

The unit tests cover the logic; this covers the process.

| # | Do | Expect |
|---|---|---|
| 6.1 | During DNS propagation, `kill -9` the daemon | the TXT record is in DNS, the `authorizations` row says `presented=0` with a token |
| 6.2 | Start it again | it adopts the existing record rather than writing a duplicate, and finishes |
| 6.3 | `kill -9` between finalize and download | the next pass resumes the same order (same `order_url`) and issues |
| 6.4 | `sqlite3 state.db 'PRAGMA quick_check;'` after each | `ok` |

## 7. Restoring a snapshot, including the caveat

The operator journey whose failure mode is silent: the restore itself succeeds, and the *next*
issuance is refused by the CA because the snapshot's rate-limit ledger stopped when it was written.
Needs a deployment that has issued something, so run it after §1.

| # | Do | Expect |
|---|---|---|
| 7.1 | With the daemon stopped, `wecert -restore latest` | prints the snapshot it chose, the date of its data, the account/certificate count, and the `caveatUntil` date; the database it replaced is kept at `state.db.replaced-<stamp>` |
| 7.2 | `ls -l state.db*` | `state.db` (0600), `state.db.restored`, the `.replaced-<stamp>` file, and **no** `-wal`/`-shm` beside the restored database |
| 7.3 | Start the daemon | a WARN naming `restoredAt`, `dataFrom` and `caveatUntil`; the first pass adopts the restored state (the in-flight order is advanced, not re-placed) |
| 7.4 | Run `wecert -restore latest` **while the daemon is up** | refused, naming the lock file and telling you to stop the process; nothing is moved |
| 7.5 | Point `-restore` at a file that is not a snapshot (`/etc/hostname`) and at a directory with no snapshots | both refused, in the operator's words; the live database is untouched |
| 7.6 | Go back: stop the daemon, `mv state.db.replaced-<stamp> state.db` | the newer state is back (delete `state.db.restored` with it, or the warning outlives the restore it describes) |

**Failure worth recognising:** if the start after a restore logs "no account in the state store;
registering a new ACME account", the snapshot came from a deployment pointed at a different ACME
directory — and that registration is one of the 10 per IP per 3 hours.

## 8. Sign-off

Record, in the release notes or the PR:

- the wecert version and commit;
- which steps ran, and which were skipped **with the reason**;
- any step that produced something other than "Expect", and what it turned out to be.

A skipped step is not a failure. An unexplained green tick is.

---

## What is deliberately not here

- **Load and soak.** Not run by hand at this size; the caps (`maxProbeConcurrency`,
  `maxConcurrentStarts`, `authzFetchConcurrency`, the limiter ceiling) are documented in code.
- **Multi-instance behaviour.** The `flock` makes a second process fail at startup, which is a
  unit-tested contract; a real second instance adds nothing.
- **Disaster recovery.** Its own runbook: `docs/recovery.md`.
