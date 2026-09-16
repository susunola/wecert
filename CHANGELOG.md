# Changelog

## Unreleased

### Added

- Property and fuzz targets for `internal/ratelimit` (`internal/ratelimit/fuzz_test.go`,
  `fuzz_parse_test.go`), with a committed regression corpus replayed by plain `go test` and a
  `make fuzz` target. **Not yet wired into CI**: the token used for that needs the `workflow`
  scope, which it does not have, so the CI step is left for whoever has it.
- **`deploy/prometheus/wecert-alerts.yml`**: 17 ready-to-load alert rules in three groups
  (`wecert.expiry`, `wecert.convergence`, `wecert.integrity`), each threshold with a comment saying
  where the number came from. Several of the failures they watch for are silent by construction — a
  revocation the CA never accepted, a pass that has not finished in two hours, a certificate serving
  that is not the one deployed — so the alert is the only thing that notices.
- **`wecert_last_reconcile_timestamp_seconds`**, stamped when a full pass finishes and never when one
  starts, so a hung pass goes stale exactly like a dead process. `wecert_reconcile_total` could not
  answer this: it stops moving both when nothing is due and when the loop is wedged.
- **`wecert_revocation_query_errors_total`**, so a frozen `wecert_revocation_pending` is
  distinguishable from a genuinely empty queue.
- **`make sbom`** (CycloneDX, from the module graph) and **`make repro-check`** (rebuilds each
  platform twice and compares the bytes). The first answers "what is in the binary" without resolving
  the transitive tree by hand; the second makes "this artifact was built from that commit" checkable
  rather than asserted.
- **`make check-alerts`**, which fails if a rule refers to a `wecert_*` series this program does not
  export, if two rules share a name, or if a rule has no expression. It exists because of the dead
  alert above: a rule against a series that does not exist is syntactically perfect and can never
  fire.
- **`SECURITY.md`**, **`CONTRIBUTING.md`**, **`.github/CODEOWNERS`**,
  **`.github/PULL_REQUEST_TEMPLATE.md`** and **`.github/dependabot.yml`**. The security policy states
  its reporting channel honestly (GitHub private reporting is currently **off** in this repository, so
  the fallback is written down instead of assumed), the contribution guide requires a test that fails
  without the change and forbids comments the code does not back, and Dependabot is weekly with one
  dependency per PR because a certificate renewer runs on a host nobody wants to babysit.
- **Periodic, consistent snapshots of `state.db`** (`stateBackup`, on by default: 24h
  interval, 7 kept, beside the database). They use `VACUUM INTO`, not a file copy — the
  database runs in WAL mode, so a copy of `state.db` alone can miss the order URL committed
  seconds earlier, which is the one thing a backup exists to recover. Snapshots are written
  `0600` (they hold the account key and every certificate private key) and pruned newest-first.
  Until now the only guidance was a README line calling it "the one thing to back up", with
  nothing implementing or checking it.
- **`docs/recovery.md`**: what is in `state.db` and what each loss costs, how to restore a
  snapshot and verify it before starting, what happens when there is no snapshot (including
  the rate-limit consequence), and how to roll a certificate back using the archived material.
- `wecert-preflight`'s `-prune-certs` documentation now states that it bypasses the
  server-side reference check on purpose. (Earlier in this release.)

### Changed

- `run-stage-ab.sh` extracts credentials with or without a leading `export`,
  so a file that is only meant to be sourced interactively is no longer
  reported as "not set".
- Deployment retries persist an uploaded Tencent Cloud certificate ID before starting
  its asynchronous rebind. A restart or timeout now resumes that same certificate
  instead of repeatedly uploading new copies; partial rebind failures remain failures.
- Failure fallback remains reported while a full-name restoration attempt is pending or
  fails; it clears only after a verified full certificate is promoted.

### Fixed

- **`ratelimit`: integer divide by zero on a limit with no refill interval.** `Remaining` divides
  by `Limit.Refill`, so a zero (or negative) interval panicked. Unreachable through today's
  callers — every `Limit` comes from the published table in that file — but reachable through the
  public API, which is what a fuzzer checks and a review does not. A degenerate interval is now
  read as "never refills", the conservative direction.
- **`ratelimit`: a negative cost credited the bucket.** `Spend` computed `tokens - cost`, so
  passing a negative cost *increased* the reported allowance. The API records consumption, so a
  negative cost is now "nothing was consumed" rather than a credit.
- **`ratelimit`: `ParseRetryAfter` reported the zero instant as a parsed deadline.**
  `"retry after 0001-01-01 00:00:00 UTC"` parses cleanly and equals `time.Time{}`, which is the
  value callers use for "no deadline" — so a malformed instant would have silently disabled the
  block that protects the rate-limit budget while looking like a successful parse.
- **`wecert_revocation_pending` can no longer report a false all-clear.** `PendingRevocations` used
  to swallow a store error and return `0`, which is a meaningful answer ("nothing outstanding") — so
  a database that could not be read looked exactly like a deployment with no outstanding revocation.
  It now returns the error, and the reconciler leaves the gauge at its last value and counts the pass
  in the new `wecert_revocation_query_errors_total` instead. A pending revocation is an outstanding
  security action: the row exists because someone decided a certificate must stop being trusted.
- **`WecertHasNotReconciledRecently` could never fire.** The rule was written against
  `wecert_reconcile_total_created_timestamp`, which is not a series: the exposition is the classic
  text format, which carries no `_created` timestamps at all. The expression parsed perfectly, so
  nothing complained, and "the daemon is up and converging nothing" had no alert. It now uses the new
  `wecert_last_reconcile_timestamp_seconds` gauge.
- `UploadCertificate` now reads `RepeatCertId`. The SDK documents that once the same
  certificate has been uploaded more than 5000 times the API ignores `Repeatable=true` and
  returns the existing copy's ID there instead of creating another one; reading only
  `CertificateId` turned that into "UploadCertificate returned no CertificateId", an error that
  names neither the cause nor the fix. The duplicate's ID is the same certificate, so it is a
  usable answer.

All three `ratelimit` findings were found by fuzz testing (`make fuzz`). The first two came from a
30-second run over 387 lines of pure arithmetic.

- A **corrupt or truncated `state.db`** now fails with an actionable error naming the file and
  pointing at `docs/recovery.md`, instead of a raw SQLite code ("database disk image is
  malformed (11)") from whichever statement happened to touch it first. The check is
  `PRAGMA quick_check`, run before any migration.
- **Losing `state.db` no longer passes silently.** If the file is absent while its lock file
  exists — which is what a deleted or lost database looks like, and never a first install —
  wecert warns loudly at startup that the ACME account key and every in-flight order are gone
  and that orders will be re-placed into the exact-set limit.
- **A retired certificate keeps its key material.** `retired_certificates` used to hold only
  the CertId while the private key was overwritten in the `certificates` row at the moment of
  renewal, so "kept for rollback" meant "whatever the cloud still has": once the retention
  period expired and the reaper deleted the cloud copy, there was nothing left to re-upload.
  The fullchain and key are now archived with the row, so the rollback is real, and they are
  pruned with it. Existing databases gain the columns on upgrade; legacy rows keep NULL.
- **The failure fallback no longer oscillates.** A successful issuance for the
  reduced subset used to reset `consecutive_failures` and clear the identifier
  ledger, the pre-expiry window was re-evaluated as "the danger is over" once a
  fresh subset certificate moved `notAfter` months out, and the SAN-drift check
  re-ordered the full set on every pass. The net effect was an order per backoff
  window for the identifier set that was already known to be broken, which
  exhausts Let's Encrypt's 5-per-exact-set/7-days quota within days. The
  fallback now holds until the failure evidence ages out.
- A degraded issuance keeps its failure evidence: `consecutive_failures` and the
  per-identifier ledger survive a successful subset order, so the next pass can
  still tell that something is broken.
- `DeleteCertificate` is treated as what it is: `IsCheckResource=true` makes the
  call asynchronous and returns a task ID, so the task is now polled through
  `DescribeDeleteCertificatesTaskResult` and `DeleteResult` is honoured.
  Reporting "accepted" as "deleted" made `ReapRetired` drop its reclaim record
  and leak the certificate forever -- including the case the resource check
  exists for, which arrives asynchronously as status 4.
- `Deploy` no longer reports a partial rebind as success. Its recovery path
  ("is the new certificate already bound?") ran for every failure, and a
  half-migrated fleet has some listener on the new certificate, so the answer
  was yes and the remaining listeners were never revisited. That path now runs
  only for the "nothing was bound to the old certificate" verdict.
- An in-progress update task is no longer adopted as this deploy's outcome.
  `DeployStatus == 0` means the request created nothing and the returned record
  ID belongs to someone else's task; that task is now waited on and then
  verified against *this* certificate before success is reported.
- The CAM policies gain the three `ssl:*` actions the runtime actually calls
  (`DescribeHostUpdateRecordDetail` on every rebind, `CreateCertificateBindResourceSyncTask`
  and `DescribeCertificateBindResourceTaskResult` behind the `deployed` metric)
  and drop the unused `ssl:DescribeCertificate`. A least-privilege role built
  from the old files failed every rebind. **If you built a role from these
  files, reapply them.**
- `renewBefore` at or beyond the profile's validity is rejected: it puts the
  renewal instant in the past from issuance, and ARI only hides that until ARI
  is unavailable, at which point every pass re-orders the same set.
- A `{"cert": ""}` (or `"cert": null`) trigger is rejected with 400 instead of
  widening into a full-fleet convergence, matching the existing `certs` guard.
  This is the shape a CI job produces when it templates an unset `$CERT`.
- A second YAML document in the config or the desired-state document is rejected
  rather than silently ignored.
- A `generatedAt` in the future is rejected: it made `time.Since` negative and
  disabled the document staleness alarm permanently, and `Revision` does not
  cover the envelope, so nothing else noticed.
- Two certificates asking for the same identifier set are rejected in every
  mode. The desired-state path already refused them; static and observe mode
  accepted them, sharing one quota bucket for no benefit.
- Negative `failureFallback` counts are rejected instead of being silently
  replaced by the defaults.
- A multi-certificate webhook trigger resolves the desired state once instead of
  once per name (a file read, a YAML decode, a validation and a hash each time,
  inside a 15s request).
- Onboarding: declarations excluded by guard 1 no longer dictate the group's
  profile/keyType/deploy -- one excluded declaration silently moved a served
  certificate onto a different profile, and two that disagreed froze the whole
  round. Guard 1 also checks the names a declaration contributes rather than the
  bare hostname, so a wildcard declaration served by a wildcard rule is no
  longer rejected.
- `install.sh` creates the state directory, so the `-dry-run` step the installer
  itself prescribes can run as the `wecert` user; previously it failed with a
  permission error, and the `sudo` workaround created `state.db` as root and
  made the service crash-loop. It also fails loudly when no systemd unit was
  found instead of telling the operator to enable one that does not exist.
- The metrics server gets read/write/idle timeouts, matching the webhook server.
- Per-host probe metric series are reclaimed when a host is no longer probed.
  `DeleteProbeSeries` existed with no caller, so a certificate leaving the
  desired state left `wecert_certificate_probe_match{host}` frozen forever --
  and the documentation says to alert on that being 0.
- Observe mode exposes `wecert_desired_state_shadow_errors_total` and
  `wecert_desired_state_shadow_last_read_timestamp_seconds`. A shadow read
  failure used to leave the diff gauge at its previous value (often 0) while
  nothing was compared, and its own help text tells operators to gate the switch
  to enforce on that 0.
- The webhook per-name path and the probe-series reclamation are covered by
  tests; so are the fallback hold, both deploy failure paths, the async delete,
  the `UpdateCert` contract, and the document trust checks.
- A certificate moved to a wholly different domain set can be issued again.
  The coverage-drift path passed the live certificate's ARI certID as `replaces`
  unconditionally, and Let's Encrypt refuses an order whose identifiers do not
  overlap the certificate it would replace:
  `malformed :: Could not validate ARI 'replaces' field`. That error comes back
  from `newOrder`, so no order is created -- and because `ari_cert_id` only
  changes after a successful issuance, every later round sends the same value and
  is refused the same way. The certificate could never be reissued at all. The
  drift path no longer sends `replaces` (a changed identifier set is not a
  same-set renewal and gets no ARI exemption anyway), and `issue` now retries
  once without it if a CA refuses the field for any other reason, so no refused
  `replaces` can ever be a dead end. Found by running the lifecycle acceptance
  case against real Let's Encrypt staging.
- A `{"certs": null}` trigger is rejected with 400 instead of escalating to a
  full-fleet convergence. `json.Unmarshal` leaves both an absent `certs` key
  and `"certs": null` as a nil pointer, and null is what a Go caller
  marshalling a nil `[]string` sends -- so a caller that named no
  certificates consumed issuance quota for every certificate in the fleet.
  Presence of the key is now decoded separately.
- One certificate's panic no longer takes the daemon down.
  `wecert_reconcile_panics_total` was declared, explained and never
  incremented because no `recover()` existed in production code: a nil map
  write in one pass killed the process and stopped every other certificate
  from renewing, and a panic in a probe goroutine did the same. Both
  boundaries now recover, count, and log a stack.
- Onboarding reports a sub-threshold declaration drop (`declarationDrop`)
  instead of accepting it silently. The fuse's baseline is rebased on every
  round that passes, so it bounds the drop per round and not cumulatively; an
  upstream that loses a slice just under the threshold every round erodes the
  set (10 -> 7 -> 5 -> 4 ...). The per-round bound is kept deliberately --
  every high-water-mark variant also counts a staged decommission's own
  grace-carried names as lost, re-trips the fuse on each step, and wedges the
  round (see `TestStagedDecommissionDoesNotWedgeTheFuse`) -- so the erosion is
  now logged at WARN and exported rather than silent. The limit is documented
  on `fuse`.
- Preflight's pruning walk no longer stops after the first 100 certificates
  when the API omits `TotalCount`. A nil total read as 0 ended the walk and
  the command reported a complete cleanup over a truncated list. A short page
  is now the end-of-list signal, a present `TotalCount` only ends the walk
  earlier, and a listing that never advances is an error instead of an
  infinite loop.
- A stale `ChallengeToken` in an authorization row is refreshed when
  `Present` runs again after an interrupted pass. The row kept the old token
  while `TxtValue` held the value for the new one, so cleanup derived a value
  that was never registered, read that as "another challenge is still live at
  this name", and never fired the provider's delete-all again for the name --
  stranding every later TXT record there for the lifetime of the process.
- A local-only renewal logs the cloud certificate ID it leaves behind. The ID
  was dropped without a trace -- the only local record that a wecert-uploaded
  certificate exists. Retiring it is deliberately *not* done: it may still be
  bound to a listener, and the deletion would then rest entirely on
  `IsCheckResource` refusing a bound certificate. The leak is bounded to one
  certificate per name, so the conservative direction wins and the ID goes to
  the journal with a pointer to `wecert-preflight prune`.
- The webhook auth limiter's sweep is amortized by time. Once the map passed
  the size threshold, every failed authentication scanned the whole map, so
  one failed request from each of many source addresses made the total work
  grow with the square of the request count.
- The download path verifies that the issued certificate belongs to the private
  key the order was placed with. `VerifyCoverage` and the `notAfter` check both
  pass a certificate for a different key -- same names, same lifetime -- and the
  result would have replaced a working certificate with one that cannot complete
  a single handshake. New `VerifyKeyMatch` closes the last gate of that triad.
  The test doubles now issue for the order's key the way a real CA does, so
  every download-path test exercises the check rather than only the one written
  for it.

### Security

- `statePath` is escaped before it is placed in the SQLite DSN, and the 0600
  permission contract is now enforced against the file the driver reports it
  opened rather than against the configured string. A `?`, `#` or `%XX` in the
  path is a DSN metacharacter, so SQLite opened a *truncated* path and created
  it with the process umask (0644 on a default machine): the ACME account key
  and every certificate private key landed in a world-readable `-wal` while
  `chmod` tightened a zero-byte decoy, and a backup of `statePath` restored
  nothing.
- The desired-state document is opened with `O_NOFOLLOW`, validated as the file
  that is actually read (owner included), and its parent directory must not be
  group- or world-writable. The previous `Lstat`-then-`ReadFile` sequence left a
  TOCTOU window, never checked the owner, and never looked at the directory --
  which is what decides whether someone else can replace the document by rename.
- The webhook auth limiter is swept on successful authentication as well as
  failed ones, and has a hard ceiling on tracked addresses. It was only ever
  collected from the failure path, so a burst of failed attempts left its
  entries behind forever; an IPv6 /64 makes that unbounded.
- The challenge-lease registry is re-seeded from the state store before any
  cleanup. The registry only knows the TXT values the *current process*
  wrote, and lego's provider cleanup deletes every TXT at the challenge name,
  so a row recovered from a process that died mid-pass was invisible: a
  cleanup for a different certificate sharing the name found "no other live
  values" and deleted a challenge that was still pending. Every presented
  authorization row is now registered first, and the two recovery paths
  (`removeAuthzTXT`, `reclaimUnpresentedTXT`) register their own value before
  asking for cleanup.
- `LookupTXT` asks the zone's authoritative nameservers instead of a
  recursive resolver, and reports three distinct outcomes: confirmed
  present, authoritatively absent, and "cannot tell". Only authoritative
  absence licenses deleting the authorization row. A recursive resolver's
  "no such record" is not evidence of absence -- a cached negative (DNSPod's
  600s TTL floor applies to the negative entry too) or a cached answer
  holding only some of the values at a shared challenge name previously read
  as "the write never happened", and the row carrying the only record of the
  value was deleted.
- `webhook.notifySecret` is a real option now. `NewSignedNotifier` existed
  with no way to set a secret -- `NewNotifier` always passed `""` -- so
  `X-Wecert-Signature` was dead code and the notify target had no way to tell
  a genuine event from anything else that could reach its URL. The secret is
  validated at load time (>= 32 characters, requires `notifyURL`) and each
  event is signed with HMAC-SHA256 over the raw body.

## 0.4.2 - 2026-09-16

### Fixed

- A missing rebind progress detail is not "nothing is bound": the first
  response carrying a `DeployRecordId` routinely has no progress detail yet,
  and reading that as "no resource bound" failed a rebind the cloud completed
  seconds later -- a failure that then repeated every round, uploading an
  orphan certificate each time. An unpopulated sync progress defers to the
  deploy record, and a null `TotalCount` is no longer treated as zero bound
  resources. The zero-resource verdict additionally waits for a short grace
  period so a just-created task reporting all-zero counters is not
  misdiagnosed.
- A cancelled or failed `renewalDecision` no longer reads as "renew now". Its
  error exits return a zero `renewAt`, which `Reconcile` treated as long
  overdue -- a reconcile pass during shutdown (or after a state-write failure)
  placed a real ACME order nobody would advance. The error is returned
  instead.
- One certificate's challenge cleanup can no longer delete another
  certificate's live TXT record. lego's dnspod/tencentcloud `CleanUp` deletes
  every TXT at the name (the comment claiming value-scoped deletion was
  wrong); per-FQDN challenge leases now skip the delete-all while another
  value is live.
- The onboarding abrupt-change fuse compares against the pure declaration set
  (new `State.LastDeclared`) instead of the eligible set including
  grace-carried names. A staged decommission (10 -> 7 -> 6 names) previously
  wedged the round into a self-sustaining freeze that only `-force` escaped.
- The preflight delegation check requires every returned NS to point at
  DNSPod. A single match previously printed "all pointing at DNSPod" -- the
  exact mid-migration state the check exists to catch.
- ACME flow: an order in `processing` waits for `valid` directly instead of
  falling into the pending branch and recording a spurious failure;
  `Present` is idempotent across an interrupted pass and orphan-TXT cleanup
  probes DNS before deleting a row, closing the zombie-record path;
  `findZone` fails fast on a public-suffix zone instead of burning the whole
  propagation budget against TLD nameservers for a typo'd domain.
- Webhook: an explicitly empty `certs` list is rejected with 400 instead of
  triggering a full convergence; `handleDesired` logs store read errors
  instead of silently reporting `issued: false`.
- Metrics: `DeleteCertSeries` also reclaims the `ReconcileTotal` and
  `ReconcilePanics` per-certificate series.
- Onboarding: a hostname rejected for conflicting declarations stays rejected
  when a third declaration arrives; a state-save failure no longer
  double-counts the change budget or resets grace clocks; a missing CLB rule
  source carries names with an honest reason (and warns at startup) instead
  of claiming a rule still references them.
- Reconcile: `RunCert` propagates the pass error instead of reporting success
  on failure.
- Config: a NaN `onboarding.dropThreshold` is rejected at load time (YAML
  `.nan` slipped past the range check while `wecert-onboard` refused it).
- State: a failed 0600 pre-create of the state file surfaces its own error
  instead of a confusing `sql.Open` failure.
- Deploy: `waitDeployRecord` reports the last known counters at the deadline
  instead of zeros from a final errored poll; error-body truncation is
  rune-aware and can no longer write invalid UTF-8 into `last_error`.
- Preflight: certificate pruning pages past the first 100 certificates.
- `clbverify`: the missing-argument message now matches the documented
  first-listener behavior.
- Scripts: the e2e staging gate is anchored to the `directory:` key (a
  comment mentioning acme-staging no longer passes it), and credential
  extraction in `run-stage-ab.sh` no longer uses `eval`.

### Security

- The webhook authentication lockout is actually wired in. `ratelimit.go`'s
  `authLimiter` landed without a single caller, so the endpoint that triggers
  real issuance (and consumes Let's Encrypt quota) accepted unlimited
  token-guessing attempts. `Server.auth()` now checks the limiter first and
  answers 429 with `Retry-After`, keyed by client IP; a window reset can no
  longer clear an active block.

## 0.4.1 - 2026-09-16

### Added

- MIT LICENSE file.
- `deploy/README.md` documenting the CAM policies, including why every statement
  uses `resource: "*"`.
- Tests for the deploy polling paths (`updateInstance` creation-window timeout,
  `waitDeployRecord` failure/timeout branches) and the CVM metadata credential
  fetch, via a narrow `sslAPI` seam; deploy coverage rises from ~11% to ~52%.

### Changed

- Replace the author's personal domain/IP defaults in `testenv/` with neutral
  placeholders (`wecert-test.invalid`); `clb_public_ip` now defaults to empty
  and the DNS record is skipped until it is set.
- Remove hardcoded personal paths from `scripts/run-stage-ab.sh`
  (`WECERT_CREDS` for the credentials file, `TF_PLUGIN_CACHE_DIR` left to the
  environment).
- Add the missing "When domains are declared elsewhere" section to
  `README.zh-CN.md`.
- The "certificate approaching expiry" warning scales with the profile instead of a
  fixed 21 days. 21 days is most of a `shortlived` certificate's 160-hour life, so
  that profile warned from the moment it was issued -- every pass, for its whole
  life -- which is the kind of alarm that trains people to ignore logs. A quarter of
  the profile's validity is the new threshold.
- `daysLeft` rounds **up** everywhere, matching `wecert-probe`. Truncation made
  "23 hours left" read as 0 days, which a caller treating 0 as expired reads as a
  down certificate.
- The `/hook/status` field `deployed` is renamed `uploaded`. It always meant "we
  hold a CertId", while the metric of the same name means "confirmed bound" -- the
  exact distinction that metric's help text was written to prevent.

### Removed

- `probe.Runner.LastState` had no callers, and `probeTXT` in `internal/acme` was left
  unused by the `...WithExchange` refactor that replaced it. `dns01.ToFqdn` (deprecated)
  is replaced by `dns.Fqdn`, which is what it forwarded to.
- The trailing newline on `wecert-preflight`'s NS error, so `staticcheck` is now
  completely clean.

### Fixed

- Keep retired cloud certificates queued when deployment is disabled, clear
  stale deployment state on local-only renewals, and record authorization
  failures that occur during validation polling.
- Reject conflicting group-level onboarding metadata instead of selecting one
  hostname's profile, key type, or deployment flag by sort order.
- Use one configurable recursive resolver view for DNS CNAME/SOA/NS discovery,
  then require authoritative answers when checking challenge TXT propagation.
- Reject `DropThreshold >= 1` in `onboarding.New` so the CLI `-drop-threshold`
  flag can no longer bypass the config layer's `[0,1)` check and silently
  disable the abrupt-change fuse. `NaN` is rejected too: every comparison against
  it is false, so it satisfied both bounds and passed straight through.
- Dial a host's resolved addresses concurrently. A single blackholed address (a
  dropped SYN, which is what a security-group or route misconfiguration looks
  like) used to consume its whole budget before the next address was attempted,
  stretching a pass by minutes.
- Reject an empty webhook token in `webhook.New`; `"Authorization: Bearer "`
  would otherwise pass the constant-time comparison against it.
- Propagate order-state persistence errors in the ACME manager instead of only
  logging them; a failed write means crash recovery would resume from stale
  state. All three `persistOrder` call sites now honour the returned error --
  `advance` initially kept discarding it, and Go does not warn about a dropped
  return value, so the pass continued past a failed write and only failed later
  with an unrelated message.
- Release the per-certificate reconcile slot with `defer` in `RunAll` so a
  panic in `reconcileOne` can no longer wedge every later pass with
  `ErrAlreadyRunning`.
- Enable Tencent Cloud deployment when an enforce-mode desired-state document
  contains certificates with `deploy.enabled: true`.
- Apply the TLS probe timeout to the handshake as well as the TCP dial.
- Verify every resolved probe address so a partially updated backend cannot
  hide behind a healthy node.
- Poll only the still-pending authorizations and persist only real status
  transitions. The wait loop fetched and rewrote the whole set every round, so a
  25-name certificate that took its entire 3-minute budget cost ~1500 CA round
  trips and ~1500 upserts, of which the first 25 carried all the information --
  and each upsert is its own WAL commit.
- `StartAll` resolves the desired state once and walks the resolved slice. It used
  to resolve once itself and then again inside every `StartCert`, plus an O(n^2)
  `Find` over data it already held: N+1 file reads, YAML decodes, validations and
  document hashes per trigger.
- A full webhook trigger converges at most 8 certificates at a time. It used to
  start one goroutine per certificate, so a 100-certificate state fired 100
  concurrent ACME orders, DNSPod writes and cloud calls from a single request,
  while the timer path walks the same certificates strictly one at a time.
- Do not read a missing `UpdateSyncProgress` as "nothing is bound". The API creates
  the rebind task and reports per-region progress separately, so the response that
  first carries a `DeployRecordId` routinely has no progress yet. wecert failed the
  rebind on that, and the cloud finished switching the listener 47 seconds later --
  after which the old certificate had no bindings left, so every later round
  uploaded another certificate, failed identically and recorded another orphan,
  while the certificate actually serving traffic sat in `retired_certificates`. A
  present-but-zero count still refuses; a missing one now defers to the task record.
- Count queued (`PendingTotalCount`) resources as unfinished when waiting for the
  rebind, so a batched dispatch cannot be judged complete while listeners still
  serve the old certificate.
- Distinguish a *null* `TotalCount` from a populated zero, per review from
  @JerryZ529: a response can list regions and still carry no count for any of
  them, which an "is the progress list empty" test would have missed. Their fix
  also diagnoses the genuine no-binding case after a short grace period rather
  than waiting out the full three minutes.
- Recover a rebind that succeeded without being recorded: when the update reports
  nothing to switch, check whether the *new* certificate is already bound, and treat
  it as done if it is. Without this, a deployment already stuck in that state stays
  stuck after upgrading -- the old certificate has no bindings, so every round fails
  the check no matter how many certificates are uploaded.
- Reclaim the per-certificate and per-host metric series when they leave the
  desired state. Nothing revisits a name that has gone, so its gauges sat at their
  last value forever -- and a `not_after` frozen at its last value trips the
  documented expiry rule permanently, for a certificate that no longer exists.
- Guard 1 and the deletion-side `referenced` check are now one predicate. Guard 1
  did an exact rule-domain match, so a `*.example.com` rule could simultaneously be
  "not serving" a name (rejecting the declaration) and "still referencing" it
  (blocking deletion) in the same file.
- Corrected `-force` in the docs: it skips the fuse, the grace period and the
  budget, but not the source-failure freeze -- that is precisely the case where
  "cannot read" must stay distinct from "genuinely gone".
- Corrected the freeze-troubleshooting snippet, whose first `jq` command printed
  `null` and exited 0, so the `||` fallback could never run.
- Corrected the `Options.MaxNames` comment: 0 means the fixed default of 25, not
  the profile's own cap.
- The "is this certificate bound yet?" lookup is throttled to once every six hours
  instead of every pass. Only a human can change the answer, and the lookup is a
  two-call enumeration that polls asynchronously for up to 30 seconds inside the
  serial convergence loop -- for an unbound certificate that can sit that way for
  its whole 90-day life. Measured: five passes used to cost five enumerations.

### Security

- Build with Go 1.26.6. The pinned 1.26.5 carried five standard-library
  vulnerabilities reachable from this code (`net/url`, `crypto/tls`, `net/http`
  twice, `encoding/asn1`), including one on the TLS handshake path every probe
  uses. `govulncheck` now reports none.
- `.gitignore` now covers `config.yaml` and `e2e-config.yaml`. Both are copies of
  the committed examples filled in with a DNSPod token (full record write over
  the account) and CAM credentials, and neither was ignored -- the reference
  readme claimed otherwise. The `*.example.yaml` and `e2e-config-*.yaml` fixtures
  stay committable.
- Bound `last_error` at the point it is persisted. It carries upstream text
  verbatim (lego embeds whole non-JSON ACME error bodies; the metadata path
  echoes response bodies), and `/hook/status` serves it while `notifyURL` posts
  it off-host.
- Stop printing a prefix of `TENCENTCLOUD_SECRET_ID` in `run-stage-ab.sh`. The
  same line was already removed from `wecert-preflight` for the same reason.
- `install.sh` verifies the binary against the `SHA256SUMS` that `make release`
  writes beside it. Nothing read that file: whatever was passed in became a
  root-owned binary that systemd runs with the CAM credentials and the
  private-key database. A mismatch or an unlisted artifact is refused; a missing
  sums file warns loudly rather than refusing, because copying a single binary to
  a CVM is a legitimate workflow.
- URL-escape `tencent.roleName` in the metadata credential request. It is
  concatenated into the URL, so an unescaped `../` walked out of the
  `security-credentials` path and read other metadata entries, whose bodies are
  echoed back in the error string.
- An empty `tencent.roleName` is rejected up front instead of requesting the
  credential *directory* and failing later with a JSON parse error.
- Documented the `LEGO_DEBUG_DNS_API_HTTP_CLIENT` hazard at the point the DNSPod
  provider is built. lego's debug dumper redacts only Authorization/Token/Api-Key
  headers, and dnspod-go sends the credential in the POST *body*, so setting that
  variable on the service writes a never-expiring DNSPod token into the journal.
- The desired-state document is refused rather than followed when it is a symlink,
  when it is group- or world-writable, or when it is not a regular file. In enforce
  mode that file *is* the desired state: anyone who can write it decides which
  domains are served and which quietly stop being renewed. Readability is
  deliberately not checked -- it is written 0644 so an operator can read it, and only
  the write bits change what it says.
- `deploy/systemd/wecert.service` gained the standard sandbox beyond the baseline:
  an empty capability bounding set, `RestrictAddressFamilies`, `RestrictNamespaces`,
  `RestrictSUIDSGID`, `LockPersonality`, `ProtectProc`, `ProcSubset`,
  `ProtectKernel*`, `ProtectControlGroups`, `ProtectClock`, `ProtectHostname`,
  `RestrictRealtime`, `RemoveIPC`, `SystemCallArchitectures`, `UMask=0077`, and
  `MemoryDenyWriteExecute` -- the last is safe because the binary is built
  `CGO_ENABLED=0` and links statically, so there is no JIT to break.
- `golang.org/x/net` 0.57.0 → 0.59.0.

### Tests

- `fakeAPI.GetCertificate` records the `bundle` argument it was called with
  instead of setting it unconditionally, which made "the download must ask for
  fullchain" a tautology: `download` could have passed `false` and the suite
  would have stayed green while the CLB received a leaf with no intermediates.
- Cover the reclamation path, which had no behavioural test at all: a certificate
  uploaded during a failed deploy is recorded, is not deleted inside the
  retention window, is deleted after it, keeps its record when the delete fails,
  and the live certificate is never recorded -- that last one would schedule the
  serving certificate for deletion.
- Cover the `certificates.deploy_confirmed` migration, which had none: the existing
  test opened a *fresh* store, so `ensureColumn` never took its "column missing ->
  ALTER TABLE" branch. A typo in that struct literal would have surfaced only as an
  upgrade failure for the users the migration exists to protect.
- Cover the authorization wait loop, `StartAll`'s single resolve, the webhook
  trigger's concurrency bound, metric reclamation, guard 1 against a wildcard rule
  domain, and `roleName` escaping.
- Cover the incident above: a task created with no progress detail whose record later
  reports success must not be failed; queued resources must keep the wait going; a
  task that reports nothing for the whole budget is diagnosed as "no resource
  appears to be bound"; and an already-bound new certificate recovers a wedged
  deployment.
- `fakeManager` is now goroutine-safe. Its `calls` slice was appended without a
  lock, which no existing test hit because they all drive the serial `RunAll`.
