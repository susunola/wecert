# Changelog

## Unreleased

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

### Added

- MIT LICENSE file.
- `deploy/README.md` documenting the CAM policies, including why every statement
  uses `resource: "*"`.
- Tests for the deploy polling paths (`updateInstance` creation-window timeout,
  `waitDeployRecord` failure/timeout branches) and the CVM metadata credential
  fetch, via a narrow `sslAPI` seam; deploy coverage rises from ~11% to ~52%.

### Fixed

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

### Changed

- Replace the author's personal domain/IP defaults in `testenv/` with neutral
  placeholders (`wecert-test.invalid`); `clb_public_ip` now defaults to empty
  and the DNS record is skipped until it is set.
- Remove hardcoded personal paths from `scripts/run-stage-ab.sh`
  (`WECERT_CREDS` for the credentials file, `TF_PLUGIN_CACHE_DIR` left to the
  environment).
- Add the missing "When domains are declared elsewhere" section to
  `README.zh-CN.md`.

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
- `fakeManager` is now goroutine-safe. Its `calls` slice was appended without a
  lock, which no existing test hit because they all drive the serial `RunAll`.
