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
