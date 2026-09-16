# Changelog

## Unreleased

### Added

- MIT LICENSE file.
- `deploy/README.md` documenting the CAM policies, including why every statement
  uses `resource: "*"`.
- Tests for the deploy polling paths (`updateInstance` creation-window timeout,
  `waitDeployRecord` failure/timeout branches) and the CVM metadata credential
  fetch, via a narrow `sslAPI` seam; deploy coverage rises from ~11% to ~52%.

### Fixed

- Enable Tencent Cloud deployment when an enforce-mode desired-state document
  contains certificates with `deploy.enabled: true`.
- Apply the TLS probe timeout to the handshake as well as the TCP dial.
- Verify every resolved probe address so a partially updated backend cannot
  hide behind a healthy node.
- Reject `DropThreshold >= 1` in `onboarding.New` so the CLI
  `-drop-threshold` flag can no longer bypass the config layer's `[0,1)` check
  and silently disable the abrupt-change fuse.
- Reject an empty webhook token in `webhook.New`; `"Authorization: Bearer "`
  would otherwise pass the constant-time comparison against it.
- Propagate order-state persistence errors in the ACME manager instead of only
  logging them; a failed write means crash recovery would resume from stale
  state.
- Release the per-certificate reconcile slot with `defer` in `RunAll` so a
  panic in `reconcileOne` can no longer wedge every later pass with
  `ErrAlreadyRunning`.

### Changed

- Replace the author's personal domain/IP defaults in `testenv/` with neutral
  placeholders (`wecert-test.invalid`); `clb_public_ip` now defaults to empty
  and the DNS record is skipped until it is set.
- Remove hardcoded personal paths from `scripts/run-stage-ab.sh`
  (`WECERT_CREDS` for the credentials file, `TF_PLUGIN_CACHE_DIR` left to the
  environment).
- Add the missing "When domains are declared elsewhere" section to
  `README.zh-CN.md`.
