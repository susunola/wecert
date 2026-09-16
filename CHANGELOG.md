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

### Fixed

- Reject an out-of-range `DropThreshold` in `onboarding.New`, not only in
  `config.Load`. The `-drop-threshold` flag overwrites the value after the config
  layer has validated it, so `-drop-threshold=30` (a percentage) silently
  disabled the abrupt-change fuse. `NaN` is rejected too: every comparison
  against it is false, so it slipped past both bounds.
- Dial a host's resolved addresses concurrently. A single blackholed address (a
  dropped SYN, which is what a security-group or route misconfiguration looks
  like) used to consume its whole budget before the next address was attempted,
  stretching a pass by minutes.
- Enable Tencent Cloud deployment when an enforce-mode desired-state document
  contains certificates with `deploy.enabled: true`.
- Apply the TLS probe timeout to the handshake as well as the TCP dial.
- Verify every resolved probe address so a partially updated backend cannot
  hide behind a healthy node.

### Tests

- `fakeAPI.GetCertificate` records the `bundle` argument it was called with
  instead of setting it unconditionally, which made the "the download must ask
  for fullchain" assertion a tautology.
- Cover the reclamation path: a certificate uploaded during a failed deploy is
  recorded, is not deleted inside the retention window, is deleted after it, and
  keeps its record when the delete fails. Recording the live certificate is
  rejected -- that would schedule the serving certificate for deletion.
