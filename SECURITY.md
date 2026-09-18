# Security policy

wecert holds an ACME account key and the private keys of every certificate it manages. A
vulnerability here is not only a bug in a daemon — it can be a path to issuing, or to reading, the
keys that terminate TLS for a production domain. Reports are welcome and taken seriously.

## Reporting a vulnerability

**Do not open a public issue describing the vulnerability.** Use GitHub's private reporting:
**Security → Report a vulnerability** (repository settings → private vulnerability reporting, enabled
2026-09-18; the API reports `"enabled": true`). A report opened there is visible only to the
maintainer until an advisory is published.

If that form is unavailable to you, the fallbacks are:

- Open a public issue that says **only** that you have a security report and would like a private
  channel. Do not include details, versions, or reproduction steps in it. A maintainer will open a
  private channel with you.
- Open a draft security advisory directly, if GitHub offers you that option on this repository.
- Message [@susunola](https://github.com/susunola) through GitHub.

There is no security email address. This is a single-maintainer project with no dedicated security
contact, and inventing an address that nobody reads would be worse than saying so.

Please include, as far as you can:

- what an attacker can achieve, and what they need in order to try (network position, local
  access, a valid webhook token, control of a DNS zone, ...)
- the version or commit, and the configuration that matters (profile, `desiredState.mode`,
  whether `webhook.listen` is set, deployment shape)
- a reproduction, or a clear argument for why it is reachable
- whether you have told anyone else

## What to expect

| | |
|---|---|
| Acknowledgement | within 3 working days |
| Initial assessment (severity, reachability, whether it is a duplicate) | within 10 working days |
| Fix or documented mitigation | severity-dependent; see below |
| Credit | in the release notes and `CHANGELOG.md`, unless you ask otherwise |

Severity is judged by impact on a deployed instance, not by category label:

- **Critical** — private key or ACME account key disclosure, or a path to issuing a certificate for
  an attacker-chosen name. Fixed as a priority release.
- **High** — unauthenticated ability to trigger issuance (burning rate-limit quota), bypass of the
  webhook token, or arbitrary file write.
- **Medium / Low** — denial of service against the daemon, information disclosure from logs or
  metrics, or a correctness bug with a security consequence.

There is no bug bounty. This is a single-maintainer project and pretending otherwise would be
dishonest.

## What is already a known, accepted limitation

Please do not report these as vulnerabilities. They are documented decisions with their reasoning:

- **The enabled webhook endpoint performs real issuance** and is therefore a rate-limit lever for
  anyone holding the token. The token is mandatory and must be ≥ 16 characters; treat it as a
  credential. See `README.reference.md` → `webhook`.
- **The metrics listener serves no authentication.** It exposes certificate names, expiry dates and
  failure counts. Bind it to `127.0.0.1` (the default) or a private interface.
- **`state.db` is written in plaintext**, including private keys, protected only by file
  permissions (0600) and the state directory's mode (0700). Disk-level encryption is the operator's
  responsibility, as is the choice of snapshots destination.
- **A single instance per state directory, enforced by `flock`.** A second process is refused rather
  than queued; that is deliberate.
- **`docs/availability.md` and `docs/challenge-types.md`** record what this deployment shape cannot
  do (host-level HA, TLS-ALPN-01). Those are answers, not gaps.

## Supported versions

Fixes land on `main` and in the next tagged release. There is no long-term-support branch: a security
fix in an older tag is not backported, so the supported version is the newest one. The practical
consequence is that an operator who pinned an older tag has to upgrade to receive a fix, and there is
no supported way to take the fix without also taking everything else in the release. That is a real
cost of a single-maintainer project, written down here rather than left to be discovered during an
incident.
