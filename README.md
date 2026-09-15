<p align="center">
  <picture>
    <source media="(prefers-color-scheme: dark)" srcset="docs/logo-dark.png">
    <img src="docs/logo.png" alt="wecert" width="150">
  </picture>
</p>

<p align="center">
  <b>English</b> &nbsp;·&nbsp; <a href="README.zh-CN.md">简体中文</a>
</p>

<p align="center">
  <img src="https://img.shields.io/badge/go-1.26%2B-00ADD8?logo=go&logoColor=white" alt="Go 1.26+">
  <img src="https://img.shields.io/badge/ACME-DNS--01-brightgreen" alt="ACME DNS-01">
  <img src="https://img.shields.io/badge/renewal-ARI%20(RFC%209773)-blueviolet" alt="ARI (RFC 9773)">
  <img src="https://img.shields.io/badge/platform-Tencent%20Cloud-0052D9" alt="Tencent Cloud">
  <a href="https://github.com/susunola/wecert/actions/workflows/ci.yml"><img src="https://github.com/susunola/wecert/actions/workflows/ci.yml/badge.svg" alt="CI"></a>
</p>

# wecert

A cert-manager-style ACME certificate renewer for deployments where **TLS terminates at Tencent Cloud CLB**.

One binary and one SQLite file. Because decryption happens at the load balancer, there is no node agent and no certificate files to distribute — the entire deploy action is a few Tencent Cloud API calls.

## Install

Requires Go 1.26+ to build.

```bash
git clone https://github.com/susunola/wecert.git
cd wecert
make build          # → bin/wecert
make tools          # → bin/wecert-preflight, bin/wecert-clbverify
```

Static binaries for linux/amd64, linux/arm64 and darwin/arm64:

```bash
make release        # → dist/ + SHA256SUMS
```

On the target CVM, `install.sh` creates the `wecert` user, installs to `/usr/local/bin/wecert`, prepares `/etc/wecert/` and drops in the systemd units:

```bash
sudo ./install.sh ./dist/wecert_linux_amd64
```

> `go.mod` currently declares `github.com/atom/wecert` while the repository is `susunola/wecert`, so `go install github.com/susunola/wecert/cmd/wecert@latest` does not work. Building from a clone does.

## Quick start

**1. Check credentials, DNS ownership and NS delegation** — all read-only:

```bash
export TENCENTCLOUD_SECRET_ID="<secret-id>"
export TENCENTCLOUD_SECRET_KEY="<secret-key>"
./bin/wecert-preflight -domain example.com
```

**2. Configure.** `config.example.yaml` is annotated, and its `acme.directory` deliberately points at Let's Encrypt **staging** — `install.sh` installs that file as your production config, so the default has to be the safe one.

```bash
sudo cp config.example.yaml /etc/wecert/config.yaml
sudo chown root:wecert /etc/wecert/config.yaml && sudo chmod 640 /etc/wecert/config.yaml
sudo -u wecert ./bin/wecert -config /etc/wecert/config.yaml -dry-run
```

**3. Start it.** Once staging is green end to end, switch `acme.directory` to production and run:

```bash
sudo systemctl enable --now wecert                      # daemon, reconciles hourly
# or: sudo systemctl enable --now wecert-once.timer     # run once, hourly
```

Run **one** of the two modes per machine. They share one state database, and the "at most one in-flight order per certificate" guarantee only holds inside a single process.

**4. Bind the certificate once.** On first issuance Tencent Cloud has no "old certificate → cloud resource" binding to look up, so wecert only uploads it:

```
证书已上传，等待在 CLB 上手动绑定一次 cert=example-com uploadedCertId=xxxxxxxx
```

Bind it in the CLB console. Every renewal after that is automatic — `UpdateCertificateInstance` makes Tencent Cloud find the listeners bound to the old certificate and swap them. **There is no listener inventory to maintain**, and other certificates on the same listener (SNI) are untouched.

## How it works

Four invariants, chosen because the limits that hurt are the ones about *state and identifiers*, not the SAN ceiling — **New Certificates per Exact Set of Identifiers is 5 per 7 days with no override**, while ARI-coordinated renewals are exempt from everything. Losing the state database therefore costs far more than re-issuing.

1. **At most one in-flight order per certificate, and the order URL must be persisted.** A restart resumes the same order instead of creating a new one. The order's private key is stored on the order, never written over the live key, so a failed deployment still leaves you something to roll back to.
2. **ARI first, and orders carry `replaces`.** Without it there is no rate-limit exemption.
3. **A wildcard and its apex share one `_acme-challenge` name**, so it is *write all → verify all → clean up*, never one at a time.
4. **The desired state is `domains`, not a timestamp.** If the live certificate's SANs differ from the config, it reissues immediately rather than waiting for the renewal window. Adding a domain to a 90-day certificate would otherwise take up to 60 days to apply — silently.

lego's high-level `certificate.Obtain` is deliberately not used: it calls `newOrder` internally, so the order URL cannot be persisted. The low-level `acme/api` package is used to own the state machine.

Full rationale in [Domains that change often](README.reference.md#domains-that-change-often) and [Field notes and pitfalls](README.reference.md#field-notes-and-pitfalls).

## Profiles

"100 domains per SAN" is profile-dependent, not fixed:

| Profile | Validity | Max Names |
|---|---|---|
| `classic` (default) | 90 days | 100 |
| `tlsserver` | 45 days | 25 |
| `shortlived` | 160 hours | 25 |

The CA/Browser Forum has scheduled **≤100 days from 2027-03-15 and ≤47 days from 2029-03-15**, so "90-day certificates plus a manual fallback" stops being an option within two years. Keeping each certificate to **25 domains or fewer** aligns with `tlsserver` and bounds the blast radius — domains in one certificate succeed, fail and expire together.

> Adding or removing a domain makes that issuance a new certificate, so it counts against **Certificates per Registered Domain (50 / 7 days)** instead of enjoying the ARI exemption.

## Documentation

- [Full reference](README.reference.md) — architecture, the reconcile state machine, the state schema, every configuration field, operations, and the pitfalls found by running it.
- [Why this exists](README.reference.md#why-this-exists) — which rate limits shaped the design.
- [Configuration reference](README.reference.md#configuration-reference) · [Operations](README.reference.md#operations) · [Metrics and alerting](README.reference.md#metrics-and-alerting).
- [Field notes and pitfalls](README.reference.md#field-notes-and-pitfalls) — the CLB SNI trap, `DescribeListeners` not reading bindings back, the DNSPod TTL floor, the lego API traps.
- [Roadmap](README.reference.md#roadmap) · [Development](README.reference.md#development).

<details>
<summary>Command reference</summary>

### `wecert`

| Flag | Default | Description |
|---|---|---|
| `-config` | `config.yaml` | Config file path |
| `-state` | — | Override `statePath` (useful for tests) |
| `-once` | `false` | Run one pass and exit (systemd timer / cron) |
| `-interval` | `1h` | Reconcile interval in daemon mode |
| `-log-level` | `info` | `debug` \| `info` \| `warn` \| `error` |
| `-dry-run` | `false` | Validate config and initialise the ACME account; sign and deploy nothing |
| `-version` | `false` | Print version and exit |

### `wecert-preflight` (read-only)

| Flag | Description |
|---|---|
| `-domain` | Verify SSL read access, DNSPod ownership, NS delegation and leftover challenge records |
| `-list-certs` | List the account's SSL certificates |
| `-prune-certs` | Delete wecert-uploaded certificates (alias prefix `wecert/`) |
| `-yes` | Skip the confirmation prompt for `-prune-certs` |

> `-prune-certs` matches on the alias prefix `wecert/`, which wecert applies to **every** certificate it uploads — including the one currently serving. It prints the list and requires confirmation; non-interactive stdin is treated as "no".

### `wecert-clbverify` (independent evidence)

| Flag | Description |
|---|---|
| `-region` / `-clb` / `-listener` | Target listener; `-listener` defaults to the first under that CLB |
| `-expect` / `-not-expect` | Assert the primary certificate ID equals / does not equal |
| `-wait` | Poll this long for the rebind (it is asynchronous, measured ~15s) |
| `-raw` | Dump the raw `DescribeListeners` JSON |

```bash
./bin/wecert-clbverify -region ap-guangzhou -clb lb-xxxx -listener lbl-yyyy \
  -expect apJdfyPa -not-expect apJRqDsC -wait 90s
```

</details>

## License

No license file is present, which means all rights reserved by default. **Add one before distributing or accepting external contributions.**
