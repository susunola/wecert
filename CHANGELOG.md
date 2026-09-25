# Changelog

## Unreleased

### Fixed

- **The coverage floor holds again.** Total statement coverage had fallen to 72.4% against the
  76% floor `scripts/check-coverage.py` records, so `make check-coverage` -- and with it the `test`
  job -- failed on every push. The gap was in surfaces that had no tests rather than in broken
  behaviour, and the tests added here are aimed at the ones where a silent wrong answer is the
  failure mode: the daemon's boot sequence and its `/admin` restore surface (`cmd/wecert`), the
  admin and inventory HTTP handlers (`internal/webhook`), the Cloudflare TXT recovery helper, the
  certificate export path (`internal/certsync`), the snapshot and pending-restore guards
  (`internal/state`), and the confirmation gate in front of `-prune-certs` (`cmd/preflight`).
  Coverage is 76.5% with the new tests. No production code changed.

- **A Route 53 issuance no longer fails a pass over a wait the provider does not need.** With
  `dns.provider: route53`, lego's provider waits for the record change to reach INSYNC before
  `Present` returns, polling every `dns.polling` for up to the propagation budget -- five minutes,
  inside a call this program bounds at 60 seconds so one wedged API call cannot hold the per-name
  TXT lease forever. Measured on the machine that failed: the `ChangeResourceRecordSets` call took
  6.5-8.6s and INSYNC arrived 23.5-31.9s later, 32.1-38.4s in total, and a staging round then
  failed with `present TXT timed out after 1m0s` for a record Route 53 had already accepted -- one
  discarded order and a backoff. That wait is now off: the write is confirmed when Route 53 accepts
  the change, and when a record is actually live stays what it already is for every provider --
  `WaitAll` probing the zone's authoritative nameservers, two independent servers agreeing, with
  the full propagation budget and the evidence in the log. Cleanup is affected the same way and is
  better for it: the delete is confirmed seconds after the API accepts it, instead of holding the
  lease through an INSYNC wait.
- **A dropped datagram during zone discovery no longer fails the whole pass.** The recursive
  lookups that run before the propagation wait -- `findZone`'s SOA walk, the NS delegation query,
  and the A/AAAA lookup that turns NS names into addresses -- asked each configured resolver once,
  and one exchange that produced no answer at all ended the pass there, before any record had been
  written. A staging run failed exactly that way: `lookup NS for <zone>.: all configured recursive
  resolvers failed: 1.1.1.1:53: read udp ...: i/o timeout; 8.8.8.8:53: read udp ...: i/o timeout`.
  Each resolver is now asked twice, 250ms apart, before the next one gets its turn. Only an
  exchange with no answer is retried, the same rule the authoritative probe follows: REFUSED,
  SERVFAIL, NXDOMAIN and a truncated answer are answers, they are never re-asked, and they still
  hand the question to the next resolver.
- **Sealed-state KDF migration no longer double-encrypts.** `migrateSealedMaterial`
  used to re-seal a v1 blob without opening it, storing `v2(v1(plain))`. The next
  open peeled only the v2 layer and handed back a second AEAD blob instead of the
  private key -- a silent brick on every upgrade from the SHA-256 KDF. v1 rows are
  now opened first, re-sealed as v2, and a regression test plants a real v1 blob.
- **Remote retention counts snapshots, not `.hmac` sidecars.** `keep: 1` with one
  signed pair used to delete the snapshot and leave the signature. Sidecars are
  deleted with their object and no longer occupy Keep slots.
- **A configured backup `hmacKeyFile` that cannot be loaded fails closed.** Upload
  and remote restore no longer fall back to unsigned when the key file is missing
  or empty. certsync export signs remote material under the same rule.
- **`/admin/recovery-plan` and `/admin/recovery-drill` honour `source`** (same
  whitelist as restore) and echo `requestedSource` + `resolvedSource`. They used
  to ignore the requested source and answer as if `latest` had been asked for.
- **Admin restore rejects symlink escapes and foreign filenames.** Sources are
  resolved with `EvalSymlinks` and must match this store's
  `<base>.backup-<stamp>.db` pattern before they are staged.
- **A pending restore is no longer applied by an unlocked open.** `OpenForTool` /
  `OpenUnlocked` (dry-run, revoke, preflight while the daemon holds the lock) used
  to call `ApplyPendingRestore`, which renames the live `state.db` out from under
  the running process. Only the exclusive-lock path applies it now. A failed apply
  releases the state lock; `Lstat` errors other than "not found" refuse to start
  instead of looking like "nothing pending"; a successful CLI `-restore` clears any
  staged `*.restore-pending` so the next start cannot roll it back.
- **`webhook.adminToken` rotates on SIGHUP** (`SetAdminToken`), matching
  `webhook.token`. Before, editing the admin token and reloading left the old one
  in force -- and the operator believed the rotation had landed.
- **Notification send/Drain no longer drop accepted events.** The slot is taken
  under the same mutex as the draining check; Drain waits for in-flight sends
  instead of filling the semaphore (which raced the accept path). Drain's budget
  is 40s so a Jira find-open + create/comment cannot be cut off mid-ticket.
- **A retention prune failure is not a failed backup upload.** The object is on the
  remote and is still verified; the caller used to skip verification and report a
  red backup while a usable snapshot sat in the bucket.
- **`/admin/restore` audit says `admin_restore_staged`** (with `restartRequired`),
  not `admin_restore_done` -- the swap happens on the next start.
- **Confirm-token refusals name the real reason** (`missing` / `expired` /
  `source_mismatch` / `wildcard_token`) in both the 403 body and the audit line.
  "missing or expired" for a source mismatch trained operators to re-issue the
  same wrong token forever. Challenge requires a non-empty `source` and the ticket
  is bound to it.
- **`nginx` with `reload: []` is honest again.** Files on disk are not "being
  served": `Bindings` reports 0 and `DeployUploaded` returns
  `ErrSwitchUnverified` so `confirmBinding` cannot mark the deployment confirmed.
- **SIGHUP refuses `stateEncryption` changes.** The sealer is built at Open;
  swapping the master under a live store leaves rows in two KDFs.
- **`Handler()` reads `adminEnabled` under `tokenMu`**, so a SIGHUP that rotates
  the admin token is no longer a data race with route mounting.

### Security

- **`/admin/*` is rate-limited like `/hook/*`** (10 failures / 5 min -> 15 min lockout).
- **inline secret warnings cover `webhook.adminToken`, `webhook.jira.apiToken` and
  `webhook.pagerduty.routingKey`** -- a 0644 config carrying the restore credential
  is no longer silent.
- **Outbound notify text is URL-, Bearer-, AKID- and PEM-redacted** before it
  reaches Jira / PagerDuty / a chat robot. A renewal error that embeds a token or
  a private key no longer ships that credential off the host.
- **Admin restore sources are limited** to `latest`, snapshot-named files under
  `stateBackup.dir` (or `localDirs`), and configured `remote:<name>` targets --
  with symlinks resolved first.
- **Confirm tokens fail hard without a CSPRNG** (no timestamp fallback) and share one
  clock for `expiresAt`.
- **PagerDuty resolves on success** (`dedup_key=wecert/<cert>`); **Jira comments
  "renewed OK"** on the open issue. Fail->ok no longer leaves an incident open.
- **Sealed-state migration collects rows before UPDATE** (SQLite does not promise a
  cursor sees each row once when the same table is written while it is open).
- **certsync `writeAtomic` fsyncs before rename** -- a crash can no longer leave
  `privkey.pem` named but empty.
- **failover treats only true transport-level "directory unreachable" as
  unavailable** -- a lost `NewOrder` response no longer double-spends on standby.
- **Remote snapshots can be signed (`stateBackup.remoteTargets[].hmacKeyFile`).**
  Upload writes a `.hmac` sidecar; download filters sidecars out of "latest" and
  refuses a missing or mismatched signature when a key is configured. The key is
  separate from the state-encryption master.

- **Jira notifications.** `webhook.notifyFormat: jira` opens (or comments on) a Jira
  issue for a failed renewal. `webhook.jira` names the instance and the issue
  (`baseURL`, `projectKey`, `issueType`), authenticates with Cloud basic
  (email + `apiToken`/`apiTokenFile`) or a bearer PAT, and adds labels `wecert` +
  `wecert-cert-<name>`. By default (`reuseOpenIssue`) a second failure for the same
  certificate comments on the open issue instead of opening a duplicate. Successful
  renewals do not create tickets. API v2, so Server/DC and Cloud both work with a
  plain-text description.

## 0.8.0 - 2026-09-24

### Added

- **Sealed state storage.** Optional `stateEncryption.keyFile` enables authenticated encryption
  for ACME account keys, in-flight order keys, live certificate material and retired rollback
  material. Existing plaintext state is migrated atomically on first sealed open; systemd
  `LoadCredential` paths are supported.
- **ACME External Account Binding.** `acme.eab.kid` plus a file-backed or environment-backed HMAC
  supports commercial and private ACME directories that require EAB.
- **Persistent TLS probe evidence.** The inventory retains the last host verdict, served expiry,
  trust result and observation time across daemon restarts.

### Added

- **Preset notification formats.** `webhook.notifyFormat` selects the POST body:
  `generic` (default, the documented JSON + `X-Wecert-Signature`), `pagerduty`
  (Events API v2; `webhook.pagerduty.routingKey` or `routingKeyFile`;
  `dedup_key` is `wecert/<cert>`, and only `result=error` pages -- a green
  renewal is not an on-call event), `feishu`, `wecom`, `dingtalk` and `slack`
  (one-sentence text for a group robot). The chat formats do not replace
  Prometheus alerts; they are the "did this renewal fail" channel.

### Added

- **Guarded web admin surface.** `webhook.adminToken` (separate from the read-only
  `webhook.token`, minimum 32 characters) mounts `/admin/backup-health`,
  `/admin/recovery-plan`, `/admin/recovery-drill`, `/admin/challenge` and
  `/admin/restore`. The first three are diagnostics; restore is destructive and
  needs a one-shot confirm token from `/admin/challenge` (10-minute TTL). Without
  `adminToken` the routes are not mounted at all -- the process stays read-only
  over the network. Every admin action is appended to `state.db.admin-audit.jsonl`
  (0600). Because the live database is open in this process, a restore is staged
  as `state.db.restore-pending` and applied on the **next** start (which holds the
  state lock legitimately); the previous database is kept as
  `state.db.replaced-<stamp>`.

### Added

- **Full-binding patrol.** Every 6 hours the Tencent deployer pages `DescribeCertificates`
  (uploaded) and re-enumerates each known certificate's live bindings, then classifies the
  gap: `confirmed` / `incomplete` / `drift` (state says deployed, cloud says bound nowhere --
  a manual unbind), `orphan_upload` (uploaded, empty remark, no state row: deploy died
  between upload and the resume anchor), `unmanaged` (console or other client upload).
  Metrics `wecert_binding_patrol_findings{kind}` and
  `wecert_binding_patrol_last_run_timestamp_seconds`; alert on persistent drift and on a
  stale patrol. Read-only: a manual console change is reported so a human decides.

### Added

- **DNS cleanup guardian.** A leftover `_acme-challenge` TXT whose cleanup could not be
  *confirmed* (authoritative NS unreachable, or the provider cannot delete the record) is
  queued on its authorization row with `attempts`, `stuck_since` and `last_error`. Every
  reconcile pass sweeps that queue independently of which certificates were walked --
  `cleanupOrphanTXT` only runs for a certificate that reaches its no-order branch, so a
  happily renewing certificate would otherwise never retry a leftover TXT from an older
  crash. Metrics `wecert_txt_reclaim_stuck` and `wecert_txt_reclaim_stuck_oldest_seconds`
  plus an alert on the oldest age; read-only `GET /diagnostics/txt-reclaims` lists
  `txtName`/`txtValue` for the DNS console. A deliberate keep inside the propagation
  window is not queued.

### Added

- **Read-only desired-state diagnostic.** Authenticated
  `POST /diagnostics/desired-state` refreshes and reports declarations without
  starting issuance, deployment or recovery.

- **Standby ACME directories.** `acme.fallbackDirectories` supplies lazily
  initialised standby CAs. They are used only for a primary directory transport
  or server outage, or an account-wide new-order refusal; order URLs are routed
  back to their originating CA and DNS/authorization failures never fail over.

- **Safe daemon configuration reload.** `SIGHUP` now reloads certificates,
  policy, credential files/environment, DNS/deploy settings, notifications and
  the webhook token without restarting the daemon. The complete replacement is
  parsed and constructed before an idle-only atomic swap; a rejected reload
  leaves the previous runtime active. State path, ACME directory, listener
  addresses and backup plan remain restart-only because they identify live
  resources.

### Fixed

- **Cloudflare and constrained DNS egress.** DNS lookups now retry over TCP when UDP returns
  `REFUSED`; lego's provider-side zone discovery stays on the host resolver while wecert's
  propagation verification can use its configured recursive resolvers. This keeps DNS-01 usable
  on networks that block public UDP/53 but permit TCP/53.
- **COS remote-backup retention.** Tencent COS requires `Content-MD5` for S3 multi-object delete,
  so COS retention deletes expired snapshots one at a time while ordinary S3 keeps batched delete.

## 0.7.0 - 2026-09-23

### Added

- **Remote state backups and restore.** `stateBackup` gains S3-compatible (including
  Tencent COS) and SFTP destinations alongside local directories: snapshot upload,
  retention, health metrics, a stale-backup alert, and `wecert -restore` pulling the
  latest snapshot back. SFTP passwords come from an environment variable and keys from
  a file -- the target struct carries no secret value.
- **Export issued certificates to local and remote targets.** `certificates[].export`
  copies the full chain and private key to `localDir` and/or `remoteTargets` after
  issuance. This is **distribution** (give the material to another system that will
  serve it), not deployment: `deploy.target` remains what makes wecert put a
  certificate into service (CLB rebind, or the nginx file pair + reload). One
  certificate can export and deploy.
- **Deploy certificates to local nginx.**
- **Deploy certificates to local nginx.** `deploy.target: nginx` writes
  `fullchain.pem` + `privkey.pem` into `nginx.dirTemplate` (`%s` is the
  certificate name; default `/etc/nginx/ssl/%s`) and runs `nginx.reload`
  (default `systemctl reload nginx`, an argv slice — never a shell string).
  There is no cloud certificate id and no console bind: the file pair is the
  deployment, so a successful write is a confirmed deploy. The process-wide
  id space is `nginx:<dir>`; `Delete` removes those two files, and a reload
  failure still returns that id so the next pass resumes the same directory
  (see the `Deployer` contract). Per-certificate `deploy.nginx.dir` overrides
  the directory. One process deploys to one backend — mixing CLB and nginx in
  one config is refused at load time. The unit still runs as `wecert`, so
  reloading nginx needs a sudoers rule, a helper, or `reload: []`.

- **Per-certificate failure fallback.** `failureFallback` can be overridden on a
  certificate (`certificates[].fallback`), so one stubborn name on a 25-SAN
  certificate can degrade without changing the fleet-wide default.
- **Multiple local snapshot destinations** for `stateBackup`, not one directory.
- **`state.db` on a network filesystem is refused** (NFS / CIFS / SMB / FUSE on Linux):
  SQLite locking over those is a known corruption source, and a corrupt state store is
  the one disaster this program cannot recover from by re-issuing.
- **Inventory shows blocked CA scopes** and onboarding respects known quota blocks, so
  a paused identifier is visible instead of looking like a silent skip.


### Fixed

- **A Cloudflare issuance no longer leaves its challenge TXT record in the zone.** With
  `dns.provider: cloudflare` and the token in a file (`cloudflare.apiTokenFile`), a fresh provider
  was built for every call, and lego's Cloudflare provider deletes a record by the ID it
  remembered when it created that record -- keyed by the challenge token. A provider built between
  `Present` and `CleanUp` has an empty map, so every cleanup answered `cloudflare: unknown record
  ID for '_acme-challenge.<name>.'` and the record stayed: one stale `_acme-challenge` TXT per
  certificate per renewal, and a stale value is what a later validation can be answered from
  (observed as `During secondary validation: Incorrect TXT record ... found`). The token file is
  still re-read on every use, so a rotated token keeps taking effect without a restart; what is
  kept is the provider instance, and only while the file holds the same token.
- **The `lego_dns` build -- `make release` and `make test-tags` -- compiles from a clean
  checkout again.** `go.mod` had no requirement for `github.com/exoscale/egoscale/v3`, which
  that build needs because lego's DNS registry imports every provider it ships, exoscale
  included, and four modules the program imports directly were still listed as `// indirect`.
  A build in `-mod=readonly`, which is what CI runs, stopped at `go: updates to go.mod needed`
  and took the `test` and `install` jobs with it -- including the Linux release build. `go mod
  tidy` restores the list; no module version changes.
- **A single dropped DNS packet no longer costs an authoritative server its whole propagation
  round.** Every address of a zone is probed once per round, and an exchange that came back with no
  answer at all put that address in the `unreachable` bucket for the rest of the round. On a flaky
  path that can decide the verdict: on this machine the same zone reported different addresses
  reachable in consecutive rounds (IPv6 addresses have no route here at all), and rounds that ended
  the five-minute budget with a single independent nameserver confirming failed the propagation
  check, which requires two independent servers to agree. `probeTXTWithExchange` now asks an
  address that produced no answer twice, 250ms apart, before the round records it as unreachable.
  Addresses are probed concurrently, so a round grows by that delay (250ms of a 300000ms budget,
  under 0.1%) and not by delay times addresses. No verdict rule was relaxed: UDP stays first with
  the TCP fallback on no answer, an answer of any kind is never re-asked (a `REFUSED` or `SERVFAIL`
  is an answer, and re-asking would burn the budget and blur the `refused` / `failed` /
  `unreachable` buckets), the evidence stays authoritative-only, and two independent servers must
  still agree, with a single-authority zone still exempt.
- **`install.sh` installs its own `make release` output again.** The unit checksum gate looked
  for a `SHA256SUMS` beside `deploy/systemd/`, where none exists, and refused to continue --
  so an install from a release layout failed on the units unless
  `WECERT_INSECURE_SKIP_CHECKSUM=1` was set, which is the opposite of what the gate is for.
  `make release` copies the units into `dist/systemd/` and lists them in `dist/SHA256SUMS`
  (`systemd/wecert.service`), so the lookup now consults the release directory the binary came
  from. The units are verified rather than refused: a tampered, unlisted, or symlinked unit is
  still rejected, and the unit that gets installed is the one the checksum was computed over.
- **A reclaim of an already-deleted TXT no longer reports a Cloudflare cleanup failure.** With
  `dns.provider: cloudflare`, a run whose challenge record had already been deleted could print
  `failed to reclaim the TXT of an interrupted pass; keeping the row  err="cloudflare: unknown
  record ID for '_acme-challenge.<name>.'"` followed by `some TXT records could not be reclaimed
  automatically ... their rows are kept and retried next round`, and the authorization row stayed
  behind as stuck -- a warning that reads like a DNS cleanup failure for a record that was in fact
  already gone. Cloudflare's provider deletes only the records whose IDs it created in this
  process, so a record deleted by the normal cleanup (while a lagging anycast node still served it,
  which is what made the reclaim probe ask for a second delete at all) can only be answered that
  way. The reclaim now waits a moment and asks the zone's authoritative nameservers again: if every
  reachable one denies the record, the cleanup is done -- the row is deleted, its lease released,
  and the run logs at Info that the provider had already forgotten the record and the servers agree
  it is gone. If the servers still hold it, the provider genuinely cannot remove it, and the run
  says so and names the record to delete in the DNS console instead of the generic retry warning.
  Any other provider error keeps its previous path, and dnspod, tencentcloud and route53 are
  unaffected: all three look the record up by name and already treat "nothing to delete" as
  success.

## 0.6.1 - 2026-09-23

### Fixed

- **A DNS-01 propagation summary no longer calls an intercepted port 53 a broken zone.**
  Every inconclusive answer was counted as `unreachable`, so a server that answered
  `REFUSED` -- which is what a middlebox that intercepts DNS says on the authority's
  behalf -- was reported the same way as a server whose packets are dropped. On a network
  that does exactly that, a healthy zone read as `unreachable 8 (of 8 addresses)` and sent
  the operator to look at the zone rather than at their egress. The summary separates them
  now: `refused` for REFUSED, `failed` for any other inconclusive response code, and
  `unreachable` only for an address that answered on neither transport.
- **A DNS-01 propagation check no longer calls a zone unreachable when only UDP is
  blocked.** `exchangeDNS` retried over TCP only for a truncated answer, so on a network
  that drops outbound UDP/53 -- measured: every authoritative address of a zone timed out
  over UDP while the same query over TCP answered in 60 ms -- every authoritative query
  failed and the wait reported `unreachable N (of N addresses)` after spending its whole
  budget, without the CA ever being asked. TCP is an equally authoritative transport
  (RFC 7766), so a server that answers over it has answered; the truncated-answer
  behaviour is unchanged.

## 0.6.0 - 2026-09-23

### Fixed

- **A `*_file` credential path that is group- or world-readable warns at load time.**
  The field comments promise a 0600 file, but `resolveSecretFiles` only read it -- a 0644
  `loginTokenFile` / `apiTokenFile` / `secretAccessKeyFile` was accepted silently. The
  warning names the field and the mode (a systemd `LoadCredential` path is usually already
  0400 and does not warn). `sessionTokenFile` without a static key pair is refused the same
  way as the inline `sessionToken`, with a regression test.

### Added

- **Cloudflare and Route 53 are DNS-01 providers in the default build.** `dns.provider:
  cloudflare` takes a scoped API token — `dns.cloudflare.apiToken`, a 0600 environment-expanded
  `dns.cloudflare.apiTokenFile` (so `LoadCredential` works), or `CLOUDFLARE_DNS_API_TOKEN` /
  `CF_DNS_API_TOKEN` — and `dns.provider: route53` takes `dns.route53.region` plus an optional
  `dns.route53.hostedZoneId`, with credentials from either an explicit static pair
  (`accessKeyId` + `secretAccessKey`/`secretAccessKeyFile`, optional session token and file) or,
  when no pair is configured, the AWS SDK's default chain: environment, shared config, instance
  role. An EC2 instance role therefore needs nothing on disk and nothing in the config beyond the
  region. Until now either provider meant `dns.provider: lego` + `dns.legoProvider: <name>`, which
  a default binary refuses with the "rebuild with -tags lego_dns" instruction — compiling all ~198
  lego providers and their hundreds of SDKs into the binary — so the two most-requested providers
  were the two an operator could not use as shipped. Both are now validated at load time, where the
  operator can act on it: a missing token names the field and both environment variables, a missing
  region names `dns.route53.region` and `AWS_REGION`, half a static key pair is refused, a
  `cloudflare:`/`route53:` block left under another provider is refused naming both, and a `dns.ttl`
  below Cloudflare's 120-second floor is refused before the provider would reject it at startup.
  The `dns.provider: lego` path is unchanged, and the other ~196 providers stay behind the tag.
  Cost: the default binary now links the AWS SDK — measured with `-trimpath -ldflags "-s -w"`,
  20.1 MB → 25.5 MB (+5.4 MB, +26.9%); the tagged build is unchanged in kind.

## 0.5.0 - 2026-09-23

### Fixed

- **`tcerr.IsThrottled(nil)` no longer panics.** The throttle check fell through to
  `err.Error()` on the right of `||` whenever `Code` returned empty, so a nil error from
  a polling loop crashed the process. `IsPermanent` and `isNoData` already guarded nil;
  this was the one that did not.
- **A legacy account row that still carried a kid is re-registered instead of paired
  with a new key.** `EnsureAccount` generated a replacement key when the stored row had
  no key, and `PutAccount` cleared the kid in the database -- but the in-memory `KID`
  survived into `api.New`, so every JWS failed for the whole pass and the next start
  registered a second account. The leftover kid is discarded with the key it belonged to.
- **The webhook auth lockout cannot be burst past.** `allowed()` and `recordFailure()`
  were two steps: a concurrent burst of wrong tokens all passed the check while the
  failure count was still 0, then each counted. Checking and counting now happen in one
  critical section (`authLimiter.fail`), so at most `authMaxFailures` guesses are ever
  admitted before the address is refused.
- **A trailing `---` is one YAML document, not two, on the desired-state path.**
  `config.rejectExtraDocuments` already skipped an empty trailing document; the
  desired-state copy still refused anything `Decode` returned without error, so the same
  separator `Load` accepts made `LoadDocument` fail and enforce mode froze on an old
  revision. Both now share `config.RejectExtraDocuments`.
- **`SetProber` is no longer a data race against concurrent probe reads.** The field was
  written without synchronisation while webhook-triggered passes read it; the
  "before the first convergence" contract had no enforcement. The pointer is guarded and
  every probe-path read goes through one accessor.
- **`transientBackoff` is swept like the sibling cooldown maps.** Certificates that left
  the desired state kept their unpersisted-backoff entry forever; the write path now
  prunes expired entries at the same `cooldownMapLimit` as `identifierCooldown` and
  `bindingChecked`.
- **`reclaimStaleProbeSeries` uses the prober snapshot for `Forget`.** It captured `p` at
  the top of the function but re-read the field in the loop, so a concurrent
  `SetProber(nil)` between the nil check and the loop was a nil dereference.
- **`restrictiveUmask` restores with `defer`.** A panic between the call and the restore
  left the process umask at 077 and deadlocked `Open` on the umask mutex; `openFiles`
  already deferred the restore and the snapshot path did not.

### Security

- **`install.sh` refuses an artifact with no `SHA256SUMS` unless
  `WECERT_INSECURE_SKIP_CHECKSUM=1`.** A missing sums file used to warn and install
  anyway -- the exact case the check exists for. A mismatch still always refuses.
- **`webhook.listen` warns when it binds beyond loopback.** The trigger carries a bearer
  token over plaintext HTTP and can spend real ACME quota; the generic "reachable from
  beyond this machine" wording understated what a same-segment observer can do with a
  sniffed token.
- **The deploy binding memo is bounded (TTL + entry cap) and dropped on delete.** It is
  keyed by certId and certificates rotate, so a long-lived daemon kept one
  `BindingSnapshot` per certificate it had ever seen. `Delete` forgets the snapshot once
  the API has accepted the delete.
- **`wecert-once.service` is hardened to match `wecert.service`.** The oneshot form runs
  the same binary with the same credentials and was missing `CapabilityBoundingSet`,
  `RestrictNamespaces`, `ProtectClock`, `MemoryDenyWriteExecute`, `UMask=0077` and the
  rest of the hardening section.

### Changed

- **Internal structure only; no behaviour change.** The longest functions and files were
  split by stage / section / table / concern so one responsibility lives in one place:
  `Reconcile` and `issue` into named stages, `Config.normalize` by config section,
  `cmd/wecert` boot into `runtime.go`, `state` by table, `reconcile` by concern, `dns`
  and `manager_flow` by phase, `onboard` by pipeline step. Unit tests in `group`,
  `inventory`, `metrics`, `probe`, `ratelimit`, `reconcile`, `spec`, `tcerr` and
  `webhook` now run with `t.Parallel`; suites that share process-wide fakes stay serial.

### Added

- **Inventory groups certificates by Tencent Cloud UIN.** `GET /api/inventory`
  includes `uin` on each row (from `tencent.uin`, or a certificate-level `uin`
  in the desired-state document). `GET /status` is a read-only register: filter
  by account, attention and expiry, search, and expand a row for CLB bindings.
  Empty `uin` is omitted rather than invented.
- **The inventory names the region a certificate is bound in.** Each row carries `regions`
  (and the page a Region column), read from the live binding rows rather than from
  configuration: a Tencent Cloud SSL certificate is not itself regional, and `tencent.regions`
  is the deployment's search list, not a property of one certificate. Absent means no
  enumeration has named one, so an unenumerated certificate shows nothing instead of a guess.
  The CLB column no longer repeats the region.

### Fixed

- **A paused identifier stops ordering instead of retrying into the pause.** Let's Encrypt's fifth
  published limit — consecutive authorization failures per identifier — is the one refusal that
  names no retry instant: crossing 1,152 consecutive failures pauses the (account, identifier) pair,
  and only the CA's self-service portal lifts it. No deadline was recorded for it, so the
  certificate kept re-ordering at the local 1m..6h backoff against a state the CA had already
  refused. Both published wordings are now recognised (`too many failed authorizations recently: …`
  and Boulder's "temporarily prevented from requesting certificates for …"), the deadline is booked
  against the identifier the message names (the certificate's own first name when it names none),
  and it is a **one-day floor** taken from the published refill rate — 1 per identifier per day —
  rather than the CA's answer, because waiting does not lift a pause. The journal says that in one
  line and names the portal, and the blocked gauge carries
  `consecutive-authz-failures-per-identifier`. A refusal that does carry an instant is still the
  per-hour failure budget, and an unrecognised refusal still retries on the local backoff.
- **The orphan teardown is no longer repeated on every pass.** Certificates that left the desired
  state keep their row by design, and the sweep tore every one of them down again on every pass:
  measured at 2,999 orphans that was 6.000 SQL statements per orphan — 17,994 per pass, identical
  on every pass, forever. A new `certificates.orphan_cleaned_at` column records that a name's
  teardown finished, and the sweep skips the teardown — one query for the whole fleet, no
  per-orphan read — while still reporting the orphan in the journal and in
  `wecert_orphaned_certificates`. The mark is cleared when the name comes back into the desired
  state, and it is never written when the teardown failed or left an order or authorization row
  behind, so a TXT record that could not be reclaimed is still retried. Measured with
  `-tags verifycount`: 18,001 statements per pass before, 7 after.
- **The inventory page reported healthy certificates as broken and broken ones as healthy.**
  Three defects shared one cause: the page asserted what nobody had observed. `probe.enabled`
  was hardcoded true while no probe answer was ever handed to the assembly, so every deployed
  certificate met the "probing is on and no sample exists" rule and read `binding_unknown` — a
  status whose own definition is "the binding enumeration is incomplete". A certificate with no
  state row at all fell through every check to `ok`, and its bindings were published as
  `count: 0, complete: true`: a confident "bound nowhere" for something that does not exist. The
  daemon now supplies `ProbeEnabled`, the prober's last answers and the deployment's resource
  types (`probe.Runner.Answer`, `internal/reconcile/probe_answers.go`); a certificate that was
  never issued is `not_issued`; an issued certificate whose first upload has not happened is
  `pending_deploy`; a name that could not be dialled is `probe_unreachable`, not
  `probe_mismatch`; "probing is on and there is no answer yet" is `probe_unknown`, which leaves
  `binding_unknown` to the case the word describes; a state row that could not be read is
  `state_unreadable`; and a store-side count is published as the lower bound it is
  (`complete: false`), never as the whole set.
- **The inventory drew live binding rows after it had already decided the status.**
  `ApplyLiveBindings` ran on the assembled snapshot, so a certificate whose enumeration came
  back incomplete stayed `ok` in both the row and the summary. Live rows are now an input to the
  assembly, and `BindingSnapshot` carries `observedAt`, so a cached row says when it was
  observed instead of passing for current.
- **The inventory's drift list named causes the probe never reported.** A mismatch with no
  problem kind was published as `served_names_mismatch`, while an untrusted chain or a served
  certificate below the validity floor produced no token at all. Tokens now come from the
  problem kinds — `served_chain_untrusted` and `served_validity_below_floor` join the list — and
  a mismatch that carries no kind produces no token.
- **`desired.frozen` was published as `false` when the desired-state document had never been
  read.** It is `null` in that case now and the page says "desired state not read";
  `/hook/desired` already answered 503 for the same state.
- **The inventory and the binding count disagreed about an unanswered enumeration.**
  `ParseCLBBindingItems` treated a finished task with no region block as a complete zero, so the
  page could print "bound nowhere" for a certificate whose regions were never answered, while
  `countBindings` called the same payload incomplete. A region block with an empty instance list
  is still a genuine zero; a missing one is not.
- **`docs/inventory-ui.md` carried seven literal escape sequences** (`\u2014`, `\u2026`) where
  the characters they stand for belong.
- **A failed certificate read erased the certificate it failed to read.** `Reconcile` answered
  a `GetCert` error by building an empty `CertState` — a name and nothing else — and passing it
  to `recordFailure`, which persists through the full-column `PutCert` upsert. One bad read (a
  row the scanner cannot decode, a transient I/O error) therefore rewrote the row with empty
  `cert_pem`, `key_pem`, `not_after`, `deployed_cert_id` and `ari_cert_id`: the only local copy
  of the private key and the deployment record, destroyed by the same pass that failed to read
  them. The read-failure path now uses the new `Store.RecordFailure`, a narrow upsert that
  touches only `consecutive_failures`, `last_error` and `next_attempt_at`.
- **The wildcard failure-budget claim named the apex, not the wildcard.** Phase 3 of the order
  flow called `noteIdentifierFailure(a.Identifier)` — the bare domain — while the other three
  bookkeeping sites and the cooldown reader use `challenge.GetTargetedDomain`, which carries the
  `*.` prefix. One wrong key, two failures: the claim that serializes concurrent passes on a
  shared wildcard never matched the cooldown lookup, and the apex entry was never cleared on
  success, so it blocked a plain `example.com` issuance for the rest of the hour. The claim now
  names the targeted identifier like everywhere else.
- **`Trouble()` reported a fully backed-off run as clean.** Backed-off certificates count into
  `rep.Backoff`, not `Skipped`, so a `-once` run in which every certificate sat inside a backoff
  window attempted nothing, skipped nothing, and exited 0 — exactly the silent stall the systemd
  timer's exit code exists to surface, and exactly what the function's own comment promised to
  catch. Backoff now counts as trouble.
- **A typo'd webhook trigger key no longer widens into a fleet-wide convergence.**
  `parseTrigger` decoded into a key set it never validated, so `{"certificate": "foo"}` — the
  shape a CI template with a renamed variable produces — parsed as "no certificates named",
  which the handler reads as "all of them", spending issuance quota for the whole fleet.
  Unknown keys are now rejected with 400, joining the existing guards for empty `cert` and null
  `certs`.
- **The onboarding lock is verified held before the state is committed.** flock is bound to the
  inode: remove the lock file and the next process locks a fresh inode, and two runs walk the
  load-compute-write critical section together. `wecert-onboard` now acquires the lock through
  the new `state.AcquireFileLock`, whose handle exposes the `VerifyHeld` check the daemon's
  store already performs, and calls it before `Commit`.
- **An ACME account is no longer lost when its registration succeeds but the state write
  fails.** `EnsureAccount` used to register first and persist second, so a failed `PutAccount`
  left the account known only to the CA and the next start registered another one, spending the
  CA's newAccount quota each time. The key is now persisted first with an empty kid and the kid
  backfilled after registration, so a restart resumes the same account.
- **A discarded order no longer triggers a second orphan-TXT sweep in the same pass.**
  `discardOrder` already runs `cleanupOrphanTXT`; `Reconcile` then ran it again at the end of
  the same pass, repeating a round of authoritative DNS probes the pass had just paid for. The
  wrap-up sweep is skipped when a discard already did it.
- **A cancellation during the recursive-resolver probe no longer reads as "TXT propagated".**
  The probe's fallback branch could reach the success return without ever checking the context,
  so a cancelled pass walked on toward `AcceptChallenge`. The success path now checks
  `ctx.Err()` first.
- **Failure fallback no longer enters through a pruned record.** `applyFallback` read
  `fallbackActive` before pruning, then pruned the record, then used the stale flag — so the
  "close enough to expiry" gate at entry was skipped for a certificate nowhere near expiry.
  Pruning now resets the in-memory flag with the record.
- **The single-authority exemption counts delegated nameservers, not resolvable ones.** A zone
  delegating to two NS names where one fails to resolve used to fall under the "one authority
  is exempt" branch and confirm propagation on a single answer. Unresolvable delegated names
  now still count toward the delegation, so the exemption only applies to genuinely
  single-homed zones.
- **`ratelimit.NoteDeadline` no longer lets an older response move the deadline earlier.** The
  `Deadline` contract says the later instant wins, but the assignment was unconditional, so a
  stale refusal processed late (the manager runs one goroutine per certificate) could pull the
  stored deadline back inside the CA's window. The later instant now wins, as documented.
- **`ParseRetryAfterHeader` rejects a delay that overflows `time.Duration`.** A Retry-After of
  more than ~292 years multiplied into a negative duration and produced a deadline in the past —
  which reads as "not blocked" on precisely the response that asked for the longest wait.
- **`wecert_ratelimit_remaining_tokens`'s help text said "lower bound" where it meant "upper
  bound".** The estimate counts only this program's own consumption, so the real remainder is
  always smaller; reading it as a floor is the dangerous direction when judging whether the
  week's issuances still fit.
- **The state store's restrictive-umask windows are now mutually exclusive.** `restrictiveUmask`
  is process-global state, and two overlapping windows restored in the wrong order left the
  whole process stuck at 077 — silently, in the code path that exists to keep private keys
  private. A package-level mutex serializes the windows, and the contract that nothing else may
  create files inside one is now written down.
- **`Open` refuses to continue when it cannot stat the file it just opened.** That stat feeds
  the inode identity `VerifyOnDisk` checks every pass; its failure used to set `openedAs = nil`,
  which disabled the replaced-database detection forever, with no log. The open now fails with
  the path named.
- **Snapshot temp files carry the store's base name.** Two deployments sharing one backup
  directory could pick the same `.snapshot-<ms>-<n>.tmp` name in the same millisecond, failing
  one side's `VACUUM INTO`, and the stale-temp sweep collected the other deployment's files.
  Temp names now match the final names' per-store prefix, and the sweep only touches its own.
- **Negative safety knobs passed to `wecert-onboard` are rejected instead of silently replaced
  by defaults.** `New()` mapped every non-positive `MaxNames`, `GracePeriod`, `BudgetWindow`,
  `Budget` and `DropThreshold` to its default — so `-budget -3` weakened a safety limit while
  reporting success, the exact "typo silently undone" the config layer refuses for the same
  knobs. Zero still means "use the default"; negative is an error.
- **`NewCLBRules` refuses an empty region list at construction.** The failure used to surface
  only at enumeration time, where it was treated as transient weather — so with `RequireRule`
  set, guard 1 silently stopped vetoing new names, round after round.
- **The onboarding state file gets the same trust checks as the desired-state document.**
  `AbsentSince` in that file is what decides whether a deletion grace period has elapsed, so a
  group/world-writable state file is one `rsync` away from a silently shortened grace period.
  `LoadState` now refuses group- or world-writable files and checks the owner, mirroring
  `spec.LoadDocument`.
- **Config validation closes the silent-typo gaps.** `dns.ttl: -1` is rejected instead of
  replaced by the default; `dns.legoProvider` set without `provider: lego` is rejected instead
  of ignored; `webhook.notifyURL` must parse as an absolute http(s) URL at load time instead of
  failing on every send; `probe.timeout` has a 1s floor; `metrics.listen`/`webhook.listen` are
  validated with `net.SplitHostPort`; and `parseDuration` errors now say there is no day unit.
- **Dual-key certificates are no longer rejected as duplicates.** `NormalizeCertificates` keyed
  duplicate detection on the domain set alone, so the standard RSA+ECDSA pair — which CLB
  supports and serves by algorithm negotiation — was refused as "one of them can only waste
  quota". The key type is now part of the key.
- **The observe-mode diff compares `renewBefore` by duration, not by spelling.** A static
  `renewBefore: 720h` against an onboarding document that omits the field reported a permanent
  diff over two spellings of the same value — and a permanent diff is what the documentation
  says must be clean before switching to enforce mode. The parsed durations are compared.
- **`spec.Revision` is order-insensitive across certificates, not just across domains.** The
  hash walked the certificate slice in input order, so a reordered document — any future
  producer, or a hand edit — changed the revision without changing anything. Certificates are
  sorted by name before hashing.
- **`Reconcile` hardening in the notification and metrics paths.** The success-path
  `notifier.Renewal` now runs under the same panic guard as the failure path — a panicking
  notifier previously rewrote a successful pass into a reported failure and notified twice.
  Publishing `wecert_certificate_not_after` first deletes the certificate's series under any
  other profile label, so switching profiles no longer strands a frozen series that keeps
  feeding the expiry alert. `OrphanedCertificates` counts every certificate present in the
  store but absent from the desired state, including ones whose teardown is deferred while a
  pass runs.
- **`reclaimStaleProbeSeries` resolves the desired state once per pass.** It used to re-resolve
  — file read, YAML decode, validation, hash — once per candidate host, with metric and log side
  effects each time, on a `context.Background()` shutdown could not cancel.
- **`waitDeleteTask` tolerates a failed poll the way `waitDeleteRecord` does.** One transient
  `DescribeDeleteCertificatesTaskResult` error used to fail the whole deletion verdict and
  postpone it a full cycle; query errors now warn and keep polling within the existing deadline.
- **`StartNamed` reports the passes it already accepted when shutdown begins mid-walk.** It used
  to return bare `ErrShuttingDown` and drop the accepted list, so the webhook answered 503 for
  reconciliations that were in fact running.
- **CLI flag hygiene.** `-interval` below one minute is rejected in daemon mode (jitter used to
  floor it at one second — a full reconcile pass per second); `tatrun -interval <= 0` is
  rejected (it spun `waitForTask` into a hot poll against the TAT API); mutually exclusive
  combinations (`-revoke` with `-once`/`-dry-run`/`-log-level`, `-once` with `-dry-run`,
  preflight's `-bindings` with `-prune-certs`) are rejected instead of silently picking a
  winner; an unknown `-log-level` is an error instead of a silent demotion to info; and
  `signal.NotifyContext` is registered at the top of `run()` instead of after the first network
  calls.
- **`tatrun` no longer garbles plaintext output that happens to be valid base64.** A remote
  `echo DONE` trims to `DONE`, which *is* legal base64 — and was decoded into three bytes of
  garbage. Decoded output now has to look like text (valid UTF-8, no control characters) or the
  original is printed.
- **`preflight -domain example.com.` (trailing dot) no longer reports the domain missing from
  DNSPod.** The comparison trims the root dot first.
- **`install.sh` verifies `wecert-onboard` against `SHA256SUMS` too, and checks the
  architecture.** The main binary got a checksum verification whose whole point is "whatever
  file was passed in becomes a root-owned binary" — and the same directory's second binary was
  installed as root with no check at all. Both are verified now, and the ELF check compares the
  binary's machine against `uname -m` instead of passing any 64-bit ELF on any architecture.
- **`tatrun` no longer exits 2 on a typo.** It was the last command in the tree using the
  package-level `flag.Parse()`, whose `ExitOnError` prints the usage and exits 2 — the code
  `wecert-onboard` reserves for "deliberately frozen, a human should look". It now parses its own
  `ContinueOnError` FlagSet and returns the conventional usage code 64, like every other command.
- **A state snapshot is no longer cut short by shutdown.** `startStateBackups` returned nothing, so
  the one background worker that writes to SQLite on its own schedule was never waited for: a pass
  that ended as the ticker fired raced the deferred `store.Close()` against `Snapshot`'s
  `VACUUM INTO`. It now returns a stop function that cancels the loop and waits for it.
- **A rejected webhook token no longer leaks the port.** `startWebhookServer` bound the listener
  and then returned on a `webhook.New` error, so the fix — edit `webhook.token`, restart — failed
  with "address already in use", pointing at a phantom instance instead of the setting just changed.
- **`preflight` cannot page a domain list forever.** `findDomain`'s two exits are both answers the
  server gives (an empty page, or a covered total), so a server that ignores `Offset` looped
  without end. It is now capped at 100 pages, and hitting the cap is an error rather than the
  function's documented "the account does not hold this domain" answer.
- **`probe.maxHostsPerCert: 0` is honoured.** As a plain int it was indistinguishable from unset,
  so `normalize` rewrote it to the default and reconcile's "a cap of 0 means probing is off" branch
  was unreachable in production: writing 0 to pause probing silently kept probing three hosts per
  certificate. It is a `*int` now, like `enabled` and `requireTrusted`, and `wecert` warns at
  startup when the cap is 0 so the silence of the probe series is not read as "nothing to report".
- **A panic after the pass's answer no longer changes that answer.** `publish` and `probeCert`
  run after the switch that decides ok/error/skipped and are both best-effort, but they ran bare: a
  panic in either unwound into `reconcileOne`'s recover, so a certificate that had just been
  renewed was reported as a failed pass — metric `ok`, report `Failed`, `-once` exiting non-zero
  for a certificate that was fine. Both are contained now: counted, logged with a stack, and no
  longer an answer.
- **One in-flight pass no longer suspends probe-series reclamation for the whole fleet.**
  `reclaimStaleProbeSeries` skipped everything while ANY pass was running, and a webhook-triggered
  pass runs for minutes while the timer's own pass finishes around it — so hosts whose certificate
  had already left the desired state kept their series, which is the permanent false alert that
  function exists to remove. The guard is per certificate now; only a pass for a certificate that
  is no longer in the desired state can still hold back a host with no owner.
- **An unreadable desired state no longer destroys the probe record.** `reclaimStaleProbeSeries`
  cleared the per-round `probedHosts` set *before* the branch that returns with "keep the series
  rather than deleting evidence", so one unreadable document threw away the record of what was
  probed — and the next round that did resolve a document deleted the series of every host the
  previous round probed and this one did not.
- **A webhook trigger that names nothing managed here answers 404, not 202.** `202` says
  "accepted, convergence is on its way" for a request that will never converge anything, and a
  deploy hook polling `/hook/status` finds the certificate absent from every field and concludes
  the trigger worked. A partial answer (some names started, others unknown) is still `202`, with
  the unrecognised names in `unknown`.
- **`clbverify` accepts its own flags again.** `-clb` was registered on the package-level
  `flag.CommandLine` instead of on the FlagSet `fs.Parse` actually reads, so every invocation
  died with "flag provided but not defined: -clb" and the tool was unusable. The flags live in
  an `options` struct behind `newFlagSet` now, and a test parses all eight of them.
- **`wecert` catches the `-revoke` contradictions it defines.** `validateFlags` walked
  `flag.Visit` — the package-level FlagSet, which nothing in this program parses — where
  `fs.Visit` was meant, so the "explicitly set" map was always empty and every contradiction the
  function exists to catch was accepted. Parsing is `parseArgs` now, and it is tested.
- **A stale DNS-01 challenge lease is released under the per-name lock.**
  `releaseStaleLeaseExcept` removed a lease without holding the per-name mutex, while
  `dns.go:CleanUp` holds that same mutex across the whole provider call (remove, then
  delete-ALL TXT). Interleaved, the delete-all ran when neither party held a lease, so a TXT
  record stayed in DNS with no row and no lease holding it. The check-then-act now runs under
  the lock.
- **A failed read no longer resets an established backoff.** `RecordFailure`'s upsert overwrote
  `consecutive_failures` and `next_attempt_at`. Its only caller passes a lower bound ("at least
  one"), so one unreadable row during an already-backed-off certificate reset a 6-hour backoff
  to the first retry — and dropped the count below the `ConsecutiveFailures >= 5` that failure
  fallback needs, so the certificates that most needed degrading were the ones that could never
  degrade. The upsert merges with `MAX` now: the count and the backoff are monotonic, and only a
  successful pass (a whole-row `PutCert`) lowers them.
- **A permanent deployment error no longer spins for the whole poll budget.** The three polling
  loops did not distinguish a permanent API error from a transient one, so an `AuthFailure` or an
  `UnsupportedOperation` spun for the full 3 minutes and the real cause was swallowed into "did
  not finish within 3m". `tcerr.IsPermanent` / `IsThrottled` / `Code` classify the SDK error now:
  permanent errors return at once, and a throttle doubles the poll interval instead of hammering
  the limit. A cancelled call also keeps *both* identities — the context, so "a stopped process
  is not a business failure" still sees it, and the API error, so a `RequestLimitExceeded` is
  still classifiable — where before one replaced the other.
- **A served chain that no client will accept is a failed probe.** `probe.Verify` compared what
  was deployed against what was served and never read `Trusted` or `ChainError`, so a listener
  serving the leaf without its intermediate — the single most common CLB misconfiguration —
  passed every check and reported `probe_match = 1`, and so did a self-signed chain. Chain
  verification is a fifth check now, reported as its own `untrusted` problem with the chain error
  as the diagnosis. It is on by default in the reconcile loop, because there the question is
  "will a client accept this"; turn it off with the new `probe.requireTrusted: false` when the CA
  is internal, where "does not chain to a public root" is permanent and trains everyone to
  ignore the alert. **This can flip `probe_match` from 1 to 0 on an existing deployment** — that
  is the point, but it is a change in what the metric means.
- **Smaller corrections:** the webhook `/hook/desired` endpoint reports a store read error as
  `error` instead of as `issued: false`; `RecordRevokeAttempt` refuses to count attempts against
  a non-existent request; `PutRateBucket(nil)` is an error like `PutAuthorization(nil)`;
  repaired snapshots are directory-fsynced; `onboarding.New` no longer sorts the caller's
  allowlist in place; onboarding decisions index hostnames instead of scanning the list three
  ways per verdict; the shutdown-drop of a queued pass logs at WARN; and `RunCert` is documented
  as the synchronous, test-oriented entry point that bypasses drain protection.

### Security

- **A config file carrying inline secrets now warns when it is readable by others.**
  `state.db`, its snapshots and the desired-state document all enforce permission discipline,
  but the config file — the one place `secretKey` and `loginToken` are explicitly documented as
  allowed inline — was read with no check at all. `Load` warns when inline secrets sit in a file
  wider than 0600.
- **`wecert` warns when `LEGO_DEBUG_DNS_API_HTTP_CLIENT` is set with the DNSPod provider.**
  lego's debug dumper redacts headers, and dnspod-go sends the credential in the POST body, so
  the variable writes the never-expiring DNSPod token into the journal; the hazard was only a
  comment. The onboarding state file permission/owner checks above are also security-relevant.

### Fixed

- **A deployment could be recorded as complete from an answer it never got.** The bind-resource
  enumeration reported "0 bound resources, finished" when a region's query had failed inside the
  task, and the deploy recovery path reads exactly that zero as "the old certificate is bound
  nowhere, so the switch must have happened" — so a half-finished switch could be recorded as done,
  with some listeners still on the old certificate and nothing left to revisit them. The same
  silence produced the opposite error in the other verification call ("this deploy did not happen"
  for one that did). The count now carries whether it is the whole answer; zero from an incomplete
  answer is refused rather than believed, and a non-zero lower bound still proves a binding (which is
  what the periodic confirmation poll needs).
- **Two deployment verification calls were reading the server-side cache.** The SDK documents
  `IsCache=1` as: if a completed task exists for this certificate within the last half hour, return
  that task's result. That is fine for the periodic "has a human bound it yet" poll and wrong for the
  two calls that decide whether a switch took effect. They now ask for a fresh answer; the periodic
  poll keeps the cache.
- **Propagation checks counted IP addresses where they meant nameservers.** DNSPod's own pools
  publish three A records per NS name and a dual-stack name publishes two, so one multi-homed
  authority satisfied "at least two independent confirmations" — the guard the comment promised was
  not there. The mirror image was worse: a single-authority zone with an unreachable second address
  could never confirm, because the "one authority is exempt" branch was keyed on the address count.
  Confirmations are now counted per NS name.
- **A SERVFAIL was read as "the record is not there".** Rcode was never inspected: SERVFAIL or
  REFUSED landed in a bucket that only fed the summary line, unless the server set the authoritative
  bit, in which case a transient failure was recorded as a denial — and a denial is what licenses
  deleting the authorization row for a name that is still being validated. NXDOMAIN stays a denial
  (it is a definitive answer); any other error code is now inconclusive.
- **`exchangeDNS` threw away a usable UDP answer when the TCP retry failed.** Both attempts share the
  caller's three-second context, so on a server that is slow on TCP — the case the retry exists for —
  the truncated UDP answer was replaced by nil and the server counted as unreachable, discarding an
  answer whose answer section may already have carried the record. A truncated answer is now returned
  marked as truncated, and the probe treats it as inconclusive rather than as a denial.
- **A late zone in the propagation wait could not succeed and was blamed for it.** Zones are processed
  serially against one shared deadline, so a zone reached after the budget was gone got a single
  doomed round and then an error reporting the *global* elapsed time as if it were that zone's own
  wait — and because the zones come from a map, which one was starved changed from pass to pass. The
  deadline is now checked before a zone is entered, and the message separates "this zone waited" from
  "the pass had already spent".
- **A store failure while solving a challenge skipped the failure accounting.** Four
  `PutAuthorization` calls in `solveChallenges` (and one `PutCert` after a successful deploy) returned
  the raw error, bypassing `recordFailure`: `ConsecutiveFailures` stayed 0, no backoff was scheduled
  and no counter moved, so a persistent write failure — a full disk, or `SQLITE_BUSY` while another
  process holds the write lock — was retried on every pass forever while the certificate's own
  metrics reported a healthy zero failures.
- **`ChallengeSent` was never cleared when the challenge changed.** The flag belongs to the challenge
  it was set for, and phase 3 skips any row that has it, so after the CA handed back a different
  challenge for the same authorization the new TXT was written, never announced, and the order sat
  pending until it expired — up to the 7-day order TTL — with nothing counting it. The stale-token
  refresh now clears it.
- **`OpenUnlocked` migrated the schema without holding the lock.** `migrate` is a CREATE TABLE batch
  plus a check-then-act `ALTER TABLE ... ADD COLUMN`, so two unlocked opens — `wecert -dry-run` and
  `wecert -revoke` both use this path, and both write — could pass the same "does this column exist?"
  check, and the loser aborted with `duplicate column name: ...`, an error that names neither the
  cause nor the fix. The unlocked path now verifies the schema and refuses with an instruction; the
  daemon owns migrations. Its doc comment also claimed the unlocked callers "only read", which was
  untrue for both of them.
- **Archived rollback material could be silently discarded.** `AddRetiredCert` used
  `ON CONFLICT(cert_id) DO NOTHING`, so when the orphan path recorded a certificate with no material
  before the retirement path recorded the same id with the fullchain and key, the real pair was
  dropped and the documented manual rollback in `docs/recovery.md` had nothing to restore. It now
  `COALESCE`s, so neither write order can lose material.
- **`dns.pollingInterval` and `dns.propagationTimeout` had no floor.** Only "positive" was checked,
  so `1ms` turned the propagation wait into a burst of UDP queries at the operator's own
  authoritative nameservers, and `1s` made every fresh record fail its round and enter backoff. There
  are now a 1s and a 30s floor plus the `polling < propagation` invariant, which the much less
  dangerous `stateBackup.interval` has had all along.
- **`stateBackup.enabled` did not do what its comment promised.** The comment says it defaults to true
  where the directory is writable and false where it cannot be; `normalize` never probed anything and
  the only caller passed a literal `true`, so a deployment with an unwritable snapshot directory
  stayed enabled and logged an ERROR every interval forever. The decision is now made where the
  directory is known.
- **The order-timeout message had its two arguments swapped** — `did not reach "3m0s" within ready`.
  Nothing catches this: `%q` is a string verb and `time.Duration` has a `String` method, so it
  compiles and passes `go vet`.
- `tencent.regions` and `tencent.resourceTypes` are trimmed, lowercased, deduplicated and checked for
  empty entries, as every other list in the config already was. They are multiplied into the deploy
  request (`types x regions`), so a duplicate was a bigger request and a typo was only found by the
  cloud API at deploy time.
- `deploy/systemd/wecert-once.service` claimed that being killed on timeout bumps
  `consecutive_failures` and "manufactures a pointless alarm". It does not: `recordFailure` returns
  early for `context.Canceled` and `context.DeadlineExceeded`. The comment was the stale artefact, not
  the code.

### Added

- **Secrets can come from a file or a systemd credential instead of `config.yaml`.** `dns.loginTokenFile`,
  `tencent.secretIdFile` and `tencent.secretKeyFile` read the credential from a file, and their paths are
  **environment-expanded** so systemd's `LoadCredential` works:
  `LoadCredential=dnspod-token:/etc/wecert/dnspod.token` plus
  `loginTokenFile: ${CREDENTIALS_DIRECTORY}/dnspod-token`. `DNSPOD_LOGIN_TOKEN` is accepted from the
  environment when neither field is set. A token in `config.yaml` was a token in every backup of it and in
  every paste into a chat window; the file variants are the difference between rotating the token and also
  rewriting every copy of the config that ever existed. Setting both is refused rather than guessed at, an
  unreadable or empty file is a config error naming the path, and the check runs at load time — before an
  order is placed, not when the challenge fails.
- **`state.Store` has transactions, and the renewal epilogue uses one.** The end of a renewal — promote the
  new certificate, retire the old one, record the certificate the order uploaded but never bound, clear the
  fallback record and the identifier ledger, discard the order — used to commit as separate statements, and
  both halves of a partial failure were states no later pass could repair: promoted-without-retired leaves
  the certificate that was serving in no table at all (never reaped, never deleted from the cloud, holding
  uploaded-certificate quota forever), and retired-without-promoted schedules the certificate that *is*
  serving for deletion. `Store.WithTx` plus `_txlock=immediate` in the DSN makes it one unit; the promotion
  is now staged on a copy, because writing it into the live state first quietly defeated the transaction —
  the failure path calls `recordFailure`, which persists that state, so the rollback was overwritten by a
  fresh write of the very promotion it had just rolled back. The failure message now says what is true: the
  certificate IS issued and deployed, the cloud does not roll back, and the next pass will re-order.
- **`make test-repeat`** (`-race -shuffle=on -count=3`), and the two defects it found. Two tests in
  `internal/reconcile` asserted absolute values on process-global counters, which holds only on the
  first run of a test binary: `go test -count=2 ./internal/reconcile/` failed with "got 2". They now
  assert the delta, which is both repeatable and the stronger claim — "this pass counted exactly
  once" rather than "the counter reads 1".
- **`scripts/test-check-alerts.py`**, wired into `make check-alerts`. `check-alerts.py` was reporting
  a green tick over files it had not understood, in four different ways — a rule written as a flow
  mapping, an `expr:` above its `alert:`, an empty `rules:` list, no `groups:` at all — each of which
  printed "0 alert rules in 0 groups; every series they reference is exported" and exited 0. It now
  fails when it reads nothing, cross-checks its own parse against a regex count of `alert:` keys, and
  refuses any list item whose shape it does not recognise; it also checks that a `{{ $labels.x }}` in
  an annotation names a label the metric actually carries, which previously rendered as an empty
  string rather than as an error. The self-test asserts that all 11 broken shapes are rejected *and*
  that two valid files are accepted.
- **Build-tag tests for the lego provider path** (`internal/acme/lego_build_*_test.go`). Whether
  `dns.provider: lego` is a valid configuration depends on `-tags lego_dns` reaching `config` through
  the acme package's `init`, and nothing tested that wiring. The test that looked like it did lived in
  the `config` package, which cannot import `acme` without a cycle and so could only observe its own
  zero value — it passed in a tagged binary that would have wrongly rejected a valid configuration.
  It is replaced by tests that run acme's init by construction and assert both directions.
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

- **The rate-limit gauges leaked a series per retired scope, and the leaked series kept firing an
  alert.** `PublishQuota` rebuilt `wecert_ratelimit_blocked` from scratch on every pass but only ever
  *added* to `wecert_ratelimit_remaining_tokens`, and `WithLabelValues` never deletes. The scope
  label is derived from the desired state — the first certificate's first domain — so an ordinary
  edit (renaming or dropping that certificate) left the old scope's series frozen at its last value
  for the life of the process. `WecertRateLimitNearlyExhausted` compares that number against 5, so
  the result was a permanent warning for a domain this program no longer manages, indistinguishable
  from a real exhaustion. Both vectors are now rebuilt on every call; absent means "not published",
  which is the honest answer for a scope that has left the desired state.
- **Expiry alert descriptions asserted a diagnosis the metrics cannot support.** The thresholds are a
  quarter of each profile's nominal validity — the same number the daemon logs a warning at — but
  they are calibrated to the profile *defaults*. `renewBefore` is per-certificate, and ARI can move
  the renewal window later still, so "reaching this point means renewal has been failing for at least
  a week" was not always true: a certificate with a short `renewBefore` tripped it before its renewal
  was due. The descriptions now say what to check (`wecert_certificate_consecutive_failures`) instead
  of asserting the cause, and the group comment states the calibration.
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
