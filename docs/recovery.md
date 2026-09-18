# Recovering wecert's state

`state.db` is the only thing in this system that cannot be regenerated. It holds:

| What | Why losing it hurts |
|---|---|
| The ACME **account private key** | A new account must be registered. Accounts are limited to **10 per IP per 3 hours**, and every order placed afterwards is a fresh order regardless of what was in flight. |
| The **order URL** of every in-flight order | The replacement order counts against **5 certificates per exact set of identifiers / 7 days**, a limit with no override. Tripping it means waiting the full week. |
| The **ARI certID** of every live certificate | A renewal without `replaces` loses the rate-limit exemption. |
| Every certificate's **private key** | The live certificate can no longer be re-uploaded or re-bound anywhere. |
| The **DeployedCertID** of every certificate | wecert forgets which cloud certificate is serving, so the next renewal cannot swap it |

None of it is reproducible from the config, from the cloud API, or from the ACME server. Treat
the file as the system's only source of truth.

---

## 1. Snapshots

Enabled by default (`stateBackup`, see `config.example.yaml`). Every `interval` (24h) wecert
writes a consistent copy beside `state.db`, keeping the newest `keep` (7) named:

```
/var/lib/wecert/state.db.backup-20060102T150405.123Z.db
```

The name is `<state.db's file name>.backup-<UTC stamp, milliseconds>.db`, so the glob for this
deployment is `state.db.backup-*.db`. (This section used to print `state.backup-<stamp>.db`, which
matches nothing the code writes: the rsync below silently copied zero files and exited 0.)

They are **not** plain file copies. The database runs in WAL mode, so the bytes on disk are
`state.db` plus a `-wal` holding everything since the last checkpoint — copying `state.db`
alone can miss the order URL persisted a second ago, which is the one thing you would be
recovering. Snapshots use `VACUUM INTO`, which asks SQLite for a consistent logical copy, and
the result is a single self-contained database with no sidecars to keep in step.

They are written `0600`. They contain the account key and every certificate private key.

**Snapshots are not a substitute for off-host backup.** They sit next to the file they
protect: a lost disk, a dropped directory or a bad `rm` takes both. Copy them somewhere else:

```sh
# Anywhere off the host. The files are small (a few hundred KB).
rsync -a /var/lib/wecert/state.db.backup-*.db backup-host:/srv/wecert/
```

If `stateBackup.enabled: false`, wecert logs a warning at startup saying so.

---

## 2. Restoring

```sh
# 1. Stop the daemon. Two processes on one state directory is a startup failure, and the
#    lock makes it obvious rather than silent.
systemctl stop wecert

# 2. Keep the damaged file. Do not delete it: if the content is partially readable, an
#    operator can still recover an order URL or an account key from it by hand.
mv /var/lib/wecert/state.db /var/lib/wecert/state.db.damaged
rm -f /var/lib/wecert/state.db-wal /var/lib/wecert/state.db-shm

# 3. Install the snapshot as the live database. A snapshot has no sidecars, so nothing else
#    has to be copied.
cp /var/lib/wecert/state.db.backup-<newest>.db /var/lib/wecert/state.db
chown wecert:wecert /var/lib/wecert/state.db
chmod 0600 /var/lib/wecert/state.db

# 4. Verify BEFORE starting. wecert does this too, but doing it by hand tells you whether
#    the snapshot is itself usable.
sqlite3 /var/lib/wecert/state.db 'PRAGMA quick_check;'          # expect: ok
sqlite3 /var/lib/wecert/state.db 'SELECT count(*) FROM accounts;'      # >= 1: the account key survived
sqlite3 /var/lib/wecert/state.db 'SELECT name, datetime(not_after,"unixepoch") FROM certificates;'
sqlite3 /var/lib/wecert/state.db 'SELECT cert_name, order_url FROM orders;'  # in-flight orders

# 5. Start and watch the first pass.
systemctl start wecert
journalctl -u wecert -f
```

### What to check in the logs

- **No "registering a new ACME account"** — if that line appears, the snapshot predates the
  account registration (or the `accounts` table is empty), and you are on a fresh account.
- **No new order for a certificate that had one in flight** — the restored `orders` row means
  the existing order is advanced instead of re-placed.
- `wecert_certificate_deployed{cert}` back to 1 for anything that was deployed.

### If the newest snapshot is broken

Try the next one. `PRAGMA quick_check` on each before installing:

```sh
for f in /var/lib/wecert/state.db.backup-*.db; do
  printf '%s: ' "$f"; sqlite3 "$f" 'PRAGMA quick_check;' 2>&1 | head -1
done
```

---

## 3. When there is no snapshot

If the database is gone and no snapshot exists, wecert starts from empty and — deliberately —
**says so loudly**:

```
wecert: WARNING: /var/lib/wecert/state.db did not exist but its lock file did -- a state
database was probably deleted or lost. Starting from an empty one: the ACME account key and
every in-flight order URL are gone, so a new account will be registered and orders will be
re-placed (which counts against the exact-set rate limit). If you have a backup, stop and
restore it before continuing (see docs/recovery.md).
```

A genuine first install has neither file, so that warning does not fire on a fresh machine.

What happens next, and what to expect:

1. A **new ACME account** is registered. If the old account is still referenced by live
   certificates, nothing breaks — renewals from the new account behave normally — but you have
   spent one of the 10-per-IP-per-3-hours registrations.
2. **Every certificate looks like a first issuance.** With the default config that means
   wecert **uploads a new certificate and waits for a human to bind it**, because
   `DeployedCertID` is empty. The cloud certificate currently serving traffic is still there
   and still valid; nothing deletes it. Bind the new one in the CLB console when convenient,
   or leave the old one in place and let it renew.
3. **Rate limits are the real cost.** One fresh issuance per certificate is well within
   limits. The danger is a loop: if certificates fail and are retried, each retry is a new
   exact-set order. Watch `wecert_certificate_consecutive_failures` for the first hour.

### If the ACME account key is all you lost

The account key lives in the `accounts` table. If you can recover just that (from a snapshot,
or by hand from a partially damaged file), restore it and keep everything else — the account
is the scarce resource, not the orders.

---

## 4. Rolling back a certificate

A renewal replaces the certificate bound to your listeners. wecert keeps the outgoing one on
a reclaim list for `retention` (7 days, currently not configurable) and **archives its key
material in `retired_certificates`**, so a rollback does not depend on the cloud copy still
existing:

```sh
sqlite3 /var/lib/wecert/state.db \
  'SELECT cert_id, cert_name, datetime(retired_at,"unixepoch"), length(cert_pem), length(key_pem)
     FROM retired_certificates;'
```

To roll back within that window, re-upload the archived pair and rebind it in the Tencent Cloud
console:

- `cert_pem` / `key_pem` come from the table above (fullchain and PKCS#8 respectively);
- the certificate ID is `cert_id`;
- after a **successful** renewal the new certificate is already bound, so a rollback means
  re-binding the old one deliberately. Nothing in wecert does that for you — it is a manual
  operation precisely because it is a decision, not a convergence step.

After `retention` elapses the row — and with it the archived key — is deleted, and the cloud
certificate is reclaimed. Only the cloud copy remains until then, which is why the archive
exists.

---

## 5. What wecert does not protect you from

- **A lost disk.** Snapshots default to the same directory. Use `stateBackup.dir` or copy them
  off-host.
- **Bit rot in a snapshot.** `quick_check` catches structurally broken files, not a silently
  altered row. If you care, keep checksums of the snapshots you copy away.
- **Two instances.** The `flock` on `state.db.lock` makes a second process fail at startup
  rather than double-order. Do not disable it by running with a copied state directory.
- **Backups of the *desired state*.** `desired-state.yaml` and `onboard-state.json` have their
  own failure modes; see the table in `README.reference.md`.
