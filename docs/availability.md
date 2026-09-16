# Availability: what wecert already survives, and what it cannot

This note exists because "add high availability" is a request that sounds like one change and is
actually three, with very different costs — and because the cheapest-looking option does not
deliver the thing it appears to promise.

## What is already covered

**Process death is handled.** `deploy/systemd/wecert.service` sets `Restart=on-failure` with
`RestartSec=30s`, so a crash, an OOM kill or a panic restarts the daemon within half a minute. A
run that is interrupted mid-issuance is safe to resume: the order URL, the order's private key,
the ARI window and the challenge state are all on disk, so the next pass carries the same order
forward instead of placing a new one (see `README.reference.md` → *The four invariants*).

**The timer is an independent trigger.** `wecert-once.timer` fires `wecert-once.service` hourly. If
the daemon is stopped, a timer run does the same convergence work — it takes the same state lock,
so it cannot overlap, and `ErrLocked` is reported rather than queued.

So the practical question is not "does a restart lose anything" (it does not) but **"what happens
when the whole host is gone"**.

## What is not covered, and why the obvious fix does not work

`state.db` lives on the host's local disk. That single fact decides this whole area:

- **Host loss takes `state.db` with it.** Losing it means a new ACME account, every in-flight
  order URL gone, and every ARI certID gone — so orders are re-placed straight into *5
  certificates per exact set of identifiers per 7 days*, which has no override. The snapshots in
  `docs/recovery.md` bound how much is lost, but recovery is a human action, not failover.
- **A second process on the same host does not help.** It would share the same disk, so it fails
  at exactly the same moment. It would also duplicate what `Restart=on-failure` already does,
  which is why no standby mode exists: it would be redundant in the case it handled and useless in
  the case that matters.

Availability here is therefore **bounded by where `state.db` lives**, not by how many wecert
processes are running.

## The three real options

| Option | What it survives | What it costs | Does it fit this product? |
|---|---|---|---|
| **A. Faster recovery from backup** — snapshot to object storage, and script the restore | Host loss, with a recovery window measured in minutes and manual steps | Almost nothing; the snapshot machinery already exists (`Store.Snapshot` in `internal/state/backup.go`, driven by `stateBackup` in the config, documented in `docs/recovery.md`) | **Yes.** This is the honest answer to "the host died" today, and it is the only option that adds no new runtime dependency |
| **B. Two hosts, one shared database** — `state.db` on network storage both instances can reach | Host loss, with failover | `flock` over network filesystems is unreliable, and SQLite's locking over NFS is a well-known source of corruption. This would require replacing the state layer with a client for a real coordination store (etcd/Redis): the lock, the buckets, the fallback ledger and the order state machine all move | **No, not as-is.** It converts a self-contained binary into a distributed system, and the failure modes it introduces (split brain, partial writes across a network) are worse than the outage it prevents |
| **C. Per-instance state (sharding)** — each instance owns a disjoint set of certificates, with its own `state.db` | Host loss for the certificates the surviving instance owns | A second source of truth for "which instance owns what". Certificate sets that share a registered domain share quota, so sharding has to respect the exact-set and per-domain limits, which are global — the shard boundary is now a quota boundary | **Partly.** It has no external dependency, which suits this product, but it makes the quota arithmetic (the thing this program exists to protect) a function of the shard map |

## Recommendation

**Do A now, and treat B/C as a product decision rather than a fix.**

A is a small, self-contained piece of work with no new dependency and it addresses the actual
exposure: how long it takes to get certificates renewing again after a host is lost. The
snapshot format, retention and restore procedure already exist; the missing part is getting the
snapshot off the host automatically and making the restore one command instead of a documented
sequence.

B and C change what the program *is* — B makes it a distributed system, C makes quota analysis
shard-dependent — so they should be decided against a concrete availability target, not adopted
because "HA" sounds like a fix. If the target is "a certificate must never expire because of one
host", note that A meets it: at worst a renewal is delayed by the restore, and the ARI window
gives weeks of margin.

## What would have to be true before B

Three things, in order, none of which are true today:

1. **A concrete target** — an RTO and RPO, and the number of certificates whose expiry actually
   depends on it. A single-host deployment renewing ten certificates has a very different answer
   from a fleet.
2. **A coordination store the operator already runs.** Adding etcd or Redis *for wecert alone*
   makes wecert the least reliable thing in the deployment.
3. **A state layer that can be remote.** Today's design leans on `flock` for "at most one pass per
   certificate" and on local-file atomicity for migrations. Both are load-bearing and both would
   have to be re-derived against the new store's semantics — including the guarantee that a
   second process cannot place a duplicate order, which is the one thing this program must never
   get wrong.
