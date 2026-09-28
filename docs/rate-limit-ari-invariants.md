# Rate-limit and ARI invariants

Who writes what, who reads it, and which rules must stay true when either is
touched. This is the map for changing `internal/ratelimit`, the ACME flow, or
the renewal clock without walking it from scratch. Numbers and sources live in
`internal/ratelimit/ratelimit.go`; this file is the wiring.

## The five limits

| Limit | Scope key | Capacity / refill | Filled by | Spendable here? |
| --- | --- | --- | --- | --- |
| `new-orders` | `""` (account) | 300 / 36s | this program (`manager_renew`) | yes |
| `certs-per-registered-domain` | registered domain | 50 / 202m | this program (`manager_done`) | yes |
| `certs-per-exact-identifier-set` | `DomainKey()` | 5 / 34h | this program (`manager_done`) | yes |
| `authz-failures-per-identifier` | **bare** identifier | 5 / 12m | this program (`flow_order`) | yes |
| `consecutive-authz-failures-per-identifier` | **bare** identifier | 1152 / 24h | **the CA** | no (`SpentByCA`) |

The last one is not a local spend estimate. Capacity/Refill document the
published model; Refill is only the **floor** booked for a refusal that names no
instant (see `noteNewOrderRefusal`). Crossing it is a Boulder **pause** with no
expiry — waiting does not clear it.

## Write / read map

| What | Written by | Stored in | Read by | Lost on restart? |
| --- | --- | --- | --- | --- |
| Token buckets | `Tracker.Spend` via `manager_renew` / `manager_done` / `flow_order` | `rate_buckets` (SQLite) | `Tracker.Remaining`, `BlockedUntil`, quota report, inventory | no |
| CA deadlines | `Tracker.NoteRetryAfter` / `NoteDeadline` from NewOrder/ARI refusals | `rate_buckets` | `BlockedUntil` gate in `manager_renew` / `manager_renew_test` path, inventory | no |
| Identifier cooldown | `flow_authz` on failure, cleared on success | **memory only** (`manager.go`) | `coolingDown` before ordering | **yes** — see comment: budget is persisted, cooldown is not |
| `identifier_failures` ledger | `flow_authz` | SQLite | failure fallback (`cert_fallback`) | no |
| ARI window / certID | `manager_renew` (`FetchRenewalInfo`) | `certificates.ari_*` columns | renewal clock, inventory, metrics | no |
| `ari_checked_at` / `ari_retry_after_ns` | `manager_renew` (success **and** failure) | same columns | `ariCheckDue` throttle | no |
| Onboarding change budget | `onboarding` (`budget()`) | onboarding state | freeze decision | no (its own store) |

Unlocked tools (`-dry-run`, `-revoke`) do not migrate and do not spend the
ledger. `-restore` installs a snapshot **as-is**: the buckets inside it stop at
the snapshot's instant (see `state.RestoreCaveatWindow`).

## Invariants

1. **Bare identifier, always.** Wildcard `*.example.com` and apex
   `example.com` share one TXT name and one CA identifier. Every scope key that
   is an identifier must go through `bareIdentifierScope` (and the pause gate
   uses the same bare name). A mismatch books the failure against one bucket and
   asks the gate about the other — measured wrong in round 14.
2. **Never spend before the act.** `NewOrdersPerAccount` is spent in
   `manager_renew` when an order is *placed*; the two cert limits are spent in
   `manager_done` when the CA has *issued* — not when deploy succeeds. A deploy
   failure must not refund them.
3. **`SpentByCA` limits are never decremented locally.** Only a CA refusal
   writes a deadline for `consecutive-authz-failures-per-identifier`. Inventory
   must keep labelling that as a CA-side estimate.
4. **Deadlines only move forward.** `NoteDeadline`/`NoteRetryAfter` must not
   roll a later `BlockedUntil` back to an earlier one. Retry-After from the
   server wins when present; the published Refill is the floor when it does not.
5. **ARI is an advisory window, not a reason.** Renewal also honours
   `renewBefore` as fallback when ARI is absent. `ari_check_due` throttles by
   `ari_checked_at` + `ariretry_after_ns`; skipping the assignment of
   `ARICheckedAt` on failure lets one certificate hammer the CA.
6. **A successful authorization clears the cooldown for that identifier.** The
   CA resets consecutive failures on success; the in-memory cooldown must too,
   or a fixed name is stuck until process restart.
7. **Restarts are not free.** Cooldown is memory-only: N certificates sharing a
   name can spend `authz-failures-per-identifier` once per restart. Do not
   “fix” that by making cooldown persistent without also deciding what a
   restored snapshot should do with it.
8. **Shared limits are not ours.** `certs-per-registered-domain` and
   `certs-per-exact-identifier-set` are global. Local remaining is an upper
   bound; anything that turns it into an allow decision must stay conservative
   (see onboarding budget).

## Checklist for a change in this area

- [ ] If the change touches a scope key: is it still the **bare** identifier?
- [ ] If the change touches a `Spend` call: is it at the right point (order vs
      issuance), and does the test count it only once?
- [ ] If the change touches ARI fields: do success *and* failure paths write
      `ARICheckedAt` / `ARIRetryAfter`?
- [ ] If the change adds a limit: does `Reportable()` include it, does the
      inventory quota panel get a name, and is `SpentByCA` set correctly?
- [ ] If the change persists something new: what does `-restore` of an older
      snapshot do to it?
- [ ] Cross-feature: sealed state (`stateEncryption`), HMAC remote backup, and
      `wecert -restore` must still open / verify / install after the change
      (`internal/state/seam_cross_test.go` is the ledger).

## Related

- `internal/ratelimit/ratelimit.go` — limit definitions and sources
- `internal/acme/manager_renew.go` — ARI fetch, throttle, pause gate
- `internal/acme/flow_order.go` / `flow_authz.go` — authz failure spend and cooldown
- `docs/recovery.md` — what a restore does to the ledger
- `docs/backlog.md` §9 — local quota vs onboarding budget (conservative only)
