# Backlog

What is worth doing next, and why. Every item here survived being questioned: two earlier candidates
turned out to be answers rather than tasks — TLS-ALPN-01 is not implementable in this deployment
shape, and the obvious HA fix does not provide HA. Both are written up in
[challenge-types](challenge-types.md) and [availability](availability.md).

They are ordered by real exposure over effort.

1. **Make the checks into gates**

   The cheapest item on this list and the one that protects all the others. CI runs `gofmt`, English, `vet`, `govulncheck`, `test -race`, `make build` and `make release` — but not `check-alerts`, `check-scripts`, `make fuzz` or `make test-pebble`, and `main` has **no branch protection** (checked against the API: "Branch not protected"), so nothing requires the run to pass before a merge. The consequence is concrete: the 17 alert rules and the fuzz corpus added most recently are verified only by whoever remembers to run `make check` locally, and `.github/CODEOWNERS` reads as if reviews were required when they are not. A few lines in `ci.yml` plus two repository settings.

2. **Switch on GitHub private vulnerability reporting**

   `SECURITY.md` documents a fallback — an empty public issue asking for a private channel — because the real channel is **off** in this repository (the API reports `"enabled": false`). One setting, and it removes an awkward step from the only path a reporter has.

3. **Finish off-host snapshots and one-command restore (option A in docs/availability.md)**

   The real availability exposure. Process death is already covered by `Restart=on-failure` plus resumable orders, and host loss is bounded by `state.db` living on local disk — so a second wecert process on the same host shares its fate and duplicates what systemd already does. The snapshot machinery (`VACUUM INTO`, retention, the documented restore procedure) already exists; what is missing is getting the file off the host automatically and making restore one command instead of a sequence. Needs a decision that is not mine to make: where the snapshots go, and what RTO is being bought.

4. **Guard against restoring a stale snapshot**

   A real, unhandled operational risk. An operator restores a snapshot from several days ago, so `NextAttemptAt`, the ARI window and the rate-limit buckets all move backwards; wecert then believes it has spent nothing and tries to issue — while the exact-set limit is a 7-day window with no override. Startup should notice that the store is far older than the wall clock and refuse, or degrade to read-only.

5. **Sign the release artifacts**

   `make repro-check` proves the binaries can be rebuilt bit-for-bit from the commit, which makes "this artifact came from that source" *checkable* — but only by someone who does the rebuilding. Nothing signs the release itself, so a download is still trusted on the strength of the transport. `gh attestation` or cosign turns reproducibility into verifiable provenance.

6. **Settle the config model for challenge types**

   If HTTP-01 is ever added, where it is configured has to be decided first. Challenge type is a per-certificate concept, but it would land in the `dns` section (or at the top level), while `state.Authorization`'s `TxtName`/`TxtValue`/`Presented` are TXT-shaped. The boundary is written down in [challenge-types](challenge-types.md); the config structure was deliberately left alone, because deciding the model is cheaper before the code than after.

7. **Refuse to start with state.db on a network filesystem**

   [availability](availability.md) now says that `flock` over network filesystems is unreliable and SQLite's NFS locking is a known corruption source, but no code checks it. An operator can configure it and be accepted, then find out as a corrupt state database. Detecting it at startup is far cheaper than diagnosing it afterwards.

8. **Test downgrade: an older binary opening the new schema**

   The revocation work added two tables (`revoke_requests`, `rate_buckets`). Migrations are additive, so an older binary should still work — explicit column lists, new tables simply ignored — but that has never been tested. For a system whose disaster case is losing the state database, which versions can be rolled back to is part of reliability rather than a nicety.

9. **Feed the local quota accounting into the change-budget decision**

   `onboarding.budget` counts changed *rounds*, while the question an operator actually asks — how much issuance quota is left — is a token count. Both models now exist and the budget one is coarser. The token-bucket accounting added for `wecert_ratelimit_remaining_tokens` is the more accurate input and should drive the freeze decision.

10. **Finish the go.sum story for `-tags lego_dns`**

   Any of lego's ~198 providers can now be selected by name, but the hundreds of third-party SDKs they pull in were deliberately kept out of the default `go.sum`. The cost is that a first tagged build needs `go mod tidy`. What is missing is a controlled check: build at least one provider, prove it can issue, and record the dependency and binary-size cost so the tradeoff is documented rather than assumed.

## The rest

A longer list is maintained outside this repository as an interactive capability panorama: 50 entries
in total, 23 of them recording what closed them. The ten above are the ones worth doing next. The
rest are mostly findings from code review whose value is in the detail, and a mechanical translation
would lose it — ask for the panorama, or read the review reports, if you want the full set.

Closed items are deliberately kept rather than deleted, in spirit if not in this file: "this was
tried and this is what fixed it" is not recoverable from a diff that no longer exists, and several
entries existed precisely because an earlier claim to have closed something was wrong.
