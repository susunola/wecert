# Backlog

What is worth doing next, and why. Every item here survived being questioned: two earlier candidates
turned out to be answers rather than tasks — TLS-ALPN-01 is not implementable in this deployment
shape, and the obvious HA fix does not provide HA. Both are written up in
[challenge-types](challenge-types.md) and [availability](availability.md).

They are ordered by real exposure over effort.

1. **Finish making the checks into gates**

   Mostly done, and what is left is not code. CI now runs `check-alerts` and `check-scripts` next to `gofmt`, English, `vet`, `govulncheck`, `test -race`, `test-tags`, `make build` and `make release`. Still missing: `make fuzz` (bounded wall-clock, so it belongs in a scheduled job) and `make test-pebble` (needs the pebble binary installed), and **`main` still has no branch protection** (checked against the API: "Branch not protected"), so nothing requires the run to pass before a merge. The repository settings are the part that is not mine to change: require the `test` job, and either fill in `.github/CODEOWNERS` or drop it, because as written it reads as if reviews were required when they are not.

2. **Switch on GitHub private vulnerability reporting**

   `SECURITY.md` documents a fallback — an empty public issue asking for a private channel — because the real channel is **off** in this repository (the API reports `"enabled": false`). One setting, and it removes an awkward step from the only path a reporter has.

3. **Finish off-host snapshots (option A in docs/availability.md)**

   The real availability exposure. Process death is already covered by `Restart=on-failure` plus resumable orders, and host loss is bounded by `state.db` living on local disk — so a second wecert process on the same host shares its fate and duplicates what systemd already does. The snapshot machinery (`VACUUM INTO`, retention) already exists, and **restore is now one command**: `wecert -restore latest` keeps the database it replaced, moves the `-wal`/`-shm` with it, verifies the snapshot before touching anything, and records the rate-limit caveat for the next start. What is still missing is getting the file off the host automatically. Needs a decision that is not mine to make: where the snapshots go, and what RTO is being bought.

4. **Notice a state database that was restored without `wecert -restore`**

   Half done, and the remaining half is the awkward one. `wecert -restore` writes `state.db.restored`, and the next start warns for seven days that the rate-limit ledger stops at the snapshot (`state.RestoreCaveatWindow`); what is still invisible is the hand path — `cp snapshot state.db`, which is what docs/recovery.md documented for years. Nothing inside the file records that it was swapped in, so `NextAttemptAt`, the ARI window and the rate-limit buckets can all move backwards in silence.

   The tempting signal is "the file's mtime is much newer than the newest row in it", and it is a false-positive generator: SQLite checkpoints the WAL at open and at close, so a daemon that wrote once and then idled for a week has exactly that signature after an ordinary restart. Ruling that out needs something the file does not carry today — a heartbeat row, or a start/stop ledger — and a warning that also fires on legitimate restarts teaches the reader to ignore the one that matters. Worth doing only once that design is settled; until then the answer is "restore through the command, which records it".

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
