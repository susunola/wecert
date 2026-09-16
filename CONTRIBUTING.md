# Contributing

Two things make a change easy to accept here: it is verified against the failure it claims to fix,
and it does not make a comment or a document untrue.

## Before you start

For anything larger than a fix, **open an issue first**. This program's decisions are shaped by the
rate limits it exists to stay inside (see `README.reference.md` → *Why this exists*), and a
reasonable-looking change can quietly spend quota — for example anything that re-issues on a
condition that can retry. A short conversation before writing code is cheaper than discovering that
afterwards.

If your change is about **availability, high availability, or a challenge type other than DNS-01**,
read `docs/availability.md` and `docs/challenge-types.md` first: both record what this deployment
shape cannot do, and why the obvious fix does not work. Those are answers rather than gaps, and a
PR that contradicts them needs to say why they are wrong.

## What a change is expected to include

**A test that fails without it.** Not "a test exists" — check it. A test that passes both before and
after pins nothing, and this repository has shipped several of those. For a bug fix, the request is
the reproduction; for a behaviour change, the test that pins the new behaviour.

**Honest comments.** A comment claiming behaviour the code does not have has been the source of more
than one real defect here — most memorably a field documented as "layer 7 only" that is actually the
instance generation, which silently hid an entire class of load balancer. If you cannot make the
code match the comment, change the comment.

**No meaningless values in anything an operator reads.** A metric, an alert or a `/hook/status`
field must not be able to report a value that is not true of the state it describes. The expiry
series is absent until a certificate is issued rather than exporting `0`, because `0` made the
documented primary alert fire on every new certificate. If you add a series, say what it means when
the answer is "unknown", and prefer absence to a wrong number.

**Operational changes need their document.** A new config key, a unit-file change, a backup or
upgrade step: update the relevant file under `docs/` in the same PR.

## Running things

```bash
make build          # bin/wecert and the tools
make check          # gofmt, vet, English, race tests, the e2e self-test, the alert rules
make test-pebble    # a real ACME lifecycle against a local CA (needs the pebble binary)
make fuzz           # property and fuzz targets, bounded per target (FUZZTIME=30s default)
```

`make check` is a **superset** of what CI runs. CI currently does `gofmt`, `check-english.py`,
`go vet`, `govulncheck`, `go test -race`, `make build` and `make release` — it does **not** run
`check-scripts`, `check-alerts`, `make fuzz` or `make test-pebble`, so those four are on you before
you push. Adding them to `.github/workflows/ci.yml` is open work, not a decision.

`make fuzz` arrives with the fuzz-target change (PR #55). On a base that predates it, run a target
directly: `go test ./internal/ratelimit/ -run XXX -fuzz FuzzParseRetryAfter -fuzztime 30s`.

`make test-pebble` is the only test that exercises a real order, finalize and chain download. If your
change touches issuance, deployment or cleanup, run it.

## Style

- **English** in code, comments, log lines, metrics and docs. `make check` enforces it outside the
  paired `README.md` / `README.zh-CN.md` documents and the generated Chinese diagram page.
- **Explain the decision, not the mechanics.** The comments worth writing are the ones that record
  why the obvious alternative is wrong — several in this codebase exist because the alternative
  caused a production incident. Do not narrate what the next line does.
- **Errors say what to do.** An error that names the problem but not the response is half a message;
  `docs/recovery.md` and the corrupt-database path are the model.

## Commit messages

The subject says what changed; the body says **why**, and what the tradeoff was. If you removed a
guard, say what made it unnecessary — otherwise the next reader cannot tell it from a mistake.

## Reporting a vulnerability

Not here — see [SECURITY.md](SECURITY.md).
