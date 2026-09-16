## What this changes, and why

<!-- The "why" is the part that is not in the diff. If a comment or doc claims something, and this
     change makes it true or false, say which. -->

## How it was verified

<!-- Not "tests pass" — what did you actually run, and what would have failed before?
     For a bug fix: the reproduction. For a behaviour change: the test that pins the new behaviour,
     and the command that shows it failing on the old code. -->

- [ ] `go test -race ./...`
- [ ] `make check` (fmt, vet, english, race, scripts)
- [ ] if this touches issuance, deployment or cleanup: `make test-pebble`
- [ ] if this touches the state schema: verified an existing database still opens, and said below
      whether it can still be opened by the previous version

## Checklist

- [ ] Every new guarantee has a test, and I have checked that the test **fails** without the change.
      (A test that passes before and after pins nothing — this has happened in this repository
      more than once.)
- [ ] No comment claims behaviour the code does not have. If I could not make the code match the
      comment, I changed the comment and said so.
- [ ] If this adds a metric, alert or report field: it cannot emit a value that is meaningless for
      the state it describes.
- [ ] If this is an operational change (config key, unit file, backup, upgrade): the relevant doc
      under `docs/` is updated.

## Anything deliberately not done

<!-- Scope you decided against, and why. This is the most useful section for a reviewer, and the
     easiest to leave out. -->
