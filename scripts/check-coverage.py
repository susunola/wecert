#!/usr/bin/env python3
"""Fail when total statement coverage drops below the floor recorded in this file.

`make cover` printed `go tool cover -func | tail -1` and nothing read it: no step
in `.github/workflows/ci.yml` and no target in `make check` compared the number to
anything, so the total could fall from 77% to 40% with every gate still green.
`docs/test-plan.md` recorded that as P0-3, "CI has no coverage floor". This is the
floor.

The number is computed from the profile itself, so this check needs no Go
toolchain and can be tested against synthetic profiles (see
`scripts/test-check-coverage.py`). `go tool cover -func` prints 77.7% for the
profile below because it only counts blocks that fall inside a function --
file-scope initialisers drop out of numerator *and* denominator. Both figures are
honest; the profile is the definition of statement coverage, and the 0.1-point
difference is far smaller than the headroom.

Exit codes: 0 at or above the floor, 1 below it, 2 the check itself could not run
(no profile, unreadable profile, or nothing in it to measure).

Usage:
    make check-coverage                             # profile + this check
    python3 scripts/check-coverage.py               # check the existing coverage.out
    python3 scripts/check-coverage.py --floor 90    # prove the gate can fail
"""

from __future__ import annotations

import argparse
import math
import pathlib
import sys

ROOT = pathlib.Path(__file__).resolve().parent.parent

# The floor, and how it was chosen. Measured 2026-09-22 on the tree that added this check:
# 77.62% (5643 of 7270 statements, from the profile `go test -coverprofile` writes; `make cover`
# printed 77.7% for the same profile, see the module docstring). The floor is 1.62 points below
# that -- about 118 statements of headroom, so a refactor may move covered code onto a new
# uncovered path without having to pair the move with new tests, while a real regression (a
# package losing its tests, or a branch added around the whole issuance path) still trips it.
# Raise it when the total rises. Lower it only in a commit that says why.
FLOOR = 76.0


def read_profile(path: pathlib.Path) -> tuple[int, int]:
    """Return (covered, total) statement counts for a Go cover profile.

    Raises ValueError for anything that is not a profile: a file that happens to
    be at this path must fail the check, not be read as "nothing regressed".
    """
    covered = total = 0
    for lineno, raw in enumerate(path.read_text(encoding="utf-8").splitlines(), 1):
        line = raw.strip()
        if not line or line.startswith("mode:"):
            continue
        # A block is `name.go:startLine.startCol,endLine.endCol numStmt count`, and the file name
        # itself may contain spaces (a package under a directory with one), so split from the
        # right. The location is what distinguishes a profile from any other text file.
        fields = line.rsplit(" ", 2)
        if len(fields) != 3 or ":" not in fields[0]:
            raise ValueError(f"line {lineno} is not a coverage block: {line[:96]!r}")
        try:
            stmts, count = int(fields[1]), int(fields[2])
        except ValueError:
            raise ValueError(f"line {lineno} has a non-numeric statement count: {line[:96]!r}")
        if stmts < 0 or count < 0:
            raise ValueError(f"line {lineno} has a negative statement count: {line[:96]!r}")
        total += stmts
        if count > 0:
            covered += stmts
    return covered, total


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--profile", type=pathlib.Path, default=ROOT / "coverage.out",
                    help="Go cover profile to read (default: coverage.out in the repository root)")
    ap.add_argument("--floor", type=float, default=FLOOR,
                    help=f"fail below this percentage (default: the {FLOOR}% recorded in this file)")
    args = ap.parse_args()

    if not args.profile.exists():
        print(f"no coverage profile at {args.profile}; run `make cover` or `make check-coverage`",
              file=sys.stderr)
        return 2
    try:
        covered, total = read_profile(args.profile)
    except (OSError, ValueError) as exc:
        print(f"cannot read {args.profile}: {exc}", file=sys.stderr)
        return 2

    # "0 of 0 statements" must not compare as 100%: that is the one false pass this check must
    # never have. An empty profile means the tests never ran or every package failed to build.
    if total == 0:
        print(f"{args.profile} contains no coverage blocks; nothing was measured", file=sys.stderr)
        return 2

    percent = 100.0 * covered / total
    print(f"coverage: {percent:.2f}% ({covered}/{total} statements) -- floor {args.floor:.2f}%")

    if percent < args.floor:
        needed = math.ceil(round(args.floor * total / 100.0, 6)) - covered
        print(f"coverage regressed: {percent:.2f}% is {args.floor - percent:.2f} points below the "
              f"floor of {args.floor:.2f}%")
        print(f"{needed} more covered statements (of {total}) would clear it -- add tests, or lower "
              f"the floor in scripts/check-coverage.py in a commit that says why")
        return 1

    print(f"✓ {args.floor:.2f}% floor held with {percent - args.floor:.2f} points to spare")
    return 0


if __name__ == "__main__":
    sys.exit(main())
