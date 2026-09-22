#!/usr/bin/env python3
"""Self-test for check-coverage.py.

A floor that cannot fail is worse than no floor: it tells the next person coverage
is watched when nothing is watching it. So every shape below is run through the
real checker (as a subprocess, on synthetic profiles), and the two that matter
most are:

  - a profile below the floor must exit 1, not 0;
  - the same profile must pass when `--floor` is lowered and fail when it is
    raised, which is what proves the verdict comes from the number rather than
    from the checker having no way to say no.

The percentage must also be statement-weighted, not block-weighted: a profile
where most *blocks* are covered but most *statements* are not is a regression, and
a block counter would call it green.

Run directly, or via `make check-coverage` (which runs it before the real
profile).

Usage: test-check-coverage.py [--verbose]
"""

from __future__ import annotations

import subprocess
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
CHECK = ROOT / "scripts" / "check-coverage.py"


def profile(blocks: list[tuple[int, int]]) -> str:
    """Build a cover profile from (numStmt, count) pairs, in the real format."""
    lines = ["mode: set"]
    for i, (stmts, count) in enumerate(blocks, 1):
        lines.append(f"github.com/susunola/wecert/internal/pkg{i}/file.go:{i}.1,{i}.2 {stmts} {count}")
    return "\n".join(lines) + "\n"


def run(body: str, *args: str) -> tuple[int, str]:
    """Write `body` to a temporary profile and run the checker against it."""
    with tempfile.NamedTemporaryFile("w", suffix=".out", delete=False) as fh:
        fh.write(body)
        path = fh.name
    try:
        proc = subprocess.run([sys.executable, str(CHECK), "--profile", path, *args],
                              capture_output=True, text=True)
        return proc.returncode, (proc.stdout + proc.stderr).strip()
    finally:
        Path(path).unlink()


def main() -> int:
    verbose = "--verbose" in sys.argv
    failures: list[str] = []

    def expect(name: str, code: int, out: str, want_code: int, *needles: str) -> None:
        if code != want_code:
            failures.append(f"{name}: exit {code}, wanted {want_code} -- {out}")
        elif any(n not in out for n in needles):
            failures.append(f"{name}: exit {code} but the output does not say {needles!r} -- {out}")
        elif verbose:
            print(f"  ok  {name}: {out.splitlines()[0]}")

    # Above the floor passes, and prints the number it measured.
    expect("90% passes", *run(profile([(900, 1), (100, 0)])), 0, "90.00%")

    # Exactly at the floor passes (`<`, not `<=`): a floor is a minimum, not a margin.
    expect("exactly at the floor passes", *run(profile([(76, 1), (24, 0)])), 0, "76.00%")

    # Below the floor fails, names the shortfall, and says what would clear it.
    expect("50% fails", *run(profile([(500, 1), (500, 0)])), 1, "regressed", "50.00%", "76.00%")

    # The verdict is the number, not the code path: unchanged profile, moved floor.
    body = profile([(90, 1), (10, 0)])  # 90.00%
    expect("90% passes the default floor", *run(body), 0, "90.00%")
    expect("90% fails a raised floor", *run(body, "--floor", "95"), 1, "regressed", "95.00%")

    # Statement-weighted, not block-weighted: 10 covered 1-statement blocks and one uncovered
    # 90-statement block is 10% of statements even though 10 of 11 blocks are covered.
    expect("block-heavy profile is not a false pass",
           *run(profile([(1, 1)] * 10 + [(90, 0)])), 1, "10.00%", "regressed")

    # "Nothing to measure" is exit 2, never a silent pass.
    expect("an empty profile cannot pass", *run("mode: set\n"), 2, "no coverage blocks")
    expect("a non-profile cannot pass", *run("this is a log file, not a profile\n"), 2, "not a coverage block")
    expect("a truncated block cannot pass", *run("mode: set\nfoo.go:1.1,1.2 3\n"), 2, "not a coverage block")

    # A missing profile is an error, not a pass.
    missing = ROOT / "coverage.out.does-not-exist"
    proc = subprocess.run([sys.executable, str(CHECK), "--profile", str(missing)],
                          capture_output=True, text=True)
    expect("a missing profile cannot pass", proc.returncode,
           (proc.stdout + proc.stderr).strip(), 2, "no coverage profile")

    if failures:
        print("check-coverage self-test FAILED")
        for f in failures:
            print("  -", f)
        return 1
    print("✓ check-coverage.py fails a regression, passes a healthy profile, follows --floor, and "
          "refuses an empty or malformed profile instead of passing it")
    return 0


if __name__ == "__main__":
    sys.exit(main())
