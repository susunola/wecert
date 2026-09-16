#!/usr/bin/env python3
"""Test `check-alerts.py`, because a checker that lies is worse than no checker.

The failure this file exists to prevent is a **false pass**: `check-alerts.py` printing a green
tick over a rules file it did not actually understand. That is not hypothetical. The first
version of it exited 0 with "0 alert rules in 0 groups; every series they reference is exported"
for all of these, each of which is a broken file:

  - a rule written as a flow mapping: `- {alert: A, expr: ...}`
  - an `expr:` written above the `alert:` it belongs to
  - an empty `rules:` list, or no `groups:` at all

Every one of those shapes was silently skipped by the line scanner, and "I read nothing" was
reported as success. The two guards added for it are a hard failure when no rules were read, and
an independent regex count of `alert:` keys cross-checked against the number of rules the scanner
understood. Both are exercised below, along with the cases that already worked.

Run directly, or via `make check-alerts` (which runs it before the real file).

Usage: test-check-alerts.py [--verbose]
"""

import subprocess
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
CHECK = ROOT / "scripts" / "check-alerts.py"
METRICS = ROOT / "internal" / "metrics" / "metrics.go"

# A rule that must be accepted, so the tests below cannot all pass by rejecting everything.
SOUND = """\
groups:
  - name: test.group
    rules:
      - alert: TestAlert
        expr: wecert_certificate_deployed == 0
        for: 5m
        labels:
          severity: warning
        annotations:
          summary: "a real one"
"""

# name -> (rules text, what the checker must complain about)
REJECTED = {
    "flow-mapping rule": ("""\
groups:
  - name: g
    rules:
      - {alert: A, expr: wecert_certificate_deployed == 0}
""", "unrecognised rule shape"),

    "expr above its alert": ("""\
groups:
  - name: g
    rules:
      - expr: wecert_certificate_deployed == 0
        alert: A
""", "unrecognised rule shape"),

    "unknown series": ("""\
groups:
  - name: g
    rules:
      - alert: A
        expr: wecert_no_such_metric > 0
""", "never exports"),

    "unknown series in a folded block": ("""\
groups:
  - name: g
    rules:
      - alert: A
        expr: |
          (time() - wecert_no_such_metric) > 7200
          and on() wecert_certificate_deployed == 1
""", "never exports"),

    "unknown series in a literal block": ("""\
groups:
  - name: g
    rules:
      - alert: A
        expr: >
          wecert_no_such_metric > 0
""", "never exports"),

    "duplicate alert names": ("""\
groups:
  - name: g
    rules:
      - alert: A
        expr: wecert_certificate_deployed == 0
      - alert: A
        expr: wecert_certificate_deployed == 1
""", "duplicate alert name"),

    "a rule with no expr": ("""\
groups:
  - name: g
    rules:
      - alert: A
        for: 5m
""", "has no expr"),

    "a recording rule": ("""\
groups:
  - name: g
    rules:
      - record: wecert:something
        expr: wecert_certificate_deployed == 0
""", "should only alert"),

    "an annotation templating a label the metric does not carry": ("""\
groups:
  - name: g
    rules:
      - alert: A
        expr: wecert_certificate_deployed == 0
        annotations:
          summary: "certificate {{ $labels.certt }} is not deployed"
""", "templates"),

    "empty rules list": ("""\
groups:
  - name: g
    rules: []
""", "no alert rules were read"),

    "no groups at all": ("""\
groups: []
""", "no alert rules were read"),
}

# A metric named in a comment is prose, not a reference. A checker that treats it as one would
# reject the real rules file the first time somebody explains a rule in a comment -- and a checker
# that cries wolf is one people learn to skip.
ACCEPTED = {
    "a series named only in a comment": """\
groups:
  - name: test.group
    rules:
      # wecert_no_such_metric is discussed here but never exported
      - alert: TestAlert
        expr: wecert_certificate_deployed == 0
""",
}

# Metrics the checker must be able to find. If the reader in check-alerts.py ever stops matching
# metrics.go, every rule would be reported as referencing an unknown series -- including the
# sound one -- and the positive control below is what catches it.
REQUIRED_DECLARATIONS = [
    "wecert_certificate_deployed",
    "wecert_revocation_pending",
    "wecert_last_reconcile_timestamp_seconds",
]


def run_check(rules_text):
    """Run the checker against synthetic rules and return (exit code, output)."""
    with tempfile.NamedTemporaryFile("w", suffix=".yml", delete=False) as fh:
        fh.write(rules_text)
        path = fh.name
    try:
        proc = subprocess.run([sys.executable, str(CHECK), path, str(METRICS)],
                              capture_output=True, text=True)
        return proc.returncode, (proc.stdout + proc.stderr).strip()
    finally:
        Path(path).unlink()


def main():
    verbose = "--verbose" in sys.argv
    failures = []

    metrics_text = METRICS.read_text(encoding="utf-8")
    for name in REQUIRED_DECLARATIONS:
        if name not in metrics_text:
            failures.append(f"metrics.go no longer declares {name}, which this test needs")

    code, out = run_check(SOUND)
    if code != 0:
        failures.append(f"a sound rule was rejected (exit {code}): {out}")
    elif verbose:
        print(f"  accepted  sound rule: {out}")

    for name, text in ACCEPTED.items():
        code, out = run_check(text)
        if code != 0:
            failures.append(f"{name}: rejected, but it is a valid file (exit {code}): {out}")
        elif verbose:
            print(f"  accepted  {name}")

    for name, (text, expected) in REJECTED.items():
        code, out = run_check(text)
        if code == 0:
            failures.append(f"{name}: ACCEPTED (false pass) -- {out.splitlines()[-1] if out else ''}")
        elif expected not in out:
            failures.append(f"{name}: rejected, but not for the expected reason "
                            f"(wanted {expected!r}): {out}")
        elif verbose:
            print(f"  rejected  {name}")

    if failures:
        for f in failures:
            print(f"  {f}", file=sys.stderr)
        print(f"\n{len(failures)} failure(s) in check-alerts.py", file=sys.stderr)
        return 1

    print(f"\u2713 check-alerts.py rejects all {len(REJECTED)} broken shapes and accepts the "
          f"{len(ACCEPTED) + 1} valid ones ({len(REQUIRED_DECLARATIONS)} metric declarations found)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
