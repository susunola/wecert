#!/usr/bin/env python3
"""Fail if the shipped Prometheus rules could not do their job.

`deploy/prometheus/wecert-alerts.yml` is the only thing watching for several
failures that are silent by construction -- a revocation the CA never accepted,
a pass that has not finished in two hours, a certificate serving that is not the
one deployed. None of them produce an error log, so a rule that is subtly wrong
is worse than no rule at all: the operator believes they are covered.

Three ways that belief can be false without anything failing:

  1. The YAML does not load, or a rule has no `alert` name or no `expr`.
  2. Two rules share a name, so one silently replaces the other.
  3. An expression references a `wecert_*` series this program never exports.
     This is the one that actually happened: `WecertHasNotReconciledRecently`
     was written against `wecert_reconcile_total_created_timestamp`, which is
     not a series -- the exposition is the classic text format, which carries no
     `_created` timestamps at all. The rule was syntactically perfect and could
     never fire.

Check 3 reads the metric names out of `internal/metrics/metrics.go`, which is
where every `wecert_*` series is declared, so a rule left behind by a renamed or
deleted metric fails here instead of in production.

PromQL **syntax** is not checked here. Doing it properly means depending on
`prometheus/prometheus`, which costs far more than this check is worth; syntax
is verified with the real parser at review time, and the three checks above are
the mistakes that actually happen.

Run directly, or via `make check`.
"""

import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
RULES = ROOT / "deploy" / "prometheus" / "wecert-alerts.yml"
METRICS = ROOT / "internal" / "metrics" / "metrics.go"

# Any wecert_* identifier inside an expression. Alert names and label values in
# this file never start with wecert_, so this only picks up series references.
SERIES = re.compile(r"\bwecert_[a-z0-9_]+\b")

# Declared series names, which is how every wecert_* series is registered.
DECLARED = re.compile(r'Name:\s*"(wecert_[a-z0-9_]+)"')

FOLDED = ("|", ">", "|-", ">-", "|+", ">+")


def read_rules(path):
    """Return (rules, problems): [(group, alert, expr)] and what is wrong.

    Read with a narrow line scanner rather than a YAML library, so the check
    runs wherever the rest of the scripts do. The file has one hand-written
    shape, and anything the scanner cannot follow is reported as a problem
    instead of being skipped -- a rule this cannot read is a rule nobody is
    checking.
    """
    rules = []
    problems = []

    group = None
    alert = None
    expr = None
    block_indent = None

    def flush():
        if alert is None:
            return
        if expr is None or not expr.strip():
            problems.append(f"alert {alert} (group {group}) has no expr")
            return
        rules.append((group, alert, expr.strip()))

    for raw in path.read_text(encoding="utf-8").splitlines():
        if raw.lstrip().startswith("#") or not raw.strip():
            continue
        indent = len(raw) - len(raw.lstrip())
        stripped = raw.strip()

        # A block scalar (`expr: |`) runs until the indentation drops back.
        if block_indent is not None and indent > block_indent:
            expr = (expr or "") + " " + stripped
            continue
        block_indent = None

        if stripped.startswith("- name:"):
            flush()
            group, alert, expr = stripped[len("- name:"):].strip(), None, None
        elif stripped.startswith("- alert:"):
            flush()
            alert, expr = stripped[len("- alert:"):].strip(), None
        elif stripped.startswith("- record:"):
            problems.append(f"recording rule {stripped} in a file that should only alert")
        elif stripped.startswith("expr:"):
            value = stripped[len("expr:"):].strip()
            if alert is None:
                problems.append(f"an expr with no alert name above it: {value}")
            elif value in FOLDED:
                block_indent = indent
                expr = ""
            else:
                # A plain scalar is one line. Continuing it into the following keys was a bug:
                # `severity:` and `summary:` are indented deeper than `expr:`, so the scanner read
                # them as part of the expression -- and then reported metric names out of the prose.
                expr = value

    flush()
    return rules, problems


def main():
    if not RULES.exists():
        print(f"missing {RULES.relative_to(ROOT)}", file=sys.stderr)
        return 1

    try:
        import yaml
    except ImportError:
        yaml = None
    if yaml is not None:
        try:
            yaml.safe_load(RULES.read_text(encoding="utf-8"))
        except Exception as exc:  # any parse failure is the point
            print(f"{RULES.relative_to(ROOT)} does not load as YAML: {exc}", file=sys.stderr)
            return 1

    rules, problems = read_rules(RULES)
    declared = set(DECLARED.findall(METRICS.read_text(encoding="utf-8")))
    if not declared:
        print(f"no metric names found in {METRICS.name}; the reader is broken, not the rules",
              file=sys.stderr)
        return 1

    seen = {}
    for group, alert, expr in rules:
        if alert in seen:
            problems.append(f"duplicate alert name {alert} (also in group {seen[alert]})")
        seen[alert] = group
        for series in sorted(set(SERIES.findall(expr))):
            if series not in declared:
                problems.append(
                    f"{alert} (group {group}) references {series}, "
                    f"which {METRICS.name} never exports")

    if problems:
        for p in sorted(set(problems)):
            print(f"  {p}", file=sys.stderr)
        print(f"\n{len(set(problems))} problem(s) in {RULES.relative_to(ROOT)}", file=sys.stderr)
        return 1

    print(f"\u2713 {len(rules)} alert rules in {len({g for g, _, _ in rules})} groups; "
          f"every series they reference is exported")
    return 0


if __name__ == "__main__":
    sys.exit(main())
