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

# Every label a rule's annotations template, e.g. {{ $labels.cert }}.
TEMPLATED = re.compile(r"\$labels\.([a-z_][a-z0-9_]*)")

FOLDED = ("|", ">", "|-", ">-", "|+", ">+")

# Independent of the line scanner: every `alert:` key in the file, however it is laid out.
ALERT_LINE = re.compile(r"^\s*(?:-\s*)?alert:\s*(\S+)", re.M)


def read_rules(text):
    """Return (rules, problems): [(group, alert, expr, rule_text)] and what is wrong.

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
    # Everything that belongs to the current rule, expressions and annotations alike. Kept so the
    # annotation templates can be checked against the labels the metrics actually carry.
    rule_text = []

    def flush():
        if alert is None:
            return
        if expr is None or not expr.strip():
            problems.append(f"alert {alert} (group {group}) has no expr")
            return
        rules.append((group, alert, expr.strip(), "\n".join(rule_text)))

    for raw in text.splitlines():
        if raw.lstrip().startswith("#") or not raw.strip():
            continue
        indent = len(raw) - len(raw.lstrip())
        stripped = raw.strip()

        # A block scalar (`expr: |`) runs until the indentation drops back.
        if block_indent is not None and indent > block_indent:
            expr = (expr or "") + " " + stripped
            rule_text.append(stripped)
            continue
        block_indent = None

        if stripped.startswith("- name:"):
            flush()
            group, alert, expr, rule_text = stripped[len("- name:"):].strip(), None, None, []
        elif stripped.startswith("- alert:"):
            flush()
            alert, expr, rule_text = stripped[len("- alert:"):].strip(), None, []
        elif stripped.startswith("- record:"):
            problems.append(f"recording rule {stripped} in a file that should only alert")
        elif stripped.startswith("-"):
            # Any other list item is a rule shape this reader does not understand -- a flow
            # mapping (`- {alert: A, expr: ...}`), an `expr:` written before the `alert:`, a
            # future key. Skipping it silently is how this checker reported a green tick over
            # zero rules; saying so is the entire point of having it.
            problems.append(f"unrecognised rule shape (the reader cannot check it): {stripped!r}")
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
                rule_text.append(stripped)
        elif alert is not None:
            # labels, annotations, summary, description -- kept for the template check.
            rule_text.append(stripped)

    flush()
    return rules, problems


def declared_labels(metrics_text):
    """Return {series: [labels]} for every metric declared in the metrics file.

    Split on the constructor calls rather than matching whole declarations: the label list sits at
    the end of a block that can be many lines long.
    """
    out = {}
    for chunk in metrics_text.split("promauto.New")[1:]:
        name = re.search(r'Name:\s*"(wecert_[a-z0-9_]+)"', chunk)
        if not name:
            continue
        labels = re.search(r"\[\]string\{([^}]*)\}", chunk)
        out[name.group(1)] = [l.strip().strip('"') for l in (labels.group(1) if labels else "").split(",")
                              if l.strip()]
    return out


def main(argv=None):
    """Check one rules file against one metrics file (defaults: the ones in this repo)."""
    global RULES, METRICS
    argv = sys.argv[1:] if argv is None else argv
    if len(argv) >= 1:
        RULES = Path(argv[0])
    if len(argv) >= 2:
        METRICS = Path(argv[1])

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

    text = RULES.read_text(encoding="utf-8")
    rules, problems = read_rules(text)

    # A checker that reads nothing must not report success. Every one of these shapes used to
    # produce "0 alert rules in 0 groups; every series they reference is exported" and exit 0:
    # a flow-mapping rule, an `expr:` before the `alert:`, an empty `rules:` list. The count
    # below is the independent cross-check -- it reads the file with a regex rather than with the
    # scanner, so a shape the scanner silently drops shows up as a mismatch.
    declared_alerts = ALERT_LINE.findall(text)
    if len(declared_alerts) != len(rules):
        problems.append(
            f"the file declares {len(declared_alerts)} alert(s) but the reader understood "
            f"{len(rules)}; part of the file is being skipped, and a rule nobody checks is a "
            f"rule that cannot fire")
    if not rules:
        problems.append(f"no alert rules were read from {RULES.name}; that is a broken rules "
                        f"file, not a clean one")

    metrics_text = METRICS.read_text(encoding="utf-8")
    declared = set(DECLARED.findall(metrics_text))
    labels_of = declared_labels(metrics_text)
    if not declared:
        print(f"no metric names found in {METRICS.name}; the reader is broken, not the rules",
              file=sys.stderr)
        return 1

    seen = {}
    for group, alert, expr, rule_text in rules:
        if alert in seen:
            problems.append(f"duplicate alert name {alert} (also in group {seen[alert]})")
        seen[alert] = group
        referenced = sorted(set(SERIES.findall(expr)))
        for series in referenced:
            if series not in declared:
                problems.append(
                    f"{alert} (group {group}) references {series}, "
                    f"which {METRICS.name} never exports")

        # An annotation templating a label its metric does not carry renders as an empty string --
        # a page that says "certificate  expires in under 22.5 days". Nothing else catches it: the
        # expression is valid, the label name is a plausible typo, and Prometheus has no schema to
        # check it against.
        #
        # Only checked when every series in the expression is known, so a rule referencing an
        # undefined series is reported once, as that, rather than twice. `label_replace` and
        # friends could add a label that no metric carries; none are used here, and the way to
        # keep this check honest if one ever is, is to add its output label to the rule's own
        # declaration rather than to weaken the check.
        if all(s in labels_of for s in referenced):
            available = {l for s in referenced for l in labels_of[s]}
            for templated in sorted(set(TEMPLATED.findall(str(rule_text)))):
                if templated not in available:
                    problems.append(
                        f"{alert} (group {group}) templates {{{{ $labels.{templated} }}}}, but "
                        f"its expression only reads series with labels "
                        f"{sorted(available) or '(none)'}")

    if problems:
        for p in sorted(set(problems)):
            print(f"  {p}", file=sys.stderr)
        print(f"\n{len(set(problems))} problem(s) in {RULES.relative_to(ROOT)}", file=sys.stderr)
        return 1

    print(f"\u2713 {len(rules)} alert rules in {len({g for g, _, _, _ in rules})} groups; "
          f"every series they reference is exported")
    return 0


if __name__ == "__main__":
    sys.exit(main())
