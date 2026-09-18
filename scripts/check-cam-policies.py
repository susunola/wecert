#!/usr/bin/env python3
"""Fail when a cloud API the code calls is missing from the shipped CAM policies.

Why this exists: the shipped policies are the only description of what wecert needs, and
nothing else connects them to the code. The runtime policy was missing
`ssl:DescribeDeleteCertificatesTaskResult` for several rounds -- every `IsCheckResource=true`
delete is asynchronous and that call is what says whether the delete happened, so on a
deployment that used the shipped policy the reclaim loop could never confirm a delete and
retried the same certificate forever. A hand-maintained list cannot stay in step with the
SDK calls; this check derives the list from the source.

It reads the request types the non-test code constructs (`ssl.NewDeleteCertificateRequest`
and the `ssl.DeleteCertificate` alias form both count) and requires each action in every
policy file, with an explicit, justified exception list for calls that are deliberately
operator-only (they run in a separate binary with its own credentials).

Exit codes: 0 clean, 1 a policy is missing an action, 2 the check itself could not run.
"""

from __future__ import annotations

import json
import pathlib
import re
import sys

ROOT = pathlib.Path(__file__).resolve().parent.parent
POLICIES = [
    "deploy/cam-policy-runtime.json",
    "deploy/cam-policy-test.json",
    "deploy/cam-policy-stage-ab.json",
]

# Services whose permissions this check tracks. Kept explicit rather than derived from the
# import list: a new SDK import should make someone decide which policy needs the action.
SERVICES = ("ssl", "dnspod", "clb", "tat")

# Actions the code calls that must NOT be required of every policy, with the reason. Anything
# added here needs a reason that says which binary holds the permission instead.
EXEMPT: dict[str, str] = {
    # clbverify is an operator-run tool for the one-time manual bind; it is not part of the
    # daemon's runtime path and can be run with the operator's own credentials.
    "clb:DescribeListeners": "cmd/clbverify (operator-run) -- verified separately in README.reference.md",
    # tatrun drives Stage C on a CVM; the runtime daemon never calls TAT.
    "tat:RunCommand": "cmd/tatrun (Stage C tooling), not the daemon",
    "tat:DescribeInvocationTasks": "cmd/tatrun (Stage C tooling), not the daemon",
}

# Every API call in this repository constructs its request type first (`ssl.NewDeleteCertificate
# Request`), which is the one signal that maps to a CAM action without guessing which identifiers
# are types and which are methods: an earlier version of this script also matched the bare
# `ssl.Something` form and duly demanded permissions for `ssl:NewClient` and
# `ssl:UploadCertificateResponse`. The alias form (`ssl.DeleteCertificate` as a type name) always
# accompanies a constructor, so nothing is lost.
RE_REQUEST = re.compile(r"\b(" + "|".join(SERVICES) + r")\.New([A-Za-z0-9]+)Request\b")


def source_actions() -> dict[str, set[str]]:
    """action -> files that build the request, from non-test Go sources."""
    found: dict[str, set[str]] = {}
    for path in sorted(ROOT.rglob("*.go")):
        rel = path.relative_to(ROOT).as_posix()
        if rel.startswith("testenv/") or rel.endswith("_test.go"):
            continue
        text = path.read_text(encoding="utf-8", errors="replace")
        for m in RE_REQUEST.finditer(text):
            found.setdefault(f"{m.group(1)}:{m.group(2)}", set()).add(rel)
    return found


def granted(policy: dict) -> set[str]:
    out: set[str] = set()
    for st in policy.get("statement", []):
        action = st.get("action") or []
        if isinstance(action, str):
            action = [action]
        for a in action:
            if a == "*":
                out.add("*")
                continue
            if ":" in a:
                out.add(a)
    return out


def main() -> int:
    try:
        actions = source_actions()
    except OSError as exc:
        print(f"cannot scan the source tree: {exc}", file=sys.stderr)
        return 2

    required = {a: files for a, files in actions.items() if a not in EXEMPT}
    failures: list[str] = []

    for name in POLICIES:
        path = ROOT / name
        if not path.exists():
            failures.append(f"{name}: missing")
            continue
        try:
            policy = json.loads(path.read_text(encoding="utf-8"))
        except json.JSONDecodeError as exc:
            failures.append(f"{name}: not valid JSON: {exc}")
            continue
        have = granted(policy)
        if "*" in have:
            continue
        missing = sorted(a for a in required if a not in have)
        for action in missing:
            where = ", ".join(sorted(required[action])[:3])
            failures.append(f"{name}: missing {action} (called by {where})")

    if failures:
        print("CAM policy drift: the shipped policies do not grant every API the code calls.")
        for f in failures:
            print(f"  - {f}")
        print("\nAdd the action to the policy, or add it to EXEMPT in this script with the reason.")
        return 1

    print(f"✓ {len(required)} cloud actions called by the code are granted by all "
          f"{len(POLICIES)} shipped CAM policies ({len(EXEMPT)} documented exemptions)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
