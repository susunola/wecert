#!/usr/bin/env python3
"""Self-test for check-cam-policies.py.

The checker's whole value is that it fails when a policy drifts; a checker that cannot fail is a
green tick with nothing behind it (which is exactly what happened to check-alerts.py once). So the
broken shapes are run first, and the real tree last.
"""

from __future__ import annotations

import importlib.util
import json
import pathlib
import shutil
import subprocess
import sys
import tempfile

ROOT = pathlib.Path(__file__).resolve().parent.parent
CHECKER = ROOT / "scripts" / "check-cam-policies.py"


def run_in(tree: pathlib.Path) -> subprocess.CompletedProcess:
    # The checker resolves ROOT from its own location, so it is copied next to the fake tree and
    # invoked from a scripts/ directory there.
    (tree / "scripts").mkdir(parents=True, exist_ok=True)
    shutil.copy2(CHECKER, tree / "scripts" / "check-cam-policies.py")
    return subprocess.run([sys.executable, str(tree / "scripts" / "check-cam-policies.py")],
                          capture_output=True, text=True)


# The import line is part of the fixture because the checker resolves the package name a file uses
# from its imports -- that is what catches an ALIASED one (`clbsdk.NewDescribeLoadBalancersRequest` in
# internal/onboarding/tencent.go), which the earlier bare-name match could not see: the runtime policy
# shipped without the two read-only CLB actions wecert-onboard's rule guard needs, and the miss only
# surfaced when the round-11 CVM verification attached that policy to a real instance role.
SSL_IMPORT = 'import ssl "github.com/tencentcloud/tencentcloud-sdk-go/tencentcloud/ssl/v20191205"\n'


def fake_tree(tmp: pathlib.Path) -> pathlib.Path:
    tree = tmp / "tree"
    (tree / "internal" / "deploy").mkdir(parents=True)
    (tree / "deploy").mkdir()
    (tree / "internal" / "deploy" / "tencent.go").write_text(
        "package deploy\n\n" + SSL_IMPORT +
        "\nfunc f() { _ = ssl.NewDeleteCertificateRequest() }\n")
    return tree


def write_policy(tree: pathlib.Path, actions: list[str]) -> None:
    for name in ("runtime", "test", "stage-ab"):
        (tree / "deploy" / f"cam-policy-{name}.json").write_text(json.dumps(
            {"statement": [{"action": actions, "resource": ["*"]}]}))


def main() -> int:
    failures: list[str] = []
    with tempfile.TemporaryDirectory() as td:
        tmp = pathlib.Path(td)

        # 1. Missing action: must fail.
        tree = fake_tree(tmp / "missing")
        write_policy(tree, ["ssl:UploadCertificate"])
        proc = run_in(tree)
        if proc.returncode != 1 or "ssl:DeleteCertificate" not in proc.stdout:
            failures.append(f"a policy missing an action was not reported: rc={proc.returncode} {proc.stdout!r}")

        # 2. Complete policy: must pass.
        tree = fake_tree(tmp / "complete")
        write_policy(tree, ["ssl:UploadCertificate", "ssl:DeleteCertificate"])
        proc = run_in(tree)
        if proc.returncode != 0:
            failures.append(f"a complete policy was rejected: rc={proc.returncode} {proc.stdout!r}")

        # 3. A new constructor with no policy update: must fail.
        tree = fake_tree(tmp / "added")
        (tree / "internal" / "deploy" / "more.go").write_text(
            "package deploy\n\n" + SSL_IMPORT +
            "\nfunc g() { _ = ssl.NewDescribeDeleteCertificatesTaskResultRequest() }\n")
        write_policy(tree, ["ssl:DeleteCertificate"])
        proc = run_in(tree)
        if proc.returncode != 1 or "DescribeDeleteCertificatesTaskResult" not in proc.stdout:
            failures.append(f"a newly used API was not reported: rc={proc.returncode} {proc.stdout!r}")

        # 4. An ALIASED SDK import must be seen too (the miss that let the runtime policy ship
        #    without the CLB guard's two actions).
        tree = fake_tree(tmp / "aliased")
        (tree / "internal" / "deploy" / "aliased.go").write_text(
            "package deploy\n\n" +
            'import clbsdk "github.com/tencentcloud/tencentcloud-sdk-go/tencentcloud/clb/v20180317"\n' +
            "\nfunc h() { _ = clbsdk.NewDescribeLoadBalancersRequest() }\n")
        write_policy(tree, ["ssl:UploadCertificate", "ssl:DeleteCertificate"])
        proc = run_in(tree)
        if proc.returncode != 1 or "clb:DescribeLoadBalancers" not in proc.stdout:
            failures.append(
                f"an aliased SDK import was not resolved: rc={proc.returncode} {proc.stdout!r}")

    if failures:
        print("check-cam-policies self-test FAILED")
        for f in failures:
            print("  -", f)
        return 1
    print("✓ check-cam-policies.py reports a missing action, passes a complete policy, notices a new "
          "API, and resolves an aliased SDK import")
    return 0


if __name__ == "__main__":
    sys.exit(main())
