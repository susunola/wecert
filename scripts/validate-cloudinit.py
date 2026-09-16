#!/usr/bin/env python3
"""Validate cloud-init user_data before apply.

Why this script exists: the scripts inside user_data only run once the machine
actually boots, so a syntax error stays hidden until the CVM is built and the
backend fails to come up — several minutes of waiting for nothing, and the symptom
is "the CLB returns 502", which is easily misdiagnosed as a network or
security-group problem.

This was hit for real: one unmatched string quote in Python, and the CVM came up
and cloud-init "succeeded" too (the systemctl call inside runcmd failed silently),
but the backend never listened on port 80.

By default it parses the .tf source (checkable before apply); add --from-state to
read from terraform state instead (more authoritative, but requires a prior apply).

Usage:
    python3 scripts/validate-cloudinit.py
    python3 scripts/validate-cloudinit.py testenv/cvm.tf
    python3 scripts/validate-cloudinit.py --from-state testenv
"""
import base64
import json
import os
import re
import subprocess
import sys
import tempfile
import textwrap


def extract_from_tf(path):
    """Extract write_files (path, content) pairs from the .tf source."""
    lines = open(path, encoding="utf-8").read().split("\n")
    found = []
    cur_path = None

    i = 0
    while i < len(lines):
        line = lines[i]

        m = re.match(r"^\s*-\s*path:\s*(\S+)\s*$", line)
        if m:
            cur_path = m.group(1)
            i += 1
            continue

        m = re.match(r"^(\s*)content:\s*\|", line)
        if m and cur_path:
            indent = len(m.group(1))
            body = []
            i += 1
            while i < len(lines):
                nxt = lines[i]
                # indentation back at content's level or shallower means the block has ended
                if nxt.strip() and (len(nxt) - len(nxt.lstrip())) <= indent:
                    break
                body.append(nxt)
                i += 1
            found.append((cur_path, textwrap.dedent("\n".join(body))))
            cur_path = None
            continue

        i += 1

    return found


def _try_b64(raw):
    try:
        return base64.b64decode(raw, validate=True).decode("utf-8")
    except Exception:
        return None


def extract_from_state(tf_dir):
    out = subprocess.run(
        ["terraform", "show", "-json"],
        cwd=tf_dir, capture_output=True, text=True, check=True,
    ).stdout
    state = json.loads(out)

    for res in state.get("values", {}).get("root_module", {}).get("resources", []):
        if res["type"] != "tencentcloud_instance":
            continue
        values = res["values"]
        raw = values.get("user_data_raw") or values.get("user_data") or ""
        if not raw:
            continue
        # the provider stores user_data as base64; user_data_raw may be plaintext
        for candidate in (raw, _try_b64(raw)):
            if candidate and candidate.lstrip().startswith("#cloud-config"):
                return res["name"], candidate
    return None, None


def check_python(name, content, failures):
    try:
        compile(content, name, "exec")
        print(f"    OK   valid Python syntax   {name}")
    except SyntaxError as e:
        print(f"    FAIL Python syntax error   {name}:{e.lineno}: {e.msg}")
        print(f"         {(e.text or '').rstrip()}")
        failures.append(f"{name} line {e.lineno}: {e.msg}")


def check_shell(name, content, failures):
    with tempfile.NamedTemporaryFile("w", suffix=".sh", delete=False) as f:
        f.write(content)
        tmp = f.name
    try:
        r = subprocess.run(["bash", "-n", tmp], capture_output=True, text=True)
        if r.returncode == 0:
            print(f"    OK   valid shell syntax    {name}")
        else:
            print(f"    FAIL shell syntax error    {name}\n         {r.stderr.strip()}")
            failures.append(f"{name}: {r.stderr.strip()}")
    finally:
        os.unlink(tmp)


def classify_and_check(name, content, failures):
    first = content.split("\n", 1)[0]
    if first.startswith("#!") and "python" in first:
        check_python(name, content, failures)
    elif first.startswith("#!"):
        check_shell(name, content, failures)
    elif name.endswith(".py"):
        check_python(name, content, failures)
    else:
        print(f"    --   skipped (not a script)     {name}")


def main():
    args = [a for a in sys.argv[1:] if not a.startswith("--")]
    from_state = "--from-state" in sys.argv
    failures = []

    if from_state:
        tf_dir = args[0] if args else "testenv"
        if not os.path.isdir(tf_dir):
            print(f"directory not found: {tf_dir}", file=sys.stderr)
            return 2
        try:
            name, user_data = extract_from_state(tf_dir)
        except subprocess.CalledProcessError as e:
            print(f"terraform show failed: {e.stderr}", file=sys.stderr)
            return 2
        if not user_data:
            print("no instance with user_data in state, skipping.")
            return 0

        print(f"validating user_data of instance {name} from state ({len(user_data)} bytes)")
        try:
            import yaml
        except ImportError:
            print("  pyyaml is required to parse cloud-init (pip install pyyaml)")
            return 0
        try:
            doc = yaml.safe_load(user_data)
        except Exception as e:
            print(f"  FAIL YAML parse failed: {e}")
            return 1
        if not isinstance(doc, dict):
            print("  FAIL not a valid cloud-init mapping")
            return 1
        print("  OK   valid YAML")

        files = [(f.get("path", "?"), f.get("content") or "")
                 for f in (doc.get("write_files") or [])]
    else:
        tf_file = args[0] if args else os.path.join("testenv", "cvm.tf")
        if not os.path.isfile(tf_file):
            print(f"file not found: {tf_file}", file=sys.stderr)
            return 2
        print(f"validating from source: {tf_file}")
        files = extract_from_tf(tf_file)

    if not files:
        print("  no write_files content extracted; check whether the .tf layout changed.")
        return 1

    print(f"  write_files: {len(files)} entries")
    for name, content in files:
        classify_and_check(name, content, failures)

    if failures:
        print(f"\nFAIL validation failed with {len(failures)} problem(s):")
        for x in failures:
            print(f"   - {x}")
        return 1

    print("\nOK cloud-init user_data syntax check passed")
    return 0


if __name__ == "__main__":
    sys.exit(main())
