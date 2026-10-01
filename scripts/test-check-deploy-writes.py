#!/usr/bin/env python3
"""Self-test for check-deploy-writes.py.

The checker's value is that it fails when a shipped artifact drifts back to a
read-only config directory; a checker that cannot fail is a green tick with
nothing behind it. So the three broken shapes that produced the console's
"read-only file system" errors are injected first -- each must be caught -- and
the real tree is checked last, which also proves the checker passes the fix it
ships with.
"""

from __future__ import annotations

import pathlib
import shutil
import subprocess
import sys
import tempfile

ROOT = pathlib.Path(__file__).resolve().parent.parent
CHECKER = ROOT / "scripts" / "check-deploy-writes.py"

UNIT = """[Service]
User=wecert
ExecStart=/usr/local/bin/wecert -config /etc/wecert/config.yaml
{sandbox}
"""


def run_in(tree: pathlib.Path) -> subprocess.CompletedProcess:
    (tree / "scripts").mkdir(parents=True, exist_ok=True)
    shutil.copy2(CHECKER, tree / "scripts" / "check-deploy-writes.py")
    return subprocess.run([sys.executable, str(tree / "scripts" / "check-deploy-writes.py")],
                          capture_output=True, text=True)


def unit(text: str) -> str:
    return UNIT.format(sandbox=text)


GOOD_UNIT = unit("""ProtectSystem=strict
ReadWritePaths=/etc/wecert
""")

GOOD_INSTALL = """mkdir -p "${CONFIG_DIR}"
chown wecert:wecert "${CONFIG_DIR}"
chmod 0750 "${CONFIG_DIR}"
install -d -o wecert -g wecert -m 0700 "${STATE_DIR}"
if [[ -f "${CONFIG_FILE}" ]]; then
\tchown wecert:wecert "${CONFIG_FILE}"
else
\tinstall -m 0600 -o wecert -g wecert "${SCRIPT_DIR}/config.example.yaml" "${CONFIG_FILE}"
fi
"""


def base_tree(tmp: pathlib.Path, slot: int = 0) -> pathlib.Path:
    # Each case gets its own tree: recreating one directory in place would hit
    # FileExistsError on the second case and look like a checker failure.
    tree = tmp / f"tree{slot}"
    (tree / "deploy" / "systemd").mkdir(parents=True)
    (tree / "deploy" / "systemd" / "wecert.service").write_text(GOOD_UNIT)
    (tree / "install.sh").write_text(GOOD_INSTALL)
    return tree


def main() -> int:
    failures: list[str] = []
    cases: list[tuple[str, callable]] = []  # noqa: F821

    def case(name: str, mutate: "callable") -> None:  # noqa: F821
        cases.append((name, mutate))

    case("ReadOnlyPaths returns",
         lambda t: (t / "deploy/systemd/wecert.service")
         .write_text(GOOD_UNIT.replace("ReadWritePaths=/etc/wecert",
                                       "ReadOnlyPaths=/etc/wecert")))
    case("strict without the grant",
         lambda t: (t / "deploy/systemd/wecert.service")
         .write_text(GOOD_UNIT.replace("ReadWritePaths=/etc/wecert\n", "")))
    case("install.sh root-owned config dir",
         lambda t: (t / "install.sh")
         .write_text(GOOD_INSTALL.replace('chown wecert:wecert "${CONFIG_DIR}"',
                                          'chown root:wecert "${CONFIG_DIR}"')))
    case("install.sh drops the grant entirely",
         lambda t: (t / "install.sh")
         .write_text(GOOD_INSTALL.replace('chown wecert:wecert "${CONFIG_DIR}"\n', "")))
    case("install.sh fresh config root:wecert 0640",
         lambda t: (t / "install.sh")
         .write_text(GOOD_INSTALL.replace(
             'install -m 0600 -o wecert -g wecert "${SCRIPT_DIR}/config.example.yaml"',
             'install -m 0640 -o root -g wecert "${SCRIPT_DIR}/config.example.yaml"')))
    case("install.sh leaves an existing config root-owned",
         lambda t: (t / "install.sh")
         .write_text(GOOD_INSTALL.replace('chown wecert:wecert "${CONFIG_FILE}"\n', "")))

    with tempfile.TemporaryDirectory() as td:
        tmp = pathlib.Path(td)
        for slot, (name, mutate) in enumerate(cases):
            tree = base_tree(tmp, slot)
            mutate(tree)
            proc = run_in(tree)
            if proc.returncode == 0:
                failures.append(f"{name}: checker passed a regression it must catch")
            else:
                print(f"caught as expected: {name}")

        # A missing units directory is a moved delivery surface, not a pass.
        tree = base_tree(tmp, len(cases))
        for svc in (tree / "deploy" / "systemd").glob("*.service"):
            svc.unlink()
        proc = run_in(tree)
        if proc.returncode == 0:
            failures.append("empty deploy/systemd: checker passed a tree with no units")
        else:
            print("caught as expected: empty deploy/systemd")

        # The real tree, last: proves the fix this checker ships with passes.
        proc = subprocess.run([sys.executable, str(CHECKER)], capture_output=True, text=True)
        print(proc.stdout, end="")
        if proc.returncode != 0:
            failures.append(f"real tree fails its own checker:\n{proc.stdout}{proc.stderr}")

    if failures:
        print()
        for f in failures:
            print(f"SELF-TEST FAIL {f}")
        return 1
    print(f"\nself-test OK: {len(cases) + 1} regressions caught, real tree passes")
    return 0


if __name__ == "__main__":
    sys.exit(main())
