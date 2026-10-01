#!/usr/bin/env python3
"""Guard the write paths the console's buttons depend on.

The daemon rewrites /etc/wecert/config.yaml atomically for every management
write -- adding a certificate, saving a notification channel, deleting one.
Three shipped artifacts used to make that impossible while every read-only page
kept working, so the console looked broken button by button:

  1. deploy/systemd/*.service set ReadOnlyPaths=/etc/wecert (the daemon could
     not write its own config even though nothing else needed the path);
  2. a unit with ProtectSystem=strict but no ReadWritePaths covering the config
     directory (the whole filesystem read-only is the default under strict);
  3. install.sh created /etc/wecert root:wecert 0750 and the config file
     root:wecert 0640, so the service user could never create the ".atomic-*"
     temp file that atomicfile.Write renames into place.

This checker asserts the opposite invariants, by content, in the shipped files.
"""

from __future__ import annotations

import pathlib
import sys

ROOT = pathlib.Path(__file__).resolve().parent.parent

FAILURES: list[str] = []


def fail(msg: str) -> None:
    FAILURES.append(msg)


def effective_lines(text: str) -> list[str]:
    """Lines minus comments.

    The unit files explain themselves at length, and the explanation mentions
    the forbidden directive by name -- matching raw text would flag the warning
    about the very thing this checker exists to prevent.
    """
    return [line for line in text.splitlines() if not line.lstrip().startswith("#")]


def check_units() -> None:
    units = sorted((ROOT / "deploy" / "systemd").glob("*.service"))
    if not units:
        fail("deploy/systemd contains no .service files; the units moved?")

    for unit in units:
        lines = effective_lines(unit.read_text())

        # The exact refusal the console surfaced, back from the dead.
        if any("ReadOnlyPaths=/etc/wecert" in line for line in lines):
            fail(f"{unit.name}: ReadOnlyPaths=/etc/wecert forbids the daemon to "
                 "rewrite its own config; management writes fail with "
                 "'read-only file system'")

        # Under ProtectSystem=strict everything is read-only unless granted, so
        # a strict unit without the grant is the same failure with fewer words.
        strict = any(line.strip() == "ProtectSystem=strict" for line in lines)
        granted = any("ReadWritePaths=" in line and "/etc/wecert" in line
                      for line in lines)
        if strict and not granted:
            fail(f"{unit.name}: ProtectSystem=strict without "
                 "ReadWritePaths=/etc/wecert makes /etc/wecert read-only")


def check_install() -> None:
    text = (ROOT / "install.sh").read_text()
    lines = effective_lines(text)

    def touching(name: str) -> list[str]:
        return [line for line in lines if name in line]

    # The config directory must be installed (or chowned) to the service user:
    # creating the ".atomic-*.tmp" sibling is a directory write.
    if any("chown root:wecert" in line for line in touching("CONFIG_DIR")):
        fail("install.sh: chown root:wecert on CONFIG_DIR leaves the service "
             "unable to create the atomic temp file in it")
    # Match on the CONFIG_DIR line itself. An "install -d -o wecert" elsewhere
    # (the state directory line) says nothing about this one.
    if not any("install -d -o wecert" in line or "chown wecert:wecert" in line
               for line in touching("CONFIG_DIR")):
        fail("install.sh: nothing gives the service user write access to "
             "CONFIG_DIR (expected install -d -o wecert or chown wecert:wecert)")

    # The config file itself must end up writable by the service user, both for
    # a fresh install and for an existing one left over from an older release.
    if any("install -m 0640 -o root" in line for line in touching("CONFIG_FILE")):
        fail("install.sh: a fresh config installed root:wecert 0640 can be read "
             "by the daemon but never rewritten by it")
    # The "config already exists" branch is the upgraded-install path: the
    # fresh-install grant below it does not help a root-owned file that already
    # sits there, so that branch must hand the file over itself.
    if not any('chown wecert:wecert "${CONFIG_FILE}"' in line for line in lines):
        fail("install.sh: an existing config file is not handed to the service "
             "user, so management writes fail on upgraded installs")


def main() -> int:
    check_units()
    check_install()

    if FAILURES:
        for f in FAILURES:
            print(f"FAIL {f}")
        print(f"\n{len(FAILURES)} check(s) failed")
        return 1
    print("deploy write paths OK: units grant /etc/wecert, install.sh hands it "
          "to the service user")
    return 0


if __name__ == "__main__":
    sys.exit(main())
