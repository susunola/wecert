#!/usr/bin/env python3
"""Fail if any code comment or string in this repo is still in Chinese.

wecert is an international project: every comment, docstring, log line and
test failure message in the *source* is English. Two things are deliberately
excluded, because their Chinese is **data rather than prose**:

  - `docs/certificate-lifecycle.html` — the hand-written source for the Chinese
    diagram set. `scripts/build-diagram-langs.py` generates the English page
    from it through `scripts/diagram_i18n.py`.
  - `scripts/diagram_i18n.py` — the zh→en translation table. Its Chinese keys
    *are* the lookup keys; translating them silently breaks the diagram build.
  - `scripts/e2e-report.py` — the label strings of the generated test report,
    which is the same content as the `docs/*.html` page it writes.

Markdown is excluded as well: the repository ships paired English and Chinese
documents on purpose (`README.md` / `README.zh-CN.md` and so on).

Everything else is scanned by *content*, not by extension, so systemd units,
`.tfvars` files and extensionless scripts are covered too.

Run directly, or via `make check`.

Usage:
    python3 scripts/check-english.py            # report and exit 1 on failure
    python3 scripts/check-english.py --count    # just print the total
"""

import argparse
import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent

CJK = re.compile(r"[\u4e00-\u9fff\u3000-\u303f\uff00-\uffef]")

# The Chinese in these files is data, not prose.
ALLOWED = {
    "docs/certificate-lifecycle.html",
    "docs/certificate-lifecycle.en.html",
    "scripts/diagram_i18n.py",
    # The report renderer's Chinese strings are its output's labels, not prose about the code --
    # the same content as the docs/*.html files it generates, which are exempt for the same
    # reason. Keeping them here rather than in a data file means the label and its use are read
    # together; the alternative was a one-entry lookup table existing only to satisfy this scan.
    "scripts/e2e-report.py",
}

SKIP_DIRS = {
    ".git", ".gopath", "bin", "dist", ".terraform", "__pycache__",
    "node_modules", ".gocache", ".terraform-plugin-cache",
}

# Machine-generated or tool state, not hand-written source.
SKIP_SUFFIXES = {
    ".pyc", ".sum", ".lock",
    ".png", ".jpg", ".jpeg", ".gif", ".ico", ".pdf", ".gz", ".tgz", ".zip",
    ".woff", ".woff2", ".ttf", ".otf",
}
# Matched against the whole name, because Path.suffix only returns the last
# segment: `terraform.tfstate.backup` has suffix `.backup`, not `.tfstate.backup`.
SKIP_NAME_PARTS = (".tfstate",)
SKIP_NAMES = {"go.sum", "package-lock.json"}


def candidates():
    """Yield every text file that is not excluded, whatever its extension.

    This is deliberately *not* an extension allowlist. systemd units, Terraform
    `.tfvars` files and extensionless scripts are all source too, and a Chinese
    comment in a `.service` file would slip straight through an allowlist.
    Binary files are recognised by content (a NUL byte) rather than by name.
    """
    for p in sorted(ROOT.rglob("*")):
        if not p.is_file():
            continue
        rel = p.relative_to(ROOT).as_posix()
        if rel in ALLOWED:
            continue
        if any(part in SKIP_DIRS for part in p.parts):
            continue
        if p.suffix.lower() in SKIP_SUFFIXES or p.name in SKIP_NAMES:
            continue
        if any(part in p.name for part in SKIP_NAME_PARTS):
            continue
        # Markdown ships as paired English/Chinese documents on purpose, and the
        # Chinese diagram page is generated, not hand-written source.
        if p.suffix == ".md":
            continue
        if rel.startswith("docs/") and p.suffix == ".html":
            continue
        yield p, rel


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--count", action="store_true", help="print the total and exit")
    args = ap.parse_args()

    bad: list[tuple[str, int, str]] = []
    scanned = 0

    for path, rel in candidates():
        try:
            raw = path.read_bytes()
        except OSError:
            continue
        if b"\x00" in raw:
            continue  # binary, despite the name
        try:
            text = raw.decode("utf-8")
        except UnicodeDecodeError:
            continue
        scanned += 1
        for i, line in enumerate(text.split("\n"), 1):
            if CJK.search(line):
                bad.append((rel, i, line.strip()))

    if args.count:
        print(f"{len(bad)} lines in {len({b[0] for b in bad})} files")
        return

    if not bad:
        print(f"✓ {scanned} source files scanned, no Chinese outside the allowed data files")
        return

    by_file: dict[str, list[tuple[int, str]]] = {}
    for rel, i, line in bad:
        by_file.setdefault(rel, []).append((i, line))

    print(f"✗ {len(bad)} lines of Chinese in {len(by_file)} source files "
          f"(wecert is an international project: comments and messages are English)\n")
    for rel in sorted(by_file):
        print(f"  {rel}")
        for i, line in by_file[rel][:3]:
            print(f"    {i}: {line[:96]}")
        if len(by_file[rel]) > 3:
            print(f"    … and {len(by_file[rel]) - 3} more")
    print("\nThe only Chinese that belongs in source is in these data files:")
    for a in sorted(ALLOWED):
        print(f"  {a}")
    sys.exit(1)


if __name__ == "__main__":
    main()
