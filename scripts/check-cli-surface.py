#!/usr/bin/env python3
"""Fail when a flag the documentation tells an operator to run is not on the binary.

Why this exists: the documented command line is a delivery surface, and nothing connected
the two. `wecert-clbverify -clb ...` was unusable for a whole round because the flag was
registered on `flag.CommandLine` instead of the tool's own FlagSet: the README's own
example exited 64 with "flag provided but not defined: -clb", and every gate stayed green
because no test ever spells the documented command. The same class of drift is a flag
renamed in `cmd/*` while the table in the docs keeps the old name.

What it reads:

  * the flag tables under a `### `binary`` heading in README.md and README.reference.md
    (`| Flag | Default | Description |` -- the first cell of every row is parsed, so a row
    written as `-report` / `-no-report` documents both flags);
  * the command lines inside code spans (fenced blocks and inline `code`) in
    docs/staging-checklist.md, which is where the operator's actual commands live.

For every documented flag it requires the flag to appear in that binary's own `-h` output.
It also pins the two conventions the documented commands depend on: `-h` exits with the
code that binary documents (0 for wecert/preflight/clbverify, 64 for the two tools that
treat a help request as usage), and an unknown flag exits 64 -- the repository's "the
command line itself is wrong" code -- so a flag that is on the wrong FlagSet cannot pass by
being absent from help alone.

Exit codes: 0 clean, 1 a documented flag is missing (or a convention broke), 2 the check
itself could not run (a doc or a binary is missing, or the tables could not be parsed).

A binary that is missing or older than the sources is rebuilt with `make build tools` first,
so the check never reports on a program that is not in the tree. That build needs a writable
Go build cache: in a sandbox that cannot write the default GOCACHE, run this with
`GOCACHE="$PWD/.gocache"` (the in-repo cache .gitignore documents).
"""

from __future__ import annotations

import argparse
import pathlib
import re
import subprocess
import sys

ROOT = pathlib.Path(__file__).resolve().parent.parent

# The binaries whose command line is documented. Every one is built by `make build tools`.
BINARIES = (
    "wecert",
    "wecert-onboard",
    "wecert-probe",
    "wecert-preflight",
    "wecert-clbverify",
)

DEFAULT_TABLES = ("README.md", "README.reference.md")
DEFAULT_SPANS = ("docs/staging-checklist.md",)

# `-h` exit codes, measured rather than assumed. wecert, preflight and clbverify let the
# flag package handle -h (flag.ExitOnError -> 0); wecert-onboard and wecert-probe treat a
# help request as usage and use 64, the repository's "invalid command line" code. Both are
# deliberate -- what this pins is that neither silently changes.
HELP_EXIT = {
    "wecert": 0,
    "wecert-onboard": 64,
    "wecert-probe": 64,
    "wecert-preflight": 0,
    "wecert-clbverify": 0,
}
# The convention for every binary, and the exact defect-2 symptom.
UNKNOWN_FLAG_EXIT = 64
UNKNOWN_FLAG = "-wecert-cli-surface-unknown-flag"

HEADING = re.compile(r"^#{2,4}\s+`(?P<name>[a-z][a-z0-9-]*)`")
FLAG_IN_CELL = re.compile(r"`(-{1,2}[A-Za-z0-9][A-Za-z0-9-]*)`")
SPAN = re.compile(r"`([^`\n]+)`")
HELP_FLAG = re.compile(r"^\s+-{1,2}([A-Za-z][A-Za-z0-9-]*)\b")
LAUNCHERS = ("sudo", "env", "command", "nohup")


def strip_dashes(flag: str) -> str:
    return flag.lstrip("-")


def die(message: str) -> None:
    """A failure of the check itself, not of the surface it checks: exit 2."""
    print(f"check-cli-surface: {message}", file=sys.stderr)
    sys.exit(2)


def run_binary(path: pathlib.Path, *argv: str) -> tuple[int, str]:
    """Run the binary with argv, returning its exit code and its combined output."""
    try:
        proc = subprocess.run(
            [str(path), *argv], capture_output=True, text=True, timeout=60
        )
    except (OSError, subprocess.SubprocessError) as exc:
        die(f"could not run {path} {' '.join(argv)}: {exc}")
    return proc.returncode, proc.stdout + proc.stderr


def newest_source_mtime() -> float:
    newest = 0.0
    for path in list((ROOT / "cmd").rglob("*.go")) + list(
        (ROOT / "internal").rglob("*.go")
    ):
        if path.name.endswith("_test.go"):
            continue
        newest = max(newest, path.stat().st_mtime)
    for name in ("go.mod", "go.sum"):
        candidate = ROOT / name
        if candidate.exists():
            newest = max(newest, candidate.stat().st_mtime)
    return newest


def ensure_binaries(bin_dir: pathlib.Path, allow_build: bool) -> dict[str, pathlib.Path]:
    """Return the path of every binary, rebuilding the set when one is missing or stale.

    A stale binary would make this check report on a program that is not in the tree --
    exactly the confusion it exists to remove -- so the source mtimes are compared.
    """
    paths = {name: bin_dir / name for name in BINARIES}
    stale = [name for name, p in paths.items() if not p.exists()]
    if not stale:
        newest = newest_source_mtime()
        stale = [name for name, p in paths.items() if p.stat().st_mtime < newest]
    if not stale:
        return paths

    if not allow_build:
        die(
            "these binaries are missing or older than the sources: "
            + ", ".join(sorted(stale))
            + "\n  run `make build tools` first (--no-build forbids building here)."
        )
    print(
        "==> building the binaries these docs describe "
        f"({', '.join(sorted(stale))} missing or stale): make build tools"
    )
    proc = subprocess.run(["make", "build", "tools"], cwd=ROOT)
    if proc.returncode != 0:
        die("`make build tools` failed; cannot check the CLI surface.")
    missing = [name for name, p in paths.items() if not p.exists()]
    if missing:
        die("`make build tools` did not produce: " + ", ".join(sorted(missing)))
    return paths


def table_flags(path: pathlib.Path) -> dict[str, list[tuple[str, int, str]]]:
    """Parse the `### `binary`` flag tables: binary -> [(flag, line, file)]."""
    found: dict[str, list[tuple[str, int, str]]] = {}
    lines = path.read_text(encoding="utf-8").splitlines()
    for i, line in enumerate(lines):
        m = HEADING.match(line)
        if not m or m.group("name") not in BINARIES:
            continue
        name = m.group("name")
        rows = parse_first_table(lines, i + 1)
        if not rows:
            die(
                f"{path}: the `### `{name}`` section has no parseable flag table; the checker "
                "can no longer see what this file documents."
            )
        found.setdefault(name, []).extend((flag, lineno, str(path)) for flag, lineno in rows)
    return found


def parse_first_table(lines: list[str], start: int) -> list[tuple[str, int]]:
    """The first markdown table at or after `start`, as [(flag_name, line_number)]."""
    j = start
    while j < len(lines) and not lines[j].lstrip().startswith("|"):
        if HEADING.match(lines[j]):
            return []
        j += 1
    # Skip the `| Flag | ... |` header and the `|---|---|` separator.
    if j + 1 < len(lines) and set(lines[j + 1].replace("|", "").replace(" ", "")) <= {"-", ":"}:
        j += 2
    else:
        return []
    flags: list[tuple[str, int]] = []
    while j < len(lines) and lines[j].lstrip().startswith("|"):
        cells = lines[j].split("|")
        if len(cells) >= 2:
            for raw in FLAG_IN_CELL.findall(cells[1]):
                flags.append((strip_dashes(raw), j + 1))
        j += 1
    return flags


def code_spans(path: pathlib.Path) -> list[tuple[str, int, str]]:
    """Every code span in the file as (text, first line, file), fences and inline alike."""
    spans: list[tuple[str, int, str]] = []
    lines = path.read_text(encoding="utf-8").splitlines()
    fence_start = None
    buf: list[str] = []
    outside: list[tuple[int, str]] = []
    for lineno, line in enumerate(lines, 1):
        if line.lstrip().startswith("```"):
            if fence_start is None:
                fence_start = lineno + 1
                buf = []
            else:
                spans.append(("\n".join(buf), fence_start, str(path)))
                fence_start = None
            continue
        if fence_start is not None:
            buf.append(line)
        else:
            outside.append((lineno, line))
    for lineno, line in outside:
        for m in SPAN.finditer(line):
            spans.append((m.group(1), lineno, str(path)))
    return spans


def command_flags(text: str) -> tuple[str, list[str]] | None:
    """The binary a code span invokes and the flags it passes, or None.

    Only a span whose *command* is one of the documented binaries counts: a span such as
    `journalctl -u wecert -f` names the unit, not a command line, and must not contribute
    flags. `sudo -u wecert wecert -config ...` does count -- the user name is skipped.
    """
    tokens = text.replace("\\\n", " ").split()
    if not tokens:
        return None
    i = 0
    if tokens[0] in LAUNCHERS:
        i = 1
        if tokens[0] == "sudo":
            if i < len(tokens) and tokens[i] == "-u":
                i += 2
            while i < len(tokens) and tokens[i] in ("-E", "-H", "-n"):
                i += 1
        elif tokens[0] == "env":
            while i < len(tokens) and "=" in tokens[i]:
                i += 1
    if i >= len(tokens):
        return None
    name = tokens[i].rsplit("/", 1)[-1]
    if name not in BINARIES:
        return None
    i += 1
    flags: list[str] = []
    while i < len(tokens):
        tok = tokens[i]
        if not (tok.startswith("-") and len(tok) > 1 and tok[1].isalpha()):
            break  # a bare word ends the invocation (the rest is prose or a placeholder)
        flags.append(tok.lstrip("-").split("=", 1)[0])
        if "=" not in tok and i + 1 < len(tokens) and not tokens[i + 1].startswith("-"):
            i += 2  # skip the flag's value
        else:
            i += 1
    return name, flags


def collect(
    tables: list[str], spans: list[str]
) -> dict[str, list[tuple[str, int, str]]]:
    documented: dict[str, list[tuple[str, int, str]]] = {}
    for rel in tables:
        path = ROOT / rel
        if not path.is_file():
            die(f"no such document: {rel}")
        for name, entries in table_flags(path).items():
            documented.setdefault(name, []).extend(entries)
    for rel in spans:
        path = ROOT / rel
        if not path.is_file():
            die(f"no such document: {rel}")
        for text, lineno, source in code_spans(path):
            parsed = command_flags(text)
            if parsed is None:
                continue
            name, flags = parsed
            for flag in flags:
                documented.setdefault(name, []).append((flag, lineno, source))
    return documented


def main() -> int:
    ap = argparse.ArgumentParser(
        description="Check that every documented flag exists on the binary that documents it.",
    )
    ap.add_argument(
        "--tables",
        action="append",
        metavar="FILE",
        help="markdown file with `### `binary`` flag tables; replaces the default document set",
    )
    ap.add_argument(
        "--spans",
        action="append",
        metavar="FILE",
        help="markdown file whose code spans hold operator command lines; replaces the default set",
    )
    ap.add_argument("--bin-dir", default="bin", help="directory holding the built binaries")
    ap.add_argument(
        "--no-build",
        action="store_true",
        help="never build; fail instead when a binary is missing or older than the sources",
    )
    args = ap.parse_args()

    tables = (args.tables or []) if (args.tables or args.spans) else list(DEFAULT_TABLES)
    spans = (args.spans or []) if (args.tables or args.spans) else list(DEFAULT_SPANS)

    documented = collect(tables, spans)
    missing_docs = [name for name in BINARIES if name not in documented]
    if missing_docs:
        die(
            "no documented flags found for: "
            + ", ".join(missing_docs)
            + "\n  the documents were restructured, or a heading was renamed; this check "
            "cannot silently cover nothing."
        )

    bin_dir = (ROOT / args.bin_dir).resolve()
    binaries = ensure_binaries(bin_dir, allow_build=not args.no_build)

    checked = 0
    failures: list[str] = []
    for name in BINARIES:
        path = binaries[name]
        if not path.is_file():
            die(f"no such binary: {path}")
        rc, out = run_binary(path, "-h")
        if rc != HELP_EXIT[name]:
            failures.append(
                f"{name}: `-h` exited {rc}, expected {HELP_EXIT[name]} "
                "(the help/usage convention this repo documents)"
            )
        help_flags = {m.group(1) for m in (HELP_FLAG.match(l) for l in out.splitlines()) if m}
        if not help_flags:
            die(f"{name} -h printed no flags; cannot check anything.")

        seen: set[str] = set()
        for flag, lineno, source in documented[name]:
            if flag in seen:
                continue
            seen.add(flag)
            checked += 1
            if flag not in help_flags:
                failures.append(
                    f"{source}:{lineno}: `{name} -{flag}` is documented but {name} -h does "
                    "not define it"
                )

        rc, out = run_binary(path, UNKNOWN_FLAG)
        if rc != UNKNOWN_FLAG_EXIT:
            first = out.strip().splitlines()[0] if out.strip() else "<empty>"
            failures.append(
                f"{name}: an unknown flag exited {rc}, expected {UNKNOWN_FLAG_EXIT} "
                f"(output: {first})"
            )

    if failures:
        print("CLI surface drift: the documented command lines do not match the binaries.")
        for f in failures:
            print(f"  - {f}")
        print(
            "\nEither fix the binary (a flag registered on flag.CommandLine instead of the "
            "tool's own FlagSet is the historical cause), or fix the document."
        )
        return 1

    print(
        f"✓ {len(BINARIES)} binaries: {checked} documented flags all appear in `-h`, "
        f"`-h` exits as documented and an unknown flag exits {UNKNOWN_FLAG_EXIT} "
        f"({', '.join(tables + spans)})"
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
