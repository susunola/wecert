#!/usr/bin/env python3
"""Generate the standalone management console from its canonical source files."""
import argparse
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent / "webconsole"

def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--check", action="store_true")
    args = parser.parse_args()
    html = (ROOT / "console.template.html").read_text()
    for name in ("css", "js"):
        marker = f"@@CONSOLE_{name.upper()}@@"
        if html.count(marker) != 1:
            raise SystemExit(f"Expected exactly one {marker} in the template")
        html = html.replace(marker, (ROOT / f"console.{name}").read_text().rstrip())
    output = ROOT / "console.html"
    if args.check:
        if output.read_text() != html:
            raise SystemExit("console.html is out of date; run make console-build")
        print("console.html matches its sources")
    else:
        output.write_text(html)

if __name__ == "__main__":
    main()
