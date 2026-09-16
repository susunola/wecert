#!/usr/bin/env python3
"""Measure in a real browser whether every diagram label overflows its box.

Why actually measure instead of estimating with a heuristic: a version that
estimated height from character width was written first, and it missed the case
where the annotation strip at the bottom of docs/certificate-lifecycle.html has a
whole line clipped — the estimate came out shorter than the box while the real
render overflowed. Real text width and line-breaking behavior (letter spacing,
`.88em` <code>, flex gap, mixed Chinese/English text) cannot be computed
accurately in a few dozen lines of Python, and what is being judged here is
precisely the **render result**.

Approach: hand the page plus a probe script to Chrome. The probe measures the
actual bounding box of the child elements inside each <foreignObject>, collects
the ones that stick out of their container, writes them into document.title, and
--dump-dom brings them back.

Usage:
    python3 scripts/check-diagram-fit.py        # exit code 1 when something is wrong
"""

import json
import os
import re
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
SOURCES = [
    ROOT / "docs" / "certificate-lifecycle.html",
    ROOT / "docs" / "certificate-lifecycle.en.html",
]

CHROME_CANDIDATES = [
    "/Applications/Google Chrome.app/Contents/MacOS/Google Chrome",
    "/Applications/Chromium.app/Contents/MacOS/Chromium",
    "/Applications/Microsoft Edge.app/Contents/MacOS/Microsoft Edge",
    "google-chrome",
    "chromium",
    "chromium-browser",
]

# The probe. getBoundingClientRect rather than scrollHeight: .fo is a
# justify-content:center flex container, so once the content overflows,
# scrollHeight behaves asymmetrically on the two sides, whereas comparing bounding
# boxes is direct and unambiguous.
PROBE = """
<script>
(function () {
  var out = [];
  document.querySelectorAll('foreignObject').forEach(function (fo, idx) {
    var box = fo.firstElementChild;
    if (!box) { return; }
    var br = box.getBoundingClientRect();

    var top = Infinity, bottom = -Infinity, left = Infinity, right = -Infinity;
    Array.prototype.forEach.call(box.children, function (c) {
      var r = c.getBoundingClientRect();
      if (r.width === 0 && r.height === 0) { return; }
      top = Math.min(top, r.top); bottom = Math.max(bottom, r.bottom);
      left = Math.min(left, r.left); right = Math.max(right, r.right);
    });
    if (top === Infinity) { return; }

    var overBottom = bottom - br.bottom;
    var overTop = br.top - top;
    var overRight = right - br.right;

    if (overBottom > 0.5 || overTop > 0.5 || overRight > 0.5) {
      var svg = fo.closest('svg');
      out.push({
        svg: Array.prototype.indexOf.call(document.querySelectorAll('svg'), svg) + 1,
        w: Math.round(parseFloat(fo.getAttribute('width'))),
        h: Math.round(parseFloat(fo.getAttribute('height'))),
        overTop: Math.round(overTop),
        overBottom: Math.round(overBottom),
        overRight: Math.round(overRight),
        text: (box.textContent || '').replace(/\\s+/g, ' ').trim().slice(0, 70)
      });
    }
  });
  // <text> has no box to compare against, so use a different test: compare
  // bounding boxes pairwise, and an overlap is a problem. Elements like section
  // headings get longer in English and they are not inside a foreignObject — if
  // they were not measured separately, "English headings collide" would never be
  // noticed.
  var texts = Array.prototype.slice.call(document.querySelectorAll('svg text'));
  texts.forEach(function (a, i) {
    var ra = a.getBoundingClientRect();
    if (ra.width === 0) { return; }
    texts.forEach(function (b, j) {
      if (j <= i) { return; }
      var rb = b.getBoundingClientRect();
      if (rb.width === 0) { return; }
      var ox = Math.min(ra.right, rb.right) - Math.max(ra.left, rb.left);
      var oy = Math.min(ra.bottom, rb.bottom) - Math.max(ra.top, rb.top);
      if (ox > 1 && oy > 1) {
        var svg = a.closest('svg');
        out.push({
          svg: Array.prototype.indexOf.call(document.querySelectorAll('svg'), svg) + 1,
          w: 0, h: 0, overTop: 0, overBottom: 0, overRight: Math.round(ox),
          text: '<text> overlap: ' + (a.textContent || '').trim() +
                '  ×  ' + (b.textContent || '').trim()
        });
      }
    });
  });

  document.title = 'FIT' + JSON.stringify(out) + 'END';
})();
</script>
"""


def find_chrome() -> str:
    for c in CHROME_CANDIDATES:
        if os.path.sep in c:
            if os.access(c, os.X_OK):
                return c
        elif shutil.which(c):
            return shutil.which(c)
    sys.exit("Chrome / Chromium not found.")


def check(chrome: str, source: Path, quiet: bool = False) -> int:
    if not source.exists():
        print(f"  {source.name}: skipped (file does not exist)")
        return 0

    html = source.read_text(encoding="utf-8")
    if "</body>" not in html:
        sys.exit("the source structure changed: no </body>, so the probe injection point is gone")

    probed = html.replace("</body>", PROBE + "</body>")

    with tempfile.TemporaryDirectory() as tmp:
        path = Path(tmp) / "probe.html"
        path.write_text(probed, encoding="utf-8")

        # The window is opened wide enough that the page lays out at desktop
        # width — the diagrams' own width is set by the viewBox and is unaffected,
        # but the rules under @media(max-width:700px) change .scroll's layout, so a
        # too-small window measures a different result.
        res = subprocess.run(
            [chrome, "--headless", "--disable-gpu", "--no-sandbox",
             "--window-size=1400,3000", "--virtual-time-budget=5000",
             "--dump-dom", path.as_uri()],
            capture_output=True, text=True, timeout=120,
        )

    m = re.search(r"<title>FIT(.*?)END</title>", res.stdout, re.S)
    if not m:
        sys.exit("the probe returned nothing. The marker is missing from the "
                 "--dump-dom output, which usually means a script error on the page.")

    bad = json.loads(m.group(1))
    label = source.name
    if not bad:
        print(f"  ✓ {label}")
        return 0

    print(f"\n✗ {label}: {len(bad)} labels overflow their box"
          f" (overrun in CSS px; it is scaled up again in the image):\n")
    for b in bad:
        bits = []
        if b["overTop"] > 0:
            bits.append(f"over top {b['overTop']}")
        if b["overBottom"] > 0:
            bits.append(f"over bottom {b['overBottom']}")
        if b["overRight"] > 0:
            bits.append(f"over right {b['overRight']}")
        print(f"  diagram {b['svg']}  box {b['w']}x{b['h']}  {', '.join(bits)}")
        print(f"        {b['text']}")
    return 1


def main() -> None:
    chrome = find_chrome()
    failed = 0
    for src in SOURCES:
        if check(chrome, src):
            failed += 1
    if failed:
        print()
        sys.exit(1)
    print("\n✓ all foreignObject labels fit inside their box")


if __name__ == "__main__":
    main()
