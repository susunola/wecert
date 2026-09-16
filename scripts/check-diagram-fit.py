#!/usr/bin/env python3
"""在真实浏览器里量每张图的标签有没有溢出它的盒子。

为什么要真测而不是用启发式估算：我先写过一个按字符宽度估算高度的版本，
它漏掉了 docs/certificate-lifecycle.html 底部注释带被裁掉一整行的情况 ——
估出来的高度比盒子矮，实际渲染却溢出了。文字宽度和折行的真实行为
（字距、`.88em` 的 <code>、flex gap、中英混排）不是几十行 Python 能算准的，
而这里要判断的恰恰是**渲染结果**。

做法：把页面连同一段探针脚本丢给 Chrome，探针量每个 <foreignObject> 里
子元素的实际外接框，超出容器的收集起来写进 document.title，
再用 --dump-dom 取回来。

用法：
    python3 scripts/check-diagram-fit.py        # 有问题时退出码 1
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
SOURCE = ROOT / "docs" / "certificate-lifecycle.html"

CHROME_CANDIDATES = [
    "/Applications/Google Chrome.app/Contents/MacOS/Google Chrome",
    "/Applications/Chromium.app/Contents/MacOS/Chromium",
    "/Applications/Microsoft Edge.app/Contents/MacOS/Microsoft Edge",
    "google-chrome",
    "chromium",
    "chromium-browser",
]

# 探针。用 getBoundingClientRect 而不是 scrollHeight：.fo 是
# justify-content:center 的 flex 容器，内容溢出时 scrollHeight 的行为
# 在两侧不对称，而外接框比较是直接、无歧义的。
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
    sys.exit("找不到 Chrome / Chromium。")


def main() -> None:
    if not SOURCE.exists():
        sys.exit(f"找不到源文件 {SOURCE}")

    chrome = find_chrome()
    html = SOURCE.read_text(encoding="utf-8")
    if "</body>" not in html:
        sys.exit("源文件结构变了：找不到 </body>，探针注入点失效")

    probed = html.replace("</body>", PROBE + "</body>")

    with tempfile.TemporaryDirectory() as tmp:
        path = Path(tmp) / "probe.html"
        path.write_text(probed, encoding="utf-8")

        # 窗口开足够大，让页面按桌面宽度排版 —— 图本身的宽度是 viewBox
        # 决定的，不受影响；但 @media(max-width:700px) 里的规则会改 .scroll
        # 的布局，窗口太小会测出另一套结果。
        res = subprocess.run(
            [chrome, "--headless", "--disable-gpu", "--no-sandbox",
             "--window-size=1400,3000", "--virtual-time-budget=5000",
             "--dump-dom", path.as_uri()],
            capture_output=True, text=True, timeout=120,
        )

    m = re.search(r"<title>FIT(.*?)END</title>", res.stdout, re.S)
    if not m:
        sys.exit("探针没有回传结果。--dump-dom 的输出里找不到标记，"
                 "多半是页面脚本报错了。")

    bad = json.loads(m.group(1))
    if not bad:
        print("✓ 所有 foreignObject 标签都在盒子里")
        return

    print(f"✗ {len(bad)} 处标签溢出盒子（超出量按 CSS px，图上还会按比例放大）:\n")
    for b in bad:
        bits = []
        if b["overTop"] > 0:
            bits.append(f"上溢 {b['overTop']}")
        if b["overBottom"] > 0:
            bits.append(f"下溢 {b['overBottom']}")
        if b["overRight"] > 0:
            bits.append(f"右溢 {b['overRight']}")
        print(f"  图{b['svg']}  盒 {b['w']}x{b['h']}  {', '.join(bits)}")
        print(f"        {b['text']}")
    print()
    sys.exit(1)


if __name__ == "__main__":
    main()
