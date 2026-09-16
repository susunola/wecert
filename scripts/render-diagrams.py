#!/usr/bin/env python3
"""把 docs/certificate-lifecycle.html 里的六张 SVG 渲成 PNG。

为什么要一个脚本而不是手工导一次：PNG 是二进制，代码改了它不会自己跟。
有一条可重跑的命令，图过期就只是一次 `make diagrams` 的事；
没有的话它一定会慢慢变成错的，而且没人发现。

为什么走 Chrome 而不是 rsvg-convert：这张图里所有的标签都在
<foreignObject> 里（那是唯一能让文字真正换行的办法，SVG 的 <text>
不会自动折行）。librsvg 会把 foreignObject 整个丢掉，渲出来是六张空图。

用法：
    python3 scripts/render-diagrams.py                # 两种语言全部重渲
    python3 scripts/render-diagrams.py --only 1       # 只渲第 1 张
    python3 scripts/render-diagrams.py --lang en      # 只渲英文
"""

import argparse
import os
import re
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
OUT_DIR = ROOT / "docs" / "diagrams"

# 两种语言各一套图。中文版是手写的事实来源，英文版由
# scripts/build-diagram-langs.py 生成。
LANGS = [
    ("zh", ROOT / "docs" / "certificate-lifecycle.html"),
    ("en", ROOT / "docs" / "certificate-lifecycle.en.html"),
]

# 每张图的文件名与所对应的 SVG 序号（1 起）。名字是给 readme 里的引用用的，
# 所以取得能自解释，而不是 diagram-1/2/3。
NAMES = [
    "00-the-problem",
    "01-system-map",
    "02-intent-to-contract",
    "03-reconcile-decisions",
    "04-order-state-machine",
    "05-dns01-sequence",
    "06-certificate-lifetime",
]

CHROME_CANDIDATES = [
    "/Applications/Google Chrome.app/Contents/MacOS/Google Chrome",
    "/Applications/Chromium.app/Contents/MacOS/Chromium",
    "/Applications/Microsoft Edge.app/Contents/MacOS/Microsoft Edge",
    "google-chrome",
    "chromium",
    "chromium-browser",
]

# 2 倍图。GitHub 会把宽图缩到容器宽度显示，一倍图在 retina 上会糊。
SCALE = 2

# 出图时的背景色，和 HTML 里 .scroll 卡片的底色一致。
#
# 不能用透明：GitHub 有暗色主题，深色文字配透明底会变成一片糊。
BACKGROUND = "#f6f5f1"


def find_chrome() -> str:
    for c in CHROME_CANDIDATES:
        if os.path.sep in c:
            if os.access(c, os.X_OK):
                return c
        elif shutil.which(c):
            return shutil.which(c)
    sys.exit(
        "找不到 Chrome / Chromium / Edge。这张图必须在真实浏览器里渲染——\n"
        "所有标签都在 <foreignObject> 里，librsvg 一类的转换器会把它整个丢掉。"
    )


def extract_style(html: str) -> str:
    """取出 <style> 的内容。

    整块照搬而不是挑出 SVG 相关的规则：多出来的 body/table 规则在 SVG
    文档里不匹配任何元素，无害；而挑漏一条就是一处静默的样式丢失。
    """
    m = re.search(r"<style>(.*?)</style>", html, re.S)
    if not m:
        sys.exit("源文件里找不到 <style> 块")
    return m.group(1)


def extract_svgs(html: str) -> list[str]:
    return re.findall(r"<svg\b.*?</svg>", html, re.S)


def standalone(svg: str, css: str, index: int) -> str:
    """把一段 <svg> 包成能独立打开的 SVG 文档。"""
    vb = re.search(r'viewBox="([\d.]+) ([\d.]+) ([\d.]+) ([\d.]+)"', svg)
    if not vb:
        sys.exit(f"第 {index} 张图没有 viewBox，无法确定尺寸")
    _, _, w, h = (float(x) for x in vb.groups())
    w, h = int(w), int(h)

    # 变量同时挂到 :root 和 svg 上：独立打开时 :root 就是 <svg>，
    # 但显式写两遍可以让"在 <img> 里引用"和"直接打开"两种情形都成立。
    vars_only = re.search(r":root\s*\{(.*?)\}", css, re.S)
    variables = vars_only.group(1) if vars_only else ""

    # 去掉原来的 viewBox，换成显式尺寸：Chrome 直接打开时按这个尺寸排版，
    # 配合 --window-size 正好铺满，不会留白边。
    body = svg[svg.index(">") + 1 : svg.rindex("</svg>")]

    return (
        f'<svg xmlns="http://www.w3.org/2000/svg" '
        f'xmlns:xhtml="http://www.w3.org/1999/xhtml" '
        f'width="{w}" height="{h}" viewBox="0 0 {w} {h}">\n'
        f"<style>\n:root{{{variables}}}\nsvg{{{variables}}}\n{css}\n</style>\n"
        f'<rect x="0" y="0" width="{w}" height="{h}" fill="{BACKGROUND}"/>\n'
        f"{body}\n</svg>\n"
    )


def render(chrome: str, svg_path: Path, png_path: Path, w: int, h: int) -> None:
    cmd = [
        chrome,
        "--headless",
        "--disable-gpu",
        "--hide-scrollbars",
        "--no-sandbox",
        "--force-device-scale-factor=%d" % SCALE,
        "--window-size=%d,%d" % (w, h),
        "--screenshot=%s" % png_path,
        svg_path.as_uri(),
    ]
    res = subprocess.run(cmd, capture_output=True, text=True, timeout=120)
    if not png_path.exists():
        sys.exit(f"渲染 {svg_path.name} 失败:\n{res.stdout}\n{res.stderr}")


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--only", type=int, help="只渲第 N 张（1 起）")
    ap.add_argument("--lang", choices=[l for l, _ in LANGS], help="只渲某一种语言")
    args = ap.parse_args()

    chrome = find_chrome()

    with tempfile.TemporaryDirectory() as tmp:
        for lang, source in LANGS:
            if args.lang and lang != args.lang:
                continue
            if not source.exists():
                sys.exit(f"找不到 {source}（英文版要先跑 scripts/build-diagram-langs.py）")

            html = source.read_text(encoding="utf-8")
            css = extract_style(html)
            svgs = extract_svgs(html)

            if len(svgs) != len(NAMES):
                sys.exit(f"{source.name} 里有 {len(svgs)} 张图，脚本预期 {len(NAMES)} 张"
                         f"——加图或删图之后记得同步 NAMES")

            out_dir = OUT_DIR / lang
            out_dir.mkdir(parents=True, exist_ok=True)
            print(f"{lang}: {source.name}")

            for i, svg in enumerate(svgs, start=1):
                if args.only and i != args.only:
                    continue

                name = NAMES[i - 1]
                vb = re.search(r'viewBox="[\d.]+ [\d.]+ ([\d.]+) ([\d.]+)"', svg)
                w, h = int(float(vb.group(1))), int(float(vb.group(2)))

                svg_path = Path(tmp) / f"{lang}-{name}.svg"
                svg_path.write_text(standalone(svg, css, i), encoding="utf-8")

                png_path = out_dir / f"{name}.png"
                render(chrome, svg_path, png_path, w, h)

                kb = png_path.stat().st_size / 1024
                print(f"  {name}.png  {w}x{h} @{SCALE}x  {kb:.0f} KB")

    print(f"\n已写入 {OUT_DIR.relative_to(ROOT)}/{{zh,en}}/")


if __name__ == "__main__":
    main()
