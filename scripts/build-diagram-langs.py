#!/usr/bin/env python3
"""从中文版页面生成英文版页面。

中文的 `docs/certificate-lifecycle.html` 是唯一的事实来源，英文版是派生产物。
这么做而不是维护两份手写文件，是因为两份手写文件一定会漂移，而漂移的表现
是"英文版里混着一段中文"—— 那种问题没人会主动去发现。

生成完之后会**再扫一遍渲染文本**，有中文残留就直接失败。所以漏译不可能
悄悄过去：要么翻译表补全，要么构建红掉。

## 为什么用 HTML 解析器而不是正则

第一版是用正则找"最内层块级元素"的。它在嵌套 `<div>` 上必然出错：正则
没法配对嵌套标签，`<div class="grid2"><div>…</div>…</div>` 会匹配到第一个
`</div>` 就收尾，于是那一整块内容被跳过 —— 更糟的是，被跳过的东西连
"待译清单"都不会出现，因为清单就是从同一次遍历里出来的。

结果就是"构建通过但页面里混着中文"。换成 html.parser 建树、自底向上替换，
这类问题从根上没有了。

用法：
    python3 scripts/build-diagram-langs.py            # 生成英文版
    python3 scripts/build-diagram-langs.py --dump     # 打印待译键的骨架
"""

import argparse
import html
import re
import sys
from html.parser import HTMLParser
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from diagram_i18n import LABELS, PROSE  # noqa: E402

ROOT = Path(__file__).resolve().parent.parent
SRC = ROOT / "docs" / "certificate-lifecycle.html"
DST = ROOT / "docs" / "certificate-lifecycle.en.html"

CJK = re.compile(r"[\u4e00-\u9fff]")

TABLE = {**LABELS, **PROSE}

VOID = {"area", "base", "br", "col", "embed", "hr", "img", "input",
        "link", "meta", "param", "source", "track", "wbr"}

# 整棵子树都不翻译的：样式表和脚本里的中文是注释，不是内容。
SKIP_SUBTREE = {"style", "script"}

# 属性里的文案
TRANSLATABLE_ATTRS = ("aria-label", "title", "alt")

# 只有这些标签才可能是"一段文案"。**白名单，不是黑名单。**
#
# 先写过一版黑名单（列出容器），结果 `html`/`head`/`body`/`svg`/`nav`
# 全漏了过去 —— 它们的直接孩子里没有块级标签，于是被当成一段文案查表，
# 而那段"文案"是整个文档拼起来的字符串。真正危险的不是查不到，
# 是万一查到了：替换会把整棵子树抹掉。
#
# 白名单的失败方向是安全的：没列进来的标签不翻译，最坏结果是漏译，
# 而漏译会被最后那道"渲染文本里还有中文吗"的检查抓住。
TEXT_UNITS = {
    "title", "p", "li", "td", "th", "caption", "h1", "h2", "h3", "h4",
    "h5", "h6", "summary", "button", "a", "strong", "em", "b", "i",
    "code", "span", "div", "text", "label", "figcaption", "dt", "dd",
    "option", "blockquote",
}

# 纯行内标签。它们的内容注定是某段文案的一部分（"必须写 <code>X</code>。"），
# 单独查表只会得到一堆碎片，所以它们自己永远不是一个翻译单元。
INLINE_ONLY = {"strong", "em", "b", "i", "code", "small", "u", "sub", "sup",
               "mark", "kbd", "samp", "var", "abbr", "cite", "q", "time",
               # <br/> 也要算进来：否则"文本 + <br/> + 文本"的 div 会被判成
               # 布局容器而不翻译，页脚那块整段留在中文里。
               "br", "wbr"}

# 块级标签：孩子里只要有这些，这个元素就是容器而不是文案，一律不查表。
BLOCKY = {
    "div", "p", "section", "table", "thead", "tbody", "tr", "ul", "ol",
    "h1", "h2", "h3", "h4", "h5", "h6", "header", "footer", "nav", "svg",
    "figure", "caption", "blockquote", "details", "main", "article",
}

missing: dict[str, str] = {}


def plain(s: str) -> str:
    """把一段带标签的 HTML 压成纯文本并折叠空白 —— 查表用的键。"""
    return re.sub(r"\s+", " ", html.unescape(re.sub(r"<[^>]+>", "", s))).strip()


# ── 建树 ────────────────────────────────────────────────────────────────────

class Node:
    __slots__ = ("tag", "raw_name", "raw_open", "children", "parent",
                 "text", "kind", "self_closed")

    def __init__(self, tag, raw_open="", kind="elem", text=""):
        self.tag = tag
        # 标签名按**原样**保留。HTMLParser 会把它小写化，而在 SVG 里
        # 标签名是大小写敏感的：`</foreignObject>` 写成 `</foreignobject>`
        # 会让 Chrome 报标签不匹配，整张图不渲染。
        m = re.match(r"<\s*([^\s/>]+)", raw_open)
        self.raw_name = m.group(1) if m else tag
        self.raw_open = raw_open
        self.children: list[Node] = []
        self.parent = None
        self.kind = kind          # elem | text | comment | decl
        self.text = text
        # 形如 <path .../> 的元素。必须单独记：它的 raw_open 里已经带了斜杠，
        # 序列化时再补一个 </path> 会让 SVG 变成非法 XML，
        # Chrome 会直接报 "Opening and ending tag mismatch" 并且不渲染。
        self.self_closed = False


class Builder(HTMLParser):
    def __init__(self):
        super().__init__(convert_charrefs=False)
        self.root = Node("#root")
        self.stack = [self.root]

    def _add(self, n: Node) -> Node:
        n.parent = self.stack[-1]
        self.stack[-1].children.append(n)
        return n

    def handle_starttag(self, tag, attrs):
        raw = self.get_starttag_text() or f"<{tag}>"
        n = self._add(Node(tag, raw_open=raw))
        if tag not in VOID:
            self.stack.append(n)

    def handle_startendtag(self, tag, attrs):
        raw = self.get_starttag_text() or f"<{tag}/>"
        n = self._add(Node(tag, raw_open=raw))  # 自闭合，不进栈
        n.self_closed = True

    def handle_endtag(self, tag):
        for i in range(len(self.stack) - 1, 0, -1):
            if self.stack[i].tag == tag:
                del self.stack[i:]
                return

    def handle_data(self, data):
        self._add(Node("#text", kind="text", text=data))

    # convert_charrefs=False 时，&gt; 这类实体不走 handle_data，而是单独回调。
    # 不接住它们，序列化时会被静默丢掉 —— `&gt;30%` 变成 `30%`，
    # 图上的文字就错了，而且错得很安静。
    def handle_entityref(self, name):
        self._add(Node("#text", kind="text", text=f"&{name};"))

    def handle_charref(self, name):
        self._add(Node("#text", kind="text", text=f"&#{name};"))

    def handle_comment(self, data):
        self._add(Node("#comment", kind="comment", text=data))

    def handle_decl(self, decl):
        self._add(Node("#decl", kind="decl", text=decl))

    def handle_pi(self, data):
        self._add(Node("#pi", kind="decl", text=data))


def parse(doc: str) -> Node:
    b = Builder()
    b.feed(doc)
    b.close()
    return b.root


# ── 翻译 ────────────────────────────────────────────────────────────────────

def inner_text(n: Node) -> str:
    out = []
    for c in n.children:
        if c.kind == "text":
            out.append(c.text)
        elif c.kind == "elem":
            out.append(inner_text(c))
    return "".join(out)


def inner_html(n: Node) -> str:
    return "".join(serialize(c) for c in n.children)


def lookup(text: str, where: str) -> str | None:
    key = plain(text)
    if not key or not CJK.search(key):
        return None
    if key in TABLE:
        return TABLE[key]
    missing.setdefault(key, where)
    return None


def has_element_child(n: Node) -> bool:
    """div 是不是布局容器。

    div 在这个页面里既当文案（`<div class="eyebrow">`）又当布局
    （`.legend`、`.badges`、`footer .row`）。布局容器整块查表即使命中也是错的：
    它的孩子是带图标/色块的 span，整块替换会把那些元素抹掉。

    判据是"有没有非纯行内的元素孩子"—— 纯文字或只带 `<b>`/`<code>` 的 div
    仍然是文案。
    """
    return any(c.kind == "elem" and c.tag not in INLINE_ONLY for c in n.children)


def translate(n: Node) -> None:
    """自顶向下翻译。

    顺序很重要：父元素先试。命中就整块替换，内部的 `<b>`/`<code>` 这些强调
    随英文一起写进译文里 —— 它们不该被当成独立的翻译单元。

    没命中才往下走。这一点必须清楚：**父元素没命中不等于子元素不用翻**。
    `<div class="legend">` 整体不是一句文案，但它里面的每个 `<span>` 是 ——
    如果因为父元素没命中就把子元素也压掉，图例会整块留在中文里。

    真正需要压制的只有纯行内碎片（`<b>`、`<code>` 之类），那是 INLINE_ONLY
    的职责，不需要再传一个状态。
    """
    if n.kind != "elem" or n.tag in SKIP_SUBTREE:
        return

    # 1) 图里的 <text>
    if n.tag == "text":
        got = lookup(inner_text(n), "<text>")
        if got is not None:
            replace_children(n, got)
        return

    # 2) foreignObject 里的 div：按 br / span 切段，逐段查表。
    #    不能整块查，因为一块里往往有几行独立的话。
    if n.tag == "div" and any(a == "class" and "fo" in v for a, v in attrs_of(n)):
        translate_fo(n)
        return

    candidate = (
        n.tag in TEXT_UNITS
        and n.tag not in INLINE_ONLY
        and not any(c.kind == "elem" and c.tag in BLOCKY for c in n.children)
        and not (n.tag == "div" and has_element_child(n))
    )

    if candidate:
        got = lookup(inner_html(n), f"<{n.tag}>")
        if got is not None:
            replace_children(n, got)
            return

    for c in n.children:
        translate(c)


def attrs_of(n: Node) -> list[tuple[str, str]]:
    return re.findall(r'([a-zA-Z-]+)\s*=\s*"([^"]*)"', n.raw_open)


def replace_children(n: Node, raw_html: str) -> None:
    """把元素的子节点换成一段原样输出的 HTML。"""
    node = Node("#raw", kind="text", text=raw_html)
    node.parent = n
    n.children = [node]


STRUCTURAL_TAGS = {"span", "br"}


def translate_fo(n: Node) -> None:
    """foreignObject 的内部：按结构性标签切段。

    `<div class="fo">A<b>B</b><br/>C<span class="s">D</span></div>` 要切成
    "A<b>B</b>"、"C"、"D" 三段分别查表 —— 整块查的话键是 "A B C D"，
    和表里任何一条都对不上。
    """
    out: list[Node] = []
    run: list[Node] = []

    def flush():
        if not run:
            return
        got = lookup("".join(serialize(c) for c in run), "foreignObject")
        if got is not None:
            node = Node("#raw", kind="text", text=got)
            out.append(node)
        else:
            out.extend(run)
        run.clear()

    for c in n.children:
        if c.kind == "elem" and c.tag in STRUCTURAL_TAGS:
            flush()
            if c.tag == "span":
                # 先查整段，没命中再往下。顺序反了的话，里面的 <a> 会先被
                # 翻译成英文，整段的键就对不上了（"挑战回环的时序见 图 ⑤"
                # 会变成 "挑战回环的时序见 diagram ⑤"）。
                got = lookup(inner_html(c), "foreignObject span")
                if got is not None:
                    replace_children(c, got)
                else:
                    for gc in c.children:
                        translate(gc)
            out.append(c)
        else:
            run.append(c)
    flush()

    for c in out:
        c.parent = n
    n.children = out


def translate_attrs(n: Node) -> None:
    if n.kind != "elem":
        for c in n.children:
            translate_attrs(c)
        return
    for name in TRANSLATABLE_ATTRS:
        m = re.search(rf'{name}="([^"]*)"', n.raw_open)
        if not m:
            continue
        got = lookup(m.group(1), f"@{name}")
        if got is not None:
            n.raw_open = n.raw_open[:m.start(1)] + got + n.raw_open[m.end(1):]
    for c in n.children:
        translate_attrs(c)


# ── 序列化 ──────────────────────────────────────────────────────────────────

def serialize(n: Node) -> str:
    if n.kind == "text":
        return n.text
    if n.kind == "comment":
        return f"<!--{n.text}-->"
    if n.kind == "decl":
        return f"<!{n.text}>"
    if n.tag == "#root":
        return "".join(serialize(c) for c in n.children)
    if n.tag in VOID or n.self_closed:
        return n.raw_open
    return n.raw_open + "".join(serialize(c) for c in n.children) + f"</{n.raw_name}>"


# ── 入口 ────────────────────────────────────────────────────────────────────

def roundtrip_check(doc: str) -> None:
    """parse → serialize 必须与原文件逐字节一致。

    这是"序列化器会不会弄坏文档"的唯一硬保证。少了它，一个像
    "自闭合标签又补了结束标签"这样的 bug 会安静地把英文页面变成
    Chrome 的错误页 —— 而尺寸检查不会发现，因为它只量盒子。
    """
    again = serialize(parse(doc))
    if again == doc:
        return
    for i, (a, b) in enumerate(zip(doc, again)):
        if a != b:
            print(f"✗ 序列化器不是无损的，第一处差异在第 {i} 字节：\n"
                  f"  原: {doc[max(0,i-60):i+60]!r}\n"
                  f"  新: {again[max(0,i-60):i+60]!r}")
            sys.exit(1)
    sys.exit(f"✗ 序列化器改变了文档长度：{len(doc)} → {len(again)}")


# 生成产物开头的横幅。手改这个文件会在下一次 `make diagrams` 时被覆盖，
# 把这句话放在第一行比写在 README 里有用。
GENERATED_BANNER = (
    "<!-- Generated by scripts/build-diagram-langs.py from "
    "docs/certificate-lifecycle.html. Do not edit by hand:\n"
    "     edit the Chinese source, or the translation table "
    "scripts/diagram_i18n.py, then run `make diagrams`. -->"
)

# 语言切换链接。这是唯一一条不走翻译表的替换 —— 因为它翻的不是文案，
# 而是"链接指向哪一边"：中文页指向英文页，英文页指向中文页。
# 用翻译表表达不了，因为键必须是含中文的串，而 "English" 不含中文。
LANG_SWITCH = re.compile(
    r'(<a class="langswitch" href=")certificate-lifecycle\.en\.html("[^>]*>)English(<)')


def switch_lang(m: re.Match) -> str:
    return m.group(1) + "certificate-lifecycle.html" + m.group(2) + "中文" + m.group(3)


def build() -> str:
    doc = SRC.read_text(encoding="utf-8")
    roundtrip_check(doc)
    root = parse(doc)
    translate(root)
    translate_attrs(root)
    out = serialize(root)
    out, n = LANG_SWITCH.subn(switch_lang, out)
    if n != 1:
        sys.exit(f"✗ 语言切换链接应当恰好匹配 1 处，实际 {n} 处 —— "
                 f"中文页头部的 langswitch 锚点被改了？")
    return out.replace("<!DOCTYPE html>", "<!DOCTYPE html>\n" + GENERATED_BANNER, 1)


def rendered_text(doc: str) -> str:
    """只看真正会渲染出来的文本（去掉注释、样式、脚本、语言切换链接）。"""
    body = re.sub(r"<!--.*?-->", "", doc, flags=re.S)
    body = re.sub(r"<style\b.*?</style>", "", body, flags=re.S)
    body = re.sub(r"<script\b.*?</script>", "", body, flags=re.S)
    # 语言切换链接在英文页里就该是中文（"中文"）—— 它是入口，不是漏译。
    body = re.sub(r'<a class="langswitch".*?</a>', "", body, flags=re.S)
    return body


def dump() -> None:
    root = parse(SRC.read_text(encoding="utf-8"))
    translate(root)
    translate_attrs(root)
    if not missing:
        print("# 没有缺的，翻译表是完整的")
        return
    print(f"# {len(missing)} 条待译，按出现顺序：\n")
    for key, where in missing.items():
        print(f"    {key!r}:")
        print('        "",  # ' + where)


def main() -> None:
    doc = build()

    if missing:
        print(f"✗ 有 {len(missing)} 条中文没有英文对照"
              f"（补进 scripts/diagram_i18n.py）:\n")
        for key, where in list(missing.items())[:80]:
            print(f"  [{where}] {key[:90]}")
        if len(missing) > 80:
            print(f"  … 还有 {len(missing) - 80} 条")
        sys.exit(1)

    left = sorted({h.strip() for h in re.findall(r">([^<]*[\u4e00-\u9fff][^<]*)<",
                                                 rendered_text(doc)) if h.strip()})
    if left:
        print(f"✗ 渲染文本里还剩 {len(left)} 处中文:\n")
        for s in left[:40]:
            print(f"  {s[:90]}")
        if len(left) > 40:
            print(f"  … 还有 {len(left) - 40} 处")
        sys.exit(1)

    DST.write_text(doc, encoding="utf-8")
    print(f"✓ 写入 {DST.relative_to(ROOT)}（{len(doc)} 字节，渲染文本无中文残留）")


if __name__ == "__main__":
    ap = argparse.ArgumentParser()
    ap.add_argument("--dump", action="store_true",
                    help="打印待译键的骨架，用于填 scripts/diagram_i18n.py")
    args = ap.parse_args()
    dump() if args.dump else main()
