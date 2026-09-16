#!/usr/bin/env python3
"""Generate the English page from the Chinese one.

The Chinese `docs/certificate-lifecycle.html` is the single source of truth; the
English page is a derived artifact. This is done instead of maintaining two
hand-written files because two hand-written files inevitably drift, and the
symptom of that drift is "a Chinese paragraph left inside the English version" —
the kind of problem nobody goes looking for.

After building, the **rendered text is scanned again**, and any Chinese left over
fails the build outright. So a missed translation cannot slip through quietly:
either the translation table gets completed, or the build goes red.

## Why an HTML parser instead of regex

The first version used a regex to find the "innermost block element". It is bound
to fail on nested `<div>`s: a regex cannot pair nested tags, so
`<div class="grid2"><div>…</div>…</div>` matches through the first `</div>` and
stops there, skipping that entire block — and worse, the skipped content never
even appears in the "to-translate list", because that list came out of the same
traversal.

The result is "the build passes but the page has Chinese mixed in". Moving to
html.parser to build a tree and substituting bottom-up removes this class of
problem at the root.

Usage:
    python3 scripts/build-diagram-langs.py            # build the English page
    python3 scripts/build-diagram-langs.py --dump     # print the skeleton of pending keys
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

# Subtrees that are never translated: the Chinese in stylesheets and scripts is
# comments, not content.
SKIP_SUBTREE = {"style", "script"}

# Copy carried in attributes
TRANSLATABLE_ATTRS = ("aria-label", "title", "alt")

# Only these tags can be "a piece of copy". **A whitelist, not a blacklist.**
#
# A blacklist version (listing containers) was written first, and it let
# `html`/`head`/`body`/`svg`/`nav` all slip through — none of them has a block
# tag among its direct children, so each was treated as one piece of copy, and
# that "copy" was the whole document concatenated into a single string. The real
# danger is not a failed lookup but a successful one: the replacement would wipe
# out the entire subtree.
#
# A whitelist fails in the safe direction: tags that are not listed are not
# translated, so the worst case is a missed translation — and a missed
# translation is caught by the final "is there any Chinese left in the rendered
# text?" check.
TEXT_UNITS = {
    "title", "p", "li", "td", "th", "caption", "h1", "h2", "h3", "h4",
    "h5", "h6", "summary", "button", "a", "strong", "em", "b", "i",
    "code", "span", "div", "text", "label", "figcaption", "dt", "dd",
    "option", "blockquote",
}

# Purely inline tags. Their content is by definition part of some piece of copy
# ("must write <code>X</code>."), and looking them up on their own only yields a
# pile of fragments, so they are never a translation unit by themselves.
INLINE_ONLY = {"strong", "em", "b", "i", "code", "small", "u", "sub", "sup",
               "mark", "kbd", "samp", "var", "abbr", "cite", "q", "time",
               # <br/> counts too: otherwise a div shaped "text + <br/> + text"
               # is judged a layout container and left untranslated, keeping that
               # whole footer block in Chinese.
               "br", "wbr"}

# Block tags: if any of these is among the children, the element is a container
# rather than copy, and is never looked up.
BLOCKY = {
    "div", "p", "section", "table", "thead", "tbody", "tr", "ul", "ol",
    "h1", "h2", "h3", "h4", "h5", "h6", "header", "footer", "nav", "svg",
    "figure", "caption", "blockquote", "details", "main", "article",
}

missing: dict[str, str] = {}


def plain(s: str) -> str:
    """Flatten a tagged HTML fragment to plain text with whitespace collapsed — the lookup key."""
    return re.sub(r"\s+", " ", html.unescape(re.sub(r"<[^>]+>", "", s))).strip()


# ── tree building ───────────────────────────────────────────────────────────

class Node:
    __slots__ = ("tag", "raw_name", "raw_open", "children", "parent",
                 "text", "kind", "self_closed")

    def __init__(self, tag, raw_open="", kind="elem", text=""):
        self.tag = tag
        # The tag name is preserved **as written**. HTMLParser lowercases it, and
        # in SVG tag names are case-sensitive: writing `</foreignObject>` as
        # `</foreignobject>` makes Chrome report a tag mismatch and the whole
        # diagram fails to render.
        m = re.match(r"<\s*([^\s/>]+)", raw_open)
        self.raw_name = m.group(1) if m else tag
        self.raw_open = raw_open
        self.children: list[Node] = []
        self.parent = None
        self.kind = kind          # elem | text | comment | decl
        self.text = text
        # Elements shaped like <path .../>. This must be tracked separately: its
        # raw_open already carries the slash, and adding another </path> at
        # serialization time makes the SVG invalid XML, so Chrome reports
        # "Opening and ending tag mismatch" and does not render it.
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
        n = self._add(Node(tag, raw_open=raw))  # self-closing, do not push onto the stack
        n.self_closed = True

    def handle_endtag(self, tag):
        for i in range(len(self.stack) - 1, 0, -1):
            if self.stack[i].tag == tag:
                del self.stack[i:]
                return

    def handle_data(self, data):
        self._add(Node("#text", kind="text", text=data))

    # With convert_charrefs=False, entities like &gt; do not go through
    # handle_data but arrive as their own callback. If they are not captured,
    # serialization silently drops them — `&gt;30%` becomes `30%`, so the text on
    # the diagram is wrong, and it is wrong very quietly.
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


# ── translation ─────────────────────────────────────────────────────────────

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
    """Is this div a layout container?

    In this page a div serves both as copy (`<div class="eyebrow">`) and as layout
    (`.legend`, `.badges`, `footer .row`). Looking a layout container up as a
    whole is wrong even when it hits: its children are spans carrying icons or
    color chips, and replacing the whole block would erase those elements.

    The test is "does it have an element child that is not purely inline" — a div
    holding only text, or only `<b>`/`<code>`, is still copy.
    """
    return any(c.kind == "elem" and c.tag not in INLINE_ONLY for c in n.children)


def translate(n: Node) -> None:
    """Translate top-down.

    Order matters: the parent is tried first. On a hit the whole block is
    replaced, and the inline emphasis inside it (`<b>`/`<code>`) is written into
    the English text along with it — those must not be treated as independent
    translation units.

    Only on a miss do we descend. This point has to be clear: **a parent miss does
    not mean the children need no translation**. `<div class="legend">` as a whole
    is not a piece of copy, but every `<span>` inside it is — suppressing the
    children just because the parent missed would leave the whole legend in
    Chinese.

    The only thing that genuinely needs suppressing is purely inline fragments
    (`<b>`, `<code>` and friends), and that is INLINE_ONLY's job; no extra state
    has to be threaded through.
    """
    if n.kind != "elem" or n.tag in SKIP_SUBTREE:
        return

    # 1) <text> inside the diagram
    if n.tag == "text":
        got = lookup(inner_text(n), "<text>")
        if got is not None:
            replace_children(n, got)
        return

    # 2) divs inside a foreignObject: split on br / span and look up each
    #    segment. The whole block cannot be looked up because one block usually
    #    holds several independent lines of text.
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
    """Replace the element's children with a snippet of HTML emitted verbatim."""
    node = Node("#raw", kind="text", text=raw_html)
    node.parent = n
    n.children = [node]


STRUCTURAL_TAGS = {"span", "br"}


def translate_fo(n: Node) -> None:
    """The inside of a foreignObject: split into segments on structural tags.

    `<div class="fo">A<b>B</b><br/>C<span class="s">D</span></div>` has to be cut
    into the three segments "A<b>B</b>", "C" and "D" and looked up separately —
    looked up as a whole the key would be "A B C D", which matches nothing in the
    table.
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
                # Look up the whole segment first, and descend only on a miss.
                # With the order reversed, an inner <a> would be translated to
                # English first and the whole-segment key would no longer match
                # the table: the inner fragment gets replaced while the outer key
                # still expects the original Chinese wording.
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


# ── serialization ───────────────────────────────────────────────────────────

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


# ── entry point ─────────────────────────────────────────────────────────────

def roundtrip_check(doc: str) -> None:
    """parse → serialize must reproduce the original file byte for byte.

    This is the only hard guarantee that the serializer does not corrupt the
    document. Without it, a bug like "self-closing tag also gets an end tag"
    would quietly turn the English page into a Chrome error page — and the size
    check would not notice, because it only measures boxes.
    """
    again = serialize(parse(doc))
    if again == doc:
        return
    for i, (a, b) in enumerate(zip(doc, again)):
        if a != b:
            print(f"✗ serializer is not lossless; first difference at byte {i}:\n"
                  f"  old: {doc[max(0,i-60):i+60]!r}\n"
                  f"  new: {again[max(0,i-60):i+60]!r}")
            sys.exit(1)
    sys.exit(f"✗ serializer changed the document length: {len(doc)} → {len(again)}")


# The banner at the top of the generated artifact. Editing that file by hand is
# overwritten by the next `make diagrams`, and putting this sentence on the first
# line is more useful than writing it in the README.
GENERATED_BANNER = (
    "<!-- Generated by scripts/build-diagram-langs.py from "
    "docs/certificate-lifecycle.html. Do not edit by hand:\n"
    "     edit the Chinese source, or the translation table "
    "scripts/diagram_i18n.py, then run `make diagrams`. -->"
)

# The language switch link. This is the one substitution that does not go through
# the translation table — because what it translates is not copy but which side
# the link points at: the Chinese page points to the English page, and the English
# page points back to the Chinese one.
# The table cannot express this, because a key must be a string containing
# Chinese, and "English" contains none.
LANG_SWITCH = re.compile(
    r'(<a class="langswitch" href=")certificate-lifecycle\.en\.html("[^>]*>)English(<)')


def switch_lang(m: re.Match) -> str:
    # "\u4e2d\u6587" is the label shown on the English page (literally "Chinese"),
    # written as an escape so this source file stays free of CJK characters.
    return m.group(1) + "certificate-lifecycle.html" + m.group(2) + "\u4e2d\u6587" + m.group(3)


def build() -> str:
    doc = SRC.read_text(encoding="utf-8")
    roundtrip_check(doc)
    root = parse(doc)
    translate(root)
    translate_attrs(root)
    out = serialize(root)
    out, n = LANG_SWITCH.subn(switch_lang, out)
    if n != 1:
        sys.exit(f"✗ language switch link should match exactly 1 place, found {n} — "
                 f"was the langswitch anchor in the Chinese page header changed?")
    return out.replace("<!DOCTYPE html>", "<!DOCTYPE html>\n" + GENERATED_BANNER, 1)


def rendered_text(doc: str) -> str:
    """Keep only the text that actually renders (comments, styles, scripts and the language switch link removed)."""
    body = re.sub(r"<!--.*?-->", "", doc, flags=re.S)
    body = re.sub(r"<style\b.*?</style>", "", body, flags=re.S)
    body = re.sub(r"<script\b.*?</script>", "", body, flags=re.S)
    # The language switch link is supposed to be Chinese on the English page —
    # it is the entry point, not a missed translation.
    body = re.sub(r'<a class="langswitch".*?</a>', "", body, flags=re.S)
    return body


def dump() -> None:
    root = parse(SRC.read_text(encoding="utf-8"))
    translate(root)
    translate_attrs(root)
    if not missing:
        print("# nothing missing, the translation table is complete")
        return
    print(f"# {len(missing)} keys pending translation, in order of appearance:\n")
    for key, where in missing.items():
        print(f"    {key!r}:")
        print('        "",  # ' + where)


def main() -> None:
    doc = build()

    if missing:
        print(f"✗ {len(missing)} Chinese strings have no English counterpart"
              f" (add them to scripts/diagram_i18n.py):\n")
        for key, where in list(missing.items())[:80]:
            print(f"  [{where}] {key[:90]}")
        if len(missing) > 80:
            print(f"  … {len(missing) - 80} more")
        sys.exit(1)

    left = sorted({h.strip() for h in re.findall(r">([^<]*[\u4e00-\u9fff][^<]*)<",
                                                 rendered_text(doc)) if h.strip()})
    if left:
        print(f"✗ {len(left)} Chinese fragments remain in the rendered text:\n")
        for s in left[:40]:
            print(f"  {s[:90]}")
        if len(left) > 40:
            print(f"  … {len(left) - 40} more")
        sys.exit(1)

    DST.write_text(doc, encoding="utf-8")
    print(f"✓ wrote {DST.relative_to(ROOT)} ({len(doc)} bytes, no Chinese left in the rendered text)")


if __name__ == "__main__":
    ap = argparse.ArgumentParser()
    ap.add_argument("--dump", action="store_true",
                    help="print the skeleton of pending keys, for filling in scripts/diagram_i18n.py")
    args = ap.parse_args()
    dump() if args.dump else main()
