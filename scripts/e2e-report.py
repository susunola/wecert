#!/usr/bin/env python3
"""Render the end-to-end run into one HTML page.

Input is machine-readable on purpose: `internal/acme/e2e_dns_test.go` writes the cases it ran (with
their evidence) as JSON, `scripts/e2e.sh` adds the other two suites, and this turns both into a
report. Nothing here re-states a result the run did not produce -- if a case did not run, it appears
in the "not run" section with the reason and the command that would run it, rather than being
omitted or, worse, shown as passing.

Same visual language as docs/lifecycle-acceptance-run-*.html: paper background, serif body, sans
headings, print-friendly, no external assets.

Usage: e2e-report.py --go-report FILE --extras FILE --out FILE
"""

import argparse
import html
import json
from datetime import datetime
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent


def esc(s):
    return html.escape(str(s), quote=True)


def badge(verdict):
    kind = {
        "pass": "pass",
        "fail": "fail",
        "needs-credentials": "skip",
        "not-possible-on-this-host": "skip",
    }.get(verdict, "skip")
    label = {
        "pass": "通过",
        "fail": "失败",
        "needs-credentials": "需要凭证",
        "not-possible-on-this-host": "本机无法运行",
    }.get(verdict, verdict)
    return f'<span class="badge {kind}">{esc(label)}</span>'


def seconds(ns):
    if isinstance(ns, str):
        return ns
    return f"{ns / 1e9:.2f}s"


def summarise_dns(queries):
    """Group the authority's query log: name + type -> count, per transport."""
    seen = {}
    for q in queries:
        parts = q.split(" ")
        if len(parts) != 3:
            continue
        proto, name, qtype = parts
        key = (name, qtype)
        entry = seen.setdefault(key, {"udp": 0, "tcp": 0})
        entry[proto] = entry.get(proto, 0) + 1
    return sorted(seen.items(), key=lambda kv: (-(kv[1]["udp"] + kv[1]["tcp"]), kv[0]))


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--go-report", required=True)
    ap.add_argument("--extras", required=True)
    ap.add_argument("--out", required=True)
    args = ap.parse_args()

    rep = json.loads(Path(args.go_report).read_text())
    extras = json.loads(Path(args.extras).read_text())

    cases = rep.get("cases", [])
    not_run = rep.get("not_run", [])
    passed = sum(1 for c in cases if c.get("verdict") == "pass")
    failed = sum(1 for c in cases if c.get("verdict") != "pass")
    suites = extras.get("suites", [])
    version = rep.get("versions", {})

    started = rep.get("started", "")
    finished = rep.get("finished", "")
    try:
        began = datetime.fromisoformat(started.replace("Z", "+00:00")).strftime("%Y-%m-%d %H:%M UTC")
    except Exception:
        began = started

    rows = []
    for c in cases:
        ev = "".join(f"<li>{esc(e)}</li>" for e in c.get("evidence", []))
        rows.append(f"""      <div class="card {'good' if c.get('verdict') == 'pass' else 'bad'}">
        <div class="t"><span class="n">{esc(c.get('name'))}</span>{badge(c.get('verdict'))}<span class="d">{seconds(c.get('duration_ns', 0))}</span></div>
        <p class="what">{esc(c.get('what'))}</p>
        {f'<ul class="ev">{ev}</ul>' if ev else ''}
      </div>""")

    suite_rows = "".join(
        f"""      <tr><td class="mono">{esc(s['name'])}</td><td>{badge(s['verdict'])}</td>"""
        f"""<td class="num">{s['seconds']}s</td><td class="muted">{esc(s['what'])}</td></tr>"""
        for s in suites
    )

    dns_rows = "".join(
        f"""      <tr><td class="mono">{esc(name)}</td><td class="mono">{esc(qtype)}</td>"""
        f"""<td class="num">{counts.get('udp', 0)}</td><td class="num">{counts.get('tcp', 0)}</td></tr>"""
        for (name, qtype), counts in summarise_dns(rep.get("dns_queries", []))[:24]
    )

    peak_rows = "".join(
        f'<li><span class="mono">{esc(k)}</span> 同时存在过 <b>{v}</b> 个值</li>'
        for k, v in rep.get("peak_txt", {}).items()
        if v > 1
    )

    not_run_rows = "".join(
        f"""      <div class="card warn">
        <div class="t"><span class="n">{esc(c.get('name'))}</span>{badge(c.get('verdict'))}</div>
        <p class="what">{esc(c.get('what'))}</p>
        <ul class="ev">{''.join(f'<li>{esc(e)}</li>' for e in c.get('evidence', []))}</ul>
      </div>"""
        for c in not_run
    )

    version_rows = "".join(
        f"""      <tr><td class="mono">{esc(k)}</td><td>{esc(v)}</td></tr>""" for k, v in version.items()
    )

    body = f"""<!DOCTYPE html>
<html lang="zh-CN">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>wecert 真实 E2E 实跑报告</title>
<style>
  :root {{
    --paper: #fbfaf7; --paper-2: #f4f2ec;
    --ink: #14161a; --ink-2: #43474e; --ink-3: #6b7079;
    --rule: #e0ddd3; --rule-2: #cec9bc;
    --accent: #0d5f5c;
    --pass: #14683f; --pass-soft: #e2f0e8;
    --fail: #a3231c; --fail-soft: #fbe6e4;
    --warn: #8a5a00; --warn-soft: #fbf0d8;
    --skip: #5f6570; --skip-soft: #eceae4;
    --code-bg: #f2f0e9;
    --mono: ui-monospace, SFMono-Regular, "SF Mono", Menlo, Consolas, monospace;
    --sans: system-ui, -apple-system, "Segoe UI", "Helvetica Neue", sans-serif;
    --serif: "Iowan Old Style", "Palatino Linotype", Palatino, Charter, Georgia, serif;
  }}
  * {{ box-sizing: border-box; }}
  body {{ margin: 0; background: var(--paper); color: var(--ink); font-family: var(--serif); font-size: 17px; line-height: 1.62; }}
  .wrap {{ max-width: 1080px; margin: 0 auto; padding: 0 24px 96px; }}
  header.masthead {{ border-bottom: 3px solid var(--ink); padding: 44px 0 20px; margin-bottom: 28px; }}
  .kicker {{ font-family: var(--sans); font-size: 12px; font-weight: 700; letter-spacing: .14em; text-transform: uppercase; color: var(--accent); margin: 0 0 10px; }}
  h1 {{ font-family: var(--sans); font-size: clamp(28px, 4.4vw, 42px); line-height: 1.14; letter-spacing: -0.015em; margin: 0 0 12px; }}
  .framing {{ font-size: 19px; color: var(--ink-2); max-width: 74ch; margin: 0 0 20px; }}
  .metabar {{ display: flex; flex-wrap: wrap; gap: 6px 22px; font-family: var(--sans); font-size: 13px; color: var(--ink-3); border-top: 1px solid var(--rule); padding-top: 14px; }}
  .metabar b {{ color: var(--ink); font-weight: 600; }}
  .strip {{ display: grid; grid-template-columns: repeat(auto-fit, minmax(158px, 1fr)); gap: 10px; margin: 0 0 34px; }}
  .stat {{ background: #fff; border: 1px solid var(--rule); border-left: 4px solid var(--rule-2); border-radius: 3px; padding: 12px 14px; }}
  .stat.ok {{ border-left-color: var(--pass); }} .stat.bad {{ border-left-color: var(--fail); }} .stat.mute {{ border-left-color: var(--skip); }}
  .stat .k {{ font-family: var(--sans); font-size: 11.5px; letter-spacing: .06em; text-transform: uppercase; color: var(--ink-3); }}
  .stat .v {{ font-family: var(--sans); font-size: 26px; font-weight: 650; letter-spacing: -0.02em; }}
  h2 {{ font-family: var(--sans); font-size: 22px; letter-spacing: -0.01em; margin: 44px 0 6px; padding-bottom: 8px; border-bottom: 2px solid var(--ink); }}
  h2 .zh {{ font-weight: 400; color: var(--ink-3); font-size: 15px; margin-left: 10px; }}
  p.lede {{ color: var(--ink-2); max-width: 80ch; }}
  .card {{ background: #fff; border: 1px solid var(--rule); border-radius: 3px; padding: 14px 16px; margin: 10px 0; }}
  .card.good {{ border-left: 4px solid var(--pass); }} .card.bad {{ border-left: 4px solid var(--fail); }} .card.warn {{ border-left: 4px solid var(--warn); }}
  .card .t {{ display: flex; align-items: center; gap: 10px; flex-wrap: wrap; }}
  .card .n {{ font-family: var(--mono); font-size: 14.5px; font-weight: 600; }}
  .card .d {{ margin-left: auto; font-family: var(--sans); font-size: 12.5px; color: var(--ink-3); }}
  .card .what {{ margin: 6px 0 0; color: var(--ink-2); font-size: 15.5px; }}
  ul.ev {{ margin: 8px 0 0; padding-left: 20px; font-family: var(--mono); font-size: 13px; color: var(--ink-2); }}
  ul.ev li {{ margin: 2px 0; }}
  .badge {{ font-family: var(--sans); font-size: 11.5px; font-weight: 700; letter-spacing: .04em; padding: 2px 8px; border-radius: 999px; }}
  .badge.pass {{ color: var(--pass); background: var(--pass-soft); }}
  .badge.fail {{ color: var(--fail); background: var(--fail-soft); }}
  .badge.skip {{ color: var(--skip); background: var(--skip-soft); }}
  .tablebox {{ overflow-x: auto; border: 1px solid var(--rule); border-radius: 3px; background: #fff; }}
  table {{ border-collapse: collapse; width: 100%; font-size: 14.5px; }}
  th, td {{ text-align: left; padding: 9px 12px; border-bottom: 1px solid var(--rule); vertical-align: top; }}
  th {{ font-family: var(--sans); font-size: 12px; text-transform: uppercase; letter-spacing: .06em; color: var(--ink-3); background: var(--paper-2); }}
  tr:last-child td {{ border-bottom: none; }}
  td.num {{ text-align: right; font-family: var(--mono); }}
  .mono {{ font-family: var(--mono); font-size: 13.5px; }}
  .muted {{ color: var(--ink-3); font-size: 14px; }}
  .note {{ background: var(--warn-soft); border: 1px solid #e8d9ae; border-radius: 3px; padding: 12px 14px; margin: 14px 0; font-size: 15.5px; }}
  code {{ font-family: var(--mono); font-size: 13.5px; background: var(--code-bg); padding: 1px 5px; border-radius: 3px; }}
  footer {{ margin-top: 56px; border-top: 1px solid var(--rule); padding-top: 16px; font-family: var(--sans); font-size: 13px; color: var(--ink-3); }}
  @media print {{ body {{ background: #fff; }} h2 {{ break-after: avoid; }} .card {{ break-inside: avoid; }} }}
</style>
</head>
<body>
<div class="wrap">
  <header class="masthead">
    <p class="kicker">wecert · end-to-end run</p>
    <h1>真实 E2E 实跑报告</h1>
    <p class="framing">不是单元测试的汇总，而是一轮可复现的端到端实跑：真实的 ACME 服务端、真实的权威 DNS 服务（53 端口）、真实的 DNS-01 记录写入与回读、真实签发的证书；以及这套环境里<strong>跑不了</strong>的部分，和它们各自需要什么才能跑。</p>
    <div class="metabar">
      <span><b>开始</b> {esc(began)}</span>
      <span><b>用例</b> {passed} 通过 / {failed} 失败</span>
      <span><b>未跑</b> {len(not_run)} 项（附原因与命令）</span>
      <span><b>宿主</b> {esc(extras.get('host', ''))}</span>
    </div>
  </header>

  <div class="strip">
    <div class="stat {'ok' if failed == 0 else 'bad'}"><div class="k">Cases</div><div class="v">{passed}/{len(cases)}</div></div>
    <div class="stat {'ok' if all(s['verdict'] == 'pass' for s in suites) else 'bad'}"><div class="k">Suites</div><div class="v">{sum(1 for s in suites if s['verdict'] == 'pass')}/{len(suites)}</div></div>
    <div class="stat mute"><div class="k">DNS queries served</div><div class="v">{len(rep.get('dns_queries', []))}</div></div>
    <div class="stat mute"><div class="k">Not run</div><div class="v">{len(not_run)}</div></div>
  </div>

  <h2>怎么测的<span class="zh">what is real, and what is not</span></h2>
  <p class="lede">这一轮里每一个"真实"都写明了边界。评审时最该看的是下面这张表：哪些部件真的在跑，哪些是替身，以及替身各自对应到哪条验收路径。</p>
  <div class="tablebox"><table>
    <tr><th>部件</th><th>这一轮实际用的是什么</th></tr>
{version_rows}
  </table></div>
  <div class="note">
    <b>关于 CA 校验（这一轮最需要看清的边界）。</b>{esc(rep.get('validation_note', ''))}
  </div>

  <h2>套件结果<span class="zh">suites</span></h2>
  <div class="tablebox"><table>
    <tr><th>套件</th><th>结论</th><th>耗时</th><th>覆盖什么</th></tr>
{suite_rows}
  </table></div>

  <h2>用例结果<span class="zh">cases</span></h2>
  <p class="lede">每条用例都是对一个可再生故障的断言，不是"跑通了"。失败会让整轮退出码非零，所以这份报告不可能在红的运行上显示成绿的。</p>
{''.join(rows)}

  <h2>DNS 证据<span class="zh">what the authority was actually asked</span></h2>
  <p class="lede">这是权威 DNS 服务器收到的全部查询的汇总。UDP 列来自 wecert 自己的传播检查，TCP 列来自校验方（本机降级模式下为 0）。</p>
  <div class="tablebox"><table>
    <tr><th>名字</th><th>类型</th><th>UDP</th><th>TCP</th></tr>
{dns_rows}
  </table></div>
  {f'<div class="note"><b>共享名证据：</b><ul>{peak_rows}</ul>通配符与 apex 共用同一个 <code>_acme-challenge</code> 名，两个值必须同时在场。</div>' if peak_rows else ''}

  <h2>未跑的部分<span class="zh">not run, and why</span></h2>
  <p class="lede">这几项属于"需要真实云凭证或真实域名"，本环境没有，所以它们<strong>没有</strong>被算进上面的通过数。每条都给出可直接执行的命令。</p>
{not_run_rows}

  <footer>
    生成方式：<code>make e2e</code>（<code>scripts/e2e.sh</code> → <code>scripts/e2e-report.py</code>）。
    原始数据：<code>dist/e2e-go.json</code>（用例与 DNS 查询日志）、<code>dist/e2e-extras.json</code>（套件与宿主）。
    报告只呈现这次运行真实产生的结论。
  </footer>
</div>
</body>
</html>
"""

    out = ROOT / args.out
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(body, encoding="utf-8")
    print(f"wrote {out} ({len(body)} bytes)")


if __name__ == "__main__":
    main()
