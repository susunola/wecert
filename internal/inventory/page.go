package inventory

import (
	"html/template"
	"io"
	"strconv"
	"strings"

	"github.com/susunola/wecert/internal/probe"
)

type pageView struct {
	Snapshot
	Accounts   []accountGroup
	ShowGroups bool
	UINCount   int
	// DesiredKnown is false when the desired-state document has never been read, so
	// the page can say that instead of presenting an empty revision as a fact.
	DesiredKnown bool
	// FrozenLabel is empty unless the document is frozen; a pointer to false must not
	// render as "frozen".
	FrozenLabel string
}

type accountGroup struct {
	UIN          string
	Count        int
	Certificates []Certificate
}

var pageTmpl = template.Must(template.New("status").Funcs(template.FuncMap{
	"join": strings.Join,
	"days": func(p *int) string {
		if p == nil {
			return "—"
		}
		return strconv.Itoa(*p) + "d"
	},
	"probe": func(p ProbeView) string {
		if !p.Enabled {
			return "Off"
		}
		if p.OK == nil {
			return "—"
		}
		if *p.OK {
			return "Match"
		}
		// "Could not dial it" and "dialled it and got the wrong certificate" are
		// different problems; the column says which one this is.
		for _, h := range p.Hosts {
			switch h.ProblemKind {
			case string(probe.ProblemUnreachable), string(probe.ProblemNoCertificate):
				return "Unreachable"
			}
		}
		return "Mismatch"
	},
	"probeClass": func(p ProbeView) string {
		// The column colour follows the same three-way split as the label: an
		// unreachable name is not a wrong certificate.
		if !p.Enabled || p.OK == nil {
			return "probe-off"
		}
		if *p.OK {
			return "probe-ok"
		}
		for _, h := range p.Hosts {
			switch h.ProblemKind {
			case string(probe.ProblemUnreachable), string(probe.ProblemNoCertificate):
				return "probe-warn"
			}
		}
		return "probe-bad"
	},
	"regions": func(list []string) string {
		if len(list) == 0 {
			return "—"
		}
		if len(list) == 1 {
			return regionLabel(list[0])
		}
		return regionLabel(list[0]) + " +" + strconv.Itoa(len(list)-1)
	},
	"bind":      bindLabel,
	"status":    statusLabel,
	"class":     statusClass,
	"names":     namesLine,
	"clb":       clbLine,
	"qblob":     queryBlob,
	"region":    regionLabel,
	"attention": isAttention,
}).Parse(pageHTML))

func countCLB(b Bindings) int {
	seen := map[string]struct{}{}
	for _, it := range b.Items {
		if it.LoadBalancerID == "" {
			continue
		}
		seen[it.LoadBalancerID] = struct{}{}
	}
	return len(seen)
}

func statusLabel(status string) string {
	switch status {
	case StatusWaitingManualBind:
		return "Waiting bind"
	case StatusPendingDeploy:
		return "Pending deploy"
	case StatusNotIssued:
		return "Not issued"
	case StatusStateUnreadable:
		return "State unreadable"
	case StatusProbeMismatch:
		return "Probe mismatch"
	case StatusProbeUnreachable:
		return "Probe unreachable"
	case StatusProbeUnknown:
		return "Probe unknown"
	case StatusFailing:
		return "Failing"
	case StatusExpiring:
		return "Expiring"
	case StatusBindingUnknown:
		return "Binding unknown"
	case StatusRateLimited:
		return "Rate limited"
	case StatusRevokePending:
		return "Revoke pending"
	case StatusFrozen:
		return "Frozen"
	case StatusOK:
		return "Healthy"
	default:
		return status
	}
}

// statusClass is the colour, which stays secondary to the token itself: an alert or a
// log line repeats the token, not the colour.
func statusClass(status string) string {
	switch status {
	case StatusOK:
		return "s-ok"
	case StatusWaitingManualBind, StatusRateLimited, StatusPendingDeploy,
		StatusProbeUnknown, StatusFrozen:
		return "s-wait"
	case StatusProbeMismatch, StatusProbeUnreachable, StatusFailing,
		StatusRevokePending, StatusStateUnreadable:
		return "s-danger"
	case StatusExpiring, StatusNotIssued:
		return "s-info"
	}
	return "s-mute"
}

func isAttention(status string) bool {
	switch status {
	case StatusWaitingManualBind, StatusPendingDeploy, StatusProbeMismatch,
		StatusProbeUnreachable, StatusProbeUnknown, StatusFailing,
		StatusBindingUnknown, StatusRateLimited, StatusRevokePending,
		StatusFrozen, StatusNotIssued, StatusStateUnreadable:
		return true
	}
	return false
}

func namesLine(c Certificate) string {
	if len(c.Domains) == 0 {
		return "—"
	}
	if len(c.Domains) == 1 {
		return c.Domains[0]
	}
	return c.Domains[0] + " +" + strconv.Itoa(len(c.Domains)-1)
}

func clbLine(c Certificate) string {
	if c.Status == StatusWaitingManualBind {
		return "—"
	}
	if c.Status == StatusBindingUnknown {
		return "Unknown"
	}
	seen := []string{}
	have := map[string]struct{}{}
	for _, it := range c.Bindings.Items {
		if it.LoadBalancerID == "" {
			continue
		}
		if _, ok := have[it.LoadBalancerID]; ok {
			continue
		}
		have[it.LoadBalancerID] = struct{}{}
		seen = append(seen, it.LoadBalancerID)
	}
	if len(seen) == 0 {
		return bindLabel(c.Bindings, c.Status)
	}
	line := seen[0]
	if len(seen) > 1 {
		line += " +" + strconv.Itoa(len(seen)-1)
	}
	return line
}

func bindLabel(b Bindings, status string) string {
	if status == StatusWaitingManualBind {
		return "waiting bind"
	}
	if b.Count == 0 {
		if b.Complete {
			return "none"
		}
		// A zero that is a lower bound, not an answer: the store cannot enumerate at
		// all, and a live task that finished without a region block did not either.
		// Both used to be printed as "none", which reads as "bound nowhere".
		return "unknown"
	}
	var line string
	if n := countCLB(b); n > 0 {
		line = strconv.Itoa(n) + " CLB / " + strconv.Itoa(b.Count) + " listeners"
	} else {
		line = strconv.Itoa(b.Count)
	}
	if !b.Complete {
		line = "≥" + line
	}
	return line
}

func regionLabel(region string) string {
	switch region {
	case "ap-guangzhou":
		return "Guangzhou"
	case "ap-shanghai":
		return "Shanghai"
	case "ap-beijing":
		return "Beijing"
	case "ap-singapore":
		return "Singapore"
	}
	return strings.TrimPrefix(region, "ap-")
}

func queryBlob(c Certificate) string {
	parts := []string{c.Name, c.UIN, c.Status, c.DeployedCertID}
	parts = append(parts, c.Domains...)
	for _, it := range c.Bindings.Items {
		parts = append(parts, it.Region, it.LoadBalancerID, it.ListenerID, it.SNIDomain)
	}
	return strings.ToLower(strings.Join(parts, " "))
}

func groupByUIN(certs []Certificate) []accountGroup {
	idx := map[string]int{}
	var groups []accountGroup
	for _, c := range certs {
		i, ok := idx[c.UIN]
		if !ok {
			i = len(groups)
			idx[c.UIN] = i
			groups = append(groups, accountGroup{UIN: c.UIN})
		}
		groups[i].Certificates = append(groups[i].Certificates, c)
		groups[i].Count++
	}
	return groups
}

const pageHTML = `<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>wecert inventory</title>
<style>
:root{
 color-scheme:dark;
 --bg:#0d1117; --panel:#12171f; --raised:#1a212b; --sunken:#0a0e13;
 --line:#232b36; --line-strong:#323b47;
 --fg:#e6edf3; --muted:#8b949e; --faint:#6e7681;
 --accent:#2fbfa8; --accent-fg:#04211d;
 --ok:63 185 80; --warn:210 153 34; --danger:248 81 73; --info:88 166 255; --neutral:139 148 158;
 --r:6px; --r-tag:4px;
}
:root[data-theme=light]{
 color-scheme:light;
 --bg:#fff; --panel:#f6f8fa; --raised:#eaeef2; --sunken:#f6f8fa;
 --line:#d0d7de; --line-strong:#afb8c1;
 --fg:#1f2328; --muted:#59636e; --faint:#818b98;
 --accent:#0f766e; --accent-fg:#fff;
 --ok:26 127 55; --warn:154 103 0; --danger:207 34 46; --info:9 105 218; --neutral:89 99 110;
}
*{box-sizing:border-box}
body{margin:0;background:var(--bg);color:var(--fg);
 font:13px/1.45 -apple-system,BlinkMacSystemFont,"Segoe UI",Roboto,Helvetica,Arial,sans-serif;
 -webkit-font-smoothing:antialiased}
.mono,.num,.statbar b,.plabel,.search,input{font-family:ui-monospace,SFMono-Regular,"SF Mono",Menlo,Consolas,"Liberation Mono",monospace}
.num,.statbar b,.plist .n{font-variant-numeric:tabular-nums}
.nowrap{white-space:nowrap}
.hidden{display:none!important}
.vh{position:absolute;width:1px;height:1px;margin:-1px;padding:0;overflow:hidden;clip:rect(0 0 0 0);white-space:nowrap;border:0}
:focus-visible{outline:2px solid var(--accent);outline-offset:1px;border-radius:var(--r-tag)}

.topbar{position:sticky;top:0;z-index:10;display:flex;align-items:center;gap:14px;
 padding:8px 16px;background:var(--bg);border-bottom:1px solid var(--line)}
.brand{display:flex;align-items:center;gap:8px;min-width:0}
.mark{width:8px;height:8px;border-radius:2px;background:var(--accent);flex:none}
.brand b{font-weight:650;letter-spacing:-.01em}
.brand span{color:var(--muted);font-size:12px}
.right{margin-left:auto;display:flex;align-items:center;gap:12px;flex:none}
.ro{font-size:10.5px;font-weight:600;letter-spacing:.08em;text-transform:uppercase;
 color:rgb(var(--ok));border:1px solid rgb(var(--ok) / .35);background:rgb(var(--ok) / .1);
 padding:1px 7px;border-radius:var(--r-tag)}
.stamp{color:var(--faint);font-size:11.5px}
.icon{appearance:none;width:26px;height:26px;display:grid;place-items:center;background:transparent;
 border:1px solid var(--line);border-radius:var(--r-tag);color:var(--muted);cursor:pointer;font-size:13px;line-height:1}
.icon:hover{color:var(--fg);border-color:var(--line-strong)}

.wrap{max-width:1360px;margin:0 auto;padding:14px 16px 40px}
.title{display:flex;align-items:baseline;gap:14px;flex-wrap:wrap;margin-bottom:10px}
h1{font-size:19px;font-weight:650;letter-spacing:-.01em;margin:0}
.title .src{margin:0 0 0 auto;display:flex;align-items:baseline;gap:8px;font-size:11.5px;color:var(--faint)}
.notice{margin:0 0 10px;padding:6px 10px;border-radius:var(--r-tag);font-size:12px;
 color:rgb(var(--warn));background:rgb(var(--warn) / .1);border:1px solid rgb(var(--warn) / .3)}

.statbar{display:flex;flex-wrap:wrap;align-items:baseline;gap:2px 0;padding:7px 0;
 border-top:1px solid var(--line);border-bottom:1px solid var(--line);margin-bottom:12px;font-size:11.5px;color:var(--muted)}
.statbar .st{display:inline-flex;align-items:baseline;gap:5px;white-space:nowrap;padding:0 10px}
.statbar .st:first-child{padding-left:0}
.statbar .st+.st{border-left:1px solid var(--line)}
.statbar b{font-size:13px;font-weight:600;color:var(--fg)}
.statbar .z b{color:var(--faint);font-weight:500}
.statbar .warn b{color:rgb(var(--warn))} .statbar .bad b{color:rgb(var(--danger))}
.statbar .info b{color:rgb(var(--info))} .statbar .ok b{color:rgb(var(--ok))}

.controls{display:flex;flex-wrap:wrap;align-items:center;gap:8px;margin-bottom:10px}
.picker{position:relative}
.pbtn{display:flex;align-items:center;gap:8px;height:28px;padding:0 8px;min-width:236px;
 background:var(--panel);border:1px solid var(--line);border-radius:var(--r);color:var(--fg);
 font:inherit;font-size:12px;cursor:pointer;text-align:left}
.pbtn:hover{border-color:var(--line-strong)}
.pbtn .pcount{color:var(--faint);margin-left:auto}
.chev{width:0;height:0;flex:none;border-left:4px solid transparent;border-right:4px solid transparent;border-top:5px solid var(--muted)}
.pmenu{position:absolute;z-index:20;top:32px;left:0;width:300px;padding:6px;
 background:var(--panel);border:1px solid var(--line-strong);border-radius:var(--r);box-shadow:0 12px 32px rgb(1 4 9 / .55)}
.psearch{width:100%;height:26px;margin-bottom:6px;padding:0 8px;font-size:12px;color:var(--fg);
 background:var(--sunken);border:1px solid var(--line);border-radius:var(--r-tag)}
.psearch::placeholder{color:var(--faint)}
.plist{list-style:none;margin:0;padding:0;max-height:300px;overflow-y:auto}
.plist li{display:flex;align-items:center;gap:10px;padding:4px 8px;border-radius:var(--r-tag);cursor:pointer;font-size:12px}
.plist li:hover,.plist li.hl{background:var(--raised)}
.plist li[aria-selected=true]{color:var(--accent)}
.plist li .n{margin-left:auto;color:var(--faint);font-size:11.5px}
.pempty{padding:8px;color:var(--faint);font-size:12px}

.seg{display:flex;border:1px solid var(--line);border-radius:var(--r);overflow:hidden}
.seg button{appearance:none;border:0;background:transparent;color:var(--muted);font:inherit;font-size:12px;
 height:28px;padding:0 10px;cursor:pointer}
.seg button+button{border-left:1px solid var(--line)}
.seg button:hover{color:var(--fg)}
.seg button.on{background:var(--raised);color:var(--fg)}
.search{flex:0 1 260px;min-width:170px;height:28px;margin-left:auto;padding:0 8px;font-size:12px;
 color:var(--fg);background:var(--panel);border:1px solid var(--line);border-radius:var(--r)}
.search::placeholder{color:var(--faint)}
.search:hover{border-color:var(--line-strong)}

/* No overflow here on wide screens: an overflow container becomes the sticky
   containing block, and the table header then sticks 38px below the panel's own top
   edge, covering the first row. Narrow screens opt into scrolling below. */
.panel{background:var(--bg);border:1px solid var(--line);border-radius:var(--r)}
table{border-collapse:separate;border-spacing:0;width:100%;table-layout:fixed}
/* Widths live on the header cells: with a fixed layout those are the ones
   the browser reads, and the colspan detail row is left alone. */
/* The status cell must never wrap: the caret plus the longest label ("Probe
   unreachable", 134px + 12px) has to fit inside the column minus its padding, or
   that one row grows taller than every other row and the table looks misaligned.
   186px leaves room for a label a little longer than today's longest. */
th:nth-child(1),td:nth-child(1){width:186px;white-space:nowrap}
th:nth-child(2){width:16%}
th:nth-child(4){width:118px} th:nth-child(5){width:20%}
th:nth-child(6){width:60px} th:nth-child(7){width:98px}
th{position:sticky;top:38px;z-index:3;background:var(--panel);text-align:left;white-space:nowrap;
 font-size:10px;font-weight:600;letter-spacing:.08em;text-transform:uppercase;color:var(--faint);
 padding:6px 12px;border-bottom:1px solid var(--line-strong)}
td{padding:6px 12px;border-bottom:1px solid var(--line);vertical-align:middle;font-size:13px}
tbody tr:last-child td{border-bottom:0}
tr.group td{background:var(--raised);color:var(--muted);font-size:11px;letter-spacing:.03em;padding:5px 12px}
tr.group b{color:var(--fg);font-weight:600;font-family:ui-monospace,SFMono-Regular,Menlo,Consolas,monospace}
tr.row{cursor:pointer}
tr.row:hover{background:var(--raised)}
tr.row.on{background:var(--raised)}
tr.row.on td:first-child{box-shadow:inset 2px 0 0 var(--accent)}
.caret{display:inline-block;width:0;height:0;margin-right:8px;vertical-align:middle;
 border-left:4px solid var(--faint);border-top:4px solid transparent;border-bottom:4px solid transparent;transition:transform .1s ease}
tr.row.on .caret{transform:rotate(90deg);border-left-color:var(--accent)}
td.name{font-weight:550}
.tag{display:inline-flex;align-items:center;gap:6px;padding:2px 7px;border-radius:var(--r-tag);
 font-size:12px;border:1px solid transparent;white-space:nowrap}
.tag i{width:6px;height:6px;border-radius:1px;background:currentColor;flex:none}
.s-ok{color:rgb(var(--ok));background:rgb(var(--ok) / .12);border-color:rgb(var(--ok) / .3)}
.s-wait{color:rgb(var(--warn));background:rgb(var(--warn) / .12);border-color:rgb(var(--warn) / .3)}
.s-danger{color:rgb(var(--danger));background:rgb(var(--danger) / .12);border-color:rgb(var(--danger) / .3)}
.s-info{color:rgb(var(--info));background:rgb(var(--info) / .12);border-color:rgb(var(--info) / .3)}
.s-mute{color:var(--muted);background:var(--raised);border-color:var(--line)}
.probe-ok{color:rgb(var(--ok))} .probe-bad{color:rgb(var(--danger))}
.probe-warn{color:rgb(var(--warn))} .probe-off{color:var(--faint)}
.days-soon{color:rgb(var(--warn))}
.muted{color:var(--faint)}

tr.detail td{background:var(--sunken);padding:12px 16px 14px}
.dgrid{display:grid;grid-template-columns:repeat(auto-fit,minmax(340px,1fr));gap:14px 28px}
.dsec h3{margin:0 0 6px;font-size:10px;font-weight:600;letter-spacing:.08em;text-transform:uppercase;color:var(--faint)}
.kv{display:grid;grid-template-columns:minmax(90px,auto) minmax(0,1fr);gap:3px 12px;margin:0;font-size:12px}
.kv dt{color:var(--faint);white-space:nowrap}
.kv dd{margin:0;overflow-wrap:anywhere}
.brow{display:flex;gap:10px;align-items:baseline;flex-wrap:wrap;padding:3px 0;border-top:1px solid var(--line);font-size:12px}
.brow:first-child{border-top:0}
.src{margin:6px 0 0;font-size:11.5px;color:var(--faint)}
ul.hosts,ul.tokens{list-style:none;margin:0;padding:0}
ul.hosts li{padding:3px 0;border-top:1px solid var(--line);font-size:12px}
ul.hosts li:first-child{border-top:0}
ul.tokens li{display:inline-block;margin:0 5px 5px 0;padding:1px 7px;border-radius:var(--r-tag);
 background:var(--raised);border:1px solid var(--line);font-size:11.5px;color:var(--muted)}
.err{margin:6px 0 0;font-size:12px;color:rgb(var(--danger));overflow-wrap:anywhere}
.empty{padding:40px 16px;text-align:center;color:var(--muted)}

.foot{display:flex;justify-content:space-between;gap:16px;flex-wrap:wrap;margin-top:12px;font-size:11.5px;color:var(--faint)}
.legend{margin-top:10px;font-size:12px;color:var(--muted)}
.legend summary{cursor:pointer;color:var(--faint);font-size:10.5px;letter-spacing:.08em;text-transform:uppercase}
.legend dl{display:grid;grid-template-columns:repeat(auto-fit,minmax(300px,1fr));gap:4px 24px;margin:8px 0 0}
.legend dt{font-family:ui-monospace,SFMono-Regular,Menlo,Consolas,monospace;font-size:11.5px;color:var(--fg)}
.legend dd{margin:0 0 4px;font-size:11.5px}
@media (max-width:820px){
 .wide{display:none}
 .panel{overflow-x:auto}
 .search{margin-left:0;flex:1 1 100%}
 .pbtn{min-width:0}
}
@media (prefers-reduced-motion:reduce){*{transition:none!important;animation:none!important}}
</style>
</head>
<body>
<header class="topbar">
  <div class="brand">
    <span class="mark" aria-hidden="true"></span>
    <b>wecert</b>
    <span>certificate inventory</span>
  </div>
  <div class="right">
    <span class="ro">Read-only</span>
    <span class="stamp mono">{{.Time}}</span>
    <button type="button" class="icon" id="theme" aria-label="Switch colour theme" title="Switch colour theme">◐</button>
  </div>
</header>

<main class="wrap">
  <div class="title">
    <h1>Inventory</h1>
    <p class="src">desired state <span class="mono">{{if .DesiredKnown}}{{.Desired.Revision}}{{else}}not read{{end}}</span></p>
  </div>
  {{if .FrozenLabel}}<p class="notice">desired state is frozen · {{.FrozenLabel}}</p>{{end}}

  <div class="statbar" aria-label="Summary">
    <span class="st"><b>{{.Summary.Certificates}}</b> certificates</span>
    <span class="st"><b>{{.UINCount}}</b> accounts</span>
    <span class="st {{if gt .Summary.WaitingManualBind 0}}warn{{else}}z{{end}}"><b>{{.Summary.WaitingManualBind}}</b> waiting bind</span>
    <span class="st {{if gt .Summary.PendingDeploy 0}}warn{{else}}z{{end}}"><b>{{.Summary.PendingDeploy}}</b> pending deploy</span>
    <span class="st {{if gt .Summary.NotIssued 0}}info{{else}}z{{end}}"><b>{{.Summary.NotIssued}}</b> not issued</span>
    <span class="st {{if gt .Summary.Failing 0}}bad{{else}}z{{end}}"><b>{{.Summary.Failing}}</b> failing</span>
    <span class="st {{if gt .Summary.Expiring 0}}info{{else}}z{{end}}"><b>{{.Summary.Expiring}}</b> expiring</span>
    <span class="st {{if gt .Summary.ProbeMismatch 0}}bad{{else}}z{{end}}"><b>{{.Summary.ProbeMismatch}}</b> probe mismatch</span>
    <span class="st {{if gt .Summary.ProbeUnreachable 0}}warn{{else}}z{{end}}"><b>{{.Summary.ProbeUnreachable}}</b> unreachable</span>
    <span class="st {{if gt .Summary.ProbeUnknown 0}}warn{{else}}z{{end}}"><b>{{.Summary.ProbeUnknown}}</b> probe unknown</span>
    <span class="st {{if gt .Summary.BindingUnknown 0}}warn{{else}}z{{end}}"><b>{{.Summary.BindingUnknown}}</b> binding unknown</span>
    <span class="st {{if gt .Summary.Unreadable 0}}bad{{else}}z{{end}}"><b>{{.Summary.Unreadable}}</b> state unreadable</span>
  </div>

  <div class="controls">
    {{if .ShowGroups}}
    <div class="picker" id="uins">
      <button type="button" class="pbtn" id="acctBtn" aria-haspopup="listbox" aria-expanded="false" aria-controls="acctMenu">
        <span class="plabel" id="acctLabel">All accounts</span>
        <span class="pcount" id="acctCount">{{.Summary.Certificates}}</span>
        <span class="chev" aria-hidden="true"></span>
      </button>
      <div class="pmenu hidden" id="acctMenu">
        <input class="psearch" id="acctSearch" type="text" placeholder="Filter accounts" aria-label="Filter accounts" autocomplete="off">
        <ul class="plist" id="acctList" role="listbox" aria-label="Account">
          <li role="option" data-uin="" aria-selected="true" tabindex="-1"><span class="mono">All accounts</span><span class="n">{{.Summary.Certificates}}</span></li>
          {{range .Accounts}}
          <li role="option" data-uin="{{.UIN}}" aria-selected="false" tabindex="-1"><span class="mono">{{if .UIN}}{{.UIN}}{{else}}unspecified{{end}}</span><span class="n">{{.Count}}</span></li>
          {{end}}
        </ul>
        <p class="pempty hidden" id="acctEmpty">no account matches</p>
      </div>
    </div>
    {{end}}
    <div class="seg" id="filters" role="group" aria-label="Filter certificates">
      <button type="button" class="on" data-filter="all">All</button>
      <button type="button" data-filter="attention">Attention</button>
      <button type="button" data-filter="expiring">Expiring</button>
    </div>
    <input class="search" id="q" type="search" placeholder="search name, domain, account, CLB" aria-label="Search certificates">
  </div>

  <div class="panel">
  <table>
  <thead>
  <tr>
    <th scope="col">Status</th><th scope="col">Certificate</th><th scope="col">Names</th><th scope="col">Region</th><th scope="col">CLB</th><th scope="col" class="num">Days</th><th scope="col" class="wide">Probe</th>
  </tr>
  </thead>
  <tbody>
  {{if not .Certificates}}
  <tr><td colspan="7" class="empty">No certificates in this snapshot.</td></tr>
  {{else}}
  {{range .Accounts}}
  {{if $.ShowGroups}}
  <tr class="group" data-group="{{.UIN}}"><td colspan="7"><b>{{if .UIN}}{{.UIN}}{{else}}unspecified account{{end}}</b> · {{.Count}} certificate{{if ne .Count 1}}s{{end}}</td></tr>
  {{end}}
  {{range .Certificates}}
  <tr class="row" data-row tabindex="0" aria-expanded="false" data-uin="{{.UIN}}" data-status="{{.Status}}" data-q="{{qblob .}}" data-attention="{{if attention .Status}}1{{else}}0{{end}}">
    <td><span class="caret" aria-hidden="true"></span><span class="tag {{class .Status}}"><i aria-hidden="true"></i>{{status .Status}}</span></td>
    <td class="name">{{.Name}}</td>
    <td class="mono">{{names .}}</td>
    <td class="mono" title="{{if .Regions}}{{join .Regions ", "}}{{else}}no binding enumeration has named a region for this certificate{{end}}">{{regions .Regions}}</td>
    <td class="mono">{{clb .}}</td>
    <td class="num {{if eq .Status "expiring"}}days-soon{{end}}">{{days .DaysLeft}}</td>
    <td class="wide {{probeClass .Probe}}">{{probe .Probe}}</td>
  </tr>
  <tr class="detail hidden" data-detail>
    <td colspan="7">
      <div class="dgrid">
        <div class="dsec">
          <h3>Certificate</h3>
          <dl class="kv">
            <dt>Account</dt><dd class="mono">{{if .UIN}}{{.UIN}}{{else}}—{{end}}</dd>
            <dt>Expires</dt><dd>{{days .DaysLeft}}{{if .NotAfter}} · <span class="mono nowrap">{{.NotAfter}}</span>{{else}} · no certificate stored{{end}}</dd>
            <dt>Issued</dt><dd class="mono">{{if .IssuedAt}}{{.IssuedAt}}{{else}}—{{end}}</dd>
            <dt>Cert id</dt><dd class="mono">{{if .DeployedCertID}}{{.DeployedCertID}}{{else}}not uploaded{{end}}</dd>
            <dt>Profile</dt><dd>{{if .Profile}}{{.Profile}}{{else}}—{{end}}{{if .KeyType}} · {{.KeyType}}{{end}}</dd>
            <dt>Names</dt><dd class="mono">{{if .Domains}}{{join .Domains ", "}}{{else}}—{{end}}</dd>
            <dt>Regions</dt><dd class="mono">{{if .Regions}}{{join .Regions ", "}}{{else}}unknown — no binding enumeration has named one{{end}}</dd>
            {{if .ARI}}<dt>ARI window</dt><dd class="mono">{{if .ARI.WindowStart}}{{.ARI.WindowStart}}{{else}}—{{end}} → {{if .ARI.WindowEnd}}{{.ARI.WindowEnd}}{{else}}—{{end}}</dd>{{end}}
            <dt>Failures</dt><dd>{{.ConsecutiveFailures}}{{if .NextAttemptAt}} · next <span class="mono nowrap">{{.NextAttemptAt}}</span>{{end}}</dd>
          </dl>
        </div>
        <div class="dsec">
          <h3>Bindings</h3>
          {{if .Bindings.Items}}
            {{range .Bindings.Items}}<div class="brow"><span class="mono">{{region .Region}} {{.LoadBalancerID}}</span><span class="mono">{{.Protocol}}:{{.Port}}</span>{{if .SNIDomain}}<span class="mono">{{.SNIDomain}}</span>{{end}}<span class="muted">{{.Role}}</span></div>{{end}}
          {{else}}<div class="brow">{{bind .Bindings .Status}}</div>{{end}}
          <p class="src">source {{.Bindings.Freshness}}{{if .Bindings.ObservedAt}} · observed {{.Bindings.ObservedAt}}{{end}}{{if not .Bindings.Complete}} · lower bound, not the whole set{{end}}{{if .Bindings.ResourceTypes}} · {{join .Bindings.ResourceTypes ", "}}{{end}}</p>
        </div>
        <div class="dsec">
          <h3>Probe</h3>
          <p class="src">served certificate read over TLS{{if not .Probe.Enabled}} · probing is off in this deployment{{end}}</p>
          <ul class="hosts">
          {{range .Probe.Hosts}}<li><span class="mono">{{.Host}}</span> · {{if .Match}}match{{else}}mismatch{{end}}{{if .ProblemKind}} · {{.ProblemKind}}{{end}}{{if .NotAfter}} · served expires <span class="mono nowrap">{{.NotAfter}}</span>{{if not .Trusted}} · chain not trusted{{end}}{{end}}</li>{{end}}
          {{if not .Probe.Hosts}}<li class="muted">no answer this process life</li>{{end}}
          </ul>
        </div>
        <div class="dsec">
          <h3>Drift{{if not .Drift}} · none{{end}}</h3>
          {{if .Drift}}<ul class="tokens">{{range .Drift}}<li>{{.}}</li>{{end}}</ul>{{end}}
          {{if .LastError}}<p class="err">last error: {{.LastError}}</p>{{end}}
        </div>
      </div>
    </td>
  </tr>
  {{end}}
  {{end}}
  {{end}}
  </tbody>
  </table>
  </div>

  <details class="legend">
    <summary>Status tokens</summary>
    <dl>
      <dt>ok</dt><dd>issued, deployed as configured, served certificate matches</dd>
      <dt>expiring</dt><dd>inside the renewal window for this certificate</dd>
      <dt>waiting_manual_bind</dt><dd>uploaded; the one-time bind in the CLB console has not happened</dd>
      <dt>pending_deploy</dt><dd>issued; the first upload has not run yet</dd>
      <dt>not_issued</dt><dd>no certificate stored for this name yet</dd>
      <dt>probe_mismatch</dt><dd>the name serves a certificate that is not the deployed one</dd>
      <dt>probe_unreachable</dt><dd>the name could not be dialled; the certificate was not read</dd>
      <dt>probe_unknown</dt><dd>probing is on and this process has no answer yet</dd>
      <dt>binding_unknown</dt><dd>a live enumeration came back incomplete with no binding</dd>
      <dt>failing</dt><dd>the last reconcile attempts failed</dd>
      <dt>rate_limited</dt><dd>a published CA rate limit is blocking this certificate</dd>
      <dt>revoke_pending</dt><dd>a revocation request is recorded for this name</dd>
      <dt>frozen</dt><dd>the desired-state document is frozen</dd>
      <dt>state_unreadable</dt><dd>the state row could not be read; see the error</dd>
    </dl>
  </details>

  <p class="foot">
    <span>The desired-state controller remains the source of truth. This register never issues, rebinds, or edits SAN sets.</span>
    <span>Read-only · token required · the only thing kept in this browser is your colour theme</span>
  </p>
</main>
<script>
(function(){
  var root=document.documentElement, filter="all", uin="", q="";
  try{ var saved=localStorage.getItem("wecert-theme"); if(saved) root.setAttribute("data-theme",saved); }catch(e){}
  var theme=document.getElementById("theme");
  if(theme) theme.addEventListener("click",function(){
    var next=root.getAttribute("data-theme")==="light"?"dark":"light";
    root.setAttribute("data-theme",next);
    try{ localStorage.setItem("wecert-theme",next); }catch(e){}
  });

  function norm(s){return (s||"").toLowerCase()}
  function rows(){return document.querySelectorAll("[data-row]")}
  function apply(){
    var vis={};
    rows().forEach(function(row){
      var ok=true;
      if(uin && row.getAttribute("data-uin")!==uin) ok=false;
      var st=row.getAttribute("data-status");
      if(filter==="attention" && row.getAttribute("data-attention")!=="1") ok=false;
      if(filter==="expiring" && st!=="expiring") ok=false;
      if(q && norm(row.getAttribute("data-q")).indexOf(q)===-1) ok=false;
      row.classList.toggle("hidden",!ok);
      var det=row.nextElementSibling;
      if(det && det.hasAttribute("data-detail") && !ok){
        det.classList.add("hidden"); row.setAttribute("aria-expanded","false");
      }
      if(ok) vis[row.getAttribute("data-uin")]=true;
    });
    document.querySelectorAll("[data-group]").forEach(function(g){
      var id=g.getAttribute("data-group");
      var show=!uin || uin===id;
      if(show && !(id in vis) && (filter!=="all" || q)) show=false;
      g.classList.toggle("hidden",!show);
    });
  }
  function select(group,attr,val){
    group.querySelectorAll("button").forEach(function(b){
      b.classList.toggle("on",(b.getAttribute(attr)||"")===val);
    });
  }
  function toggle(row){
    var det=row.nextElementSibling;
    if(!det || !det.hasAttribute("data-detail")) return;
    var open=!det.classList.contains("hidden");
    document.querySelectorAll("[data-detail]").forEach(function(d){ d.classList.add("hidden"); });
    rows().forEach(function(r){ r.classList.remove("on"); r.setAttribute("aria-expanded","false"); });
    if(!open){ det.classList.remove("hidden"); row.classList.add("on"); row.setAttribute("aria-expanded","true"); }
  }
  var f=document.getElementById("filters");
  if(f) f.addEventListener("click",function(e){
    var b=e.target.closest("button"); if(!b) return;
    filter=b.getAttribute("data-filter")||"all";
    select(f,"data-filter",filter); apply();
  });
  var s=document.getElementById("q");
  if(s) s.addEventListener("input",function(){ q=norm(s.value.trim()); apply(); });

  var body=document.querySelector("tbody");
  body.addEventListener("click",function(e){
    var row=e.target.closest("[data-row]"); if(!row) return;
    toggle(row);
  });
  body.addEventListener("keydown",function(e){
    if(e.key!=="Enter" && e.key!==" ") return;
    var row=e.target.closest("[data-row]"); if(!row) return;
    e.preventDefault(); toggle(row);
  });

  var picker=document.getElementById("uins"), btn=document.getElementById("acctBtn"),
      menu=document.getElementById("acctMenu"), list=document.getElementById("acctList"),
      search=document.getElementById("acctSearch"), label=document.getElementById("acctLabel"),
      count=document.getElementById("acctCount"), none=document.getElementById("acctEmpty");
  function openMenu(open){
    if(!menu) return;
    menu.classList.toggle("hidden",!open);
    btn.setAttribute("aria-expanded",open?"true":"false");
    if(open){
      search.value=""; showOptions(""); search.focus();
    }
  }
  function options(){ return list.querySelectorAll("li[role=option]") }
  function showOptions(needle){
    var shown=0;
    options().forEach(function(o){
      var hit=!needle || norm(o.getAttribute("data-uin")).indexOf(needle)!==-1;
      o.classList.toggle("hidden",!hit);
      if(hit) shown++;
    });
    none.classList.toggle("hidden",shown>0);
  }
  function choose(o){
    uin=o.getAttribute("data-uin")||"";
    options().forEach(function(x){ x.setAttribute("aria-selected", x===o ? "true" : "false"); });
    label.textContent=uin||"All accounts";
    count.textContent=o.querySelector(".n").textContent;
    openMenu(false); apply();
  }
  if(picker){
    btn.addEventListener("click",function(){ openMenu(menu.classList.contains("hidden")); });
    search.addEventListener("input",function(){ showOptions(norm(search.value.trim())) });
    search.addEventListener("keydown",function(e){
      if(e.key==="Escape"){ openMenu(false); btn.focus(); return; }
      if(e.key==="ArrowDown"){ e.preventDefault(); var first=list.querySelector("li[role=option]:not(.hidden)"); if(first) first.focus(); }
    });
    list.addEventListener("click",function(e){
      var o=e.target.closest("li[role=option]"); if(o) choose(o);
    });
    list.addEventListener("keydown",function(e){
      var o=e.target.closest("li[role=option]"); if(!o) return;
      if(e.key==="Enter" || e.key===" "){ e.preventDefault(); choose(o); btn.focus(); return; }
      if(e.key==="Escape"){ openMenu(false); btn.focus(); return; }
      var step=e.key==="ArrowDown"?1:e.key==="ArrowUp"?-1:0;
      if(!step) return;
      e.preventDefault();
      var all=Array.prototype.filter.call(options(),function(x){ return !x.classList.contains("hidden") });
      var i=all.indexOf(o)+step;
      if(i>=0 && i<all.length) all[i].focus();
    });
    document.addEventListener("click",function(e){
      if(!menu.classList.contains("hidden") && !picker.contains(e.target)) openMenu(false);
    });
    document.addEventListener("keydown",function(e){
      if(e.key==="Escape" && !menu.classList.contains("hidden")){ openMenu(false); btn.focus(); }
    });
  }
})();
</script>


</body>
</html>
`

// WritePage renders the HTML inventory. No external script or font.
func WritePage(w io.Writer, snap Snapshot) error {
	groups := groupByUIN(snap.Certificates)
	view := pageView{Snapshot: snap, Accounts: groups}
	// Frozen is a pointer: nil means the document was never read, which is not the
	// same answer as "not frozen", and it must not render as one.
	view.DesiredKnown = snap.Desired.Frozen != nil
	if snap.Desired.Frozen != nil && *snap.Desired.Frozen {
		view.FrozenLabel = snap.Desired.FreezeReason
		if view.FrozenLabel == "" {
			view.FrozenLabel = "no reason given"
		}
	}
	n := 0
	for _, g := range groups {
		if g.UIN != "" {
			n++
		}
	}
	view.UINCount = n
	if n == 0 {
		view.UINCount = 0
	}
	view.ShowGroups = n > 0
	if len(groups) > 1 {
		view.ShowGroups = true
		if view.UINCount == 0 {
			view.UINCount = len(groups)
		}
	}
	return pageTmpl.Execute(w, view)
}
