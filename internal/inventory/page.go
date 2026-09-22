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
	return ""
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
		seen = append(seen, regionLabel(it.Region)+"  "+it.LoadBalancerID)
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
:root{--bg:#efece6;--surface:#fffcf7;--elev:#efebe3;--fg:#1b1c1a;--muted:#5c615c;--subtle:#6f746e;--line:#e2ddd4;--accent:#1f2a24;--ok:#2c6a45;--wait:#8a5a16;--danger:#a33b35;--info:#3d4d7a}
*{box-sizing:border-box}
body{margin:0;font:14px/1.5 ui-sans-serif,system-ui,sans-serif;background:var(--bg);color:var(--fg)}
.bar{height:2px;background:var(--accent)}
.wrap{max-width:1200px;margin:0 auto;padding:24px 20px 40px}
h1{font-size:28px;font-weight:600;letter-spacing:-.02em;margin:0}
.meta{color:var(--muted);margin:6px 0 0}
.head{display:flex;justify-content:space-between;gap:16px;flex-wrap:wrap;align-items:flex-end;margin-bottom:18px}
.stamp{font-size:11px;letter-spacing:.1em;text-transform:uppercase;color:var(--muted)}
.mono{font-family:ui-monospace,SFMono-Regular,Menlo,Consolas,monospace;font-size:12px}
.stats{display:flex;flex-wrap:wrap;gap:12px 28px;border-top:1px solid var(--line);border-bottom:1px solid var(--line);padding:12px 0;margin-bottom:16px}
.stat .n{font-size:22px;font-weight:600;font-variant-numeric:tabular-nums}
.stat .l{font-size:11px;letter-spacing:.1em;text-transform:uppercase;color:var(--muted);margin-top:4px}
.stat.warn .n{color:var(--wait)} .stat.bad .n{color:var(--danger)} .stat.info .n{color:var(--info)} .stat.zero .n{color:var(--subtle)}
.chips{display:flex;gap:6px;overflow-x:auto;padding-bottom:4px;margin-bottom:10px;align-items:center}
.chips .lab{font-size:11px;letter-spacing:.1em;text-transform:uppercase;color:var(--muted);margin-right:4px;flex:none}
.chip,.seg button{appearance:none;border:0;background:var(--elev);color:var(--muted);min-height:40px;padding:0 12px;border-radius:4px;font:inherit;cursor:pointer;white-space:nowrap;flex:none}
.chip.on,.seg button.on{background:var(--surface);color:var(--fg);box-shadow:0 0 0 1px rgb(27 28 26 / .06),0 1px 2px rgb(27 28 26 / .05)}
.toolbar{display:flex;flex-wrap:wrap;gap:10px;justify-content:space-between;margin-bottom:14px}
.seg{display:flex;gap:4px;background:var(--elev);padding:4px;border-radius:8px}
.search{flex:1;min-width:200px;max-width:320px;height:40px;border:1px solid var(--line);border-radius:4px;padding:0 12px;font:inherit;background:var(--surface);color:var(--fg)}
.panel{background:var(--surface);border-radius:12px;box-shadow:0 0 0 1px rgb(27 28 26 / .06),0 8px 24px -16px rgb(27 28 26 / .18);overflow:auto}
table{border-collapse:collapse;width:100%}
th{text-align:left;font-size:11px;letter-spacing:.1em;text-transform:uppercase;color:var(--muted);font-weight:500;padding:10px 12px;background:var(--elev);border-bottom:1px solid var(--line)}
td{padding:12px;border-bottom:1px solid var(--line);vertical-align:middle}
tr.group td{background:var(--elev);font-size:13px;padding:8px 12px}
tr.row{cursor:pointer}
tr.row:hover{background:var(--elev)}
tr.row.on{background:var(--elev)}
td.st{border-left:2px solid transparent;white-space:nowrap}
tr.row.on td.st{border-left-color:var(--accent)}
.dot{display:inline-block;width:6px;height:6px;border-radius:50%;margin-right:6px;background:var(--subtle);vertical-align:middle}
.s-ok{color:var(--ok)} .s-ok .dot{background:var(--ok)}
.s-wait{color:var(--wait)} .s-wait .dot{background:var(--wait)}
.s-danger{color:var(--danger)} .s-danger .dot{background:var(--danger)}
.s-info{color:var(--info)} .s-info .dot{background:var(--info)}
.num{font-variant-numeric:tabular-nums;text-align:right}
.hidden{display:none !important}
.detail{background:var(--elev);font-size:13px}
.detail td{padding:12px 16px 16px 24px}
.kv{display:grid;grid-template-columns:7rem 1fr;gap:8px 12px;max-width:720px}
.kv b{font-weight:500;font-size:11px;letter-spacing:.1em;text-transform:uppercase;color:var(--muted);padding-top:2px}
.foot{margin-top:14px;font-size:12px;color:var(--subtle)}
.empty{padding:48px 16px;text-align:center;color:var(--muted)}
@media (max-width:720px){ .wide{display:none} }
</style>
</head>
<body>
<div class="bar"></div>
<div class="wrap">
<div class="head">
  <div>
    <h1>Inventory</h1>
    <p class="meta">wecert · {{.Summary.Certificates}} certificates{{if .UINCount}} · {{.UINCount}} UIN{{if ne .UINCount 1}}s{{end}}{{end}} · {{.Time}}</p>
  </div>
  <div>
    <div class="stamp">Read-only</div>
    <div class="mono">{{if .DesiredKnown}}{{.Desired.Revision}}{{else}}desired state not read{{end}}</div>
    {{if .FrozenLabel}}<div class="mono">frozen · {{.FrozenLabel}}</div>{{end}}
  </div>
</div>
<section class="stats">
  <div class="stat"><div class="n">{{.Summary.Certificates}}</div><div class="l">certificates</div></div>
  <div class="stat"><div class="n">{{.UINCount}}</div><div class="l">UIN</div></div>
  <div class="stat {{if gt .Summary.WaitingManualBind 0}}warn{{else}}zero{{end}}"><div class="n">{{.Summary.WaitingManualBind}}</div><div class="l">waiting bind</div></div>
  <div class="stat {{if gt .Summary.PendingDeploy 0}}warn{{else}}zero{{end}}"><div class="n">{{.Summary.PendingDeploy}}</div><div class="l">pending deploy</div></div>
  <div class="stat {{if gt .Summary.NotIssued 0}}info{{else}}zero{{end}}"><div class="n">{{.Summary.NotIssued}}</div><div class="l">not issued</div></div>
  <div class="stat {{if gt .Summary.Failing 0}}bad{{else}}zero{{end}}"><div class="n">{{.Summary.Failing}}</div><div class="l">failing</div></div>
  <div class="stat {{if gt .Summary.Expiring 0}}info{{else}}zero{{end}}"><div class="n">{{.Summary.Expiring}}</div><div class="l">expiring</div></div>
  <div class="stat {{if gt .Summary.ProbeMismatch 0}}bad{{else}}zero{{end}}"><div class="n">{{.Summary.ProbeMismatch}}</div><div class="l">probe mismatch</div></div>
  <div class="stat {{if gt .Summary.ProbeUnreachable 0}}warn{{else}}zero{{end}}"><div class="n">{{.Summary.ProbeUnreachable}}</div><div class="l">probe unreachable</div></div>
  <div class="stat {{if gt .Summary.ProbeUnknown 0}}warn{{else}}zero{{end}}"><div class="n">{{.Summary.ProbeUnknown}}</div><div class="l">probe unknown</div></div>
  <div class="stat {{if gt .Summary.BindingUnknown 0}}warn{{else}}zero{{end}}"><div class="n">{{.Summary.BindingUnknown}}</div><div class="l">binding unknown</div></div>
  <div class="stat {{if gt .Summary.Unreadable 0}}bad{{else}}zero{{end}}"><div class="n">{{.Summary.Unreadable}}</div><div class="l">state unreadable</div></div>
</section>
{{if .ShowGroups}}
<div class="chips" id="uins">
  <span class="lab">UIN</span>
  <button type="button" class="chip on" data-uin="">All <span>{{.UINCount}}</span></button>
  {{range .Accounts}}
  <button type="button" class="chip" data-uin="{{.UIN}}">{{if .UIN}}{{.UIN}}{{else}}unspecified{{end}} <span>{{.Count}}</span></button>
  {{end}}
</div>
{{end}}
<div class="toolbar">
  <div class="seg" id="filters">
    <button type="button" class="on" data-filter="all">All</button>
    <button type="button" data-filter="attention">Attention</button>
    <button type="button" data-filter="expiring">Expiring</button>
  </div>
  <input class="search" id="q" type="search" placeholder="Search name, domain, UIN, CLB…" aria-label="Search certificates">
</div>
<div class="panel">
<table>
<thead>
<tr>
  <th>Status</th><th>Certificate</th><th>Names</th><th>CLB</th><th class="num">Days</th><th class="wide">Probe</th>
</tr>
</thead>
<tbody>
{{if not .Certificates}}
<tr><td colspan="6" class="empty">No certificates in this snapshot.</td></tr>
{{else}}
{{range .Accounts}}
{{if $.ShowGroups}}
<tr class="group" data-group="{{.UIN}}"><td colspan="6"><strong>{{if .UIN}}{{.UIN}}{{else}}unspecified{{end}}</strong> · {{.Count}} cert{{if ne .Count 1}}s{{end}}</td></tr>
{{end}}
{{range .Certificates}}
<tr class="row" data-row data-uin="{{.UIN}}" data-status="{{.Status}}" data-q="{{qblob .}}" data-attention="{{if attention .Status}}1{{else}}0{{end}}">
  <td class="st"><span class="{{class .Status}}"><span class="dot"></span>{{status .Status}}</span></td>
  <td>{{.Name}}</td>
  <td class="mono">{{names .}}</td>
  <td class="mono">{{clb .}}</td>
  <td class="num">{{days .DaysLeft}}</td>
  <td class="wide">{{probe .Probe}}</td>
</tr>
<tr class="detail hidden" data-detail>
  <td colspan="6">
    <div class="kv">
      <b>UIN</b><div class="mono">{{if .UIN}}{{.UIN}}{{else}}—{{end}}</div>
      <b>Expires</b><div>{{days .DaysLeft}} · {{.NotAfter}}</div>
      <b>Issued</b><div>{{if .IssuedAt}}{{.IssuedAt}}{{else}}—{{end}}</div>
      <b>Cert id</b><div class="mono">{{if .DeployedCertID}}{{.DeployedCertID}}{{else}}not uploaded{{end}}</div>
      <b>Names</b><div class="mono">{{join .Domains ", "}}</div>
      <b>CLB</b><div>
        {{if .Bindings.Items}}
          {{range .Bindings.Items}}<div class="mono">{{region .Region}} {{.LoadBalancerID}} · {{.Protocol}}:{{.Port}}{{if .SNIDomain}} · {{.SNIDomain}}{{end}} · {{.Role}}</div>{{end}}
        {{else}}{{bind .Bindings .Status}}{{end}}
        <div class="mono">source: {{.Bindings.Freshness}}{{if .Bindings.ObservedAt}} · observed {{.Bindings.ObservedAt}}{{end}}{{if not .Bindings.Complete}} · lower bound, not the whole set{{end}}</div>
      </div>
      <b>Probe</b><div>{{probe .Probe}}{{range .Probe.Hosts}}<div class="mono">{{.Host}} · {{if .Match}}match{{else}}mismatch{{end}}{{if .ProblemKind}} · {{.ProblemKind}}{{end}}{{if .NotAfter}} · served expires {{.NotAfter}}{{if not .Trusted}} · chain not trusted{{end}}{{end}}</div>{{end}}</div>
      {{if .Drift}}<b>Drift</b><div class="mono">{{join .Drift ", "}}</div>{{end}}
      {{if .LastError}}<b>Error</b><div>{{.LastError}}</div>{{end}}
    </div>
  </td>
</tr>
{{end}}
{{end}}
{{end}}
</tbody>
</table>
</div>
<p class="foot">Desired-state controller remains the source of truth. This register never issues, rebinds, or edits SAN sets.</p>
</div>
<script>
(function(){
  var filter="all", uin="", q="";
  function norm(s){return (s||"").toLowerCase()}
  function apply(){
    var rows=document.querySelectorAll("[data-row]");
    var vis={};
    rows.forEach(function(row){
      var ok=true;
      if(uin && row.getAttribute("data-uin")!==uin) ok=false;
      var st=row.getAttribute("data-status");
      if(filter==="attention" && row.getAttribute("data-attention")!=="1") ok=false;
      if(filter==="expiring" && st!=="expiring") ok=false;
      if(q && norm(row.getAttribute("data-q")).indexOf(q)===-1) ok=false;
      row.classList.toggle("hidden", !ok);
      var det=row.nextElementSibling;
      if(det && det.hasAttribute("data-detail") && !ok) det.classList.add("hidden");
      if(ok) vis[row.getAttribute("data-uin")]=true;
    });
    document.querySelectorAll("[data-group]").forEach(function(g){
      var id=g.getAttribute("data-group");
      var show=!uin || uin===id;
      if(show && !(id in vis) && filter!=="all") show=false;
      if(q && !(id in vis)) show=false;
      g.classList.toggle("hidden", !show);
    });
  }
  function select(group, attr, val){
    group.querySelectorAll("button").forEach(function(b){
      b.classList.toggle("on", (b.getAttribute(attr)||"")===val);
    });
  }
  var f=document.getElementById("filters");
  if(f) f.addEventListener("click", function(e){
    var b=e.target.closest("button"); if(!b) return;
    filter=b.getAttribute("data-filter")||"all";
    select(f,"data-filter",filter); apply();
  });
  var u=document.getElementById("uins");
  if(u) u.addEventListener("click", function(e){
    var b=e.target.closest("button"); if(!b) return;
    uin=b.getAttribute("data-uin")||"";
    select(u,"data-uin",uin); apply();
  });
  var s=document.getElementById("q");
  if(s) s.addEventListener("input", function(){ q=norm(s.value.trim()); apply(); });
  document.querySelector("tbody").addEventListener("click", function(e){
    var row=e.target.closest("[data-row]"); if(!row) return;
    var det=row.nextElementSibling;
    if(!det || !det.hasAttribute("data-detail")) return;
    var open=!det.classList.contains("hidden");
    document.querySelectorAll("[data-detail]").forEach(function(d){ d.classList.add("hidden"); });
    document.querySelectorAll("[data-row]").forEach(function(r){ r.classList.remove("on"); });
    if(!open){ det.classList.remove("hidden"); row.classList.add("on"); }
  });
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
