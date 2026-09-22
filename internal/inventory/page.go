package inventory

import (
	"html/template"
	"io"
	"strconv"
	"strings"
)

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
			return "off"
		}
		if p.OK == nil {
			return "—"
		}
		if *p.OK {
			return "match"
		}
		return "mismatch"
	},
	"bind": func(b Bindings, status string) string {
		if status == StatusWaitingManualBind {
			return "waiting bind"
		}
		if !b.Complete && b.Count == 0 {
			return "unknown"
		}
		if b.Count == 0 {
			return "none"
		}
		if n := countCLB(b); n > 0 {
			return strconv.Itoa(n) + " CLB / " + strconv.Itoa(b.Count) + " listeners"
		}
		return strconv.Itoa(b.Count)
	},
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

const pageHTML = `<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>wecert inventory</title>
<style>
body{font:14px/1.4 ui-sans-serif,system-ui,sans-serif;margin:24px;color:#111;background:#fafafa}
h1{font-size:18px;margin:0 0 8px}
.meta{color:#555;margin-bottom:16px}
table{border-collapse:collapse;width:100%;background:#fff}
th,td{text-align:left;padding:8px 10px;border-bottom:1px solid #e5e5e5;vertical-align:top}
th{font-size:12px;text-transform:uppercase;letter-spacing:.04em;color:#666}
.status-waiting_manual_bind,.status-probe_mismatch,.status-failing{font-weight:600}
details{margin-top:6px}
code{font-size:12px}
</style>
</head>
<body>
<h1>wecert inventory</h1>
<p class="meta">
{{if .Desired.Frozen}}frozen ({{.Desired.FreezeReason}}) · {{end}}
{{.Summary.Certificates}} certs
· {{.Summary.WaitingManualBind}} waiting bind
· {{.Summary.Failing}} failing
· {{.Summary.Expiring}} expiring
· {{.Summary.ProbeMismatch}} probe mismatch
· {{.Time}}
</p>
<table>
<thead>
<tr>
<th>name</th><th>names</th><th>expires</th><th>cert id</th><th>bindings</th><th>443</th>
</tr>
</thead>
<tbody>
{{range .Certificates}}
<tr>
<td>
  <div class="status-{{.Status}}">{{.Name}}</div>
  <div><code>{{.Status}}</code></div>
  {{if .Drift}}<details><summary>drift</summary><code>{{join .Drift ", "}}</code></details>{{end}}
  {{if .LastError}}<details><summary>last error</summary>{{.LastError}}</details>{{end}}
</td>
<td>{{join .Domains ", "}}</td>
<td>{{days .DaysLeft}}</td>
<td><code>{{.DeployedCertID}}</code></td>
<td>
  {{bind .Bindings .Status}}
  {{if .Bindings.Items}}
  <details><summary>where</summary>
    {{range .Bindings.Items}}
    <div><code>{{.Region}} {{.LoadBalancerID}} {{.ListenerID}} {{.Protocol}}{{if .SNIDomain}} {{.SNIDomain}}{{end}} {{.Role}}</code></div>
    {{end}}
  </details>
  {{end}}
</td>
<td>{{probe .Probe}}</td>
</tr>
{{end}}
</tbody>
</table>
</body>
</html>
`

// WritePage renders the HTML inventory. No external script or font.
func WritePage(w io.Writer, snap Snapshot) error {
	return pageTmpl.Execute(w, snap)
}
