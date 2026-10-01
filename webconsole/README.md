# wecert web console

Standalone management UI for a wecert daemon: certificate create / bind /
renew / delete, cloud accounts, bindings, and activity.

Three frontends live here:

- `console.html` — the certificate-first console, and the one nginx serves at
  `/`. A clickable KPI strip (total, needs attention, expiring, CLB binding
  issues) above a UIN-grouped inventory table, a certificate detail drawer, and
  a four-step create wizard (Identity / Policy / DNS / Deploy) ending in a
  review. Built from `certificate-first-prototype.html` + `.css` + `.js`,
  inlined into one file.
- `index.html` — the original management layout, kept at `/index.html` as a
  rollback path.
- `certificate-first-prototype.html` — the design source for `console.html`.
  It is a three-file prototype and is not served.

All are self-contained (inline CSS + JS, no build step, no CDN). Serve them as
static files and point the browser at the same origin as the daemon's HTTP
surface, or set the base URL in System settings.

`console.html` never renders sample data: with no session it reports
"Disconnected" and shows an empty table, and a rejected token surfaces the
daemon's error instead of a fake fleet. CLB binding issues count certificates
that need a binding and have none — including not-issued ones, and ones whose
payload omits `bindings.complete` entirely, which the daemon does for
certificates that never bound.

The prototype shipped the markup for the inventory rows, the kebab menu, the
UIN dropdown, the group headers and the copy buttons but none of the handlers,
so it looked interactive and was not. `console.html` wires all of them; if you
rebuild from the prototype, that wiring has to come with it.

The inventory keeps the original management layout: title/count above a toolbar
with status, account, sort, and search controls. The browser-only ACME environment
switch and badge have been removed. Issuance follows the connected daemon's
configuration; this frontend does not select an ACME directory or change the
server configuration. Existing management API contracts remain unchanged.

Run the isolated browser regressions with `make check-webconsole PYTHON=/path/to/python`.
Use the same Playwright 1.62.0 environment and Chromium setup documented in
[`docs/console.md`](../docs/console.md). The suite blocks network access and tests
synthetic data at 320, 390, 768, and 1440px in light/dark themes. It also checks
initialization, removal of environment controls, mocked inventory refresh, and
the existing create-request contract. `make check-console` runs all three.

`scripts/check-console2.py` covers `console.html` on its own: KPI counting,
UIN grouping and collapse, search, the UIN and KPI filters, the detail drawer,
the row menu, the four wizard steps and the payload it posts, the disconnected
and 401 states, and the 390px layout. No daemon or credential is involved.

Typical nginx layout (TLS terminator in front), with `console.html` as the
landing page and `index.html` left reachable:

```
location /       { root /opt/wecert/console; index console.html;
                   try_files $uri $uri/ /console.html; }
location /api/   { proxy_pass http://127.0.0.1:9801; }
location /hook/  { proxy_pass http://127.0.0.1:9801; }
location /admin/ { proxy_pass http://127.0.0.1:9801; }
```

The daemon's tokens come from `webhook.token` (read-only) and
`webhook.adminToken` (management). AK/SK entered here are written as 0600
files on the daemon host and are never echoed back to the browser.
