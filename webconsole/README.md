# wecert web console

Standalone management UI for a wecert daemon: certificate create / bind /
renew / delete, cloud accounts, bindings, and activity.

Two frontends live here:

- `console.html` — the certificate-first console: a KPI strip (total, needs
  attention, expiring, CLB binding issues) above a UIN-grouped inventory table,
  plus a one-screen create form with a live request summary. Same API surface
  and token storage keys as `index.html`, so both talk to the same daemon.
- `index.html` — the original management layout.

Both are self-contained (inline CSS + JS, no build step, no CDN). Serve them as
static files and point the browser at the same origin as the daemon's HTTP
surface, or set the base URL in the Connect panel.

`console.html` never renders sample data: with no token it shows a connect
panel, and a rejected token surfaces the daemon's error instead of a fake
fleet. CLB binding issues count certificates that need a binding and have none,
including not-issued ones whose payload carries no `deploy.enabled`.

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
the existing create-request contract. `make check-console` runs both frontends.

This scoped restoration does not repair the existing cramped mobile table,
narrow-screen/long-account-label overflow, or the creation wizard's unreachable
Deploy step. The suite reports
those baseline limitations separately; passing checks are not a claim that all
management flows or responsive layouts are fixed.

Typical nginx layout (TLS terminator in front):

```
location /       { root /opt/wecert/console; try_files $uri $uri/ /index.html; }
location /api/   { proxy_pass http://127.0.0.1:9801; }
location /hook/  { proxy_pass http://127.0.0.1:9801; }
location /admin/ { proxy_pass http://127.0.0.1:9801; }
```

The daemon's tokens come from `webhook.token` (read-only) and
`webhook.adminToken` (management). AK/SK entered here are written as 0600
files on the daemon host and are never echoed back to the browser.
