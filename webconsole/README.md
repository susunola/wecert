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

TLS is not optional. The console refuses to send a secret — an AK/SK pair, a
scoped DNS token, a webhook URL — over plain HTTP, so on an HTTP origin the
"Connect UIN" drawer and the notification form fail with that message and
nothing else. Serve the page over HTTPS.

Serve it over a **hostname with a certificate a browser actually trusts**. A
self-signed certificate is technically enough to satisfy the transport check,
and it is still the wrong answer: browsers refuse a bare-IP self-signed
certificate outright, with no "proceed anyway" escape hatch, so the operator is
locked out of the console by the very change that was meant to protect it.
Get a real certificate and point port 80 at the name it was issued for —
redirecting to `$host` sends a bare-IP visitor to `https://203.0.113.10/`, which
no CA will ever sign.

On a CVM in a mainland-China region, HTTP-01 does not work: Let's Encrypt
fetches the challenge from outside the mainland and gets connection-reset
against the box, even when the same URL fetches fine locally. Use DNS-01
instead. With acme.sh and DNSPod/Tencent Cloud DNS:

```
export Tencent_SecretId=... Tencent_SecretKey=...
acme.sh --issue --server letsencrypt --dns dns_tencent -d wecert.example.com
acme.sh --install-cert -d wecert.example.com \
  --fullchain-file /etc/nginx/tls/fullchain.pem \
  --key-file       /etc/nginx/tls/wecert.key.pem \
  --reloadcmd      "systemctl reload nginx"
```

`--install-cert` is what makes renewal real: acme.sh records these paths and
re-runs the reload command after each renewal, so the cron job it installs
renews the certificate and nginx picks it up with no further wiring. Verify
unattended renewal once with `acme.sh --renew -d wecert.example.com --force
--test` — a renewal that only works when someone is watching the terminal is
not a renewal.

Resulting nginx layout, with `console.html` as the landing page, `index.html`
left reachable, and port 80 doing nothing but redirecting:

```
server {
    listen 80 default_server;
    server_name _;
    return 301 https://wecert.example.com$request_uri;
}

server {
    listen 443 ssl http2 default_server;
    server_name wecert.example.com;

    ssl_certificate     /etc/nginx/tls/fullchain.pem;
    ssl_certificate_key /etc/nginx/tls/wecert.key.pem;
    ssl_protocols       TLSv1.2 TLSv1.3;

    root /opt/wecert/console;
    index console.html;

    location /       { try_files $uri $uri/ /console.html; }
    location /api/   { proxy_pass http://127.0.0.1:9801; }
    location /hook/  { proxy_pass http://127.0.0.1:9801; }
    location /admin/ { proxy_pass http://127.0.0.1:9801; }
}
```

Opening inbound 443 is a separate step — a security group created through the
API has no default rules at all, in either direction.

The daemon's tokens come from `webhook.token` (read-only) and
`webhook.adminToken` (management). AK/SK entered here are written as 0600
files on the daemon host and are never echoed back to the browser.
