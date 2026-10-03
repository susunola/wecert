# wecert web console

Standalone management UI for a wecert daemon: certificate create / bind /
renew / delete, cloud accounts, bindings, and activity.

The current management UI is `console.html`, served by nginx at `/`. It has a
KPI strip, an account-grouped inventory, a details drawer and a single-page
create form with a live request summary.

Edit `console.template.html`, `console.css` and `console.js`, then run
`make console-build`. The generated `console.html` has inline CSS and JavaScript,
so deployment needs no frontend runtime or CDN. `make check-console-build`
rejects an out-of-date artifact in CI.

`index.html` is the legacy management layout. The `certificate-first-prototype.*`
files are historical design examples, not sources for the current console.
Their Node checks cover the prototype only. Apply current fixes to the canonical
`console.*` sources and validate with `make check-console2`.

Serve the console on the same origin as the daemon's proxied HTTP routes.
System settings accepts only this page's origin; a different-origin daemon
requires a reverse proxy. TLS is required except on loopback. Login exchanges
tokens for HttpOnly cookies, clears password fields and legacy stored tokens,
and never reads tokens from URL parameters. Use **Sign out** in System settings
to expire the cookies. A read session can inspect inventory; an admin session
is also required for certificate and account management.

`console.html` never renders sample data: with no session it reports
"Disconnected" and shows an empty table, and a rejected token surfaces the
daemon's error instead of a fake fleet. CLB binding issues count certificates
that need a binding and have none — including not-issued ones, and ones whose
payload omits `bindings.complete` entirely, which the daemon does for
certificates that never bound.

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
the row menu, the create form and the payload it posts, the disconnected
and 401 states, and the 390px layout. No daemon or credential is involved.

## How the console is reached

There is no hostname baked into this project. Nothing here knows or needs a
domain of its own; the address is whatever the operator puts in front of the
daemon. Two shapes are supported, and the first one needs no domain and no
certificate at all.

**1. Loopback plus an SSH tunnel.** Serve `console.html` from a listener bound
to `127.0.0.1` on the daemon host and reach it with
`ssh -N -L 127.0.0.1:9802:127.0.0.1:9802 user@daemon-host`. No DNS record, no
certificate, nothing exposed on a public interface. The transport check exempts
`localhost`, `127.0.0.1` and `::1`, so secret entry works here over plain HTTP —
there is no network between the browser and the daemon for anyone else to read.
This is the same topology [`docs/console.md`](../docs/console.md) recommends for
the daemon's own read-only page; that page is a different frontend served by
`GET /status`, but the reasoning is identical.

Note that opening `console.html` straight off the filesystem does not work: with
a `file://` origin there is no daemon to talk to and no same-origin API to call.
It has to be served, even if only from loopback.

**2. A public hostname — only if the console has to be reachable by more than
the person who can SSH to the host.** Then it does need a name and a
certificate, because the same transport check refuses to send a secret over
plain HTTP to anything that is not loopback. That is the case the rest of this
section covers.

Wherever `wecert.example.com` appears below, substitute the name you own. The
name in `server_name` and the name in the port 80 redirect must be the one on
the certificate — a redirect that names some other host sends visitors to an
origin whose certificate will not match, and the browser will stop them there.

If you need shared access but have no domain of your own, put the console behind
your existing TLS and SSO gateway rather than inventing a public name.

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

    add_header Content-Security-Policy "default-src 'self'; img-src 'self' data:; style-src 'self' 'unsafe-inline'; script-src 'self' 'unsafe-inline'; connect-src 'self'; base-uri 'none'; form-action 'self'; frame-ancestors 'none'" always;
    add_header Referrer-Policy "no-referrer" always;
    add_header X-Frame-Options "DENY" always;
    add_header X-Content-Type-Options "nosniff" always;
    proxy_set_header Host $http_host;
    proxy_set_header X-Forwarded-Proto $scheme;

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


### Deployment choices

The Web Console supports Tencent CLB deployment and **Issue only**.
`GET /api/deployment` reports the running backend so unsupported choices are
disabled. Nginx deployment cannot be created, edited or triggered through the
Console. Existing daemon-side Nginx configuration remains supported and is
shown as read-only inventory metadata.

The binding UI exposes Tencent CLB only. Its sole management entry is the
certificate row actions menu; certificate details show binding information
without duplicating the action. Other deployment backends are not offered in
the binding selector or rendered as cloud binding resources.
