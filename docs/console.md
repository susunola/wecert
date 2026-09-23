# Read-only inventory console

The console is served at `GET /status` by the existing webhook listener. It shows
certificate status, cloud bindings, expiration, and the latest in-memory TLS
verification results. Search by certificate, domain, account UIN, certificate ID,
CLB, or listener; filter by status or account; open a row for the underlying evidence.
Light and dark themes and a mobile card layout are included.

![Certificate inventory console](console-overview.png)

*Representative example data, rendered by the same `inventory.WritePage` used by the daemon.*

## Enable the listener

Build and install the updated binary using the repository's normal installation
procedure. The HTML, CSS, JavaScript, icons, and logos are embedded in the binary;
there is no frontend build, CDN, asset directory to deploy, or separate UI flag.

Add this block to the existing `/etc/wecert/config.yaml`:

```yaml
webhook:
  listen: 127.0.0.1:9801
  token: "REPLACE_WITH_A_RANDOM_SECRET_OF_AT_LEAST_16_CHARACTERS"
```

Generate a token with `openssl rand -hex 32` and put that value in `webhook.token`.
An existing webhook configuration already enables the console. Optionally set
`tencent.uin` for account grouping; per-certificate `uin` values take precedence.

Restart the installed daemon:

```bash
sudo systemctl restart wecert
```

For a foreground installation, run `./bin/wecert -config /path/to/config.yaml`
without `-once`. Use the existing configuration and state database. The console is
available only while the daemon is running; an hourly `-once` timer does not provide
a continuously available UI. The daemon continues its normal reconciliation work;
only the console and inventory API are read-only.

## Authentication and a quick local snapshot

Both `/status` and `/api/inventory` require the configured token, supplied as
`Authorization: Bearer <token>` or `X-Wecert-Token: <token>`. The token is never
included in the HTML. Opening the daemon URL in an ordinary browser without an
authentication header returns `401`; query-string tokens are not supported.

From a Bash shell on the daemon host:

```bash
read -r -s -p 'Webhook token: ' WECERT_TOKEN
printf '\n'
umask 077
curl --fail --silent --show-error \
  -H "Authorization: Bearer ${WECERT_TOKEN}" \
  http://127.0.0.1:9801/status -o console.html
unset WECERT_TOKEN
```

Open the resulting `console.html` in a browser. Search, filters, sorting, themes,
and details work offline. This file contains a point-in-time inventory: **Refresh
only reloads the saved file**. Fetch it again for new data. It contains no private
keys or certificate PEM, but does contain inventory metadata.

The same authenticated request to `http://127.0.0.1:9801/api/inventory` returns JSON.

## Live browser access

Use an authenticated TLS reverse proxy that inserts the upstream token, or a
loopback-only proxy reached through SSH. Expose only the two read-only routes to
console users: the same upstream listener also has a write-capable
`POST /hook/reconcile` route, and the webhook token can invoke it.

For example, this Nginx `server` block belongs inside the existing `http` context
on the daemon host. Replace the placeholder with the same `webhook.token`, and
keep this configuration readable only by the proxy administrator:

```nginx
server {
    listen 127.0.0.1:9802;
    server_name localhost;

    proxy_set_header Authorization "Bearer REPLACE_WITH_WEBHOOK_TOKEN";
    proxy_set_header X-Wecert-Token "";

    location = /status {
        limit_except GET { deny all; }
        proxy_pass http://127.0.0.1:9801;
    }
    location = /api/inventory {
        limit_except GET { deny all; }
        proxy_pass http://127.0.0.1:9801;
    }
    location / { return 404; }
}
```

Validate and reload your Nginx configuration. This example grants read access to
local users of the daemon host; it deliberately listens only on loopback. From
your workstation, establish a tunnel:

```bash
ssh -N -L 127.0.0.1:9802:127.0.0.1:9802 user@daemon-host
```

Open **http://127.0.0.1:9802/status** on the workstation. **Refresh** requests a new
server snapshot. Reads use the daemon's existing state and caches; they do not
trigger issuance or a Tencent Cloud API enumeration. For shared browser access,
use your existing TLS and SSO gateway instead of exposing this unauthenticated
loopback proxy on a public interface.

## Reading the evidence

- **Configured state**, **deployment record**, and **TLS verification** are separate
  sources. A confirmed upload alone does not prove what an endpoint serves.
- **Passed**, **Failed**, **Unreachable**, **No result**, and **Disabled** remain
  distinct. Each observed host has its own verdict, served expiration, and trust
  result. TLS results are cleared when the daemon restarts.
- **≥** is a minimum known binding count, not a complete cloud inventory. Unknown
  bindings do not mean unbound. Cached bindings include their observation time;
  local deployment records do not invent a cloud observation timestamp.
- **Expiring** means within the configured renewal window. Details include an ARI
  window, retry time, failure reason, and drift tokens when those fields exist.
- Account UINs organize the display. They do not change which cloud credentials
  the daemon uses.

![Certificate evidence drawer](console-detail.png)

## Reproduce the screenshots

The preview test renders the production page with reserved example domains and
synthetic IDs; it does not need cloud credentials or issue certificates:

```bash
WECERT_PREVIEW=/tmp/wecert-console.html \
  go test ./internal/inventory -run '^TestWritePreviewPage$' -count=1
```

Open that file in a browser. For account-picker stress testing, also set
`WECERT_PREVIEW_EXTRA_ACCOUNTS=1`. For edge states and hostile-text escaping, set
`WECERT_EDGE_PREVIEW=/tmp/wecert-console-edge.html` and run
`go test ./internal/inventory -run '^TestWriteConsoleEdgePreview$' -count=1`.
