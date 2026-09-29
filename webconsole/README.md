# wecert web console

Standalone management UI for a wecert daemon: certificate create / bind /
renew / delete, cloud accounts, bindings, and activity.

`index.html` is self-contained (inline CSS + JS, no build step, no CDN). Serve
it as static files and point the browser at the same origin as the daemon's
HTTP surface, or set the base URL in the Connect panel.

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
