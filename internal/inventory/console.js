"use strict";
const snapshot = JSON.parse(
  document.getElementById("inventory-data").textContent,
);
const records = (snapshot.certificates || []).map((r, index) => ({
  ...r,
  index,
  domains: r.domains || [],
  regions: r.regions || [],
  drift: r.drift || [],
  bindings: {
    ...r.bindings,
    items: r.bindings.items || [],
    resourceTypes: r.bindings.resourceTypes || [],
  },
  probe: { ...r.probe, hosts: r.probe.hosts || [] },
}));
const $ = (id) => document.getElementById(id);
const esc = (value) =>
  String(value ?? "").replace(
    /[&<>"']/g,
    (c) =>
      ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" })[
        c
      ],
  );
const icon = (name) =>
  `<svg class="icon" aria-hidden="true"><use href="#${name}"/></svg>`;
const statuses = {
  frozen: [
    "Frozen",
    "amber",
    "lock-simple",
    "Changes are paused by the desired-state document.",
  ],
  rate_limited: [
    "Rate limited",
    "amber",
    "clock",
    "An issuance rate limit is delaying reconciliation.",
  ],
  revoke_pending: [
    "Revocation pending",
    "red",
    "warning",
    "A requested revocation has not yet been accepted by the CA.",
  ],
  state_unreadable: [
    "State unavailable",
    "red",
    "warning-circle",
    "The local certificate state could not be read.",
  ],
  not_issued: [
    "Not issued",
    "blue",
    "clock",
    "No issued certificate is available in the local state.",
  ],
  waiting_manual_bind: [
    "Awaiting binding",
    "amber",
    "clock",
    "The certificate is uploaded, but its initial CLB binding has not been confirmed.",
  ],
  pending_deploy: [
    "Deployment pending",
    "amber",
    "clock",
    "An issued certificate has not yet been confirmed on the cloud.",
  ],
  probe_mismatch: [
    "TLS check failed",
    "red",
    "warning-circle",
    "The served certificate failed one or more checks for domain coverage, validity, or chain trust.",
  ],
  probe_unreachable: [
    "TLS unreachable",
    "red",
    "plugs",
    "The TLS probe could not retrieve a certificate from the endpoint.",
  ],
  binding_unknown: [
    "Bindings unknown",
    "neutral",
    "cloud",
    "Cloud enumeration is incomplete, so the binding count cannot be determined.",
  ],
  probe_unknown: [
    "TLS unverified",
    "neutral",
    "clock",
    "TLS probing is enabled, but no result has been recorded since daemon startup.",
  ],
  failing: [
    "Reconcile failed",
    "red",
    "warning",
    "One or more recent reconciliation attempts failed.",
  ],
  expiring: [
    "Expiring",
    "amber",
    "clock",
    "The certificate is within its configured renewal window.",
  ],
  ok: [
    "Healthy",
    "green",
    "check-circle",
    "The certificate is issued, deployed as configured, and outside its renewal window. TLS verification has passed or is disabled.",
  ],
};
const statusOf = (r) =>
  statuses[r.status] || [
    "Unknown status",
    "neutral",
    "info",
    "No description is available for this status.",
  ];
const attention = (r) => !["ok", "expiring"].includes(r.status);
const plural = (n, word) => `${n} ${word}${n === 1 ? "" : "s"}`;
const accountLabel = (uin) => uin || "Account unspecified";
const badge = (r) =>
  `<span class="badge badge-${statusOf(r)[1]}" title="${esc(r.status)}">${icon(statusOf(r)[2])}${statusOf(r)[0]}</span>`;
function formatDate(value, withTime = false) {
  if (!value) return "Unavailable";
  const date = new Date(value);
  if (Number.isNaN(date.getTime())) return "Unavailable";
  const options = {
    day: "2-digit",
    month: "short",
    year: "numeric",
    timeZone: "UTC",
  };
  if (withTime)
    Object.assign(options, {
      hour: "2-digit",
      minute: "2-digit",
      hourCycle: "h23",
    });
  return (
    new Intl.DateTimeFormat("en-GB", options).format(date) +
    (withTime ? " UTC" : "")
  );
}
const shortTime = (value) =>
  !value || Number.isNaN(new Date(value).getTime())
    ? "Time unavailable"
    : new Intl.DateTimeFormat("en-GB", {
        hour: "2-digit",
        minute: "2-digit",
        hourCycle: "h23",
        timeZone: "UTC",
      }).format(new Date(value)) + " UTC";
const unread = (kind) => ["unreachable", "no_certificate"].includes(kind);
function probeResult(probe) {
  if (!probe.enabled) return ["Disabled", "unknown", "info"];
  if (probe.ok == null) return ["No result", "unknown", "clock"];
  if (probe.ok) return ["Passed", "good", "check-circle"];
  // A reachable mismatch takes precedence over another host being unreachable.
  const failed = probe.hosts.filter((h) => !h.match);
  if (failed.length && failed.every((h) => unread(h.problemKind)))
    return ["Unreachable", "bad", "plugs"];
  return ["Failed", "bad", "warning-circle"];
}
const probeHTML = (probe) => {
  const result = probeResult(probe);
  return `<span class="probe-result ${result[1]}">${icon(result[2])}${result[0]}</span>`;
};
const bindingSource = (b) =>
  ({
    store: "Local deployment record",
    cached: "Cached cloud inventory",
    live: "Cloud inventory",
    unavailable: "Unavailable",
  })[b.freshness] || "Unavailable";
function bindingCount(b) {
  if (!b.complete && !b.count) return "Bindings unknown";
  return (b.complete ? "" : "≥") + plural(b.count, "binding");
}
const regionLabel = (region) =>
  ({
    "ap-guangzhou": "Guangzhou",
    "ap-shanghai": "Shanghai",
    "ap-beijing": "Beijing",
    "ap-singapore": "Singapore",
  })[region] || region;
function bindingsHTML(r) {
  const b = r.bindings;
  if (r.status === "waiting_manual_bind")
    return '<div class="cell-main muted">Awaiting confirmation</div><div class="cell-sub">Initial CLB binding</div>';
  const regions = r.regions;
  return `<div class="cell-main bind-count">${icon("cloud")}${bindingCount(b)}${regions.length ? `<span class="more" title="${esc(regions.join(", "))}">${esc(regionLabel(regions[0]))}${regions.length > 1 ? " +" + (regions.length - 1) : ""}</span>` : ""}</div><div class="cell-sub">${b.observedAt ? (b.freshness === "cached" ? "Cached " : "Observed ") + esc(shortTime(b.observedAt)) : b.freshness === "store" ? "Deployment record only" : "No observation available"}</div>`;
}
function expiryHTML(r, compact = false) {
  if (r.daysLeft == null)
    return `<span class="muted">${r.status === "not_issued" ? "Not issued" : "Unavailable"}</span>`;
  const days = Math.abs(r.daysLeft);
  if (compact) return `${days}d${r.daysLeft < 0 ? " overdue" : " left"}`;
  return `<div class="days">${days}<span>${r.daysLeft < 0 ? "days overdue" : days === 1 ? "day" : "days"}</span></div><div class="cell-sub">${esc(formatDate(r.notAfter))}</div>`;
}
const state = {
  filter: "all",
  account: "all",
  q: "",
  sort: "attention",
  selected: null,
};
let visibleRecords = [],
  previousFocus;
const statusOrder = [
  "state_unreadable",
  "revoke_pending",
  "frozen",
  "rate_limited",
  "waiting_manual_bind",
  "pending_deploy",
  "probe_mismatch",
  "probe_unreachable",
  "failing",
  "not_issued",
  "binding_unknown",
  "probe_unknown",
  "expiring",
  "ok",
];
function matchingContext() {
  return records.filter(
    (r) =>
      (state.account === "all" || (r.uin || "") === state.account) &&
      [
        r.name,
        r.uin,
        r.deployedCertId,
        r.status,
        ...r.domains,
        ...r.regions,
        ...r.bindings.items.flatMap((b) => [
          b.loadBalancerId,
          b.listenerId,
          b.region,
          b.sniDomain,
        ]),
      ]
        .join(" ")
        .toLowerCase()
        .includes(state.q),
  );
}
function compareRecords(a, b) {
  if (state.sort === "name") return a.name.localeCompare(b.name);
  const expiry = (a.daysLeft ?? Infinity) - (b.daysLeft ?? Infinity);
  if (state.sort === "expiry") return expiry || a.name.localeCompare(b.name);
  return (
    statusOrder.indexOf(a.status) - statusOrder.indexOf(b.status) ||
    expiry ||
    a.name.localeCompare(b.name)
  );
}
function render() {
  const context = matchingContext();
  const counts = {
    all: context.length,
    attention: context.filter(attention).length,
    expiring: context.filter((r) => r.status === "expiring").length,
    healthy: context.filter((r) => r.status === "ok").length,
  };
  const rows = context.filter(
    (r) =>
      state.filter === "all" ||
      (state.filter === "attention" && attention(r)) ||
      (state.filter === "expiring" && r.status === "expiring") ||
      (state.filter === "healthy" && r.status === "ok"),
  );
  const groups = [...new Set(rows.map((r) => r.uin || ""))];
  let html = "",
    mobile = "";
  visibleRecords = [];
  for (const uin of groups) {
    const group = rows
      .filter((r) => (r.uin || "") === uin)
      .sort(compareRecords);
    visibleRecords.push(...group);
    const count = group.filter(attention).length;
    html += `<tr class="group"><td colspan="6"><div class="group-content">${icon("cloud")}<b class="mono">${esc(accountLabel(uin))}</b><span class="certcount">${plural(group.length, "certificate")}</span><span class="group-alert">${count ? `${count} require${count === 1 ? "s" : ""} attention` : "No attention required"}</span></div></td></tr>`;
    mobile += `<section class="mobile-group" aria-label="${esc(accountLabel(uin))}"><h3>${icon("cloud")}<span class="mono">${esc(accountLabel(uin))}</span><span class="small-count">${plural(group.length, "certificate")}</span></h3>`;
    for (const r of group) {
      const domains = `<span class="mono row-domain">${esc(r.domains[0] || "Unavailable")}</span>${r.domains.length > 1 ? `<span class="more">+${r.domains.length - 1}</span>` : ""}`;
      const selected = state.selected === r.index ? "selected" : "";
      html += `<tr class="row ${selected}" data-open="${r.index}"><td>${badge(r)}</td><td><button class="name-button" aria-label="Inspect ${esc(r.name)}" data-open="${r.index}">${esc(r.name)}</button></td><td>${domains}</td><td>${bindingsHTML(r)}</td><td class="${r.status === "expiring" ? "expiry-soon" : ""}">${expiryHTML(r)}</td><td><div class="probe-end">${probeHTML(r.probe)}${icon("caret-right").replace('class="icon"', 'class="icon row-arrow"')}</div></td></tr>`;
      const b = r.bindings;
      mobile += `<button class="cert-card ${selected}" data-open="${r.index}" aria-label="Inspect ${esc(r.name)}"><span class="cert-card-head"><span class="cert-card-title">${esc(r.name)}</span>${icon("caret-right")}</span><div class="cert-card-domain">${domains}</div><div class="cert-card-meta">${badge(r)}<span class="cert-card-signals"><span class="card-expiry ${r.status === "expiring" ? "caution" : ""}">${icon("clock")}${expiryHTML(r, true)}</span>${probeHTML(r.probe)}</span></div><span class="cert-card-binding">${icon("cloud")}${r.status === "waiting_manual_bind" ? "Initial binding unconfirmed" : bindingCount(b)}<span class="source-caption">${b.observedAt ? (b.freshness === "cached" ? "Cached " : "Observed ") + esc(shortTime(b.observedAt)) : b.freshness === "store" ? "Local record" : "Unavailable"}</span></span></button>`;
    }
    mobile += "</section>";
  }
  const empty = `<div class="empty"><strong>${records.length ? "No matching certificates" : "No certificates configured"}</strong><p>${records.length ? "Adjust the account, status, or search term." : "Certificates appear after the daemon reads its configuration or desired-state document."}</p>${records.length ? '<button class="btn" data-reset>Clear filters</button>' : ""}</div>`;
  $("rows").innerHTML = html || `<tr><td colspan="6">${empty}</td></tr>`;
  $("mobile-list").innerHTML = mobile || empty;
  $("result-count").textContent =
    `Showing ${rows.length} of ${context.length} certificates · ${plural(groups.length, "account group")}`;
  $("list-count").textContent = rows.length;
  document.querySelectorAll("[data-filter]").forEach((button) => {
    button.setAttribute("aria-pressed", button.dataset.filter === state.filter);
    button.querySelector("b,.metric-value").textContent =
      counts[button.dataset.filter];
  });
  const accounts = new Set(context.map((r) => r.uin).filter(Boolean)).size;
  const mismatches = context.filter(
    (r) => r.status === "probe_mismatch",
  ).length;
  const waiting = context.filter(
    (r) => r.status === "waiting_manual_bind",
  ).length;
  const closest = context
    .filter((r) => r.status === "expiring" && r.daysLeft != null)
    .sort(compareExpiry)[0];
  const notes = {
    all: accounts
      ? `Across ${plural(accounts, "cloud account")}`
      : "No cloud account specified",
    attention: `${plural(mismatches, "TLS failure")} · ${waiting} awaiting binding`,
    expiring: closest
      ? closest.daysLeft < 0
        ? `${plural(-closest.daysLeft, "day")} overdue`
        : `Next expiration in ${plural(closest.daysLeft, "day")}`
      : counts.expiring
        ? "Expiration time unavailable"
        : "None in the renewal window",
    healthy: "Issued and deployed · No pending renewal",
  };
  document
    .querySelectorAll(".metric")
    .forEach(
      (b) =>
        (b.querySelector(".metric-note").textContent = notes[b.dataset.filter]),
    );
  $("reset-filters").classList.toggle(
    "hidden",
    state.filter === "all" &&
      state.account === "all" &&
      !state.q &&
      state.sort === "attention",
  );
}
function compareExpiry(a, b) {
  return a.daysLeft - b.daysLeft;
}
function resetFilters() {
  Object.assign(state, {
    filter: "all",
    account: "all",
    q: "",
    sort: "attention",
  });
  $("search").value = "";
  $("account").value = "all";
  $("sort").value = "attention";
  render();
}
const field = (label, value, mono = false) =>
  `<div><dt>${label}</dt><dd${mono ? ' class="mono"' : ""}>${esc(value || "Unavailable")}</dd></div>`;
function noticeHTML(r) {
  if (r.status === "ok" && !r.drift.length) return "";
  const s = statusOf(r);
  let message = s[3];
  if (r.status === "waiting_manual_bind")
    message += " Review the listener in the Tencent Cloud console.";
  if (r.status === "probe_unknown")
    message +=
      " Deployment confirmation does not establish which certificate the endpoint serves.";
  if (r.status === "binding_unknown")
    message +=
      " A zero count does not confirm that the certificate is unbound.";
  if (r.status === "frozen" && snapshot.desired.freezeReason)
    message += " " + snapshot.desired.freezeReason;
  return `<div class="notice ${s[1] === "amber" ? "amber" : ["neutral", "blue", "green"].includes(s[1]) ? "neutral" : ""}">${icon(s[2])}<div><h3>${s[0]}</h3><p>${esc(message)}</p>${r.drift.map((d) => `<code>${esc(d)}</code>`).join(" ")}</div></div>`;
}
function bindingDetails(r) {
  const b = r.bindings;
  const items = b.items.length
    ? b.items
        .map(
          (item) =>
            `<div class="binding-item"><div class="binding-item-head"><span class="mono">${esc(item.loadBalancerId || "Resource ID unavailable")}</span><span>${esc(item.region || "Region unavailable")}</span></div><dl class="facts">${field("Resource type", item.resourceType)}${field("Listener ID", item.listenerId, true)}${field("Protocol / port", [item.protocol, item.port || ""].filter(Boolean).join(" / "), true)}${field("SNI hostname", item.sniDomain, true)}${field("Certificate role", { primary: "Primary", ext: "Extended (SNI)" }[item.role] || item.role)}</dl></div>`,
        )
        .join("")
    : `<div class="binding-empty"><div class="binding-empty-title">${icon("cloud")}${bindingCount(b)}</div><p>${b.complete ? "The complete cloud inventory contains no binding resources." : b.count ? "The local deployment record provides a minimum binding count. Resource IDs require cloud enumeration." : "No complete binding inventory is available. A missing count does not mean the certificate is unbound."}</p></div>`;
  return `<section class="detail-section"><h3 class="section-heading">${icon("cloud")}Cloud bindings<span class="right-label">${b.complete ? "Complete inventory" : "Incomplete inventory"}</span></h3>${r.regions.length ? `<div class="section-heading muted" style="font-size:12px">Regions: ${esc(r.regions.map(regionLabel).join(", "))}</div>` : ""}${items}<div class="source-line">${icon("info")}Source: ${bindingSource(b)}${b.observedAt ? " · observed " + esc(formatDate(b.observedAt, true)) : " · observation time unavailable"}${b.resourceTypes.length ? " · scope: " + esc(b.resourceTypes.join(", ")) : ""}</div></section>`;
}
const problems = {
  names_missing: "Configured domains are missing from the served certificate",
  names_extra: "Served certificate contains unexpected domains",
  not_covered: "Served certificate does not cover this hostname",
  not_after: "Expiration does not match the deployed certificate",
  untrusted: "Untrusted certificate chain",
  min_valid_for: "Remaining validity is below the configured minimum",
  unreachable: "Endpoint could not be reached",
  no_certificate: "No certificate received",
};
function probeDetails(r) {
  const p = r.probe;
  let body;
  if (!p.enabled)
    body =
      '<div class="binding-empty"><div class="binding-empty-title">TLS verification is disabled</div><p>Enable TLS probing in the daemon configuration to verify the certificate served by each endpoint.</p></div>';
  else if (!p.hosts.length)
    body =
      '<div class="binding-empty"><div class="binding-empty-title">No TLS result available</div><p>TLS results are held in memory and cleared when the daemon restarts.</p></div>';
  else
    body = p.hosts
      .map((host) => {
        const observed = host.match
          ? "Certificate checks passed"
          : problems[host.problemKind] || "Certificate verification failed";
        const result = probeHTML({
          enabled: true,
          ok: host.match,
          hosts: [host],
        });
        const trust = unread(host.problemKind)
          ? "Certificate validity and chain trust could not be verified"
          : `Served certificate expires ${formatDate(host.notAfter, true)} · Chain ${host.trusted ? "trusted" : "untrusted"}`;
        return `<div class="probe-box"><div class="probe-box-head"><span class="mono">${esc(host.host)}</span>${result}</div><div class="probe-box-body"><div class="comparison"><div><label>EXPECTED</label><p>Configured domains and deployed expiration</p><p class="mono">${esc(formatDate(r.notAfter, true))}</p></div><div><label>OBSERVED</label><div class="evidence-val ${host.match ? "positive" : "negative"}">${icon(host.match ? "check-circle" : "warning-circle")}${observed}</div>${host.problemKind ? `<p class="mono muted">${esc(host.problemKind)}</p>` : ""}</div></div><div class="probe-note">${icon("info")}${esc(trust)}</div></div></div>`;
      })
      .join("");
  return `<section class="detail-section"><h3 class="section-heading">${icon("shield-check")}TLS verification<span class="right-label">Since daemon startup</span></h3>${body}</section>`;
}
function openDetail(index) {
  const r = records[index];
  if (!r) return;
  if (state.selected == null) previousFocus = document.activeElement;
  state.selected = index;
  render();
  const position = visibleRecords.indexOf(r);
  const issued = !!r.notAfter;
  const deployment = r.deployConfirmed
    ? "Confirmed"
    : r.uploaded
      ? "Uploaded, unconfirmed"
      : issued
        ? "Not uploaded"
        : "Unavailable";
  const evidence = `<h3 class="section-heading">${icon("stack")}State comparison</h3><div class="evidence-grid"><div class="evidence"><div class="evidence-label">CONFIGURED STATE</div><div class="evidence-val">${icon("certificate")}${r.domains.length ? "Configured" : "Unavailable"}</div><div class="evidence-sub">${plural(r.domains.length, "configured domain")}</div></div><div class="evidence"><div class="evidence-label">DEPLOYMENT RECORD</div><div class="evidence-val ${r.deployConfirmed ? "positive" : "caution"}">${icon(r.deployConfirmed ? "check-circle" : "clock")}${deployment}</div><div class="evidence-sub">${r.deployedCertId ? "Tencent Cloud SSL" : "No deployment ID"}</div></div><div class="evidence"><div class="evidence-label">TLS VERIFICATION</div><div class="evidence-val">${probeHTML(r.probe)}</div><div class="evidence-sub">${r.probe.enabled ? plural(r.probe.hosts.length, "observed host") : "Probing disabled"}</div></div></div>`;
  const facts = `<h3 class="section-heading">${icon("certificate")}Certificate</h3><dl class="facts"><div><dt>Certificate ID</dt><dd class="mono">${esc(r.deployedCertId || "Unavailable")}${r.deployedCertId ? `<button class="copy-btn" data-copy aria-label="Copy certificate ID">${icon("copy")}</button>` : ""}</dd></div>${field("Expires on", formatDate(r.notAfter, true))}${field("ACME profile / key type", [r.profile, r.keyType].filter(Boolean).join(" / "), true)}${field("Issued on", formatDate(r.issuedAt, true))}</dl><div class="section-heading">Configured domains (SANs)</div><div class="domains-list">${r.domains.map((d) => `<span class="domain-chip mono">${esc(d)}</span>`).join("") || '<span class="muted">Unavailable</span>'}</div>`;
  const ari = r.ari
    ? `<section class="detail-section"><h3 class="section-heading">ACME renewal window</h3><dl class="facts">${field("Window starts", formatDate(r.ari.windowStart, true))}${field("Window ends", formatDate(r.ari.windowEnd, true))}</dl></section>`
    : "";
  const reconcile =
    r.consecutiveFailures || r.nextAttemptAt || r.lastError || r.error
      ? `<section class="detail-section"><h3 class="section-heading">Reconciliation</h3><dl class="facts">${field("Consecutive failures", String(r.consecutiveFailures))}${field("Next attempt", formatDate(r.nextAttemptAt, true))}</dl>${r.error || r.lastError ? `<div class="binding-empty"><p>${esc(r.error || r.lastError)}</p></div>` : ""}</section>`
      : "";
  $("drawer").innerHTML =
    `<div class="drawer-top">${icon("certificate")}Certificate details<span class="spacer"></span><span class="quiet mono">${position + 1} / ${visibleRecords.length}</span><button class="icon-btn" data-step="-1" aria-label="Previous certificate" ${position <= 0 ? "disabled" : ""}>${icon("caret-left")}</button><button class="icon-btn" data-step="1" aria-label="Next certificate" ${position >= visibleRecords.length - 1 ? "disabled" : ""}>${icon("caret-right")}</button><button class="icon-btn" id="drawer-close" aria-label="Close details">${icon("x")}</button></div><div class="drawer-heading"><div class="drawer-title-line">${badge(r)}<span class="pill pill-ro">${icon("lock-simple")}Read-only</span></div><h2 id="detail-title">${esc(r.name)}</h2><div class="drawer-sub">${icon("cloud")}<span class="mono">${esc(accountLabel(r.uin))}</span><span>·</span><span>${plural(r.domains.length, "configured domain")}</span></div><div class="drawer-tabs"><span class="drawer-tab active">Overview and evidence</span><span class="drawer-tab mono" style="margin-left:auto">${esc(r.status)}</span></div></div><div class="drawer-scroll">${noticeHTML(r)}${evidence}${facts}${ari}${bindingDetails(r)}${probeDetails(r)}${reconcile}</div><div class="drawer-bottom">${icon("lock-simple")}Read-only. Changes are managed by the desired-state controller.</div>`;
  $("backdrop").classList.remove("hidden");
  $("drawer").classList.remove("hidden");
  document.querySelector("main").inert = true;
  document.querySelector(".topbar").inert = true;
  document.body.style.overflow = "hidden";
  $("drawer-close").focus({ preventScroll: true });
}
function closeDetail() {
  const index = state.selected;
  $("drawer").classList.add("hidden");
  $("backdrop").classList.add("hidden");
  document.querySelector("main").inert = false;
  document.querySelector(".topbar").inert = false;
  document.body.style.overflow = "";
  state.selected = null;
  render();
  const button = [
    ...document.querySelectorAll(`button[data-open="${index}"]`),
  ].find((el) => el.getClientRects().length);
  (button || previousFocus)?.focus({ preventScroll: true });
}
let toastTimer;
function toast(message) {
  clearTimeout(toastTimer);
  $("toast").textContent = message;
  $("toast").classList.remove("hidden");
  toastTimer = setTimeout(() => $("toast").classList.add("hidden"), 2800);
}
document.querySelectorAll("[data-filter]").forEach((b) =>
  b.addEventListener("click", () => {
    state.filter = b.dataset.filter;
    render();
  }),
);
$("search").addEventListener("input", (e) => {
  state.q = e.target.value.trim().toLowerCase();
  render();
});
$("account").addEventListener("change", (e) => {
  state.account = e.target.value;
  render();
});
$("sort").addEventListener("change", (e) => {
  state.sort = e.target.value;
  render();
});
$("reset-filters").addEventListener("click", resetFilters);
document.querySelector(".inventory").addEventListener("click", (e) => {
  if (e.target.closest("[data-reset]")) {
    resetFilters();
    $("search").focus();
    return;
  }
  const row = e.target.closest("[data-open]");
  if (row) openDetail(Number(row.dataset.open));
});
$("drawer").addEventListener("click", async (e) => {
  if (e.target.closest("#drawer-close")) {
    closeDetail();
    return;
  }
  const step = e.target.closest("[data-step]");
  if (step) {
    const position = visibleRecords.findIndex(
      (r) => r.index === state.selected,
    );
    const next = visibleRecords[position + Number(step.dataset.step)];
    if (next) openDetail(next.index);
  }
  if (e.target.closest("[data-copy]")) {
    try {
      await navigator.clipboard.writeText(
        records[state.selected].deployedCertId,
      );
      toast("Certificate ID copied");
    } catch {
      toast("Unable to copy certificate ID");
    }
  }
});
$("backdrop").addEventListener("click", closeDetail);
function setTheme(theme) {
  document.documentElement.dataset.theme = theme;
  $("theme").innerHTML = icon(theme === "dark" ? "sun" : "moon");
  $("theme").setAttribute(
    "aria-label",
    theme === "dark" ? "Switch to light theme" : "Switch to dark theme",
  );
}
$("theme").addEventListener("click", () => {
  const theme =
    document.documentElement.dataset.theme === "dark" ? "light" : "dark";
  setTheme(theme);
  try {
    localStorage.setItem("wecert-theme", theme);
  } catch {}
});
$("refresh").addEventListener("click", () => location.reload());
$("legend-list").innerHTML = Object.entries(statuses)
  .map(
    ([key, value]) =>
      `<dt>${value[0]}<br><code>${key}</code></dt><dd>${value[3]}</dd>`,
  )
  .join("");
$("legend-open").addEventListener("click", () => $("legend").showModal());
$("legend-close").addEventListener("click", () => $("legend").close());
document.addEventListener("keydown", (e) => {
  if (e.key === "Escape" && state.selected != null) closeDetail();
  if (
    e.key === "/" &&
    !["INPUT", "TEXTAREA", "SELECT"].includes(document.activeElement.tagName) &&
    state.selected == null &&
    !$("legend").open
  ) {
    e.preventDefault();
    $("search").focus();
  }
  if (e.key === "Tab" && state.selected != null) {
    const controls = [
      ...$("drawer").querySelectorAll(
        'button:not(:disabled),a,input,select,[tabindex="0"]',
      ),
    ];
    const first = controls[0],
      last = controls[controls.length - 1];
    if (e.shiftKey && document.activeElement === first) {
      e.preventDefault();
      last.focus();
    } else if (!e.shiftKey && document.activeElement === last) {
      e.preventDefault();
      first.focus();
    }
  }
});
$("snapshot-time").textContent = formatDate(snapshot.time, true);
$("revision").textContent =
  snapshot.desired.revision ||
  (snapshot.desired.frozen == null ? "Not read" : "Revision unavailable");
$("revision").title = snapshot.desired.generatedAt
  ? "Generated " + formatDate(snapshot.desired.generatedAt, true)
  : "";
$("freeze-state").textContent =
  snapshot.desired.frozen == null
    ? "Freeze state unknown"
    : snapshot.desired.frozen
      ? "Frozen"
      : "Not frozen";
$("freeze-state").title = snapshot.desired.freezeReason || "";
$("account").options[0].textContent =
  `All accounts (${new Set(records.map((r) => r.uin || "")).size})`;
let theme = "light";
try {
  theme = localStorage.getItem("wecert-theme") === "dark" ? "dark" : "light";
} catch {}
setTheme(theme);
render();
