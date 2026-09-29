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
const quotas = snapshot.quotas || [];
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
const certIDOf = (r) => String(r.deployedCertId || "").trim();
const aliasOf = (r) => String(r.alias || "").trim();
const serialOf = (r) => String(r.serial || "").trim();
// The full serial is 40 hex characters -- too long for a table cell, and the tail is not what
// anyone reads. The row shows a prefix; the whole value stays in the tooltip and in the detail
// panel, where it can be copied.
const shortSerial = (serial) =>
  serial.length <= 16 ? serial : serial.slice(0, 16) + "…";
// A row shows at most this many names: the certificates here carry one or two (the
// MultiCertInfo pair) and a wildcard set could carry more, but past three the table stops
// being scannable -- the remainder is counted instead of listed.
const MAX_ROW_DOMAINS = 3;
function rowDomainCell(domains) {
  const list = (domains || []).filter(Boolean);
  if (!list.length) return '<span class="mono row-domain">Unavailable</span>';
  const shown = list.slice(0, MAX_ROW_DOMAINS);
  const hidden = list.length - shown.length;
  return (
    '<div class="row-domains">' +
    shown.map((d) => `<div class="mono row-domain">${esc(d)}</div>`).join("") +
    "</div>" +
    (hidden ? `<span class="more">+${hidden} more</span>` : "")
  );
}
// The certificate cell answers "which certificate is this" in both vocabularies an operator has
// to move between: the certificate's own serial number first -- it is what a browser, an auditor
// or the CA asks for, and the only identity that survives a change of DNS provider, cloud account
// or deployment target -- and underneath it the Tencent Cloud SSL id with the remark its console
// lists, which is what the bindings are checked against. The wecert name stays in the tooltip and
// the accessible label, so nothing is lost.
function certificateCell(r) {
  const id = certIDOf(r);
  const alias = aliasOf(r);
  const serial = serialOf(r);
  const label = `Inspect ${r.name}${serial ? ` (serial ${serial})` : ""}${id ? ` (${id})` : ""}`;
  const primary = serial
    ? `<span class="mono cert-id" title="${esc(serial)}">${esc(shortSerial(serial))}</span>`
    : '<span class="cert-id pending">Not issued</span>';
  const cloud = [id, alias].filter(Boolean).join(" · ");
  const secondary = cloud
    ? `<span class="mono cert-alias">${esc(cloud)}</span>`
    : serial
      ? '<span class="cert-alias">Not uploaded</span>'
      : "";
  return `<button class="name-button" title="${esc(r.name)}" aria-label="${esc(label)}" data-open="${r.index}">${primary}${secondary}</button>`;
}
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
const quotaNames = {
  "new-orders": "New orders",
  "certs-per-registered-domain": "Certificates per registered domain",
  "certs-per-exact-identifier-set": "Certificates per exact identifier set",
};
const quotaOrder = Object.keys(quotaNames);
const quotaRecovery = (seconds) => {
  if (seconds < 60) return `Recovers 1 every ${seconds}s`;
  if (seconds < 3600) return `Recovers 1 every ${Math.round(seconds / 60)}m`;
  return `Recovers 1 every ${Math.round(seconds / 3600)}h`;
};
function quotaClass(q) {
  if (q.blocked) return "bad";
  if (q.unreadable || q.spentByCA) return "";
  return q.remaining <= Math.max(1, q.capacity * 0.2) ? "warn" : "";
}
function quotaNote(q) {
  if (q.blocked)
    return q.blockedUntil
      ? `CA blocked until ${formatDate(q.blockedUntil, true)}`
      : "CA has blocked this request type";
  if (q.unreadable) return "Local quota state could not be read";
  if (q.spentByCA) return "Only CA refusals can confirm this state";
  return quotaRecovery(q.refillSeconds);
}
function renderQuotas() {
  const panel = $("quota-panel");
  const families = quotaOrder
    .map((limit) => quotas.filter((q) => q.limit === limit))
    .filter((rows) => rows.length);
  const relevant = families.map((rows) =>
    rows.reduce(
      (worst, row) =>
        !worst || row.blocked || row.remaining < worst.remaining ? row : worst,
      null,
    ),
  );
  if (!relevant.length) return;
  panel.hidden = false;
  const blocked = relevant.filter((q) => q.blocked).length;
  const warning = relevant.filter((q) => quotaClass(q) === "warn").length;
  $("quota-state").className =
    `quota-state ${blocked ? "bad" : warning ? "warn" : ""}`;
  $("quota-state").innerHTML = blocked
    ? `${icon("warning-circle")}${blocked} blocked by CA`
    : warning
      ? `${icon("warning-circle")}${warning} near limit`
      : `${icon("check-circle")}Within local estimate`;
  $("quota-grid").innerHTML = relevant
    .map((q, index) => {
      const cls = quotaClass(q);
      const percent =
        q.unreadable || q.spentByCA
          ? 0
          : Math.max(0, Math.min(100, (q.remaining / q.capacity) * 100));
      const value = q.unreadable || q.spentByCA ? "—" : Math.floor(q.remaining);
      const count = families[index].length;
      return `<article class="quota-item ${cls}"><div class="quota-label"><span>${esc(quotaNames[q.limit] || q.limit)}</span><span class="scope">${count} scope${count === 1 ? "" : "s"}</span></div><div class="quota-value"><strong>${value}</strong><span>of ${q.capacity}</span></div><div class="quota-meter" aria-hidden="true"><span style="width:${percent}%"></span></div><div class="quota-note">${esc(quotaNote(q))}</div></article>`;
    })
    .join("");
  const detailRows = families
    .flat()
    .sort(
      (a, b) =>
        Number(b.blocked) - Number(a.blocked) ||
        a.remaining - b.remaining ||
        a.scope.localeCompare(b.scope),
    );
  $("quota-details-summary").textContent =
    `View ${detailRows.length} tracked quota scopes, ordered by available capacity`;
  $("quota-rows").innerHTML = detailRows
    .map((q) => {
      const cls = quotaClass(q);
      const available =
        q.unreadable || q.spentByCA
          ? "Unavailable"
          : `${Math.floor(q.remaining)} of ${q.capacity}`;
      return `<tr><td>${esc(quotaNames[q.limit] || q.limit)}</td><td class="mono" title="${esc(q.scope || "This account")}">${esc(q.scope || "This account")}</td><td class="quota-number ${cls}">${esc(available)}</td><td>${esc(quotaNote(q))}</td></tr>`;
    })
    .join("");
}
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
        r.alias,
        r.deployedCertId,
        r.serial,
        r.ariCertId,
        r.acmeCertUrl,
        r.previous && r.previous.certId,
        ...(r.retired || []).map((x) => x.certId),
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
  renderQuotas();
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
    html += `<tr class="group"><td colspan="7"><div class="group-content">${icon("cloud")}<b class="mono">${esc(accountLabel(uin))}</b><span class="certcount">${plural(group.length, "certificate")}</span><span class="group-alert">${count ? `${count} require${count === 1 ? "s" : ""} attention` : "No attention required"}</span></div></td></tr>`;
    mobile += `<section class="mobile-group" aria-label="${esc(accountLabel(uin))}"><h3>${icon("cloud")}<span class="mono">${esc(accountLabel(uin))}</span><span class="small-count">${plural(group.length, "certificate")}</span></h3>`;
    for (const r of group) {
      const domains = rowDomainCell(r.domains);
      const selected = state.selected === r.index ? "selected" : "";
      html += `<tr class="row ${selected}" data-open="${r.index}"><td>${badge(r)}</td><td>${certificateCell(r)}</td><td>${domains}</td><td>${bindingsHTML(r)}</td><td class="${r.status === "expiring" ? "expiry-soon" : ""}">${expiryHTML(r)}</td><td><div class="probe-end">${probeHTML(r.probe)}${icon("caret-right").replace('class="icon"', 'class="icon row-arrow"')}</div></td><td class="row-actions">${renewButton(r)}</td></tr>`;
      const b = r.bindings;
      mobile += `<button class="cert-card ${selected}" data-open="${r.index}" aria-label="Inspect ${esc(r.name)}${serialOf(r) ? ` (serial ${esc(serialOf(r))})` : ""}${certIDOf(r) ? ` (${esc(certIDOf(r))})` : ""}"><span class="cert-card-head"><span class="cert-card-title">${esc(serialOf(r) ? shortSerial(serialOf(r)) : r.name)}</span>${icon("caret-right")}</span><div class="cert-card-domain">${domains}</div>${certIDOf(r) || aliasOf(r) ? `<div class="cert-card-alias mono">${esc([certIDOf(r), aliasOf(r)].filter(Boolean).join(" · "))}</div>` : ""}<div class="cert-card-meta">${badge(r)}<span class="cert-card-signals"><span class="card-expiry ${r.status === "expiring" ? "caution" : ""}">${icon("clock")}${expiryHTML(r, true)}</span>${probeHTML(r.probe)}</span></div><span class="cert-card-binding">${icon("cloud")}${r.status === "waiting_manual_bind" ? "Initial binding unconfirmed" : bindingCount(b)}<span class="source-caption">${b.observedAt ? (b.freshness === "cached" ? "Cached " : "Observed ") + esc(shortTime(b.observedAt)) : b.freshness === "store" ? "Local record" : "Unavailable"}</span></span></button><div class="mobile-actions">${renewButton(r)}</div>`;
    }
    mobile += "</section>";
  }
  const empty = `<div class="empty"><strong>${records.length ? "No matching certificates" : "No certificates configured"}</strong><p>${records.length ? "Adjust the account, status, or search term." : "Certificates appear after the daemon reads its configuration or desired-state document."}</p>${records.length ? '<button class="btn" data-reset>Clear filters</button>' : ""}</div>`;
  $("rows").innerHTML = html || `<tr><td colspan="7">${empty}</td></tr>`;
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
// The certificate's two identities, side by side, because they answer different questions: the
// serial number is on the certificate itself -- what a browser, an auditor or the CA asks for, and
// the only identity that survives a change of DNS provider, cloud account or deployment target --
// while the cloud id and its remark are what the SSL console lists and what the bindings hang off.
function identityFacts(r) {
  const serial = serialOf(r);
  const id = certIDOf(r);
  const copy = (what, title) =>
    `<button class="copy-btn" data-copy="${what}" aria-label="${title}">${icon("copy")}</button>`;
  const rows = [
    `<div><dt>Serial number</dt><dd class="mono">${esc(serial || "Unavailable")}${serial ? copy("serial", "Copy serial number") : ""}</dd></div>`,
    `<div><dt>Certificate ID (Tencent Cloud)</dt><dd class="mono">${esc(id || "Unavailable")}${id ? copy("deployedCertId", "Copy certificate ID") : ""}</dd></div>`,
  ];
  if (aliasOf(r))
    rows.push(`<div><dt>SSL remark</dt><dd class="mono">${esc(aliasOf(r))}</dd></div>`);
  if (r.acmeCertUrl) rows.push(field("ACME certificate URL", r.acmeCertUrl, true));
  if (r.ariCertId) rows.push(field("ARI certificate ID", r.ariCertId, true));
  rows.push(
    r.previous
      ? `<div><dt>Previous certificate</dt><dd class="mono">${esc(r.previous.certId)}${r.previous.swappedAt ? ` · swapped ${esc(formatDate(r.previous.swappedAt, true))}` : ""}</dd></div>`
      : // Empty is the normal answer for a first issuance, and the honest one for a name that was
        // renewed before this column existed: the reclaim queue cannot say which of its rows the
        // name actually served, so nothing is claimed here.
        `<div><dt>Previous certificate</dt><dd>No swap recorded yet${(r.retired || []).length ? '<span class="muted"> — see the rollback window below</span>' : ""}</dd></div>`,
  );
  return rows.join("");
}
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
      '<div class="binding-empty"><div class="binding-empty-title">No TLS result available</div><p>No completed TLS probe has been recorded for this certificate yet.</p></div>';
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
        const at = host.observedAt ? ` · Observed ${formatDate(host.observedAt, true)}` : "";
        return `<div class="probe-box"><div class="probe-box-head"><span class="mono">${esc(host.host)}</span>${result}</div><div class="probe-box-body"><div class="comparison"><div><label>EXPECTED</label><p>Configured domains and deployed expiration</p><p class="mono">${esc(formatDate(r.notAfter, true))}</p></div><div><label>OBSERVED</label><div class="evidence-val ${host.match ? "positive" : "negative"}">${icon(host.match ? "check-circle" : "warning-circle")}${observed}</div>${host.problemKind ? `<p class="mono muted">${esc(host.problemKind)}</p>` : ""}</div></div><div class="probe-note">${icon("info")}${esc(trust + at)}</div></div></div>`;
      })
      .join("");
  return `<section class="detail-section"><h3 class="section-heading">${icon("shield-check")}TLS verification<span class="right-label">Last recorded result</span></h3>${body}</section>`;
}
// ── Renew: the one write action on this page ────────────────────────────────────────────────────
//
// Everything else here only changes what is displayed, and that property is worth keeping: the
// page cannot issue, bind, or delete anything on its own. Renew is the deliberate exception. It
// edits the desired-state document through the renew agent (loopback, Basic Auth in front, a
// custom header to keep a cross-site form post out) and triggers one convergence for that
// certificate, so the panel says what it will do, asks for the certificate name as confirmation,
// and then reports what the server actually did.
//
// The domain set lives in the desired-state document, not in this page: the panel reads the
// current set from the agent, and the server validates the whole candidate document with wecert
// itself before writing it -- any rule this page gets wrong is caught there.

const RENEW_HEADERS = { "X-Wecert-Intent": "renew", "Content-Type": "application/json" };
let renew = null; // {index, name, data, draft, dirty, busy, notice, error, poll}

function renewButton(r) {
  // No data-open: the row itself opens the detail drawer, and a click here must do one thing.
  return `<button class="renew-btn" data-renew="${r.index}" aria-label="Renew ${esc(r.name)}">${icon("arrow-clockwise")}Renew</button>`;
}

async function renewRequest(path, options) {
  const response = await fetch(path, { cache: "no-store", headers: RENEW_HEADERS, ...options });
  const body = await response.json().catch(() => ({ error: `HTTP ${response.status}` }));
  if (!response.ok) {
    const detail = body.detail ? `${body.error}: ${String(body.detail).split("\n").slice(-1)[0]}` : body.error;
    throw new Error(detail || `HTTP ${response.status}`);
  }
  return body;
}

async function openRenew(index) {
  const r = records[index];
  if (!r) return;
  if (renew && renew.poll) clearTimeout(renew.poll);
  renew = { index, name: r.name, data: null, draft: [], audit: [], dirty: false, busy: false, notice: "", error: "", poll: null };
  if (state.selected == null) previousFocus = document.activeElement;
  state.selected = index;
  render();
  $("drawer").innerHTML = renewShell();
  $("backdrop").classList.remove("hidden");
  $("drawer").classList.remove("hidden");
  document.querySelector("main").inert = true;
  document.querySelector(".topbar").inert = true;
  document.body.style.overflow = "hidden";
  $("drawer-close").focus({ preventScroll: true });
  await refreshRenew();
}

function renewShell() {
  return `<div class="drawer-top">${icon("arrow-clockwise")}Renew certificate<span class="spacer"></span><span class="pill pill-write">${icon("warning")}Writes desired state</span><button class="icon-btn" id="drawer-close" aria-label="Close renew panel">${icon("x")}</button></div><div class="drawer-heading"><div class="drawer-title-line"><span class="pill pill-ro">${icon("certificate")}${esc(renew.name)}</span></div><h2 id="detail-title">Renew now</h2><div class="drawer-sub">Change the domain set and reissue. The certificate keeps its name, so the cloud keeps the existing bindings and swaps them to the new certificate.</div></div><div class="drawer-scroll" id="renew-body"><p class="muted">Loading the current state…</p></div>`;
}

async function refreshRenew() {
  if (!renew) return;
  try {
    renew.data = await renewRequest(`/renew/cert/${encodeURIComponent(renew.name)}`);
    // The audit trail is a separate read: it is the record of what was asked for, which is a
    // different question from what the certificate looks like now.
    const audit = await renewRequest(`/renew/audit?cert=${encodeURIComponent(renew.name)}&limit=8`);
    renew.audit = audit.lines || [];
  } catch (err) {
    renew.error = String(err.message || err);
  }
  if (!renew.dirty && renew.data) renew.draft = (renew.data.desiredDomains || []).slice();
  paintRenew();
}

function renewDiff() {
  const before = (renew.data && renew.data.desiredDomains) || [];
  const now = renew.draft.map((d) => (d || "").trim().toLowerCase()).filter(Boolean);
  return {
    added: now.filter((d) => !before.includes(d)),
    removed: before.filter((d) => !now.includes(d)),
    domains: now,
  };
}

function renewBoundRemoved() {
  const bound = (renew.data && renew.data.boundDomains) || [];
  return renewDiff().removed.filter((d) => bound.includes(d));
}

function renewPreviewHTML() {
  const diff = renewDiff();
  const parts = [];
  if (diff.added.length) parts.push(`<div class="renew-chips">${diff.added.map((d) => `<span class="renew-chip add mono">+ ${esc(d)}</span>`).join("")}</div>`);
  if (diff.removed.length) parts.push(`<div class="renew-chips">${diff.removed.map((d) => `<span class="renew-chip remove mono">− ${esc(d)}</span>`).join("")}</div>`);
  if (!parts.length) parts.push('<p class="muted">No change yet: add or remove a domain.</p>');
  return parts.join("");
}

function renewWarnHTML() {
  const boundRemoved = renewBoundRemoved();
  if (!boundRemoved.length) return "";
  return `<div class="renew-warn">${icon("warning-circle")}<div><strong>Remove the cloud reference first.</strong> ${boundRemoved.map((d) => `<span class="mono">${esc(d)}</span>`).join(", ")} ${boundRemoved.length > 1 ? "are" : "is"} still referenced by a load balancer. Renew anyway and the listener will serve a certificate that no longer covers ${boundRemoved.length > 1 ? "them" : "it"}: delete the reference on the Tencent Cloud side first, then bind again by hand.</div></div>`;
}

function renewProgressHTML() {
  const issue = (renew.data && renew.data.issue) || {};
  const state = issue.state || "unchanged";
  const label = {
    unchanged: ["Idle", "No renewal filed from this console yet."],
    reissuing: ["Reissuing…", "The order is running: DNS challenge, validation, upload, then the cloud swaps the existing bindings."],
    issued: ["Done", "A new certificate is in effect. Check the serial and the binding below."],
    failed: ["Failed or stuck", issue.hint || "No new issuance was recorded. Check the daemon journal for this certificate."],
    rejected: ["Rejected", "The last edit was refused; nothing was written."],
  }[state] || [state, ""];
  const last = issue.lastChange;
  const detail = last
    ? `<p class="muted mono">${esc(last.ts || "")} · ${esc(last.result || "")}${last.to && last.to.length ? ` · ${esc(last.to.join(", "))}` : ""}</p>`
    : "";
  // The table behind this panel was rendered from the snapshot the page loaded with, so it keeps
  // showing the previous certificate until the page is reloaded. Saying that here is cheaper than
  // letting someone conclude the renewal did nothing.
  const stale = state === "issued" ? '<p class="muted">The table behind this panel still shows the previous certificate: reload the page to refresh it.</p>' : "";
  return `<div class="renew-progress" data-state="${esc(state)}"><strong>${esc(label[0])}</strong><span>${esc(label[1])}</span>${detail}${stale}${issue.lastError ? `<p class="renew-error mono">${esc(issue.lastError)}</p>` : ""}</div>`;
}

function paintRenew() {
  if (!renew || !$("renew-body")) return;
  const data = renew.data;
  if (!data && renew.error) {
    $("renew-body").innerHTML = `<div class="renew-warn">${icon("warning-circle")}<div>${esc(renew.error)}</div></div><p class="muted">The renew agent answers on <span class="mono">/renew/</span> and is only reachable through the console ingress.</p>`;
    return;
  }
  if (!data) return;
  const issued = data.issued || {};
  // html:true marks the one value that is markup (the binding list), so nothing else can be
  // injected by accident -- a certificate id or an error string is data, not markup.
  const facts = [
    { label: "Serial number", value: issued.serial || "Unavailable", mono: true },
    { label: "Certificate ID · SSL remark", value: [issued.certId, issued.alias].filter(Boolean).join(" · ") || "Not uploaded", mono: true },
    { label: "Expires", value: issued.notAfter ? `${formatDate(issued.notAfter, true)}${issued.daysLeft != null ? ` · ${issued.daysLeft} days left` : ""}` : "Unavailable" },
    { label: "Last issued", value: issued.issuedAt ? formatDate(issued.issuedAt, true) : "Unavailable" },
  ];
  if (data.previous && data.previous.certId) {
    facts.push({ label: "Previous certificate", value: `${data.previous.certId}${data.previous.swappedAt ? ` · swapped ${formatDate(data.previous.swappedAt, true)}` : ""}`, mono: true });
  }
  const bindings = (data.bindings || []).length
    ? data.bindings
        .map((b) => esc([b.lb, b.listener, b.protocol, b.port, b.role].filter(Boolean).join(" · ") + (b.sniDomain ? ` · ${b.sniDomain}` : "")))
        .join("<br>")
    : "None";
  facts.push({ label: "Current bindings", value: bindings, html: true });

  const audit = (renew.audit || []).slice(0, 8);
  $("renew-body").innerHTML =
    `<section class="detail-section"><h3 class="section-heading">${icon("certificate")}Current certificate</h3><dl class="facts">${facts.map((f) => `<div><dt>${esc(f.label)}</dt><dd${f.mono ? ' class="mono"' : ""}>${f.html ? f.value : esc(f.value)}</dd></div>`).join("")}</dl></section>` +
    `<section class="detail-section"><h3 class="section-heading">${icon("plugs")}Domains<span class="right-label">${renew.draft.length} of ${data.profiles ? data.profiles.maxNames : 100}</span></h3><p class="muted">One certificate must stay inside one registered domain. Wildcards are written as <span class="mono">*.example.com</span> and do not cover deeper subdomains.</p><div class="renew-domains">${renew.draft.map((d, i) => `<div class="renew-domain"><input class="renew-input mono" data-renew-field="${i}" value="${esc(d)}" spellcheck="false" autocomplete="off" aria-label="Domain ${i + 1}" /><button class="icon-btn" data-renew-remove="${i}" aria-label="Remove domain ${i + 1}">${icon("x")}</button></div>`).join("")}</div><div class="renew-actions"><button class="btn" data-renew-add>${icon("arrow-right")}Add domain</button><button class="btn" data-renew-reset ${renew.dirty ? "" : "disabled"}>Revert to current</button></div></section>` +
    `<section class="detail-section"><h3 class="section-heading">${icon("stack")}Preview</h3><div id="renew-preview">${renewPreviewHTML()}</div><div id="renew-warnings">${renewWarnHTML()}</div></section>` +
    `<section class="detail-section"><h3 class="section-heading">${icon("clock")}Renewal plan</h3><dl class="facts"><div><dt>Renewal window</dt><dd class="mono">${data.ari && data.ari.windowStart ? `${esc(formatDate(data.ari.windowStart, true))} → ${esc(formatDate(data.ari.windowEnd, true))}` : "Unavailable"}</dd></div><div><dt>Document revision</dt><dd class="mono">${esc(data.documentRevision || "")}</dd></div></dl><p class="muted">A renewal outside the window is allowed but spends the CA's per-set quota: five certificates for the same identifier set per week. The window exists so an ordinary renewal costs nothing.</p></section>` +
    `<section class="detail-section"><h3 class="section-heading">${icon("arrow-clockwise")}Submit</h3><p class="muted">Type the certificate name to confirm. Only the domain set of this certificate changes; nothing else in the desired state is touched.</p><div class="renew-confirm"><input id="renew-confirm" class="renew-input mono" placeholder="${esc(renew.name)}" spellcheck="false" autocomplete="off" aria-label="Type the certificate name to confirm" /><button class="btn btn-primary" data-renew-submit ${renew.busy ? "disabled" : ""}>${icon("arrow-clockwise")}${renew.busy ? "Filing…" : "Renew now"}</button></div>${renew.notice ? `<div class="renew-notice">${icon("check-circle")}<div>${renew.notice}</div></div>` : ""}${renew.error ? `<div class="renew-warn">${icon("warning-circle")}<div>${esc(renew.error)}</div></div>` : ""}${renewProgressHTML()}</section>` +
    (audit.length
      ? `<section class="detail-section"><h3 class="section-heading">${icon("book-open")}Recent changes<span class="right-label">from the audit log</span></h3><div class="renew-audit">${audit.map((a) => `<div class="renew-audit-row"><span class="mono">${esc(a.ts || "")}</span><span class="mono">${esc(a.ip || "")}</span><span class="renew-audit-result" data-result="${esc(a.result || "")}">${esc(a.result || "")}</span><span class="mono">${esc((a.from || []).join(", "))} → ${esc((a.to || []).join(", "))}</span></div>`).join("")}</div></section>`
      : "");
}

async function submitRenew() {
  if (!renew || renew.busy) return;
  const confirm = ($("renew-confirm") || {}).value || "";
  const domains = renewDiff().domains;
  if (!domains.length) {
    renew.error = "The domain list cannot be empty: a certificate with no names is not something the CA will issue.";
    paintRenew();
    return;
  }
  renew.busy = true;
  renew.error = "";
  renew.notice = "";
  paintRenew();
  try {
    const result = await renewRequest(`/renew/cert/${encodeURIComponent(renew.name)}`, {
      method: "POST",
      body: JSON.stringify({ domains, confirm: confirm.trim() }),
    });
    const lines = [];
    if (result.added && result.added.length) lines.push(`added ${result.added.join(", ")}`);
    if (result.removed && result.removed.length) lines.push(`removed ${result.removed.join(", ")}`);
    renew.notice =
      `Filed. ${lines.length ? lines.join("; ") + ". " : ""}The previous document is kept as <span class="mono">${esc((result.backup || "").split("/").pop() || "a backup")}</span> and revision <span class="mono">${esc(result.revisionBefore || "")}</span> → <span class="mono">${esc(result.revisionAfter || "")}</span>.`;
    renew.dirty = false;
    if (result.warning) renew.error = result.warning;
    scheduleRenewPoll();
  } catch (err) {
    renew.error = String(err.message || err);
  } finally {
    renew.busy = false;
    await refreshRenew();
  }
}

function scheduleRenewPoll() {
  if (!renew) return;
  clearTimeout(renew.poll);
  renew.poll = setTimeout(async () => {
    if (!renew) return;
    await refreshRenew();
    const state = (renew.data && renew.data.issue && renew.data.issue.state) || "unchanged";
    if (state === "reissuing") scheduleRenewPoll();
    else renew.poll = null;
  }, 5000);
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
  const facts = `<h3 class="section-heading">${icon("certificate")}Certificate</h3><dl class="facts">${identityFacts(r)}${field("Expires on", formatDate(r.notAfter, true))}${field("ACME profile / key type", [r.profile, r.keyType].filter(Boolean).join(" / "), true)}${field("Issued on", formatDate(r.issuedAt, true))}</dl><div class="section-heading">Configured domains (SANs)</div><div class="domains-list">${r.domains.map((d) => `<span class="domain-chip mono">${esc(d)}</span>`).join("") || '<span class="muted">Unavailable</span>'}</div>`;
  const ari = r.ari
    ? `<section class="detail-section"><h3 class="section-heading">ACME renewal window</h3><dl class="facts">${field("Window starts", formatDate(r.ari.windowStart, true))}${field("Window ends", formatDate(r.ari.windowEnd, true))}</dl></section>`
    : "";
  // What is still inside the rollback window. It is deliberately a separate section from "Previous
  // certificate": this list is every certificate queued for reclamation under the name, which
  // includes uploads that were never bound, so it is not a history of what served traffic.
  const rollback = (r.retired || []).length
    ? `<section class="detail-section"><h3 class="section-heading">Rollback window</h3><dl class="facts">${r.retired.map((x) => field(x.certId, x.retiredAt ? formatDate(x.retiredAt, true) : "material not archived", true)).join("")}</dl><p class="muted" style="margin-top:6px">Retired certificates stay reclaimable for seven days. The list also holds uploads that were never bound; the certificate this name served before the current one is the one named under "Previous certificate".</p></section>`
    : "";
  const reconcile =
    r.consecutiveFailures || r.nextAttemptAt || r.lastError || r.error
      ? `<section class="detail-section"><h3 class="section-heading">Reconciliation</h3><dl class="facts">${field("Consecutive failures", String(r.consecutiveFailures))}${field("Next attempt", formatDate(r.nextAttemptAt, true))}</dl>${r.error || r.lastError ? `<div class="binding-empty"><p>${esc(r.error || r.lastError)}</p></div>` : ""}</section>`
      : "";
  $("drawer").innerHTML =
    `<div class="drawer-top">${icon("certificate")}Certificate details<span class="spacer"></span><span class="quiet mono">${position + 1} / ${visibleRecords.length}</span><button class="icon-btn" data-step="-1" aria-label="Previous certificate" ${position <= 0 ? "disabled" : ""}>${icon("caret-left")}</button><button class="icon-btn" data-step="1" aria-label="Next certificate" ${position >= visibleRecords.length - 1 ? "disabled" : ""}>${icon("caret-right")}</button><button class="icon-btn" id="drawer-close" aria-label="Close details">${icon("x")}</button></div><div class="drawer-heading"><div class="drawer-title-line">${badge(r)}<span class="pill pill-ro">${icon("lock-simple")}Read-only</span></div><h2 id="detail-title">${esc(r.name)}</h2><div class="drawer-sub">${icon("cloud")}<span class="mono">${esc(accountLabel(r.uin))}</span><span>·</span><span>${plural(r.domains.length, "configured domain")}</span></div><div class="drawer-tabs"><span class="drawer-tab active">Overview and evidence</span><span class="drawer-tab mono" style="margin-left:auto">${esc(r.status)}</span></div></div><div class="drawer-scroll">${noticeHTML(r)}${evidence}${facts}${ari}${rollback}${bindingDetails(r)}${probeDetails(r)}${reconcile}</div><div class="drawer-bottom">${icon("lock-simple")}Read-only. The only change this page can make is <strong>Renew</strong>, which edits the desired-state document for one certificate and triggers one convergence.</div>`;
  $("backdrop").classList.remove("hidden");
  $("drawer").classList.remove("hidden");
  document.querySelector("main").inert = true;
  document.querySelector(".topbar").inert = true;
  document.body.style.overflow = "hidden";
  $("drawer-close").focus({ preventScroll: true });
}
function closeDetail() {
  const index = state.selected;
  // A renewal may still be polling for its result; leaving the timer behind would keep hitting the
  // agent (and repainting a panel that is no longer on screen) long after the drawer closed.
  if (renew) {
    clearTimeout(renew.poll);
    renew = null;
  }
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
  // Before the row check: the Renew button sits inside a row that opens the detail drawer, and a
  // click on it has to do exactly one thing.
  const renewBtn = e.target.closest("[data-renew]");
  if (renewBtn) {
    openRenew(Number(renewBtn.dataset.renew));
    return;
  }
  const row = e.target.closest("[data-open]");
  if (row) openDetail(Number(row.dataset.open));
});
$("drawer").addEventListener("input", (e) => {
  const field = e.target.closest("[data-renew-field]");
  if (!field || !renew) return;
  renew.draft[Number(field.dataset.renewField)] = e.target.value;
  renew.dirty = true;
  // Repaint the preview and the warnings only: re-rendering the whole panel would take the focus
  // out of the field being typed into, and the warnings are the part that has to keep up.
  if ($("renew-preview")) $("renew-preview").innerHTML = renewPreviewHTML();
  if ($("renew-warnings")) $("renew-warnings").innerHTML = renewWarnHTML();
});
$("drawer").addEventListener("click", async (e) => {
  if (e.target.closest("#drawer-close")) {
    closeDetail();
    return;
  }
  // ── renew panel controls (only present while that panel is open) ──
  if (renew) {
    if (e.target.closest("[data-renew-add]")) {
      renew.draft.push("");
      renew.dirty = true;
      paintRenew();
      const inputs = document.querySelectorAll("[data-renew-field]");
      if (inputs.length) inputs[inputs.length - 1].focus();
      return;
    }
    const removeBtn = e.target.closest("[data-renew-remove]");
    if (removeBtn) {
      renew.draft.splice(Number(removeBtn.dataset.renewRemove), 1);
      renew.dirty = true;
      paintRenew();
      return;
    }
    if (e.target.closest("[data-renew-reset]")) {
      renew.dirty = false;
      renew.error = "";
      renew.notice = "";
      await refreshRenew();
      return;
    }
    if (e.target.closest("[data-renew-submit]")) {
      await submitRenew();
      return;
    }
  }
  const step = e.target.closest("[data-step]");
  if (step) {
    const position = visibleRecords.findIndex(
      (r) => r.index === state.selected,
    );
    const next = visibleRecords[position + Number(step.dataset.step)];
    if (next) openDetail(next.index);
  }
  const copyBtn = e.target.closest("[data-copy]");
  if (copyBtn) {
    // Two identities, two copy buttons: the serial number is what the CA and a browser know the
    // certificate by, the certificate id is what the cloud console and the bindings use.
    const record = records[state.selected] || {};
    const which = copyBtn.dataset.copy;
    const isSerial = which === "serial";
    const what = isSerial ? "Serial number" : "Certificate ID";
    const value = isSerial ? record.serial : record.deployedCertId;
    try {
      await navigator.clipboard.writeText(value || "");
      toast(`${what} copied`);
    } catch {
      toast(`Unable to copy ${what.toLowerCase()}`);
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
