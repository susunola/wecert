const $ = (selector) => document.querySelector(selector);
const escapeHTML = (value) => String(value ?? '').replace(/[&<>"']/g, (char) => ({
  '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;'
})[char]);

// Local, monochrome icons keep the file preview independent of network access.
function icon(name) {
  const paths = {
    certificate: '<rect x="5" y="3" width="14" height="18" rx="2"/><path d="M9 8h6M9 12h6M9 16h3"/>',
    alert: '<path d="m12 3 10 18H2L12 3Z M12 9v5 M12 17h.01"/>',
    clock: '<circle cx="12" cy="12" r="9"/><path d="M12 7v5l3 2"/>',
    link: '<path d="m10 13 4-4M8 16l-1 1a4 4 0 0 1-6-6l4-4a4 4 0 0 1 6 0m2 1 1-1a4 4 0 0 1 6 6l-4 4a4 4 0 0 1-6 0"/>',
    bell: '<path d="M18 8a6 6 0 0 0-12 0c0 7-3 7-3 9h18c0-2-3-2-3-9M10 21h4"/>',
    settings: '<path d="M4 7h16M4 17h16"/><circle cx="9" cy="7" r="3" fill="white"/><circle cx="15" cy="17" r="3" fill="white"/>',
    plus: '<path d="M12 5v14M5 12h14"/>',
    search: '<circle cx="10.5" cy="10.5" r="6.5"/><path d="m16 16 5 5"/>',
    down: '<path d="m6 9 6 6 6-6"/>',
    close: '<path d="m6 6 12 12M6 18 18 6"/>',
    copy: '<rect x="8" y="8" width="12" height="12" rx="2"/><path d="M16 8V4H4v12h4"/>',
    globe: '<circle cx="12" cy="12" r="9"/><ellipse cx="12" cy="12" rx="4" ry="9"/><path d="M3 12h18"/>',
    refresh: '<path d="M20 7v5h-5M4 17v-5h5M5 8a8 8 0 0 1 13-3l2 3M4 16l2 3a8 8 0 0 0 13-3"/>'
  };
  return `<svg class="ui-icon" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.7" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true">${paths[name] || paths.certificate}</svg>`;
}

const RETRY_SECONDS = 15;
const state = {
  base: '', token: '', adminToken: '', live: false, preview: false,
  lastSync: null, retryTimer: null,
  accounts: [], certificates: [], uin: 'all', status: 'all',
  sort: 'expiry', search: '', selected: '', detailOpen: false, collapsed: new Set()
};
let toastTimer;
const operationLog = [];
let detailReturnFocus;
function recordOperation(name, message) {
  operationLog.unshift({ name, message, time: new Date().toLocaleTimeString() });
  operationLog.splice(30);
  if (state.detailOpen) renderDetail();
}
/* Cloud bindings. The count is what the last enumeration saw -- a store-side count is what wecert
   deployed, not what exists, which is why the completeness marker and the freshness line are part
   of the cell rather than footnotes: "1 binding" and "≥1 binding, local record" are different
   claims about the world. */
const REGION_LABELS = {
  'ap-guangzhou': 'Guangzhou', 'ap-shanghai': 'Shanghai', 'ap-beijing': 'Beijing',
  'ap-chengdu': 'Chengdu', 'ap-chongqing': 'Chongqing', 'ap-hongkong': 'Hong Kong',
  'ap-singapore': 'Singapore', 'ap-tokyo': 'Tokyo', 'ap-seoul': 'Seoul', 'ap-bangkok': 'Bangkok',
  'ap-jakarta': 'Jakarta', 'na-siliconvalley': 'Silicon Valley', 'na-ashburn': 'Ashburn',
  'eu-frankfurt': 'Frankfurt', 'eu-moscow': 'Moscow'
};
function regionLabel(region) {
  return REGION_LABELS[region] || region;
}

function bindingCount(cert) {
  const b = cert.bindings;
  if (!b || (!b.complete && !b.count)) return 'Bindings unknown';
  const n = b.count || 0;
  return (b.complete ? '' : '≥') + `${n} binding${n === 1 ? '' : 's'}`;
}

function bindingSummary(cert) {
  const b = cert.bindings || {};
  const item = (b.items || [])[0];
  const regions = (cert.regions || []).map(regionLabel);
  const where = regions.length ? regions[0] : item && item.region ? regionLabel(item.region) : '';
  const count = bindingCount(cert);
  return where ? `${count} · ${where}` : count;
}

function freshnessCaption(cert) {
  const b = cert.bindings || {};
  if (b.observedAt) {
    const parsed = new Date(b.observedAt);
    const at = Number.isNaN(parsed.getTime()) ? '' : ` ${parsed.toISOString().slice(11, 16)} UTC`;
    return `${b.freshness === 'cached' ? 'Cached' : 'Observed'}${at}`;
  }
  if (b.freshness === 'store') return 'Local record';
  return 'Never enumerated';
}

function toast(message) {
  const element = $('#toast');
  element.textContent = message;
  element.classList.add('show');
  clearTimeout(toastTimer);
  toastTimer = setTimeout(() => element.classList.remove('show'), 3500);
}

function dateIn(days) {
  return new Date(Date.now() + days * 86400000).toISOString();
}

function previewCertificate(name, uin, domains, days, status = 'ok', count = 1) {
  return {
    name, uin, domains, status,
    daysLeft: days,
    notAfter: days == null ? '' : dateIn(days),
    bindings: {
      count,
      items: Array.from({ length: count }, (_, index) => ({
        protocol: 'HTTPS', listenerId: `listener-${index + 1}`, loadBalancerId: 'clb-example'
      }))
    }
  };
}

const preview = {
  accounts: [
    { name: 'Production', uin: '100012345678' },
    { name: 'Commerce', uin: '200098765432' },
    { name: 'Staging', uin: '300011122222' }
  ],
  certificates: [
    previewCertificate('prod-api-tls', '100012345678', ['api.example.com', 'www.example.com', 'app.example.com'], 58, 'ok', 2),
    previewCertificate('www-corp', '100012345678', ['www.example.com'], 17, 'ok', 1),
    previewCertificate('internal', '100012345678', ['internal.example.com'], null, 'not_issued', 0),
    previewCertificate('legacy', '100012345678', ['legacy.example.com'], -4, 'expired', 1),
    previewCertificate('shop-tls', '200098765432', ['shop.example.com', 'checkout.example.com'], 75, 'ok', 3),
    previewCertificate('media', '200098765432', ['media.example.com'], null, 'not_issued', 0),
    previewCertificate('assets', '200098765432', ['cdn.example.com'], 101, 'ok', 1),
    previewCertificate('staging', '300011122222', ['staging.example.com'], 29, 'ok', 1),
    previewCertificate('blog', '300011122222', ['blog.example.com'], 80, 'waiting_manual_bind', 0)
  ]
};

async function request(method, path, body, admin = false, intent = false) {
  // Same-origin reads need no token here: the host serving this page fronts the daemon and injects
  // the read-only token on /api/*, so an operator never has to paste a secret into a browser.
  // A cross-origin base, and anything that needs the admin token, still has to be connected
  // explicitly in System settings.
  const sameOriginRead = !admin && (!state.base || state.base === location.origin);
  const token = admin ? state.adminToken : state.token;
  if (!sameOriginRead && !token) throw new Error('Connect in System settings with the required token first.');
  if (admin && !token) throw new Error('Connect in System settings with the required admin token first.');
  const headers = { Accept: 'application/json' };
  if (token) headers.Authorization = `Bearer ${token}`;
  if (body !== undefined) headers['Content-Type'] = 'application/json';
  // The renew agent refuses anything a plain HTML form could have produced: it requires this
  // custom header (plus a same-origin Origin) on every request, reads included.
  if (intent) headers['X-Wecert-Intent'] = 'renew';
  const response = await fetch(`${state.base}${path}`, {
    method, headers, body: body === undefined ? undefined : JSON.stringify(body), cache: 'no-store'
  });
  const data = await response.json().catch(() => ({}));
  if (!response.ok) throw new Error(data.error || `${response.status} ${response.statusText}`);
  return data;
}

function statusInfo(cert) {
  if (cert.status === 'not_issued') return { label: 'Not issued', lifecycle: 'Ready to issue', tone: 'ready', dot: 'warn' };
  if (cert.status === 'expired' || cert.daysLeft != null && cert.daysLeft < 0) return { label: 'Expired', lifecycle: 'Expired', tone: 'expired', dot: 'bad' };
  if (cert.status === 'failing') return { label: 'Error', lifecycle: 'Needs attention', tone: 'expired', dot: 'bad' };
  if (cert.status === 'waiting_manual_bind') return { label: 'Bind needed', lifecycle: 'Awaiting binding', tone: 'renewing', dot: 'warn' };
  if (cert.daysLeft != null && cert.daysLeft <= 30) return { label: 'Expiring', lifecycle: 'Expiring', tone: 'renewing', dot: 'warn' };
  if (cert.status !== 'ok') return { label: String(cert.status || 'Unknown').replaceAll('_', ' '), lifecycle: 'Needs review', tone: 'renewing', dot: 'warn' };
  return { label: 'Active', lifecycle: 'Issued', tone: 'issued', dot: 'ok' };
}

function expiry(cert) {
  if (!cert.notAfter) return '—';
  const parsed = new Date(cert.notAfter);
  return Number.isNaN(parsed.getTime()) ? cert.notAfter : parsed.toISOString().slice(0, 10);
}

function primaryAction(cert) {
  if (cert.status === 'not_issued') return ['issue', 'Issue'];
  if (cert.status === 'failing') return ['view', 'Inspect'];
  if (cert.status === 'expired' || cert.daysLeft != null && cert.daysLeft <= 30) return ['renew', 'Renew'];
  if (cert.status === 'waiting_manual_bind') return ['bindings', 'Bindings'];
  return ['view', 'Details'];
}

function bindingIssue(cert) {
  return cert.status === 'waiting_manual_bind' || Boolean(state.live && cert.bindings && !cert.bindings.complete);
}

function copyButton(value) {
  return `<button class="copy-value" data-copy="${escapeHTML(value)}" aria-label="Copy ${escapeHTML(value)}">${escapeHTML(value)} ${icon('copy')}</button>`;
}

function accountOptions() {
  const byUIN = new Map(state.accounts.map((account) => [account.uin, account]));
  state.certificates.forEach((cert) => {
    if (cert.uin && !byUIN.has(cert.uin)) byUIN.set(cert.uin, { uin: cert.uin, name: cert.uin });
  });
  return [...byUIN.values()];
}

function renderUINMenu() {
  const counts = new Map();
  state.certificates.forEach((cert) => counts.set(cert.uin, (counts.get(cert.uin) || 0) + 1));
  $('.uin-menu').innerHTML = `
    <button data-uin="all">All UINs <span class="count">${state.certificates.length}</span></button>
    ${accountOptions().map((account) => `<button data-uin="${escapeHTML(account.uin)}">UIN ${escapeHTML(account.uin)}<span class="count">${counts.get(account.uin) || 0}</span></button>`).join('')}
    `;
  $('#uin-label').textContent = state.uin === 'all' ? 'All UINs' : state.uin;
}

function filteredCertificates() {
  const query = state.search.toLowerCase();
  const result = state.certificates.filter((cert) => {
    if (state.uin !== 'all' && cert.uin !== state.uin) return false;
    const status = statusInfo(cert);
    if (state.status === 'ok' && status.dot !== 'ok') return false;
    if (state.status === 'attention' && status.dot === 'ok') return false;
    if (state.status === 'not_issued' && cert.status !== 'not_issued') return false;
    if (state.status === 'expiring' && !(cert.daysLeft != null && cert.daysLeft >= 0 && cert.daysLeft <= 30)) return false;
    if (state.status === 'bindings' && !bindingIssue(cert)) return false;
    return !query || [cert.name, cert.uin, ...(cert.domains || [])].some((value) => String(value || '').toLowerCase().includes(query));
  });
  result.sort((a, b) => state.sort === 'name'
    ? a.name.localeCompare(b.name)
    : (a.daysLeft ?? Infinity) - (b.daysLeft ?? Infinity));
  return result;
}

function renderRows() {
  const visible = filteredCertificates();
  $('#inventory-count').textContent = visible.length;
  $('#clear-filter').hidden = state.uin === 'all' && state.status === 'all' && !state.search;
  $('#inventory-footer').textContent = `${state.live ? 'Live inventory' : state.preview ? 'Preview data' : 'Not connected'} · ${visible.length} of ${state.certificates.length} certificates across ${accountOptions().length} UINs${state.live && state.lastSync ? ` · read ${state.lastSync.toLocaleTimeString()}` : ''}`;
  const grouped = new Map();
  visible.forEach((cert) => {
    const uin = cert.uin || 'unassigned';
    if (!grouped.has(uin)) grouped.set(uin, []);
    grouped.get(uin).push(cert);
  });
  $('#certificate-rows').innerHTML = [...grouped].map(([uin, certs]) => `
    <tr class="group"><td colspan="6"><button class="group-toggle" data-group="${escapeHTML(uin)}" aria-expanded="${!state.collapsed.has(uin)}"><span class="group-chevron">${state.collapsed.has(uin) ? '›' : '⌄'}</span><span>${uin === 'unassigned' ? 'Unassigned UIN' : `UIN ${escapeHTML(uin)}`}</span><span class="group-count">${certs.length} certificates</span></button></td></tr>
    ${(state.collapsed.has(uin) ? [] : certs).map((cert) => {
      const status = statusInfo(cert);
      const bindingCountValue = cert.bindings?.count || 0;
      const bindingCell = bindingCountValue || !cert.bindings?.complete
        ? `<span class="binding"><img src="binding-logo.png" alt=""><span>${escapeHTML(bindingSummary(cert))}<small>${escapeHTML(freshnessCaption(cert))}</small></span></span>`
        : '<span class="unbound">— <span>No bindings reported</span></span>';
      return `<tr data-name="${escapeHTML(cert.name)}" class="${state.detailOpen && state.selected === cert.name ? 'selected' : ''}">
        <td class="cert"><div class="certificate-cell"><span class="certificate-mark">${icon('certificate')}</span><div><button class="cert-link" data-action="view" data-name="${escapeHTML(cert.name)}">${escapeHTML(cert.name)}</button>${sslIdentityLine(cert)}</div></div></td>
        <td class="domains">${domainCell(cert)}</td>
        <td class="status"><span class="status-pill status-${cert.status === 'not_issued' ? 'neutral' : status.dot}">${icon(status.dot === 'ok' ? 'certificate' : cert.status === 'not_issued' ? 'clock' : 'alert')}${status.label === 'Active' ? 'Healthy' : status.label}</span></td>
        <td>${bindingCell}</td>
        <td class="expiry-cell ${cert.daysLeft != null && cert.daysLeft <= 30 ? 'expiry-attention' : ''} ${cert.daysLeft != null && cert.daysLeft < 0 ? 'expiry-expired' : ''}" title="${escapeHTML(expiry(cert))}">${cert.daysLeft == null ? '—' : cert.daysLeft < 0 ? `${Math.abs(cert.daysLeft)} days ago<span class="sub">Expired</span>` : `${cert.daysLeft} days`}</td>
        <td class="row-actions"><button class="menu-trigger" data-menu="${escapeHTML(cert.name)}" aria-label="Actions for ${escapeHTML(cert.name)}" aria-haspopup="true">•••</button></td>
      </tr>`;
    }).join('')}`).join('') || `<tr><td colspan="6"><div class="empty-state"><strong>${state.certificates.length ? 'No matching certificates' : 'No certificates to show'}</strong><span>${state.certificates.length ? 'Try a different UIN, status, or search term.' : state.preview ? 'Sample mode: open the daemon-served page to read the real inventory.' : 'Waiting for the daemon — the page retries on its own, and the banner above says what it saw last.'}</span></div></td></tr>`;
}

/* Certificate identity, in the two vocabularies an operator has to move between.
   Line one is the name wecert knows it by; line two is what the Tencent Cloud SSL console lists
   it under -- the upload remark ("wecert/<name>") and the cloud certificate ID -- because that is
   the pair that lets a row here be matched with a row there. The serial (which the certificate
   itself carries, and which survives a change of account or deployment target) is the tooltip of
   that line and a fact in the detail panel. Line three is the domain set: three names, then a
   count, so a certificate with twenty SANs does not stretch the row. */
const MAX_ROW_DOMAINS = 3;

function shortSerial(serial) {
  return serial.length > 16 ? `${serial.slice(0, 16)}…` : serial;
}

function sslIdentityLine(cert) {
  const cloud = [cert.alias, cert.deployedCertId].filter(Boolean);
  const serial = cert.serial ? shortSerial(cert.serial) : '';
  if (!cloud.length && !serial) return '';
  const title = [cert.serial ? `Serial ${cert.serial}` : '', cloud.join(' · ')].filter(Boolean).join(' — ');
  if (!cloud.length) return `<span class="sub certificate-domain mono" title="${escapeHTML(title)}">Not uploaded to Tencent Cloud SSL</span>`;
  return `<span class="sub certificate-domain mono" title="${escapeHTML(title)}">${escapeHTML(cloud.join(' · '))}</span>`;
}

/* The domain set gets its own column: three names stacked, then a count. The certificate column
   answers "which certificate is this" (name, upload remark, cloud id); this one answers "what does
   it cover". Stacked rather than joined by separators, because three names on one line is where a
   fixed-layout table starts truncating the middle of a host name. */
function domainCell(cert) {
  const list = (cert.domains || []).filter(Boolean);
  if (!list.length) return '<span class="unbound">—</span>';
  const shown = list.slice(0, MAX_ROW_DOMAINS);
  const hidden = list.length - shown.length;
  return `<div class="domain-cell">${shown
    .map((domain) => `<span class="domain-line" title="${escapeHTML(domain)}">${escapeHTML(domain)}</span>`)
    .join('')}${hidden ? `<span class="domain-more">+${hidden} more</span>` : ''}</div>`;
}

function domainRows(cert) {
  return (cert.domains || []).map((domain, index) => `<div class="domain-row">${icon('globe')}${copyButton(domain)}${index === 0 ? '<em>Primary</em>' : ''}</div>`).join('') || '<p class="empty-detail">No domains recorded.</p>';
}

function bindingRows(cert) {
  return (cert.bindings?.items || []).map((binding) => `<div class="binding-row"><img src="binding-logo.png" alt=""><div><strong>${escapeHTML(binding.protocol || 'Protocol not reported')}${binding.port ? ` :${binding.port}` : ' · port not reported'}</strong><small>${escapeHTML(binding.region || 'Region not reported')}</small><small>Load balancer</small>${binding.loadBalancerId ? copyButton(binding.loadBalancerId) : '<span>Not reported</span>'}<small>Listener</small>${binding.listenerId ? copyButton(binding.listenerId) : '<span>Not reported</span>'}</div></div>`).join('') || '<p class="empty-detail">No CLB bindings recorded.</p>';
}

function validityLabel(cert) {
  if (cert.daysLeft == null) return cert.status === 'not_issued' ? 'Not issued yet' : 'Expiry not reported';
  if (cert.daysLeft < 0) return `Expired ${Math.abs(cert.daysLeft)} days ago`;
  if (cert.daysLeft === 0) return 'Expires today';
  return `${cert.daysLeft} days remaining`;
}

function renderDetail() {
  const cert = state.certificates.find((item) => item.name === state.selected);
  if (!cert) {
    $('#certificate-detail').innerHTML = '<div class="detail-empty"><strong>No certificate selected</strong><span>Select a certificate to view its details.</span></div>';
    return;
  }
  const info = statusInfo(cert);
  const overdue = cert.daysLeft != null && cert.daysLeft < 0;
  const soon = cert.daysLeft != null && cert.daysLeft >= 0 && cert.daysLeft <= 30;
  const content = `<div class="validity-card ${overdue ? 'overdue' : soon ? 'due-soon' : ''}">${icon(overdue ? 'alert' : 'clock')}<div><span>Certificate validity</span><strong>${validityLabel(cert)}</strong><p>${overdue ? 'Renew this certificate and verify its deployed bindings.' : soon ? 'Review renewal before the certificate expires.' : cert.notAfter ? `Valid until ${escapeHTML(expiry(cert))}` : 'Validity will appear after issuance.'}</p></div></div>
    <section class="block"><h3>${icon('certificate')}Certificate information</h3><dl class="kv"><dt>UIN</dt><dd>${cert.uin ? copyButton(cert.uin) : '—'}</dd>${cert.deployedCertId ? `<dt>Certificate ID</dt><dd>${copyButton(cert.deployedCertId)}</dd>` : ''}<dt>Lifecycle</dt><dd>${info.lifecycle}</dd><dt>Expires on</dt><dd>${escapeHTML(expiry(cert))}</dd></dl></section>
    <section class="block"><h3>${icon('globe')}Domains <span class="section-count">${cert.domains?.length || 0}</span></h3><div class="resource-list">${domainRows(cert)}</div></section>
    <section class="block" id="detail-bindings"><h3>${icon('link')}CLB bindings <span class="section-count">${cert.bindings?.count || 0}</span></h3><div class="resource-list">${bindingRows(cert)}</div>${cert.status === 'waiting_manual_bind' ? '<p class="security-note">Binding is required. Use the row actions menu to bind an existing listener; account ownership is checked by the server.</p>' : ''}</section>`;
  $('#certificate-detail').innerHTML = `<div class="detail-head"><div><span class="detail-overline">Certificate details</span><h2>${escapeHTML(cert.name)}</h2></div><div class="detail-head-actions"><span class="badge ${info.tone}">${info.label}</span><button class="icon-close" data-close-detail aria-label="Close certificate details">${icon('close')}</button></div></div>
    <div class="detail-content">${content}</div>`;
  $('#certificate-detail .detail-content').insertAdjacentHTML('beforeend', `<section class="block"><h3>Issuance & diagnostics</h3><dl class="kv"><dt>Issuer</dt><dd>${escapeHTML(cert.issuer || 'Not reported')}</dd><dt>Valid from</dt><dd>${escapeHTML(cert.notBefore || 'Not reported')}</dd><dt>Issued at</dt><dd>${escapeHTML(cert.issuedAt || 'Not reported')}</dd><dt>Key type</dt><dd>${escapeHTML(cert.keyType || 'Not reported')}</dd><dt>Next attempt</dt><dd>${escapeHTML(cert.nextAttemptAt || 'Not reported')}</dd><dt>Last error</dt><dd>${escapeHTML(cert.lastError || cert.error || 'None reported')}</dd></dl></section><section class="block"><h3>Session activity</h3><p>Local to this page session; not a server audit log.</p><ul class="operation-log">${operationLog.filter(item => item.name === cert.name).map(item => `<li><span class="sub">${escapeHTML(item.time)}</span>${escapeHTML(item.message)}</li>`).join('') || '<li>No operations in this session.</li>'}</ul></section>`);
}

function renderAll() {
  const certs = state.certificates;
  $('#metric-total').textContent = certs.length;
  $('#metric-attention').textContent = certs.filter((cert) => statusInfo(cert).dot !== 'ok').length;
  $('#metric-expiring').textContent = certs.filter((cert) => cert.daysLeft != null && cert.daysLeft >= 0 && cert.daysLeft <= 30).length;
  $('#metric-bindings').textContent = certs.filter(bindingIssue).length;
  renderUINMenu();
  renderRows();
  renderDetail();
  $('#certificate-uin').innerHTML = accountOptions().map((account) => `<option value="${escapeHTML(account.uin)}">UIN ${escapeHTML(account.uin)}</option>`).join('') || '<option value="">Connect a UIN first</option>';
}

function setInventory(certificates, accounts, live) {
  state.certificates = certificates;
  state.accounts = accounts;
  state.live = live;
  if (live) state.lastSync = new Date();
  if (state.detailOpen && !certificates.some((cert) => cert.name === state.selected)) closeDetail();
  const chip = $('#connection-status');
  chip.classList.toggle('live', live);
  chip.lastChild.textContent = live ? 'Live data' : state.preview ? 'Preview data' : 'No data';
  chip.title = live
    ? `Last synced ${state.lastSync.toLocaleString()}`
    : state.preview
      ? 'Built-in sample inventory — this page is not talking to a daemon'
      : 'The daemon has not answered yet';
  $('#refresh-inventory').disabled = false;
  renderAll();
}

/* A failed read must never turn into plausible-looking certificates. A page that shows invented
   rows (legacy, www-corp, ...) is worse than an empty one: the operator reads them as real, and
   the one question this page exists to answer becomes unanswerable. So the page starts empty,
   keeps the last successful reading across failures, and says out loud that it is retrying. */
function showSyncProblem(message) {
  const warning = $('#sync-warning');
  if (!warning) return;
  warning.hidden = false;
  warning.innerHTML = `<b>Live data unavailable.</b> ${escapeHTML(message)}. ` +
    (state.lastSync
      ? `Showing the last reading, ${escapeHTML(state.lastSync.toLocaleTimeString())}. `
      : 'Nothing has been read from the daemon yet. ') +
    `Retrying every ${RETRY_SECONDS}s.`;
  const retry = document.createElement('button');
  retry.type = 'button';
  retry.className = 'small-btn';
  retry.textContent = 'Retry now';
  retry.onclick = () => {
    retry.disabled = true;
    loadLive().catch(() => {}).finally(() => { retry.disabled = false; });
  };
  warning.appendChild(document.createTextNode(' '));
  warning.appendChild(retry);
  // The chip must not keep claiming "Live data" while the banner says the read failed: whatever
  // is on screen is the last known answer, and the two labels have to agree.
  const chip = $('#connection-status');
  if (chip) {
    chip.classList.remove('live');
    chip.lastChild.textContent = 'Stale data';
    chip.title = 'The last successful read is shown; the daemon is not answering right now';
  }
  }

function clearSyncProblem() {
  const warning = $('#sync-warning');
  if (warning) warning.hidden = true;
}

function scheduleRetry() {
  if (state.retryTimer) return;
  state.retryTimer = setTimeout(() => {
    state.retryTimer = null;
    loadLive().catch(() => { /* the banner already says so */ });
  }, RETRY_SECONDS * 1000);
}

async function loadLive() {
 try {
  const [inventory, accounts] = await Promise.all([
    request('GET', '/api/inventory'), request('GET', '/api/accounts')
  ]);
  setInventory(inventory.certificates || [], accounts.accounts || [], true);
  clearSyncProblem();
  if (state.retryTimer) {
    clearTimeout(state.retryTimer);
    state.retryTimer = null;
  }
 } catch (error) {
  showSyncProblem(error.message);
  scheduleRetry();
  throw error;
 }
}

function closeDrawer() {
  $('#connect-drawer').classList.remove('open');
  $('#drawer-scrim').classList.remove('open');
}

function openDrawer() {
  if (!state.live) { $('#backend-modal').classList.add('open'); return; }
  $('#connect-drawer').classList.add('open');
  $('#drawer-scrim').classList.add('open');
  $('#uin-control').classList.remove('open');
}

function selectCertificate(name) {
  detailReturnFocus = document.activeElement;
  state.selected = name;
  state.detailOpen = true;
  renderRows();
  renderDetail();
  $('#certificate-detail').classList.add('open');
  $('#detail-scrim').classList.add('open');
  document.body.classList.add('detail-open');
  $('#certificate-detail [data-close-detail]').focus();
}

function closeDetail() {
  const wasOpen = state.detailOpen;
  state.selected = '';
  state.detailOpen = false;
  $('#certificate-detail').classList.remove('open');
  $('#detail-scrim').classList.remove('open');
  document.body.classList.remove('detail-open');
  renderRows();
  if (wasOpen) {
    if (detailReturnFocus?.isConnected) detailReturnFocus.focus();
    else $('#certificate-search').focus();
  }
}

$('#uin-trigger').onclick = () => $('#uin-control').classList.toggle('open');
function updateFilteredView() {
  document.querySelectorAll('[data-metric]').forEach(button => button.setAttribute('aria-pressed', String(button.dataset.metric === state.status)));
  if (state.detailOpen && !filteredCertificates().some((cert) => cert.name === state.selected)) closeDetail();
  else { renderRows(); if (state.detailOpen) renderDetail(); }
}
$('#status-filter').insertAdjacentHTML('beforeend', '<option value="expiring">Expiring within 30 days</option><option value="bindings">CLB binding issues</option>');
document.querySelectorAll('.metric').forEach((metric, index) => {
  const button = document.createElement('button');
  button.className = 'metric';
  button.dataset.metric = ['all', 'attention', 'expiring', 'bindings'][index];
  button.setAttribute('aria-pressed', String(index === 0));
  button.innerHTML = `<span class="metric-icon">${icon(['certificate', 'alert', 'clock', 'link'][index])}</span><span class="metric-content">${metric.innerHTML}</span>`;
  metric.replaceWith(button);
});
for (const [selector, symbol, label] of [
  ['#connect-backend', 'settings', 'Settings'],
  ['#refresh-inventory', 'refresh', 'Refresh']
]) $(selector).innerHTML = `${icon(symbol)}<span>${label}</span>`;
document.querySelectorAll('.icon-close').forEach(button => button.innerHTML = icon('close'));
const search = $('#certificate-search');
const searchBox = document.createElement('div');
searchBox.className = 'search-box';
search.before(searchBox);
searchBox.innerHTML = icon('search');
searchBox.append(search);
search.placeholder = 'Search name or domain';
searchBox.insertAdjacentHTML('beforeend', '<kbd>/</kbd>');
$('.filters').prepend(searchBox);
$('#status-filter').hidden = true;
const sortLabel = document.createElement('label');
sortLabel.className = 'sort-label';
sortLabel.textContent = 'Sort by';
$('#sort-order').before(sortLabel);
sortLabel.append($('#sort-order'));
$('#uin-trigger').innerHTML = `<span id="uin-label">All UINs</span>${icon('down')}`;
$('#clear-filter').onclick = () => {
  state.uin = 'all'; state.status = 'all'; state.search = '';
  $('#certificate-search').value = ''; $('#status-filter').value = 'all';
  renderUINMenu(); updateFilteredView();
};
$('#certificate-search').oninput = (event) => { state.search = event.target.value.trim(); updateFilteredView(); };
$('#status-filter').onchange = (event) => { state.status = event.target.value; updateFilteredView(); };
$('#sort-order').onchange = (event) => { state.sort = event.target.value; updateFilteredView(); };
$('#refresh-inventory').onclick = async () => { try { await loadLive(); toast('Inventory updated'); } catch (error) { toast(error.message); } };
$('#connect-backend').onclick = () => $('#backend-modal').classList.add('open');
$('.inventory-heading').insertAdjacentHTML('afterend', '<p id="sync-warning" class="sync-warning" role="alert" hidden></p>');
$('#notification-modal').innerHTML = `<form class="modal-card" id="notification-form"><header class="modal-head"><h2>Alert notifications</h2><span class="spacer"></span><button type="button" class="icon-close" data-close-notifications aria-label="Close">×</button></header><p>Renewal success and failure notifications. Expiry and CLB events are not yet emitted.</p><label class="field">Channel<select id="notify-format"><option value="wecom">企业微信 · WeCom</option><option value="feishu">飞书 · Feishu</option><option value="dingtalk">钉钉 · DingTalk</option></select></label><label class="field">Robot Webhook URL<input id="notify-url" type="password" autocomplete="new-password" placeholder="Leave blank to keep the saved URL"></label><p class="security-note">Only official HTTPS robot endpoints are accepted. Signed Feishu / DingTalk robots are not supported by this form. Saving requires a daemon reload to activate.</p><p id="notify-result" role="status"></p><div class="modal-actions"><button type="button" class="small-btn" id="notify-test">Send test</button><button class="primary">Save</button></div></form>`;
async function notificationAction(method) {
  const result = $('#notify-result');
  const buttons = document.querySelectorAll('#notification-form button');
  buttons.forEach(button => button.disabled = true);
  result.textContent = method === 'POST' ? 'Sending test…' : 'Saving…';
  try {
    const data = await request(method, '/admin/notifications', { format: $('#notify-format').value, url: $('#notify-url').value.trim() }, true);
    result.textContent = data.delivered ? `Test delivered at ${data.time}` : data.note;
    if (method === 'PUT') $('#notify-url').value = '';
  } catch (error) { result.textContent = error.message; }
  finally { buttons.forEach(button => button.disabled = false); }
}
$('#notification-form').onsubmit = event => { event.preventDefault(); notificationAction('PUT'); };
$('#notify-test').onclick = () => notificationAction('POST');
$('#backend-modal h2').textContent = 'System settings';
$('#backend-modal p').textContent = 'Console API access only — this is separate from outgoing alert Webhooks. Tokens are held in memory for this session.';

document.querySelectorAll('[data-close-notifications]').forEach((button) => button.onclick = () => $('#notification-modal').classList.remove('open'));
$('#close-connect').onclick = closeDrawer;
$('#cancel-uin').onclick = closeDrawer;
$('#drawer-scrim').onclick = closeDrawer;
$('#detail-scrim').onclick = closeDetail;
$('#new-uin-cred').onchange = (event) => $('#credential-fields').classList.toggle('is-hidden', event.target.value !== 'static');
document.querySelectorAll('[data-close-modal]').forEach((button) => button.onclick = () => $('#certificate-modal').classList.remove('open'));
document.querySelectorAll('[data-close-backend]').forEach((button) => button.onclick = () => $('#backend-modal').classList.remove('open'));

$('#backend-form').onsubmit = async (event) => {
  event.preventDefault();
  const error = $('#backend-error');
  error.textContent = '';
  try {
    const base = new URL($('#backend-url').value.trim());
    if (!['http:', 'https:'].includes(base.protocol)) throw new Error('Enter an HTTP or HTTPS daemon URL.');
    if (base.protocol !== 'https:' && !['localhost', '127.0.0.1', '[::1]'].includes(base.hostname)) throw new Error('Use HTTPS for remote API access to protect tokens.');
    state.base = base.href.replace(/\/+$/, '');
    state.token = $('#backend-token').value.trim();
    state.adminToken = $('#backend-admin-token').value.trim();
    await loadLive();
    $('#backend-modal').classList.remove('open');
    toast('Live inventory loaded');
  } catch (failure) {
    error.textContent = `Could not connect: ${failure.message}`;
  }
};

$('#save-uin').onclick = async () => {
  const uin = $('#new-uin').value.trim();
  const name = $('#new-uin-name').value.trim() || `account-${uin}`;
  const credential = $('#new-uin-cred').value;
  const secretId = $('#new-uin-secret-id').value.trim();
  const secretKey = $('#new-uin-secret-key').value;
  if (!uin) throw new Error('Enter a UIN.');
  if (credential === 'static' && (!secretId || !secretKey)) throw new Error('Enter both SecretId and SecretKey.');
  const hostname = new URL(state.base).hostname;
  if (credential === 'static' && !state.base.startsWith('https:') && !['localhost', '127.0.0.1', '[::1]'].includes(hostname)) throw new Error('Use HTTPS when sending cloud credentials.');
  try {
    await request('POST', '/admin/accounts', { uin, name, cred: credential, secretId, secretKey }, true);
    $('#new-uin-secret-id').value = '';
    $('#new-uin-secret-key').value = '';
    closeDrawer();
    await loadLive();
    toast(`UIN ${uin} connected`);
  } catch (error) { if ($('#connect-drawer').classList.contains('open')) throw error; toast(`Account saved; refresh failed: ${error.message}`); }
};

$('#certificate-form').onsubmit = async (event) => {
  event.preventDefault();
  const name = $('#certificate-name').value.trim();
  const domains = $('#certificate-domains').value.split(',').map((domain) => domain.trim()).filter(Boolean);
  if (!$('#certificate-uin').value) throw new Error('Connect a UIN first.');
  if (!name || !domains.length) throw new Error('Enter a certificate name and at least one domain.');
  try {
    const created = await request('POST', '/admin/certificates', {
      name, uin: $('#certificate-uin').value, domains,
      renewBefore: $('#certificate-renew').value, profile: 'classic', keyType: 'ecdsa-p256',
      dns: { cred: 'reused' }
    }, true);
    $('#certificate-modal').classList.remove('open');
    await loadLive();
    try {
      await request('POST', '/hook/reconcile', { cert: name });
      toast(`${name} created; issuance queued`);
    } catch (error) { toast(`${name} created; automatic issuance will retry (${error.message})`); }
    if (created.status === 'registered') toast(`${name} registered; check daemon configuration before issuance.`);
  } catch (error) { if ($('#certificate-modal').classList.contains('open')) throw error; toast(`Certificate created; refresh failed: ${error.message}`); }
};

// Keep errors beside the form and guard the full asynchronous operation.
for (const [container, buttonSelector, eventName] of [
  ['#connect-drawer', '#save-uin', 'onclick'],
  ['#certificate-form', '#certificate-form .primary', 'onsubmit'],
  ['#backend-form', '#backend-form .primary', 'onsubmit']
]) {
  const form = $(container);
  const button = $(buttonSelector);
  const target = eventName === 'onclick' ? button : form;
  const handler = target[eventName];
  const error = document.createElement('p');
  error.className = 'form-error';
  error.setAttribute('role', 'alert');
  button.parentElement.before(error);
  let pending = false;
  target[eventName] = async event => {
    event.preventDefault();
    if (pending) return;
    pending = true;
    button.disabled = true;
    form.setAttribute('aria-busy', 'true');
    error.textContent = '';
    const label = button.textContent;
    button.textContent = 'Working…';
    try { await handler(event); }
    catch (failure) { error.textContent = failure.message; }
    finally {
      pending = false;
      button.disabled = false;
      button.textContent = label;
      form.removeAttribute('aria-busy');
    }
  };
}

document.addEventListener('click', async (event) => {
  const trigger = event.target.closest('[data-menu]');
  if (trigger) {
    const cert = state.certificates.find(item => item.name === trigger.dataset.menu);
    if (!cert) return;
    const menu = $('#row-menu');
    // Details and renewal only: creating, binding and deleting certificates is done in the
    // Tencent Cloud console. This page manages what Let's Encrypt issued, and "renew" here means
    // editing that certificate's declared domain set through the renew agent (openRenewPanel).
    menu.innerHTML = `<button data-action="view" data-name="${escapeHTML(cert.name)}">View details</button>`
      + (cert.status === 'not_issued' ? '' : `<button data-action="renew" data-name="${escapeHTML(cert.name)}">Renew (edit domains)</button>`);
    menu.showPopover();
    const rect = trigger.getBoundingClientRect();
    menu.style.left = `${Math.max(8, Math.min(rect.right - menu.offsetWidth, window.innerWidth - menu.offsetWidth - 8))}px`;
    menu.style.top = `${Math.max(8, Math.min(rect.bottom + 4, window.innerHeight - menu.offsetHeight - 8))}px`;
    return;
  }
  const metric = event.target.closest('[data-metric]');
  if (metric) {
    state.status = metric.dataset.metric;
    $('#status-filter').value = state.status;
    state.collapsed.clear();
    updateFilteredView();
    return;
  }
  const copy = event.target.closest('[data-copy]');
  if (copy) {
    try { await navigator.clipboard.writeText(copy.dataset.copy); toast('Copied'); }
    catch { toast('Clipboard unavailable. Select the value and copy it manually.'); }
    return;
  }
  const group = event.target.closest('[data-group]');
  if (group) {
    const uin = group.dataset.group;
    if (state.collapsed.has(uin)) state.collapsed.delete(uin); else state.collapsed.add(uin);
    renderRows();
    return;
  }
  const uin = event.target.closest('[data-uin]');
  if (uin) {
    state.uin = uin.dataset.uin;
    $('#uin-control').classList.remove('open');
    renderUINMenu();
    updateFilteredView();
    return;
  }
  if (!event.target.closest('#uin-control')) $('#uin-control').classList.remove('open');
  if (event.target.closest('[data-close-detail]')) return closeDetail();
  const button = event.target.closest('[data-action]');
  if (button) {
    $('#row-menu').hidePopover();
    const name = button.dataset.name;
    if (button.dataset.action === 'renew') { openRenewPanel(name); return; }
    if (['view', 'bindings'].includes(button.dataset.action)) {
      selectCertificate(name);
      if (button.dataset.action === 'bindings') $('#detail-bindings').scrollIntoView({ block: 'nearest' });
      return;
    }
    return;
  }
  const row = event.target.closest('tr[data-name]');
  if (row) selectCertificate(row.dataset.name);
});

document.addEventListener('keydown', (event) => {
  const overlay = document.querySelector('.modal.open, .connect-drawer.open, .detail.open');
  if (event.key === 'Tab' && overlay) {
    const controls = [...overlay.querySelectorAll('button:not(:disabled), input:not(:disabled), select:not(:disabled), [tabindex="0"]')].filter(node => node.getClientRects().length);
    if (controls.length && (!overlay.contains(document.activeElement) || event.shiftKey && document.activeElement === controls[0] || !event.shiftKey && document.activeElement === controls[controls.length - 1])) {
      event.preventDefault(); controls[event.shiftKey ? controls.length - 1 : 0].focus();
    }
  }
  if (event.key === '/' && !event.ctrlKey && !event.metaKey && !event.altKey && !event.target.closest('input, textarea, select, [contenteditable="true"]') && !document.querySelector('.modal.open, .connect-drawer.open, .detail.open')) {
    event.preventDefault(); $('#certificate-search').focus(); return;
  }
  if (event.key !== 'Escape') return;
  closeDrawer();
  closeDetail();
  $('#backend-modal').classList.remove('open');
  $('#notification-modal').classList.remove('open');
  $('#certificate-modal').classList.remove('open');
  $('#uin-control').classList.remove('open');
  document.getElementById('certificate-action')?.classList.remove('open');
});

/* The sample inventory is for opening this file with no backend at all (a plain file:// view,
   or a design review). A page served by the daemon never renders it -- see the bootstrap at the
   end of this file. */
if (location.protocol === 'file:') {
  state.preview = true;
  setInventory(preview.certificates, preview.accounts, false);
}

/* ── renew: edit one certificate's declared domains ───────────────────────────
   Renewal here means editing the declaration, not re-running issuance with the same names: the
   agent (GET/POST /renew/...) reads the certificate's declared names, validates the candidate
   desired-state document with the daemon's own dry run, keeps a backup, writes it, and only then
   reconciles that one certificate. This page never writes the document itself, never needs its
   path, and never touches the cloud account -- binding and deletion stay Tencent Cloud console
   operations. */
let renewState = null;

// The profile cap the agent enforces for one certificate (redundant wildcard names excluded).
// The panel stops offering "Add" at the cap instead of letting the agent reject the whole write.
const RENEW_MAX_DOMAINS = 100;

function renewDraftDirty() {
  const s = renewState;
  if (!s || !s.snapshot) return false;
  const before = (s.snapshot.desiredDomains || []).slice().sort();
  const after = s.draft.slice().sort();
  return before.length !== after.length || before.some((domain, index) => domain !== after[index]);
}

function renewRemovedBound() {
  const s = renewState;
  if (!s || !s.snapshot) return [];
  return (s.snapshot.boundDomains || []).filter((domain) => !s.draft.includes(domain));
}

function addRenewDomain(raw) {
  const s = renewState;
  if (!s) return;
  const value = String(raw || '').trim().toLowerCase().replace(/\.$/, '');
  if (!value) return;
  if (s.draft.length >= RENEW_MAX_DOMAINS) {
    s.warn = `${RENEW_MAX_DOMAINS} names is the cap for a certificate; remove one before adding another.`;
    renderRenewPanel();
    return;
  }
  if (!/^(\*\.)?[a-z0-9]([a-z0-9-]*[a-z0-9])?(\.[a-z0-9]([a-z0-9-]*[a-z0-9])?)+$/.test(value)) {
    s.warn = `"${value}" is not a domain name. A wildcard has to be the left-most label: *.example.com`;
  } else if (s.draft.includes(value)) {
    s.warn = `${value} is already in the list.`;
  } else {
    s.draft.push(value);
    s.warn = '';
    s.result = null;
  }
  renderRenewPanel();
  // Adding several names in a row is the common case: keep the caret in the field.
  const field = $('#renew-add');
  if (field) field.focus();
}

function removeRenewDomain(value) {
  if (!renewState) return;
  renewState.draft = renewState.draft.filter((domain) => domain !== value);
  renewState.warn = '';
  renewState.result = null;
  renderRenewPanel();
}

async function openRenewPanel(name) {
  renewState = { name, snapshot: null, draft: [], busy: true, error: '', warn: '', result: null, adding: false };
  renderRenewPanel();
  $('#renew-modal').classList.add('open');
  try {
    const snapshot = await request('GET', `/renew/cert/${encodeURIComponent(name)}`, undefined, false, true);
    renewState.snapshot = snapshot;
    renewState.draft = (snapshot.desiredDomains || []).slice();
    renewState.busy = false;
  } catch (error) {
    renewState.busy = false;
    renewState.error = error.message;
  }
  renderRenewPanel();
}

async function applyRenew() {
  const s = renewState;
  if (!s || !s.snapshot || !renewDraftDirty()) return;
  const draft = s.draft.slice();
  s.busy = true;
  s.warn = '';
  renderRenewPanel();
  try {
    // The agent's confirmation phrase is the certificate name; clicking "File change" in a panel
    // that names the certificate is that confirmation.
    const body = await request('POST', `/renew/cert/${encodeURIComponent(s.name)}`, { domains: draft, confirm: s.name }, false, true);
    s.result = body;
    // The write landed: the declaration now is the draft, so the panel stops offering to file it
    // again (an identical set is refused by the agent anyway -- it would only spend quota).
    s.snapshot.desiredDomains = draft.slice();
    recordOperation(s.name, `Filed renewal (+${(body.added || []).length} / −${(body.removed || []).length}), revision ${String(body.revisionAfter || '').slice(0, 12)}`);
    toast(`${s.name}: change filed`);
    setTimeout(() => $('#refresh-inventory').click(), 1500);
  } catch (error) {
    s.warn = error.message;
  }
  s.busy = false;
  renderRenewPanel();
}

function renderRenewPanel() {
  const s = renewState;
  if (!s) return;
  const modal = $('#renew-modal');
  const snapshot = s.snapshot;
  const desired = (snapshot && snapshot.desiredDomains) || [];
  const added = s.draft.filter((domain) => !desired.includes(domain));
  const removed = desired.filter((domain) => !s.draft.includes(domain));
  const boundRemoved = renewRemovedBound();
  const dirty = renewDraftDirty();
  const atCap = s.draft.length >= RENEW_MAX_DOMAINS;
  // One row per name, numbered, in declaration order: the first name is the certificate's CN, so
  // the order is meaning, not presentation. Nothing here sorts or re-flows the list -- re-rendering
  // must never shuffle a set an operator just arranged.
  const rows = s.draft.length
    ? s.draft.map((domain, index) => `<div class="renew-domain-row${added.includes(domain) ? ' added' : ''}">
        <span class="idx">${index + 1}</span>
        <span class="name" title="${escapeHTML(domain)}">${escapeHTML(domain)}</span>
        ${index === 0 ? '<span class="role primary">Primary (CN)</span>' : added.includes(domain) ? '<span class="role">new</span>' : ''}
        <button type="button" class="renew-remove" data-renew-remove="${escapeHTML(domain)}" aria-label="Remove ${escapeHTML(domain)}" title="Remove this name">×</button>
      </div>`).join('')
    : '<div class="renew-empty">No names left — a certificate needs at least one.</div>';
  const result = s.result
    ? `<section class="renew-section"><h3>Filed</h3><div class="renew-box history">
        <div class="renew-history-row"><span class="when">revision</span><span class="detail">${escapeHTML(String(s.result.revisionBefore || '').slice(0, 12))} → ${escapeHTML(String(s.result.revisionAfter || '').slice(0, 12))}</span></div>
        <div class="renew-history-row"><span class="when">added</span><span class="detail">${escapeHTML((s.result.added || []).join(', ') || '—')}</span></div>
        <div class="renew-history-row"><span class="when">removed</span><span class="detail">${escapeHTML((s.result.removed || []).join(', ') || '—')}</span></div>
        <div class="renew-history-row"><span class="when">reconcile</span><span class="detail">HTTP ${escapeHTML(String((s.result.trigger && s.result.trigger.httpStatus) || '?'))} — the daemon converges this one certificate now; the row refreshes itself.</span></div>
        ${(s.result.boundRemoved || []).length ? `<div class="renew-history-row"><span class="when">bound</span><span class="detail">still attached to a CLB: ${escapeHTML(s.result.boundRemoved.join(', '))}</span></div>` : ''}
      </div></section>`
    : '';
  const body = s.busy && !snapshot
    ? '<p class="renew-lead">Reading the current declaration…</p>'
    : s.error
      ? `<p class="renew-lead">${escapeHTML(s.error)}</p><div class="security-note">The renew agent may be down (systemctl status wecert-renew-agent), or this certificate is not declared in the desired-state document.</div>`
      : `<p class="renew-lead">Edit the names this certificate covers, then file the change. The agent validates the candidate with the daemon's dry run, keeps a backup of the desired-state document, then reconciles this one certificate.</p>
      <section class="renew-section">
        <h3>Domains <span class="count">${s.draft.length}</span> <span class="muted">· ordered, first name is the CN · up to ${RENEW_MAX_DOMAINS}</span></h3>
        <div class="renew-box domains">${rows}</div>
        ${s.adding
          ? `<div class="renew-add-row">
              <input id="renew-add" placeholder="www.example.com or *.example.com" autocomplete="off" spellcheck="false" ${atCap ? 'disabled' : ''}>
              <button class="small-btn" id="renew-add-btn" type="button" ${atCap ? 'disabled' : ''}>Add</button>
              <button class="small-btn" id="renew-add-cancel" type="button">Cancel</button>
            </div>`
          : `<div class="renew-add-row">
              <button class="small-btn" id="renew-add-open" type="button" ${atCap ? 'disabled' : ''}>＋ Add domain</button>
              ${atCap ? `<span class="field-hint">${RENEW_MAX_DOMAINS} names is the profile cap.</span>` : ''}
            </div>`}
      </section>
      ${s.warn ? `<div class="renew-warn">${escapeHTML(s.warn)}</div>` : ''}
      ${boundRemoved.length ? `<div class="renew-warn">Still bound to a CLB: <b>${escapeHTML(boundRemoved.join(', '))}</b>. Removing a name from the declaration does not detach it from the listener.</div>` : ''}
      ${snapshot.canRenew === false ? `<div class="renew-warn">The agent is holding writes for another ${escapeHTML(String(snapshot.cooldownSeconds || 0))}s.</div>` : ''}
      ${result}`;
  modal.innerHTML = `<div class="modal-card wide" role="document">
    <header class="modal-head"><h2 id="renew-title">Renew ${escapeHTML(s.name)}</h2><span class="spacer"></span><button class="icon-close" data-close-renew aria-label="Close">×</button></header>
    <div class="renew-body">${body}</div>
    ${snapshot && !s.error ? `<footer class="modal-actions renew-foot">
      <span class="field-hint">${dirty ? `declaration now: ${s.draft.length} names (${added.length ? `+${added.length}` : ''}${added.length && removed.length ? ' ' : ''}${removed.length ? `−${removed.length}` : ''})` : 'no change yet'}</span>
      <span class="spacer"></span>
      <button class="small-btn" data-close-renew>Cancel</button>
      <button class="primary" id="renew-apply" ${dirty ? '' : 'disabled'}>${dirty ? `File change (${added.length ? `+${added.length}` : ''}${added.length && removed.length ? ' ' : ''}${removed.length ? `−${removed.length}` : ''})` : 'No change yet'}</button>
    </footer>` : ''}
  </div>`;
  modal.querySelectorAll('[data-close-renew]').forEach((button) => {
    button.onclick = () => { modal.classList.remove('open'); renewState = null; };
  });
  modal.querySelectorAll('[data-renew-remove]').forEach((button) => {
    button.onclick = () => removeRenewDomain(button.dataset.renewRemove);
  });
  const open = $('#renew-add-open');
  if (open) open.onclick = () => { s.adding = true; renderRenewPanel(); };
  const cancel = $('#renew-add-cancel');
  if (cancel) cancel.onclick = () => { s.adding = false; renderRenewPanel(); };
  const input = $('#renew-add');
  if (input) {
    input.onkeydown = (event) => { if (event.key === 'Enter') { event.preventDefault(); addRenewDomain(input.value); } };
    input.focus();
  }
  const addButton = $('#renew-add-btn');
  if (addButton) addButton.onclick = () => { const field = $('#renew-add'); addRenewDomain(field.value); };
  const apply = $('#renew-apply');
  if (apply) apply.onclick = applyRenew;
}

// Same-origin deployment: read through the daemon that serves this page. There is no sample
// fallback -- a failed read keeps the last real answer on screen and turns on the banner above
// the table. "I cannot reach the daemon" and "these are your certificates" must never look the
// same, and the one question this page exists to answer is which certificates exist.
if (!state.base && !state.token) loadLive().catch(() => { /* the banner already says so */ });
