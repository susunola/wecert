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

const state = {
  base: '', token: '', adminToken: '', live: false, sessionOK: false,
  accounts: [], certificates: [], clbs: [], uin: 'all', status: 'all',
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
function bindingSummary(cert) {
  const items = cert.bindings?.items || [];
  if (!items.length) return cert.bindings?.count ? `${cert.bindings.count} bindings · details not reported` : 'No bindings reported';
  const item = items[0];
  return [item.loadBalancerId || 'CLB ID not reported', item.region || 'Region not reported', item.port ? `${item.protocol || 'TLS'} :${item.port}` : 'Port not reported'].join(' · ');
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

async function request(method, path, body, admin = false) {
  if (!state.base) throw new Error('Connect in System settings with the daemon URL first.');
  const tok = admin ? state.adminToken : state.token;
  if (!state.sessionOK && !tok) throw new Error('Connect in System settings once — the session is then remembered.');
  const headers = { Accept: 'application/json' };
  if (tok) headers.Authorization = `Bearer ${tok}`;
  if (body !== undefined) headers['Content-Type'] = 'application/json';
  const response = await fetch(`${state.base}${path}`, {
    method, headers, credentials: 'include',
    body: body === undefined ? undefined : JSON.stringify(body), cache: 'no-store'
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
    <hr><button class="connect" id="connect-uin">＋ Connect UIN</button>`;
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
  $('#inventory-footer').textContent = `${state.live ? 'Live inventory' : 'Preview data'} · ${visible.length} of ${state.certificates.length} certificates across ${accountOptions().length} UINs`;
  const grouped = new Map();
  visible.forEach((cert) => {
    const uin = cert.uin || 'unassigned';
    if (!grouped.has(uin)) grouped.set(uin, []);
    grouped.get(uin).push(cert);
  });
  $('#certificate-rows').innerHTML = [...grouped].map(([uin, certs]) => `
    <tr class="group"><td colspan="5"><button class="group-toggle" data-group="${escapeHTML(uin)}" aria-expanded="${!state.collapsed.has(uin)}"><span class="group-chevron">${state.collapsed.has(uin) ? '›' : '⌄'}</span><span>${uin === 'unassigned' ? 'Unassigned UIN' : `UIN ${escapeHTML(uin)}`}</span><span class="group-count">${certs.length} certificates</span></button></td></tr>
    ${(state.collapsed.has(uin) ? [] : certs).map((cert) => {
      const status = statusInfo(cert);
      const bindings = cert.bindings?.count || 0;
      const domainCount = cert.domains?.length || 0;
      return `<tr data-name="${escapeHTML(cert.name)}" class="${state.detailOpen && state.selected === cert.name ? 'selected' : ''}">
        <td class="cert"><div class="certificate-cell"><span class="certificate-mark">${icon('certificate')}</span><div><button class="cert-link" data-action="view" data-name="${escapeHTML(cert.name)}">${escapeHTML(cert.name)}</button><span class="sub certificate-domain">${escapeHTML(cert.domains?.[0] || '—')}${domainCount > 1 ? ` <span>+${domainCount - 1} domains</span>` : ''}</span></div></div></td>
        <td class="status"><span class="status-pill status-${cert.status === 'not_issued' ? 'neutral' : status.dot}">${icon(status.dot === 'ok' ? 'certificate' : cert.status === 'not_issued' ? 'clock' : 'alert')}${status.label === 'Active' ? 'Healthy' : status.label}</span></td>
        <td>${bindings ? `<span class="binding"><img src="data:image/png;base64,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" alt=""><span>${escapeHTML(bindingSummary(cert))}<small>${bindings} bindings · ${escapeHTML(cert.bindings.freshness || 'Freshness not reported')}</small></span></span>` : '<span class="unbound">— <span>No bindings reported</span></span>'}</td>
        <td class="expiry-cell ${cert.daysLeft != null && cert.daysLeft <= 30 ? 'expiry-attention' : ''} ${cert.daysLeft != null && cert.daysLeft < 0 ? 'expiry-expired' : ''}" title="${escapeHTML(expiry(cert))}">${cert.daysLeft == null ? '—' : cert.daysLeft < 0 ? `${Math.abs(cert.daysLeft)} days ago<span class="sub">Expired</span>` : `${cert.daysLeft} days`}</td>
        <td class="row-actions"><button class="menu-trigger" data-menu="${escapeHTML(cert.name)}" aria-label="Actions for ${escapeHTML(cert.name)}" aria-haspopup="true">•••</button></td>
      </tr>`;
    }).join('')}`).join('') || `<tr><td colspan="5"><div class="empty-state"><strong>${state.certificates.length ? 'No matching certificates' : 'No certificates yet'}</strong><span>${state.certificates.length ? 'Try a different UIN, status, or search term.' : 'Create a certificate to start building your inventory.'}</span></div></td></tr>`;
}

function domainRows(cert) {
  return (cert.domains || []).map((domain, index) => `<div class="domain-row">${icon('globe')}${copyButton(domain)}${index === 0 ? '<em>Primary</em>' : ''}</div>`).join('') || '<p class="empty-detail">No domains recorded.</p>';
}

function bindingRows(cert) {
  return (cert.bindings?.items || []).map((binding) => `<div class="binding-row"><img src="data:image/png;base64,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" alt=""><div><strong>${escapeHTML(binding.protocol || 'Protocol not reported')}${binding.port ? ` :${binding.port}` : ' · port not reported'}</strong><small>${escapeHTML(binding.region || 'Region not reported')}</small><small>Load balancer</small>${binding.loadBalancerId ? copyButton(binding.loadBalancerId) : '<span>Not reported</span>'}<small>Listener</small>${binding.listenerId ? copyButton(binding.listenerId) : '<span>Not reported</span>'}</div></div>`).join('') || '<p class="empty-detail">No CLB bindings recorded.</p>';
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
  const uinOptions = accountOptions().map((account) => `<option value="${escapeHTML(account.uin)}">UIN ${escapeHTML(account.uin)}</option>`).join('');
  const uinSelect = $('#certificate-uin');
  if (uinSelect) {
    const chosen = uinSelect.value;
    uinSelect.innerHTML = uinOptions || '<option value="">No accounts yet</option>';
    uinSelect.disabled = !uinOptions;
    // Re-rendering must not undo a selection the operator already made.
    if (chosen && [...uinSelect.options].some((option) => option.value === chosen)) {
      uinSelect.value = chosen;
    }
  }
}

function setInventory(certificates, accounts, live) {
  state.certificates = certificates;
  state.accounts = accounts;
  state.live = live;
  if (state.detailOpen && !certificates.some((cert) => cert.name === state.selected)) closeDetail();
  $('#connection-status').classList.toggle('live', live);
  $('#connection-status').lastChild.textContent = live ? 'Live data' : 'Preview data';
  $('#refresh-inventory').disabled = !live;
  $('#connection-status').title = live ? `Last synced ${new Date().toLocaleString()}` : 'Sample inventory — no changes are sent to cloud accounts';
  renderAll();
}

async function loadLive() {
 try {
  const [inventory, accounts, bindings] = await Promise.all([
    request('GET', '/api/inventory'), request('GET', '/api/accounts'),
    request('GET', '/api/bindings').catch(() => ({ bindings: [] }))
  ]);
  state.clbs = bindings.bindings || bindings.clbs || [];
  setInventory(inventory.certificates || [], accounts.accounts || [], true);
  paintEnv(inventory);
  $('#sync-warning').hidden = true;
 } catch (error) {
  $('#sync-warning').hidden = false;
  $('#sync-warning').textContent = `Sync failed: ${error.message}. Displayed data may be outdated; use Refresh to retry.`;
  throw error;
 }
}

function closeDrawer() {
  $('#connect-drawer').classList.remove('open');
  $('#drawer-scrim').classList.remove('open');
}

function openDrawer() {
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

function collectCLBs() {
  // The daemon enumerates the account's load balancers (GET /api/bindings).
  // Fall back to what the binding rows show, then -- only in preview -- to a
  // sample, so the create-listener path can be exercised offline.
  const byLb = new Map();
  for (const b of state.clbs || []) {
    if (!b || !b.id) continue;
    byLb.set(b.id, {
      id: b.id,
      region: b.region || 'ap-guangzhou',
      name: b.name || '',
      listeners: (b.listeners || []).map((l) => ({
        id: l.id, proto: l.proto || 'HTTPS', port: l.port || '', sni: l.sni ? (l.sniDomain || l.sni || '') : ''
      }))
    });
  }
  for (const cert of state.certificates) {
    for (const item of (cert.bindings?.items || [])) {
      const id = item.loadBalancerId || 'unknown';
      if (!byLb.has(id)) byLb.set(id, { id, region: item.region || 'ap-guangzhou', listeners: [] });
      if (item.listenerId && !byLb.get(id).listeners.some((l) => l.id === item.listenerId)) {
        byLb.get(id).listeners.push({ id: item.listenerId, proto: item.protocol || 'HTTPS', port: item.port || '', sni: item.sniDomain || item.sni || '' });
      }
    }
  }
  if (!byLb.size && !state.live) {
    byLb.set('lb-4z28ujji', {
      id: 'lb-4z28ujji', region: 'ap-guangzhou',
      listeners: [{ id: 'lbl-dr1sy3l0', proto: 'HTTPS', port: 443, sni: '' }]
    });
  }
  return [...byLb.values()];
}

function openCertificateAction(name, action) {
  const cert = state.certificates.find(item => item.name === name);
  if (!cert) return;
  if (!state.live) { toast('Preview data: connect to the backend before changing certificates.'); return; }
  let modal = document.getElementById('certificate-action');
  if (!modal) { modal = document.createElement('div'); modal.id = 'certificate-action'; modal.className = 'modal'; document.body.append(modal); }
  const deletion = action === 'delete';
  const unbind = action === 'unbind';
  const title = deletion ? 'Delete certificate' : unbind ? 'Detach bindings' : 'Bind CLB listener';
  const clbs = collectCLBs();
  const lbOptions = clbs.map((b) => `<option value="${escapeHTML(b.id)}" data-region="${escapeHTML(b.region)}">${escapeHTML(b.id)} · ${escapeHTML(b.region)}</option>`).join('');
  const listenerOptions = (clbs[0]?.listeners || []).map((l) =>
    `<option value="${escapeHTML(l.id)}">${escapeHTML(l.id)} · ${escapeHTML(l.proto)}/${escapeHTML(l.port || '?')}${l.sni ? ' · ' + escapeHTML(l.sni) : ''}</option>`
  ).join('');

  modal.innerHTML = `<form class="modal-card">
    <header class="modal-head"><h2>${title}</h2></header>
    <p>${escapeHTML(name)} · UIN ${escapeHTML(cert.uin || 'Unknown')}</p>
    <p class="security-note">${
      deletion
        ? `This removes WeCert management and local certificate state. It does not detach cloud listeners or revoke the certificate. ${cert.bindings?.count || 0} bindings are reported; verify their impact before continuing.`
        : unbind
          ? 'Leave the certificate in inventory and drop its binding bookkeeping. Detach listeners in the cloud console if you need traffic to stop using it.'
          : 'This attaches the certificate to a CLB listener. The first bind may need a one-time confirmation in the Tencent Cloud console; later renewals switch automatically.'
    }</p>
    ${
      deletion
        ? `<label class="field">Type the certificate name to confirm<input name="confirmation" required autocomplete="off"></label>`
        : unbind
          ? ''
          : `${clbs.length
              ? `<label class="field">Load balancer<select name="loadBalancerId" id="bind-lb">${lbOptions}</select></label>`
              : `<label class="field">Load balancer ID <span class="field-hint">(no known load balancer — paste the id)</span><input name="loadBalancerId" class="mono" required placeholder="lb-…" autocomplete="off"></label>
                 <label class="field">Region<input name="region" class="mono" placeholder="ap-guangzhou" autocomplete="off"></label>`}
             <label class="field">Listener<select name="listenerId" id="bind-listener"><option value="">— create new HTTPS listener —</option>${listenerOptions}</select></label>
             <label class="field">SNI hostname<input name="sniDomain" id="bind-sni" class="mono" placeholder="${escapeHTML((cert.domains && cert.domains[0]) || 'app.example.com')}"></label>
             <details class="bind-new"><summary>Create a new HTTPS listener…</summary>
               <div class="field-row"><label class="field">Port<input name="newPort" type="number" min="1" max="65535" value="443"></label>
               <label class="field">Name<input name="newName" placeholder="https-443"></label></div>
               <label class="field"><input type="checkbox" name="newSni" checked> SNI mode (per-hostname certificates)</label>
               <p class="field-hint">Uncheck SNI to make this certificate the listener default. Leave Listener on “create new” to use these settings.</p>
             </details>`
    }
    <p class="form-error" role="alert"></p>
    <div class="modal-actions"><button type="button" class="small-btn">Cancel</button><button class="primary">${
      deletion ? 'Delete' : unbind ? 'Detach' : 'Confirm binding'
    }</button></div></form>`;
  modal.classList.add('open');
  const form = modal.querySelector('form');
  const cancel = form.querySelector('button[type="button"]');
  cancel.onclick = () => { modal.classList.remove('open'); $('#certificate-search').focus(); };
  form.querySelector('input, select')?.focus();

  const lbSel = form.querySelector('#bind-lb');
  const lisSel = form.querySelector('#bind-listener');
  if (lbSel && lisSel) {
    const refreshListeners = () => {
      const b = clbs.find((x) => x.id === lbSel.value);
      lisSel.innerHTML = `<option value="">— create new HTTPS listener —</option>` + (b?.listeners || []).map((l) =>
        `<option value="${escapeHTML(l.id)}">${escapeHTML(l.id)} · ${escapeHTML(l.proto)}/${escapeHTML(l.port || '?')}${l.sni ? ' · ' + escapeHTML(l.sni) : ''}</option>`
      ).join('');
    };
    lbSel.onchange = refreshListeners;
  }

  form.onsubmit = async event => {
    event.preventDefault();
    const button = form.querySelector('.primary');
    if (button.disabled) return;
    const data = Object.fromEntries(new FormData(form));
    const error = form.querySelector('.form-error');
    if (deletion && data.confirmation !== name) { error.textContent = 'Certificate name does not match.'; return; }
    button.disabled = true; cancel.disabled = true; error.textContent = '';
    recordOperation(name, deletion ? 'Deletion requested' : unbind ? 'Unbind requested' : 'Binding requested');
    try {
      if (deletion) {
        await request('DELETE', `/admin/certificates/${encodeURIComponent(name)}`, undefined, true);
        recordOperation(name, 'Deletion completed');
        toast('Certificate management record deleted; cloud resources were not removed.');
      } else if (unbind) {
        await request('POST', `/admin/certificates/${encodeURIComponent(name)}/unbind`, {}, true);
        recordOperation(name, 'Unbind requested');
        toast('Unbind recorded; detach cloud listeners in the cloud console if needed.');
      } else {
        const selectedLB = form.querySelector('#bind-lb option:checked');
        const body = {
          loadBalancerId: (data.loadBalancerId || '').trim(),
          region: (selectedLB?.dataset.region || data.region || 'ap-guangzhou').trim(),
          sniDomain: (data.sniDomain || '').trim()
        };
        if (!body.loadBalancerId) throw new Error('Enter a load balancer ID.');
        if (data.listenerId) body.listenerId = data.listenerId;
        else {
          const port = parseInt(data.newPort || '443', 10);
          if (!(port >= 1 && port <= 65535)) throw new Error('Port must be 1-65535');
          body.createListener = { port, name: (data.newName || '').trim(), sni: data.newSni !== undefined };
        }
        await request('POST', `/admin/certificates/${encodeURIComponent(name)}/bind`, body, true);
        recordOperation(name, 'Cloud binding API completed; inventory refresh required');
        toast('Binding request completed');
      }
      modal.classList.remove('open');
      try { await loadLive(); } catch { /* Persistent sync warning explains stale data. */ }
    } catch (failure) { error.textContent = failure.message; recordOperation(name, `Failed: ${failure.message}`); }
    finally { button.disabled = false; cancel.disabled = false; }
  };
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
  ['#notifications', 'bell', 'Notifications'],
  ['#connect-backend', 'settings', 'Settings'],
  ['#new-certificate', 'plus', 'New certificate'],
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
$('#connect-backend').onclick = () => {
  const url = $('#backend-url');
  // Same-origin is the right default: the daemon is usually behind the same
  // nginx as this page. A literal http://127.0.0.1:9801 is the *browser's*
  // loopback, not the server's, and mixed content blocks it from HTTPS anyway.
  if (url && !url.value.trim()) url.value = location.origin;
  $('#backend-modal').classList.add('open');
};
$('.inventory-heading').insertAdjacentHTML('afterend', '<p id="sync-warning" class="sync-warning" role="alert" hidden></p>');
$('#notification-modal').innerHTML = `<form class="modal-card" id="notification-form"><header class="modal-head"><h2>Alert notifications</h2><span class="spacer"></span><button type="button" class="icon-close" data-close-notifications aria-label="Close">×</button></header><p>Renewal success and failure notifications. Expiry and CLB events are not yet emitted.</p><label class="field">Channel<select id="notify-format"><option value="wecom">WeCom</option><option value="feishu">Feishu</option><option value="dingtalk">DingTalk</option></select></label><label class="field">Robot Webhook URL<input id="notify-url" type="password" autocomplete="new-password" placeholder="Leave blank to keep the saved URL"></label><p class="security-note">Only official HTTPS robot endpoints are accepted. Signed Feishu / DingTalk robots are not supported by this form. Saving requires a daemon reload to activate.</p><p id="notify-result" role="status"></p><div class="modal-actions"><button type="button" class="small-btn" id="notify-test">Send test</button><button class="primary">Save</button></div></form>`;
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
$('#notifications').onclick = async () => {
  $('#notification-modal').classList.add('open');
  $('#notify-format').focus();
  try {
    const data = await request('GET', '/admin/notifications', undefined, true);
    if (['wecom','feishu','dingtalk'].includes(data.format)) $('#notify-format').value = data.format;
    $('#notify-result').textContent = data.configured ? `Saved channel: ${data.format}. Secret URL hidden.` : 'No channel saved.';
  } catch (error) { $('#notify-result').textContent = error.message; }
};
document.querySelectorAll('[data-close-notifications]').forEach((button) => button.onclick = () => $('#notification-modal').classList.remove('open'));
$('#new-certificate').onclick = () => $('#certificate-modal').classList.add('open');
$('#certificate-uin-add') && ($('#certificate-uin-add').onclick = (event) => { event.stopPropagation(); openDrawer(); });
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
    state.token = ($('#backend-token')?.value || '').trim();
    state.adminToken = ($('#backend-admin-token')?.value || '').trim();
    // Exchange tokens for HttpOnly session cookies so later reloads need no paste.
    try {
      const exchange = await fetch(`${state.base}/api/session`, {
        method: 'POST', credentials: 'include',
        headers: { 'Content-Type': 'application/json', Accept: 'application/json' },
        body: JSON.stringify({ token: state.token, adminToken: state.adminToken })
      });
      // fetch resolves on 4xx too, so only trust it when the daemon actually minted a session.
      state.sessionOK = exchange.ok;
    } catch { /* cross-origin without CORS: fall back to in-memory tokens */ }
    await loadLive();
    $('#backend-modal').classList.remove('open');
    $('#backend-token').value = '';
    $('#backend-admin-token').value = '';
    toast('Connected — session remembered');
  } catch (failure) {
    error.textContent = 'Could not connect: ' + explainConnectError(failure);
  }
};

// "Failed to fetch" is a browser network error, not a daemon reply: the usual
// causes are pointing at 127.0.0.1 from another machine, HTTP from an HTTPS
// page, or a CORS-rejected cross-origin call. Say which.
function explainConnectError(err) {
  const msg = String((err && err.message) || err);
  if (/failed to fetch|networkerror|load failed/i.test(msg)) {
    return 'Failed to reach the daemon. Use this page\'s own origin when nginx proxies /api. 127.0.0.1 is the browser\'s machine, and an HTTP URL cannot be called from an HTTPS page.';
  }
  return msg;
}

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

function syncDnsCredFields() {
  const cred = $('#certificate-dns-cred')?.value || 'reused';
  $('#dns-token-wrap')?.classList.toggle('is-hidden', cred !== 'token');
  $('#dns-file-wrap')?.classList.toggle('is-hidden', cred !== 'file');
}
$('#certificate-dns-cred') && ($('#certificate-dns-cred').onchange = syncDnsCredFields);

/* ── create wizard ─────────────────────────────────────── */
const wizard = {
  step: 0,
  total: 4,
  labels: ['Identity', 'Policy', 'DNS', 'Deploy']
};

function wizardShow(step) {
  wizard.step = step;
  document.querySelectorAll('#wizard-steps li').forEach((li, index) => {
    li.classList.toggle('is-current', index === step);
    li.classList.toggle('is-done', index < step);
  });
  document.querySelectorAll('#certificate-form .wizard-pane').forEach((pane) => {
    const on = Number(pane.dataset.pane) === step;
    pane.hidden = !on;
    pane.classList.toggle('is-current', on);
  });
  const back = $('#wizard-back');
  const next = $('#wizard-next');
  const submit = $('#wizard-submit');
  if (back) back.hidden = step === 0;
  if (next) next.hidden = step >= wizard.total - 1;
  if (submit) submit.hidden = step < wizard.total - 1;
  const progress = $('#wizard-progress');
  if (progress) progress.textContent = `Step ${step + 1} of ${wizard.total} · ${wizard.labels[step] || ''}`;
  if (step === wizard.total - 1) wizardReview();
}

function wizardValidate(step) {
  if (step === 0) {
    const name = $('#certificate-name')?.value.trim();
    const domains = ($('#certificate-domains')?.value || '').split(/[\s,]+/).map((d) => d.trim()).filter(Boolean);
    if (!name) return 'Enter a certificate name.';
    if (!domains.length) return 'Enter at least one domain.';
    if (!$('#certificate-uin')?.value) return 'Connect a UIN first.';
  }
  return '';
}

function wizardReview() {
  const box = $('#wizard-review');
  if (!box) return;
  const domains = ($('#certificate-domains')?.value || '').split(/[\s,]+/).map((d) => d.trim()).filter(Boolean);
  const cred = $('#certificate-dns-cred')?.value || 'reused';
  const credLabel = { reused: 'Reuse daemon credential', token: 'Per-cert API token', file: 'Host key file' }[cred] || cred;
  box.innerHTML = `<dl>
    <dt>Name</dt><dd>${escapeHTML($('#certificate-name')?.value.trim() || '—')}</dd>
    <dt>Domains</dt><dd>${escapeHTML(domains.join(', ') || '—')}</dd>
    <dt>Profile</dt><dd>${escapeHTML($('#certificate-profile')?.value || 'classic')}</dd>
    <dt>Key</dt><dd>${escapeHTML($('#certificate-key')?.value || 'ecdsa-p256')}</dd>
    <dt>DNS</dt><dd>${escapeHTML($('#certificate-dns-provider')?.value || 'cloudflare')} · ${escapeHTML(credLabel)}</dd>
    <dt>Deploy</dt><dd>${escapeHTML($('#certificate-deploy')?.value || 'clb')}</dd>
  </dl>`;
}

$('#wizard-back') && ($('#wizard-back').onclick = () => {
  if (wizard.step > 0) wizardShow(wizard.step - 1);
});
$('#wizard-next') && ($('#wizard-next').onclick = () => {
  const err = wizardValidate(wizard.step);
  const box = $('#certificate-form .form-error');
  if (err) { if (box) box.textContent = err; return; }
  if (box) box.textContent = '';
  if (wizard.step < wizard.total - 1) wizardShow(wizard.step + 1);
});
document.querySelectorAll('#wizard-steps li').forEach((li) => {
  li.addEventListener('click', () => {
    const target = Number(li.dataset.step);
    if (Number.isNaN(target) || target === wizard.step) return;
    if (target < wizard.step) { wizardShow(target); return; }
    // only advance when intermediate steps validate
    for (let i = wizard.step; i < target; i += 1) {
      const err = wizardValidate(i);
      if (err) {
        const box = $('#certificate-form .form-error');
        if (box) box.textContent = err;
        wizardShow(i);
        return;
      }
    }
    wizardShow(target);
  });
});

$('#certificate-form').onsubmit = async (event) => {
  event.preventDefault();
  const name = $('#certificate-name').value.trim();
  const domains = $('#certificate-domains').value.split(/[\s,]+/).map((d) => d.trim()).filter(Boolean);
  if (!$('#certificate-uin').value) throw new Error('Connect a UIN first.');
  if (!name || !domains.length) throw new Error('Enter a certificate name and at least one domain.');
  const dnsCred = $('#certificate-dns-cred')?.value || 'reused';
  const dns = { provider: $('#certificate-dns-provider')?.value || 'cloudflare', cred: dnsCred };
  if (dnsCred === 'token') dns.token = $('#certificate-dns-token')?.value || '';
  if (dnsCred === 'file') dns.file = $('#certificate-dns-file')?.value || '';
  try {
    const created = await request('POST', '/admin/certificates', {
      name, uin: $('#certificate-uin').value, domains,
      renewBefore: $('#certificate-renew').value,
      profile: $('#certificate-profile')?.value || 'classic',
      keyType: $('#certificate-key')?.value || 'ecdsa-p256',
      deploy: $('#certificate-deploy')?.value || 'clb',
      dns
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

// reset wizard when the create modal opens
(function hookCreateOpen() {
  const btn = $('#new-certificate');
  if (!btn) return;
  const prev = btn.onclick;
  btn.onclick = (event) => {
    if (typeof prev === 'function') prev(event);
    wizardShow(0);
    const box = $('#certificate-form .form-error');
    if (box) box.textContent = '';
  };
})();

// Auto-connect: same-origin daemon already issues session cookies, so a
// reload should not demand the tokens again.
(async function autoConnect() {
  if (typeof location === 'undefined' || typeof fetch !== 'function') return;
  const bases = [];
  if (location.protocol === 'http:' || location.protocol === 'https:') {
    bases.push(location.origin);
    if (location.port !== '9801') bases.push(`${location.protocol}//${location.hostname}:9801`);
  }
  for (const base of bases) {
    try {
      const res = await fetch(`${base}/api/session`, { credentials: 'include', cache: 'no-store' });
      if (!res.ok) continue;
      const data = await res.json();
      if (!data.read && !data.admin) continue;
      state.base = base;
      state.sessionOK = true;
      state.live = true;
      await loadLive();
      const status = $('#connection-status');
      if (status) { status.classList.add('live'); status.innerHTML = '<i></i>Live inventory'; }
      return;
    } catch { /* try next */ }
  }
})();

// Keep errors beside the form and guard the full asynchronous operation.
for (const [container, buttonSelector, eventName] of [
  ['#connect-drawer', '#save-uin', 'onclick'],
  ['#certificate-form', '#wizard-submit', 'onsubmit'],
  ['#backend-form', '#backend-form .primary', 'onsubmit']
]) {
  const form = $(container);
  const button = $(buttonSelector);
  if (!form || !button) continue;
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
    const [action, label] = primaryAction(cert);
    const menu = $('#row-menu');
    menu.innerHTML = `<button data-action="view" data-name="${escapeHTML(cert.name)}">View details</button><button data-action="${cert.status === 'not_issued' ? 'issue' : 'renew'}" data-name="${escapeHTML(cert.name)}">${cert.status === 'not_issued' ? 'Issue' : 'Check renewal'}</button><button data-action="bind" data-name="${escapeHTML(cert.name)}">Bind CLB</button><button data-action="unbind" data-name="${escapeHTML(cert.name)}">Detach bindings</button><button class="danger-action" data-action="delete" data-name="${escapeHTML(cert.name)}">Delete certificate</button>`;
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
  if (event.target.closest('#connect-uin') || event.target.closest('#certificate-uin-add')) return openDrawer();
  if (!event.target.closest('#uin-control')) $('#uin-control').classList.remove('open');
  if (event.target.closest('[data-close-detail]')) return closeDetail();
  const button = event.target.closest('[data-action]');
  if (button) {
    $('#row-menu').hidePopover();
    const name = button.dataset.name;
    if (['bind', 'delete', 'unbind'].includes(button.dataset.action)) { openCertificateAction(name, button.dataset.action); return; }
    if (['view', 'bindings'].includes(button.dataset.action)) {
      selectCertificate(name);
      if (button.dataset.action === 'bindings') $('#detail-bindings').scrollIntoView({ block: 'nearest' });
      return;
    }
    if (!state.live) {
      toast('Preview data — connect in Settings to send this request.');
      return;
    }
    button.disabled = true;
    try {
      const result = await request('POST', '/hook/reconcile', { cert: name });
      const message = `Reconciliation response: ${JSON.stringify(result)}. This is not a confirmation of issuance; refresh inventory to check results.`;
      recordOperation(name, message);
      toast(`${name}: request accepted; refresh to check results`);
    } catch (error) { toast(error.message); }
    finally { button.disabled = false; }
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

setInventory(preview.certificates, preview.accounts, false);


function paintEnv(inventory) {
  const pill = $('#env-pill');
  if (!pill) return;
  const rev = inventory?.desired?.revision || '';
  const text = String(inventory?.acme?.directory || inventory?.directory || rev || '');
  const prod = /acme-v02\.api\.letsencrypt\.org/.test(text) || inventory?.production === true;
  pill.textContent = prod ? 'production' : text.includes('staging') ? 'staging' : rev ? rev.slice(0, 18) : 'live';
  pill.dataset.env = prod ? 'production' : 'staging';
}
