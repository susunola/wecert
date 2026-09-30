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
        <td>${bindings ? `<span class="binding"><span class="binding-mark" aria-hidden="true">${icon('link')}</span><span>${escapeHTML(bindingSummary(cert))}<small>${bindings} bindings · ${escapeHTML(cert.bindings.freshness || 'Freshness not reported')}</small></span></span>` : '<span class="unbound">— <span>No bindings reported</span></span>'}</td>
        <td class="expiry-cell ${cert.daysLeft != null && cert.daysLeft <= 30 ? 'expiry-attention' : ''} ${cert.daysLeft != null && cert.daysLeft < 0 ? 'expiry-expired' : ''}" title="${escapeHTML(expiry(cert))}">${cert.daysLeft == null ? '—' : cert.daysLeft < 0 ? `${Math.abs(cert.daysLeft)} days ago<span class="sub">Expired</span>` : `${cert.daysLeft} days`}</td>
        <td class="row-actions"><button class="menu-trigger" data-menu="${escapeHTML(cert.name)}" aria-label="Actions for ${escapeHTML(cert.name)}" aria-haspopup="true">•••</button></td>
      </tr>`;
    }).join('')}`).join('') || `<tr><td colspan="5"><div class="empty-state"><strong>${state.certificates.length ? 'No matching certificates' : 'No certificates yet'}</strong><span>${state.certificates.length ? 'Try a different UIN, status, or search term.' : 'Create a certificate to start building your inventory.'}</span></div></td></tr>`;
}

function domainRows(cert) {
  return (cert.domains || []).map((domain, index) => `<div class="domain-row">${icon('globe')}${copyButton(domain)}${index === 0 ? '<em>Primary</em>' : ''}</div>`).join('') || '<p class="empty-detail">No domains recorded.</p>';
}

function bindingRows(cert) {
  return (cert.bindings?.items || []).map((binding) => `<div class="binding-row"><span class="binding-mark" aria-hidden="true">${icon('link')}</span><div><strong>${escapeHTML(binding.protocol || 'Protocol not reported')}${binding.port ? ` :${binding.port}` : ' · port not reported'}</strong><small>${escapeHTML(binding.region || 'Region not reported')}</small><small>Load balancer</small>${binding.loadBalancerId ? copyButton(binding.loadBalancerId) : '<span>Not reported</span>'}<small>Listener</small>${binding.listenerId ? copyButton(binding.listenerId) : '<span>Not reported</span>'}</div></div>`).join('') || '<p class="empty-detail">No CLB bindings recorded.</p>';
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
