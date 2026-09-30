#!/usr/bin/env python3
"""Run isolated unittest regressions for the restored webconsole.

Defaults to webconsole/index.html. Use --html PATH for a frozen version and
--artifacts-dir DIR for list-only screenshots and a JSON result summary in a
unique run directory. Requires Python Playwright and an installed Chromium.
WECERT_CHROME may override the browser executable, as in check-console.py.

Every test starts without tokens in a fresh browser context. Only the synthetic
origin's main document is fulfilled from local bytes; all other requests and
WebSockets are blocked. API responses are stubbed in memory; no daemon or real
credentials are used. The create payload test intercepts and rejects the write.
Checks retain the original toolbar and generic empty state, not a redesign.
Desktop geometry is checked at 1440px with normal account labels. Narrow-screen
and long-label overflow, plus the unreachable Deploy wizard pane, are measured
and reported as original limitations, not skipped tests or claims of a fix.
"""

import argparse
import hashlib
import importlib.metadata
import json
import os
from pathlib import Path
import re
import sys
import tempfile
import unittest

from playwright.sync_api import Error as PlaywrightError, expect, sync_playwright


ROOT = Path(__file__).resolve().parent.parent
CHROME = Path("/Applications/Google Chrome.app/Contents/MacOS/Google Chrome")
DOCUMENT = "https://wecert.test/webconsole/"
ACCOUNT_A = "900000000001"
ACCOUNT_B = "900000000002"
LONG_LABEL = "Regional inventory account " + "LongAccountLabel" * 16
WIDTHS = (320, 390, 768, 1440)

# These records never originate from a daemon or a user's browser storage.
CERTIFICATES = [
    dict(name="zeta-failing", uin=ACCOUNT_A, status="failing", expiryDays=40,
         domains=["failure.example.test"], lb="lb-failure"),
    dict(name="alpha-healthy", uin=ACCOUNT_A, status="ok", expiryDays=80,
         domains=["alpha.example.test", "alias.example.test"], lb="lb-alpha"),
    dict(name="bravo-expiring", uin=ACCOUNT_B, status="expiring", expiryDays=5,
         domains=["bravo.example.test"]),
    dict(name="delta-pending", uin=ACCOUNT_B, status="waiting_manual_bind", expiryDays=60,
         domains=["delta.example.test"]),
    dict(name="charlie-unassigned", uin="", status="ok", expiryDays=35,
         domains=["charlie.example.test"]),
]
ATTENTION_ORDER = ["zeta-failing", "delta-pending", "bravo-expiring",
                   "charlie-unassigned", "alpha-healthy"]
EXPIRY_ORDER = ["bravo-expiring", "charlie-unassigned", "zeta-failing",
                "delta-pending", "alpha-healthy"]
NAME_ORDER = sorted(c["name"] for c in CERTIFICATES)

GENERIC_EMPTY = ("No matching certificates "
                 "Adjust the account, status, or search term — or create a certificate.")
DAEMON_NOTE = "Certificate issuance follows the daemon configuration."

# The deployed baseline has a title above a tabs/account/sort/search toolbar.
# Check normal-label desktop geometry, but measure rather than conceal the
# original overflow at narrower widths and with extremely long account labels.
LIST_LAYOUT = r"""
desktop => {
  const issues = [], tolerance = 1;
  const panel = document.querySelector('#view-inventory');
  const selectors = {
    head: ':scope > .panel-head', title: ':scope > .panel-head > h2',
    toolbar: ':scope > .panel-head > .toolbar',
    tabs: '.toolbar > #tabs', account: '.toolbar > #account',
    sort: '.toolbar > #sort', searchbox: '.toolbar > .searchbox-right',
    search: '.toolbar > .searchbox-right > #search',
    scroll: ':scope > .table-scroll', table: ':scope > .table-scroll > table',
    thead: 'thead', footer: ':scope > .table-footer'
  };
  if (!panel) return {issues: ['Missing #view-inventory'], measurements: {}};
  const elements = {};
  for (const [name, selector] of Object.entries(selectors)) {
    const matches = panel.querySelectorAll(selector);
    if (matches.length !== 1) issues.push(`Expected one ${selector}, got ${matches.length}`);
    else elements[name] = matches[0];
  }
  if (issues.length) return {issues, measurements: {}};
  const rect = el => el.getBoundingClientRect();
  const boxes = Object.fromEntries(Object.entries(elements).map(([k, el]) => [k, rect(el)]));
  const check = (ok, message) => { if (!ok) issues.push(message); };
  const near = (a, b, message) => check(Math.abs(a - b) <= tolerance,
    `${message}: ${a.toFixed(2)} versus ${b.toFixed(2)}`);
  const order = [...elements.toolbar.children].map(el =>
    el.id || (el.matches('.spacer') ? 'spacer' : el.matches('.searchbox') ? 'searchbox' : el.tagName));
  check(JSON.stringify(order) === JSON.stringify(['tabs', 'account', 'sort', 'spacer', 'searchbox']),
        `Original toolbar order changed: ${order.join(', ')}`);
  check(elements.title.nextElementSibling === elements.toolbar, 'Title must precede toolbar');
  check(panel.querySelectorAll('.inventory-heading, .inventory-controls, .inventory-sort').length === 0,
        'Rejected inventory layout wrappers must not return');
  check(elements.tabs.querySelectorAll('[data-filter]').length === 4, 'Keep all four status filters');
  check(getComputedStyle(elements.scroll).overflowX === 'auto', 'Keep original table scroll container');
  for (const [name, box] of Object.entries(boxes)) {
    check(box.width > 0 && box.height > 0, `${name} must have nonzero rendered dimensions`);
  }
  const panelBox = rect(panel), style = getComputedStyle(elements.head);
  const left = boxes.head.left + parseFloat(style.paddingLeft);
  const right = boxes.head.right - parseFloat(style.paddingRight);
  const overflowing = ['tabs', 'account', 'sort', 'searchbox', 'search'].filter(name =>
    boxes[name].left < panelBox.left - tolerance || boxes[name].right > panelBox.right + tolerance);
  const measurements = {
    viewport: innerWidth,
    pageOverflowPx: Math.max(0, document.documentElement.scrollWidth - innerWidth),
    panelWidth: Math.round(panelBox.width), overflowingControls: overflowing,
    tableClientWidth: elements.scroll.clientWidth, tableScrollWidth: elements.scroll.scrollWidth,
    tableMinWidth: getComputedStyle(elements.table).minWidth
  };
  if (desktop) {
    check(panelBox.left >= -tolerance && panelBox.right <= innerWidth + tolerance,
          'Desktop inventory must fit viewport');
    check(overflowing.length === 0, `Desktop controls exceed panel: ${overflowing.join(', ')}`);
    near(boxes.title.left, left, 'Title left alignment');
    near(boxes.tabs.left, left, 'Tabs lead toolbar');
    check(boxes.toolbar.top >= boxes.title.bottom + 13, 'Keep title above toolbar with original gap');
    near(boxes.account.left - boxes.tabs.right, 12, 'Tabs/account gap');
    near(boxes.sort.left - boxes.account.right, 12, 'Account/sort gap');
    check(boxes.searchbox.left > boxes.sort.right, 'Search follows sort on the right');
    near(boxes.searchbox.right, right, 'Search right alignment');
    near(boxes.account.top, boxes.sort.top, 'Account/sort alignment');
    near(boxes.sort.top, boxes.searchbox.top, 'Sort/search alignment');
    for (const key of ['account', 'sort', 'searchbox']) {
      near(boxes[key].height, 36, `${key} original height`);
    }
    check(boxes.tabs.bottom <= boxes.thead.top + tolerance, 'Tabs must not overlap table headers');
    check(boxes.searchbox.bottom < boxes.thead.top, 'Search stays above table headers');
    near(boxes.table.width, boxes.scroll.width, 'Table fills original panel width');
    check(boxes.footer.top >= boxes.thead.bottom, 'Footer remains below table');
  }
  return {issues, measurements};
}
"""


class WebConsoleRegression(unittest.TestCase):
    browser = None
    html = b""
    artifacts = None
    limitations = []

    def setUp(self):
        self.context = self.browser.new_context(
            viewport={"width": 1440, "height": 1200}, locale="en-US",
            timezone_id="UTC", color_scheme="light", reduced_motion="reduce",
            service_workers="block",
        )
        self.addCleanup(self.context.close)
        self.page = self.context.new_page()
        self.page.set_default_timeout(3000)
        self.page.set_default_navigation_timeout(10000)
        self.page_errors = []
        self.expected_activity = []
        self.blocked_requests = []
        self.blocked_sockets = []
        self.documents = 0
        self.page.on("pageerror", lambda error: self.page_errors.append(str(error)))

        def route_request(route):
            request = route.request
            if (request.url == DOCUMENT and request.method == "GET"
                    and request.is_navigation_request() and request.resource_type == "document"
                    and request.frame == self.page.main_frame and self.documents == 0):
                self.documents += 1
                route.fulfill(status=200, content_type="text/html; charset=utf-8", body=self.html)
            else:
                self.blocked_requests.append((request.method, request.url))
                route.abort("blockedbyclient")

        def block_socket(socket):
            self.blocked_sockets.append(socket.url)
            socket.close()

        self.context.route("**/*", route_request)
        self.context.route_web_socket("**/*", block_socket)
        self.page.goto(DOCUMENT, wait_until="load")
        self.addCleanup(self.capture)
        self.assertEqual(self.page_errors, [], "Local HTML must initialize without script errors")
        self.assertEqual(self.page.evaluate("wecertAPI.token()"), "")
        self.assertEqual(self.page.evaluate("wecertAPI.adminToken()"), "")

    def tearDown(self):
        self.assertEqual(self.page_errors, [], "Unexpected uncaught browser script error")
        self.assertEqual(self.documents, 1)
        self.assertEqual(self.blocked_requests, [], "Isolated tests must not request network data")
        self.assertEqual(self.blocked_sockets, [], "Isolated tests must not open WebSockets")
        self.assertEqual(self.page.evaluate("state.activity.map(a => a.text)"),
                         self.expected_activity, "Only expected fixture activity is allowed")
        self.assertEqual(self.page.evaluate("wecertAPI.token()"), "")
        self.assertEqual(self.page.evaluate("wecertAPI.adminToken()"), "")
        self.assertIsNone(self.page.evaluate("state.confirm"))
        self.assertIsNone(self.page.evaluate("state.bindCert"))

    def capture(self, phase="final"):
        if self.artifacts is not None and not self.page.is_closed():
            target = self.artifacts / f"{self._testMethodName}-{phase}.png"
            if target.exists():
                raise RuntimeError(f"Refusing to overwrite screenshot: {target}")
            self.page.locator("#view-inventory").screenshot(path=str(target), animations="disabled")

    def report_limitation(self, description, measurements):
        entry = {"test": self._testMethodName, "description": description, **measurements}
        self.limitations.append(entry)
        print("\nBASELINE LIMITATION: " + json.dumps(entry, sort_keys=True), flush=True)

    def seed(self, *, empty=False):
        self.page.evaluate("""records => {
          closeModals();
          closeDrawer();
          state.certs = records.map(c => ({
            ...c, id: c.name, profile: 'classic', keyType: 'ecdsa-p256',
            notAfter: Date.now() + c.expiryDays * 86400000,
            deployedCertId: 'cert-' + c.name, deployConfirmed: c.status === 'ok',
            clb: c.lb ? {id: c.lb, listener: 'listener-test', region: 'test-region',
                         sni: c.domains[0]} : null
          }));
          state.accounts = [
            {uin: '900000000001', name: 'Account Alpha', cred: 'test-only'},
            {uin: '900000000002', name: 'Account Beta', cred: 'test-only'}
          ];
          state.live = true;
          state.inventory = null;
          state.q = ''; state.account = 'all'; state.filter = 'all'; state.sort = 'attention';
          document.querySelector('#search').value = '';
          document.querySelector('#sort').value = 'attention';
          document.querySelectorAll('#tabs [data-filter]').forEach(el =>
            el.setAttribute('aria-pressed', String(el.dataset.filter === 'all')));
          render();
        }""", [] if empty else CERTIFICATES)

    def row_names(self):
        return self.page.locator("#rows .cert-name").all_text_contents()

    def choose_filter(self, value):
        button = self.page.locator(f'#tabs [data-filter="{value}"]')
        button.click()
        self.assertEqual(button.get_attribute("aria-pressed"), "true")
        self.assertEqual(self.page.locator('#tabs [aria-pressed="true"]').count(), 1)
        self.assertEqual(self.page.evaluate("state.filter"), value)

    def assert_empty(self, state):
        empty = self.page.locator("#empty")
        self.assertTrue(empty.is_visible(), f"{state} explanation must be visible")
        self.assertIsNone(empty.get_attribute("data-state"), "Original empty state has no variants")
        self.assertEqual(self.row_names(), [])
        message = " ".join(empty.inner_text().split())
        self.assertEqual(message, GENERIC_EMPTY, f"Keep the generic message for {state}")
        return message

    def test_no_environment_ui_or_css(self):
        self.assertEqual(self.page.locator(
            '.env-switch, .env-btn, .env-pill, #env-pill, [data-env], #c-env-dir, #c-env-note, '
            '[aria-label="ACME environment"]'
        ).count(), 0, "The environment switch, pill, and directory display must be removed")
        self.assertNotRegex(self.page.locator('.topbar').inner_text(), r'(?i)staging|production')
        css = self.page.locator('style').all_text_contents()
        self.assertNotRegex('\n'.join(css), r'\.env-(?:switch|btn|pill)|\.dot\.(?:staging|prod)')

    def test_no_environment_state_functions_or_references(self):
        source = self.html.decode('utf-8')
        for pattern in (r'\benv-(?:switch|btn|pill)\b', r'\bc-env-(?:dir|note)\b',
                        r'\bdata-env\b', r'\bstate\s*\.\s*env\b',
                        r'\bACME_DIR\b', r'\bsetEnv\b'):
            with self.subTest(pattern=pattern):
                self.assertIsNone(re.search(pattern, source), f"Removed environment reference: {pattern}")
        self.assertEqual(self.page.evaluate("""() => ({
          stateHasEnv: Object.prototype.hasOwnProperty.call(state, 'env'),
          setEnvType: typeof setEnv, directoryType: typeof ACME_DIR
        })"""), {"stateHasEnv": False, "setEnvType": "undefined", "directoryType": "undefined"})

    def test_no_hardcoded_issuance_directory(self):
        pattern = r'(?i)acme[\w.-]*\.letsencrypt\.org|https?://[^\s<>\"\x27]+/directory'
        self.assertIsNone(re.search(pattern, self.html.decode('utf-8')),
                          "Issuance directory selection belongs to the daemon, not this page")

    def test_initialization_navigation_theme_and_connection(self):
        self.assertEqual(self.page.evaluate('state.view'), 'inventory')
        self.assertEqual(self.page.locator('#result-count').inner_text(),
                         'Connect to a wecert daemon to load live inventory')
        self.assertEqual(self.page.locator('#account option').all_text_contents(),
                         ['All accounts', 'Unspecified'])
        self.page.keyboard.press('Escape')
        for view in ('accounts', 'bindings', 'activity', 'inventory'):
            self.page.locator(f'.topnav [data-view="{view}"]').click()
            self.assertEqual(self.page.evaluate('state.view'), view)
            self.assertTrue(self.page.locator(f'#view-{view}').is_visible())
            self.assertEqual(self.page.locator('.nav-item.active').get_attribute('data-view'), view)
        for theme in ('dark', 'light'):
            self.page.locator('#theme').click()
            self.assertEqual(self.page.locator('html').get_attribute('data-theme'), theme)
        self.page.locator('#btn-connect').click()
        self.assertTrue(self.page.locator('#modal-connect').is_visible())
        self.assertEqual(self.page.locator('#k-token').input_value(), '')
        self.assertEqual(self.page.locator('#k-admin').input_value(), '')

    def test_mock_inventory_load_without_environment_pill(self):
        self.page.evaluate("""records => {
          closeModals();
          window.fixtureCalls = [];
          const snapshot = {
            desired: {revision: 'fixture-revision'},
            certificates: records.map(c => ({
              ...c, notAfter: new Date(Date.now() + c.expiryDays * 86400000).toISOString(),
              profile: 'classic', keyType: 'ecdsa-p256', deployConfirmed: c.status === 'ok',
              bindings: {count: c.lb ? 1 : 0, complete: true, items: c.lb ? [{
                loadBalancerId: c.lb, listenerId: 'listener-test', region: 'test-region',
                sniDomain: c.domains[0], protocol: 'HTTPS', port: 443
              }] : []}
            })),
            quotas: [{limit: 'certs-per-exact-identifier-set', remaining: 4, capacity: 5}]
          };
          wecertAPI.inventory = async () => { fixtureCalls.push('inventory'); return snapshot; };
          wecertAPI.accounts = async () => {
            fixtureCalls.push('accounts');
            return {accounts: [
              {uin: '900000000001', name: 'Account Alpha', cred: 'test-only'},
              {uin: '900000000002', name: 'Account Beta', cred: 'test-only'}
            ]};
          };
          wecertAPI.status = async () => { fixtureCalls.push('status'); return {certificates: []}; };
        }""", CERTIFICATES)
        outcome = self.page.evaluate("""async () => {
          try { await loadRealData(); render(); return null; }
          catch (error) { return String(error); }
        }""")
        self.assertIsNone(outcome, f"Mock inventory load must not touch a removed env-pill: {outcome}")
        self.expected_activity = ['Inventory refreshed from live daemon (5 certificates)']
        self.assertEqual(self.page.evaluate('fixtureCalls'), ['inventory', 'accounts', 'status'])
        self.assertTrue(self.page.evaluate('state.live'))
        self.assertEqual(self.page.evaluate('state.inventory.desired.revision'), 'fixture-revision')
        self.assertEqual(self.row_names(), ATTENTION_ORDER)
        self.assertEqual(self.page.locator('#m-total').inner_text(), '5')
        self.assertEqual(self.page.locator('#m-quota').inner_text(), '4 / 5')
        self.assertEqual(self.page.evaluate('state.accounts.map(a => a.name)'), ['Account Alpha', 'Account Beta'])
        self.assertEqual(self.page.evaluate('state.clbs.map(b => b.id)'), ['lb-failure', 'lb-alpha'])
        self.assertFalse(self.page.locator('#empty').is_visible())

    def open_wizard_policy(self):
        self.seed()
        self.page.locator('#btn-create').click()
        self.assertTrue(self.page.locator('#modal-create').is_visible())
        self.assertEqual(self.page.evaluate('state.createStep'), 0)
        self.assertTrue(self.page.locator('.wizard-pane[data-pane="0"]').is_visible())
        self.page.locator('#c-name').fill('  fixture-certificate  ')
        self.page.locator('#c-domains').fill(' fixture.example.test \n\n *.fixture.example.test ')
        self.page.locator('#c-next').click()
        self.assertEqual(self.page.evaluate('state.createStep'), 1)
        self.assertTrue(self.page.locator('.wizard-pane[data-pane="1"]').is_visible())
        self.page.locator('#c-dns').select_option('dnspod')
        self.page.locator('#c-dns-cred').select_option('reused')
        self.page.locator('#c-next').click()
        self.assertEqual(self.page.evaluate('state.createStep'), 2)
        self.assertTrue(self.page.locator('.wizard-pane[data-pane="2"]').is_visible())

    def test_create_wizard_daemon_wording_and_original_bind_explanation(self):
        self.open_wizard_policy()
        # The original syncWizard hides Next at Policy, before the Deploy pane.
        # Inspect retained copy without pretending this is a visible user flow.
        note = self.page.locator('.wizard-pane[data-pane="3"] .callout')
        self.assertEqual(note.count(), 1)
        wording = ' '.join(note.text_content().split())
        self.assertEqual(wording, DAEMON_NOTE + ' After issuance, use Bind to CLB on the row. '
                         'The first bind is confirmed once in the Tencent console; '
                         'later renewals switch automatically.')
        self.report_limitation('Original wizard Deploy pane reachability', {
            'nextVisibleOnPolicy': self.page.locator('#c-next').is_visible(),
            'deployPaneVisibleOnPolicy': self.page.locator('.wizard-pane[data-pane="3"]').is_visible(),
            'noteVisibleOnPolicy': note.is_visible(),
            'scope': 'Wizard opening and Policy navigation tested; Deploy note checked as DOM copy',
        })
        self.page.locator('#modal-create [data-close]').first.click()
        self.assertFalse(self.page.locator('#modal-create').is_visible())

    def test_create_payload_and_api_route_no_environment(self):
        self.open_wizard_policy()
        self.page.locator('#c-profile').select_option('tlsserver')
        self.page.locator('#c-key').select_option('ecdsa-p384')
        # Exercise submitCreate -> real API wrapper -> in-memory fetch. Reject at
        # that boundary so no write, reconcile, refresh, or timer can occur.
        self.page.evaluate("""() => {
          window.fixtureRequests = [];
          window.fetch = async (url, options) => {
            fixtureRequests.push({url, ...options});
            return new Response(JSON.stringify({error: 'Isolated payload captured; nothing issued'}), {
              status: 409, headers: {'Content-Type': 'application/json'}
            });
          };
        }""")
        for renewal, hours in [('30d', '720h'), ('14d', '336h'), ('7d', '168h')]:
            with self.subTest(renewal=renewal):
                self.page.locator('#c-renew').select_option(renewal)
                self.page.locator('#c-submit').click()
                expect(self.page.locator('#toast')).to_have_text('Isolated payload captured; nothing issued')
                requests = self.page.evaluate('fixtureRequests')
                self.assertEqual(len(requests), 1)
                request = requests[0]
                self.assertEqual(request['url'], 'admin/certificates')
                self.assertEqual(request['method'], 'POST')
                self.assertEqual(request['headers'], {'Accept': 'application/json', 'Content-Type': 'application/json'})
                self.assertEqual(request['cache'], 'no-store')
                self.assertEqual(json.loads(request['body']), {
                    'name': 'fixture-certificate',
                    'domains': ['fixture.example.test', '*.fixture.example.test'],
                    'profile': 'tlsserver', 'keyType': 'ecdsa-p384', 'renewBefore': hours,
                    'deploy': 'clb', 'uin': ACCOUNT_A, 'dns': {'provider': 'dnspod', 'cred': 'reused'},
                })
                self.assertTrue(self.page.locator('#modal-create').is_visible())
                self.page.evaluate("() => { fixtureRequests.length = 0; document.querySelector('#toast').textContent = ''; }")
        self.page.keyboard.press('Escape')

    def test_default_logged_out(self):
        self.assertFalse(self.page.evaluate("state.live"))
        self.assertEqual(self.page.evaluate("state.certs"), [])
        self.assertTrue(self.page.locator("#modal-connect").is_visible())
        self.assertEqual(self.page.locator("#k-token").input_value(), "")
        self.assertEqual(self.page.locator("#k-admin").input_value(), "")
        self.assertEqual(self.context.cookies(), [])
        self.assertEqual(self.blocked_requests, [])
        self.page.evaluate("closeModals()")
        self.assert_empty("disconnected")

    def test_empty_live_inventory(self):
        self.seed(empty=True)
        self.assert_empty("empty")
        # All original empty cases deliberately share the same explanation.
        self.page.locator("#search").fill("no-such-certificate")
        self.choose_filter("healthy")
        self.assert_empty("empty")
        self.page.evaluate("() => { state.live = false; render(); }")
        self.assert_empty("disconnected")

    def test_filtered_empty_search(self):
        self.seed()
        self.page.locator("#search").fill("no-such-certificate")
        self.assert_empty("filtered")
        self.page.locator("#search").fill("")
        self.assertEqual(self.row_names(), ATTENTION_ORDER)
        self.assertFalse(self.page.locator("#empty").is_visible())

    def test_filtered_empty_account_and_status(self):
        self.seed()
        self.page.locator("#account").select_option(ACCOUNT_A)
        self.choose_filter("expiring")
        self.assert_empty("filtered")
        self.page.locator("#account").select_option(ACCOUNT_B)
        self.assertEqual(self.row_names(), ["bravo-expiring"])
        self.assertFalse(self.page.locator("#empty").is_visible())

    def test_empty_states_share_original_generic_message(self):
        self.page.evaluate("closeModals()")
        disconnected = " ".join(self.page.locator("#empty").inner_text().split())
        self.seed(empty=True)
        empty = " ".join(self.page.locator("#empty").inner_text().split())
        self.seed()
        self.page.locator("#search").fill("no-such-certificate")
        filtered = " ".join(self.page.locator("#empty").inner_text().split())
        self.assertEqual([disconnected, empty, filtered], [GENERIC_EMPTY] * 3,
                         "Restore the deployed generic empty state, not new distinct messages")

    def test_populated_inventory_hides_empty(self):
        self.seed()
        self.assertEqual(self.row_names(), ATTENTION_ORDER)
        self.assertFalse(self.page.locator("#empty").is_visible())
        self.assertEqual(self.page.locator("#list-count").inner_text(), "5")

    def test_search_name_domain_and_clb(self):
        self.seed()
        for query in ("  ALPHA-HEALTHY  ", "alias.example.test", "lb-alpha"):
            with self.subTest(query=query):
                self.page.locator("#search").fill(query)
                self.assertEqual(self.page.evaluate("state.q"), query.strip().lower())
                self.assertEqual(self.row_names(), ["alpha-healthy"])
        self.page.locator("#search").fill("")
        self.assertEqual(self.row_names(), ATTENTION_ORDER)

    def test_status_filters(self):
        self.seed()
        for value, names in [
            ("attention", ["zeta-failing", "delta-pending"]),
            ("expiring", ["bravo-expiring"]),
            ("healthy", ["charlie-unassigned", "alpha-healthy"]),
            ("all", ATTENTION_ORDER),
        ]:
            with self.subTest(filter=value):
                self.choose_filter(value)
                self.assertEqual(self.row_names(), names)

    def test_account_filter_including_unspecified(self):
        self.seed()
        for value, names in [
            (ACCOUNT_A, ["zeta-failing", "alpha-healthy"]),
            (ACCOUNT_B, ["delta-pending", "bravo-expiring"]),
            ("", ["charlie-unassigned"]),
            ("all", ATTENTION_ORDER),
        ]:
            with self.subTest(account=value):
                self.page.locator("#account").select_option(value)
                self.assertEqual(self.page.evaluate("state.account"), value)
                self.assertEqual(self.page.locator("#account").input_value(), value)
                self.assertEqual(self.row_names(), names)

    def test_sort_modes(self):
        self.seed()
        for value, names in [("name", NAME_ORDER), ("expiry", EXPIRY_ORDER),
                             ("attention", ATTENTION_ORDER)]:
            with self.subTest(sort=value):
                self.page.locator("#sort").select_option(value)
                self.assertEqual(self.page.evaluate("state.sort"), value)
                self.assertEqual(self.row_names(), names)

    def test_combined_search_account_status_and_sort(self):
        self.seed()
        self.page.locator("#search").fill("example.test")
        self.page.locator("#account").select_option(ACCOUNT_B)
        self.page.locator("#sort").select_option("expiry")
        self.assertEqual(self.row_names(), ["bravo-expiring", "delta-pending"])
        self.choose_filter("attention")
        self.assertEqual(self.row_names(), ["delta-pending"])
        self.page.locator("#search").fill("bravo")
        self.assertEqual(self.row_names(), [])
        self.choose_filter("expiring")
        self.assertEqual(self.row_names(), ["bravo-expiring"])

    def test_details_after_filtering_and_sorting(self):
        self.seed()
        self.page.locator("#search").fill("alpha")
        self.page.locator("#account").select_option(ACCOUNT_A)
        self.choose_filter("healthy")
        self.page.locator("#sort").select_option("name")
        before = self.page.evaluate("JSON.stringify(state.certs)")
        self.page.locator("#rows").get_by_role("button", name="Details", exact=True).click()
        self.assertTrue(self.page.get_by_role("dialog", name="alpha-healthy", exact=True).is_visible())
        self.assertEqual(self.page.evaluate("state.selected"), "alpha-healthy")
        self.assertIn("alias.example.test", self.page.locator("#drawer").inner_text())
        self.page.get_by_role("button", name="Close details", exact=True).click()
        self.assertFalse(self.page.locator("#drawer").is_visible())
        self.assertEqual(self.page.evaluate("JSON.stringify(state.certs)"), before)
        self.assertEqual(self.row_names(), ["alpha-healthy"])

    def test_keyboard_original_tabs_account_sort_search_order(self):
        self.seed()
        for width in WIDTHS:
            with self.subTest(width=width):
                self.page.set_viewport_size({"width": width, "height": 1200})
                self.page.locator('#tabs [data-filter="healthy"]').focus()
                for expected in ("account", "sort", "search"):
                    self.page.keyboard.press("Tab")
                    self.assertEqual(self.page.evaluate("document.activeElement.id"), expected)
                for expected in ("sort", "account"):
                    self.page.keyboard.press("Shift+Tab")
                    self.assertEqual(self.page.evaluate("document.activeElement.id"), expected)

    def test_responsive_search_filter_sort_and_details(self):
        for width in WIDTHS:
            with self.subTest(width=width):
                self.seed()
                self.page.set_viewport_size({"width": width, "height": 1200})
                self.page.locator("#search").fill("example.test")
                self.page.locator("#account").select_option(ACCOUNT_B)
                self.page.locator("#sort").select_option("expiry")
                self.assertEqual(self.row_names(), ["bravo-expiring", "delta-pending"])
                # Keyboard activation remains usable even where baseline overflow
                # clips a pointer target; this is not a mobile pointer-layout claim.
                tab = self.page.locator('#tabs [data-filter="attention"]')
                tab.focus()
                tab.press("Space")
                self.assertEqual(tab.get_attribute("aria-pressed"), "true")
                self.assertEqual(self.row_names(), ["delta-pending"])
                self.page.locator("#search").fill("no-match")
                self.assert_empty("filtered")
                self.page.locator("#search").fill("")
                before = self.page.evaluate("JSON.stringify(state.certs)")
                self.page.locator("#rows .cert-name").focus()
                self.page.keyboard.press("Enter")
                self.assertTrue(self.page.get_by_role("dialog", name="delta-pending", exact=True).is_visible())
                self.assertEqual(self.page.evaluate("state.selected"), "delta-pending")
                self.page.keyboard.press("Escape")
                self.assertFalse(self.page.locator("#drawer").is_visible())
                self.assertEqual(self.page.evaluate("JSON.stringify(state.certs)"), before)
                self.assertEqual(self.row_names(), ["delta-pending"])

    def check_layout(self, width, theme):
        self.page.set_viewport_size({"width": width, "height": 1200})
        self.page.emulate_media(color_scheme=theme)
        self.page.evaluate("theme => { document.documentElement.dataset.theme = theme; closeModals(); }", theme)
        self.page.evaluate("() => document.fonts.ready")
        for phase in ("disconnected", "populated", "long-account"):
            with self.subTest(phase=phase, width=width, theme=theme):
                if phase == "populated":
                    self.seed()
                elif phase == "long-account":
                    self.page.evaluate("""label => {
                      state.accounts[0].name = label;
                      render();
                    }""", LONG_LABEL)
                    self.page.locator("#account").select_option(ACCOUNT_A)
                    selected = self.page.locator("#account option:checked").text_content()
                    self.assertIn(LONG_LABEL, selected)
                    self.assertEqual(self.row_names(), ["zeta-failing", "alpha-healthy"])
                self.page.evaluate("window.scrollTo(0, 0)")
                try:
                    desktop = width == 1440 and phase != "long-account"
                    layout = self.page.evaluate(LIST_LAYOUT, desktop)
                    self.assertEqual(layout["issues"], [],
                                     f"Original inventory baseline at {width}px in {theme} ({phase})")
                    if not desktop:
                        self.report_limitation("Original responsive/long-label layout", {
                            "phase": phase, "theme": theme, **layout["measurements"],
                            "scope": "Structure and interactions checked; overflow is not fixed",
                        })
                finally:
                    self.capture(phase)

    def test_layout_320_light(self):
        self.check_layout(320, "light")

    def test_layout_320_dark(self):
        self.check_layout(320, "dark")

    def test_layout_390_light(self):
        self.check_layout(390, "light")

    def test_layout_390_dark(self):
        self.check_layout(390, "dark")

    def test_layout_768_light(self):
        self.check_layout(768, "light")

    def test_layout_768_dark(self):
        self.check_layout(768, "dark")

    def test_layout_1440_light(self):
        self.check_layout(1440, "light")

    def test_layout_1440_dark(self):
        self.check_layout(1440, "dark")


def browser_options():
    override = os.environ.get("WECERT_CHROME")
    if override:
        executable = Path(override).expanduser().resolve()
        if not executable.is_file() or not os.access(executable, os.X_OK):
            raise RuntimeError(f"WECERT_CHROME is not an executable file: {executable}")
    else:
        executable = CHROME if CHROME.is_file() and os.access(CHROME, os.X_OK) else None
    options = {"headless": True, "args": ["--disable-background-networking"]}
    if executable is not None:
        options["executable_path"] = str(executable)
    print(f"Browser: {executable or 'Playwright Chromium'}", flush=True)
    return options


def main():
    parser = argparse.ArgumentParser(description=__doc__,
                                     formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--html", type=Path, default=ROOT / "webconsole" / "index.html",
                        help="Read local HTML bytes, including a frozen pre-change version")
    parser.add_argument("--artifacts-dir", type=Path,
                        help="Save list screenshots and summary.json in a unique subdirectory")
    args = parser.parse_args()
    source = args.html.expanduser().resolve()
    contents = source.read_bytes()
    WebConsoleRegression.html = contents
    digest = hashlib.sha256(contents).hexdigest()
    version = importlib.metadata.version("playwright")
    print(f"Playwright: {version}\nFixture: {source}\nSHA256: {digest}", flush=True)
    if args.artifacts_dir:
        destination = args.artifacts_dir.expanduser().resolve()
        destination.mkdir(parents=True, exist_ok=True)
        WebConsoleRegression.artifacts = Path(tempfile.mkdtemp(prefix="webconsole-", dir=destination))
        print(f"Artifacts: {WebConsoleRegression.artifacts}", flush=True)
    with sync_playwright() as playwright:
        browser = playwright.chromium.launch(**browser_options())
        try:
            WebConsoleRegression.browser = browser
            suite = unittest.defaultTestLoader.loadTestsFromTestCase(WebConsoleRegression)
            result = unittest.TextTestRunner(verbosity=2).run(suite)
        finally:
            browser.close()
    summary = {
        "html": str(source), "html_sha256": digest, "playwright": version,
        "script_sha256": hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
        "tests_run": result.testsRun, "successful": result.wasSuccessful(),
        "failure_count": len(result.failures), "error_count": len(result.errors),
        "skipped_count": len(result.skipped),
        "baseline_limitations": WebConsoleRegression.limitations,
        "failures": [{"test": str(test), "traceback": trace} for test, trace in result.failures],
        "errors": [{"test": str(test), "traceback": trace} for test, trace in result.errors],
    }
    if WebConsoleRegression.artifacts:
        target = WebConsoleRegression.artifacts / "summary.json"
        with target.open("x", encoding="utf-8") as output:
            json.dump(summary, output, indent=2)
            output.write("\n")
        print(f"Saved summary: {target}", flush=True)
    print(f"Result: {'PASS' if result.wasSuccessful() else 'FAIL'}; {result.testsRun} tests, "
          f"{len(result.failures)} failures (including subtests), {len(result.errors)} errors, "
          f"{len(result.skipped)} skipped", flush=True)
    return 0 if result.wasSuccessful() else 1


if __name__ == "__main__":
    try:
        sys.exit(main())
    except (OSError, RuntimeError, PlaywrightError) as error:
        print(f"Webconsole regression setup failed: {error}", file=sys.stderr)
        sys.exit(2)
