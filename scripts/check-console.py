#!/usr/bin/env python3
"""Run isolated, real-browser regressions for the embedded inventory console.

Usage:
    python3 scripts/check-console.py
    python3 scripts/check-console.py --html /path/to/frozen/console.html
    python3 scripts/check-console.py --artifacts-dir /tmp/console-evidence

Requires Python Playwright (no npm packages). WECERT_CHROME may name a browser
executable; otherwise use installed macOS Google Chrome, then Playwright Chromium.
The default fixture comes from TestWritePreviewPage in a TemporaryDirectory. No
server, daemon, credentials, cloud API, or external browser networking is needed.
Each test gets a fresh context; the sole document is fulfilled from memory.

Screenshots go into a unique run directory, never over existing evidence.
"""

import argparse
import copy
import hashlib
import importlib.metadata
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

from playwright.sync_api import sync_playwright


ROOT = Path(__file__).resolve().parent.parent
CHROME = Path("/Applications/Google Chrome.app/Contents/MacOS/Google Chrome")
ORIGIN = "https://wecert.test"
DOCUMENT = ORIGIN + "/status"
AUTHZ = "authz-failures-per-identifier"
CONSECUTIVE = "consecutive-authz-failures-per-identifier"

# Capture production interval callbacks before the application registers them.
# Fetches remain pending until the test explicitly resolves or rejects them.
# No test sleeps for the actual refresh interval or contacts an inventory API.
HARNESS = r"""
(() => {
  const h = window.consoleTest = {intervals: new Map(), requests: [], deadlines: new Map(), nextID: 1};
  const realTimeout = window.setTimeout.bind(window);
  const realClearTimeout = window.clearTimeout.bind(window);
  window.setTimeout = (callback, delay, ...args) => {
    if (delay !== 15000) return realTimeout(callback, delay, ...args);
    const id = -h.nextID++;
    h.deadlines.set(id, () => callback(...args));
    return id;
  };
  window.clearTimeout = id => { h.deadlines.delete(id); realClearTimeout(id); };
  h.expireRequests = () => { for (const callback of [...h.deadlines.values()]) callback(); };
  window.setInterval = (callback, delay, ...args) => {
    const id = h.nextID++;
    h.intervals.set(id, {callback: () => callback(...args), delay: Number(delay)});
    return id;
  };
  window.clearInterval = id => h.intervals.delete(id);
  window.fetch = (input, init = {}) => {
    const url = new URL(typeof input === 'string' ? input : input.url, location.href);
    if (url.origin !== location.origin || url.pathname !== '/api/inventory') {
      return Promise.reject(new TypeError('Network access denied by console suite'));
    }
    return new Promise((resolve, reject) => {
      const request = {url: url.href, init, resolve, reject, settled: false};
      h.requests.push(request);
      init.signal?.addEventListener('abort', () => {
        request.settled = true;
        reject(new DOMException('Controlled deadline', 'AbortError'));
      }, {once: true});
    });
  };
  h.tickRefresh = () => {
    const timers = [...h.intervals.values()].filter(t => t.delay === 60000);
    if (timers.length !== 1) throw new Error('Expected one production refresh timer');
    timers[0].callback();
  };
  h.settle = ({payload, failure, status = 200}) => {
    for (const request of h.requests.filter(r => !r.settled)) {
      request.settled = true;
      if (failure) request.reject(new TypeError('Controlled network failure'));
      else request.resolve({ok: status >= 200 && status < 300, status,
                            json: async () => structuredClone(payload)});
    }
  };
})();
"""

# Measure glyph rectangles, not just document.scrollWidth: overflow:hidden can
# conceal a broken grid without creating a page scrollbar. The detail table has
# its own intentional scroll container and is not required to fit all columns.
QUOTA_GEOMETRY = r"""
() => {
  const issues = [];
  const tolerance = 1;
  const visible = el => el.getClientRects().length &&
    getComputedStyle(el).visibility !== 'hidden' &&
    getComputedStyle(el).display !== 'none';
  const outside = (r, b) => r.left < b.left - tolerance ||
    r.right > b.right + tolerance || r.top < b.top - tolerance ||
    r.bottom > b.bottom + tolerance;
  const panel = document.querySelector('#quota-panel').getBoundingClientRect();
  if (panel.left < -tolerance || panel.right > innerWidth + tolerance)
    issues.push('Quota panel exceeds viewport');
  const items = [...document.querySelectorAll('#quota-grid .quota-item')];
  for (const [index, item] of items.entries()) {
    const box = item.getBoundingClientRect();
    const label = item.querySelector('.quota-label');
    const value = item.querySelector('.quota-value');
    if (!label || !value || !visible(label) || !visible(value)) {
      issues.push(`Item ${index}: label or value missing/hidden`);
      continue;
    }
    for (const el of [label, value]) {
      const bounds = el.getBoundingClientRect();
      if (outside(bounds, box)) issues.push(`Item ${index}: ${el.className} exceeds card`);
      const walker = document.createTreeWalker(el, NodeFilter.SHOW_TEXT);
      while (walker.nextNode()) {
        const node = walker.currentNode;
        if (!node.textContent.trim() || !visible(node.parentElement)) continue;
        const range = document.createRange();
        range.selectNodeContents(node);
        for (const rect of range.getClientRects()) {
          if (outside(rect, box) || outside(rect, bounds))
            issues.push(`Item ${index}: clipped text ${node.textContent.trim()}`);
        }
      }
    }
    const a = label.getBoundingClientRect(), b = value.getBoundingClientRect();
    if (Math.min(a.right, b.right) - Math.max(a.left, b.left) > tolerance &&
        Math.min(a.bottom, b.bottom) - Math.max(a.top, b.top) > tolerance)
      issues.push(`Item ${index}: quota label overlaps quota number`);
  }
  for (const selector of ['.quota-heading', '#quota-details-summary']) {
    const el = document.querySelector(selector);
    const walker = document.createTreeWalker(el, NodeFilter.SHOW_TEXT);
    while (walker.nextNode()) {
      const node = walker.currentNode;
      if (!node.textContent.trim() || !visible(node.parentElement)) continue;
      const range = document.createRange();
      range.selectNodeContents(node);
      for (const rect of range.getClientRects()) {
        if (rect.left < panel.left - tolerance || rect.right > panel.right + tolerance)
          issues.push(`${selector}: text exceeds quota panel`);
      }
    }
  }
  return issues;
}
"""


def quota(limit="new-orders", scope="account", **changes):
    row = dict(limit=limit, scope=scope, capacity=300, remaining=284,
               refillSeconds=36, blocked=False, unreadable=False, spentByCA=False)
    row.update(changes)
    return row


def healthy_quotas():
    return [quota(),
            quota("certs-per-registered-domain", "example.test",
                  capacity=50, remaining=40, refillSeconds=12120),
            quota("certs-per-exact-identifier-set", "a.example.test,b.example.test",
                  capacity=5, remaining=4, refillSeconds=122400)]


class ConsoleRegression(unittest.TestCase):
    browser = None
    html = ""
    artifacts = None

    def setUp(self):
        self.context = self.browser.new_context(
            viewport={"width": 1440, "height": 1000}, locale="en-US",
            timezone_id="UTC", color_scheme="light", reduced_motion="reduce",
            service_workers="block",
        )
        self.addCleanup(self.context.close)
        self.page = self.context.new_page()
        self.page.set_default_timeout(3000)
        self.page.set_default_navigation_timeout(10000)
        self.addCleanup(self.capture)
        self.page_errors = []
        self.page.on("pageerror", lambda error: self.page_errors.append(str(error)))

        def route_request(route):
            request = route.request
            if (request.url == DOCUMENT and request.is_navigation_request()
                    and request.resource_type == "document"):
                route.fulfill(status=200, content_type="text/html", body=self.html)
            else:
                route.abort("blockedbyclient")

        self.context.route("**/*", route_request)
        self.context.route_web_socket("**/*", lambda socket: socket.close())
        self.context.add_init_script(HARNESS)
        self.page.goto(DOCUMENT, wait_until="load")
        self.assertEqual(self.page_errors, [], "Preview must initialize without script errors")
        self.base = self.page.evaluate("() => structuredClone(snapshot)")
        self.assertTrue(self.base["certificates"], "Preview must include sample certificates")

    def tearDown(self):
        self.assertEqual(self.page_errors, [], "Unexpected uncaught browser script error")

    def capture(self):
        if self.artifacts is not None and not self.page.is_closed():
            target = self.artifacts / (self._testMethodName + ".png")
            if target.exists():
                raise RuntimeError(f"Refusing to overwrite screenshot: {target}")
            self.page.screenshot(path=str(target), full_page=True, animations="disabled")

    def fixture(self, **changes):
        result = copy.deepcopy(self.base)
        result.update(changes)
        return result

    def apply(self, **changes):
        self.page.evaluate("next => applySnapshot(next, {silent: true})", self.fixture(**changes))

    def account_picker(self):
        return self.page.get_by_role("combobox", name="Filter by cloud account")

    def option_values(self):
        return self.account_picker().locator("option").evaluate_all("els => els.map(e => e.value)")

    def url_value(self, key):
        return self.page.evaluate("key => new URL(location.href).searchParams.get(key)", key)

    def request_count(self):
        return self.page.evaluate("consoleTest.requests.length")

    def tick(self):
        self.page.evaluate("() => consoleTest.tickRefresh()")

    def settle(self, payload=None, failure=False, status=200):
        self.page.evaluate("args => consoleTest.settle(args)",
                           {"payload": payload, "failure": failure, "status": status})
        self.page.wait_for_function("!document.querySelector('#refresh').disabled")

    def refresh_button(self):
        return self.page.get_by_role("button", name="Refresh", exact=True)

    def family_label(self, limit):
        return self.page.evaluate("limit => quotaNames[limit] || limit", limit)

    def family_card(self, limit):
        return self.page.locator("#quota-grid .quota-item").filter(
            has=self.page.locator(".quota-label > span:first-child").filter(
                has_text=self.family_label(limit)))

    def open_quota_details(self):
        if not self.page.locator("#quota-details").evaluate("el => el.open"):
            self.page.locator("#quota-details-summary").click()

    def detail_row(self, scope):
        return self.page.locator("#quota-rows").get_by_role("row").filter(
            has=self.page.get_by_role("cell", name=scope, exact=True))

    def assert_not_all_clear(self):
        summary = self.page.locator("#quota-state")
        self.assertTrue(summary.is_visible(), "Quota uncertainty must remain visible")
        self.assertTrue(summary.inner_text().strip(), "Quota summary must explain its state")
        self.assertEqual(summary.locator('use[href="#check-circle"]').count(), 0,
                         "Unknown or blocked quotas must not use the all-clear icon")
        self.assertFalse({"good", "healthy"} & set(summary.get_attribute("class").split()),
                         "Unknown or blocked quotas must not have a healthy state class")

    def assert_blocked(self, limit, scope):
        self.assertIn("bad", self.page.locator("#quota-state").get_attribute("class").split(),
                      "A known CA block must dominate the quota summary")
        self.assert_not_all_clear()
        card = self.family_card(limit)
        self.assertEqual(card.count(), 1, f"Blocked family must be represented: {limit}")
        self.assertIn("bad", card.get_attribute("class").split())
        self.open_quota_details()
        row = self.detail_row(scope)
        self.assertEqual(row.count(), 1, f"Blocked scope must remain discoverable: {scope}")
        self.assertEqual(row.get_by_role("cell").first.inner_text(), self.family_label(limit))
        self.assertIn("bad", row.locator(".quota-number").get_attribute("class").split())

    def test_authz_failure_block_is_displayed(self):
        self.apply(quotas=healthy_quotas() + [quota(
            AUTHZ, "authz.example.test", capacity=5, remaining=0, blocked=True)])
        self.assert_blocked(AUTHZ, "authz.example.test")

    def test_consecutive_authz_block_is_displayed(self):
        self.apply(quotas=healthy_quotas() + [quota(
            CONSECUTIVE, "paused.example.test", capacity=1152, remaining=1152,
            spentByCA=True, blocked=True)])
        self.assert_blocked(CONSECUTIVE, "paused.example.test")

    def test_all_unreadable_quotas_are_not_all_clear(self):
        rows = healthy_quotas()
        for row in rows:
            row.update(unreadable=True, remaining=0)
        self.apply(quotas=rows)
        self.assert_not_all_clear()

    def test_some_unreadable_families_are_not_all_clear(self):
        rows = healthy_quotas()
        rows[1]["unreadable"] = True
        self.apply(quotas=rows)
        self.assert_not_all_clear()

    def test_unreadable_nonrepresentative_scope_is_not_all_clear(self):
        # The unreadable row has a larger remaining value, so choosing the
        # smallest readable balance alone would incorrectly declare all-clear.
        self.apply(quotas=[quota(scope="readable", remaining=200),
                           quota(scope="unknown", remaining=300, unreadable=True)])
        self.assert_not_all_clear()

    def test_known_block_survives_unreadable_scope_with_lower_balance(self):
        self.apply(quotas=[quota(scope="blocked", remaining=200, blocked=True),
                           quota(scope="unknown", remaining=0, unreadable=True)])
        self.assert_blocked("new-orders", "blocked")

    def test_known_block_survives_same_row_unreadability(self):
        self.apply(quotas=[quota(scope="blocked-and-unreadable", remaining=0,
                                 blocked=True, unreadable=True)])
        self.assert_blocked("new-orders", "blocked-and-unreadable")

    def test_spent_by_ca_unknown_is_not_a_numeric_balance(self):
        self.apply(quotas=[quota(CONSECUTIVE, "unknown-ca.example.test",
                                 capacity=1152, remaining=1152, spentByCA=True)])
        card = self.family_card(CONSECUTIVE)
        self.assertEqual(card.count(), 1, "CA-only family must not disappear")
        balance = card.locator(".quota-value strong").inner_text().strip()
        self.assertTrue(balance, "Unknown balance needs a visible placeholder")
        self.assertNotRegex(balance, r"\d", "CA-only balance must not imply measured capacity")
        self.open_quota_details()
        value = self.detail_row("unknown-ca.example.test").locator(".quota-number").inner_text()
        self.assertTrue(value.strip())
        self.assertNotRegex(value, r"\d", "Unknown detail balance must not be numeric")
        self.assert_not_all_clear()

    def test_quota_panel_disappears_after_empty_snapshot(self):
        self.apply(quotas=healthy_quotas())
        self.assertTrue(self.page.locator("#quota-panel").is_visible())
        self.apply(quotas=[])
        self.assertFalse(self.page.locator("#quota-panel").is_visible(),
                         "An empty quota snapshot must not leave stale quota cards")

    def test_account_options_reconcile_added_removed_and_unspecified(self):
        first = copy.deepcopy(self.base["certificates"][0])
        second = copy.deepcopy(first)
        third = copy.deepcopy(first)
        second.update(name="new-account", uin="900000000001")
        third.update(name="unspecified-account", uin="")
        self.apply(certificates=[first, second, third])
        self.assertCountEqual(self.option_values(), ["all", first["uin"], second["uin"], ""],
                              "Options must exactly match current accounts, without stale entries")

    def test_account_options_escape_untrusted_uin(self):
        record = copy.deepcopy(self.base["certificates"][0])
        record["uin"] = '9000"><img data-console-injection="1" src="x">'
        self.apply(certificates=[record])
        self.assertCountEqual(self.option_values(), ["all", record["uin"]])
        self.assertEqual(self.page.locator("[data-console-injection]").count(), 0,
                         "Account values must be text, never injected markup")
        option = self.account_picker().locator("option").nth(1)
        self.assertEqual(option.text_content(), record["uin"])

    def test_valid_account_selection_survives_refresh(self):
        uin = self.base["certificates"][0]["uin"]
        self.account_picker().select_option(uin)
        next_records = [r for r in self.base["certificates"] if r.get("uin") == uin]
        self.apply(certificates=next_records)
        self.assertEqual(self.account_picker().input_value(), uin)
        self.assertEqual(self.page.evaluate("state.account"), uin)
        self.assertEqual(self.url_value("account"), uin)
        self.assertEqual(self.page.locator("#rows tr.row").count(), len(next_records))

    def test_removed_account_resets_selection_and_url(self):
        selected = self.base["certificates"][0]["uin"]
        self.account_picker().select_option(selected)
        remaining = [r for r in self.base["certificates"] if r.get("uin") != selected]
        self.assertTrue(remaining, "Preview needs a second account for this transition")
        self.apply(certificates=remaining)
        with self.subTest(state="picker"):
            self.assertEqual(self.account_picker().input_value(), "all")
        with self.subTest(state="model"):
            self.assertEqual(self.page.evaluate("state.account"), "all")
        with self.subTest(state="URL"):
            self.assertIsNone(self.url_value("account"), "Removed account must not persist in URL")
        with self.subTest(state="rows"):
            self.assertEqual(self.page.locator("#rows tr.row").count(), len(remaining))

    def test_unspecified_account_is_selectable_and_preserved(self):
        unspecified = copy.deepcopy(self.base["certificates"][0])
        unspecified.update(name="unspecified-account", uin="")
        rows = [self.base["certificates"][0], unspecified]
        self.apply(certificates=rows)
        self.assertIn("", self.option_values(), "Unspecified account must have its own option")
        self.account_picker().select_option("")
        self.apply(certificates=rows)
        self.assertEqual(self.account_picker().input_value(), "")
        self.assertEqual(self.page.evaluate("state.account"), "")
        self.assertEqual(self.url_value("account"), "", "Unspecified must not become all accounts")
        self.assertEqual(self.page.locator("#rows tr.row").count(), 1)

    def test_manual_and_timer_refresh_are_single_flight(self):
        self.refresh_button().click()
        self.assertEqual(self.request_count(), 1)
        self.assertTrue(self.refresh_button().is_disabled())
        self.tick()
        self.tick()
        with self.subTest(phase="overlap"):
            self.assertEqual(self.request_count(), 1,
                             "Timer callbacks must share the pending manual request")
        next_snapshot = self.fixture()
        next_snapshot["desired"]["revision"] = "single-flight-complete"
        self.settle(next_snapshot)
        self.assertEqual(self.page.locator("#revision").inner_text(), "single-flight-complete")
        self.assertTrue(self.refresh_button().is_enabled())
        self.assertEqual(self.page.evaluate("snapshot.desired.revision"), "single-flight-complete")

    def test_timer_refresh_does_not_duplicate_an_inflight_timer(self):
        self.tick()
        self.assertEqual(self.request_count(), 1)
        self.tick()
        with self.subTest(phase="overlap"):
            self.assertEqual(self.request_count(), 1, "Repeated timer ticks must stay single-flight")
        self.settle(self.fixture())
        self.assertTrue(self.refresh_button().is_enabled())

    def retry_after_error(self, *, failure=False, status=200):
        before = self.page.evaluate("() => structuredClone(snapshot)")
        self.refresh_button().click()
        self.settle(self.fixture(), failure=failure, status=status)
        self.assertTrue(self.refresh_button().is_enabled(), "Failure must release the refresh guard")
        self.assertEqual(self.page.evaluate("() => snapshot"), before,
                         "A failed request must not replace the last good snapshot")
        self.refresh_button().click()
        self.assertEqual(self.request_count(), 2, "A user must be able to retry after failure")
        next_snapshot = self.fixture()
        next_snapshot["desired"]["revision"] = "retry-complete"
        self.settle(next_snapshot)
        self.assertEqual(self.page.locator("#revision").inner_text(), "retry-complete")

    def test_network_error_can_retry_without_losing_snapshot(self):
        self.retry_after_error(failure=True)

    def test_http_error_can_retry_without_losing_snapshot(self):
        self.retry_after_error(status=503)

    def test_stalled_refresh_times_out_and_can_retry(self):
        before = self.page.evaluate("() => structuredClone(snapshot)")
        self.refresh_button().click()
        self.assertTrue(self.page.evaluate("consoleTest.deadlines.size > 0"),
                        "In-flight refresh needs a bounded deadline")
        self.page.evaluate("consoleTest.expireRequests()")
        self.page.wait_for_function("!document.querySelector('#refresh').disabled")
        self.assertEqual(self.page.evaluate("() => snapshot"), before)
        self.assertEqual(self.page.evaluate("consoleTest.deadlines.size"), 0)
        self.refresh_button().click()
        self.assertEqual(self.request_count(), 2)
        self.settle(self.fixture())
        self.assertEqual(self.page.evaluate("consoleTest.deadlines.size"), 0)

    def drawer_records(self):
        record = copy.deepcopy(self.base["certificates"][0])
        record.update(name="regression-primary", status="ok", deployedCertId="test-cert-before")
        binding = dict(resourceType="clb", region="ap-guangzhou", protocol="HTTPS",
                       port=443, role="primary", sniDomain="example.test")
        record["bindings"]["items"] = [dict(binding, loadBalancerId=f"test-lb-{i}",
                                             listenerId=f"test-listener-{i}") for i in range(8)]
        record["bindings"].update(count=8, complete=True)
        other = copy.deepcopy(record)
        other["name"] = "regression-secondary"
        return [record, other]

    def open_drawer(self):
        rows = self.drawer_records()
        self.apply(certificates=rows)
        self.page.get_by_role("button", name="Inspect regression-primary", exact=True).click()
        self.assertTrue(self.page.get_by_role("dialog", name="regression-primary").is_visible())
        return rows

    def test_drawer_refresh_preserves_scroll_and_copy_focus(self):
        rows = self.open_drawer()
        self.page.get_by_role("button", name="Copy certificate ID").focus()
        self.page.locator(".drawer-scroll").evaluate("el => { el.scrollTop = 400; }")
        self.assertEqual(self.page.locator(".drawer-scroll").evaluate("el => el.scrollTop"), 400,
                         "Fixture must provide enough real drawer content to scroll")
        self.assertTrue(self.page.locator("[data-copy]").evaluate("el => el === document.activeElement"))
        rows[0]["deployedCertId"] = "test-cert-after"
        self.tick()
        self.settle(self.fixture(certificates=list(reversed(rows))))
        self.assertEqual(self.page.locator("#detail-title").inner_text(), "regression-primary")
        self.assertTrue(self.page.get_by_text("test-cert-after", exact=True).is_visible(),
                        "Drawer content must update; freezing the old DOM is not preservation")
        with self.subTest(preserve="scroll"):
            self.assertAlmostEqual(self.page.locator(".drawer-scroll").evaluate("el => el.scrollTop"),
                                   400, delta=1, msg="Refreshing the same certificate must retain scroll")
        with self.subTest(preserve="focus"):
            self.assertTrue(self.page.get_by_role("button", name="Copy certificate ID").evaluate(
                "el => el === document.activeElement"), "Refresh must retain copy-button focus")

    def test_drawer_close_restores_trigger_focus(self):
        self.open_drawer()
        self.page.get_by_role("button", name="Close details").click()
        trigger = self.page.get_by_role("button", name="Inspect regression-primary", exact=True)
        self.assertTrue(trigger.evaluate("el => el === document.activeElement"),
                        "Close must focus the current trigger, not a detached pre-render element")
        self.assertFalse(self.page.locator("#drawer").is_visible())
        self.assertIsNone(self.url_value("cert"))
        self.assertFalse(self.page.locator("main").evaluate("el => el.inert"))

    def test_drawer_traps_tab_and_escape_restores_focus(self):
        self.open_drawer()
        drawer = self.page.get_by_role("dialog", name="regression-primary")
        controls = drawer.get_by_role("button", disabled=False)
        self.assertGreaterEqual(controls.count(), 2)
        controls.last.focus()
        self.page.keyboard.press("Tab")
        self.assertTrue(controls.first.evaluate("el => el === document.activeElement"),
                        "Tab from last control must wrap to the first enabled control")
        self.page.keyboard.press("Shift+Tab")
        self.assertTrue(controls.last.evaluate("el => el === document.activeElement"),
                        "Shift+Tab from first control must wrap to the last control")
        self.page.keyboard.press("Escape")
        self.assertFalse(self.page.locator("#drawer").is_visible())
        self.assertTrue(self.page.get_by_role("button", name="Inspect regression-primary", exact=True)
                        .evaluate("el => el === document.activeElement"))
        self.assertFalse(self.page.locator(".topbar").evaluate("el => el.inert"))

    def test_removing_selected_certificate_closes_drawer(self):
        rows = self.open_drawer()
        self.apply(certificates=[rows[1]])
        self.assertFalse(self.page.locator("#drawer").is_visible())
        self.assertFalse(self.page.locator("#backdrop").is_visible())
        self.assertIsNone(self.page.evaluate("state.selected"))
        self.assertIsNone(self.url_value("cert"))
        self.assertFalse(self.page.locator("main").evaluate("el => el.inert"))
        self.assertFalse(self.page.locator(".topbar").evaluate("el => el.inert"))
        self.assertNotEqual(self.page.locator("body").evaluate("el => el.style.overflow"), "hidden")

    def check_quota_layout(self, width):
        self.page.set_viewport_size({"width": width, "height": 1000})
        self.apply(quotas=healthy_quotas() + [
            quota(AUTHZ, "failed.example.test", capacity=5, remaining=4),
            quota(CONSECUTIVE, "unknown.example.test", capacity=1152,
                  remaining=1152, spentByCA=True),
        ])
        self.assertTrue(self.page.locator("#quota-panel").is_visible())
        self.assertGreaterEqual(self.page.locator("#quota-grid .quota-item").count(), 3)
        self.page.evaluate("() => document.fonts.ready")
        self.assertEqual(self.page.evaluate(QUOTA_GEOMETRY), [],
                         f"Quota glyphs and numbers must fit without overlap at {width}px")

    def test_quota_layout_at_390px(self):
        self.check_quota_layout(390)

    def test_quota_layout_at_320px(self):
        self.check_quota_layout(320)

    def test_quota_layout_at_1440px(self):
        self.check_quota_layout(1440)


def preview_html(directory):
    target = directory / "console.html"
    env = os.environ.copy()
    env["WECERT_PREVIEW"] = str(target)
    env.pop("WECERT_PREVIEW_EXTRA_ACCOUNTS", None)
    command = ["go", "test", "./internal/inventory", "-run", "^TestWritePreviewPage$", "-count=1"]
    result = subprocess.run(command, cwd=ROOT, env=env, text=True,
                            capture_output=True, timeout=120)
    if result.returncode or not target.is_file():
        raise RuntimeError("Preview generation failed:\n" + result.stdout + result.stderr)
    print(result.stdout.strip(), flush=True)
    return target


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
    parser.add_argument("--html", type=Path, help="Use an existing frozen preview without regenerating it")
    parser.add_argument("--artifacts-dir", type=Path,
                        help="Create a unique subdirectory containing per-test screenshots")
    args = parser.parse_args()
    print(f"Playwright: {importlib.metadata.version('playwright')}", flush=True)
    with tempfile.TemporaryDirectory(prefix="wecert-console-") as directory:
        source = args.html.expanduser().resolve() if args.html else preview_html(Path(directory))
        contents = source.read_bytes()
        ConsoleRegression.html = contents.decode("utf-8")
        print(f"Fixture: {source}\nSHA256: {hashlib.sha256(contents).hexdigest()}", flush=True)
        if args.artifacts_dir:
            destination = args.artifacts_dir.expanduser().resolve()
            destination.mkdir(parents=True, exist_ok=True)
            ConsoleRegression.artifacts = Path(tempfile.mkdtemp(prefix="console-", dir=destination))
            print(f"Screenshots: {ConsoleRegression.artifacts}", flush=True)
        options = browser_options()
        with sync_playwright() as playwright:
            browser = playwright.chromium.launch(**options)
            try:
                ConsoleRegression.browser = browser
                suite = unittest.defaultTestLoader.loadTestsFromTestCase(ConsoleRegression)
                result = unittest.TextTestRunner(verbosity=2).run(suite)
            finally:
                browser.close()
        return 0 if result.wasSuccessful() else 1


if __name__ == "__main__":
    try:
        sys.exit(main())
    except (OSError, RuntimeError, subprocess.SubprocessError) as error:
        print(f"Console regression setup failed: {error}", file=sys.stderr)
        sys.exit(2)
