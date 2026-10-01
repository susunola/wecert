#!/usr/bin/env python3
"""Isolated unittest regressions for webconsole/console.html.

The page under test is the certificate-first console: a KPI strip, a grouped
inventory table and a one-screen create form. Every test runs in a fresh
browser context with no stored tokens. The synthetic origin's main document is
fulfilled from local bytes; everything else is aborted. Daemon API responses are
stubbed in memory, so no daemon, cloud account or real credential is involved.
The create test intercepts the POST and never lets it reach a server.

Run: make check-console2   (or python3 scripts/check-console2.py)
"""

import json
import sys
import time
import unittest
from pathlib import Path

from playwright.sync_api import sync_playwright

ROOT = Path(__file__).resolve().parent.parent
DOCUMENT = "https://wecert.test/console.html"
READONLY = "test-readonly-token"
ADMIN = "test-admin-token-0123456789abcdef"
DAY = 86400000
NOW = time.time() * 1000

HTML = (ROOT / "webconsole" / "console.html").read_text()

ACCOUNTS = {"accounts": [
    {"uin": "100012345678", "name": "intl-prod"},
    {"uin": "998877665544", "name": "staging"},
]}


def cert(name, uin, status, domains, days=None, bindings=0, deploy=True, error=""):
    out = {
        "name": name, "uin": uin, "status": status, "domains": domains,
        "deploy": {"enabled": deploy} if deploy else None,
        "bindings": {"count": bindings, "items": [], "complete": True},
    }
    if days is not None:
        out["notAfter"] = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(NOW / 1000 + days * 86400))
        out["daysLeft"] = days
    if error:
        out["lastError"] = error
    return out


# Five certificates chosen so every KPI and every grouping branch is exercised:
# not-issued with zero bindings (two of them, one without a deploy flag at all,
# which is what the real daemon sends), healthy + bound, expiring + bound, and
# waiting for the first bind.
FIXTURE = {
    "time": "2026-10-01T10:20:00Z",
    "desired": {"revision": "sha256:abc", "frozen": False},
    "summary": {},
    "certificates": [
        cert("welcome", "<nil>", "not_issued", ["wecome.invalid"]),
        cert("no-deploy-flag", "<nil>", "not_issued", ["bare.example.org"], deploy=None),
        cert("api-example", "100012345678", "expiring", ["api.example.com"], days=12, bindings=1),
        cert("shop-example", "100012345678", "ok",
             ["shop.example.com", "cdn.example.com"], days=82, bindings=1),
        cert("legacy-zone", "998877665544", "waiting_manual_bind",
             ["legacy.example.net"], days=200, error="uploaded, waiting for the first CLB bind"),
    ],
    "quotas": [],
}

CREATED = []


def route_handler(page, inventory, status_code=200):
    def handle(route):
        url = route.request.url
        method = route.request.method
        if url.startswith(DOCUMENT):
            route.fulfill(status=200, content_type="text/html; charset=utf-8", body=HTML)
        elif "/api/inventory" in url:
            route.fulfill(status=status_code, content_type="application/json",
                          body=json.dumps(inventory if status_code == 200 else {"error": "unauthorized"}))
        elif "/api/accounts" in url:
            route.fulfill(status=200, content_type="application/json", body=json.dumps(ACCOUNTS))
        elif "/admin/certificates" in url and method == "POST":
            CREATED.append(json.loads(route.request.post_data or "{}"))
            route.fulfill(status=200, content_type="application/json",
                          body=json.dumps({"ok": True, "note": "staged"}))
        else:
            route.abort()
    return handle


class Console2Regression(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls._pw = sync_playwright().start()
        cls.browser = cls._pw.chromium.launch()
        cls.errors = []

    @classmethod
    def tearDownClass(cls):
        cls.browser.close()
        cls._pw.stop()

    def setUp(self):
        CREATED.clear()
        self.ctx = self.browser.new_context(viewport={"width": 1080, "height": 800})
        self.page = self.ctx.new_page()
        # per-test error list: a browser-reported abort in one test must not
        # leak into another test's "no console errors" assertion
        self.errors = []
        self.page.on("pageerror", lambda e: self.errors.append("pageerror: " + str(e)))
        self.page.on("console",
                     lambda m: self.errors.append("console: " + m.text) if m.type == "error" else None)

    def tearDown(self):
        self.ctx.close()

    # -- helpers -----------------------------------------------------------
    def load(self, inventory=None, status_code=200, tokens=None):
        inv = FIXTURE if inventory is None else inventory
        self.page.route("**/*", route_handler(self.page, inv, status_code))
        if tokens:
            readonly, admin = tokens
            script = "try{localStorage.setItem('wecert.token',%r);" % readonly
            if admin:
                script += "localStorage.setItem('wecert.adminToken',%r);" % admin
            script += "sessionStorage.setItem('wecert.token',%r);}catch(e){}" % readonly
            self.page.add_init_script(script)
        self.page.goto(DOCUMENT, wait_until="domcontentloaded")
        self.page.wait_for_timeout(500)

    def rows(self):
        return self.page.locator("tbody tr.row")

    def text(self, sel):
        return self.page.text_content(sel).strip()

    # -- tests -------------------------------------------------------------
    def test_connect_modal_opens_without_tokens_and_loads_with_one(self):
        self.load()
        self.assertTrue(self.page.is_visible("#connect-overlay"), "connect modal opens")
        self.assertEqual(self.text("#foot-text"), "Not connected", "footer says not connected")
        self.page.fill("#k-token", READONLY)
        self.page.click("#connect-submit")
        self.page.wait_for_timeout(400)
        self.assertFalse(self.page.is_visible("#connect-overlay"), "modal closes after connect")
        self.assertEqual(self.text("#live-text"), "Live data", "live pill switches to Live data")

    def test_kpis_count_total_attention_expiring_and_binding_issues(self):
        self.load(tokens=(READONLY, ""))
        self.assertEqual(self.text("#kpi-total"), "5")
        # not ok and not expiring: both not_issued + waiting_manual_bind
        self.assertEqual(self.text("#kpi-attention"), "3")
        self.assertEqual(self.text("#kpi-expiring"), "1")
        # a certificate that needs a CLB binding and has none, including the
        # not-issued ones whose payload carries no deploy.enabled at all
        self.assertEqual(self.text("#kpi-binding"), "3")

    def test_grouping_by_uin_and_expiry_soonest_order(self):
        self.load(tokens=(READONLY, ""))
        labels = self.page.eval_on_selector_all(
            "tr.group .glabel", "els => els.map(e => e.textContent.trim())")
        self.assertEqual(len(labels), 3, "three groups: intl-prod, staging, unassigned")
        self.assertTrue(any("Unassigned UIN" in l for l in labels))
        self.assertEqual(self.text("tbody tr.row .cert-name"), "api-example",
                         "expiry-soonest sorts the 12-day certificate first")
        self.assertIn("2 certificates", labels[0])
        self.assertIn("2 certificates", labels[2])

    def test_group_collapse_hides_and_restores_rows(self):
        self.load(tokens=(READONLY, ""))
        self.assertEqual(self.rows().count(), 5)
        self.page.click('[data-toggle="__none__"]')
        self.page.wait_for_timeout(150)
        self.assertEqual(self.rows().count(), 3, "collapsing hides the unassigned rows")
        self.page.click('[data-toggle="__none__"]')
        self.page.wait_for_timeout(150)
        self.assertEqual(self.rows().count(), 5, "expanding restores every row")

    def test_search_narrows_by_name_and_domain(self):
        self.load(tokens=(READONLY, ""))
        self.page.fill("#q", "cdn.example.com")
        self.page.wait_for_timeout(150)
        self.assertEqual(self.rows().count(), 1, "domain search finds shop-example")
        self.assertEqual(self.text("tbody tr.row .cert-name"), "shop-example")
        self.page.fill("#q", "nobody-matches")
        self.page.wait_for_timeout(150)
        self.assertEqual(self.rows().count(), 0)
        self.assertIn("No matching certificates", self.text("#state-title"))
        # the generic empty state must keep its guidance wording
        self.assertIn("Adjust the account, status, or search term", self.text("#state-text"))

    def test_uin_filter_includes_unassigned(self):
        self.load(tokens=(READONLY, ""))
        options = self.page.eval_on_selector_all(
            "#uin-filter option", "els => els.map(e => e.value)")
        self.assertIn("__none__", options, "an Unassigned UIN option is offered")
        self.page.select_option("#uin-filter", "998877665544")
        self.page.wait_for_timeout(150)
        self.assertEqual(self.rows().count(), 1)
        self.assertEqual(self.text("tbody tr.row .cert-name"), "legacy-zone")
        self.page.select_option("#uin-filter", "__none__")
        self.page.wait_for_timeout(150)
        self.assertEqual(self.rows().count(), 2, "unassigned filter shows both unassigned rows")

    def test_kpi_tabs_filter_the_table(self):
        self.load(tokens=(READONLY, ""))
        self.page.click('.kpi[data-kpi="binding"]')
        self.page.wait_for_timeout(150)
        self.assertEqual(self.rows().count(), 3, "binding-issue tab shows the three unbound rows")
        self.page.click('.kpi[data-kpi="expiring"]')
        self.page.wait_for_timeout(150)
        self.assertEqual(self.rows().count(), 1)
        self.page.click('.kpi[data-kpi="all"]')
        self.page.wait_for_timeout(150)
        self.assertEqual(self.rows().count(), 5)

    def test_footer_reports_live_counts_and_snapshot(self):
        self.load(tokens=(READONLY, ""))
        foot = self.text("#foot-text")
        self.assertIn("Live inventory · 5 of 5 certificates across 2 UINs", foot)
        self.assertIn("Snapshot 2026-10-01 10:20 UTC", self.text("#foot-meta"))

    def test_row_menu_warns_without_a_distinct_admin_token(self):
        self.load(tokens=(READONLY, ""))
        self.page.click('[data-menu="welcome"]')
        self.page.wait_for_timeout(150)
        self.assertTrue(self.page.is_visible("#row-menu"), "row menu opens")
        self.assertIn("admin token", self.text("#row-menu"),
                      "write actions are flagged as needing the admin token")

    def test_create_form_summary_mirrors_the_fields(self):
        self.load(tokens=(READONLY, ADMIN))
        self.page.click("#btn-new")
        self.page.wait_for_timeout(200)
        self.assertTrue(self.page.is_visible("#new-overlay"))
        self.page.fill("#c-name", "demo-com")
        self.page.fill("#c-domains", "demo.com\nwww.demo.com")
        self.page.wait_for_timeout(150)
        self.assertEqual(self.text("#s-domains"), "2")
        self.assertEqual(self.text("#s-subject"), "demo.com")
        self.assertEqual(self.text("#s-name"), "demo-com")
        self.assertIn("follows the daemon configuration", self.text("#new-overlay .callout"),
                      "issuance wording stays daemon-controlled")

    def test_create_posts_expected_payload_to_admin_route(self):
        self.load(tokens=(READONLY, ADMIN))
        self.page.click("#btn-new")
        self.page.wait_for_timeout(200)
        self.page.fill("#c-name", "demo-com")
        self.page.fill("#c-domains", "demo.com\nwww.demo.com")
        self.page.select_option("#c-profile", "tlsserver")
        self.page.wait_for_timeout(150)
        self.page.click("#create-submit")
        self.page.wait_for_timeout(400)
        self.assertEqual(len(CREATED), 1, "exactly one POST was issued")
        payload = CREATED[0]
        self.assertEqual(payload["name"], "demo-com")
        self.assertEqual(payload["domains"], ["demo.com", "www.demo.com"])
        self.assertEqual(payload["profile"], "tlsserver")
        self.assertTrue(payload["deploy"]["enabled"])
        self.assertNotIn("dns", payload, "no DNS block is sent when the daemon default applies")

    def test_unauthorized_inventory_surfaces_an_error(self):
        self.load(inventory=FIXTURE, status_code=401, tokens=("wrong-token", ""))
        self.assertIn("Unauthorized", self.text("#foot-text"), "401 is reported in the footer")
        self.assertEqual(self.text("#live-text"), "Offline", "live pill falls back to Offline")

    def test_no_console_errors_across_the_whole_flow(self):
        self.load(tokens=(READONLY, ADMIN))
        self.page.click("#btn-new")
        self.page.wait_for_timeout(200)
        self.page.keyboard.press("Escape")
        self.page.click('.kpi[data-kpi="binding"]')
        self.page.wait_for_timeout(150)
        self.page.keyboard.press("/")
        focused = self.page.evaluate("document.activeElement && document.activeElement.id")
        self.assertEqual(focused, "q", "the / shortcut focuses search")
        self.assertEqual([e for e in self.errors], [], "no page or console errors")

    def test_narrow_layout_keeps_the_table_scrollable(self):
        self.load(tokens=(READONLY, ""))
        self.page.set_viewport_size({"width": 390, "height": 844})
        self.page.wait_for_timeout(250)
        overflow = self.page.evaluate(
            "(() => { const el = document.querySelector('.panel');"
            "return el ? el.scrollWidth <= el.clientWidth + 1 : null; })()")
        self.assertTrue(overflow, "the panel does not overflow horizontally at 390px")


if __name__ == "__main__":
    unittest.main(verbosity=2)
