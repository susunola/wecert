#!/usr/bin/env python3
"""Isolated unittest regressions for webconsole/console.html.

The page under test is the certificate-first console built from
webconsole/certificate-first-prototype.html: a clickable KPI strip, a grouped
inventory table, a certificate detail drawer and a single-page create form with
a live request summary.
Every test runs in a fresh browser context. The synthetic origin's main
document is fulfilled from local bytes; every other request is either stubbed
in memory or aborted, so no daemon, cloud account or real credential is
involved. The create test intercepts the POST and never lets it reach a
server.

Run: make check-console2   (or python3 scripts/check-console2.py)
"""

import json
import time
import unittest
from pathlib import Path

from playwright.sync_api import sync_playwright

ROOT = Path(__file__).resolve().parent.parent
DOCUMENT = "https://wecert.test/console.html"
READONLY = "test-readonly-token"
ADMIN = "test-admin-token-0123456789abcdef"

HTML = (ROOT / "webconsole" / "console.html").read_text()

ACCOUNTS = {"accounts": [
    {"uin": "100012345678", "name": "intl-prod"},
    {"uin": "998877665544", "name": "staging"},
]}
BINDINGS = {"bindings": [
    {"id": "lb-fixture01", "region": "ap-guangzhou", "name": "fixture-clb",
     "listeners": [{"id": "lbl-fixture01", "proto": "HTTPS", "port": 443}]},
]}


def cert(name, uin, status, domains, days=None, bindings=0, complete=True,
         deploy=True, error=""):
    """One inventory entry shaped like what the daemon actually sends."""
    out = {
        "name": name, "status": status, "domains": domains,
        "bindings": {
            "count": bindings,
            "items": [{"loadBalancerId": "lb-fixture01", "region": "ap-guangzhou",
                       "listenerId": "lbl-fixture01", "protocol": "HTTPS", "port": 443}]
            if bindings else [],
        },
    }
    # The real payload omits `complete` on certificates that never bound, and
    # omits `deploy` on certificates that were never issued. Both are covered.
    if complete is not None:
        out["bindings"]["complete"] = complete
    if uin:
        out["uin"] = uin
    if deploy is not None:
        out["deploy"] = {"enabled": deploy}
    if days is not None:
        out["notAfter"] = time.strftime(
            "%Y-%m-%dT%H:%M:%SZ", time.gmtime(time.time() + days * 86400))
        out["daysLeft"] = days
    if error:
        out["lastError"] = error
    return out


# Five certificates chosen so every KPI and every grouping branch is exercised:
# two not-issued with no bindings (one carrying no `complete` flag at all),
# healthy + bound, expiring + bound, and waiting for the first bind.
FIXTURE = {
    "time": "2026-10-01T10:20:00Z",
    "desired": {"revision": "sha256:abc", "frozen": False},
    "summary": {},
    "certificates": [
        cert("welcome", None, "not_issued", ["wecome.invalid"], complete=False),
        cert("no-complete-flag", None, "not_issued", ["bare.example.org"],
             complete=None, deploy=None),
        cert("api-example", "100012345678", "expiring", ["api.example.com"],
             days=12, bindings=1),
        cert("shop-example", "100012345678", "ok",
             ["shop.example.com", "cdn.example.com"], days=82, bindings=1),
        cert("legacy-zone", "998877665544", "waiting_manual_bind",
             ["legacy.example.net"], days=200,
             error="uploaded, waiting for the first CLB bind"),
    ],
    "quotas": [],
}

CREATED = []


def route_handler(page, inventory, status_code=200, session=None):
    sess = {"read": True, "admin": True} if session is None else session

    def handle(route):
        url = route.request.url
        method = route.request.method
        if url.startswith(DOCUMENT):
            route.fulfill(status=200, content_type="text/html; charset=utf-8", body=HTML)
        elif "/api/session" in url:
            route.fulfill(status=200, content_type="application/json", body=json.dumps(sess))
        elif "/api/inventory" in url:
            route.fulfill(status=status_code, content_type="application/json",
                          body=json.dumps(inventory if status_code == 200 else {"error": "unauthorized"}))
        elif "/api/accounts" in url:
            route.fulfill(status=200, content_type="application/json", body=json.dumps(ACCOUNTS))
        elif "/api/bindings" in url:
            route.fulfill(status=200, content_type="application/json", body=json.dumps(BINDINGS))
        elif "/admin/certificates" in url and method == "POST":
            CREATED.append(json.loads(route.request.post_data or "{}"))
            route.fulfill(status=200, content_type="application/json",
                          body=json.dumps({"ok": True, "status": "created"}))
        elif "/hook/reconcile" in url and method == "POST":
            route.fulfill(status=202, content_type="application/json", body=json.dumps({"ok": True}))
        else:
            route.abort()
    return handle


class Console2Regression(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls._pw = sync_playwright().start()
        cls.browser = cls._pw.chromium.launch()

    @classmethod
    def tearDownClass(cls):
        cls.browser.close()
        cls._pw.stop()

    def setUp(self):
        CREATED.clear()
        self.ctx = self.browser.new_context(viewport={"width": 1280, "height": 900})
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
    def load(self, inventory=None, status_code=200, tokens=None, session=None):
        inv = FIXTURE if inventory is None else inventory
        self.page.route("**/*", route_handler(self.page, inv, status_code, session))
        if tokens:
            readonly, admin = tokens
            script = "try{localStorage.setItem('wecert.token',%r);" % readonly
            if admin:
                script += "localStorage.setItem('wecert.adminToken',%r);" % admin
            script += "sessionStorage.setItem('wecert.token',%r);}catch(e){}" % readonly
            self.page.add_init_script(script)
        self.page.goto(DOCUMENT, wait_until="domcontentloaded")
        self.page.wait_for_timeout(600)

    def rows(self):
        return self.page.locator("tbody tr[data-name]")

    def text(self, sel):
        return self.page.text_content(sel).strip()

    def kpis(self):
        return [self.text(s) for s in
                ("#metric-total", "#metric-attention", "#metric-expiring", "#metric-bindings")]

    # -- tests -------------------------------------------------------------
    def test_disconnected_state_says_so_and_shows_nothing(self):
        # No session and no token: the page must not invent an inventory.
        self.load(session={"read": False, "admin": False}, tokens=None)
        self.assertEqual(self.text("#connection-status"), "Disconnected",
                         "the header says the console is not connected")
        self.assertEqual(self.rows().count(), 0, "no certificate rows are invented")
        self.assertIn("Disconnected", self.text("#inventory-footer"))
        self.assertFalse(self.page.is_visible("#sync-warning") is False,
                         "a sync warning explains why the table is empty")

    def test_kpis_count_total_attention_expiring_and_binding_issues(self):
        self.load(tokens=(READONLY, ""))
        self.assertEqual(self.kpis(), ["5", "4", "1", "3"],
                         "total / needs attention / expiring / binding issues")

    def test_binding_issues_counted_when_the_complete_flag_is_absent(self):
        # The daemon omits bindings.complete on certificates that never bound.
        # Counting only complete:false would miss them entirely.
        inv = dict(FIXTURE, certificates=[
            cert("no-complete-flag", None, "not_issued", ["bare.example.org"],
                 complete=None, deploy=None)])
        self.load(inventory=inv, tokens=(READONLY, ""))
        self.assertEqual(self.text("#metric-bindings"), "1",
                         "a certificate with no bindings is a binding issue")

    def test_grouping_by_uin_and_expiry_soonest_order(self):
        self.load(tokens=(READONLY, ""))
        groups = self.page.locator("tr.group")
        self.assertEqual(groups.count(), 3, "two UINs plus an unassigned group")
        labels = [groups.nth(i).inner_text().replace("\n", " ") for i in range(groups.count())]
        self.assertIn("Unassigned UIN", labels[-1], "certificates without a UIN group last")
        first = self.rows().first.get_attribute("data-name")
        self.assertEqual(first, "api-example", "expiry soonest puts the 12-day cert first")

    def test_group_count_uses_the_singular_for_one_certificate(self):
        inv = dict(FIXTURE, certificates=[
            cert("shop-example", "100012345678", "ok", ["shop.example.com"], days=82, bindings=1)])
        self.load(inventory=inv, tokens=(READONLY, ""))
        self.assertIn("1 certificate", self.page.locator("tr.group").first.inner_text())
        self.assertNotIn("1 certificates", self.page.locator("tr.group").first.inner_text())

    def test_group_collapse_hides_and_restores_rows(self):
        self.load(tokens=(READONLY, ""))
        before = self.rows().count()
        self.page.locator("tr.group").first.locator("[data-group]").click()
        self.page.wait_for_timeout(200)
        collapsed = self.rows().count()
        self.assertLess(collapsed, before, "collapsing a group hides its rows")
        self.page.locator("tr.group").first.locator("[data-group]").click()
        self.page.wait_for_timeout(200)
        self.assertEqual(self.rows().count(), before, "expanding restores them")

    def test_search_narrows_by_name_and_domain(self):
        self.load(tokens=(READONLY, ""))
        self.page.fill("#certificate-search", "shop")
        self.page.wait_for_timeout(250)
        self.assertEqual(self.rows().count(), 1, "search matches the certificate name")
        self.assertEqual(self.rows().first.get_attribute("data-name"), "shop-example")
        self.page.fill("#certificate-search", "legacy.example.net")
        self.page.wait_for_timeout(250)
        self.assertEqual(self.rows().count(), 1, "search matches a SAN domain")

    def test_uin_filter_includes_the_unassigned_group(self):
        self.load(tokens=(READONLY, ""))
        self.page.click("#uin-trigger")
        self.page.wait_for_timeout(150)
        self.page.click('.uin-menu [data-uin=""]')
        self.page.wait_for_timeout(250)
        self.assertEqual(self.rows().count(), 2, "both UIN-less certificates")
        self.assertEqual(self.text("#uin-label"), "Unassigned UIN")

    def test_kpi_card_filters_the_table_and_toggles_back(self):
        self.load(tokens=(READONLY, ""))
        self.page.click('[data-metric="bindings"]')
        self.page.wait_for_timeout(250)
        self.assertEqual(self.rows().count(), 3, "only binding issues remain")
        self.page.click('[data-metric="bindings"]')
        self.page.wait_for_timeout(250)
        self.assertEqual(self.rows().count(), 5, "clicking again restores the full list")

    def test_clear_filter_resets_everything(self):
        self.load(tokens=(READONLY, ""))
        self.page.fill("#certificate-search", "shop")
        self.page.wait_for_timeout(200)
        self.assertTrue(self.page.is_visible("#clear-filter"), "clear appears once filtered")
        self.page.click("#clear-filter")
        self.page.wait_for_timeout(250)
        self.assertEqual(self.rows().count(), 5, "the filter is cleared")

    def test_footer_reports_live_counts_without_a_zero_uin_clause(self):
        self.load(tokens=(READONLY, ""))
        self.assertIn("Live inventory · 5 of 5 certificates across 2 UINs",
                      self.text("#inventory-footer"))

    def test_footer_drops_the_uin_clause_when_nothing_carries_one(self):
        inv = dict(FIXTURE, certificates=[
            cert("welcome", None, "not_issued", ["wecome.invalid"], complete=False)])
        self.load(inventory=inv, tokens=(READONLY, ""))
        foot = self.text("#inventory-footer")
        self.assertIn("Live inventory · 1 of 1 certificate", foot)
        self.assertNotIn("across", foot, "the UIN clause must not be printed at zero")

    def test_detail_drawer_opens_on_the_certificate_link_and_escape_closes_it(self):
        self.load(tokens=(READONLY, ""))
        self.page.click('[data-action="view"][data-name="api-example"]')
        self.page.wait_for_timeout(250)
        self.assertTrue(self.page.locator("#certificate-detail").evaluate("e => e.classList.contains('open')"))
        self.assertIn("api-example", self.text("#certificate-detail"))
        self.assertIn("api.example.com", self.text("#certificate-detail"),
                      "the drawer lists the certificate's domains")
        self.page.keyboard.press("Escape")
        self.page.wait_for_timeout(250)
        self.assertFalse(self.page.locator("#certificate-detail").evaluate("e => e.classList.contains('open')"))

    def test_row_menu_offers_actions_and_delete_asks_for_the_name(self):
        self.load(tokens=(READONLY, ADMIN))
        self.page.click('[data-menu="shop-example"]')
        self.page.wait_for_timeout(250)
        self.assertTrue(self.page.is_visible("#row-menu"), "the row menu opens")
        labels = [b.inner_text() for b in self.page.query_selector_all("#row-menu button")]
        self.assertIn("View details", labels)
        self.assertIn("Delete certificate", labels)
        self.page.click('#row-menu [data-row-action="delete"]')
        self.page.wait_for_timeout(250)
        modal = self.text("#certificate-action")
        self.assertIn("Delete certificate", modal)
        self.assertIn("shop-example", modal, "the confirmation names the certificate")

    def test_row_menu_warns_when_the_daemon_is_not_connected(self):
        self.load(session={"read": False, "admin": False}, tokens=None,
                  inventory={"certificates": [], "summary": {}})
        self.assertIn("Disconnected", self.text("#connection-status"))

    def test_create_form_posts_the_payload_and_mirrors_the_summary(self):
        self.load(tokens=(READONLY, ADMIN))
        self.page.click("#new-certificate")
        self.page.wait_for_timeout(250)
        self.assertTrue(self.page.is_visible("#certificate-modal"), "the create form opens")
        self.assertEqual(self.page.locator("#domain-list .domain-input").count(), 1,
                         "the form starts with a single empty domain row")

        self.page.fill("#certificate-name", "prod-api-tls")
        self.page.select_option("#certificate-uin", "100012345678")
        self.page.fill("#domain-list .domain-input", "api.example.com")
        self.page.click("#domain-add")
        self.page.fill("#domain-list .domain-row:nth-child(2) .domain-input", "www.example.com")
        self.page.wait_for_timeout(200)

        summary = self.text("#summary-rows")
        self.assertIn("2 domains", summary, "the summary counts the domains live")
        self.assertIn("www.example.com", summary, "the summary mirrors every domain")
        self.assertIn("100012345678", summary, "the summary mirrors the cloud account")
        self.assertIn("cloudflare", summary, "the summary mirrors the DNS provider")
        self.assertIn("Tencent CLB", summary, "the summary mirrors the deploy target")
        self.assertIn("Ready to create", self.text("#summary-state"),
                      "a complete form reports itself ready")

        self.page.click("#create-submit")
        self.page.wait_for_timeout(600)
        self.assertEqual(len(CREATED), 1, "exactly one create request is posted")
        body = CREATED[0]
        self.assertEqual(body["name"], "prod-api-tls")
        self.assertEqual(body["uin"], "100012345678")
        self.assertEqual(body["domains"], ["api.example.com", "www.example.com"])
        self.assertEqual(body["profile"], "classic")
        self.assertEqual(body["keyType"], "ecdsa-p256")
        self.assertEqual(body["deploy"], "clb")
        self.assertEqual(body["dns"]["provider"], "cloudflare")

    def test_create_form_refuses_an_unqualified_domain(self):
        self.load(tokens=(READONLY, ADMIN))
        self.page.click("#new-certificate")
        self.page.wait_for_timeout(250)
        self.page.fill("#certificate-name", "bad")
        self.page.fill("#domain-list .domain-input", "localhost")
        self.page.wait_for_timeout(200)
        self.assertIn("fully qualified", self.text("#summary-state"),
                      "the summary names the blocking problem before submission")
        self.page.click("#create-submit")
        self.page.wait_for_timeout(300)
        self.assertIn("fully qualified", self.text("#certificate-form .form-error"))
        self.assertEqual(len(CREATED), 0, "no create request is posted")

    def test_unauthorized_inventory_surfaces_an_error(self):
        self.load(status_code=401, tokens=(READONLY, ""))
        self.assertIn("unauthorized", self.text("#sync-warning"),
                      "a rejected token is reported instead of silently emptying the table")

    def test_slash_focuses_the_search_box(self):
        self.load(tokens=(READONLY, ""))
        self.page.click("body")
        self.page.keyboard.press("/")
        self.page.wait_for_timeout(200)
        self.assertEqual(self.page.evaluate("document.activeElement.id"), "certificate-search")

    def test_no_console_errors_across_the_whole_flow(self):
        self.load(tokens=(READONLY, ADMIN))
        self.page.click('[data-action="view"][data-name="api-example"]')
        self.page.wait_for_timeout(200)
        self.page.keyboard.press("Escape")
        self.page.click('[data-menu="shop-example"]')
        self.page.wait_for_timeout(200)
        self.page.keyboard.press("Escape")
        self.page.click("#new-certificate")
        self.page.wait_for_timeout(200)
        self.page.keyboard.press("Escape")
        self.assertEqual(self.errors, [], "the flow runs without a console error")

    def test_narrow_layout_keeps_the_table_scrollable(self):
        self.ctx.close()
        self.ctx = self.browser.new_context(viewport={"width": 390, "height": 780})
        self.page = self.ctx.new_page()
        self.load(tokens=(READONLY, ""))
        overflow = self.page.evaluate(
            "document.documentElement.scrollWidth - document.documentElement.clientWidth")
        self.assertLessEqual(overflow, 0, "no horizontal overflow at 390px")


if __name__ == "__main__":
    unittest.main(verbosity=2)
