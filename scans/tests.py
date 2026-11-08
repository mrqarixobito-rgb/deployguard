from unittest import mock

from django.contrib.auth import get_user_model
from django.core.cache import cache
from django.core.management import call_command
from django.test import TestCase, override_settings
from django.urls import reverse
from requests.structures import CaseInsensitiveDict

from accounts.models import Profile
from core.models import GEMINI_API_KEY, AppSetting
from scans import ai, scanner
from scans.checks import CHECKS, CheckResult
from scans.compare import classify, record_scan, score_for
from scans.models import AIPrompt, Finding, Scan, Website
from scans.pdf import build_pdf
from scans.security import UnsafeTarget, normalize_url, validate_target

User = get_user_model()


def make_user(name, status=Profile.APPROVED, superuser=False):
    u = User.objects.create_user(name, f"{name}@example.com", "Str0ng!Pass-99")
    u.is_superuser = u.is_staff = superuser
    u.save()
    Profile.objects.create(user=u, status=status)
    return u


def results(failing):
    return [CheckResult(c.id, c.id in failing, f"evidence for {c.id}" if c.id in failing else "ok") for c in CHECKS]


class ClassifyTests(TestCase):
    def test_all_cases(self):
        self.assertEqual(classify(True, None, False), Finding.NEW)
        self.assertEqual(classify(False, None, False), Finding.PASSED)
        self.assertEqual(classify(True, True, True), Finding.UNCHANGED)
        self.assertEqual(classify(False, True, True), Finding.RESOLVED)
        self.assertEqual(classify(True, False, True), Finding.RECURRING)
        self.assertEqual(classify(True, False, False), Finding.NEW)

    def test_score(self):
        self.assertEqual(score_for(results([])), 100)
        self.assertEqual(score_for(results({"cookie", "hsts"})), 100 - 18 - 12)
        self.assertEqual(score_for(results({c.id for c in CHECKS})), max(0, 100 - sum(c.weight for c in CHECKS)))


class HistoryComparisonTests(TestCase):
    def test_new_resolved_recurring_across_scans(self):
        site = Website.objects.create(owner=make_user("dev"), url="https://example.com")
        s1 = record_scan(site, results({"hsts", "csp"}))
        s2 = record_scan(site, results({"csp"}))          # hsts fixed
        s3 = record_scan(site, results({"csp", "hsts"}))  # hsts comes back
        st = lambda s, cid: s.findings.get(check_id=cid).status
        self.assertEqual((st(s1, "hsts"), st(s1, "csp")), ("new", "new"))
        self.assertEqual((st(s2, "hsts"), st(s2, "csp")), ("resolved", "unchanged"))
        self.assertEqual((st(s3, "hsts"), st(s3, "csp")), ("recurring", "unchanged"))
        self.assertEqual([s1.number, s2.number, s3.number], [1, 2, 3])
        self.assertEqual(s3.counts()["recurring"], 1)


@override_settings(REQUIRE_ADMIN_MFA=False)
class IsolationAndAccessTests(TestCase):
    def setUp(self):
        cache.clear()
        self.a, self.b = make_user("alice"), make_user("bob")
        self.admin = make_user("root", superuser=True)
        self.site = Website.objects.create(owner=self.a, url="https://alice.example")
        self.scan = record_scan(self.site, results({"hsts"}))
        self.finding = self.scan.findings.get(check_id="hsts")

    def test_other_user_cannot_open_scan_report_rescan_or_explain(self):
        self.client.force_login(self.b)
        self.assertEqual(self.client.get(reverse("scans:detail", args=[self.scan.pk])).status_code, 404)
        self.assertEqual(self.client.get(reverse("scans:report", args=[self.scan.pk])).status_code, 404)
        self.assertEqual(self.client.post(reverse("scans:rescan", args=[self.scan.pk])).status_code, 404)
        self.assertEqual(self.client.post(reverse("scans:explain", args=[self.finding.pk])).status_code, 404)

    def test_owner_sees_scan_and_pdf(self):
        self.client.force_login(self.a)
        self.assertContains(self.client.get(reverse("scans:detail", args=[self.scan.pk])), "HSTS header missing")
        pdf = self.client.get(reverse("scans:report", args=[self.scan.pk]))
        self.assertEqual(pdf["Content-Type"], "application/pdf")
        self.assertTrue(pdf.content.startswith(b"%PDF"))

    def test_dashboard_lists_only_own_sites(self):
        Website.objects.create(owner=self.b, url="https://bob.example")
        record_scan(Website.objects.get(url="https://bob.example"), results(set()))
        self.client.force_login(self.a)
        body = self.client.get(reverse("scans:dashboard")).content.decode()
        self.assertIn("alice.example", body)
        self.assertNotIn("bob.example", body)

    def test_regular_user_gets_403_on_panel_and_settings(self):
        self.client.force_login(self.a)
        for name in ("overview", "approvals", "users", "prompts", "links", "database", "settings"):
            self.assertEqual(self.client.get(reverse(f"panel:{name}")).status_code, 403, name)

    def test_anonymous_redirected_to_login(self):
        r = self.client.get(reverse("scans:dashboard"))
        self.assertEqual(r.status_code, 302)
        self.assertIn("/login/", r["Location"])

    def test_admin_sees_every_panel_page_and_user_data(self):
        self.client.force_login(self.admin)
        for name in ("overview", "approvals", "users", "prompts", "links", "database", "settings"):
            self.assertEqual(self.client.get(reverse(f"panel:{name}")).status_code, 200, name)
        self.assertContains(self.client.get(reverse("panel:links")), "alice.example")
        self.assertContains(self.client.get(reverse("panel:user", args=[self.a.pk])), "alice.example")
        self.assertEqual(self.client.get(reverse("panel:database") + "?table=scans").status_code, 200)

    def test_admin_goes_to_panel_not_dashboard(self):
        self.client.force_login(self.admin)
        self.assertEqual(self.client.get(reverse("scans:dashboard"))["Location"], reverse("panel:overview"))


@override_settings(REQUIRE_ADMIN_MFA=False)
class AccountFlowTests(TestCase):
    def setUp(self):
        cache.clear()

    def test_register_pending_then_approve_then_login(self):
        r = self.client.post(reverse("accounts:register"), {"username": "newdev", "email": "n@example.com", "organization": "Acme",
                                                           "password": "Str0ng!Pass-99", "password2": "Str0ng!Pass-99"})
        self.assertRedirects(r, reverse("accounts:login"))
        user = User.objects.get(username="newdev")
        self.assertEqual(user.profile.status, Profile.PENDING)
        denied = self.client.post(reverse("accounts:login"), {"username": "newdev", "password": "Str0ng!Pass-99"})
        self.assertContains(denied, "waiting for admin approval")
        admin = make_user("root", superuser=True)
        self.client.force_login(admin)
        self.client.post(reverse("panel:status", args=[user.pk]), {"status": "approved"})
        self.client.logout()
        ok = self.client.post(reverse("accounts:login"), {"username": "newdev", "password": "Str0ng!Pass-99"})
        self.assertRedirects(ok, reverse("scans:dashboard"))

    def test_rejected_user_cannot_login(self):
        make_user("nope", status=Profile.REJECTED)
        r = self.client.post(reverse("accounts:login"), {"username": "nope", "password": "Str0ng!Pass-99"})
        self.assertContains(r, "declined")

    def test_weak_password_and_duplicate_rejected(self):
        make_user("taken")
        r = self.client.post(reverse("accounts:register"), {"username": "taken", "email": "x@example.com", "password": "12345678", "password2": "12345678"})
        self.assertContains(r, "That username is taken.")
        self.assertFalse(User.objects.filter(email="x@example.com").exists())

    def test_login_lockout_after_five_failures(self):
        make_user("victim")
        for _ in range(5):
            self.client.post(reverse("accounts:login"), {"username": "victim", "password": "wrong"})
        r = self.client.post(reverse("accounts:login"), {"username": "victim", "password": "Str0ng!Pass-99"})
        self.assertContains(r, "Too many failed attempts")

    def test_create_admin_command(self):
        with mock.patch.dict("os.environ", {"ADMIN_USERNAME": "uzair.root", "ADMIN_PASSWORD": "@Uzair.1122", "ADMIN_EMAIL": "a@example.com"}):
            call_command("create_admin")
        u = User.objects.get(username="uzair.root")
        self.assertTrue(u.is_superuser and u.check_password("@Uzair.1122"))
        self.assertTrue(self.client.login(username="uzair.root", password="@Uzair.1122"))


@override_settings(REQUIRE_ADMIN_MFA=False)
class ApiKeyStorageTests(TestCase):
    def setUp(self):
        self.admin = make_user("root", superuser=True)

    def test_key_saved_encrypted_in_database_and_only_admin_sees_hint(self):
        self.client.force_login(self.admin)
        self.client.post(reverse("panel:settings"), {"action": "save", "api_key": "AIzaSyTESTKEY1234567890", "model": "gemini-2.5-flash"})
        raw = AppSetting.objects.get(key=GEMINI_API_KEY)
        self.assertTrue(raw.is_secret)
        self.assertNotIn("AIzaSyTESTKEY", raw.value)
        self.assertEqual(AppSetting.get(GEMINI_API_KEY), "AIzaSyTESTKEY1234567890")
        page = self.client.get(reverse("panel:settings")).content.decode()
        self.assertNotIn("AIzaSyTESTKEY1234567890", page)
        db_page = self.client.get(reverse("panel:database") + "?table=app_settings").content.decode()
        self.assertIn("(encrypted)", db_page)
        self.assertNotIn("AIzaSyTESTKEY1234567890", db_page)

    def test_empty_key_field_keeps_existing_key_and_clear_removes_it(self):
        AppSetting.put(GEMINI_API_KEY, "keep-me-123456", secret=True)
        self.client.force_login(self.admin)
        self.client.post(reverse("panel:settings"), {"action": "save", "api_key": "", "model": "gemini-2.5-flash"})
        self.assertEqual(AppSetting.get(GEMINI_API_KEY), "keep-me-123456")
        self.client.post(reverse("panel:settings"), {"action": "clear"})
        self.assertEqual(AppSetting.get(GEMINI_API_KEY), "")

    def test_regular_user_cannot_post_settings(self):
        self.client.force_login(make_user("dev"))
        r = self.client.post(reverse("panel:settings"), {"action": "save", "api_key": "stolen"})
        self.assertEqual(r.status_code, 403)
        self.assertEqual(AppSetting.get(GEMINI_API_KEY), "")


class AiTests(TestCase):
    def setUp(self):
        cache.clear()
        self.user = make_user("dev")
        site = Website.objects.create(owner=self.user, url="https://ai.example")
        self.finding = record_scan(site, results({"csp"})).findings.get(check_id="csp")
        self.client.force_login(self.user)

    def test_sample_answer_without_key_is_logged(self):
        r = self.client.post(reverse("scans:explain", args=[self.finding.pk]))
        self.assertEqual(r.json()["source"], "sample")
        self.assertEqual(AIPrompt.objects.count(), 1)
        self.assertIn("Content-Security-Policy", AIPrompt.objects.get().prompt)

    def test_gemini_used_when_key_in_database_and_second_call_reuses_answer(self):
        AppSetting.put(GEMINI_API_KEY, "AIza-test", secret=True)
        fake = mock.Mock(status_code=200)
        fake.raise_for_status = lambda: None
        fake.json.return_value = {"candidates": [{"content": {"parts": [{"text": "Gemini says: add a CSP header."}]}}]}
        with mock.patch("scans.ai.requests.post", return_value=fake) as post:
            first = self.client.post(reverse("scans:explain", args=[self.finding.pk])).json()
            second = self.client.post(reverse("scans:explain", args=[self.finding.pk])).json()
        self.assertEqual(first["source"], "gemini")
        self.assertEqual(second["text"], first["text"])
        self.assertEqual(post.call_count, 1)
        self.assertEqual(post.call_args.kwargs["headers"]["x-goog-api-key"], "AIza-test")
        self.assertEqual(AIPrompt.objects.count(), 1)

    def test_gemini_failure_falls_back_to_sample(self):
        import requests
        AppSetting.put(GEMINI_API_KEY, "AIza-test", secret=True)
        with mock.patch("scans.ai.requests.post", side_effect=requests.ConnectionError):
            r = self.client.post(reverse("scans:explain", args=[self.finding.pk])).json()
        self.assertEqual(r["source"], "sample")

    @override_settings(AI_LIMIT_PER_HOUR=1)
    def test_rate_limit(self):
        site = Website.objects.get(url="https://ai.example")
        other = record_scan(site, results({"hsts"})).findings.get(check_id="hsts")
        self.client.post(reverse("scans:explain", args=[self.finding.pk]))
        self.assertEqual(self.client.post(reverse("scans:explain", args=[other.pk])).status_code, 429)


class SecurityGuardTests(TestCase):
    def test_private_and_metadata_targets_blocked(self):
        for url in ("http://127.0.0.1/", "http://169.254.169.254/latest/meta-data/", "http://10.0.0.5/", "http://localhost/"):
            with self.assertRaises(UnsafeTarget, msg=url):
                validate_target(url)

    def test_nonstandard_port_and_scheme_blocked(self):
        with self.assertRaises(UnsafeTarget):
            validate_target("https://example.com:22/")
        with self.assertRaises(UnsafeTarget):
            normalize_url("file:///etc/passwd")
        with self.assertRaises(UnsafeTarget):
            normalize_url("https://user:pw@example.com")

    def test_normalize(self):
        self.assertEqual(normalize_url("Example.com/path?x=1"), "https://example.com")

    def test_scan_form_requires_consent_and_blocks_private(self):
        cache.clear()
        self.client.force_login(make_user("dev"))
        r = self.client.post(reverse("scans:new"), {"url": "https://example.com"}, follow=True)
        self.assertContains(r, "Confirm that you own this website")
        r = self.client.post(reverse("scans:new"), {"url": "http://169.254.169.254", "authorized": "1"}, follow=True)
        self.assertContains(r, "private or internal network")
        self.assertEqual(Website.objects.count(), 0)


class FakeResp:
    def __init__(self, headers, url="https://site.example/", status=200, cookies=()):
        self.headers = CaseInsensitiveDict(headers)
        self.url, self.status_code = url, status
        self.is_redirect = False
        self.raw = mock.Mock()
        self.raw.headers.getlist = lambda name: list(cookies)

    def close(self):
        pass


class ScannerTests(TestCase):
    GOOD = {"Strict-Transport-Security": "max-age=63072000; includeSubDomains", "Content-Security-Policy": "default-src 'self'; frame-ancestors 'none'",
            "X-Content-Type-Options": "nosniff", "Referrer-Policy": "no-referrer", "Permissions-Policy": "camera=()", "Server": "cloudflare"}

    def run_with(self, resp, redirect_ok=True):
        probe = FakeResp({"Location": "https://site.example/"}, url="http://site.example/", status=301)
        probe.is_redirect = redirect_ok
        if not redirect_ok:
            probe.headers = CaseInsensitiveDict({}); probe.status_code = 200
        calls = iter([resp, probe, FakeResp({})])
        with mock.patch.object(scanner, "safe_request", side_effect=lambda *a, **k: next(calls)), \
             mock.patch.object(scanner, "_check_tls", return_value=CheckResult("tls", False, "ok")):
            return {r.id: r for r in scanner.run_checks("https://site.example")}

    def test_hardened_site_passes_everything(self):
        res = self.run_with(FakeResp(self.GOOD, cookies=["sessionid=abc; Secure; HttpOnly; Path=/"]))
        self.assertEqual([i for i, r in res.items() if r.failed], [])

    def test_bare_site_fails_header_checks(self):
        res = self.run_with(FakeResp({"Server": "nginx/1.18.0", "X-Powered-By": "PHP/7.4"}, cookies=["sessionid=abc; Path=/"]), redirect_ok=False)
        failed = {i for i, r in res.items() if r.failed}
        self.assertTrue({"hsts", "csp", "xfo", "xcto", "ref", "perm", "cookie", "redir", "server"} <= failed)
        self.assertIn("missing: Secure, HttpOnly", res["cookie"].evidence)

    def test_weak_hsts_and_report_only_csp(self):
        h = dict(self.GOOD, **{"Strict-Transport-Security": "max-age=300"})
        del h["Content-Security-Policy"]
        h["Content-Security-Policy-Report-Only"] = "default-src 'self'"
        res = self.run_with(FakeResp(h))
        self.assertTrue(res["hsts"].failed and res["csp"].failed)
        self.assertIn("Report-Only", res["csp"].evidence)


class PdfAndSeedTests(TestCase):
    def test_seed_demo_and_pdf_for_every_platform(self):
        call_command("seed_demo")
        self.assertTrue(Scan.objects.exists())
        scan = Scan.objects.filter(website__url="https://northwind.dev").order_by("-number").first()
        self.assertGreater(scan.number, 1)
        for plat in ("nginx", "apache", "django", "express", "static", "bogus"):
            pdf = build_pdf(scan, plat)
            self.assertTrue(pdf.startswith(b"%PDF") and len(pdf) > 3000)
