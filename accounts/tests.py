import time
from io import StringIO

from django.contrib.auth import get_user_model
from django.core.cache import cache
from django.core.management import call_command
from django.test import TestCase, override_settings
from django.urls import reverse

from accounts import mfa
from accounts.models import Profile

User = get_user_model()
PW = "Str0ng!Pass-99"


def now_code(secret, offset=0):
    return mfa._code_for(secret, int(time.time() // mfa.STEP_SECONDS) + offset)


def make(name, superuser=False, with_mfa=False):
    u = User.objects.create_user(name, f"{name}@example.com", PW, is_superuser=superuser, is_staff=superuser)
    p = Profile.objects.create(user=u, status=Profile.APPROVED)
    codes = []
    if with_mfa:
        secret = mfa.new_secret()
        codes, hashes = mfa.new_recovery_codes()
        p.set_secret(secret)
        p.mfa_enabled, p.recovery_hashes = True, hashes
        p.save()
    return u, codes


@override_settings(REQUIRE_ADMIN_MFA=False)
class MfaLoginTests(TestCase):
    def setUp(self):
        cache.clear()

    def _password_step(self, name):
        return self.client.post(reverse("accounts:login"), {"username": name, "password": PW})

    def test_password_alone_does_not_sign_in_when_mfa_is_on(self):
        make("sam", with_mfa=True)
        r = self._password_step("sam")
        self.assertRedirects(r, reverse("accounts:mfa_verify"))
        self.assertNotIn("_auth_user_id", self.client.session)
        self.assertEqual(self.client.get(reverse("scans:dashboard")).status_code, 302)

    def test_valid_code_signs_in_and_replay_is_rejected(self):
        u, _ = make("sam", with_mfa=True)
        secret = u.profile.secret
        self._password_step("sam")
        r = self.client.post(reverse("accounts:mfa_verify"), {"code": now_code(secret)})
        self.assertRedirects(r, reverse("scans:dashboard"), fetch_redirect_response=False)
        self.assertIn("_auth_user_id", self.client.session)
        self.client.logout()
        self._password_step("sam")
        again = self.client.post(reverse("accounts:mfa_verify"), {"code": now_code(secret)})
        self.assertContains(again, "not valid")
        self.assertNotIn("_auth_user_id", self.client.session)

    def test_wrong_code_then_lockout(self):
        make("sam", with_mfa=True)
        self._password_step("sam")
        for _ in range(5):
            self.client.post(reverse("accounts:mfa_verify"), {"code": "000000"})
        r = self.client.post(reverse("accounts:mfa_verify"), {"code": "000000"})
        self.assertContains(r, "Too many wrong codes")

    def test_recovery_code_works_once(self):
        u, codes = make("sam", with_mfa=True)
        self._password_step("sam")
        self.client.post(reverse("accounts:mfa_verify"), {"code": codes[0]})
        self.assertIn("_auth_user_id", self.client.session)
        self.client.logout()
        self._password_step("sam")
        r = self.client.post(reverse("accounts:mfa_verify"), {"code": codes[0]})
        self.assertContains(r, "not valid")
        u.profile.refresh_from_db()
        self.assertEqual(len(u.profile.recovery_hashes), len(codes) - 1)

    def test_verify_page_without_password_step_redirects_to_login(self):
        self.assertRedirects(self.client.get(reverse("accounts:mfa_verify")), reverse("accounts:login"))

    def test_totp_matches_rfc6238_vector(self):
        # RFC 6238 appendix B, SHA1, secret "12345678901234567890", T=59 -> 94287082 (last 6 digits 287082).
        import base64
        secret = base64.b32encode(b"12345678901234567890").decode()
        self.assertEqual(mfa._code_for(secret, 59 // 30), "287082")


@override_settings(REQUIRE_ADMIN_MFA=False)
class MfaSecurityPageTests(TestCase):
    def setUp(self):
        cache.clear()
        self.u, _ = make("dev")
        self.client.force_login(self.u)

    def test_enrol_flow_shows_qr_and_recovery_codes(self):
        self.client.post(reverse("accounts:security"), {"action": "start"})
        page = self.client.get(reverse("accounts:security"))
        self.assertContains(page, "<svg")
        secret = self.client.session["mfa_setup_secret"]
        self.client.post(reverse("accounts:security"), {"action": "confirm", "code": now_code(secret)})
        self.u.profile.refresh_from_db()
        self.assertTrue(self.u.profile.mfa_enabled)
        self.assertEqual(len(self.u.profile.recovery_hashes), mfa.RECOVERY_COUNT)
        self.assertEqual(self.u.profile.secret, secret)
        self.assertNotIn(secret, self.u.profile.__dict__.get("totp_secret", ""))  # stored encrypted, not plain

    def test_wrong_confirmation_code_does_not_enable(self):
        self.client.post(reverse("accounts:security"), {"action": "start"})
        self.client.post(reverse("accounts:security"), {"action": "confirm", "code": "123456"})
        self.u.profile.refresh_from_db()
        self.assertFalse(self.u.profile.mfa_enabled)

    def test_disable_needs_password_and_code(self):
        u, _ = make("sec", with_mfa=True)
        self.client.force_login(u)
        self.client.post(reverse("accounts:security"), {"action": "disable", "password": "bad", "code": now_code(u.profile.secret)})
        u.profile.refresh_from_db()
        self.assertTrue(u.profile.mfa_enabled)
        self.client.post(reverse("accounts:security"), {"action": "disable", "password": PW, "code": now_code(u.profile.secret)})
        u.profile.refresh_from_db()
        self.assertFalse(u.profile.mfa_enabled)


class AdminMfaEnforcementTests(TestCase):
    def setUp(self):
        cache.clear()
        self.admin, _ = make("boss", superuser=True)

    @override_settings(REQUIRE_ADMIN_MFA=True)
    def test_admin_without_mfa_is_sent_to_security_page(self):
        self.client.force_login(self.admin)
        r = self.client.get(reverse("panel:overview"))
        self.assertRedirects(r, reverse("accounts:security"), fetch_redirect_response=False)
        self.assertEqual(self.client.get(reverse("accounts:security")).status_code, 200)

    @override_settings(REQUIRE_ADMIN_MFA=True)
    def test_admin_with_mfa_reaches_panel(self):
        admin, _ = make("boss2", superuser=True, with_mfa=True)
        self.client.force_login(admin)
        self.assertEqual(self.client.get(reverse("panel:overview")).status_code, 200)

    @override_settings(REQUIRE_ADMIN_MFA=True)
    def test_django_admin_login_cannot_bypass(self):
        r = self.client.get("/django-admin/login/")
        self.assertEqual(r.status_code, 302)
        self.assertIn(reverse("accounts:login"), r["Location"])

    @override_settings(REQUIRE_ADMIN_MFA=True)
    def test_admin_resets_user_mfa_from_panel(self):
        admin, _ = make("boss3", superuser=True, with_mfa=True)
        user, _ = make("locked", with_mfa=True)
        self.client.force_login(admin)
        self.client.post(reverse("panel:reset_mfa", args=[user.pk]))
        user.profile.refresh_from_db()
        self.assertFalse(user.profile.mfa_enabled)

    def test_reset_mfa_command(self):
        user, _ = make("cmd", with_mfa=True)
        out = StringIO()
        call_command("reset_mfa", "cmd", stdout=out)
        user.profile.refresh_from_db()
        self.assertFalse(user.profile.mfa_enabled)


class HomePageTests(TestCase):
    def test_home_is_public_and_logo_links_to_it(self):
        r = self.client.get(reverse("home"))
        self.assertEqual(r.status_code, 200)
        self.assertContains(r, 'href="/"')
        self.assertContains(self.client.get(reverse("accounts:login")), 'href="/"')


@override_settings(ADMIN_WHATSAPP="923001234567")
class WhatsAppApprovalTests(TestCase):
    def test_register_shows_whatsapp_button_with_username(self):
        r = self.client.post(reverse("accounts:register"), {"username": "newdev", "email": "n@example.com", "organization": "Acme",
                                                           "password": PW, "password2": PW}, follow=True)
        self.assertContains(r, "https://wa.me/923001234567?text=")
        self.assertContains(r, "Username%3A%20newdev")

    def test_pending_login_shows_button(self):
        u, _ = make("wait")
        u.profile.status = Profile.PENDING
        u.profile.save()
        r = self.client.post(reverse("accounts:login"), {"username": "wait", "password": PW})
        self.assertContains(r, "Username%3A%20wait")

    @override_settings(ADMIN_WHATSAPP="")
    def test_no_button_without_number(self):
        r = self.client.get(reverse("accounts:login"))
        self.assertNotContains(r, "wa.me")
