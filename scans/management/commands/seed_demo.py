"""Fill the database with demo users and scan history so every screen has data on first run.

    python manage.py seed_demo
"""
import random

from django.contrib.auth import get_user_model
from django.core.management.base import BaseCommand
from django.utils import timezone
from datetime import timedelta

from accounts.models import Profile
from scans.checks import CHECKS, CheckResult
from scans.compare import record_scan
from scans.models import Website

User = get_user_model()
EVIDENCE = {
    "hsts": "Strict-Transport-Security: (not present)", "csp": "Content-Security-Policy: (not present)",
    "xfo": "X-Frame-Options: (not present)\nCSP frame-ancestors: (not present)", "xcto": "X-Content-Type-Options: (not present)",
    "ref": "Referrer-Policy: (not present)", "perm": "Permissions-Policy: (not present)",
    "cookie": "Set-Cookie: sessionid=…  (missing: Secure, HttpOnly)", "redir": "GET http://HOST/ -> 200\nExpected a 301 redirect to https://HOST/",
    "server": "Server: nginx/1.18.0 (Ubuntu)\nX-Powered-By: PHP/7.4.3", "cors": "Access-Control-Allow-Origin: *\nAccess-Control-Allow-Credentials: true",
    "tls": "Handshake TLSv1.1 -> accepted",
}


def simulate(url, rounds):
    """Yield CheckResult lists for successive scans: some fixes land, some issues come back."""
    base = random.Random(url)
    fail = [base.random() < 0.55 for _ in CHECKS]
    host = url.split("//")[1]
    for r in range(rounds + 1):
        if r:
            g = random.Random(f"{url}#{r}")
            fail = [(g.random() >= 0.45) if f else (g.random() < 0.2) for f in fail]
        yield [CheckResult(c.id, f, EVIDENCE[c.id].replace("HOST", host) if f else "Present and valid.") for c, f in zip(CHECKS, fail)]


class Command(BaseCommand):
    help = "Create demo users, websites and scan history (demo data, clearly marked mode=demo)."

    def handle(self, *args, **options):
        def user(name, email, org, status):
            u, created = User.objects.get_or_create(username=name, defaults={"email": email})
            if created:
                u.set_password("Demo@1234")
                u.save()
            Profile.objects.update_or_create(user=u, defaults={"organization": org, "status": status})
            return u

        dev = user("demo.dev", "demo@northwind.dev", "Northwind Labs", Profile.APPROVED)
        aisha = user("aisha.khan", "aisha@brightpay.io", "BrightPay", Profile.APPROVED)
        user("bilal.ahmed", "bilal@campusmart.pk", "CampusMart", Profile.PENDING)
        user("sara.malik", "sara@ledgerly.app", "Ledgerly", Profile.PENDING)
        plan = [(dev, "https://northwind.dev", 3, 30), (dev, "https://shop.northwind.dev", 1, 12), (aisha, "https://brightpay.io", 2, 18)]
        for owner, url, rounds, start in plan:
            site, _ = Website.objects.get_or_create(owner=owner, url=url)
            if site.scans.exists():
                continue
            for i, results in enumerate(simulate(url, rounds)):
                scan = record_scan(site, results, mode="demo")
                scan.created_at = timezone.now() - timedelta(days=start - i * (start / (rounds + 1)))
                scan.save(update_fields=["created_at"])
        self.stdout.write(self.style.SUCCESS("Demo data ready. Demo user: demo.dev / Demo@1234"))
