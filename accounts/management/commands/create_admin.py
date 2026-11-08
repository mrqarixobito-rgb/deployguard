"""Create or update the administrator from environment variables.

    python manage.py create_admin

Reads ADMIN_USERNAME, ADMIN_PASSWORD and ADMIN_EMAIL from the environment or .env file.
"""
import os

from django.contrib.auth import get_user_model
from django.core.management.base import BaseCommand, CommandError

from accounts.models import Profile


class Command(BaseCommand):
    help = "Create (or reset the password of) the admin account from ADMIN_* environment variables."

    def handle(self, *args, **options):
        username = os.environ.get("ADMIN_USERNAME", "").strip()
        password = os.environ.get("ADMIN_PASSWORD", "")
        email = os.environ.get("ADMIN_EMAIL", "").strip()
        if not username or not password:
            raise CommandError("Set ADMIN_USERNAME and ADMIN_PASSWORD (see .env.example).")
        User = get_user_model()
        user, created = User.objects.get_or_create(username=username, defaults={"email": email})
        user.is_staff = user.is_superuser = True
        user.email = email or user.email
        user.set_password(password)
        user.save()
        Profile.objects.update_or_create(user=user, defaults={"status": Profile.APPROVED})
        self.stdout.write(self.style.SUCCESS(f"Admin '{username}' {'created' if created else 'updated'}."))
