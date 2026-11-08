"""Create several approved users at once.

    python manage.py create_users mukhlis zubair arfeel sultan zeeshan --password "Abc@123456"

Existing usernames are skipped (their password is not changed) unless --reset-password is given.
"""
from django.contrib.auth import get_user_model
from django.contrib.auth.password_validation import validate_password
from django.core.exceptions import ValidationError
from django.core.management.base import BaseCommand, CommandError
from django.db import transaction

from accounts.models import Profile

User = get_user_model()


class Command(BaseCommand):
    help = "Create approved user accounts from a list of usernames sharing one starting password."

    def add_arguments(self, parser):
        parser.add_argument("usernames", nargs="+")
        parser.add_argument("--password", required=True, help="Starting password for every new user.")
        parser.add_argument("--reset-password", action="store_true", help="Also set the password of users that already exist.")

    def handle(self, *args, **opts):
        password = opts["password"]
        try:
            validate_password(password)
        except ValidationError as exc:
            raise CommandError("Password rejected: " + " ".join(exc.messages))
        for raw in opts["usernames"]:
            name = raw.strip().lower()
            if not name:
                continue
            with transaction.atomic():
                user = User.objects.filter(username__iexact=name).first()
                if user and not opts["reset_password"]:
                    self.stdout.write(f"skipped  {name} (already exists)")
                    continue
                created = user is None
                if created:
                    user = User(username=name, email=f"{name}@example.com")
                user.set_password(password)
                user.save()
                profile, _ = Profile.objects.get_or_create(user=user)
                profile.status = Profile.APPROVED
                profile.save()
                self.stdout.write(self.style.SUCCESS(f"{'created ' if created else 'updated '} {name} (approved)"))
