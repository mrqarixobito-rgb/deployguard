"""Turn off MFA for a user who lost their device and recovery codes.

    python manage.py reset_mfa USERNAME
"""
from django.contrib.auth import get_user_model
from django.core.management.base import BaseCommand, CommandError


class Command(BaseCommand):
    help = "Remove the authenticator and recovery codes of one user."

    def add_arguments(self, parser):
        parser.add_argument("username")

    def handle(self, *args, **opts):
        user = get_user_model().objects.filter(username=opts["username"]).select_related("profile").first()
        if not user or not hasattr(user, "profile"):
            raise CommandError("No such user.")
        user.profile.clear_mfa()
        user.profile.save()
        self.stdout.write(self.style.SUCCESS(f"MFA reset for {user.username}. They can sign in with their password and set it up again."))
