from django.conf import settings
from django.db import models

from core.crypto import decrypt, encrypt


class Profile(models.Model):
    """Extra account data. New users start as 'pending' until an admin approves them."""

    PENDING, APPROVED, REJECTED = "pending", "approved", "rejected"
    STATUS_CHOICES = [(PENDING, "Pending"), (APPROVED, "Approved"), (REJECTED, "Rejected")]

    user = models.OneToOneField(settings.AUTH_USER_MODEL, on_delete=models.CASCADE, related_name="profile")
    organization = models.CharField(max_length=120, blank=True)
    status = models.CharField(max_length=10, choices=STATUS_CHOICES, default=PENDING, db_index=True)
    decided_at = models.DateTimeField(null=True, blank=True)
    decided_by = models.ForeignKey(settings.AUTH_USER_MODEL, null=True, blank=True, on_delete=models.SET_NULL, related_name="+")

    # Multi-factor authentication (TOTP authenticator app + one-time recovery codes)
    mfa_enabled = models.BooleanField(default=False)
    totp_secret = models.TextField(blank=True)  # encrypted at rest
    totp_last_step = models.BigIntegerField(default=0)  # blocks re-using the same 30-second code
    recovery_hashes = models.JSONField(default=list, blank=True)
    mfa_enabled_at = models.DateTimeField(null=True, blank=True)

    @property
    def secret(self) -> str:
        return decrypt(self.totp_secret) if self.totp_secret else ""

    def set_secret(self, plain: str) -> None:
        self.totp_secret = encrypt(plain) if plain else ""

    def clear_mfa(self) -> None:
        self.mfa_enabled = False
        self.totp_secret = ""
        self.totp_last_step = 0
        self.recovery_hashes = []
        self.mfa_enabled_at = None

    def __str__(self):
        return f"{self.user.username} ({self.status})"
