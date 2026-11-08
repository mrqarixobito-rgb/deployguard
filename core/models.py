from django.conf import settings
from django.db import models

from .crypto import decrypt, encrypt


class AppSetting(models.Model):
    """Key/value settings saved in the database. Secret values are stored encrypted."""

    key = models.CharField(max_length=80, unique=True)
    value = models.TextField(blank=True)
    is_secret = models.BooleanField(default=False)
    updated_at = models.DateTimeField(auto_now=True)
    updated_by = models.ForeignKey(settings.AUTH_USER_MODEL, null=True, blank=True, on_delete=models.SET_NULL, related_name="+")

    def __str__(self):
        return self.key

    @classmethod
    def get(cls, key: str, default: str = "") -> str:
        row = cls.objects.filter(key=key).first()
        if not row or not row.value:
            return default
        return decrypt(row.value) if row.is_secret else row.value

    @classmethod
    def put(cls, key: str, value: str, *, secret: bool = False, user=None) -> None:
        stored = encrypt(value) if (secret and value) else value
        cls.objects.update_or_create(key=key, defaults={"value": stored, "is_secret": secret, "updated_by": user})


GEMINI_API_KEY = "gemini_api_key"
GEMINI_MODEL = "gemini_model"
DEFAULT_GEMINI_MODEL = "gemini-2.5-flash"
