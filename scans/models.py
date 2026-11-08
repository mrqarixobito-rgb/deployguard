from urllib.parse import urlparse

from django.conf import settings
from django.db import models

from .checks import CHECK_BY_ID, SEVERITY_ORDER


class Website(models.Model):
    owner = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.CASCADE, related_name="websites")
    url = models.URLField(max_length=300)
    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        unique_together = [("owner", "url")]
        ordering = ["-created_at"]

    def __str__(self):
        return self.url

    @property
    def host(self) -> str:
        return urlparse(self.url).netloc


class Scan(models.Model):
    website = models.ForeignKey(Website, on_delete=models.CASCADE, related_name="scans")
    number = models.PositiveIntegerField()
    score = models.PositiveSmallIntegerField()
    mode = models.CharField(max_length=10, default="live")  # "live" or "demo"
    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        unique_together = [("website", "number")]
        ordering = ["-created_at"]

    def __str__(self):
        return f"{self.website.url} #{self.number}"

    @property
    def score_class(self) -> str:
        return "ok" if self.score >= 80 else "med" if self.score >= 55 else "crit"

    def counts(self) -> dict:
        c = {"new": 0, "recurring": 0, "unchanged": 0, "resolved": 0, "passed": 0}
        for f in self.findings.all():
            c[f.status] += 1
        return c

    def previous(self):
        return self.website.scans.filter(number__lt=self.number).order_by("-number").first()


class Finding(models.Model):
    NEW, RECURRING, UNCHANGED, RESOLVED, PASSED = "new", "recurring", "unchanged", "resolved", "passed"
    STATUS_CHOICES = [(s, s.title()) for s in (NEW, RECURRING, UNCHANGED, RESOLVED, PASSED)]

    scan = models.ForeignKey(Scan, on_delete=models.CASCADE, related_name="findings")
    check_id = models.CharField(max_length=20)
    failed = models.BooleanField(default=False)
    status = models.CharField(max_length=10, choices=STATUS_CHOICES)
    evidence = models.TextField(blank=True)

    class Meta:
        unique_together = [("scan", "check_id")]

    @property
    def meta(self):
        return CHECK_BY_ID[self.check_id]

    @property
    def title(self) -> str:
        return self.meta.title

    @property
    def severity(self) -> str:
        return self.meta.severity

    @property
    def severity_rank(self) -> int:
        return SEVERITY_ORDER.index(self.meta.severity)

    def __str__(self):
        return f"{self.scan} {self.check_id} {self.status}"


class AIPrompt(models.Model):
    """Every request sent to the AI model, with the answer. Visible to the admin."""

    user = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.CASCADE, related_name="ai_prompts")
    scan = models.ForeignKey(Scan, null=True, blank=True, on_delete=models.SET_NULL, related_name="ai_prompts")
    finding = models.ForeignKey(Finding, null=True, blank=True, on_delete=models.SET_NULL, related_name="ai_prompts")
    site = models.CharField(max_length=300)
    finding_title = models.CharField(max_length=200)
    prompt = models.TextField()
    response = models.TextField()
    source = models.CharField(max_length=10, default="sample")  # "gemini" or "sample"
    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        ordering = ["-created_at"]

    def __str__(self):
        return f"{self.user} / {self.finding_title}"
