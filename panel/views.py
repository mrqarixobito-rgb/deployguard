"""Admin panel (superuser only): approvals, users, their prompts and website links, the database viewer and AI settings."""
from django.contrib import messages
from django.contrib.auth import get_user_model
from django.db.models import Count, Q
from django.db.models.functions import TruncDate
from django.shortcuts import get_object_or_404, redirect, render
from django.utils import timezone
from django.views.decorators.http import require_POST
import requests

from accounts.decorators import admin_required
from accounts.models import Profile
from core.models import DEFAULT_GEMINI_MODEL, GEMINI_API_KEY, GEMINI_MODEL, AppSetting
from scans import ai
from scans.models import AIPrompt, Finding, Scan, Website
from scans.charts import day_bars
from scans.views import sparkline

User = get_user_model()
GEMINI_MODELS = ["gemini-2.5-flash", "gemini-2.5-flash-lite", "gemini-2.0-flash"]


def _people():
    return User.objects.filter(is_superuser=False).select_related("profile")


@admin_required
def overview(request):
    ctx = {
        "pending": _people().filter(profile__status=Profile.PENDING).order_by("-date_joined"),
        "stats": {
            "pending": Profile.objects.filter(status=Profile.PENDING).count(),
            "approved": Profile.objects.filter(status=Profile.APPROVED, user__is_superuser=False).count(),
            "sites": Website.objects.count(), "scans": Scan.objects.count(), "prompts": AIPrompt.objects.count(),
        },
        "prompts": AIPrompt.objects.select_related("user")[:4],
        "ai_ready": bool(AppSetting.get(GEMINI_API_KEY)),
    }
    since = timezone.now() - timezone.timedelta(days=14)
    per_day = {r["d"]: r["n"] for r in Scan.objects.filter(created_at__gte=since).annotate(d=TruncDate("created_at")).values("d").annotate(n=Count("id"))}
    ctx["bars"] = day_bars(per_day)
    ctx["bars_total"] = sum(b["count"] for b in ctx["bars"])
    people = Profile.objects.filter(user__is_superuser=False)
    total = people.count() or 1
    approved, pending = people.filter(status=Profile.APPROVED).count(), people.filter(status=Profile.PENDING).count()
    ctx["donut"] = {"a": round(approved / total * 100, 1), "b": round(pending / total * 100, 1), "total": people.count(),
                    "approved": approved, "pending": pending, "rejected": people.filter(status=Profile.REJECTED).count()}
    ctx["mfa_users"] = Profile.objects.filter(mfa_enabled=True).count()
    return render(request, "panel/overview.html", ctx)


@admin_required
def approvals(request):
    people = _people()
    return render(request, "panel/approvals.html", {
        "pending": people.filter(profile__status=Profile.PENDING).order_by("-date_joined"),
        "decided": people.exclude(profile__status=Profile.PENDING).order_by("username"),
    })


@admin_required
@require_POST
def set_status(request, pk):
    user = get_object_or_404(User, pk=pk, is_superuser=False)
    status = request.POST.get("status")
    if status not in (Profile.APPROVED, Profile.REJECTED):
        messages.error(request, "Unknown status.")
    else:
        Profile.objects.update_or_create(user=user, defaults={"status": status, "decided_at": timezone.now(), "decided_by": request.user})
        messages.success(request, f"{user.username} {status}.")
    nxt = request.POST.get("next", "")
    return redirect(nxt if nxt.startswith("/panel/") else "panel:approvals")


@admin_required
@require_POST
def reset_mfa(request, pk):
    """For a user who lost their device and recovery codes. They sign in with the password and set MFA up again."""
    user = get_object_or_404(User, pk=pk, is_superuser=False)
    if hasattr(user, "profile"):
        user.profile.clear_mfa()
        user.profile.save()
    messages.success(request, f"MFA reset for {user.username}.")
    return redirect("panel:user", pk=user.pk)


@admin_required
def users(request):
    q = request.GET.get("q", "").strip()
    qs = _people().annotate(n_sites=Count("websites", distinct=True), n_prompts=Count("ai_prompts", distinct=True)).order_by("username")
    if q:
        qs = qs.filter(Q(username__icontains=q) | Q(email__icontains=q) | Q(profile__organization__icontains=q))
    rows = [(u, Scan.objects.filter(website__owner=u).count()) for u in qs]
    return render(request, "panel/users.html", {"rows": rows, "q": q})


@admin_required
def user_detail(request, pk):
    person = get_object_or_404(_people(), pk=pk)
    sites = []
    for site in person.websites.all():
        scans = list(site.scans.order_by("number"))
        if scans:
            sites.append({"site": site, "latest": scans[-1], "count": len(scans), "spark": sparkline([s.score for s in scans])})
    return render(request, "panel/user_detail.html", {
        "person": person, "sites": sites,
        "scans": Scan.objects.filter(website__owner=person).select_related("website")[:30],
        "prompts": AIPrompt.objects.filter(user=person),
    })


@admin_required
def prompts(request):
    q = request.GET.get("q", "").strip()
    qs = AIPrompt.objects.select_related("user")
    if q:
        qs = qs.filter(Q(finding_title__icontains=q) | Q(site__icontains=q) | Q(user__username__icontains=q))
    return render(request, "panel/prompts.html", {"prompts": qs[:200], "q": q})


@admin_required
def links(request):
    q = request.GET.get("q", "").strip()
    qs = Website.objects.select_related("owner")
    if q:
        qs = qs.filter(Q(url__icontains=q) | Q(owner__username__icontains=q))
    rows = []
    for site in qs:
        latest = site.scans.order_by("-number").first()
        if latest:
            c = latest.counts()
            rows.append({"site": site, "latest": latest, "count": site.scans.count(), "open": c["new"] + c["recurring"] + c["unchanged"]})
    return render(request, "panel/links.html", {"rows": rows, "q": q})


def _short(value, n=70):
    s = "" if value is None else str(value)
    return s if len(s) <= n else s[:n] + "…"


@admin_required
def database(request):
    """Read-only view of every table. Password hashes and secrets are masked."""
    def users_rows():
        return [[u.id, u.username, u.email, u.is_superuser, u.is_active, f"{u.date_joined:%d %b %Y %H:%M}", _short(u.password, 18)] for u in User.objects.all()]
    tables = {
        "users": (["id", "username", "email", "is_superuser", "is_active", "date_joined", "password_hash"], users_rows),
        "profiles": (["id", "user", "organization", "status", "mfa_enabled", "decided_at"],
                     lambda: [[p.id, p.user.username, p.organization, p.status, p.mfa_enabled, p.decided_at or ""] for p in Profile.objects.select_related("user")]),
        "websites": (["id", "owner", "url", "created_at"],
                     lambda: [[w.id, w.owner.username, w.url, f"{w.created_at:%d %b %Y %H:%M}"] for w in Website.objects.select_related("owner")]),
        "scans": (["id", "website", "number", "score", "mode", "created_at"],
                  lambda: [[s.id, s.website.url, s.number, s.score, s.mode, f"{s.created_at:%d %b %Y %H:%M}"] for s in Scan.objects.select_related("website")]),
        "findings": (["id", "scan_id", "check_id", "failed", "status", "evidence"],
                     lambda: [[f.id, f.scan_id, f.check_id, f.failed, f.status, _short(f.evidence.replace("\n", " | "))] for f in Finding.objects.all()[:500]]),
        "ai_prompts": (["id", "user", "site", "finding", "source", "created_at", "prompt"],
                       lambda: [[p.id, p.user.username, p.site, p.finding_title, p.source, f"{p.created_at:%d %b %Y %H:%M}", _short(p.prompt.replace("\n", " "))] for p in AIPrompt.objects.select_related("user")]),
        "app_settings": (["key", "is_secret", "value", "updated_at"],
                         lambda: [[s.key, s.is_secret, "(encrypted)" if s.is_secret else _short(s.value), f"{s.updated_at:%d %b %Y %H:%M}"] for s in AppSetting.objects.all()]),
    }
    current = request.GET.get("table", "users")
    if current not in tables:
        current = "users"
    cols, loader = tables[current]
    rows = loader()
    from django.conf import settings
    return render(request, "panel/database.html", {
        "table_names": [(name, len(load())) for name, (_, load) in tables.items()],
        "current": current, "cols": cols, "rows": rows[:200], "db_path": settings.DATABASES["default"]["NAME"],
    })


@admin_required
def ai_settings(request):
    if request.method == "POST":
        action = request.POST.get("action", "save")
        if action == "clear":
            AppSetting.put(GEMINI_API_KEY, "", secret=True, user=request.user)
            messages.success(request, "API key removed. Users now get sample explanations.")
        elif action == "test":
            key = AppSetting.get(GEMINI_API_KEY)
            if not key:
                messages.error(request, "Save an API key first.")
            else:
                try:
                    ai._call_gemini("Reply with the single word OK.", key, AppSetting.get(GEMINI_MODEL, DEFAULT_GEMINI_MODEL))
                    messages.success(request, "The key works. Gemini answered.")
                except requests.RequestException as exc:
                    code = getattr(getattr(exc, "response", None), "status_code", "no response")
                    messages.error(request, f"Gemini rejected the request ({code}). Check the key and model.")
                except (KeyError, IndexError, ValueError):
                    messages.error(request, "Gemini answered with an unexpected format.")
        else:
            model = request.POST.get("model", DEFAULT_GEMINI_MODEL)
            if model not in GEMINI_MODELS:
                model = DEFAULT_GEMINI_MODEL
            AppSetting.put(GEMINI_MODEL, model, user=request.user)
            key = request.POST.get("api_key", "").strip()
            if key:
                AppSetting.put(GEMINI_API_KEY, key, secret=True, user=request.user)
                messages.success(request, "API key saved in the database (encrypted).")
            else:
                messages.success(request, "Model saved. The existing API key was kept.")
        return redirect("panel:settings")
    key = AppSetting.get(GEMINI_API_KEY)
    return render(request, "panel/settings.html", {
        "has_key": bool(key), "key_hint": f"{key[:4]}{'•' * 8}{key[-4:]}" if len(key) > 8 else "",
        "model": AppSetting.get(GEMINI_MODEL, DEFAULT_GEMINI_MODEL), "models": GEMINI_MODELS,
        "updated": AppSetting.objects.filter(key=GEMINI_API_KEY).first(),
    })
