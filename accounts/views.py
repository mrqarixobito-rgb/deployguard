import time
from urllib.parse import quote

from django.conf import settings
from django.contrib import messages
from django.contrib.auth import authenticate, get_user_model, login, logout
from django.contrib.auth.decorators import login_required
from django.core.cache import cache
from django.db import transaction
from django.shortcuts import redirect, render
from django.utils import timezone
from django.views.decorators.http import require_POST

from . import mfa
from .forms import RegisterForm
from .models import Profile

User = get_user_model()
MAX_FAILS, LOCK_SECONDS = 5, 15 * 60
MFA_LOGIN_WINDOW = 5 * 60  # seconds the user has to enter the code after the password step
BACKEND = "django.contrib.auth.backends.ModelBackend"


def _client_ip(request) -> str:
    return request.META.get("REMOTE_ADDR", "unknown")


def _home_for(user):
    return redirect("panel:overview" if user.is_superuser else "scans:dashboard")


def whatsapp_link(username: str) -> str:
    """wa.me link that opens the admin's WhatsApp chat with a ready message. Empty if no number is configured."""
    if not settings.ADMIN_WHATSAPP or not username:
        return ""
    text = f"Need approval for DeployGuard AI.\nUsername: {username}"
    return f"https://wa.me/{settings.ADMIN_WHATSAPP}?text={quote(text)}"


def mfa_required_for(user) -> bool:
    return settings.REQUIRE_ADMIN_MFA if user.is_superuser else settings.REQUIRE_USER_MFA


def login_view(request):
    if request.user.is_authenticated:
        return _home_for(request.user)
    error = ""
    if request.method == "POST":
        username = request.POST.get("username", "").strip()
        password = request.POST.get("password", "")
        lock_key = f"loginfail:{_client_ip(request)}:{username.lower()}"
        if cache.get(lock_key, 0) >= MAX_FAILS:
            error = "Too many failed attempts. Try again in 15 minutes."
        else:
            user = authenticate(request, username=username, password=password)
            if user is None:
                cache.set(lock_key, cache.get(lock_key, 0) + 1, LOCK_SECONDS)
                error = "Incorrect username or password."
            else:
                profile = getattr(user, "profile", None)
                status = profile.status if profile else Profile.APPROVED
                if not user.is_superuser and status == Profile.PENDING:
                    error = "Your account is waiting for admin approval."
                    request.session["wa_username"] = user.username
                elif not user.is_superuser and status == Profile.REJECTED:
                    error = "This account request was declined. Contact the administrator."
                else:
                    cache.delete(lock_key)
                    if profile and profile.mfa_enabled:
                        # Password is correct, but the user is not signed in until the second factor passes.
                        request.session["mfa_user"] = user.pk
                        request.session["mfa_at"] = time.time()
                        return redirect("accounts:mfa_verify")
                    login(request, user)
                    return _home_for(user)
    return render(request, "accounts/login.html", {"error": error, "wa_link": whatsapp_link(request.session.get("wa_username", ""))})


def mfa_verify(request):
    """Second step of sign-in: authenticator code or one-time recovery code."""
    uid, started = request.session.get("mfa_user"), request.session.get("mfa_at", 0)
    user = User.objects.filter(pk=uid).select_related("profile").first() if uid else None
    if user is None or time.time() - started > MFA_LOGIN_WINDOW:
        for k in ("mfa_user", "mfa_at"):
            request.session.pop(k, None)
        messages.error(request, "Your sign-in timed out. Enter your username and password again.")
        return redirect("accounts:login")
    profile, error = user.profile, ""
    if request.method == "POST":
        lock_key = f"mfafail:{user.pk}"
        code = request.POST.get("code", "")
        if cache.get(lock_key, 0) >= MAX_FAILS:
            error = "Too many wrong codes. Try again in 15 minutes."
        else:
            step = mfa.verify(profile.secret, code, profile.totp_last_step)
            used_recovery = False
            if step:
                profile.totp_last_step = step
                profile.save(update_fields=["totp_last_step"])
            else:
                used_recovery = mfa.use_recovery_code(profile, code)
            if step or used_recovery:
                cache.delete(lock_key)
                for k in ("mfa_user", "mfa_at"):
                    request.session.pop(k, None)
                login(request, user, backend=BACKEND)
                if used_recovery:
                    messages.warning(request, f"You used a recovery code. {len(profile.recovery_hashes)} left. Generate new ones in Security.")
                return _home_for(user)
            cache.set(lock_key, cache.get(lock_key, 0) + 1, LOCK_SECONDS)
            error = "That code is not valid. Check the code in your authenticator app and try again."
    return render(request, "accounts/mfa_verify.html", {"error": error, "username": user.username})


def register_view(request):
    if request.user.is_authenticated:
        return _home_for(request.user)
    form = RegisterForm(request.POST or None)
    if request.method == "POST" and form.is_valid():
        d = form.cleaned_data
        with transaction.atomic():
            user = User.objects.create_user(username=d["username"], email=d["email"], password=d["password"])
            Profile.objects.create(user=user, organization=d["organization"], status=Profile.PENDING)
        request.session["wa_username"] = user.username
        messages.success(request, "Request sent. Message the admin on WhatsApp to get approved, then sign in.")
        return redirect("accounts:login")
    return render(request, "accounts/register.html", {"form": form})


@require_POST
def logout_view(request):
    logout(request)
    return redirect("accounts:login")


def _code_ok(request, profile, code: str) -> bool:
    """Check an authenticator or recovery code for a sensitive action. Shares the lockout with sign-in."""
    lock_key = f"mfafail:{request.user.pk}"
    if cache.get(lock_key, 0) >= MAX_FAILS:
        messages.error(request, "Too many wrong codes. Try again in 15 minutes.")
        return False
    step = mfa.verify(profile.secret, code, profile.totp_last_step)
    if step:
        profile.totp_last_step = step
        profile.save(update_fields=["totp_last_step"])
        return True
    if mfa.use_recovery_code(profile, code):
        return True
    cache.set(lock_key, cache.get(lock_key, 0) + 1, LOCK_SECONDS)
    messages.error(request, "That code is not valid.")
    return False


@login_required
def security(request):
    profile, _ = Profile.objects.get_or_create(user=request.user, defaults={"status": Profile.APPROVED})
    required = mfa_required_for(request.user)
    if request.method == "POST":
        action = request.POST.get("action")
        if action == "start" and not profile.mfa_enabled:
            request.session["mfa_setup_secret"] = mfa.new_secret()
        elif action == "cancel":
            request.session.pop("mfa_setup_secret", None)
        elif action == "confirm" and not profile.mfa_enabled:
            secret = request.session.get("mfa_setup_secret", "")
            step = mfa.verify(secret, request.POST.get("code", ""), 0)
            if not step:
                messages.error(request, "That code did not match. Check the 6 digits in your app and try again.")
            else:
                shown, hashes = mfa.new_recovery_codes()
                profile.set_secret(secret)
                profile.mfa_enabled, profile.totp_last_step, profile.recovery_hashes = True, step, hashes
                profile.mfa_enabled_at = timezone.now()
                profile.save()
                request.session.pop("mfa_setup_secret", None)
                request.session["mfa_new_codes"] = shown
                messages.success(request, "Multi-factor authentication is on. Save your recovery codes now.")
        elif action == "regenerate" and profile.mfa_enabled:
            if _code_ok(request, profile, request.POST.get("code", "")):
                shown, hashes = mfa.new_recovery_codes()
                profile.recovery_hashes = hashes
                profile.save(update_fields=["recovery_hashes"])
                request.session["mfa_new_codes"] = shown
                messages.success(request, "New recovery codes created. The old ones no longer work.")
        elif action == "disable" and profile.mfa_enabled:
            if required:
                messages.error(request, "This account must keep multi-factor authentication on.")
            elif not request.user.check_password(request.POST.get("password", "")):
                messages.error(request, "Incorrect password.")
            elif _code_ok(request, profile, request.POST.get("code", "")):
                profile.clear_mfa()
                profile.save()
                messages.success(request, "Multi-factor authentication is off.")
        return redirect("accounts:security")

    secret = request.session.get("mfa_setup_secret") if not profile.mfa_enabled else None
    ctx = {
        "profile": profile, "required": required, "new_codes": request.session.pop("mfa_new_codes", None),
        "remaining": len(profile.recovery_hashes),
    }
    if secret:
        ctx.update(setup=True, qr=mfa.qr_svg(mfa.provisioning_uri(secret, request.user.username)), secret_text=mfa.format_secret(secret))
    return render(request, "accounts/security.html", ctx)
