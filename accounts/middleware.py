from django.conf import settings
from django.contrib import messages
from django.shortcuts import redirect
from django.urls import reverse


class RequireMFASetupMiddleware:
    """Signed-in users whose role requires MFA can only reach the security page (and log out) until it is on."""

    def __init__(self, get_response):
        self.get_response = get_response

    def __call__(self, request):
        user = request.user
        if user.is_authenticated:
            required = settings.REQUIRE_ADMIN_MFA if user.is_superuser else settings.REQUIRE_USER_MFA
            profile = getattr(user, "profile", None)
            if required and not (profile and profile.mfa_enabled):
                allowed = (reverse("accounts:security"), reverse("accounts:logout"))
                if request.path not in allowed and not request.path.startswith(settings.STATIC_URL if settings.STATIC_URL.startswith("/") else "/" + settings.STATIC_URL):
                    messages.warning(request, "Turn on multi-factor authentication to continue.")
                    return redirect("accounts:security")
        return self.get_response(request)
