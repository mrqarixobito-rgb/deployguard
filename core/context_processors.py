from django.conf import settings


def site(request):
    ctx = {"SITE_NAME": settings.SITE_NAME, "DEBUG": settings.DEBUG}
    user = getattr(request, "user", None)
    if user is not None and user.is_authenticated and user.is_superuser:
        from accounts.models import Profile
        ctx["pending_count"] = Profile.objects.filter(status=Profile.PENDING).count()
    return ctx
