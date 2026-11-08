from functools import wraps

from django.contrib.auth.decorators import login_required
from django.core.exceptions import PermissionDenied
from django.shortcuts import redirect

from .models import Profile


def approved_required(view):
    """Signed-in, approved, non-admin users only. Admins are sent to the panel."""
    @wraps(view)
    @login_required
    def wrapper(request, *args, **kwargs):
        if request.user.is_superuser:
            return redirect("panel:overview")
        profile = getattr(request.user, "profile", None)
        if profile is None or profile.status != Profile.APPROVED:
            raise PermissionDenied
        return view(request, *args, **kwargs)
    return wrapper


def admin_required(view):
    """Superusers only. Everyone else gets 403."""
    @wraps(view)
    @login_required
    def wrapper(request, *args, **kwargs):
        if not request.user.is_superuser:
            raise PermissionDenied
        return view(request, *args, **kwargs)
    return wrapper
