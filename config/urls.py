from django.conf import settings
from django.contrib import admin
from django.shortcuts import redirect
from django.urls import include, path
from core import views as core_views

# Django admin must not offer its own password-only login: that would skip the MFA step.
admin.site.login = lambda request, extra_context=None: redirect(settings.LOGIN_URL)

urlpatterns = [
    path("", core_views.home, name="home"),
    path("django-admin/", admin.site.urls),  # Django's built-in database admin (superuser only)
    path("", include("accounts.urls")),
    path("panel/", include("panel.urls")),
    path("", include("scans.urls")),
]
