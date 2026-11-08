from django.shortcuts import render

from scans.checks import CHECKS


def home(request):
    """Public landing page. The logo on every page links here."""
    return render(request, "home.html", {"checks": CHECKS})
