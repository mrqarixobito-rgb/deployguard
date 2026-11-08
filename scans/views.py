import json

from django.conf import settings
from django.contrib import messages
from django.core.cache import cache
from django.db.models import Count
from django.http import HttpResponse, JsonResponse
from django.shortcuts import get_object_or_404, redirect, render
from django.utils import timezone
from django.views.decorators.http import require_POST
import requests

from accounts.decorators import approved_required

from . import ai
from .charts import score_chart
from .checks import CHECKS, SEVERITY_ORDER
from .compare import record_scan
from .fixes import PLATFORMS, fix_for
from .models import Finding, Scan, Website
from .pdf import build_pdf
from .scanner import run_checks
from .security import UnsafeTarget, normalize_url


def _hourly_limit(user, bucket: str, limit: int) -> bool:
    """True if the user is still under the limit. Counts requests in the last hour."""
    key = f"rate:{bucket}:{user.pk}"
    cache.add(key, 0, 3600)
    return cache.incr(key) <= limit


def sparkline(values, w=90, h=28):
    if len(values) < 2:
        return None
    pts = [(4 + i * (w - 8) / (len(values) - 1), h - 4 - (v / 100) * (h - 8)) for i, v in enumerate(values)]
    return {"points": " ".join(f"{x:.1f},{y:.1f}" for x, y in pts), "x": f"{pts[-1][0]:.1f}", "y": f"{pts[-1][1]:.1f}", "w": w, "h": h}


@approved_required
def dashboard(request):
    sites = []
    for site in request.user.websites.prefetch_related("scans").all():
        scans = list(site.scans.order_by("number"))
        if not scans:
            continue
        latest = scans[-1]
        sites.append({"site": site, "latest": latest, "count": len(scans), "counts": latest.counts(), "spark": sparkline([s.score for s in scans])})
    sites.sort(key=lambda s: s["latest"].created_at, reverse=True)
    open_findings = sum(s["counts"]["new"] + s["counts"]["recurring"] + s["counts"]["unchanged"] for s in sites)
    latest_ids = [s["latest"].pk for s in sites]
    open_list = list(Finding.objects.filter(scan_id__in=latest_ids, failed=True).select_related("scan__website"))
    sev_counts = {k: 0 for k in SEVERITY_ORDER}
    for f in open_list:
        sev_counts[f.severity] += 1
    total_open = len(open_list) or 1
    avg = round(sum(s["latest"].score for s in sites) / len(sites)) if sites else None
    posture = {
        "avg": avg, "class": "ok" if (avg or 0) >= 80 else "med" if (avg or 0) >= 55 else "crit",
        "sev": [(k, sev_counts[k], round(sev_counts[k] / total_open * 100, 1)) for k in SEVERITY_ORDER],
        "total": len(open_list),
    }
    attention = sorted(open_list, key=lambda f: (f.status != Finding.RECURRING, f.severity_rank))[:6]
    stats = {
        "sites": len(sites),
        "scans": Scan.objects.filter(website__owner=request.user).count(),
        "open": open_findings,
        "recurring": sum(s["counts"]["recurring"] for s in sites),
        "fixed": Finding.objects.filter(scan__website__owner=request.user, status=Finding.RESOLVED).count(),
    }
    return render(request, "scans/dashboard.html", {"sites": sites, "stats": stats, "posture": posture, "attention": attention})


def _run_and_record(request, site):
    if not _hourly_limit(request.user, "scan", settings.SCAN_LIMIT_PER_HOUR):
        messages.error(request, "Scan limit reached. Try again in an hour.")
        return None
    try:
        results = run_checks(site.url)
    except UnsafeTarget as exc:
        messages.error(request, str(exc))
    except requests.RequestException:
        messages.error(request, "The website did not answer. Check the address and that the site is online, then try again.")
    else:
        return record_scan(site, results)
    return None


@approved_required
@require_POST
def new_scan(request):
    if not request.POST.get("authorized"):
        messages.error(request, "Confirm that you own this website or have permission to test it.")
        return redirect("scans:dashboard")
    try:
        url = normalize_url(request.POST.get("url", ""))
    except UnsafeTarget as exc:
        messages.error(request, str(exc))
        return redirect("scans:dashboard")
    site, _ = Website.objects.get_or_create(owner=request.user, url=url)
    scan = _run_and_record(request, site)
    if scan is None:
        if not site.scans.exists():
            site.delete()
        return redirect("scans:dashboard")
    messages.success(request, "Baseline scan saved." if scan.number == 1 else "Scan finished. Changes are marked below.")
    return redirect("scans:detail", pk=scan.pk)


def _own_scan(request, pk):
    return get_object_or_404(Scan.objects.select_related("website"), pk=pk, website__owner=request.user)


@approved_required
@require_POST
def rescan(request, pk):
    scan = _own_scan(request, pk)
    new = _run_and_record(request, scan.website)
    if new is None:
        return redirect("scans:detail", pk=scan.pk)
    messages.success(request, "Re-scan finished. Old and new results are compared below.")
    return redirect("scans:detail", pk=new.pk)


@approved_required
def detail(request, pk):
    scan = _own_scan(request, pk)
    platform = request.GET.get("platform", "nginx")
    if platform not in dict(PLATFORMS):
        platform = "nginx"
    status_filter = request.GET.get("filter", "all")
    open_id = int(request.GET["open"]) if request.GET.get("open", "").isdigit() else None
    host = scan.website.host
    findings = list(scan.findings.prefetch_related("ai_prompts").all())
    by_check = {f.check_id: f for f in findings}
    counts = scan.counts()
    shown = [f for f in findings if f.status != "passed" and status_filter in ("all", f.status)]
    shown.sort(key=lambda f: (f.status == "resolved", f.severity_rank))
    for f in shown:
        f.fix = fix_for(f.check_id, host) if f.failed else None
        f.code = f.fix["code"][platform] if f.fix else ""
        f.ai = next((p for p in f.ai_prompts.all() if p.user_id == request.user.id), None)
    history = list(scan.website.scans.order_by("number"))
    failed_ever = set(Finding.objects.filter(scan__website=scan.website, failed=True).values_list("scan_id", "check_id"))
    matrix = []
    for c in CHECKS:
        if not any(cid == c.id for _, cid in failed_ever):
            continue
        cells = [(s, (s.id, c.id) in failed_ever) for s in history]
        now = by_check.get(c.id)
        matrix.append({"check": c, "cells": cells, "now": now.status if now else "passed"})
    passed_titles = [by_check[c.id].title for c in CHECKS if c.id in by_check and by_check[c.id].status == "passed"]
    prev = scan.previous()
    return render(request, "scans/scan_detail.html", {
        "scan": scan, "host": host, "counts": counts, "findings": shown, "all_count": sum(counts[k] for k in ("new", "recurring", "unchanged", "resolved")),
        "platform": platform, "platforms": PLATFORMS, "open_id": open_id, "filter": status_filter, "history": history, "matrix": matrix,
        "chart": score_chart(history), "prev": prev, "is_latest": history[-1].pk == scan.pk, "passed_titles": passed_titles, "checks_total": len(CHECKS),
    })


@approved_required
def report_pdf(request, pk):
    scan = _own_scan(request, pk)
    pdf = build_pdf(scan, request.GET.get("platform", "nginx"))
    resp = HttpResponse(pdf, content_type="application/pdf")
    resp["Content-Disposition"] = f'attachment; filename="DeployGuard-{scan.website.host}-scan{scan.number}.pdf"'
    return resp


@approved_required
@require_POST
def explain(request, pk):
    finding = get_object_or_404(Finding.objects.select_related("scan__website"), pk=pk, scan__website__owner=request.user, failed=True)
    if not finding.ai_prompts.filter(user=request.user).exists() and not _hourly_limit(request.user, "ai", settings.AI_LIMIT_PER_HOUR):
        return JsonResponse({"error": "AI explanation limit reached. Try again in an hour."}, status=429)
    prompt = ai.explain(finding, request.user)
    return JsonResponse({"text": prompt.response, "source": prompt.source})
