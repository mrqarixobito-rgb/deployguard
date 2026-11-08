"""Comparison logic: classify each finding against the previous scan and the site's history."""
from django.db import transaction

from .checks import CHECK_BY_ID, CheckResult
from .models import Finding, Scan


def classify(failed_now: bool, failed_prev: bool | None, failed_ever_before: bool) -> str:
    """Status of one check.

    failed_prev is None for the first scan of a website.
      - fails now, passed (or first scan), never failed before  -> new
      - fails now, passed last time, but failed in an older scan -> recurring (came back)
      - fails now and failed last time                          -> unchanged
      - passes now, failed last time                            -> resolved
      - passes now and last time                                -> passed
    """
    if failed_now:
        if failed_prev:
            return Finding.UNCHANGED
        return Finding.RECURRING if failed_ever_before else Finding.NEW
    return Finding.RESOLVED if failed_prev else Finding.PASSED


def score_for(results: list[CheckResult]) -> int:
    lost = sum(CHECK_BY_ID[r.id].weight for r in results if r.failed)
    return max(0, 100 - lost)


@transaction.atomic
def record_scan(website, results: list[CheckResult], mode: str = "live") -> Scan:
    prev = website.scans.order_by("-number").first()
    prev_failed = set(prev.findings.filter(failed=True).values_list("check_id", flat=True)) if prev else set()
    ever_failed = set(Finding.objects.filter(scan__website=website, failed=True).values_list("check_id", flat=True))
    scan = Scan.objects.create(website=website, number=(prev.number + 1 if prev else 1), score=score_for(results), mode=mode)
    Finding.objects.bulk_create([
        Finding(
            scan=scan, check_id=r.id, failed=r.failed, evidence=r.evidence,
            status=classify(r.failed, (r.id in prev_failed) if prev else None, r.id in ever_failed),
        )
        for r in results
    ])
    return scan
