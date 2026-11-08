"""AI explanations. The model only explains evidence measured by the scanner; it never decides findings.

The Gemini API key is read from the database (set by the admin in the panel), never from the browser.
"""
import logging

import requests

from core.models import DEFAULT_GEMINI_MODEL, GEMINI_API_KEY, GEMINI_MODEL, AppSetting

from .fixes import fix_for
from .models import AIPrompt

log = logging.getLogger(__name__)
API_URL = "https://generativelanguage.googleapis.com/v1beta/models/{model}:generateContent"


def build_prompt(finding) -> str:
    scan, check = finding.scan, finding.meta
    return (
        "You are a web security assistant. Explain ONLY from the scanner evidence below. Do not invent findings.\n"
        f"Site: {scan.website.url}\n"
        f"Finding: {check.title} (severity: {check.severity}, status vs previous scan: {finding.status})\n"
        f"Evidence:\n{finding.evidence}\n\n"
        "Return: 1) what it means in plain words, 2) potential impact, 3) the exact fix, 4) how to verify the fix."
    )


def sample_answer(finding) -> str:
    check, fx = finding.meta, fix_for(finding.check_id, finding.scan.website.host)
    when = {"recurring": "a repeat: it was fixed earlier and has come back after an update",
            "new": "new since the previous scan", "unchanged": "unchanged since the previous scan"}.get(finding.status, "present in this scan")
    steps = "\n".join(f"{i}. {s}" for i, s in enumerate(fx["steps"], 1))
    return (f"What it means\n{check.title}. The scan found this on the live site, and it is {when}.\n\n"
            f"Potential impact\n{check.impact}\n\nHow to fix\n{steps}\n\nVerify\n{fx['verify']}")


def _call_gemini(prompt: str, key: str, model: str) -> str:
    resp = requests.post(
        API_URL.format(model=model), timeout=30,
        headers={"x-goog-api-key": key, "Content-Type": "application/json"},
        json={"contents": [{"parts": [{"text": prompt}]}]},
    )
    resp.raise_for_status()
    parts = resp.json()["candidates"][0]["content"]["parts"]
    text = "".join(p.get("text", "") for p in parts).strip()
    if not text:
        raise ValueError("empty response")
    return text


def explain(finding, user) -> AIPrompt:
    """Return the stored explanation for a finding, creating it (and logging the prompt) if needed."""
    existing = finding.ai_prompts.filter(user=user).first()
    if existing:
        return existing
    prompt = build_prompt(finding)
    key = AppSetting.get(GEMINI_API_KEY)
    model = AppSetting.get(GEMINI_MODEL, DEFAULT_GEMINI_MODEL)
    text, source = "", "sample"
    if key:
        try:
            text, source = _call_gemini(prompt, key, model), "gemini"
        except (requests.RequestException, KeyError, IndexError, ValueError) as exc:
            log.warning("Gemini request failed: %s", exc.__class__.__name__)  # never log the key or response body
    if not text:
        text = sample_answer(finding)
    return AIPrompt.objects.create(
        user=user, scan=finding.scan, finding=finding, site=finding.scan.website.url,
        finding_title=finding.title, prompt=prompt, response=text, source=source,
    )
