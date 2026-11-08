"""Catalogue of deterministic security checks. The scanner measures; AI never decides findings."""
from dataclasses import dataclass


@dataclass(frozen=True)
class Check:
    id: str
    title: str
    severity: str  # critical | high | medium | low
    weight: int    # points removed from the 100-point score when the check fails
    impact: str


SEVERITY_ORDER = ["critical", "high", "medium", "low"]

CHECKS = [
    Check("hsts", "HSTS header missing", "high", 12,
          "Browsers can be tricked into using plain HTTP, which lets a network attacker strip TLS on the first visit."),
    Check("csp", "No Content-Security-Policy", "high", 12,
          "Without a CSP, any injected script runs with full page privileges, which makes cross-site scripting far more damaging."),
    Check("xfo", "Clickjacking protection missing", "medium", 7,
          "Another site can embed your pages in a hidden frame and trick users into clicking buttons they cannot see."),
    Check("xcto", "MIME sniffing not disabled", "low", 3,
          "Browsers may treat an uploaded file as a script, which can turn a harmless upload into code execution in the browser."),
    Check("ref", "Referrer-Policy not set", "low", 3,
          "Full page URLs, including tokens in query strings, can leak to third-party sites through the Referer header."),
    Check("perm", "Permissions-Policy not set", "low", 3,
          "Embedded content may request camera, microphone or location access that your site never needs."),
    Check("cookie", "Session cookie lacks Secure or HttpOnly", "critical", 18,
          "A script injected into the page can read the session cookie, and the cookie can travel over plain HTTP. Either lets an attacker take over a logged-in account."),
    Check("redir", "HTTP does not redirect to HTTPS", "high", 12,
          "Visitors who type the bare domain stay on an unencrypted connection, exposing logins and cookies on shared networks."),
    Check("server", "Server version disclosed", "low", 3,
          "Exact versions tell attackers which published vulnerabilities to try first."),
    Check("cors", "CORS allows any origin", "medium", 7,
          "Any website can call your API from a visitor's browser. Combined with credentials this can expose private data."),
    Check("tls", "Legacy TLS 1.0 / 1.1 accepted", "medium", 7,
          "Old protocol versions have known weaknesses and fail modern compliance checks."),
]
CHECK_BY_ID = {c.id: c for c in CHECKS}


@dataclass
class CheckResult:
    id: str
    failed: bool
    evidence: str
    tested: bool = True
