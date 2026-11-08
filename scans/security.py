"""SSRF-safe HTTP client. A scanner that fetches user-supplied URLs must never reach internal systems."""
import ipaddress
import socket
from urllib.parse import urljoin, urlparse

import requests
from django.conf import settings

USER_AGENT = "DeployGuardBot/1.0 (+security configuration check; contact the site owner)"
ALLOWED_PORTS = {None, 80, 443}


class UnsafeTarget(Exception):
    """Raised when a URL must not be fetched. The message is safe to show to the user."""


def normalize_url(raw: str) -> str:
    raw = (raw or "").strip()
    if not raw:
        raise UnsafeTarget("Enter a website address.")
    if "://" not in raw:
        raw = "https://" + raw
    parts = urlparse(raw)
    if parts.scheme not in ("http", "https"):
        raise UnsafeTarget("Only http:// and https:// addresses can be scanned.")
    if not parts.hostname or "." not in parts.hostname and parts.hostname != "localhost":
        raise UnsafeTarget("Enter a full website address, for example https://example.com.")
    if parts.username or parts.password:
        raise UnsafeTarget("Remove the username and password from the address.")
    return f"{parts.scheme}://{parts.netloc.lower()}"


def validate_target(url: str) -> None:
    parts = urlparse(url)
    if parts.scheme not in ("http", "https") or not parts.hostname:
        raise UnsafeTarget("Only http:// and https:// addresses can be scanned.")
    if not settings.ALLOW_PRIVATE_TARGETS and parts.port not in ALLOWED_PORTS:
        raise UnsafeTarget("Only the standard web ports (80 and 443) can be scanned.")
    try:
        infos = socket.getaddrinfo(parts.hostname, parts.port or (443 if parts.scheme == "https" else 80), type=socket.SOCK_STREAM)
    except socket.gaierror:
        raise UnsafeTarget("That address could not be found. Check the spelling.")
    for info in infos:
        ip = ipaddress.ip_address(info[4][0])
        if not settings.ALLOW_PRIVATE_TARGETS and not ip.is_global:
            raise UnsafeTarget("That address points to a private or internal network and cannot be scanned.")


def safe_request(url: str, *, headers: dict | None = None, follow: bool = True, max_redirects: int = 3) -> requests.Response:
    """GET a URL, validating every redirect hop. Returns the final response (body not read)."""
    hdrs = {"User-Agent": USER_AGENT, "Accept": "text/html,*/*;q=0.5"}
    hdrs.update(headers or {})
    current = url
    for _ in range(max_redirects + 1):
        validate_target(current)
        resp = requests.get(current, headers=hdrs, allow_redirects=False, timeout=settings.SCAN_TIMEOUT_SECONDS, stream=True)
        if follow and resp.is_redirect and resp.headers.get("Location"):
            current = urljoin(current, resp.headers["Location"])
            resp.close()
            continue
        return resp
    raise UnsafeTarget("The site redirected too many times.")
