"""SSRF-safe HTTP client. A scanner that fetches user-supplied URLs must never reach internal systems."""
import contextlib
import ipaddress
import socket
import threading
from urllib.parse import urljoin, urlparse

import requests
from django.conf import settings

USER_AGENT = "DeployGuardBot/1.0 (+security configuration check; contact the site owner)"
ALLOWED_PORTS = {None, 80, 443}


# --- DNS pinning -------------------------------------------------------------------------------
# validate_target() resolves a hostname and checks the IPs. If the HTTP client then resolved the name
# again, an attacker's DNS server could answer with a public IP the first time and 127.0.0.1 the
# second ("DNS rebinding"). So while a request runs, the checked IPs are pinned for that hostname in
# this thread: every lookup of it returns only those IPs. TLS and the Host header still use the name.
_real_getaddrinfo = socket.getaddrinfo
_pins = threading.local()


def _pinned_getaddrinfo(host, port, family=0, type=0, proto=0, flags=0):
    ips = getattr(_pins, "map", {}).get(str(host).lower()) if isinstance(host, str) else None
    if not ips:
        return _real_getaddrinfo(host, port, family, type, proto, flags)
    out = []
    for ip in ips:
        out.extend(_real_getaddrinfo(ip, port, family, type, proto, flags))
    return out


socket.getaddrinfo = _pinned_getaddrinfo


@contextlib.contextmanager
def pinned(hostname: str, ips: list[str]):
    mapping = getattr(_pins, "map", None)
    if mapping is None:
        mapping = _pins.map = {}
    key, previous = hostname.lower(), mapping.get(hostname.lower())
    mapping[key] = list(ips)
    try:
        yield
    finally:
        if previous is None:
            mapping.pop(key, None)
        else:
            mapping[key] = previous


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


def validate_target(url: str) -> list[str]:
    """Check the target and return the IP addresses it resolved to (all of them are public unless ALLOW_PRIVATE_TARGETS)."""
    parts = urlparse(url)
    if parts.scheme not in ("http", "https") or not parts.hostname:
        raise UnsafeTarget("Only http:// and https:// addresses can be scanned.")
    if not settings.ALLOW_PRIVATE_TARGETS and parts.port not in ALLOWED_PORTS:
        raise UnsafeTarget("Only the standard web ports (80 and 443) can be scanned.")
    try:
        infos = socket.getaddrinfo(parts.hostname, parts.port or (443 if parts.scheme == "https" else 80), type=socket.SOCK_STREAM)
    except socket.gaierror:
        raise UnsafeTarget("That address could not be found. Check the spelling.")
    ips = []
    for info in infos:
        ip = ipaddress.ip_address(info[4][0])
        if not settings.ALLOW_PRIVATE_TARGETS and not ip.is_global:
            raise UnsafeTarget("That address points to a private or internal network and cannot be scanned.")
        if str(ip) not in ips:
            ips.append(str(ip))
    return ips


@contextlib.contextmanager
def pinned_target(url: str):
    """Validate a URL and, for the duration of the block, force every lookup of its host to the validated IPs."""
    ips = validate_target(url)
    with pinned(urlparse(url).hostname, ips):
        yield


def safe_request(url: str, *, headers: dict | None = None, follow: bool = True, max_redirects: int = 3) -> requests.Response:
    """GET a URL, validating every redirect hop. Returns the final response (body not read)."""
    hdrs = {"User-Agent": USER_AGENT, "Accept": "text/html,*/*;q=0.5"}
    hdrs.update(headers or {})
    current = url
    for _ in range(max_redirects + 1):
        with pinned_target(current):
            resp = requests.get(current, headers=hdrs, allow_redirects=False, timeout=settings.SCAN_TIMEOUT_SECONDS, stream=True)
        if follow and resp.is_redirect and resp.headers.get("Location"):
            current = urljoin(current, resp.headers["Location"])
            resp.close()
            continue
        return resp
    raise UnsafeTarget("The site redirected too many times.")
