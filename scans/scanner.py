"""Real, repeatable website configuration checks (headers, cookies, redirects, CORS, TLS)."""
import re
import socket
import ssl
from urllib.parse import urlparse

import requests
from django.conf import settings

from .checks import CHECKS, CheckResult
from .security import UnsafeTarget, pinned_target, safe_request

SESSION_NAME = re.compile(r"(sess|sid|auth|token|jwt|login)", re.I)
VERSIONED = re.compile(r"\d+\.\d+")


def _hdr(resp, name: str) -> str:
    return resp.headers.get(name, "")


def _fail(check_id, evidence):
    return CheckResult(check_id, True, evidence)


def _pass(check_id, evidence="Present and valid."):
    return CheckResult(check_id, False, evidence)


def _skip(check_id, why):
    return CheckResult(check_id, False, f"Not tested: {why}", tested=False)


def _check_hsts(resp, https):
    v = _hdr(resp, "Strict-Transport-Security")
    if not https:
        return _fail("hsts", "The site is served over plain HTTP, so HSTS cannot apply.")
    m = re.search(r"max-age=(\d+)", v, re.I)
    if not v or not m:
        return _fail("hsts", f"Strict-Transport-Security: (not present)\nHTTP {resp.status_code} on {resp.url}")
    if int(m.group(1)) < 15552000:
        return _fail("hsts", f"Strict-Transport-Security: {v}\nmax-age is below 180 days (15552000).")
    return _pass("hsts", f"Strict-Transport-Security: {v}")


def _check_csp(resp):
    v = _hdr(resp, "Content-Security-Policy")
    if v:
        return _pass("csp", f"Content-Security-Policy: {v[:200]}")
    ro = _hdr(resp, "Content-Security-Policy-Report-Only")
    note = "\nOnly a Report-Only policy is set, which does not block anything." if ro else ""
    return _fail("csp", "Content-Security-Policy: (not present)" + note)


def _check_xfo(resp):
    xfo, csp = _hdr(resp, "X-Frame-Options"), _hdr(resp, "Content-Security-Policy")
    if xfo or "frame-ancestors" in csp.lower():
        return _pass("xfo", f"X-Frame-Options: {xfo or '(none)'}  CSP frame-ancestors: {'set' if 'frame-ancestors' in csp.lower() else '(none)'}")
    return _fail("xfo", "X-Frame-Options: (not present)\nCSP frame-ancestors: (not present)")


def _check_simple(resp, check_id, header, ok_check=None):
    v = _hdr(resp, header)
    if v and (ok_check is None or ok_check(v)):
        return _pass(check_id, f"{header}: {v}")
    return _fail(check_id, f"{header}: {v or '(not present)'}")


def _check_cookies(resp):
    raw = []
    try:
        raw = resp.raw.headers.getlist("Set-Cookie")
    except AttributeError:
        v = resp.headers.get("Set-Cookie")
        raw = [v] if v else []
    if not raw:
        return _pass("cookie", "No cookies were set on the home page.")
    problems, lines = [], []
    for c in raw:
        name = c.split("=", 1)[0].strip()
        flags = c.lower()
        missing = []
        if "secure" not in flags:
            missing.append("Secure")
        if SESSION_NAME.search(name) and "httponly" not in flags:
            missing.append("HttpOnly")
        lines.append(f"Set-Cookie: {name}=…" + (f"  (missing: {', '.join(missing)})" if missing else "  (ok)"))
        if missing:
            problems.append(name)
    return _fail("cookie", "\n".join(lines)) if problems else _pass("cookie", "\n".join(lines))


def _check_redirect(url):
    parts = urlparse(url)
    if parts.scheme == "http":
        return _fail("redir", f"{url} is served over plain HTTP and was not upgraded to HTTPS.")
    probe = f"http://{parts.hostname}/"
    try:
        r = safe_request(probe, follow=False)
    except (requests.RequestException, UnsafeTarget):
        return _pass("redir", "Port 80 did not answer, so plain HTTP is not served.")
    loc = r.headers.get("Location", "")
    r.close()
    if r.is_redirect and loc.lower().startswith("https://"):
        return _pass("redir", f"GET {probe} -> {r.status_code} {loc}")
    return _fail("redir", f"GET {probe} -> {r.status_code}\nExpected a 301 redirect to https://{parts.hostname}/")


def _check_server(resp):
    server, powered = _hdr(resp, "Server"), _hdr(resp, "X-Powered-By")
    if powered or (server and VERSIONED.search(server)):
        return _fail("server", f"Server: {server or '(none)'}\nX-Powered-By: {powered or '(none)'}")
    return _pass("server", f"Server: {server or '(not shown)'}")


def _check_cors(url):
    probe_origin = "https://deployguard-probe.example"
    try:
        r = safe_request(url, headers={"Origin": probe_origin})
    except (requests.RequestException, UnsafeTarget):
        return _skip("cors", "the CORS probe request failed")
    acao, acac = r.headers.get("Access-Control-Allow-Origin", ""), r.headers.get("Access-Control-Allow-Credentials", "")
    r.close()
    if acao == "*" or acao == probe_origin:
        return _fail("cors", f"Access-Control-Allow-Origin: {acao}\nAccess-Control-Allow-Credentials: {acac or '(none)'}\nAn unknown origin was accepted.")
    return _pass("cors", f"Access-Control-Allow-Origin: {acao or '(not set)'}")


def _check_tls(url):
    parts = urlparse(url)
    if parts.scheme != "https":
        return _skip("tls", "the site is not served over HTTPS")
    try:
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        ctx.minimum_version = ssl.TLSVersion.TLSv1
        ctx.maximum_version = ssl.TLSVersion.TLSv1_1
        ctx.set_ciphers("DEFAULT:@SECLEVEL=0")
    except (ssl.SSLError, ValueError, AttributeError):
        return _skip("tls", "this server's TLS library cannot offer TLS 1.0 or 1.1")
    try:
        with pinned_target(url), socket.create_connection((parts.hostname, parts.port or 443), timeout=settings.SCAN_TIMEOUT_SECONDS) as raw:
            with ctx.wrap_socket(raw, server_hostname=parts.hostname) as tls:
                return _fail("tls", f"Handshake {tls.version()} -> accepted")
    except UnsafeTarget:
        return _skip("tls", "the address is not allowed to be scanned")
    except ssl.SSLError:
        return _pass("tls", "TLS 1.0 and 1.1 handshakes were rejected.")
    except OSError:
        return _skip("tls", "the connection to port 443 failed")


def run_checks(url: str) -> list[CheckResult]:
    """Fetch the site once and evaluate every check. Raises UnsafeTarget or requests exceptions if unreachable."""
    resp = safe_request(url)
    https = urlparse(resp.url).scheme == "https"
    try:
        results = {
            "hsts": _check_hsts(resp, https),
            "csp": _check_csp(resp),
            "xfo": _check_xfo(resp),
            "xcto": _check_simple(resp, "xcto", "X-Content-Type-Options", lambda v: v.lower() == "nosniff"),
            "ref": _check_simple(resp, "ref", "Referrer-Policy"),
            "perm": _check_simple(resp, "perm", "Permissions-Policy"),
            "cookie": _check_cookies(resp),
            "server": _check_server(resp),
        }
    finally:
        resp.close()
    results["redir"] = _check_redirect(url if urlparse(resp.url).scheme == "https" else resp.url)
    results["cors"] = _check_cors(url)
    results["tls"] = _check_tls(resp.url)
    return [results[c.id] for c in CHECKS]
