"""Time-based one-time passwords (RFC 6238) and recovery codes, using only the standard library plus segno for the QR image."""
import base64
import hashlib
import hmac
import secrets
import struct
import time
from urllib.parse import quote

import segno
from django.conf import settings

STEP_SECONDS = 30
DIGITS = 6
RECOVERY_ALPHABET = "ABCDEFGHJKLMNPQRSTUVWXYZ23456789"  # no 0/O/1/I to avoid typing mistakes
RECOVERY_COUNT = 8


def new_secret() -> str:
    return base64.b32encode(secrets.token_bytes(20)).decode("ascii").rstrip("=")


def _code_for(secret: str, counter: int) -> str:
    key = base64.b32decode(secret + "=" * (-len(secret) % 8))
    digest = hmac.new(key, struct.pack(">Q", counter), hashlib.sha1).digest()
    offset = digest[-1] & 0x0F
    number = (struct.unpack(">I", digest[offset:offset + 4])[0] & 0x7FFFFFFF) % (10 ** DIGITS)
    return f"{number:0{DIGITS}d}"


def verify(secret: str, code: str, last_step: int = 0, now: float | None = None, window: int = 1) -> int | None:
    """Return the matching time step, or None. Accepts one step either side for clock drift.
    Steps at or below last_step are rejected, so a code cannot be used twice."""
    code = (code or "").strip().replace(" ", "")
    if not (code.isdigit() and len(code) == DIGITS) or not secret:
        return None
    current = int((now if now is not None else time.time()) // STEP_SECONDS)
    for step in range(current - window, current + window + 1):
        if step > last_step and hmac.compare_digest(_code_for(secret, step), code):
            return step
    return None


def provisioning_uri(secret: str, username: str) -> str:
    issuer = settings.SITE_NAME
    return (f"otpauth://totp/{quote(issuer)}:{quote(username)}?secret={secret}"
            f"&issuer={quote(issuer)}&algorithm=SHA1&digits={DIGITS}&period={STEP_SECONDS}")


def qr_svg(uri: str) -> str:
    """Inline SVG of the QR code (generated on the server, so the secret never goes to a third party)."""
    return segno.make(uri, error="m").svg_inline(scale=5, border=2, dark="#0a0f1e", light="#ffffff", omitsize=True)


def format_secret(secret: str) -> str:
    return " ".join(secret[i:i + 4] for i in range(0, len(secret), 4))


def _hash_code(code: str) -> str:
    norm = code.strip().upper().replace("-", "").replace(" ", "")
    return hashlib.sha256(f"{settings.SECRET_KEY}:{norm}".encode()).hexdigest()


def new_recovery_codes() -> tuple[list[str], list[str]]:
    """Return (codes to show the user once, hashes to store)."""
    codes = ["".join(secrets.choice(RECOVERY_ALPHABET) for _ in range(10)) for _ in range(RECOVERY_COUNT)]
    shown = [f"{c[:5]}-{c[5:]}" for c in codes]
    return shown, [_hash_code(c) for c in codes]


def use_recovery_code(profile, code: str) -> bool:
    """Consume a recovery code if it matches. Each code works once."""
    digest = _hash_code(code)
    for stored in list(profile.recovery_hashes):
        if hmac.compare_digest(stored, digest):
            profile.recovery_hashes.remove(stored)
            profile.save(update_fields=["recovery_hashes"])
            return True
    return False
