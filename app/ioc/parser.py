"""
Extract, validate and normalise indicators of compromise.

Handles the defanged forms analysts actually paste from reports
(`hxxp://evil[.]com`, `1.2.3[.]4`) and refuses the noise that makes IOC
databases useless: private ranges, reserved addresses and known-good domains.
"""

from __future__ import annotations

import ipaddress
import re
from dataclasses import dataclass

from app.models import IOCType

_DEFANG = [
    (re.compile(r"\[\.\]|\(\.\)|\{\.\}", re.I), "."),
    (re.compile(r"\[:\]|\(:\)", re.I), ":"),
    (re.compile(r"\bhxxps\b", re.I), "https"),
    (re.compile(r"\bhxxp\b", re.I), "http"),
    (re.compile(r"\[at\]|\(at\)", re.I), "@"),
    (re.compile(r"\[dot\]|\(dot\)", re.I), "."),
]

_RX = {
    IOCType.URL: re.compile(r"\bhttps?://[^\s<>\"')\]]{4,2048}", re.I),
    IOCType.EMAIL: re.compile(r"\b[A-Z0-9._%+-]{1,64}@[A-Z0-9.-]{1,255}\.[A-Z]{2,24}\b", re.I),
    IOCType.IPV4: re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b"),
    IOCType.IPV6: re.compile(r"\b(?:[A-F0-9]{1,4}:){2,7}[A-F0-9]{1,4}\b", re.I),
    IOCType.SHA256: re.compile(r"\b[a-f0-9]{64}\b", re.I),
    IOCType.SHA1: re.compile(r"\b[a-f0-9]{40}\b", re.I),
    IOCType.MD5: re.compile(r"\b[a-f0-9]{32}\b", re.I),
    IOCType.CVE: re.compile(r"\bCVE-\d{4}-\d{4,7}\b", re.I),
    IOCType.DOMAIN: re.compile(
        r"\b(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.){1,8}"
        r"(?:com|net|org|io|ai|co|ru|cn|info|biz|xyz|top|club|online|site|shop|live|"
        r"dev|app|cloud|gov|edu|mil|int|uk|de|fr|jp|in|br|au|ca|nl|se|no|fi|pl|it|es|"
        r"tk|ml|ga|cf|gq|zip|mov|link|click|work|rest|fit|icu|cyou|su|pw)\b", re.I),
}

# Never store these as threat indicators.
_SAFE_DOMAINS = {
    "google.com", "www.google.com", "microsoft.com", "windows.com", "apple.com",
    "github.com", "githubusercontent.com", "cloudflare.com", "amazonaws.com",
    "office.com", "live.com", "gstatic.com", "akamai.net", "digicert.com",
    "mozilla.org", "python.org", "npmjs.com", "example.com", "localhost",
}

# Order matters: longer/more specific patterns win before shorter ones.
_ORDER = [
    IOCType.URL, IOCType.EMAIL, IOCType.SHA256, IOCType.SHA1, IOCType.MD5,
    IOCType.CVE, IOCType.IPV6, IOCType.IPV4, IOCType.DOMAIN,
]


@dataclass(frozen=True)
class ParsedIOC:
    value: str
    ioc_type: IOCType

    def defanged(self) -> str:
        """Render safe for e-mail, tickets and chat."""
        out = self.value.replace("http", "hxxp")
        out = re.sub(r"\.(?=[^.]*$)|\.", "[.]", out) if self.ioc_type in {
            IOCType.IPV4, IOCType.DOMAIN, IOCType.URL, IOCType.EMAIL
        } else out
        return out.replace("@", "[at]")


def refang(text: str) -> str:
    out = text
    for rx, sub in _DEFANG:
        out = rx.sub(sub, out)
    return out


def is_routable_ip(value: str) -> bool:
    """False for private, loopback, link-local, multicast and reserved space."""
    try:
        ip = ipaddress.ip_address(value)
    except ValueError:
        return False
    return not (
        ip.is_private or ip.is_loopback or ip.is_link_local
        or ip.is_multicast or ip.is_reserved or ip.is_unspecified
    )


def is_noise_domain(value: str) -> bool:
    host = value.lower().strip(".")
    if host in _SAFE_DOMAINS:
        return True
    return any(host.endswith("." + safe) for safe in _SAFE_DOMAINS)


def normalize(value: str, ioc_type: IOCType) -> str:
    v = value.strip().strip(".,;:'\"()[]<>")
    match ioc_type:
        case IOCType.MD5 | IOCType.SHA1 | IOCType.SHA256:
            return v.lower()
        case IOCType.CVE:
            return v.upper()
        case IOCType.EMAIL | IOCType.DOMAIN:
            return v.lower().rstrip(".")
        case IOCType.IPV6:
            try:
                return str(ipaddress.ip_address(v))
            except ValueError:
                return v.lower()
        case IOCType.URL:
            # Keep the path (it carries payload names) but normalise the host.
            m = re.match(r"^(https?://)([^/]+)(.*)$", v, re.I)
            if not m:
                return v
            scheme, host, rest = m.groups()
            return f"{scheme.lower()}{host.lower()}{rest}"
        case _:
            return v


def validate(value: str, ioc_type: IOCType) -> bool:
    v = normalize(value, ioc_type)
    match ioc_type:
        case IOCType.IPV4 | IOCType.IPV6:
            return is_routable_ip(v)
        case IOCType.DOMAIN:
            return bool(_RX[IOCType.DOMAIN].fullmatch(v)) and not is_noise_domain(v)
        case IOCType.URL:
            host = re.sub(r"^https?://", "", v).split("/")[0].split(":")[0]
            return bool(host) and not is_noise_domain(host)
        case IOCType.EMAIL:
            return bool(_RX[IOCType.EMAIL].fullmatch(v))
        case IOCType.MD5 | IOCType.SHA1 | IOCType.SHA256 | IOCType.CVE:
            return bool(_RX[ioc_type].fullmatch(v))
    return False


def extract(text: str, *, keep_noise: bool = False) -> list[ParsedIOC]:
    """Pull every distinct indicator out of free text, best type first."""
    haystack = refang(text or "")
    claimed: list[tuple[int, int]] = []
    found: dict[tuple[str, str], ParsedIOC] = {}

    def overlaps(start: int, end: int) -> bool:
        return any(not (end <= s or start >= e) for s, e in claimed)

    for ioc_type in _ORDER:
        for m in _RX[ioc_type].finditer(haystack):
            if overlaps(m.start(), m.end()):
                continue
            value = normalize(m.group(0), ioc_type)
            if not keep_noise and not validate(value, ioc_type):
                continue
            claimed.append((m.start(), m.end()))
            found[(value, ioc_type.value)] = ParsedIOC(value=value, ioc_type=ioc_type)

    return sorted(found.values(), key=lambda p: (p.ioc_type.value, p.value))


def detect_type(value: str) -> IOCType | None:
    """Classify a single indicator supplied on its own."""
    v = refang(value).strip()
    for ioc_type in _ORDER:
        if _RX[ioc_type].fullmatch(v) and validate(v, ioc_type):
            return ioc_type
    return None
