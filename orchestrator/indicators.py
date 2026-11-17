"""
Indicator validation and normalisation for agentic calls (and cache keys).

The non-routable IP rule is the exact predicate ti_query's tools apply
(tools.shodan_tool.validate_ip: rejects private, loopback and link-local addresses).
"""
import ipaddress
import re
from urllib.parse import urlsplit

from orchestrator.entity import DOMAIN_PATTERN
from tools.shodan_tool import validate_ip as is_routable_ipv4

INDICATOR_TYPES = ("ip", "domain", "url", "hash")
MAX_INDICATOR_LENGTH = 2048

_HASH_RE = re.compile(r"[0-9a-fA-F]{32}|[0-9a-fA-F]{40}|[0-9a-fA-F]{64}")
_DOMAIN_RE = re.compile(DOMAIN_PATTERN, re.IGNORECASE)
_IPV4_RE = re.compile(r"\d{1,3}(?:\.\d{1,3}){3}")
_WHITESPACE_OR_CONTROL = re.compile(r"[\s\x00-\x1f\x7f]")


class IndicatorError(Exception):
    def __init__(self, reason: str):
        super().__init__(reason)
        self.reason = reason  # "invalid_indicator_type" | "invalid_indicator" | "non_routable_ip"


def _ipv4(value: str) -> str:
    if not _IPV4_RE.fullmatch(value):
        raise IndicatorError("invalid_indicator")
    try:
        ip = ipaddress.IPv4Address(value)
    except ValueError:
        raise IndicatorError("invalid_indicator")
    if not is_routable_ipv4(str(ip)):
        raise IndicatorError("non_routable_ip")
    return str(ip)


def _url(value: str) -> str:
    if _WHITESPACE_OR_CONTROL.search(value):
        raise IndicatorError("invalid_indicator")
    try:
        parts = urlsplit(value)
        host = parts.hostname
    except ValueError:
        raise IndicatorError("invalid_indicator")
    if parts.scheme.lower() not in ("http", "https") or not host:
        raise IndicatorError("invalid_indicator")
    if host == "localhost" or host.endswith(".localhost"):
        raise IndicatorError("non_routable_ip")
    try:
        ip = ipaddress.ip_address(host)
    except ValueError:
        ip = None
    if ip is not None and (ip.is_private or ip.is_loopback or ip.is_link_local):
        raise IndicatorError("non_routable_ip")
    return value


def normalize_indicator(indicator_type: str, value) -> str:
    """Return the canonical form of a valid indicator, or raise IndicatorError."""
    if indicator_type not in INDICATOR_TYPES:
        raise IndicatorError("invalid_indicator_type")
    if not isinstance(value, str):
        raise IndicatorError("invalid_indicator")
    value = value.strip()
    if not value or len(value) > MAX_INDICATOR_LENGTH:
        raise IndicatorError("invalid_indicator")

    if indicator_type == "ip":
        return _ipv4(value)
    if indicator_type == "hash":
        if not _HASH_RE.fullmatch(value):
            raise IndicatorError("invalid_indicator")
        return value.lower()
    if indicator_type == "domain":
        domain = value.lower().rstrip(".")
        if len(domain) > 253 or not _DOMAIN_RE.fullmatch(domain):
            raise IndicatorError("invalid_indicator")
        return domain
    return _url(value)


def cache_key_indicator(indicator_type: str, value: str) -> str:
    """Cache key form for ti_query: normalised when valid, otherwise the raw value (ti_query never rejects)."""
    try:
        return normalize_indicator(indicator_type, value)
    except IndicatorError:
        return value
