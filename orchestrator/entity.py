"""
Entity Detection Module
Responsibility: Deterministically identify if a query targets an IP, URL, or Domain.
Importance: Layer A of the router relies on this classification.
"""
import re
from enum import Enum
from typing import NamedTuple, Optional

class EntityType(str, Enum):
    IP = "ip"
    URL = "url"
    DOMAIN = "domain"
    UNKNOWN = "unknown"

class DetectedEntity(NamedTuple):
    type: EntityType
    value: str

# Regex Patterns
# IPv4: Basic 0-255 octet check
IPV4_PATTERN = r'\b(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b'

# IPv6: Loose match for common formats
IPV6_PATTERN = r'\b(?:[A-F0-9]{1,4}:){7}[A-F0-9]{1,4}\b'

# URL: Must start with http/https
URL_PATTERN = r'https?://(?:[-\w.]|(?:%[\da-fA-F]{2}))+[^\s]*'

# Domain: Loose match for domain-like strings (last resort after URL)
DOMAIN_PATTERN = r'\b((?=[a-z0-9-]{1,63}\.)(xn--)?[a-z0-9]+(-[a-z0-9]+)*\.)+[a-z]{2,63}\b'

def detect_entity(query: str) -> DetectedEntity:
    """
    Detects the primary entity in a query string using strict precedence.
    Order: URL -> IP -> Domain -> UNKNOWN
    """
    query = query.strip()
    
    # 1. URL Check (Highest Specificity)
    url_match = re.search(URL_PATTERN, query, re.IGNORECASE)
    if url_match:
        return DetectedEntity(EntityType.URL, url_match.group(0))

    # 2. IP Check (IPv4)
    ip_match = re.search(IPV4_PATTERN, query)
    if ip_match:
        return DetectedEntity(EntityType.IP, ip_match.group(0))
        
    # 3. Domain Check (Lowest Specificity)
    # Caution: IPs can match domain regex, but we checked IP first.
    domain_match = re.search(DOMAIN_PATTERN, query, re.IGNORECASE)
    if domain_match:
        return DetectedEntity(EntityType.DOMAIN, domain_match.group(0))

    return DetectedEntity(EntityType.UNKNOWN, query)
