"""
DNS Threat Intelligence & Machine Learning
Module: Standalone Threat Intelligence Lookup

This module provides functions to load threat feeds (e.g., URLhaus by abuse.ch),
normalize domain names, and perform fast exact/subdomain lookups against known malicious domains.
"""

import os
import re

DEFAULT_FEED_FILE = os.path.abspath(
    os.path.join(os.path.dirname(__file__), "..", "data", "threat_intelligence", "urlhaus_domains.txt")
)
DEFAULT_HOSTS_FILE = os.path.abspath(
    os.path.join(os.path.dirname(__file__), "..", "data", "threat_intelligence", "urlhaus_hosts.txt")
)

_threat_feed_set = None


def normalize_domain(domain_str: str) -> str:
    """
    Normalize domain name for consistent lookup:
    - Strips whitespace
    - Converts to lowercase
    - Removes URL scheme (http://, https://) and path/query string
    - Removes trailing dots (e.g., 'example.com.' -> 'example.com')
    """
    if not domain_str or not isinstance(domain_str, str):
        return ""

    domain_str = domain_str.strip().lower()

    # Remove protocol scheme if present (e.g., http://, https://)
    domain_str = re.sub(r'^(?:https?|ftp)://', '', domain_str)

    # Remove path, query string, or port if present (e.g., example.com/path -> example.com)
    domain_str = domain_str.split('/')[0].split('?')[0].split(':')[0]

    # Remove trailing dot if present
    domain_str = domain_str.rstrip('.')

    return domain_str


def load_threat_feed(feed_file: str = None) -> set:
    """
    Load malicious domain indicators from local threat feed file into a set.
    """
    global _threat_feed_set
    if feed_file is None:
        feed_file = DEFAULT_FEED_FILE
        if not os.path.exists(feed_file) and os.path.exists(DEFAULT_HOSTS_FILE):
            feed_file = DEFAULT_HOSTS_FILE

    if not os.path.exists(feed_file):
        raise FileNotFoundError(f"Threat feed file not found at {feed_file}")

    domains = set()
    with open(feed_file, "r", encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            parts = line.split()
            # If line is formatted as IP domain (hosts file)
            if len(parts) >= 2 and parts[0] in ("127.0.0.1", "0.0.0.0"):
                norm = normalize_domain(parts[1])
            else:
                norm = normalize_domain(parts[0])
            if norm and norm not in ("127.0.0.1", "localhost"):
                domains.add(norm)

    _threat_feed_set = domains
    return _threat_feed_set


def check_domain(domain_str: str, feed_file: str = None) -> dict:
    """
    Check if a domain (or its parent domain) is present in the Threat Intelligence feed.
    
    Returns:
        dict: {
            "domain": str,
            "normalized_domain": str,
            "known_malicious": bool,
            "source": str,
            "status": str ("known_malicious" or "not_found")
        }
    """
    global _threat_feed_set
    if _threat_feed_set is None:
        load_threat_feed(feed_file)

    norm_domain = normalize_domain(domain_str)
    
    # Direct lookup
    is_malicious = norm_domain in _threat_feed_set

    # Check parent domain if subdomain (e.g. sub.malicious.com -> malicious.com)
    if not is_malicious and "." in norm_domain:
        parts = norm_domain.split(".")
        for i in range(1, len(parts) - 1):
            parent = ".".join(parts[i:])
            if parent in _threat_feed_set:
                is_malicious = True
                break

    return {
        "domain": domain_str,
        "normalized_domain": norm_domain,
        "known_malicious": is_malicious,
        "source": "URLhaus by abuse.ch",
        "status": "known_malicious" if is_malicious else "not_found"
    }


if __name__ == "__main__":
    print("=== Testing Standalone Threat Intelligence Module ===")
    feed = load_threat_feed()
    print(f"Loaded {len(feed)} indicators from URLhaus feed.\n")

    # Pick a real indicator from loaded feed for testing
    sample_indicator = list(feed)[0] if feed else "0following.com"

    test_domains = [
        sample_indicator,                          # Real known malicious indicator from feed
        sample_indicator.upper() + ".",           # Test normalization (uppercase + trailing dot)
        "google.com",                              # Known benign domain
        "http://www.google.com/search?q=test"      # Test URL normalization
    ]

    for d in test_domains:
        res = check_domain(d)
        print(f"Domain: {d:<40} -> Malicious: {res['known_malicious']!s:<5} | Status: {res['status']:<15} | Norm: {res['normalized_domain']}")
