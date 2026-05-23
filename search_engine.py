"""
search_engine.py - Forensic search across all artifacts
Universal Browser Forensic Investigation Suite
"""

from urllib.parse import urlparse
from typing import Optional


def search_history(records: list, query: str = "", browser: Optional[str] = None,
                   profile: Optional[str] = None, start_date: Optional[str] = None,
                   end_date: Optional[str] = None) -> list:
    """Filter history records based on search criteria."""
    q = query.strip().lower()
    results = []
    for r in records:
        if browser and r.get("browser") != browser:
            continue
        if profile and r.get("profile") != profile:
            continue
        ts = r.get("visit_ts", "")
        if start_date and ts and ts < start_date:
            continue
        if end_date and ts and ts > end_date:
            continue
        if q:
            if q not in r.get("url", "").lower() and q not in r.get("title", "").lower():
                continue
        results.append(r)
    return results


def extract_domain(url: str) -> str:
    """Extract domain from URL."""
    try:
        return urlparse(url).netloc
    except Exception:
        return ""


def domain_frequency(records: list) -> dict:
    """Count visits per domain."""
    freq = {}
    for r in records:
        domain = extract_domain(r.get("url", ""))
        if domain:
            freq[domain] = freq.get(domain, 0) + 1
    return dict(sorted(freq.items(), key=lambda x: x[1], reverse=True))
