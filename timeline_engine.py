"""
timeline_engine.py - Unified forensic timeline
Universal Browser Forensic Investigation Suite
"""

from typing import Optional
import logging

logger = logging.getLogger(__name__)


def build_timeline(history: list, downloads: list) -> list:
    """Merge history and downloads into a unified sorted timeline."""
    events = []

    for item in history:
        events.append({
            "timestamp": item.get("visit_ts", ""),
            "type": "Visit",
            "browser": item.get("browser", ""),
            "profile": item.get("profile", ""),
            "detail": item.get("url", ""),
            "title": item.get("title", ""),
        })

    for item in downloads:
        events.append({
            "timestamp": item.get("download_time", ""),
            "type": "Download",
            "browser": item.get("browser", ""),
            "profile": item.get("profile", ""),
            "detail": item.get("download_url", ""),
            "title": item.get("file_name", ""),
        })

    events.sort(key=lambda x: x.get("timestamp", ""), reverse=True)
    return events


def filter_timeline(events: list, start_date: Optional[str] = None, end_date: Optional[str] = None,
                    browser: Optional[str] = None, profile: Optional[str] = None,
                    keyword: Optional[str] = None) -> list:
    filtered = []
    for e in events:
        ts = e.get("timestamp", "")
        if start_date and ts and ts < start_date:
            continue
        if end_date and ts and ts > end_date:
            continue
        if browser and e.get("browser") != browser:
            continue
        if profile and e.get("profile") != profile:
            continue
        if keyword:
            kw = keyword.lower()
            if kw not in e.get("detail", "").lower() and kw not in e.get("title", "").lower():
                continue
        filtered.append(e)
    return filtered
