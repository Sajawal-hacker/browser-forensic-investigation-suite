"""
chromium_parser.py - Parse Chromium-based browser artifacts
Universal Browser Forensic Investigation Suite
"""

import sqlite3
import json
import tempfile
import shutil
from pathlib import Path
from datetime import datetime, timezone
from typing import Optional
import logging

from hash_utility import make_forensic_copy

logger = logging.getLogger(__name__)

# Chromium epoch starts Jan 1, 1601
CHROME_EPOCH = datetime(1601, 1, 1, tzinfo=timezone.utc)


def chrome_ts_to_dt(microseconds: int) -> Optional[datetime]:
    """Convert Chrome timestamp (microseconds since 1601-01-01) to datetime."""
    if not microseconds:
        return None
    try:
        return CHROME_EPOCH + __import__("datetime").timedelta(microseconds=microseconds)
    except Exception:
        return None


def _open_db_copy(db_path: Path, tmp_dir: Path) -> tuple[sqlite3.Connection, str]:
    """Safely copy and open a SQLite database. Returns (connection, sha256)."""
    copy_path, file_hash = make_forensic_copy(db_path, tmp_dir)
    conn = sqlite3.connect(f"file:{copy_path}?mode=ro", uri=True)
    conn.row_factory = sqlite3.Row
    return conn, file_hash


def parse_history(profile_path: Path, browser_name: str, profile_name: str, tmp_dir: Path) -> list:
    """Parse Chromium History database."""
    db_path = profile_path / "History"
    if not db_path.exists():
        return []

    records = []
    try:
        conn, _ = _open_db_copy(db_path, tmp_dir)
        cur = conn.cursor()
        cur.execute("""
            SELECT u.url, u.title, u.visit_count, v.visit_time
            FROM urls u
            JOIN visits v ON u.id = v.url
            ORDER BY v.visit_time DESC
        """)
        for row in cur.fetchall():
            dt = chrome_ts_to_dt(row["visit_time"])
            records.append({
                "browser": browser_name,
                "profile": profile_name,
                "url": row["url"] or "",
                "title": row["title"] or "",
                "visit_count": row["visit_count"] or 0,
                "visit_date": dt.strftime("%Y-%m-%d") if dt else "",
                "visit_time": dt.strftime("%H:%M:%S") if dt else "",
                "visit_ts": dt.isoformat() if dt else "",
                "source_db": str(db_path),
            })
        conn.close()
    except Exception as e:
        logger.error(f"History parse error {db_path}: {e}")

    return records


def parse_downloads(profile_path: Path, browser_name: str, profile_name: str, tmp_dir: Path) -> list:
    """Parse Chromium downloads."""
    db_path = profile_path / "History"
    if not db_path.exists():
        return []

    records = []
    try:
        conn, _ = _open_db_copy(db_path, tmp_dir)
        cur = conn.cursor()
        cur.execute("""
            SELECT current_path, tab_url, start_time, end_time, total_bytes, state
            FROM downloads
            ORDER BY start_time DESC
        """)
        for row in cur.fetchall():
            dt = chrome_ts_to_dt(row["start_time"])
            records.append({
                "browser": browser_name,
                "profile": profile_name,
                "file_name": Path(row["current_path"] or "").name,
                "download_url": row["tab_url"] or "",
                "download_time": dt.isoformat() if dt else "",
                "save_path": row["current_path"] or "",
                "total_bytes": row["total_bytes"] or 0,
                "state": row["state"],
            })
        conn.close()
    except Exception as e:
        logger.error(f"Downloads parse error {db_path}: {e}")

    return records


def parse_cookies(profile_path: Path, browser_name: str, profile_name: str, tmp_dir: Path) -> list:
    """Parse Chromium Cookies database."""
    db_path = profile_path / "Network" / "Cookies"
    if not db_path.exists():
        db_path = profile_path / "Cookies"
    if not db_path.exists():
        return []

    records = []
    try:
        conn, _ = _open_db_copy(db_path, tmp_dir)
        cur = conn.cursor()
        cur.execute("""
            SELECT host_key, name, creation_utc, expires_utc
            FROM cookies
            ORDER BY creation_utc DESC
            LIMIT 5000
        """)
        for row in cur.fetchall():
            created = chrome_ts_to_dt(row["creation_utc"])
            expires = chrome_ts_to_dt(row["expires_utc"])
            records.append({
                "browser": browser_name,
                "profile": profile_name,
                "domain": row["host_key"] or "",
                "name": row["name"] or "",
                "creation_time": created.isoformat() if created else "",
                "expiry_time": expires.isoformat() if expires else "",
            })
        conn.close()
    except Exception as e:
        logger.error(f"Cookies parse error {db_path}: {e}")

    return records


def parse_extensions(profile_path: Path, browser_name: str, profile_name: str) -> list:
    """Parse installed Chromium extensions."""
    ext_path = profile_path / "Extensions"
    records = []
    if not ext_path.exists():
        return records

    try:
        for ext_id_dir in ext_path.iterdir():
            if not ext_id_dir.is_dir():
                continue
            for version_dir in ext_id_dir.iterdir():
                if not version_dir.is_dir():
                    continue
                manifest_path = version_dir / "manifest.json"
                if not manifest_path.exists():
                    continue
                try:
                    with open(manifest_path, "r", encoding="utf-8", errors="ignore") as f:
                        manifest = json.load(f)
                    name = manifest.get("name", ext_id_dir.name)
                    if name.startswith("__MSG_"):
                        # Try to resolve from _locales
                        locales_path = version_dir / "_locales" / "en" / "messages.json"
                        if locales_path.exists():
                            try:
                                with open(locales_path, "r", encoding="utf-8") as lf:
                                    msgs = json.load(lf)
                                key = name.replace("__MSG_", "").replace("__", "")
                                name = msgs.get(key, {}).get("message", name)
                            except Exception:
                                pass

                    perms = manifest.get("permissions", [])
                    records.append({
                        "browser": browser_name,
                        "profile": profile_name,
                        "name": name,
                        "version": manifest.get("version", ""),
                        "permissions": ", ".join(str(p) for p in perms),
                        "install_time": "",
                        "ext_id": ext_id_dir.name,
                    })
                except Exception:
                    pass
    except Exception as e:
        logger.error(f"Extensions parse error {ext_path}: {e}")

    return records


def get_login_databases(profile_path: Path, user_data_path: Path) -> list:
    """Return metadata for Chromium login-related databases."""
    dbs = []
    for db_name in ["Login Data", "Login Data For Account"]:
        db_path = profile_path / db_name
        if db_path.exists():
            stat = db_path.stat()
            dbs.append({
                "name": db_name,
                "path": str(db_path),
                "encryption": "AES-256 (DPAPI)",
                "last_modified": datetime.fromtimestamp(stat.st_mtime).isoformat(),
                "size": stat.st_size,
            })

    local_state = user_data_path / "Local State"
    if local_state.exists():
        stat = local_state.stat()
        dbs.append({
            "name": "Local State",
            "path": str(local_state),
            "encryption": "Contains encrypted_key for DPAPI",
            "last_modified": datetime.fromtimestamp(stat.st_mtime).isoformat(),
            "size": stat.st_size,
        })
    return dbs
