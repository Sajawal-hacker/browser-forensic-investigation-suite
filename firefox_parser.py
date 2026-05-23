"""
firefox_parser.py - Parse Firefox/Gecko-based browser artifacts
Universal Browser Forensic Investigation Suite
"""

import sqlite3
import json
from pathlib import Path
from datetime import datetime, timezone
from typing import Optional
import logging

from hash_utility import make_forensic_copy

logger = logging.getLogger(__name__)

# Firefox epoch: microseconds since Unix epoch
def ff_ts_to_dt(microseconds) -> Optional[datetime]:
    if not microseconds:
        return None
    try:
        return datetime.fromtimestamp(int(microseconds) / 1_000_000, tz=timezone.utc)
    except Exception:
        return None


def ff_ms_to_dt(milliseconds) -> Optional[datetime]:
    if not milliseconds:
        return None
    try:
        return datetime.fromtimestamp(int(milliseconds) / 1000, tz=timezone.utc)
    except Exception:
        return None


def _open_db_copy(db_path: Path, tmp_dir: Path) -> tuple[sqlite3.Connection, str]:
    copy_path, file_hash = make_forensic_copy(db_path, tmp_dir)
    conn = sqlite3.connect(f"file:{copy_path}?mode=ro", uri=True)
    conn.row_factory = sqlite3.Row
    return conn, file_hash


def parse_history(profile_path: Path, browser_name: str, profile_name: str, tmp_dir: Path) -> list:
    db_path = profile_path / "places.sqlite"
    if not db_path.exists():
        return []

    records = []
    try:
        conn, _ = _open_db_copy(db_path, tmp_dir)
        cur = conn.cursor()
        cur.execute("""
            SELECT p.url, p.title, p.visit_count, h.visit_date
            FROM moz_places p
            JOIN moz_historyvisits h ON p.id = h.place_id
            ORDER BY h.visit_date DESC
        """)
        for row in cur.fetchall():
            dt = ff_ts_to_dt(row["visit_date"])
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
        logger.error(f"Firefox history error {db_path}: {e}")

    return records


def parse_downloads(profile_path: Path, browser_name: str, profile_name: str, tmp_dir: Path) -> list:
    db_path = profile_path / "places.sqlite"
    if not db_path.exists():
        return []

    records = []
    try:
        conn, _ = _open_db_copy(db_path, tmp_dir)
        cur = conn.cursor()
        cur.execute("""
            SELECT a.content AS file_path,
                   p.url AS source_url,
                   a.dateAdded AS download_time,
                   a.lastModified
            FROM moz_annos a
            JOIN moz_places p ON a.place_id = p.id
            WHERE a.anno_attribute_id IN (
                SELECT id FROM moz_anno_attributes WHERE name='downloads/destinationFileURI'
            )
            ORDER BY a.dateAdded DESC
        """)
        for row in cur.fetchall():
            dt = ff_ms_to_dt(row["download_time"])
            file_path = (row["file_path"] or "").replace("file:///", "").replace("/", "\\")
            records.append({
                "browser": browser_name,
                "profile": profile_name,
                "file_name": Path(file_path).name if file_path else "",
                "download_url": row["source_url"] or "",
                "download_time": dt.isoformat() if dt else "",
                "save_path": file_path,
            })
        conn.close()
    except Exception as e:
        logger.error(f"Firefox downloads error {db_path}: {e}")

    return records


def parse_cookies(profile_path: Path, browser_name: str, profile_name: str, tmp_dir: Path) -> list:
    db_path = profile_path / "cookies.sqlite"
    if not db_path.exists():
        return []

    records = []
    try:
        conn, _ = _open_db_copy(db_path, tmp_dir)
        cur = conn.cursor()
        cur.execute("""
            SELECT host, name, creationTime, expiry
            FROM moz_cookies
            ORDER BY creationTime DESC
            LIMIT 5000
        """)
        for row in cur.fetchall():
            created = ff_ts_to_dt(row["creationTime"])
            expiry = ff_ms_to_dt(row["expiry"]) if row["expiry"] else None
            records.append({
                "browser": browser_name,
                "profile": profile_name,
                "domain": row["host"] or "",
                "name": row["name"] or "",
                "creation_time": created.isoformat() if created else "",
                "expiry_time": expiry.isoformat() if expiry else "",
            })
        conn.close()
    except Exception as e:
        logger.error(f"Firefox cookies error {db_path}: {e}")

    return records


def parse_extensions(profile_path: Path, browser_name: str, profile_name: str) -> list:
    ext_file = profile_path / "extensions.json"
    records = []
    if not ext_file.exists():
        return records
    try:
        with open(ext_file, "r", encoding="utf-8", errors="ignore") as f:
            data = json.load(f)
        addons = data.get("addons", [])
        for addon in addons:
            if addon.get("type") not in ("extension", "theme"):
                continue
            perms = [p.get("permission", "") for p in addon.get("userPermissions", {}).get("permissions", [])]
            records.append({
                "browser": browser_name,
                "profile": profile_name,
                "name": addon.get("defaultLocale", {}).get("name", addon.get("id", "")),
                "version": addon.get("version", ""),
                "permissions": ", ".join(perms),
                "install_time": addon.get("installDate", ""),
                "ext_id": addon.get("id", ""),
            })
    except Exception as e:
        logger.error(f"Firefox extensions error {ext_file}: {e}")
    return records


def get_login_databases(profile_path: Path) -> list:
    dbs = []
    for db_name, enc in [("logins.json", "AES-256-CBC (key4.db)"), ("key4.db", "NSS/SQLite encrypted")]:
        db_path = profile_path / db_name
        if db_path.exists():
            stat = db_path.stat()
            dbs.append({
                "name": db_name,
                "path": str(db_path),
                "encryption": enc,
                "last_modified": datetime.fromtimestamp(stat.st_mtime).isoformat(),
                "size": stat.st_size,
            })
    return dbs
