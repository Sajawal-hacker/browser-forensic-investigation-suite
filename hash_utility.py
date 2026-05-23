"""
hash_utility.py - Forensic hashing utilities
Universal Browser Forensic Investigation Suite
"""

import hashlib
import shutil
import tempfile
from pathlib import Path
from datetime import datetime
import logging

logger = logging.getLogger(__name__)


def sha256_file(path: Path) -> str:
    """Compute SHA-256 hash of a file."""
    h = hashlib.sha256()
    try:
        with open(path, "rb") as f:
            for chunk in iter(lambda: f.read(65536), b""):
                h.update(chunk)
        return h.hexdigest()
    except Exception as e:
        logger.warning(f"Could not hash {path}: {e}")
        return "ERROR"


def make_forensic_copy(src: Path, tmp_dir: Path) -> tuple[Path, str]:
    """
    Create a read-only forensic copy of a file in tmp_dir.
    Returns (copy_path, sha256_hash).
    Does NOT modify the original.
    """
    if not src.exists():
        raise FileNotFoundError(f"Source not found: {src}")

    dest = tmp_dir / src.name
    shutil.copy2(src, dest)

    # Compute hash of original for chain of custody
    original_hash = sha256_file(src)

    return dest, original_hash


def acquisition_timestamp() -> str:
    return datetime.utcnow().isoformat() + "Z"
