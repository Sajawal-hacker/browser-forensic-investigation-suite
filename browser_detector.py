"""
browser_detector.py - Detects installed browsers on Windows systems
Universal Browser Forensic Investigation Suite
"""

import os
import json
import winreg
from pathlib import Path
from dataclasses import dataclass, field
from typing import Optional
import logging

logger = logging.getLogger(__name__)


@dataclass
class BrowserProfile:
    name: str
    path: Path
    last_used: Optional[str] = None
    email: Optional[str] = None
    browser_name: str = ""


@dataclass
class BrowserInfo:
    name: str
    browser_type: str  # 'chromium' or 'firefox'
    executable_path: Optional[Path] = None
    user_data_path: Optional[Path] = None
    version: str = "Unknown"
    vendor: str = "Unknown"
    profiles: list = field(default_factory=list)
    detected: bool = False

    @property
    def profile_count(self):
        return len(self.profiles)


CHROMIUM_BROWSERS = {
    "Google Chrome": {
        "vendor": "Google",
        "reg_keys": [
            r"SOFTWARE\Google\Chrome\BLBeacon",
            r"SOFTWARE\WOW6432Node\Google\Chrome\BLBeacon",
        ],
        "exe_paths": [
            Path(os.environ.get("PROGRAMFILES", "C:/Program Files")) / "Google/Chrome/Application/chrome.exe",
            Path(os.environ.get("PROGRAMFILES(X86)", "C:/Program Files (x86)")) / "Google/Chrome/Application/chrome.exe",
            Path(os.environ.get("LOCALAPPDATA", "")) / "Google/Chrome/Application/chrome.exe",
        ],
        "user_data": Path(os.environ.get("LOCALAPPDATA", "")) / "Google/Chrome/User Data",
    },
    "Microsoft Edge": {
        "vendor": "Microsoft",
        "reg_keys": [
            r"SOFTWARE\Microsoft\Edge\BLBeacon",
        ],
        "exe_paths": [
            Path(os.environ.get("PROGRAMFILES", "C:/Program Files")) / "Microsoft/Edge/Application/msedge.exe",
            Path(os.environ.get("PROGRAMFILES(X86)", "C:/Program Files (x86)")) / "Microsoft/Edge/Application/msedge.exe",
        ],
        "user_data": Path(os.environ.get("LOCALAPPDATA", "")) / "Microsoft/Edge/User Data",
    },
    "Brave Browser": {
        "vendor": "Brave Software",
        "reg_keys": [],
        "exe_paths": [
            Path(os.environ.get("PROGRAMFILES", "C:/Program Files")) / "BraveSoftware/Brave-Browser/Application/brave.exe",
            Path(os.environ.get("LOCALAPPDATA", "")) / "BraveSoftware/Brave-Browser/Application/brave.exe",
        ],
        "user_data": Path(os.environ.get("LOCALAPPDATA", "")) / "BraveSoftware/Brave-Browser/User Data",
    },
    "Opera": {
        "vendor": "Opera Software",
        "reg_keys": [],
        "exe_paths": [
            Path(os.environ.get("LOCALAPPDATA", "")) / "Programs/Opera/opera.exe",
        ],
        "user_data": Path(os.environ.get("APPDATA", "")) / "Opera Software/Opera Stable",
    },
    "Opera GX": {
        "vendor": "Opera Software",
        "reg_keys": [],
        "exe_paths": [
            Path(os.environ.get("LOCALAPPDATA", "")) / "Programs/Opera GX/opera.exe",
        ],
        "user_data": Path(os.environ.get("APPDATA", "")) / "Opera Software/Opera GX Stable",
    },
    "Vivaldi": {
        "vendor": "Vivaldi Technologies",
        "reg_keys": [],
        "exe_paths": [
            Path(os.environ.get("LOCALAPPDATA", "")) / "Vivaldi/Application/vivaldi.exe",
        ],
        "user_data": Path(os.environ.get("LOCALAPPDATA", "")) / "Vivaldi/User Data",
    },
    "Chromium": {
        "vendor": "Chromium",
        "reg_keys": [],
        "exe_paths": [
            Path(os.environ.get("LOCALAPPDATA", "")) / "Chromium/Application/chrome.exe",
        ],
        "user_data": Path(os.environ.get("LOCALAPPDATA", "")) / "Chromium/User Data",
    },
}

FIREFOX_BROWSERS = {
    "Firefox": {
        "vendor": "Mozilla",
        "reg_keys": [
            r"SOFTWARE\Mozilla\Mozilla Firefox",
        ],
        "exe_paths": [
            Path(os.environ.get("PROGRAMFILES", "C:/Program Files")) / "Mozilla Firefox/firefox.exe",
            Path(os.environ.get("PROGRAMFILES(X86)", "C:/Program Files (x86)")) / "Mozilla Firefox/firefox.exe",
        ],
        "profiles_ini": Path(os.environ.get("APPDATA", "")) / "Mozilla/Firefox/profiles.ini",
        "profiles_root": Path(os.environ.get("APPDATA", "")) / "Mozilla/Firefox/Profiles",
    },
    "Firefox ESR": {
        "vendor": "Mozilla",
        "reg_keys": [],
        "exe_paths": [
            Path(os.environ.get("PROGRAMFILES", "C:/Program Files")) / "Mozilla Firefox ESR/firefox.exe",
        ],
        "profiles_ini": Path(os.environ.get("APPDATA", "")) / "Mozilla/Firefox/profiles.ini",
        "profiles_root": Path(os.environ.get("APPDATA", "")) / "Mozilla/Firefox/Profiles",
    },
    "Waterfox": {
        "vendor": "Waterfox",
        "reg_keys": [],
        "exe_paths": [
            Path(os.environ.get("PROGRAMFILES", "C:/Program Files")) / "Waterfox/waterfox.exe",
        ],
        "profiles_ini": Path(os.environ.get("APPDATA", "")) / "Waterfox/Profiles/profiles.ini",
        "profiles_root": Path(os.environ.get("APPDATA", "")) / "Waterfox/Profiles",
    },
    "LibreWolf": {
        "vendor": "LibreWolf",
        "reg_keys": [],
        "exe_paths": [
            Path(os.environ.get("PROGRAMFILES", "C:/Program Files")) / "LibreWolf/librewolf.exe",
        ],
        "profiles_ini": Path(os.environ.get("LOCALAPPDATA", "")) / "LibreWolf/Profiles/profiles.ini",
        "profiles_root": Path(os.environ.get("LOCALAPPDATA", "")) / "LibreWolf/Profiles",
    },
}


def _get_registry_version(reg_key: str) -> Optional[str]:
    """Try to read version from Windows registry."""
    for hive in (winreg.HKEY_LOCAL_MACHINE, winreg.HKEY_CURRENT_USER):
        try:
            key = winreg.OpenKey(hive, reg_key)
            version, _ = winreg.QueryValueEx(key, "version")
            winreg.CloseKey(key)
            return version
        except (FileNotFoundError, OSError):
            continue
    return None


def _get_chromium_version_from_path(exe_path: Path) -> str:
    """Read version from chrome app manifest or executable directory."""
    try:
        app_dir = exe_path.parent
        # Try to find version subdirectory
        for item in app_dir.iterdir():
            if item.is_dir() and item.name[0].isdigit():
                return item.name
    except Exception:
        pass
    return "Unknown"


def _enumerate_chromium_profiles(user_data: Path, browser_name: str) -> list:
    """Enumerate Chromium browser profiles."""
    profiles = []
    if not user_data.exists():
        return profiles

    profile_dirs = ["Default"]
    try:
        for item in user_data.iterdir():
            if item.is_dir() and item.name.startswith("Profile "):
                profile_dirs.append(item.name)
    except PermissionError:
        pass

    for pdir in profile_dirs:
        profile_path = user_data / pdir
        if not profile_path.exists():
            continue

        prefs_file = profile_path / "Preferences"
        name = pdir
        email = None
        last_used = None

        if prefs_file.exists():
            try:
                with open(prefs_file, "r", encoding="utf-8", errors="ignore") as f:
                    prefs = json.load(f)
                    name = prefs.get("profile", {}).get("name", pdir)
                    # Try to get email
                    account_info = prefs.get("account_info", [])
                    if account_info:
                        email = account_info[0].get("email")
                    profile_info = prefs.get("profile", {})
                    last_used = profile_info.get("last_used_desktop_timestamp", None)
            except Exception:
                pass

        profiles.append(BrowserProfile(
            name=name,
            path=profile_path,
            last_used=str(last_used) if last_used else None,
            email=email,
            browser_name=browser_name,
        ))

    return profiles


def _enumerate_firefox_profiles(profiles_root: Path, profiles_ini: Path, browser_name: str) -> list:
    """Enumerate Firefox browser profiles."""
    profiles = []

    if profiles_root.exists():
        try:
            for item in profiles_root.iterdir():
                if item.is_dir():
                    profiles.append(BrowserProfile(
                        name=item.name,
                        path=item,
                        browser_name=browser_name,
                    ))
        except PermissionError:
            pass
    elif profiles_ini.exists():
        try:
            import configparser
            config = configparser.ConfigParser()
            config.read(profiles_ini)
            for section in config.sections():
                if section.startswith("Profile"):
                    path_val = config[section].get("Path", "")
                    is_relative = config[section].get("IsRelative", "0") == "1"
                    if path_val:
                        if is_relative:
                            profile_path = profiles_ini.parent / path_val
                        else:
                            profile_path = Path(path_val)
                        profiles.append(BrowserProfile(
                            name=config[section].get("Name", section),
                            path=profile_path,
                            browser_name=browser_name,
                        ))
        except Exception:
            pass

    return profiles


def detect_all_browsers() -> dict:
    """Detect all installed browsers and return BrowserInfo objects."""
    results = {}

    # Chromium-based browsers
    for name, cfg in CHROMIUM_BROWSERS.items():
        info = BrowserInfo(name=name, browser_type="chromium", vendor=cfg["vendor"])

        # Check executable
        for exe in cfg["exe_paths"]:
            if exe.exists():
                info.executable_path = exe
                info.detected = True
                break

        # Check registry for version
        for reg_key in cfg.get("reg_keys", []):
            v = _get_registry_version(reg_key)
            if v:
                info.version = v
                break

        # Fallback: read version from disk
        if info.version == "Unknown" and info.executable_path:
            info.version = _get_chromium_version_from_path(info.executable_path)

        # Check user data
        user_data = cfg.get("user_data")
        if user_data and user_data.exists():
            info.user_data_path = user_data
            info.detected = True
            info.profiles = _enumerate_chromium_profiles(user_data, name)

        results[name] = info

    # Firefox-based browsers
    for name, cfg in FIREFOX_BROWSERS.items():
        info = BrowserInfo(name=name, browser_type="firefox", vendor=cfg["vendor"])

        for exe in cfg["exe_paths"]:
            if exe.exists():
                info.executable_path = exe
                info.detected = True
                break

        profiles_root = cfg.get("profiles_root", Path(""))
        profiles_ini = cfg.get("profiles_ini", Path(""))

        if profiles_root.exists() or profiles_ini.exists():
            info.detected = True
            info.user_data_path = profiles_root if profiles_root.exists() else profiles_ini.parent
            info.profiles = _enumerate_firefox_profiles(profiles_root, profiles_ini, name)

        results[name] = info

    return results
