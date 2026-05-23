"""
main.py - Browser Forensic Investigation Suite By Sajawal Hacker
Main PyQt6 Application Entry Point

AUTHORIZED DFIR USE ONLY.
This software must only be used on systems where legal permission has been granted.
"""

import sys
import os
import tempfile
import shutil
import logging
from pathlib import Path
from datetime import datetime
from concurrent.futures import ThreadPoolExecutor

from PyQt6.QtWidgets import (
    QApplication, QMainWindow, QWidget, QVBoxLayout, QHBoxLayout,
    QSplitter, QTabWidget, QTableWidget, QTableWidgetItem, QLabel,
    QPushButton, QProgressBar, QLineEdit, QStatusBar, QHeaderView,
    QListWidget, QListWidgetItem, QFrame, QScrollArea, QTextEdit,
    QComboBox, QDateEdit, QGroupBox, QFormLayout, QFileDialog,
    QMessageBox, QSizePolicy, QAbstractItemView, QMenu
)
from PyQt6.QtCore import (
    Qt, QThread, pyqtSignal, QTimer, QSortFilterProxyModel,
    QDate, QSize
)
from PyQt6.QtGui import (
    QFont, QColor, QPalette, QIcon, QAction, QBrush
)

# ─── Module imports ────────────────────────────────────────────────
import browser_detector as bd
import chromium_parser as cp
import firefox_parser as fp
import timeline_engine as te
import search_engine as se
import report_generator as rg
from hash_utility import sha256_file, acquisition_timestamp

# ─── Logging ───────────────────────────────────────────────────────
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
)
logger = logging.getLogger(__name__)

APP_VERSION = "1.0.0"
APP_NAME = "Browser Forensic Investigation Suite By Sajawal Hacke"

# ═══════════════════════════════════════════════════════════════════
# DARK THEME STYLESHEET
# ═══════════════════════════════════════════════════════════════════
DARK_STYLE = """
QMainWindow, QWidget {
    background-color: #0d1117;
    color: #e6edf3;
    font-family: 'Segoe UI', 'Consolas', monospace;
    font-size: 13px;
}
QSplitter::handle {
    background-color: #21262d;
    width: 2px;
}
/* ── Sidebar ── */
#sidebar {
    background-color: #161b22;
    border-right: 1px solid #21262d;
    min-width: 260px;
    max-width: 300px;
}
#sidebarHeader {
    background-color: #0d1117;
    padding: 10px;
    border-bottom: 1px solid #21262d;
}
QListWidget {
    background-color: #161b22;
    border: none;
    outline: none;
}
QListWidget::item {
    padding: 8px 12px;
    border-radius: 4px;
    margin: 2px 6px;
    color: #8b949e;
}
QListWidget::item:selected {
    background-color: #1f6feb;
    color: #ffffff;
}
QListWidget::item:hover:!selected {
    background-color: #21262d;
    color: #e6edf3;
}
/* ── Header ── */
#appHeader {
    background: qlineargradient(x1:0, y1:0, x2:1, y2:0,
        stop:0 #0d1117, stop:0.5 #1a2744, stop:1 #0d1117);
    border-bottom: 1px solid #1f6feb;
    padding: 12px 20px;
    min-height: 60px;
}
#appTitle {
    font-size: 18px;
    font-weight: bold;
    color: #58a6ff;
    letter-spacing: 1px;
}
#appSubtitle {
    font-size: 11px;
    color: #8b949e;
}
/* ── Tabs ── */
QTabWidget::pane {
    border: 1px solid #21262d;
    background-color: #0d1117;
}
QTabBar::tab {
    background-color: #161b22;
    color: #8b949e;
    padding: 8px 16px;
    border: 1px solid #21262d;
    border-bottom: none;
    margin-right: 2px;
    border-radius: 4px 4px 0 0;
}
QTabBar::tab:selected {
    background-color: #1f6feb;
    color: #ffffff;
    border-color: #1f6feb;
}
QTabBar::tab:hover:!selected {
    background-color: #21262d;
    color: #e6edf3;
}
/* ── Tables ── */
QTableWidget {
    background-color: #0d1117;
    gridline-color: #21262d;
    border: 1px solid #21262d;
    selection-background-color: #1f3a5f;
    alternate-background-color: #161b22;
    color: #e6edf3;
}
QTableWidget::item {
    padding: 4px 8px;
    border: none;
}
QTableWidget::item:selected {
    background-color: #1f3a5f;
    color: #e6edf3;
}
QHeaderView::section {
    background-color: #21262d;
    color: #8b949e;
    padding: 6px 8px;
    border: none;
    border-right: 1px solid #30363d;
    font-weight: bold;
    font-size: 12px;
}
QHeaderView::section:hover {
    background-color: #30363d;
}
/* ── Buttons ── */
QPushButton {
    background-color: #21262d;
    color: #e6edf3;
    border: 1px solid #30363d;
    padding: 7px 16px;
    border-radius: 6px;
    font-weight: bold;
}
QPushButton:hover {
    background-color: #30363d;
    border-color: #58a6ff;
}
QPushButton:pressed {
    background-color: #1f6feb;
}
QPushButton#scanBtn {
    background-color: #1f6feb;
    color: white;
    border-color: #388bfd;
    font-size: 13px;
    padding: 9px 24px;
}
QPushButton#scanBtn:hover {
    background-color: #388bfd;
}
QPushButton#exportBtn {
    background-color: #238636;
    color: white;
    border-color: #2ea043;
}
QPushButton#exportBtn:hover {
    background-color: #2ea043;
}
/* ── Search / LineEdit ── */
QLineEdit {
    background-color: #161b22;
    color: #e6edf3;
    border: 1px solid #30363d;
    padding: 7px 12px;
    border-radius: 6px;
    font-size: 13px;
}
QLineEdit:focus {
    border-color: #58a6ff;
    background-color: #1c2128;
}
/* ── Combobox ── */
QComboBox {
    background-color: #161b22;
    color: #e6edf3;
    border: 1px solid #30363d;
    padding: 5px 10px;
    border-radius: 6px;
}
QComboBox::drop-down {
    border: none;
}
QComboBox QAbstractItemView {
    background-color: #1c2128;
    color: #e6edf3;
    selection-background-color: #1f6feb;
    border: 1px solid #30363d;
}
/* ── Progress Bar ── */
QProgressBar {
    background-color: #21262d;
    border: 1px solid #30363d;
    border-radius: 4px;
    text-align: center;
    color: #e6edf3;
    font-size: 11px;
}
QProgressBar::chunk {
    background-color: #1f6feb;
    border-radius: 4px;
}
/* ── Status Bar ── */
QStatusBar {
    background-color: #161b22;
    color: #8b949e;
    border-top: 1px solid #21262d;
    font-size: 11px;
}
/* ── Group Box ── */
QGroupBox {
    border: 1px solid #21262d;
    border-radius: 6px;
    margin-top: 8px;
    padding-top: 8px;
    color: #58a6ff;
    font-weight: bold;
}
QGroupBox::title {
    subcontrol-origin: margin;
    subcontrol-position: top left;
    padding: 0 6px;
    color: #58a6ff;
}
/* ── Scroll Bars ── */
QScrollBar:vertical {
    background: #161b22;
    width: 8px;
    border: none;
}
QScrollBar::handle:vertical {
    background: #30363d;
    border-radius: 4px;
    min-height: 20px;
}
QScrollBar::handle:vertical:hover {
    background: #58a6ff;
}
QScrollBar::add-line:vertical, QScrollBar::sub-line:vertical { height: 0px; }
QScrollBar:horizontal {
    background: #161b22;
    height: 8px;
    border: none;
}
QScrollBar::handle:horizontal {
    background: #30363d;
    border-radius: 4px;
    min-width: 20px;
}
QScrollBar::handle:horizontal:hover {
    background: #58a6ff;
}
QScrollBar::add-line:horizontal, QScrollBar::sub-line:horizontal { width: 0px; }
/* ── TextEdit ── */
QTextEdit {
    background-color: #161b22;
    color: #e6edf3;
    border: 1px solid #21262d;
    font-family: 'Consolas', monospace;
    font-size: 12px;
}
/* ── Date Edit ── */
QDateEdit {
    background-color: #161b22;
    color: #e6edf3;
    border: 1px solid #30363d;
    padding: 5px 10px;
    border-radius: 6px;
}
/* ── Frames ── */
QFrame#card {
    background-color: #161b22;
    border: 1px solid #21262d;
    border-radius: 8px;
    padding: 12px;
}
/* ── Labels ── */
QLabel#statValue {
    font-size: 22px;
    font-weight: bold;
    color: #58a6ff;
}
QLabel#statLabel {
    font-size: 11px;
    color: #8b949e;
}
QLabel#sectionTitle {
    font-size: 14px;
    font-weight: bold;
    color: #e6edf3;
    padding: 8px 0;
}
/* ── Tool Tip ── */
QToolTip {
    background-color: #1c2128;
    color: #e6edf3;
    border: 1px solid #30363d;
    padding: 4px 8px;
    border-radius: 4px;
}
"""

# ═══════════════════════════════════════════════════════════════════
# WORKER THREAD
# ═══════════════════════════════════════════════════════════════════
class ScanWorker(QThread):
    progress = pyqtSignal(int, str)
    browser_found = pyqtSignal(str, object)   # name, BrowserInfo
    artifact_ready = pyqtSignal(str, list)    # type, data
    finished = pyqtSignal()
    error = pyqtSignal(str)

    def __init__(self, selected_browser: str = None, browser_info=None, tmp_dir: Path = None):
        super().__init__()
        self.selected_browser = selected_browser
        self.browser_info = browser_info
        self.tmp_dir = tmp_dir

    def run(self):
        try:
            if self.selected_browser is None:
                # Full detection scan
                self.progress.emit(10, "Detecting installed browsers...")
                browsers = bd.detect_all_browsers()
                total = len(browsers)
                for i, (name, info) in enumerate(browsers.items()):
                    self.progress.emit(10 + int(80 * i / total), f"Scanning: {name}")
                    self.browser_found.emit(name, info)
                self.progress.emit(100, "Detection complete.")
            else:
                # Deep scan for selected browser
                info = self.browser_info
                if not info or not info.detected:
                    self.finished.emit()
                    return

                self.progress.emit(5, "Creating forensic copies...")
                all_history, all_downloads, all_cookies, all_extensions = [], [], [], []
                all_logins = []

                profiles = info.profiles
                total = max(len(profiles), 1)

                for i, profile in enumerate(profiles):
                    pct = 10 + int(75 * i / total)
                    self.progress.emit(pct, f"Parsing profile: {profile.name}")

                    if info.browser_type == "chromium":
                        all_history += cp.parse_history(profile.path, info.name, profile.name, self.tmp_dir)
                        all_downloads += cp.parse_downloads(profile.path, info.name, profile.name, self.tmp_dir)
                        all_cookies += cp.parse_cookies(profile.path, info.name, profile.name, self.tmp_dir)
                        all_extensions += cp.parse_extensions(profile.path, info.name, profile.name)
                        if info.user_data_path:
                            all_logins += cp.get_login_databases(profile.path, info.user_data_path)
                    else:
                        all_history += fp.parse_history(profile.path, info.name, profile.name, self.tmp_dir)
                        all_downloads += fp.parse_downloads(profile.path, info.name, profile.name, self.tmp_dir)
                        all_cookies += fp.parse_cookies(profile.path, info.name, profile.name, self.tmp_dir)
                        all_extensions += fp.parse_extensions(profile.path, info.name, profile.name)
                        all_logins += fp.get_login_databases(profile.path)

                self.progress.emit(90, "Building timeline...")
                self.artifact_ready.emit("history", all_history)
                self.artifact_ready.emit("downloads", all_downloads)
                self.artifact_ready.emit("cookies", all_cookies)
                self.artifact_ready.emit("extensions", all_extensions)
                self.artifact_ready.emit("logins", all_logins)

                timeline = te.build_timeline(all_history, all_downloads)
                self.artifact_ready.emit("timeline", timeline)

                self.progress.emit(100, "Scan complete.")
        except Exception as e:
            logger.exception("Scan worker error")
            self.error.emit(str(e))
        finally:
            self.finished.emit()


# ═══════════════════════════════════════════════════════════════════
# HELPER: Build a styled table widget
# ═══════════════════════════════════════════════════════════════════
def make_table(headers: list) -> QTableWidget:
    t = QTableWidget()
    t.setColumnCount(len(headers))
    t.setHorizontalHeaderLabels(headers)
    t.setAlternatingRowColors(True)
    t.setSelectionBehavior(QAbstractItemView.SelectionBehavior.SelectRows)
    t.setEditTriggers(QAbstractItemView.EditTrigger.NoEditTriggers)
    t.horizontalHeader().setStretchLastSection(True)
    t.horizontalHeader().setSectionResizeMode(QHeaderView.ResizeMode.Interactive)
    t.verticalHeader().setVisible(False)
    t.setSortingEnabled(True)
    t.setShowGrid(True)
    return t


def fill_table(table: QTableWidget, data: list, keys: list):
    table.setSortingEnabled(False)
    table.setRowCount(len(data))
    for row, record in enumerate(data):
        for col, key in enumerate(keys):
            val = str(record.get(key, ""))
            item = QTableWidgetItem(val)
            item.setFlags(item.flags() & ~Qt.ItemFlag.ItemIsEditable)
            table.setItem(row, col, item)
    table.setSortingEnabled(True)
    table.resizeColumnsToContents()


# ═══════════════════════════════════════════════════════════════════
# BROWSER LIST ITEM WIDGET
# ═══════════════════════════════════════════════════════════════════
class BrowserListItem(QWidget):
    def __init__(self, info: bd.BrowserInfo, parent=None):
        super().__init__(parent)
        layout = QVBoxLayout(self)
        layout.setContentsMargins(4, 4, 4, 4)
        layout.setSpacing(2)

        name_layout = QHBoxLayout()
        name_lbl = QLabel(info.name)
        name_lbl.setFont(QFont("Segoe UI", 11, QFont.Weight.Bold))
        name_lbl.setStyleSheet("color: #e6edf3;")

        status_dot = QLabel("●")
        if info.detected:
            status_dot.setStyleSheet("color: #3fb950; font-size: 10px;")
            status_dot.setToolTip("Detected")
        else:
            status_dot.setStyleSheet("color: #6e7681; font-size: 10px;")
            status_dot.setToolTip("Not Found")
        name_layout.addWidget(status_dot)
        name_layout.addWidget(name_lbl)
        name_layout.addStretch()
        layout.addLayout(name_layout)

        detail = f"v{info.version}  ·  {info.profile_count} profile(s)"
        detail_lbl = QLabel(detail)
        detail_lbl.setStyleSheet("color: #8b949e; font-size: 11px;")
        layout.addWidget(detail_lbl)


# ═══════════════════════════════════════════════════════════════════
# OVERVIEW TAB
# ═══════════════════════════════════════════════════════════════════
class OverviewTab(QWidget):
    def __init__(self, parent=None):
        super().__init__(parent)
        layout = QVBoxLayout(self)
        layout.setSpacing(16)
        layout.setContentsMargins(16, 16, 16, 16)

        self.form = QFormLayout()
        self.form.setLabelAlignment(Qt.AlignmentFlag.AlignRight)
        self.form.setHorizontalSpacing(20)
        self.form.setVerticalSpacing(10)

        self.fields = {}
        for label in ["Browser Name", "Version", "Vendor", "Browser Type",
                       "Install Path", "User Data Path", "Profile Count", "Last Activity"]:
            val = QLabel("—")
            val.setStyleSheet("color: #58a6ff;")
            val.setTextInteractionFlags(Qt.TextInteractionFlag.TextSelectableByMouse)
            lbl = QLabel(label + ":")
            lbl.setStyleSheet("color: #8b949e;")
            self.form.addRow(lbl, val)
            self.fields[label] = val

        box = QGroupBox("Browser Information")
        box.setLayout(self.form)
        layout.addWidget(box)
        layout.addStretch()

    def populate(self, info: bd.BrowserInfo):
        self.fields["Browser Name"].setText(info.name)
        self.fields["Version"].setText(info.version)
        self.fields["Vendor"].setText(info.vendor)
        self.fields["Browser Type"].setText(info.browser_type.capitalize())
        self.fields["Install Path"].setText(str(info.executable_path or "Not found"))
        self.fields["User Data Path"].setText(str(info.user_data_path or "Not found"))
        self.fields["Profile Count"].setText(str(info.profile_count))
        self.fields["Last Activity"].setText("—")


# ═══════════════════════════════════════════════════════════════════
# PROFILES TAB
# ═══════════════════════════════════════════════════════════════════
class ProfilesTab(QWidget):
    def __init__(self, parent=None):
        super().__init__(parent)
        layout = QVBoxLayout(self)
        layout.setContentsMargins(12, 12, 12, 12)
        self.table = make_table(["Profile Name", "Profile Path", "Last Used", "Account Email"])
        layout.addWidget(self.table)

    def populate(self, profiles: list):
        self.table.setRowCount(len(profiles))
        for row, p in enumerate(profiles):
            for col, val in enumerate([p.name, str(p.path), p.last_used or "—", p.email or "—"]):
                item = QTableWidgetItem(val)
                item.setFlags(item.flags() & ~Qt.ItemFlag.ItemIsEditable)
                self.table.setItem(row, col, item)
        self.table.resizeColumnsToContents()


# ═══════════════════════════════════════════════════════════════════
# LOGIN DB TAB
# ═══════════════════════════════════════════════════════════════════
class LoginDbTab(QWidget):
    def __init__(self, parent=None):
        super().__init__(parent)
        layout = QVBoxLayout(self)
        layout.setContentsMargins(12, 12, 12, 12)

        info_lbl = QLabel("⚠  Forensic-safe read-only access. Original files are never modified.")
        info_lbl.setStyleSheet("color: #f0883e; background: #2d1b00; padding: 8px 12px; border-radius: 6px;")
        layout.addWidget(info_lbl)

        self.table = make_table(["Database Name", "Database Path", "Encryption Status",
                                  "Last Modified", "Size (bytes)"])
        layout.addWidget(self.table)

    def populate(self, logins: list):
        self.table.setRowCount(len(logins))
        for row, db in enumerate(logins):
            vals = [db.get("name",""), db.get("path",""), db.get("encryption",""),
                    db.get("last_modified",""), str(db.get("size",""))]
            for col, v in enumerate(vals):
                item = QTableWidgetItem(v)
                item.setFlags(item.flags() & ~Qt.ItemFlag.ItemIsEditable)
                self.table.setItem(row, col, item)
        self.table.resizeColumnsToContents()


# ═══════════════════════════════════════════════════════════════════
# HISTORY TAB
# ═══════════════════════════════════════════════════════════════════
class HistoryTab(QWidget):
    def __init__(self, parent=None):
        super().__init__(parent)
        layout = QVBoxLayout(self)
        layout.setContentsMargins(12, 8, 12, 12)
        layout.setSpacing(8)

        # Search bar
        search_row = QHBoxLayout()
        self.search_edit = QLineEdit()
        self.search_edit.setPlaceholderText("🔍  Search URL, title, keyword...")
        self.search_edit.textChanged.connect(self._filter)

        self.count_lbl = QLabel("0 records")
        self.count_lbl.setStyleSheet("color: #8b949e; min-width: 90px;")

        search_row.addWidget(self.search_edit)
        search_row.addWidget(self.count_lbl)
        layout.addLayout(search_row)

        self.table = make_table(["Browser", "Profile", "URL", "Title",
                                  "Visit Count", "Date", "Time", "Source DB"])
        layout.addWidget(self.table)

        self._data = []

    def populate(self, records: list):
        self._data = records
        self._render(records)

    def _filter(self):
        q = self.search_edit.text().strip().lower()
        if not q:
            self._render(self._data)
            return
        filtered = [r for r in self._data
                    if q in r.get("url","").lower() or q in r.get("title","").lower()]
        self._render(filtered)

    def _render(self, records):
        keys = ["browser","profile","url","title","visit_count","visit_date","visit_time","source_db"]
        fill_table(self.table, records, keys)
        self.count_lbl.setText(f"{len(records):,} records")


# ═══════════════════════════════════════════════════════════════════
# DOWNLOADS TAB
# ═══════════════════════════════════════════════════════════════════
class DownloadsTab(QWidget):
    def __init__(self, parent=None):
        super().__init__(parent)
        layout = QVBoxLayout(self)
        layout.setContentsMargins(12, 12, 12, 12)
        self.table = make_table(["File Name", "Download URL", "Download Time",
                                  "Save Path", "Browser", "Profile"])
        layout.addWidget(self.table)

    def populate(self, records: list):
        keys = ["file_name","download_url","download_time","save_path","browser","profile"]
        fill_table(self.table, records, keys)


# ═══════════════════════════════════════════════════════════════════
# COOKIES TAB
# ═══════════════════════════════════════════════════════════════════
class CookiesTab(QWidget):
    def __init__(self, parent=None):
        super().__init__(parent)
        layout = QVBoxLayout(self)
        layout.setContentsMargins(12, 8, 12, 12)
        layout.setSpacing(8)

        search_row = QHBoxLayout()
        self.search_edit = QLineEdit()
        self.search_edit.setPlaceholderText("🔍  Filter by domain or name...")
        self.search_edit.textChanged.connect(self._filter)
        self.count_lbl = QLabel("0 records")
        self.count_lbl.setStyleSheet("color: #8b949e;")
        search_row.addWidget(self.search_edit)
        search_row.addWidget(self.count_lbl)
        layout.addLayout(search_row)

        self.table = make_table(["Domain", "Cookie Name", "Creation Time", "Expiry Time", "Browser", "Profile"])
        layout.addWidget(self.table)
        self._data = []

    def populate(self, records: list):
        self._data = records
        self._render(records)

    def _filter(self):
        q = self.search_edit.text().strip().lower()
        if not q:
            self._render(self._data)
            return
        filtered = [r for r in self._data
                    if q in r.get("domain","").lower() or q in r.get("name","").lower()]
        self._render(filtered)

    def _render(self, records):
        keys = ["domain","name","creation_time","expiry_time","browser","profile"]
        fill_table(self.table, records, keys)
        self.count_lbl.setText(f"{len(records):,} cookies")


# ═══════════════════════════════════════════════════════════════════
# EXTENSIONS TAB
# ═══════════════════════════════════════════════════════════════════
class ExtensionsTab(QWidget):
    def __init__(self, parent=None):
        super().__init__(parent)
        layout = QVBoxLayout(self)
        layout.setContentsMargins(12, 12, 12, 12)
        self.table = make_table(["Extension Name", "Version", "Permissions",
                                  "Install Time", "Browser", "Profile"])
        layout.addWidget(self.table)

    def populate(self, records: list):
        keys = ["name","version","permissions","install_time","browser","profile"]
        fill_table(self.table, records, keys)


# ═══════════════════════════════════════════════════════════════════
# TIMELINE TAB
# ═══════════════════════════════════════════════════════════════════
class TimelineTab(QWidget):
    def __init__(self, parent=None):
        super().__init__(parent)
        layout = QVBoxLayout(self)
        layout.setContentsMargins(12, 8, 12, 12)
        layout.setSpacing(8)

        filter_row = QHBoxLayout()
        self.kw_edit = QLineEdit()
        self.kw_edit.setPlaceholderText("🔍  Keyword filter...")
        self.kw_edit.textChanged.connect(self._filter)

        self.browser_combo = QComboBox()
        self.browser_combo.addItem("All Browsers")
        self.browser_combo.currentTextChanged.connect(self._filter)

        self.type_combo = QComboBox()
        self.type_combo.addItems(["All Types", "Visit", "Download"])
        self.type_combo.currentTextChanged.connect(self._filter)

        self.count_lbl = QLabel("0 events")
        self.count_lbl.setStyleSheet("color: #8b949e;")

        filter_row.addWidget(QLabel("Filter:"))
        filter_row.addWidget(self.kw_edit, 3)
        filter_row.addWidget(self.browser_combo, 2)
        filter_row.addWidget(self.type_combo, 1)
        filter_row.addWidget(self.count_lbl)
        layout.addLayout(filter_row)

        self.table = make_table(["Timestamp", "Type", "Browser", "Profile", "Detail", "Title"])
        layout.addWidget(self.table)
        self._data = []

    def populate(self, events: list):
        self._data = events
        # Update browser combo
        browsers = sorted(set(e.get("browser","") for e in events))
        self.browser_combo.blockSignals(True)
        self.browser_combo.clear()
        self.browser_combo.addItem("All Browsers")
        for b in browsers:
            if b:
                self.browser_combo.addItem(b)
        self.browser_combo.blockSignals(False)
        self._render(events)

    def _filter(self):
        kw = self.kw_edit.text().strip().lower()
        browser = self.browser_combo.currentText()
        typ = self.type_combo.currentText()

        filtered = self._data
        if kw:
            filtered = [e for e in filtered
                        if kw in e.get("detail","").lower() or kw in e.get("title","").lower()]
        if browser != "All Browsers":
            filtered = [e for e in filtered if e.get("browser") == browser]
        if typ != "All Types":
            filtered = [e for e in filtered if e.get("type") == typ]

        self._render(filtered)

    def _render(self, events):
        keys = ["timestamp","type","browser","profile","detail","title"]
        fill_table(self.table, events, keys)
        self.count_lbl.setText(f"{len(events):,} events")


# ═══════════════════════════════════════════════════════════════════
# INVESTIGATION PANEL (right side with all tabs)
# ═══════════════════════════════════════════════════════════════════
class InvestigationPanel(QWidget):
    def __init__(self, parent=None):
        super().__init__(parent)
        layout = QVBoxLayout(self)
        layout.setContentsMargins(0, 0, 0, 0)
        layout.setSpacing(0)

        # Browser header bar
        self.header_bar = QFrame()
        self.header_bar.setStyleSheet("background: #161b22; border-bottom: 1px solid #21262d;")
        hbar_layout = QHBoxLayout(self.header_bar)
        hbar_layout.setContentsMargins(16, 10, 16, 10)
        self.browser_lbl = QLabel("Select a browser from the sidebar")
        self.browser_lbl.setStyleSheet("color: #8b949e; font-size: 13px;")
        self.scan_btn = QPushButton("⚡  Deep Scan")
        self.scan_btn.setObjectName("scanBtn")
        self.scan_btn.setEnabled(False)
        hbar_layout.addWidget(self.browser_lbl)
        hbar_layout.addStretch()
        hbar_layout.addWidget(self.scan_btn)
        layout.addWidget(self.header_bar)

        # Progress bar
        self.progress = QProgressBar()
        self.progress.setFixedHeight(4)
        self.progress.setTextVisible(False)
        self.progress.setRange(0, 100)
        self.progress.setValue(0)
        self.progress.setStyleSheet("QProgressBar { border: none; border-radius: 0; } "
                                     "QProgressBar::chunk { background: #1f6feb; }")
        layout.addWidget(self.progress)

        # Tabs
        self.tabs = QTabWidget()
        self.tab_overview = OverviewTab()
        self.tab_profiles = ProfilesTab()
        self.tab_logins = LoginDbTab()
        self.tab_history = HistoryTab()
        self.tab_downloads = DownloadsTab()
        self.tab_cookies = CookiesTab()
        self.tab_extensions = ExtensionsTab()
        self.tab_timeline = TimelineTab()

        self.tabs.addTab(self.tab_overview, "📋 Overview")
        self.tabs.addTab(self.tab_profiles, "👤 Profiles")
        self.tabs.addTab(self.tab_logins, "🔐 Login Databases")
        self.tabs.addTab(self.tab_history, "🕐 History")
        self.tabs.addTab(self.tab_downloads, "⬇ Downloads")
        self.tabs.addTab(self.tab_cookies, "🍪 Cookies")
        self.tabs.addTab(self.tab_extensions, "🧩 Extensions")
        self.tabs.addTab(self.tab_timeline, "📊 Timeline")
        layout.addWidget(self.tabs)


# ═══════════════════════════════════════════════════════════════════
# MAIN WINDOW
# ═══════════════════════════════════════════════════════════════════
class MainWindow(QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle(APP_NAME)
        self.setMinimumSize(1200, 750)
        self.resize(1440, 860)

        # Forensic temp directory
        self.tmp_dir = Path(tempfile.mkdtemp(prefix="bfis_"))
        self.browsers: dict = {}
        self.current_browser: str = None
        self.worker: ScanWorker = None
        self.scan_start_time = None

        # Evidence hashes dict
        self.evidence_hashes = {}

        self._build_ui()
        self._apply_style()
        self._connect_signals()
        self._initial_scan()

    def _build_ui(self):
        central = QWidget()
        self.setCentralWidget(central)
        root = QVBoxLayout(central)
        root.setContentsMargins(0, 0, 0, 0)
        root.setSpacing(0)

        # Header
        header = QFrame()
        header.setObjectName("appHeader")
        header.setFixedHeight(66)
        h_layout = QHBoxLayout(header)
        h_layout.setContentsMargins(20, 0, 20, 0)

        icon_lbl = QLabel("🔬")
        icon_lbl.setFont(QFont("Segoe UI Emoji", 22))
        h_layout.addWidget(icon_lbl)

        title_block = QVBoxLayout()
        title_block.setSpacing(0)
        title_lbl = QLabel(APP_NAME)
        title_lbl.setObjectName("appTitle")
        subtitle_lbl = QLabel(f"Digital Forensics & Incident Response  ·  v{APP_VERSION}  ·  Authorized Use Only")
        subtitle_lbl.setObjectName("appSubtitle")
        title_block.addWidget(title_lbl)
        title_block.addWidget(subtitle_lbl)
        h_layout.addLayout(title_block)
        h_layout.addStretch()

        # Export buttons in header
        self.export_csv_btn = QPushButton("📄 CSV")
        self.export_json_btn = QPushButton("📦 JSON")
        self.export_pdf_btn = QPushButton("📑 PDF")
        for btn in [self.export_csv_btn, self.export_json_btn, self.export_pdf_btn]:
            btn.setObjectName("exportBtn")
            btn.setFixedHeight(32)
            h_layout.addWidget(btn)

        root.addWidget(header)

        # Body splitter
        self.splitter = QSplitter(Qt.Orientation.Horizontal)
        root.addWidget(self.splitter, 1)

        # ── Sidebar ──────────────────────────────────────────
        sidebar = QFrame()
        sidebar.setObjectName("sidebar")
        sidebar_layout = QVBoxLayout(sidebar)
        sidebar_layout.setContentsMargins(0, 0, 0, 0)
        sidebar_layout.setSpacing(0)

        sidebar_header = QFrame()
        sidebar_header.setObjectName("sidebarHeader")
        sh_layout = QVBoxLayout(sidebar_header)
        sh_layout.setContentsMargins(12, 8, 12, 8)
        sh_layout.setSpacing(6)

        browsers_lbl = QLabel("DETECTED BROWSERS")
        browsers_lbl.setStyleSheet("color: #8b949e; font-size: 11px; font-weight: bold; letter-spacing: 1px;")
        sh_layout.addWidget(browsers_lbl)

        self.rescan_btn = QPushButton("↺  Rescan")
        self.rescan_btn.setFixedHeight(28)
        sh_layout.addWidget(self.rescan_btn)

        sidebar_layout.addWidget(sidebar_header)

        self.browser_list = QListWidget()
        self.browser_list.setSpacing(2)
        sidebar_layout.addWidget(self.browser_list, 1)

        # Summary stats at bottom of sidebar
        stats_frame = QFrame()
        stats_frame.setStyleSheet("background: #0d1117; border-top: 1px solid #21262d;")
        stats_layout = QHBoxLayout(stats_frame)
        stats_layout.setContentsMargins(12, 8, 12, 8)
        self.total_browsers_lbl = QLabel("0 browsers")
        self.total_browsers_lbl.setStyleSheet("color: #58a6ff; font-size: 11px;")
        self.total_profiles_lbl = QLabel("0 profiles")
        self.total_profiles_lbl.setStyleSheet("color: #3fb950; font-size: 11px;")
        stats_layout.addWidget(self.total_browsers_lbl)
        stats_layout.addStretch()
        stats_layout.addWidget(self.total_profiles_lbl)
        sidebar_layout.addWidget(stats_frame)

        self.splitter.addWidget(sidebar)

        # ── Main Investigation Area ───────────────────────────
        self.investigation = InvestigationPanel()
        self.splitter.addWidget(self.investigation)

        self.splitter.setSizes([270, 1100])
        self.splitter.setStretchFactor(1, 1)

        # ── Status Bar ────────────────────────────────────────
        self.status_bar = QStatusBar()
        self.setStatusBar(self.status_bar)
        self.status_bar.showMessage("Ready  ·  DFIR Mode  ·  Forensic-safe read-only access")

        # Progress label in status bar
        self.progress_status = QLabel("")
        self.progress_status.setStyleSheet("color: #58a6ff;")
        self.status_bar.addPermanentWidget(self.progress_status)

        # Timestamp label
        self.ts_lbl = QLabel(f"Acquisition: {acquisition_timestamp()}")
        self.ts_lbl.setStyleSheet("color: #8b949e; font-size: 11px;")
        self.status_bar.addPermanentWidget(self.ts_lbl)

    def _apply_style(self):
        self.setStyleSheet(DARK_STYLE)

    def _connect_signals(self):
        self.browser_list.currentItemChanged.connect(self._on_browser_selected)
        self.investigation.scan_btn.clicked.connect(self._deep_scan)
        self.rescan_btn.clicked.connect(self._initial_scan)
        self.export_csv_btn.clicked.connect(lambda: self._export("csv"))
        self.export_json_btn.clicked.connect(lambda: self._export("json"))
        self.export_pdf_btn.clicked.connect(lambda: self._export("pdf"))

    def _initial_scan(self):
        """Run browser detection scan."""
        self.browser_list.clear()
        self.browsers.clear()
        self.rescan_btn.setEnabled(False)
        self.investigation.progress.setValue(0)
        self.status_bar.showMessage("Scanning for installed browsers...")

        worker = ScanWorker()
        worker.progress.connect(self._on_progress)
        worker.browser_found.connect(self._on_browser_found)
        worker.finished.connect(self._on_detection_done)
        worker.error.connect(self._on_error)
        self.worker = worker
        worker.start()

    def _deep_scan(self):
        if not self.current_browser:
            return
        info = self.browsers.get(self.current_browser)
        if not info or not info.detected:
            QMessageBox.warning(self, "Not Found", f"{self.current_browser} was not detected on this system.")
            return

        self.investigation.scan_btn.setEnabled(False)
        self.investigation.progress.setValue(0)
        self.status_bar.showMessage(f"Deep scanning: {self.current_browser}...")
        self.scan_start_time = datetime.utcnow()

        # Clear previous data
        self.investigation.tab_history.populate([])
        self.investigation.tab_downloads.populate([])
        self.investigation.tab_cookies.populate([])
        self.investigation.tab_extensions.populate([])
        self.investigation.tab_logins.populate([])
        self.investigation.tab_timeline.populate([])

        worker = ScanWorker(
            selected_browser=self.current_browser,
            browser_info=info,
            tmp_dir=self.tmp_dir,
        )
        worker.progress.connect(self._on_progress)
        worker.artifact_ready.connect(self._on_artifact_ready)
        worker.finished.connect(self._on_deep_scan_done)
        worker.error.connect(self._on_error)
        self.worker = worker
        worker.start()

    def _on_browser_found(self, name: str, info):
        self.browsers[name] = info

        item = QListWidgetItem(self.browser_list)
        widget = BrowserListItem(info)
        item.setSizeHint(widget.sizeHint() + QSize(0, 12))
        item.setData(Qt.ItemDataRole.UserRole, name)
        self.browser_list.addItem(item)
        self.browser_list.setItemWidget(item, widget)

        if not info.detected:
            item.setFlags(item.flags() & ~Qt.ItemFlag.ItemIsEnabled)

    def _on_detection_done(self):
        detected = sum(1 for b in self.browsers.values() if b.detected)
        total_profiles = sum(b.profile_count for b in self.browsers.values())
        self.total_browsers_lbl.setText(f"{detected} detected")
        self.total_profiles_lbl.setText(f"{total_profiles} profiles")
        self.rescan_btn.setEnabled(True)
        self.status_bar.showMessage(f"Detection complete  ·  {detected} browser(s) found  ·  {total_profiles} profile(s)")
        self.investigation.progress.setValue(0)

    def _on_artifact_ready(self, artifact_type: str, data: list):
        if artifact_type == "history":
            self.investigation.tab_history.populate(data)
        elif artifact_type == "downloads":
            self.investigation.tab_downloads.populate(data)
        elif artifact_type == "cookies":
            self.investigation.tab_cookies.populate(data)
        elif artifact_type == "extensions":
            self.investigation.tab_extensions.populate(data)
        elif artifact_type == "logins":
            self.investigation.tab_logins.populate(data)
        elif artifact_type == "timeline":
            self.investigation.tab_timeline.populate(data)

    def _on_deep_scan_done(self):
        self.investigation.scan_btn.setEnabled(True)
        elapsed = ""
        if self.scan_start_time:
            secs = (datetime.utcnow() - self.scan_start_time).total_seconds()
            elapsed = f"  ·  {secs:.1f}s"
        self.status_bar.showMessage(f"Deep scan complete: {self.current_browser}{elapsed}")

    def _on_progress(self, value: int, message: str):
        self.investigation.progress.setValue(value)
        self.progress_status.setText(message)

    def _on_error(self, msg: str):
        self.status_bar.showMessage(f"Error: {msg}")
        logger.error(f"Worker error: {msg}")
        self.investigation.scan_btn.setEnabled(True)

    def _on_browser_selected(self, current, previous):
        if not current:
            return
        name = current.data(Qt.ItemDataRole.UserRole)
        if not name:
            return
        self.current_browser = name
        info = self.browsers.get(name)
        if not info:
            return

        self.investigation.browser_lbl.setText(
            f"🌐  {info.name}  ·  {info.vendor}  ·  v{info.version}  ·  {info.profile_count} profile(s)"
        )
        self.investigation.scan_btn.setEnabled(info.detected)
        self.investigation.tab_overview.populate(info)
        self.investigation.tab_profiles.populate(info.profiles)

    def _export(self, fmt: str):
        if not self.current_browser:
            QMessageBox.information(self, "No Browser Selected", "Select a browser and run a deep scan first.")
            return

        ts = datetime.now().strftime("%Y%m%d_%H%M%S")
        default_name = f"bfis_report_{self.current_browser.replace(' ','_')}_{ts}.{fmt}"
        file_filter = {
            "csv": "CSV Files (*.csv)",
            "json": "JSON Files (*.json)",
            "pdf": "PDF Files (*.pdf)",
        }.get(fmt, "All Files (*)")

        path, _ = QFileDialog.getSaveFileName(self, "Export Report", default_name, file_filter)
        if not path:
            return

        path = Path(path)
        try:
            # Gather current data
            hist_tab = self.investigation.tab_history
            dl_tab = self.investigation.tab_downloads
            data = {
                "history": hist_tab._data,
                "downloads": dl_tab._data,
            }
            if fmt == "csv":
                rg.export_csv(hist_tab._data, path, "history")
            elif fmt == "json":
                rg.export_json(data, path)
            elif fmt == "pdf":
                rg.export_pdf(data, path, self.evidence_hashes)

            QMessageBox.information(self, "Export Complete", f"Report saved to:\n{path}")
            self.status_bar.showMessage(f"Exported: {path}")
        except Exception as e:
            QMessageBox.critical(self, "Export Error", str(e))

    def closeEvent(self, event):
        """Clean up forensic temp files on exit."""
        try:
            if self.tmp_dir.exists():
                shutil.rmtree(self.tmp_dir)
                logger.info(f"Cleaned up temp dir: {self.tmp_dir}")
        except Exception as e:
            logger.warning(f"Cleanup error: {e}")
        event.accept()


# ═══════════════════════════════════════════════════════════════════
# ENTRY POINT
# ═══════════════════════════════════════════════════════════════════
def main():
    app = QApplication(sys.argv)
    app.setApplicationName(APP_NAME)
    app.setApplicationVersion(APP_VERSION)
    app.setOrganizationName("DFIR Suite")

    # High-DPI
    # app.setAttribute(Qt.ApplicationAttribute.AA_UseHighDpiPixmaps, True)

    window = MainWindow()
    window.show()
    sys.exit(app.exec())


if __name__ == "__main__":
    main()
