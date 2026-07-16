"""The overview page: headline tiles, risk gauge, and top findings."""

from __future__ import annotations

from typing import List

from PyQt6.QtCore import Qt
from PyQt6.QtWidgets import (
    QGridLayout, QHBoxLayout, QLabel, QVBoxLayout, QWidget,
)

from ..model import Category, Severity
from . import theme
from .widgets import Card, FindingBlock, RiskGauge, SeverityLegend, Tile


def _find(categories: List[Category], key: str):
    for c in categories:
        if c.key == key:
            return c
    return None


def _kv(cat: Category, section_title: str, key: str, default: str = "—") -> str:
    if not cat:
        return default
    for s in cat.sections:
        if s.title != section_title:
            continue
        for k, v in s.rows:
            if k == key:
                return v or default
    return default


def _table_len(cat: Category, section_title: str) -> int:
    if not cat:
        return 0
    for s in cat.sections:
        if s.title == section_title:
            return len(s.table_rows)
    return 0


class Dashboard(QWidget):
    """Answers 'what am I looking at, and how bad is it' without scrolling."""

    def __init__(self, categories: List[Category], parent=None):
        super().__init__(parent)
        v = QVBoxLayout(self)
        v.setContentsMargins(0, 0, 0, 0)
        v.setSpacing(14)

        system = _find(categories, "system")
        hardware = _find(categories, "hardware")
        users = _find(categories, "users")
        network = _find(categories, "network")
        software = _find(categories, "software")
        processes = _find(categories, "processes")
        audit = _find(categories, "audit")

        counts = {s.value: 0 for s in Severity}
        for c in categories:
            for f in c.findings:
                counts[f.severity.value] += 1

        # --- headline tiles -------------------------------------------------
        tiles = QGridLayout()
        tiles.setSpacing(12)

        model = _kv(hardware, "Machine", "Model Name", "Mac")
        chip = _kv(hardware, "Machine", "Chip", "—")
        os_ver = _kv(system, "Operating System", "Version", "—")
        codename = _kv(system, "Operating System", "Codename", "")
        memory = _kv(hardware, "Machine", "Memory", "—")
        uptime = _kv(system, "Boot & Runtime", "Uptime", "—")

        admin_count = 0
        if users:
            for s in users.sections:
                if s.title == "User Accounts":
                    idx = s.headers.index("Admin") if "Admin" in s.headers else -1
                    if idx >= 0:
                        admin_count = sum(
                            1 for r in s.table_rows
                            if len(r) > idx and r[idx] == "Yes")

        exposed = 0
        if network:
            for s in network.sections:
                if s.title == "Listening Ports":
                    idx = (s.headers.index("Exposure")
                           if "Exposure" in s.headers else -1)
                    if idx >= 0:
                        exposed = sum(
                            1 for r in s.table_rows
                            if len(r) > idx and r[idx] == "All interfaces")

        flagged = 0
        if processes:
            for s in processes.sections:
                if s.title == "Third-Party Launch Items":
                    idx = s.headers.index("Flag") if "Flag" in s.headers else -1
                    if idx >= 0:
                        flagged = sum(
                            1 for r in s.table_rows
                            if len(r) > idx and r[idx].startswith("⚠"))

        fv = _kv(system, "Security Posture", "FileVault", "—")
        sip = _kv(system, "Security Posture", "System Integrity Protection", "—")

        specs = [
            ("🖥", model, "Machine", f"{chip} · {memory}", None),
            ("🍎", f"macOS {os_ver}", codename or "Version", f"Up {uptime}", None),
            ("🔒", fv, "FileVault",
             "Disk encryption at rest",
             theme.GOOD if fv == "On" else theme.SEVERITY["High"]),
            ("🛡", sip, "SIP",
             "System Integrity Protection",
             theme.GOOD if sip == "Enabled" else theme.SEVERITY["Critical"]),
            ("👤", str(admin_count), "Admin accounts",
             "Each is a path to root",
             theme.WARN if admin_count > 2 else None),
            ("📡", str(exposed), "Exposed services",
             "Listening on all interfaces",
             theme.WARN if exposed else theme.GOOD),
            ("⚡", str(flagged), "Flagged launch items",
             "Suspicious persistence",
             theme.SEVERITY["High"] if flagged else theme.GOOD),
            ("📦", str(_table_len(software, "Applications")), "Applications",
             f"{_table_len(software, 'Unsigned & Quarantined')} unsigned/quarantined",
             None),
        ]
        for i, (icon, val, label, sub, color) in enumerate(specs):
            tiles.addWidget(Tile(icon, val, label, sub, color), i // 4, i % 4)
        v.addLayout(tiles)

        # --- risk + top findings ----------------------------------------------
        mid = QHBoxLayout()
        mid.setSpacing(14)

        risk_card = Card("Risk Summary")
        risk_row = QHBoxLayout()
        risk_row.setSpacing(14)
        gauge = RiskGauge()
        gauge.set_counts(counts)
        legend = SeverityLegend()
        legend.set_counts(counts)
        risk_row.addWidget(gauge, 1)
        risk_row.addWidget(legend, 0, Qt.AlignmentFlag.AlignVCenter)
        holder = QWidget()
        holder.setLayout(risk_row)
        # Without this the holder paints the window background and reads as a
        # darker panel sitting inside the card.
        holder.setStyleSheet("background: transparent;")
        risk_card.add(holder)
        risk_card.add_note(
            "Severity reflects how much each issue widens this Mac's attack "
            "surface — not how alarming it sounds."
        )
        # Keep the gauge pinned under its title when the findings card next to
        # it is taller.
        risk_card.v.addStretch(1)
        risk_card.setMinimumWidth(360)
        risk_card.setMaximumWidth(400)
        mid.addWidget(risk_card, 0, Qt.AlignmentFlag.AlignTop)

        actionable = []
        if audit:
            actionable = [
                f for f in audit.findings
                if f.severity in (Severity.CRITICAL, Severity.HIGH,
                                  Severity.MEDIUM)
            ]
        top_card = Card("Priority Findings", len(actionable))
        if actionable:
            for f in actionable[:4]:
                top_card.add(FindingBlock(f))
            if len(actionable) > 4:
                top_card.add_note(
                    f"{len(actionable) - 4} further finding(s) on the Security "
                    "Audit page."
                )
        else:
            ok = QLabel("No Critical, High or Medium findings.\n"
                        "Full detail on the Security Audit page.")
            ok.setStyleSheet(f"color: {theme.GOOD}; font-size: 13px;")
            top_card.add(ok)
        mid.addWidget(top_card, 1)
        v.addLayout(mid)
        v.addStretch(1)
