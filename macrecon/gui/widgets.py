"""Reusable presentation widgets: cards, tables, findings, tiles, gauge."""

from __future__ import annotations

from typing import Optional

from PyQt6.QtCore import QRectF, Qt
from PyQt6.QtGui import QColor, QFont, QPainter, QPen
from PyQt6.QtWidgets import (
    QAbstractItemView, QFrame, QHBoxLayout, QHeaderView, QLabel, QSizePolicy,
    QTableWidget, QTableWidgetItem, QVBoxLayout, QWidget,
)

from ..model import Section, Severity
from . import theme


class Card(QFrame):
    """A titled panel. Everything on a page lives in one of these."""

    def __init__(self, title: str, count: Optional[int] = None, parent=None):
        super().__init__(parent)
        self.setObjectName("Card")
        self.v = QVBoxLayout(self)
        self.v.setContentsMargins(16, 13, 16, 15)
        self.v.setSpacing(9)

        head = QHBoxLayout()
        head.setSpacing(8)
        lbl = QLabel(title.upper())
        lbl.setObjectName("CardTitle")
        head.addWidget(lbl)
        if count is not None:
            badge = QLabel(str(count))
            badge.setObjectName("CountBadge")
            head.addWidget(badge)
        head.addStretch(1)
        self.v.addLayout(head)

    def add(self, w: QWidget):
        self.v.addWidget(w)

    def add_note(self, text: str):
        if not text:
            return
        note = QLabel(text)
        note.setObjectName("CardNote")
        note.setWordWrap(True)
        self.v.addWidget(note)


class KeyValueBlock(QWidget):
    """Two-column label/value grid with semantic colouring."""

    def __init__(self, section: Section, parent=None):
        super().__init__(parent)
        grid = QVBoxLayout(self)
        grid.setContentsMargins(0, 0, 0, 0)
        grid.setSpacing(5)
        for key, value in section.rows:
            row = QHBoxLayout()
            row.setSpacing(12)
            k = QLabel(key)
            k.setObjectName("KvKey")
            k.setMinimumWidth(190)
            k.setMaximumWidth(190)
            k.setWordWrap(True)
            k.setAlignment(Qt.AlignmentFlag.AlignTop | Qt.AlignmentFlag.AlignLeft)
            v = QLabel(value or "—")
            v.setObjectName("KvVal")
            v.setWordWrap(True)
            v.setTextInteractionFlags(
                Qt.TextInteractionFlag.TextSelectableByMouse)
            color = theme.semantic_color(section.title, key, value)
            if color:
                v.setStyleSheet(f"color: {color}; font-weight: 600;")
            row.addWidget(k)
            row.addWidget(v, 1)
            grid.addLayout(row)


class TableBlock(QTableWidget):
    """Read-only table sized to its content, with semantic cell colouring."""

    def __init__(self, section: Section, parent=None):
        super().__init__(parent)
        rows, cols = len(section.table_rows), len(section.headers)
        self.setRowCount(rows)
        self.setColumnCount(cols)
        self.setHorizontalHeaderLabels([h.upper() for h in section.headers])
        self.verticalHeader().setVisible(False)
        self.setEditTriggers(QAbstractItemView.EditTrigger.NoEditTriggers)
        self.setSelectionBehavior(
            QAbstractItemView.SelectionBehavior.SelectRows)
        self.setShowGrid(False)
        self.setAlternatingRowColors(False)
        self.setWordWrap(False)
        self.setFocusPolicy(Qt.FocusPolicy.NoFocus)

        for r, row in enumerate(section.table_rows):
            for c in range(cols):
                text = row[c] if c < len(row) else ""
                item = QTableWidgetItem(text)
                item.setToolTip(text)
                header = section.headers[c] if c < len(section.headers) else ""
                color = theme.semantic_color(section.title, header, text)
                if color:
                    item.setForeground(QColor(color))
                self.setItem(r, c, item)

        header = self.horizontalHeader()
        header.setSectionResizeMode(QHeaderView.ResizeMode.Interactive)
        self.resizeColumnsToContents()
        # Cap any single column so one long value (a launchd Program path, a
        # process command line) can't consume the width and squeeze the last
        # column — often the Flag/Exposure column carrying the finding — down
        # to an unreadable sliver. Elided cells keep their full text in a
        # tooltip, and the cap tightens as the column count grows.
        cap = 420 if cols <= 4 else 330
        for c in range(cols):
            if self.columnWidth(c) > cap:
                self.setColumnWidth(c, cap)
        header.setStretchLastSection(True)

        self.setVerticalScrollBarPolicy(Qt.ScrollBarPolicy.ScrollBarAlwaysOff)
        self.setHorizontalScrollBarPolicy(Qt.ScrollBarPolicy.ScrollBarAsNeeded)
        # Size to content: the page scrolls, not each individual table.
        h = self.horizontalHeader().height() + 2
        for r in range(rows):
            h += self.rowHeight(r)
        self.setFixedHeight(max(h, 46))
        self.setSizePolicy(QSizePolicy.Policy.Expanding,
                           QSizePolicy.Policy.Fixed)


class FindingBlock(QFrame):
    """One audit finding: severity badge, title, detail, fix, evidence."""

    def __init__(self, finding, parent=None):
        super().__init__(parent)
        self.setObjectName("Finding")
        color = theme.SEVERITY[finding.severity.value]
        self.setStyleSheet(
            f"#Finding {{ border-left: 3px solid {color}; }}"
        )
        v = QVBoxLayout(self)
        v.setContentsMargins(13, 11, 13, 12)
        v.setSpacing(6)

        head = QHBoxLayout()
        head.setSpacing(9)
        badge = QLabel(finding.severity.value.upper())
        badge.setObjectName("SevBadge")
        badge.setStyleSheet(
            f"color: {color}; border: 1px solid {color};"
        )
        title = QLabel(finding.title)
        title.setObjectName("FindingTitle")
        title.setWordWrap(True)
        head.addWidget(badge, 0, Qt.AlignmentFlag.AlignTop)
        head.addWidget(title, 1)
        v.addLayout(head)

        detail = QLabel(finding.detail)
        detail.setObjectName("FindingDetail")
        detail.setWordWrap(True)
        detail.setTextInteractionFlags(
            Qt.TextInteractionFlag.TextSelectableByMouse)
        v.addWidget(detail)

        if finding.recommendation:
            rec = QLabel("→  " + finding.recommendation)
            rec.setObjectName("FindingRec")
            rec.setWordWrap(True)
            v.addWidget(rec)

        if finding.evidence:
            ev = QLabel(finding.evidence)
            ev.setObjectName("FindingEv")
            ev.setWordWrap(True)
            ev.setTextInteractionFlags(
                Qt.TextInteractionFlag.TextSelectableByMouse)
            v.addWidget(ev)


class Tile(QFrame):
    """A single headline number on the dashboard."""

    def __init__(self, icon: str, value: str, label: str, sub: str = "",
                 color: str = None, parent=None):
        super().__init__(parent)
        self.setObjectName("Tile")
        self.setMinimumHeight(96)
        v = QVBoxLayout(self)
        v.setContentsMargins(15, 12, 15, 12)
        v.setSpacing(2)

        top = QHBoxLayout()
        ic = QLabel(icon)
        ic.setObjectName("TileIcon")
        top.addWidget(ic)
        top.addStretch(1)
        v.addLayout(top)

        val = QLabel(value)
        val.setObjectName("TileVal")
        if color:
            val.setStyleSheet(f"color: {color};")
        v.addWidget(val)

        lab = QLabel(label.upper())
        lab.setObjectName("TileLabel")
        v.addWidget(lab)

        if sub:
            s = QLabel(sub)
            s.setObjectName("TileSub")
            s.setWordWrap(True)
            v.addWidget(s)
        v.addStretch(1)


class RiskGauge(QWidget):
    """Painted arc summarising finding counts by severity.

    A stacked arc rather than a number: the shape shows the *mix* of severities
    at a glance, which is the thing you actually want to read across the room.
    """

    def __init__(self, parent=None):
        super().__init__(parent)
        self.counts = {}
        self.label = "—"
        self.color = theme.MUTED
        self.setMinimumWidth(180)
        # Fixed height, or the gauge absorbs the slack when its card is
        # stretched to match a taller neighbour and floats away from the title.
        self.setFixedHeight(158)
        self.setSizePolicy(QSizePolicy.Policy.Expanding,
                           QSizePolicy.Policy.Fixed)

    def set_counts(self, counts: dict):
        self.counts = counts
        self.label, self.color = theme.risk_level(counts)
        self.update()

    def paintEvent(self, event):
        p = QPainter(self)
        p.setRenderHint(QPainter.RenderHint.Antialiasing)

        w, h = self.width(), self.height()
        size = min(w, h - 18)
        rect = QRectF((w - size) / 2 + 11, 8, size - 22, size - 22)

        # Track.
        pen = QPen(QColor(theme.BORDER), 11, Qt.PenStyle.SolidLine,
                   Qt.PenCapStyle.RoundCap)
        p.setPen(pen)
        p.drawArc(rect, 210 * 16, -240 * 16)

        actionable = [k for k in ("Critical", "High", "Medium", "Low")
                      if self.counts.get(k)]
        total = sum(self.counts.get(k, 0) for k in actionable)

        if total:
            start = 210 * 16
            for key in actionable:
                n = self.counts.get(key, 0)
                span = int(-240 * 16 * (n / total))
                pen = QPen(QColor(theme.SEVERITY[key]), 11,
                           Qt.PenStyle.SolidLine, Qt.PenCapStyle.FlatCap)
                p.setPen(pen)
                p.drawArc(rect, start, span)
                start += span
        else:
            pen = QPen(QColor(theme.GOOD), 11, Qt.PenStyle.SolidLine,
                       Qt.PenCapStyle.RoundCap)
            p.setPen(pen)
            p.drawArc(rect, 210 * 16, -240 * 16)

        # Centre label.
        p.setPen(QColor(self.color))
        f = QFont()
        f.setPointSize(15)
        f.setBold(True)
        p.setFont(f)
        p.drawText(rect, Qt.AlignmentFlag.AlignCenter, self.label)

        p.setPen(QColor(theme.MUTED))
        f2 = QFont()
        f2.setPointSize(9)
        p.setFont(f2)
        p.drawText(
            QRectF(rect.x(), rect.center().y() + 16, rect.width(), 20),
            Qt.AlignmentFlag.AlignCenter,
            f"{total} finding{'s' if total != 1 else ''}",
        )
        p.end()


class SeverityLegend(QWidget):
    """Compact per-severity counts under the gauge."""

    def __init__(self, parent=None):
        super().__init__(parent)
        self.v = QVBoxLayout(self)
        self.v.setContentsMargins(0, 0, 0, 0)
        self.v.setSpacing(5)
        self._rows = {}
        for sev in Severity:
            row = QHBoxLayout()
            row.setSpacing(8)
            dot = QLabel("●")
            dot.setStyleSheet(
                f"color: {theme.SEVERITY[sev.value]}; font-size: 10px;")
            name = QLabel(sev.value)
            name.setStyleSheet(f"color: {theme.MUTED}; font-size: 11px;")
            count = QLabel("0")
            count.setStyleSheet(
                f"color: {theme.TEXT}; font-size: 11px; font-weight: 700;")
            row.addWidget(dot)
            row.addWidget(name)
            row.addStretch(1)
            row.addWidget(count)
            self.v.addLayout(row)
            self._rows[sev.value] = count

    def set_counts(self, counts: dict):
        for key, lbl in self._rows.items():
            lbl.setText(str(counts.get(key, 0)))


def section_widget(section: Section) -> Optional[QWidget]:
    """Build the right block for a section, or ``None`` if there's nothing."""
    if section.kind == "keyvalue" and section.rows:
        return KeyValueBlock(section)
    if section.kind == "table" and section.table_rows:
        return TableBlock(section)
    if section.kind == "findings" and section.findings:
        holder = QWidget()
        v = QVBoxLayout(holder)
        v.setContentsMargins(0, 0, 0, 0)
        v.setSpacing(8)
        for f in section.findings:
            v.addWidget(FindingBlock(f))
        return holder
    return None
