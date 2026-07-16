"""Main window: sidebar navigation, threaded scan, search, export.

The scan runs on a worker thread. Collectors shell out to system_profiler and
netstat, which take seconds; doing that on the GUI thread would freeze the
window mid-scan and make the app feel broken exactly when it is working.
"""

from __future__ import annotations

import datetime
import os
from typing import List

from PyQt6.QtCore import QObject, Qt, QThread, pyqtSignal
from PyQt6.QtWidgets import (
    QButtonGroup, QFileDialog, QFrame, QHBoxLayout, QLabel, QLineEdit,
    QMessageBox, QProgressBar, QPushButton, QScrollArea, QStackedWidget,
    QVBoxLayout, QWidget,
)

from ..collectors import ALL_COLLECTORS
from ..collectors.base import is_demo
from ..model import Category, Severity
from ..redact import Redactor
from ..report import to_html, to_json, to_text
from . import theme
from .dashboard import Dashboard
from .widgets import Card, section_widget


class ScanWorker(QObject):
    """Runs the collectors off the GUI thread."""

    progress = pyqtSignal(int, str)
    finished = pyqtSignal(list)

    def run(self):
        cats: List[Category] = []
        total = len(ALL_COLLECTORS)
        for i, collector in enumerate(ALL_COLLECTORS):
            self.progress.emit(
                int(i / total * 100), f"Collecting {collector.name}…")
            try:
                cats.append(collector.collect())
            except Exception as exc:
                # One broken collector must not take down the scan; surface it
                # as an error card and keep the other six.
                cat = Category(collector.key, collector.name, collector.icon,
                               collector.subtitle)
                cat.error = f"{type(exc).__name__}: {exc}"
                cats.append(cat)
        self.progress.emit(100, "Done")
        self.finished.emit(cats)


class MainWindow(QWidget):
    def __init__(self, redact: bool = True):
        super().__init__()
        self.setWindowTitle("MacRecon — macOS Information Gatherer")
        self.resize(1280, 840)
        self.setMinimumSize(1060, 680)

        self.raw_categories: List[Category] = []
        self.categories: List[Category] = []
        self.redact_on = redact
        self._buttons = []

        root = QHBoxLayout(self)
        root.setContentsMargins(0, 0, 0, 0)
        root.setSpacing(0)
        root.addWidget(self._sidebar())

        right = QVBoxLayout()
        right.setContentsMargins(0, 0, 0, 0)
        right.setSpacing(0)
        right.addWidget(self._topbar())
        right.addWidget(self._banner())

        self.stack = QStackedWidget()
        right.addWidget(self.stack, 1)
        right.addWidget(self._statusbar())

        holder = QWidget()
        holder.setLayout(right)
        root.addWidget(holder, 1)

        self._start_scan()

    # --- chrome -------------------------------------------------------------
    def _sidebar(self) -> QWidget:
        bar = QFrame()
        bar.setObjectName("Sidebar")
        bar.setFixedWidth(214)
        v = QVBoxLayout(bar)
        v.setContentsMargins(14, 20, 14, 16)
        v.setSpacing(4)

        brand = QLabel(
            f'<span style="color:{theme.ACCENT}">Mac</span>'
            f'<span style="color:{theme.TEXT}">Recon</span>'
        )
        brand.setObjectName("Brand")
        v.addWidget(brand)
        sub = QLabel("INFORMATION GATHERER")
        sub.setObjectName("BrandSub")
        v.addWidget(sub)
        v.addSpacing(18)

        self.nav_group = QButtonGroup(self)
        self.nav_group.setExclusive(True)

        pages = [("◈", "Dashboard")] + [
            (c.icon, c.name) for c in ALL_COLLECTORS
        ]
        for idx, (icon, name) in enumerate(pages):
            btn = QPushButton(f"  {icon}   {name}")
            btn.setObjectName("NavButton")
            btn.setCheckable(True)
            btn.setCursor(Qt.CursorShape.PointingHandCursor)
            btn.clicked.connect(lambda _, i=idx: self._go(i))
            self.nav_group.addButton(btn, idx)
            self._buttons.append(btn)
            v.addWidget(btn)
        self._buttons[0].setChecked(True)

        v.addStretch(1)
        hint = QLabel("Read-only.\nNothing on this Mac is modified.")
        hint.setStyleSheet(f"color: {theme.BORDER_HI}; font-size: 10px;")
        hint.setWordWrap(True)
        v.addWidget(hint)
        return bar

    def _topbar(self) -> QWidget:
        bar = QFrame()
        bar.setObjectName("TopBar")
        bar.setFixedHeight(72)
        h = QHBoxLayout(bar)
        h.setContentsMargins(24, 12, 20, 12)
        h.setSpacing(10)

        titles = QVBoxLayout()
        titles.setSpacing(1)
        self.title = QLabel("Dashboard")
        self.title.setObjectName("PageTitle")
        self.subtitle = QLabel("Overview of this Mac")
        self.subtitle.setObjectName("PageSub")
        titles.addWidget(self.title)
        titles.addWidget(self.subtitle)
        h.addLayout(titles)
        h.addStretch(1)

        self.search = QLineEdit()
        self.search.setObjectName("Search")
        self.search.setPlaceholderText("Filter this page…")
        self.search.setFixedWidth(190)
        self.search.textChanged.connect(self._filter)
        h.addWidget(self.search)

        # The redaction toggle is deliberately in the permanent chrome, not
        # buried in a menu: it changes what leaves this machine, so its state
        # should always be visible.
        self.shield = QPushButton("🛡  Redaction ON")
        self.shield.setObjectName("Shield")
        self.shield.setCheckable(True)
        self.shield.setChecked(not self.redact_on)
        self.shield.setCursor(Qt.CursorShape.PointingHandCursor)
        self.shield.setToolTip(
            "Masks serials, hardware UUIDs, MAC addresses, IPs, usernames and "
            "SSIDs everywhere — on screen and in every export.\n"
            "Turn off only for your own records on a machine you own."
        )
        self.shield.clicked.connect(self._toggle_redaction)
        h.addWidget(self.shield)

        self.rescan_btn = QPushButton("↻  Rescan")
        self.rescan_btn.setObjectName("Action")
        self.rescan_btn.setCursor(Qt.CursorShape.PointingHandCursor)
        self.rescan_btn.clicked.connect(self._start_scan)
        h.addWidget(self.rescan_btn)

        self.export_btn = QPushButton("↓  Export report")
        self.export_btn.setObjectName("Primary")
        self.export_btn.setCursor(Qt.CursorShape.PointingHandCursor)
        self.export_btn.setEnabled(False)
        self.export_btn.clicked.connect(self._export)
        h.addWidget(self.export_btn)
        return bar

    def _banner(self) -> QWidget:
        self.banner = QFrame()
        self.banner.setObjectName("Banner")
        self.banner.setFixedHeight(34)
        h = QHBoxLayout(self.banner)
        h.setContentsMargins(24, 0, 24, 0)
        self.banner_text = QLabel()
        self.banner_text.setObjectName("BannerText")
        h.addWidget(self.banner_text)
        h.addStretch(1)
        self._paint_banner()
        return self.banner

    def _paint_banner(self):
        if self.redact_on:
            self.banner.setStyleSheet(
                f"#Banner {{ background: rgba(40,224,200,0.07); "
                f"border-bottom: 1px solid rgba(40,224,200,0.25); }}")
            self.banner_text.setText(
                "🛡  Redaction ON — serials, MACs, addresses, usernames and "
                "SSIDs are masked on screen and in exports. Safe to screenshot."
            )
            self.banner_text.setStyleSheet(f"color: {theme.ACCENT};")
        else:
            self.banner.setStyleSheet(
                f"#Banner {{ background: rgba(255,138,61,0.08); "
                f"border-bottom: 1px solid rgba(255,138,61,0.3); }}")
            self.banner_text.setText(
                "⚠  Redaction OFF — this view and any export now contain "
                "identifying data about this Mac. Do not screenshot or share."
            )
            self.banner_text.setStyleSheet(f"color: {theme.WARN};")

    def _statusbar(self) -> QWidget:
        bar = QFrame()
        bar.setObjectName("StatusBar")
        bar.setFixedHeight(30)
        h = QHBoxLayout(bar)
        h.setContentsMargins(24, 0, 24, 0)
        h.setSpacing(12)

        self.mode = QLabel()
        if is_demo():
            self.mode.setText("● DEMO DATA")
            self.mode.setObjectName("ModeDemo")
            self.mode.setToolTip(
                "Synthetic dataset — no real system was read. "
                "This is what the README screenshots are captured from."
            )
        else:
            self.mode.setText("● LIVE")
            self.mode.setObjectName("ModeLive")
            self.mode.setToolTip("Reading this Mac, read-only.")
        h.addWidget(self.mode)

        self.status = QLabel("Starting…")
        h.addWidget(self.status)
        h.addStretch(1)

        self.progress = QProgressBar()
        self.progress.setFixedWidth(180)
        self.progress.setTextVisible(False)
        h.addWidget(self.progress)
        return bar

    # --- scanning -----------------------------------------------------------
    def _start_scan(self):
        self.export_btn.setEnabled(False)
        self.rescan_btn.setEnabled(False)
        self.progress.setValue(0)
        self.status.setText("Scanning…")

        self.thread = QThread()
        self.worker = ScanWorker()
        self.worker.moveToThread(self.thread)
        self.thread.started.connect(self.worker.run)
        self.worker.progress.connect(self._on_progress)
        self.worker.finished.connect(self._on_finished)
        self.worker.finished.connect(self.thread.quit)
        self.thread.start()

    def _on_progress(self, pct: int, msg: str):
        self.progress.setValue(pct)
        self.status.setText(msg)

    def _on_finished(self, categories: List[Category]):
        self.raw_categories = categories
        self._rebuild()
        self.rescan_btn.setEnabled(True)
        self.export_btn.setEnabled(True)
        counts = self._counts()
        total = sum(counts.get(k, 0) for k in
                    ("Critical", "High", "Medium", "Low"))
        self.status.setText(
            f"Scan complete · {datetime.datetime.now():%H:%M:%S} · "
            f"{total} finding{'s' if total != 1 else ''}"
        )

    def _counts(self) -> dict:
        counts = {s.value: 0 for s in Severity}
        for c in self.categories:
            for f in c.findings:
                counts[f.severity.value] += 1
        return counts

    # --- pages --------------------------------------------------------------
    def _rebuild(self):
        """Re-apply redaction and rebuild every page from the raw scan.

        Redaction is applied here, once, from the untouched raw scan — so
        toggling the shield is lossless in both directions and never has to
        re-run the collectors.
        """
        self.categories = Redactor(self.redact_on).apply(self.raw_categories)

        while self.stack.count():
            w = self.stack.widget(0)
            self.stack.removeWidget(w)
            w.deleteLater()

        self.stack.addWidget(self._scroll(Dashboard(self.categories)))
        for cat in self.categories:
            self.stack.addWidget(self._scroll(self._page(cat)))

        idx = self.nav_group.checkedId()
        self._go(idx if idx >= 0 else 0)

    def _page(self, cat: Category) -> QWidget:
        page = QWidget()
        v = QVBoxLayout(page)
        v.setContentsMargins(0, 0, 0, 0)
        v.setSpacing(14)

        if cat.error:
            card = Card("Collector Error")
            lbl = QLabel(
                f"This collector failed and returned no data:\n\n{cat.error}\n\n"
                "The other pages are unaffected."
            )
            lbl.setWordWrap(True)
            lbl.setStyleSheet(f"color: {theme.SEVERITY['High']};")
            card.add(lbl)
            v.addWidget(card)

        for section in cat.sections:
            widget = section_widget(section)
            if widget is None and not section.note:
                continue
            count = None
            if section.kind == "table":
                count = len(section.table_rows)
            elif section.kind == "findings":
                count = len(section.findings)
            card = Card(section.title, count)
            if widget is not None:
                card.add(widget)
            elif section.note:
                empty = QLabel("Nothing found.")
                empty.setStyleSheet(f"color: {theme.MUTED};")
                card.add(empty)
            card.add_note(section.note)
            v.addWidget(card)

        v.addStretch(1)
        return page

    def _scroll(self, inner: QWidget) -> QScrollArea:
        area = QScrollArea()
        area.setWidgetResizable(True)
        area.setHorizontalScrollBarPolicy(
            Qt.ScrollBarPolicy.ScrollBarAlwaysOff)
        holder = QWidget()
        lay = QVBoxLayout(holder)
        lay.setContentsMargins(24, 18, 24, 24)
        lay.addWidget(inner)
        area.setWidget(holder)
        return area

    def _go(self, index: int):
        if index < 0 or index >= self.stack.count():
            return
        self.stack.setCurrentIndex(index)
        if index < len(self._buttons):
            self._buttons[index].setChecked(True)
        if index == 0:
            self.title.setText("Dashboard")
            self.subtitle.setText("Overview of this Mac")
        else:
            cat = self.categories[index - 1]
            self.title.setText(cat.name)
            self.subtitle.setText(cat.subtitle)
        self.search.clear()

    def _filter(self, text: str):
        """Hide cards on the current page that don't match the query."""
        area = self.stack.currentWidget()
        if not isinstance(area, QScrollArea):
            return
        holder = area.widget()
        if holder is None:
            return
        query = text.strip().lower()
        for card in holder.findChildren(Card):
            if not query:
                card.setVisible(True)
                continue
            # Match against everything the card renders, so a search for an
            # IP or a username finds the card containing it.
            hay = " ".join(
                lbl.text() for lbl in card.findChildren(QLabel)
            ).lower()
            from .widgets import TableBlock

            for tbl in card.findChildren(TableBlock):
                for r in range(tbl.rowCount()):
                    for c in range(tbl.columnCount()):
                        item = tbl.item(r, c)
                        if item:
                            hay += " " + item.text().lower()
            card.setVisible(query in hay)

    # --- actions ------------------------------------------------------------
    def _toggle_redaction(self):
        turning_off = self.shield.isChecked()
        if turning_off:
            confirm = QMessageBox(self)
            confirm.setWindowTitle("Turn off redaction?")
            confirm.setIcon(QMessageBox.Icon.Warning)
            confirm.setText("Reveal identifying data about this Mac?")
            confirm.setInformativeText(
                "The window and every export will then contain this Mac's "
                "serial number, hardware UUID, MAC addresses, local IPs, "
                "usernames and saved Wi-Fi networks.\n\n"
                "Only do this on a machine you own or are authorised to "
                "assess — and don't screenshot the result."
            )
            confirm.setStandardButtons(
                QMessageBox.StandardButton.Cancel |
                QMessageBox.StandardButton.Yes)
            confirm.setDefaultButton(QMessageBox.StandardButton.Cancel)
            if confirm.exec() != QMessageBox.StandardButton.Yes:
                self.shield.setChecked(False)
                return

        self.redact_on = not turning_off
        self.shield.setText(
            "🛡  Redaction ON" if self.redact_on else "⚠  Redaction OFF")
        self._paint_banner()
        if self.raw_categories:
            self._rebuild()

    def _export(self):
        stamp = datetime.datetime.now().strftime("%Y%m%d-%H%M%S")
        suffix = "" if self.redact_on else "-UNREDACTED"
        default = os.path.expanduser(
            f"~/Desktop/macrecon-report-{stamp}{suffix}.html")
        path, selected = QFileDialog.getSaveFileName(
            self, "Export report", default,
            "HTML report (*.html);;JSON (*.json);;Plain text (*.txt)",
        )
        if not path:
            return

        if path.endswith(".json") or "JSON" in selected:
            data = to_json(self.categories, self.redact_on)
        elif path.endswith(".txt") or "text" in selected:
            data = to_text(self.categories, self.redact_on)
        else:
            data = to_html(self.categories, self.redact_on)

        try:
            with open(path, "w", encoding="utf-8") as fh:
                fh.write(data)
        except Exception as exc:
            QMessageBox.critical(self, "Export failed", str(exc))
            return

        note = (
            "Identifiers are masked — safe to share."
            if self.redact_on else
            "⚠  This file is UNREDACTED and identifies this Mac. "
            "Store it encrypted."
        )
        QMessageBox.information(
            self, "Report exported", f"Saved to:\n{path}\n\n{note}")
