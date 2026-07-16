"""Colour palette, semantic highlighting rules, and the Qt stylesheet.

Semantic colour lives here rather than in the collectors on purpose: a
collector's job is to report that Gatekeeper is "Disabled", not to decide that
disabled is alarming. Keeping the judgement in the view means the same value
can read as good in one column and bad in another without the collector
knowing anything about presentation.
"""

from __future__ import annotations

BG = "#0a0e14"
PANEL = "#111721"
CARD = "#161b22"
CARD_HI = "#1b222c"
BORDER = "#232b36"
BORDER_HI = "#2c3644"
TEXT = "#e6edf3"
MUTED = "#8b98a9"
ACCENT = "#28e0c8"       # teal
ACCENT2 = "#3d8bfd"      # electric blue

SEVERITY = {
    "Critical": "#ff4d5e",
    "High": "#ff8a3d",
    "Medium": "#ffd23d",
    "Low": "#4dc3ff",
    "Info": "#8b98a9",
    "Good": "#28e0c8",
}
GOOD = "#39d98a"
WARN = "#ff8a3d"

# Values that mean "a control is doing its job".
_ON = {"enabled", "on", "yes", "active", "installed", "connected",
       "on (block all)"}
# Values that mean "a control is not doing its job".
_OFF = {"disabled", "off", "no", "inactive", "not installed", "unknown"}


def semantic_color(section_title: str, key: str, value: str):
    """Return a highlight colour for a security-meaningful cell, else ``None``.

    Matching is scoped by section + key so the same word reads correctly in
    different contexts: "Yes" under *Admin* is a risk, "Yes" under *Encrypted*
    is reassurance.
    """
    t = (section_title or "").lower()
    k = (key or "").lower()
    v = (value or "").strip()
    vl = v.lower()
    if not vl:
        return None

    if "security posture" in t:
        # Controls where "off" is the finding.
        if k in ("system integrity protection", "filevault", "gatekeeper",
                 "firewall", "automatic updates"):
            if vl in _ON:
                return GOOD
            if vl in _OFF or vl == "default":
                return SEVERITY["High"] if k in (
                    "system integrity protection", "filevault") else WARN
            return None
        if k == "stealth mode":
            return GOOD if vl in _ON else SEVERITY["Low"]
        return None

    if "user accounts" in t:
        if k == "admin" and vl == "yes":
            return WARN
        return None

    if "ssh keys" in t and k == "encrypted":
        if vl == "no":
            return SEVERITY["High"]
        if vl == "yes":
            return GOOD
        return None

    if "listening ports" in t and k == "exposure":
        if vl == "all interfaces":
            return WARN
        if vl == "loopback only":
            return MUTED
        return None

    if "nearby networks" in t and k == "security":
        if "open" in vl:
            return WARN
        if "wep" in vl:
            return SEVERITY["High"]
        if "wpa3" in vl:
            return GOOD
        return None

    if "wi-fi" in t and k == "security":
        if "open" in vl:
            return SEVERITY["High"]
        if "wep" in vl:
            return SEVERITY["High"]
        return GOOD if "wpa" in vl else None

    if "launch items" in t and k == "flag":
        return WARN if v.startswith("⚠") else None

    if "applications" in t and k == "signed by":
        if vl.startswith("unsigned"):
            return WARN
        return None

    if "unsigned" in t and k == "issue":
        return WARN

    if "interfaces" in t and k == "status":
        return GOOD if vl == "active" else MUTED

    if "vpn" in t and k == "status":
        return GOOD if vl == "connected" else MUTED

    return None


def risk_level(counts: dict):
    """Map finding counts to a ``(label, colour)`` badge."""
    if counts.get("Critical"):
        return "CRITICAL", SEVERITY["Critical"]
    if counts.get("High"):
        return "ELEVATED", SEVERITY["High"]
    if counts.get("Medium"):
        return "MODERATE", SEVERITY["Medium"]
    return "LOW", GOOD


def stylesheet() -> str:
    return f"""
    QWidget {{
        background: {BG};
        color: {TEXT};
        font-family: -apple-system, "SF Pro Text", "Helvetica Neue", sans-serif;
        font-size: 13px;
    }}
    QLabel {{ background: transparent; }}
    QToolTip {{
        background: {CARD_HI}; color: {TEXT}; border: 1px solid {BORDER_HI};
        padding: 6px 9px; border-radius: 6px;
    }}

    /* ---- Sidebar ------------------------------------------------------- */
    #Sidebar {{ background: {PANEL}; border-right: 1px solid {BORDER}; }}
    #Brand {{ color: {TEXT}; font-size: 21px; font-weight: 800; }}
    #BrandSub {{ color: {MUTED}; font-size: 10px; letter-spacing: 1.6px; }}

    QPushButton#NavButton {{
        text-align: left; padding: 11px 14px; border: none;
        border-radius: 10px; color: {MUTED}; font-size: 13px; font-weight: 500;
        background: transparent;
    }}
    QPushButton#NavButton:hover {{ background: {CARD}; color: {TEXT}; }}
    QPushButton#NavButton:checked {{
        background: {CARD_HI}; color: {ACCENT}; font-weight: 700;
    }}
    #NavCount {{
        color: {MUTED}; font-size: 10px; font-weight: 700;
    }}

    /* ---- Top bar ------------------------------------------------------- */
    #TopBar {{ background: {BG}; border-bottom: 1px solid {BORDER}; }}
    #PageTitle {{ font-size: 21px; font-weight: 700; }}
    #PageSub {{ color: {MUTED}; font-size: 12px; }}

    QLineEdit#Search {{
        background: {CARD}; border: 1px solid {BORDER}; border-radius: 9px;
        padding: 8px 12px; color: {TEXT}; selection-background-color: {ACCENT2};
    }}
    QLineEdit#Search:focus {{ border: 1px solid {ACCENT}; }}

    QPushButton#Action {{
        background: {CARD}; border: 1px solid {BORDER}; border-radius: 9px;
        padding: 8px 15px; color: {TEXT}; font-weight: 600;
    }}
    QPushButton#Action:hover {{ border: 1px solid {ACCENT}; color: {ACCENT}; }}
    QPushButton#Action:disabled {{ color: {BORDER_HI}; border-color: {BORDER}; }}
    QPushButton#Primary {{
        background: {ACCENT}; border: none; border-radius: 9px;
        padding: 8px 18px; color: #05231e; font-weight: 700;
    }}
    QPushButton#Primary:hover {{ background: #43ecd6; }}
    QPushButton#Primary:disabled {{ background: {BORDER}; color: {MUTED}; }}

    /* Redaction toggle: reads as a live state, not a button. */
    QPushButton#Shield {{
        background: rgba(40,224,200,0.10); border: 1px solid {ACCENT};
        border-radius: 9px; padding: 8px 14px; color: {ACCENT};
        font-weight: 700; font-size: 12px;
    }}
    QPushButton#Shield:hover {{ background: rgba(40,224,200,0.18); }}
    QPushButton#Shield:checked {{
        background: rgba(255,138,61,0.10); border: 1px solid {WARN};
        color: {WARN};
    }}

    /* ---- Cards --------------------------------------------------------- */
    #Card {{ background: {CARD}; border: 1px solid {BORDER}; border-radius: 12px; }}
    #CardTitle {{ color: {ACCENT2}; font-size: 10px; font-weight: 700;
                  letter-spacing: 1.1px; }}
    #CountBadge {{ color: {MUTED}; background: {CARD_HI}; border: 1px solid {BORDER};
                   border-radius: 8px; padding: 1px 8px; font-size: 10px;
                   font-weight: 700; }}
    #CardNote {{ color: {MUTED}; font-size: 11px; font-style: italic; }}
    #KvKey {{ color: {MUTED}; }}
    #KvVal {{ color: {TEXT}; font-family: ui-monospace, Menlo, monospace;
              font-size: 12px; }}

    /* ---- Stat tiles ---------------------------------------------------- */
    #Tile {{ background: {CARD}; border: 1px solid {BORDER}; border-radius: 12px; }}
    #TileVal {{ font-size: 25px; font-weight: 800; color: {TEXT}; }}
    #TileLabel {{ color: {MUTED}; font-size: 10px; letter-spacing: .6px; }}
    #TileIcon {{ font-size: 19px; }}
    #TileSub {{ color: {MUTED}; font-size: 10px; }}

    /* ---- Tables -------------------------------------------------------- */
    QTableWidget {{
        background: {CARD}; border: none; gridline-color: transparent;
        selection-background-color: {CARD_HI}; selection-color: {ACCENT};
        font-family: ui-monospace, Menlo, monospace; font-size: 12px;
    }}
    QHeaderView::section {{
        background: {CARD}; color: {ACCENT}; border: none;
        border-bottom: 1px solid {BORDER}; padding: 8px 10px;
        font-size: 10px; font-weight: 700;
    }}
    QTableWidget::item {{ padding: 6px 10px; border-bottom: 1px solid #1c2430; }}
    QTableCornerButton::section {{ background: {CARD}; border: none; }}

    /* ---- Findings ------------------------------------------------------ */
    #Finding {{ background: #12181f; border: 1px solid {BORDER};
                border-radius: 9px; }}
    #FindingTitle {{ font-weight: 700; font-size: 13px; }}
    #FindingDetail {{ color: #c2ccd8; }}
    #FindingRec {{ color: {ACCENT}; }}
    #FindingEv {{ color: {MUTED}; font-family: ui-monospace, Menlo, monospace;
                  font-size: 10px; }}
    #SevBadge {{ font-size: 9px; font-weight: 800; border-radius: 5px;
                 padding: 2px 7px; }}
    #RiskBadge {{ font-size: 12px; font-weight: 800; border-radius: 9px;
                  padding: 4px 13px; letter-spacing: .5px; }}

    /* ---- Banner -------------------------------------------------------- */
    #Banner {{ border-radius: 10px; padding: 2px; }}
    #BannerText {{ font-size: 12px; }}

    /* ---- Scrollbars ---------------------------------------------------- */
    QScrollArea {{ border: none; background: {BG}; }}
    QScrollBar:vertical {{ background: transparent; width: 10px; margin: 2px; }}
    QScrollBar::handle:vertical {{ background: {BORDER_HI}; border-radius: 5px;
                                   min-height: 30px; }}
    QScrollBar::handle:vertical:hover {{ background: {MUTED}; }}
    QScrollBar::add-line, QScrollBar::sub-line {{ height: 0; width: 0; }}
    QScrollBar:horizontal {{ background: transparent; height: 10px; margin: 2px; }}
    QScrollBar::handle:horizontal {{ background: {BORDER_HI}; border-radius: 5px;
                                     min-width: 30px; }}

    /* ---- Status bar ---------------------------------------------------- */
    #StatusBar {{ background: {PANEL}; border-top: 1px solid {BORDER};
                  color: {MUTED}; font-size: 11px; }}
    #ModeLive {{ color: {GOOD}; font-weight: 700; }}
    #ModeDemo {{ color: {ACCENT}; font-weight: 700; }}
    QProgressBar {{ background: {CARD}; border: none; border-radius: 3px;
                    height: 5px; text-align: center; }}
    QProgressBar::chunk {{ background: {ACCENT}; border-radius: 3px; }}
    """
