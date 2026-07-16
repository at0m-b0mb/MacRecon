"""Export a collected scan to HTML, JSON or plain text.

All three formats render from the same :class:`~macrecon.model.Category` list,
after redaction has already been applied by the caller. There is deliberately
no "export raw" path that skips the redactor: if you want unmasked output you
turn redaction off explicitly for the whole scan, and the report says so on its
face.
"""

from __future__ import annotations

import datetime
import html
import json
from typing import List

from .model import Category, Severity

SEVERITY_COLORS = {
    "Critical": "#ff4d5e",
    "High": "#ff8a3d",
    "Medium": "#ffd23d",
    "Low": "#4dc3ff",
    "Info": "#8b98a9",
    "Good": "#28e0c8",
}


def _counts(categories: List[Category]):
    tally = {s.value: 0 for s in Severity}
    for cat in categories:
        for f in cat.findings:
            tally[f.severity.value] += 1
    return tally


def risk_label(categories: List[Category]):
    t = _counts(categories)
    if t["Critical"]:
        return "CRITICAL", SEVERITY_COLORS["Critical"]
    if t["High"]:
        return "ELEVATED", SEVERITY_COLORS["High"]
    if t["Medium"]:
        return "MODERATE", SEVERITY_COLORS["Medium"]
    return "LOW", SEVERITY_COLORS["Good"]


# --- JSON -------------------------------------------------------------------


def to_json(categories: List[Category], redacted: bool) -> str:
    payload = {
        "tool": "MacRecon",
        "version": __import__("macrecon").__version__,
        "generated": datetime.datetime.now().isoformat(timespec="seconds"),
        "redacted": redacted,
        "risk": risk_label(categories)[0],
        "finding_counts": _counts(categories),
        "categories": [],
    }
    for cat in categories:
        c = {"key": cat.key, "name": cat.name, "subtitle": cat.subtitle,
             "sections": []}
        for s in cat.sections:
            sec = {"title": s.title, "kind": s.kind, "note": s.note}
            if s.kind == "keyvalue":
                sec["rows"] = {k: v for k, v in s.rows}
            elif s.kind == "table":
                sec["headers"] = s.headers
                sec["rows"] = s.table_rows
            else:
                sec["findings"] = [
                    {"title": f.title, "severity": f.severity.value,
                     "detail": f.detail, "recommendation": f.recommendation,
                     "evidence": f.evidence}
                    for f in s.findings
                ]
            c["sections"].append(sec)
        payload["categories"].append(c)
    return json.dumps(payload, indent=2)


# --- Text -------------------------------------------------------------------


def to_text(categories: List[Category], redacted: bool) -> str:
    out = []
    w = 78
    out.append("=" * w)
    out.append("  MacRecon — macOS Information Gatherer".center(w))
    out.append("=" * w)
    out.append(f"  Generated : {datetime.datetime.now():%Y-%m-%d %H:%M:%S}")
    out.append(f"  Risk      : {risk_label(categories)[0]}")
    out.append(f"  Redaction : {'ON — identifiers masked' if redacted else 'OFF — contains identifying data'}")
    out.append("=" * w)
    out.append("")

    for cat in categories:
        out.append("")
        out.append("-" * w)
        out.append(f"  {cat.name.upper()}  —  {cat.subtitle}")
        out.append("-" * w)
        for s in cat.sections:
            if s.is_empty and not s.note:
                continue
            out.append("")
            out.append(f"  [ {s.title} ]")
            if s.kind == "keyvalue":
                width = max((len(k) for k, _ in s.rows), default=0)
                for k, v in s.rows:
                    out.append(f"    {k.ljust(width)}  :  {v}")
            elif s.kind == "table":
                if s.table_rows:
                    cols = len(s.headers)
                    widths = [len(h) for h in s.headers]
                    for row in s.table_rows:
                        for i in range(min(cols, len(row))):
                            widths[i] = max(widths[i], len(row[i]))
                    widths = [min(x, 34) for x in widths]
                    header = "  ".join(
                        h[:widths[i]].ljust(widths[i])
                        for i, h in enumerate(s.headers))
                    out.append("    " + header)
                    out.append("    " + "  ".join("-" * x for x in widths))
                    for row in s.table_rows:
                        out.append("    " + "  ".join(
                            str(row[i])[:widths[i]].ljust(widths[i])
                            for i in range(min(cols, len(row)))))
            else:
                for f in s.findings:
                    out.append(f"    [{f.severity.value.upper()}] {f.title}")
                    for line in _wrap(f.detail, w - 8):
                        out.append(f"        {line}")
                    if f.recommendation:
                        for line in _wrap("Fix: " + f.recommendation, w - 8):
                            out.append(f"        {line}")
                    if f.evidence:
                        out.append(f"        Evidence: {f.evidence}")
                    out.append("")
            if s.note:
                for line in _wrap(s.note, w - 6):
                    out.append(f"    * {line}" if line == _wrap(s.note, w - 6)[0]
                               else f"      {line}")
    out.append("")
    out.append("=" * w)
    out.append("  MacRecon is read-only. Only scan machines you are authorised to assess.")
    out.append("=" * w)
    return "\n".join(out)


def _wrap(text: str, width: int) -> List[str]:
    import textwrap

    return textwrap.wrap(text, width) or [""]


# --- HTML -------------------------------------------------------------------


def to_html(categories: List[Category], redacted: bool) -> str:
    e = html.escape
    tally = _counts(categories)
    risk, risk_color = risk_label(categories)
    now = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    banner = (
        '<div class="banner ok">Redaction is <b>ON</b> — serials, MACs, '
        'addresses, usernames and SSIDs are masked. Safe to share.</div>'
        if redacted else
        '<div class="banner warn">Redaction is <b>OFF</b> — this report '
        'contains identifying data about the host (serial number, hardware '
        'UUID, MAC addresses, usernames, Wi-Fi networks). Treat it as '
        'sensitive: store it encrypted and share it only with the asset '
        'owner.</div>'
    )

    nav = "".join(
        f'<a href="#{e(c.key)}">{e(c.icon)} {e(c.name)}</a>' for c in categories
    )

    chips = "".join(
        f'<span class="chip" style="--c:{SEVERITY_COLORS[k]}">'
        f'<b>{v}</b> {e(k)}</span>'
        for k, v in tally.items() if v
    )

    body = []
    for cat in categories:
        body.append(f'<section id="{e(cat.key)}"><h2>{e(cat.icon)} '
                    f'{e(cat.name)}</h2>'
                    f'<p class="sub">{e(cat.subtitle)}</p>')
        for s in cat.sections:
            if s.is_empty and not s.note:
                continue
            body.append(f'<div class="card"><h3>{e(s.title)}</h3>')
            if s.kind == "keyvalue" and s.rows:
                body.append('<table class="kv">')
                for k, v in s.rows:
                    body.append(f"<tr><td class='k'>{e(k)}</td>"
                                f"<td class='v'>{e(v)}</td></tr>")
                body.append("</table>")
            elif s.kind == "table" and s.table_rows:
                body.append('<div class="scroll"><table class="grid"><thead><tr>')
                for h in s.headers:
                    body.append(f"<th>{e(h)}</th>")
                body.append("</tr></thead><tbody>")
                for row in s.table_rows:
                    body.append("<tr>")
                    for cell in row:
                        cls = ""
                        low = str(cell).lower()
                        if cell.startswith("⚠"):
                            cls = ' class="flag"'
                        elif low in ("yes", "all interfaces", "on", "enabled"):
                            cls = ' class="hi"'
                        body.append(f"<td{cls}>{e(str(cell))}</td>")
                    body.append("</tr>")
                body.append("</tbody></table></div>")
            elif s.kind == "findings":
                for f in s.findings:
                    col = SEVERITY_COLORS[f.severity.value]
                    body.append(
                        f'<div class="finding" style="--c:{col}">'
                        f'<div class="fhead"><span class="sev">'
                        f'{e(f.severity.value)}</span>'
                        f'<span class="ftitle">{e(f.title)}</span></div>'
                        f'<p class="fdetail">{e(f.detail)}</p>'
                    )
                    if f.recommendation:
                        body.append(f'<p class="frec"><b>Fix:</b> '
                                    f'{e(f.recommendation)}</p>')
                    if f.evidence:
                        body.append(f'<p class="fev"><code>{e(f.evidence)}'
                                    f'</code></p>')
                    body.append("</div>")
            if s.note:
                body.append(f'<p class="note">{e(s.note)}</p>')
            body.append("</div>")
        body.append("</section>")

    return f"""<!doctype html>
<html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>MacRecon Report — {now}</title>
<style>
:root {{
  --bg:#0a0e14; --panel:#111721; --card:#161b22; --border:#232b36;
  --text:#e6edf3; --muted:#8b98a9; --accent:#28e0c8; --accent2:#3d8bfd;
}}
* {{ box-sizing:border-box; }}
body {{ margin:0; background:var(--bg); color:var(--text);
  font-family:-apple-system,BlinkMacSystemFont,"Segoe UI",Roboto,sans-serif;
  font-size:14px; line-height:1.6; }}
.wrap {{ max-width:1180px; margin:0 auto; padding:32px 20px 80px; }}
header {{ border-left:4px solid var(--accent); padding:8px 0 8px 18px;
  margin-bottom:22px; }}
h1 {{ margin:0; font-size:30px; letter-spacing:-.5px; }}
h1 .a {{ color:var(--accent); }}
.meta {{ color:var(--muted); font-size:12.5px; margin-top:6px; }}
.risk {{ display:inline-block; padding:3px 12px; border-radius:8px;
  font-weight:800; font-size:12px; letter-spacing:.5px;
  color:#05231e; background:{risk_color}; }}
.banner {{ padding:12px 16px; border-radius:10px; margin:18px 0;
  font-size:13px; border:1px solid; }}
.banner.ok {{ background:rgba(40,224,200,.08); border-color:rgba(40,224,200,.4);
  color:#9ff0e4; }}
.banner.warn {{ background:rgba(255,138,61,.08);
  border-color:rgba(255,138,61,.45); color:#ffc79a; }}
nav {{ display:flex; flex-wrap:wrap; gap:8px; margin:18px 0 26px; }}
nav a {{ color:var(--muted); text-decoration:none; background:var(--card);
  border:1px solid var(--border); padding:7px 13px; border-radius:9px;
  font-size:12.5px; font-weight:600; }}
nav a:hover {{ color:var(--accent); border-color:var(--accent); }}
.chips {{ display:flex; flex-wrap:wrap; gap:8px; margin:14px 0 0; }}
.chip {{ font-size:11.5px; padding:3px 11px; border-radius:20px;
  border:1px solid var(--c); color:var(--c);
  background:color-mix(in srgb, var(--c) 12%, transparent); }}
section {{ margin:34px 0; scroll-margin-top:18px; }}
h2 {{ font-size:21px; margin:0 0 2px; }}
.sub {{ color:var(--muted); font-size:12.5px; margin:0 0 14px; }}
.card {{ background:var(--card); border:1px solid var(--border);
  border-radius:12px; padding:16px 18px; margin-bottom:14px; }}
h3 {{ font-size:11px; letter-spacing:1.1px; text-transform:uppercase;
  color:var(--accent2); margin:0 0 12px; font-weight:700; }}
table {{ border-collapse:collapse; width:100%; }}
.kv td {{ padding:5px 0; vertical-align:top; border-bottom:1px solid #1b222c; }}
.kv .k {{ color:var(--muted); width:230px; }}
.kv .v {{ font-family:ui-monospace,Menlo,monospace; font-size:12.5px;
  word-break:break-word; }}
.scroll {{ overflow-x:auto; }}
.grid {{ font-family:ui-monospace,Menlo,monospace; font-size:12px;
  min-width:520px; }}
.grid th {{ text-align:left; color:var(--accent); font-size:10px;
  text-transform:uppercase; letter-spacing:.6px; padding:7px 10px;
  border-bottom:1px solid var(--border); white-space:nowrap; }}
.grid td {{ padding:6px 10px; border-bottom:1px solid #1b222c;
  vertical-align:top; }}
.grid td.hi {{ color:var(--accent); }}
.grid td.flag {{ color:#ff8a3d; font-weight:600; }}
.grid tr:hover td {{ background:#1b222c; }}
.finding {{ border:1px solid var(--border); border-left:3px solid var(--c);
  border-radius:9px; padding:12px 14px; margin-bottom:10px;
  background:#12181f; }}
.fhead {{ display:flex; align-items:center; gap:10px; margin-bottom:5px; }}
.sev {{ font-size:9.5px; font-weight:800; letter-spacing:.7px;
  text-transform:uppercase; color:var(--c); border:1px solid var(--c);
  border-radius:5px; padding:1px 7px; }}
.ftitle {{ font-weight:700; font-size:13.5px; }}
.fdetail {{ color:#c2ccd8; margin:5px 0; font-size:13px; }}
.frec {{ color:var(--accent); margin:5px 0; font-size:12.5px; }}
.fev code {{ color:var(--muted); font-size:11.5px; background:#0d131a;
  padding:2px 7px; border-radius:5px; border:1px solid var(--border); }}
.note {{ color:var(--muted); font-size:11.5px; font-style:italic;
  margin:10px 0 0; }}
footer {{ margin-top:50px; padding-top:18px; border-top:1px solid var(--border);
  color:var(--muted); font-size:11.5px; }}
@media print {{ body {{ background:#fff; color:#000; }}
  .card,.finding {{ break-inside:avoid; }} nav {{ display:none; }} }}
</style></head><body><div class="wrap">
<header>
  <h1><span class="a">Mac</span>Recon <span style="font-size:15px;color:var(--muted);font-weight:400">report</span></h1>
  <div class="meta">Generated {now} &nbsp;·&nbsp; Overall risk
    <span class="risk">{risk}</span></div>
  <div class="chips">{chips}</div>
</header>
{banner}
<nav>{nav}</nav>
{"".join(body)}
<footer>
  Generated by <b>MacRecon</b> v{__import__("macrecon").__version__} by
  at0m-b0mb — read-only macOS reconnaissance.
  Only scan machines you own or are explicitly authorised to assess.
</footer>
</div></body></html>"""
