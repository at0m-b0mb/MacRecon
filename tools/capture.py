#!/usr/bin/env python3
"""Render MacRecon offscreen and grab a PNG of each page for the README.

Two safety rails, because these images go into a public repository:

1. Demo mode is forced before any collector can run, so the app is populated
   from the synthetic dataset and has no route to this machine's real state.
2. Before anything is saved, :func:`assert_safe` checks the *live* machine for
   its real serial, UUID, hostname, username and SSID, and refuses to write if
   any of them appear in the rendered widget tree.

Rail 2 exists because rail 1 is a promise about code paths, and a promise is
not a check. If someone later adds a collector that ignores demo mode, this
script fails loudly instead of quietly publishing someone's serial number.
"""

import getpass
import os
import plistlib
import socket
import subprocess
import sys

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from PyQt6.QtCore import QEventLoop, QTimer  # noqa: E402
from PyQt6.QtWidgets import QApplication, QLabel, QTableWidget  # noqa: E402

from macrecon.collectors.base import set_demo_mode  # noqa: E402
from macrecon.gui.main_window import MainWindow  # noqa: E402
from macrecon.gui.theme import stylesheet  # noqa: E402

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
OUT = os.path.join(ROOT, "assets", "screenshots")

PAGES = [
    "01_dashboard.png", "02_system.png", "03_hardware.png", "04_users.png",
    "05_network.png", "06_software.png", "07_processes.png", "08_audit.png",
]


def real_secrets() -> dict:
    """Collect this machine's actual identifiers, to assert their absence."""
    s = {}
    try:
        s["username"] = getpass.getuser()
    except Exception:
        pass
    try:
        host = socket.gethostname()
        s["hostname"] = host.replace(".local", "")
    except Exception:
        pass
    try:
        p = subprocess.run(
            ["system_profiler", "-xml", "-detailLevel", "full",
             "SPHardwareDataType"],
            capture_output=True, timeout=40,
        )
        hw = plistlib.loads(p.stdout)[0]["_items"][0]
        s["serial"] = hw.get("serial_number", "")
        s["hardware UUID"] = hw.get("platform_UUID", "")
    except Exception:
        pass
    try:
        p = subprocess.run(
            ["system_profiler", "-xml", "-detailLevel", "full",
             "SPAirPortDataType"],
            capture_output=True, timeout=40,
        )
        iface = plistlib.loads(p.stdout)[0]["_items"][0][
            "spairport_airport_interfaces"][0]
        cur = iface.get("spairport_current_network_information") or {}
        s["current SSID"] = cur.get("_name", "")
        s["Wi-Fi MAC"] = iface.get("spairport_wireless_mac_address", "")
    except Exception:
        pass
    return {k: v for k, v in s.items() if v and len(str(v)) > 2}


def rendered_text(win) -> str:
    """Every string the window is currently displaying."""
    parts = [lbl.text() for lbl in win.findChildren(QLabel)]
    for tbl in win.findChildren(QTableWidget):
        for r in range(tbl.rowCount()):
            for c in range(tbl.columnCount()):
                item = tbl.item(r, c)
                if item:
                    parts.append(item.text())
    return "\n".join(parts)


def assert_safe(win, secrets: dict) -> None:
    """Abort the capture if any real identifier reached the screen."""
    haystack = rendered_text(win)
    leaked = {k: v for k, v in secrets.items() if str(v) in haystack}
    if leaked:
        print("\n  REFUSING TO CAPTURE — real data reached the UI:",
              file=sys.stderr)
        for k in leaked:
            print(f"    · {k}", file=sys.stderr)
        print("\n  Demo mode should have prevented this. Fix the collector "
              "before capturing.\n", file=sys.stderr)
        sys.exit(1)
    print(f"  safety check: none of {len(secrets)} real identifiers "
          f"({', '.join(secrets)}) appear in the UI")


def pump(ms: int) -> None:
    loop = QEventLoop()
    QTimer.singleShot(ms, loop.quit)
    loop.exec()


def grab(win, name: str) -> None:
    win.repaint()
    pump(140)
    pix = win.grab()
    path = os.path.join(OUT, name)
    pix.save(path)
    print(f"  saved {name}  ({pix.width()}x{pix.height()})")


def main() -> int:
    os.makedirs(OUT, exist_ok=True)

    print("Collecting this machine's real identifiers (to assert absence)…")
    secrets = real_secrets()

    # Rail 1: no collector may touch the real system.
    set_demo_mode(True)

    app = QApplication(sys.argv)
    app.setStyleSheet(stylesheet())
    win = MainWindow(redact=True)
    win.resize(1280, 840)
    win.show()

    for _ in range(80):
        pump(100)
        if win.categories and win.export_btn.isEnabled():
            break
    pump(400)

    # Rail 2: verify, don't trust.
    assert_safe(win, secrets)

    for idx, name in enumerate(PAGES):
        win._go(idx)
        pump(180)
        grab(win, name)

    print(f"\n{len(PAGES)} screenshots written to assets/screenshots/")
    return 0


if __name__ == "__main__":
    sys.exit(main())
