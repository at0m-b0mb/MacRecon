"""Software collector: applications, package managers, extensions, signing."""

from __future__ import annotations

import os
import plistlib

from ..model import Category
from .base import Collector, is_demo, run


def _app_info(path: str):
    """Read version + bundle id straight from Info.plist.

    ``system_profiler SPApplicationsDataType`` returns the same thing but can
    take 30+ seconds on a full /Applications; reading the plists directly is
    near-instant and gives identical fields.
    """
    plist = os.path.join(path, "Contents", "Info.plist")
    try:
        with open(plist, "rb") as fh:
            data = plistlib.load(fh)
    except Exception:
        return "", ""
    ver = (data.get("CFBundleShortVersionString")
           or data.get("CFBundleVersion") or "")
    bid = data.get("CFBundleIdentifier", "")
    return str(ver), str(bid)


def _signature(path: str) -> str:
    """Summarise the code signature: who signed it, and is it notarised."""
    out = run(["codesign", "-dv", "--verbose=2", path], timeout=8)
    if not out:
        return "Unsigned"
    authority = ""
    for line in out.splitlines():
        if line.startswith("Authority="):
            authority = line.split("=", 1)[1].strip()
            break
    if not authority:
        return "Unsigned / ad-hoc"
    if "Apple Mac OS Application Signing" in authority:
        return "Mac App Store"
    if "Software Signing" in authority or "Apple Code Signing" in authority:
        return "Apple"
    if authority.startswith("Developer ID Application:"):
        return "Developer ID: " + authority.split(":", 1)[1].strip()
    return authority


def _quarantined(path: str) -> bool:
    out = run(["xattr", "-p", "com.apple.quarantine", path], timeout=5)
    return bool(out.strip()) and "No such xattr" not in out


class SoftwareCollector(Collector):
    key = "software"
    name = "Software"
    icon = "📦"
    subtitle = "Applications, packages, extensions and code signing"

    def collect(self) -> Category:
        if is_demo():
            from ..demo_data import software_demo

            return software_demo()

        cat = Category(self.key, self.name, self.icon, self.subtitle)

        # --- Applications -----------------------------------------------------
        apps = cat.new_section(
            "Applications", kind="table",
            headers=["Application", "Version", "Bundle ID", "Signed By"],
        )
        entries = []
        for root in ("/Applications", "/Applications/Utilities",
                     os.path.expanduser("~/Applications")):
            if not os.path.isdir(root):
                continue
            try:
                names = sorted(os.listdir(root))
            except Exception:
                continue
            for name in names:
                if not name.endswith(".app"):
                    continue
                path = os.path.join(root, name)
                ver, bid = _app_info(path)
                entries.append((name[:-4], ver, bid, path))

        # Signature checks are the slow part (~40ms each); cap the number we
        # verify so a Mac with 300 apps still scans promptly. Third-party apps
        # are checked first because Apple's own bundles are the least
        # interesting answer.
        third_party = [e for e in entries if not e[2].startswith("com.apple.")]
        apple = [e for e in entries if e[2].startswith("com.apple.")]
        checked = third_party[:60]
        # Verify once and reuse: codesign costs ~40ms per bundle, so the
        # Applications table and the Unsigned table share one pass.
        signatures = {e[3]: _signature(e[3]) for e in checked}
        for nm, ver, bid, path in checked:
            apps.add_row(nm, ver, bid, signatures[path])
        for nm, ver, bid, _ in apple:
            apps.add_row(nm, ver, bid, "Apple")
        apps.note = (
            f"{len(entries)} bundles found. Signature verified for the first "
            f"{len(checked)} third-party apps."
        )

        # --- Unsigned / quarantined -------------------------------------------
        flagged = cat.new_section(
            "Unsigned & Quarantined", kind="table",
            headers=["Application", "Issue", "Path"],
        )
        for nm, ver, bid, path in checked:
            issues = []
            if signatures[path].startswith("Unsigned"):
                issues.append("No valid code signature")
            if _quarantined(path):
                issues.append("Quarantine xattr set (downloaded)")
            for issue in issues:
                flagged.add_row(nm, issue, path)
        if not flagged.table_rows:
            flagged.note = "Every third-party app checked carries a valid signature."
        else:
            flagged.note = (
                "Unsigned bundles bypass Gatekeeper's identity guarantee — "
                "confirm provenance before trusting them."
            )

        # --- Homebrew ---------------------------------------------------------
        brew = run(["brew", "list", "--versions"], timeout=30)
        if brew.strip() and "command not found" not in brew:
            hb = cat.new_section(
                "Homebrew Packages", kind="table",
                headers=["Formula", "Version"],
            )
            for line in sorted(brew.splitlines()):
                parts = line.split()
                if parts:
                    hb.add_row(parts[0], " ".join(parts[1:]))
            hb.note = f"{len(hb.table_rows)} formulae installed."

        # --- Installer receipts ------------------------------------------------
        pkgs = run(["pkgutil", "--pkgs"], timeout=20)
        if pkgs.strip():
            lines = [l for l in pkgs.splitlines() if l.strip()]
            non_apple = [l for l in lines if not l.startswith("com.apple.")]
            pk = cat.new_section(
                "Installer Receipts", kind="table",
                headers=["Package ID"],
            )
            for line in sorted(non_apple)[:50]:
                pk.add_row(line)
            pk.note = (
                f"{len(lines)} receipts total, {len(non_apple)} non-Apple. "
                "Receipts persist after an app is deleted — useful history."
            )

        # --- System extensions -------------------------------------------------
        sysext = run(["systemextensionsctl", "list"], timeout=15)
        if sysext.strip():
            se = cat.new_section(
                "System Extensions", kind="table",
                headers=["Bundle ID", "Team", "Name", "State"],
            )
            for line in sysext.splitlines():
                if "\t" not in line or line.strip().startswith("---"):
                    continue
                cols = [c.strip() for c in line.split("\t") if c.strip()]
                if len(cols) >= 4 and "enabled" in line.lower():
                    se.add_row(cols[1] if len(cols) > 1 else "",
                               cols[0] if cols else "",
                               cols[2] if len(cols) > 2 else "",
                               cols[-1])
            se.note = (
                "System extensions run with elevated privilege — network "
                "and endpoint-security extensions can see all traffic."
                if se.table_rows else
                "No third-party system extensions active."
            )

        # --- Kernel extensions -------------------------------------------------
        kexts = run(["kmutil", "showloaded", "--list-only"], timeout=25)
        if kexts.strip():
            non_apple_kexts = [
                l for l in kexts.splitlines()
                if l.strip() and "com.apple." not in l and l.split()[:1]
            ]
            kx = cat.new_section(
                "Third-Party Kernel Extensions", kind="table",
                headers=["Index", "Bundle ID", "Version"],
            )
            for line in non_apple_kexts[:25]:
                parts = line.split()
                if len(parts) >= 6:
                    kx.add_row(parts[0], parts[5], parts[6] if len(parts) > 6 else "")
            kx.note = (
                "Loaded kexts run in the kernel. Any third-party kext is a "
                "high-value review target."
                if kx.table_rows else
                "No third-party kernel extensions loaded — the modern, healthy "
                "state on Apple Silicon."
            )

        return cat
