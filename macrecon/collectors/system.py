"""System collector: OS build, kernel, boot state, locale, uptime."""

from __future__ import annotations

import datetime
import os
import re
import time

from ..model import Category
from . import posture
from .base import Collector, is_demo, run, sysctl


def _uptime() -> str:
    """Human uptime derived from the kernel boot timestamp."""
    raw = sysctl("kern.boottime")
    m = re.search(r"sec\s*=\s*(\d+)", raw)
    if not m:
        return ""
    boot = int(m.group(1))
    delta = int(time.time()) - boot
    days, rem = divmod(delta, 86400)
    hours, rem = divmod(rem, 3600)
    mins = rem // 60
    parts = []
    if days:
        parts.append(f"{days}d")
    if hours or days:
        parts.append(f"{hours}h")
    parts.append(f"{mins}m")
    return " ".join(parts)


def _boot_time() -> str:
    raw = sysctl("kern.boottime")
    m = re.search(r"sec\s*=\s*(\d+)", raw)
    if not m:
        return ""
    return datetime.datetime.fromtimestamp(int(m.group(1))).strftime(
        "%Y-%m-%d %H:%M:%S"
    )


class SystemCollector(Collector):
    key = "system"
    name = "System"
    icon = "🖥"
    subtitle = "Operating system, kernel and boot state"

    def collect(self) -> Category:
        if is_demo():
            from ..demo_data import system_demo

            return system_demo()

        cat = Category(self.key, self.name, self.icon, self.subtitle)

        # --- OS ------------------------------------------------------------
        product = run(["sw_vers", "-productName"]).strip()
        version = run(["sw_vers", "-productVersion"]).strip()
        build = run(["sw_vers", "-buildVersion"]).strip()

        os_sec = cat.new_section("Operating System")
        os_sec.kv("Product", product or "macOS")
        os_sec.kv("Version", version)
        os_sec.kv("Build", build)
        os_sec.kv("Codename", _codename(version))
        os_sec.kv("Kernel", run(["uname", "-v"]).strip()[:80])
        os_sec.kv("Kernel Release", run(["uname", "-r"]).strip())
        os_sec.kv("Architecture", run(["uname", "-m"]).strip())
        arm = sysctl("hw.optional.arm64") == "1"
        os_sec.kv("Silicon", "Apple Silicon" if arm else "Intel")

        # --- Identity ------------------------------------------------------
        ident = cat.new_section("Identity")
        ident.kv("Computer Name", run(["scutil", "--get", "ComputerName"]).strip(),
                 sensitive=True)
        ident.kv("Local Hostname",
                 run(["scutil", "--get", "LocalHostName"]).strip(),
                 sensitive=True)
        hostname = run(["scutil", "--get", "HostName"]).strip()
        if "not set" in hostname.lower():
            hostname = "(not set)"
        ident.kv("Host Name", hostname, sensitive=True)
        ident.kv("Current User", os.environ.get("USER", ""), sensitive=True)
        ident.kv("Running As", "root" if os.geteuid() == 0 else "standard user")

        # --- Boot & runtime -------------------------------------------------
        boot = cat.new_section("Boot & Runtime")
        boot.kv("Boot Time", _boot_time())
        boot.kv("Uptime", _uptime())
        boot.kv("Boot Volume", run(["sysctl", "-n", "kern.bootargs"]).strip()
                or "/")
        sb_state, _ = posture.secure_boot()
        boot.kv("Boot Args", sb_state)
        ros_state, _ = posture.rosetta()
        boot.kv("Rosetta 2", ros_state)
        boot.kv("Translated Process",
                "Yes" if sysctl("sysctl.proc_translated") == "1" else "No")

        # --- Locale ---------------------------------------------------------
        loc = cat.new_section("Locale & Time")
        tz = run(["systemsetup", "-gettimezone"]).strip()
        if "Time Zone:" in tz:
            tz = tz.split("Time Zone:", 1)[1].strip()
        elif "error" in tz.lower() or not tz:
            tz = time.strftime("%Z")
        loc.kv("Time Zone", tz)
        loc.kv("Local Time", datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S"))
        loc.kv("Language", os.environ.get("LANG", "") or "(inherited)")

        # --- Security posture snapshot --------------------------------------
        # Mirrors the Audit page's raw inputs; Audit turns these into findings.
        sec = cat.new_section("Security Posture")
        sec.kv("System Integrity Protection", posture.sip()[0])
        sec.kv("FileVault", posture.filevault()[0])
        sec.kv("Gatekeeper", posture.gatekeeper()[0])
        sec.kv("Firewall", posture.firewall()[0])
        sec.kv("Stealth Mode", posture.firewall_stealth()[0])
        sec.kv("XProtect Version", posture.xprotect_version()[0])
        sec.kv("Automatic Updates", posture.auto_updates()[0])
        sec.note = "Read-only posture snapshot. See Security Audit for graded findings."

        return cat


# macOS marketing names, for the "what am I actually looking at" moment when a
# report says 26.6 and you need to know that's Tahoe.
_CODENAMES = {
    "26": "Tahoe",
    "15": "Sequoia",
    "14": "Sonoma",
    "13": "Ventura",
    "12": "Monterey",
    "11": "Big Sur",
    "10.15": "Catalina",
    "10.14": "Mojave",
    "10.13": "High Sierra",
}


def _codename(version: str) -> str:
    if not version:
        return ""
    major = version.split(".")[0]
    if major == "10":
        minor = ".".join(version.split(".")[:2])
        return _CODENAMES.get(minor, "")
    return _CODENAMES.get(major, "")
