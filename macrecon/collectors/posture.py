"""Security-posture probes shared by the System page and the Security Audit.

Both pages need the same facts -- is SIP on, is FileVault on, is the firewall
up -- but they present them differently: System renders state, Audit renders
judgement. Probing once here keeps them from drifting apart, and keeps the
macOS-version quirks in a single place.

Each probe returns a ``(state, raw)`` tuple: a normalised state string the
callers can branch on, plus the raw command output kept as evidence so a
report reader can reproduce the check by hand.
"""

from __future__ import annotations

import os
from typing import Dict, Tuple

from .base import defaults_read, is_demo, run, sysctl

# --- individual probes ------------------------------------------------------


def sip() -> Tuple[str, str]:
    """System Integrity Protection. ``csrutil`` needs no privileges to read."""
    out = run(["csrutil", "status"]).strip()
    low = out.lower()
    if "enabled" in low:
        return "Enabled", out
    if "disabled" in low:
        return "Disabled", out
    if "unsupported configuration" in low or "custom" in low:
        return "Custom", out
    return "Unknown", out


def filevault() -> Tuple[str, str]:
    out = run(["fdesetup", "status"]).strip()
    low = out.lower()
    if "filevault is on" in low:
        return "On", out
    if "filevault is off" in low:
        return "Off", out
    if "deferred" in low:
        return "Deferred", out
    return "Unknown", out


def gatekeeper() -> Tuple[str, str]:
    out = run(["spctl", "--status"]).strip()
    low = out.lower()
    if "assessments enabled" in low:
        return "Enabled", out
    if "assessments disabled" in low:
        return "Disabled", out
    return "Unknown", out


def firewall() -> Tuple[str, str]:
    """Application firewall state.

    The old ``defaults read /Library/Preferences/com.apple.alf globalstate``
    reads that circulate widely no longer resolve on current macOS -- the key
    is gone and the read errors out. ``socketfilterfw`` is the supported
    interface and works unprivileged for reads.
    """
    out = run(
        ["/usr/libexec/ApplicationFirewall/socketfilterfw", "--getglobalstate"]
    ).strip()
    low = out.lower()
    if "state = 1" in low or ("enabled" in low and "disabled" not in low):
        return "On", out
    if "state = 2" in low or "block all" in low:
        return "On (block all)", out
    if "state = 0" in low or "disabled" in low:
        return "Off", out
    return "Unknown", out


def firewall_stealth() -> Tuple[str, str]:
    out = run(
        ["/usr/libexec/ApplicationFirewall/socketfilterfw", "--getstealthmode"]
    ).strip()
    low = out.lower()
    if "on" in low and "off" not in low:
        return "On", out
    if "off" in low:
        return "Off", out
    return "Unknown", out


def remote_login() -> Tuple[str, str]:
    """SSH (Remote Login).

    ``systemsetup -getremotelogin`` requires root, so fall back to asking
    launchd whether the sshd job is loaded -- that read is unprivileged.
    """
    out = run(["systemsetup", "-getremotelogin"]).strip()
    low = out.lower()
    if "on" in low and "error" not in low and "permission" not in low:
        return "On", out
    if "off" in low and "error" not in low:
        return "Off", out
    lst = run(["launchctl", "list"])
    if "com.openssh.sshd" in lst:
        return "On", "launchctl list | grep com.openssh.sshd"
    return "Off", "launchctl list (no com.openssh.sshd)"


def screen_sharing() -> Tuple[str, str]:
    lst = run(["launchctl", "list"])
    if "com.apple.screensharing" in lst:
        return "On", "launchctl list | grep com.apple.screensharing"
    return "Off", "launchctl list (no com.apple.screensharing)"


def remote_management() -> Tuple[str, str]:
    """Apple Remote Desktop agent."""
    if is_demo():
        return "Off", ""
    path = "/Library/Application Support/Apple/Remote Desktop"
    lst = run(["launchctl", "list"])
    if "com.apple.RemoteDesktop" in lst or "ARDAgent" in lst:
        return "On", "launchctl list | grep RemoteDesktop"
    if os.path.isdir(path):
        return "Configured", f"{path} present"
    return "Off", "no ARD agent loaded"


def auto_login() -> Tuple[str, str]:
    val = defaults_read("/Library/Preferences/com.apple.loginwindow",
                        "autoLoginUser")
    if val:
        return "Enabled", f"autoLoginUser = {val}"
    return "Disabled", "autoLoginUser not set"


def guest_account() -> Tuple[str, str]:
    val = defaults_read("/Library/Preferences/com.apple.loginwindow",
                        "GuestEnabled")
    if val.strip() in ("1", "true", "YES"):
        return "Enabled", "GuestEnabled = 1"
    return "Disabled", "GuestEnabled = 0 / unset"


def auto_updates() -> Tuple[str, str]:
    check = defaults_read("/Library/Preferences/com.apple.SoftwareUpdate",
                          "AutomaticCheckEnabled")
    download = defaults_read("/Library/Preferences/com.apple.SoftwareUpdate",
                             "AutomaticDownload")
    critical = defaults_read("/Library/Preferences/com.apple.SoftwareUpdate",
                             "CriticalUpdateInstall")
    on = check.strip() in ("1", "true")
    raw = (f"AutomaticCheckEnabled={check or 'unset'} "
           f"AutomaticDownload={download or 'unset'} "
           f"CriticalUpdateInstall={critical or 'unset'}")
    if on:
        return "Enabled", raw
    if check == "":
        return "Default", raw
    return "Disabled", raw


def rosetta() -> Tuple[str, str]:
    """Rosetta 2 presence (Apple Silicon only)."""
    if sysctl("hw.optional.arm64") != "1":
        return "N/A (Intel)", "hw.optional.arm64 != 1"
    if os.path.exists("/Library/Apple/usr/libexec/oah/libRosettaRuntime"):
        return "Installed", "libRosettaRuntime present"
    return "Not installed", "libRosettaRuntime absent"


def secure_boot() -> Tuple[str, str]:
    """Secure-boot policy.

    ``bputil -d`` needs root on Apple Silicon; without it we can still tell
    Full vs reduced security is *unknown* rather than guess.
    """
    out = run(["nvram", "-p"], timeout=10)
    if "boot-args" in out:
        for line in out.splitlines():
            if line.startswith("boot-args"):
                args = line.split("\t", 1)[-1].strip()
                if args:
                    return "Custom boot-args", f"nvram boot-args = {args}"
    return "Default", "no custom boot-args in nvram"


def xprotect_version() -> Tuple[str, str]:
    """XProtect malware-signature bundle version."""
    from .base import read_plist_file

    for path in (
        "/Library/Apple/System/Library/CoreServices/XProtect.bundle/Contents/"
        "Info.plist",
        "/System/Library/CoreServices/XProtect.bundle/Contents/Info.plist",
    ):
        data = read_plist_file(path)
        if data:
            ver = data.get("CFBundleShortVersionString") or data.get(
                "CFBundleVersion"
            )
            if ver:
                return str(ver), path
    return "Unknown", "XProtect.bundle not readable"


def sudo_nopasswd() -> Tuple[str, str]:
    """Whether any sudoers rule grants NOPASSWD.

    /etc/sudoers is root-readable only; a non-root scan reports Unknown rather
    than a false clean bill of health.
    """
    if is_demo():
        return "Unknown", ""
    hits = []
    for path in ["/etc/sudoers"]:
        try:
            with open(path, "r", errors="replace") as fh:
                for line in fh:
                    s = line.strip()
                    if s.startswith("#") or not s:
                        continue
                    if "NOPASSWD" in s:
                        hits.append(f"{os.path.basename(path)}: {s}")
        except PermissionError:
            return "Unknown (needs root)", f"{path} unreadable"
        except Exception:
            return "Unknown", f"{path} unreadable"
    try:
        d = "/etc/sudoers.d"
        for name in sorted(os.listdir(d)):
            p = os.path.join(d, name)
            with open(p, "r", errors="replace") as fh:
                for line in fh:
                    if "NOPASSWD" in line:
                        hits.append(f"sudoers.d/{name}: {line.strip()}")
    except PermissionError:
        return "Unknown (needs root)", "/etc/sudoers.d unreadable"
    except Exception:
        pass
    if hits:
        return "Present", "; ".join(hits[:4])
    return "None", "no NOPASSWD rules found"


def snapshot() -> Dict[str, Tuple[str, str]]:
    """Run every probe once and return ``{name: (state, evidence)}``."""
    return {
        "sip": sip(),
        "filevault": filevault(),
        "gatekeeper": gatekeeper(),
        "firewall": firewall(),
        "firewall_stealth": firewall_stealth(),
        "remote_login": remote_login(),
        "screen_sharing": screen_sharing(),
        "remote_management": remote_management(),
        "auto_login": auto_login(),
        "guest_account": guest_account(),
        "auto_updates": auto_updates(),
        "rosetta": rosetta(),
        "secure_boot": secure_boot(),
        "xprotect": xprotect_version(),
        "sudo_nopasswd": sudo_nopasswd(),
    }
