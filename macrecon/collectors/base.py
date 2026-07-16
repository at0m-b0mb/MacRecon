"""Collector infrastructure: platform detection and a safe command runner.

On macOS the collectors shell out to native tooling (``sw_vers``,
``system_profiler``, ``csrutil``, ``dscl``, ``scutil`` ...).  On any other OS --
or with ``--demo`` -- they fall back to the bundled demo dataset so the GUI
stays fully populated for screenshots and development anywhere.

**Everything here is read-only.** Every command in this package observes state;
none writes, installs, or reaches out to another host. That is a deliberate
constraint, not an accident of the current command list -- see ``run()``.
"""

from __future__ import annotations

import os
import platform
import plistlib
import subprocess
from typing import Any, Dict, List, Optional

IS_MACOS = platform.system() == "Darwin"

_FORCE_DEMO = not IS_MACOS

# Commands that mutate state, install software, or touch the network. A
# collector that reaches for one of these is a bug, so we fail loudly in
# development rather than silently shipping a tool that writes to the host it
# is supposed to be quietly observing.
_FORBIDDEN = {
    "rm", "mv", "cp", "dd", "mkfs", "chmod", "chown", "kill", "killall",
    "shutdown", "reboot", "installer", "brew-install", "pip", "curl", "wget",
    "nc", "ssh", "scp", "defaults-write", "launchctl-load", "csrutil-disable",
    "fdesetup-disable", "spctl-disable", "nvram-write",
}


def set_demo_mode(force: bool) -> None:
    global _FORCE_DEMO
    _FORCE_DEMO = force or not IS_MACOS


def is_demo() -> bool:
    return _FORCE_DEMO


def is_root() -> bool:
    return os.geteuid() == 0


def run(cmd: List[str], timeout: int = 25) -> str:
    """Run a read-only command and return stdout, or ``""`` on any failure.

    Never raises. Collectors depend on this degrading gracefully so that one
    missing or SIP-restricted binary can't take down a whole scan -- macOS
    moves these around between releases (``airport`` was removed in 14.4,
    ``kextstat`` deprecated in 11).
    """
    if _FORCE_DEMO:
        return ""
    if cmd and os.path.basename(cmd[0]) in _FORBIDDEN:
        raise RuntimeError(
            f"MacRecon is read-only; refusing to run {cmd[0]!r}. "
            "If you are adding a collector, find a command that observes "
            "rather than changes state."
        )
    try:
        completed = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=timeout,
            errors="replace",
        )
        # Several macOS tools (csrutil, spctl, pmset) report meaningful state
        # on stderr with a non-zero exit, so merge rather than gate on rc.
        return (completed.stdout or "") + (completed.stderr or "")
    except Exception:
        return ""


def run_plist(cmd: List[str], timeout: int = 40) -> Optional[Any]:
    """Run a command emitting an XML plist and return the parsed object.

    ``system_profiler -xml`` is the only reliable machine-readable source for
    most hardware facts; parsing its human output is a trap (it reflows and
    localises).
    """
    if _FORCE_DEMO:
        return None
    try:
        completed = subprocess.run(
            cmd, capture_output=True, timeout=timeout, check=False
        )
        if not completed.stdout:
            return None
        return plistlib.loads(completed.stdout)
    except Exception:
        return None


def profiler(
    datatype: str, timeout: int = 40, detail: str = "mini"
) -> List[Dict[str, Any]]:
    """Return the ``_items`` list from a ``system_profiler`` datatype.

    ``detail`` matters more than it looks: at ``mini`` -- the safe default --
    system_profiler deliberately withholds identifying fields such as
    ``serial_number`` and ``platform_UUID``. Collectors that genuinely need
    those must opt in with ``detail="full"``, which is a deliberate speed bump
    on collecting hardware identifiers.
    """
    data = run_plist(
        ["system_profiler", "-xml", "-detailLevel", detail, datatype],
        timeout=timeout,
    )
    if not data or not isinstance(data, list) or not data:
        return []
    return data[0].get("_items", []) or []


def read_plist_file(path: str) -> Optional[Any]:
    """Parse a plist from disk, returning ``None`` if unreadable."""
    if _FORCE_DEMO:
        return None
    try:
        with open(os.path.expanduser(path), "rb") as fh:
            return plistlib.load(fh)
    except Exception:
        return None


def defaults_read(domain: str, key: str = "") -> str:
    """Read a `defaults` value, returning ``""`` when the key is absent."""
    cmd = ["defaults", "read", domain]
    if key:
        cmd.append(key)
    out = run(cmd, timeout=10).strip()
    if "does not exist" in out or out.startswith("20"):  # date-stamped error
        return ""
    return out


def sysctl(name: str) -> str:
    return run(["sysctl", "-n", name], timeout=8).strip()


def first_line(text: str, default: str = "") -> str:
    for line in text.splitlines():
        line = line.strip()
        if line:
            return line
    return default


def human_bytes(n) -> str:
    try:
        n = float(n)
    except (TypeError, ValueError):
        return str(n)
    for unit in ("B", "KB", "MB", "GB", "TB", "PB"):
        if abs(n) < 1024.0:
            return f"{n:.0f} {unit}" if unit == "B" else f"{n:.1f} {unit}"
        n /= 1024.0
    return f"{n:.1f} EB"


class Collector:
    """Base class for a single category collector."""

    key = "base"
    name = "Base"
    icon = "•"
    subtitle = ""

    def collect(self):  # -> Category
        raise NotImplementedError
