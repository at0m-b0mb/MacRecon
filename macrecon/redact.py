"""Sensitive-value masking for screenshots, demos and shareable reports.

A recon report is, by construction, a list of everything that identifies a
machine: serial number, hardware UUID, MAC addresses, the operator's username,
saved Wi-Fi networks, internal addressing.  That is exactly what you want in
your own notes and exactly what you do *not* want in a screenshot on GitHub,
a slide, or a client-facing appendix.

Redaction runs as a post-processing pass over the collected
:class:`~macrecon.model.Category` tree, so it applies identically to the GUI
and to every export format. There is no path that writes a report bypassing it.

Design goals, in order:

1. **Never leak.** Unknown-but-suspicious shapes get masked, not passed through.
2. **Stay useful.** Masks keep the part that carries analytic meaning and drop
   the part that identifies. A MAC keeps its OUI (tells you *Apple*, not *which
   Mac*); an RFC1918 address keeps its /16 (tells you the subnet layout, not
   the host).
3. **Stay stable.** The same input maps to the same placeholder within a run,
   so "these three processes belong to the same user" survives redaction.
"""

from __future__ import annotations

import getpass
import ipaddress
import os
import re
from dataclasses import replace
from typing import Dict, List

from .model import Category, Finding, Section

# --- patterns ---------------------------------------------------------------

MAC_RE = re.compile(r"\b([0-9a-fA-F]{2}(?::[0-9a-fA-F]{2}){5})\b")
IPV4_RE = re.compile(r"\b(\d{1,3}(?:\.\d{1,3}){3})\b")
# Full-form IPv6 only: 8 hextets, so 7 colons. The obvious {2,7} version is a
# trap -- it also matches a wall-clock timestamp like "20:14:32", which turns
# every kernel build string into "<ipv6>". Compressed forms are matched
# separately by IPV6_ZERO_RE, which keys off the unambiguous "::".
IPV6_RE = re.compile(r"\b((?:[0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4})\b")
IPV6_ZERO_RE = re.compile(
    r"\b((?:[0-9a-fA-F]{1,4}:){1,6}:(?:[0-9a-fA-F]{1,4}:?){0,6})"
)
UUID_RE = re.compile(
    r"\b[0-9A-Fa-f]{8}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-"
    r"[0-9A-Fa-f]{4}-[0-9A-Fa-f]{12}\b"
)
EMAIL_RE = re.compile(r"\b([A-Za-z0-9._%+-]+)@([A-Za-z0-9.-]+\.[A-Za-z]{2,})\b")
# Apple serials: 10-12 alphanumerics, no vowels in the modern scheme.
SERIAL_RE = re.compile(r"\b([A-Z0-9]{3})([A-Z0-9]{7,9})\b")
HOME_RE = re.compile(r"/Users/([^/\s\"']+)")

# Names that identify no individual. Masking these is not merely noise -- it
# actively destroys meaning, because "/Users/Shared is world-writable" is the
# entire point of a finding that says so, and "root" masked to "<user-3>"
# makes a process listing unreadable while protecting nobody.
NOT_A_USER = {
    "shared", "guest", ".localized", "deleted users", "addhoc",
    "root", "daemon", "nobody", "wheel", "staff", "admin", "unknown",
}

MASK = "•" * 6  # bullet run, reads clearly as "removed" in screenshots


def _mask_mac(mac: str) -> str:
    """Keep the OUI (vendor), drop the device-unique half."""
    parts = mac.split(":")
    return ":".join(parts[:3] + ["xx", "xx", "xx"])


def _mask_v6_zero(m) -> str:
    """Mask a ``::``-compressed IPv6 address, keeping loopback readable."""
    v = m.group(1)
    stripped = v.rstrip(":")
    if stripped in ("::1", "::"):
        return v  # loopback / unspecified identify nobody
    if v.lower().startswith("fe80"):
        # Link-local: the host half is derived from the interface MAC, so the
        # scope prefix is safe to keep and the rest is not.
        return "fe80::<masked>"
    return "<ipv6>"


def _mask_ipv4(ip: str) -> str:
    """Keep the network shape for private space; erase public addresses."""
    try:
        addr = ipaddress.IPv4Address(ip)
    except ValueError:
        return ip
    if addr.is_loopback or addr.is_unspecified:
        return ip  # 127.0.0.1 / 0.0.0.0 identify nobody
    if addr.is_multicast or str(addr) == "255.255.255.255":
        return ip
    octets = ip.split(".")
    if addr.is_private or addr.is_link_local:
        # 192.168.x.x -- subnet layout is the analytically useful part.
        return f"{octets[0]}.{octets[1]}.x.x"
    return "<public-ip>"


class Redactor:
    """Masks identifying values in a collected category tree.

    Construct once per scan; the instance memoises placeholder assignments so
    the same SSID or username renders identically everywhere in the report.
    """

    def __init__(self, enabled: bool = True):
        self.enabled = enabled
        self._ssid_map: Dict[str, str] = {}
        self._user_map: Dict[str, str] = {}
        self._host_map: Dict[str, str] = {}
        # Real local identifiers, gathered up front so we can catch them even
        # when they appear inside free text we have no pattern for.
        self._literals: List[str] = []
        try:
            me = getpass.getuser()
            if me and len(me) > 2:
                self._literals.append(me)
        except Exception:
            pass
        try:
            import socket

            host = socket.gethostname()
            for cand in {host, host.split(".")[0], host.replace(".local", "")}:
                if cand and len(cand) > 2:
                    self._literals.append(cand)
        except Exception:
            pass
        try:
            for entry in os.listdir("/Users"):
                if not entry.startswith(".") and entry.lower() not in NOT_A_USER:
                    self._literals.append(entry)
        except Exception:
            pass
        # Longest-first so "kailash.parshad" masks before "kailash".
        self._literals = sorted(set(self._literals), key=len, reverse=True)

    # --- placeholder allocation -------------------------------------------
    def _placeholder(self, store: Dict[str, str], value: str, kind: str) -> str:
        key = value.lower()
        if key not in store:
            store[key] = f"<{kind}-{len(store) + 1}>"
        return store[key]

    def ssid(self, value: str) -> str:
        if not self.enabled or not value:
            return value
        return self._placeholder(self._ssid_map, value, "wifi")

    def user(self, value: str) -> str:
        if not self.enabled or not value:
            return value
        v = value.strip()
        # macOS service principals are all _-prefixed and identical on every
        # Mac, so they name no one.
        if v.lower() in NOT_A_USER or v.startswith("_"):
            return value
        return self._placeholder(self._user_map, v, "user")

    def host(self, value: str) -> str:
        if not self.enabled or not value:
            return value
        return self._placeholder(self._host_map, value, "host")

    # --- generic text sweep ------------------------------------------------
    def text(self, value: str) -> str:
        """Mask every identifying pattern found anywhere in ``value``."""
        if not self.enabled or not value:
            return value
        out = value

        # Order matters: MACs before IPv6, or a MAC's hextets get eaten by the
        # v6 patterns; UUIDs before anything that splits on '-'.
        out = MAC_RE.sub(lambda m: _mask_mac(m.group(1)), out)
        out = UUID_RE.sub("<uuid>", out)
        out = EMAIL_RE.sub(lambda m: f"{MASK}@{m.group(2)}", out)
        out = IPV4_RE.sub(lambda m: _mask_ipv4(m.group(1)), out)
        out = IPV6_RE.sub("<ipv6>", out)
        # Handles fe80:: link-local too -- masking it here rather than in its
        # own earlier pass avoids substituting into our own replacement text.
        out = IPV6_ZERO_RE.sub(_mask_v6_zero, out)
        out = HOME_RE.sub(lambda m: f"/Users/{self.user(m.group(1))}", out)

        for literal in self._literals:
            if literal in out:
                out = out.replace(literal, self.user(literal))

        return out

    def serial(self, value: str) -> str:
        if not self.enabled or not value:
            return value
        v = value.strip()
        if len(v) < 6:
            return MASK
        return v[:3] + "•" * (len(v) - 3)

    def full(self, value: str) -> str:
        """Mask a value completely, keeping only its length as a hint."""
        if not self.enabled or not value:
            return value
        return MASK

    # --- tree pass ---------------------------------------------------------
    def apply(self, categories: List[Category]) -> List[Category]:
        """Return a redacted deep copy; the originals are left untouched."""
        if not self.enabled:
            return categories
        return [self._category(c) for c in categories]

    def _category(self, cat: Category) -> Category:
        return Category(
            key=cat.key,
            name=cat.name,
            icon=cat.icon,
            subtitle=cat.subtitle,
            error=cat.error,
            sections=[self._section(s) for s in cat.sections],
        )

    def _section(self, sec: Section) -> Section:
        rows = []
        for label, value in sec.rows:
            if label in sec.sensitive_keys:
                rows.append((label, self._by_key(label, value)))
            else:
                rows.append((label, self.text(value)))

        table_rows = []
        for row in sec.table_rows:
            new_row = []
            for idx, cell in enumerate(row):
                if idx in sec.sensitive_cols:
                    header = sec.headers[idx] if idx < len(sec.headers) else ""
                    new_row.append(self._by_key(header, cell))
                else:
                    new_row.append(self.text(cell))
            table_rows.append(new_row)

        findings = [
            replace(
                f,
                detail=self.text(f.detail),
                recommendation=self.text(f.recommendation),
                evidence=self.text(f.evidence),
            )
            for f in sec.findings
        ]

        return Section(
            title=sec.title,
            kind=sec.kind,
            rows=rows,
            headers=list(sec.headers),
            table_rows=table_rows,
            findings=findings,
            note=sec.note,
            sensitive_cols=list(sec.sensitive_cols),
            sensitive_keys=list(sec.sensitive_keys),
        )

    def _by_key(self, key: str, value: str) -> str:
        """Mask a value a collector flagged, according to what the key means.

        Only values with no exploitable *structure* get a blanket mask -- a
        serial or an SSID is an opaque string no regex can partially preserve.
        Everything else falls through to the pattern sweep, which masks the
        identifying parts while keeping the parts an analyst is reading for.

        Blanket-masking the fallthrough case is tempting and wrong: it turns
        the Command and Program columns into rows of dots, so a launch item
        flagged "world-writable path" no longer shows the path. Redaction has
        to remove identity, not evidence.
        """
        if not value:
            return value
        k = (key or "").lower()

        if "serial" in k:
            return self.serial(value)
        if "udid" in k or "uuid" in k:
            # Structurally opaque, and platform_UUID pins the exact device.
            return self.full(value)
        if "ssid" in k or "network name" in k:
            return self.ssid(value)
        if "real name" in k:
            return self.full(value)
        if "computer name" in k or "hostname" in k or "host name" in k:
            return self.host(value)
        if k in ("user", "owner", "account", "current user"):
            return self.user(value)
        return self.text(value)


def scrub(categories: List[Category], enabled: bool = True) -> List[Category]:
    """One-shot convenience wrapper around :class:`Redactor`."""
    return Redactor(enabled).apply(categories)
