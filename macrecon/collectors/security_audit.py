"""Security audit: turn posture probes into graded, actionable findings.

Severity here answers "how much does this widen the attack surface of *this*
Mac", not "how scary does the word sound". A finding earns Critical only if it
removes a control the rest of the system's security assumes -- SIP being off
means every other check on this page is advisory at best, because a local
attacker can rewrite the tooling that reports them.

Every finding carries the command that produced it so a reader can verify the
claim rather than trust it.
"""

from __future__ import annotations

import os
import platform

from ..model import Category, Finding, Severity
from . import posture
from .base import Collector, is_demo, is_root, run


class SecurityAuditCollector(Collector):
    key = "audit"
    name = "Security Audit"
    icon = "🛡"
    subtitle = "Graded findings with remediation guidance"

    def collect(self) -> Category:
        if is_demo():
            from ..demo_data import audit_demo

            return audit_demo()

        cat = Category(self.key, self.name, self.icon, self.subtitle)
        sec = cat.new_section("Findings", kind="findings")
        p = posture.snapshot()

        def add(title, severity, detail, rec="", evidence=""):
            sec.add_finding(Finding(title, severity, detail, rec, evidence))

        # --- SIP ---------------------------------------------------------------
        state, raw = p["sip"]
        if state == "Disabled":
            add("System Integrity Protection is disabled", Severity.CRITICAL,
                "SIP is off. Protected system locations are writable by root, "
                "kernel extensions load unchecked, and process injection into "
                "Apple binaries is possible. Every other finding on this page "
                "is advisory while SIP is off, because the tooling that "
                "reports them can itself be modified.",
                "Reboot into Recovery (hold the power button on Apple Silicon) "
                "and run `csrutil enable`.", raw)
        elif state == "Custom":
            add("System Integrity Protection is partially disabled",
                Severity.HIGH,
                "SIP is running a custom configuration — one or more "
                "protections have been individually switched off.",
                "Run `csrutil clear` in Recovery to return to full protection.",
                raw)
        else:
            add("System Integrity Protection is enabled", Severity.GOOD,
                "SIP is protecting system locations, restricting kernel "
                "extension loading, and preventing injection into Apple "
                "binaries.", "", raw)

        # --- FileVault ----------------------------------------------------------
        state, raw = p["filevault"]
        if state == "Off":
            add("FileVault disk encryption is off", Severity.HIGH,
                "The internal disk is not encrypted at rest. Anyone with "
                "physical access can read every file by booting to Recovery or "
                "attaching the Mac in target-disk mode — no password needed.",
                "Enable in System Settings → Privacy & Security → FileVault, "
                "and store the recovery key somewhere other than this Mac.",
                raw)
        elif state == "Deferred":
            add("FileVault is enabled but not yet active", Severity.MEDIUM,
                "FileVault is scheduled to switch on at next login but the "
                "disk is not encrypted yet.",
                "Log out and back in to complete enablement.", raw)
        else:
            add("FileVault is on", Severity.GOOD,
                "The startup disk is encrypted at rest.", "", raw)

        # --- Gatekeeper ----------------------------------------------------------
        state, raw = p["gatekeeper"]
        if state == "Disabled":
            add("Gatekeeper assessments are disabled", Severity.HIGH,
                "macOS is not verifying the signature or notarisation of "
                "applications before they run. Any downloaded binary executes "
                "without an identity check.",
                "Run `sudo spctl --master-enable`, or re-enable in System "
                "Settings → Privacy & Security.", raw)
        else:
            add("Gatekeeper is enabled", Severity.GOOD,
                "Applications are checked for a valid signature and "
                "notarisation before first run.", "", raw)

        # --- Firewall -------------------------------------------------------------
        state, raw = p["firewall"]
        if state == "Off":
            add("Application firewall is off", Severity.MEDIUM,
                "Incoming connections are not filtered. Any service currently "
                "listening on a non-loopback address is reachable by every "
                "host on the local network — see the Network page for what is "
                "actually exposed.",
                "Enable in System Settings → Network → Firewall.", raw)
        else:
            add("Application firewall is on", Severity.GOOD,
                f"Incoming connections are filtered ({state}).", "", raw)
            stealth, sraw = p["firewall_stealth"]
            if stealth == "Off":
                add("Firewall stealth mode is off", Severity.LOW,
                    "The Mac answers ICMP pings and probes to closed ports, "
                    "confirming its presence to anyone sweeping the subnet.",
                    "Enable stealth mode in the firewall's Options panel.",
                    sraw)

        # --- Remote access ----------------------------------------------------------
        state, raw = p["remote_login"]
        if state == "On":
            add("Remote Login (SSH) is enabled", Severity.MEDIUM,
                "sshd is accepting connections. This is a fully remote, "
                "pre-authentication attack surface and the most common "
                "brute-force target on an exposed Mac.",
                "Disable it if unused (System Settings → General → Sharing). "
                "If needed, restrict it to key-only auth and limit access to "
                "the com.apple.access_ssh group.", raw)

        state, raw = p["screen_sharing"]
        if state == "On":
            add("Screen Sharing (VNC) is enabled", Severity.MEDIUM,
                "The screen-sharing service is running, exposing an "
                "interactive remote session on port 5900.",
                "Disable in System Settings → General → Sharing if not "
                "required.", raw)

        state, raw = p["remote_management"]
        if state in ("On", "Configured"):
            add("Apple Remote Desktop is present", Severity.MEDIUM,
                "The ARD agent is installed or loaded. ARD grants full "
                "interactive control and has a history of privilege-escalation "
                "issues.",
                "Disable Remote Management in Sharing if it is not in use.",
                raw)

        # --- Login policy -------------------------------------------------------------
        state, raw = p["auto_login"]
        if state == "Enabled":
            add("Automatic login is enabled", Severity.HIGH,
                "The Mac logs into a user account at boot without a password. "
                "This defeats FileVault's protection in practice: an attacker "
                "with the powered-off machine only has to turn it on.",
                "Disable in System Settings → Users & Groups → Login Options.",
                raw)

        state, raw = p["guest_account"]
        if state == "Enabled":
            add("Guest account is enabled", Severity.MEDIUM,
                "An unauthenticated user can log in and get local code "
                "execution, which is a foothold for local privilege-escalation "
                "chains.",
                "Disable the Guest User in System Settings → Users & Groups.",
                raw)

        # --- Patching --------------------------------------------------------------------
        state, raw = p["auto_updates"]
        if state == "Disabled":
            add("Automatic update checks are disabled", Severity.MEDIUM,
                "macOS is not checking for security updates. Apple ships "
                "actively-exploited fixes through this channel, often without "
                "a full OS upgrade.",
                "Re-enable in System Settings → General → Software Update.",
                raw)

        ver = platform.mac_ver()[0]
        if ver:
            major = int(ver.split(".")[0]) if ver.split(".")[0].isdigit() else 0
            # Apple provides security updates for roughly the current and two
            # previous majors.
            if 0 < major <= 12:
                add(f"macOS {ver} no longer receives security updates",
                    Severity.HIGH,
                    f"This Mac runs macOS {ver}. Apple supports approximately "
                    "the current release and the two before it; this version "
                    "is outside that window and will not receive fixes for "
                    "newly-discovered vulnerabilities.",
                    "Upgrade to a supported macOS release.",
                    f"sw_vers -productVersion -> {ver}")

        # --- Privilege -----------------------------------------------------------------
        state, raw = p["sudo_nopasswd"]
        if state == "Present":
            add("Passwordless sudo is configured", Severity.HIGH,
                "A sudoers rule grants NOPASSWD. Any process running as that "
                "user can escalate to root silently, with no password prompt "
                "to notice.",
                "Remove the NOPASSWD rule with `sudo visudo` unless it is "
                "required for a specific automation account.", raw)

        admins = _admin_users()
        if len(admins) > 2:
            add(f"{len(admins)} accounts have administrator rights",
                Severity.LOW,
                f"Admin group members: {', '.join(sorted(admins))}. Each is a "
                "sudo-capable path to root, so each is an equivalent target.",
                "Reduce to the minimum set and use standard accounts for "
                "day-to-day work.",
                "dscl . -read /Groups/admin GroupMembership")

        # --- Persistence -----------------------------------------------------------------
        self._persistence_findings(add)

        # --- SSH keys ---------------------------------------------------------------------
        naked = _unencrypted_keys()
        if naked:
            add(f"{len(naked)} SSH private key(s) without a passphrase",
                Severity.MEDIUM,
                "These private keys are stored unencrypted: "
                f"{', '.join(naked)}. Any process running as that user can "
                "copy them silently and reuse them anywhere they are trusted.",
                "Add a passphrase with `ssh-keygen -p -f <keyfile>`, and "
                "consider moving to a hardware-backed key.",
                "~/.ssh key headers")

        # --- Exposure -------------------------------------------------------------------------
        exposed = _exposed_ports()
        if exposed:
            listing = ", ".join(f"{p}/{n}" for p, n in exposed[:8])
            add(f"{len(exposed)} service(s) listening on all interfaces",
                Severity.MEDIUM if p["firewall"][0] == "Off" else Severity.LOW,
                f"Bound to 0.0.0.0 or ::, reachable from the network: "
                f"{listing}. "
                + ("The firewall is off, so these are reachable right now by "
                   "any host on the same network."
                   if p["firewall"][0] == "Off"
                   else "The firewall is filtering incoming connections, which "
                        "limits reachability."),
                "Bind development services to 127.0.0.1, and turn off sharing "
                "services you are not using.",
                "netstat -an | grep LISTEN")

        # --- Scan integrity ---------------------------------------------------------------------
        if not is_root():
            add("Scan ran without root — some checks were limited",
                Severity.INFO,
                "MacRecon deliberately runs unprivileged by default. A few "
                "checks (sudoers contents, firmware password, full BTM login "
                "items) need root and reported Unknown rather than guessing.",
                "For a complete audit run `sudo python3 macrecon.py --cli`. "
                "Read the source first — never run a security tool as root on "
                "someone else's word, including mine.",
                f"euid={os.geteuid()}")

        sec.findings.sort(key=lambda f: f.severity.rank)
        return cat

    def _persistence_findings(self, add) -> None:
        """Flag launch items whose program path or arguments look wrong."""
        from .processes import LAUNCH_DOMAINS, _read_job

        flagged = []
        total = 0
        for path, scope, _owner, is_third_party in LAUNCH_DOMAINS:
            if not is_third_party:
                continue
            expanded = os.path.expanduser(path)
            if not os.path.isdir(expanded):
                continue
            try:
                names = sorted(os.listdir(expanded))
            except Exception:
                continue
            for name in names:
                if not name.endswith(".plist"):
                    continue
                job = _read_job(os.path.join(expanded, name))
                if not job:
                    continue
                total += 1
                if job["flag"].startswith("⚠"):
                    flagged.append((job, scope))

        for job, scope in flagged:
            add(f"Suspicious launch item: {job['label']}", Severity.HIGH,
                f"A {scope} launch item runs `{job['program']}` "
                f"({job['flag'].lstrip('⚠ ')}). Legitimate software does not "
                "normally persist out of a world-writable path or fetch and "
                "evaluate code at load time.",
                "Inspect the plist and the program it points at. If you did "
                "not install it, treat this Mac as compromised until proven "
                "otherwise.",
                job["path"])

        if total and not flagged:
            add(f"{total} third-party launch items, none suspicious",
                Severity.INFO,
                f"{total} non-Apple launchd jobs are installed. None run from "
                "a world-writable path or evaluate downloaded code. They are "
                "listed in full on the Processes page — persistence is worth "
                "reviewing by eye even when nothing is flagged.",
                "Confirm each corresponds to software you installed "
                "deliberately.",
                "~/Library/LaunchAgents, /Library/Launch*")


def _admin_users():
    out = run(["dscl", ".", "-read", "/Groups/admin", "GroupMembership"],
              timeout=15)
    if "GroupMembership:" not in out:
        return []
    raw = out.split("GroupMembership:", 1)[1]
    return [m.strip() for m in raw.split() if m.strip() and m.strip() != "root"]


def _unencrypted_keys():
    from .users import _key_info

    found = []
    home = os.path.expanduser("~")
    ssh_dir = os.path.join(home, ".ssh")
    if not os.path.isdir(ssh_dir):
        return found
    try:
        names = sorted(os.listdir(ssh_dir))
    except Exception:
        return found
    for name in names:
        if name.endswith(".pub") or name in ("known_hosts", "config"):
            continue
        info = _key_info(os.path.join(ssh_dir, name))
        if info and info[1] == "No":
            found.append(f"~/.ssh/{name}")
    return found


def _exposed_ports():
    from .network import RISKY_PORTS, _listening

    out = []
    for proto, addr, port, service, exposure in _listening():
        if exposure == "All interfaces":
            out.append((port, service or RISKY_PORTS.get(port, proto)))
    return out
