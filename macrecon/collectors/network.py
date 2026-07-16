"""Network collector: interfaces, Wi-Fi, DNS, routes, ARP, listening ports.

Everything here observes the local host only. MacRecon never scans, probes, or
sends a packet to another machine -- the listening-port view is read from the
kernel's own socket table, not from scanning yourself.
"""

from __future__ import annotations

import re

from ..model import Category
from .base import Collector, is_demo, profiler, run

# Ports that materially widen the remote attack surface if exposed.
RISKY_PORTS = {
    "21": "FTP (cleartext)",
    "23": "Telnet (cleartext)",
    "80": "HTTP (cleartext)",
    "445": "SMB",
    "548": "AFP",
    "3306": "MySQL",
    "3389": "RDP",
    "5432": "PostgreSQL",
    "5900": "VNC / Screen Sharing",
    "6379": "Redis",
    "27017": "MongoDB",
}


class NetworkCollector(Collector):
    key = "network"
    name = "Network"
    icon = "🌐"
    subtitle = "Interfaces, Wi-Fi, DNS, routing and open sockets"

    def collect(self) -> Category:
        if is_demo():
            from ..demo_data import network_demo

            return network_demo()

        cat = Category(self.key, self.name, self.icon, self.subtitle)

        # --- Hardware ports --------------------------------------------------
        ports = cat.new_section(
            "Interfaces", kind="table",
            headers=["Port", "Device", "MAC", "IPv4", "Status"],
            sensitive_cols=[2, 3],
        )
        for port, dev, mac in _hardware_ports():
            ip, status = _iface_state(dev)
            ports.add_row(port, dev, mac, ip or "—", status)

        # --- Wi-Fi ------------------------------------------------------------
        self._wifi(cat)

        # --- DNS / routing ----------------------------------------------------
        dns = cat.new_section("DNS & Routing")
        gw = ""
        route = run(["route", "-n", "get", "default"])
        for line in route.splitlines():
            if "gateway:" in line:
                gw = line.split(":", 1)[1].strip()
        dns.kv("Default Gateway", gw or "(none)")
        resolvers = []
        for line in run(["scutil", "--dns"]).splitlines():
            m = re.search(r"nameserver\[\d+\]\s*:\s*(\S+)", line)
            if m and m.group(1) not in resolvers:
                resolvers.append(m.group(1))
        dns.kv("Nameservers", ", ".join(resolvers[:6]) or "(none)")
        dns.kv("Search Domains",
               ", ".join(_search_domains()[:4]) or "(none)")
        proxy = _proxy_summary()
        dns.kv("Proxies", proxy or "None configured")
        if proxy and proxy != "None configured":
            dns.note = (
                "An unexpected proxy is a classic interception foothold — "
                "verify you configured it."
            )

        # --- VPN --------------------------------------------------------------
        vpn = cat.new_section(
            "VPN Configurations", kind="table",
            headers=["Name", "Type", "Status"],
            sensitive_cols=[0],
        )
        for line in run(["scutil", "--nc", "list"]).splitlines():
            if not line.strip().startswith("*"):
                continue
            m = re.match(r"\*\s*\((\w+)\)\s+\S+\s+(\S+)\s+.*?\"(.+?)\"", line)
            if m:
                status, vtype, name = m.groups()
                vpn.add_row(name, vtype, status)
        if not vpn.table_rows:
            vpn.note = "No VPN services configured."

        # --- ARP neighbours ---------------------------------------------------
        arp = cat.new_section(
            "ARP Neighbours", kind="table",
            headers=["IP Address", "MAC", "Interface"],
            sensitive_cols=[0, 1],
        )
        for line in run(["arp", "-a"]).splitlines()[:40]:
            m = re.match(r"\S*\s*\((\S+)\)\s+at\s+(\S+)\s+on\s+(\S+)", line)
            if m:
                arp.add_row(m.group(1), m.group(2), m.group(3))
        arp.note = (
            "Passively read from the local ARP cache — no hosts were probed. "
            "Two IPs sharing one MAC can indicate spoofing."
        )

        # --- Listening sockets -------------------------------------------------
        listen = cat.new_section(
            "Listening Ports", kind="table",
            headers=["Proto", "Local Address", "Port", "Service", "Exposure"],
            sensitive_cols=[1],
        )
        for row in _listening():
            listen.add_row(*row)
        listen.note = (
            "Exposure reflects the bind address: loopback is reachable only "
            "from this Mac; all-interfaces is reachable from the network."
        )

        return cat

    def _wifi(self, cat: Category) -> None:
        """Wi-Fi state via system_profiler.

        The ``airport`` CLI that most guides still reference was deprecated and
        then removed by Apple; on current macOS it exits 127. SPAirPortDataType
        is the supported source and needs no extra privileges.

        detail="full" is required here: at ``mini`` the interface reports its
        capabilities but omits ``spairport_current_network_information`` and
        the nearby-network scan entirely.
        """
        items = profiler("SPAirPortDataType", detail="full")
        if not items:
            return
        interfaces = items[0].get("spairport_airport_interfaces") or []
        if not interfaces:
            return

        iface = interfaces[0]
        current = iface.get("spairport_current_network_information") or {}

        wifi = cat.new_section("Wi-Fi")
        wifi.kv("Interface", iface.get("_name", ""))
        wifi.kv("Card Type", iface.get("spairport_wireless_card_type", ""))
        wifi.kv("Firmware", iface.get("spairport_wireless_firmware_version", ""))
        wifi.kv("MAC Address", iface.get("spairport_wireless_mac_address", ""),
                sensitive=True)
        wifi.kv("Country Code", iface.get("spairport_wireless_country_code", ""))
        if current:
            wifi.kv("Current SSID", current.get("_name", ""), sensitive=True)
            wifi.kv("Channel", current.get("spairport_network_channel", ""))
            wifi.kv("Security", _pretty_security(
                current.get("spairport_security_mode", "")))
            wifi.kv("PHY Mode", current.get("spairport_network_phymode", ""))
            wifi.kv("Signal / Noise", current.get("spairport_signal_noise", ""))
            wifi.kv("Transmit Rate", current.get("spairport_network_rate", ""))
        else:
            wifi.kv("Status", "Not associated")

        nearby = iface.get("spairport_airport_other_local_wireless_networks") or []
        if nearby:
            scan = cat.new_section(
                "Nearby Networks", kind="table",
                headers=["SSID", "Channel", "Security", "Signal"],
                sensitive_cols=[0],
            )
            for net in nearby[:25]:
                scan.add_row(
                    net.get("_name", ""),
                    net.get("spairport_network_channel", ""),
                    _pretty_security(net.get("spairport_security_mode", "")),
                    net.get("spairport_signal_noise", ""),
                )
            scan.note = (
                f"{len(nearby)} networks seen by the Wi-Fi radio. Open or WEP "
                "networks nearby are worth noting on an assessment."
            )


def _pretty_security(raw: str) -> str:
    if not raw:
        return ""
    return {
        "spairport_security_mode_wpa2_personal": "WPA2 Personal",
        "spairport_security_mode_wpa3_personal": "WPA3 Personal",
        "spairport_security_mode_wpa3_transition": "WPA2/WPA3 Transition",
        "spairport_security_mode_wpa2_enterprise": "WPA2 Enterprise",
        "spairport_security_mode_wpa3_enterprise": "WPA3 Enterprise",
        "spairport_security_mode_wep": "WEP (broken)",
        "spairport_security_mode_none": "Open (no encryption)",
    }.get(
        raw,
        raw.replace("spairport_security_mode_", "").replace("_", " ").title(),
    )


def _hardware_ports():
    """Parse ``networksetup -listallhardwareports`` into (port, device, mac)."""
    out = run(["networksetup", "-listallhardwareports"])
    rows, port, dev, mac = [], "", "", ""
    for line in out.splitlines():
        line = line.strip()
        if line.startswith("Hardware Port:"):
            port = line.split(":", 1)[1].strip()
        elif line.startswith("Device:"):
            dev = line.split(":", 1)[1].strip()
        elif line.startswith("Ethernet Address:"):
            mac = line.split(":", 1)[1].strip()
            if port and dev:
                rows.append((port, dev, mac))
            port, dev, mac = "", "", ""
    return rows


def _iface_state(dev: str):
    """Return ``(ipv4, status)`` for one BSD interface name."""
    out = run(["ifconfig", dev], timeout=8)
    if not out:
        return "", "not present"
    ip = ""
    m = re.search(r"inet (\d+\.\d+\.\d+\.\d+)", out)
    if m:
        ip = m.group(1)
    status = "inactive"
    if "status: active" in out:
        status = "active"
    elif "status: inactive" in out:
        status = "inactive"
    elif ip:
        status = "active"
    return ip, status


def _search_domains():
    doms = []
    for line in run(["scutil", "--dns"]).splitlines():
        m = re.search(r"search domain\[\d+\]\s*:\s*(\S+)", line)
        if m and m.group(1) not in doms:
            doms.append(m.group(1))
    return doms


def _proxy_summary():
    out = run(["scutil", "--proxy"])
    enabled = []
    for key, label in (("HTTPEnable", "HTTP"), ("HTTPSEnable", "HTTPS"),
                       ("SOCKSEnable", "SOCKS"), ("ProxyAutoConfigEnable", "PAC")):
        if re.search(rf"{key}\s*:\s*1", out):
            enabled.append(label)
    return ", ".join(enabled)


def _listening():
    """Listening TCP/UDP sockets from the kernel socket table."""
    rows = []
    seen = set()
    out = run(["netstat", "-an"], timeout=20)
    for line in out.splitlines():
        parts = line.split()
        if len(parts) < 4:
            continue
        proto = parts[0]
        if not proto.startswith(("tcp", "udp")):
            continue
        is_tcp = proto.startswith("tcp")
        if is_tcp and "LISTEN" not in line:
            continue
        local = parts[3]
        if "." not in local:
            continue
        addr, _, port = local.rpartition(".")
        if not port.isdigit():
            continue
        key = (proto, addr, port)
        if key in seen:
            continue
        seen.add(key)

        if addr in ("127.0.0.1", "::1", "localhost"):
            exposure = "Loopback only"
        elif addr in ("*", "0.0.0.0", "::"):
            exposure = "All interfaces"
        else:
            exposure = "Bound to address"
        rows.append([
            proto, addr or "*", port,
            RISKY_PORTS.get(port, _service_name(port)),
            exposure,
        ])
    rows.sort(key=lambda r: (r[4] != "All interfaces", int(r[2])))
    return rows[:60]


_SERVICES = {
    "22": "SSH", "53": "DNS", "88": "Kerberos", "111": "RPC",
    "443": "HTTPS", "631": "CUPS / printing", "5000": "AirPlay / dev server",
    "7000": "AirPlay", "8080": "HTTP alt", "49152": "Dynamic",
}


def _service_name(port: str) -> str:
    return _SERVICES.get(port, "")
