"""Hardware collector: model, chip, memory, storage, battery, displays."""

from __future__ import annotations

import re

from ..model import Category
from .base import Collector, human_bytes, is_demo, profiler, run, sysctl


def _cores() -> str:
    """Decode ``number_processors``.

    Apple Silicon reports ``proc 14:10:4:0`` -- total : performance :
    efficiency : (reserved). Intel reports a plain integer.
    """
    raw = str(_hw().get("number_processors", ""))
    m = re.match(r"proc\s+(\d+):(\d+):(\d+)", raw)
    if m:
        total, perf, eff = m.groups()
        return f"{total} ({perf} performance + {eff} efficiency)"
    if raw:
        return raw
    phys = sysctl("hw.physicalcpu")
    logi = sysctl("hw.logicalcpu")
    if phys and logi:
        return f"{phys} physical / {logi} logical"
    return ""


_HW_CACHE = None


def _hw() -> dict:
    global _HW_CACHE
    if _HW_CACHE is None:
        # detail="full" because 'mini' strips serial_number and platform_UUID,
        # which are exactly the fields an asset inventory or a stolen-device
        # check needs. The redaction layer masks them on output.
        items = profiler("SPHardwareDataType", detail="full")
        _HW_CACHE = items[0] if items else {}
    return _HW_CACHE


class HardwareCollector(Collector):
    key = "hardware"
    name = "Hardware"
    icon = "⚙"
    subtitle = "Model, silicon, memory, storage and power"

    def collect(self) -> Category:
        if is_demo():
            from ..demo_data import hardware_demo

            return hardware_demo()

        cat = Category(self.key, self.name, self.icon, self.subtitle)
        hw = _hw()

        # --- Machine --------------------------------------------------------
        mach = cat.new_section("Machine")
        mach.kv("Model Name", hw.get("machine_name", ""))
        mach.kv("Model Identifier", hw.get("machine_model", ""))
        mach.kv("Model Number", hw.get("model_number", ""))
        mach.kv("Chip", hw.get("chip_type") or sysctl("machdep.cpu.brand_string"))
        mach.kv("Total Cores", _cores())
        mach.kv("Memory", hw.get("physical_memory")
                or human_bytes(sysctl("hw.memsize")))
        mach.kv("Serial Number", hw.get("serial_number", ""), sensitive=True)
        mach.kv("Hardware UUID", hw.get("platform_UUID", ""), sensitive=True)
        mach.kv("Provisioning UDID", hw.get("provisioning_UDID", ""),
                sensitive=True)
        mach.kv("Activation Lock",
                _pretty_activation(hw.get("activation_lock_status", "")))
        mach.kv("Boot ROM Version", hw.get("boot_rom_version", ""))
        mach.kv("OS Loader Version", hw.get("os_loader_version", ""))

        # --- CPU detail -----------------------------------------------------
        cpu = cat.new_section("Processor")
        cpu.kv("Brand", sysctl("machdep.cpu.brand_string")
               or hw.get("chip_type", ""))
        cpu.kv("Physical Cores", sysctl("hw.physicalcpu"))
        cpu.kv("Logical Cores", sysctl("hw.logicalcpu"))
        cpu.kv("L1 Cache (data)", human_bytes(sysctl("hw.l1dcachesize")))
        cpu.kv("L2 Cache", human_bytes(sysctl("hw.l2cachesize")))
        cpu.kv("Page Size", human_bytes(sysctl("hw.pagesize")))
        cpu.kv("Byte Order",
               "little-endian" if sysctl("hw.byteorder") == "1234" else "big-endian")

        # --- Memory ---------------------------------------------------------
        mem = cat.new_section("Memory")
        total = sysctl("hw.memsize")
        mem.kv("Total Physical", human_bytes(total))
        vm = run(["vm_stat"])
        page = 16384 if sysctl("hw.pagesize") == "16384" else 4096
        stats = {}
        for line in vm.splitlines():
            if ":" in line:
                k, v = line.split(":", 1)
                v = v.strip().rstrip(".")
                if v.isdigit():
                    stats[k.strip()] = int(v)
        if stats:
            free = stats.get("Pages free", 0) * page
            active = stats.get("Pages active", 0) * page
            inactive = stats.get("Pages inactive", 0) * page
            wired = stats.get("Pages wired down", 0) * page
            compressed = stats.get("Pages occupied by compressor", 0) * page
            mem.kv("Free", human_bytes(free))
            mem.kv("Active", human_bytes(active))
            mem.kv("Inactive", human_bytes(inactive))
            mem.kv("Wired", human_bytes(wired))
            mem.kv("Compressed", human_bytes(compressed))
        swap = sysctl("vm.swapusage")
        if swap:
            mem.kv("Swap", swap)

        # --- Storage --------------------------------------------------------
        store = cat.new_section(
            "Storage", kind="table",
            headers=["Volume", "Size", "Used", "Free", "Used %", "Filesystem"],
        )
        for row in _volumes():
            store.add_row(*row)

        # --- Graphics -------------------------------------------------------
        gfx = cat.new_section(
            "Graphics & Displays", kind="table",
            headers=["Chipset", "Type", "Cores/VRAM", "Displays"],
        )
        for item in profiler("SPDisplaysDataType"):
            displays = item.get("spdisplays_ndrvs") or []
            gfx.add_row(
                item.get("sppci_model", item.get("_name", "")),
                item.get("sppci_device_type", "").replace(
                    "spdisplays_", "").replace("_", " ").title(),
                item.get("sppci_cores") or item.get("spdisplays_vram")
                or item.get("spdisplays_vram_shared") or "",
                ", ".join(d.get("_name", "") for d in displays) or "None",
            )

        # --- Power ----------------------------------------------------------
        power = cat.new_section("Power & Battery")
        batt = run(["pmset", "-g", "batt"])
        if "InternalBattery" in batt:
            m = re.search(r"(\d+)%", batt)
            power.kv("Charge", f"{m.group(1)}%" if m else "")
            state = "Unknown"
            for s in ("charging", "discharging", "charged", "AC attached"):
                if s in batt.lower():
                    state = s.title()
                    break
            power.kv("State", state)
            power.kv("Power Source",
                     "AC Power" if "AC Power" in batt else "Battery Power")
            for item in profiler("SPPowerDataType"):
                health = item.get("sppower_battery_health_info") or {}
                if health:
                    power.kv("Cycle Count",
                             health.get("sppower_battery_cycle_count", ""))
                    power.kv("Condition",
                             health.get("sppower_battery_health", ""))
                    power.kv("Maximum Capacity",
                             health.get("sppower_battery_health_maximum_capacity",
                                        ""))
        else:
            power.kv("Battery", "None (desktop or AC-only)")
            power.kv("Power Source", "AC Power")

        return cat


def _pretty_activation(raw: str) -> str:
    if not raw:
        return ""
    return {
        "activation_lock_enabled": "Enabled",
        "activation_lock_disabled": "Disabled",
    }.get(raw, raw.replace("activation_lock_", "").title())


def _volumes():
    """Parse ``df -k`` into per-volume rows, skipping pseudo filesystems."""
    out = run(["df", "-k", "-l"])
    rows = []
    for line in out.splitlines()[1:]:
        parts = line.split()
        if len(parts) < 9:
            continue
        fs, blocks, used, avail, pct = parts[0], parts[1], parts[2], parts[3], parts[4]
        mount = " ".join(parts[8:])
        # Skip the read-only system snapshot and VM/system overlays: they are
        # implementation detail, not capacity a reader cares about.
        if mount.startswith(("/System/Volumes/", "/dev", "/private/var/vm")):
            if mount not in ("/System/Volumes/Data",):
                continue
        if not fs.startswith("/dev/"):
            continue
        try:
            rows.append([
                mount,
                human_bytes(int(blocks) * 1024),
                human_bytes(int(used) * 1024),
                human_bytes(int(avail) * 1024),
                pct,
                fs,
            ])
        except ValueError:
            continue
    return rows
