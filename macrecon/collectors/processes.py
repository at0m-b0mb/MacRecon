"""Processes & persistence collector.

Persistence is where macOS intrusions actually live. An attacker who lands on a
Mac needs to survive a reboot, and the launchd domains below are the overwhelming
majority of how that is done in the wild. This collector enumerates every
launchd scope, separates Apple's own jobs from third-party ones, and resolves
each job to the program it actually executes -- because "com.adobe.updater" in
a plist filename means nothing if the ``Program`` key points at /tmp.
"""

from __future__ import annotations

import os
import plistlib

from ..model import Category
from .base import Collector, is_demo, run

# The launchd search domains, in the order an incident responder walks them.
# Per-user agents come first: they need no root to install, which makes them
# the cheapest persistence an attacker can buy.
LAUNCH_DOMAINS = [
    ("~/Library/LaunchAgents", "User Agent", "user", True),
    ("/Library/LaunchAgents", "Global Agent", "admin", True),
    ("/Library/LaunchDaemons", "Global Daemon", "root", True),
    ("/System/Library/LaunchAgents", "System Agent", "Apple", False),
    ("/System/Library/LaunchDaemons", "System Daemon", "Apple", False),
]

# Paths a legitimate launchd job essentially never executes from.
SUSPICIOUS_PREFIXES = (
    "/tmp/", "/private/tmp/", "/var/tmp/", "/Users/Shared/",
    "/private/var/tmp/", "/.hidden", "/Volumes/",
)


class ProcessesCollector(Collector):
    key = "processes"
    name = "Processes"
    icon = "⚡"
    subtitle = "Running processes, launchd jobs and persistence"

    def collect(self) -> Category:
        if is_demo():
            from ..demo_data import processes_demo

            return processes_demo()

        cat = Category(self.key, self.name, self.icon, self.subtitle)

        # --- Top processes -----------------------------------------------------
        top = cat.new_section(
            "Top Processes by CPU", kind="table",
            headers=["PID", "User", "CPU %", "MEM %", "Started", "Command"],
            sensitive_cols=[1, 5],
        )
        out = run(["ps", "-Ao", "pid,user,%cpu,%mem,lstart,command", "-r"],
                  timeout=20)
        for line in out.splitlines()[1:26]:
            parts = line.split(None, 4)
            if len(parts) < 5:
                continue
            pid, user, cpu, mem, rest = parts
            # lstart is five whitespace-separated fields; the command follows.
            rest_parts = rest.split(None, 5)
            started = " ".join(rest_parts[:5]) if len(rest_parts) >= 5 else ""
            command = rest_parts[5] if len(rest_parts) > 5 else rest
            top.add_row(pid, user, cpu, mem, started, command[:90])

        counts = _process_counts()
        summary = cat.new_section("Process Summary")
        summary.kv("Total Processes", counts["total"])
        summary.kv("Running as root", counts["root"])
        summary.kv("Running as you", counts["user"])
        summary.kv("Load Average", run(["sysctl", "-n", "vm.loadavg"]).strip())

        # --- launchd persistence -------------------------------------------------
        third_party = cat.new_section(
            "Third-Party Launch Items", kind="table",
            headers=["Label", "Scope", "Program", "RunAtLoad", "Flag"],
            sensitive_cols=[2],
        )
        apple_count = 0
        tp_rows = []
        for path, scope, _owner, is_third_party in LAUNCH_DOMAINS:
            expanded = os.path.expanduser(path)
            if not os.path.isdir(expanded):
                continue
            try:
                names = sorted(os.listdir(expanded))
            except PermissionError:
                continue
            except Exception:
                continue
            for name in names:
                if not name.endswith(".plist"):
                    continue
                job = _read_job(os.path.join(expanded, name))
                if not job:
                    continue
                if not is_third_party:
                    apple_count += 1
                    continue
                tp_rows.append((job, scope))

        for job, scope in tp_rows:
            third_party.add_row(
                job["label"], scope, job["program"],
                "Yes" if job["run_at_load"] else "No",
                job["flag"],
            )
        third_party.note = (
            f"{len(tp_rows)} third-party launch items across user, global and "
            f"daemon scopes ({apple_count} Apple items excluded). Every one of "
            "these runs automatically — this is the first place to look for "
            "persistence."
            if tp_rows else
            f"No third-party launch items. ({apple_count} Apple items excluded.)"
        )

        # --- Loaded jobs ---------------------------------------------------------
        loaded = cat.new_section(
            "Loaded launchd Jobs", kind="table",
            headers=["PID", "Status", "Label"],
        )
        lst = run(["launchctl", "list"], timeout=15)
        rows = []
        for line in lst.splitlines()[1:]:
            parts = line.split("\t")
            if len(parts) < 3:
                continue
            pid, status, label = parts[0], parts[1], parts[2]
            if label.startswith(("com.apple.", "application.com.apple")):
                continue
            rows.append((pid, status, label))
        for pid, status, label in rows[:40]:
            loaded.add_row(pid, status, label)
        loaded.note = (
            f"{len(rows)} non-Apple jobs currently loaded in launchd. "
            "A non-zero Status is a job that ran and exited with an error."
        )

        # --- cron / periodic ------------------------------------------------------
        cron = cat.new_section(
            "Scheduled Tasks", kind="table",
            headers=["Source", "Entry"],
            sensitive_cols=[1],
        )
        crontab = run(["crontab", "-l"], timeout=8)
        if crontab and "no crontab" not in crontab.lower():
            for line in crontab.splitlines():
                if line.strip() and not line.strip().startswith("#"):
                    cron.add_row("user crontab", line.strip())
        for d in ("/etc/periodic/daily", "/etc/periodic/weekly",
                  "/etc/periodic/monthly"):
            try:
                for name in sorted(os.listdir(d)):
                    # Apple ships 3 stock periodic scripts; anything else was
                    # added by someone.
                    if not name[0].isdigit() or not name.startswith(
                        ("100.", "110.", "130.", "199.", "400.", "410.",
                         "430.", "450.", "499.", "500.")
                    ):
                        cron.add_row(d.replace("/etc/periodic/", "periodic "),
                                     name)
            except Exception:
                continue
        cron.note = (
            "cron still works on macOS and is far less monitored than launchd."
            if cron.table_rows else
            "No user crontab and no non-stock periodic scripts."
        )

        return cat


def _read_job(path: str):
    """Parse a launchd plist into the fields that matter for triage."""
    try:
        with open(path, "rb") as fh:
            data = plistlib.load(fh)
    except Exception:
        return None
    if not isinstance(data, dict):
        return None

    label = str(data.get("Label", os.path.basename(path)[:-6]))
    program = data.get("Program", "")
    if not program:
        args = data.get("ProgramArguments") or []
        if isinstance(args, list) and args:
            program = " ".join(str(a) for a in args)
    program = str(program)

    run_at_load = bool(data.get("RunAtLoad", False))
    keep_alive = bool(data.get("KeepAlive", False))

    return {
        "label": label,
        "program": program or "(none)",
        "run_at_load": run_at_load,
        "keep_alive": keep_alive,
        "flag": _flag(program, data),
        "path": path,
    }


def _flag(program: str, data: dict) -> str:
    """Cheap heuristics that separate 'normal' from 'look at this now'.

    These are triage hints, not verdicts: a RunAtLoad job executing a shell
    one-liner out of /tmp is worth a human look, and saying so is the whole
    point of the column.
    """
    prog = program.strip()
    low = prog.lower()

    for prefix in SUSPICIOUS_PREFIXES:
        if prog.startswith(prefix) or f" {prefix}" in prog:
            return "⚠ world-writable path"
    if any(sh in low for sh in ("curl ", "wget ", "| sh", "|sh", "| bash",
                                "base64 -d", "osascript -e")):
        return "⚠ downloads or evals code"
    if low.startswith(("/bin/sh", "/bin/bash", "/bin/zsh")) and "-c" in low:
        return "⚠ inline shell"
    if data.get("StartInterval") or data.get("StartCalendarInterval"):
        return "scheduled"
    if data.get("KeepAlive"):
        return "keep-alive"
    if not prog or prog == "(none)":
        return "no program"
    return ""


def _process_counts():
    out = run(["ps", "-Ao", "user"], timeout=15)
    lines = [l.strip() for l in out.splitlines()[1:] if l.strip()]
    me = os.environ.get("USER", "")
    return {
        "total": len(lines),
        "root": sum(1 for l in lines if l == "root"),
        "user": sum(1 for l in lines if l == me),
    }
