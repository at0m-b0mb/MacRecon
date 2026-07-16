"""Users collector: accounts, group membership, sessions, login history, keys.

Note on TCC: this collector deliberately never shells out to ``osascript``.
Asking System Events to enumerate login items is the widely-copied recipe, but
it trips an Automation consent prompt and blocks the scan behind a modal --
and a recon tool that mutates the target's privacy database to read it has
already failed. launchd agents (see :mod:`.processes`) cover the same
persistence ground from files we can simply read.
"""

from __future__ import annotations

import os
import pwd

from ..model import Category
from .base import Collector, is_demo, run


def _dscl_map(attribute: str) -> dict:
    """``dscl . -list /Users <attr>`` -> ``{user: value}``.

    One call per attribute beats one call per user; a Mac with a directory
    service bound can have hundreds of principals.
    """
    out = run(["dscl", ".", "-list", "/Users", attribute], timeout=20)
    mapping = {}
    for line in out.splitlines():
        parts = line.split(None, 1)
        if len(parts) == 2:
            mapping[parts[0].strip()] = parts[1].strip()
        elif len(parts) == 1:
            mapping[parts[0].strip()] = ""
    return mapping


def _group_members(group: str) -> set:
    out = run(["dscl", ".", "-read", f"/Groups/{group}", "GroupMembership"],
              timeout=15)
    if "GroupMembership:" not in out:
        return set()
    raw = out.split("GroupMembership:", 1)[1]
    return {m.strip() for m in raw.split() if m.strip()}


class UsersCollector(Collector):
    key = "users"
    name = "Users"
    icon = "👤"
    subtitle = "Accounts, privileges, sessions and login history"

    def collect(self) -> Category:
        if is_demo():
            from ..demo_data import users_demo

            return users_demo()

        cat = Category(self.key, self.name, self.icon, self.subtitle)

        uids = _dscl_map("UniqueID")
        homes = _dscl_map("NFSHomeDirectory")
        shells = _dscl_map("UserShell")
        real = _dscl_map("RealName")
        admins = _group_members("admin")

        # --- Human accounts -------------------------------------------------
        accounts = cat.new_section(
            "User Accounts", kind="table",
            headers=["User", "UID", "Real Name", "Admin", "Shell", "Home"],
            sensitive_cols=[0, 2, 5],
        )
        hidden = cat.new_section(
            "Service Accounts", kind="table",
            headers=["User", "UID", "Shell"],
        )

        for user in sorted(uids):
            uid = uids.get(user, "")
            shell = shells.get(user, "")
            # UID >= 500 and no leading underscore is the practical definition
            # of "a person" on macOS; _-prefixed daemons live below 500.
            try:
                is_human = int(uid) >= 500 and not user.startswith("_")
            except ValueError:
                is_human = False
            if is_human:
                accounts.add_row(
                    user,
                    uid,
                    real.get(user, ""),
                    "Yes" if user in admins else "No",
                    shell,
                    homes.get(user, ""),
                )
            else:
                hidden.add_row(user, uid, shell)
        hidden.note = (
            f"{len(hidden.table_rows)} system/service principals (UID < 500). "
            "Expected on every Mac; listed for completeness."
        )

        # --- Privileged groups ----------------------------------------------
        groups = cat.new_section(
            "Privileged Groups", kind="table",
            headers=["Group", "Members"],
            sensitive_cols=[1],
        )
        for g in ("admin", "wheel", "staff", "_developer",
                  "com.apple.access_ssh", "com.apple.access_screensharing"):
            members = _group_members(g)
            if members:
                groups.add_row(g, ", ".join(sorted(members)))
        groups.note = (
            "admin = sudo-capable. com.apple.access_ssh gates Remote Login "
            "when it is restricted to specific users."
        )

        # --- Current sessions -----------------------------------------------
        sessions = cat.new_section(
            "Active Sessions", kind="table",
            headers=["User", "TTY", "Since", "From"],
            sensitive_cols=[0, 3],
        )
        for line in run(["who"]).splitlines():
            parts = line.split()
            if len(parts) >= 3:
                frm = " ".join(parts[5:]).strip("()") if len(parts) > 5 else "local"
                sessions.add_row(parts[0], parts[1],
                                 " ".join(parts[2:5]), frm or "local")

        # --- Login history ---------------------------------------------------
        history = cat.new_section(
            "Recent Logins", kind="table",
            headers=["User", "TTY", "From", "When"],
            sensitive_cols=[0, 2],
        )
        for line in run(["last", "-20"]).splitlines()[:20]:
            if not line.strip() or line.startswith("wtmp"):
                continue
            parts = line.split()
            if len(parts) < 4:
                continue
            user, tty = parts[0], parts[1]
            if tty.startswith("tty") or tty.startswith("console") or tty == "ttys000":
                frm, when = "local", " ".join(parts[2:])
            else:
                frm, when = parts[2], " ".join(parts[3:])
            history.add_row(user, tty, frm, when)
        history.note = "From wtmp via `last`. Gaps here can indicate log tampering."

        # --- SSH material ----------------------------------------------------
        keys = cat.new_section(
            "SSH Keys & Trust", kind="table",
            headers=["User", "File", "Type", "Encrypted"],
            sensitive_cols=[0],
        )
        for user in sorted(uids):
            home = homes.get(user, "")
            if not home or not home.startswith("/Users"):
                continue
            ssh_dir = os.path.join(home, ".ssh")
            if not os.path.isdir(ssh_dir):
                continue
            try:
                names = sorted(os.listdir(ssh_dir))
            except PermissionError:
                keys.add_row(user, "~/.ssh", "(unreadable)", "—")
                continue
            except Exception:
                continue
            for name in names:
                path = os.path.join(ssh_dir, name)
                if name.endswith(".pub") or name in (
                    "known_hosts", "config", "known_hosts.old"
                ):
                    continue
                info = _key_info(path)
                if info:
                    keys.add_row(user, f"~/.ssh/{name}", info[0], info[1])
            auth = os.path.join(ssh_dir, "authorized_keys")
            if os.path.isfile(auth):
                try:
                    with open(auth, errors="replace") as fh:
                        n = len([l for l in fh if l.strip()
                                 and not l.startswith("#")])
                    keys.add_row(user, "~/.ssh/authorized_keys",
                                 f"{n} trusted key(s)", "—")
                except Exception:
                    pass
        keys.note = (
            "An unencrypted private key is a credential any process running as "
            "that user can copy silently."
        )

        return cat


def _key_info(path: str):
    """Classify an SSH private key and whether it is passphrase-protected.

    Only the header and the first base64 block are read -- never the key
    material itself, which stays out of memory and out of any report.
    """
    try:
        with open(path, "r", errors="replace") as fh:
            head = fh.read(2048)
    except Exception:
        return None
    if "PRIVATE KEY" not in head:
        return None

    if "OPENSSH PRIVATE KEY" in head:
        ktype = "OpenSSH"
    elif "RSA PRIVATE KEY" in head:
        ktype = "RSA (PEM)"
    elif "EC PRIVATE KEY" in head:
        ktype = "ECDSA (PEM)"
    elif "DSA PRIVATE KEY" in head:
        ktype = "DSA (PEM)"
    else:
        ktype = "Private key"

    if "OPENSSH PRIVATE KEY" in head:
        enc = _openssh_encrypted(head)
    elif "ENCRYPTED" in head or "DEK-Info" in head:
        # Legacy PEM advertises encryption in a plaintext header.
        enc = "Yes"
    else:
        enc = "No"
    return ktype, enc


def _openssh_encrypted(head: str) -> str:
    """Whether an openssh-key-v1 blob names a KDF (encrypted) or 'none'.

    The cipher and KDF names live *inside* the base64 body, not in the
    armour, so a text search for "bcrypt" against the file never matches --
    the body has to be decoded first.
    """
    import base64

    body = []
    for line in head.splitlines():
        if line.startswith("-----"):
            continue
        body.append(line.strip())
    try:
        blob = base64.b64decode("".join(body) + "===", validate=False)
    except Exception:
        return "Unknown"
    # Header layout: "openssh-key-v1\0" then length-prefixed cipher name.
    window = blob[:64]
    if b"bcrypt" in window:
        return "Yes"
    if b"none" in window:
        return "No"
    return "Unknown"
