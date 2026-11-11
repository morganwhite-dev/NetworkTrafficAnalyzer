"""Give up root as soon as the capture device is open.

When started with sudo, the app opens the BPF capture socket while it is
still root and then switches to the user who ran sudo. Everything after that,
including the web server and every packet parser, runs unprivileged.
"""

from __future__ import annotations

import os
import pwd


class PrivilegeError(RuntimeError):
    pass


def running_as_root() -> bool:
    return os.geteuid() == 0


def drop_to_sudo_user() -> str | None:
    """Switch to SUDO_UID/SUDO_GID. Returns the user name, or None if not under sudo."""
    if os.geteuid() != 0:
        return None
    uid_s, gid_s = os.environ.get("SUDO_UID"), os.environ.get("SUDO_GID")
    if not uid_s or not gid_s:
        return None
    uid, gid = int(uid_s), int(gid_s)
    if uid == 0:
        raise PrivilegeError("SUDO_UID is 0; refusing to keep running as root.")
    user = pwd.getpwuid(uid)
    os.setgroups([])
    os.setgid(gid)
    os.setuid(uid)
    try:
        os.setuid(0)
    except PermissionError:
        pass
    else:
        raise PrivilegeError("Still able to regain root after dropping privileges.")
    os.environ["HOME"] = user.pw_dir
    os.environ["USER"] = user.pw_name
    os.environ["LOGNAME"] = user.pw_name
    return user.pw_name
