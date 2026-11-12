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


def drop_target() -> tuple[int, int] | None:
    """Who to become after the capture socket is open.

    Under sudo that is the user who ran sudo (SUDO_UID/SUDO_GID). In a container there is no
    sudo, so NTA_DROP_UID/NTA_DROP_GID name an unprivileged user instead. Returns None when
    neither is set.
    """
    env = os.environ
    uid_s = env.get("SUDO_UID") or env.get("NTA_DROP_UID")
    gid_s = env.get("SUDO_GID") or env.get("NTA_DROP_GID")
    if not uid_s or not gid_s:
        return None
    try:
        uid, gid = int(uid_s), int(gid_s)
    except ValueError as exc:
        raise PrivilegeError("The user and group to drop to must be numbers.") from exc
    if uid <= 0 or gid <= 0:
        raise PrivilegeError("Refusing to keep running as root (the drop user or group is 0).")
    return uid, gid


def drop_to_sudo_user() -> str | None:
    """Switch to the unprivileged user from `drop_target`. Returns its name, or None if there
    is nobody to switch to (not root, or no sudo and no NTA_DROP_UID)."""
    if os.geteuid() != 0:
        return None
    target = drop_target()
    if target is None:
        return None
    uid, gid = target
    try:
        user = pwd.getpwuid(uid)
        name, home = user.pw_name, user.pw_dir
    except KeyError:                       # containers often have no passwd entry for it
        name, home = f"uid{uid}", "/tmp"  # noqa: S108 - the container's private tmpfs
    os.setgroups([])
    os.setgid(gid)
    os.setuid(uid)
    try:
        os.setuid(0)
    except PermissionError:
        pass
    else:
        raise PrivilegeError("Still able to regain root after dropping privileges.")
    os.environ["HOME"] = home
    os.environ["USER"] = name
    os.environ["LOGNAME"] = name
    return name
