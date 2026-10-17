import datetime
import os
import re
import signal
import time


class SidedoorError(Exception):
    """A user-facing error. `code` is the process exit status."""

    def __init__(self, msg, code=64):
        super().__init__(msg)
        self.code = code


DURATION_RE = re.compile(r"^(\d+)([smhdw])$")
UNITS = {"s": 1, "m": 60, "h": 3600, "d": 86400, "w": 604800}


def parse_duration(text, what="duration"):
    m = DURATION_RE.match(str(text).strip())
    if not m or int(m.group(1)) == 0:
        raise SidedoorError(f"Invalid {what} '{text}': expected a positive number plus s, m, h, d or w (for example 90s, 30m, 12h, 30d, 2w)")
    return int(m.group(1)) * UNITS[m.group(2)]


def parse_when(text, flag):
    """A duration ago (30d) or an absolute date/datetime in local time -> epoch seconds."""
    t = str(text).strip()
    if DURATION_RE.match(t):
        return time.time() - parse_duration(t, flag)
    try:
        dt = datetime.datetime.fromisoformat(t)
        return dt.timestamp() if dt.tzinfo else dt.astimezone().timestamp()
    except ValueError:
        raise SidedoorError(f"Invalid {flag} value '{text}': expected a duration like 30d, 12h, 45m, 2w or a date like 2026-10-01 or 2026-10-01T12:30")


def fmt_ts(ts, with_date=True):
    if ts is None:
        return "-"
    d = datetime.datetime.fromtimestamp(ts).astimezone()
    return d.strftime("%Y-%m-%d %H:%M:%S" if with_date else "%H:%M:%S.%f")[:23]


def iso(ts):
    if ts is None:
        return None
    return datetime.datetime.fromtimestamp(ts, datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3] + "Z"


def mask(value):
    return "****" + value[-4:]


def proc_start(pid):
    """Process start time token (Linux), used to defeat pid reuse."""
    try:
        with open(f"/proc/{pid}/stat") as f:
            data = f.read()
        return data.rsplit(")", 1)[1].split()[19]
    except (OSError, IndexError):
        return None


def pid_alive(pid, start=None):
    if not pid:
        return False
    try:
        os.kill(pid, 0)
    except ProcessLookupError:
        return False
    except PermissionError:
        return True
    if start:
        cur = proc_start(pid)
        if cur is not None and cur != start:
            return False
    try:  # zombies count as dead
        with open(f"/proc/{pid}/stat") as f:
            if f.read().rsplit(")", 1)[1].split()[0] == "Z":
                return False
    except (OSError, IndexError):
        pass
    return True


def pgroup_alive(pgid):
    if not pgid:
        return False
    try:
        os.killpg(pgid, 0)
        return True
    except ProcessLookupError:
        return False
    except PermissionError:
        return True


def kill_group(pgid, sig=signal.SIGKILL):
    if not pgid or pgid <= 1:
        return
    try:
        os.killpg(pgid, sig)
    except (ProcessLookupError, PermissionError):
        pass


def table(headers, rows):
    rows = [[str(c) for c in r] for r in rows]
    widths = [max(len(h), *(len(r[i]) for r in rows)) if rows else len(h) for i, h in enumerate(headers)]
    lines = ["  ".join(h.ljust(w) for h, w in zip(headers, widths)).rstrip()]
    lines.append("  ".join("-" * w for w in widths))
    for r in rows:
        lines.append("  ".join(c.ljust(w) for c, w in zip(r, widths)).rstrip())
    return "\n".join(lines)


NAME_RE = re.compile(r"^[a-z0-9-]{1,40}$")


def check_name(name, what):
    if not NAME_RE.match(name or ""):
        raise SidedoorError(f"Invalid {what} name '{name}': use only a-z, 0-9 and '-', at most 40 characters")
    return name
