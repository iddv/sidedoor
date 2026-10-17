"""File-open detection on decoy files via inotify (Linux only)."""
import ctypes
import ctypes.util
import os
import select
import struct
import sys
import threading
import time

IN_OPEN = 0x20
IN_NONBLOCK = 0o4000
IN_CLOEXEC = 0o2000000
HDR = struct.Struct("iIII")


def _libc():
    return ctypes.CDLL(ctypes.util.find_library("c") or None, use_errno=True)


def available():
    if not sys.platform.startswith("linux"):
        return False, "inotify is Linux-only; file reads cannot be detected on this platform (shim calls and target requests still are)"
    try:
        libc = _libc()
        fd = libc.inotify_init1(IN_NONBLOCK | IN_CLOEXEC)
        if fd < 0:
            return False, f"inotify unavailable: {os.strerror(ctypes.get_errno())}"
        os.close(fd)
        return True, "inotify is available"
    except (OSError, AttributeError) as e:
        return False, f"inotify unavailable: {e}"


class Watcher:
    def __init__(self, on_read):
        self.libc = _libc()
        self.fd = self.libc.inotify_init1(IN_NONBLOCK | IN_CLOEXEC)
        if self.fd < 0:
            raise OSError(ctypes.get_errno(), "inotify_init1 failed")
        self.on_read = on_read  # (door, path, ts)
        self.wds = {}
        self.lock = threading.Lock()
        self._stop = threading.Event()
        self._thread = None

    def add(self, door, path):
        wd = self.libc.inotify_add_watch(self.fd, str(path).encode(), IN_OPEN)
        if wd < 0:
            raise OSError(ctypes.get_errno(), f"cannot watch {path}")
        self.wds[wd] = (door, str(path))

    def drain(self):
        with self.lock:
            while True:
                try:
                    buf = os.read(self.fd, 65536)
                except (BlockingIOError, OSError):
                    return
                off = 0
                while off + HDR.size <= len(buf):
                    wd, mask, _, ln = HDR.unpack_from(buf, off)
                    off += HDR.size + ln
                    if mask & IN_OPEN and wd in self.wds:
                        door, path = self.wds[wd]
                        self.on_read(door, path, time.time())

    def start(self):
        def loop():
            while not self._stop.is_set():
                try:
                    r, _, _ = select.select([self.fd], [], [], 0.05)
                except (OSError, ValueError):
                    return
                if r:
                    self.drain()

        self._thread = threading.Thread(target=loop, daemon=True)
        self._thread.start()

    def stop(self):
        self._stop.set()
        if self._thread:
            self._thread.join(timeout=2)
        self.drain()
        os.close(self.fd)
