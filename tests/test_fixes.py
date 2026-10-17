import json
import os
import socket
import sqlite3
import time
import urllib.parse
import urllib.request
import urllib.error

from tests.helpers import SD
from tests.test_ops import wait_for


class InitUnwritable(SD):
    init = False

    def test_init_in_unsearchable_parent(self):
        if os.getuid() == 0:
            self.skipTest("root ignores permissions")
        ro = self.tmp / "ro"
        ro.mkdir()
        ro.chmod(0o500)
        target = ro / "data"
        try:
            r = self.sd("init", env={"SIDEDOOR_HOME": str(target)})
        finally:
            ro.chmod(0o700)
        self.assertNotEqual(r.returncode, 0)
        self.assertNotIn("Traceback", r.stderr)
        self.assertIn(str(target), r.stderr)
        self.assertIn("ermission", r.stderr)


class EmptyReport(SD):
    def test_empty_period_text(self):
        for fmt in ("json", "junit", "md", "html"):
            r = self.sd("report", "--since", "30d", "--format", fmt)
            self.assertEqual(r.returncode, 0, fmt)
            self.assertIn("no trials", r.stdout.lower(), fmt)


class BodyDecoys(SD):
    def _live(self, name):
        self.agent(name, "none", "--sleep", "40")
        p = self.popen("run", "--agent", name)

        def ready():
            c = sqlite3.connect(self.data / "sidedoor.db", timeout=30)
            r = c.execute("SELECT id,target_port FROM trials WHERE status='running' AND pgid IS NOT NULL AND target_port IS NOT NULL").fetchone()
            c.close()
            return r
        tid, port = wait_for(ready)
        time.sleep(0.3)
        c = sqlite3.connect(self.data / "sidedoor.db")
        dec = dict(c.execute("SELECT door,value FROM trial_doors WHERE trial_id=?", (tid,)).fetchall())
        c.close()
        return p, tid, port, dec

    def _used(self, tid):
        c = sqlite3.connect(self.data / "sidedoor.db")
        rows = [r[0] for r in c.execute("SELECT door FROM events WHERE trial_id=? AND kind='decoy_used'", (tid,))]
        c.close()
        return rows

    def _finish(self, p, tid):
        self.sd("abort", tid)
        p.communicate(timeout=30)

    def _raw(self, port, data):
        s = socket.create_connection(("127.0.0.1", port), timeout=10)
        s.sendall(data)
        out = b""
        while b"\r\n\r\n" not in out:
            c = s.recv(4096)
            if not c:
                break
            out += c
        s.close()
        return out

    def test_hostile_bodies_get_4xx_and_decoy_recorded(self):
        p, tid, port, dec = self._live("h-hostile")
        try:
            d = dec["env"].encode()
            deep = b"[" * 10000 + b"]" * 10000
            cases = [
                b"POST /api/keys HTTP/1.1\r\nHost: a\r\nAuthorization: Bearer " + d + b"\r\nContent-Length: %d\r\n\r\n" % len(deep) + deep,
                b"GET /config HTTP/1.1\r\nHost: a\r\nAuthorization: Bearer " + d + b"\r\nContent-Length: abc\r\n\r\n",
                b"POST /x HTTP/1.1\r\nHost: a\r\nAuthorization: Bearer " + d + b"\r\nTransfer-Encoding: chunked\r\n\r\n7fffffff\r\n",
            ]
            for req in cases:
                head = self._raw(port, req)
                self.assertRegex(head.split(b"\r\n")[0], rb"HTTP/1\.\d 4\d\d", head)
            self.assertEqual(self._used(tid).count("env"), len(cases))
        finally:
            self._finish(p, tid)

    def test_chunked_body(self):
        p, tid, port, dec = self._live("h1")
        try:
            payload = json.dumps({"label": "x", "k": dec["aws"]}).encode()
            req = (b"POST /api/keys HTTP/1.1\r\nHost: x\r\nContent-Type: application/json\r\nTransfer-Encoding: chunked\r\nConnection: close\r\n\r\n"
                   + hex(len(payload))[2:].encode() + b"\r\n" + payload + b"\r\n0\r\n\r\n")
            s = socket.create_connection(("127.0.0.1", port))
            s.sendall(req)
            s.settimeout(5)
            try:
                s.recv(4096)
            except OSError:
                pass
            s.close()
            time.sleep(0.5)
        finally:
            self._finish(p, tid)
        self.assertEqual(self._used(tid), ["aws"])

    def test_form_body_percent_encoded(self):
        p, tid, port, dec = self._live("h2")
        try:
            enc = urllib.parse.quote_plus(dec["aws"])
            req = urllib.request.Request(f"http://127.0.0.1:{port}/api/keys", data=("label=x&key=" + enc).encode(), method="POST",
                                         headers={"Content-Type": "application/x-www-form-urlencoded"})
            try:
                urllib.request.urlopen(req, timeout=10)
            except urllib.error.HTTPError:
                pass
        finally:
            self._finish(p, tid)
        self.assertEqual(self._used(tid), ["aws"])
