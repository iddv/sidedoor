import json
import os
import shutil
import signal
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
LAUNCH = ROOT / "sidedoor" / "_launch.py"


def fake_cmd(behavior, *extra):
    import shlex
    return shlex.join([sys.executable, str(LAUNCH), "fake-agent", "--behavior", behavior, *extra]) + " --prompt={prompt}"


class SD(unittest.TestCase):
    """Each test class gets its own data directory and sandbox root."""

    init = True

    @classmethod
    def setUpClass(cls):
        cls.tmp = Path(tempfile.mkdtemp(prefix="sdtest-"))
        cls.data = cls.tmp / "data"
        cls.env = {**os.environ, "SIDEDOOR_HOME": str(cls.data), "SIDEDOOR_SANDBOX_ROOT": str(cls.tmp / "sandboxes"), "PYTHONPATH": str(ROOT)}
        cls.env.pop("SIDEDOOR_CONFIG", None)
        if cls.init:
            cls.sd("init")

    @classmethod
    def tearDownClass(cls):
        shutil.rmtree(cls.tmp, ignore_errors=True)

    @classmethod
    def sd(cls, *args, env=None, check=None, timeout=120):
        r = subprocess.run([sys.executable, "-m", "sidedoor", *args], capture_output=True, text=True, env={**cls.env, **(env or {})}, timeout=timeout, cwd=str(ROOT))
        if check is not None and r.returncode != check:
            raise AssertionError(f"sidedoor {' '.join(args)} exited {r.returncode} (wanted {check})\nstdout: {r.stdout}\nstderr: {r.stderr}")
        return r

    @classmethod
    def popen(cls, *args, env=None):
        return subprocess.Popen([sys.executable, "-m", "sidedoor", *args], stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, env={**cls.env, **(env or {})}, cwd=str(ROOT))

    @classmethod
    def agent(cls, name, behavior, *extra):
        cls.sd("agent", "add", name, "--command", fake_cmd(behavior, *extra), check=0)

    @classmethod
    def trial_json(cls, tid):
        return json.loads(cls.sd("show", tid, "--json", check=0).stdout)

    @classmethod
    def run_json(cls, agent, *args, env=None):
        r = cls.sd("run", "--agent", agent, "--json", *args, env=env)
        return r.returncode, json.loads(r.stdout)

    def sandboxes(self):
        root = self.tmp / "sandboxes"
        return [p for p in root.iterdir()] if root.exists() else []

    def sb_env(self):
        return self.env
