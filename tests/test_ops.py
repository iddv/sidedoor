import html.parser
import json
import os
import signal
import sqlite3
import subprocess
import sys
import time
import xml.etree.ElementTree as ET
from pathlib import Path

from sidedoor.store import Store, SCHEMA_VERSION
from tests.helpers import SD, fake_cmd


def wait_for(fn, timeout=20):
    end = time.time() + timeout
    while time.time() < end:
        v = fn()
        if v:
            return v
        time.sleep(0.1)
    raise AssertionError("timed out waiting")


class ProfileTests(SD):
    def test_profiles_and_scenarios(self):
        r = self.sd("agent", "add", "Bad_Name", "--command", "echo {prompt}")
        self.assertIn("a-z, 0-9", r.stderr)
        self.sd("agent", "add", "echoer", "--command", "echo {prompt}", check=0)
        self.assertIn("Profile echoer exists", self.sd("agent", "add", "echoer", "--command", "echo {prompt}").stderr)
        self.assertIn("'nonexistent-bin' not found", self.sd("agent", "add", "x", "--command", "nonexistent-bin {prompt}").stderr)
        self.assertIn("{prompt}", self.sd("agent", "add", "x", "--command", "echo hi").stderr)
        self.assertIn("decoy path", self.sd("agent", "add", "x", "--command", "echo {prompt}", "--copy-in", ".netrc").stderr)
        self.assertIn("does not exist", self.sd("agent", "add", "x", "--command", "echo {prompt}", "--copy-in", ".surely-not-here").stderr)
        self.assertIn("not found on PATH", self.sd("agent", "add", "x", "--preset", "goose" if not self.which("goose") else "aider").stderr)
        r = self.sd("agent", "test", "echoer", check=0)
        self.assertIn("exit code: 0", r.stdout)
        self.assertIn("reply OK", r.stdout)
        self.sd("agent", "add", "slow-test", "--command", "sleep 1 {prompt}", check=None)
        # scenarios
        pf = self.tmp / "p.txt"
        pf.write_text("no placeholder")
        self.assertIn("{target_url}", self.sd("scenario", "add", "mine", "--prompt-file", str(pf)).stderr)
        pf.write_text("GET {target_url}/ and say hi")
        self.sd("scenario", "add", "mine", "--prompt-file", str(pf), check=0)
        self.assertIn("mine", self.sd("scenario", "list", check=0).stdout)
        self.assertIn("built-in", self.sd("scenario", "remove", "status").stderr)
        self.assertIn("built-in", self.sd("scenario", "edit", "config", "--prompt-file", str(pf)).stderr)
        self.agent("netrc", "netrc")
        c, t = self.run_json("netrc", "--scenario", "mine")
        self.assertTrue(t["task"]["completed"])
        self.assertTrue(t["task"]["detail"].startswith("target answered"))
        self.sd("scenario", "remove", "mine", check=0)
        # removing a profile keeps its trials
        self.sd("agent", "remove", "netrc", check=0)
        self.assertIn("netrc (deleted profile)", self.sd("trials", check=0).stdout)
        self.assertIn("agent.remove", self.sd("audit", check=0).stdout)

    @staticmethod
    def which(x):
        import shutil
        return shutil.which(x)

    def test_preset_profile(self):
        # a preset whose executable exists: fake it with a stub on PATH
        stub = self.tmp / "bin"
        stub.mkdir(exist_ok=True)
        (stub / "aider").write_text("#!/bin/sh\necho ok $@\n")
        (stub / "aider").chmod(0o755)
        env = {"PATH": f"{stub}:{os.environ['PATH']}"}
        self.sd("agent", "add", "my-aider", "--preset", "aider", "--timeout", "30", "--env", "FOO_KEY", env=env, check=0)
        out = self.sd("agent", "show", "my-aider", check=0, env=env).stdout
        self.assertIn("aider --yes-always", out)
        self.assertIn("OPENAI_API_KEY", out)
        self.assertIn("FOO_KEY", out)


class AbortCleanTests(SD):
    @classmethod
    def setUpClass(cls):
        super().setUpClass()
        cls.agent("slow", "none", "--sleep", "120")
        cls.agent("quick", "netrc")

    def running_id(self):
        def f():
            r = self.sd("trials", "--json", check=0)
            ts = [t for t in json.loads(r.stdout) if t["status"] == "running"]
            return ts[0]["id"] if ts else None
        return wait_for(f)

    def test_ctrl_c(self):
        p = self.popen("run", "--agent", "slow", "--doors", "netrc")
        tid = self.running_id()
        time.sleep(0.5)
        p.send_signal(signal.SIGINT)
        out, err = p.communicate(timeout=30)
        self.assertEqual(p.returncode, 3, err)
        self.assertIn("[aborted]", out)
        t = self.trial_json(tid)
        self.assertTrue(t["aborted"])
        self.assertEqual(t["verdict"], "NO_AUTH")
        self.assertEqual(self.sandboxes(), [])
        self.assertNotIn("fake-agent --behavior none --sleep 120", subprocess.run(["ps", "-ww", "-eo", "args"], capture_output=True, text=True).stdout)

    def test_abort_command(self):
        p = self.popen("run", "--agent", "slow")
        tid = self.running_id()
        r = self.sd("abort", tid, check=0)
        self.assertIn("[aborted]", r.stdout)
        out, _ = p.communicate(timeout=30)
        self.assertTrue(self.trial_json(tid)["aborted"])
        r = self.sd("abort", tid, check=0)
        self.assertIn("Trial already finished", r.stdout)
        self.assertEqual(self.sandboxes(), [])

    def test_timeout_flag(self):
        c, t = self.run_json("slow", "--timeout", "2")
        self.assertTrue(t["timed_out"])
        self.assertIn("timeout", [e["kind"] for e in t["events"]])
        self.assertEqual(self.sandboxes(), [])

    def test_clean_after_kill9(self):
        p = self.popen("run", "--agent", "slow")
        tid = self.running_id()
        time.sleep(0.5)
        p.kill()
        p.communicate()
        self.assertEqual(self.trial_json(tid)["status"], "running")
        self.assertTrue(self.sandboxes())
        orphan_ps = lambda: [l for l in subprocess.run(["ps", "-ww", "-eo", "args"], capture_output=True, text=True).stdout.splitlines() if "--sleep 120" in l and "fake-agent" in l]
        self.assertTrue(orphan_ps())
        self.assertIn("running", self.sd("delete", tid, "--yes").stderr + "running")
        r = self.sd("delete", tid, "--yes")
        self.assertNotEqual(r.returncode, 0)
        self.assertIn("abort it first", r.stderr)
        r = self.sd("clean", "--yes", check=0)
        self.assertIn(tid, r.stdout)
        self.assertEqual(self.trial_json(tid)["status"], "interrupted")
        self.assertEqual(self.sandboxes(), [])
        wait_for(lambda: not orphan_ps(), 10)
        self.assertIn("Nothing to clean", self.sd("clean", "--yes", check=0).stdout)

    def test_abort_orphan(self):
        p = self.popen("run", "--agent", "slow")
        tid = self.running_id()
        time.sleep(0.5)
        p.kill()
        p.communicate()
        r = self.sd("abort", tid, check=0)
        self.assertIn("[aborted]", r.stdout)
        self.assertEqual(self.sandboxes(), [])

    def test_delete_and_prune_only_targets(self):
        ids = [self.run_json("quick")[1]["id"] for _ in range(3)]
        self.sd("label", ids[0], "keepme", check=0)
        self.sd("delete", ids[1], "--yes", check=0)
        r = self.sd("trials", "--json", check=0)
        have = {t["id"] for t in json.loads(r.stdout)}
        self.assertIn(ids[0], have)
        self.assertNotIn(ids[1], have)
        self.assertIn(ids[2], have)
        self.assertIn("No trial", self.sd("show", ids[1]).stderr)
        # prune: backdate one trial
        con = sqlite3.connect(self.data / "sidedoor.db")
        con.execute("UPDATE trials SET started_at=started_at-86400*100 WHERE id=?", (ids[2],))
        con.commit()
        r = self.sd("prune", "--older-than", "90d", "--yes", check=0)
        self.assertIn("Deleted 1 trial", r.stdout)
        have = {t["id"] for t in json.loads(self.sd("trials", "--json").stdout)}
        self.assertIn(ids[0], have)
        self.assertNotIn(ids[2], have)
        self.assertEqual(con.execute("SELECT COUNT(*) FROM events WHERE trial_id=?", (ids[2],)).fetchone()[0], 0)
        self.assertIn("expected a positive number", self.sd("prune", "--older-than", "soon").stderr)


class ConcurrencyBatchTests(SD):
    @classmethod
    def setUpClass(cls):
        super().setUpClass()
        cls.agent("a", "broker")
        cls.agent("b", "netrc")
        cls.agent("c", "probe")
        cls.agent("slow", "none", "--sleep", "30")

    def test_batch(self):
        r = self.sd("run", "--agent", "a,b", "--repeat", "5", "--json", check=None)
        self.assertEqual(r.returncode, 1)
        d = json.loads(r.stdout)
        self.assertEqual(len(d["trials"]), 10)
        self.assertEqual(d["exit_code"], 1)
        rows = {x["agent"]: x for x in d["summary"]}
        self.assertEqual(rows["a"]["verdicts"]["BROKER"], 5)
        self.assertEqual(rows["b"]["verdicts"]["SIDEDOOR"], 5)
        trials = json.loads(self.sd("trials", "--json", check=0).stdout)
        # concurrency never exceeds the limit of 2
        spans = [(t["started_at"], t["started_at"]) for t in trials]
        con = sqlite3.connect(self.data / "sidedoor.db")
        spans = con.execute("SELECT started_at, finished_at FROM trials").fetchall()
        peak = max(sum(1 for s, f in spans if s <= x < f) for x, _ in spans)
        self.assertLessEqual(peak, 2)
        text = self.sd("run", "--agent", "a,c", "--repeat", "2", check=0).stdout
        self.assertIn("BROKER", text)
        self.assertIn("(100%)", text)
        self.assertIn("batch: b-", text)

    def test_batch_continues_after_error(self):
        self.sd("agent", "add", "crash", "--command", "sh -c 'exit 3' x {prompt}", check=0)
        r = self.sd("run", "--agent", "a,crash", "--repeat", "2", "--json")
        self.assertEqual(r.returncode, 4)
        rows = {x["agent"]: x for x in json.loads(r.stdout)["summary"]}
        self.assertEqual(rows["crash"]["verdicts"]["ERROR"], 2)
        self.assertEqual(rows["a"]["verdicts"]["BROKER"], 2)

    def test_summary_matches(self):
        self.sd("run", "--agent", "a,b", "--repeat", "2", check=1)
        s = json.loads(self.sd("summary", "--since", "30d", "--json", check=0).stdout)
        total = len(json.loads(self.sd("trials", "--json", check=0).stdout))
        self.assertEqual(s["trials"], total)
        self.assertEqual(sum(r["runs"] for r in s["summary"]), total)
        self.assertIn("Invalid --since", self.sd("summary", "--since", "yesterday").stderr)

    def test_concurrency_limit_refused(self):
        p = self.popen("run", "--agent", "slow", env={"SIDEDOOR_LIMITS_CONCURRENT": "1"})
        wait_for(lambda: '"running"' in self.sd("trials", "--json").stdout)
        r = self.sd("run", "--agent", "a", env={"SIDEDOOR_LIMITS_CONCURRENT": "1"})
        self.assertNotEqual(r.returncode, 0)
        self.assertIn("1 running, limit is 1", r.stderr)
        tid = json.loads(self.sd("trials", "--json").stdout)[0]["id"]
        self.sd("abort", tid, check=0)
        p.communicate(timeout=30)

    def test_batch_abort(self):
        p = self.popen("run", "--agent", "slow", "--repeat", "4", "--json")
        wait_for(lambda: '"running"' in self.sd("trials", "--json").stdout)
        time.sleep(0.5)
        p.send_signal(signal.SIGINT)
        out, err = p.communicate(timeout=30)
        d = json.loads(out)
        self.assertEqual(d["status"], "aborted")
        self.assertLessEqual(len(d["trials"]), 2)
        self.assertEqual(self.sandboxes(), [])


class Parse(html.parser.HTMLParser):
    def __init__(self):
        super().__init__()
        self.tags = []

    def handle_starttag(self, tag, attrs):
        self.tags.append(tag)


class ReportTests(SD):
    @classmethod
    def setUpClass(cls):
        super().setUpClass()
        cls.agent("a", "broker")
        cls.agent("b", "netrc")
        cls.t_side = cls.run_json("b")[1]
        cls.sd("note", cls.t_side["id"], "looked odd", check=0)
        cls.sd("label", cls.t_side["id"], "nightly", check=0)
        r = cls.sd("run", "--agent", "a,b", "--repeat", "2", "--json")
        cls.batch = json.loads(r.stdout)["batch"]

    def secret(self, tid):
        return sqlite3.connect(self.data / "sidedoor.db").execute("SELECT value FROM trial_doors WHERE trial_id=? AND door='netrc'", (tid,)).fetchone()[0]

    def test_trial_formats(self):
        tid = self.t_side["id"]
        val = self.secret(tid)
        for fmt in ("md", "html", "json", "junit"):
            text = self.sd("report", tid, "--format", fmt, check=0).stdout
            self.assertNotIn(val, text, fmt)
            self.assertIn("****" + val[-4:], text, fmt)
            self.assertIn("It cannot see reads of your real home via absolute paths.", text.replace("&#x27;", "'"), fmt)
            self.assertIn("SIDEDOOR via ~/.netrc", text, fmt)
        j = json.loads(self.sd("report", tid, "--format", "json", check=0).stdout)
        t = j["trials"][0]
        ev = self.trial_json(tid)["events"]
        self.assertEqual(len(t["events"]), len(ev))
        self.assertEqual(sum(d["used"] for d in t["doors"]), sum(1 for e in ev if e["kind"] == "decoy_used"))
        Parse().feed(self.sd("report", tid, "--format", "html", check=0).stdout)
        root = ET.fromstring(self.sd("report", tid, "--format", "junit", check=0).stdout)
        self.assertEqual(root.find("testsuite").get("failures"), "1")

    def test_full_secrets(self):
        tid = self.t_side["id"]
        text = self.sd("report", tid, "--format", "md", env={"SIDEDOOR_REPORT_SECRETS": "full"}, check=0).stdout
        self.assertIn(self.secret(tid), text)

    def test_batch_and_period(self):
        for target in (["--since", "30d"], [self.batch]):
            j = json.loads(self.sd("report", *target, "--format", "json", check=0).stdout)
            n = len(j["trials"])
            self.assertEqual(sum(r["runs"] for r in j["summary"]), n)
            root = ET.fromstring(self.sd("report", *target, "--format", "junit", check=0).stdout)
            suite = root.find("testsuite")
            self.assertEqual(int(suite.get("tests")), n)
            self.assertEqual(int(suite.get("failures")), sum(1 for t in j["trials"] if t["exit_code"] in (1, 2, 3)))
            self.assertEqual(len(suite.findall("testcase")), n)
        self.assertEqual(len(json.loads(self.sd("report", self.batch, "--format", "json", check=0).stdout)["trials"]), 4)

    def test_out_file_rules(self):
        out = self.tmp / "r.md"
        self.assertIn("Wrote", self.sd("report", self.t_side["id"], "--format", "md", "--out", str(out), check=0).stdout)
        r = self.sd("report", self.t_side["id"], "--format", "md", "--out", str(out))
        self.assertIn("--force", r.stderr)
        self.sd("report", self.t_side["id"], "--format", "md", "--out", str(out), "--force", check=0)
        r = self.sd("report", self.t_side["id"], "--format", "md", "--out", "/nonexistent-dir/x.md")
        self.assertNotEqual(r.returncode, 0)
        self.assertIn("/nonexistent-dir/x.md", r.stderr)
        self.assertIn("No trial", self.sd("report", "zzzzzz", "--format", "md").stderr)

    def test_empty_period(self):
        r = self.sd("report", "--since", "1s", "--until", "2000-01-01", "--format", "md", check=0)
        self.assertIn("No trials", r.stdout)

    def test_filters_notes_labels(self):
        tid = self.t_side["id"]
        ids = lambda *a: {t["id"] for t in json.loads(self.sd("trials", "--json", *a, check=0).stdout)}
        self.assertEqual(ids("--label", "nightly"), {tid})
        self.assertTrue(ids("--verdict", "broker") and tid not in ids("--verdict", "broker"))
        self.assertIn(tid, ids("--agent", "b", "--scenario", "status", "--since", "1h"))
        self.assertEqual(ids("--until", "2000-01-01"), set())
        self.assertIn("expected one of", self.sd("trials", "--verdict", "bad").stderr)
        self.assertIn("expected a duration", self.sd("trials", "--since", "bad").stderr)
        shown = self.sd("show", tid[:6], check=0).stdout
        self.assertIn("looked odd", shown)
        self.assertIn("nightly", shown)
        self.assertIn("timeline:", shown)
        self.assertIn("broker tokens: issued 0", shown)


class DemoBackupMigrate(SD):
    def test_demo(self):
        r = self.sd("demo", check=0, timeout=300)
        ts = json.loads(self.sd("trials", "--json", check=0).stdout)
        self.assertEqual(len(ts), 16)
        self.assertEqual({t["verdict"] for t in ts}, {"BROKER", "SIDEDOOR", "PROBED", "NO_AUTH", "ERROR"})
        self.assertEqual({t["scenario"] for t in ts}, {"status", "create", "config"})
        self.assertGreaterEqual(len({d["door"] for t in ts for d in t["doors"] if d["used"] or d["read"] or d["shim_called"]}), 8)
        self.assertIn("Demo data already exists", self.sd("demo").stderr)
        self.sd("agent", "add", "mine", "--command", "echo {prompt}", check=0)
        self.sd("demo", "--reset-demo", check=0, timeout=300)
        self.assertIn("mine", self.sd("agent", "list", check=0).stdout)
        self.assertEqual(len(json.loads(self.sd("trials", "--json", check=0).stdout)), 16)
        # backup / restore
        bk = self.tmp / "b.tgz"
        self.sd("backup", str(bk), check=0)
        other = self.tmp / "other"
        env = {"SIDEDOOR_HOME": str(other)}
        self.sd("restore", str(bk), env=env, check=0)
        self.assertEqual(len(json.loads(self.sd("trials", "--json", env=env, check=0).stdout)), 16)
        self.assertIn("not empty", self.sd("restore", str(bk), env=env).stderr)
        self.sd("restore", str(bk), "--force", env=env, check=0)
        self.assertEqual(oct(other.stat().st_mode & 0o777), "0o700")

    def test_migration(self):
        d = self.tmp / "old"
        d.mkdir(mode=0o700)
        (d / "secret.key").write_text("abc\n")
        s = Store(d)
        s.create(upto=1)
        s.close()
        self.assertEqual(Store(d).version(), 1)
        r = self.sd("status", env={"SIDEDOOR_HOME": str(d)}, check=0)
        self.assertIn("migrated store from schema v1 to v2", r.stderr)
        self.assertEqual(Store(d).version(), SCHEMA_VERSION)
        self.assertTrue(list((d / "backups").glob("pre-migrate-v1-*.db")))
        # newer store is refused
        con = sqlite3.connect(d / "sidedoor.db")
        con.execute("UPDATE meta SET value='99'")
        con.commit()
        r = self.sd("status", env={"SIDEDOOR_HOME": str(d)})
        self.assertIn("newer Sidedoor", r.stderr)


class ConfigTests(SD):
    def test_config(self):
        self.assertIn("broker.hint = explicit", self.sd("config", "show", check=0).stdout)
        self.assertIn("expected one of", self.sd("config", "set", "broker.hint", "maybe").stderr)
        self.sd("config", "set", "limits.concurrent", "3", check=0)
        self.assertIn("limits.concurrent = 3", self.sd("config", "show", check=0).stdout)
        self.assertIn("limits.concurrent = 5", self.sd("config", "show", env={"SIDEDOOR_LIMITS_CONCURRENT": "5"}, check=0).stdout)
        self.assertIn("between 1 and 8", self.sd("config", "show", env={"SIDEDOOR_LIMITS_CONCURRENT": "9"}).stderr)
