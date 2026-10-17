import fcntl
import json
import os
import sqlite3
import threading
import time
import uuid
from contextlib import contextmanager
from pathlib import Path

from .util import SidedoorError, pid_alive

M1 = """
BEGIN;
CREATE TABLE meta(key TEXT PRIMARY KEY, value TEXT);
CREATE TABLE profiles(
  id INTEGER PRIMARY KEY AUTOINCREMENT, name TEXT UNIQUE NOT NULL, preset TEXT, command TEXT NOT NULL,
  timeout INTEGER, env TEXT NOT NULL DEFAULT '[]', copyin TEXT NOT NULL DEFAULT '[]',
  demo INTEGER NOT NULL DEFAULT 0, created_at REAL, updated_at REAL);
CREATE TABLE scenarios(name TEXT PRIMARY KEY, prompt TEXT NOT NULL, created_at REAL, updated_at REAL);
CREATE TABLE trials(
  id TEXT PRIMARY KEY, profile_id INTEGER, agent_name TEXT NOT NULL, scenario TEXT NOT NULL, doors TEXT NOT NULL,
  broker_mode TEXT, status TEXT NOT NULL, verdict TEXT, exit_code INTEGER, aborted INTEGER NOT NULL DEFAULT 0,
  timed_out INTEGER NOT NULL DEFAULT 0, task_ok INTEGER, task_detail TEXT, prompt TEXT, settings TEXT,
  started_at REAL, finished_at REAL, pid INTEGER, pid_start TEXT, pgid INTEGER, sandbox TEXT,
  target_port INTEGER, broker_port INTEGER, output_dir TEXT, error TEXT,
  abort_requested INTEGER NOT NULL DEFAULT 0, demo INTEGER NOT NULL DEFAULT 0);
CREATE TABLE events(
  trial_id TEXT NOT NULL, seq INTEGER NOT NULL, ts REAL NOT NULL, kind TEXT NOT NULL, door TEXT,
  method TEXT, path TEXT, detail TEXT, PRIMARY KEY(trial_id, seq));
CREATE TRIGGER events_append_only BEFORE UPDATE ON events BEGIN SELECT RAISE(ABORT, 'events are append-only'); END;
CREATE TABLE trial_doors(trial_id TEXT NOT NULL, door TEXT NOT NULL, label TEXT, location TEXT, value TEXT, PRIMARY KEY(trial_id, door));
CREATE TABLE notes(id INTEGER PRIMARY KEY AUTOINCREMENT, trial_id TEXT NOT NULL, ts REAL, text TEXT);
CREATE INDEX trials_started ON trials(started_at);
INSERT INTO meta VALUES('schema_version','1');
COMMIT;
"""

M2 = """
BEGIN;
ALTER TABLE trials ADD COLUMN batch_id TEXT;
CREATE TABLE batches(
  id TEXT PRIMARY KEY, created_at REAL, finished_at REAL, agents TEXT, repeat INTEGER, scenario TEXT,
  doors TEXT, broker_mode TEXT, status TEXT, exit_code INTEGER, demo INTEGER NOT NULL DEFAULT 0);
CREATE TABLE labels(trial_id TEXT NOT NULL, label TEXT NOT NULL, ts REAL, PRIMARY KEY(trial_id, label));
CREATE TABLE audit(id INTEGER PRIMARY KEY AUTOINCREMENT, ts REAL, action TEXT, subject TEXT, detail TEXT);
UPDATE meta SET value='2' WHERE key='schema_version';
COMMIT;
"""

MIGRATIONS = [M1, M2]
SCHEMA_VERSION = len(MIGRATIONS)


class ConcurrencyLimit(SidedoorError):
    def __init__(self, running, limit):
        super().__init__(f"Concurrent-trial limit reached: {running} running, limit is {limit} (limits.concurrent)")
        self.running, self.limit = running, limit


class Store:
    def __init__(self, data_dir):
        self.data_dir = Path(data_dir)
        self.path = self.data_dir / "sidedoor.db"
        self._local = threading.local()

    # -- connections ------------------------------------------------------
    def conn(self):
        c = getattr(self._local, "c", None)
        if c is None:
            c = sqlite3.connect(self.path, timeout=60, isolation_level=None)
            c.row_factory = sqlite3.Row
            c.execute("PRAGMA busy_timeout=60000")
            c.execute("PRAGMA journal_mode=WAL")
            self._local.c = c
        return c

    def close(self):
        c = getattr(self._local, "c", None)
        if c is not None:
            c.close()
            self._local.c = None

    @contextmanager
    def tx(self):
        c = self.conn()
        c.execute("BEGIN IMMEDIATE")
        try:
            yield c
        except BaseException:
            c.execute("ROLLBACK")
            raise
        c.execute("COMMIT")

    # -- schema -----------------------------------------------------------
    def version(self):
        try:
            r = self.conn().execute("SELECT value FROM meta WHERE key='schema_version'").fetchone()
            return int(r[0]) if r else 0
        except sqlite3.OperationalError:
            return 0

    def create(self, upto=None):
        if self.path.exists():
            raise SidedoorError(f"Store already exists at {self.path}")
        for m in MIGRATIONS[: upto or SCHEMA_VERSION]:
            self.conn().executescript(m)
        os.chmod(self.path, 0o600)

    def ensure_current(self):
        """Migrate to the current schema, after writing an automatic backup. Returns (from, to) or None."""
        if not self.path.exists():
            raise SidedoorError("Not initialised; run `sidedoor init`")
        v = self.version()
        if v > SCHEMA_VERSION:
            raise SidedoorError(f"Store schema v{v} was written by a newer Sidedoor (this one supports v{SCHEMA_VERSION}); upgrade Sidedoor")
        if v == SCHEMA_VERSION:
            return None
        with open(self.data_dir / ".migrate.lock", "w") as lock:
            fcntl.flock(lock, fcntl.LOCK_EX)
            v = self.version()
            if v >= SCHEMA_VERSION:
                return None
            bdir = self.data_dir / "backups"
            bdir.mkdir(mode=0o700, exist_ok=True)
            dest = bdir / f"pre-migrate-v{v}-{time.strftime('%Y%m%dT%H%M%S')}.db"
            self.backup_to(dest)
            for m in MIGRATIONS[v:]:
                self.conn().executescript(m)
            return (v, SCHEMA_VERSION)

    def backup_to(self, dest):
        dst = sqlite3.connect(dest)
        try:
            self.conn().backup(dst)
        finally:
            dst.close()
        os.chmod(dest, 0o600)

    # -- audit ------------------------------------------------------------
    def audit(self, action, subject, detail=""):
        self.conn().execute("INSERT INTO audit(ts,action,subject,detail) VALUES(?,?,?,?)", (time.time(), action, subject, detail))

    # -- profiles ---------------------------------------------------------
    def get_profile(self, name):
        r = self.conn().execute("SELECT * FROM profiles WHERE name=?", (name,)).fetchone()
        return self._profile(r) if r else None

    def profile_by_id(self, pid):
        r = self.conn().execute("SELECT * FROM profiles WHERE id=?", (pid,)).fetchone()
        return self._profile(r) if r else None

    def list_profiles(self):
        return [self._profile(r) for r in self.conn().execute("SELECT * FROM profiles ORDER BY name")]

    @staticmethod
    def _profile(r):
        d = dict(r)
        d["env"] = json.loads(d["env"])
        d["copyin"] = json.loads(d["copyin"])
        return d

    def save_profile(self, p, new):
        now = time.time()
        c = self.conn()
        if new:
            c.execute(
                "INSERT INTO profiles(name,preset,command,timeout,env,copyin,demo,created_at,updated_at) VALUES(?,?,?,?,?,?,?,?,?)",
                (p["name"], p.get("preset"), p["command"], p.get("timeout"), json.dumps(p["env"]), json.dumps(p["copyin"]), int(p.get("demo", 0)), now, now),
            )
        else:
            c.execute(
                "UPDATE profiles SET command=?,timeout=?,env=?,copyin=?,updated_at=? WHERE name=?",
                (p["command"], p.get("timeout"), json.dumps(p["env"]), json.dumps(p["copyin"]), now, p["name"]),
            )

    def delete_profile(self, name):
        with self.tx() as c:
            p = c.execute("SELECT id FROM profiles WHERE name=?", (name,)).fetchone()
            if not p:
                raise SidedoorError(f"No profile {name}")
            for t in c.execute("SELECT pid,pid_start FROM trials WHERE profile_id=? AND status='running'", (p["id"],)):
                if pid_alive(t["pid"], t["pid_start"]):
                    raise SidedoorError(f"Profile {name} is used by a running trial; abort it first or wait")
            c.execute("DELETE FROM profiles WHERE id=?", (p["id"],))

    # -- scenarios --------------------------------------------------------
    def list_scenarios(self):
        return [dict(r) for r in self.conn().execute("SELECT * FROM scenarios ORDER BY name")]

    def get_scenario(self, name):
        r = self.conn().execute("SELECT * FROM scenarios WHERE name=?", (name,)).fetchone()
        return dict(r) if r else None

    # -- trials -----------------------------------------------------------
    def new_trial_id(self):
        return uuid.uuid4().hex[:10]

    def begin_trial(self, row, limit):
        with self.tx() as c:
            live = [r for r in c.execute("SELECT pid,pid_start FROM trials WHERE status='running'") if pid_alive(r["pid"], r["pid_start"])]
            if len(live) >= limit:
                raise ConcurrencyLimit(len(live), limit)
            cols = ",".join(row)
            c.execute(f"INSERT INTO trials({cols}) VALUES({','.join('?' * len(row))})", list(row.values()))

    def update_trial(self, tid, **kw):
        sets = ",".join(f"{k}=?" for k in kw)
        self.conn().execute(f"UPDATE trials SET {sets} WHERE id=?", [*kw.values(), tid])

    def finish_trial(self, tid, status="finished", **kw):
        """First finisher wins; returns True if this call wrote the final state."""
        kw["status"] = status
        kw.setdefault("finished_at", time.time())
        sets = ",".join(f"{k}=?" for k in kw)
        cur = self.conn().execute(f"UPDATE trials SET {sets} WHERE id=? AND status='running'", [*kw.values(), tid])
        return cur.rowcount == 1

    def get_trial(self, tid):
        r = self.conn().execute("SELECT * FROM trials WHERE id=?", (tid,)).fetchone()
        return dict(r) if r else None

    def resolve_trial(self, prefix):
        rows = self.conn().execute("SELECT id FROM trials WHERE id LIKE ? ESCAPE '\\' ORDER BY started_at DESC", (prefix.replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_") + "%",)).fetchall()
        if not rows:
            raise SidedoorError(f"No trial {prefix}")
        exact = [r for r in rows if r["id"] == prefix]
        if exact:
            return self.get_trial(prefix)
        if len(rows) > 1:
            raise SidedoorError(f"Ambiguous trial ID {prefix}; matches: " + ", ".join(r["id"] for r in rows))
        return self.get_trial(rows[0]["id"])

    def list_trials(self, agent=None, verdict=None, scenario=None, since=None, until=None, label=None, batch=None, status=None, until_col="started_at"):
        q, a = ["1=1"], []
        for col, val in (("agent_name", agent), ("verdict", verdict), ("scenario", scenario), ("batch_id", batch), ("status", status)):
            if val is not None:
                q.append(f"{col}=?")
                a.append(val)
        if since is not None:
            q.append("started_at>=?")
            a.append(since)
        if until is not None:
            q.append("COALESCE(finished_at, started_at)<=?" if until_col == "finished_at" else "started_at<=?")
            a.append(until)
        if label is not None:
            q.append("id IN (SELECT trial_id FROM labels WHERE label=?)")
            a.append(label)
        rows = self.conn().execute(f"SELECT * FROM trials WHERE {' AND '.join(q)} ORDER BY started_at DESC, id", a)
        return [dict(r) for r in rows]

    def events(self, tid):
        out = []
        for r in self.conn().execute("SELECT * FROM events WHERE trial_id=? ORDER BY seq", (tid,)):
            d = dict(r)
            d["detail"] = json.loads(d["detail"]) if d["detail"] else {}
            out.append(d)
        return out

    def emit(self, tid, kind, door=None, method=None, path=None, detail=None):
        """Append one evidence event; sequence and timestamp are assigned under the write lock."""
        with self.tx() as c:
            seq = c.execute("SELECT COALESCE(MAX(seq),0)+1 FROM events WHERE trial_id=?", (tid,)).fetchone()[0]
            c.execute(
                "INSERT INTO events(trial_id,seq,ts,kind,door,method,path,detail) VALUES(?,?,?,?,?,?,?,?)",
                (tid, seq, time.time(), kind, door, method, path, json.dumps(detail) if detail else None),
            )
        return seq

    def trial_doors(self, tid):
        return [dict(r) for r in self.conn().execute("SELECT * FROM trial_doors WHERE trial_id=? ORDER BY rowid", (tid,))]

    def notes(self, tid):
        return [dict(r) for r in self.conn().execute("SELECT * FROM notes WHERE trial_id=? ORDER BY id", (tid,))]

    def labels(self, tid):
        return [r[0] for r in self.conn().execute("SELECT label FROM labels WHERE trial_id=? ORDER BY ts, label", (tid,))]

    def delete_trials(self, ids):
        with self.tx() as c:
            for tid in ids:
                for t in ("events", "trial_doors", "notes", "labels"):
                    c.execute(f"DELETE FROM {t} WHERE trial_id=?", (tid,))
                c.execute("DELETE FROM trials WHERE id=?", (tid,))
            c.execute("DELETE FROM batches WHERE id NOT IN (SELECT DISTINCT batch_id FROM trials WHERE batch_id IS NOT NULL) AND status!='running'")

    # -- batches ----------------------------------------------------------
    def new_batch(self, **kw):
        bid = "b-" + uuid.uuid4().hex[:8]
        kw.update(id=bid, created_at=time.time(), status="running")
        self.conn().execute(f"INSERT INTO batches({','.join(kw)}) VALUES({','.join('?' * len(kw))})", list(kw.values()))
        return bid

    def get_batch(self, bid):
        r = self.conn().execute("SELECT * FROM batches WHERE id=?", (bid,)).fetchone()
        return dict(r) if r else None

    def resolve_batch(self, prefix):
        rows = self.conn().execute("SELECT id FROM batches WHERE id LIKE ?", (prefix + "%",)).fetchall()
        if not rows:
            raise SidedoorError(f"No batch {prefix}")
        if len(rows) > 1 and not any(r["id"] == prefix for r in rows):
            raise SidedoorError(f"Ambiguous batch ID {prefix}; matches: " + ", ".join(r["id"] for r in rows))
        return self.get_batch(prefix if any(r["id"] == prefix for r in rows) else rows[0]["id"])

    def update_batch(self, bid, **kw):
        sets = ",".join(f"{k}=?" for k in kw)
        self.conn().execute(f"UPDATE batches SET {sets} WHERE id=?", [*kw.values(), bid])

    def running_live(self):
        return [dict(r) for r in self.conn().execute("SELECT * FROM trials WHERE status='running'") if pid_alive(r["pid"], r["pid_start"])]

