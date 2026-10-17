import argparse
import json
import os
import re
import secrets
import shlex
import shutil
import signal
import socket
import sys
import tarfile
import tempfile
import threading
import time
from pathlib import Path

from . import __version__
from . import config as configmod
from . import doors as doormod
from . import report as reportmod
from . import scenarios, trial as trialmod, verdict as vd, watcher as watchmod
from .app import App, resolve_exe
from .presets import PRESETS
from .sandbox import default_root
from .store import SCHEMA_VERSION, ConcurrencyLimit, Store
from .util import SidedoorError, check_name, fmt_ts, iso, parse_duration, parse_when, pid_alive, pgroup_alive, kill_group, table

LABEL_RE = re.compile(r"^[A-Za-z0-9._:-]{1,40}$")
TRIAL_FILTER_VERDICTS = vd.VERDICTS + ["INTERRUPTED"]


def out(*a):
    print(*a, flush=True)


def confirm(prompt, yes):
    if yes:
        return True
    if not sys.stdin.isatty():
        raise SidedoorError(f"{prompt} Not a terminal: re-run with --yes to confirm")
    return input(f"{prompt} [y/N] ").strip().lower() in ("y", "yes")


# ---------------------------------------------------------------- init / doctor / status

def cmd_init(a):
    data = configmod.default_data_dir()
    store = Store(data)
    try:
        exists = store.path.exists()
    except OSError as e:
        raise SidedoorError(f"Cannot write to data directory {data}: {e.strerror or e} (check its permissions or set SIDEDOOR_HOME)", 70)
    if exists:
        out(f"Already initialised at {data}")
        return 0
    try:
        data.mkdir(mode=0o700, parents=True, exist_ok=True)
        os.chmod(data, 0o700)
        probe = data / ".write-test"
        probe.write_text("x")
        probe.unlink()
    except OSError as e:
        raise SidedoorError(f"Cannot write to data directory {data}: {e.strerror or e} (check its permissions or set SIDEDOOR_HOME)", 70)
    cfgp = configmod.config_path(data)
    if not cfgp.exists():
        cfgp.parent.mkdir(parents=True, exist_ok=True)
        cfgp.write_text(configmod.render({}))
        os.chmod(cfgp, 0o600)
    configmod.load(data)  # fail early on a bad config / env override
    sec = data / "secret.key"
    sec.write_text(secrets.token_hex(32) + "\n")
    os.chmod(sec, 0o600)
    (data / "outputs").mkdir(mode=0o700, exist_ok=True)
    store.create()
    store.audit("init", str(data), f"schema v{SCHEMA_VERSION}")
    out(f"Initialised Sidedoor at {data}")
    out(f"  config:   {cfgp}")
    out(f"  store:    {store.path} (schema v{SCHEMA_VERSION})")
    out("  signing secret generated")
    out("Next: `sidedoor doctor`, then `sidedoor status`.")
    return 0


def cmd_doctor(a):
    app = App.load()
    rows = []

    def add(level, name, msg):
        rows.append((level, name, msg))

    d = app.data_dir
    try:
        p = d / ".doctor-test"
        p.write_text("x")
        p.unlink()
        add("OK", "data directory", f"{d} is writable")
    except OSError as e:
        add("FAIL", "data directory", f"{d} is not writable: {e.strerror}")
    root = default_root(app.cfg)
    home = Path(os.path.expanduser("~")).resolve()
    rr = root.resolve()
    if rr == home or rr.is_relative_to(home) and rr.relative_to(home).parts[0].startswith("."):
        add("FAIL", "sandbox root", f"{rr} is your home or inside a home dotfile directory")
    elif rr.is_relative_to(home):
        add("WARN", "sandbox root", f"{rr} is inside your home directory (not a dotfile directory); /tmp is safer")
    else:
        try:
            root.mkdir(mode=0o700, parents=True, exist_ok=True)
            probe = root / ".doctor-test"
            probe.write_text("x")
            probe.unlink()
            add("OK", "sandbox root", f"{rr} is outside your home dotfiles and writable")
        except OSError as e:
            add("FAIL", "sandbox root", f"{rr} is not writable: {e.strerror}")
    try:
        s = socket.socket()
        s.bind(("127.0.0.1", 0))
        port = s.getsockname()[1]
        s.close()
        add("OK", "loopback ports", f"can bind 127.0.0.1 (tried port {port})")
    except OSError as e:
        add("FAIL", "loopback ports", f"cannot bind 127.0.0.1: {e.strerror}")
    ok, msg = watchmod.available()
    add("OK" if ok else "WARN", "file-read detection", msg)
    add("OK" if shutil.which("git") else "WARN", "git", "found" if shutil.which("git") else "not found; sandbox workspaces will not be git repositories")
    found = [n for n, p in PRESETS.items() if shutil.which(p["exe"])]
    missing = [n for n in PRESETS if n not in found]
    add("OK" if found else "WARN", "preset agents", ("found: " + ", ".join(found) if found else "none found on PATH") + (f"; not found: {', '.join(missing)}" if missing else ""))
    if app.cfg["agent.env"] == "inherit":
        add("WARN", "agent.env", "inherit: agents receive your full environment (risky)")
    for lvl, name, msg in rows:
        out(f"{lvl:<5} {name}: {msg}")
    out("")
    out("Limitations: " + reportmod.LIMITATIONS)
    return 1 if any(r[0] == "FAIL" for r in rows) else 0


def cmd_status(a):
    app = App.load()
    c = app.store.conn()
    n_prof = c.execute("SELECT COUNT(*) FROM profiles").fetchone()[0]
    n_tr = c.execute("SELECT COUNT(*) FROM trials").fetchone()[0]
    n_run = len(app.store.running_live())
    n_sc = c.execute("SELECT COUNT(*) FROM scenarios").fetchone()[0]
    out(f"Sidedoor {__version__}")
    out(f"Data:      {app.data_dir}")
    out(f"Store:     schema v{app.store.version()}")
    out(f"Profiles:  {n_prof}")
    out(f"Scenarios: {len(scenarios.BUILTIN)} built-in, {n_sc} custom")
    out(f"Trials:    {n_tr}" + (f" ({n_run} running)" if n_run else ""))
    if n_tr == 0:
        out("Hint: run `sidedoor demo` to try it")
    return 0


# ---------------------------------------------------------------- agents

def split_list(values):
    res = []
    for v in values or []:
        res += [x.strip() for x in v.split(",") if x.strip()]
    return res


def cmd_agent(a):
    app = App.load()
    st = app.store
    sub = a.agent_cmd
    if sub == "list":
        rows = [[p["name"], p["preset"] or "custom", p["timeout"] or f"{app.cfg['agent.timeout']} (default)", ",".join(p["env"]) or "-", ",".join(p["copyin"]) or "-", p["command"]] for p in st.list_profiles()]
        out(table(["name", "preset", "timeout", "env", "copy-in", "command"], rows) if rows else "No profiles. Add one with `sidedoor agent add <name> --preset <preset>`.")
        return 0
    if sub == "show":
        p = st.get_profile(a.name) or _no_profile(a.name, st)
        out(f"name:     {p['name']}\npreset:   {p['preset'] or 'custom'}\ncommand:  {p['command']}\ntimeout:  {p['timeout'] or str(app.cfg['agent.timeout']) + ' (default)'}\nenv:      {', '.join(p['env']) or '-'}\ncopy-in:  {', '.join(p['copyin']) or '-'}\nupdated:  {fmt_ts(p['updated_at'])}")
        return 0
    if sub == "remove":
        if not st.get_profile(a.name):
            _no_profile(a.name, st)
        st.delete_profile(a.name)
        st.audit("agent.remove", a.name)
        out(f"Removed profile {a.name} (its past trials are kept)")
        return 0
    if sub == "test":
        p = st.get_profile(a.name) or _no_profile(a.name, st)
        out(f"Testing {a.name}: running the agent with the prompt 'reply OK' (no decoys, up to {trialmod.AGENT_TEST_TIMEOUT}s)...")
        code, timed_out, text = trialmod.agent_test(app, p)
        out(("TIMEOUT after %ds" % trialmod.AGENT_TEST_TIMEOUT) if timed_out else f"exit code: {code}")
        lines = text.splitlines()
        out("output (first 20 lines):")
        out("\n".join(lines[:20]) or "(no output)")
        if len(lines) > 20:
            out(f"... {len(lines) - 20} more lines")
        return 0 if (code == 0 and not timed_out) else 1
    # add / edit
    if sub == "add":
        check_name(a.name, "profile")
        if st.get_profile(a.name):
            raise SidedoorError(f"Profile {a.name} exists")
        if bool(a.preset) == bool(a.command):
            raise SidedoorError("Give exactly one of --preset <preset> or --command '<template>'. Presets: " + ", ".join(PRESETS))
        env, copyin, command = split_list(a.env), split_list(a.copy_in), a.command
        if a.preset:
            pr = app.preset_defaults(a.preset)
            command = pr["command"]
            env = list(dict.fromkeys(pr["env"] + env))
            defaults = app.existing_preset_copyin(pr["copyin"])
            skipped = [x for x in pr["copyin"] if x not in defaults]
            copyin = list(dict.fromkeys(defaults + copyin))
            if skipped:
                out(f"note: preset copy-in paths not present in your home, skipped: {', '.join(skipped)}")
        timeout = a.timeout
        copyin = app.validate_profile(a.name, command, timeout, env, copyin)
        st.save_profile(dict(name=a.name, preset=a.preset, command=command, timeout=timeout, env=env, copyin=copyin), True)
        st.audit("agent.add", a.name, command)
        out(f"Added profile {a.name}")
        return 0
    p = st.get_profile(a.name) or _no_profile(a.name, st)
    if a.command is not None:
        p["command"] = a.command
    if a.timeout is not None:
        p["timeout"] = a.timeout
    if a.env is not None:
        p["env"] = split_list(a.env)
    if a.copy_in is not None:
        p["copyin"] = split_list(a.copy_in)
    p["copyin"] = app.validate_profile(p["name"], p["command"], p["timeout"], p["env"], p["copyin"])
    st.save_profile(p, False)
    st.audit("agent.edit", a.name, p["command"])
    out(f"Updated profile {a.name}")
    return 0


def _no_profile(name, st):
    names = [p["name"] for p in st.list_profiles()]
    raise SidedoorError(f"No profile {name}" + (f"; profiles: {', '.join(names)}" if names else "; add one with `sidedoor agent add`"))


def cmd_scenario(a):
    app = App.load()
    st = app.store
    sub = a.scenario_cmd
    if sub == "list":
        rows = [[n, "built-in", s["describe"]] for n, s in scenarios.BUILTIN.items()]
        rows += [[s["name"], "custom", s["prompt"].replace("\n", " ")[:70]] for s in st.list_scenarios()]
        out(table(["name", "kind", "description"], rows))
        return 0
    check_name(a.name, "scenario")
    if sub == "show":
        out(app.scenario_prompt(a.name))
        return 0
    if a.name in scenarios.BUILTIN:
        raise SidedoorError(f"Scenario {a.name} is built-in and cannot be {'added' if sub == 'add' else 'edited or removed'}")
    exists = st.get_scenario(a.name)
    if sub == "remove":
        if not exists:
            raise SidedoorError(f"No custom scenario {a.name}")
        st.conn().execute("DELETE FROM scenarios WHERE name=?", (a.name,))
        st.audit("scenario.remove", a.name)
        out(f"Removed scenario {a.name}")
        return 0
    try:
        text = Path(a.prompt_file).read_text()
    except OSError as e:
        raise SidedoorError(f"Cannot read prompt file {a.prompt_file}: {e.strerror}")
    scenarios.validate_prompt(text)
    now = time.time()
    if sub == "add":
        if exists:
            raise SidedoorError(f"Scenario {a.name} exists")
        st.conn().execute("INSERT INTO scenarios VALUES(?,?,?,?)", (a.name, text, now, now))
    else:
        if not exists:
            raise SidedoorError(f"No custom scenario {a.name}")
        st.conn().execute("UPDATE scenarios SET prompt=?, updated_at=? WHERE name=?", (text, now, a.name))
    st.audit(f"scenario.{sub}", a.name)
    out(f"{'Added' if sub == 'add' else 'Updated'} scenario {a.name}")
    return 0


# ---------------------------------------------------------------- run

def validate_run(app, a):
    cfg = app.cfg
    names = [n.strip() for n in a.agent.split(",") if n.strip()]
    if not names:
        raise SidedoorError("--agent needs at least one profile name")
    known = {p["name"]: p for p in app.store.list_profiles()}
    bad = [n for n in names if n not in known]
    if bad:
        raise SidedoorError(f"Unknown agent {', '.join(bad)}; valid agents: {', '.join(known) or '(none; add one with `sidedoor agent add`)'}")
    if a.scenario not in app.scenario_names():
        raise SidedoorError(f"Unknown scenario '{a.scenario}'; valid scenarios: {', '.join(app.scenario_names())}")
    try:
        doors = doormod.parse_doors(a.doors)
    except ValueError as e:
        raise SidedoorError(str(e))
    if a.broker not in ("up", "down"):
        raise SidedoorError(f"Invalid --broker '{a.broker}': expected up or down")
    if not 1 <= a.repeat <= cfg["limits.max_repeat"]:
        raise SidedoorError(f"--repeat {a.repeat} is out of range: the limit is {cfg['limits.max_repeat']} (minimum 1)")
    if a.timeout is not None and not 1 <= a.timeout <= cfg["limits.max_timeout"]:
        raise SidedoorError(f"Invalid --timeout {a.timeout}: expected 1..{cfg['limits.max_timeout']} seconds")
    for lab in a.label or []:
        if not LABEL_RE.match(lab):
            raise SidedoorError(f"Invalid label '{lab}': use letters, digits, . _ : - (max 40)")
    return [known[n] for n in dict.fromkeys(names)], doors


def install_abort_handler(ev):
    def handler(signum, frame):
        ev.set()
        signal.signal(signum, signal.SIG_DFL)  # a second Ctrl-C terminates immediately

    old = {s: signal.signal(s, handler) for s in (signal.SIGINT, signal.SIGTERM)}
    return old


def cmd_run(a):
    app = App.load()
    profiles, doors = validate_run(app, a)
    if app.cfg["agent.env"] == "inherit":
        print("warning: agent.env=inherit, the agent receives your full environment (risky)", file=sys.stderr)
    ev = threading.Event()
    install_abort_handler(ev)
    live = sys.stderr.isatty() and not a.json
    if len(profiles) == 1 and a.repeat == 1:
        spec = trialmod.Spec(profiles[0], a.scenario, doors, a.broker, None, tuple(a.label or ()), a.timeout)
        t = trialmod.run_trial(app, spec, ev, live=live)
        if a.json:
            out(json.dumps(reportmod.bundle(app, t), indent=2))
        else:
            for line in trialmod.result_lines(app, t):
                out(line)
        return t["exit_code"]
    total = len(profiles) * a.repeat
    done = [0]

    def progress(t):
        done[0] += 1
        if not a.json:
            print(f"  [{done[0]}/{total}] {t['id']} {t['agent_name']}: {_headline(app, t)}", file=sys.stderr, flush=True)

    bid, trials, code = trialmod.run_batch(app, profiles, a.scenario, doors, a.broker, a.repeat, ev, a.label or (), a.timeout, progress=progress)
    rows = reportmod.aggregate(app, trials)
    batch = app.store.get_batch(bid)
    if a.json:
        out(json.dumps({"batch": bid, "status": batch["status"], "exit_code": code, "summary": rows, "trials": [t["id"] for t in trials]}, indent=2))
    else:
        out(reportmod.summary_text(rows))
        out(f"batch: {bid} ({batch['status']}, {len(trials)}/{total} trials)   exit code: {code}")
    if getattr(app, "batch_refusal", None):
        print(f"sidedoor: error: {app.batch_refusal}; no further trials were started", file=sys.stderr)
    return code


def _headline(app, t):
    events = app.store.events(t["id"])
    v, s = vd.compute(events, t["error"])
    return vd.headline(v, s, t["error"], bool(t["aborted"]), bool(t["timed_out"]))


# ---------------------------------------------------------------- inspect

def trial_filters(app, a):
    verdict = None
    if a.verdict:
        verdict = a.verdict.upper()
        if verdict not in TRIAL_FILTER_VERDICTS:
            raise SidedoorError(f"Invalid --verdict '{a.verdict}': expected one of {', '.join(TRIAL_FILTER_VERDICTS)}")
    return dict(agent=a.agent, verdict=verdict if verdict != "INTERRUPTED" else None, scenario=getattr(a, "scenario", None),
                since=parse_when(a.since, "--since") if a.since else None, until=parse_when(a.until, "--until") if a.until else None,
                label=getattr(a, "label", None), status="interrupted" if verdict == "INTERRUPTED" else None)


def cmd_trials(a):
    app = App.load()
    ts = app.store.list_trials(**trial_filters(app, a))
    if a.json:
        out(json.dumps([reportmod.bundle(app, t) for t in ts], indent=2))
        return 0
    if not ts:
        out("No trials.")
        return 0
    rows = []
    for t in ts:
        ev = app.store.events(t["id"])
        _, s = vd.compute(ev, t["error"])
        used = ", ".join(f"{vd.short_label(d)} ×{n}" for d, n in s["used"].items()) or "-"
        verdict_s = (t["verdict"] or t["status"]) + (" (aborted)" if t["aborted"] else "") + (" (timeout)" if t["timed_out"] else "")
        task = "-" if t["task_ok"] is None else ("done" if t["task_ok"] else "not done")
        rows.append([t["id"], fmt_ts(t["started_at"]), reportmod.profile_label(app, t), t["scenario"], verdict_s, used, task])
    out(table(["id", "time", "agent", "scenario", "verdict", "doors used", "task"], rows))
    return 0


def cmd_show(a):
    app = App.load()
    t = app.store.resolve_trial(a.id)
    b = reportmod.bundle(app, t)
    if a.json:
        out(json.dumps(b, indent=2))
        return 0
    out(f"Trial {t['id']}   {b['headline']}")
    out(f"agent: {b['agent']}   scenario: {t['scenario']}   broker: {t['broker_mode']}   status: {t['status']}")
    out(f"started: {b['started_local']}   duration: {b['duration_s']}s   exit code: {t['exit_code']}   aborted: {b['aborted']}   timeout: {b['timed_out']}")
    out(f"doors planted: {', '.join(b['doors_planted'])}")
    if b["labels"]:
        out("labels: " + ", ".join(b["labels"]))
    st = b["settings"]
    out(f"settings: command={st.get('command')!r} timeout={st.get('timeout')}s broker.hint={st.get('broker_hint')} agent.env={st.get('agent_env')} ttl={st.get('token_ttl')}s")
    tk = b["task"]
    out("task: " + ("not checked" if tk["completed"] is None else ("completed" if tk["completed"] else "NOT completed") + f" ({tk['detail']})"))
    if t["error"]:
        out(f"error: {t['error']}")
    out("\nprompt:\n  " + (t["prompt"] or "(not rendered)").replace("\n", "\n  "))
    out("\ntimeline:")
    rows = [[e["seq"], e["time_local"], e["kind"], e["door"] or "-", ((e["method"] or "") + " " + (e["path"] or "")).strip() or "-", e["note"]] for e in b["events"]]
    out(table(["#", "time", "kind", "door", "request", "note"], rows) if rows else "  (no events)")
    out("\ndoors:")
    out(table(["door", "planted", "read", "shim called", "used"], [[d["door"], d["planted"], d["read"], d["shim_called"], d["used"]] for d in b["doors"]]) if b["doors"] else "  (none)")
    events = app.store.events(t["id"])
    issued = [e for e in events if e["kind"] == "broker_issued"]
    used = [e for e in events if e["kind"] == "broker_used"]
    out(f"\nbroker tokens: issued {len(issued)}, used at target {len(used)}, expired-token uses {b['broker']['expired']}")
    for e in issued:
        n_used = sum(1 for u in used if u["detail"].get("jti") == e["detail"].get("jti"))
        out(f"  {e['detail'].get('jti')}  scope={e['detail'].get('scope')}  issued {fmt_ts(e['ts'], False)}  used {n_used}×")
    if b["notes"]:
        out("\nnotes:")
        for n in app.store.notes(t["id"]):
            out(f"  {fmt_ts(n['ts'])}  {n['text']}")
    out(f"\ncaptured output: {t['output_dir'] or '(none)'}")
    return 0


def cmd_note(a):
    app = App.load()
    t = app.store.resolve_trial(a.id)
    if not a.text.strip():
        raise SidedoorError("Note text is empty")
    app.store.conn().execute("INSERT INTO notes(trial_id,ts,text) VALUES(?,?,?)", (t["id"], time.time(), a.text))
    out(f"Note added to {t['id']}")
    return 0


def cmd_label(a):
    app = App.load()
    t = app.store.resolve_trial(a.id)
    if not LABEL_RE.match(a.label):
        raise SidedoorError(f"Invalid label '{a.label}': use letters, digits, . _ : - (max 40)")
    app.store.conn().execute("INSERT OR IGNORE INTO labels(trial_id,label,ts) VALUES(?,?,?)", (t["id"], a.label, time.time()))
    out(f"Labelled {t['id']} with {a.label}")
    return 0


def cmd_summary(a):
    app = App.load()
    f = trial_filters(app, argparse.Namespace(agent=a.agent, verdict=None, scenario=None, since=a.since, until=None, label=None))
    ts = [t for t in app.store.list_trials(**f)]
    rows = reportmod.aggregate(app, ts)
    if a.json:
        out(json.dumps({"trials": len(ts), "summary": rows}, indent=2))
    else:
        out(reportmod.summary_text(rows) if rows else "No trials in this period.")
    return 0


# ---------------------------------------------------------------- report

def cmd_report(a):
    app = App.load()
    st = app.store
    batch = None
    if a.target:
        if a.since or a.until or a.agent:
            raise SidedoorError("Give either an ID or period filters (--since/--until/--agent), not both")
        if a.target.startswith("b-"):
            batch = st.resolve_batch(a.target)
            trials = list(reversed(st.list_trials(batch=batch["id"])))
            title = f"Sidedoor batch report {batch['id']}"
        else:
            trials = [st.resolve_trial(a.target)]
            title = f"Sidedoor trial report {trials[0]['id']}"
    else:
        if not a.since:
            raise SidedoorError("Give a trial or batch ID, or --since <duration|date> for a period report")
        f = trial_filters(app, argparse.Namespace(agent=a.agent, verdict=None, scenario=None, since=a.since, until=a.until, label=None))
        trials = list(reversed(st.list_trials(**f)))
        title = f"Sidedoor period report (since {a.since})"
    data = reportmod.build(app, trials, batch, title)
    text = reportmod.FORMATS[a.format](data)
    if a.format == "junit":
        text = re.sub(r"[\x00-\x08\x0b\x0c\x0e-\x1f]", "", text)
    text = reportmod.scrub(app, text, app.cfg["report.secrets"])
    if not a.out:
        sys.stdout.write(text if text.endswith("\n") else text + "\n")
        return 0
    path = Path(a.out)
    if path.exists() and not a.force:
        raise SidedoorError(f"{path} exists; use --force to overwrite")
    try:
        path.write_text(text if text.endswith("\n") else text + "\n")
    except OSError as e:
        raise SidedoorError(f"Cannot write {path}: {e.strerror}")
    out(f"Wrote {path}")
    return 0


# ---------------------------------------------------------------- abort / clean / delete

def cmd_abort(a):
    app = App.load()
    t = app.store.resolve_trial(a.id)
    if t["status"] != "running":
        out("Trial already finished")
        return 0
    if pid_alive(t["pid"], t["pid_start"]):
        app.store.update_trial(t["id"], abort_requested=1)
        for _ in range(300):
            time.sleep(0.1)
            t = app.store.get_trial(t["id"])
            if t["status"] != "running":
                break
        else:
            raise SidedoorError(f"Trial {t['id']} did not stop within 30s; try `sidedoor clean` if its runner is stuck", 70)
    else:
        trialmod.orphan_abort(app, t)
        t = app.store.get_trial(t["id"])
    out(_headline(app, t))
    out(f"trial: {t['id']}")
    return 0


def find_orphans(app):
    st = app.store
    trials = []
    for t in st.conn().execute("SELECT * FROM trials WHERE status='running'").fetchall():
        t = dict(t)
        if not pid_alive(t["pid"], t["pid_start"]):
            trials.append(t)
    live_ids = {t["id"] for t in st.running_live()}
    dead_ids = {t["id"] for t in trials}
    sandboxes = []
    root = default_root(app.cfg)
    if root.is_dir():
        for d in sorted(root.iterdir()):
            if not d.is_dir() or d.name in live_ids:
                continue
            row = st.get_trial(d.name)
            if d.name in dead_ids:
                continue  # handled with its trial
            if d.name.startswith("test-"):
                if time.time() - d.stat().st_mtime > 300:
                    sandboxes.append(d)
            elif row is None or row["status"] == "interrupted" or (row["status"] == "finished" and json.loads(row["settings"] or "{}").get("after_run") == "delete"):
                if row is None and not re.fullmatch(r"[0-9a-f]{10}", d.name):
                    continue
                sandboxes.append(d)
    return trials, sandboxes


def cmd_clean(a):
    app = App.load()
    trials, sandboxes = find_orphans(app)
    if not trials and not sandboxes:
        out("Nothing to clean")
        return 0
    for t in trials:
        extra = []
        if pgroup_alive(t["pgid"]):
            extra.append(f"agent process group {t['pgid']} still running")
        if t["sandbox"] and Path(t["sandbox"]).exists():
            extra.append(f"sandbox {t['sandbox']}")
        out(f"trial {t['id']} ({t['agent_name']}) is marked running but its runner is gone: " + ("; ".join(extra) or "no leftovers") + " -> mark interrupted")
    for d in sandboxes:
        out(f"orphaned sandbox {d}")
    if not confirm("Remove these?", a.yes):
        out("Nothing removed")
        return 0
    for t in trials:
        kill_group(t["pgid"])
        if t["sandbox"]:
            trialmod.remove_sandbox(t["sandbox"])
        app.store.finish_trial(t["id"], status="interrupted")
    for d in sandboxes:
        trialmod.remove_sandbox(d)
    app.store.audit("clean", "", f"{len(trials)} trials, {len(sandboxes)} sandboxes")
    out(f"Cleaned {len(trials)} interrupted trial(s) and {len(sandboxes)} orphaned sandbox(es)")
    return 0


def remove_trials(app, ts, yes, what):
    running = [t["id"] for t in ts if t["status"] == "running"]
    if running:
        raise SidedoorError(f"Trial {', '.join(running)} is running; abort it first (`sidedoor abort <id>`, or `sidedoor clean` if its runner died)")
    if not ts:
        out("No trials to remove")
        return 0
    if not confirm(f"Delete {len(ts)} trial(s) and their evidence ({what})?", yes):
        out("Nothing deleted")
        return 0
    for t in ts:
        if t["sandbox"] and Path(t["sandbox"]).exists():
            trialmod.remove_sandbox(t["sandbox"])
        if t["output_dir"]:
            shutil.rmtree(t["output_dir"], ignore_errors=True)
    app.store.delete_trials([t["id"] for t in ts])
    app.store.audit("trials.delete", ",".join(t["id"] for t in ts), what)
    out(f"Deleted {len(ts)} trial(s)")
    return 0


def cmd_delete(a):
    app = App.load()
    ts = []
    for i in a.ids:
        t = app.store.resolve_trial(i)
        if t["id"] not in [x["id"] for x in ts]:
            ts.append(t)
    return remove_trials(app, ts, a.yes, ", ".join(t["id"] for t in ts))


def cmd_prune(a):
    app = App.load()
    secs = parse_duration(a.older_than or f"{app.cfg['limits.prune_days']}d", "--older-than")
    cutoff = time.time() - secs
    ts = [t for t in app.store.list_trials(until=cutoff, until_col="finished_at" if configmod.setting("prune.age_from") == "finish" else "started_at") if t["status"] != "running"]
    return remove_trials(app, ts, a.yes, f"older than {a.older_than or str(app.cfg['limits.prune_days']) + 'd'}")


# ---------------------------------------------------------------- backup / restore / config / audit

def cmd_backup(a):
    app = App.load()
    if app.store.running_live():
        raise SidedoorError("A trial is running; wait for it or abort it before backing up")
    dest = Path(a.file)
    if dest.exists() and not a.force:
        raise SidedoorError(f"{dest} exists; use --force to overwrite")
    with tempfile.TemporaryDirectory() as td:
        snap = Path(td) / "sidedoor.db"
        app.store.backup_to(snap)
        try:
            with tarfile.open(dest, "w:gz") as tar:
                tar.add(snap, "sidedoor-data/sidedoor.db")
                for name in ("config.toml", "secret.key"):
                    if (app.data_dir / name).exists():
                        tar.add(app.data_dir / name, f"sidedoor-data/{name}")
                if (app.data_dir / "outputs").is_dir():
                    tar.add(app.data_dir / "outputs", "sidedoor-data/outputs")
        except OSError as e:
            raise SidedoorError(f"Cannot write {dest}: {e.strerror}")
    os.chmod(dest, 0o600)
    out(f"Backup written to {dest}")
    return 0


def cmd_restore(a):
    data = configmod.default_data_dir()
    src = Path(a.file)
    if not src.is_file():
        raise SidedoorError(f"Backup file {src} not found")
    if data.exists() and any(data.iterdir()) and not a.force:
        raise SidedoorError(f"Data directory {data} is not empty; use --force to replace it")
    try:
        tar = tarfile.open(src, "r:gz")
    except (tarfile.TarError, OSError) as e:
        raise SidedoorError(f"{src} is not a Sidedoor backup: {e}")
    with tar:
        names = tar.getnames()
        if "sidedoor-data/sidedoor.db" not in names:
            raise SidedoorError(f"{src} is not a Sidedoor backup (no sidedoor-data/sidedoor.db)")
        for m in tar.getmembers():
            if m.name.startswith("/") or ".." in Path(m.name).parts or not (m.isfile() or m.isdir()):
                raise SidedoorError(f"Unsafe entry in backup: {m.name}")
        if data.exists():
            for child in data.iterdir():
                shutil.rmtree(child) if child.is_dir() else child.unlink()
        data.mkdir(mode=0o700, parents=True, exist_ok=True)
        os.chmod(data, 0o700)
        with tempfile.TemporaryDirectory() as td:
            tar.extractall(td)
            for child in (Path(td) / "sidedoor-data").iterdir():
                shutil.move(str(child), data / child.name)
    for name in ("sidedoor.db", "secret.key", "config.toml"):
        if (data / name).exists():
            os.chmod(data / name, 0o600)
    out(f"Restored into {data}")
    return 0


def cmd_config(a):
    data = configmod.default_data_dir()
    if not (data / "sidedoor.db").exists():
        raise SidedoorError("Not initialised; run `sidedoor init`")
    if a.config_cmd == "set":
        configmod.set_value(data, a.key, a.value)
        Store(data).conn()
        out(f"{a.key} = {a.value}")
        return 0
    if a.config_cmd == "path":
        out(configmod.config_path(data))
        return 0
    for k, v in configmod.load(data).items():
        out(f"{k} = {v}")
    return 0


def cmd_audit(a):
    app = App.load()
    rows = [[fmt_ts(r["ts"]), r["action"], r["subject"], r["detail"] or ""] for r in app.store.conn().execute("SELECT * FROM audit ORDER BY id")]
    out(table(["time", "action", "subject", "detail"], rows) if rows else "No audit entries.")
    return 0


def cmd_demo(a):
    from . import demo
    app = App.load()
    return demo.run(app, a.reset_demo)


# ---------------------------------------------------------------- parser

def build_parser():
    p = argparse.ArgumentParser(prog="sidedoor", description="Does your coding agent use the broker, or sneak around it?")
    p.add_argument("--version", action="version", version=f"sidedoor {__version__}")
    sub = p.add_subparsers(dest="cmd", metavar="<command>")

    def add(name, fn, help, **kw):
        sp = sub.add_parser(name, help=help, **kw)
        sp.set_defaults(fn=fn)
        return sp

    add("init", cmd_init, "create the data directory, config, store and signing secret")
    add("doctor", cmd_doctor, "check this machine is ready")
    add("status", cmd_status, "show profiles, trials and data path")
    s = add("demo", cmd_demo, "create demo profiles and run demo trials")
    s.add_argument("--reset-demo", action="store_true", help="remove existing demo records first")

    s = add("agent", cmd_agent, "manage agent profiles")
    asub = s.add_subparsers(dest="agent_cmd", required=True)
    for n in ("add", "edit"):
        sp = asub.add_parser(n, help=f"{n} a profile")
        sp.add_argument("name")
        if n == "add":
            sp.add_argument("--preset", choices=list(PRESETS))
        sp.add_argument("--command", help="command template containing {prompt} (and optionally {workspace})")
        sp.add_argument("--timeout", type=int, help="seconds")
        sp.add_argument("--env", action="append", help="environment variable names to pass through (comma list, repeatable)")
        sp.add_argument("--copy-in", action="append", help="files in your home to copy into the sandbox home (comma list, repeatable)")
    for n in ("list", "show", "remove", "test"):
        sp = asub.add_parser(n)
        if n != "list":
            sp.add_argument("name")
    s.set_defaults(fn=cmd_agent)

    s = add("scenario", cmd_scenario, "manage scenarios")
    ssub = s.add_subparsers(dest="scenario_cmd", required=True)
    for n in ("list", "show", "add", "edit", "remove"):
        sp = ssub.add_parser(n)
        if n != "list":
            sp.add_argument("name")
        if n in ("add", "edit"):
            sp.add_argument("--prompt-file", required=True)

    s = add("run", cmd_run, "run a trial (or a batch)")
    s.add_argument("--agent", required=True, help="profile name, or a comma list for a batch")
    s.add_argument("--scenario", default="status")
    s.add_argument("--doors", default="all", help="all or a comma list: " + ",".join(doormod.ALL_IDS))
    s.add_argument("--broker", default="up", help="up|down")
    s.add_argument("--repeat", type=int, default=1)
    s.add_argument("--timeout", type=int)
    s.add_argument("--label", action="append")
    s.add_argument("--json", action="store_true")

    s = add("trials", cmd_trials, "list trials")
    for f in ("agent", "verdict", "scenario", "since", "until", "label"):
        s.add_argument(f"--{f}")
    s.add_argument("--json", action="store_true")
    s = add("show", cmd_show, "show one trial in detail")
    s.add_argument("id")
    s.add_argument("--json", action="store_true")
    s = add("note", cmd_note, "add a note to a trial")
    s.add_argument("id")
    s.add_argument("text")
    s = add("label", cmd_label, "label a trial")
    s.add_argument("id")
    s.add_argument("label")
    s = add("summary", cmd_summary, "per-agent comparison over a period")
    s.add_argument("--since")
    s.add_argument("--agent")
    s.add_argument("--json", action="store_true")
    s = add("report", cmd_report, "export a report")
    s.add_argument("target", nargs="?", help="trial ID or batch ID (omit with --since)")
    s.add_argument("--since")
    s.add_argument("--until")
    s.add_argument("--agent")
    s.add_argument("--format", required=True, choices=list(reportmod.FORMATS))
    s.add_argument("--out")
    s.add_argument("--force", action="store_true")
    s = add("abort", cmd_abort, "abort a running trial")
    s.add_argument("id")
    s = add("clean", cmd_clean, "remove leftovers of crashed runs")
    s.add_argument("--yes", action="store_true")
    s = add("delete", cmd_delete, "delete trials and their evidence")
    s.add_argument("ids", nargs="+")
    s.add_argument("--yes", action="store_true")
    s = add("prune", cmd_prune, "delete old trials")
    s.add_argument("--older-than", help="duration, default limits.prune_days (90d)")
    s.add_argument("--yes", action="store_true")
    s = add("backup", cmd_backup, "write one archive of the data directory")
    s.add_argument("file")
    s.add_argument("--force", action="store_true")
    s = add("restore", cmd_restore, "restore a backup into an empty data directory")
    s.add_argument("file")
    s.add_argument("--force", action="store_true")
    s = add("config", cmd_config, "show or change configuration")
    csub = s.add_subparsers(dest="config_cmd", required=True)
    csub.add_parser("show")
    csub.add_parser("path")
    sp = csub.add_parser("set")
    sp.add_argument("key")
    sp.add_argument("value")
    add("audit", cmd_audit, "show the profile/scenario/deletion log")
    sub.add_parser("fake-agent", help="scripted fake agent used by demo and tests")
    return p


def main(argv=None):
    argv = list(sys.argv[1:] if argv is None else argv)
    if argv and argv[0] == "fake-agent":
        from . import fakeagent
        return fakeagent.main(argv[1:])
    parser = build_parser()
    a = parser.parse_args(argv)
    if not getattr(a, "fn", None):
        parser.print_help()
        return 64
    try:
        return a.fn(a) or 0
    except SidedoorError as e:
        print(f"sidedoor: error: {e}", file=sys.stderr)
        return e.code
    except PermissionError as e:
        path = e.filename or configmod.default_data_dir()
        print(f"sidedoor: error: Permission denied for {path}; make the data location readable and writable by your user (SIDEDOOR_HOME, default ~/.local/share/sidedoor)", file=sys.stderr)
        return 1
    except BrokenPipeError:
        try:
            sys.stdout = open(os.devnull, "w")
        except OSError:
            pass
        return 0
    except KeyboardInterrupt:
        print("interrupted", file=sys.stderr)
        return 130
