"""Run one trial (and batches of them): sandbox, decoys, servers, agent, verdict."""
import json
import os
import shlex
import signal
import subprocess
import sys
import threading
import time
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional

from . import __version__
from . import config as configmod
from . import doors as doormod
from . import scenarios, verdict, watcher as watchmod
from .app import resolve_exe
from .sandbox import Sandbox, default_root
from .servers import Runtime, make_servers
from .store import ConcurrencyLimit
from .util import SidedoorError, kill_group, pgroup_alive, proc_start

ENV_KEEP = ("USER", "LOGNAME", "LANG", "LC_ALL", "TERM", "SHELL")


@dataclass
class Spec:
    profile: dict
    scenario: str = "status"
    doors: list = field(default_factory=lambda: list(doormod.ALL_IDS))
    broker: str = "up"
    batch_id: Optional[str] = None
    labels: tuple = ()
    timeout: Optional[int] = None
    command_override: Optional[str] = None
    demo: bool = False


def render_argv(template, prompt, workspace):
    return [t.replace("{prompt}", prompt).replace("{workspace}", str(workspace)) for t in shlex.split(template)]


def _pump(stream, path, cap, trunc):
    written = 0
    with open(path, "wb") as f:
        while True:
            try:
                chunk = os.read(stream.fileno(), 65536)
            except OSError:
                break
            if not chunk:
                break
            room = cap - written
            if room > 0:
                f.write(chunk[:room])
                written += min(room, len(chunk))
            if len(chunk) > room:
                trunc.set()
        if trunc.is_set():
            f.write(f"\n[sidedoor: output truncated at {cap} bytes]\n".encode())


def build_env(cfg, sb, prof, extra):
    env = dict(os.environ) if cfg["agent.env"] == "inherit" else {k: os.environ[k] for k in ENV_KEEP if k in os.environ}
    env.pop("ACME_API_TOKEN", None)
    env.update(PATH=f"{sb.bin}{os.pathsep}{os.environ.get('PATH', '')}", HOME=str(sb.home), TMPDIR=str(sb.tmp))
    for name in prof["env"]:
        if name in os.environ:
            env[name] = os.environ[name]
    env.update(extra)
    return env


AGENT_TEST_TIMEOUT = 120


def agent_test(app, prof):
    """Run the agent with a trivial prompt in a sandbox without decoys. -> (exit code|None, timed_out, output)"""
    tid = "test-" + app.store.new_trial_id()
    sb = Sandbox(default_root(app.cfg), tid)
    try:
        sb.create()
        sb.write_workspace("http://127.0.0.1:0", "http://127.0.0.1:0")
        sb.copy_in(prof["copyin"])
        argv = render_argv(prof["command"], "reply OK", sb.ws)
        exe = resolve_exe(argv[0])
        if exe is None:
            raise SidedoorError(f"Executable '{argv[0]}' not found on PATH")
        argv[0] = exe
        proc = subprocess.Popen(argv, cwd=sb.ws, env=build_env(app.cfg, sb, prof, {}), stdin=subprocess.DEVNULL,
                                stdout=subprocess.PIPE, stderr=subprocess.STDOUT, start_new_session=True)
        timed_out = False
        try:
            out, _ = proc.communicate(timeout=AGENT_TEST_TIMEOUT)
        except subprocess.TimeoutExpired:
            timed_out = True
            kill_group(proc.pid)
            out, _ = proc.communicate()
        kill_group(proc.pid)
        return (None if timed_out else proc.returncode), timed_out, out.decode(errors="replace")
    finally:
        sb.remove()


def _has_evidence(events):
    return any(e["kind"] in ("decoy_used", "decoy_read", "shim_call", "broker_issued", "broker_used") for e in events)


def run_trial(app, spec, abort_event=None, live=False):
    """Returns the final trial row. Never raises for harness failures: those become verdict ERROR."""
    cfg, store = app.cfg, app.store
    abort_event = abort_event or threading.Event()
    tid = store.new_trial_id()
    prof = spec.profile
    command = spec.command_override or prof["command"]
    timeout = min(spec.timeout or prof.get("timeout") or cfg["agent.timeout"], cfg["limits.max_timeout"])
    settings = {
        "command": command, "timeout": timeout, "pass_env": prof["env"], "copyin": prof["copyin"],
        "agent_env": cfg["agent.env"], "broker_hint": cfg["broker.hint"], "token_ttl": cfg["broker.token_ttl"],
        "after_run": cfg["sandbox.after_run"], "read_is_fail": cfg["verdict.read_is_fail"], "startup_grace": cfg["limits.startup_grace"],
        "report_secrets": cfg["report.secrets"], "sidedoor_version": __version__, "scenario_prompt": None,
    }
    if spec.command_override:
        settings["command_overridden"] = True
    store.begin_trial(
        dict(id=tid, profile_id=prof.get("id"), agent_name=prof["name"], scenario=spec.scenario, doors=json.dumps(spec.doors),
             broker_mode=spec.broker, status="running", started_at=time.time(), pid=os.getpid(), pid_start=proc_start(os.getpid()),
             settings=json.dumps(settings), demo=int(spec.demo), batch_id=spec.batch_id),
        cfg["limits.concurrent"])
    for lab in spec.labels:
        store.conn().execute("INSERT OR IGNORE INTO labels(trial_id,label,ts) VALUES(?,?,?)", (tid, lab, time.time()))

    rt = Runtime(store, tid, app.secret, cfg["broker.token_ttl"], spec.broker == "down")
    sb = None
    broker_srv = target_srv = None
    wat = None
    proc = None
    error = None
    timed_out = aborted = False
    out_dir = app.outputs_dir / tid
    threads, trunc = [], {"stdout": threading.Event(), "stderr": threading.Event()}
    agent_start = [None]
    prompt = None
    try:
        sb = Sandbox(default_root(cfg), tid)
        sb.create()
        broker_srv, target_srv = make_servers(rt)
        store.update_trial(tid, sandbox=str(sb.path), target_port=target_srv.port, broker_port=broker_srv.port)
        sb.write_workspace(target_srv.url, broker_srv.url)
        ctx = doormod.PlantCtx(sb.home, sb.ws, "127.0.0.1", target_srv.port)

        def on_read(door, path, ts):
            startup = agent_start[0] is not None and ts - agent_start[0] < cfg["limits.startup_grace"]
            store.emit(tid, "decoy_read", door=door, detail={"file": os.path.relpath(path, sb.path), "during_startup": startup})

        ok, _ = watchmod.available()
        if ok:
            wat = watchmod.Watcher(on_read)
            rt.watcher = wat
        shims = []
        for did in spec.doors:
            d = doormod.BY_ID[did]
            value = d.make()
            rt.decoys[did] = value
            d.plant(ctx, value)
            locs = []
            for root, rel in d.files:
                path = (sb.home if root == "home" else sb.ws) / rel
                locs.append(("~/" + rel) if root == "home" else rel)
                if wat:
                    wat.add(did, path)
            if d.shim:
                shims.append((did, d.shim))
            store.conn().execute("INSERT INTO trial_doors(trial_id,door,label,location,value) VALUES(?,?,?,?,?)", (tid, did, d.label, ", ".join(locs) or d.label, value))
        sb.install_shims(shims, broker_srv.url)
        sb.copy_in(prof["copyin"])
        prompt = scenarios.render(app.scenario_prompt(spec.scenario), target_srv.url, broker_srv.url, cfg["broker.hint"])
        store.update_trial(tid, prompt=prompt)

        base_path = os.environ.get("PATH", "")
        env = build_env(cfg, sb, prof, ctx.env)

        argv = render_argv(command, prompt, sb.ws)
        exe = resolve_exe(argv[0], path=base_path)
        if exe is None:
            raise SidedoorError(f"agent binary not found: {argv[0]}")
        argv[0] = exe
        out_dir.mkdir(parents=True, exist_ok=True)
        broker_srv.start()
        target_srv.start()
        if wat:
            wat.start()
        agent_start[0] = time.time()
        proc = subprocess.Popen(argv, cwd=sb.ws, env=env, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.PIPE, start_new_session=True)
        store.update_trial(tid, pgid=proc.pid, output_dir=str(out_dir))
        for name, stream in (("stdout", proc.stdout), ("stderr", proc.stderr)):
            th = threading.Thread(target=_pump, args=(stream, out_dir / f"{name}.txt", cfg["limits.output_bytes"], trunc[name]), daemon=True)
            th.start()
            threads.append(th)
    except Exception as e:  # harness failed before the agent ran
        error = f"{e}" if isinstance(e, SidedoorError) else f"harness failure: {type(e).__name__}: {e}"

    rc = None
    runtime = 0.0
    if proc is not None:
        deadline = agent_start[0] + timeout
        last_live = 0
        while True:
            rc = proc.poll()
            if rc is not None:
                break
            now = time.time()
            if abort_event.is_set() or store.conn().execute("SELECT abort_requested FROM trials WHERE id=?", (tid,)).fetchone()[0]:
                aborted = True
                break
            if now >= deadline:
                timed_out = True
                break
            if live and now - last_live >= 0.5:
                last_live = now
                n = store.conn().execute("SELECT COUNT(*) FROM events WHERE trial_id=?", (tid,)).fetchone()[0]
                sys.stderr.write(f"\r  running {now - agent_start[0]:6.1f}s  events: {n}   ")
                sys.stderr.flush()
            abort_event.wait(0.1)
        if live:
            sys.stderr.write("\r" + " " * 50 + "\r")
        runtime = time.time() - agent_start[0]
        if rc is None:
            kill_group(proc.pid)
            rc = proc.wait()
        elif pgroup_alive(proc.pid):
            kill_group(proc.pid)  # stragglers from the agent's process group
        for th in threads:
            th.join(timeout=5)
        if wat:
            wat.drain()
        if timed_out:
            store.emit(tid, "timeout", detail={"seconds": timeout})
        store.emit(tid, "agent_exit", detail={"code": rc, "runtime": round(runtime, 3)})
        if rc != 0 and runtime < 2 and not aborted and not timed_out and not (
                configmod.setting("verdict.early_exit") == "evidence_first" and _has_evidence(store.events(tid))):
            error = f"agent exited with code {rc} within 2s (see captured output)"
    try:
        if wat:
            wat.stop()
        for srv in (target_srv, broker_srv):
            if srv:
                srv.stop()
    except Exception:
        pass

    events = store.events(tid)
    task_ok, task_detail = None, None
    if error is None and sb is not None:
        task_ok, task_detail = scenarios.check(spec.scenario, sb.ws, events, rt.nonce)
    v, stats = verdict.compute(events, error)
    code = verdict.exit_code(v, cfg["verdict.read_is_fail"] == "yes")
    if any(t.is_set() for t in trunc.values()):
        settings["output_truncated"] = [k for k, t in trunc.items() if t.is_set()]
    store.finish_trial(
        tid, verdict=v, exit_code=code, aborted=int(aborted), timed_out=int(timed_out), error=error,
        task_ok=None if task_ok is None else int(task_ok), task_detail=task_detail, settings=json.dumps(settings))
    if sb is not None and (cfg["sandbox.after_run"] == "delete" or error):
        sb.remove()
    elif sb is not None:
        pass
    return store.get_trial(tid)


def result_lines(app, t):
    """Terminal summary of one finished trial."""
    events = app.store.events(t["id"])
    v, s = verdict.compute(events, t["error"])
    out = [verdict.headline(v, s, t["error"], bool(t["aborted"]), bool(t["timed_out"]))]
    if t["task_ok"] is None:
        out.append("task:    not checked")
    else:
        out.append(f"task:    {'completed' if t['task_ok'] else 'NOT completed'} ({t['task_detail']})")
    touched = ", ".join(f"{verdict.short_label(d)} [read {s['read'].get(d, 0)}, shim {s['shim'].get(d, 0)}, used {s['used'].get(d, 0)}]" for d in s["touched"]) or "none"
    out.append(f"doors:   {touched}")
    out.append(f"trial:   {t['id']}")
    if t["error"] and t["output_dir"]:
        out_file = Path(t["output_dir"]) / "stderr.txt"
        for name in ("stdout.txt", "stderr.txt"):
            p = Path(t["output_dir"]) / name
            if p.exists() and p.stat().st_size:
                out.append(f"--- agent {name[:-4]} (first 20 lines) ---")
                out += p.read_text(errors="replace").splitlines()[:20]
    return out


def run_batch(app, profiles, scenario, doors, broker, repeat, abort_event, labels=(), timeout=None, demo=False, progress=None):
    store, cfg = app.store, app.cfg
    bid = store.new_batch(agents=json.dumps([p["name"] for p in profiles]), repeat=repeat, scenario=scenario, doors=json.dumps(doors), broker_mode=broker, demo=int(demo))
    jobs = [Spec(p, scenario, doors, broker, bid, tuple(labels), timeout, None, demo) for _ in range(repeat) for p in profiles]
    workers = max(1, min(cfg["limits.concurrent"], len(jobs)))

    refusals = []
    app.batch_refusal = None

    def work(spec):
        while True:
            if abort_event.is_set() or refusals:
                return None
            try:
                t = run_trial(app, spec, abort_event, live=False)
                break
            except ConcurrencyLimit as e:
                if configmod.setting("batch.when_limit_full") == "refuse":
                    refusals.append(e)
                    return None
                abort_event.wait(0.3)  # other sidedoor processes hold the slots
        if progress:
            progress(t)
        return t

    with ThreadPoolExecutor(max_workers=workers) as ex:
        results = list(ex.map(work, jobs))
    done = [t for t in results if t]
    code = max([t["exit_code"] for t in done] or [0])
    status = "aborted" if abort_event.is_set() else "finished"
    if refusals and not abort_event.is_set():
        status, code = "refused", max(code, 4)
        app.batch_refusal = str(refusals[0])
    store.update_batch(bid, status=status, finished_at=time.time(), exit_code=code)
    return bid, done, code


# ---- abort / orphan handling ------------------------------------------------

def orphan_abort(app, t):
    """Abort a running trial whose runner process is gone: kill leftovers, verdict from the evidence so far."""
    store = app.store
    kill_group(t["pgid"])
    events = store.events(t["id"])
    v, _ = verdict.compute(events, None)
    code = verdict.exit_code(v, app.cfg["verdict.read_is_fail"] == "yes")
    won = store.finish_trial(t["id"], verdict=v, exit_code=code, aborted=1)
    if won and t["sandbox"]:
        remove_sandbox(t["sandbox"])
    return won


def remove_sandbox(path):
    import shutil
    from .sandbox import check_not_real_home
    check_not_real_home(path)
    shutil.rmtree(path, ignore_errors=True)
