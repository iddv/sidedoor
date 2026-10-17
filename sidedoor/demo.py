"""`sidedoor demo`: four scripted fake-agent profiles and about 16 trials covering every verdict."""
import shlex
import shutil
import sys
import threading
from pathlib import Path

from . import doors as doormod
from . import report as reportmod
from . import trial as trialmod
from .util import SidedoorError

LAUNCH = str(Path(__file__).resolve().parent / "_launch.py")
PROFILES = {"careful": "broker", "leaky-env": "env", "netrc-sneak": "netrc", "flaky": "broker-then-netrc"}


def fake_cmd(behavior, *extra):
    return shlex.join([sys.executable, LAUNCH, "fake-agent", "--behavior", behavior, *extra]) + " --prompt={prompt}"


def has_demo(store):
    c = store.conn()
    return any(c.execute(f"SELECT 1 FROM {t} WHERE demo=1 LIMIT 1").fetchone() for t in ("profiles", "trials", "batches"))


def reset(app):
    st = app.store
    ts = [t for t in st.list_trials() if t["demo"]]
    if any(t["status"] == "running" for t in ts):
        raise SidedoorError("A demo trial is running; abort it first")
    for t in ts:
        if t["output_dir"]:
            shutil.rmtree(t["output_dir"], ignore_errors=True)
    st.delete_trials([t["id"] for t in ts])
    st.conn().execute("DELETE FROM batches WHERE demo=1")
    st.conn().execute("DELETE FROM profiles WHERE demo=1")
    st.audit("demo.reset", "", f"{len(ts)} trials")


def run(app, reset_demo):
    st = app.store
    if has_demo(st):
        if not reset_demo:
            raise SidedoorError("Demo data already exists; run `sidedoor demo --reset-demo` to remove it and start over")
        reset(app)
    profs = {}
    for name, behavior in PROFILES.items():
        st.save_profile(dict(name=name, preset=None, command=fake_cmd(behavior), timeout=60, env=[], copyin=[], demo=1), True)
        profs[name] = st.get_profile(name)
    st.audit("demo.create", "", "profiles " + ", ".join(PROFILES))
    ev = threading.Event()
    plan = [  # profile, scenario, doors, broker, command override
        ("careful", "status", "all", "up", None),
        ("careful", "create", "all", "up", None),
        ("careful", "config", "all", "up", None),
        ("leaky-env", "status", "all", "up", None),
        ("netrc-sneak", "status", "all", "up", None),
        ("flaky", "create", "all", "up", None),
        ("netrc-sneak", "status", "dotenv,netrc", "up", fake_cmd("dotenv")),
        ("netrc-sneak", "create", "all", "up", fake_cmd("pass")),
        ("netrc-sneak", "config", "all", "up", fake_cmd("door", "--door", "aws")),
        ("careful", "status", "all", "up", fake_cmd("probe")),
        ("careful", "status", "all", "down", None),
        ("careful", "status", "all", "up", "sh -c 'exit 3' fake-agent {prompt}"),
    ]
    n = 0
    for pname, scen, dspec, broker, override in plan:
        spec = trialmod.Spec(profs[pname], scen, doormod.parse_doors(dspec), broker, labels=("demo",), command_override=override, demo=True)
        t = trialmod.run_trial(app, spec, ev)
        n += 1
        print(f"  [{n}] {pname:12} {scen:7} {t['verdict']}", flush=True)
    bid, trials, code = trialmod.run_batch(app, [profs["careful"], profs["netrc-sneak"]], "status", doormod.parse_doors("all"), "up", 2, ev, ("demo",), None, demo=True)
    print(f"  batch {bid}: {len(trials)} trials")
    print()
    print(reportmod.summary_text(reportmod.aggregate(app, [t for t in st.list_trials() if t["demo"]])))
    print(f"\nDemo created: {len(PROFILES)} profiles, {n + len(trials)} trials. Try `sidedoor trials` or `sidedoor show <id>`.")
    return 0
