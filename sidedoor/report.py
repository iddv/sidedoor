import html
import json
import time
from collections import Counter
from pathlib import Path
from xml.sax.saxutils import escape as xesc, quoteattr

from . import __version__, verdict as vd
from .util import fmt_ts, iso, mask, table

LIMITATIONS = ("The agent runs as your user and is not contained. Sidedoor sees only the sandbox decoys, shims and target. "
               "It cannot see reads of your real home via absolute paths.")


def profile_label(app, t):
    if t["profile_id"] is not None and app.store.profile_by_id(t["profile_id"]):
        return t["agent_name"]
    return f"{t['agent_name']} (deleted profile)"


def event_note(e):
    d = e["detail"]
    bits = []
    if "status" in d:
        bits.append(f"HTTP {d['status']}")
    if d.get("during_startup"):
        bits.append("during agent startup")
    if e["kind"] == "decoy_read" and d.get("file"):
        bits.append(d["file"])
    if e["kind"] == "shim_call":
        bits.append(" ".join([d.get("shim", "")] + d.get("args", [])).strip())
    if e["kind"] == "broker_issued":
        bits.append(f"scope {d.get('scope')}")
    if e["kind"] == "agent_exit":
        bits.append(f"code {d.get('code')}")
    if e["kind"] == "timeout":
        bits.append(f"after {d.get('seconds')}s")
    return ", ".join(bits)


def bundle(app, t, secrets_mode=None):
    store = app.store
    mode = secrets_mode or app.cfg["report.secrets"]
    events = store.events(t["id"])
    v, s = vd.compute(events, t["error"])
    doors = []
    for d in store.trial_doors(t["id"]):
        k = d["door"]
        doors.append({
            "door": k, "label": d["label"], "location": d["location"],
            "planted": d["value"] if mode == "full" else mask(d["value"]),
            "read": s["read"].get(k, 0), "shim_called": s["shim"].get(k, 0), "used": s["used"].get(k, 0)})
    return {
        "id": t["id"], "batch": t["batch_id"], "agent": profile_label(app, t), "scenario": t["scenario"],
        "status": t["status"], "verdict": t["verdict"], "exit_code": t["exit_code"], "aborted": bool(t["aborted"]), "timed_out": bool(t["timed_out"]),
        "headline": vd.headline(v, s, t["error"], bool(t["aborted"]), bool(t["timed_out"])) if t["status"] == "finished" else t["status"],
        "error": t["error"], "started_at": iso(t["started_at"]), "finished_at": iso(t["finished_at"]),
        "started_local": fmt_ts(t["started_at"]), "duration_s": round((t["finished_at"] or t["started_at"]) - t["started_at"], 2),
        "doors_planted": json.loads(t["doors"]), "doors": doors,
        "broker": {"mode": t["broker_mode"], "issued": s["broker_issued"], "used": s["broker_used"], "expired": s["broker_expired"]},
        "unauth_requests": s["unauth"],
        "task": {"completed": None if t["task_ok"] is None else bool(t["task_ok"]), "detail": t["task_detail"]},
        "prompt": t["prompt"], "settings": json.loads(t["settings"] or "{}"), "output_dir": t["output_dir"],
        "events": [{"seq": e["seq"], "time": iso(e["ts"]), "time_local": fmt_ts(e["ts"], False), "kind": e["kind"], "door": e["door"], "method": e["method"], "path": e["path"], "note": event_note(e)} for e in events],
        "notes": [{"time": iso(n["ts"]), "text": n["text"]} for n in store.notes(t["id"])],
        "labels": store.labels(t["id"]),
    }


def aggregate(app, trials):
    """Per-agent comparison rows. Counts come from stored trial verdicts and events."""
    by = {}
    for t in trials:
        by.setdefault(profile_label(app, t), []).append(t)
    rows = []
    for agent, ts in sorted(by.items()):
        c = Counter(t["verdict"] or ("INTERRUPTED" if t["status"] == "interrupted" else "RUNNING") for t in ts)
        doors = Counter()
        for t in ts:
            for e in app.store.events(t["id"]):
                if e["kind"] == "decoy_used":
                    doors[e["door"]] += 1
        done = sum(1 for t in ts if t["task_ok"])
        rows.append({
            "agent": agent, "runs": len(ts), "verdicts": {v: c.get(v, 0) for v in vd.VERDICTS},
            "other": {k: n for k, n in c.items() if k not in vd.VERDICTS},
            "task_completed": done, "task_rate": round(100 * done / len(ts), 1),
            "top_doors": [{"door": d, "count": n} for d, n in doors.most_common(3)]})
    return rows


def pct(n, total):
    return f"{n} ({100 * n / total:.0f}%)" if total else "0"


def summary_text(rows):
    headers = ["agent", "runs", *vd.VERDICTS, "task done", "top doors"]
    out = []
    for r in rows:
        n = r["runs"]
        out.append([r["agent"], n, *(pct(r["verdicts"][v], n) for v in vd.VERDICTS), f"{r['task_completed']}/{n} ({r['task_rate']:.0f}%)",
                    ", ".join(f"{vd.short_label(d['door'])} ×{d['count']}" for d in r["top_doors"]) or "-"])
    return table(headers, out)


def build(app, trials, batch=None, title=None, secrets_mode=None):
    bundles = [bundle(app, t, secrets_mode) for t in trials]
    worst = max([b["exit_code"] for b in bundles if b["exit_code"] is not None] or [0])
    return {
        "sidedoor_version": __version__, "generated_at": iso(time.time()), "title": title or "Sidedoor report",
        "limitations": LIMITATIONS, "secrets": secrets_mode or app.cfg["report.secrets"],
        "batch": ({"id": batch["id"], "status": batch["status"], "agents": json.loads(batch["agents"]), "repeat": batch["repeat"], "scenario": batch["scenario"]} if batch else None),
        "trial_count": len(bundles), "worst_exit_code": worst,
        "summary": aggregate(app, trials), "trials": bundles,
    }


def scrub(app, text, mode):
    if mode == "full":
        return text
    for (v,) in app.store.conn().execute("SELECT value FROM trial_doors"):
        text = text.replace(v, mask(v))
    return text


def to_json(r):
    if not r["trials"]:
        r = {**r, "message": "no trials"}
    return json.dumps(r, indent=2)


def to_md(r):
    o = [f"# {r['title']}", "", f"Sidedoor {r['sidedoor_version']}, generated {r['generated_at']}. Trials: {r['trial_count']}.", "", f"> {r['limitations']}", ""]
    if not r["trials"]:
        return "\n".join(o + ["No trials in this report.", ""])
    if r["batch"]:
        b = r["batch"]
        o += [f"Batch `{b['id']}` ({b['status']}): agents {', '.join(b['agents'])}, {b['repeat']} run(s) each, scenario `{b['scenario']}`.", ""]
    o += ["## Summary", "", "```", summary_text(r["summary"]), "```", ""]
    for t in r["trials"]:
        o += [f"## Trial {t['id']}: {t['headline']}", "",
              f"- Agent: {t['agent']}  Scenario: {t['scenario']}  Verdict: **{t['verdict']}** (exit code {t['exit_code']})",
              f"- Started: {t['started_local']}  Duration: {t['duration_s']}s  Aborted: {t['aborted']}  Timed out: {t['timed_out']}",
              f"- Task: {'completed' if t['task']['completed'] else ('not completed' if t['task']['completed'] is not None else 'not checked')} ({t['task']['detail']})",
              f"- Broker: mode {t['broker']['mode']}, issued {t['broker']['issued']}, used {t['broker']['used']}, expired-token use {t['broker']['expired']}",
              f"- Unauthenticated requests: {t['unauth_requests']}"]
        if t["error"]:
            o.append(f"- Error: {t['error']}")
        o += ["", "### Doors", "", "| door | planted value | read | shim called | used |", "|---|---|---|---|---|"]
        o += [f"| {d['label']} | `{d['planted']}` | {d['read']} | {d['shim_called']} | {d['used']} |" for d in t["doors"]]
        o += ["", "### Timeline", "", "| # | time | kind | door | request | note |", "|---|---|---|---|---|---|"]
        o += [f"| {e['seq']} | {e['time_local']} | {e['kind']} | {e['door'] or ''} | {((e['method'] or '') + ' ' + (e['path'] or '')).strip()} | {e['note']} |" for e in t["events"]]
        o += ["", "### Prompt", "", "```", t["prompt"] or "", "```", "", "### Settings", "", "```json", json.dumps(t["settings"], indent=2), "```", ""]
    return "\n".join(o)


def to_html(r):
    e = html.escape

    def tbl(headers, rows):
        return "<table><tr>" + "".join(f"<th>{e(h)}</th>" for h in headers) + "</tr>" + "".join("<tr>" + "".join(f"<td>{e(str(c))}</td>" for c in row) + "</tr>" for row in rows) + "</table>"

    o = ["<!doctype html><html lang=en><head><meta charset=utf-8>", f"<title>{e(r['title'])}</title>",
         "<style>body{font:14px/1.5 system-ui,sans-serif;max-width:1000px;margin:2em auto;padding:0 1em;color:#222}"
         "table{border-collapse:collapse;margin:.5em 0;width:100%}th,td{border:1px solid #ccc;padding:3px 8px;text-align:left;vertical-align:top}th{background:#f3f3f3}"
         "pre{background:#f6f6f6;padding:.7em;overflow:auto}.v{font-weight:bold;padding:2px 8px;border-radius:4px;color:#fff}"
         ".BROKER{background:#1a7f37}.SIDEDOOR{background:#cf222e}.PROBED{background:#bf8700}.NO_AUTH{background:#6e7781}.ERROR{background:#8250df}"
         ".note{background:#fff8c5;border:1px solid #d4a72c;padding:.6em}</style></head><body>",
         f"<h1>{e(r['title'])}</h1><p>Sidedoor {e(r['sidedoor_version'])}, generated {e(r['generated_at'])}. Trials: {r['trial_count']}.</p>",
         f"<p class=note>{e(r['limitations'])}</p>"]
    if not r["trials"]:
        return "".join(o) + "<p>No trials in this report.</p></body></html>"
    if r["batch"]:
        b = r["batch"]
        o.append(f"<p>Batch <code>{e(b['id'])}</code> ({e(b['status'])}): agents {e(', '.join(b['agents']))}, {b['repeat']} run(s) each, scenario {e(b['scenario'])}.</p>")
    o.append("<h2>Summary</h2><pre>" + e(summary_text(r["summary"])) + "</pre>")
    for t in r["trials"]:
        o.append(f"<h2>Trial {e(t['id'])} <span class='v {e(str(t['verdict']))}'>{e(str(t['verdict']))}</span></h2><p><b>{e(t['headline'])}</b></p>")
        o.append(tbl(["agent", "scenario", "started", "duration", "exit code", "aborted", "timed out", "task"],
                     [[t["agent"], t["scenario"], t["started_local"], f"{t['duration_s']}s", t["exit_code"], t["aborted"], t["timed_out"],
                       ("completed" if t["task"]["completed"] else "not completed") if t["task"]["completed"] is not None else "not checked"]]))
        o.append(f"<p>Broker: mode {e(str(t['broker']['mode']))}, issued {t['broker']['issued']}, used {t['broker']['used']}, expired-token use {t['broker']['expired']}. Unauthenticated requests: {t['unauth_requests']}.</p>")
        if t["error"]:
            o.append(f"<p>Error: {e(t['error'])}</p>")
        o.append("<h3>Doors</h3>" + tbl(["door", "planted value", "read", "shim called", "used"], [[d["label"], d["planted"], d["read"], d["shim_called"], d["used"]] for d in t["doors"]]))
        o.append("<h3>Timeline</h3>" + tbl(["#", "time", "kind", "door", "request", "note"], [[x["seq"], x["time_local"], x["kind"], x["door"] or "", ((x["method"] or "") + " " + (x["path"] or "")).strip(), x["note"]] for x in t["events"]]))
        o.append(f"<h3>Prompt</h3><pre>{e(t['prompt'] or '')}</pre><h3>Settings</h3><pre>{e(json.dumps(t['settings'], indent=2))}</pre>")
    return "".join(o) + "</body></html>"


def to_junit(r):
    trials = r["trials"]
    fails = [t for t in trials if t["exit_code"] in (1, 2, 3)]
    errs = [t for t in trials if t["exit_code"] == 4]
    o = ['<?xml version="1.0" encoding="UTF-8"?>', "<testsuites>",
         f'<testsuite name="sidedoor" tests="{len(trials)}" failures="{len(fails)}" errors="{len(errs)}" skipped="0" timestamp={quoteattr(r["generated_at"])}>',
         f'<properties><property name="sidedoor.version" value={quoteattr(r["sidedoor_version"])}/></properties>']
    for t in trials:
        o.append(f'<testcase classname={quoteattr(t["agent"])} name={quoteattr(t["scenario"] + " " + t["id"])} time="{t["duration_s"]}">')
        if t["exit_code"] == 4:
            o.append(f'<error message={quoteattr(t["headline"])}>{xesc(t["headline"])}</error>')
        elif t["exit_code"] in (1, 2, 3):
            o.append(f'<failure message={quoteattr(t["headline"])} type={quoteattr(str(t["verdict"]))}>{xesc(t["headline"])}</failure>')
        lines = [f"verdict={t['verdict']} exit_code={t['exit_code']} aborted={t['aborted']} timed_out={t['timed_out']}"]
        lines += [f"{d['label']}: planted={d['planted']} read={d['read']} shim={d['shim_called']} used={d['used']}" for d in t["doors"]]
        lines += [f"#{x['seq']} {x['time']} {x['kind']} {x['door'] or ''} {x['method'] or ''} {x['path'] or ''}".rstrip() for x in t["events"]]
        lines.append(r["limitations"])
        o.append(f"<system-out>{xesc(chr(10).join(lines))}</system-out></testcase>")
    if not trials:
        o.append("<system-out>no trials</system-out>")
    o += ["</testsuite>", "</testsuites>", ""]
    return "\n".join(o)


FORMATS = {"md": to_md, "html": to_html, "json": to_json, "junit": to_junit}
