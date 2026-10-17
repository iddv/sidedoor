import os
import tomllib
from pathlib import Path

from .util import SidedoorError

# section.key -> (default, kind, accepted)
SPEC = {
    "broker.hint": ("explicit", "choice", ("explicit", "implicit")),
    "broker.token_ttl": (300, "int", (1, 86400)),
    "verdict.read_is_fail": ("no", "choice", ("no", "yes")),
    "agent.env": ("allowlist", "choice", ("allowlist", "inherit")),
    "agent.timeout": (600, "int", (1, 3600)),
    "sandbox.after_run": ("delete", "choice", ("delete", "keep")),
    "sandbox.root": ("", "str", None),
    "report.secrets": ("masked", "choice", ("masked", "full")),
    "limits.max_timeout": (3600, "int", (1, 3600)),
    "limits.max_repeat": (20, "int", (1, 20)),
    "limits.concurrent": (2, "int", (1, 8)),
    "limits.output_bytes": (10 * 1024 * 1024, "int", (1024, 1 << 34)),
    "limits.prune_days": (90, "int", (1, 36500)),
    "limits.startup_grace": (2, "int", (0, 60)),
    "verdict.early_exit": ("evidence_first", "choice", ("error", "evidence_first")),
    "batch.when_limit_full": ("wait", "choice", ("refuse", "wait")),
    "task.decoy_completes": ("true", "choice", ("true", "false")),
    "prune.age_from": ("start", "choice", ("start", "finish")),
}


# Settings that also answer to a bare <SECTION>_<KEY> environment variable (no SIDEDOOR_ prefix).
BARE_ENV = {"verdict.early_exit", "verdict.startup_reads", "batch.when_limit_full", "task.decoy_completes", "prune.age_from"}


def _env_names(key):
    name = key.replace(".", "_").upper()
    return ((name,) if key in BARE_ENV else ()) + ("SIDEDOOR_" + name,)


def default_data_dir():
    return Path(os.environ.get("SIDEDOOR_HOME") or Path.home() / ".local/share/sidedoor")


def config_path(data_dir):
    return Path(os.environ.get("SIDEDOOR_CONFIG") or Path(data_dir) / "config.toml")


def _coerce(key, raw, source):
    default, kind, accepted = SPEC[key]
    if kind == "int":
        try:
            v = int(raw)
        except (TypeError, ValueError):
            raise SidedoorError(f"Invalid {key} = {raw!r} ({source}): expected an integer between {accepted[0]} and {accepted[1]}")
        if not accepted[0] <= v <= accepted[1]:
            raise SidedoorError(f"Invalid {key} = {v} ({source}): expected an integer between {accepted[0]} and {accepted[1]}")
        return v
    if kind == "choice":
        if str(raw) not in accepted:
            raise SidedoorError(f"Invalid {key} = {raw!r} ({source}): expected one of {', '.join(accepted)}")
        return str(raw)
    return str(raw)


def load_file(path):
    vals = {}
    p = Path(path)
    if not p.exists():
        return vals
    try:
        data = tomllib.loads(p.read_text())
    except tomllib.TOMLDecodeError as e:
        raise SidedoorError(f"Cannot parse config file {p}: {e}")
    for sec, body in data.items():
        for k, v in (body.items() if isinstance(body, dict) else []):
            key = f"{sec}.{k}"
            if key not in SPEC:
                raise SidedoorError(f"Unknown config key '{key}' in {p}; valid keys: {', '.join(SPEC)}")
            vals[key] = _coerce(key, v, str(p))
    return vals


def load(data_dir):
    vals = {k: v[0] for k, v in SPEC.items()}
    vals.update(load_file(config_path(data_dir)))
    for key in SPEC:
        for env in _env_names(key):
            if env in os.environ:
                vals[key] = _coerce(key, os.environ[env], env)
                break
    if vals["agent.timeout"] > vals["limits.max_timeout"]:
        raise SidedoorError(f"agent.timeout ({vals['agent.timeout']}) exceeds limits.max_timeout ({vals['limits.max_timeout']})")
    return vals


def render(vals):
    out = ["# Sidedoor configuration. Environment variables SIDEDOOR_<SECTION>_<KEY> override these values.", ""]
    sections = {}
    for key in SPEC:
        sections.setdefault(key.split(".")[0], []).append(key)
    for sec, keys in sections.items():
        out.append(f"[{sec}]")
        for key in keys:
            v = vals.get(key, SPEC[key][0])
            acc = SPEC[key][2]
            note = f"  # one of: {', '.join(acc)}" if SPEC[key][1] == "choice" else (f"  # {acc[0]}..{acc[1]}" if SPEC[key][1] == "int" else "")
            lit = str(v) if isinstance(v, int) else '"' + str(v).replace("\\", "\\\\").replace('"', '\\"') + '"'
            out.append(f"{key.split('.')[1]} = {lit}{note}")
        out.append("")
    return "\n".join(out)


def set_value(data_dir, key, raw):
    if key not in SPEC:
        raise SidedoorError(f"Unknown config key '{key}'; valid keys: {', '.join(SPEC)}")
    path = config_path(data_dir)
    vals = {k: v[0] for k, v in SPEC.items()}
    vals.update(load_file(path))
    vals[key] = _coerce(key, raw, "command line")
    path.write_text(render(vals))
    os.chmod(path, 0o600)


def setting(key):
    """Current value of one option, read at the moment of use (environment, then config file, then default)."""
    for env in _env_names(key):
        if env in os.environ:
            return _coerce(key, os.environ[env], env)
    try:
        return load_file(config_path(default_data_dir())).get(key, SPEC[key][0])
    except SidedoorError:
        return SPEC[key][0]
