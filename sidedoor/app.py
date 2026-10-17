import os
import re
import shlex
import shutil
import sys
from pathlib import Path

from . import config as configmod
from . import doors as doormod
from . import scenarios
from .presets import PRESETS
from .store import Store
from .util import SidedoorError, check_name

ENV_RE = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*$")


class App:
    def __init__(self, data_dir, cfg, store):
        self.data_dir, self.cfg, self.store = Path(data_dir), cfg, store

    @classmethod
    def load(cls):
        data_dir = configmod.default_data_dir()
        store = Store(data_dir)
        if not data_dir.is_dir() or not store.path.exists():
            raise SidedoorError("Not initialised; run `sidedoor init`")
        cfg = configmod.load(data_dir)
        migrated = store.ensure_current()
        if migrated:
            print(f"sidedoor: migrated store from schema v{migrated[0]} to v{migrated[1]} (backup written to {data_dir / 'backups'})", file=sys.stderr)
        return cls(data_dir, cfg, store)

    @property
    def secret(self):
        return (self.data_dir / "secret.key").read_text().strip()

    @property
    def outputs_dir(self):
        return self.data_dir / "outputs"

    # -- scenarios --------------------------------------------------------
    def scenario_prompt(self, name):
        if name in scenarios.BUILTIN:
            return scenarios.BUILTIN[name]["prompt"]
        s = self.store.get_scenario(name)
        if not s:
            raise SidedoorError(f"Unknown scenario '{name}'; valid scenarios: {', '.join(self.scenario_names())}")
        return s["prompt"]

    def scenario_names(self):
        return list(scenarios.BUILTIN) + [s["name"] for s in self.store.list_scenarios()]

    # -- profiles ---------------------------------------------------------
    def normalize_copyin(self, paths):
        home = Path(os.path.expanduser("~")).resolve()
        decoys = doormod.home_decoy_paths()
        out = []
        for raw in paths:
            p = Path(os.path.expanduser(raw))
            rel = p.relative_to(home) if p.is_absolute() and (p == home or home in p.parents) else p
            if rel.is_absolute() or ".." in rel.parts or str(rel) in ("", "."):
                raise SidedoorError(f"Copy-in path '{raw}' must be inside your home directory ({home})")
            rel_s = str(rel)
            for d in decoys:
                if rel_s == d or rel_s.startswith(d + "/") or d.startswith(rel_s + "/"):
                    raise SidedoorError(f"Copy-in path '{raw}' is a decoy path ({d}); decoys are planted by Sidedoor and real credentials are never copied")
            if not (home / rel).exists():
                raise SidedoorError(f"Copy-in path '{raw}' does not exist ({home / rel})")
            out.append(rel_s)
        return out

    def validate_profile(self, name, command, timeout, env, copyin, check_exe=True):
        check_name(name, "profile")
        if "{prompt}" not in (command or ""):
            raise SidedoorError("Command template must contain {prompt} (and may contain {workspace})")
        try:
            tokens = shlex.split(command)
        except ValueError as e:
            raise SidedoorError(f"Cannot parse command template: {e}")
        if not tokens:
            raise SidedoorError("Command template is empty")
        if check_exe and resolve_exe(tokens[0]) is None:
            raise SidedoorError(f"Executable '{tokens[0]}' not found on PATH")
        if timeout is not None:
            cap = self.cfg["limits.max_timeout"]
            if not 1 <= int(timeout) <= cap:
                raise SidedoorError(f"Invalid timeout {timeout}: expected 1..{cap} seconds")
        for e in env:
            if not ENV_RE.match(e):
                raise SidedoorError(f"Invalid environment variable name '{e}'")
            if e == "ACME_API_TOKEN":
                raise SidedoorError("ACME_API_TOKEN is reserved for the env decoy and cannot be passed through")
        return self.normalize_copyin(copyin)

    def preset_defaults(self, preset):
        if preset not in PRESETS:
            raise SidedoorError(f"Unknown preset '{preset}'; valid presets: {', '.join(PRESETS)}")
        return PRESETS[preset]

    def existing_preset_copyin(self, paths):
        home = Path(os.path.expanduser("~"))
        return [p for p in paths if (home / p).exists()]


def resolve_exe(exe, path=None):
    if os.sep in exe:
        return exe if os.access(exe, os.X_OK) and os.path.isfile(exe) else None
    return shutil.which(exe, path=path)
