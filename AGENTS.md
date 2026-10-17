# AGENTS.md — Sidedoor

Sidedoor is a command-line tool that checks whether a coding agent gets its secrets from the intended broker or from somewhere else on the machine. It plants decoy credentials in places such as environment variables, `.netrc`, `.env` files and a `pass` store, runs the agent, and reports where the agent took its credential from. Run `sidedoor init` and then `sidedoor doctor`, and try `sidedoor demo`, which uses scripted fake agents instead of a real one. It needs Python 3.11 or newer and has no dependencies.

Built by an autonomous build (see NOTICE); maintained through GitHub issues by the owner, by
bears, and by any coding agent that reads this file. CLAUDE.md imports this file.

## What this is

- **For:** see SCOPE.md › Users
- **Does:** Command-line tool that plants decoy credentials, runs a coding agent, and reports whether it took a secret from the broker or from a hidden place; run its tests with `python3 -m unittest discover -s tests -t .`.
- **Stack:** Python 3.11+, standard library only, a command-line tool.
- **Scope:** `SCOPE.md` (users, numbered flows F1–F7, domain rules, definition of done).
  `ASSUMPTIONS.md` lists the questions the idea left open and what this version does.

## Setup, run, test

bears runs these commands exactly as written before it proposes a fix.
If you change a command, change it here in the same commit. A line marked `# serve` starts the
service; the check waits for it to answer on 127.0.0.1, then stops it.

```sh
./install.sh   # install
python3 -m unittest discover -s tests -t .   # the product's own tests
python -m pip install pytest==8.3.3 && python -m pytest tests/acceptance   # the acceptance suite
```

- pytest is only needed for the acceptance suite; install it inside a virtual environment if
  your system Python refuses.
- Demo data: `see README` (empty install only).
- Backup and restore: `see README`, `see README`.
- Configuration: environment variables or `a config file` (see README › Configuration).

## Architecture in brief

| Path | Holds |
|---|---|
| `install.sh` | The launcher the README uses: `./install.sh` is its first command. |
| `sidedoor/__main__.py` | Runs the package as a command: `python -m sidedoor`. |
| `sidedoor/_launch.py` | Run sidedoor from a source checkout without installing (used by the demo fake agent). |
| `sidedoor/app.py` | Not described yet: read the module itself (it has no docstring). |
| `sidedoor/brokercli.py` | The mock broker CLI: `broker token --scope <scope>` (stdlib only). |
| `sidedoor/cli.py` | Not described yet: read the module itself (it has no docstring). |
| `sidedoor/config.py` | Not described yet: read the module itself (it has no docstring). |
| `sidedoor/demo.py` | `sidedoor demo`: four scripted fake-agent profiles and about 16 trials covering every verdict. |
| `sidedoor/doors.py` | The doors: places a credential can be picked up from, how each decoy is planted and recognised. |
| `sidedoor/fakeagent.py` | Scripted fake agent used by `demo` and the test suite. It behaves like a coding agent that is either well-behaved (asks the broker) or sneaky (takes a credential from some hiding spot). |
| `sidedoor/presets.py` | Preset agent profiles: non-interactive command, auto-approve flags, env and copy-in defaults. |
| `sidedoor/report.py` | Not described yet: read the module itself (it has no docstring). |
| `sidedoor/sandbox.py` | Not described yet: read the module itself (it has no docstring). |
| `sidedoor/scenarios.py` | Not described yet: read the module itself (it has no docstring). |
| `sidedoor/servers.py` | Mock broker (+ shim endpoint) and the target API, both bound to 127.0.0.1 on random ports. |
| `sidedoor/shimmain.py` | Standalone secret-store shim client: `shimmain.py <door> <broker-url> args...` (stdlib only). |
| `sidedoor/store.py` | Not described yet: read the module itself (it has no docstring). |
| `sidedoor/trial.py` | Run one trial (and batches of them): sandbox, decoys, servers, agent, verdict. |
| `sidedoor/util.py` | Not described yet: read the module itself (it has no docstring). |
| `sidedoor/verdict.py` | Not described yet: read the module itself (it has no docstring). |
| `sidedoor/watcher.py` | File-open detection on decoy files via inotify (Linux only). |
| `tests/test_core.py` | Unit tests (the product's own test command). |
| `tests/test_fixes.py` | Unit tests (the product's own test command). |
| `tests/test_ops.py` | Unit tests (the product's own test command). |
| `tests/test_settings.py` | Unit tests (the product's own test command). |

Data lives in `./data`; the schema is versioned (the schema version is stored with the data; pending migrations run at start), and a
pre-migration backup is written before any upgrade.

Evidence (`events`) is append-only (enforced by a database trigger), numbered per trial; verdicts, summaries and reports are derived from stored events.

## Conventions

- Standard library only. Do not add a dependency to fix a bug.
- Operator settings (binary business rules) are settings with an environment override; a new one
  goes in the config file and flags, the README table, `ASSUMPTIONS.md`, and gets an acceptance test per
  value. Never hard-code one side of a business rule.
- Every behaviour has one acceptance test file, `tests/acceptance/test_<what_it_checks>.py`,
  with a plain docstring (what it checks, what is expected, where the rule comes from). Helpers
  live in `tests/acceptance/_helpers/` and drive the product's real interface.
- Plain words in user-facing files: no build-process jargon, no internal ids.

## The acceptance suite, readiness and security

- `tests/acceptance/README.md` lists the **known open items**: tests marked
  `xfail(strict=False)` because the behaviour is not there yet. **To fix one:** make the test
  pass, then delete the mark block at the end of its file and the line in that README. CI fails
  if an xfail test now passes and still carries the mark.
- `READINESS.md` is the operational scorecard (install, localhost default, empty start, first
  admin, backup, restart, logs, CI, docs). Keep it true: a change that moves an item from amber
  to green edits the row.
- `SECURITY.md` is the threat model, what was probed, and the findings with their status. A fix
  for a finding changes its status there and names its test. Report new weaknesses privately
  (see its last section), never in a public issue.

## Operator settings

None yet. A new one follows the operator-settings convention above.

## Maintenance protocol (issues and labels)

Labels are the state; GitHub is the only record. `.github/labels.yml` defines them.

1. **Pick** an open issue labelled `go` with no assignee and no `claim:*` label (or one whose
   lease comment has expired and that has no open linked PR). `p1` before `p2` before `p3`.
2. **Claim** it: a person assigns themself; an agent adds `claim:agent` and a comment
   `<!-- bears:claim lease_until=<UTC+6h> branch=<branch> -->  Working on this.` Leave issues
   with `claim:bears` or an assignee alone.
3. **Branch** from `main`: `<who>/<N>-<slug>` (bears uses `bears/<N>-<slug>`).
4. **Reproduce first:** write `tests/acceptance/test_<slug>.py` that fails on `main` for the
   reason the issue describes. If you cannot make it fail, label `cannot-reproduce`, say why in a
   comment, remove your claim, and stop.
5. **Fix** with the smallest change that makes it pass without weakening another test.
6. **Verify:** run every command in *Setup, run, test*; the whole suite must be green; the
   README's quick start must still work as written.
7. **Documents:** update this file if a command, module or convention changed; `READINESS.md`
   or `SECURITY.md` if a row changed; add a line under *Unreleased* in `CHANGELOG.md`.
8. **Open a PR** with the template (`.github/pull_request_template.md`): what and why, the
   failing test's name, the verification you ran, and `Fixes #N`. Remove your claim label; the
   PR is now the lock. **Never push to `main`. Never change `.github/workflows/` in a fix PR.**
   Never commit a secret, a database file or demo credentials.
9. The owner reviews and merges on GitHub. A release follows (`.github/bears.yml` ›
   `release.on_merge`).

bears follows exactly these steps; its comments carry `<!-- bears:… -->` markers and the PR
label `bears`. Policy for this repo: `.github/bears.yml`.

## Provenance

Generated by an autonomous software build from a short product brief, with automated checks (its tests, a walk of every documented flow, a security review and a readiness review) before release. See `NOTICE`, `LICENSE` and `READINESS.md`.
