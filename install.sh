#!/bin/sh
# Install Sidedoor and put `sidedoor` on PATH (Linux and macOS). Needs Python >= 3.11.
set -eu
here=$(cd "$(dirname "$0")" && pwd)
py=${PYTHON:-python3}
"$py" -c 'import sys; sys.exit(0 if sys.version_info >= (3, 11) else 1)' || { echo "sidedoor: Python 3.11 or newer is required (set PYTHON=/path/to/python)" >&2; exit 1; }
if command -v pipx >/dev/null 2>&1; then
  pipx install --force "$here"
elif command -v uv >/dev/null 2>&1; then
  uv tool install --force "$here"
else
  venv=${SIDEDOOR_VENV:-$HOME/.local/share/sidedoor-venv}
  bindir=${SIDEDOOR_BIN:-$HOME/.local/bin}
  mkdir -p "$bindir"
  rm -rf "$venv"
  if "$py" -m venv "$venv" >/dev/null 2>&1 && "$venv/bin/pip" install --quiet --upgrade "$here" >/dev/null 2>&1; then
    ln -sf "$venv/bin/sidedoor" "$bindir/sidedoor"
  else
    # No venv/pip available: sidedoor has no dependencies, so copy it and add a launcher.
    rm -rf "$venv"
    lib=${SIDEDOOR_LIB:-$HOME/.local/share/sidedoor-lib}
    rm -rf "$lib"
    mkdir -p "$lib"
    cp -R "$here/sidedoor" "$lib/sidedoor"
    find "$lib" -name __pycache__ -type d -prune -exec rm -rf {} +
    pyabs=$(command -v "$py")
    rm -f "$bindir/sidedoor"
    printf '#!/bin/sh\nPYTHONPATH=%s${PYTHONPATH:+:$PYTHONPATH} exec %s -m sidedoor "$@"\n' "$lib" "$pyabs" > "$bindir/sidedoor"
    chmod 755 "$bindir/sidedoor"
  fi
  case ":$PATH:" in *":$bindir:"*) ;; *) echo "Add $bindir to your PATH, e.g.: export PATH=\"$bindir:\$PATH\"" ;; esac
fi
echo "Installed. Next: sidedoor init && sidedoor doctor"
