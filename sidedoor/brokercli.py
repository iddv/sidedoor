"""The mock broker CLI: `broker token --scope <scope>` (stdlib only)."""
import json
import sys
import urllib.error
import urllib.request


def main():
    url, args = sys.argv[1], sys.argv[2:]
    if not args or args[0] != "token":
        sys.stderr.write("usage: broker token --scope <scope> [--json]\n")
        return 2
    scope = "default"
    if "--scope" in args and args.index("--scope") + 1 < len(args):
        scope = args[args.index("--scope") + 1]
    req = urllib.request.Request(f"{url}/token", data=json.dumps({"scope": scope}).encode(), method="POST", headers={"Content-Type": "application/json"})
    try:
        with urllib.request.urlopen(req, timeout=10) as r:
            data = json.loads(r.read())
    except urllib.error.HTTPError as e:
        sys.stderr.write(f"broker: {e.code} {'broker unavailable' if e.code == 503 else 'error'}\n")
        return 1
    except Exception as e:
        sys.stderr.write(f"broker: broker unavailable ({e})\n")
        return 1
    print(json.dumps(data) if "--json" in args else data["token"])
    return 0


sys.exit(main())
