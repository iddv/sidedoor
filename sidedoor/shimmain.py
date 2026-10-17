"""Standalone secret-store shim client: `shimmain.py <door> <broker-url> args...` (stdlib only)."""
import json
import sys
import urllib.request


def main():
    door, url, args = sys.argv[1], sys.argv[2], sys.argv[3:]
    req = urllib.request.Request(f"{url}/_shim/{door}", data=json.dumps({"args": args}).encode(), method="POST")
    try:
        with urllib.request.urlopen(req, timeout=10) as r:
            sys.stdout.write(r.read().decode())
            return int(r.headers.get("X-Exit-Code", "0"))
    except Exception as e:
        sys.stderr.write(f"{door}: unavailable ({e})\n")
        return 1


sys.exit(main())
