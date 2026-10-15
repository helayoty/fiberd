"""A caller of one handoff fiber written with fiberd.client, driven by the Go harness (handoff_linux_test.go).

What a Clone would have returned comes as JSON on stdin, with the caller's
certificate files, and the one line printed says what dial_handoff did:
the fiber's reply to "ping", or the name of the exception it raised.
"""

import base64
import json
import sys

from fiberd.client import Fence, Fiber, Kind


def main():
    cfg = json.load(sys.stdin)
    f = Fiber(id="g/1/1", endpoint=cfg["endpoint"], fence=Fence("g", 1, 1), kind=Kind.CREATE, session="", home="",
              routing_key=cfg["routing_key"], server_key_sha256=cfg["server_key_sha256"],
              server_cert=base64.b64decode(cfg["server_cert"]))
    try:
        with f.dial_handoff(cfg["cert"], cfg["key"], timeout=10) as s:
            s.sendall(b"ping\n")
            print(json.dumps({"reply": s.recv(64).decode().strip()}), flush=True)
    except Exception as e:  # noqa: BLE001 - the harness wants the type, whatever it is
        print(json.dumps({"error": type(e).__name__}), flush=True)


if __name__ == "__main__":
    main()
