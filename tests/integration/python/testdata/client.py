"""A caller written with fiberd.client, driven by the Go harness (client_linux_test.go).

The home's address, the grant token and the certificate files come as
JSON on stdin, never on the command line, and each step goes out as one
JSON line on stdout. The scenario is the one argument.
"""

import json
import sys

from fiberd.client import Client, Deferred, NotFound, Shed, TierGap

DEADLINE = 20


def out(**kw):
    print(json.dumps(kw), flush=True)


def talk(f, line):
    with f.dial(timeout=5) as s:
        s.sendall(line.encode() + b"\n")
        return s.recv(4096).decode().rstrip("\n")


def clone(c, cfg, session):
    f = c.clone(cfg["grant"], session, deadline=DEADLINE, timeout=60)
    out(step="clone", id=f.id, kind=f.kind.name, seq=f.fence.seq, session=f.session, home=f.home)
    return f


def lifecycle(c, cfg):
    f = clone(c, cfg, cfg["session"])
    out(step="ping", reply=talk(f, "ping"))
    c.park(f, sync=True, timeout=60)
    out(step="park")
    f = clone(c, cfg, cfg["session"])
    out(step="ping", reply=talk(f, "ping"))
    c.release(f, discard=True, timeout=60)
    out(step="release")
    try:
        c.release(f, timeout=60)
    except NotFound as e:
        out(step="notfound", reason=e.reason)


def miss(c, cfg):
    f = clone(c, cfg, None)
    try:
        clone(c, cfg, None)
    except Shed as e:
        out(step="miss", type="Shed", retry_after=e.retry_after, issuer=e.issuer, reason=e.reason)
    except Deferred as e:
        out(step="miss", type="Deferred", preferred_home=e.preferred_home, issuer=e.issuer, reason=e.reason)
    except TierGap as e:
        out(step="miss", type="TierGap", reason=e.reason)
    c.release(f, timeout=60)


def tiergap(c, cfg):
    try:
        clone(c, cfg, None)
    except TierGap as e:
        out(step="miss", type="TierGap", reason=e.reason)


def watch(c, cfg):
    f = clone(c, cfg, None)
    for st in c.watch(timeout=30):
        if st.running >= 1:
            out(step="status", grant_uid=st.grant_uid, running=st.running, latest=str(st.latest))
            break
    c.release(f, timeout=60)


SCENARIOS = {"lifecycle": lifecycle, "miss": miss, "tiergap": tiergap, "watch": watch}


def main():
    cfg = json.load(sys.stdin)
    if cfg.get("tls"):
        c = Client.dial_tls(cfg["addr"], cfg["tls"]["cert"], cfg["tls"]["key"], cfg["tls"]["ca"])
    else:
        c = Client.dial(cfg["addr"])
    with c:
        SCENARIOS[sys.argv[1]](c, cfg)


if __name__ == "__main__":
    main()
