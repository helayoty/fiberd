"""The reference workload plus an incarnation hook, whose record a fiber serves as "incarnations" and whose seeds it serves as "seeds"."""
import fiberd.template as ft
from fiberd.template import ref

ft.init()
seen = []
seeds = []


@ft.on_incarnation
def record(inc):
    seen.append(f"{inc.kind}:{inc.generation}:{inc.fence}")
    seeds.append(bytes(inc.seed).hex())


warm = ref.Warm(1)


def on_fiber(f):
    st = ref.State(warm, f)

    def handle(conn):
        buf = b""
        while True:
            chunk = conn.recv(512)
            if not chunk:
                return
            buf += chunk
            while b"\n" in buf:
                line, buf = buf.split(b"\n", 1)
                line = line.decode()
                if line == "incarnations":
                    reply = " ".join(seen)
                elif line == "seeds":
                    reply = " ".join(seeds)
                else:
                    reply = ref.answer(st, line)
                conn.sendall(reply.encode() + b"\n")

    f.serve(handle)
    return 0


ft.serve(on_fiber)
