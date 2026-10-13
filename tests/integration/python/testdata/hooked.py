"""The reference workload plus an incarnation hook, whose record a fiber serves as "incarnations"."""
import fiberd.template as ft
from fiberd.template import ref

ft.init()
seen = []
ft.on_incarnation(lambda inc: seen.append(f"{inc.kind}:{inc.generation}:{inc.fence}"))
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
                reply = " ".join(seen) if line == "incarnations" else ref.answer(st, line)
                conn.sendall(reply.encode() + b"\n")

    f.serve(handle)
    return 0


ft.serve(on_fiber)
