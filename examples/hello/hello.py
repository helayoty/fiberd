# The smallest fiberd template. It warms once, and every fiber forked
# from it answers each connection with one line.
#
#   bin/fiberd run examples/hello/hello.py
import fiberd.template as ft

ft.init()  # first, before any thread


def on_fiber(f: ft.Fiber) -> int:
    name = f.payload.decode() or "world"
    f.serve(lambda conn: conn.sendall(f"hello, {name}\n".encode()))
    return 0


ft.serve(on_fiber)
