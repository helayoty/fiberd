# A template with state. Each fiber counts the connections it answers.
# The count lives in the fiber's memory, so a park and resume keeps it.
#
#   bin/fiberd run -park examples/hello/counter.py
import fiberd.template as ft

ft.init()  # first, before any thread

count = 0  # each fiber is a fork of this process, so each has its own


def on_fiber(f: ft.Fiber) -> int:
    def answer(conn):
        global count
        count += 1
        conn.sendall(f"count {count}\n".encode())

    # serve notices a park between connections, at least every poll
    # seconds, so a short poll keeps the park from waiting on it.
    f.serve(answer, poll=0.05)
    return 0


ft.serve(on_fiber)
