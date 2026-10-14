"""The reference workload under an async on_fiber, on a unix endpoint or as a handoff fiber.

The payload {"mode": "connections"} serves a handoff fiber from
connections() instead of serve_async, so both twins are driven.
"""
import fiberd.template as ft
from fiberd.template import ref

ft.init()
warm = ref.Warm(1)


async def on_fiber(f):
    st = ref.State(warm, f)

    async def handle(reader, writer):
        while True:
            line = await reader.readline()
            if not line:
                return
            writer.write((ref.answer(st, line.decode().rstrip("\r\n")) + "\n").encode())
            await writer.drain()

    if ref.payload_dict(f.payload).get("mode") == "connections":
        f.ready()
        async for reader, writer in f.connections():
            await handle(reader, writer)
            writer.close()
        return 0
    await f.serve_async(handle)
    return 0


ft.serve(on_fiber)
