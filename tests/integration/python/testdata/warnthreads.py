"""A template with a sleeping thread that serves under threads="warn", the escape hatch."""
import threading
import time

import fiberd.template as ft
from fiberd.template import ref

ft.init()
threading.Thread(target=lambda: time.sleep(3600), daemon=True).start()
warm = ref.Warm(1)
ft.serve(lambda f: ref.on_fiber(warm, f), threads="warn")
