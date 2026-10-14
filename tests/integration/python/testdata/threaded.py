"""A template that starts a thread after init() and before serve(), which serve() refuses."""
import threading
import time

import fiberd.template as ft

ft.init()
threading.Thread(target=lambda: time.sleep(3600), daemon=True).start()
ft.serve(lambda f: 0)
