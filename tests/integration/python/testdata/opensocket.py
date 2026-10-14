"""A template that holds a socket at serve(), which serve() refuses."""
import socket

import fiberd.template as ft

ft.init()
keep = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
ft.serve(lambda f: 0)
