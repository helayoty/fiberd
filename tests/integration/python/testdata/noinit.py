"""A template that skipped init(), which serve() refuses."""
import fiberd.template as ft

ft.serve(lambda f: 0)
