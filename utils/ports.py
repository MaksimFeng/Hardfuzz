# util/ports.py
from __future__ import annotations
import contextlib, socket


def get_free_tcp_port() -> int:
    """
    Let the kernel choose an unused TCP port and return it.

    Works on every OS that supports AF_INET sockets.
    """
    with contextlib.closing(socket.socket()) as s:
        s.bind(("", 0))
        return s.getsockname()[1]
