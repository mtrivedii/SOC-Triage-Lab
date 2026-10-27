"""Block outbound network access (tests and `triage reproduce`). Standard library only.

Any socket connection or DNS lookup to a non-local host raises NetworkBlocked, so code that would
call a real model API fails loudly instead of using the network. Localhost and Unix sockets stay
allowed.
"""

from __future__ import annotations

import socket

_LOCAL_HOSTS = {"localhost", "127.0.0.1", "::1", "0.0.0.0", ""}


class NetworkBlocked(RuntimeError):
    """Raised when code tries to reach a non-local host."""


def _is_local(host) -> bool:
    host = host.decode() if isinstance(host, bytes) else str(host)
    return host in _LOCAL_HOSTS or host.startswith("127.")


def guards() -> dict:
    """Replacement callables, keyed by (owner, attribute name)."""
    real_connect = socket.socket.connect
    real_connect_ex = socket.socket.connect_ex
    real_getaddrinfo = socket.getaddrinfo

    def _check(sock, address):
        if getattr(socket, "AF_UNIX", None) is not None and sock.family == socket.AF_UNIX:
            return
        host = address[0] if isinstance(address, tuple) else address
        if not _is_local(host):
            raise NetworkBlocked(f"blocked network connection to {address!r}")

    def connect(self, address):
        _check(self, address)
        return real_connect(self, address)

    def connect_ex(self, address):
        _check(self, address)
        return real_connect_ex(self, address)

    def getaddrinfo(host, *args, **kwargs):
        if host is not None and not _is_local(host):
            raise NetworkBlocked(f"blocked DNS lookup of {host!r}")
        return real_getaddrinfo(host, *args, **kwargs)

    return {
        (socket.socket, "connect"): connect,
        (socket.socket, "connect_ex"): connect_ex,
        (socket, "getaddrinfo"): getaddrinfo,
    }


def install() -> None:
    """Block the network for the rest of this process."""
    for (owner, name), fn in guards().items():
        setattr(owner, name, fn)
