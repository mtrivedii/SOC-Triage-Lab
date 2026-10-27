"""Test-wide guard: no outbound network. Any socket connection or DNS lookup to a non-local host
raises NetworkBlocked, so a test that would call a real model API fails loudly (locally and in
CI) instead of using the network. Localhost and Unix sockets stay allowed. Standard library only.
"""

import socket

import pytest

_LOCAL_HOSTS = {"localhost", "127.0.0.1", "::1", "0.0.0.0", ""}


class NetworkBlocked(RuntimeError):
    """Raised when a test tries to reach a non-local host."""


def _is_local(host) -> bool:
    host = host.decode() if isinstance(host, bytes) else str(host)
    return host in _LOCAL_HOSTS or host.startswith("127.")


@pytest.fixture(autouse=True)
def _block_network(monkeypatch):
    real_connect = socket.socket.connect
    real_connect_ex = socket.socket.connect_ex
    real_getaddrinfo = socket.getaddrinfo

    def _check(sock, address):
        if getattr(socket, "AF_UNIX", None) is not None and sock.family == socket.AF_UNIX:
            return
        host = address[0] if isinstance(address, tuple) else address
        if not _is_local(host):
            raise NetworkBlocked(f"test tried to open a network connection to {address!r}")

    def guarded_connect(self, address):
        _check(self, address)
        return real_connect(self, address)

    def guarded_connect_ex(self, address):
        _check(self, address)
        return real_connect_ex(self, address)

    def guarded_getaddrinfo(host, *args, **kwargs):
        if host is not None and not _is_local(host):
            raise NetworkBlocked(f"test tried to resolve {host!r}")
        return real_getaddrinfo(host, *args, **kwargs)

    monkeypatch.setattr(socket.socket, "connect", guarded_connect)
    monkeypatch.setattr(socket.socket, "connect_ex", guarded_connect_ex)
    monkeypatch.setattr(socket, "getaddrinfo", guarded_getaddrinfo)
