"""The conftest network guard: outbound blocked, localhost allowed."""

import socket
import threading

import openai
import pytest
from conftest import NetworkBlocked


def test_outbound_connection_blocked():
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s, pytest.raises(NetworkBlocked):
        s.connect(("203.0.113.1", 443))  # TEST-NET-3, never routable


def test_dns_lookup_blocked():
    with pytest.raises(NetworkBlocked):
        socket.getaddrinfo("api.groq.com", 443)


def test_real_api_client_call_fails_loudly():
    client = openai.OpenAI(api_key="test-key", base_url="https://api.groq.com/openai/v1",
                           max_retries=0)
    with pytest.raises(NetworkBlocked):  # not swallowed into a retry/connection error
        client.models.list()


def test_localhost_allowed():
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as srv:
        srv.bind(("127.0.0.1", 0))
        srv.listen(1)
        port = srv.getsockname()[1]
        t = threading.Thread(target=lambda: srv.accept()[0].close())
        t.start()
        with socket.create_connection(("127.0.0.1", port), timeout=5):
            pass
        t.join(timeout=5)
