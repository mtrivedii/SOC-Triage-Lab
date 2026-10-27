"""Test-wide guard: no outbound network (see triage.netguard). A test that would call a real
model API fails loudly, locally and in CI. Localhost and Unix sockets stay allowed.
"""

import pytest

from triage import netguard


@pytest.fixture(autouse=True)
def _block_network(monkeypatch):
    for (owner, name), fn in netguard.guards().items():
        monkeypatch.setattr(owner, name, fn)
