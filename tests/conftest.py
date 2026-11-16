"""Shared test setup.

Every test runs with the network switched off, so a test can never reach the
internet by accident (and never becomes slow or flaky because of it). Tests
that genuinely need the network must be marked `@pytest.mark.live`; those are
skipped by default and run with `pytest -m live`.
"""

import socket

import pytest


@pytest.fixture(autouse=True)
def block_network(request, monkeypatch):
    if request.node.get_closest_marker("live"):
        return

    def blocked(*args, **kwargs):
        raise RuntimeError(
            "Network access is blocked in tests. Use a fake opener, "
            "or mark the test with @pytest.mark.live."
        )

    monkeypatch.setattr(socket.socket, "connect", blocked)
    monkeypatch.setattr(socket.socket, "connect_ex", blocked)
    monkeypatch.setattr(socket, "create_connection", blocked)
    monkeypatch.setattr(socket, "getaddrinfo", blocked)


@pytest.fixture(autouse=True)
def no_exploit_lookups(request, monkeypatch):
    """The command line never fetches EPSS or KEV data in tests.

    Tests that want exploitation evidence replace `cli.gather_exploit_data`
    themselves; tests of the client call it directly with a fake opener.
    """
    if request.node.get_closest_marker("live"):
        return
    from valtrix import cli
    from valtrix.databases import ExploitData

    monkeypatch.setattr(cli, "gather_exploit_data", lambda cves: ExploitData())
