"""Checks that the safety nets themselves work."""

import socket
import urllib.request

import pytest


def test_sockets_are_blocked():
    with pytest.raises(RuntimeError, match="Network access is blocked"):
        socket.create_connection(("example.com", 80))


def test_urllib_cannot_reach_the_internet():
    with pytest.raises(RuntimeError, match="Network access is blocked"):
        urllib.request.urlopen("https://api.osv.dev/v1/query", timeout=1)
