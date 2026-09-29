"""Loopback-only network fixture for auth tests (not a test module).

A patch aimed at the wrong binding once let a Codex auth test POST a synthetic refresh token to
the real token endpoint. Patches decide which function runs; this guard decides where bytes can
go: every DNS lookup or connect to a non-loopback host is refused AND recorded, and the test fails
at teardown even when the code under test swallowed the refusal (quota probes and pre-probe
refreshes log and carry on). Loopback stays open for local fake servers.

Use it from a test module with::

    from tests.network_guard import no_external_network  # noqa: F401  (fixture)
    pytestmark = pytest.mark.usefixtures("no_external_network")
"""

from __future__ import annotations

import ipaddress
import socket

import pytest


def _is_loopback(host) -> bool:
    if isinstance(host, bytes):
        host = host.decode("ascii", "replace")
    if not isinstance(host, str):
        return False
    if host.lower() == "localhost":
        return True
    try:
        return ipaddress.ip_address(host.split("%", 1)[0]).is_loopback
    except ValueError:
        return False


@pytest.fixture
def no_external_network(monkeypatch):
    attempts: list = []
    real_connect, real_connect_ex = socket.socket.connect, socket.socket.connect_ex
    real_getaddrinfo = socket.getaddrinfo

    def _refuse(target):
        attempts.append(repr(target))
        return OSError(f"external network disabled in auth tests: {target!r}")

    def _connect(self, address):
        if isinstance(address, tuple) and not _is_loopback(address[0]):
            raise _refuse(address)
        return real_connect(self, address)

    def _connect_ex(self, address):
        if isinstance(address, tuple) and not _is_loopback(address[0]):
            raise _refuse(address)
        return real_connect_ex(self, address)

    def _getaddrinfo(host, *args, **kwargs):
        if host is not None and not _is_loopback(host):
            attempts.append(repr(host))
            raise socket.gaierror(socket.EAI_NONAME, f"external DNS disabled in auth tests: {host!r}")
        return real_getaddrinfo(host, *args, **kwargs)

    monkeypatch.setattr(socket.socket, "connect", _connect)
    monkeypatch.setattr(socket.socket, "connect_ex", _connect_ex)
    monkeypatch.setattr(socket, "getaddrinfo", _getaddrinfo)
    yield attempts
    assert not attempts, f"test tried to reach an external host: {attempts}"
