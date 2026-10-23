"""Real sockets are allowed only to this test's registered lab endpoints."""

import socket

import pytest


class SocketGuard:
    def __init__(self) -> None:
        self.dns: tuple[str, int] | None = None
        self.tcp: set[tuple[str, int]] = set()
        self.dns_clients: set[tuple[str, int]] = set()

    def allow(self, lab) -> None:
        self.dns = lab.dns.address
        self.tcp = set(lab.http.endpoints.values())

    def destination(self, sock: socket.socket, address: tuple) -> None:
        target = address[:2]
        allowed = self.tcp if sock.type == socket.SOCK_STREAM else {self.dns}
        if sock.family != socket.AF_INET or target not in allowed:
            raise AssertionError(f"Integration egress forbidden: {target}")

    def register_dns_client(self, sock: socket.socket) -> None:
        if sock.type == socket.SOCK_DGRAM:
            port = sock.getsockname()[1]
            if port:
                self.dns_clients.add(("127.0.0.1", port))


@pytest.fixture(autouse=True)
def block_network(monkeypatch):
    # Deliberately override the unit-test blanket ban only in this directory.
    # The replacement still rejects public/private/other-loopback destinations.
    guard = SocketGuard()
    connect = socket.socket.connect
    connect_ex = socket.socket.connect_ex
    sendto = socket.socket.sendto
    getaddrinfo = socket.getaddrinfo

    def checked_connect(sock, address):
        guard.destination(sock, address)
        try:
            return connect(sock, address)
        finally:
            guard.register_dns_client(sock)

    def checked_connect_ex(sock, address):
        guard.destination(sock, address)
        value = connect_ex(sock, address)
        guard.register_dns_client(sock)
        return value

    def checked_sendto(sock, data, *args):
        address = args[-1]
        if address[:2] != guard.dns:
            if sock.getsockname()[:2] != guard.dns or address[:2] not in guard.dns_clients:
                raise AssertionError(f"Integration UDP egress forbidden: {address}")
        result = sendto(sock, data, *args)
        if address[:2] == guard.dns:
            guard.register_dns_client(sock)
        return result

    def checked_getaddrinfo(host, port, *args, **kwargs):
        name = host.decode("ascii") if isinstance(host, bytes) else host
        if name != "127.0.0.1" or (port != 0 and (name, port) not in guard.tcp | {guard.dns}):
            raise AssertionError(f"Integration system DNS forbidden: {host}:{port}")
        return getaddrinfo(host, port, *args, **kwargs)

    monkeypatch.setattr(socket.socket, "connect", checked_connect)
    monkeypatch.setattr(socket.socket, "connect_ex", checked_connect_ex)
    monkeypatch.setattr(socket.socket, "sendto", checked_sendto)
    monkeypatch.setattr(socket, "getaddrinfo", checked_getaddrinfo)
    return guard
