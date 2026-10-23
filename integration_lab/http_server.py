"""Small loopback HTTP/HTTPS fixture server with deterministic event gates."""

import asyncio
from dataclasses import dataclass
from http import HTTPStatus
from importlib.resources import as_file, files
import ssl

from integration_lab.dns_server import DNSServer
from integration_lab.scenarios import BY_HOST, load_responses


class ResponseGate:
    """Hold a first wave until all workers arrive; no timing-based sleeps."""

    def __init__(self, hosts: tuple[str, ...], *, hold: bool = False) -> None:
        self.hosts = hosts
        self.hold = hold
        self.arrived: set[str] = set()
        self.ready = asyncio.Event()
        self.release = asyncio.Event()
        self.sent = {host: asyncio.Event() for host in hosts}

    async def wait(self, hostname: str) -> None:
        if hostname not in self.sent:
            return
        self.arrived.add(hostname)
        if len(self.arrived) == len(self.hosts):
            self.ready.set()
            if not self.hold:
                self.release.set()
        await self.release.wait()
        # The first input's response is sent after its peers, proving that input
        # order is independent of server response order.
        if hostname == self.hosts[0]:
            for host in self.hosts[1:]:
                await self.sent[host].wait()

    def mark_sent(self, hostname: str) -> None:
        if hostname in self.sent:
            self.sent[hostname].set()


@dataclass(frozen=True)
class HTTPRequest:
    hostname: str
    method: str
    path: str
    tls: bool
    user_agent: str


class HTTPServer:
    def __init__(self, dns_server: DNSServer, gate: ResponseGate) -> None:
        self.dns = dns_server
        self.gate = gate
        self.responses = load_responses()
        self.servers: list[asyncio.Server] = []
        self.endpoints: dict[str, tuple[str, int]] = {}
        self.requests: list[HTTPRequest] = []
        self.response_order: list[str] = []
        self.errors: list[str] = []
        self.tasks: set[asyncio.Task] = set()
        self.writers: set[asyncio.StreamWriter] = set()
        self.active_requests = 0
        self.peak_requests = 0
        self.closed = False

    async def __aenter__(self) -> "HTTPServer":
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        fixtures = files("integration_lab").joinpath("fixtures")
        with as_file(fixtures.joinpath("server-cert.pem")) as cert, as_file(fixtures.joinpath("server-key.pem")) as key:
            context.load_cert_chain(cert, key)
        try:
            for scheme, tls in (("http", None), ("https", context)):
                server = await asyncio.start_server(
                    self._handle, "127.0.0.1", 0, ssl=tls, limit=8192,
                    **({"ssl_handshake_timeout": 3.0, "ssl_shutdown_timeout": 1.0} if tls else {}),
                )
                self.servers.append(server)
                address = server.sockets[0].getsockname()[:2]
                if address[1] < 1024:
                    raise RuntimeError("HTTP ephemeral port was not unprivileged")
                self.endpoints[scheme] = address
        except BaseException:
            await self.__aexit__(None, None, None)
            raise
        return self

    async def __aexit__(self, *args: object) -> None:
        for server in self.servers:
            server.close()
        for writer in tuple(self.writers):
            writer.close()
        for task in tuple(self.tasks):
            task.cancel()
        if self.tasks:
            outcomes = await asyncio.gather(*tuple(self.tasks), return_exceptions=True)
            for outcome in outcomes:
                if isinstance(outcome, Exception):
                    self.errors.append(f"HTTP cleanup: {type(outcome).__name__}: {outcome}")
        for server in self.servers:
            await server.wait_closed()
        self.closed = True

    async def _handle(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        task = asyncio.current_task()
        self.tasks.add(task)
        self.writers.add(writer)
        counted = False
        try:
            async with asyncio.timeout(5.0):
                raw = await reader.readuntil(b"\r\n\r\n")
                lines = raw.decode("ascii").split("\r\n")
                method, path, version = lines[0].split(" ")
                headers: dict[str, str] = {}
                for line in lines[1:]:
                    if not line:
                        continue
                    name, value = line.split(":", 1)
                    name = name.lower()
                    if name in headers:
                        raise ValueError("duplicate request header")
                    headers[name] = value.strip()
                hostname = headers.get("host", "")
                scenario = BY_HOST.get(hostname)
                if (method != "GET" or version != "HTTP/1.1" or path not in ("/", "/after-redirect")
                        or scenario is None or scenario.fixture is None):
                    raise ValueError("request outside fixture routes")
                self.requests.append(HTTPRequest(hostname, method, path,
                                                 writer.get_extra_info("ssl_object") is not None,
                                                 headers.get("user-agent", "")))
                self.active_requests += 1
                self.peak_requests = max(self.peak_requests, self.active_requests)
                counted = True
                await self.gate.wait(hostname)
                fixture = self.responses[scenario.fixture]
                if scenario.id == "dns-rebinding":
                    self.dns.rebound = True
                body = fixture["body"].encode("utf-8") + b"x" * fixture.get("padding_bytes", 0)
                length = len(body) + fixture.get("missing_bytes", 0)
                status = fixture["status"]
                response_headers = {**fixture["headers"], "Content-Type": "text/plain; charset=utf-8",
                                    "Content-Length": str(length), "Connection": "close"}
                head = f"HTTP/1.1 {status} {HTTPStatus(status).phrase}\r\n"
                head += "".join(f"{key}: {value}\r\n" for key, value in response_headers.items())
                writer.write(head.encode("ascii") + b"\r\n" + body)
                await writer.drain()
                self.response_order.append(hostname)
                self.gate.mark_sent(hostname)
        except (asyncio.IncompleteReadError, ConnectionResetError, BrokenPipeError):
            # Expected when a client stops at the body cap or is cancelled.
            pass
        except asyncio.CancelledError:
            raise
        except Exception as exc:
            self.errors.append(f"HTTP handler: {type(exc).__name__}: {exc}")
        finally:
            if counted:
                self.active_requests -= 1
            writer.close()
            try:
                await writer.wait_closed()
            except (ConnectionResetError, BrokenPipeError, ssl.SSLError):
                pass
            finally:
                self.writers.discard(writer)
                self.tasks.discard(task)
