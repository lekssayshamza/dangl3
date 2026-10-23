"""Authoritative fixture DNS over real loopback UDP; no forwarding code."""

import asyncio
from dataclasses import dataclass

import dns.exception
import dns.flags
import dns.message
import dns.opcode
import dns.rcode
import dns.rdataclass
import dns.rdatatype
import dns.rrset

from integration_lab.scenarios import BY_HOST, LOOP_PEER, SCENARIOS


@dataclass(frozen=True)
class DNSQuery:
    name: str
    record_type: str
    rcode: str
    addresses: tuple[str, ...] = ()


class _Protocol(asyncio.DatagramProtocol):
    def __init__(self, owner: "DNSServer") -> None:
        self.owner = owner

    def datagram_received(self, data: bytes, address: tuple) -> None:
        if address[0] != "127.0.0.1":
            return
        try:
            query = dns.message.from_wire(data)
            response = self.owner.answer(query)
        except dns.exception.DNSException:
            if len(data) < 2:
                return
            response = dns.message.Message(id=int.from_bytes(data[:2], "big"))
            response.flags = dns.flags.QR
            response.set_rcode(dns.rcode.FORMERR)
        self.owner.transport.sendto(response.to_wire(), address)

    def error_received(self, exc: Exception) -> None:
        self.owner.errors.append(f"DNS transport: {exc}")

    def connection_lost(self, exc: Exception | None) -> None:
        if exc:
            self.owner.errors.append(f"DNS shutdown: {exc}")
        self.owner.closed.set()


class DNSServer:
    def __init__(self) -> None:
        self.transport: asyncio.DatagramTransport | None = None
        self.address: tuple[str, int] | None = None
        self.queries: list[DNSQuery] = []
        self.errors: list[str] = []
        self.closed = asyncio.Event()
        self.rebound = False
        self.aliases = {s.hostname: s.target for s in SCENARIOS if s.target}
        self.aliases[LOOP_PEER] = BY_HOST["cname-loop.dangl3.test"].hostname
        self.terminals = {s.target for s in SCENARIOS if s.fixture}

    async def __aenter__(self) -> "DNSServer":
        loop = asyncio.get_running_loop()
        transport, _ = await loop.create_datagram_endpoint(lambda: _Protocol(self), local_addr=("127.0.0.1", 0))
        self.transport = transport
        self.address = transport.get_extra_info("sockname")[:2]
        if self.address[1] < 1024:
            await self.__aexit__(None, None, None)
            raise RuntimeError("DNS ephemeral port was not unprivileged")
        return self

    async def __aexit__(self, *args: object) -> None:
        if self.transport is not None:
            self.transport.close()
            await self.closed.wait()

    def answer(self, query: dns.message.Message) -> dns.message.Message:
        response = dns.message.make_response(query)
        response.flags |= dns.flags.AA
        response.flags &= ~dns.flags.RA
        if len(query.question) != 1 or query.opcode() != dns.opcode.QUERY:
            response.set_rcode(dns.rcode.FORMERR)
            return response
        question = query.question[0]
        name = question.name.to_text().rstrip(".").lower()
        kind = question.rdtype
        addresses: tuple[str, ...] = ()
        if question.rdclass != dns.rdataclass.IN:
            response.set_rcode(dns.rcode.REFUSED)
        elif name not in self.aliases and name not in self.terminals:
            response.set_rcode(dns.rcode.NXDOMAIN)
        elif kind == dns.rdatatype.CNAME and name in self.aliases:
            response.answer.append(dns.rrset.from_text(name + ".", 0, "IN", "CNAME", self.aliases[name] + "."))
        elif kind == dns.rdatatype.A and name in self.terminals:
            address = ("169.254.169.254" if self.rebound and name == BY_HOST["dns-rebinding.dangl3.test"].target
                       else "127.0.0.1")
            addresses = (address,)
            response.answer.append(dns.rrset.from_text(name + ".", 0, "IN", "A", address))
        elif kind == dns.rdatatype.A and name in self.aliases and self.aliases[name] in self.terminals:
            target = self.aliases[name]
            response.answer.append(dns.rrset.from_text(name + ".", 0, "IN", "CNAME", target + "."))
            address = "169.254.169.254" if self.rebound and name == "dns-rebinding.dangl3.test" else "127.0.0.1"
            addresses = (address,)
            response.answer.append(dns.rrset.from_text(target + ".", 0, "IN", "A", address))
        # Known names: AAAA and unsupported types have deterministic NODATA.
        self.queries.append(DNSQuery(name, dns.rdatatype.to_text(kind), dns.rcode.to_text(response.rcode()), addresses))
        return response
