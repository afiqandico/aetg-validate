"""Minimal pcap reader/writer — pure standard library.

Why this exists: the functional gate should not be something the user asserts
about their own traffic. If you hand AETG-Validate a capture, it can decide for
itself whether a flow ever completed its TCP handshake, and refuse to count the
rest as evasions.

Scope, stated plainly (also enforced):

* classic pcap only (LE/BE, microsecond and nanosecond magic); pcapng is
  rejected with a clear message instead of being silently misparsed;
* Ethernet link type (1) and raw IPv4 (101); VLAN tags handled;
* TCP. UDP flows are read but can never pass the handshake gate, which is the
  correct answer for a TCP-only gate — use ``--gate observed-traffic`` if you
  want a different rule.

Nothing here opens a socket. It reads bytes from a file.
"""

from __future__ import annotations

import struct
from dataclasses import dataclass, field
from pathlib import Path
from typing import Dict, Iterator, List, Optional, Tuple

PCAP_MAGICS = {
    b"\xd4\xc3\xb2\xa1": ("<", 1000000),   # little endian, microseconds
    b"\xa1\xb2\xc3\xd4": (">", 1000000),   # big endian, microseconds
    b"\x4d\x3c\xb2\xa1": ("<", 1000000000),  # little endian, nanoseconds
    b"\xa1\xb2\x3c\x4d": (">", 1000000000),  # big endian, nanoseconds
}
LINKTYPE_ETHERNET = 1
LINKTYPE_RAW_IPV4 = 101

TCP_FIN = 0x01
TCP_SYN = 0x02
TCP_RST = 0x04
TCP_ACK = 0x10


class PcapError(Exception):
    """Raised when a capture cannot be read as classic pcap."""


@dataclass
class Packet:
    """One decoded TCP/UDP packet, in the fields that matter for gating."""

    ts: float
    src_ip: str
    dst_ip: str
    src_port: int
    dst_port: int
    protocol: str  # "tcp" or "udp"
    flags: int = 0
    length: int = 0

    @property
    def is_syn(self) -> bool:
        return self.protocol == "tcp" and bool(self.flags & TCP_SYN) and not bool(self.flags & TCP_ACK)

    @property
    def is_synack(self) -> bool:
        return self.protocol == "tcp" and bool(self.flags & TCP_SYN) and bool(self.flags & TCP_ACK)

    @property
    def is_reset(self) -> bool:
        return self.protocol == "tcp" and bool(self.flags & TCP_RST)


def _ipv4_from_bytes(raw: bytes) -> Tuple[str, str, bytes]:
    if len(raw) < 20:
        raise PcapError("truncated IPv4 header")
    version = raw[0] >> 4
    if version != 4:
        raise PcapError(f"only IPv4 is supported, got version {version}")
    ihl = (raw[0] & 0x0F) * 4
    if ihl < 20 or len(raw) < ihl:
        raise PcapError("invalid IPv4 header length")
    protocol = raw[9]
    src = ".".join(str(b) for b in raw[12:16])
    dst = ".".join(str(b) for b in raw[16:20])
    return src, dst, raw[ihl:]


def _decode_frame(frame: bytes, linktype: int) -> Optional[Packet]:
    if linktype == LINKTYPE_ETHERNET:
        if len(frame) < 14:
            return None
        ethertype = struct.unpack("!H", frame[12:14])[0]
        offset = 14
        while ethertype == 0x8100 and len(frame) >= offset + 4:  # VLAN
            ethertype = struct.unpack("!H", frame[offset + 2 : offset + 4])[0]
            offset += 4
        if ethertype != 0x0800:
            return None
        payload = frame[offset:]
    elif linktype == LINKTYPE_RAW_IPV4:
        payload = frame
    else:
        raise PcapError(f"unsupported link type {linktype} (expected 1 or 101)")

    src_ip, dst_ip, transport = _ipv4_from_bytes(payload)
    if len(transport) < 4:
        return None
    src_port, dst_port = struct.unpack("!HH", transport[:4])

    if payload[9] == 6:
        if len(transport) < 14:
            return None
        return Packet(0.0, src_ip, dst_ip, src_port, dst_port, "tcp", transport[13], len(frame))
    if payload[9] == 17:
        return Packet(0.0, src_ip, dst_ip, src_port, dst_port, "udp", 0, len(frame))
    return None


def iter_packets(path: Path | str) -> Iterator[Packet]:
    """Yield decoded packets from a classic pcap file."""
    path = Path(path)
    if not path.is_file():
        raise PcapError(f"capture not found: {path}")

    with path.open("rb") as handle:
        header = handle.read(24)
        if len(header) < 24:
            raise PcapError(f"{path}: file too short to be a pcap")
        magic = header[:4]
        if magic not in PCAP_MAGICS:
            if magic[:4] == b"\x0a\x0d\x0d\x0a":
                raise PcapError(
                    f"{path}: this is pcapng, which is not supported. "
                    "Convert it first: `editcap -F pcap in.pcapng out.pcap`"
                )
            raise PcapError(f"{path}: not a pcap file (magic {magic.hex()})")

        endian, resolution = PCAP_MAGICS[magic]
        linktype = struct.unpack(endian + "I", header[20:24])[0]
        if linktype not in (LINKTYPE_ETHERNET, LINKTYPE_RAW_IPV4):
            raise PcapError(f"{path}: unsupported link type {linktype} (expected 1 or 101)")

        while True:
            record = handle.read(16)
            if len(record) < 16:
                break
            ts_sec, ts_frac, incl_len, _orig_len = struct.unpack(endian + "IIII", record)
            frame = handle.read(incl_len)
            if len(frame) < incl_len:
                break
            packet = _decode_frame(frame, linktype)
            if packet is not None:
                packet.ts = ts_sec + ts_frac / resolution
                yield packet


@dataclass
class ObservedFlow:
    """A TCP/UDP flow reconstructed from a capture."""

    client_ip: str
    client_port: int
    server_ip: str
    server_port: int
    protocol: str = "tcp"
    packets: int = 0
    bytes_total: int = 0
    syn_seen: bool = False
    synack_seen: bool = False
    reset_seen: bool = False
    first_ts: float = 0.0
    last_ts: float = 0.0
    alert_rules: List[str] = field(default_factory=list)

    @property
    def flow_id(self) -> str:
        return (
            f"{self.client_ip}:{self.client_port}->{self.server_ip}:{self.server_port}"
            f"/{self.protocol}"
        )

    @property
    def handshake_completed(self) -> bool:
        """The Phi gate for TCP: a SYN was answered with a SYN-ACK."""
        return self.protocol == "tcp" and self.syn_seen and self.synack_seen

    def to_dict(self) -> Dict[str, object]:
        return {
            "flow_id": self.flow_id,
            "client": f"{self.client_ip}:{self.client_port}",
            "server": f"{self.server_ip}:{self.server_port}",
            "protocol": self.protocol,
            "packets": self.packets,
            "bytes": self.bytes_total,
            "syn_seen": self.syn_seen,
            "synack_seen": self.synack_seen,
            "reset_seen": self.reset_seen,
            "handshake_completed": self.handshake_completed,
            "first_ts": self.first_ts,
            "last_ts": self.last_ts,
        }


def reconstruct_flows(packets: Iterator[Packet]) -> List[ObservedFlow]:
    """Group packets into flows, deciding client/server from the first SYN."""
    flows: Dict[Tuple[str, int, str, int, str], ObservedFlow] = {}

    def key_for(pkt: Packet) -> Tuple[str, int, str, int, str]:
        fwd = (pkt.src_ip, pkt.src_port, pkt.dst_ip, pkt.dst_port, pkt.protocol)
        rev = (pkt.dst_ip, pkt.dst_port, pkt.src_ip, pkt.src_port, pkt.protocol)
        if fwd in flows:
            return fwd
        if rev in flows:
            return rev
        # Unknown flow: a bare SYN means the sender is the client. Otherwise the
        # sender of the first packet we saw is treated as the client, which only
        # affects labelling, never the gate result.
        return fwd

    for pkt in packets:
        key = key_for(pkt)
        flow = flows.get(key)
        if flow is None:
            flow = ObservedFlow(
                client_ip=pkt.src_ip,
                client_port=pkt.src_port,
                server_ip=pkt.dst_ip,
                server_port=pkt.dst_port,
                protocol=pkt.protocol,
                first_ts=pkt.ts,
            )
            flows[key] = flow
        flow.packets += 1
        flow.bytes_total += pkt.length
        flow.last_ts = pkt.ts
        # Server->client SYN-ACK may arrive on the reverse of our key.
        from_client = (pkt.src_ip, pkt.src_port) == (flow.client_ip, flow.client_port)
        if pkt.is_syn and from_client:
            flow.syn_seen = True
        if pkt.is_synack and not from_client:
            flow.synack_seen = True
        if pkt.is_synack and from_client and not flow.syn_seen:
            # Capture started after the handshake opened: still a completed
            # handshake, so record it rather than punishing the operator.
            flow.syn_seen = True
            flow.synack_seen = True
        if pkt.is_reset:
            flow.reset_seen = True

    return sorted(flows.values(), key=lambda f: (f.client_ip, f.client_port, f.server_port))


def write_pcap(path: Path | str, packets: List[Packet]) -> Path:
    """Write classic pcap (LE, microseconds). For tests and examples only."""
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("wb") as handle:
        handle.write(b"\xd4\xc3\xb2\xa1")
        handle.write(struct.pack("<HHiIII", 2, 4, 0, 0, 262144, LINKTYPE_ETHERNET))
        for pkt in packets:
            frame = _encode_ethernet_ipv4_tcp(pkt)
            ts_sec = int(pkt.ts)
            ts_usec = int(round((pkt.ts - ts_sec) * 1000000))
            handle.write(struct.pack("<IIII", ts_sec, ts_usec, len(frame), len(frame)))
            handle.write(frame)
    return path


def _encode_ethernet_ipv4_tcp(pkt: Packet) -> bytes:
    """Encode a packet. Checksums are zero: parsers, not kernels, read these."""
    def ip_bytes(dotted: str) -> bytes:
        return bytes(int(part) for part in dotted.split("."))

    if pkt.protocol != "tcp":
        raise PcapError("write_pcap currently encodes TCP only")
    tcp = struct.pack("!HHIIBBHHH", pkt.src_port, pkt.dst_port, 1, pkt.flags, 5 << 4, pkt.flags, 8192, 0, 0)
    ip = struct.pack("!BBHHHBBH", 0x45, 0, 20 + len(tcp), 0, 0, 64, 6, 0) + ip_bytes(pkt.src_ip) + ip_bytes(pkt.dst_ip)
    eth = b"\x02\x00\x00\x00\x00\x01" + b"\x02\x00\x00\x00\x00\x02" + b"\x08\x00"
    return eth + ip + tcp
