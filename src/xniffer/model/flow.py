"""Flows -- bidirectional conversations assembled from individual packets.

A flow is the unit at which most real analysis happens. One packet rarely means
anything; "this host opened 400 connections and 398 of them were refused" means
a great deal. :class:`FlowKey` canonicalises the two endpoints so that both
directions of a conversation land in the same bucket, and :class:`Flow`
accumulates the per-conversation state that detection rules read.

Memory is bounded by construction. A flow never retains packets -- only
counters, a capped list of packet indices for evidence, and a capped ring of
timestamps for timing analysis. A capture running for hours cannot grow a flow
without limit.
"""

from __future__ import annotations

from collections import deque
from dataclasses import dataclass, field
from typing import Any

from xniffer.model._serde import jsonify
from xniffer.model.enums import Direction, TcpState
from xniffer.model.packet import PacketRecord
from xniffer.util.net import describe_port, is_syn_ack, is_syn_only
from xniffer.util.stats import IntervalProfile, profile_intervals, ratio

#: Packet indices retained per flow, for citing as evidence in findings.
MAX_EVIDENCE_INDICES = 64

#: Timestamps retained per flow for interval analysis.
MAX_TIMESTAMPS = 512


@dataclass(frozen=True, slots=True, order=True)
class FlowKey:
    """A canonical, direction-independent identifier for a conversation.

    The two endpoints are stored in a fixed sorted order as ``a`` and ``b``, so
    a packet from A to B and its reply from B to A produce the same key and
    therefore the same :class:`Flow`. :meth:`direction_of` recovers which way
    any individual packet was travelling.
    """

    protocol: str
    ip_a: str
    port_a: int
    ip_b: str
    port_b: int

    @classmethod
    def from_endpoints(
        cls,
        protocol: str,
        src_ip: str,
        src_port: int | None,
        dst_ip: str,
        dst_port: int | None,
    ) -> FlowKey:
        """Build a canonical key from a packet's source and destination.

        Protocols without ports (ICMP, raw IP) use port 0 on both sides, which
        collapses all such traffic between a pair of hosts into one flow -- the
        right granularity for those protocols.
        """
        left = (src_ip, src_port or 0)
        right = (dst_ip, dst_port or 0)
        if left <= right:
            (ip_a, port_a), (ip_b, port_b) = left, right
        else:
            (ip_a, port_a), (ip_b, port_b) = right, left
        return cls(protocol=protocol, ip_a=ip_a, port_a=port_a, ip_b=ip_b, port_b=port_b)

    @classmethod
    def from_record(cls, record: PacketRecord) -> FlowKey | None:
        """Derive a key from a packet record, or ``None`` when it has no IP pair."""
        if not record.has_ip:
            return None
        protocol = record.transport or (f"IPv{record.ip_version}" if record.ip_version else "IP")
        return cls.from_endpoints(
            protocol=protocol,
            src_ip=record.src_ip or "",
            src_port=record.src_port,
            dst_ip=record.dst_ip or "",
            dst_port=record.dst_port,
        )

    def direction_of(self, src_ip: str, src_port: int | None) -> Direction:
        """Which direction a packet from ``src_ip:src_port`` is travelling."""
        if (src_ip, src_port or 0) == (self.ip_a, self.port_a):
            return Direction.A_TO_B
        return Direction.B_TO_A

    @property
    def endpoint_a(self) -> str:
        """Endpoint A as ``ip:port``."""
        return self._format(self.ip_a, self.port_a)

    @property
    def endpoint_b(self) -> str:
        """Endpoint B as ``ip:port``."""
        return self._format(self.ip_b, self.port_b)

    @staticmethod
    def _format(ip: str, port: int) -> str:
        if not port:
            return ip
        return f"[{ip}]:{port}" if ":" in ip else f"{ip}:{port}"

    def __str__(self) -> str:
        return f"{self.protocol} {self.endpoint_a} <-> {self.endpoint_b}"

    def to_dict(self) -> dict[str, Any]:
        """Serialise for JSON output."""
        return jsonify(self)


@dataclass(slots=True)
class Flow:
    """Accumulated state for one conversation.

    Counters are kept per direction so that asymmetry -- the signature of both
    data exfiltration and scanning -- is directly measurable rather than
    inferred.
    """

    key: FlowKey
    first_seen: float
    last_seen: float

    packets_a_to_b: int = 0
    packets_b_to_a: int = 0
    bytes_a_to_b: int = 0
    bytes_b_to_a: int = 0
    payload_bytes_a_to_b: int = 0
    payload_bytes_b_to_a: int = 0

    first_packet_index: int = 0
    last_packet_index: int = 0

    syn_count: int = 0
    syn_ack_count: int = 0
    fin_count: int = 0
    rst_count: int = 0
    state: TcpState = TcpState.UNKNOWN

    app_protocols: set[str] = field(default_factory=set)
    server_name: str | None = None
    """Hostname the client asked for -- TLS SNI or HTTP ``Host``."""

    dns_names: set[str] = field(default_factory=set)
    """DNS names that resolved to one of this flow's endpoints, when known."""

    secret_categories: set[str] = field(default_factory=set)
    """Categories of credential material seen in cleartext on this flow."""

    tls_versions: set[str] = field(default_factory=set)
    ja3_hashes: set[str] = field(default_factory=set)

    packet_indices: deque[int] = field(
        default_factory=lambda: deque(maxlen=MAX_EVIDENCE_INDICES)
    )
    timestamps: deque[float] = field(default_factory=lambda: deque(maxlen=MAX_TIMESTAMPS))

    max_payload_entropy: float = 0.0

    # -- ingestion --------------------------------------------------------- #

    def observe(self, record: PacketRecord) -> None:
        """Fold one packet into this flow's state.

        Assumes the caller has already confirmed the record belongs to this
        flow -- the analyzer looks the flow up by key before calling.
        """
        direction = self.key.direction_of(record.src_ip or "", record.src_port)

        self.last_seen = record.timestamp
        self.last_packet_index = record.index
        if not self.first_packet_index:
            self.first_packet_index = record.index
        self.packet_indices.append(record.index)
        self.timestamps.append(record.timestamp)

        payload_length = record.payload_length
        if direction is Direction.A_TO_B:
            self.packets_a_to_b += 1
            self.bytes_a_to_b += record.length
            self.payload_bytes_a_to_b += payload_length
        else:
            self.packets_b_to_a += 1
            self.bytes_b_to_a += record.length
            self.payload_bytes_b_to_a += payload_length

        if record.app_protocol:
            self.app_protocols.add(record.app_protocol)

        if record.is_tcp:
            self._observe_tcp_flags(record.tcp_flags)

        if record.tls:
            if record.tls.sni:
                self.server_name = self.server_name or record.tls.sni
            if record.tls.effective_version:
                self.tls_versions.add(record.tls.effective_version)
            if record.tls.ja3_hash:
                self.ja3_hashes.add(record.tls.ja3_hash)

        if record.http and record.http.host:
            self.server_name = self.server_name or record.http.host

        if record.payload:
            self.secret_categories.update(record.payload.secret_categories)
            self.max_payload_entropy = max(self.max_payload_entropy, record.payload.entropy)

    def _observe_tcp_flags(self, flags: str | None) -> None:
        """Advance the coarse TCP state machine."""
        if flags is None:
            return

        if is_syn_only(flags):
            self.syn_count += 1
            if self.state in (TcpState.UNKNOWN, TcpState.NEW):
                self.state = TcpState.SYN_SENT
        elif is_syn_ack(flags):
            self.syn_ack_count += 1
            self.state = TcpState.ESTABLISHED

        if "R" in flags:
            self.rst_count += 1
            # A reset before anything was established means the port was
            # closed; after establishment it means an abrupt teardown. The
            # distinction matters: the first is scan evidence, the second is not.
            self.state = (
                TcpState.RESET if self.state is TcpState.ESTABLISHED else TcpState.REFUSED
            )
        elif "F" in flags:
            self.fin_count += 1
            self.state = TcpState.CLOSED if self.state is TcpState.CLOSING else TcpState.CLOSING

    # -- derived views ----------------------------------------------------- #

    @property
    def duration(self) -> float:
        """Seconds between the first and last packet."""
        return max(0.0, self.last_seen - self.first_seen)

    @property
    def total_packets(self) -> int:
        """Packets seen in both directions."""
        return self.packets_a_to_b + self.packets_b_to_a

    @property
    def total_bytes(self) -> int:
        """Wire bytes seen in both directions."""
        return self.bytes_a_to_b + self.bytes_b_to_a

    @property
    def total_payload_bytes(self) -> int:
        """Application-layer bytes seen in both directions."""
        return self.payload_bytes_a_to_b + self.payload_bytes_b_to_a

    @property
    def is_established(self) -> bool:
        """True when the conversation was actually answered."""
        return self.state in (TcpState.ESTABLISHED, TcpState.CLOSING, TcpState.CLOSED,
                              TcpState.RESET)

    @property
    def is_unanswered(self) -> bool:
        """True for a connection attempt that nothing ever replied to.

        The building block of scan detection: a scanner produces a large
        population of these, a normal client produces very few.
        """
        return self.syn_count > 0 and self.syn_ack_count == 0 and self.packets_b_to_a == 0

    @property
    def was_refused(self) -> bool:
        """True when the peer explicitly rejected the connection with RST."""
        return self.state is TcpState.REFUSED

    def payload_asymmetry(self, outbound_is_a: bool = True) -> float:
        """Ratio of outbound to inbound application-layer bytes.

        A value far above 1.0 means this endpoint sent much more than it
        received -- the shape of an upload, a backup, or an exfiltration.
        """
        if outbound_is_a:
            return ratio(self.payload_bytes_a_to_b, self.payload_bytes_b_to_a, default=float("inf")
                         if self.payload_bytes_a_to_b else 0.0)
        return ratio(self.payload_bytes_b_to_a, self.payload_bytes_a_to_b, default=float("inf")
                     if self.payload_bytes_b_to_a else 0.0)

    def interval_profile(self) -> IntervalProfile:
        """Regularity of packet arrivals within this flow."""
        return profile_intervals(list(self.timestamps))

    @property
    def evidence_indices(self) -> tuple[int, ...]:
        """Packet indices retained for citing in findings."""
        return tuple(self.packet_indices)

    def label(self) -> str:
        """A readable one-line description of the conversation."""
        service = describe_port(self.key.port_b if self.key.port_b else None)
        name = f" ({self.server_name})" if self.server_name else ""
        return (
            f"{self.key.protocol} {self.key.endpoint_a} <-> "
            f"{self.key.endpoint_b}{name} [{service}]"
        )

    def to_dict(self) -> dict[str, Any]:
        """Serialise for JSON output."""
        return {
            "key": self.key.to_dict(),
            "first_seen": round(self.first_seen, 6),
            "last_seen": round(self.last_seen, 6),
            "duration": round(self.duration, 6),
            "state": self.state.value,
            "packets": {
                "a_to_b": self.packets_a_to_b,
                "b_to_a": self.packets_b_to_a,
                "total": self.total_packets,
            },
            "bytes": {
                "a_to_b": self.bytes_a_to_b,
                "b_to_a": self.bytes_b_to_a,
                "total": self.total_bytes,
            },
            "payload_bytes": {
                "a_to_b": self.payload_bytes_a_to_b,
                "b_to_a": self.payload_bytes_b_to_a,
                "total": self.total_payload_bytes,
            },
            "tcp": {
                "syn": self.syn_count,
                "syn_ack": self.syn_ack_count,
                "fin": self.fin_count,
                "rst": self.rst_count,
            },
            "app_protocols": sorted(self.app_protocols),
            "server_name": self.server_name,
            "dns_names": sorted(self.dns_names),
            "tls_versions": sorted(self.tls_versions),
            "ja3_hashes": sorted(self.ja3_hashes),
            "secret_categories": sorted(self.secret_categories),
            "max_payload_entropy": round(self.max_payload_entropy, 4),
            "first_packet_index": self.first_packet_index,
            "last_packet_index": self.last_packet_index,
        }


__all__ = ["MAX_EVIDENCE_INDICES", "MAX_TIMESTAMPS", "Flow", "FlowKey"]
