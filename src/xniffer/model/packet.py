"""The ``PacketRecord`` -- xniffer's normalised, Scapy-free view of a packet.

This is the single most important type in the project. Everything downstream of
capture speaks ``PacketRecord`` and nothing else, which buys three things:

* **Testability.** Analysis and detection can be exercised by constructing
  records in a test, with no interface, no root and no pcap file.
* **Replaceability.** Scapy appears in exactly one package (``xniffer.capture``).
  Swapping the decoding backend would not touch a single rule.
* **A stable output contract.** ``to_dict()`` here defines the JSON shape that
  downstream consumers depend on.

Decoders do not build ``PacketRecord`` objects themselves. Each decoder is a
pure function returning a ``dict`` of the fields it understands; the pipeline
merges those dicts and constructs the record once. That keeps decoders tiny,
independently testable, and free of any ordering requirement between them.
"""

from __future__ import annotations

import hashlib
from dataclasses import dataclass, field
from typing import Any

from xniffer.model._serde import jsonify
from xniffer.model.enums import RedactionMode
from xniffer.util.net import describe_port, tcp_flag_names
from xniffer.util.text import printable_preview, redact_secrets, shannon_entropy

# --------------------------------------------------------------------------- #
# Payload
# --------------------------------------------------------------------------- #

#: How many bytes of payload are scanned for credential material. Secrets past
#: this point are missed, but scanning unbounded payloads on every packet would
#: dominate the capture loop's cost.
SECRET_SCAN_LIMIT = 8192

#: Default number of payload bytes kept for display.
PREVIEW_LIMIT = 96


@dataclass(frozen=True, slots=True)
class PayloadInfo:
    """What xniffer retains about a packet's application-layer bytes.

    Note what is *not* here: the raw bytes. A ``PacketRecord`` is designed to
    be safe to log, serialise and share. The digest lets an analyst prove two
    payloads were identical without either of them ever being written down.
    """

    length: int
    """Payload size in bytes, before any truncation for display."""

    sha256: str
    """Hex digest of the full payload -- an integrity and correlation handle."""

    entropy: float
    """Shannon entropy in bits per byte. High values suggest encryption."""

    preview: str
    """A short printable rendering, masked according to the redaction mode."""

    redaction: RedactionMode = RedactionMode.REDACTED
    """Which redaction policy produced :attr:`preview`."""

    secret_categories: tuple[str, ...] = ()
    """Kinds of credential material detected (``password``, ``token``, ...).

    Populated regardless of redaction mode, because it is a detection signal
    rather than content. The secrets themselves are never retained.
    """

    @property
    def short_digest(self) -> str:
        """First 12 hex characters of :attr:`sha256`, for compact display."""
        return self.sha256[:12]

    @property
    def has_secrets(self) -> bool:
        """True when credential material was detected in the payload."""
        return bool(self.secret_categories)

    @property
    def looks_encrypted(self) -> bool:
        """True when entropy is high enough to suggest encrypted content.

        Only meaningful for payloads of a reasonable size -- a four-byte
        payload can hit maximum entropy by coincidence.
        """
        return self.length >= 64 and self.entropy >= 6.5

    @classmethod
    def from_bytes(
        cls,
        data: bytes,
        mode: RedactionMode = RedactionMode.REDACTED,
        preview_limit: int = PREVIEW_LIMIT,
    ) -> PayloadInfo:
        """Build a :class:`PayloadInfo` from raw bytes under a redaction policy.

        The secret scan always runs over a large window of the payload, while
        the preview stays short. Scanning only the preview would let a password
        one line below the visible area pass unnoticed -- which is exactly the
        case the detection is for.
        """
        length = len(data)
        if length == 0:
            return cls(
                length=0,
                sha256=hashlib.sha256(b"").hexdigest(),
                entropy=0.0,
                preview="",
                redaction=mode,
                secret_categories=(),
            )

        digest = hashlib.sha256(data).hexdigest()
        entropy = shannon_entropy(data)

        scan_window = printable_preview(data[:SECRET_SCAN_LIMIT], limit=SECRET_SCAN_LIMIT)
        scan = redact_secrets(scan_window)

        if mode is RedactionMode.NONE:
            preview = ""
        else:
            raw_preview = printable_preview(data, limit=preview_limit)
            if mode is RedactionMode.FULL:
                preview = raw_preview
            else:
                preview = redact_secrets(raw_preview).text

        return cls(
            length=length,
            sha256=digest,
            entropy=entropy,
            preview=preview,
            redaction=mode,
            secret_categories=scan.categories,
        )

    def to_dict(self) -> dict[str, Any]:
        """Serialise for JSON output."""
        return jsonify(self)


# --------------------------------------------------------------------------- #
# Protocol detail records
# --------------------------------------------------------------------------- #


@dataclass(frozen=True, slots=True)
class ArpInfo:
    """Address Resolution Protocol details."""

    operation: int
    """1 = request, 2 = reply."""

    sender_mac: str
    sender_ip: str
    target_mac: str
    target_ip: str

    @property
    def operation_name(self) -> str:
        """``request``, ``reply``, or ``opcode-N`` for anything unusual."""
        return {1: "request", 2: "reply"}.get(self.operation, f"opcode-{self.operation}")

    @property
    def is_request(self) -> bool:
        """True for an ARP request (``who-has``)."""
        return self.operation == 1

    @property
    def is_reply(self) -> bool:
        """True for an ARP reply (``is-at``)."""
        return self.operation == 2

    @property
    def is_gratuitous(self) -> bool:
        """True for a gratuitous ARP -- sender and target IP are the same.

        Legitimate during failover and address changes, and also the standard
        mechanism for poisoning a neighbour's ARP cache. Volume and repetition
        are what separate the two, not the individual packet.
        """
        return bool(self.sender_ip) and self.sender_ip == self.target_ip

    def to_dict(self) -> dict[str, Any]:
        """Serialise for JSON output."""
        data = jsonify(self)
        data["operation_name"] = self.operation_name
        return data


@dataclass(frozen=True, slots=True)
class DnsQuestion:
    """A single question section entry."""

    name: str
    qtype: str
    """Record type as a name (``A``, ``AAAA``, ``TXT``, ``NULL``, ...)."""

    qclass: str = "IN"


@dataclass(frozen=True, slots=True)
class DnsAnswer:
    """A single answer, authority or additional section entry."""

    name: str
    rtype: str
    ttl: int
    data: str
    """The record's payload, rendered as text (an IP, a name, a TXT string)."""


@dataclass(frozen=True, slots=True)
class DnsInfo:
    """Domain Name System message details."""

    transaction_id: int
    is_response: bool
    opcode: int = 0
    rcode: int = 0
    questions: tuple[DnsQuestion, ...] = ()
    answers: tuple[DnsAnswer, ...] = ()
    authority_count: int = 0
    additional_count: int = 0
    is_truncated: bool = False
    recursion_desired: bool = True

    #: Response codes worth naming. Anything else renders as ``rcode-N``.
    RCODE_NAMES = {
        0: "NOERROR",
        1: "FORMERR",
        2: "SERVFAIL",
        3: "NXDOMAIN",
        4: "NOTIMP",
        5: "REFUSED",
    }

    @property
    def rcode_name(self) -> str:
        """Human-readable response code."""
        return self.RCODE_NAMES.get(self.rcode, f"rcode-{self.rcode}")

    @property
    def is_query(self) -> bool:
        """True for a DNS query."""
        return not self.is_response

    @property
    def is_nxdomain(self) -> bool:
        """True when the server reported the name does not exist.

        A burst of these from one host is the classic signature of malware
        cycling through algorithmically generated domains.
        """
        return self.is_response and self.rcode == 3

    @property
    def primary_name(self) -> str:
        """The first queried name, or empty when there is no question section."""
        return self.questions[0].name if self.questions else ""

    @property
    def primary_qtype(self) -> str:
        """The first queried record type, or empty."""
        return self.questions[0].qtype if self.questions else ""

    @property
    def queried_names(self) -> tuple[str, ...]:
        """Every name in the question section."""
        return tuple(question.name for question in self.questions)

    @property
    def resolved_addresses(self) -> tuple[str, ...]:
        """Every A/AAAA address in the answer section."""
        return tuple(answer.data for answer in self.answers if answer.rtype in ("A", "AAAA"))

    def to_dict(self) -> dict[str, Any]:
        """Serialise for JSON output."""
        data = jsonify(self)
        data["rcode_name"] = self.rcode_name
        return data


@dataclass(frozen=True, slots=True)
class TlsInfo:
    """Transport Layer Security handshake and record details.

    xniffer reads only what is visible before encryption begins: the record
    header, the ClientHello and the ServerHello. That is deliberate -- it is
    the metadata that survives on a modern network, and it is enough to say
    *who* is talking to *what* and *how well protected* the session is.
    """

    content_type: str
    """``handshake``, ``application_data``, ``alert``, ``change_cipher_spec``."""

    handshake_type: str | None = None
    """``client_hello``, ``server_hello``, ``certificate``, ..."""

    record_version: str | None = None
    """Version from the record header -- often understated for compatibility."""

    negotiated_version: str | None = None
    """The genuinely meaningful version, from the hello's supported versions."""

    sni: str | None = None
    """Server Name Indication -- the hostname the client asked for."""

    alpn: tuple[str, ...] = ()
    """Application protocols offered or selected (``h2``, ``http/1.1``)."""

    cipher_suites: tuple[int, ...] = ()
    """Cipher suites offered by the client."""

    selected_cipher: int | None = None
    """Cipher suite chosen by the server."""

    ja3: str | None = None
    """The JA3 fingerprint string, before hashing."""

    ja3_hash: str | None = None
    """MD5 of :attr:`ja3` -- the conventional JA3 client fingerprint.

    MD5 is used here because it is what the JA3 specification defines and what
    every threat-intelligence feed keys on. It is an interoperability
    identifier, never a security control.
    """

    ja3s: str | None = None
    """The JA3S (server) fingerprint string."""

    ja3s_hash: str | None = None
    """MD5 of :attr:`ja3s`."""

    #: Versions that are deprecated or actively unsafe.
    WEAK_VERSIONS = frozenset({"SSLv2", "SSLv3", "TLS 1.0", "TLS 1.1"})

    @property
    def effective_version(self) -> str | None:
        """The best available view of the session's actual TLS version."""
        return self.negotiated_version or self.record_version

    @property
    def is_weak_version(self) -> bool:
        """True when the session uses a deprecated protocol version."""
        return self.effective_version in self.WEAK_VERSIONS

    @property
    def is_client_hello(self) -> bool:
        """True for a ClientHello record."""
        return self.handshake_type == "client_hello"

    @property
    def is_server_hello(self) -> bool:
        """True for a ServerHello record."""
        return self.handshake_type == "server_hello"

    def to_dict(self) -> dict[str, Any]:
        """Serialise for JSON output."""
        data = jsonify(self)
        if self.effective_version:
            data["effective_version"] = self.effective_version
        data["is_weak_version"] = self.is_weak_version
        return data


@dataclass(frozen=True, slots=True)
class HttpInfo:
    """HTTP request/response metadata.

    Headers and the request line only -- xniffer never retains a body. On a
    modern network cleartext HTTP is the exception rather than the rule, so
    this exists to characterise the exceptions, not to reconstruct sessions.
    """

    is_request: bool
    method: str | None = None
    path: str | None = None
    version: str | None = None
    host: str | None = None
    user_agent: str | None = None
    referer: str | None = None
    status_code: int | None = None
    reason: str | None = None
    content_type: str | None = None
    content_length: int | None = None
    server: str | None = None
    header_count: int = 0
    auth_scheme: str | None = None
    """Scheme from an ``Authorization`` header (``Basic``, ``Bearer``, ...)."""

    has_cookie: bool = False

    @property
    def is_response(self) -> bool:
        """True for an HTTP response."""
        return not self.is_request

    @property
    def has_basic_auth(self) -> bool:
        """True when HTTP Basic authentication was used.

        Basic auth is base64, not encryption. Over cleartext HTTP it is
        equivalent to sending the password in the clear.
        """
        return (self.auth_scheme or "").lower() == "basic"

    @property
    def url(self) -> str | None:
        """Best-effort reconstruction of the requested URL."""
        if not self.is_request or not self.path:
            return None
        return f"http://{self.host}{self.path}" if self.host else self.path

    def to_dict(self) -> dict[str, Any]:
        """Serialise for JSON output."""
        return jsonify(self)


@dataclass(frozen=True, slots=True)
class IcmpInfo:
    """ICMP / ICMPv6 message details."""

    icmp_type: int
    code: int
    identifier: int | None = None
    sequence: int | None = None
    type_name: str | None = None
    is_v6: bool = False

    #: The message types xniffer names explicitly.
    TYPE_NAMES_V4 = {
        0: "echo-reply",
        3: "destination-unreachable",
        4: "source-quench",
        5: "redirect",
        8: "echo-request",
        11: "time-exceeded",
        12: "parameter-problem",
        13: "timestamp-request",
        14: "timestamp-reply",
    }
    TYPE_NAMES_V6 = {
        1: "destination-unreachable",
        2: "packet-too-big",
        3: "time-exceeded",
        4: "parameter-problem",
        128: "echo-request",
        129: "echo-reply",
        133: "router-solicitation",
        134: "router-advertisement",
        135: "neighbor-solicitation",
        136: "neighbor-advertisement",
    }

    @property
    def name(self) -> str:
        """Human-readable message type."""
        if self.type_name:
            return self.type_name
        table = self.TYPE_NAMES_V6 if self.is_v6 else self.TYPE_NAMES_V4
        return table.get(self.icmp_type, f"type-{self.icmp_type}")

    @property
    def is_echo(self) -> bool:
        """True for echo request or reply -- the ``ping`` messages."""
        return self.name in ("echo-request", "echo-reply")

    def to_dict(self) -> dict[str, Any]:
        """Serialise for JSON output."""
        data = jsonify(self)
        data["name"] = self.name
        return data


# --------------------------------------------------------------------------- #
# The packet record
# --------------------------------------------------------------------------- #


@dataclass(frozen=True, slots=True)
class PacketRecord:
    """One captured packet, normalised and independent of any capture library.

    Only :attr:`index`, :attr:`timestamp` and :attr:`length` are required;
    every other field is optional because a packet may be an ARP frame with no
    IP layer, or an IP fragment with no transport layer, or a malformed frame
    that decoded only partially.

    Instances are frozen. Once the pipeline has produced a record, no analyzer
    or rule can mutate it -- which means a rule can never corrupt the evidence
    a later rule depends on.
    """

    # -- core -------------------------------------------------------------- #
    index: int
    """1-based position in the capture. This is the pivot an analyst uses:
    every finding cites these numbers, and ``xniffer packet --id N`` resolves
    them back to the full packet."""

    timestamp: float
    """Capture time as a Unix epoch float."""

    length: int
    """Length of the packet on the wire, in bytes."""

    captured_length: int | None = None
    """Bytes actually captured, which is smaller when a snaplen truncated it."""

    layers: tuple[str, ...] = ()
    """Protocol layer names, outermost first, e.g. ``("Ethernet","IPv4","TCP")``."""

    link_type: str | None = None
    """Link layer encapsulation (``Ethernet``, ``Linux cooked``, ``Raw``)."""

    # -- link layer -------------------------------------------------------- #
    src_mac: str | None = None
    dst_mac: str | None = None
    ether_type: int | None = None
    vlan_id: int | None = None

    # -- network layer ----------------------------------------------------- #
    ip_version: int | None = None
    src_ip: str | None = None
    dst_ip: str | None = None
    ip_proto: int | None = None
    ip_proto_name: str | None = None
    ttl: int | None = None
    """IPv4 TTL or IPv6 hop limit."""

    ip_id: int | None = None
    ip_flags: str | None = None
    ip_fragment_offset: int | None = None
    ip_total_length: int | None = None
    dscp: int | None = None

    # -- transport layer --------------------------------------------------- #
    transport: str | None = None
    """``TCP``, ``UDP``, ``ICMP``, ``ICMPv6``, or ``None``."""

    src_port: int | None = None
    dst_port: int | None = None
    tcp_flags: str | None = None
    """Scapy-style flag letters, e.g. ``"SA"``. Interpret via
    :func:`xniffer.util.net.tcp_flag_names` and friends."""

    tcp_seq: int | None = None
    tcp_ack: int | None = None
    tcp_window: int | None = None
    tcp_options: tuple[str, ...] = ()
    udp_length: int | None = None

    # -- application layer ------------------------------------------------- #
    app_protocol: str | None = None
    """``DNS``, ``TLS``, ``HTTP``, or ``None`` when unidentified."""

    arp: ArpInfo | None = None
    dns: DnsInfo | None = None
    tls: TlsInfo | None = None
    http: HttpInfo | None = None
    icmp: IcmpInfo | None = None

    # -- payload ----------------------------------------------------------- #
    payload: PayloadInfo | None = None

    # -- decoding metadata ------------------------------------------------- #
    truncated: bool = False
    """True when the capture snaplen cut the packet short."""

    decode_errors: tuple[str, ...] = ()
    """Non-fatal decoding problems. Decoding is best-effort: a malformed frame
    yields a partial record with the failure noted here, never an exception
    that aborts the capture."""

    interface: str | None = None
    """Interface the packet arrived on, for multi-interface captures."""

    # -- derived views ----------------------------------------------------- #

    @property
    def has_ip(self) -> bool:
        """True when both IP endpoints were decoded."""
        return self.src_ip is not None and self.dst_ip is not None

    @property
    def has_ports(self) -> bool:
        """True when both transport ports were decoded."""
        return self.src_port is not None and self.dst_port is not None

    @property
    def is_ipv4(self) -> bool:
        """True for IPv4 packets."""
        return self.ip_version == 4

    @property
    def is_ipv6(self) -> bool:
        """True for IPv6 packets."""
        return self.ip_version == 6

    @property
    def is_tcp(self) -> bool:
        """True for TCP packets."""
        return self.transport == "TCP"

    @property
    def is_udp(self) -> bool:
        """True for UDP packets."""
        return self.transport == "UDP"

    @property
    def is_icmp(self) -> bool:
        """True for ICMP or ICMPv6 packets."""
        return self.transport in ("ICMP", "ICMPv6")

    @property
    def is_arp(self) -> bool:
        """True for ARP frames."""
        return self.arp is not None

    @property
    def payload_length(self) -> int:
        """Application-layer payload size, or 0 when there is none."""
        return self.payload.length if self.payload else 0

    @property
    def tcp_flag_names(self) -> tuple[str, ...]:
        """Expanded TCP flag names, e.g. ``("SYN", "ACK")``."""
        return tcp_flag_names(self.tcp_flags)

    @property
    def source(self) -> str:
        """Source endpoint as ``ip:port``, or just the IP/MAC when no port."""
        return self._endpoint(self.src_ip, self.src_port, self.src_mac)

    @property
    def destination(self) -> str:
        """Destination endpoint as ``ip:port``, or just the IP/MAC when no port."""
        return self._endpoint(self.dst_ip, self.dst_port, self.dst_mac)

    @staticmethod
    def _endpoint(ip: str | None, port: int | None, mac: str | None) -> str:
        if ip and port is not None:
            return f"[{ip}]:{port}" if ":" in ip else f"{ip}:{port}"
        if ip:
            return ip
        return mac or "-"

    @property
    def protocol(self) -> str:
        """The most specific protocol name known for this packet.

        Application protocol if identified, else transport, else the outermost
        network layer. This is what the packet list column shows.
        """
        if self.app_protocol:
            return self.app_protocol
        if self.transport:
            return self.transport
        if self.arp:
            return "ARP"
        if self.ip_version:
            return f"IPv{self.ip_version}"
        return self.link_type or "unknown"

    def summary(self) -> str:
        """A single readable line describing the packet.

        Modelled on how an analyst would actually say it out loud, with the
        protocol-specific detail that matters -- the queried name for DNS, the
        requested host for TLS, the flags for a bare TCP segment.
        """
        if self.arp:
            arp = self.arp
            if arp.is_request:
                return f"ARP who-has {arp.target_ip} tell {arp.sender_ip}"
            if arp.is_reply:
                return f"ARP {arp.sender_ip} is-at {arp.sender_mac}"
            return f"ARP {arp.operation_name} {arp.sender_ip} -> {arp.target_ip}"

        route = f"{self.source} -> {self.destination}"

        if self.dns:
            dns = self.dns
            if dns.is_query:
                return f"DNS {route} query {dns.primary_qtype} {dns.primary_name}".rstrip()
            answers = ", ".join(dns.resolved_addresses[:3])
            detail = f" {answers}" if answers else ""
            return f"DNS {route} response {dns.rcode_name} {dns.primary_name}{detail}".rstrip()

        if self.tls:
            tls = self.tls
            if tls.is_client_hello:
                target = f" sni={tls.sni}" if tls.sni else ""
                return f"TLS {route} ClientHello{target}"
            if tls.is_server_hello:
                version = f" {tls.effective_version}" if tls.effective_version else ""
                return f"TLS {route} ServerHello{version}"
            return f"TLS {route} {tls.content_type}"

        if self.http:
            http = self.http
            if http.is_request:
                return f"HTTP {route} {http.method} {http.path}"
            return f"HTTP {route} {http.status_code} {http.reason or ''}".rstrip()

        if self.icmp:
            return f"ICMP {route} {self.icmp.name}"

        if self.is_tcp:
            flags = f" [{','.join(self.tcp_flag_names)}]" if self.tcp_flags else ""
            payload = f" len={self.payload_length}" if self.payload_length else ""
            return f"TCP {route}{flags}{payload}"

        if self.is_udp:
            payload = f" len={self.payload_length}" if self.payload_length else ""
            return f"UDP {route}{payload}"

        if self.has_ip:
            return f"IPv{self.ip_version} {route} proto={self.ip_proto_name or self.ip_proto}"

        return f"{self.protocol} {self.src_mac or '?'} -> {self.dst_mac or '?'} len={self.length}"

    def describe_ports(self) -> str:
        """Render the port pair with service names, e.g. ``54321 -> 443 (https)``."""
        if not self.has_ports:
            return "-"
        return f"{describe_port(self.src_port)} -> {describe_port(self.dst_port)}"

    def to_dict(self) -> dict[str, Any]:
        """Serialise for JSON output.

        Optional fields that were never populated are omitted rather than
        emitted as ``null``, and a few derived values are added so consumers
        do not have to reimplement the logic.
        """
        data = jsonify(self)
        data["protocol"] = self.protocol
        data["summary"] = self.summary()
        return data


@dataclass(slots=True)
class PacketFields:
    """Mutable accumulator used while decoding a single packet.

    Decoders return plain ``dict`` field contributions; the pipeline folds them
    into one of these and calls :meth:`build` once. Keeping the mutable phase
    separate from the frozen result means decoders cannot accidentally depend
    on each other's ordering, and the record they produce is immutable from the
    moment it exists.
    """

    values: dict[str, Any] = field(default_factory=dict)
    errors: list[str] = field(default_factory=list)

    def update(self, contribution: dict[str, Any] | None) -> None:
        """Merge one decoder's field contribution.

        ``layers`` and ``decode_errors`` accumulate; every other field is
        overwritten by the more specific decoder that ran later.
        """
        if not contribution:
            return
        for key, value in contribution.items():
            if key == "layers":
                existing = tuple(self.values.get("layers", ()))
                self.values["layers"] = existing + tuple(value)
            elif key == "decode_errors":
                self.errors.extend(value)
            else:
                self.values[key] = value

    def note_error(self, message: str) -> None:
        """Record a non-fatal decoding problem."""
        self.errors.append(message)

    def build(self, index: int, timestamp: float, length: int) -> PacketRecord:
        """Construct the immutable :class:`PacketRecord`.

        Unknown keys are dropped with an error note rather than raising: a
        third-party decoder that emits a field this version does not know about
        should degrade gracefully, not crash the capture.
        """
        known = {f.name for f in PacketRecord.__dataclass_fields__.values()}
        payload = {}
        for key, value in self.values.items():
            if key in known:
                payload[key] = value
            else:
                self.errors.append(f"unknown field from decoder: {key}")

        payload["index"] = index
        payload["timestamp"] = timestamp
        payload["length"] = length
        if self.errors:
            payload["decode_errors"] = tuple(self.errors)
        return PacketRecord(**payload)


__all__ = [
    "PREVIEW_LIMIT",
    "SECRET_SCAN_LIMIT",
    "ArpInfo",
    "DnsAnswer",
    "DnsInfo",
    "DnsQuestion",
    "HttpInfo",
    "IcmpInfo",
    "PacketFields",
    "PacketRecord",
    "PayloadInfo",
    "TlsInfo",
]
