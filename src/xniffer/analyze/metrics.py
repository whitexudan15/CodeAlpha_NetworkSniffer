"""The metric catalogue -- every measurement a rule is allowed to reference.

This module is the reason a YAML rule can say ``host.unanswered_syn_ratio >=
0.8`` and have that mean something precise. Each metric is declared once here,
with its scope, type, unit and a description written for the person authoring
the rule rather than the person implementing the analyzer.

Declaring them buys three things:

* The rule loader rejects unknown metric names at load time. A typo becomes an
  error message instead of a rule that quietly never fires -- which is the worst
  failure mode a detection tool has, because it looks exactly like "no threats
  found".
* The analysis layer and the rule set can be written in parallel against one
  agreed vocabulary.
* ``xniffer rules metrics`` can print the catalogue, so authoring a rule does
  not require reading the analyzer's source.

Metric names are namespaced by scope (``host.``, ``flow.``, ``pair.``, ``dns.``,
``capture.``) so that a rule declaring ``scope: host`` can only reach metrics
that exist for a host.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Literal

from xniffer.analyze.subject import SubjectScope

#: How a metric's value should be read. Used for validation and for rendering
#: thresholds in reports ("0.82" vs "82%" vs "1.4 KB").
MetricKind = Literal["count", "ratio", "duration", "bytes", "rate", "entropy", "flag", "text"]


@dataclass(frozen=True, slots=True)
class MetricSpec:
    """The declaration of one measurable quantity."""

    name: str
    """Fully-qualified catalogue name, e.g. ``host.unanswered_syn_ratio``."""

    scope: SubjectScope
    kind: MetricKind
    description: str
    """Written for a rule author: what it measures and when it is meaningful."""

    unit: str = ""
    """Display suffix, e.g. ``s``, ``bytes``, ``bits``. Empty for bare numbers."""

    range_hint: str = ""
    """Expected span, e.g. ``0.0-1.0``. Documentation only -- never enforced,
    because clamping a measurement to make it fit a rule would be lying."""

    @property
    def short_name(self) -> str:
        """The name without its scope prefix."""
        _, _, rest = self.name.partition(".")
        return rest or self.name

    def format_value(self, value: object) -> str:
        """Render a measured value the way reports should show it."""
        if isinstance(value, bool):
            return "yes" if value else "no"
        if isinstance(value, float):
            if self.kind == "ratio":
                return f"{value:.3f}"
            return f"{value:.2f}{self.unit}"
        return f"{value}{self.unit}"


def _spec(
    name: str,
    scope: SubjectScope,
    kind: MetricKind,
    description: str,
    unit: str = "",
    range_hint: str = "",
) -> MetricSpec:
    return MetricSpec(
        name=name,
        scope=scope,
        kind=kind,
        description=description,
        unit=unit,
        range_hint=range_hint,
    )


_HOST = SubjectScope.HOST
_FLOW = SubjectScope.FLOW
_PAIR = SubjectScope.HOST_PAIR
_DNS = SubjectScope.DNS
_CAPTURE = SubjectScope.CAPTURE


# --------------------------------------------------------------------------- #
# Host metrics -- one subject per IP address seen in the capture.
# --------------------------------------------------------------------------- #

_HOST_METRICS: tuple[MetricSpec, ...] = (
    _spec("host.packets_sent", _HOST, "count", "Packets this host transmitted."),
    _spec("host.packets_received", _HOST, "count", "Packets addressed to this host."),
    _spec("host.bytes_sent", _HOST, "bytes", "Total bytes transmitted.", unit=" bytes"),
    _spec("host.bytes_received", _HOST, "bytes", "Total bytes received.", unit=" bytes"),
    _spec(
        "host.distinct_peers",
        _HOST,
        "count",
        "How many distinct remote IPs this host contacted. High values suggest "
        "scanning, a proxy, or a busy server.",
    ),
    _spec(
        "host.distinct_ports_contacted",
        _HOST,
        "count",
        "Distinct destination ports this host reached out to, summed across all "
        "peers. The core vertical-scan signal.",
    ),
    _spec(
        "host.max_ports_on_single_peer",
        _HOST,
        "count",
        "The largest number of distinct ports this host touched on any one peer. "
        "Separates a vertical scan (many ports, one target) from ordinary traffic "
        "to many services.",
    ),
    _spec(
        "host.distinct_peers_on_single_port",
        _HOST,
        "count",
        "The largest number of distinct peers this host contacted on one port. "
        "The horizontal-scan signal -- sweeping :445 across a subnet.",
    ),
    _spec("host.syn_sent", _HOST, "count", "TCP SYN packets sent (connection attempts)."),
    _spec(
        "host.unanswered_syns",
        _HOST,
        "count",
        "SYNs that drew neither a SYN-ACK nor a RST. Closed ports usually answer "
        "with RST; silence normally means a filtered port or a dead host.",
    ),
    _spec(
        "host.unanswered_syn_ratio",
        _HOST,
        "ratio",
        "Unanswered SYNs over SYNs sent. Near 1.0 with a high SYN count is a scan "
        "hitting mostly filtered ports.",
        range_hint="0.0-1.0",
    ),
    _spec(
        "host.refused_connections",
        _HOST,
        "count",
        "Connection attempts answered with RST -- a closed port that replied.",
    ),
    _spec(
        "host.refused_ratio",
        _HOST,
        "ratio",
        "Refused attempts over attempts made. A scan across mostly-closed ports "
        "on a live host pushes this toward 1.0.",
        range_hint="0.0-1.0",
    ),
    _spec(
        "host.failed_connection_ratio",
        _HOST,
        "ratio",
        "Attempts that never reached ESTABLISHED, over all attempts. Covers both "
        "refused and unanswered in one number.",
        range_hint="0.0-1.0",
    ),
    _spec(
        "host.scan_window_seconds",
        _HOST,
        "duration",
        "Seconds between this host's first and last connection attempt. Pair with "
        "a port count to separate a burst scan from slow legitimate use.",
        unit="s",
    ),
    _spec(
        "host.connection_attempt_rate",
        _HOST,
        "rate",
        "Connection attempts per second across the capture.",
        unit="/s",
    ),
    _spec(
        "host.null_scan_packets",
        _HOST,
        "count",
        "TCP packets sent with no flags set. Not produced by a normal stack -- a "
        "NULL scan probing how the target's TCP implementation responds.",
    ),
    _spec(
        "host.xmas_scan_packets",
        _HOST,
        "count",
        "TCP packets with FIN+PSH+URG set. Same reasoning as NULL: crafted, not "
        "emitted by any ordinary application.",
    ),
    _spec(
        "host.fin_scan_packets",
        _HOST,
        "count",
        "Bare FIN packets with no prior handshake for that connection.",
    ),
    _spec(
        "host.cleartext_credential_packets",
        _HOST,
        "count",
        "Packets in which credential-shaped material was seen in cleartext. "
        "Counted from redaction categories -- the credential itself is never kept.",
    ),
    _spec(
        "host.cleartext_service_packets",
        _HOST,
        "count",
        "Packets on protocols that carry authentication without encryption "
        "(telnet, ftp, http basic-auth, pop3, imap, smtp).",
    ),
    _spec(
        "host.listener_ports",
        _HOST,
        "count",
        "Distinct local ports on which this host accepted connections.",
    ),
    _spec(
        "host.suspicious_listener_ports",
        _HOST,
        "count",
        "Accepted connections on ports conventionally used by tooling rather than "
        "services -- 4444, 31337, 9001 and similar. Convention, not proof.",
    ),
    _spec(
        "host.arp_replies_sent",
        _HOST,
        "count",
        "ARP replies this host emitted, gratuitous ones included.",
    ),
    _spec(
        "host.arp_conflicting_claims",
        _HOST,
        "count",
        "Times this MAC claimed an IP that another MAC also claimed. The direct "
        "ARP-spoofing signal.",
    ),
    _spec(
        "host.max_payload_entropy",
        _HOST,
        "entropy",
        "Highest Shannon entropy of any payload this host sent, in bits per byte. "
        "Above ~7.5 means encrypted or compressed.",
        unit=" bits",
        range_hint="0.0-8.0",
    ),
    _spec(
        "host.is_local",
        _HOST,
        "flag",
        "True when the address is in RFC1918, loopback or link-local space.",
    ),
)


# --------------------------------------------------------------------------- #
# Flow metrics -- one subject per conversation.
# --------------------------------------------------------------------------- #

_FLOW_METRICS: tuple[MetricSpec, ...] = (
    _spec("flow.packets", _FLOW, "count", "Packets in both directions."),
    _spec("flow.bytes", _FLOW, "bytes", "Bytes in both directions.", unit=" bytes"),
    _spec(
        "flow.duration",
        _FLOW,
        "duration",
        "Seconds between the first and last packet of the conversation.",
        unit="s",
    ),
    _spec(
        "flow.bytes_to_server",
        _FLOW,
        "bytes",
        "Bytes sent by the initiator. Large values on an otherwise quiet flow are "
        "the upload half of an exfiltration.",
        unit=" bytes",
    ),
    _spec(
        "flow.bytes_to_client",
        _FLOW,
        "bytes",
        "Bytes returned by the responder.",
        unit=" bytes",
    ),
    _spec(
        "flow.payload_asymmetry",
        _FLOW,
        "ratio",
        "Initiator payload over total payload. Near 1.0 is almost pure upload; "
        "most client sessions sit well below 0.5.",
        range_hint="0.0-1.0",
    ),
    _spec(
        "flow.max_payload_entropy",
        _FLOW,
        "entropy",
        "Highest payload entropy observed, in bits per byte.",
        unit=" bits",
        range_hint="0.0-8.0",
    ),
    _spec(
        "flow.is_established",
        _FLOW,
        "flag",
        "True when the TCP handshake completed.",
    ),
    _spec(
        "flow.was_refused",
        _FLOW,
        "flag",
        "True when the connection attempt was answered with RST.",
    ),
    _spec(
        "flow.is_unanswered",
        _FLOW,
        "flag",
        "True when a SYN drew no response at all.",
    ),
    _spec(
        "flow.uses_cleartext_service",
        _FLOW,
        "flag",
        "True when the port carries authentication without encryption.",
    ),
    _spec(
        "flow.has_credentials",
        _FLOW,
        "flag",
        "True when credential-shaped material appeared in the payload.",
    ),
    _spec(
        "flow.tls_weak_version",
        _FLOW,
        "flag",
        "True when the negotiated TLS version is SSLv3, TLS 1.0 or TLS 1.1.",
    ),
    _spec(
        "flow.server_port",
        _FLOW,
        "count",
        "The responder's port -- the service being reached.",
    ),
    _spec(
        "flow.is_encrypted",
        _FLOW,
        "flag",
        "True when payload entropy indicates encryption or compression.",
    ),
)


# --------------------------------------------------------------------------- #
# Host-pair metrics -- all traffic between two hosts, across connections.
#
# Beaconing lives here. An implant that opens a fresh connection every sixty
# seconds shows nothing at flow scope: each flow is short, small and ordinary.
# The periodicity is only visible once the connections are viewed together.
# --------------------------------------------------------------------------- #

_PAIR_METRICS: tuple[MetricSpec, ...] = (
    _spec("pair.connections", _PAIR, "count", "Distinct connections between the two hosts."),
    _spec("pair.packets", _PAIR, "count", "Packets exchanged in total."),
    _spec("pair.bytes", _PAIR, "bytes", "Bytes exchanged in total.", unit=" bytes"),
    _spec(
        "pair.mean_interval",
        _PAIR,
        "duration",
        "Average seconds between successive contacts.",
        unit="s",
    ),
    _spec(
        "pair.interval_stdev",
        _PAIR,
        "duration",
        "Standard deviation of those intervals. Small relative to the mean means "
        "machine-driven timing.",
        unit="s",
    ),
    _spec(
        "pair.interval_variation",
        _PAIR,
        "ratio",
        "Coefficient of variation: stdev over mean. The beaconing metric. Human "
        "browsing lands well above 0.5; a scheduled callback sits near 0.0. Jitter "
        "deliberately raises it, so a high value does not clear a host.",
        range_hint="0.0+",
    ),
    _spec(
        "pair.regularity",
        _PAIR,
        "ratio",
        "1 - interval_variation, floored at 0. The same signal read the intuitive "
        "way: 1.0 is perfectly periodic.",
        range_hint="0.0-1.0",
    ),
    _spec(
        "pair.contact_count",
        _PAIR,
        "count",
        "Contacts used for the interval statistics. Below four, periodicity is not "
        "measurable and rules should not claim it.",
    ),
    _spec(
        "pair.observation_window",
        _PAIR,
        "duration",
        "Seconds between the first and last contact.",
        unit="s",
    ),
    _spec(
        "pair.mean_bytes_per_contact",
        _PAIR,
        "bytes",
        "Average bytes per contact. Small and constant fits a check-in; large fits "
        "a transfer.",
        unit=" bytes",
    ),
    _spec(
        "pair.payload_asymmetry",
        _PAIR,
        "ratio",
        "Outbound payload over total payload across every connection in the pair.",
        range_hint="0.0-1.0",
    ),
    _spec(
        "pair.destination_is_external",
        _PAIR,
        "flag",
        "True when the destination is a public address. A periodic callback inside "
        "the LAN is usually monitoring; the same pattern leaving the network is not.",
    ),
)


# --------------------------------------------------------------------------- #
# DNS metrics -- one subject per client, aggregating its resolver behaviour.
# --------------------------------------------------------------------------- #

_DNS_METRICS: tuple[MetricSpec, ...] = (
    _spec("dns.queries", _DNS, "count", "DNS queries this client issued."),
    _spec("dns.distinct_names", _DNS, "count", "Distinct names queried."),
    _spec(
        "dns.nxdomain_responses",
        _DNS,
        "count",
        "Responses saying the name does not exist.",
    ),
    _spec(
        "dns.nxdomain_ratio",
        _DNS,
        "ratio",
        "NXDOMAIN over answered queries. Sustained high values fit domain-generation "
        "malware hunting for a live C2 name.",
        range_hint="0.0-1.0",
    ),
    _spec(
        "dns.max_subdomain_entropy",
        _DNS,
        "entropy",
        "Highest Shannon entropy of any subdomain part queried, in bits per "
        "character. Encoded data carried in a hostname scores far above a name a "
        "person would choose.",
        unit=" bits",
        range_hint="0.0-8.0",
    ),
    _spec(
        "dns.max_label_length",
        _DNS,
        "count",
        "Longest single DNS label seen. The protocol caps a label at 63 bytes, and "
        "tunnels push right up against it.",
    ),
    _spec(
        "dns.encoded_name_count",
        _DNS,
        "count",
        "Names whose subdomain looks hex or base32 encoded rather than linguistic.",
    ),
    _spec(
        "dns.max_names_per_domain",
        _DNS,
        "count",
        "Most distinct subdomains queried under a single registrable domain. A "
        "tunnel generates a new one per request, because the name is the payload.",
    ),
    _spec(
        "dns.query_rate",
        _DNS,
        "rate",
        "Queries per second.",
        unit="/s",
    ),
    _spec(
        "dns.txt_query_ratio",
        _DNS,
        "ratio",
        "TXT queries over all queries. TXT carries more bytes back than A, which "
        "is why tunnels favour it.",
        range_hint="0.0-1.0",
    ),
    _spec(
        "dns.distinct_resolvers",
        _DNS,
        "count",
        "Distinct DNS servers this client used. More than one or two suggests the "
        "configured resolver is being bypassed.",
    ),
)


# --------------------------------------------------------------------------- #
# Capture metrics -- one subject for the whole capture.
# --------------------------------------------------------------------------- #

_CAPTURE_METRICS: tuple[MetricSpec, ...] = (
    _spec("capture.packets", _CAPTURE, "count", "Packets decoded."),
    _spec("capture.bytes", _CAPTURE, "bytes", "Bytes captured.", unit=" bytes"),
    _spec("capture.duration", _CAPTURE, "duration", "Capture span in seconds.", unit="s"),
    _spec("capture.distinct_hosts", _CAPTURE, "count", "Distinct IP addresses observed."),
    _spec("capture.distinct_flows", _CAPTURE, "count", "Distinct conversations observed."),
    _spec(
        "capture.cleartext_credential_packets",
        _CAPTURE,
        "count",
        "Packets anywhere in the capture carrying credential-shaped material.",
    ),
    _spec(
        "capture.decode_failure_ratio",
        _CAPTURE,
        "ratio",
        "Packets that failed to decode, over packets read. A high value means the "
        "findings rest on a partial view and should be read as such.",
        range_hint="0.0-1.0",
    ),
)


#: Every metric, keyed by fully-qualified name.
CATALOGUE: dict[str, MetricSpec] = {
    spec.name: spec
    for spec in (
        *_HOST_METRICS,
        *_FLOW_METRICS,
        *_PAIR_METRICS,
        *_DNS_METRICS,
        *_CAPTURE_METRICS,
    )
}


def lookup(name: str) -> MetricSpec | None:
    """Return the spec for ``name``, or ``None`` when it is not catalogued."""
    return CATALOGUE.get(name)


def is_known(name: str) -> bool:
    """True when ``name`` is a catalogued metric."""
    return name in CATALOGUE


def metrics_for_scope(scope: SubjectScope) -> tuple[MetricSpec, ...]:
    """Every metric available to subjects of ``scope``, in catalogue order."""
    return tuple(spec for spec in CATALOGUE.values() if spec.scope is scope)


def names_for_scope(scope: SubjectScope) -> tuple[str, ...]:
    """Metric names available to ``scope``, in catalogue order."""
    return tuple(spec.name for spec in metrics_for_scope(scope))


def suggest(name: str, limit: int = 3) -> tuple[str, ...]:
    """Catalogue names closest to ``name``, for "did you mean" on a typo.

    Uses stdlib fuzzy matching, then falls back to a suffix match so that
    ``host.syn_ratio`` still points at ``host.unanswered_syn_ratio`` even when
    the edit distance is too large.
    """
    from difflib import get_close_matches

    close = get_close_matches(name, CATALOGUE, n=limit, cutoff=0.6)
    if close:
        return tuple(close)

    _, _, short = name.partition(".")
    if not short:
        return ()
    return tuple(
        candidate for candidate in CATALOGUE if candidate.endswith(f".{short}")
    )[:limit]


def validate_reference(name: str, scope: SubjectScope) -> str | None:
    """Check that ``name`` exists and belongs to ``scope``.

    Returns ``None`` when the reference is valid, or a message explaining the
    problem. The rule loader turns that message into a load-time error, which is
    the whole point of having a catalogue: a rule referencing a metric that does
    not exist must fail loudly rather than evaluate to false forever.
    """
    spec = CATALOGUE.get(name)
    if spec is None:
        message = f"unknown metric {name!r}"
        hints = suggest(name)
        if hints:
            message += f" (did you mean {', '.join(repr(h) for h in hints)}?)"
        return message

    if spec.scope is not scope:
        return (
            f"metric {name!r} is measured at {spec.scope.value!r} scope "
            f"but the rule declares {scope.value!r} scope"
        )
    return None


__all__ = [
    "CATALOGUE",
    "MetricKind",
    "MetricSpec",
    "is_known",
    "lookup",
    "metrics_for_scope",
    "names_for_scope",
    "suggest",
    "validate_reference",
]
