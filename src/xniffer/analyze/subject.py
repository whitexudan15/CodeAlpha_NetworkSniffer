"""Subjects -- the hand-off between analysis and detection.

The analysis layer does not decide what is suspicious. It measures, and it
publishes those measurements as :class:`Subject` objects: "here is host
10.0.0.15, here are forty named numbers about it, and here are the packet
indices behind them". The detection layer then compares those numbers against
thresholds declared in YAML.

Splitting it this way is what makes the rules declarative. A rule author never
writes a loop over packets; they write ``host.unanswered_syn_ratio >= 0.8`` and
the engine resolves it. And because every metric has a name from a published
catalogue (see :mod:`xniffer.analyze.metrics`), a typo in a rule is a load-time
error instead of a rule that silently never fires.
"""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass, field
from enum import Enum
from typing import Any

from xniffer.model._serde import jsonify

#: The value types a metric may hold. Kept narrow on purpose: everything here
#: must be comparable against a literal written in a YAML file.
MetricValue = int | float | str | bool


class SubjectScope(str, Enum):
    """What a subject describes.

    Scope determines which metrics are available and, for a rule, what "one
    finding" means -- per host, per conversation, per host pair, or one for the
    whole capture.
    """

    HOST = "host"
    """A single IP address, aggregating everything it did."""

    FLOW = "flow"
    """One conversation between two endpoints."""

    HOST_PAIR = "pair"
    """All traffic between a source and destination, across many connections.

    This is the scope beaconing needs: an implant that opens a fresh
    connection every sixty seconds looks unremarkable at flow scope and
    obvious at pair scope.
    """

    DNS = "dns"
    """A client's DNS behaviour, aggregated across its queries."""

    CAPTURE = "capture"
    """The capture as a whole."""


@dataclass(frozen=True, slots=True)
class Subject:
    """A named thing plus everything measured about it."""

    scope: SubjectScope
    entity: str
    """The identifier -- an IP, a flow label, a ``src -> dst`` pair."""

    metrics: Mapping[str, MetricValue] = field(default_factory=dict)
    """Measurements, keyed by fully-qualified catalogue name."""

    context: Mapping[str, str] = field(default_factory=dict)
    """Ordered human-readable detail, copied into any finding's context."""

    packet_ids: tuple[int, ...] = ()
    """Representative capture indices, for citing as evidence."""

    first_seen: float = 0.0
    last_seen: float = 0.0

    extras: Mapping[str, Any] = field(default_factory=dict)
    """Non-comparable detail a renderer may want but a rule cannot match on."""

    @property
    def duration(self) -> float:
        """Seconds spanned by this subject's activity."""
        return max(0.0, self.last_seen - self.first_seen)

    def metric(self, name: str, default: MetricValue = 0) -> MetricValue:
        """Look up a metric, returning ``default`` when it was not measured."""
        return self.metrics.get(name, default)

    def has_metric(self, name: str) -> bool:
        """True when ``name`` was measured for this subject."""
        return name in self.metrics

    def to_dict(self) -> dict[str, Any]:
        """Serialise for JSON output."""
        return {
            "scope": self.scope.value,
            "entity": self.entity,
            "metrics": jsonify(dict(self.metrics)),
            "context": dict(self.context),
            "packet_ids": list(self.packet_ids),
            "first_seen": round(self.first_seen, 6),
            "last_seen": round(self.last_seen, 6),
        }


__all__ = ["MetricValue", "Subject", "SubjectScope"]
