"""Analysis -- turning decoded packets into measured subjects.

This layer holds every stateful tracker: the flow table, host profiles, the DNS
map, host-pair timing. It decides nothing about what is suspicious. It measures,
names its measurements from :mod:`xniffer.analyze.metrics`, and hands
:class:`~xniffer.analyze.subject.Subject` objects to the detection layer.

All state here is bounded. Trackers keep counters, capped evidence indices and
capped timestamp rings -- never packets. A capture running for hours has a
memory ceiling.
"""

from __future__ import annotations

from xniffer.analyze.metrics import (
    CATALOGUE,
    MetricSpec,
    is_known,
    lookup,
    metrics_for_scope,
    names_for_scope,
    suggest,
    validate_reference,
)
from xniffer.analyze.subject import MetricValue, Subject, SubjectScope

__all__ = [
    "CATALOGUE",
    "MetricSpec",
    "MetricValue",
    "Subject",
    "SubjectScope",
    "is_known",
    "lookup",
    "metrics_for_scope",
    "names_for_scope",
    "suggest",
    "validate_reference",
]
