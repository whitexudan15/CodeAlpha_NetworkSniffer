"""The xniffer data model -- the contract every other layer speaks.

Import from here rather than from the individual modules::

    from xniffer.model import PacketRecord, Finding, Severity

Everything in this package is a plain dataclass with no dependency on Scapy,
Typer, Rich or the network. That is what makes the analysis and detection
layers testable in isolation.
"""

from __future__ import annotations

from xniffer.model.enums import (
    Confidence,
    Direction,
    FindingStatus,
    RedactionMode,
    Severity,
    SourceType,
    TcpState,
)
from xniffer.model.finding import (
    AttackTechnique,
    Evidence,
    Finding,
    assign_ids,
    sort_findings,
)
from xniffer.model.flow import Flow, FlowKey
from xniffer.model.packet import (
    ArpInfo,
    DnsAnswer,
    DnsInfo,
    DnsQuestion,
    HttpInfo,
    IcmpInfo,
    PacketFields,
    PacketRecord,
    PayloadInfo,
    TlsInfo,
)
from xniffer.model.provenance import CaptureProvenance

__all__ = [
    "ArpInfo",
    "AttackTechnique",
    "CaptureProvenance",
    "Confidence",
    "Direction",
    "DnsAnswer",
    "DnsInfo",
    "DnsQuestion",
    "Evidence",
    "Finding",
    "FindingStatus",
    "Flow",
    "FlowKey",
    "HttpInfo",
    "IcmpInfo",
    "PacketFields",
    "PacketRecord",
    "PayloadInfo",
    "RedactionMode",
    "Severity",
    "SourceType",
    "TcpState",
    "TlsInfo",
    "assign_ids",
    "sort_findings",
]
