"""Capture provenance -- the record of where a capture came from.

Every analysis xniffer produces carries one of these. It answers the questions
that come up when a capture is used as evidence, or simply when someone finds a
findings file three weeks later: which interface, which filter, how long, under
what authority, and with what redaction policy.

The :attr:`CaptureProvenance.authorized_by` field is deliberately prominent.
Packet capture on a network you do not own is unlawful in most jurisdictions,
and the honest way to build a capture tool is to make recording the
authorisation a normal part of using it -- not to bury a warning in a README.
"""

from __future__ import annotations

import getpass
import platform
import socket
from dataclasses import dataclass, field
from typing import Any

from xniffer.model._serde import jsonify
from xniffer.model.enums import RedactionMode, SourceType
from xniffer.util.text import human_duration


def _current_operator() -> str:
    """Best-effort ``user@host`` for the account running the capture."""
    try:
        user = getpass.getuser()
    except Exception:  # pragma: no cover - depends on a broken environment
        user = "unknown"
    try:
        host = socket.gethostname()
    except Exception:  # pragma: no cover - depends on a broken environment
        host = "unknown"
    return f"{user}@{host}"


@dataclass(slots=True)
class CaptureProvenance:
    """Metadata describing one capture or one pcap read."""

    source: str
    """Interface name for a live capture, or the file path for a pcap."""

    source_type: SourceType
    xniffer_version: str

    started_at: float = 0.0
    ended_at: float = 0.0

    packets_read: int = 0
    """Packets pulled from the source."""

    packets_decoded: int = 0
    """Packets that produced a usable record."""

    decode_failures: int = 0
    """Packets that could not be decoded at all."""

    bytes_read: int = 0

    bpf_filter: str | None = None
    """The kernel-level BPF filter, when one was applied."""

    snaplen: int | None = None
    promiscuous: bool = False
    redaction: RedactionMode = RedactionMode.REDACTED

    operator: str = field(default_factory=_current_operator)
    """Who ran the capture, as ``user@host``."""

    authorized_by: str | None = None
    """Free-text note recording who authorised this capture, if provided.

    xniffer never verifies this -- it cannot. Recording it makes the question
    part of the workflow, and gives the resulting evidence a chain of custody.
    """

    platform: str = field(default_factory=lambda: f"{platform.system()} {platform.release()}")
    notes: tuple[str, ...] = ()

    # -- derived views ----------------------------------------------------- #

    @property
    def duration(self) -> float:
        """Capture duration in seconds."""
        return max(0.0, self.ended_at - self.started_at)

    @property
    def is_live(self) -> bool:
        """True when this came from a network interface rather than a file."""
        return self.source_type is SourceType.LIVE

    @property
    def packets_per_second(self) -> float:
        """Average capture rate, or 0.0 when the duration is unmeasurable."""
        return self.packets_read / self.duration if self.duration > 0 else 0.0

    @property
    def decode_success_rate(self) -> float:
        """Fraction of read packets that decoded successfully, 0.0-1.0."""
        return self.packets_decoded / self.packets_read if self.packets_read else 0.0

    def summary_lines(self) -> list[str]:
        """Render provenance as aligned ``label: value`` lines for reports."""
        rows: list[tuple[str, str]] = [
            ("source", f"{self.source} ({self.source_type.value})"),
            ("packets", f"{self.packets_read} read, {self.packets_decoded} decoded"),
            ("duration", human_duration(self.duration) if self.duration else "-"),
            ("redaction", self.redaction.value),
            ("operator", self.operator),
            ("xniffer", self.xniffer_version),
        ]
        if self.bpf_filter:
            rows.insert(1, ("filter", self.bpf_filter))
        if self.decode_failures:
            rows.append(("decode failures", str(self.decode_failures)))
        if self.authorized_by:
            rows.append(("authorized by", self.authorized_by))

        width = max(len(label) for label, _ in rows)
        return [f"{label.ljust(width)}  {value}" for label, value in rows]

    def to_dict(self) -> dict[str, Any]:
        """Serialise for JSON output."""
        data = jsonify(self)
        data["duration"] = round(self.duration, 6)
        data["packets_per_second"] = round(self.packets_per_second, 2)
        return data


__all__ = ["CaptureProvenance"]
