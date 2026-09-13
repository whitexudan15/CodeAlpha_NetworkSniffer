"""Enumerations shared across the whole pipeline.

These are part of the public contract: rule files reference severity and
confidence by name, the JSONL output serialises them by value, and the
renderers switch on them. Keeping them in one module means a rule author, a
downstream JSON consumer and the terminal renderer all agree on the vocabulary.

Note that no presentation concern (colour, icon, ordering in a table) lives
here. That belongs to ``xniffer.report`` -- the model stays renderer-agnostic.
"""

from __future__ import annotations

from enum import Enum, IntEnum


class Severity(IntEnum):
    """How much attention a finding deserves.

    Ordered, so callers can filter with a comparison::

        [f for f in findings if f.severity >= Severity.MEDIUM]

    Severity answers "how bad would this be if the benign explanation is
    wrong". It is an analytical judgement about impact, not a claim that an
    attack occurred -- see :class:`Confidence` for the other axis.
    """

    INFO = 0
    LOW = 1
    MEDIUM = 2
    HIGH = 3
    CRITICAL = 4

    @property
    def label(self) -> str:
        """The uppercase name, as it appears in reports and rule files."""
        return self.name

    @classmethod
    def parse(cls, value: str | int | Severity) -> Severity:
        """Coerce a rule-file string, an int, or a Severity into a Severity.

        Raises :class:`ValueError` with the list of valid names, because this
        runs against user-authored YAML and the error text is the only
        feedback a rule author gets.
        """
        if isinstance(value, cls):
            return value
        if isinstance(value, int) and not isinstance(value, bool):
            try:
                return cls(value)
            except ValueError:
                raise ValueError(
                    f"invalid severity {value!r}; expected 0-4"
                ) from None
        if isinstance(value, str):
            try:
                return cls[value.strip().upper()]
            except KeyError:
                valid = ", ".join(member.name for member in cls)
                raise ValueError(
                    f"invalid severity {value!r}; expected one of: {valid}"
                ) from None
        raise ValueError(f"invalid severity {value!r}")


class Confidence(IntEnum):
    """How sure xniffer is that the observation means what the rule says.

    This is the second axis, and it is what keeps xniffer honest. A rule can
    legitimately say "if this is real it is CRITICAL, but I am only LOW
    confidence that it is real" -- which is very different from a tool that
    prints a single blended score and lets the reader assume certainty.
    """

    LOW = 0
    MEDIUM = 1
    HIGH = 2

    @property
    def label(self) -> str:
        """The uppercase name, as it appears in reports and rule files."""
        return self.name

    @classmethod
    def parse(cls, value: str | int | Confidence) -> Confidence:
        """Coerce a rule-file string, an int, or a Confidence into a Confidence."""
        if isinstance(value, cls):
            return value
        if isinstance(value, int) and not isinstance(value, bool):
            try:
                return cls(value)
            except ValueError:
                raise ValueError(f"invalid confidence {value!r}; expected 0-2") from None
        if isinstance(value, str):
            try:
                return cls[value.strip().upper()]
            except KeyError:
                valid = ", ".join(member.name for member in cls)
                raise ValueError(
                    f"invalid confidence {value!r}; expected one of: {valid}"
                ) from None
        raise ValueError(f"invalid confidence {value!r}")


class RedactionMode(str, Enum):
    """How much of a packet payload xniffer is allowed to retain and show.

    The default is :attr:`REDACTED`, not :attr:`FULL`. Capturing traffic means
    handling other people's data, and a tool that dumps raw bytes by default
    makes it easy to leak credentials into a terminal history, a screenshot or
    a bug report. Choosing to see the real bytes should be a deliberate act.
    """

    NONE = "none"
    """Discard payload content entirely; keep only length and digest."""

    REDACTED = "redacted"
    """Default. Keep a printable preview with credential material masked."""

    FULL = "full"
    """Keep the printable preview unmasked. Requires an explicit opt-in."""

    @classmethod
    def parse(cls, value: str | RedactionMode) -> RedactionMode:
        """Coerce a CLI string into a RedactionMode."""
        if isinstance(value, cls):
            return value
        try:
            return cls(str(value).strip().lower())
        except ValueError:
            valid = ", ".join(member.value for member in cls)
            raise ValueError(
                f"invalid redaction mode {value!r}; expected one of: {valid}"
            ) from None


class SourceType(str, Enum):
    """Where a capture came from."""

    LIVE = "live"
    """Read from a network interface in real time."""

    PCAP = "pcap"
    """Read from a capture file on disk."""


class Direction(str, Enum):
    """Which way a packet travelled within its flow.

    A :class:`~xniffer.model.flow.FlowKey` canonicalises the two endpoints into
    a fixed ``A``/``B`` order so both directions hash to the same flow. This
    enum records which of those two endpoints actually sent a given packet.
    """

    A_TO_B = "a_to_b"
    B_TO_A = "b_to_a"

    @property
    def reversed(self) -> Direction:
        """The opposite direction."""
        return Direction.B_TO_A if self is Direction.A_TO_B else Direction.A_TO_B


class TcpState(str, Enum):
    """A deliberately coarse view of a TCP conversation's progress.

    This is not a conformant TCP state machine, and does not try to be. It
    captures the handful of distinctions that matter for detection: did anyone
    answer, did the connection get refused, did it complete and close.
    """

    NEW = "new"
    """A SYN was seen; nothing has answered yet."""

    SYN_SENT = "syn_sent"
    """One or more SYNs sent, still unanswered."""

    ESTABLISHED = "established"
    """The handshake was answered -- a real service is listening."""

    REFUSED = "refused"
    """The peer answered with RST -- the port is closed."""

    CLOSING = "closing"
    """A FIN was seen; the conversation is winding down."""

    CLOSED = "closed"
    """The conversation finished cleanly."""

    RESET = "reset"
    """An established conversation was torn down with RST."""

    UNKNOWN = "unknown"
    """Not a TCP flow, or the handshake was never observed."""


class FindingStatus(str, Enum):
    """Triage state of a finding, for downstream workflow tools.

    xniffer itself always emits :attr:`NEW`. The field exists so that a SOAR
    pipeline or an analyst's notes can round-trip through the JSONL format
    without inventing a parallel schema.
    """

    NEW = "new"
    CONFIRMED = "confirmed"
    BENIGN = "benign"
    SUPPRESSED = "suppressed"


__all__ = [
    "Confidence",
    "Direction",
    "FindingStatus",
    "RedactionMode",
    "Severity",
    "SourceType",
    "TcpState",
]
