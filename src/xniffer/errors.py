"""Exception hierarchy for xniffer.

Every error raised deliberately by xniffer derives from :class:`XnifferError`,
so a caller (or the CLI) can catch that single base class and be sure it is
handling an xniffer problem rather than swallowing an unrelated bug.

The CLI maps these onto distinct exit codes -- see ``xniffer.cli``.
"""

from __future__ import annotations


class XnifferError(Exception):
    """Base class for all errors raised by xniffer."""

    exit_code = 1


class CaptureError(XnifferError):
    """Raised when traffic cannot be captured."""

    exit_code = 3


class PermissionDeniedError(CaptureError):
    """Raised when live capture is attempted without sufficient privileges.

    Packet capture needs ``CAP_NET_RAW``. The CLI turns this into an
    actionable message rather than a bare ``PermissionError`` traceback.
    """

    exit_code = 4


class InterfaceNotFoundError(CaptureError):
    """Raised when the requested network interface does not exist."""

    exit_code = 5


class CaptureFileError(CaptureError):
    """Raised when a pcap file is missing, unreadable, or not a capture file."""

    exit_code = 6


class DecodeError(XnifferError):
    """Raised when a packet cannot be decoded.

    Decoding is best-effort: the pipeline records the failure on the
    ``PacketRecord`` and moves on rather than aborting a whole capture because
    of one malformed frame.
    """

    exit_code = 7


class RuleError(XnifferError):
    """Base class for problems with detection rules."""

    exit_code = 8


class RuleLoadError(RuleError):
    """Raised when a rule file is malformed or fails schema validation."""


class RuleEvaluationError(RuleError):
    """Raised when a rule's condition cannot be evaluated."""


class ReportError(XnifferError):
    """Raised when a report cannot be produced or written."""

    exit_code = 9


class ConfigurationError(XnifferError):
    """Raised when user-supplied configuration is invalid."""

    exit_code = 2


__all__ = [
    "CaptureError",
    "CaptureFileError",
    "ConfigurationError",
    "DecodeError",
    "InterfaceNotFoundError",
    "PermissionDeniedError",
    "ReportError",
    "RuleError",
    "RuleEvaluationError",
    "RuleLoadError",
    "XnifferError",
]
