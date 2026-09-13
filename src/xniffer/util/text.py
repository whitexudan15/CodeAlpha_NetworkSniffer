"""Pure text helpers: entropy, safe previews, and secret redaction.

This module deliberately has no xniffer imports -- it is the bottom of the
dependency graph and is trivially unit-testable.

The redaction pass here does double duty. It is primarily a *privacy* control:
xniffer never prints raw payload bytes unless the operator explicitly asks for
them, and credential material is masked even then. But the same pass reports
*which categories* of secret it masked, and the detection layer consumes that
signal to raise "credentials observed in cleartext" findings. One scan, two
purposes -- the privacy feature is what makes the detection possible.
"""

from __future__ import annotations

import math
import re
from collections import Counter
from dataclasses import dataclass, field

# --------------------------------------------------------------------------- #
# Entropy
# --------------------------------------------------------------------------- #


def shannon_entropy(data: bytes | str) -> float:
    """Return the Shannon entropy of ``data`` in bits per byte (0.0 - 8.0).

    Rough interpretation for network payloads:

    * ``< 3.0``  -- structured text (HTTP headers, plaintext protocols)
    * ``3.0-5.0`` -- mixed text, base64-ish, compressed text
    * ``> 6.5``  -- encrypted or compressed binary

    High entropy inside a protocol that is supposed to be cleartext is a
    classic tunneling indicator, which is why several detection rules read
    this value.
    """
    if isinstance(data, str):
        data = data.encode("utf-8", errors="replace")
    if not data:
        return 0.0
    counts = Counter(data)
    total = len(data)
    return -sum((c / total) * math.log2(c / total) for c in counts.values())


def normalized_entropy(data: bytes | str) -> float:
    """Return :func:`shannon_entropy` rescaled to the 0.0 - 1.0 range."""
    return shannon_entropy(data) / 8.0


# --------------------------------------------------------------------------- #
# Safe rendering
# --------------------------------------------------------------------------- #

_SAFE_CHARS = frozenset(range(0x20, 0x7F))


def printable_preview(data: bytes, limit: int = 96) -> str:
    """Render ``data`` as a single-line, printable-only preview.

    Bytes outside printable ASCII become ``.``; the result is truncated to
    ``limit`` characters with an ellipsis marker. This never returns control
    characters, so it is safe to drop straight into a terminal or a log line
    without worrying about ANSI escape injection from hostile traffic.
    """
    if not data:
        return ""
    chunk = data[:limit]
    text = "".join(chr(b) if b in _SAFE_CHARS else "." for b in chunk)
    if len(data) > limit:
        text += f"... (+{len(data) - limit} bytes)"
    return text


def hexdump(data: bytes, limit: int = 256, width: int = 16) -> str:
    """Return a classic offset/hex/ASCII dump of ``data``, capped at ``limit``."""
    if not data:
        return ""
    chunk = data[:limit]
    lines: list[str] = []
    for offset in range(0, len(chunk), width):
        row = chunk[offset : offset + width]
        hex_part = " ".join(f"{b:02x}" for b in row)
        hex_part = hex_part.ljust(width * 3 - 1)
        ascii_part = "".join(chr(b) if b in _SAFE_CHARS else "." for b in row)
        lines.append(f"{offset:08x}  {hex_part}  |{ascii_part}|")
    if len(data) > limit:
        lines.append(f"... {len(data) - limit} more bytes not shown")
    return "\n".join(lines)


def truncate(text: str, limit: int, marker: str = "...") -> str:
    """Truncate ``text`` to ``limit`` characters, appending ``marker``."""
    if len(text) <= limit:
        return text
    if limit <= len(marker):
        return marker[:limit]
    return text[: limit - len(marker)] + marker


def human_bytes(count: float) -> str:
    """Format a byte count as a short human-readable string (e.g. ``1.4 MB``)."""
    value = float(count)
    for unit in ("B", "KB", "MB", "GB", "TB"):
        if abs(value) < 1024.0 or unit == "TB":
            return f"{value:.0f} {unit}" if unit == "B" else f"{value:.1f} {unit}"
        value /= 1024.0
    return f"{value:.1f} TB"


def human_duration(seconds: float) -> str:
    """Format a duration in seconds as a short human-readable string."""
    if seconds < 1.0:
        return f"{seconds * 1000:.0f} ms"
    if seconds < 60.0:
        return f"{seconds:.1f} s"
    if seconds < 3600.0:
        minutes, secs = divmod(int(seconds), 60)
        return f"{minutes}m {secs}s"
    hours, remainder = divmod(int(seconds), 3600)
    minutes = remainder // 60
    return f"{hours}h {minutes}m"


# --------------------------------------------------------------------------- #
# Secret redaction
# --------------------------------------------------------------------------- #

# Each entry is (category, compiled pattern). Every pattern MUST define a named
# group called ``secret`` -- that group, and only that group, is masked, so the
# surrounding context stays readable for an analyst.
_SECRET_PATTERNS: tuple[tuple[str, re.Pattern[str]], ...] = (
    (
        "password",
        re.compile(
            r"(?i)\b(?:pass(?:word|wd)?|pwd|passphrase)\s*[=:]\s*(?P<secret>[^\s&;,\"'<>]{1,256})"
        ),
    ),
    (
        "api-key",
        re.compile(
            r"(?i)\b(?:api[_-]?key|apikey|client[_-]?secret|private[_-]?key)"
            r"\s*[=:]\s*(?P<secret>[^\s&;,\"'<>]{1,256})"
        ),
    ),
    (
        "token",
        re.compile(
            r"(?i)\b(?:access[_-]?token|auth[_-]?token|id[_-]?token|refresh[_-]?token|token)"
            r"\s*[=:]\s*(?P<secret>[^\s&;,\"'<>]{4,512})"
        ),
    ),
    (
        "http-authorization",
        re.compile(
            r"(?i)\bauthorization\s*:\s*(?:basic|bearer|digest|negotiate|ntlm)\s+"
            r"(?P<secret>[^\r\n]{1,1024})"
        ),
    ),
    (
        "http-cookie",
        re.compile(r"(?i)\b(?:set-)?cookie\s*:\s*(?P<secret>[^\r\n]{1,1024})"),
    ),
    (
        "ftp-credentials",
        re.compile(r"(?im)^\s*(?:USER|PASS|ACCT)\s+(?P<secret>[^\r\n]{1,256})"),
    ),
    (
        "smtp-auth",
        re.compile(r"(?im)^\s*AUTH\s+(?:LOGIN|PLAIN|CRAM-MD5)\s+(?P<secret>[^\r\n]{1,512})"),
    ),
    (
        "pan",  # Primary Account Number -- card-like digit runs.
        re.compile(r"(?<![\d.])(?P<secret>\d{13,19})(?![\d.])"),
    ),
    (
        "private-key-block",
        re.compile(r"(?P<secret>-----BEGIN (?:RSA |EC |OPENSSH |PGP )?PRIVATE KEY-----)"),
    ),
)


@dataclass(frozen=True, slots=True)
class RedactionResult:
    """Outcome of a redaction pass over a text payload."""

    text: str
    """The payload with every detected secret replaced by a masked marker."""

    categories: tuple[str, ...] = ()
    """Sorted, de-duplicated categories of secret that were masked."""

    count: int = 0
    """Total number of individual secrets masked."""

    @property
    def found_secrets(self) -> bool:
        """True when at least one secret was masked."""
        return self.count > 0


def redact_secrets(text: str) -> RedactionResult:
    """Mask credential material in ``text`` and report what was found.

    Masked values are replaced with ``<redacted:CATEGORY:N>`` where ``N`` is
    the length of the original value. The length is intentionally preserved --
    it is useful evidence ("a 64-character bearer token crossed the wire in
    cleartext") and it leaks nothing about the value itself.

    This is heuristic and pattern-based. It is a strong default, not a
    guarantee; treat any capture of real traffic as sensitive regardless.
    """
    if not text:
        return RedactionResult(text="", categories=(), count=0)

    found: Counter[str] = Counter()
    redacted = text

    for category, pattern in _SECRET_PATTERNS:

        def _mask(match: re.Match[str], _category: str = category) -> str:
            secret = match.group("secret")
            found[_category] += 1
            start, end = match.span("secret")
            whole_start = match.start()
            prefix = match.group(0)[: start - whole_start]
            suffix = match.group(0)[end - whole_start :]
            return f"{prefix}<redacted:{_category}:{len(secret)}>{suffix}"

        redacted = pattern.sub(_mask, redacted)

    return RedactionResult(
        text=redacted,
        categories=tuple(sorted(found)),
        count=sum(found.values()),
    )


@dataclass(slots=True)
class SecretTally:
    """Accumulates redaction categories across many payloads.

    Used by the analysis layer to answer "did any cleartext credential
    material appear on this flow?" without retaining the secrets themselves.
    """

    categories: Counter[str] = field(default_factory=Counter)
    packet_indices: list[int] = field(default_factory=list)

    def record(self, result: RedactionResult, packet_index: int, max_indices: int = 32) -> None:
        """Fold one redaction result into the tally."""
        if not result.found_secrets:
            return
        for category in result.categories:
            self.categories[category] += 1
        if len(self.packet_indices) < max_indices:
            self.packet_indices.append(packet_index)

    @property
    def total(self) -> int:
        """Total number of secrets seen."""
        return sum(self.categories.values())

    @property
    def sorted_categories(self) -> tuple[str, ...]:
        """Categories seen, most frequent first."""
        return tuple(name for name, _ in self.categories.most_common())


__all__ = [
    "RedactionResult",
    "SecretTally",
    "hexdump",
    "human_bytes",
    "human_duration",
    "normalized_entropy",
    "printable_preview",
    "redact_secrets",
    "shannon_entropy",
    "truncate",
]
