"""The decoder contract.

A decoder is a pure function that looks at a Scapy packet and returns the
subset of :class:`~xniffer.model.packet.PacketRecord` fields it understands --
or ``None`` when the packet is not its business::

    def decode_dns(packet, ctx) -> dict[str, Any] | None: ...

Decoders never construct records, never mutate shared state, and never depend
on each other's ordering. The pipeline runs every registered decoder over a
packet and folds the contributions together with
:class:`~xniffer.model.packet.PacketFields`. Two consequences follow:

* A decoder can be tested with three lines and one crafted packet.
* A decoder that raises does not take the capture down with it -- the failure
  is recorded on the record's ``decode_errors`` and the rest still runs.

That second property matters more than it looks. Packet decoding runs on
attacker-influenced input, and malformed frames are routine even without an
adversary. A capture tool that aborts on the first unparseable byte is useless
on exactly the traffic you most want to look at.
"""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass
from typing import Any

from xniffer.model.enums import RedactionMode
from xniffer.model.packet import PREVIEW_LIMIT


@dataclass(frozen=True, slots=True)
class DecodeContext:
    """Options a decoder may need, passed to every decoder call."""

    redaction: RedactionMode = RedactionMode.REDACTED
    """Payload retention policy -- pass through to ``PayloadInfo.from_bytes``."""

    preview_limit: int = PREVIEW_LIMIT
    """How many payload bytes to keep for display."""

    decode_payloads: bool = True
    """When false, skip payload extraction entirely for speed."""


#: The signature every decoder implements.
DecoderFn = Callable[[Any, DecodeContext], "dict[str, Any] | None"]


@dataclass(frozen=True, slots=True)
class Decoder:
    """A registered decoder: a name, a function, and an ordering priority."""

    name: str
    fn: DecoderFn
    priority: int = 100
    """Lower runs earlier. Link-layer decoders run before application ones so
    that a later, more specific decoder's fields win on collision."""

    def __call__(self, packet: Any, ctx: DecodeContext) -> dict[str, Any] | None:
        """Invoke the underlying decoder function."""
        return self.fn(packet, ctx)


class DecoderRegistry:
    """An ordered collection of decoders.

    Third-party packages can extend decoding by registering here, which is how
    a site adds support for an internal protocol without forking xniffer.
    """

    def __init__(self) -> None:
        self._decoders: list[Decoder] = []

    def register(self, name: str, fn: DecoderFn, priority: int = 100) -> None:
        """Add a decoder, keeping the registry sorted by priority."""
        self._decoders.append(Decoder(name=name, fn=fn, priority=priority))
        self._decoders.sort(key=lambda decoder: (decoder.priority, decoder.name))

    def __iter__(self):
        """Iterate decoders in execution order."""
        return iter(self._decoders)

    def __len__(self) -> int:
        return len(self._decoders)

    @property
    def names(self) -> tuple[str, ...]:
        """Registered decoder names, in execution order."""
        return tuple(decoder.name for decoder in self._decoders)


__all__ = [
    "DecodeContext",
    "Decoder",
    "DecoderFn",
    "DecoderRegistry",
]
