"""Decoding -- Scapy packets into plain field dictionaries.

Decoders are pure functions registered against a
:class:`~xniffer.decode.base.DecoderRegistry`. The pipeline runs each one over a
packet and folds the results together, so a decoder never sees another
decoder's output and a decoder that raises cannot take the capture down.
"""

from __future__ import annotations

from xniffer.decode.base import DecodeContext, Decoder, DecoderFn, DecoderRegistry

__all__ = [
    "DecodeContext",
    "Decoder",
    "DecoderFn",
    "DecoderRegistry",
]
