"""Shared serialisation helper for the model layer.

Every model object exposes ``to_dict()`` so it can be written to JSONL and
consumed by other tools. Rather than reimplement the conversion in each class,
they all delegate to :func:`jsonify`, which understands the handful of types
the model actually uses: dataclasses, enums, tuples, sets and scalars.
"""

from __future__ import annotations

import dataclasses
from collections.abc import Mapping, Sequence
from enum import Enum
from typing import Any


def jsonify(value: Any, *, drop_none: bool = True) -> Any:
    """Recursively convert ``value`` into JSON-serialisable primitives.

    ``drop_none`` removes keys whose value is ``None``. Packet records have
    many optional fields -- an ARP frame has no TCP ports, a DNS response has
    no TLS handshake -- and emitting a wall of ``null`` for every one of them
    would triple the size of the JSONL output for no benefit.
    """
    if value is None:
        return None
    if isinstance(value, Enum):
        return value.value
    if dataclasses.is_dataclass(value) and not isinstance(value, type):
        result: dict[str, Any] = {}
        for field in dataclasses.fields(value):
            converted = jsonify(getattr(value, field.name), drop_none=drop_none)
            if drop_none and converted is None:
                continue
            if drop_none and converted == () or (drop_none and converted == []):
                continue
            result[field.name] = converted
        return result
    if isinstance(value, Mapping):
        return {
            str(key): jsonify(item, drop_none=drop_none)
            for key, item in value.items()
            if not (drop_none and item is None)
        }
    if isinstance(value, (set, frozenset)):
        return sorted(jsonify(item, drop_none=drop_none) for item in value)
    if isinstance(value, Sequence) and not isinstance(value, (str, bytes, bytearray)):
        return [jsonify(item, drop_none=drop_none) for item in value]
    if isinstance(value, (bytes, bytearray)):
        return value.hex()
    if isinstance(value, float):
        # Keep floats readable in JSON output; network timings do not need
        # seventeen significant digits.
        return round(value, 6)
    return value


__all__ = ["jsonify"]
