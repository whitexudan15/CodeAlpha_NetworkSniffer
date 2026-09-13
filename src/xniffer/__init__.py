"""xniffer -- a modular network traffic analyzer.

xniffer captures network traffic, decodes it into protocol-agnostic records,
analyzes those records with bounded in-memory state, and turns the result into
*explainable security findings*: every finding carries the packet indices that
produced it, the values that matched, and the reasons it might be a false
positive.

The package is layered, and each layer only depends on the ones above it::

    model/    frozen dataclasses -- the contract every other layer speaks
    util/     pure helpers (entropy, redaction, IP/port classification)
    capture/  the ONLY place Scapy is imported; yields PacketRecord objects
    decode/   protocol decoders, pure field-dict producers
    analyze/  bounded stateful trackers (flows, hosts, DNS, time windows)
    detect/   YAML-driven rule engine producing Finding objects
    report/   rich terminal, JSONL and Markdown renderers
    cli/      Typer command-line entry points

Keeping Scapy behind ``capture/`` means the analysis and detection layers can
be unit-tested without a network interface, without root, and without pcap
files -- you build ``PacketRecord`` objects directly.
"""

from __future__ import annotations

__version__ = "0.1.0"

__all__ = ["__version__"]
