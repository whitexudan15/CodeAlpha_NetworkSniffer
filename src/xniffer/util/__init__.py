"""Pure, dependency-free helpers shared by every xniffer layer."""

from __future__ import annotations

from xniffer.util.net import (
    DomainProfile,
    classify_ip,
    cleartext_service,
    describe_port,
    is_global_ip,
    is_private_ip,
    is_syn_ack,
    is_syn_only,
    port_service,
    profile_domain,
    tcp_flag_names,
)
from xniffer.util.text import (
    RedactionResult,
    SecretTally,
    hexdump,
    human_bytes,
    human_duration,
    printable_preview,
    redact_secrets,
    shannon_entropy,
    truncate,
)

__all__ = [
    "DomainProfile",
    "RedactionResult",
    "SecretTally",
    "classify_ip",
    "cleartext_service",
    "describe_port",
    "hexdump",
    "human_bytes",
    "human_duration",
    "is_global_ip",
    "is_private_ip",
    "is_syn_ack",
    "is_syn_only",
    "port_service",
    "printable_preview",
    "profile_domain",
    "redact_secrets",
    "shannon_entropy",
    "tcp_flag_names",
    "truncate",
]
