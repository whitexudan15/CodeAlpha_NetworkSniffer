"""Detection -- declarative rules over measured subjects.

Rules live in YAML, are validated against the metric catalogue at load time,
and produce :class:`~xniffer.model.finding.Finding` objects that cite the
packets and thresholds behind them.
"""

from __future__ import annotations

from xniffer.detect.rule import OPERATORS, Condition, RuleSpec, compare, parse_rule

__all__ = [
    "OPERATORS",
    "Condition",
    "RuleSpec",
    "compare",
    "parse_rule",
]
