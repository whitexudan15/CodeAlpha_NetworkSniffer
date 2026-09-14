"""The rule schema -- what a YAML detection rule is allowed to say.

A rule is a declaration, not code. It names the metrics it cares about, the
thresholds they must cross, and the sentences a human should read when it fires::

    id: port-scan-vertical
    version: 1
    title: Vertical port scan
    scope: host
    severity: high
    confidence: medium
    conditions:
      - metric: host.max_ports_on_single_peer
        op: ">="
        value: 20
      - metric: host.failed_connection_ratio
        op: ">="
        value: 0.7
    reason: >
      {entity} attempted {host.max_ports_on_single_peer} distinct ports on a
      single host, and {host.failed_connection_ratio} of those attempts failed.
    false_positive_notes:
      - Vulnerability scanners and asset-inventory tools produce this pattern.
    attack:
      - id: T1046
        name: Network Service Discovery
        tactic: Discovery

Three properties of this schema are deliberate.

**Every condition carries its threshold into the finding.** The engine does not
just decide true or false; it records "measured 34, threshold 20" as evidence.
That is what lets a reader judge a finding instead of trusting it.

**Every rule must declare false-positive notes.** Loading fails without them.
Network behaviour is genuinely ambiguous -- backup jobs look like exfiltration,
monitoring agents look like beacons -- and a rule whose author could not name a
benign explanation has usually not thought hard enough about the detection.

**Metric references are validated at load time** against
:mod:`xniffer.analyze.metrics`. A typo is an error, never a rule that silently
never fires.
"""

from __future__ import annotations

import re
from collections.abc import Mapping, Sequence
from dataclasses import dataclass, field
from typing import Any

from xniffer.analyze.metrics import validate_reference
from xniffer.analyze.subject import MetricValue, Subject, SubjectScope
from xniffer.errors import RuleLoadError
from xniffer.model.enums import Confidence, Severity
from xniffer.model.finding import AttackTechnique

#: Comparison operators a condition may use.
#:
#: Deliberately small. Anything a rule cannot express here belongs in the
#: analysis layer as a new named metric -- that keeps the measurement testable
#: and gives every rule author the same vocabulary, instead of letting rules
#: grow their own private arithmetic.
OPERATORS: dict[str, str] = {
    ">=": "at least",
    ">": "more than",
    "<=": "at most",
    "<": "less than",
    "==": "exactly",
    "!=": "not",
    "in": "one of",
    "not_in": "none of",
    "contains": "contains",
    "matches": "matches pattern",
}

#: ``{metric.name}`` placeholders inside a template string.
_PLACEHOLDER = re.compile(r"\{([a-z_][a-z0-9_.]*)\}")


@dataclass(frozen=True, slots=True)
class Condition:
    """One metric compared against one threshold."""

    metric: str
    op: str
    value: Any

    label: str = ""
    """Evidence label shown in the finding. Defaults to the metric's short name."""

    def evaluate(self, subject: Subject) -> bool:
        """Test this condition against a subject's measurements.

        A subject missing the metric fails the condition rather than raising:
        not every host has DNS metrics, and a rule should simply not fire there.
        """
        if not subject.has_metric(self.metric):
            return False
        return compare(subject.metric(self.metric), self.op, self.value)

    def describe(self) -> str:
        """Render as ``host.syn_rate at least 20`` for rule listings."""
        return f"{self.metric} {OPERATORS.get(self.op, self.op)} {self.value}"


def compare(measured: MetricValue, op: str, threshold: Any) -> bool:
    """Apply one operator, returning False on a type mismatch rather than raising.

    A rule comparing a string metric with ``>=`` is an authoring bug, but it must
    not crash a capture mid-run. The loader catches what it can up front; this is
    the backstop for what it cannot.
    """
    try:
        match op:
            case ">=":
                return measured >= threshold  # type: ignore[operator]
            case ">":
                return measured > threshold  # type: ignore[operator]
            case "<=":
                return measured <= threshold  # type: ignore[operator]
            case "<":
                return measured < threshold  # type: ignore[operator]
            case "==":
                return measured == threshold
            case "!=":
                return measured != threshold
            case "in":
                return measured in threshold  # type: ignore[operator]
            case "not_in":
                return measured not in threshold  # type: ignore[operator]
            case "contains":
                return str(threshold) in str(measured)
            case "matches":
                return re.search(str(threshold), str(measured)) is not None
            case _:
                return False
    except (TypeError, ValueError, re.error):
        return False


@dataclass(frozen=True, slots=True)
class RuleSpec:
    """A complete detection rule, as loaded from YAML."""

    id: str
    title: str
    scope: SubjectScope
    severity: Severity
    confidence: Confidence
    conditions: tuple[Condition, ...]

    version: int = 1
    """Bumped when thresholds change, so a finding records which version fired."""

    reason: str = ""
    """Template for the finding's one-paragraph explanation. ``{metric.name}``
    placeholders are substituted with measured values."""

    description: str = ""
    """What the rule looks for, for ``xniffer rules list``."""

    recommendation: str = ""
    """What an analyst should do next."""

    false_positive_notes: tuple[str, ...] = ()
    """Benign explanations this rule cannot rule out. Required, not optional."""

    attack: tuple[AttackTechnique, ...] = ()
    """MITRE ATT&CK techniques this behaviour maps to."""

    context_metrics: tuple[str, ...] = ()
    """Extra metrics to attach as context, beyond those in the conditions."""

    tags: tuple[str, ...] = ()
    enabled: bool = True
    source: str = ""
    """Where the rule came from -- a file path or a plugin name."""

    metadata: Mapping[str, Any] = field(default_factory=dict)

    # -- evaluation -------------------------------------------------------- #

    def matches(self, subject: Subject) -> bool:
        """True when the subject satisfies every condition.

        Conditions are ANDed. Rules needing OR are written as two rules, which
        keeps each one's evidence honest: a finding then cites the thresholds
        that actually fired, not a disjunction the reader has to untangle.
        """
        if not self.enabled or subject.scope is not self.scope:
            return False
        return all(condition.evaluate(subject) for condition in self.conditions)

    def render(self, template: str, subject: Subject) -> str:
        """Substitute ``{metric.name}`` placeholders with measured values.

        ``{entity}`` resolves to the subject's identifier. Unknown placeholders
        are left untouched -- a malformed template should produce an odd
        sentence, not an exception during a capture.
        """

        def substitute(match: re.Match[str]) -> str:
            name = match.group(1)
            if name == "entity":
                return subject.entity
            if subject.has_metric(name):
                return _format_metric(name, subject.metric(name))
            if name in subject.context:
                return subject.context[name]
            return match.group(0)

        return _PLACEHOLDER.sub(substitute, template).strip()

    @property
    def referenced_metrics(self) -> tuple[str, ...]:
        """Every metric this rule reads, conditions and context together."""
        seen: dict[str, None] = {}
        for condition in self.conditions:
            seen[condition.metric] = None
        for name in self.context_metrics:
            seen[name] = None
        return tuple(seen)

    def describe(self) -> str:
        """One-line summary for rule listings."""
        conditions = " AND ".join(condition.describe() for condition in self.conditions)
        return f"[{self.id}] {self.title} -- {conditions}"

    def to_dict(self) -> dict[str, Any]:
        """Serialise for ``xniffer rules list --json``."""
        return {
            "id": self.id,
            "version": self.version,
            "title": self.title,
            "scope": self.scope.value,
            "severity": self.severity.label,
            "confidence": self.confidence.label,
            "enabled": self.enabled,
            "description": self.description,
            "conditions": [
                {"metric": c.metric, "op": c.op, "value": c.value} for c in self.conditions
            ],
            "false_positive_notes": list(self.false_positive_notes),
            "attack": [
                {"id": t.id, "name": t.name, "tactic": t.tactic, "url": t.url}
                for t in self.attack
            ],
            "tags": list(self.tags),
            "source": self.source,
        }


def _format_metric(name: str, value: MetricValue) -> str:
    """Render a measured value for insertion into a sentence."""
    from xniffer.analyze.metrics import lookup

    spec = lookup(name)
    if spec is not None:
        return spec.format_value(value)
    if isinstance(value, float):
        return f"{value:.2f}"
    return str(value)


# --------------------------------------------------------------------------- #
# Parsing
# --------------------------------------------------------------------------- #


def _require(data: Mapping[str, Any], key: str, source: str) -> Any:
    if key not in data:
        raise RuleLoadError(f"{source}: rule is missing required field {key!r}")
    return data[key]


def _parse_condition(raw: Any, scope: SubjectScope, rule_id: str, source: str) -> Condition:
    """Build one condition, validating its metric against the catalogue."""
    if not isinstance(raw, Mapping):
        raise RuleLoadError(f"{source}: rule {rule_id!r} has a condition that is not a mapping")

    metric = raw.get("metric")
    if not isinstance(metric, str):
        raise RuleLoadError(f"{source}: rule {rule_id!r} has a condition without a metric name")

    problem = validate_reference(metric, scope)
    if problem is not None:
        raise RuleLoadError(f"{source}: rule {rule_id!r}: {problem}")

    op = raw.get("op", ">=")
    if op not in OPERATORS:
        valid = ", ".join(sorted(OPERATORS))
        raise RuleLoadError(
            f"{source}: rule {rule_id!r} uses unknown operator {op!r} (valid: {valid})"
        )

    if "value" not in raw:
        raise RuleLoadError(
            f"{source}: rule {rule_id!r} has a condition on {metric!r} without a value"
        )

    value = raw["value"]
    if op in ("in", "not_in"):
        if not isinstance(value, Sequence) or isinstance(value, str):
            raise RuleLoadError(
                f"{source}: rule {rule_id!r}: operator {op!r} on {metric!r} needs a list value"
            )
        value = tuple(value)

    label = raw.get("label", "")
    if not isinstance(label, str):
        raise RuleLoadError(f"{source}: rule {rule_id!r}: condition label must be text")

    return Condition(metric=metric, op=op, value=value, label=label)


def _parse_attack(raw: Any, rule_id: str, source: str) -> tuple[AttackTechnique, ...]:
    """Parse the ATT&CK block, accepting either bare IDs or full mappings."""
    if raw is None:
        return ()
    if not isinstance(raw, Sequence) or isinstance(raw, str):
        raise RuleLoadError(f"{source}: rule {rule_id!r}: 'attack' must be a list")

    techniques: list[AttackTechnique] = []
    for entry in raw:
        if isinstance(entry, str):
            techniques.append(AttackTechnique(id=entry, name="", tactic=""))
            continue
        if not isinstance(entry, Mapping) or "id" not in entry:
            raise RuleLoadError(
                f"{source}: rule {rule_id!r}: each 'attack' entry needs at least an 'id'"
            )
        techniques.append(
            AttackTechnique(
                id=str(entry["id"]),
                name=str(entry.get("name", "")),
                tactic=str(entry.get("tactic", "")),
            )
        )
    return tuple(techniques)


def _parse_string_list(raw: Any, field_name: str, rule_id: str, source: str) -> tuple[str, ...]:
    if raw is None:
        return ()
    if isinstance(raw, str):
        return (raw,)
    if not isinstance(raw, Sequence):
        raise RuleLoadError(f"{source}: rule {rule_id!r}: {field_name!r} must be a list of text")
    return tuple(str(item) for item in raw)


def parse_rule(data: Mapping[str, Any], source: str = "<memory>") -> RuleSpec:
    """Build a :class:`RuleSpec` from parsed YAML, validating as it goes.

    Every failure raises :class:`~xniffer.errors.RuleLoadError` naming the file
    and the rule. Rules are configuration written by hand, so the error message
    is the entire user interface for getting one wrong.
    """
    if not isinstance(data, Mapping):
        raise RuleLoadError(f"{source}: expected a rule mapping, got {type(data).__name__}")

    rule_id = str(_require(data, "id", source))
    title = str(_require(data, "title", source))

    raw_scope = str(_require(data, "scope", source))
    try:
        scope = SubjectScope(raw_scope)
    except ValueError:
        valid = ", ".join(s.value for s in SubjectScope)
        raise RuleLoadError(
            f"{source}: rule {rule_id!r} has unknown scope {raw_scope!r} (valid: {valid})"
        ) from None

    try:
        severity = Severity.parse(str(_require(data, "severity", source)))
        confidence = Confidence.parse(str(_require(data, "confidence", source)))
    except ValueError as exc:
        raise RuleLoadError(f"{source}: rule {rule_id!r}: {exc}") from None

    raw_conditions = _require(data, "conditions", source)
    if not isinstance(raw_conditions, Sequence) or isinstance(raw_conditions, str):
        raise RuleLoadError(f"{source}: rule {rule_id!r}: 'conditions' must be a list")
    if not raw_conditions:
        raise RuleLoadError(
            f"{source}: rule {rule_id!r} has no conditions -- a rule that matches "
            f"everything is not a detection"
        )

    conditions = tuple(
        _parse_condition(raw, scope, rule_id, source) for raw in raw_conditions
    )

    false_positive_notes = _parse_string_list(
        data.get("false_positive_notes"), "false_positive_notes", rule_id, source
    )
    if not false_positive_notes:
        raise RuleLoadError(
            f"{source}: rule {rule_id!r} declares no false_positive_notes. Every "
            f"detection has benign explanations; naming them is required."
        )

    context_metrics = _parse_string_list(
        data.get("context_metrics"), "context_metrics", rule_id, source
    )
    for name in context_metrics:
        problem = validate_reference(name, scope)
        if problem is not None:
            raise RuleLoadError(f"{source}: rule {rule_id!r}: context_metrics: {problem}")

    return RuleSpec(
        id=rule_id,
        title=title,
        scope=scope,
        severity=severity,
        confidence=confidence,
        conditions=conditions,
        version=int(data.get("version", 1)),
        reason=str(data.get("reason", "")),
        description=str(data.get("description", "")),
        recommendation=str(data.get("recommendation", "")),
        false_positive_notes=false_positive_notes,
        attack=_parse_attack(data.get("attack"), rule_id, source),
        context_metrics=context_metrics,
        tags=_parse_string_list(data.get("tags"), "tags", rule_id, source),
        enabled=bool(data.get("enabled", True)),
        source=source,
        metadata=dict(data.get("metadata", {})),
    )


__all__ = [
    "OPERATORS",
    "Condition",
    "RuleSpec",
    "compare",
    "parse_rule",
]
