"""Security findings -- xniffer's output, and the reason the project exists.

A finding is not an alert. An alert says "port scan detected" and leaves the
reader to trust it. A finding carries everything needed to check the claim:

* **Evidence** -- the measured values, each next to the threshold it crossed.
* **Packet references** -- the exact capture indices, so the raw traffic is one
  command away.
* **False-positive notes** -- the benign explanations the rule cannot rule out.
* **Recommendations** -- what an analyst should actually do next.
* **Two independent axes** -- :class:`~xniffer.model.enums.Severity` for impact
  and :class:`~xniffer.model.enums.Confidence` for certainty, never blended
  into one number that hides which is which.

The false-positive notes are not a disclaimer bolted on at the end. Network
behaviour is genuinely ambiguous -- a vulnerability scanner and an attacker
produce identical packets -- and a tool that hides that ambiguity trains its
users to either over-react or stop reading. Stating the ambiguity is what makes
the finding trustworthy.
"""

from __future__ import annotations

import hashlib
from collections.abc import Mapping
from dataclasses import dataclass, field
from typing import Any

from xniffer.model._serde import jsonify
from xniffer.model.enums import Confidence, FindingStatus, Severity


@dataclass(frozen=True, slots=True)
class Evidence:
    """One measured fact that contributed to a finding.

    Storing the threshold alongside the value is what turns "suspicious
    activity" into "21 destination hosts, and the rule fires at 15". The reader
    can immediately judge whether the rule was close to the line or far past it.
    """

    label: str
    """What was measured, in plain words (``distinct destination hosts``)."""

    value: str
    """The measured value, pre-formatted for display."""

    threshold: str | None = None
    """The comparison that made it notable (``>= 15``), when there was one."""

    packet_ids: tuple[int, ...] = ()
    """Capture indices that specifically demonstrate this fact."""

    def to_dict(self) -> dict[str, Any]:
        """Serialise for JSON output."""
        return jsonify(self)

    def __str__(self) -> str:
        if self.threshold:
            return f"{self.label}: {self.value} (threshold {self.threshold})"
        return f"{self.label}: {self.value}"


@dataclass(frozen=True, slots=True)
class AttackTechnique:
    """A MITRE ATT&CK technique reference.

    Included so findings can be correlated with detection coverage frameworks
    and other tooling. xniffer maps to techniques it can genuinely evidence and
    leaves the mapping empty otherwise -- an inaccurate mapping is worse than
    none, because it inflates apparent coverage.
    """

    id: str
    """Technique identifier, e.g. ``T1046`` or ``T1071.004``."""

    name: str
    """Technique name, e.g. ``Network Service Discovery``."""

    tactic: str | None = None
    """The ATT&CK tactic, e.g. ``Discovery``."""

    @property
    def url(self) -> str:
        """Canonical ATT&CK URL for the technique."""
        path = self.id.replace(".", "/")
        return f"https://attack.mitre.org/techniques/{path}/"

    def to_dict(self) -> dict[str, Any]:
        """Serialise for JSON output."""
        data = jsonify(self)
        data["url"] = self.url
        return data

    def __str__(self) -> str:
        return f"{self.id} {self.name}"


@dataclass(frozen=True, slots=True)
class Finding:
    """A single security-relevant observation, with its full justification."""

    # -- identity ---------------------------------------------------------- #
    id: str
    """Human-facing identifier within one run, e.g. ``F-003``."""

    rule_id: str
    """The rule that produced this, e.g. ``net.scan.horizontal``."""

    title: str
    """A short headline, phrased as a possibility rather than a verdict."""

    severity: Severity
    confidence: Confidence

    # -- justification ----------------------------------------------------- #
    reason: str = ""
    """One or two sentences explaining what behaviour triggered the rule."""

    evidence: tuple[Evidence, ...] = ()
    packet_ids: tuple[int, ...] = ()
    """Capture indices supporting the finding, in ascending order."""

    context: Mapping[str, str] = field(default_factory=dict)
    """Ordered key/value pairs identifying the subject (source host, ports...)."""

    recommendation: tuple[str, ...] = ()
    """Concrete next steps, ordered from cheapest to most involved."""

    false_positive_notes: tuple[str, ...] = ()
    """Benign explanations this rule cannot distinguish from a real threat."""

    attack: tuple[AttackTechnique, ...] = ()
    matched_values: Mapping[str, Any] = field(default_factory=dict)
    """Raw measured values, machine-readable, for downstream tooling."""

    # -- provenance -------------------------------------------------------- #
    entity: str = ""
    """The primary subject -- usually the source host the finding is about."""

    first_seen: float = 0.0
    last_seen: float = 0.0
    tags: tuple[str, ...] = ()
    status: FindingStatus = FindingStatus.NEW
    rule_version: str = "1"

    # -- derived views ----------------------------------------------------- #

    @property
    def duration(self) -> float:
        """Seconds spanned by the observed behaviour."""
        return max(0.0, self.last_seen - self.first_seen)

    @property
    def packet_count(self) -> int:
        """How many packets are cited as evidence."""
        return len(self.packet_ids)

    @property
    def fingerprint(self) -> str:
        """A stable hash identifying *what* this finding is about.

        Derived from the rule and the subject, never from counts or timestamps,
        so the same underlying condition produces the same fingerprint across
        runs. This is what a suppression list or a deduplicating pipeline keys
        on -- ``id`` is only unique within a single run.
        """
        material = "|".join(
            [self.rule_id, self.entity, *(f"{k}={v}" for k, v in sorted(self.context.items()))]
        )
        return hashlib.sha256(material.encode("utf-8")).hexdigest()[:16]

    @property
    def priority(self) -> tuple[int, int]:
        """Sort key: most severe first, then most confident."""
        return (-int(self.severity), -int(self.confidence))

    def cited_packets(self, limit: int = 8) -> str:
        """Render the packet references compactly, e.g. ``#142, #143 (+19 more)``."""
        if not self.packet_ids:
            return "-"
        shown = ", ".join(f"#{index}" for index in self.packet_ids[:limit])
        remaining = len(self.packet_ids) - limit
        return f"{shown} (+{remaining} more)" if remaining > 0 else shown

    # -- rendering --------------------------------------------------------- #

    def explain(self, capture_hint: str = "<capture>") -> str:
        """Return the full plain-text justification for this finding.

        This is what ``xniffer explain`` prints. It is deliberately plain text
        with no markup: it must be readable when piped into a ticket, an email
        or an incident timeline, not only in a terminal that speaks ANSI.
        """
        lines: list[str] = []
        lines.append(f"{self.id}  {self.title}")
        lines.append(
            f"  rule {self.rule_id} (v{self.rule_version})"
            f"  |  severity {self.severity.label}"
            f"  |  confidence {self.confidence.label}"
        )
        if self.attack:
            techniques = ", ".join(str(technique) for technique in self.attack)
            lines.append(f"  ATT&CK: {techniques}")
        lines.append("")

        if self.reason:
            lines.append("WHY THIS FIRED")
            lines.append(f"  {self.reason}")
            lines.append("")

        if self.evidence:
            lines.append("WHAT MATCHED")
            label_width = max(len(item.label) for item in self.evidence)
            value_width = max(len(item.value) for item in self.evidence)
            for item in self.evidence:
                row = f"  {item.label.ljust(label_width)}   {item.value.ljust(value_width)}"
                if item.threshold:
                    row += f"   threshold {item.threshold}"
                lines.append(row.rstrip())
            lines.append("")

        if self.context:
            lines.append("CONTEXT")
            key_width = max(len(key) for key in self.context)
            for key, value in self.context.items():
                lines.append(f"  {key.ljust(key_width)}   {value}")
            lines.append("")

        if self.packet_ids:
            lines.append("EVIDENCE PACKETS")
            lines.append(f"  {self.cited_packets(limit=12)}")
            lines.append(
                f"  inspect with: xniffer packet {capture_hint} --id {self.packet_ids[0]}"
            )
            lines.append("")

        if self.false_positive_notes:
            lines.append("WHY THIS MIGHT BE BENIGN")
            for note in self.false_positive_notes:
                lines.append(f"  - {note}")
            lines.append("")

        if self.recommendation:
            lines.append("SUGGESTED NEXT STEPS")
            for position, step in enumerate(self.recommendation, start=1):
                lines.append(f"  {position}. {step}")
            lines.append("")

        return "\n".join(lines).rstrip() + "\n"

    def to_dict(self) -> dict[str, Any]:
        """Serialise for JSON/JSONL output.

        The shape here is the tool's machine-readable contract. Severity and
        confidence are emitted as both name and numeric level so a consumer can
        display them or threshold on them without a lookup table.
        """
        return {
            "id": self.id,
            "fingerprint": self.fingerprint,
            "rule_id": self.rule_id,
            "rule_version": self.rule_version,
            "title": self.title,
            "severity": self.severity.label,
            "severity_level": int(self.severity),
            "confidence": self.confidence.label,
            "confidence_level": int(self.confidence),
            "status": self.status.value,
            "entity": self.entity,
            "reason": self.reason,
            "evidence": [item.to_dict() for item in self.evidence],
            "packet_ids": list(self.packet_ids),
            "packet_count": self.packet_count,
            "context": dict(self.context),
            "matched_values": jsonify(dict(self.matched_values)),
            "recommendation": list(self.recommendation),
            "false_positive_notes": list(self.false_positive_notes),
            "attack": [technique.to_dict() for technique in self.attack],
            "first_seen": round(self.first_seen, 6),
            "last_seen": round(self.last_seen, 6),
            "duration": round(self.duration, 6),
            "tags": list(self.tags),
        }

    def with_id(self, new_id: str) -> Finding:
        """Return a copy carrying ``new_id``.

        Rules produce findings without knowing their position in the final
        report; the engine assigns sequential identifiers once everything has
        been collected and sorted.
        """
        import dataclasses

        return dataclasses.replace(self, id=new_id)


def sort_findings(findings: list[Finding]) -> list[Finding]:
    """Order findings the way an analyst wants to read them.

    Severity first, then confidence, then earliest occurrence -- so the thing
    most likely to matter is at the top, and ties break in chronological order
    rather than arbitrarily.
    """
    return sorted(findings, key=lambda item: (*item.priority, item.first_seen, item.rule_id))


def assign_ids(findings: list[Finding], prefix: str = "F") -> list[Finding]:
    """Renumber ``findings`` sequentially as ``F-001``, ``F-002``, ..."""
    width = max(3, len(str(len(findings))))
    return [
        finding.with_id(f"{prefix}-{position:0{width}d}")
        for position, finding in enumerate(findings, start=1)
    ]


__all__ = [
    "AttackTechnique",
    "Evidence",
    "Finding",
    "assign_ids",
    "sort_findings",
]
