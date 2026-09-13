"""Small statistical helpers used by the analysis and detection layers.

Deliberately stdlib-only. xniffer avoids a NumPy dependency: the sample sizes
here are tiny (tens to low thousands of intervals), the arithmetic is trivial,
and staying dependency-light keeps the tool installable on a locked-down
incident-response box.
"""

from __future__ import annotations

import math
from collections.abc import Sequence
from dataclasses import dataclass


def mean(values: Sequence[float]) -> float:
    """Arithmetic mean, or 0.0 for an empty sequence."""
    return sum(values) / len(values) if values else 0.0


def stdev(values: Sequence[float]) -> float:
    """Sample standard deviation, or 0.0 when there are fewer than two values."""
    if len(values) < 2:
        return 0.0
    average = mean(values)
    variance = sum((value - average) ** 2 for value in values) / (len(values) - 1)
    return math.sqrt(variance)


def median(values: Sequence[float]) -> float:
    """Median value, or 0.0 for an empty sequence."""
    if not values:
        return 0.0
    ordered = sorted(values)
    midpoint = len(ordered) // 2
    if len(ordered) % 2:
        return ordered[midpoint]
    return (ordered[midpoint - 1] + ordered[midpoint]) / 2


def percentile(values: Sequence[float], fraction: float) -> float:
    """Linear-interpolated percentile; ``fraction`` is 0.0-1.0."""
    if not values:
        return 0.0
    ordered = sorted(values)
    if len(ordered) == 1:
        return ordered[0]
    position = fraction * (len(ordered) - 1)
    lower = int(math.floor(position))
    upper = int(math.ceil(position))
    if lower == upper:
        return ordered[lower]
    weight = position - lower
    return ordered[lower] * (1 - weight) + ordered[upper] * weight


def intervals_between(timestamps: Sequence[float]) -> list[float]:
    """Return the gaps between consecutive (sorted) timestamps."""
    if len(timestamps) < 2:
        return []
    ordered = sorted(timestamps)
    return [later - earlier for earlier, later in zip(ordered, ordered[1:], strict=False)]


@dataclass(frozen=True, slots=True)
class IntervalProfile:
    """Regularity measurements for a series of timestamps.

    This is the machinery behind beacon detection. A human browsing the web
    produces wildly irregular gaps between connections; a scheduled process --
    a software updater, a monitoring agent, or an implant calling home --
    produces gaps clustered tightly around a fixed period.

    The tool cannot tell those last three apart from timing alone, and does not
    pretend to. It reports the regularity and leaves attribution to the analyst.
    """

    count: int
    """Number of intervals measured (one fewer than the number of events)."""

    mean: float
    """Average gap, in seconds."""

    stdev: float
    """Sample standard deviation of the gaps, in seconds."""

    median: float
    """Median gap, in seconds."""

    minimum: float
    maximum: float

    @property
    def coefficient_of_variation(self) -> float:
        """Standard deviation divided by the mean -- a unitless jitter measure.

        Near 0.0 means metronomic. Around 1.0 is what random arrivals look
        like. This normalisation is what lets one threshold work for a beacon
        every 30 seconds and a beacon every 6 hours.
        """
        return self.stdev / self.mean if self.mean > 0 else 0.0

    @property
    def regularity(self) -> float:
        """A 0.0-1.0 score where 1.0 is perfectly periodic."""
        return max(0.0, 1.0 - self.coefficient_of_variation)

    def is_periodic(self, max_variation: float = 0.15, min_samples: int = 4) -> bool:
        """True when the series looks scheduled rather than human-driven.

        Requires a minimum sample count as well as low variation: three
        connections that happen to be evenly spaced prove nothing.
        """
        return self.count >= min_samples and self.coefficient_of_variation <= max_variation

    def to_dict(self) -> dict[str, float | int]:
        """Serialise for JSON output and finding evidence."""
        return {
            "count": self.count,
            "mean_seconds": round(self.mean, 3),
            "stdev_seconds": round(self.stdev, 3),
            "median_seconds": round(self.median, 3),
            "min_seconds": round(self.minimum, 3),
            "max_seconds": round(self.maximum, 3),
            "coefficient_of_variation": round(self.coefficient_of_variation, 4),
            "regularity": round(self.regularity, 4),
        }


EMPTY_INTERVAL_PROFILE = IntervalProfile(
    count=0, mean=0.0, stdev=0.0, median=0.0, minimum=0.0, maximum=0.0
)


def profile_intervals(timestamps: Sequence[float]) -> IntervalProfile:
    """Measure the regularity of a series of event timestamps."""
    gaps = intervals_between(timestamps)
    if not gaps:
        return EMPTY_INTERVAL_PROFILE
    return IntervalProfile(
        count=len(gaps),
        mean=mean(gaps),
        stdev=stdev(gaps),
        median=median(gaps),
        minimum=min(gaps),
        maximum=max(gaps),
    )


def ratio(numerator: float, denominator: float, default: float = 0.0) -> float:
    """Safe division that returns ``default`` instead of raising on zero."""
    return numerator / denominator if denominator else default


__all__ = [
    "EMPTY_INTERVAL_PROFILE",
    "IntervalProfile",
    "intervals_between",
    "mean",
    "median",
    "percentile",
    "profile_intervals",
    "ratio",
    "stdev",
]
