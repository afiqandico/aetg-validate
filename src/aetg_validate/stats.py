"""Statistical helpers for AETG-Validate.

Every proportion reported by this tool carries a Wilson score interval.
Wilson (not Wald) is used because evasion results sit at the boundaries
(0/N or N/N) where the normal approximation collapses: with 0 escapes out of
20 000 flows the Wald interval degenerates to a zero-width interval, which
would be a false claim of certainty.

Reference: Wilson, E. B. (1927). Probable inference, the law of succession,
and statistical inference. JASA 22(158), 209-212.
"""

from __future__ import annotations

import math
from dataclasses import dataclass
from typing import Any, Dict

#: 95 % two-sided normal quantile.
Z95: float = 1.959963984540054


@dataclass(frozen=True)
class Interval:
    """A proportion with its confidence interval."""

    point: float
    low: float
    high: float
    k: int
    n: int

    def as_dict(self) -> Dict[str, Any]:
        return {
            "point": self.point,
            "low": self.low,
            "high": self.high,
            "k": self.k,
            "n": self.n,
        }

    def percent(self) -> Dict[str, Any]:
        """Same interval expressed in percent, for human-readable reports."""
        return {
            "point_pct": round(self.point * 100.0, 4),
            "low_pct": round(self.low * 100.0, 4),
            "high_pct": round(self.high * 100.0, 4),
            "k": self.k,
            "n": self.n,
        }

    def __str__(self) -> str:  # pragma: no cover - cosmetic
        return (
            f"{self.point * 100:.2f}% "
            f"[{self.low * 100:.2f}, {self.high * 100:.2f}] (k={self.k}, n={self.n})"
        )


def wilson_interval(k: int, n: int, z: float = Z95) -> Interval:
    """Wilson score interval for ``k`` successes out of ``n`` trials.

    Args:
        k: number of successes (e.g. escaped flows).
        n: number of trials (e.g. Phi-valid flows).
        z: normal quantile; 1.959963984540054 for 95 % two-sided.

    Raises:
        ValueError: if ``n <= 0`` or ``k`` is outside ``[0, n]``.
    """
    if n <= 0:
        raise ValueError(f"wilson_interval needs n > 0, got n={n}")
    if k < 0 or k > n:
        raise ValueError(f"wilson_interval needs 0 <= k <= n, got k={k}, n={n}")

    p = k / n
    z2 = z * z
    denom = 1.0 + z2 / n
    center = (p + z2 / (2.0 * n)) / denom
    half = z * math.sqrt((p * (1.0 - p) / n) + (z2 / (4.0 * n * n))) / denom
    low = max(0.0, center - half)
    high = min(1.0, center + half)
    # Floating point can leave 3.5e-18 where the mathematical bound is exactly
    # 0; a report must not print "0.0000000000000000035%" as if it mattered.
    if low < 1e-12:
        low = 0.0
    if high > 1.0 - 1e-12:
        high = 1.0
    return Interval(point=p, low=low, high=high, k=k, n=n)


def format_interval(value: Interval, digits: int = 2) -> str:
    """``12.34% [1.23, 45.67]`` — the shape used across all reports."""
    fmt = f"{{:.{digits}f}}%"
    return (
        f"{fmt.format(value.point * 100)} "
        f"[{fmt.format(value.low * 100)}, {fmt.format(value.high * 100)}] "
        f"(k={value.k}, n={value.n})"
    )
