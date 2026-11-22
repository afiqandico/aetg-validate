"""Metric computation — the part that must be right.

Two evasion rates are computed and never mixed:

``ESR (Phi-valid)``  — binding. Denominator: flows that passed the functional
    gate. Numerator: those of them the IDS did not alert on.
``ESR (feature-space)`` — diagnostic. Denominator: every flow produced.
    Numerator: every flow the IDS did not alert on, including flows that never
    completed a handshake.

Reporting only the second one is how a tool can claim "70 % evasion" while a
large share of the "evasions" were packets no real stack would have accepted.
AETG-Validate reports both, labels them, and puts the Phi-valid number first.
"""

from __future__ import annotations

from typing import Any, Dict, List, Sequence

from .models import FlowRecord, ScanMetrics, TechniqueBreakdown
from .stats import Interval, wilson_interval


def compute(records: Sequence[FlowRecord]) -> ScanMetrics:
    """Reduce flow records to aggregate counts."""
    metrics = ScanMetrics(n_total=len(records))
    rules: set[str] = set()
    per_technique: Dict[str, TechniqueBreakdown] = {}
    min_p: float | None = None

    for record in records:
        metrics.n_valid += 1 if record.func_valid else 0
        if not record.detected:
            metrics.n_escaped_raw += 1
            if record.func_valid:
                metrics.n_escaped_phi += 1
        if record.detected and record.rule_id:
            rules.add(record.rule_id)
        if record.p_ids is not None and (min_p is None or record.p_ids < min_p):
            min_p = record.p_ids

        bucket = per_technique.get(record.technique)
        if bucket is None:
            bucket = TechniqueBreakdown(record.technique, 0, 0, 0)
            per_technique[record.technique] = bucket
        bucket.n_total += 1
        if record.func_valid:
            bucket.n_valid += 1
            if not record.detected:
                bucket.n_escaped += 1

    metrics.n_gate_rejected = metrics.n_total - metrics.n_valid
    metrics.rules_hit = sorted(rules)
    metrics.min_p_ids = min_p
    metrics.techniques = sorted(per_technique.values(), key=lambda t: t.technique)
    return metrics


def summarize(metrics: ScanMetrics) -> Dict[str, Any]:
    """Attach intervals to the counts.

    Raises ValueError when there is nothing to report on, rather than emitting
    a zero that would be a fabricated measurement.
    """
    if metrics.n_total <= 0:
        raise ValueError("cannot summarize a scan with no flows")

    fvr: Interval = wilson_interval(metrics.n_valid, metrics.n_total)
    esr_phi: Interval = wilson_interval(metrics.n_escaped_phi, metrics.n_valid) if metrics.n_valid > 0 else None  # type: ignore[assignment]
    esr_raw: Interval = wilson_interval(metrics.n_escaped_raw, metrics.n_total)

    return {
        "population": {
            "n_total": metrics.n_total,
            "n_phi_valid": metrics.n_valid,
            "n_gate_rejected": metrics.n_gate_rejected,
        },
        "fvr": fvr.as_dict(),
        "fvr_pct": fvr.percent(),
        "esr_phi": esr_phi.as_dict() if esr_phi else None,
        "esr_phi_pct": esr_phi.percent() if esr_phi else None,
        "esr_feature_space": esr_raw.as_dict(),
        "esr_feature_space_pct": esr_raw.percent(),
        "detection": {
            "rules_hit_count": len(metrics.rules_hit),
            "rules_hit": list(metrics.rules_hit),
            "min_p_ids": metrics.min_p_ids,
        },
        "techniques": [t.to_dict() for t in metrics.techniques],
    }
