"""Data model for AETG-Validate.

A *flow record* is the atom of the tool: one network flow that an adversarial
traffic generator produced, plus everything we know about it afterwards:

* ``func_valid`` — did the flow pass the functional gate (Phi)? For the
  reference implementation that means a completed SYN-ACK / a valid HTTP
  response. A flow that never completed a handshake is not an evasion; it is
  malformed traffic, and counting it inflates every number in the report.
* ``detected`` — did the IDS under test raise an alert for it?
* ``p_ids`` — optional detector confidence, when the detector exposes one.

Keeping these two booleans separate is the whole point of the product: the
report can then show feature-space evasion (ungated) next to Phi-valid evasion
(binding) without ever mixing them.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional


@dataclass
class FlowRecord:
    """One generated flow and its measured outcome."""

    flow_id: str
    technique: str = "unknown"
    func_valid: bool = True
    detected: bool = True
    rule_id: Optional[str] = None
    p_ids: Optional[float] = None
    params: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "flow_id": self.flow_id,
            "technique": self.technique,
            "func_valid": self.func_valid,
            "detected": self.detected,
            "rule_id": self.rule_id,
            "p_ids": self.p_ids,
            "params": self.params,
        }

    @classmethod
    def from_dict(cls, raw: Dict[str, Any]) -> "FlowRecord":
        return cls(
            flow_id=str(raw.get("flow_id", raw.get("id", ""))),
            technique=str(raw.get("technique", "unknown")),
            func_valid=bool(raw.get("func_valid", True)),
            detected=bool(raw.get("detected", True)),
            rule_id=(str(raw["rule_id"]) if raw.get("rule_id") is not None else None),
            p_ids=(float(raw["p_ids"]) if raw.get("p_ids") is not None else None),
            params=dict(raw.get("params") or {}),
        )


@dataclass
class TechniqueBreakdown:
    """Per-technique view, so a report can point at *which* trick worked."""

    technique: str
    n_total: int
    n_valid: int
    n_escaped: int

    def to_dict(self) -> Dict[str, Any]:
        return {
            "technique": self.technique,
            "n_total": self.n_total,
            "n_valid": self.n_valid,
            "n_escaped": self.n_escaped,
        }


@dataclass
class ScanMetrics:
    """Aggregate outcome of one validation run.

    ``esr_phi`` is the binding number. ``esr_feature_space`` is diagnostic
    only and is labelled as such everywhere it appears.
    """

    n_total: int = 0
    n_valid: int = 0
    n_gate_rejected: int = 0
    n_escaped_phi: int = 0
    n_escaped_raw: int = 0
    rules_hit: List[str] = field(default_factory=list)
    min_p_ids: Optional[float] = None
    techniques: List[TechniqueBreakdown] = field(default_factory=list)
