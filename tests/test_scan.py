"""The metric engine must never let a malformed flow count as an evasion."""

from __future__ import annotations

import pytest

from aetg_validate.models import FlowRecord
from aetg_validate.scan import compute, summarize


def _record(index: int, *, valid: bool, detected: bool, technique: str = "t") -> FlowRecord:
    return FlowRecord(flow_id=f"f{index:03d}", technique=technique, func_valid=valid, detected=detected)


def test_phi_gated_rate_excludes_gate_rejected_flows():
    # 10 flows: 2 gate-rejected, of which both escaped; 8 valid, 1 escaped.
    records = [
        _record(1, valid=False, detected=False),
        _record(2, valid=False, detected=False),
        _record(3, valid=True, detected=False),
        *[_record(i, valid=True, detected=True) for i in range(4, 11)],
    ]
    summary = summarize(compute(records))

    assert summary["population"] == {"n_total": 10, "n_phi_valid": 8, "n_gate_rejected": 2}
    # Binding rate: 1 escape out of 8 valid flows.
    assert summary["esr_phi"]["k"] == 1
    assert summary["esr_phi"]["n"] == 8
    # Diagnostic rate: 3 escapes out of 10 produced flows.
    assert summary["esr_feature_space"]["k"] == 3
    assert summary["esr_feature_space"]["n"] == 10
    # FVR = 8/10.
    assert summary["fvr"]["k"] == 8
    assert summary["fvr"]["n"] == 10


def test_perfect_detection_yields_zero_point_and_nonzero_upper_bound():
    records = [_record(i, valid=True, detected=True) for i in range(200)]
    summary = summarize(compute(records))
    assert summary["esr_phi"]["point"] == 0.0
    assert summary["esr_phi"]["high"] > 0.0


def test_technique_breakdown_is_per_technique():
    records = [
        _record(1, valid=True, detected=False, technique="ttl"),
        _record(2, valid=True, detected=True, technique="ttl"),
        _record(3, valid=True, detected=False, technique="frag"),
    ]
    summary = summarize(compute(records))
    by_name = {row["technique"]: row for row in summary["techniques"]}
    assert by_name["ttl"] == {"technique": "ttl", "n_total": 2, "n_valid": 2, "n_escaped": 1}
    assert by_name["frag"]["n_escaped"] == 1


def test_rules_and_min_confidence_are_collected():
    records = [
        FlowRecord("a", detected=True, rule_id="1:alpha", p_ids=0.91),
        FlowRecord("b", detected=True, rule_id="2:beta", p_ids=0.43),
        FlowRecord("c", detected=False, p_ids=0.02),
    ]
    summary = summarize(compute(records))
    assert summary["detection"]["rules_hit"] == ["1:alpha", "2:beta"]
    assert summary["detection"]["min_p_ids"] == pytest.approx(0.02)


def test_empty_scan_is_refused_rather_than_reported_as_zero():
    with pytest.raises(ValueError):
        summarize(compute([]))


def test_all_flows_gate_rejected_has_no_binding_rate():
    records = [_record(1, valid=False, detected=False), _record(2, valid=False, detected=True)]
    summary = summarize(compute(records))
    assert summary["esr_phi"] is None
    assert summary["fvr"]["point"] == 0.0
