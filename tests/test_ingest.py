"""Ingest readers: JSONL, CSV, Suricata eve.json, AETG artefacts."""

from __future__ import annotations

import json

import pytest

from aetg_validate.ingest import (
    IngestError,
    apply_suricata_verdicts,
    read_aetg_artifacts,
    read_flows_csv,
    read_flows_jsonl,
    read_suricata_alerts,
)
from aetg_validate.models import FlowRecord


def test_read_jsonl(tmp_path):
    path = tmp_path / "flows.jsonl"
    path.write_text(
        "\n".join(
            [
                json.dumps({"flow_id": "1", "technique": "ttl", "func_valid": True, "detected": False}),
                json.dumps({"flow_id": "2", "technique": "frag", "func_valid": False, "detected": True}),
            ]
        )
        + "\n",
        encoding="utf-8",
    )
    records = read_flows_jsonl(path)
    assert [r.flow_id for r in records] == ["1", "2"]
    assert records[0].detected is False
    assert records[1].func_valid is False


def test_read_jsonl_reports_line_number(tmp_path):
    path = tmp_path / "bad.jsonl"
    path.write_text('{"flow_id": "1"}\nnot json\n', encoding="utf-8")
    with pytest.raises(IngestError, match=r":2:"):
        read_flows_jsonl(path)


def test_read_csv(tmp_path):
    path = tmp_path / "flows.csv"
    path.write_text(
        "flow_id,technique,func_valid,detected\n1,ttl,true,false\n2,frag,false,true\n",
        encoding="utf-8",
    )
    records = read_flows_csv(path)
    assert records[0].detected is False
    assert records[1].func_valid is False


def test_suricata_alerts_and_verdict_override(tmp_path):
    path = tmp_path / "eve.json"
    path.write_text(
        "\n".join(
            [
                json.dumps({"event_type": "flow", "flow_id": 1}),
                json.dumps(
                    {
                        "event_type": "alert",
                        "flow_id": 2,
                        "alert": {"signature_id": 2001219, "signature": "ET SCAN"},
                    }
                ),
            ]
        )
        + "\n",
        encoding="utf-8",
    )
    alerts = read_suricata_alerts(path)
    assert alerts["by_flow"] == {"2"}
    assert alerts["rules"] == {"2001219:ET SCAN"}

    records = [FlowRecord("1", detected=True), FlowRecord("2", detected=False)]
    hits = apply_suricata_verdicts(records, alerts)
    assert hits == 1
    assert records[0].detected is False  # no alert in the log -> not detected
    assert records[1].detected is True


def test_aetg_artifacts_adapter(tmp_path):
    (tmp_path / "esr_internal.json").write_text(
        json.dumps({"esr": 0.0, "total_adv_flows": 200, "detected": 200, "undetected": 0}),
        encoding="utf-8",
    )
    (tmp_path / "fvr_results.json").write_text(
        json.dumps({"fvr": 100.0, "total_steps": 4995, "valid_steps": 4995}),
        encoding="utf-8",
    )
    data = read_aetg_artifacts(tmp_path)
    assert data["n_total"] == 200
    assert data["n_valid"] == 200
    assert data["n_undetected"] == 0


def test_aetg_artifacts_missing_file(tmp_path):
    with pytest.raises(IngestError):
        read_aetg_artifacts(tmp_path)
