"""End-to-end CLI behaviour: outputs exist, digests verify, tampering is caught."""

from __future__ import annotations

import json

import pytest

from aetg_validate.cli import main


@pytest.fixture()
def demo_dir(tmp_path, monkeypatch):
    monkeypatch.delenv("AETG_VALIDATE_KEY", raising=False)
    out = tmp_path / "demo"
    assert main(["demo", "--out", str(out)]) == 0
    return out


def test_demo_writes_three_formats(demo_dir):
    for name in ("scan.json", "report.md", "report.html"):
        assert (demo_dir / name).is_file(), name


def test_demo_report_states_both_rates(demo_dir):
    text = (demo_dir / "report.md").read_text(encoding="utf-8")
    assert "ESR, Phi-valid (binding)" in text
    assert "ESR, feature-space (diagnostic only)" in text
    assert "not** interchangeable" in text or "not interchangeable" in text


def test_demo_reveals_the_gate_rejected_difference(demo_dir):
    report = json.loads((demo_dir / "scan.json").read_text(encoding="utf-8"))
    summary = report["summary"]
    # Fixture is built so feature-space evasion > Phi-valid evasion.
    assert summary["esr_feature_space"]["k"] > summary["esr_phi"]["k"]
    assert summary["population"]["n_gate_rejected"] == 3


def test_digest_verifies_and_render_works(demo_dir, tmp_path):
    out = tmp_path / "rendered"
    assert main(["report", "--scan", str(demo_dir / "scan.json"), "--out", str(out)]) == 0
    assert (out / "report.html").is_file()


def test_tampered_scan_fails_integrity_check(demo_dir, tmp_path):
    scan = json.loads((demo_dir / "scan.json").read_text(encoding="utf-8"))
    scan["summary"]["esr_phi"]["point"] = 0.99  # forged "no evasion" headline
    forged = tmp_path / "forged.json"
    forged.write_text(json.dumps(scan), encoding="utf-8")

    assert main(["report", "--scan", str(forged), "--out", str(tmp_path / "x")]) == 2


def test_signing_produces_signature(tmp_path, monkeypatch):
    monkeypatch.setenv("AETG_VALIDATE_KEY", "unit-test-key")
    out = tmp_path / "signed"
    assert main(["demo", "--out", str(out)]) == 0
    report = json.loads((out / "scan.json").read_text(encoding="utf-8"))
    signature = report["integrity"]["signature"]
    assert signature is not None
    assert signature["alg"] == "hmac-sha256"
    assert len(signature["value"]) == 64


def test_unsigned_report_says_so(demo_dir):
    report = json.loads((demo_dir / "scan.json").read_text(encoding="utf-8"))
    assert report["integrity"]["signature"] is None
    text = (demo_dir / "report.md").read_text(encoding="utf-8")
    assert "none (no signing key configured)" in text


def test_run_from_flow_file_with_suricata(tmp_path):
    flows = tmp_path / "flows.jsonl"
    flows.write_text(
        "\n".join(
            [
                json.dumps({"flow_id": "1", "technique": "ttl", "func_valid": True, "detected": True}),
                json.dumps({"flow_id": "2", "technique": "frag", "func_valid": True, "detected": False}),
            ]
        )
        + "\n",
        encoding="utf-8",
    )
    eve = tmp_path / "eve.json"
    eve.write_text(
        json.dumps(
            {
                "event_type": "alert",
                "flow_id": 1,
                "alert": {"signature_id": 2001219, "signature": "ET SCAN"},
            }
        )
        + "\n",
        encoding="utf-8",
    )
    out = tmp_path / "run"
    assert main(["run", "--input", str(flows), "--suricata", str(eve), "--out", str(out)]) == 0
    report = json.loads((out / "scan.json").read_text(encoding="utf-8"))
    assert report["summary"]["esr_phi"]["k"] == 1
    assert report["summary"]["detection"]["rules_hit"] == ["2001219:ET SCAN"]
    assert any("Suricata" in note for note in report["provenance"]["notes"])


def test_run_without_input_fails_cleanly(tmp_path):
    assert main(["run", "--out", str(tmp_path / "r")]) == 2


# --- 0.2.0: reproducibility vs. tamper-detection ------------------------------


def _write_flows(path, *, detected_second: bool):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(
        "\n".join(
            [
                json.dumps({"flow_id": "1", "technique": "ttl", "func_valid": True, "detected": True}),
                json.dumps(
                    {"flow_id": "2", "technique": "frag", "func_valid": True, "detected": detected_second}
                ),
            ]
        )
        + "\n",
        encoding="utf-8",
    )
    return path


def test_measurement_digest_is_identical_across_paths_and_titles(tmp_path, monkeypatch):
    """The reproducibility claim: same bytes, different machine, same digest."""
    monkeypatch.delenv("AETG_VALIDATE_KEY", raising=False)
    a = _write_flows(tmp_path / "a" / "flows.jsonl", detected_second=False)
    b = _write_flows(tmp_path / "b" / "elsewhere.jsonl", detected_second=False)
    a.parent.mkdir(parents=True, exist_ok=True)
    b.parent.mkdir(parents=True, exist_ok=True)

    assert main(["run", "--input", str(a), "--out", str(tmp_path / "oa"), "--title", "box A"]) == 0
    assert main(["run", "--input", str(b), "--out", str(tmp_path / "ob"), "--title", "box B"]) == 0

    ra = json.loads((tmp_path / "oa" / "scan.json").read_text(encoding="utf-8"))
    rb = json.loads((tmp_path / "ob" / "scan.json").read_text(encoding="utf-8"))

    assert ra["integrity"]["measurement_digest"] == rb["integrity"]["measurement_digest"]
    # The full report digest does differ: different path, different title.
    assert ra["integrity"]["report_digest"] != rb["integrity"]["report_digest"]


def test_measurement_digest_changes_when_the_measurement_changes(tmp_path, monkeypatch):
    monkeypatch.delenv("AETG_VALIDATE_KEY", raising=False)
    same = _write_flows(tmp_path / "same" / "flows.jsonl", detected_second=False)
    other = _write_flows(tmp_path / "other" / "flows.jsonl", detected_second=True)
    same.parent.mkdir(parents=True, exist_ok=True)
    other.parent.mkdir(parents=True, exist_ok=True)

    assert main(["run", "--input", str(same), "--out", str(tmp_path / "o1")]) == 0
    assert main(["run", "--input", str(other), "--out", str(tmp_path / "o2")]) == 0

    d1 = json.loads((tmp_path / "o1" / "scan.json").read_text(encoding="utf-8"))["integrity"]
    d2 = json.loads((tmp_path / "o2" / "scan.json").read_text(encoding="utf-8"))["integrity"]
    assert d1["measurement_digest"] != d2["measurement_digest"]


def test_legacy_report_without_new_digests_is_rejected(tmp_path):
    legacy = tmp_path / "legacy.json"
    legacy.write_text(
        json.dumps(
            {
                "title": "old",
                "provenance": {"tool_version": "0.1.0", "kind": "x", "timestamp": "t", "inputs": [], "notes": []},
                "summary": {"population": {"n_total": 1}},
                "integrity": {"digest": "deadbeef", "signature": None},
            }
        ),
        encoding="utf-8",
    )
    assert main(["report", "--scan", str(legacy), "--out", str(tmp_path / "x")]) == 2
