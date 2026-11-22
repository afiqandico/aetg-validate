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
