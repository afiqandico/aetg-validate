"""pcap gate, IDS join, and PDF rendering.

These tests build a real pcap on disk with three flows chosen so the two rates
must differ, then check the tool refuses to call an unfinished handshake an
evasion.
"""

import json
import shutil
import subprocess

import pytest

from aetg_validate.cli import main
from aetg_validate.harness import HarnessError, apply_alert_verdicts, load_alerts
from aetg_validate.pcap import PcapError, iter_packets, reconstruct_flows, write_pcap
from aetg_validate.pdf import render_pdf

SYN = 0x02
SYNACK = 0x12
ACK = 0x10

SERVER = "10.0.0.9"


def _pkt(ts, sip, sport, dip, dport, flags, length=60):
    from aetg_validate.pcap import Packet

    return Packet(
        ts=ts,
        src_ip=sip,
        dst_ip=dip,
        src_port=sport,
        dst_port=dport,
        protocol="tcp",
        flags=flags,
        length=length,
    )


def build_capture(path):
    """Three flows: one completed+alerted, one completed+quiet, one never opened."""
    packets = [
        # A: full handshake, will be alerted
        _pkt(1.0, "10.0.0.5", 40001, SERVER, 22, SYN),
        _pkt(1.1, SERVER, 22, "10.0.0.5", 40001, SYNACK),
        _pkt(1.2, "10.0.0.5", 40001, SERVER, 22, ACK),
        # B: full handshake, no alert -> a real evasion
        _pkt(2.0, "10.0.0.5", 40002, SERVER, 22, SYN),
        _pkt(2.1, SERVER, 22, "10.0.0.5", 40002, SYNACK),
        _pkt(2.2, "10.0.0.5", 40002, SERVER, 22, ACK),
        # C: SYN only, handshake never completed -> must be gate-rejected
        _pkt(3.0, "10.0.0.6", 40003, SERVER, 22, SYN),
    ]
    return write_pcap(path, packets)


def write_eve(path, alerted_port=40001):
    events = [
        {
            "event_type": "alert",
            "src_ip": "10.0.0.5",
            "src_port": alerted_port,
            "dest_ip": SERVER,
            "dest_port": 22,
            "proto": "TCP",
            "alert": {"signature_id": 1000001, "signature": "ET SCAN Test Rule"},
        },
        {"event_type": "flow", "src_ip": "10.0.0.5", "src_port": 40002},
    ]
    path.write_text("\n".join(json.dumps(e) for e in events) + "\n", encoding="utf-8")
    return path


# --- pcap parsing ------------------------------------------------------------


def test_capture_is_read_and_flows_reconstructed(tmp_path):
    pcap = build_capture(tmp_path / "cap.pcap")
    packets = list(iter_packets(pcap))
    assert len(packets) == 7

    flows = reconstruct_flows(iter_packets(pcap))
    assert len(flows) == 3

    by_port = {flow.client_port: flow for flow in flows}
    assert by_port[40001].handshake_completed is True
    assert by_port[40002].handshake_completed is True
    assert by_port[40003].handshake_completed is False
    assert by_port[40003].syn_seen is True and by_port[40003].synack_seen is False


def test_pcapng_is_rejected_with_advice(tmp_path):
    bad = tmp_path / "x.pcap"
    bad.write_bytes(b"\x0a\x0d\x0d\x0a" + b"\x00" * 40)
    with pytest.raises(PcapError) as exc:
        list(iter_packets(bad))
    assert "pcapng" in str(exc.value)
    assert "editcap" in str(exc.value)


def test_non_pcep_file_is_rejected(tmp_path):
    bad = tmp_path / "x.pcap"
    bad.write_bytes(b"not a capture at all, honestly" * 2)
    with pytest.raises(PcapError):
        list(iter_packets(bad))


# --- IDS join ----------------------------------------------------------------


def test_alerts_join_by_five_tuple_both_directions(tmp_path):
    pcap = build_capture(tmp_path / "cap.pcap")
    flows = reconstruct_flows(iter_packets(pcap))
    alerts = load_alerts(write_eve(tmp_path / "eve.json"))

    hits, rules = apply_alert_verdicts(flows, alerts)
    assert hits == 1
    assert rules == {"1000001:ET SCAN Test Rule"}
    assert [flow.alert_rules for flow in flows if flow.client_port == 40001] == [
        ["1000001:ET SCAN Test Rule"]
    ]


def test_flow_events_are_not_alerts(tmp_path):
    """eve.json has many event types; only `alert` may count as detection."""
    pcap = build_capture(tmp_path / "cap.pcap")
    flows = reconstruct_flows(iter_packets(pcap))
    alerts = load_alerts(write_eve(tmp_path / "eve.json"))
    assert len(alerts) == 1  # the `flow` event was ignored


def test_missing_eve_raises(tmp_path):
    with pytest.raises(HarnessError):
        load_alerts(tmp_path / "nope.json")


# --- end to end through the CLI ---------------------------------------------


def test_scan_separates_binding_rate_from_naive_rate(tmp_path, monkeypatch):
    monkeypatch.delenv("AETG_VALIDATE_KEY", raising=False)
    pcap = build_capture(tmp_path / "cap.pcap")
    eve = write_eve(tmp_path / "eve.json")
    out = tmp_path / "out"

    assert main(["scan", "--pcap", str(pcap), "--eve-json", str(eve), "--out", str(out)]) == 0

    report = json.loads((out / "scan.json").read_text(encoding="utf-8"))
    summary = report["summary"]

    assert summary["population"]["n_total"] == 3
    assert summary["population"]["n_phi_valid"] == 2
    assert summary["population"]["n_gate_rejected"] == 1

    phi = summary["esr_phi_pct"]
    raw = summary["esr_feature_space_pct"]
    # One of two valid flows escaped -> 50 %. Naively it looks like 2 of 3.
    assert phi["k"] == 1 and phi["n"] == 2
    assert phi["point_pct"] == pytest.approx(50.0)
    assert raw["k"] == 2 and raw["n"] == 3
    assert (out / "report.pdf").is_file()
    assert (out / "report.pdf").read_bytes().startswith(b"%PDF")


def test_scan_without_verdict_source_fails_loudly(tmp_path):
    pcap = build_capture(tmp_path / "cap.pcap")
    assert main(["scan", "--pcap", str(pcap), "--out", str(tmp_path / "o")]) == 2


def test_scan_gate_off_changes_the_number_and_says_so(tmp_path, monkeypatch):
    monkeypatch.delenv("AETG_VALIDATE_KEY", raising=False)
    pcap = build_capture(tmp_path / "cap.pcap")
    eve = write_eve(tmp_path / "eve.json")
    out = tmp_path / "out_off"

    assert (
        main(
            [
                "scan",
                "--pcap", str(pcap),
                "--eve-json", str(eve),
                "--gate", "observed",
                "--out", str(out),
            ]
        )
        == 0
    )
    report = json.loads((out / "scan.json").read_text(encoding="utf-8"))
    assert report["summary"]["population"]["n_phi_valid"] == 3
    assert any("NOT comparable" in note for note in report["provenance"]["notes"])


# --- PDF ---------------------------------------------------------------------


def test_pdf_is_structurally_valid():
    data = render_pdf([("Hello world", 10.0), ("", 10.0)], title="t")
    assert data.startswith(b"%PDF-1.4")
    assert data.rstrip().endswith(b"%%EOF")
    assert b"/Type /Catalog" in data and b"startxref" in data


@pytest.mark.skipif(shutil.which("pdftotext") is None, reason="pdftotext not installed")
def test_pdf_text_is_extractable(tmp_path):
    pdf = tmp_path / "t.pdf"
    pdf.write_bytes(render_pdf([("ESR (Phi-valid, binding): 1.52%", 10.0)], title="t"))
    out = subprocess.run(["pdftotext", str(pdf), "-"], capture_output=True, text=True, check=True)
    assert "Phi-valid" in out.stdout
