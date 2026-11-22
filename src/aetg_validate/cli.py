"""Command-line interface for AETG-Validate.

Subcommands:

``demo``    run a self-contained, deterministic synthetic scan (no docker, no
            network) so anyone can see the output shape in seconds;
``run``     scan real inputs — flow records, Suricata ``eve.json``, or the
            aggregate artefacts of a reference AETG-DRL run;
``report``  re-render a saved ``scan.json`` and verify its digest.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import random
import sys
from pathlib import Path
from typing import Any, Dict, List, Optional, Sequence

from . import __version__
from .ingest import (
    IngestError,
    apply_suricata_verdicts,
    read_aetg_artifacts,
    read_flows_csv,
    read_flows_jsonl,
    read_suricata_alerts,
)
from .models import FlowRecord, ScanMetrics, TechniqueBreakdown
from .harness import HarnessError, apply_alert_verdicts, load_alerts, run_suricata, to_flow_records
from .pcap import PcapError, iter_packets, reconstruct_flows
from .pdf import write_pdf
from .report import (
    TOOL_NAME,
    digest,
    measurement_digest,
    pdf_lines,
    render_html,
    render_markdown,
    sign,
    utc_now,
)
from .scan import compute, summarize

DEFAULT_RULES = [
    "2001219:ET SCAN Potential SSH Scan",
    "2010935:ET POLICY Outbound SSH",
    "2024218:ET MALWARE Possible Reverse Shell",
    "2013028:ET POLICY Suspicious NULL Scan",
    "2100498:GPL ATTACK_RESPONSE id check returned root",
]

DEMO_TECHNIQUES = [
    "tcp_fragmentation",
    "ttl_manipulation",
    "window_size_scaling",
    "tcp_options_padding",
    "flag_anomaly",
    "source_port_rotation",
    "dest_port_rotation",
    "payload_segmentation",
]


class CliError(Exception):
    """User-facing failure (bad arguments, unreadable input, failed check)."""


def _sha256(path: Path) -> str:
    hasher = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1 << 16), b""):
            hasher.update(chunk)
    return hasher.hexdigest()


def _build_report(
    *,
    summary: Dict[str, Any],
    title: str,
    kind: str,
    inputs: Sequence[Dict[str, Any]],
    notes: Sequence[str],
    key: Optional[str],
    tool_version: str = __version__,
) -> Dict[str, Any]:
    """Assemble a report with two digests.

    ``measurement_digest`` covers only what a re-run can reproduce (tool
    version, kind, summary, input content hashes) — no timestamp, no title, no
    paths. ``report_digest`` covers the whole document including its provenance,
    so nothing can be edited without being noticed. The signature is over the
    measurement digest, because that is the claim someone else can re-derive.
    """
    provenance = {
        "tool": TOOL_NAME,
        "tool_version": tool_version,
        "timestamp": utc_now(),
        "kind": kind,
        "inputs": list(inputs),
        "notes": list(notes),
    }
    payload = {"title": title, "provenance": provenance, "summary": summary}
    report_d = digest(payload)
    meas_d = measurement_digest(
        tool_version=tool_version, kind=kind, summary=summary, inputs=inputs
    )
    payload["integrity"] = {
        "measurement_digest": meas_d,
        "report_digest": report_d,
        "signature": sign(meas_d, key),
    }
    return payload


def _write_outputs(report: Dict[str, Any], out_dir: Path) -> Dict[str, Path]:
    out_dir.mkdir(parents=True, exist_ok=True)
    if "integrity" not in report:
        raise CliError("refusing to write a report without an integrity block")

    written: Dict[str, Path] = {}
    written["json"] = out_dir / "scan.json"
    written["json"].write_text(json.dumps(report, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    written["md"] = out_dir / "report.md"
    written["md"].write_text(render_markdown(report), encoding="utf-8")
    written["html"] = out_dir / "report.html"
    written["html"].write_text(render_html(report), encoding="utf-8")
    written["pdf"] = out_dir / "report.pdf"
    write_pdf(written["pdf"], pdf_lines(report), title=report["title"])
    return written


def _demo_records(seed: int = 20261022) -> List[FlowRecord]:
    """Deterministic synthetic scan.

    Deliberately constructed so the two rates differ: three flows are evasions
    that also passed the gate, and one more evasion never completed a
    handshake. A tool that reported a single number would hide that
    distinction; this is exactly the case the product exists to expose.
    """
    rng = random.Random(seed)
    records: List[FlowRecord] = []
    index = 0
    for technique in DEMO_TECHNIQUES:
        for _ in range(25):
            index += 1
            func_valid = index not in {14, 97, 188}
            detected = index not in {31, 88, 143, 97}
            records.append(
                FlowRecord(
                    flow_id=f"demo-{index:04d}",
                    technique=technique,
                    func_valid=func_valid,
                    detected=detected,
                    rule_id=(DEFAULT_RULES[index % len(DEFAULT_RULES)] if detected else None),
                    p_ids=(round(rng.uniform(0.90, 0.99999), 6) if detected else round(rng.uniform(0.0001, 0.45), 6)),
                    params={"demo": True},
                )
            )
    return records


def _metrics_from_artifacts(directory: Path) -> ScanMetrics:
    """Rebuild counts from aggregate artefacts.

    The artefacts carry totals only, so one thing cannot be recovered: whether
    an undetected flow also passed the functional gate. We take the worst case
    for the detector under test (every undetected flow counted as Phi-valid),
    and the report says so in its notes. Worst case instead of best case is the
    honest direction: a validation tool must not flatter the thing it validates.
    """
    data = read_aetg_artifacts(directory)
    n_total = int(data["n_total"])  # type: ignore[arg-type]
    n_valid = int(data["n_valid"])  # type: ignore[arg-type]
    n_undetected = int(data["n_undetected"])  # type: ignore[arg-type]

    gate_rejected = max(0, n_total - n_valid)
    escaped_raw = max(0, min(n_undetected, n_total))
    escaped_phi = min(escaped_raw, n_valid)

    techniques = [
        TechniqueBreakdown(
            technique="(aggregate artefacts: per-technique breakdown unavailable)",
            n_total=n_total,
            n_valid=n_valid,
            n_escaped=escaped_phi,
        )
    ] if n_total else []

    return ScanMetrics(
        n_total=n_total,
        n_valid=n_valid,
        n_gate_rejected=gate_rejected,
        n_escaped_phi=escaped_phi,
        n_escaped_raw=escaped_raw,
        rules_hit=[],
        min_p_ids=None,
        techniques=techniques,
    )



def _load_records(path: Path, fmt: str) -> List[FlowRecord]:
    suffix = path.suffix.lower()
    if fmt == "auto":
        fmt = "csv" if suffix == ".csv" else "jsonl"
    if fmt == "csv":
        return read_flows_csv(path)
    if fmt == "jsonl":
        return read_flows_jsonl(path)
    raise CliError(f"unknown format {fmt!r} (expected auto, csv or jsonl)")


def _input_meta(path: Path, records: int) -> Dict[str, Any]:
    return {"path": str(path), "sha256": _sha256(path), "records": records}


def cmd_demo(args: argparse.Namespace) -> int:
    records = _demo_records()
    summary = summarize(compute(records))
    report = _build_report(
        summary=summary,
        title=args.title,
        kind="synthetic demo (deterministic, seed=20261022) — NOT a measurement of any real IDS",
        inputs=[{"path": "(generated in memory)", "sha256": hashlib.sha256(b"aetg-validate-demo").hexdigest(), "records": len(records)}],
        notes=[
            "Synthetic data. Run `aetg-validate run` against a real eve.json or flow export before drawing any conclusion.",
            "esr_phi is the binding number; esr_feature_space is diagnostic only.",
        ],
        key=os.environ.get("AETG_VALIDATE_KEY"),
    )
    written = _write_outputs(report, Path(args.out))
    _print_result(report, written)
    return 0


def cmd_run(args: argparse.Namespace) -> int:
    inputs: List[Dict[str, Any]] = []
    notes: List[str] = []

    if args.aetg_artifacts:
        directory = Path(args.aetg_artifacts)
        metrics = _metrics_from_artifacts(directory)
        for name in ("esr_internal.json", "fvr_results.json"):
            candidate = directory / name
            if candidate.is_file():
                inputs.append(_input_meta(candidate, 0))
        kind = "reference AETG-DRL aggregate artefacts (per-technique breakdown unavailable)"
    elif args.input:
        path = Path(args.input)
        records = _load_records(path, args.format)
        inputs.append(_input_meta(path, len(records)))
        if args.suricata:
            eve = Path(args.suricata)
            alerts = read_suricata_alerts(eve)
            hits = apply_suricata_verdicts(records, alerts)
            inputs.append(_input_meta(eve, len(alerts["by_flow"])))
            notes.append(
                f"`detected` was derived from Suricata eve.json: {hits}/{len(records)} flows matched an alert."
            )
        metrics = compute(records)
        kind = "flow records + IDS alert log" if args.suricata else "flow records"
    else:
        raise CliError("run needs either --input or --aetg-artifacts")

    if metrics.n_total <= 0:
        raise CliError("no flows were read; refusing to emit an empty report")

    if metrics.n_valid < metrics.n_total:
        notes.append(
            f"{metrics.n_gate_rejected} flow(s) were rejected by the functional gate and are excluded "
            "from the binding metric."
        )
    notes.append("esr_phi is the binding number; esr_feature_space is diagnostic only.")

    for extra in args.note or []:
        notes.append(extra)

    summary = summarize(metrics)
    report = _build_report(
        summary=summary,
        title=args.title,
        kind=kind,
        inputs=inputs,
        notes=notes,
        key=os.environ.get("AETG_VALIDATE_KEY"),
    )
    written = _write_outputs(report, Path(args.out))
    _print_result(report, written)
    return 0


def cmd_scan(args: argparse.Namespace) -> int:
    """Scan a pcap: the gate is decided from the capture, not asserted by you."""
    pcap_path = Path(args.pcap)
    flows = reconstruct_flows(iter_packets(pcap_path))
    if not flows:
        raise CliError(f"no TCP/UDP flows found in {pcap_path}")

    inputs: List[Dict[str, Any]] = [_input_meta(pcap_path, len(flows))]
    notes: List[str] = []

    if args.eve_json:
        eve_path = Path(args.eve_json)
        alerts = load_alerts(eve_path)
        inputs.append(_input_meta(eve_path, sum(len(r) for r in alerts.values())))
        notes.append(f"`detected` came from an IDS log you supplied: {eve_path}")
    elif args.docker_image:
        ids_dir = Path(args.out) / "ids-run"
        eve_path = run_suricata(pcap_path, ids_dir, image=args.docker_image, rules=args.rules)
        alerts = load_alerts(eve_path)
        inputs.append(_input_meta(eve_path, sum(len(r) for r in alerts.values())))
        notes.append(
            f"`detected` came from Suricata run by this tool (image {args.docker_image}) over {pcap_path.name}."
        )
    else:
        raise CliError(
            "scan needs --eve-json (bring your own IDS log) or --docker-image "
            "(let this tool run Suricata in a container). Neither is guessed."
        )

    hits, rules = apply_alert_verdicts(flows, alerts)
    records = to_flow_records(flows, gate=args.gate, group_by=args.group_by)
    metrics = compute(records)

    if args.gate == "synack":
        notes.append(
            "Functional gate = a TCP SYN answered by a SYN-ACK observed in the capture. "
            "Flows without a completed handshake are excluded from the binding metric."
        )
    else:
        notes.append(
            "Functional gate DISABLED (--gate observed): every flow in the capture counts as valid. "
            "The resulting rate is NOT comparable to a Phi-gated number."
        )

    notes.append(
        f"Alerts were joined to flows by 5-tuple in both directions ({hits}/{len(flows)} flows matched)."
    )
    notes.append("esr_phi is the binding number; esr_feature_space is diagnostic only.")
    for extra in args.note or []:
        notes.append(extra)

    summary = summarize(metrics)
    report = _build_report(
        summary=summary,
        title=args.title,
        kind="pcap capture + IDS alerts (5-tuple join)",
        inputs=inputs,
        notes=notes,
        key=os.environ.get("AETG_VALIDATE_KEY"),
    )
    written = _write_outputs(report, Path(args.out))
    _print_result(report, written)
    return 0


def cmd_report(args: argparse.Namespace) -> int:
    scan_path = Path(args.scan)
    if not scan_path.is_file():
        raise CliError(f"scan file not found: {scan_path}")
    report = json.loads(scan_path.read_text(encoding="utf-8"))

    integrity = report.get("integrity") or {}
    stored_meas = integrity.get("measurement_digest")
    stored_rep = integrity.get("report_digest")
    if not stored_meas or not stored_rep:
        raise CliError(
            "scan file has no measurement/report digest; it was not produced by "
            "this tool (or predates 0.2.0)"
        )

    recomputed_rep = digest(
        {"title": report["title"], "provenance": report["provenance"], "summary": report["summary"]}
    )
    provenance = report["provenance"]
    recomputed_meas = measurement_digest(
        tool_version=provenance["tool_version"],
        kind=provenance["kind"],
        summary=report["summary"],
        inputs=provenance.get("inputs", []),
    )

    failures = []
    if recomputed_rep != stored_rep:
        failures.append(
            f"report digest: stored={stored_rep[:16]}… recomputed={recomputed_rep[:16]}…"
        )
    if recomputed_meas != stored_meas:
        failures.append(
            f"measurement digest: stored={stored_meas[:16]}… recomputed={recomputed_meas[:16]}…"
        )
    if failures:
        print("INTEGRITY CHECK FAILED: " + "; ".join(failures), file=sys.stderr)
        return 2

    out_dir = Path(args.out)
    out_dir.mkdir(parents=True, exist_ok=True)
    if args.format in {"md", "all"}:
        (out_dir / "report.md").write_text(render_markdown(report), encoding="utf-8")
    if args.format in {"html", "all"}:
        (out_dir / "report.html").write_text(render_html(report), encoding="utf-8")
    if args.format in {"pdf", "all"}:
        write_pdf(out_dir / "report.pdf", pdf_lines(report), title=report["title"])
    print(f"integrity OK  measurement={stored_meas[:16]}…  report={stored_rep[:16]}…")
    print(f"rendered {args.format} into {out_dir}")
    return 0


def _print_result(report: Dict[str, Any], written: Dict[str, Path]) -> None:
    summary = report["summary"]
    phi = summary.get("esr_phi_pct")
    raw = summary["esr_feature_space_pct"]
    fvr = summary["fvr_pct"]
    print(f"ESR (Phi-valid, binding) : {phi['point_pct']:.2f}% [{phi['low_pct']:.2f}, {phi['high_pct']:.2f}]  (k={phi['k']}, n={phi['n']})" if phi else "ESR (Phi-valid, binding) : n/a (no Phi-valid flows)")
    print(f"ESR (feature-space)      : {raw['point_pct']:.2f}% [{raw['low_pct']:.2f}, {raw['high_pct']:.2f}]  (k={raw['k']}, n={raw['n']})")
    print(f"FVR                      : {fvr['point_pct']:.2f}% [{fvr['low_pct']:.2f}, {fvr['high_pct']:.2f}]  (k={fvr['k']}, n={fvr['n']})")
    print(f"rules fired              : {summary['detection']['rules_hit_count']}")
    print(f"measurement digest       : {report['integrity']['measurement_digest'][:32]}…  (reproducible)")
    print(f"report digest            : {report['integrity']['report_digest'][:32]}…  (includes timestamp)")
    for kind, path in written.items():
        print(f"  {kind:4s} -> {path}")


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="aetg-validate",
        description=(
            "Validate an IDS/ML-NIDS the way it deserves: measure evasion only on "
            "traffic that is still functionally valid (Phi-gated), and report "
            "intervals instead of a single misleading number."
        ),
    )
    parser.add_argument("--version", action="version", version=f"{TOOL_NAME} {__version__}")
    sub = parser.add_subparsers(dest="command", required=True)

    demo = sub.add_parser("demo", help="run a deterministic synthetic scan (no docker, no network)")
    demo.add_argument("--out", default="aetg-demo-report", help="output directory")
    demo.add_argument("--title", default="synthetic demo")
    demo.set_defaults(func=cmd_demo)

    run = sub.add_parser("run", help="scan flow records, a Suricata eve.json, or AETG-DRL artefacts")
    run.add_argument("--input", help="flows.jsonl or flows.csv")
    run.add_argument("--format", default="auto", choices=["auto", "jsonl", "csv"])
    run.add_argument("--suricata", help="Suricata eve.json used to derive the `detected` field")
    run.add_argument("--aetg-artifacts", help="directory containing esr_internal.json + fvr_results.json")
    run.add_argument("--out", default="aetg-report", help="output directory")
    run.add_argument("--title", default="IDS evasion validation")
    run.add_argument("--note", action="append", help="extra provenance note (repeatable)")
    run.set_defaults(func=cmd_run)

    rep = sub.add_parser("report", help="re-render a saved scan.json and verify its digest")
    rep.add_argument("--scan", required=True, help="path to scan.json")
    rep.add_argument("--out", default="aetg-report-rendered")
    rep.add_argument("--format", default="all", choices=["md", "html", "pdf", "all"])
    rep.set_defaults(func=cmd_report)

    scan = sub.add_parser(
        "scan",
        help="scan a pcap capture (gate decided from the capture) with an IDS verdict",
    )
    scan.add_argument("--pcap", required=True, help="classic pcap file to scan")
    scan.add_argument("--eve-json", help="Suricata eve.json you produced yourself")
    scan.add_argument("--docker-image", help="container image to run Suricata from (e.g. jasonish/suricata:latest)")
    scan.add_argument("--rules", help="Suricata rules file (used with --docker-image)")
    scan.add_argument("--gate", default="synack", choices=["synack", "observed"])
    scan.add_argument("--group-by", default="service", choices=["service", "client"])
    scan.add_argument("--out", default="aetg-scan-report", help="output directory")
    scan.add_argument("--title", default="pcap scan")
    scan.add_argument("--note", action="append", help="extra provenance note (repeatable)")
    scan.set_defaults(func=cmd_scan)

    return parser


def main(argv: Optional[Sequence[str]] = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    try:
        return int(args.func(args))
    except (CliError, IngestError, PcapError, HarnessError, ValueError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
