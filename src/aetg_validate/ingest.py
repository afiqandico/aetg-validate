"""Readers for flow records and IDS alert logs.

Three input shapes are supported, all of them real formats rather than an
invented one:

1. ``flows.jsonl`` — one JSON object per line (the generator's native output).
2. ``flows.csv``   — the same fields as columns, for spreadsheet people.
3. ``eve.json``    — Suricata's alert log, used to derive ``detected`` from
   the IDS that actually ran, so nobody has to trust a hand-copied verdict.
"""

from __future__ import annotations

import csv
import json
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional, Sequence, Set

from .models import FlowRecord


class IngestError(Exception):
    """Raised when an input file cannot be interpreted."""


def _coerce_bool(value: object, default: bool = True) -> bool:
    if value is None or value == "":
        return default
    if isinstance(value, bool):
        return value
    text = str(value).strip().lower()
    if text in {"1", "true", "yes", "y", "t"}:
        return True
    if text in {"0", "false", "no", "n", "f"}:
        return False
    raise IngestError(f"cannot interpret {value!r} as a boolean")


def read_flows_jsonl(path: Path | str) -> List[FlowRecord]:
    """Read newline-delimited JSON flow records."""
    path = Path(path)
    if not path.is_file():
        raise IngestError(f"flow file not found: {path}")

    records: List[FlowRecord] = []
    with path.open("r", encoding="utf-8") as handle:
        for lineno, line in enumerate(handle, start=1):
            line = line.strip()
            if not line:
                continue
            try:
                raw = json.loads(line)
            except json.JSONDecodeError as exc:
                raise IngestError(f"{path}:{lineno}: invalid JSON ({exc})") from exc
            if not isinstance(raw, dict):
                raise IngestError(f"{path}:{lineno}: expected a JSON object")
            record = FlowRecord.from_dict(raw)
            if not record.flow_id:
                raise IngestError(f"{path}:{lineno}: missing flow_id")
            records.append(record)
    if not records:
        raise IngestError(f"{path}: no flow records found")
    return records


def read_flows_csv(path: Path | str) -> List[FlowRecord]:
    """Read flow records from CSV with a header row."""
    path = Path(path)
    if not path.is_file():
        raise IngestError(f"flow file not found: {path}")

    records: List[FlowRecord] = []
    with path.open("r", encoding="utf-8", newline="") as handle:
        reader = csv.DictReader(handle)
        if not reader.fieldnames:
            raise IngestError(f"{path}: CSV has no header row")
        for row in reader:
            flow_id = (row.get("flow_id") or row.get("id") or "").strip()
            if not flow_id:
                raise IngestError(f"{path}: row without flow_id: {row!r}")
            records.append(
                FlowRecord(
                    flow_id=flow_id,
                    technique=(row.get("technique") or "unknown").strip(),
                    func_valid=_coerce_bool(row.get("func_valid"), True),
                    detected=_coerce_bool(row.get("detected"), True),
                    rule_id=(row.get("rule_id") or None),
                    p_ids=(float(row["p_ids"]) if row.get("p_ids") else None),
                )
            )
    if not records:
        raise IngestError(f"{path}: no flow records found")
    return records


def read_suricata_alerts(path: Path | str) -> Dict[str, Any]:
    """Index Suricata ``eve.json`` alerts by flow id and by rule signature.

    Returns:
        ``{"by_flow": {"1234", ...}, "rules": {"sid:msg", ...}}``
    """
    path = Path(path)
    if not path.is_file():
        raise IngestError(f"Suricata log not found: {path}")

    by_flow: Set[str] = set()
    rules: Set[str] = set()
    rules_by_flow: Dict[str, Set[str]] = {}
    with path.open("r", encoding="utf-8") as handle:
        for lineno, line in enumerate(handle, start=1):
            line = line.strip()
            if not line:
                continue
            try:
                event = json.loads(line)
            except json.JSONDecodeError as exc:
                raise IngestError(f"{path}:{lineno}: invalid JSON ({exc})") from exc
            if event.get("event_type") != "alert":
                continue
            flow_id = event.get("flow_id")
            if flow_id is not None:
                by_flow.add(str(flow_id))
            alert = event.get("alert") or {}
            sid = alert.get("signature_id")
            msg = alert.get("signature")
            if sid is not None and msg:
                label = f"{sid}:{msg}"
                rules.add(label)
                if flow_id is not None:
                    rules_by_flow.setdefault(str(flow_id), set()).add(label)
    return {"by_flow": by_flow, "rules": rules, "rules_by_flow": rules_by_flow}


def apply_suricata_verdicts(
    records: Sequence[FlowRecord], alerts: Dict[str, Any]
) -> int:
    """Overwrite ``detected``/``rule_id`` from a Suricata alert index.

    Only flows whose id appears in the alert index are touched; every other
    flow is marked undetected, which is the honest interpretation of "the IDS
    we ran raised nothing for it".

    Returns the number of flows marked as detected.
    """
    by_flow = alerts.get("by_flow", set())
    rules_by_flow = alerts.get("rules_by_flow", {})
    hit = 0
    for record in records:
        if record.flow_id in by_flow:
            record.detected = True
            matched = rules_by_flow.get(record.flow_id)
            if matched:
                record.rule_id = sorted(matched)[0]
            hit += 1
        else:
            record.detected = False
    return hit


def read_aetg_artifacts(directory: Path | str) -> Dict[str, object]:
    """Read the aggregate artefacts produced by the reference AETG-DRL runs.

    These files contain summary counts only (no per-flow rows), so the tool
    can report real numbers from real runs but cannot break them down by
    technique. Reports built this way say so in their provenance block.
    """
    directory = Path(directory)
    esr_path = directory / "esr_internal.json"
    fvr_path = directory / "fvr_results.json"
    if not esr_path.is_file():
        raise IngestError(f"missing {esr_path}")

    esr_raw = json.loads(esr_path.read_text(encoding="utf-8"))
    fvr_raw: Optional[dict] = None
    if fvr_path.is_file():
        fvr_raw = json.loads(fvr_path.read_text(encoding="utf-8"))

    total = int(esr_raw.get("total_adv_flows", 0))
    detected = int(esr_raw.get("detected", 0))
    undetected = int(esr_raw.get("undetected", total - detected))
    if total <= 0:
        raise IngestError(f"{esr_path}: total_adv_flows must be > 0")

    valid = total
    if fvr_raw:
        valid_steps = int(fvr_raw.get("valid_steps", total))
        total_steps = int(fvr_raw.get("total_steps", total)) or total
        # Scale the FVR ratio onto the flow count so both numbers refer to the
        # same population instead of mixing steps and flows silently.
        valid = max(0, min(total, round(total * valid_steps / total_steps)))

    return {
        "n_total": total,
        "n_valid": valid,
        "n_detected": detected,
        "n_undetected": undetected,
        "fvr_source": str(fvr_path) if fvr_raw else None,
        "esr_source": str(esr_path),
    }


def merge_verdicts(
    records: Iterable[FlowRecord], verdicts: Dict[str, Dict[str, object]]
) -> None:
    """Apply external detector verdicts keyed by flow id."""
    for record in records:
        verdict = verdicts.get(record.flow_id)
        if not verdict:
            continue
        if "detected" in verdict:
            record.detected = bool(verdict["detected"])
        if "p_ids" in verdict and verdict["p_ids"] is not None:
            record.p_ids = float(str(verdict["p_ids"]))
        if verdict.get("rule_id"):
            record.rule_id = str(verdict["rule_id"])
