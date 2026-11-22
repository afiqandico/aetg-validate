"""Running an IDS against a capture, and joining its verdicts back to flows.

Two supported modes, both honest about what they prove:

1. **Bring your own log** (``--eve-json``): you ran Suricata/Zeek yourself; this
   module only joins its alerts to the reconstructed flows by 5-tuple.
2. **Let the tool run Suricata** (``--docker-image``): AETG-Validate invokes
   Suricata inside a container over your pcap. No image is pulled implicitly —
   if it is not present locally, you will see docker's own error, not a silent
   substitution.

The join is by 5-tuple, in both directions, because Suricata's ``flow_id`` is an
internal hash that has no relationship to the flow ids of a generator manifest.
Joining on it would silently report "nothing detected".
"""

from __future__ import annotations

import json
import shutil
import subprocess
from pathlib import Path
from typing import Any, Dict, Iterable, List, Sequence, Set, Tuple

from .models import FlowRecord
from .pcap import ObservedFlow

AlertKey = Tuple[str, int, str, int, str]


class HarnessError(Exception):
    """Raised when the IDS cannot be run or its output cannot be read."""


def _tuple_from_event(event: Dict[str, Any]) -> AlertKey | None:
    try:
        return (
            str(event["src_ip"]),
            int(event["src_port"]),
            str(event["dest_ip"]),
            int(event["dest_port"]),
            str(event.get("proto", "TCP")).lower(),
        )
    except (KeyError, TypeError, ValueError):
        return None


def load_alerts(eve_path: Path | str) -> Dict[AlertKey, Set[str]]:
    """Index Suricata ``eve.json`` alerts by 5-tuple."""
    path = Path(eve_path)
    if not path.is_file():
        raise HarnessError(f"IDS log not found: {path}")

    alerts: Dict[AlertKey, Set[str]] = {}
    with path.open("r", encoding="utf-8") as handle:
        for lineno, line in enumerate(handle, start=1):
            line = line.strip()
            if not line:
                continue
            try:
                event = json.loads(line)
            except json.JSONDecodeError as exc:
                raise HarnessError(f"{path}:{lineno}: invalid JSON ({exc})") from exc
            if event.get("event_type") != "alert":
                continue
            key = _tuple_from_event(event)
            if key is None:
                continue
            alert = event.get("alert") or {}
            sid = alert.get("signature_id")
            msg = alert.get("signature")
            label = f"{sid}:{msg}" if sid is not None and msg else "unknown-rule"
            alerts.setdefault(key, set()).add(label)
    return alerts


def apply_alert_verdicts(
    flows: Sequence[ObservedFlow], alerts: Dict[AlertKey, Set[str]]
) -> Tuple[int, Set[str]]:
    """Mark each flow detected if any alert matched it in either direction.

    Returns ``(hits, distinct_rules)``.
    """
    hits = 0
    rules: Set[str] = set()
    for flow in flows:
        forward = (flow.client_ip, flow.client_port, flow.server_ip, flow.server_port, flow.protocol)
        reverse = (flow.server_ip, flow.server_port, flow.client_ip, flow.client_port, flow.protocol)
        matched = alerts.get(forward) or alerts.get(reverse)
        if matched:
            hits += 1
            rules |= matched
            setattr(flow, "alert_rules", sorted(matched))
        else:
            setattr(flow, "alert_rules", [])
    return hits, rules


def run_suricata(
    pcap: Path | str,
    out_dir: Path | str,
    *,
    image: str,
    rules: Path | str | None = None,
    timeout: int = 600,
) -> Path:
    """Run Suricata in a container over ``pcap``; return the ``eve.json`` path.

    Refuses to fall back to anything else: if docker is missing or the image is
    not present locally, this raises with the exact command it tried.
    """
    pcap = Path(pcap).resolve()
    out_dir = Path(out_dir).resolve()
    out_dir.mkdir(parents=True, exist_ok=True)

    if shutil.which("docker") is None:
        raise HarnessError(
            "docker not found. Either install docker, or run your IDS yourself "
            "and pass its log with --eve-json."
        )
    if not pcap.is_file():
        raise HarnessError(f"capture not found: {pcap}")

    mount_pcap = "/aetg/in.pcap"
    mount_out = "/aetg/out"
    cmd: List[str] = [
        "docker", "run", "--rm", "--net=none",
        "-v", f"{pcap}:/aetg/in.pcap:ro",
        "-v", f"{out_dir}:{mount_out}",
    ]
    if rules:
        rules_path = Path(rules).resolve()
        if not rules_path.is_file():
            raise HarnessError(f"rules file not found: {rules_path}")
        cmd += ["-v", f"{rules_path}:/aetg/rules.rules:ro"]
        cmd += [image, "-r", mount_pcap, "-l", mount_out, "-S", "/aetg/rules.rules"]
    else:
        cmd += [image, "-r", mount_pcap, "-l", mount_out]

    try:
        completed = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
    except subprocess.TimeoutExpired as exc:
        raise HarnessError(f"suricata timed out after {timeout}s: {' '.join(cmd)}") from exc

    eve = out_dir / "eve.json"
    if completed.returncode != 0 and not eve.is_file():
        detail = (completed.stderr or completed.stdout or "").strip().splitlines()[-6:]
        raise HarnessError(
            "suricata failed (exit %d).\n  command: %s\n  output: %s"
            % (completed.returncode, " ".join(cmd), " | ".join(detail))
        )
    if not eve.is_file():
        raise HarnessError(
            f"suricata exited {completed.returncode} but produced no eve.json in {out_dir}.\n"
            "  If the capture lives under a private /tmp (systemd PrivateTmp), the docker\n"
            "  daemon cannot see it and mounts an empty directory instead — keep the\n"
            f"  capture under your home directory. Command tried: {' '.join(cmd)}"
        )
    return eve


def to_flow_records(
    flows: Iterable[ObservedFlow],
    *,
    gate: str = "synack",
    group_by: str = "service",
) -> List[FlowRecord]:
    """Convert observed flows into the record shape the metric engine uses."""
    records: List[FlowRecord] = []
    for flow in flows:
        if gate == "synack":
            valid = flow.handshake_completed
        elif gate == "observed":
            valid = True
        else:
            raise HarnessError(f"unknown gate {gate!r} (expected synack or observed)")

        if group_by == "service":
            technique = f"service:{flow.server_port}/{flow.protocol}"
        elif group_by == "client":
            technique = f"client:{flow.client_ip}"
        else:
            raise HarnessError(f"unknown grouping {group_by!r} (expected service or client)")

        rules = getattr(flow, "alert_rules", []) or []
        records.append(
            FlowRecord(
                flow_id=flow.flow_id,
                technique=technique,
                func_valid=valid,
                detected=bool(rules),
                rule_id=(rules[0] if rules else None),
                p_ids=None,
                params=flow.to_dict(),
            )
        )
    return records
