"""Generate a sample capture + rule set for trying `aetg-validate scan`.

    python examples/make_sample_capture.py --out ./sample
    aetg-validate scan --pcap ./sample/sample.pcap \
        --docker-image jasonish/suricata:latest \
        --rules ./sample/sample.rules --out ./sample/aetg-scan

The capture contains three flows on purpose:

* ``40001 -> 22``  full handshake, matched by the rule  -> detected
* ``40002 -> 23``  full handshake, no rule matches      -> an actual evasion
* ``40003 -> 23``  SYN only, handshake never completed  -> must be gate-rejected

So the correct answer is ESR (Phi-valid) 50 % (1/2) while the naive
feature-space rate reads 66.7 % (2/3). If a tool reports 66.7 % as its headline,
it is counting a half-open scan as an evasion.
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

# Allow running straight from a checkout without installing.
sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "src"))

from aetg_validate.pcap import Packet, write_pcap  # noqa: E402

SYN, SYNACK, ACK = 0x02, 0x12, 0x10
SERVER = "10.0.0.9"

RULE = (
    'alert tcp any any -> any 22 (msg:"AETG sample: SSH connection attempt"; '
    "sid:1000001; rev:1;)\n"
)


def packet(ts, src, sport, dst, dport, flags, length=60):
    return Packet(
        ts=ts,
        src_ip=src,
        dst_ip=dst,
        src_port=sport,
        dst_port=dport,
        protocol="tcp",
        flags=flags,
        length=length,
    )


def build_packets():
    return [
        packet(1.0, "10.0.0.5", 40001, SERVER, 22, SYN),
        packet(1.1, SERVER, 22, "10.0.0.5", 40001, SYNACK),
        packet(1.2, "10.0.0.5", 40001, SERVER, 22, ACK),
        packet(2.0, "10.0.0.5", 40002, SERVER, 23, SYN),
        packet(2.1, SERVER, 23, "10.0.0.5", 40002, SYNACK),
        packet(2.2, "10.0.0.5", 40002, SERVER, 23, ACK),
        packet(3.0, "10.0.0.6", 40003, SERVER, 23, SYN),
    ]


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--out", default="sample", help="output directory")
    args = parser.parse_args(argv)

    out = Path(args.out)
    out.mkdir(parents=True, exist_ok=True)
    pcap = write_pcap(out / "sample.pcap", build_packets())
    rules = out / "sample.rules"
    rules.write_text(RULE, encoding="utf-8")

    print(f"wrote {pcap} ({pcap.stat().st_size} bytes, 7 packets, 3 flows)")
    print(f"wrote {rules}")
    print("\nNext:\n  aetg-validate scan --pcap {p} --docker-image jasonish/suricata:latest "
          "--rules {r} --out {o}/aetg-scan".format(p=pcap, r=rules, o=out))
    print("\nExpected: ESR (Phi-valid) 50.00% (1/2), ESR (feature-space) 66.67% (2/3)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
