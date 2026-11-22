# AETG-Validate

**Phi-gated IDS / ML-NIDS evasion validation with confidence intervals.**

Most "IDS evasion" numbers are not measurements — they count packets that never
completed a handshake. AETG-Validate refuses to do that: a flow only counts as an
evasion if it is still **functionally valid** (the gate we call Phi), and every rate
is reported with a **95 % Wilson confidence interval**.

```
ESR (Phi-valid, binding) : 0.00% [0.00, 1.88]  (k=0, n=200)
ESR (feature-space)      : 0.00% [0.00, 1.88]  (k=0, n=200)
FVR                      : 100.00% [98.12, 100.00]  (k=200, n=200)
```

That output is a **real run** against the reference AETG-DRL artefacts
(UNSW-NB15, 175 341 flows, audited XGBoost detector, AUC 0.9925). "0 % evasion"
is a legitimate — and much more useful — result than an invented 70 %.

---

## Why Phi matters

| What people report | What it actually measures |
|---|---|
| "70 % evasion rate" | 70 % of generated packets were not alerted on, **including** malformed ones that would be dropped by any real stack |
| `ESR (Phi-valid)` | of the flows that completed their handshake, how many slipped past the IDS |

Without the gate, a generator can reach a 100 % "evasion rate" by emitting
garbage. With the gate, the number survives contact with a security reviewer.

AETG-Validate always reports **both**, labels them, and puts the Phi-valid
number first. It never merges them into one headline.

## Install

```bash
git clone https://github.com/afiqandico/aetg-validate
cd aetg-validate
python3 -m venv .venv && . .venv/bin/activate
pip install -e .
```

No runtime dependencies: the analysis path is pure standard library.

## Try it in 10 seconds (no docker, no network)

```bash
aetg-validate demo --out aetg-demo-report
```

The demo is deterministic synthetic data and says so in its provenance block.
It exists to show the output shape, not to measure anything.

## Run it against your own IDS

### From flow records + a Suricata alert log

```bash
aetg-validate run \
  --input flows.jsonl \
  --suricata /var/log/suricata/eve.json \
  --out aetg-report \
  --title "prod-soc-2026-11"
```

`detected` is then derived from the IDS that actually ran, not from a
hand-copied verdict. The join key is `flow_id`, so your flow records and
`eve.json` must agree on it — if they do not, every flow is reported as
undetected (silently inflating the evasion rate), which is why the run prints
the match count and records it in the report notes.

### From flow records you already scored yourself

```bash
aetg-validate run --input flows.csv --out aetg-report
```

Flow record fields (`flows.jsonl`, one object per line):

```json
{"flow_id": "0001", "technique": "tcp_fragmentation",
 "func_valid": true, "detected": false, "rule_id": null, "p_ids": 0.031}
```

* `func_valid` — did the flow pass your functional gate (SYN-ACK, HTTP 200, …)?
* `detected` — did the IDS raise an alert for it?
* `p_ids` — optional detector confidence, if it exposes one.

### From a packet capture (the gate is decided from the capture, not by you)

```bash
# let this tool run Suricata for you (no implicit image pull)
aetg-validate scan --pcap capture.pcap \
  --docker-image jasonish/suricata:latest \
  --rules local.rules --out aetg-scan

# or bring the IDS log you already produced
aetg-validate scan --pcap capture.pcap --eve-json /var/log/suricata/eve.json --out aetg-scan
```

In this mode a flow is Phi-valid only if the capture shows a **SYN answered by a
SYN-ACK**. Flows that never opened a connection are excluded from the binding
metric — the tool will not let a half-open scan pass for an evasion.

Alerts are joined to flows by **5-tuple in both directions** (Suricata's internal
`flow_id` has no relationship to a generator's ids; joining on it would silently
report "nothing detected").

`--gate observed` disables the gate; the report then says so in bold print,
because that number is not comparable to a Phi-gated one.

> Docker caveat: the daemon must be able to see the capture. If your shell's
> `/tmp` is private (`systemd PrivateTmp`), docker will mount an empty directory
> there — keep the pcap under your home directory.

### Verify a report someone sent you

```bash
aetg-validate report --scan aetg-report/scan.json --out verified/
```

Both digests are recomputed. A tampered report fails with exit code 2 — try it:
edit `esr_phi.point` in `scan.json` and watch the check refuse.

Because `measurement_digest` ignores timestamps, titles, notes and input paths,
two people scanning the same bytes on different machines get the **same**
measurement digest. That is the number worth quoting in a report — quote it,
not the report digest.

## What this tool claims — and what it does not

**Claims**

* evasion rates are measured only on functionally valid traffic;
* every rate carries a Wilson 95 % interval, so `0/200` reads as
  `[0, 1.88] %`, not as "impossible";
* a report carries a **reproducible** `measurement_digest` (over tool version,
  summary and input content hashes — no timestamp, no paths) plus a
  `report_digest` over the whole document, so a re-run on the same bytes yields
  the same measurement digest and any edit is still detected.

**Does not claim**

* that a low evasion rate means the IDS is secure;
* that feature-space evasion is irrelevant — it is a real signal, it is just
  not a *wire-level* claim;
* anything about IDS you did not actually run.

## Output

| File | Purpose |
|---|---|
| `scan.json` | canonical payload + provenance + digest (machine readable) |
| `report.md` | human-readable summary (Markdown) |
| `report.html` | self-contained, no JS, no external assets |
| `report.pdf` | one-file artefact for auditors — generated in pure Python, no browser or LaTeX needed |

## Development

```bash
make install   # editable install + pytest
make test      # 42 tests
make verify    # tests + demo + digest re-verification
```

## License

Core is **AGPL-3.0-or-later**. If you want to embed AETG-Validate in a closed
product, or run a modified version as a network service without publishing your
modifications, a **commercial license** is available — see
[COMMERCIAL.md](COMMERCIAL.md).

## Background

The Phi-gate and the two-rate reporting convention come from the AETG-DRL
research programme on adversarial Machine Learning for network intrusion
detection: PPO-generated problem-space evasion against an audited XGBoost
detector, with a functional verifier standing between "generated" and "counted".

See [docs/PRODUCT_DECISION_2026-11-22.md](docs/PRODUCT_DECISION_2026-11-22.md)
for why this product exists and who it is for.
