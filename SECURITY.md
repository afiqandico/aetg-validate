# Security policy

## Reporting a vulnerability

Email **afiqandico13@gmail.com** with subject `[aetg-validate security]`.

Please include: affected version/commit, a reproduction (input file or command),
and the impact you believe it has. Do not open a public issue for a
vulnerability before a fix is available.

Expected response: acknowledgement within 5 business days, assessment within
10 business days. Credit will be given in the release notes unless you ask
otherwise.

## Scope notes

AETG-Validate is an **analysis tool**: it reads logs and flow exports and writes
reports. It does not send packets and does not touch a live network. The realistic
attack surface is therefore:

* **malicious input files** — a crafted `flows.jsonl` / `eve.json` must not be
  able to execute code, exhaust memory unboundedly, or escape the output dir;
* **report integrity** — a forged `scan.json` must not pass the digest check.

Both are covered by tests; reports of gaps are welcome.

## What is explicitly out of scope

* The accuracy of numbers you supply. If your generator lies about
  `func_valid`, the report will faithfully repeat that lie — the tool records
  provenance and digests, it does not independently verify your gate.
* Vulnerabilities in Suricata, Zeek, or your IDS. Report those upstream.

## Supported versions

Latest minor release only, until 1.0.
