# Announcement kit — v0.3.0

Ready-to-post text. Nothing here has been posted yet; publishing under your name
is yours to do. Each block is written for its venue, in English, and says the
same uncomfortable thing: most "IDS evasion rates" count packets that never
completed a handshake.

Do not paste the same block everywhere — adapt the first line to the venue's
rules and post at most one per day.

---

## 1. Show HN

**Title:** Show HN: Measure IDS evasion only on traffic that actually works

**Text:**

Most IDS evasion numbers you see are inflated by garbage. A generator emits
50,000 malformed packets, the IDS alerts on none of them, and the result is
reported as "70 % evasion rate". Those packets would be dropped by the kernel
long before an attacker benefited.

AETG-Validate makes the gate explicit: a flow only counts as an evasion if it is
still functionally valid — for TCP, a SYN answered by a SYN-ACK observed in the
capture. Every rate carries a 95 % Wilson interval, and the tool always prints
two numbers: the Phi-gated rate (binding) and the naive feature-space rate
(diagnostic), never merged into one headline.

```
ESR (Phi-valid, binding) : 0.00% [0.00, 1.88]   (k=0, n=200)
FVR                      : 100.00% [98.12, 100.00]
```

That is a real run against my own research artefacts, not marketing. "0 %
evasion" is a valid and useful answer — it means the controls held.

It reads pcap directly, can run Suricata in a container for you, joins alerts by
5-tuple, and emits JSON/Markdown/HTML/PDF with a reproducible digest so a third
party can re-run your numbers and compare.

Pure Python, zero runtime dependencies, AGPL-3.0, works air-gapped.

https://github.com/afiqandico/aetg-validate

Feedback I am specifically looking for: is the SYN-ACK gate the right definition
for your environment, or do you need application-layer validity (HTTP 200,
TLS handshake) as the gate? That is the next thing on the list.

---

## 2. r/netsec (check their self-post rules first) / r/AskNetsec

**Title:** I built a tool that refuses to count half-open scans as IDS evasions

**Text:**

The two-rate problem, stated plainly: if you generate adversarial traffic and
report "undetected / generated", you are counting packets that never completed a
handshake. Your evasion rate goes up, your actual attack capability does not.

AETG-Validate reports:

* `ESR (Phi-valid)` — of the flows that passed the functional gate, how many
  slipped past the IDS. Binding.
* `ESR (feature-space)` — undetected / all generated. Diagnostic only.

It will not merge them. The CLI prints both, the report labels both, and the
test suite fails if a PR tries to collapse them.

Practical details: reads classic pcap (pure stdlib parser), can invoke Suricata
in a container over your capture, joins alerts by 5-tuple in both directions
(not by Suricata's internal `flow_id`), Wilson 95 % intervals, JSON/MD/HTML/PDF,
SHA-256 measurement digest that is stable across machines.

Code: https://github.com/afiqandico/aetg-validate (AGPL-3.0)
Sample capture that shows a 50 % vs 66.7 % divergence in one command: see
`examples/make_sample_capture.py`.

Disclosure: I am the author, and the method comes from my own adversarial-ML
research. The tool is designed to make researchers' numbers smaller, mine
included — that is the point.

---

## 3. Suricata / OISF community (forum or mailing list)

**Subject:** Tool: Phi-gated validation of Suricata rule coverage (pcap in, report out)

**Body:**

If you have ever tried to answer "does my rule set actually catch this
technique?", the awkward part is not generating traffic — it is deciding which
generated flows deserve to be counted.

AETG-Validate takes a pcap, reconstructs TCP flows, and marks a flow valid only
if it saw a SYN answered by a SYN-ACK. It then either runs Suricata over the
capture in a container (`--docker-image jasonish/suricata:latest`) or consumes an
`eve.json` you already produced (`--eve-json`), and joins alerts to flows by
5-tuple in both directions.

Output: per-service breakdown of generated / Phi-valid / escaped flows, the rules
that fired, Wilson intervals, and a digest anyone can reproduce.

```
aetg-validate scan --pcap capture.pcap \
  --docker-image jasonish/suricata:latest --rules local.rules --out out/
```

Verified against Suricata 8.0.8. Two caveats I would rather state than have you
discover: the gate is TCP-handshake level (not application level), and the
container needs the capture on a path the docker daemon can see.

https://github.com/afiqandico/aetg-validate

Corrections from people who run Suricata in production are the most useful thing
you can send me.

---

## 4. Mastodon / LinkedIn (short)

I published a small tool that measures IDS evasion the boring way: only flows
that completed their TCP handshake are allowed to count as evasions. Every rate
comes with a 95 % Wilson interval, and the naive rate is printed next to the
gated one so nobody can quote the wrong one by accident.

Real result from my own artefacts: 0 of 200 Phi-valid flows escaped — with an
upper bound of 1.88 %, because 0/200 is not zero.

Pure Python, no dependencies, AGPL, runs offline.
https://github.com/afiqandico/aetg-validate

---

## 5. arXiv / preprint — needs your account

An announcement is not a paper. If you want a citable artefact, the honest
route is the existing AETG-DRL manuscript plus this tool as the reference
implementation. Two real blockers only you can clear:

* the arXiv endorsement/account step;
* deciding whether the tool is cited in the paper as submitted or as a separate
  software note.

Suggested software-note abstract (reuse if useful):

> We present AETG-Validate, a reference implementation of Phi-gated evaluation
> for IDS/ML-NIDS evasion claims. The tool admits a flow into the evasion
> denominator only if it remains functionally valid — for TCP, a SYN answered by
> a SYN-ACK observed in the capture — and reports Wilson 95 % intervals for both
> the gated and the ungated rate, keeping them structurally separate. On the
> AETG-DRL reference artefacts, 0 of 200 Phi-valid flows escaped detection
> (upper bound 1.88 %), against a naive feature-space rate that is routinely
> reported in the literature as evidence of IDS failure. Reports carry a
> reproducible measurement digest so published numbers can be independently
> re-derived.

---

## Sequencing that actually moves the number

1. Post Show HN on a weekday morning UTC (Tuesday–Thursday). Link the repo, not a
   landing page — there is no landing page.
2. Answer every comment for the first six hours. The questions people ask become
   the README's FAQ, which is the highest-leverage documentation you can write.
3. Wait for the first issue before touching pricing. A pricing table with zero
   users is fiction; the current one is a hypothesis labelled as such.
4. Only after the first "we ran it on our capture" report should you start the
   assessment offer — that is the tier that converts without a sales team.
