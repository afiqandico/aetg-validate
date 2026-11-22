# Commercial licensing

AETG-Validate's core is licensed under **AGPL-3.0-or-later**. That license is
deliberate: it keeps the measurement method open and auditable, which is the
whole reason a validation tool is worth trusting.

AGPL is not compatible with every use case. A commercial license removes the
AGPL obligations for your organisation.

## When you need a commercial license

You need one if you want to:

* embed AETG-Validate (or a modified version) in a **closed-source** product;
* offer it as a **hosted/managed service** without publishing your modifications
  (AGPL §13 network clause);
* ship it inside an appliance or appliance-like distribution;
* obtain a **support SLA** or a signed **report-attestation** for audit purposes.

You do **not** need one to:

* use it internally to test your own IDS (AGPL already allows this);
* run it in CI on your own infrastructure;
* publish reports it generates (they are your data);
* fork it and keep your fork open under AGPL.

## Tiers

| Tier | Includes | Price (annual, per organisation) |
|---|---|---|
| **Community** | CLI, all ingest formats, Phi-gated metrics, JSON/MD reports, 1 target | Free (AGPL-3.0) |
| **Pro** | Commercial license, signed HTML/PDF reports, up to 5 targets, CI integration, rule-coverage pack | **USD 1 490** |
| **Enterprise** | Unlimited targets, SSO, support SLA (48 h), custom rule packs, multi-site consolidated report | **USD 4 900** |
| **Assessment** | We run the validation, write the report, present the findings | **USD 1 200 – 2 500** per engagement |

Prices are per organisation, not per seat. Startups, academic labs and
individual researchers: ask — there is a reduced rate.

## How to buy

Email **afiqandico13@gmail.com** with:

* organisation name and country,
* which tier,
* the target IDS/IPS and how many targets,
* whether you need the PDF attestation or just the license.

You get a signed license file (offline validation, no phone-home) and an
invoice. Payment by bank transfer or Wise.

## Why not just Apache-2.0?

Because a validation tool that anyone can silently fork into a closed product
loses the auditability that makes it credible. AGPL keeps the method open while
still letting organisations that need closed integration pay for that freedom.
