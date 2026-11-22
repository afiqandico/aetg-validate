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

Every row below describes something that exists in this repository **today**,
except where the Status column says *roadmap*. Selling a feature that is not
built is how software companies lose the only asset a validation tool has:
credibility.

| Tier | Includes | Price (annual, per organisation) | Status |
|---|---|---|---|
| **Community** | CLI, all ingest formats, Phi-gated metrics, JSON/MD/HTML/PDF reports, HMAC signing (`AETG_VALIDATE_KEY`), unlimited local runs | Free (AGPL-3.0) | available |
| **Pro** | Commercial license (closed embedding / hosted use), next-business-day email support, rule-coverage pack, CI integration help | **USD 1 490** | available |
| **Enterprise** | Unlimited targets, 48 h SLA, custom rule packs, review of your measurement setup before you publish a number | **USD 4 900** | available |
| **Assessment** | We run the validation, write the report, present the findings | **USD 1 200 – 2 500** per engagement | available |
| — | SSO, multi-site consolidated report, hosted dashboard | — | roadmap, not for sale |

Prices are per organisation, not per seat. Startups, academic labs and
individual researchers: ask — there is a reduced rate.

## What you are actually paying for

The code is the same in every tier, and that is on purpose: an auditor must be
able to read the measurement path. What a paid tier buys is the **license
freedom** (closed integration, hosted service) plus a human who answers and, for
Assessment, someone who signs their name under the number.

If you only need to test your own IDS internally, you never have to pay. That is
a feature, not a leak.

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
