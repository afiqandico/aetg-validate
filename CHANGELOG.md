# Changelog

All notable changes to this project are documented here.
Format: [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).
Versioning: [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.2.0] — 2026-11-22

### Fixed

- **The reproducibility claim is now actually true.** In 0.1.0 the report digest
  included the generation timestamp, so a re-run produced a different digest and
  "re-run it and you will get the same number" was not verifiable. Reports now
  carry two digests:
  - `measurement_digest` — over tool version, kind, summary and the *content
    hashes* of the inputs. Excludes timestamp, title, notes and file paths, so
    the same bytes on two machines give the same digest.
  - `report_digest` — over the whole document including provenance, so any edit
    is still detected.
  The HMAC signature is now taken over `measurement_digest`, because that is the
  claim a third party can independently re-derive.

### Changed

- `aetg-validate report` verifies both digests and reports which one failed.
- Reports produced by 0.1.0 are rejected with an explicit message rather than
  being silently re-verified against the old schema.
- `requires-python` is now `>=3.10`; CI matrix is 3.10 / 3.12 / 3.13 (Python 3.9
  is no longer available on `ubuntu-latest`).

## [0.1.0] — 2026-11-22

### Added

- Phi-gated metric engine: binding `ESR (Phi-valid)` alongside diagnostic
  `ESR (feature-space)`, both with 95 % Wilson intervals.
- Ingest: `flows.jsonl`, `flows.csv`, Suricata `eve.json`, and the aggregate
  artefacts of a reference AETG-DRL run.
- Reports: canonical `scan.json`, Markdown, self-contained HTML; SHA-256
  integrity digest; optional HMAC-SHA256 signature.
- CLI: `demo`, `run`, `report`.
- 28 tests; `make verify` gate; AGPL-3.0 with a commercial licensing path.
