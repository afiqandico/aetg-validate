# Contributing to AETG-Validate

## Ground rules

1. **No claim without a test.** Every number the tool reports must be derivable
   from an input and covered by a test.
2. **Never merge the two rates.** `esr_phi` (binding) and `esr_feature_space`
   (diagnostic) are separate by design. A PR that presents a single "evasion
   rate" will be rejected.
3. **No new runtime dependencies** unless there is no way to do it in the
   standard library. The analysis path must stay installable on an air-gapped box.

## Workflow

```bash
git checkout -b fix/short-description
make install
make test
make verify
```

Commit messages: `type(scope): summary` — e.g. `fix(ingest): keep rule_id when
eve.json has repeated alerts`.

## Adding an input format

1. Add a reader in `src/aetg_validate/ingest.py` returning `List[FlowRecord]`.
2. Raise `IngestError` with the file **and line number** on malformed input.
3. Add tests covering: happy path, malformed line, empty file.
4. Document the format in `README.md` with a one-line example record.

## Adding a metric

New metrics must come with:

* a docstring stating the denominator explicitly;
* a test with hand-computed expected values;
* an interval, or a written justification for why a point estimate is enough.

## Reporting bugs

Open an issue with the exact command, the tool version
(`aetg-validate --version`), and the smallest input that reproduces it.
Redact anything sensitive — see `SECURITY.md`.
