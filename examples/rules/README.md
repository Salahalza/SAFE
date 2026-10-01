# Example external detection rules

These are sample custom detection rules for SAFE's behavioral engine. They are
**not** loaded automatically — copy the ones you want into your active rules
directory:

- `--rules-dir <path>` passed to `safe-analyze --analyze`, or
- the `SAFE_RULES_DIR` environment variable, or
- a `rules/` folder next to the `safe-analyze` executable.

Then re-run `safe-analyze --analyze <case>`.

See `docs/DETECTION_RULES.md` for the full rule-authoring reference (schema,
operators, override/disable semantics).
