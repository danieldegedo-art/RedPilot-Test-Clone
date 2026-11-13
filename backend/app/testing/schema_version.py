"""Single source of truth for this project's machine-readable result
schema version.

WHY THIS EXISTS
----------------
Before this file, nothing exported by Reporter.to_json() or returned by
the /runs API carried any version marker at all -- a machine consumer
parsing a JSON export had no way to detect that a field was renamed,
removed, or changed meaning between one version of this project and the
next; it would either silently misinterpret the data or fail in a way
that gives no clue why. Grepped for "schema_version"/"SCHEMA_VERSION"
across the whole project before adding this: zero prior hits.

VERSIONING POLICY
-------------------
Semver-shaped, but scoped to the SHAPE of TestResultSchema /
RunSummarySchema / RunDetailSchema (schemas/run.py) and the JSON export
payload (reporter.py), not to the project as a whole:

  MAJOR: a field is removed, renamed, or changes type/meaning in a way
         that breaks an existing consumer's parsing code.
  MINOR: a field is added in a backward-compatible way (existing
         consumers ignoring unknown fields keep working unchanged).
  PATCH: no field-shape change at all -- reserved for the rare case where
         this policy document itself needs a documentation-only fix.

Bump SCHEMA_VERSION in the SAME commit as the schema change that
motivates the bump, never separately -- a version bump with no
accompanying schema diff (or vice versa) is itself a bug this file's
existence is meant to prevent.
"""
from __future__ import annotations

SCHEMA_VERSION = "1.1.0"

# One line per released version, oldest first, so a consumer (or a future
# maintainer) can see what changed between any two versions without
# having to dig through commit history. Append-only: never edit or
# remove a past entry, even to fix a typo -- see lifecycle_model.py's own
# "why the tables moved, not why the state model changed" distinction for
# the same "history is not something you edit in place" principle applied
# here to versions instead of file locations.
CHANGELOG: tuple[tuple[str, str], ...] = (
    ("1.0.0", "Initial versioned schema: TestResultSchema, RunSummarySchema, RunDetailSchema, and the JSON/CSV export payloads as they existed before this field was introduced."),
    ("1.1.0", "Additive only: new TestCategory value 'payment_integrity'; run summary_json gains 'scope_guard' (requests used/denied, kill/deadline state) and 'skipped_modules'; payment_integrity results carry their pre-registered oracle, verdict and hashed evidence under input_parameters['_integrity']; persisted evidence is redacted (secrets masked) and over-long test_case_id values are shortened to <=48 chars with a stable hash suffix."),
)
