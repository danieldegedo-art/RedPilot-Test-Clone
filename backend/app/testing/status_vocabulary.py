"""Provider status-vocabulary mapping: translates a provider's own status
strings ("SETTLED", "AUTH", "VOIDED", ...) to the canonical state names
app.testing.lifecycle_model.py defines ("captured", "authorized",
"cancelled", ...).

WHY THIS IS SEPARATE FROM EndpointMap
----------------------------------------
EndpointMap (endpoints.py) solves "which route reaches which operation" --
a REQUEST-side problem. This solves a RESPONSE-side problem: what a
provider's status field actually MEANS. The two are independent axes (a
provider can differ in either, both, or neither), and conflating them
into one config would make the common case -- same status vocabulary,
different routes, which is what Provider A and Provider B in this
project's own verification infrastructure both do -- carry configuration
for a problem it doesn't have. IDENTITY below is exactly that common
case: an empty mapping that passes every string through unchanged.

WHY THIS MATTERS BEYOND BOOKKEEPING (the actual reason it was built, not
just to close a documentation gap): grepped state_machine_exploration.py
before writing this file -- no line reads a response's `status` field at
all; every existing check compares only HTTP status CODES (2xx/4xx). That
is sufficient for "was this operation accepted or rejected" but not for
the payment-integrity mission's trust-boundary concern: whether a
CLAIMED status (from a return-flow page, a client-supplied field, or any
source this project does not independently control) agrees with an
EXTERNALLY OBSERVED outcome. Comparing those requires canonicalizing both
sides first -- a claim of "SETTLED" and an observed "captured" are the same
fact under Provider C's vocabulary, and a naive string comparison would
wrongly treat every Provider-C response as a mismatch.
PURE BLACK-BOX NOTE: the authority is never a target-internal record. The
only authority the project accepts is an external Protected-Feature Oracle
(app/testing/integrity/oracle.py: a synthetic identity actually USES the
server-enforced feature); a claimed status is judged against that, and a
disagreement is reported as a divergence (PBB-E), never as an internal
cause. (The legacy check that required the target's own server-side record
was quarantined: backend/quarantine/legacy_greybox/.)
"""
from __future__ import annotations

from dataclasses import dataclass, field


@dataclass(frozen=True)
class StatusVocabulary:
    payment: dict[str, str] = field(default_factory=dict)
    subscription: dict[str, str] = field(default_factory=dict)

    def canonicalize(self, raw_status: str | None, resource_type: str = "payment") -> str | None:
        """Returns the canonical lifecycle_model state name for
        `raw_status`, or `raw_status` itself UNCHANGED if it isn't in the
        map -- an unrecognized status is a real, reportable finding (an
        unmapped status this vocabulary doesn't know about yet), not
        something to silently drop or crash on. Callers that need to
        distinguish "known and mapped" from "passed through unmapped"
        should check `raw_status in self.payment` (or `.subscription`)
        themselves; this method's contract is "always returns something
        usable for a canonical comparison, never raises, never returns
        None unless given None."""
        if raw_status is None:
            return None
        table = self.subscription if resource_type == "subscription" else self.payment
        return table.get(raw_status, raw_status)


# The common case: a provider that already reports canonical names
# (Provider A and Provider B in this project's own verification
# infrastructure both do). An empty dict is a correct, complete
# vocabulary for such a provider -- not a placeholder for "not configured
# yet".
IDENTITY = StatusVocabulary()
