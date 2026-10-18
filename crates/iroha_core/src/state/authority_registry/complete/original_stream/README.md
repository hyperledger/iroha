# Original State byte stream

This internal adapter borrows the existing frozen `StateBlock`. It does not open
State views, build another state copy, select a root implementation, or grant
proof, finality, execution, or publication authority.

The existing World field declaration supplies all native table and cell sources.
The authority registry determines the exact complete set, including empty tables
and all cells. Trigger and executor owners encode borrowed semantic values;
Musubi's existing publisher must finish both original-image semantic checks and
retire its temporary structural readers before complete capture. Policy codecs
consume original runtime/parameter cells and the policy handles already captured
in the same block. Current process handles are never read.

The existing construction owner now retains oracle, governance, content,
settlement, and cryptography inputs in one immutable bundle. Blocks expose only
shared field access and transactions borrow that exact bundle, including the
original crypto Arc. There is no mutable test escape or replacement constructor:
fixtures configure State before acquisition. This prevents a temporary change to
an execution input from being hidden before publication. It establishes original
input custody only: these five families still originate in node configuration,
and freezing them does not migrate their validity semantics to committed policy.
TODO: complete that policy ownership migration under the existing canonical
owners; this adapter does not close F.4 or the related G1 policy defects.

Every retained frame and row backing belongs to the original State allocation
pool. A partial row keeps its key and any completed value; completed fields and
rows survive refusal. The retry retains the same block borrow and fixed limits.
No capacity refusal is converted to transaction rejection or an empty table.
Physical source-row scans share one admission counter per traversal. Native
current/undo scans include retained prefixes; each membership count/filter scan
admits the original owner's physical count, including filtered history rows.
A retry resets only traversal admission, retaining source identities and bytes.
Canonical frame byte work and policy-internal collection work remain separately
bounded; source-row admission does not claim to measure elapsed CPU time.
Every delivery rechecks the exact source targets and generation. Consumer
refusals stop emission and preserve their original error; consumers must keep
partial work provisional until the complete visit succeeds.

Fields and keys are ordered by their exact canonical bytes. Cell keys are empty.
Native changes preserve every original undo entry, including equal-value and
absent-to-absent touches. A mutation written repeatedly emits its first preimage
once. Membership is a full replacement of each of the two complete tables under
one prepared source surface and frontier. Consumers **must clear the preceding
table even if the replacement is empty**; this branch makes no incremental-work
claim and does not manufacture unavailable rollback preimages.

TODO: Select the keyed engine against the current authoritative G2 evidence,
join all relation/history owners under the existing StatePublication capsule,
bind this stream to the authenticated predecessor and execution cut, and replace
the World-only root in one first-release cutover. Authenticate the final pre-tail
cut and replay its deterministic tail during atomic restore, including a terminal
payment with no later traffic. The adapter alone does not close G3 or G4 and does
not enable snapshot acceptance or row disclosure.
