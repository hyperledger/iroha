# Original State byte stream

This internal adapter borrows the existing frozen `StateBlock`. It does not open
State views, build another state copy, select a root implementation, or grant
proof, finality, execution, or publication authority.

The constructor requires immutable `CaptureIntent::Complete` or
`CaptureIntent::Changes`. Complete intent retains every current table row and
supports cold-image delivery. Changes intent retains only native journal touches,
including an explicit absent successor for deletion, and refuses complete-image
`visit` before any callback. Both intents emit the same original change stream.
Complete registry and source checks still apply to every field in either intent;
a completed delta does not become a complete snapshot.

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
Physical source-row scans share one admission counter per traversal. Complete
native current/undo scans include retained prefixes. Change intent uses the
existing original touched-entry iterator and admits both touched-row traversals,
including skipped retained prefixes, without enumerating untouched current rows.
Complete membership count/filter scans admit the original owner's physical count,
including filtered history rows. Change intent instead admits the exact staged/latest
key-set visits of the existing paired delta owner. Historical values use point
lookups under its original writer; no accumulated history scan occurs. Completed
paired fields skip both counting and encoding after their original base is checked.
Untouched cells retain an empty descriptor after the same frozen source, target,
generation and schema checks. They admit no value visits, row backing or payload
frames. Policy owners skip unchanged borrowed projections before sorting,
materializing or hashing them. Parameter/runtime and shared-handle touches select
mutable projections; equal-value touches still retain both original frames.
Materialized lane manifests also depend on the runtime catalog and retain its
original binding check whenever that runtime is touched. Complete intent still
captures every value. A retry resets only traversal admission, retaining source
identities and bytes.
Canonical frame byte work and policy-internal collection work remain separately
bounded; source-row admission does not claim to measure elapsed CPU time.
Every delivery rechecks the exact source targets and generation. Consumer
refusals stop emission and preserve their original error; consumers must keep
partial work provisional until the complete visit succeeds.

Fields and keys are ordered by their exact canonical bytes. Cell keys are empty.
Native changes preserve every original undo entry, including equal-value and
absent-to-absent touches. A mutation written repeatedly emits its first preimage
once. Complete intent captures membership as full replacements of both tables;
consumers must clear the previous table even for an empty replacement. Changes
intent emits the existing owner's net current-map changes plus the exact rollback
delta: ordinary advance promotes the previous tip, whereas replacement and
repeated publication retain rollback. No older rollback journal is invented.

The Changes base names the exact committed publication pair, its original staged
surface, and committed/logical/successor frontiers. On replacement the committed
frontier and logical execution predecessor differ. The frontier delta uses the
committed base; Complete retains its existing logical-predecessor frame. Before
any Changes callback, the consumer must accept that explicit base or preserve
its exact refusal. This is a local physical-source binding, not authentication of
a State root or permission to mix unrelated execution and publication cuts.
TODO: integrate the selected commitment owner's authenticated baseline and both
State cuts before claiming complete incremental State work. Skipping an untouched
projection is local journal accounting, not authentication of an external prior
root. The static configuration-policy migration above remains open. Changed
policy projections still inspect and encode their complete internals; no claim
of work proportional to nested policy changes is made.

TODO: Select the keyed engine against the current authoritative G2 evidence,
join all relation/history owners under the existing StatePublication capsule,
bind this stream to the authenticated predecessor and execution cut, and replace
the World-only root in one first-release cutover. Authenticate the final pre-tail
cut and replay its deterministic tail during atomic restore, including a terminal
payment with no later traffic. The adapter alone does not close G3 or G4 and does
not enable snapshot acceptance or row disclosure.
