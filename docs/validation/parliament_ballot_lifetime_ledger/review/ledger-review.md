# Independent conditional ledger review

Reviewed the stable `ledger.py` SHA-256
`5af7ed9e7e133fd2a9885239616ff8dbc0d0e74c5e658c6c5457e90c312acd7e`,
its updated design and README. The final revision adds only three TODO
docstring lines; the independent suite was rerun on those exact final bytes. No remaining findings within the declared
conditional metadata scope. The independent module has 72 passing controls;
JUnit and exact after-run source observations are recorded beside this note.
No owner implementation, captured machine file, tracked source or runtime was
changed. No full actual gate stream, Cargo job or native worker was run.

## Independent arithmetic and ownership checks

The W rebase is compared against the pinned actual `ProgrammedWrites` component
for every row/role at T/b pairs (1,23), (2,64), (2^44,4096) and (2^64,64).
A separate per-binary-column formula checks the append population sum, counter
width, per-slot scan count, complete staging and work. L0 formulas are compared
against the frozen overlay at zero, ordinary and maximal capacities. These are
resource-expression evaluations, not native or full-stream executions.

The original 72-pin catalog authenticates four selected accepted shapes only.
Tests check the exact public/coin partition, source coin formula, 97-bit accepted
return header and row proof sizes. A mixed accepted/query/size-rejected trace
has its summed gate vector reconstructed independently, and its allocation
inventory proves no duplicate log/counter or coin addition. Rejected inputs
retain `3608+1024*n` borrowed bits through u64::MAX, use the common 253-bit return
header, reserve no log slots and sample no coins. Purification adds exactly one
separate purifier per retained coin and reports H/CX preparation outside the body.

Sparse explicit placements preserve the count but change address span as stated.
Wrong widths, omitted regions and aliases refuse. No placement operation moves
quantum data; relocation/routing remains an external term. Actual log occupancy
is never inferred from the conservative M+2 reservation.

## Refusal and provenance controls

Controls reject mismatched N, b, F or completion names, unsupported endpoint
shapes, duplicate IDs, request/query cap violations, excessive query capacities,
wrong source identities and source drift at the final check. Catalog state is
frozen. The CLI returns the same conditional report on ordinary success and
`--require-qualified`, with exits 0 and 2 respectively; unsupported kinds fail
without a report. Every full qualification/resource/driver flag remains false.

One concrete parser finding was corrected before this final run: an empty object
or empty string in the JSON `events` position previously became an empty trace.
The parser now requires an exact JSON array (and an exact experiment object).
Six independent malformed collection controls preserve that refusal. The earlier
61-case exploratory run had 60 passes and one test expectation failure because
the owner added the explicit clean-input purification field while the draft was
being reviewed; the final test now asserts that field. Its exploratory JUnit is
retained and does not qualify the final helper.

## Limits retained

The tool does not execute an adaptive driver or establish a joint-state theorem.
Source identity checks cannot validate caller-supplied semantic assertions about
F, canonical support, original request descriptors, fresh randomness, accepted
content, atomicity or disjoint physical ownership. Equal names are equality
checks, not oracle attestations. The four accepted observations do not establish
family maxima or price P0/ContentFamily; unsupported cases fail closed.

Unknown adversary, preparation, routing, driver, base-oracle and uniform-envelope
resources remain null. Original retained coins are not free scratch. The full
state's support must have canonical encodings, and all physical register regions
must be disjoint even when their values are correlated or equal. Complete
resource, primitive-entry, independent cryptographic review, physical workspace,
current-candidate and production qualification remain false.
