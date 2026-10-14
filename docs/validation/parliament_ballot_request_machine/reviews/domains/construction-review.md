# Retained-generator oracle-domain review

The reviewed concrete fixed-shape generator has only ordinary backend domains
`{0,1,4,5,8}`. Its programmed transcript keys have final domain bytes
`{9,10,11}`. I found no address alias or extra backend query in the reviewed
factory and its selected emitters. This is a finite source inventory and a
conditional cleanup argument, not a cryptographic review, native execution
claim, complete simulator certificate or complete resource vector.

The [report](report.json) records 54 selected before/after source identities,
the 28-module local static import closure, concrete call sites and actual
bounded witnesses. All 54 identities were unchanged during the successful
21.25-second run. The [recipe](review_domains.py) ran with bytecode disabled;
[stdout](stdout.txt) and [stderr](stderr.txt) retain its outcome. This is an
observed selected-source map, not an atomic read trace or complete Python,
standard-library, cache, compiler or dependency authentication. Python/module
integrity and the already reviewed concrete primitive implementations remain
premises. No complete real-row gate stream was expanded.

## Exact ordinary addresses

Let `NS` be the actual 77-byte namespace, consisting of literal
`PARL/FAEST/v1` followed by the supplied/computed 64-byte digest. A trailing
hexadecimal byte in this table is an actual constant byte of the query.
Field byte order follows the source; it is not a hash of field identities.

| Use | Actual byte string | Native response copied | Calls in one clean local component |
| --- | --- | --- | --- |
| H0 | `NS || IV16 || 00` (94 bytes) | 128 bytes | 2 |
| H1 vector | `NS || com112[0] || ... || com112[2^depth-1] || 01` | 64 bytes | 4 per vector, including digest cleanup |
| H1 aggregate | `NS || digest64[0] || ... || digest64[tau-1] || 01` | 64 bytes | 2 |
| Hmu | `NS || framed_REG_or_VOTE_public_message || 08` | 64 bytes | 4 within clean P1 |
| H4 | `NS || iv_pre16 || mu64 || 04` (158 bytes) | 16 bytes | 4 within clean P1 |
| H5 gate e | `NS || IV16 || salt32 || u32le(e) || label32 || 05` (162 bytes) | low 10 bits | 4 per gate |

The source authority is `hash.rs::Oracle::domain_byte`,
`Hasher::new_in/finalize_xof`, `h0_as` and `h5_as`; BAVC `hash_leaves` uses
H1 for both vector and aggregate digests. `transcript.rs::derive_iv` absorbs
iv_pre then mu. `proving.rs::message_digest` absorbs the complete public frame
under Hmu. The corresponding emitters are `hash_machine.py::H0` and
`H1Aggregation`, `public_machine.py::PublicBuilder.backend/prepare_public`,
and `crt_machine.py::CrtReconstruction.emit_clean`. Their exact identities
and source paths are in the report.

`hash_machine.py::prefix_query` is the only fixed-length F-opcode producer in
the generator's selected local module closure. It passes the entire query's
wire tuple in order, receives all 2,112 response bits into disjoint clean
scratch, copies the requested prefix, and repeats the same F instruction to
clear the response. All `F:length` opcodes denote restrictions of **one**
immutable function on byte strings, not independent functions by length.
The source-domain padding premise includes the upper six bits of H5's second
byte and the rest of its 264-byte response. This review does not implement F
as concrete SHAKE or derive that premise from a query-count bound.

H0/H1/H5 prepare fresh query wires with controlled source-bit copies and fixed
trailing X gates. Source fields end before the last byte. P1 allocates the
last eight wires as fresh constant SSA nodes; both backend kernel calls retain
them through compute/copy/uncompute. The CRT label is the actual source matrix
combination of column bits. Its gate index is a public fixed-loop u32le
constant; the selector, corrections and label cannot rewrite the domain byte.

The actual P1 SSA witnesses cover each row and both roles at their two size
boundaries. Hmu query lengths are 392–6,024 bytes for REG and 968–128,584 bytes
for accepted-shape VOTE (3–1,000 commitments). In every case its suffix is a
constant 08; H4 is 158 bytes and ends in constant 04. The argument for the
intermediate shapes is the same source construction, not exhaustive testing
of every possible request. Content-invalid values at those fixed shapes do
not alter either suffix.

## No hidden generator F calls

B0 opening/geometry, the S0 bounded schedule, tree and leaf routing, V0 row
generation/folding, mask folding, R0/R1 field/relation responses, return
projection, and P0 validation add no F query. They use only Boolean gates and
the pinned concrete AES, field, admissibility and Keccak kernels. Profile
table SHAKE256 and public SHA3 are concrete circuits, with their gate costs;
they are not silently included in or replaced by F. Field and AES adaptors,
including their selected loaded helper identities, were read. The local
factory loads these concrete kernels; generic injectable kernel objects are
not certified merely because their metadata says `base_calls == 0`.

Prescribed challenge1/challenge2 values and the S0 primary/auxiliary tapes
are original generator inputs. They are not read back through domains 9, 10
or 11. H3 (domain 3) exists in the larger backend interface but is not invoked
by this direct ideal sampler's generator. This inventory is for that defined
generator, not a claim that every Rust prover/verifier call uses only these
five domains. The complete request's variable-length adversary lookup is a
separate L0 component and is not traversed by G or its inverse.

Every reviewed composition relocates each gate's wire labels through a
checked fixed interval map, preserving opcode and argument order. Shared clean
scratch does not overlap retained inputs or outputs. BAVC reconstruction
executes H0 twice and H1 aggregation once; opening reconstruction executes
BAVC twice and V0/V1 once. V0/V1 executes its F-free V0 twice and H5 once.
The retained stage DAG invokes P1, S0, opening, R0 and R1 once; the outer
request later invokes their clean inverses in dependency order. P0 insertion
adds no query. No data-dependent memory address, host callback dispatch or
unpriced length-to-oracle selection is introduced by these maps.

This does **not** account for arbitrary coherent row/role/length dispatch.
Those remain supplied classical shape choices. The content controller handles
invalid values only inside its bounded accepted-shape VOTE family. The source
inventory is not permission to extend that claim to rejected out-of-family
requests or to substitute different callback kernels.

## Programming addresses and lookup identity

`write_machine.py::actual_frames` authenticates the frozen framing helper;
both roles and both rows were loaded in the witness. `ProgrammedWrites`
requires domains exactly `[9,10,11]`. The three keys are:

1. `NS || mu64 || commitment64 || corrections || mult_corrections || iv_pre16 || salt32 || 09`.
2. `NS || challenge1_264 || Utilde128 || Dtilde128 || d || 0a`.
3. `NS || challenge2_104 || recovered_A0_32 || coefficients192 || counter_u32le || 0b`.

The framing adds no backend per-field length prefix. The **log key encoding**
separately prefixes the semantic key length and appends canonical zero padding
to its fixed key capacity. Length, key and response occupy disjoint staging
intervals. Values are separately padded to 264 bytes. The last semantic byte,
not the last padded-buffer byte, distinguishes these domains.

`chronological_log.py::EnabledAppend` copies those key bits unchanged into a
fresh canonical slot when enabled. It neither truncates nor rehashes the
query. `ValidatedWrites` adds a valid control and a fixed wire relocation;
it changes no key contents. W makes M+2 fixed scans, with only S0-selected
primary writes enabled; it has no F call or auxiliary write. The domain
restriction is structural even if field bytes or trial values collide.

L0's separate reviewed equality compares the encoded length and padded key.
Under its canonical-active-key and canonical-query premises, an equal address
must have equal semantic lengths. Its last semantic byte would therefore
have to belong to both disjoint sets, which is impossible. H0's zero suffix,
zero padding and arbitrary payload bytes containing 09/0a/0b do not create an
alias. A query longer than the write-key capacity cannot match a canonical
write; its full byte string still reaches the shared base F. The fixed/variable
oracle identity is an explicit experiment premise, not a property of Python
opcode names alone. The supplemental receipt identifies the L0 source read
for this argument; the prior L0 review and tests remain separate evidence.

## Query count and cleanup consequence

Counting actual clean calls, one G has the following source-derived census:

| Domain | Calls in G | Candidate tau=33, g=704 | Comparator tau=22, g=696 |
| --- | --- | --- | --- |
| 0 | 8 | 8 | 8 |
| 1 | 8 tau + 4 | 268 | 180 |
| 4 | 4 | 4 | 4 |
| 5 | 4 g | 2,816 | 2,784 |
| 8 | 4 | 4 | 4 |
| Total | 8 tau + 20 + 4 g | 3,100 | 2,980 |

The actual request pays G and its inverse: 6,200 and 5,960 base calls,
respectively. These counts include each two-call prefix adapter and nested
cleanup. They exclude separately priced adversary L0 lookups and do not
double-charge concrete public hashes as F. W/E contribute zero base calls.
Changing M changes the schedule and write gates/storage, not these fixed
reconstruction domain counts. No smaller M is thereby source-qualified.

Given one immutable F, no interleaving, a canonical log containing only keys
with suffixes 9/10/11, sufficient fresh append capacity without counter wrap,
and W/E preserving all G controls in disjoint registers, G receives the same
ordinary answers before and after W. Thus G inverse clears its retained
derived history without restoring an old log. The statement is a joint map
on oracle/request/tape/log/return/work registers; copied fields may remain
entangled with the log, and original randomness is not reset for free.
Invalid-content rejection disables W/proof output and cancels its still-charged
temporary F calls. Reversing the whole transition requires W's true inverse,
not a second forward append.

## Witness limits and retained failed attempt

The executable witness streams actual H0 (two queries), a two-vector H1
instance (ten queries), and an eight-gate H5 instance (32 queries). It compares
complete observed byte strings with independently assembled expected fields,
checks gate/query tallies, preserves source basis labels and clears shared
scratch. It uses one explicit deterministic padded test function. This
function is only an interpreter fixture. Actual P1 SSA is inspected without
expanding SHA3/Keccak. Small W scatter runs cover full source field ordering,
u32le counter, exact length, padding and unscatter; source-sized W metadata
is read for all four row/role combinations. A domain-8 programmed-frame
mutation is refused. This is not a new full machine test suite.

The initial witness invocation failed in the review script because it passed
public role `REG`/`VOTE` directly to the framing helper, whose interface uses
`registration`/`vote`. The production factory already performs that conversion.
The exact failed script and logs are retained as `attempt-1-*`; only the
review script's call was corrected. No component source changed. All
qualification/whole-resource flags remain false.
