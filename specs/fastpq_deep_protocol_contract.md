# FASTPQ masked DEEP protocol contract

Source contract: 2026-09-30; q77 native qualification pending. The normal-library
[`offline_compact`](../crates/fastpq_prover/src/backend/offline_compact.rs)
quantity producer and verifier select this single fixed profile. Core transfer
proofs and AXT envelopes use canonical artifacts with bounded verification.
This implementation contract does not establish cryptographic or deployment
qualification. A verifier result grants no execution authority,
source finality or AXT spend authorization. The implemented producer samples
trace, quotient and independent composition masks. The complete construction
still has no independently qualified zero-knowledge claim. Current evidence and remaining release
gates belong in [production readiness](fastpq_production_readiness.md).

## Fixed relation and geometry

The sealed [`DeepRelation`](../crates/fastpq_prover/src/backend/deep_relation.rs)
bridge admits the complete SMT AIR and its ordinary/AXT prepared batch segment
wrappers. It binds the outer relation identity and exact complete statement;
the borrowed inner AIR must have identical statement bytes and geometry.
Artifact contents cannot select a verifier or replace independent expectations.
The public facade compares all seven PublicIO fields and the canonical statement
digest; AXT additionally compares complete binding, metadata, mirrors and remote
preimages. Every segment binds its ordinal, complete batch and ordered root chain.

The typed [`fastpq_prover::air`](../crates/fastpq_prover/src/backend/air.rs)
interface is consumed by the engine at three points. `air::q77` views a sealed
relation as a `SemanticAir` (its own declared schema, statement bytes, the 41
public columns and one field-generic evaluator):

- the out-of-domain check of the verifier, and of the producer before it
  commits its answers, compares that view's geometry with the engine constants
  and evaluates the relation through it;
- bounded verification and the producer's whole-attempt plan take only
  `air::q77::VerifierLimits` and `air::q77::ProducerLimits`. Each carries one
  `air::WorkLimits`, checked against the view's declared shape and statement and
  against the operation's declared payload and work before a proof byte is
  decoded or a private column is read. The public facade maps its segment
  policies to them with `for_segment`. For verification the declared payload
  charge is the frame bytes plus the admitted decode allocation charges, and
  the declared work charge is 29,751 units: one per enumerated field-value slot
  and numerator evaluation of a maximal frame. Neither is verifier scratch,
  peak memory, a complete arithmetic cost, gas or a work-security statement;
  complete resource accounting stays open under B.2 and F.2. `WorkLimits::default()`
  is the producer's default projection;
- construction and verification report their public outcome to the
  `air::q77` process observer, which cannot change a result.

These readers still bypass the interface and are B.2 work: transcript binding
reads the relation identity and statement from `FixedAir`
([`deep_binding`](../crates/fastpq_prover/src/backend/deep_binding.rs)); the
producer's masked quotient uses the prepared evaluator and the degree owner of
`CompactTransferAir`
([`deep_masked_quotient`](../crates/fastpq_prover/src/backend/deep_masked_quotient.rs));
and public columns are rebuilt by the closed-form `PublicColumnReconstruction`,
not from `SemanticAir::public_value`.

The accepted relation set stays closed; `air::q77::PROFILE` and
`SEALED_RELATIONS` publish this geometry and every sealed identity as data.
A relation outside that set has only the uncommitted `build_reference` /
`check_reference` algebra, which is nonsuccinct, non-hiding and not a proof.

[`deep_geometry`](../crates/fastpq_prover/src/backend/deep_geometry.rs) fixes:

| Item | Value |
| --- | --- |
| Base/extension field | `p=2^64-2^32+1`, `K=F_p[u]/(u^4-7)` |
| Trace rows `N` / complete AIR columns / numerator slots | 65,536 / 342 / 923 |
| Retained committed columns | 301; 41 public columns reconstructed independently |
| Evaluation rows `L` / blowup | 8,388,608 / 128 |
| Order-`L` root `g` | `0x35c4528b4aa62eb8` |
| Evaluation domain | `a<g>`, `a=FASTPQ_FINAL_V1.omega_coset` |
| Trace generator `omega` | `g^128 = FASTPQ_FINAL_V1.trace_root` |
| Ordered FRI arities | `[16,16,8,8,4]` |
| FRI domain lengths | `[8388608,524288,32768,4096,512,128]` |
| Exclusive FRI degree bounds | `[131072,8192,512,64,8,2]` |
| Initial queries / sampled candidates | 77 distinct positions / 87 candidates |

The [public-column owner](../crates/fastpq_prover/src/backend/compact_public_columns.rs)
fixes the 342-to-301 projection and evaluates known polynomials at the actual
extension points. Each retained base polynomial is
`A_j(X)=C_j(X)+(X^N-1)r_j(X)`, where `C_j` interpolates the physical source and
`r_j` has 162 independent base-field coefficients. The 41 public columns are
unchanged. The complete numerator has exclusive degree bound 196,803; exact
4N-domain interpolation and division produce a quotient of degree `<131267`.
Every remainder coefficient must be zero.

The quotient is split by coefficients as `Q=Q0+X^N Q1`, then independently
masked as `Q0'=Q0+X^N T`, `Q1'=Q1-T`, with 78 Fp4 coefficients in `T`.
The resulting exclusive chunk bounds are 65,614 and 65,731: the high chunk is
not truncated to the split length. Independently sampled `R` has 131,072 Fp4
coefficients. Every chunk and composition fits the fixed `<2N` FRI envelope.
The [construction note](fastpq_deep_hiding_construction.md) distinguishes the
finite-opening rank argument from the outstanding complete FRI/Fiat–Shamir
privacy and soundness obligations.

## Frozen transcript profile

Task H.2 of the [ZK delivery plan](zk_delivery_plan.md) selected this engine's
transcript as the shared backend transcript and froze its semantics: the
**FIPS 202-based atomic whole-tape transcript, version 1**
(`fips202-atomic-whole-tape-transcript-v1`). SHA3-256 produces every leaf,
parent, out-of-domain and chain commitment. SHAKE256 produces one atomic tape
of a fixed extent per verifier message. Freezing fixes what is bound and in
what order. It is not cryptographic qualification and establishes no numerical
soundness level.

Every SHA3-256 and SHAKE256 input is one canonical prefix frame followed by one
typed body frame. The prefix
(`fastpq_prover::compact_sha3::ProfileContextV1`) holds, in order: the framing
version, the catalog, the construction name, the **complete canonical bytes of
the typed profile descriptor**, and the statement context. No digest replaces
any of these bytes.

The descriptor is one typed semantic profile
([`transcript_profile`](../crates/fastpq_prover/src/backend/transcript_profile.rs),
published as `fastpq_prover::air::q77::transcript_profile()`), named
`fastpq.transcript.q77.v1`. Its canonical frame and its SHA3-256 identity are
owned by
[`fastpq_isi::semantic_profile`](../crates/fastpq_isi/src/semantic_profile.rs).
Every number is read from the engine's constants. It binds:

| Group | Parameters |
| --- | --- |
| Versions and framing | descriptor version, construction, framing version, the prefix, body and context frame names, body kinds (leaf 1, parent 2, chain 3, tape 4), oracle tags (row 1, quotient and mask 3, FRI 4 with rounds 0-4, terminal 4 with round 5, out-of-domain 5) |
| Primitives | SHA3-256 with suffix `06` and 32-byte output; SHAKE256 with suffix `1f`; one atomic tape per verifier message over prefix and body |
| Field and encodings | modulus, canonical little-endian `u64` base words, extension degree 4, nonresidue 7, polynomial basis `1, u, u^2, u^3`, four canonical coefficients with the constant first, 32 bytes |
| Domains and geometry | trace and evaluation rows and roots, coset offset, 342 columns of which 301 are committed and 41 public, 923 constraints |
| Masking | 162 trace, 78 quotient and 131,072 composition mask coefficients; the quotient split and its masked pair in one joined leaf |
| Out-of-domain and DEEP | points `z` and `omega*z`; 604 answers in current-row, next-row, low and high quotient order; 606 components in the order `(h_j, X^2 h_j)` per committed column then `(t_0, X t_0, t_1, X t_1)`; the mask has weight one and component `k` has weight `lambda^k` |
| FRI | arities, domain lengths and degree bounds; strided fibers; the fiber encoding that omits the smallest known incoming coordinate; 128 terminal values of degree below two in one leaf whose parent duplicates it; binary Merkle addressing by oracle, round, level and index |
| Sampling | 77 queries from 87 candidates in 93 raw words; words at or above the modulus are rejected, never reduced, and nothing more is squeezed; a base-field out-of-domain point aborts; all candidates are drawn before the first distinct positions are kept in ascending order |
| Schedule | the ten tape extents, the commitment that follows each message, the chain rule and the permanent-abort rule |
| Grinding | zero bits and no nonce |
| Declared envelope | maximum relation identity, statement, context and frame bytes; decoder allocation, sequence, total-element and nesting bounds; layer, path and fiber bounds; the structural work charge of 29,751 units under accounting version 1 |

The descriptor holds semantic data only. It contains no source, build or binary
digest, no measurement, no qualification status and no caller ceiling. The
declared envelope is the profile's own fixed shape; `WorkLimits`,
`VerifierLimits` and `ProducerLimits` values are admission policy and never
change proof bytes. The structural work charge is a charge of a maximal frame
under its stated accounting, not complete verification work; complete resource
accounting stays open under B.2 and F.2.

The identity is `b1b3be0bc1b548e32fa6f949500c0de43c8f7412a5586623c4d3f1ca705f945b`
over a 3,871-byte frame. `specs/zk_primitive_workloads.json` records the
parameter list and names this identity for every workload that depends on the
transcript; a measurement that names another identity does not describe this
profile. The identity grants no authority and selects no verifier.

The statement context (`fastpq_prover::deep::StatementContextV1`, owned by
[`deep_binding`](../crates/fastpq_prover/src/backend/deep_binding.rs)) holds what
belongs to one statement: relation identity, public-column layout, the geometry
again, and the complete statement bytes. Identity length is 1..=256 bytes;
statement length is 1..=240 KiB. The relation's public IO, State anchors,
execution context and replay domain are part of the statement; their
completeness is the relation owner's obligation.

Binding order, with the test that mutates each element:

1. Descriptor, catalog and statement context precede every commitment: they
   begin the first leaf and the first tape.
2. The row root is chained before the 923 constraint coefficients.
3. The joined quotient and composition-mask root is chained before the
   out-of-domain point.
4. All 604 out-of-domain answers are hashed and chained before the batching
   scalar.
5. Each FRI root is chained before its own folding challenge.
6. The root of the complete terminal is chained before the query positions.
   With zero grinding bits there is no nonce to bind.
7. The verifier derives every opening index from the query tape and
   authenticates every opened row, quotient leaf, fiber and the whole terminal
   against the committed roots under the same prefix.

A changed commitment changes every later tape and no earlier one. The tests in
`deep_binding/frozen_tests.rs` change, reorder and omit each of the 73
descriptor parameters, each statement-context field, each commitment and each
out-of-domain answer. `deep_fixture/frozen_tests.rs` builds one complete seeded
proof and retains it; `fixtures/fastpq/q77-frozen-transcript-proof.json` pins
its length and SHA3-256 together with the profile identity it was built under.
The binding test reads the retained bytes named by that pin, proves nothing,
and requires the bounded verifier to reject the proof under every changed,
reordered or omitted root, answer, opening, index and descriptor parameter. `fixtures/fastpq/q77-transcript-profile.json` holds known answers
that `scripts/zk_semantic_profile_reference.py` computes without this crate.
These tests show conformance with the frozen binding, not soundness.

Security statement of the frozen profile:

- Any claim is an absolute error at a stated query budget, stated separately
  for the classical and the quantum random-oracle model. No work-normalized
  128-bit claim is made.
- SHA3-256 commitments: generic collision search costs about `2^128` classical
  work and about `2^85` quantum queries; these are ideal-hash estimates.
- Classical random-oracle model: conditional on a round-by-round soundness
  bound for this exact geometry and on the mapping of this chained transcript
  to the BCS compilation. Neither is in the tree; B.2 owns the reduction and
  the checked accounting.
- Quantum random-oracle model: open. Ordinary round-by-round soundness supports
  the Chiesa-Manohar-Spooner chain that contains the verifier messages, but the
  exact mapping of this transcript, with its query accounting, is not supplied.
- Hiding: only the honest-verifier algebraic answer view is argued.
- Grinding: none, and no work-security term is claimed. B.2 counts repeated
  attempts in the adversary budget.
- Algebraic and FRI error sums alone establish neither Fiat-Shamir soundness
  nor hiding.

A change of any descriptor parameter, including a query count or FRI schedule
that B.2's accounting requires, is a new identity. It changes every proof byte
and both artifact profile ids, is declared under the `proof` surface of
[first-release history](first_release_history_cutover.md), and leaves every
measurement that names the previous identity inapplicable. No old transcript
path is kept and no reviewer token is involved. The hand-written identity
string and the legacy parameter-set name that this prefix carried before H.2
are removed.

## Commitment and challenge order

The ten messages and the commitment that follows each:

| Message | Decoded whole tape | Bytes | Following commitment |
| --- | --- | --- | --- |
| 1 | Dummy | 32 | 301-column row root |
| 2 | 923 independent Fp4 alphas | 29,584 | Joined Q0/Q1/R root |
| 3 | One Fp4 OOD point `z` | 80 | All 604 OOD answers |
| 4 | One Fp4 batching scalar `lambda` | 80 | Initial composition FRI root |
| 5..8 | One Fp4 beta each | 80 each | Next FRI root |
| 9 | Fifth Fp4 beta | 80 | Complete terminal root |
| 10 | 77 sorted distinct positions | 744 | None |

Every successful transcript materializes ten whole raw tapes totaling 30,920 bytes.
Raw words are arbitrary bytes: noncanonical field words are rejected within each
finite tape and are never reduced or replaced with extra output. All rejected
and unused bytes enter the following chain commitment. OOD answers are hashed
in current-row, next-row, quotient-half order. A base-field OOD point aborts.
The final 744-byte tape contains 93 raw words and must yield all 87 accepted
field candidates before selection of the first 77 distinct positions. Wrong
phase, finite exhaustion or malformed message permanently aborts the attempt.
The fixed primitive and framing still require complete concrete transcript,
Fiat–Shamir/qROM, soundness and hiding qualification.

## OOD identity and low-degree composition

The verifier evaluates all 923 AIR slots once at `z`, reconstructing all 41 public
columns at `z` and `omega*z`. With the supplied retained answers it checks

```
sum_k alpha_k C_k(z, A(z), A(omega*z))
    = (z^N - 1) * (Q0(z) + z^N Q1(z)).
```

For retained column `j`, let `I_j` be the linear interpolant of its two OOD
answers. [`deep_composition`](../crates/fastpq_prover/src/backend/deep_composition.rs)
defines `h_j=(A_j-I_j)/((X-z)(X-omega*z))` and
`t_k=(Qk-Qk(z))/(X-z)`. The 606 components, in order, are
`(h_j,X^2*h_j)` for each of 301 columns, followed by
`(t_0,X*t_0,t_1,X*t_1)`. The composition is `R` plus their power batch with weights
`lambda,lambda^2,...,lambda^606`; only the independent mask has weight one. Both shifts are required for the reconstructed degree
obligations; dropping them is a different protocol.

[`deep_prover`](../crates/fastpq_prover/src/backend/deep_prover.rs) constructs this
composition in coefficient space with exact division before evaluating its LDE.
It computes the AIR numerator on the shared 4N interpolation domain and exactly
divides by `X^N-1`; no zero-mask adapter or pointwise 8M AIR replay is used.
Private coefficient/evaluation buffers use the existing erased-storage owner.
Base trace replay retains the source, coefficients, masks and one N-row stripe;
it visits 128 stripes per complete row pass. The numerator uses only its four
nested stripes. Q0/Q1/R and all FRI layers use coefficient replay too. The first
commitment passes retain internal Merkle nodes under the same immutable attempt
context. Once the transcript chooses queries, replay regenerates only stripes
containing queried leaves or leaf-level siblings, including every coordinate of
FRI fibers. Each opening reconstructs the original root with the existing
canonical multiproof before exposing values. Entropy, challenges, leaf/parent
framing and proof encoding remain unchanged. No complete 20,199,768,064-byte base
LDE or full leaf-digest array is retained.

The whole `ProducerPlan` charges source, coefficients, masks, maximum selected
rows, active stripe, quotient/FRI coefficients, all retained internal-node caches,
coverage, shared immutable prefixes, canonical bodies, executor scratch and
codec/self-verification buffers. SHA3 nodes have 32 bytes. Keccak permutation
charges distinguish logical H/G queries from internal work, including public
readiness KATs and retained device pools. Native current-plan measurements are
pending; old six-lane plan totals do not describe this candidate. The prior full
replay work remains charged even when only selected stripes are evaluated.
It preflights payload, arithmetic/inspection work, hash calls and proof bytes
before private transforms. The offline wrapper also checks source conversion,
private SMT, bundle and decode budgets. These are checked payload/work charges,
not RSS or latency bounds. Defaults allow a 2 GiB segment charge and 2^42
structural work units; an oversized plan fails before private computation.

Internal-node retention, coverage, pending owners and opening scratch are
charged before work. Root/frontier, erasure and independent proof verification
controls remain required. Measured proof resources and source scope are recorded
in [production readiness](fastpq_production_readiness.md#captured-proof-evidence);
checked payload charges are not measurements of peak RSS.

Fresh entropy comes from an explicit `TryCryptoRng`; the normal offline wrapper
uses `OsRng`. Failed attempts do not reuse masks. CPU and required-device policies
select bulk leaf and independent lower-tree parent hashing. The ordered upper
tree stack and transcript hashing use CPU. Parent batching preserves every
natural level/index and reuses caller-owned clearing digest slots.
Required-device availability is checked with public input before private-tree
work, entropy and transforms, and actual dispatch checks quarantine again.
There is no implicit CPU fallback for required-device failures. Leaves are
prepared in fixed batches of at most 1024, independent of worker count; the
shared plan charges canonical bodies, frames, ordered parallel job results and
executor buffers before allocation. No hardware
or whole-prover performance qualification follows from this dispatch wiring.

## Bounded wire verification

The sole child frame is `fastpq_prover::deep_compact::MaskedCompositionProofV1` in
[`deep_proof`](../crates/fastpq_prover/src/backend/deep_proof.rs). It carries row and
joined Q0/Q1/R roots, six FRI/terminal roots, complete OOD answers, queried rows
and Q0/Q1/R triples, minimal sibling frontiers, five sets of complete strided FRI
fibers and the complete 128-value terminal. Row cells are fixed canonical u64
fields. Each FRI fiber has one arity byte and arity-minus-one raw canonical Fp4
values. The smallest known incoming coordinate is omitted deterministically;
the verifier reconstructs it, checks every shared incoming coordinate and
hashes/folds the complete original fiber. No proof-selected omission, vector
count or per-value framing is accepted. Every index/frontier is derived.

[`deep_engine::verify_committed`](../crates/fastpq_prover/src/backend/deep_engine.rs)
performs one bounded canonical decode, the OOD identity, authenticated opening
checks and at most 385 fold checks. Shared fibers preserve every distinct
incoming equality before authentication and deduplication; the exact count is
77 plus the distinct fiber counts in rounds zero through three. Fiber `j` at length `M`
and arity `r` contains positions `j+k*(M/r)`, not adjacent positions. Domains
advance by the `r`th-power map. The entire authenticated terminal must represent
one polynomial of degree `<2` on the folded coset. Both linear terminal
coefficients are retained and all values are checked. A singleton terminal tree has its required
duplicate-child parent.
The verifier constructs no private witness, trace, FFT or full LDE.

The fixed DTO upper envelope is 500,084 bytes, below the 512 KiB child target;
this shape bound is not an end-to-end proof-generation measurement. Decoding
intersects the caller's allocation allowance with 8 MiB and retains stricter
outer scopes. The enclosing ordinary/AXT carrier accumulates bytes, statement
bytes, 77 queries per segment and all decode charges. It publishes ordered row
roots only after every child verifies. Two maximal children use 1,000,168 bytes;
actual context and framing must still fit the independently enforced bundle and
artifact limits. No arbitrary-size batch is promised to fit 1 MiB.

The metadata ID is SHA-256 of the canonical
`fastpq_prover::deep_compact::QuantityArtifactProfileV1` descriptor in
[`compact_artifact`](../crates/fastpq_prover/src/backend/compact_artifact.rs).
It binds the exact geometry, ten tapes, field/hash parameters, child-frame schema,
quantity schemas and both ordinary/AXT relation identities. Its
`transcript_profile` field holds the same descriptor bytes the transcript
absorbs, so one typed descriptor is shared by the transcript and the artifact
identity. The AXT quantity id is
`4f0ece59b3f42d1c318f597b0df2f5af8b8db41bc95dfbb11974ddb285f20b0b` and the
ordinary execution-effect id is
`e4b83c36dca6915f908d6509ef43511ae6da1b8254cb2724b2b6fe00918779b8`; both are
pinned beside the semantic identity in `transcript_profile/tests.rs`.
The previous profile ID and child layout are not accepted alternatives. Their
proof, codec, replay and transcript implementations are removed. Immutable old
identity bytes remain only as rejection fixtures. The conditional
[375-query analysis](fastpq_compact_typed_profile.md) is historical and does not
qualify this profile. The descriptor pin
`fixtures/fastpq/q77-quantity-profile.json`, the seeded proof pins
`fixtures/fastpq/q77-quantity-ordinary-single.json` and
`fixtures/fastpq/q77-quantity-axt-single.json`, the seeded fixed-SMT proof
golden in `deep_prover/tests.rs` and the frozen-transcript proof pin are
regenerated for the frozen transcript. They are test goldens of the current
source: they pin bytes, not a review, and they qualify nothing. The proofs
themselves are retained outside the tracked tree; the tests that read them are
ignored by default because building a proof takes minutes.
