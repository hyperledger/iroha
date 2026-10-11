# iroha_plonk

The Iroha-native PIPA-v1 PLONKish/IPA proof system (`specs/plonk_ipa_v1.md`),
built on `iroha_pasta`. Independent captured vectors and native reference tests
pin arithmetic and protocol behavior. The temporary vendored proof oracle is
retired; there is no second production proof engine.

PIPA-R uses explicit `CircuitDescriptorV2` admission (`DescriptorBinding::new_v2`
or `decode_v2`) and `KeygenConfigV2::pipa_r`. Its RP57 transcript runs in the
proof curve's base field, with canonical point coordinates, injective scalar
encodings and declared instance ranges. V1 retained consumers continue to choose
their scalar transcript explicitly; a V2 frame is never retried as V1.
`VerifyingKey::transcript_repr` returns an explicit scalar/base-field enum.

`create_proof_owned_with_claim` returns proof bytes and the same run's `(G, u)`
opening obligation. `accumulate_generator` checks the succinct equation and
returns a `#[must_use]` `GeneratorClaim`; only `decide`, or inclusion in a finally
decided recursive accumulation, accepts that claim. The retained
`accumulate_succinct` wire accumulator accepts scalar-profile provenance only.
The native PIPA-R KATs have a standard-library Python calculation in
`tests/pipa_r_reference.py`; the full independent reference verifier remains an
M4 requirement.

Stage ENGINE-1 (tasks T8 and T9) provides:

- `cs`: the constraint-system IR. Expressions, gates, halo2 permuted lookups,
  the permutation argument with the vendored union-find copy assembly, the
  exact port of halo2 selector compression, and `CircuitDescriptorV1`, the
  canonical Norito frame of everything a verifier evaluates, with its
  `BLAKE2b` digest, `transcript_repr` and the `PINNED_PARAMS_V1` table.
- `frontend`: `Circuit`, `Layouter`, `Region`, `Value`, `Assigned`, the
  halo2-axiom `SimpleFloorPlanner` layout (every region starts at row 0) and
  the `Assembly` that records fixed values, selectors, copies and witnesses.
- `check`: the constraint checker. It interprets the uncompressed source
  expressions and reports cell-level diagnostics. Strict mode also flags reads
  of unassigned advice, blinding rows and wrapped rotations, and unassigned
  copied cells; `Halo2Compatible` mode matches the halo2-axiom `MockProver`.

Stage ENGINE-2 (tasks T10, T11 and the PCS half of T13) provides:

- `keys`: `VerifyingKey` with the vendored `0x02` byte layout and a strict
  reader bound to a `DescriptorBinding` (exact `k`, compress flag and
  fixed-column count, canonical non-identity points, zero bitmap padding, no
  trailing bytes, and the selector-compression registration rule);
  `transcript_repr` from the descriptor digest and the VK bytes; `ProvingKey`
  with the selector-substituted constraint system and its selector plan
  (`KeyConstraintSystem`; the selector columns are kept once, as the last
  fixed columns, `ProvingKey::selector_values`), the fixed and `sigma`
  columns, the masks, the exact quotient cosets (`QuotientDomain`: `d - 1`
  cosets and a small Vandermonde recombination), the fixed- and
  `sigma`-coset cache (the masks are computed per coset from their closed
  forms, never cached) and the digest of its copy mapping; deterministic key
  generation from a circuit or from explicit assignment tables (public API
  with no soundness effect; imported tables may not touch rows at or beyond
  the usable rows), with the permutation cycles built exactly as halo2 builds
  them.
- `transcript`: the `BLAKE2b` `Challenge255` transcript (byte-identical to
  the vendored `Blake2bWrite`/`Blake2bRead`) and the KAGEMUSHA RP57 Poseidon
  transcript (snark-verifier `NativeLoader` semantics, injective point
  absorption in production), canonical message decoding, trailing-byte
  rejection and the instance-frame prelude.
- `pcs::ipa`: commitments, the BGH19 inner-product argument (the prover
  returns the folded generator `G'_0`), succinct accumulation into a
  `#[must_use]` `PendingAccumulator` (`PendingOpening::accumulate`, never a
  verdict), the `AccumulatorV1` codec, `decide` and the deterministic
  `BLAKE2b`-weighted `batch_decide`, `PinnedParams` (parameters derived here
  or matching the pinned digest), and `msm_complete`, the portable
  complete-formula Pippenger that every verifier-side MSM uses (S10), on
  GLV-split scalars with signed-digit windows. The split keeps the two
  halves, their signs and the endomorphism image per term (97 bytes) and
  recodes each window's digits from the halves; terms are split in chunks
  whose split data takes at most half the memory budget. Complete verifier
  MSMs reserve all split, limb, window-result and bucket buffers against
  the same process-wide 64 MiB scratch ceiling as the Pasta prover MSMs.
  `msm_complete_with_shared_budget` additionally accepts a shared caller
  ceiling; contention takes a stack-only complete path without waiting.
- `pcs::multiopen`: the halo2 multi-point opening with static query grouping:
  queries are grouped by slot (column kind and index), never by commitment
  value, and a repeated query must repeat its evaluation bit for bit.

Stage ENGINE-3 (tasks T12 and T13) provides:

- `protocol`: the tables the prover and verifier share, derived from the
  descriptor alone: the opening queries of spec 9.1 and their static plan,
  the exact proof length, the Lagrange and Direct-instance evaluations, the
  explicit-stack expression evaluator, the S7 zero-knowledge budget
  computed from the opening plan, and (S11) the constraint-term table that
  the verifier's fold interprets and the transcript schedule that the prover
  and the verifier are tested against operation for operation.
- `prover`: `create_proof`, `create_proof_owned` and `prove_circuit`.
  `create_proof_owned` consumes its witness; `prove_circuit` uses that path.
  Advice buffers are moved into the prover and transformed to coefficients
  in place after the lookup and permutation products consume evaluations.
  The borrowed `create_proof` remains available for callers reusing a
  witness; both paths produce identical proof bytes, and the owned advice
  and coefficient buffers are zeroized on success and errors. Randomness
  comes only from an
  opaque `ProverRandomness` (OS-keyed ChaCha20, a hedged derivation over OS
  entropy, the statement digest and the witness digest, or a recovery stream:
  the prover draws 32 bytes from the caller's derivation and keys ChaCha20
  itself with them and the witness and statement context, so a derivation
  cannot opt out of the binding) and is drawn in the `BlindingScheduleV1`
  order. The quotient is evaluated on exactly `d - 1` cosets by a compiled,
  hash-consed expression DAG and recombined with a Vandermonde solve.
  Gate terms use fixed groups of eight with shared public challenge powers;
  omitted gates keep their original zero-valued positions and the final partial
  group uses serial Horner evaluation. Both-field tests compare the full
  quotient against the independent serial evaluator and retain proof-byte goldens.
  `Witness::from_circuit` checks that a circuit matches its key (copies
  through the key's copy digest, in constant memory) and moves the
  synthesized advice into the zeroizing witness; `Witness::from_columns`
  imports assignment tables (public, no soundness effect).
- `verifier`: `verify_full`, `accumulate_succinct` (a `#[must_use]` pending
  accumulator; its `Ok` is satisfiable for false statements until decided,
  so it is never a verdict), `verify_full_from_bytes` and `batch_verify`
  (deterministic weights, one merged `g` MSM, suffixes as accumulator
  items). Rejections are typed `VerifyError`s.

Proving and verification accept an explicit operation cancellation token from
`iroha_pasta`. `ProverConfig::cancellation` and the `_cancellable` witness,
original-key import, and verification entry points share this signal. Kernels
check it at Rayon task boundaries and in bounded sequential batches. Every
spawned task joins before `Cancelled` is returned; owned secret polynomials,
blinding buffers, and quotient leases are wiped before resources are released.
Cancellation has no proof verdict and must never authorize a corrected claim or
burn. Original-key installation and pinned-parameter derivation are separate
startup work; no cancellation bound is claimed for those noncancellable APIs.

A cancelled operation consumes its witness and may have advanced its transcript
and randomness. Retry with a fresh operation token, transcript, witness, and
randomness owner. Do not continue or publish a partially written IPA transcript.
The ordinary APIs invoke the same implementation with no token, and an
uncancelled token preserves proof bytes and arithmetic ordering.

Unit-test-only `create_proof_oracle` and `verify_full_oracle` reproduce and
check the retained independent proof vectors. These hooks are never compiled
into shipping binaries.

For a singleton, unrotated fixed-table lookup, the prover derives a public bit
bound from the entire authenticated fixed column. Membership-checked usable
rows of the permuted input and table therefore fit that bound. The commitment
validates every prefix scalar and computes the same sum using fewer secret MSM
windows; full-width random padding and the original blind are unchanged. Tuple,
rotated and compound tables retain the general commitment path. Neither random
draw order nor transcript messages change. Optional commitment tables retain
their existing path after prefix validation, and all scratch shares the process
64 MiB ceiling. The MSM remains variable-time in its digit bucket access.

Rules this crate enforces:

- queries are interned in halo2's order;
- descriptors reject repeated `(column, rotation)` queries and rotations that
  collide modulo `n`;
- instance columns declare their exact lengths in `configure`, and the
  transcript prelude frames the instance shape;
- params digests are pinned per `(curve, k)`; verifiers accept only derived
  or pinned parameters;
- the zero-knowledge query budget (S7) is checked;
- opening queries are grouped statically (S1) and never overwritten (S3);
- every proof message decodes canonically, the identity is never absorbed,
  the proof length is exact, `x = 0` and `x^n = 1` are rejected, instance
  column counts and lengths are exact in both instance modes, and only
  `verify_full`, `batch_verify`, `decide` and `batch_decide` accept;
- verifier MSMs use complete formulas only; memory budgets change speed,
  never verdicts;
- provers draw randomness only from `ProverRandomness`; fixed seeds exist
  only in unit tests;
- key generation refuses imported tables that copy, enable a selector or set
  a fixed value at or beyond the usable rows;
- nothing panics on misuse: errors are typed.

Offline compiler recovery can use `keys::source_fingerprint_v2` to identify
exact witnessless public source tables before generating commitments. It runs the
ordinary key preparation and hashes the complete descriptor, copy mapping digest,
finalized fixed/permutation evaluations and selector bitmaps. Its matching
`keys::pk::artifact::source_fingerprint_v2` checks bounded canonical originals
and streams their scalar bytes without retaining a second set of tables or
loading parameter arrays. Both return lookup DATA only. Cache/table/MSM resource
choices do not change the identity, and no global cache is introduced.

A fingerprint match does not authenticate a VK or authorize its use. In
particular, a different valid commitment can retain the same lookup fingerprint.
The compiler must still call `ProvingKey::from_artifact_v2_cancellable` against
the exact installed source and reject every source, copy, profile or commitment
mismatch before publishing a reused key. These helpers do not change proof
bytes, original-key encoding or source-qualified capability construction.

Large polynomial evaluations use fixed Horner subtrees, and multiopen reconstruction
walks the original slot order over disjoint coefficient blocks. Grand-product
inversions use constant-time field inversion in worker-sized chunks; their scratch
lengths sum to at most the original column length. These phases use the caller's
Rayon pool without copying a coefficient column or changing the transcript schedule.

Every output is a pure function of its inputs and the prover's random stream;
results do not depend on the Rayon pool size, and no behaviour comes from
environment variables.

The ignored `actual_descriptor_node_major_tile_experiment` unit test compares
row-wise evaluation with node-major tiles on exact M3 workload descriptors.
The `iroha_plonk_gadgets` M3 test's
`actual_m3_source_descriptors_for_dag_experiment` exporter supplies those frames
without generating keys. Pin the exported bytes and both executable/source
identities before running the experiment on either field with one or four workers.
It compares every node and row, checks cancellation and a fresh retry, and bounds
additional DAG scratch at 16 MiB. Its deterministic dense inputs are not satisfying
witnesses; kernel timings and lifetime RSS cannot qualify proofs or M3 gates.
The experiment itself provides no complete-proof qualification. The production
candidate uses four-row tiles with a strided row view, preserving node arithmetic,
root order and constraint folding. Scratch expansion beyond the scalar buffer is
reserved before spawning work, with a shared 16 MiB sublimit inside the existing
process-wide 64 MiB scratch ceiling. Contention or oversized public shapes select
the scalar evaluator immediately. Zeroizing worker buffers drop before reservation
release; no task waits while retaining scratch.

Validate:

```sh
cargo test -p iroha_plonk
cargo test -p iroha_plonk --release --test pinned_params -- --include-ignored
cargo test -p iroha_plonk --release --lib measure_prove_and_verify -- --ignored --nocapture
cargo test -p iroha_plonk --release --lib captured_goldens
cargo test -p iroha_plonk --release --lib bounded_tests
```
