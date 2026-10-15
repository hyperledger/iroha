# iroha_plonk

The Iroha-native PIPA-v1 PLONKish/IPA proof system (`specs/plonk_ipa_v1.md`),
built on `iroha_pasta`. Independent captured vectors and native reference tests
pin the arithmetic and protocol behavior of their recorded source. Changes to
challenge roles, norm products and masking require fresh full-proof captures;
historical proof bytes do not qualify the changed protocol. The temporary
vendored proof oracle is retired; there is no second production proof engine.

PIPA-R uses explicit `CircuitDescriptorV2` admission (`DescriptorBinding::new_v2`
or `decode_v2`) and `KeygenConfigV2::pipa_r`. Its RP57 transcript runs in the
proof curve's base field, with canonical point coordinates, injective scalar
encodings and declared instance ranges. V1 retained consumers continue to choose
their scalar transcript explicitly; a V2 frame is never retried as V1.
`VerifyingKey::transcript_repr` returns an explicit scalar/base-field enum.

Native prover and verifier apply total challenge-role maps after raw field
conversion: `nz(0) = 1` and `nz(a) = a` otherwise; evaluation uses
`5 * nz(a)^2`, multiopening uses `25 * nz(a)^4`, and actual IPA round and
masking challenges use `nz(a)`. Evaluation points are nonzero nonsquares outside
the supported power-of-two domains; multiopening points are squares but not
fourth powers and cannot equal a rotated evaluation point. Source-k normalization
padding remains exactly zero. Permutation and lookup products use the norm
factor `N(t) = t^2 - 5`; the recursive constraints enforce the same equations.
These are protocol choices, with no challenge or salt retry.

`accumulate_frame_cancellable` returns a closed `SuccinctFrame` only after the
complete succinct parse and equation check. It retains the exact descriptor,
original typed instances, first raw base-field squeeze and same-proof opening
claim. The consumer must authenticate the selected key and source, enforce its
frame schema, and fold or decide the claim. A frame is not a final verdict or a
caller-supplied transcript prefix.

Deferred generator `G` values admit the full group, including the canonical
all-zero identity encoding. This exception is scoped to the unabsorbed generator
suffix and its claim carriers. Absorbed commitments and IPA `L`/`R` messages
remain canonical finite nonidentity points.

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
  Strict public-source admission keeps an owner-scoped 8,192-entry computed
  column memo. On a miss, a separate 16,384-entry FIFO reuses exact unblinded
  1,024-row MSMs keyed by native scalar bytes, row offset and length. Only
  computed projective points persist; the column blind is added once and every
  original VK commitment is still compared. Up to eight borrowed blocks run
  together under the same scratch ceiling; every worker joins before ordered
  cache insertion and summation. Native scalar encodings feed the unchanged
  source and column hashes together; private immutable-slice handles retain
  only column digests until the complete source fingerprint passes. Source
  fingerprints, key/proof
  bytes, cancellation and process-wide scratch limits remain unchanged.
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
  witness; both paths use the same proof construction, and the owned advice
  and coefficient buffers are zeroized on success and errors. Each new proof
  consumes one opaque `ProverRandomness` owner from fresh OS entropy, either
  directly through `os` or through `hedged` with statement and witness digests.
  No shipping API accepts a seeded recovery stream or caller randomness callback.
  Recovery verifies and restores retained original proof bytes; a new attempt
  samples fresh randomness. Draws follow the `BlindingScheduleV1` order. The quotient is evaluated on exactly `d - 1` cosets by a compiled,
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
uncancelled token preserves arithmetic ordering and verification behavior.
Independent fresh attempts are not required to reproduce proof bytes.

Proof construction and verification use ordinary descriptor-bound native
framing; injected transcript representations and alternate proof entry points
are absent. Historical Poseidon primitive known-answer vectors retain test-only
reference absorption without a proof-mode selector. The current native-generated
regression corpus is not an independent prover oracle and must be recaptured for
the changed equations.

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
- every proof message decodes canonically and the identity is never absorbed;
  only deferred generator claims admit the canonical identity. The proof length
  and instance shapes are exact; total role maps keep evaluation points outside
  the domain. Only `verify_full`, `batch_verify`, `decide` and `batch_decide` accept;
- verifier MSMs use complete formulas only; memory budgets change speed,
  never verdicts;
- provers draw randomness only from `ProverRandomness`; fixed seeds exist
  only in unit tests;
- key generation refuses imported tables that copy, enable a selector or set
  a fixed value at or beyond the usable rows;
- nothing panics on misuse: errors are typed.

`PinnedParams::for_domain(k)` uses embedded canonical transparent parameters for
Vesta k12/k14/k16 and Pallas k16. Every selection still passes the existing native
SHA-256 pin and canonical point decoder, and its header must match the requested
domain. Selected-byte corruption is an error, never a derivation retry. Other
domains use the unchanged transparent `derive` constructor; explicit derivation
remains available for independent parity checks. These four public assets total
9,699,600 bytes per native architecture. They introduce no device file cache,
parameter authority, proof-format change or expanded proving-key storage, and
remain ordinary source-closure inputs for compiled-profile freshness.

Offline compiler recovery can use `keys::source_fingerprint_v2` to identify
exact witnessless public source tables before generating commitments. It runs the
ordinary key preparation and hashes the complete descriptor, copy mapping digest,
finalized fixed/permutation evaluations and selector bitmaps. Its matching
`keys::pk::artifact::source_fingerprint_v2` checks bounded canonical compact
originals and reads their claimed source fingerprint without synthesizing tables
or loading parameter arrays. Both return lookup DATA only. Cache/table/MSM resource
choices do not change the identity, and no global cache is introduced.

A fingerprint match does not authenticate a VK or authorize its use. In
particular, a different valid commitment can retain the same lookup fingerprint.
The compiler must still call strict original admission against the exact
installed source and reject every source, copy, profile or commitment mismatch
before publishing a reused key. A compact original contains
`PIPACPK1 || descriptor_digest32 || LE32(vk_bytes) || canonical_vk ||
copy_digest32 || source_fingerprint32`. The native importer reconstructs the
fixed and permutation tables from its witnessless circuit, checks the complete
source fingerprint and every original VK commitment. Full `ProvingKey` import
then builds proving buffers; `SourceBoundVerifyingKeyV2::from_artifact_v2` retains
only the admitted public metadata and opaque source seal, avoiding FFT, mask and
coset buffers that startup would immediately discard. Both share the complete
admission checks. Actual proving reconstructs buffers through the existing
source-bound path. Neither accepts a dense-format fallback or decodes a
source-admission seal. Proof bytes are unchanged; signed packages must bind the
new original bytes.

`BuiltinSourceProfileV1` is an explicit additional source-authority boundary for
a finite generated native registry. Exact complete profile DATA selects only a
fresh compiled entry; exact role paths select only that entry's members. Each
member checks complete descriptor/VK/compact-original identities, canonical
framing, pinned parameters and current bounds before returning source-bound
metadata. No runtime entry registration or digest-to-seal API exists. Missing,
stale or unsupported profiles fail explicitly; ordinary strict imports and the
independent strict exporter do not consult this registry. The owning wallet must
still authenticate its installation and finish the complete source graph before
granting a wallet capability. Proof-time source reconstruction remains unchanged.

The build computes registry freshness from actual tracked and unignored inputs,
including higher-level circuit code, assets, manifests, lockfile and configuration.
The census includes unknown owners and file formats by default. It omits unrelated
Python, Swift, Kotlin and JavaScript client owners, Android/iOS examples, and
Markdown prose under the workspace root, `docs` and `specs`. Every inventoried
nested Cargo package takes precedence over these exclusions, so a native package
inside an SDK or vendor directory retains all its inventoried files. Native crate
prose, scripts, tests, fixtures, machine-readable specifications and assets remain
inputs. The optional `iroha-docs` gitlink does not affect native identity.

Declared external native inputs and conservatively resolved Rust include/path
literal references restore otherwise excluded files, including referenced documentation
and SDK fixtures. This restoration intentionally retains false positives; it is
not a Rust parser or an exhaustive compiler-input analysis. Generator/mobile
compiler input containment checks must still reject mathematical inputs outside
the census; generated `OUT_DIR` inputs require their exact maintained generator
relationship. A new external compiler input must be included before its artifact
is accepted. The census does not replace those existing build-correctness checks.
The canonical Android and Apple bridge builders run the maintained check directly;
standalone generator builds use `python3 scripts/audit_native_source_inputs.py
--cargo-json <successful-json> --expected-source-digest <digest> --output
<audit.json>`. An optional `--snapshot-tool` must be pinned to the maintained
snapshot driver and helper. For top-level native libraries, the audit binds every
Cargo-reported output to one unique byte-identical `deps` output in the same
compiler family. It checks the complete direct depfile against every output and
the exact source entry point, includes the aggregate depfile, and rechecks these
bindings before reporting success.

Native mathematical sources and assets belong under a package's `src` or
`build_support` tree. These trees for all inventoried Cargo owners, the existing
top-level crate source roots, and root `.cargo` are also walked without Git ignore
filtering. Thus ignored native modules, binary constants and Cargo configuration
remain inputs. Generated registry DATA is excluded from the digest to avoid a
self-hash. The existing Swift generated-framework symlink contributes its exact
path and link text only. Other included symlinks must resolve to an already
included regular input inside the workspace. Missing selected tracked inputs,
incomplete Git inventory or changing inputs disable built-in admission while
allowing strict compilation/generation. This source identity is not an external
dependency or toolchain attestation.

Cargo recomputes membership and file contents on each invocation through an absent
`OUT_DIR` rerun input. This detects newly added untracked sources or build config
without recursively watching ignored native outputs. The identity module is only
rewritten when its contents change; warm targets and compiler caches remain in use.
Target architecture, width and byte order are checked separately from the shared
mathematical source identity. Unsupported targets cannot select a built-in member.
The support check does not replace cross-target correctness tests.

Strict admission may reuse an already computed public column commitment within
one immutable `PinnedParams` owner. Its clones share a private, bounded FIFO memo
of at most 8,192 column digests and computed affine points. The digest covers the
Lagrange/default-blind operation, blind, row count and canonical scalar bytes;
the typed parameter owner fixes the curve and generator basis. Only the actual
public commitment computation populates it. Original VK points and declared
source fingerprints cannot seed this memo, and every original commitment is
still compared. Independent parameter admission starts a fresh memo; it is
neither global nor persisted and retains no column tables. Cancellation fails
closed, and a poisoned memo causes recomputation. This optimization changes no
source-admission authority or proof bytes.

On ARM64 targets other than Windows, SHA-256 source and column hashing uses the
existing `sha2` hardware backend with runtime CPU detection and portable fallback.
The exact fingerprint bytes and all admission checks remain unchanged. Other
architectures retain their existing hashing backend.

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
