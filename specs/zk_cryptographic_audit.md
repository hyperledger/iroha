# Iroha ZK Cryptographic Audit

Original findings: 2026-08-23. Current implementation reconciliation: 2026-09-07.

This is a repository-owned finding and disposition record, not an independent
cryptographic audit certificate. Remediation statements describe source changes
and scoped regressions; they do not qualify a mutable working tree for release.

This report audits Iroha-owned zero-knowledge verifier code and proof-bearing runtime
integrations. Vendored Halo2, curve, hash, encoding, and arithmetic libraries are
treated as dependency assumptions. The audited surfaces are native STARK/FRI,
ZK-ACE AIR, Iroha-owned IPA/Halo2 wrappers, verifier registry policy, proof
envelopes, Torii proof endpoints, IVM host syscalls, Kaigi privacy flows, and FASTPQ
lane proof binding.

## Executive Summary

Normal ledger-grade ZK admission is designed to fail closed. A
registry-dispatched proof must bind a registered verifying key that is active at
the execution block height, backend label, circuit id, schema/public-input
commitment, verifying-key hash, and proof bytes. A typed privacy proof instead binds an exact compiled protocol
activation, statement schema, verifier and engine digests, signed transaction
intent, and proof bytes. Both surfaces reject unsupported or substituted
artifacts before verifier dispatch.

The native STARK/FRI verifier performs canonical Goldilocks field checks,
Merkle opening checks, Fiat--Shamir query derivation, FRI folding checks, and
AIR composition checks. Generic circuits bind `OpenVerifyEnvelope` metadata.
The separate typed `PrivacyProofEnvelopeV1` path adds compiled-profile,
governed-policy, signed-transaction-intent, trusted-genesis, transfer, and
replay-nullifier binding. Native STARK commitments and transcripts now use the
canonical six independent Goldilocks Poseidon-x7 lanes. ZK-ACE identity and
replay outputs use the same independent-lane construction. ZK-ACE activation
remains unavailable pending an independent qROM Fiat--Shamir reduction,
artifact-bound collision/multi-target accounting, and implementation review.

The Iroha-owned IPA/Halo2 stack is a transparent IPA verifier wrapper. Production
IPA bases are independently mapped with domain-separated hash-to-curve. The
additive Goldilocks IPA module, types, decoded variants, and feature have been
removed from Halo2, Core, IVM, and Torii. Goldilocks remains a STARK field
identity; selecting it for IPA unconditionally returns an unsupported-backend
error.
This audit does not source-audit vendored Halo2 or curve crates; it audits Iroha's
generator derivation, transcript labels, public-input shape checks, metadata
binding, registry limits, batch dispatch, and runtime guardrails.

FASTPQ lane admission binds the proof to the lane envelope and AXT claim metadata:
dataspace, manifest root, source transaction commitment, effect type, claim digest,
optional committed amount, batch seal, transfer witnesses, public I/O, transcript
challenges, AIR openings, Merkle paths, FRI query chains, and proof-size limits.

The principal audit risk is boundary management. Recovery-only trust paths and
diagnostic endpoints must never be usable as fresh ledger-admission proof. This report
records that as the primary finding and models the same class of failure in TLA+.

## Scope and Evidence

Audited code evidence:

- [../crates/iroha_data_model/src/zk.rs](../crates/iroha_data_model/src/zk.rs):
  `OpenVerifyEnvelope`, generic STARK wrapper payloads,
  `ZkAcePrivacyPublicInputsV1`, replay-nullifier derivation, and canonical
  public-input hashing.
- [../crates/iroha_data_model/src/privacy.rs](../crates/iroha_data_model/src/privacy.rs):
  the closed privacy protocol registry, compiled-artifact bindings, governed
  ZK-ACE policy records, typed statements, and proof envelopes.
- [../crates/iroha_data_model/src/proof.rs](../crates/iroha_data_model/src/proof.rs):
  `ProofBox`, `ProofAttachment`, `VerifyingKeyBox`, `VerifyingKeyRecord`, key status,
  and backend/commitment serialization policy.
- [../crates/iroha_core_zk/src/lib.rs](../crates/iroha_core_zk/src/lib.rs): verifier
  dispatch, preverify/dedup, backend-label guardrails, envelope metadata checks,
  STARK/Halo2 entry points, and timing/size guardrails.
- [../crates/iroha_core_zk/src/stark.rs](../crates/iroha_core_zk/src/stark.rs):
  generic native Goldilocks STARK/FRI verifier and AIR bindings; the generic
  boundary explicitly rejects the retired ZK-ACE relation.
- [../crates/iroha_core_privacy/src/privacy_engines/zk_ace.rs](../crates/iroha_core_privacy/src/privacy_engines/zk_ace.rs)
  and
  [../crates/iroha_core_privacy/src/privacy_engines/zk_ace_stark.rs](../crates/iroha_core_privacy/src/privacy_engines/zk_ace_stark.rs):
  the private zeroizing witness, compiled profile, dedicated masked AIR,
  theorem-bound DEEP/FRI prover, and native verifier.
- [../crates/iroha_core_privacy/src/privacy_engines/transparent_stark.rs](../crates/iroha_core_privacy/src/privacy_engines/transparent_stark.rs),
  [../crates/iroha_core_privacy/src/privacy_engines/aggregate_stark.rs](../crates/iroha_core_privacy/src/privacy_engines/aggregate_stark.rs),
  and
  [../crates/iroha_core_privacy/src/privacy_engines/proof_managed_note_stark.rs](../crates/iroha_core_privacy/src/privacy_engines/proof_managed_note_stark.rs):
  shared field, transcript, Merkle, aggregate DEEP/FRI, exact proof-codec, and
  proof-managed relation-profile boundaries.
- [../crates/iroha_zkp_halo2/src/lib.rs](../crates/iroha_zkp_halo2/src/lib.rs):
  IPA verifier wrapper, generator derivation, envelope decoding, limits, and batch
  verification API.
- [../crates/zk_ace_prover/src/lib.rs](../crates/zk_ace_prover/src/lib.rs):
  governed transfer construction, typed proof-envelope assembly, exact
  transaction-intent binding, and signed `SubmitPrivacyProofV1` creation.
- [../crates/iroha_core/src/smartcontracts/isi/privacy.rs](../crates/iroha_core/src/smartcontracts/isi/privacy.rs):
  privacy activation and ZK-ACE policy governance, typed proof verification,
  atomic transfer effects, and replay-nullifier consumption.
- [../crates/iroha_core/src/smartcontracts/isi/world.rs](../crates/iroha_core/src/smartcontracts/isi/world.rs):
  generic verifying-key registry policy, `VerifyProof` and governance proof
  checks.
- [../crates/iroha_core/src/smartcontracts/ivm/host.rs](../crates/iroha_core/src/smartcontracts/ivm/host.rs):
  IVM VK loading, envelope enforcement, verifier syscalls, and batch verification.
- [../crates/iroha_core/src/smartcontracts/isi/kaigi/privacy.rs](../crates/iroha_core/src/smartcontracts/isi/kaigi/privacy.rs):
  Kaigi privacy proof metadata and roster-root verification.
- [../crates/iroha_torii/src/lib.rs](../crates/iroha_torii/src/lib.rs),
  [../crates/iroha_torii/src/zk_attachments.rs](../crates/iroha_torii/src/zk_attachments.rs),
  and [../crates/iroha_torii/src/zk_prover.rs](../crates/iroha_torii/src/zk_prover.rs):
  app-facing proof submission, verification, storage, and non-consensus worker
  boundaries.
- [../crates/fastpq_prover/src/proof.rs](../crates/fastpq_prover/src/proof.rs),
  [../crates/fastpq_prover/src/axt_binding.rs](../crates/fastpq_prover/src/axt_binding.rs),
  and [../crates/iroha_data_model/src/fastpq.rs](../crates/iroha_data_model/src/fastpq.rs):
  FASTPQ public I/O, transcript arithmetic, AIR/FRI verification, AXT packaging,
  lane claim binding, and transfer transcripts.

Out of scope: source audit of vendored Halo2, curve, finite-field, SHA-2, Blake2,
Poseidon2, and Norito implementations; full algebraic proof of STARK/FRI or IPA
soundness; runtime API, schema, or wire-format changes.

## Findings

### ZK-AUDIT-01: Recovery trust flag can bypass local ZK-ACE verifier failure

Severity: High if reachable during fresh transaction admission; otherwise a
replay-boundary risk.

Status: Remediated. ZK-ACE authorization now rejects local verifier failure even
when committed-result trust is set; the flag may log the replay condition but no
longer authorizes transfer execution, replay-nullifier consumption, or balance
movement for a failed ZK-ACE proof.

Evidence: the direct `SubmitZkAceAuthorizedTransfer` wire is retired. The
canonical `zk_ace_prover` path does not expose a caller-selected backend,
verifier key, proof attachment, or generic `OpenVerifyEnvelope`, and now fails
with `CompiledProfileUnavailable` before proof construction. If the candidate
is eventually requalified, `SubmitPrivacyProofV1` execution in
[../crates/iroha_core/src/smartcontracts/isi/privacy.rs](../crates/iroha_core/src/smartcontracts/isi/privacy.rs)
validates the signed transaction intent, compiled activation, governed policy,
native proof, and replay state before committing the transfer effects. The
native verifier does not consult committed-result trust and currently returns
`EngineUnavailable` before proof parsing.

Impact: the original bypass could authorize a transparent transfer and consume a
replay nullifier if the flag were enabled during new block production, fresh
transaction admission, or uncommitted ledger execution. The remediated ZK-ACE path
no longer depends on that operational boundary.

Regression coverage:
`zk_ace_production_dispatch_has_no_activatable_profile` and
`zk_ace_submit_has_no_activatable_compiled_profile` pin verifier and state
transition fail-closure. The four-peer exact-12 lifecycle tests also reject
ZK-ACE activation and proof submission before and after restart.

The retired `trust_committed_execution_results` switch is absent from the
first-release implementation. Committed-block replay/recovery must execute the
same proof-authorizing checks as new blocks; do not add a replay-only verifier
bypass.

### ZK-AUDIT-02: Diagnostic proof endpoints require an explicit non-ledger contract

Severity: Medium.

Status: Closed. The pre-release decode-only `/v1/zk/verify` and
`/v1/zk/submit-proof` routes, their Rust client helpers, and their CLI commands were
removed. Ledger proof records can be created only by a signed transaction containing
`VerifyProof` or another proof-bearing instruction that reaches the guarded core
verifier.

Evidence: the remaining `POST /v1/zk/verify-batch` route performs bounded
cryptographic verification of its standalone IPA diagnostic format and is documented
as non-ledger-equivalent. Attachment storage and the background prover worker remain
report-only and do not return a ledger-acceptance result.

The standalone IPA envelope no longer accepts inline commitment bases. Its
`IpaParams` field is only a `(version, curve, n)` selector; the verifier derives
the sole V1 generator set for that selector and binds the complete derived
parameter fingerprint into the transcript before producing challenges. Retired
wire layouts carrying `g`, `h`, or `u` are non-canonical.

Regression coverage: `zk_subrouter_smoke` asserts that both retired routes return
`404 Not Found`; the existing `zk_verify_batch_*` integration suites cover the
remaining bounded diagnostic verifier.

### ZK-AUDIT-03: ZK-ACE commitment and complete-system security qualification

Severity: Critical if activated; fail-closed in the current tree.

Status: Independent-lane replacement implemented; production qualification
remains unavailable. The original sequential outputs of one capacity-one
sponge did not establish the claimed commitment strength. The sole V1 AIR now
constrains six independently initialized and parameterized Poseidon-x7 lanes
for identity commitments and six separately domain-bound lanes for replay
nullifiers. Native Merkle trees, public transcripts, DEEP challenges, and FRI
use the same typed 48-byte digest; SHA-256 remains only an artifact checksum.

The compiled geometry is a 4,096-row, 88-column masked trace, 32,768-row LDE
(8x blowup), quartic Goldilocks challenges, 136 distinct queries, and eleven
binary folds to a complete 16-element terminal domain of degree at most two.

`ZK_ACE_FULL_ENGINE_AVAILABLE_V1` is therefore false. Proving, verification,
and compiled-profile activation return `EngineUnavailable` before processing
proof material. The candidate relation and exact 2,131,222-byte `ZKA1` wire stay
testable, but are not an executable privacy protocol.

Required evidence: independently review the complete qROM Fiat--Shamir
reduction and six-lane collision/multi-target accounting, then qualify the AIR,
masking, transcript, wire, fixtures, witness lifecycle, hardware parity, and
deployment against the final compiled profile and artifacts. The local
classical-ROM arithmetic certificate is not that independent evidence.

### ZK-AUDIT-04: BN254/Halo2 naming must remain segregated from ledger-grade IPA policy

Severity: Low.

Evidence: `iroha_zkp_halo2` has raw decoding/verification support for multiple curve
identifiers, while registry/runtime policy rejects trusted-setup and non-IPA labels.

Recommendation: keep production backend identifiers narrow and explicit, for example
`halo2/ipa/pallas`; continue rejecting KZG/Groth16/SRS/PTAU-style labels in registry
and runtime dispatch.

The additive Goldilocks IPA implementation and its build feature are removed.
Always-on Core and Torii regressions submit a structurally valid IPA envelope
with the field selector changed to Goldilocks and require rejection. The
Goldilocks selector remains identifiable for STARK metadata without admitting
an alternate IPA group.

### ZK-AUDIT-05: Fixed binding-AIR residual weights admitted a public kernel

Severity: High for generic native STARK metadata binding.

Status: Remediated. The generic binding AIR previously compressed twelve row
residuals with the public fixed coefficients `3, 5, ..., 25`. A malicious prover
could add the non-zero residual vector `(1, -2, 1)` to both opened rows while
preserving a zero composition value because `3 - 2·5 + 7 = 0` and the analogous
next-row coefficients also cancel.

The verifier now compares every coordinate of each transcript-sampled current
and next row with the verifier-owned deterministic binding row. Sampling alone
would still miss a sparse mutation with high probability, so the verifier also
reconstructs the canonical public trace root with a streaming Merkle accumulator
and requires exact equality. It likewise reconstructs the all-zero composition
tree root and matches it exactly; a sparse nonzero composition layer can no
longer pass merely because every sampled opening is zero. Generic binding proofs
and verifying keys are capped at `n_log2 = 12`; larger domains fail closed
instead of forcing unbounded verification work. The regression
`binding_air_rejects_fixed_coefficient_cancellation_rows` constructs the former
collision, while `binding_air_rejects_unsampled_row_via_exact_trace_root` places
a mutation outside every sampled current/successor opening and requires the
exact-root check to reject it. A separate sparse-composition regression pins the
exact zero-root rule.

### ZK-AUDIT-06: FASTPQ accepted alternate Goldilocks representatives

Severity: Medium; proof malleability and canonical-wire boundary failure.

Status: Canonical field checks implemented. The original field decoder could
treat a Merkle sibling encoded as `p` as canonical zero after reduction. V1
uses canonical base-field scalars, four-coefficient Fp4 values, and six-word
48-byte digests. Every coefficient and digest word must be strictly below the
Goldilocks prime.

After resource limits, and before semantic or transcript work, verification now
rejects every noncanonical proof-carried field scalar, Merkle sibling, AIR/FRI
opening, Poseidon root, and permission-field hash. Opaque public hash bytes are
not misclassified as field elements. Public and container-completeness
regressions pin the preflight and reject noncanonical scalar, Fp4, and digest
representations.

### ZK-AUDIT-07: BN254 radix-2 transforms omitted input bit reversal

Severity: High for BN254 FFT/LDE correctness.

Status: Remediated in the CPU, CUDA, and Metal paths. Their iterative
decimation-in-time butterflies consumed coefficient-order input without first
applying the required bit-reversal permutation, so even a degree-one polynomial
produced the wrong evaluation vector. GPU parity could not expose the error
because its CPU reference implemented the same ordering bug.

All three transforms now bit-reverse after canonical-to-Montgomery conversion
and coset scaling, before the butterfly stages. CPU regressions compare FFT and
coset-LDE output with independent direct Horner evaluation; Metal parity reuses
that tested oracle, and the CUDA benchmark reference follows the corrected
ordering. Hardware qualification remains part of release evidence.

### ZK-AUDIT-08: Native Poseidon Merkle paths admitted a noncanonical field alias

Severity: Medium; proof malleability and transcript ambiguity.

Status: The sole V1 decoder rejects noncanonical words. Every native-STARK
root, sibling, and transcript digest is `GoldilocksDigest384V1`, encoded as six
canonical little-endian Goldilocks words. Its constructor and decoder reject
any word greater than or equal to `p`; no modulo-reducing digest decoder is
accepted. Merkle hashing also binds the catalog, profile, tree role, level, and
index. Native-STARK parameter and verifier-key wires have no hash selector,
and selector-bearing layouts fail canonical decoding. The fixed profile is
`stark/fri/poseidon-x7-goldilocks-6x64-v1`; no SHA-256 native-STARK path remains.

### ZK-AUDIT-09: Native FRI used the wrong point for bit-reversed pairs

Severity: High for the claimed polynomial-fold relation.

Status: Fold equation remediated; degree-bound qualification remains open. FRI
layers store adjacent `(x, -x)` evaluations in bit-reversed order, but the prover
and verifier both used `x = omega^j`. They now use
`x = omega^bit_reverse(j, log2(layer_size) - 1)`. An independent `N = 8`,
`f(X) = X` regression proves that pair `j = 1` folds to `beta` at `omega^2` and
that the former `omega` calculation does not.

The generic native verifier still does not turn `blowup_log2` into an explicit
initial degree bound for hidden trace columns. It does authenticate the final
folded value and require it to be the zero Fp4 element. This consistency check
does not establish the missing hidden-trace proximity argument.

Current production callers do not rely on that argument: the verifier-owned
Binding profile reconstructs the complete canonical trace and zero-composition
roots, while Explicit verification reconstructs both roots from required full
trace material. The BFV verifier and both Soracloud structural-precheck callers
require this full-material replay before acceptance. The public-only BFV
entrypoint fails closed. Dedicated ZK-ACE and aggregate transparent engines use
their own DEEP/FRI and terminal-degree verifiers; they do not enter the generic
Binding or Explicit verifier. No generic hidden-witness acceptance path was
identified in this callsite review.

Geometry prevalidation now computes the binary layer count directly and
rejects all invalid wire exponents/arities before any shift. Domain-point
derivation also requires the subgroup size to divide `p - 1`, excluding
nonexistent domains beyond Goldilocks' two-adicity. Exhaustive exponent/arity
and exact-order subgroup regressions cover these checks. They do not close
the missing low-degree argument.

### ZK-AUDIT-10: FASTPQ FRI folded contiguous chunks without domain points

Severity: High for the claimed Reed--Solomon/low-degree argument.

Status: Fold and terminal-degree relation remediated; release security profile
remains open.
The previous fold `sum(y_j * beta^j)` neither opened multiplicative cosets nor
used their domain points. Proving and verification now open strided cosets
`i + k*m`, recover residue-class polynomials with the inverse subgroup DFT and
`x^-j` factors, evaluate them at `beta`, advance the generator and offset by the
round arity, and use a real smaller final subgroup instead of repeat-last
padding. The old schedule then folded all the way to one value, under which any
committed function has a valid terminal scalar and the degree check is vacuous.
The prover now stops with the complete terminal domain still present
(`2^19 -> ... -> 2` for the sole V1 profile). The
verifier derives the conservative exclusive bound `2 * N_trace` from the
quadratic V1 residue ledger, reduces it alongside each fold, authenticates the
single terminal leaf, inverse-interpolates all terminal evaluations, and rejects
every coefficient at or above that bound. Independent constant/linear,
Lagrange-interpolation, schedule, and high-terminal-degree regressions pin both
parts of the relation.

The current FASTPQ verifier also reconstructs the complete batch trace, checks
its base constraints, and recomputes its trace/AIR commitments. That current
boundary prevents the FRI layer from becoming the sole semantic batch check.
An independent security analysis of the commitment/transcript construction
and implemented FRI profile remains a release blocker.
The sole parameter record is `fastpq-state-transition-stark-v1`: an 8x LDE,
Fp4 challenges, 136 distinct queries, and at most eighteen binary reductions.
The compiled domain follows `2^19 -> ... -> 2`, with terminal degree strictly
below one. Every commitment and transcript uses six independent Goldilocks
Poseidon-x7 lanes. The exact local accounting selects the 128-bit target with
54 aggregate artifacts and `Q <= 2^32`; this arithmetic does not establish the
missing protocol-specific qROM reduction or independent digest review.
`FastpqProductionQualificationV1` therefore remains `Unavailable`.

### ZK-AUDIT-11: Exact Halo2 production labels bypassed the outer envelope

Severity: High availability failure for registered production circuits.

Status: Remediated. Registry dispatch previously ran before the Halo2 outer
envelope handler. Exact IVM, Kaigi, transfer, top-up, and unshield labels were
therefore sent to the legacy raw decoder and rejected even when their canonical
`OpenVerifyEnvelope` was valid. Every production Pasta/IPA label now enters the
same authenticated outer-envelope boundary first. Valid-proof regressions cover
all seven exact labels. Production verification now accepts only the strict ZK1
inner carrier. The legacy binary carrier's caller-controlled `n_in`, `n_out`,
and lookup flags were not transcript-authenticated, so it has been retired from
production dispatch. Its standalone parser and compatibility path were removed;
verifier keys now require `IPAK` → `CID1` → `H2VK`, and proofs require `PROF`
followed by optional `I10P`.

### ZK-AUDIT-12: IVM verifier helpers panicked or accepted impossible control flow

Severity: Medium; malformed-witness denial of service and verifier/runtime drift.

Status: Remediated. Constraint trace indices, secp256k1 scalars, heap allocation
arithmetic, memory-region limits, and instruction fetches now use checked
conversion/arithmetic and return verification errors rather than panicking or
truncating. VM trace fetch accepts only an aligned in-range instruction or the
exact end-of-code padding row. Jump and branch helpers preserve the runtime's
four-byte PC alignment class, and `JALR` applies the same relative `!3` mask as
runtime execution. No-panic and half-word-target regressions cover the former
paths.

### ZK-AUDIT-13: FASTPQ's `x^5` S-box was not a Goldilocks permutation

Severity: Critical for FASTPQ and every shared digest using that permutation.

Status: Algebraic collision removed; affected proof systems remain
unqualified. For the Goldilocks prime, `gcd(5, p - 1) = 5`, so `x -> x^5` is
five-to-one rather than a permutation. A chosen pair of distinct first sponge
words reaches the same post-S-box state and produces an identical hash. More
importantly, two valid ZK-ACE identity roots with the same nonzero blinding were
found to produce the same legacy identity commitment.

CPU, CUDA, Metal, public-data digests, and the ZK-ACE AIR now use `x^7`, for
which the exponent is coprime to `p - 1`. FastPQ V1 accepts only its exact named
canonical parameter records; regenerated domain roots/coset offsets and the
coherent trace/LDE relation are pinned by known-answer and collision
regressions. There is no independent pre-release parameter-version field.
Descriptors now call it dense-MDS Goldilocks Poseidon `x^7`; it is not
Poseidon2.

The concrete non-permutation collision is removed, and V1 also replaces the
single-state commitment with six independent lanes. That construction still
requires independent parameter, collision/multi-target, and full-protocol
review. FASTPQ remains release-blocked, and ZK-ACE remains unavailable under
ZK-AUDIT-03.

### ZK-AUDIT-14: BFV public-padding sampling did not bind hidden trace columns

Severity: Critical if the public-only verifier is treated as an execution proof.

Status: Fail-closed. The BFV public-padding entry point authenticated sampled
public rows and composition openings but did not prove low degree for the
unobserved private trace columns. A prover could therefore decouple a hidden
trace from the zero composition values seen at sampled public rows.

Both public-padding-only entry points now reject unconditionally. The governed
full-material verifier retains the structural checks and then deterministically
reconstructs and exactly matches every trace row, composition value, trace root,
and composition root. Re-enabling public-only verification requires separately
committing every hidden trace polynomial, proving its degree bound, and binding
those commitments into the sampled composition relation.

The Core arithmetic conformance suite previously generated local reviewer keys
and expected a signed test package to qualify production execution. The production
gate correctly rejected all eight dependent BFV tests. Deterministic construction
now resides only in a crypto unit-test module, which calls crate-private arithmetic
and asserts that both audited wrappers still reject that local package with
`KnownInsecureExactProfile`. The exact plaintext-multiple profile is known
insecure; adding review evidence cannot activate it. The two generator tests
remain arithmetic diagnostics, with no encryption qualification.
Only canonical two-slot arithmetic material is exported; the 807,864-byte fixture
contains no audit package or reviewer signing key. Core consumes it through strict
complete-material validation and exact re-encoding, preserving every adversarial
assertion. The current actual Core native-STARK suite passes all 63 tests,
including the ten BFV-prefixed cases, in 849.78 seconds with command-local
opt-level 3 for `fastpq_isi`, `fastpq_prover`, and `iroha_crypto`. This test seam
adds no production API or qualification switch. See the
[fixture record](../fixtures/soracloud/bfv_full_bootstrap_conformance_v1.md).

### ZK-AUDIT-15: Secret STARK buffers used optimizable ordinary overwrites

Severity: Medium for prover-side witness confidentiality; malformed-input panic
was a low-severity availability issue.

Status: Remediated. Replayable trace masks, aggregate base/FP4 columns, and
proof-managed-note IFFT coefficients previously used ordinary assignment or
`fill` immediately before deallocation. An optimizer is allowed to remove such
dead stores. They now route each field limb through the `zeroize` crate's
hardened overwrite. The shared masked-trace helper also rejects noncanonical
mask residues before field subtraction, avoiding a debug underflow/panic on
malformed internal input.

The current ZK-ACE prover additionally owns raw witness packing, trace rows,
columns, masked LDE buffers, FRI random coefficients/evaluations, and DEEP
coefficient buffers through `Zeroizing` guards. Base and extension-field
`Zeroize` implementations erase every limb on success, error, and unwind.
This source-level cleanup is not a side-channel or physical-memory audit.

### ZK-AUDIT-16: Halo2 outer schema bytes were not authenticated by generic dispatch

Severity: High metadata-substitution risk for direct production verifier calls.

Status: Remediated. Halo2 authenticates its concrete instance columns, but it
does not absorb the surrounding data-model `OpenVerifyEnvelope.public_inputs`
field. Generic `verify_backend` therefore accepted the same valid proof after
those nonempty outer schema bytes were replaced. Registry-owned call sites often
performed a separate schema-hash comparison, but the public production verifier
did not make that invariant universal.

All seven admitted production circuit ids now normalize through one closed map
to exactly one authoritative schema descriptor. Preverification, timing
guardrails, final verification, and strict verifying-key record preparation
require exact descriptor bytes or their Iroha-hash commitment. Generic and exact
backend aliases select the same entry, and unknown/unmapped circuits fail closed.
Valid IVM proof regressions mutate the outer schema under both generic and exact
labels; Kaigi exports its two owner-crate schema constants so fixtures and
registry policy cannot drift.

### ZK-AUDIT-17: Generic FRI challenges did not bind their round

Severity: Medium transcript-domain-separation weakness.

Status: Remediated. The generic native-STARK prover and verifier derived each
FRI beta from the parameter set, transcript label, and current layer root, but
omitted the layer number. Equal roots at two depths therefore reused the same
challenge. The shared six-lane derivation now binds the round as the typed
`u64` level domain in proof construction, shape validation, and final verification. The
`fri_challenges_bind_the_exact_round` regression pins both determinism within a
round and separation across rounds.

### ZK-AUDIT-18: Aggregate domain validation omitted fixed core roles across layers

Severity: Medium for a misconfigured or future aggregate profile.

Status: Remediated. `AggregateStarkDomainsV1::validate` rejected collisions
among caller-supplied domains and fixed DEEP labels, but did not include the
three fixed FRI-mask leaf, node, and root labels in that uniqueness set. A
profile could therefore pass validation while aliasing masked and unmasked
commitments or transcript frames. The proof-managed relation layer also checked
its own labels against only the fifteen caller-supplied aggregate domains, not
the five fixed DEEP and FRI-mask roles.

The aggregate core now owns one closed five-role set and exposes a collision
predicate to relation layers. Aggregate and proof-managed validation both check
the complete cross-layer set. `aggregate_domains_cannot_alias_fixed_core_roles`
and `malformed_trace_profile_and_entropy_never_emit_a_proof` iterate the
authoritative set so future fixed-role additions cannot silently lose coverage.

### ZK-AUDIT-19: Batch inversion accepted empty and noncanonical inputs

Severity: Low internal invariant weakness.

Status: Remediated. The shared Goldilocks batch inversion helper treated an
empty slice as a successful inversion and allowed noncanonical field wrappers
to enter modular multiplication. It now rejects empty input and every residue
outside the canonical field range before computing prefixes. The regression
`batch_inversion_rejects_empty_and_noncanonical_inputs` pins both cases.

### ZK-AUDIT-20: Kaigi scalar commitments lost one field bit in `Hash`

Severity: Medium public-input ambiguity and honest-proof availability failure.

Status: Remediated. Kaigi previously placed a canonical Pasta scalar directly
inside `Hash::prehashed`. The `Hash` constructor unconditionally sets bit 248,
so scalars that differed only in that bit produced the same instruction
artifact, and roughly half of honest circuit outputs decoded as a different
public input. Kaigi now packs all 255 scalar bits injectively by shifting the
seven high representation bits left, inserting the required marker at bit 248,
and reversing that operation before canonical field decoding. The JS-facing
byte helpers and Rust `Hash` helpers share this encoding. The regression
`scalar_hash_encoding_does_not_overwrite_field_bit_248` demonstrates the old
two-to-one carrier and round-trips both formerly colliding values.

### ZK-AUDIT-21: Kaigi roster proofs did not bind the signed participant

Severity: Critical authorization and proof-replay failure.

Status: Contained by fail-closed production admission. The roster circuit binds
an arbitrary private `account` witness to commitment and nullifier outputs, but
none of its public inputs is derived from the account that signed the
`JoinKaigi` instruction. A non-interactive proof is transferable: an observer
could copy a pending proof and artifacts, name their own signed account as the
participant, and satisfy the former outer authorization check. The roster root
does not repair that missing authority relation.

Production `ZkRosterV1` join verification now rejects before proof dispatch
until a versioned circuit, public-input schema, and deterministic key bind the
canonical signed participant. Transparent Kaigi and usage commitment proofs are
unaffected. Host create/end remains separately usable because every end now
requires the stored host's transaction signature; host-create nullifiers are
recorded and cannot be replayed as end nullifiers. Public JS/native roster
builders fail with the same unavailable status; candidate construction remains
test-only and uses the canonical schema bytes, `CID1` key carrier, nonzero
verifier-key commitment, and canonical Norito outer envelope.

### ZK-AUDIT-22: FASTPQ trace and LDE generators disagreed on the AIR row stride

Severity: High protocol-domain mismatch.

Status: Remediated. Both canonical roots had their advertised exact subgroup
orders, but they were generated independently. Consequently
`lde_root^blowup_factor != trace_root`, while the AIR prover and verifier opened
the alleged next trace row at `index + blowup_factor`. That index was not the
evaluation point obtained by multiplying the current point by the trace
generator, so the transition composition was formed over the wrong row pair.

The sole V1 trace root is derived as `lde_root^blowup_factor`, and
`Planner::new` fails fast if individually primitive roots do not satisfy that
relation. Catalogue tests independently pin
exact orders, outside-subgroup cosets, and the cross-domain equality. Canonical
admission compares the complete parameter record instead of only
its name, and rejects a same-name mutation before trace planning.

The same audit found that the reusable Merkle verifier ignored index bits above
the authentication-path depth, allowing `i + k * 2^depth` to reuse the path for
`i`. Proof verification already derived in-range indices from its transcript,
but the helper now also requires all residual high bits to be zero; an
adversarial-index regression pins the rejection.

### ZK-AUDIT-23: Zero collapsed the aggregate DEEP current/next geometry

Severity: Low-probability verifier-soundness invariant gap.

Status: Remediated. The shared DEEP admissibility predicate excluded trace,
evaluation, query, and translated next-row domains, but accepted zero because
zero lies outside every multiplicative domain. At zero, however,
`z * omega_H == z` for every native trace group. The proof still carried and
mixed independent current and next openings, so the sampled point could
collapse the distinct-point geometry assumed by that relation.

Zero is now explicitly inadmissible. Prover and verifier call the same
`derive_deep_point_v1` after absorbing the FRI-mask roots, so both apply the
same predicate and transcript schedule. Rejection sampling is deterministic and
bounded to sixteen framed attempts; a rejected candidate is not absorbed, and
exhaustion leaves the transcript unchanged and fails closed. The regressions
`deep_point_exclusion_covers_trace_evaluation_query_and_next_domains` and
`goldilocks_fp4_transcript_and_rng_sampling_fail_closed` pin zero rejection,
the exact retry counter/attempt sequence, and bounded exhaustion.

### ZK-AUDIT-24: Oversized Merkle domains reached an infallible hash assertion

Severity: Low profile-misconfiguration availability risk.

Status: Domain checks retained by the sole six-lane implementation. Merkle
tree construction and path/multiproof verification formerly checked only
that node domains were nonempty, allowing an oversized configured domain to
reach an infallible framing assertion. The typed context and role validation
now enforce nonempty, `u16`-bounded domains before six-lane hashing.

Aggregate and proof-managed domain validation now rejects every empty or
oversized framed role. Full-tree, streaming-tree, single-path, and canonical
multiproof entry points independently enforce the same bound before hashing.
`layout_domains_and_frontiers_are_fail_closed`,
`malformed_trace_profile_and_entropy_never_emit_a_proof`, and
`merkle_paths_bind_domain_index_leaf_order_and_depth` cover the configuration,
construction, and verification boundaries.

### ZK-AUDIT-25: Unanchored FASTPQ became generic AXT authorization

Severity: Critical authorization-boundary failure.

Status: Contained for standalone IVM admission; handle-backed authorization
remains release-blocked. FASTPQ's current catalogue uses six independent
Goldilocks digest lanes and explicitly lacks complete production
qualification. Its transfer verifier reconstructs the
complete caller-carried batch, transcript, SMT witness, trace, lookup material,
and commitments. That deterministic replay checks transfer arithmetic and root
chaining, but it does not make caller-supplied `old_root`, `new_root`, or
transaction-set context an authoritative finalized source-state statement.
Several trace fields—including key/asset identity, path-node, running-counter,
and permission columns—are enforced by that replay rather than by every column
appearing in the sampled AIR residue vector. The replay is therefore mandatory
for current correctness and does not supply the missing protocol-specific
qROM reduction or authoritative source-state anchor.

Production CoreHost formerly let `AXT_VERIFY_DS_PROOF` expose successful FASTPQ
verification to a contract and record/cache the proof without matching its
roots and transaction set to a finalized/QC-backed source anchor. A valid
caller-carried witness could therefore be mistaken for authorization without
a finalized source-state anchor. Non-null standalone
admission now returns `PermissionDenied` with `AxtRejectReason::Proof` before
recording proof state or touching an existing verified-proof cache entry. A
zero pointer remains an explicit proof-clear operation. The adversarial
`axt_verify_ds_proof_rejects_unanchored_fastpq_without_state_or_cache_mutation`
regression preloads a valid cache sentinel, submits a fully valid FASTPQ proof,
and proves the proof map, cache contents, and cache slot remain unchanged.

Specialized callsites have distinct trust analyses. Fee-sponsor vault allocation is checked
against authenticated owner/delegation and current authoritative vault/policy
state. Those paths do not derive authority from generic syscall success. The
issuer-signed asset handle path is narrower but not release-qualified: its
signature covers capability and asset identity, not the
`RemoteSpendIntent`, proof bytes, or effective amount. Exact intent and amount
still rely on FASTPQ metadata and its unqualified complete protocol. The
handle path must remain outside production release authorization until those
facts have independently qualified binding or are matched to an
authoritative finalized source-state statement.

### ZK-AUDIT-26: ZK-ACE composition used terminal size as the next-row stride

Severity: High; inconsistent AIR quotient and honest-proof rejection.

Status: Shared trace-stride calculation implemented; all 26 dedicated Core
ZK-ACE tests pass, including the full proof roundtrip. The sole V1 profile has an 8x LDE and a 16-element FRI terminal
domain. Composition construction used `index + 16`, while query openings and
the DEEP relation used `index + 8` and multiplication by the trace generator.
The composition therefore committed a different next-row polynomial.

Composition, query construction, and verification now share
`trace_next_lde_index_v1`; the vanishing-residue schedule also uses the 8x
trace stride. Independent subgroup translation and synthetic `f(X) = X`
quotient regressions pass in the Core test binary, covering interior indices and
wraparound. The field/witness erasure regression also passes. The complete
2,131,222-byte proof roundtrip, canonical re-encoding, second randomized proof,
raw-witness exclusion, terminal degree, and replay-mutation tests pass in the
combined Core binary. The refreshed 26-test run includes the shared prepared-frame
hashing refactor and unused SHA helper removal; it passes in 562.73 seconds with
command-local opt-level 3 for `fastpq_isi`, `fastpq_prover`, and `iroha_crypto`.
The actual executable is `iroha_core-e31551a426162592`, SHA-256
`88bb869aef878c6981e50f1acf0fb1a0a38de2d3b0299c0055d8ae086156adf6`.
This is scoped implementation evidence; it predates later unrelated SoraFS and
SDK changes. Production activation remains unavailable under ZK-AUDIT-03.

### ZK-AUDIT-27: FASTPQ transcript layout and Fp4 wire were not fixed

Severity: High for deterministic transcript agreement and canonical proof decoding.

Status: Canonical layout and exact field codec implemented; focused local
regressions pass. Ordering and transcript initialization inherited ambient
Norito layout flags, so identical logical inputs could produce different
commitments and challenges. Both now explicitly select the canonical default
layout. Ordering, transcript, and complete raw-proof regressions each failed
before this correction and pass afterward under altered ambient layout flags.

The V1 Fp4 codec now writes exactly four little-endian canonical coefficients
(32 bytes), checks every coefficient before archive or slice decoding, and
rejects truncation and the removed struct-framed carrier. Slice decoding
reports exactly 32 consumed bytes so the enclosing decoder owns suffix checks.
Seven field tests, two proof codec tests, the typed FRI commitment-binding
regression, and four canonical-preflight tests pass locally. The sole active
64-row raw-transcript fixture was regenerated and its standard Cargo replay
test passes with exact byte equality. These tests do not establish independent
cryptographic qualification.

The generic native-STARK `GoldilocksFp4V1` carrier now delegates to the same
exact field codec. It also rejects noncanonical coefficients on serialization.
Three regressions pass in the combined Core test binary, covering byte equality,
archive/slice canonicality, truncation, and rejection of the removed struct
frame under the same schema name. The new exhaustive exponent/arity, hostile
opening geometry, and subgroup-order tests also pass in that binary.

### ZK-AUDIT-28: AIR composition replay used the auxiliary tree domain

Severity: High; honest generic and explicit AIR proofs were rejected.

Status: AIR composition root reconstruction now uses the AIR composition role.
The prover committed composition evaluations under `air-composition`, but the
shared root-reconstruction helper used `auxiliary-composition`. Generic prover
self-verification enters the Explicit context, so even an honest proof failed
before reaching the Binding verifier. Governed Soracloud root checks also use
that helper and encountered the same mismatch.

The helper now reconstructs the exact AIR composition root. The separate
auxiliary-composition path helper retains its own role. The named regression
`air_composition_root_uses_its_own_role_for_every_tree_level` covers singleton
leaves and trees with internal nodes, requires equality with the AIR builder,
and rejects equality with the auxiliary builder. The pre-existing constant-zero
root-equivalence test independently detects this mismatch. Exact-module tests
reproduced honest-proof rejection before the fix and acceptance afterward.
A caller linked to the rebuilt production Core library also passes the public
AIR prove/self-verify/verify roundtrip (6,197 bytes). A probe of the complete current
native module using the final Core build's dependencies, with both `fastpq_isi`
and `fastpq_prover` at opt-level 3, produces byte-identical output. Its SHA-256 is
`a0d3bda0df5dadeb515da9a8bb1bc6664e8f967490b49a585e7fdf12ef427549`.
This is scoped CPU build parity, not GPU evidence or a rebuilt whole-Core library.
The subsequent combined Core unit binary passes all 54 non-BFV native tests,
including the new role regression and all 14 earlier AIR-domain failures.
That run's eight BFV tests reached the separate domain-length defect in
ZK-AUDIT-31. After its correction, the refreshed actual Core binary passes all
63 native tests, including the BFV cases and these AIR regressions.

### ZK-AUDIT-29: Native FASTPQ proof execution could report an unused GPU path

Severity: High for hardware qualification and operator-visible execution claims.

Status: Native-V1 proof admission now rejects explicit GPU requirements before
statement or witness processing. The six-lane proof pipeline used CPU work even
when its mode resolution reported GPU. An optional parity test consequently
compared two CPU executions and did not establish GPU proof parity.

`NativeV1GpuUnavailable` is enforced at prover construction and proof entrypoints;
automatic execution resolves and reports CPU for both execution and Poseidon
work. Core syscall 315 now uses the native-V1 GPU preflight, which returns false.
The standalone scalar-kernel preflight cannot qualify the six-lane proof engine.
The misleading optional parity test was replaced by an unconditional rejection
test, with additional tests for error precedence and actual execution reporting.
Six native-V1 admission regressions pass under Cargo, including byte equality
between CPU and automatic execution. Seven observer tests also pass. The
GPU-feature admission regression also passes with `fastpq-gpu` enabled; it
asserts rejection despite scalar-kernel availability.

The bounded message-by-six-lane frame API and lane-specific Metal/CUDA kernels
now exist. The M1 Ultra kernel matches the independent Python SHAKE256/integer
reference for 12 frames and 72 lanes; the Rust-to-Metal host-frame parity test
also passes. The shared Merkle executor routes every tree role and absolute
index through bounded typed frames. A required real Metal test matches every
level and root across empty, singleton, odd shapes and FRI rounds 0 and 7
(2.63 seconds); injected-failure, executor, and preprocessing tests also pass.
Public KAT failure quarantines a backend, and secret host staging plus device
cleanup erase buffers after completion.

This is partial hash/Merkle execution evidence. Native proof constructors and
preflight remain unavailable for GPU: leaf hashes, FFT/LDE/FRI arithmetic, and
transcripts remain on CPU, and CUDA compilation/device qualification is absent.
Complete proof integration and exact deterministic CPU/GPU proof equality are
still required. No complete GPU proof qualification follows from these slices.

### ZK-AUDIT-30: AXT source-state and ordered-set authority were incomplete

Severity: Critical release qualification blocker at the state-authorization boundary.

Status: Ordered-wire producers and an anchor-bound verifier are corrected in
source. Six anchor-verifier tests and seven focused Core producer, lane, state,
and sealed-reveal regressions pass; runtime AXT release remains unavailable.
Full FASTPQ replay establishes consistency of the supplied transfer batch. It
does not make a locally reconstructed balance tree the finalized world-state tree.
This finding does not assert an exploit of an enabled release path.

Both Core block execution paths previously sorted execution-call identities before
applying `tx_set_hash_from_ordered_hashes`. They now use the shared
`axt_ordered_transaction_set_digest_v1` over exact ordered
`TransactionEntrypoint::encode_wire_v1` bytes, including time-trigger entrypoints.
The commitment binds the domain, count, each wire length, and every complete wire.
Its counting pass enforces the consensus 256 MiB wire ceiling, and its streaming
pass must reproduce the count and each wire length exactly. The 65,536-entry
anchored-proof witness limit belongs to that verifier rather than to the general
block commitment helper. Missing or
zero block-owned transaction-set context is rejected instead of reconstructed from
raw transcripts. The model no longer equates a per-execution `source_tx_commitment`
to the whole-set digest.

`verify_axt_proof_envelope_against_anchor_v1` (currently test-only; no production
admission path calls it yet) checks exact ordered-wire commitment,
exactly-once execution identity membership, transfer-only semantics, and equality
of proof roots, transaction set, dataspace, DA commitment, and expiry with the
supplied anchor. For sealed reveals the membership identity is derived from the
exact outer wire. The caller must still authenticate that anchor through finalized
ledger state, QC/committee facts, issuer signatures, successful source execution,
transfer facts, and nonce consumption. This helper does not authorize a spend by
itself. `TrustedBlockProofAnchor::from_verified_finality` accepts only a
`VerifiedSumeragiBlock` from the portable finality verifier, whose checks are relative
to the genesis or checkpoint its caller selected, and `from_committed_execution`
accepts only an executed-wire identity that the certified-chain reader authenticated.
The future AXT resolver must still pin the expected network and trust root from
immutable trusted WSV state, using the `SumeragiFinalityVerifier` trust boundary
([bridge finality](bridge_finality.md)); proof self-consistency alone is insufficient. The six passing tests cover a real transfer proof with a fabricated test
anchor, exact root/set/dataspace bytes, DA/expiry/profile/cap rejection, wire order,
exactly-once membership, and sealed-reveal identity. The complete AXT module suite
passes 76 tests, including those six regressions. The seven Core regressions
passed in 5.55 seconds in the actual `iroha_core-64e142613562998b` test executable;
that executable predates the later shared hash-frame refactor. These fixtures do
not prove authoritative finalized WSV or runtime authorization.

The root foundation also requires replacement on the consensus side.
`post_state_from_witness` and `parent_state_from_witness` in
[the execution-witness roots](../crates/iroha_core/src/exec_witness/roots.rs) use only
witnessed writes and their pre-values, or witnessed reads when there are no writes.
[The SMT constructor](../crates/iroha_core/src/exec_witness/smt.rs) fills absent siblings
with its empty hash. These roots commit to those projections, not the full persisted
WSV. Canonical executed-block bytes and QC authentication do not change that root
meaning. An authoritative root resolver cannot treat this projection as an existing
full-WSV commitment; the persisted commitment design and state proofs remain required.

`batch_from_transcripts` constructs SMT witnesses from the bundle's touched
balances and overwrites the supplied `old_root` and `new_root` with those local
roots. Binding that result to a caller-carried batch and transcript does not prove
that either root is the authoritative finalized WSV root. Transcript binding of
`PublicIO.tx_set_hash` alone also supplies no entry-membership relation.

Closure still requires the Core finalized state witness, authoritative resolver,
and nonce integration to establish and consume those exact facts. A helper or
verifier regression alone cannot qualify the complete runtime path; independent
FASTPQ qualification under ZK-AUDIT-25 is also still required.

### ZK-AUDIT-31: The retired domain-length ceiling rejected full BFV digests

Severity: High; every honest BFV native-STARK proof failed parameter validation.

Status: The native domain ceiling now derives from twice the typed six-lane digest
byte length. The BFV domain helper already returned the complete 48-byte digest as
96 lowercase hexadecimal characters, but generic Core admission still capped the
string at the retired 32-byte digest's 64-character encoding. Once conformance
material reached real BFV proving, all eight dependent tests exposed this mismatch.
The same Core run passed the other 54 native tests, including the AIR-role repair.

The new ceiling is exactly 96 bytes. A named BFV regression admits the full canonical
domain, rejects a 97th character, and preserves a caller's stricter bound. No digest
limb is truncated or re-encoded through an alternate carrier. The stale crypto
regression also expected a 32-byte BLAKE2 digest; it now pins two complete domain
vectors independently reproduced with the separate public six-lane implementation
and explicit BFV domain fields. The corrected crypto regression passes under Cargo
and reproduced failure before the correction. The final actual Core suite passes
all 63 native tests, including the ten BFV-prefixed cases. The arithmetic-only
conformance fixture and production qualification gate remain unchanged.

A supplementary exact-native-module probe using the actual Core dependency
selections generated, fully verified, and canonically re-encoded both BFV slots
in two independent processes. Each proof is 737,089 bytes and repeats exactly;
slot SHA-256 digests are
`fc0e9ff79c781cafb77c8291dc2dfa096992748336841666014db0abc2c4c5c2`
and `69a17c3c0fc851d825da35cd0e04b84cf892d05d642f67a80e7616254e376e61`.
The 6,197-byte generic native proof also matches its saved earlier actual-Core
public-API output exactly. BFV repetition is a determinism check, not a comparison
against an unoptimized BFV build or device execution.


### ZK-AUDIT-32: Archived SDK capability bytes could acquire admission authority

Severity: High at the SDK construction boundary; no enabled transaction bypass
is demonstrated.

Status: The JavaScript decoder is now inspection-only. Previously it bound a
private admission callback to every native-valid archive, including bytes loaded
offline. Its fetch helper also accepted a caller-defined symbol method without
proving that an actual Torii client owned the transport. A fully qualified archive
could therefore supply the public guard's missing transport provenance. The
current production qualification gates remain closed, and no retained transaction
builder consuming this guard was identified.

Only an actual Node Torii client's constructor-registered transport can now issue
a receipt. Its private fetch requires canonical request authentication, HTTPS,
exact response URL without redirects, and a no-store request. It takes the expected
network from the immutable local signing context. The helper consumes the receipt
once and binds admission to that exact manifest object, origin, and network;
copying or re-decoding the archive loses admission authority. Capability fetching
also uses private request, authentication, status, header, and bounded-body helpers;
overriding public client methods cannot replace the authenticated response bytes.
Explicit configured custom fetch implementations remain trusted transport
dependencies and must preserve these authentication and response-metadata requirements.

The native tuple call now requires expected network bytes and compares both the
signed deployment network and genesis hash, while retaining complete archive,
qualification, activation, and local compiled-profile checks. JavaScript controls
cover archived qualified manifests, forged clients, network substitution, HTTP,
redirects, other-origin responses, native rejection, and exact success values.
The fifteen Exact12 controls use an explicit mock native validator to isolate
flow control; they do not fabricate cryptographic qualification. The mutable-helper
regression reproduced failure before the private-path correction and passes after
it. The combined selection, including canonical request authentication, catalog,
FFI, and package-type parity, passes 62 tests with no skips. Native regression
validation and a current provenance-checked local native package are pending.
This finding does not claim that transport provenance alone grants production
readiness or authorizes a transaction.

### ZK-AUDIT-33: FASTPQ balance identity depended on account display configuration

Severity: High for deterministic witness construction; no live consensus split
is demonstrated.

Status: Corrected in the shared model encoder, Core producer and prover. The
focused model/prover selection passes 181 tests and all 11 Core integration
tests pass. The regenerated 1,138,854-byte raw64 proof passes independent replay
under its diagnostic budget; it still exceeds the production 512-KiB cap.

Both balance-key helpers formerly concatenated the asset and account display
strings. `AccountId` display uses an ambient chain discriminant, so the same
canonical account could acquire different balance keys, paths and tree roots
when that display setting changed. Parsing the resulting string in the trace
also treated presentation text as the asset identity boundary.

`iroha_data_model::fastpq::transfer_balance_key` now exclusively encodes the
canonical Norito frame for `FastpqBalanceKeyV1`, with the asset definition and
complete domainless account controller in declared field order. Trace projection
strictly decodes that schema and takes the asset's 16-byte UUID. Display strings,
alternate Norito layouts and other schemas are rejected without another decoder.
The regression crosses four display discriminants with all ten declared caller
layouts and checks identical key bytes, transfer paths and roots. Core fixtures
also cover all eleven account algorithms and complete multisig controllers.
The exact generated key fixture covers all 16 complete controllers. These
results are not four-validator qualification. Subsequent coupled canonical
batch/proof publication corrections are awaiting the next combined capture.

### ZK-AUDIT-34: Managed SDK address admission accepted malformed curve keys

Severity: High for canonical identity parity; on-chain acceptance of those keys
is not demonstrated.

Status: Remediation and native-package verification are in progress. Existing
full-controller fixture passes do not close this finding.

Public construction and parsing accepted eleven of twelve malformed vectors in
C#, nine in Swift, JavaScript and Kotlin, and seven in each Python address
implementation. The vectors include out-of-range secp256k1
coordinates, invalid BLS encodings, invalid GOST coordinates and malformed SM2
points. C# also admitted invalid Ed25519 representatives. Swift and JavaScript
performed stricter Ed25519 checks, but their checks for the other affected curves
were only structural. Length and algorithm tags cannot establish canonical
public-key validity or subgroup membership.

The remediation routes public address admission through the existing Rust ABI
owner and fails closed when that owner is unavailable. It must preserve exact
full-controller fixtures, reject every malformed vector through constructors and
parsers, and execute against each actual final native package. Managed-only
diagnostics and mocked native calls cannot close that package gate. Exact vectors
and before-fix observations are retained under
`target/privacy-release-evidence/2026-09-07-recovery/sdk-final/key-admission-audit.json`.

Kotlin now uses a fixed eleven-algorithm catalog and one JNI admission method;
the process-global curve selector and alternate parser APIs are removed.
Fresh-process absence checks cover eight public entry points. Python separates
the native owner into the transport-independent `iroha-native` distribution,
with exact identity validation shared by the full SDK and Torii. Their source
compile and absence checks do not replace installed native package execution.

### ZK-AUDIT-35: Kotlin public-key multihash length narrowed a signed u64

Severity: Medium for canonical SDK wire admission; on-chain acceptance is not
demonstrated.

Status: Source corrected and the bounded decoder regression passes. Actual
rebuilt JNI positive/negative account suites remain pending.

`Varint.decode` returns the bits of a decoded u64 in a signed `Long`. The public
key decoder checked only its upper signed bound before narrowing to `Int`.
The canonical length prefix `a0808080808080808001` represents `2^63 + 32` but
narrowed to 32, allowing a valid Ed25519 key to satisfy a malformed enclosing
length. Native cryptographic admission alone cannot detect this discarded
envelope information.

The decoder now requires the decoded value to be in `1..65535` before narrowing
and compares it with the exact remaining bytes by subtraction. Truncated,
overflowing and nonminimal varints return `null`; native-unavailable errors are
preserved. Regressions cover the exact wrapping vector, other oversized lengths,
truncation and pre-copy input bounds. Encoding snapshots caller key bytes before
admission and publication, preventing validation of one mutable value followed
by publication of another. The complete Rust key validator remains mandatory.

## Dependency Assumptions

- SHA-256 and Blake2 are collision resistant and implemented correctly.
- Implementations actually identified as Poseidon2 are domain-separated and
  apply delimiter framing before field-sponge padding. FASTPQ and ZK-ACE use a
  separately versioned dense-MDS Goldilocks `x^7` construction and receive no
  Poseidon2 security assumption from this audit.
- Vendored Halo2 and curve crates implement advertised group, scalar-field, and
  transcript APIs correctly.
- Norito encoding is deterministic and rejects malformed payloads according to its
  API contract.
- Committed replay does not bypass proof verification; ZK-ACE verifier failure
  is always rejected.
- Mock privacy features such as Kaigi privacy mock modes are not enabled in
  production.

## Binding and Guardrails

`OpenVerifyEnvelope` carries backend tag, circuit id, VK hash, public inputs,
proof bytes, and auxiliary bytes for the generic proof surface. Admission
validation rejects unsupported backends, empty circuit ids, zero VK hashes,
empty public inputs, empty proofs, oversized fields, and nonempty aux unless
explicitly allowed. ZK-ACE identifiers are reserved at this generic boundary;
the generic STARK prover and verifier reject them and direct callers to
`SubmitPrivacyProofV1`.

`ProofAttachment` rejects inconsistent backend fields and legacy inline VK fields.
`VerifyingKeyRecord` binds circuit id, backend, curve, schema hash, commitment, size
limits, gas schedule id, status, and optional inline key. Ledger admission accepts
active registered VK records only.

Registry and runtime guardrails reject trusted-setup and developer-only labels.
`preverify_with_budget()` checks active VK status, budget, VK commitment, envelope
metadata, and dedup cache keys. Its result is advisory only: it is not persisted
as an authoritative acceptance decision and ledger execution always invokes the
guarded cryptographic verifier. `verify_backend_with_timing_guardrails()` enforces
backend enablement and maximum envelope/proof sizes before dispatch.

## Native STARK/FRI and ZK-ACE AIR

The native STARK verifier uses Goldilocks modulus `2^64 - 2^32 + 1`, six
independent Poseidon-x7 digest lanes, and Fp4 binary folds. It rejects
noncanonical field elements and digest words, validates verifier parameters, verifies Merkle openings,
derives Fiat-Shamir query indices from bound transcript material, binds every
FRI folding challenge to its exact round, checks FRI folds, and binds AIR
trace/composition/public digests. Generic binding-AIR verification
checks every coordinate of each sampled current/next row against the
verifier-owned row instead of compressing residuals with public fixed weights,
then reconstructs and matches the complete canonical public trace root within
the bounded `2^12` generic Binding domain. It also requires the exact Merkle
root of an all-zero composition vector. Explicit full-material verification
recomputes both roots from the complete caller-independent material.

The reserved ZK-ACE ledger shape carries
`PrivacyProofEnvelopeV1::ZkAcePqAuthorizationV1`. Its public input is
`ZkAcePrivacyPublicInputsV1`: the exact typed
`ZkAcePqAuthorizationStatementV1` plus the trusted genesis hash. The statement
binds the chain, action index, transaction-intent digest, compiled artifact
digests, governed policy id and digest, authorization epoch, identity
commitment, transfer participants, asset, atomic amount, and replay nullifier.
The low-level AIR projection is internal to the dedicated prover and verifier.

`ZkAcePrivacyWitnessV1` owns the identity root, identity blinding, and replay
secret behind private fields. It is non-serializable, non-cloneable, and
zeroized on drop; construction rejects an all-zero component. Runtime admission
requires the exact active compiled protocol activation, a valid active governed
policy, an allowlisted source, the signed transaction-intent binding, trusted
genesis, matching statement and policy epochs, a valid native proof, and an
unused replay nullifier. The compiled profile is currently unavailable, so this
validation shape cannot activate or execute a ZK-ACE proof.

The unavailable candidate prover independently masks the execution trace and the
full FRI batching space before transcript challenges, links the AIR at a
quartic-extension DEEP point, and self-verifies each produced proof. Adversarial
tests mutate typed public bindings, witness relations, mask geometry, DEEP
openings, query schedules, and FRI paths.

## Parameter Security

The sole ZK-ACE V1 profile is fixed in the compiled engine descriptor. It has
no caller-selected parameter record or verifier key. The descriptor commits
the Goldilocks base and quartic extension, degree-two AIR, 4,096-row trace,
88 columns, 32,768-row LDE, 512 trace-mask coefficients, an independently
committed FRI mask, one DEEP point, 136 unique queries, eleven binary FRI
rounds, terminal size 16 with degree at most two, the SHA3-384 outer domains,
the six-lane Poseidon identity and nullifier domains,
and the exact 2,131,222-byte wire.

Its parameter asset checksum is
`84c5055b47cc7289835e0a5f31d4563849244ffddbf51f5d67b1db95222ce3e6`
(SHA3-256). The complete profile artifact checksum is
`b3eecf3d57826fbc6fa0dc6811631771629771ee1f30e79757d93009f9e1eb4d`
(SHA-256). These checksums identify artifacts; they are not STARK hashes or
independent audit endorsements.

Security interpretation: the local exact-integer certificate describes a
128-bit work-normalized classical-ROM target for its stated model. It does
not prove the missing qROM Fiat--Shamir reduction or independently qualify
the six-lane construction, AIR implementation, leakage behavior, or hardware
paths. The complete ZK-ACE engine remains unavailable.

## IPA/Halo2 Verification

The Iroha-owned IPA wrapper uses deterministic transparent generator derivation
at circuit-fixed degrees, transcript label limits, curve/parameter consistency
checks, exact compiled verifier-key equality, public instance shape checks,
proof round count checks, final verifier equality, batch helpers, and envelope
decoding limits. Persisted proving keys use bounded canonical Norito archives;
their processed Halo2 payloads are structurally preflighted before the vendored
reader and must re-encode canonically.

Ledger integration adds active VK requirements, backend-label policy, envelope backend
tag checks, VK hash/commitment checks, circuit/schema/public-input metadata checks,
and disabled-backend fail-closed behavior. External Halo2 circuit soundness is an
assumption.

## Torii, IVM, Kaigi, and FASTPQ

Torii ZK endpoints are diagnostic/report surfaces. IVM host verification enforces
backend enablement, active VK maps, namespace binding, envelope size limits, circuit
id matching, inline VK hash matching, owner manifest matching, curve/backend
allowance, schema hash matching, proof caps, and batch limits. Kaigi usage and
host-proof verification enforce configured active VKs, roster-root binding, an
injective canonical Pasta-scalar carrier, envelope backend/circuit/VK-hash
metadata, proof registration, and guardrailed dispatch. Production
`ZkRosterV1` joins fail closed until the roster statement binds the signed
participant authority; see ZK-AUDIT-21.

FASTPQ `verify_with_limits()` checks the sole V1 protocol and exact named canonical
parameter record, batch consistency,
proof size/shape, trace commitment, expected public I/O, nonzero LDE domain, transcript
challenges, lookup/AIR coefficients, sampled query indices, Merkle paths, AIR row
widths, next-row openings, FRI roots, folded values, and query chains. A bounded
preflight first rejects noncanonical representations in every proof-carried
Goldilocks scalar and field container.

Its canonical capacity is a 65,536-row trace and 524,288-row LDE, with blowup
8, 136 distinct queries, no grinding, and eighteen binary folds to two
terminal evaluations of degree strictly below one. FRI challenges, folds,
and openings use Fp4; column mixing and the twenty AIR composition
coefficients remain in the base field. Verification reconstructs the complete
batch, transcript, SMT witness, trace, LDE, and roots. This audit assigns no
standalone succinct AIR soundness claim to that mandatory full-replay path.

AXT/FASTPQ binding checks canonical binding normalization, dataspace, manifest root,
payload size, batch parameter, batch public dataspace, concrete execution batch,
source transaction commitment, embedded binding metadata, claim digest, witness and
policy commitments, source receipt id, target dataspaces, effect type, corridor, batch
seal, transfer transitions, and transfer transcripts. These metadata checks do not
establish the missing ordered entry membership or authoritative WSV witness relation
in ZK-AUDIT-30.

## Formal Model

The audit adds a TLA+ control-plane model under [../formal/zk](../formal/zk) and a
runner at [../scripts/formal/zk_tlc.sh](../scripts/formal/zk_tlc.sh). The model
asserts active matching VK requirements, backend/circuit/schema/VK-hash/domain/public
input non-swappability, disabled/trusted/developer/oversized/decode-only fail-closed
behavior, diagnostic endpoint separation, ZK-ACE replay rejection, and FASTPQ claim
binding. Mutation configs enable one fail-open bug each and must produce TLC
counterexamples.

## Claim Matrix

| Claim | Result | Evidence |
| --- | --- | --- |
| Active VK required | Satisfied for normal ledger paths | `VerifyingKeyRecord::is_active`, registry resolution, `preverify_with_budget`, `VerifyProof` |
| VK hash cannot be swapped | Satisfied | `OpenVerifyEnvelope.vk_hash`, `hash_vk`, registry commitment checks |
| Backend cannot be swapped | Satisfied | `ProofAttachment`, attachment validation, `verify_backend`, guardrails |
| Circuit/schema/public inputs cannot be swapped | Satisfied for production registry and direct dispatch | normalized circuit checks, closed Halo2 schema map, schema hash checks, public-input digest checks; see ZK-AUDIT-16 |
| STARK domain tag is bound | Satisfied | derived STARK domain tag checked against inner envelope |
| Malformed STARK proof rejection | Satisfied by code shape and tests | decode, parameter, Merkle, AIR, and FRI checks |
| ZK-ACE replay rejected | Satisfied; verifier-failure trust bypass remediated | signed transaction intent, governed policy, and replay-nullifier checks; see ZK-AUDIT-01 |
| ZK-ACE privacy strength | Unavailable pending independent qROM reduction, digest accounting, and implementation review | six-lane profile and fail-closed engine flag; see ZK-AUDIT-03 and ZK-AUDIT-13 |
| IPA metadata binding | Satisfied for Iroha-owned wrapper | generator DST, transcript limits, shape checks, canonical outer schema, strict ZK1 carrier, VK/envelope checks |
| Trusted setup fail-closed | Satisfied in audited policy | registry and runtime label rejection |
| Diagnostic endpoint not ledger-grade | Satisfied in code; documentation risk | Torii attachment/prover worker are report-only; see ZK-AUDIT-02 |
| FASTPQ transfer replay and lane claim binding | Local transfer replay and anchor-relative ordered entry membership implemented; authoritative source-state binding unresolved | `ensure_public_io_matches`, transcript/SMT replay, `verify_batch_matches_binding`, and the anchor-bound verifier; authenticating that anchor against finalized WSV remains open under ZK-AUDIT-25 and ZK-AUDIT-30 |
| AXT remote-spend authorization strength | Unavailable for release; generic proof admission fails closed and handle intent/amount binding depends on unqualified FASTPQ | non-mutating `AXT_VERIFY_DS_PROOF` rejection, inline authenticated-handle tests, missing authoritative state witness and resolver/nonce integration, and independent proof qualification; see ZK-AUDIT-25 and ZK-AUDIT-30 |

## Verification Plan

```bash
scripts/formal/zk_tlc.sh fast
scripts/formal/zk_tlc.sh mutations
cargo test -p iroha_core_zk --lib stark::tests::
cargo test -p iroha_core --features zk-stark --lib zk_ace
cargo test -p iroha_core_zk --lib
cargo test -p iroha_zkp_halo2
cargo test -p fastpq_prover
```

The broad `zk::` library slice exercises the fast builder, preflight,
public-input substitution, transcript, range, and metadata-binding negative
paths. The heavyweight KAGEMUSHA V1 MockProver subtests were deleted with the
old KAGEMUSHA circuits on 2026-10-05.

Audit-driven regression coverage includes the retired ZK-ACE trust-flag
bypass, diagnostic success not creating ledger proof records, continued
backend-label rejection, compiled-profile substitution, typed-statement
mutation, governed-policy drift, and malformed dedicated STARK proofs.
Additional trust-boundary regressions cover tampered confidential-transfer
proofs when committed-result trust is set. Add further
regressions only for newly confirmed gaps.

## Conclusion

The reviewed ZK admission paths bind active VK registry policy, envelope metadata,
backend guardrails, public inputs, and proof dispatch. Native STARK/FRI and FASTPQ
also contain malformed-proof rejection and statement-binding checks. These scoped
properties do not close the protocol qualification, authoritative source-state,
hardware, or deployment obligations recorded above.

ZK-ACE now carries a quantitative compiled-profile certificate and fixed proof
wire instead of the historical caller-selected PoC parameters. Independent
review must be repeated if that profile changes, and the current certificate is
strictly a classical random-oracle claim rather than a qROM claim.
Recovery-only trust and diagnostic endpoints must remain outside fresh ledger
admission, with tests proving that separation across proof-bearing flows.
