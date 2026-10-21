//! Iroha-native PIPA-v1 PLONKish/IPA proof system (`specs/plonk_ipa_v1.md`).
//!
//! `iroha_plonk` reimplements the halo2-axiom arithmetization natively on
//! [`iroha_pasta`]. Arithmetic references and current native regression captures
//! exercise its norm products, total challenge maps and scoped generator claims.
//!
//! # Contents
//!
//! Stage ENGINE-1 (tasks T8, T9):
//!
//! - [`cs`]: the constraint-system IR. [`cs::Expression`] trees over fixed,
//!   advice and instance queries, gates, halo2 permuted lookups, the chunked
//!   permutation argument and its copy assembly, an exact port of halo2
//!   selector compression with a canonical packing budget, and [`cs::CircuitDescriptorV1`], the canonical
//!   Norito statement of everything a verifier evaluates, with its digest.
//! - [`frontend`]: the circuit API. [`frontend::Circuit`], [`frontend::Layouter`],
//!   [`frontend::Region`], [`frontend::Value`] and [`frontend::Assigned`], a
//!   floor planner whose layout equals the halo2-axiom `SimpleFloorPlanner`, and
//!   the [`frontend::Assembly`] that records fixed values, selectors, copies and
//!   witnesses.
//! - [`check`]: the constraint checker, a naive interpreter over the
//!   uncompressed source expressions with cell-level diagnostics. It replaces
//!   halo2's `MockProver` and is stricter: queries of unassigned advice cells,
//!   of blinding rows and across the domain boundary are reported.
//!
//! Stage ENGINE-2 (tasks T10, T11, T13 PCS):
//!
//! - [`keys`]: the [`keys::VerifyingKey`] `0x02` codec with a strict reader
//!   bound to a [`keys::DescriptorBinding`], the [`keys::ProvingKey`] with the
//!   exact quotient cosets and its fixed-coset cache, and deterministic key
//!   generation with halo2's permutation cycles.
//! - [`transcript`]: the `BLAKE2b` `Challenge255` transcript and the KAGEMUSHA
//!   RP57 Poseidon transcript (injective point absorption in production), the
//!   canonical proof-message decoding and the instance-frame prelude.
//! - [`pcs`]: commitments, the BGH19 IPA whose prover returns the folded
//!   generator, succinct accumulation into a `#[must_use]` pending
//!   accumulator (never a verdict), `decide` and the deterministic
//!   `batch_decide`, the complete-formula verifier MSM, and the multiopen
//!   with static query grouping.
//!
//! Stage ENGINE-3 (tasks T12, T13):
//!
//! - [`protocol`]: the tables the prover and verifier share, derived from the
//!   descriptor alone: the shape, the opening queries of spec 9.1 and their
//!   static plan, the exact proof length, the Lagrange and Direct-instance
//!   evaluations, the explicit-stack expression evaluator, the S7
//!   zero-knowledge budget computed from the opening plan, and the
//!   declarative constraint-term and transcript-schedule tables every
//!   verifier walks (S11).
//! - [`prover`]: [`prover::create_proof`] with the `BlindingScheduleV1` draw
//!   order from an opaque [`prover::ProverRandomness`] selecting fresh OS entropy
//!   directly or hedged with the witness and statement digests, the advice, lookup,
//!   permutation and vanishing commitments, the quotient on exactly `d - 1`
//!   cosets evaluated by a compiled, hash-consed expression DAG, and the
//!   multiopen; [`prover::Witness`] checks a circuit against its key.
//! - [`verifier`]: [`verifier::verify_full`], [`verifier::accumulate_succinct`]
//!   (deferral into an accumulator, never a verdict) and
//!   [`verifier::batch_verify`] with typed [`verifier::VerifyError`]
//!   rejections: canonical decoding, the exact proof length, exact instance
//!   shapes in both modes, pinned parameters, the descriptor-bound
//!   `transcript_repr`, total role-specific challenge maps and static opening
//!   groups.
//! - [`verification_counters`]: always-on, in-memory, observation-only
//!   per-thread counts of full verifications, decides and their `<s(u), g>`
//!   MSMs. No verifier reads them.
//!
//! The unit-only `captured_goldens` suite freshly proves native circuits and
//! compares descriptors, keys and proof bytes with the current native-generated
//! corpus. Its capture provenance is recorded with the fixtures. This is
//! deterministic regression evidence, not an independent implementation oracle.
//!
//! # Determinism
//!
//! Every output is a pure function of its inputs: exact field and group
//! arithmetic, ordered maps only, no behaviour sourced from environment
//! variables. Kernels run on the caller's Rayon pool and their results do not
//! depend on the thread count. Prover randomness comes only from a consumed
//! fresh-randomness owner, drawn in the `BlindingScheduleV1` order. Arithmetic on sizes
//! is checked; an overflow is an error, never a wrap.
//!
//! # Soundness rules enforced here
//!
//! - Queries are interned per `(column, rotation)` exactly as halo2 interns
//!   them, and a descriptor with a repeated `(column, rotation)` query, or with
//!   rotations that collide modulo `n`, is rejected (spec section 12, S2).
//! - Opening queries are grouped by slot (column kind and index), never by
//!   commitment value, and a repeated query must repeat its evaluation bit
//!   for bit (S1, S3).
//! - Descriptors fix the exact length of every instance column, and the
//!   transcript prelude frames the instance shape (S4).
//! - Verifiers accept only parameters derived here or matching the pinned
//!   digest per `(curve, k)` (S5), and descriptors pin the zero-knowledge
//!   query budget (S7).
//! - Every proof message decodes canonically, the identity point is never
//!   absorbed, the proof length is exact (trailing bytes are rejected),
//!   mapped `x` is nonzero and outside the evaluation domain, and only `verify_full`,
//!   `batch_verify`, `decide` and `batch_decide` accept (S9, spec section
//!   11). [`accumulate_succinct`] is satisfiable for false statements until
//!   its accumulator is decided, so its `Ok` is never a verdict.
//! - Verifier MSMs use complete formulas only ([`pcs::ipa::commit::msm_complete`]);
//!   budgets change speed, never verdicts (S10).
//! - Provers draw randomness only from [`prover::ProverRandomness`]; fixed
//!   seeds exist only in unit tests (S8).
//!
//! # Independent reference tests
//!
//! Current native captures remain checked by `captured_goldens`; quotient
//! evaluation is compared with the serial `row_wise_reference` in
//! `prover/quotient/streamed_tests.rs`. The separate standard-library Python
//! verifier under `fixtures/native_prover/reference_verifier` implements the
//! current norm equations and total challenge maps without a second Rust prover.
//! It rejects ancestor fixture formats. Genuine current-source captures and their
//! independent verification remain required before numerical qualification.
//!
//! Proof construction and verification use only descriptor-bound native framing.
//! Historical Poseidon primitive vectors retain test-only reference absorption;
//! they cannot select a proof protocol. Caller-seeded randomness is also confined
//! to unit tests; shipping builds expose no fixed-seed proving API.
//!
//! ```compile_fail
//! let _ = iroha_plonk::ProverRandomness::fixed_seed_for_tests([0; 32]);
//! ```
#![forbid(unsafe_code)]

pub mod check;
pub mod cs;
pub mod frontend;
pub mod keys;
pub mod pcs;
pub mod protocol;
pub mod prover;
#[cfg(test)]
mod test_circuits;
pub mod transcript;
pub mod verification_attempt;
pub mod verification_counters;
pub mod verifier;
pub mod work_metrics;

pub use check::{CheckFailure, CheckMode, CheckReport};
pub use cs::{
    CircuitDescriptorV1, CircuitDescriptorV2, ConstraintSystem, CsError, DescriptorError,
    Expression, InstanceType, TranscriptV2,
};
pub use frontend::{Circuit, Error, Layouter, Region, SimpleFloorPlanner, Value};
pub use keys::{DescriptorBinding, KeyError, ProvingKey, VerifyingKey};
pub use pcs::{
    ipa::{
        IpaError, PinnedParams,
        accumulator::{AccumulatorError, PendingAccumulator, batch_decide},
    },
    multiopen::{MultiopenError, OpeningPlan, OpeningQuery, Slot, SlotKind},
};
pub use protocol::{Protocol, ProtocolError, Shape};
pub use prover::{
    ProverConfig, ProverError, ProverOutput, ProverRandomness, QuotientWorkspace, Witness,
    WorkspaceError, create_proof, create_proof_owned, create_proof_owned_with_claim,
    create_proof_owned_with_workspace, prove_circuit,
};
pub use transcript::{Transcript, TranscriptError, TranscriptRead, TranscriptWrite};
pub use verification_counters::VerificationCounts;
pub use verifier::{
    BatchItem, VerifyError, accumulate_generator, accumulate_succinct, batch_verify, verify_full,
    verify_full_from_bytes, verify_full_from_bytes_v2,
};

#[cfg(test)]
mod pipa_r_tests;

mod secret;

#[cfg(test)]
mod cancellation_integration_tests;

#[cfg(test)]
mod captured_goldens;

/// Canonical local verification attempt owners, shared by native consumers and the VM.
pub use verification_attempt::{
    NativeVerifierInitError, VerificationAttemptError, VerificationRefusal, VerificationRefusalKind,
};

mod norm;
pub(crate) use norm::norm_factor;

#[cfg(test)]
mod native_reference_capture;
