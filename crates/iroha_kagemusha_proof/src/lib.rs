//! Native-only KAGEMUSHA step relations on the PIPA-R engine
//! ([`iroha_plonk`], `specs/plonk_ipa_v1.md`).
//!
//! This crate is the compilation boundary of KAGEMUSHA relations built on the
//! native stack: it links [`iroha_pasta`], [`iroha_plonk`] and
//! [`iroha_plonk_gadgets`] and [`iroha_plonk_recursion`], never the vendored halo2 stack or
//! `iroha_core_zk`.
//!
//! # Status
//!
//! The split-lineage step relations `sigma_send` and `sigma_recv`
//! (`specs/kagemusha_single_design_proposal.md` sections 3, 3.2, 5.1 and 7)
//! in the G1 wallet layout of `iroha_data_model`
//! (`specs/kagemusha_wallet_wire_v1.md` sections 3.2 to 3.4): the G1
//! Poseidon domains, the 33-element core and 8-element rest, the `Fp` head
//! commitment, the chain appends, the one-element Poseidon `credit_id` over
//! the 26-element Request body (both account digests included), the
//! 26-element statement and every enabled control: the blacklist gap
//! opening and list age, the quota windows and usage update and the
//! attestation lease in `sigma_send`, and the receiver's blacklist in
//! `sigma_recv`. The shared vectors of
//! `fixtures/kagemusha/wallet_v1_vectors.json` pin them
//! (`tests/digest_parity.rs`). The native wallet provider and ledger verifier
//! consume these relations. The complete installed artifact set, actual proof
//! lengths and end-to-end acceptance remain release qualification work.
//! Keys use V2 descriptors and the `kgwvkey1` digest.
//!
//! # Contents
//!
//! - [`witness`]: the native witness types ([`StepWitness`]), the relations
//!   with their verifying-key selector ([`SigmaRelation`]), the reference
//!   evaluation ([`StepWitness::evaluate`]: every digest, the successor and
//!   the relation [`Violation`]s), the Request body ([`RequestBody`]) and
//!   the public input ([`StepPublic`]).
//! - [`controls`]: the control witnesses (blacklist gap, quota segments and
//!   charges) and their native reference rules.
//! - [`tree`]: the native blacklist gap tree, quota-window tree and depth-32
//!   indexed Merkle tree, their domains and openings.
//! - [`circuit`]: [`SigmaCircuit`], the step relations on Pow5 sponge lanes,
//!   running-sum range checks, checked `u128`/`u64` arithmetic and glue
//!   gates, with folded or absorbed Poseidon prefixes.
//! - [`consumer`]: the native spec section 3.2 checks a package consumer
//!   runs on a statement before selecting the verifying key and verifying
//!   its proof.
//! - [`shape`]: [`SigmaShape`] and the shape selector [`select_shape`] (the
//!   smallest `k` that fits, optionally within a proof byte budget), with
//!   exact proof lengths from the descriptor.
//! - [`proof`]: key generation, proving and verification ([`SigmaProver`],
//!   [`SigmaVerifier`]) and the verifying-key allowlist selected by
//!   `(operation tag, mask)` ([`SigmaAllowlist`]).
//! - [`q_sigma`]: shared-lane recursive verification, exact proof-byte export,
//!   witness-key allowlist binding and local sigma obligation accumulation.
//! - [`vectors`]: deterministic sample witnesses and relation mutations.
//!
//! # Relation
//!
//! Both steps open the predecessor commitment `P(kgwcore1, core ||
//! P(kgwrest1, rest))` (lifecycle Active or Retiring, carried unchanged),
//! check a nonzero `u128` amount and `sequence + 1 < 2^128`, derive
//! `credit_id = P(kgwcrdt1, Request body)` in circuit (with the scheme,
//! asset and own wallet of the Request taken from the opened core), require
//! distinct payer and receiver wallets, append one chain and commit the
//! successor. `sigma_send` takes `burned_total` and the pending-outgoing
//! root of the predecessor's lineage proof as public inputs, requires the
//! core's enabled-controls mask to be its relation's, checks
//! `amount + fee <= balance - burned_total`, advances the send ordinal,
//! requires `request_policy_epoch <= policy_epoch` and
//! `max(accepted_time_floor, request_time) <= lower <= upper`, raises the
//! successor's accepted-time floor to `lower` and enforces each control of
//! its mask: with a held blacklist, the receiver's account absent from the
//! list and the maximum list age; the quota windows the interval touches,
//! their limits and the aligned fixed64 quota-usage update, quota-share expiry
//! and accepted-span bound; the lease expiry.
//! `sigma_recv` matches the Request's receiver by `wallet_id`, credits the
//! amount without overflow and selects blacklist enforcement from the
//! Request's recorded version, opening the payer's account against that
//! recorded root regardless of current-list changes. The public input is the digest of the
//! 26-element G1 statement.
//!
//! # Determinism
//!
//! Layouts, keys and digests are pure functions of their inputs: ordered
//! containers, checked row arithmetic, no environment variables and no
//! `unsafe`. Proofs depend only on the inputs and the caller's
//! [`iroha_plonk::ProverRandomness`]; the Rayon pool size changes no key or
//! proof byte (`tests/real_proofs.rs` checks 1, 2, 4 and 7 threads).
#![forbid(unsafe_code)]

pub mod a_relation;
pub mod admin_sigma;
pub mod circuit;
pub mod consumer;
mod control_circuit;
pub mod controls;
pub mod omega;
pub mod operation_relation;
pub mod proof;
pub mod q_sigma;
pub mod q_signature;
mod relation;
pub mod shape;
pub mod tree;
pub mod vectors;
pub mod witness;

pub use circuit::{
    HashSite, Inventory, LanePlan, MAX_LANES, MAX_UNFOLDED_PERMUTATIONS, PUBLIC_OUTPUTS,
    ParamsError, PrefixMode, RelationOutput, RelationShape, STARTS_PER_SELECTOR_COLUMN,
    SigmaCircuit, SigmaConfig, SigmaParams, UsagePath,
};
pub use consumer::{
    Accepted, ConsumerError, LineageView, check_receive, check_send, lineage_view_of,
};
pub use controls::{QuotaCharge, QuotaWitness, WindowSegment, WindowSlot};
pub use iroha_plonk_gadgets::statement::{StatementV1, StepRelation};
pub use proof::{
    KeyOptions, SigmaAllowlist, SigmaError, SigmaProof, SigmaProver, SigmaVerifier,
    VERIFYING_KEY_ENTRY_TRANSCRIPT_BYTES, VerifyingKeyEntry, selector_for,
};
pub use shape::{
    PROOF_BYTES_GATE, ShapeChoice, ShapePolicy, SigmaShape, limb_bits_for, select_shape,
    wallet_monetary_shape,
};
pub use tree::{BlacklistGap, IndexedInsert, IndexedLeaf, QuotaWindow};
pub use vectors::{Mutation, SAMPLE_RELATION_ID, sample_witness};
pub use witness::{
    CONTROL_ATTESTATION_LEASE, CONTROL_BLACKLIST, CONTROL_QUOTAS, CONTROLS_DEFINED, Controls,
    CoreState, Identity, LIFECYCLE_ACTIVE, LIFECYCLE_RETIRING, LineageInputs, MapRoots, NativeStep,
    RECEIVE_CONTROLS, ReceiveInputs, RequestBody, RequestTerms, SendInputs, SigmaRelation,
    StateRest, StateV1, StepDigests, StepInputs, StepPublic, StepWitness, Violation,
};
