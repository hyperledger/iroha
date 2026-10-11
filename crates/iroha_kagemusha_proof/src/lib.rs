//! Native-only KAGEMUSHA step relations on the PIPA-v1 engine
//! ([`iroha_plonk`], `specs/plonk_ipa_v1.md`).
//!
//! This crate is the compilation boundary of KAGEMUSHA relations built on the
//! native stack: it links [`iroha_pasta`], [`iroha_plonk`] and
//! [`iroha_plonk_gadgets`] only, never the vendored halo2 stack or
//! `iroha_core_zk`.
//!
//! # Status
//!
//! The split-lineage step relations `sigma_send` and `sigma_recv`
//! (`specs/kagemusha_single_design_proposal.md` sections 3, 3.2, 5.1 and 7)
//! in the G1 wallet layout of `iroha_data_model`
//! (`specs/kagemusha_wallet_wire_v1.md` section 3.2): the G1 Poseidon
//! domains, the 32-element core and 13-element rest, the `Fp` head
//! commitment, the chain appends, the one-element Poseidon `credit_id` and
//! the 28-element statement, pinned by the shared vectors of
//! `fixtures/kagemusha/wallet_v1_vectors.json` (`tests/digest_parity.rs`).
//! No protocol path uses them yet, and the artifact set (verifying keys,
//! their digest rule and the frozen proof lengths) is G3 work.
//!
//! # Contents
//!
//! - [`witness`]: the native witness types ([`StepWitness`]), the relations
//!   with their verifying-key selector ([`SigmaRelation`]), the reference
//!   evaluation ([`StepWitness::evaluate`]: every digest, the successor and
//!   the relation [`Violation`]s), the Request body ([`RequestBody`]) and
//!   the public input ([`StepPublic`]).
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
//! successor's accepted-time floor to `lower` and, with the blacklist
//! control, enforces the maximum list age. `sigma_recv` matches the
//! Request's receiver by `wallet_id` and credits the amount without
//! overflow. The public input is the digest of the 28-element G1 statement.
//!
//! # Determinism
//!
//! Layouts, keys and digests are pure functions of their inputs: ordered
//! containers, checked row arithmetic, no environment variables and no
//! `unsafe`. Proofs depend only on the inputs and the caller's
//! [`iroha_plonk::ProverRandomness`]; the Rayon pool size changes no key or
//! proof byte (`tests/real_proofs.rs` checks 1, 2, 4 and 7 threads).
#![forbid(unsafe_code)]

pub mod circuit;
pub mod consumer;
pub mod proof;
mod relation;
pub mod shape;
pub mod vectors;
pub mod witness;

pub use circuit::{
    HashSite, Inventory, LanePlan, MAX_LANES, PUBLIC_OUTPUTS, ParamsError, PrefixMode,
    RelationOutput, RelationShape, SigmaCircuit, SigmaConfig, SigmaParams,
};
pub use consumer::{
    Accepted, ConsumerError, LineageView, check_receive, check_send, lineage_view_of,
};
pub use iroha_plonk_gadgets::statement::{StatementV1, StepRelation};
pub use proof::{
    KeyOptions, SigmaAllowlist, SigmaError, SigmaProof, SigmaProver, SigmaVerifier,
    VERIFYING_KEY_ENTRY_TRANSCRIPT_BYTES, VerifyingKeyEntry, selector_for,
};
pub use shape::{
    PROOF_BYTES_GATE, ProofFormat, ShapeChoice, ShapePolicy, SigmaShape, limb_bits_for,
    select_shape,
};
pub use vectors::{Mutation, SAMPLE_RELATION_ID, sample_witness};
pub use witness::{
    CONTROL_ATTESTATION_LEASE, CONTROL_BLACKLIST, CONTROL_QUOTAS, CONTROLS_DEFINED,
    CONTROLS_SUPPORTED, Controls, CoreState, Identity, LIFECYCLE_ACTIVE, LIFECYCLE_RETIRING,
    LineageInputs, MapRoots, NativeStep, ReceiveInputs, RequestBody, RequestTerms, SendInputs,
    SigmaRelation, StateRest, StateV1, StepDigests, StepInputs, StepPublic, StepWitness, Violation,
};
