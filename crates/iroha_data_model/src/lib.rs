//! Ledger identities, transactions, instructions, events, queries and protocol records.
//!
//! Binary and JSON codecs are part of the aggregate protocol model. JSON carries
//! admission policies, consensus parameters and retained state, so its validation
//! and canonical representations are available in every feature selection.
#![allow(unexpected_cfgs)]
#![allow(semicolon_in_expressions_from_macros)]
#![cfg_attr(
    test,
    expect(
        clippy::large_stack_arrays,
        reason = "test-only derive expansion materializes the complete data-model type registry as one local array; production code does not allocate it"
    )
)]
#[cfg(test)]
extern crate self as iroha_data_model;
// NOTE: Documentation coverage is enforced at the workspace level. If a
// module lacks coverage, add targeted documentation at the module boundary
// rather than silencing the lint at the crate root.
pub use iroha_crypto::PublicKey;
pub use iroha_data_model_derive::model;
pub use norito::codec::{Decode, Encode};

pub use norito::json::{JsonDeserialize, JsonSerialize};

pub use norito_derive::{
    FastJson as DeriveFastJson, FastJsonWrite as DeriveFastJsonWrite,
    JsonDeserialize as DeriveJsonDeserialize, JsonSerialize as DeriveJsonSerialize,
};
/// Data model compatibility version for SDK and node handshakes.
///
/// Version 2 makes the signature-bound fee payment intent mandatory and replaces account/policy fee
/// sponsorship with on-chain sponsor programs. Version 3 adds the flat ordered transaction/trigger
/// executable batch that atomically interleaves native instructions and deployed-contract calls.
/// Version 4 requires validation-fee policy and payout-lifecycle proposals to use the canonical
/// certificate-only Parliament lifecycle and its retained proposal records.
pub const DATA_MODEL_VERSION: u32 = 4;
#[macro_use]
mod id_macros;
pub mod account;
/// Account domain model types and queries.
pub mod alias;
/// Declarative alias/SNS setup names, intents, plans, and diagnostics.
pub mod alias_setup;
/// Asset definitions, instances, and utilities.
pub mod asset;
mod inline_fields;
pub use asset::{AssetDefinitionId, AssetId};
/// Block-level data structures and helpers.
pub mod block;
/// Bridge-related data types.
pub mod bridge;
/// Application-owned upgraded racing replay and state types; no custody authority.
pub mod classed_race_v1;
/// Shared primitives reused across data model modules.
pub mod common;
/// Compute lane requests, manifests, and receipts.
pub mod compute;
/// Confidential registries and parameter descriptors.
pub mod confidential;
/// Consensus-related messages and state representations.
pub mod consensus;
/// Static content hosting records.
pub mod content;
/// Accumulated exact-value contract-state commitments and inclusion proofs.
pub mod contract_state_proof;
/// Data availability ingest, manifest, and governance types.
pub mod da;
/// Domain metadata and registration structures.
pub mod domain;
/// Common error types surfaced by the data model.
pub mod error;
/// Canonical error codes and structured contexts surfaced by AMX/DA/settlement.
pub mod errors;
/// Generic native asset escrow records.
pub mod escrow;
/// Event payloads emitted by the ledger.
pub mod events;
/// Native execution-proof statements and deterministic race replay types.
pub mod execution_proofs;
/// Canonical execution-witness key namespaces shared by producers and verifiers.
pub mod execution_witness;
/// Executor configuration and API types.
pub mod executor;
/// FASTPQ-specific transcripts shared between host and prover.
pub mod fastpq;
/// Fraud detection and risk scoring data types.
pub mod fraud;
pub mod sccp;
// Certificate-bearing Parliament data must remain available to the always-on
// validation-fee registry without enabling governance instructions or events.
/// Application-independent game session records and signed gameplay messages.
pub mod game;
pub mod game_resources;
/// Governance protocol types.
pub mod governance;
mod governance_fingerprint;
/// Hijiri reputation system data types.
pub mod hijiri;
/// Identifier newtypes and supporting helpers.
pub mod id;
/// Hidden-function-backed identifier policy and claim types.
pub mod identifier;
/// IPFS helper types used for off-chain references.
pub mod ipfs;
/// Instruction-set interface (ISI) data types.
pub mod isi;
mod json_helpers;

mod json_key_codec;

pub mod fee_evidence;
mod json_object_key;
/// Jurisdiction Data Guardian attestations and committee types.
pub mod jurisdiction;
/// KAGEMUSHA hardware-backed cash commitments, proofs, and settlement models.
pub mod kagemusha;
/// Kaigi session descriptors and billing profile definitions.
pub mod kaigi;
/// Log-level and severity utilities.
pub mod level;
/// Ministry transparency/governance payload types.
pub mod ministry;
/// Musubi package registry data types for Kotodama source packages.
pub mod musubi;
/// Nexus-lane scaffolding and identifiers.
pub mod nexus;
/// Non-fungible token structures and specs.
pub mod nft;
/// Native NFT custody and exact-price sale records.
pub mod nft_market;
/// Oracle feed schemas and deterministic committee helpers.
pub mod oracle;
/// Runtime parameter definitions and schema.
pub mod parameter;
/// Finality-bound SORA Parliament timed-OVN casting commitments and proofs.
pub mod parliament_casting;
#[path = "governance/types.rs"]
#[doc(hidden)]
pub mod parliament_types;
/// Peer and network-topology types.
pub mod peer;
/// Permission token and grant model.
pub mod permission;
/// Provider-backed phone-control challenge, credential and provider policy.
pub mod phone_control;
/// Committed execution-limit policy: the typed chain parameter, its protocol default and validation.
pub mod pipeline_validity_policy;
/// Canonical protocol-bound privacy proof and activation types.
pub mod privacy;
/// Opaque certified private-root anchors with owner-authorized parent registration.
pub mod private_dataspace;
/// Zero-knowledge proof payload types
pub mod proof;
/// QR stream framing types for offline payload handoff.
pub mod qr_stream;
/// Query builders, predicates, and parameter types.
pub mod query;
/// Generic hidden-program RAM-LFE program policies and receipts.
pub mod ram_lfe;
/// Repo agreement descriptors and governance knobs.
pub mod repo;
/// Role-based access control definitions.
pub mod role;
/// Runtime upgrade payloads and manifests.
pub mod runtime;
/// Real-world asset lot structures and controls.
pub mod rwa;
/// Smart contract descriptors and execution metadata.
pub mod smart_contract;
/// Sora Name Service registrar data structures.
pub mod sns;
/// Viral social incentive records and escrows.
pub mod social;
/// Soracloud manifests for deterministic service hosting.
pub mod soracloud;
/// SoraDNS attestation and directory data structures.
pub mod soradns;
/// SoraFS data structures (pin registry, manifests).
pub mod sorafs;
/// Strict `sorafs://...` URI literals.
pub mod sorafs_uri;
/// SoraNet transport and privacy data model extensions.
pub mod soranet;
/// World state snapshot representations.
pub mod state;
/// Subscription metadata schemas for trigger-based billing.
pub mod subscription;
/// Sumeragi status served by the node (projection of the consensus core's diagnostics).
pub mod sumeragi;
/// Atomic cross-dataspace transactions (AMX): records, proofs, the foreign-committee tracker
/// and the global chain's two-phase-commit state.
pub mod sumeragi_amx;
/// Portable finality proofs for the current embedded consensus certificate.
pub mod sumeragi_finality;
/// Lanes of the global chain: lifecycle records and merge references.
pub mod sumeragi_lanes;
/// Taikai broadcast metadata and segment envelope types.
pub mod taikai;
/// Test fixtures exposed for SDK/guardrail consumers.
#[cfg(any(test, feature = "test-fixtures"))]
pub mod testing;
/// Transaction structures, payloads, and signatures.
pub mod transaction;
/// Extended transaction responses for Torii/SDK integrations.
pub mod transactions;
/// Trigger definitions and scheduling utilities.
pub mod trigger;
/// Parliament-governed validation-fee policy and transaction metadata bindings.
pub mod validation_fee;
/// Protected conversion accounting and validator rewards.
pub mod validation_fee_rewards;
/// Permission tokens and helpers related to validators.
pub mod validator;
/// Verification helper traits and host bindings.
pub mod verification;
/// Compiled wire-schema identity: canonical root hashing and the block wire root.
pub mod wire_schema;
/// Zero-knowledge proof payload types.
pub mod zk;
/// Committed ZK validity policy: the typed chain parameter, its protocol default and validation.
pub mod zk_validity_policy;
/// Helpers for constructing and accessing instruction registries used by the IVM.
pub mod instruction_registry {
    pub use crate::isi::{InstructionRegistry, registry::default};
}
/// Reserved identifiers used for fast keyword lookups during schema generation.
pub const PRECOMPUTED_KEYWORDS: &[&str] = &["account", "domain", "asset", "trigger"];
/// Whether the internal mutable model API is enabled.
pub const TRANSPARENT_API: bool = cfg!(feature = "transparent_api");
pub use crate::account::{Account, AccountId, NewAccount};
pub use crate::block::SignedBlock;
pub use crate::domain::{Domain, NewDomain};
pub use crate::events::{EventBox, EventFilterBox, TriggeringEventType};
pub use crate::executor::{Executor, ExecutorDataModel};
pub use crate::ipfs::IpfsPath;
pub use crate::nft::{NewNft, Nft, NftId};
pub use crate::peer::Peer;
pub use crate::permission::Permission;
pub use crate::query::{
    AnyQueryBox, CommittedTransaction, QueryBox, QueryOutput, QueryOutputBatchBox,
    QueryOutputBatchBoxTuple, QueryRequest, QueryRequestWithAuthority, QueryResponse,
    QuerySignature, QueryWithFilter, QueryWithParams, SignedQuery, SingularQueryBox,
    SingularQueryOutputBox,
};
pub use crate::role::{NewRole, Role, RoleId};
pub use crate::rwa::{NewRwa, Rwa, RwaControlPolicy, RwaId, RwaParentRef};
// Slice-based Norito decoders for model types used in packed sequences and
// options. These forward to the archived Norito representation to avoid
// duplicating decoding logic.
#[cfg(test)]
mod base_wire_fixtures;
#[cfg(test)]
#[path = "../tests/support/fixture_json.rs"]
mod fixture_json;
mod norito_slice_decode;
/// Private module defining sealing traits for `iroha_data_model`.
mod seal {
    /// Seals the [`Instruction`](crate::isi::Instruction) trait.
    pub trait Instruction {}
    /// Seals the [`SingularQuery`](crate::query::SingularQuery) trait.
    pub trait SingularQuery {}
    /// Seals the [`crate::query::Query`](crate::query::Query) trait.
    pub trait Query {}
}
pub use error::EnumTryAsError;
pub use errors::{
    AmxStage, CanonicalError, CanonicalErrorKind, CircuitBreakerKind, SettlementRouterOutage,
};
pub use executor::ValidationFail;
pub use id::{IdBox, NetworkId};
pub use level::Level;
/// Uniquely identifiable entity ([`domain::Domain`], [`account::Account`], etc.).
/// This trait should always be derived with `IdEqOrdHash`.
pub trait Identifiable: Ord + Eq {
    /// Type of the entity identifier
    type Id: Into<IdBox> + Ord + Eq + core::hash::Hash;
    /// Get reference to the type identifier
    fn id(&self) -> &Self::Id;
}
/// Trait for proxy objects used for registration.
pub trait Registrable {
    /// Constructed type
    type Target;
    /// Construct [`Self::Target`] with given authority
    fn build(self, authority: &crate::account::AccountId) -> Self::Target;
}
/// Trait that marks the entity as having metadata.
pub trait HasMetadata {
    // Uncomment when stable.
    /// The metadata associated to this object.
    fn metadata(&self) -> &iroha_model_base::metadata::Metadata;
}
/// Trait for objects that are registered by proxy.
pub trait Registered: Identifiable {
    /// The proxy type that is used to register this entity. Usually `Self`, but if you have a
    /// complex structure where most fields would be empty, to save space you create a builder for
    /// it, and set `With` to the builder's type.
    type With;
}
/// Auxiliary trait for objects which are stored in parts in `World`.
/// E.g. `Account` is stored as `AccountId`+`AccountEntry` in `World::accounts`
pub trait IntoKeyValue {
    /// Object ID
    type Key;
    /// Object data
    type Value;
    /// Method to split object into parts
    fn into_key_value(self) -> (Self::Key, Self::Value);
}
#[allow(ambiguous_glob_reexports)]
pub mod prelude {
    //! Prelude: re-export of most commonly used traits, structs and macros in this crate.
    pub use super::{
        Decode, Encode, HasMetadata, IdBox, Identifiable, Level, NetworkId, Registrable,
        ValidationFail,
        account::prelude::*,
        alias_setup::*,
        asset::prelude::*,
        block::prelude::*,
        bridge::*,
        confidential::prelude::*,
        content::prelude::*,
        domain::prelude::*,
        error::EnumTryAsError,
        escrow::prelude::*,
        events::prelude::*,
        executor::prelude::*,
        fastpq::*,
        identifier::prelude::*,
        ipfs::IpfsPath,
        isi::prelude::*,
        kaigi::prelude::*,
        nexus::{
            DataSpaceCatalog, DataSpaceCatalogError, DataSpaceMetadata, DomainCommittee,
            DomainEndorsement, DomainEndorsementPolicy, DomainEndorsementScope,
            DomainEndorsementSignature, FeeDebitSource, FeeRejectionCode, FeeSponsorAssetBudget,
            FeeSponsorBudgetCounter, FeeSponsorBudgetCounterKey, FeeSponsorBudgetWindow,
            FeeSponsorEligibility, FeeSponsorEnrollment, FeeSponsorEnrollmentKey,
            FeeSponsorProgram, FeeSponsorProgramActivation, FeeSponsorProgramId,
            FeeSponsorProgramLifecycle, FeeSponsorProgramRevision, FeeSponsorProgramRevisionKey,
            FeeSponsorRule, FeeSponsorRuleEffect, FeeSponsorRuleSelector, FeeSponsorVault,
            FeeSponsorVaultKey, LaneCatalog, LaneCatalogError, LaneConfig, LaneStorageProfile,
            LaneStorageProfileParseError, LaneVisibility, LaneVisibilityParseError,
            VerifiedFeeSponsorVaultAllocation,
        },
        nft::prelude::*,
        parameter::prelude::*,
        peer::prelude::*,
        permission::prelude::*,
        query::prelude::*,
        ram_lfe::prelude::*,
        repo::prelude::*,
        role::prelude::*,
        rwa::prelude::*,
        smart_contract::prelude::*,
        sns::prelude::*,
        social::prelude::*,
        sorafs_uri::SorafsUri,
        subscription::prelude::*,
        transaction::prelude::*,
        trigger::prelude::*,
    };
    pub use iroha_crypto::{
        Algorithm, ExposedPrivateKey, Hash, HashOf, KeyPair, MerkleTree, PrivateKey, PublicKey,
        Signature, SignatureOf,
    };
    pub use iroha_primitives::{
        json::Json,
        numeric::{Numeric, NumericOperationError, NumericSpec, Quantity, numeric},
        numeric_abi::{
            DECIMAL_SCHEMA_HASH_V1, DECIMAL_SCHEMA_NAME_V1, DecimalValueV1, INT_SCHEMA_HASH_V1,
            INT_SCHEMA_NAME_V1, IntValueV1, MAX_DECIMAL_ENVELOPE_BYTES_V1,
            MAX_DECIMAL_FRAME_BYTES_V1, MAX_INT_ENVELOPE_BYTES_V1, MAX_INT_FRAME_BYTES_V1,
            MAX_QUANTITY_ENVELOPE_BYTES_V1, MAX_QUANTITY_FRAME_BYTES_V1,
            NUMERIC_FRAME_HEADER_BYTES_V1, NUMERIC_POINTER_ENVELOPE_OVERHEAD_V1, NumericAbiError,
            QUANTITY_SCHEMA_HASH_V1, QUANTITY_SCHEMA_NAME_V1, QuantityValueV1,
        },
    };
}

#[cfg(test)]
mod captured_schema_tests;

#[cfg(test)]
mod frame_owner_identity_tests;

#[cfg(test)]
mod generic_identity_tests;

#[cfg(test)]
mod concrete_identity_tests;

#[cfg(test)]
mod manual_schema_identity;

#[cfg(test)]
mod registration_identity_tests;

#[cfg(test)]
mod checked_snapshot_leaf_cleanup_tests;

#[cfg(test)]
mod checked_container_refusal_controls;
