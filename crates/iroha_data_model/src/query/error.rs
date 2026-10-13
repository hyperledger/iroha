//! Error types produced by query execution.
//!
//! Module containing errors that can occur during query execution.
pub use self::model::*;
use super::*;
use crate::prelude::*;
use iroha_model_base::name::Name;

use iroha_crypto::HashOf;
use iroha_data_model_derive::model;
use iroha_macro::FromVariant;
use iroha_schema::{EnumMeta, EnumVariant, Ident, IntoSchema, MetaMap, Metadata, TypeId};
use norito::codec::{Decode, Encode};
#[model]
mod model {
    use super::*;
    /// Query errors.
    #[derive(
        Debug,
        displaydoc::Display,
        Clone,
        PartialEq,
        Eq,
        PartialOrd,
        Ord,
        FromVariant,
        Decode,
        Encode,
        IntoSchema,
        crate :: DeriveJsonSerialize,
        crate :: DeriveJsonDeserialize,
    )]
    /// High-level failure reasons for query execution.
    #[norito(tag = "kind", content = "content")]
    #[derive(thiserror::Error, norito::NoritoSchema)]
    #[norito_schema(name = "iroha_data_model::query::error::model::QueryExecutionFail")]
    pub enum QueryExecutionFail {
        /// {0}
        #[error(transparent)]
        Find(FindError),
        /// {0}
        #[error(transparent)]
        CanonicalHistory(CanonicalHistoryError),
        /// Query rejected: {0}
        Conversion(
            #[skip_from]
            #[skip_try_from]
            String,
        ),
        /// Query not found in the live query store.
        NotFound,
        /// The server's cursor does not match the provided cursor.
        CursorMismatch,
        /// There aren't enough items for the cursor to proceed.
        CursorDone,
        /// `fetch_size` must not exceed [`MAX_FETCH_SIZE`](crate::query::parameters::MAX_FETCH_SIZE).
        FetchSizeTooBig,
        /// Query execution exceeded the configured gas/materialization budget.
        GasBudgetExceeded,
        /// Some of the specified parameters (`filter/pagination/fetch_size/sorting`) are not applicable to singular queries
        InvalidSingularParameters,
        /// Reached the limit of parallel queries. Either wait for previous queries to complete, or increase the limit in the config.
        CapacityLimit,
        /// The stored cursor has expired and was removed from the server.
        Expired,
        /// The authority reached the per-tenant limit of stored cursors.
        AuthorityQuotaExceeded,
    }
    /// A canonical block-history body is unavailable or contradicts the
    /// committed world-state hash journal.
    #[derive(
        Debug,
        displaydoc::Display,
        Clone,
        Copy,
        PartialEq,
        Eq,
        PartialOrd,
        Ord,
        Decode,
        Encode,
        crate :: DeriveJsonSerialize,
        crate :: DeriveJsonDeserialize,
    )]
    #[norito(tag = "kind", content = "content")]
    #[derive(thiserror::Error)]
    pub enum CanonicalHistoryError {
        /// Canonical history height {height} is outside the committed snapshot ending at `{committed_height}`
        HeightOutsideSnapshot {
            /// Requested one-based height.
            height: u64,
            /// Last height committed by the immutable query snapshot.
            committed_height: u64,
        },
        /// Canonical history body at height {height} is unavailable; expected hash `{expected_hash}`
        BodyUnavailable {
            /// One-based committed height.
            height: u64,
            /// Header hash committed by the WSV.
            expected_hash: HashOf<BlockHeader>,
        },
        /// Canonical history body at height {height} has hash `{actual_hash}`, expected `{expected_hash}`
        BlockHashMismatch {
            /// One-based committed height.
            height: u64,
            /// Header hash committed by the WSV.
            expected_hash: HashOf<BlockHeader>,
            /// Header hash decoded from the Kura body.
            actual_hash: HashOf<BlockHeader>,
        },
        /// Canonical history slot {height} contains header height `{actual_height}`
        BlockHeightMismatch {
            /// One-based committed slot.
            height: u64,
            /// Height declared by the Kura block header.
            actual_height: u64,
        },
    }
    /// Stable identity carried by a missing chain-authoritative `SoraFS` proof outcome.
    #[derive(
        Debug,
        Clone,
        Copy,
        PartialEq,
        Eq,
        PartialOrd,
        Ord,
        Decode,
        Encode,
        IntoSchema,
        crate :: DeriveJsonSerialize,
        crate :: DeriveJsonDeserialize,
    )]
    #[norito(deny_unknown_fields)]
    pub struct SorafsProofOutcomeFindErrorV1 {
        /// Proof protocol namespace.
        pub kind: crate::sorafs::proof_ledger::ProofOutcomeKindV1,
        /// Protocol-scoped challenge or request identity.
        #[norito(json = "crate::json_helpers::fixed_bytes")]
        pub identity_digest: [u8; 32],
    }
    /// Type assertion error
    #[derive(
        Debug,
        displaydoc::Display,
        Clone,
        PartialEq,
        Eq,
        PartialOrd,
        Ord,
        Decode,
        Encode,
        IntoSchema,
        crate :: DeriveJsonSerialize,
        crate :: DeriveJsonDeserialize,
    )]
    #[norito(tag = "kind", content = "content")]
    #[derive(thiserror::Error)]
    /// Item-level errors returned when resolving query inputs.
    pub enum FindError {
        /// Failed to find asset: `{0}`
        Asset(Box<AssetId>),
        /// Failed to find asset definition: `{0}`
        AssetDefinition(AssetDefinitionId),
        /// Failed to find NFT: `{0}`
        Nft(NftId),
        /// Failed to find RWA: `{0}`
        Rwa(RwaId),
        /// Failed to find account: `{0}`
        Account(AccountId),
        /// Failed to find domain: `{0}`
        Domain(DomainId),
        /// Failed to find metadata key: `{0}`
        MetadataKey(Name),
        /// Block with hash `{0}` not found
        Block(HashOf<BlockHeader>),
        /// Transaction with hash `{0}` not found
        Transaction(HashOf<SignedTransaction>),
        /// Peer with id `{0}` not found
        Peer(PeerId),
        /// Trigger with id `{0}` not found
        Trigger(TriggerId),
        /// Role with id `{0}` not found
        Role(RoleId),
        /// Failed to find [`Permission`] by id.
        Permission(Box<Permission>),
        /// Failed to find public key: `{0}`
        PublicKey(PublicKey),
        /// Failed to find twitter binding for keyed hash `{0:?}`
        TwitterBinding(crate::oracle::KeyedHash),
        /// Failed to find oracle feed `{0}`
        OracleFeed(crate::oracle::FeedId),
        /// Failed to find oracle dispute `{0:?}`
        OracleDispute(crate::oracle::OracleDisputeId),
        /// Failed to find oracle change `{0:?}`
        OracleChange(crate::oracle::OracleChangeId),
        /// Failed to find oracle provider stats `{0:?}`
        OracleProviderStats(crate::oracle::OracleProviderKey),
        /// Failed to find `DeFi` oracle attestation `{0:?}`
        DefiOracleAttestation(crate::oracle::DefiOracleAttestationKey),
        /// Failed to find native asset escrow: `{0:?}`
        AssetEscrow(crate::escrow::EscrowId),
        /// Failed to find chain-authoritative `SoraFS` pin manifest: `{0:?}`
        SorafsPinManifest(crate::sorafs::pin_registry::ManifestDigest),
        /// Failed to find the active authoritative `SoraFS` orderbook policy
        SorafsOrderbookPolicy,
        /// Failed to find authoritative `SoraFS` orderbook order: `{0:?}`
        SorafsOrderbookOrder([u8; 32]),
        /// Failed to find authoritative `SoraFS` orderbook cancellation: `{0:?}`
        SorafsOrderbookCancellation([u8; 32]),
        /// Failed to find authoritative `SoraFS` orderbook receipt: `{0:?}`
        SorafsOrderbookReceipt([u8; 32]),
        /// Failed to find authoritative `SoraFS` orderbook trade: `{0:?}`
        SorafsOrderbookTrade([u8; 32]),
        /// Failed to find authoritative `SoraFS` orderbook channel: `{0:?}`
        SorafsOrderbookChannel([u8; 32]),
        /// Failed to find authoritative `SoraFS` orderbook status
        SorafsOrderbookStatus,
        /// Failed to find the active authoritative `SoraFS` reserve policy
        SorafsReservePolicy,
        /// Failed to find authoritative `SoraFS` provider reserve account: `{0:?}`
        SorafsReserveProvider(crate::sorafs::capacity::ProviderId),
        /// Failed to find authoritative `SoraFS` reserve movement: `{0:?}`
        SorafsReserveMovement([u8; 32]),
        /// Failed to find authoritative `SoraFS` reserve appeal: `{0:?}`
        SorafsReserveAppeal([u8; 32]),
        /// Failed to find the active authoritative `SoraFS` `PoP` issuer policy
        SorafsPopIssuerPolicy,
        /// Failed to find authoritative `SoraFS` `PoP` credential commitment: `{0:?}`
        SorafsPopCredentialCommitment([u8; 32]),
        /// Failed to find authoritative `SoraFS` `PoP` commitment root version `{0}`
        SorafsPopCommitmentRoot(u64),
        /// Failed to find authoritative `SoraFS` `PoP` revocation publication version `{0}`
        SorafsPopRevocationPublication(u64),
        /// Failed to find authoritative `SoraFS` `PoP` revocation commitment: `{0:?}`
        SorafsPopRevocation([u8; 32]),
        /// Failed to find authoritative `SoraFS` `PoP` registry audit sequence `{0}`
        SorafsPopAuditDigest(u64),
        /// Failed to find authoritative `SoraFS` `PoP` registry status
        SorafsPopRegistryStatus,
        /// Failed to find a `SoraFS` citizen bond by immutable serial commitment.
        SorafsCitizenBond([u8; 32]),
        /// Failed to find the current frozen citizen-bond snapshot.
        SorafsCitizenBondSnapshot,
        /// Failed to find chain-authoritative `SoraFS` repair task `{0}`
        SorafsRepairTask(String),
        /// Failed to find chain-authoritative `SoraFS` repair status
        SorafsRepairStatus,
        /// Failed to find chain-authoritative `SoraFS` proof outcome `{0:?}`
        SorafsProofOutcome(SorafsProofOutcomeFindErrorV1),
        /// Failed to find the active authoritative `SoraFS` reputation-journal authority policy
        SorafsReputationJournalAuthorityPolicy,
        /// Failed to find a finalized `SoraFS` reputation-journal event for source `{0:?}`
        SorafsReputationJournalEvent(crate::sorafs::reputation::ReputationJournalSourceIdV1),
        /// Failed to find the active authoritative `SoraFS` moderation policy
        SorafsModerationPolicy,
        /// Failed to find authoritative `SoraFS` moderation appeal `{0}`
        SorafsModerationAppeal(String),
        /// Failed to find authoritative `SoraFS` moderation juror eligibility `{0}`
        SorafsModerationJurorEligibility(String),
        /// Failed to find authoritative `SoraFS` moderation case `{0}`
        SorafsModerationCase(String),
        /// Failed to find authoritative `SoraFS` moderation commit `{0}`
        SorafsModerationCommit(String),
        /// Failed to find authoritative `SoraFS` moderation reveal `{0}`
        SorafsModerationReveal(String),
        /// Failed to find authoritative `SoraFS` moderation challenge `{0}`
        SorafsModerationChallenge(String),
        /// Failed to find authoritative `SoraFS` moderation outcome `{0}`
        SorafsModerationOutcome(String),
        /// Failed to find authoritative `SoraFS` moderation no-show `{0}`
        SorafsModerationNoShow(String),
        /// Failed to find authoritative `SoraFS` moderation status
        SorafsModerationStatus,
        /// Native game session `{0}` not found
        GameSession(iroha_crypto::Hash),
        /// Native execution proof verification `{0}` not found
        ExecutionProofVerification(iroha_crypto::Hash),
        /// Native settlement receipt `{0}` not found
        SettlementReceipt(crate::isi::SettlementId),
    }
}

/// Schema projection for a canonical-history height bounded by a committed
/// snapshot height.
#[derive(IntoSchema)]
#[allow(dead_code)]
struct CanonicalHistorySnapshotHeightSchema {
    /// Requested one-based height.
    height: u64,
    /// Last height committed by the immutable query snapshot.
    committed_height: u64,
}

/// Shared schema projection for a canonical-history height and its committed
/// header hash.
#[derive(IntoSchema)]
#[allow(dead_code)]
struct CanonicalHistoryHeightHashSchema {
    /// One-based committed height.
    height: u64,
    /// Header hash authenticated by the snapshot lineage and WSV.
    expected_hash: HashOf<BlockHeader>,
}

/// Schema projection for a canonical-history body whose decoded header hash
/// contradicts the committed hash.
#[derive(IntoSchema)]
#[allow(dead_code)]
struct CanonicalHistoryHashMismatchSchema {
    /// One-based committed height.
    height: u64,
    /// Header hash committed by the WSV.
    expected_hash: HashOf<BlockHeader>,
    /// Header hash decoded from the Kura body.
    actual_hash: HashOf<BlockHeader>,
}

/// Schema projection for a canonical-history slot whose decoded header height
/// does not match the slot.
#[derive(IntoSchema)]
#[allow(dead_code)]
struct CanonicalHistoryHeightMismatchSchema {
    /// One-based committed slot.
    height: u64,
    /// Height declared by the Kura block header.
    actual_height: u64,
}

impl TypeId for CanonicalHistoryError {
    fn id() -> Ident {
        "CanonicalHistoryError".to_owned()
    }
}

impl IntoSchema for CanonicalHistoryError {
    fn type_name() -> Ident {
        "CanonicalHistoryError".to_owned()
    }

    fn update_schema_map(metamap: &mut MetaMap) {
        if metamap.contains_key::<Self>() {
            return;
        }
        CanonicalHistorySnapshotHeightSchema::update_schema_map(metamap);
        CanonicalHistoryHeightHashSchema::update_schema_map(metamap);
        CanonicalHistoryHashMismatchSchema::update_schema_map(metamap);
        CanonicalHistoryHeightMismatchSchema::update_schema_map(metamap);
        metamap.insert::<Self>(Metadata::Enum(EnumMeta {
            variants: vec![
                EnumVariant {
                    tag: "HeightOutsideSnapshot".to_owned(),
                    discriminant: 0,
                    ty: Some(core::any::TypeId::of::<CanonicalHistorySnapshotHeightSchema>()),
                },
                EnumVariant {
                    tag: "BodyUnavailable".to_owned(),
                    discriminant: 1,
                    ty: Some(core::any::TypeId::of::<CanonicalHistoryHeightHashSchema>()),
                },
                EnumVariant {
                    tag: "BlockHashMismatch".to_owned(),
                    discriminant: 2,
                    ty: Some(core::any::TypeId::of::<CanonicalHistoryHashMismatchSchema>()),
                },
                EnumVariant {
                    tag: "BlockHeightMismatch".to_owned(),
                    discriminant: 3,
                    ty: Some(core::any::TypeId::of::<CanonicalHistoryHeightMismatchSchema>()),
                },
            ],
        }));
    }
}

impl CanonicalHistoryError {
    /// Return whether the committed hash is valid but its corresponding body
    /// cannot be served from this snapshot.
    #[must_use]
    pub const fn is_unavailable(self) -> bool {
        matches!(
            self,
            Self::HeightOutsideSnapshot { .. } | Self::BodyUnavailable { .. }
        )
    }
}

#[cfg(test)]
mod tests {
    use core::any::TypeId as RustTypeId;

    use iroha_schema::{IntoSchema as _, Metadata};

    use super::*;

    #[test]
    fn canonical_history_error_schema_preserves_variant_payloads() {
        let schema = CanonicalHistoryError::schema();
        let Metadata::Enum(metadata) = schema
            .get::<CanonicalHistoryError>()
            .expect("canonical-history error schema")
        else {
            panic!("canonical-history error schema must be an enum");
        };

        let expected = [
            (
                "HeightOutsideSnapshot",
                0,
                RustTypeId::of::<CanonicalHistorySnapshotHeightSchema>(),
            ),
            (
                "BodyUnavailable",
                1,
                RustTypeId::of::<CanonicalHistoryHeightHashSchema>(),
            ),
            (
                "BlockHashMismatch",
                2,
                RustTypeId::of::<CanonicalHistoryHashMismatchSchema>(),
            ),
            (
                "BlockHeightMismatch",
                3,
                RustTypeId::of::<CanonicalHistoryHeightMismatchSchema>(),
            ),
        ];
        assert_eq!(metadata.variants.len(), expected.len());
        for (variant, (tag, discriminant, ty)) in metadata.variants.iter().zip(expected) {
            assert_eq!(variant.tag, tag);
            assert_eq!(variant.discriminant, discriminant);
            assert_eq!(variant.ty, Some(ty));
        }
        assert!(schema.contains_key::<CanonicalHistorySnapshotHeightSchema>());
        assert!(schema.contains_key::<CanonicalHistoryHeightHashSchema>());
        assert!(schema.contains_key::<CanonicalHistoryHashMismatchSchema>());
        assert!(schema.contains_key::<CanonicalHistoryHeightMismatchSchema>());
    }

    #[test]
    fn canonical_history_query_failure_roundtrips_norito_and_json() {
        let failure =
            QueryExecutionFail::CanonicalHistory(CanonicalHistoryError::BlockHashMismatch {
                height: 7,
                expected_hash: HashOf::from_untyped_unchecked(iroha_crypto::Hash::prehashed(
                    [0x17; 32],
                )),
                actual_hash: HashOf::from_untyped_unchecked(iroha_crypto::Hash::prehashed(
                    [0x27; 32],
                )),
            });
        let bytes = norito::to_bytes(&failure).expect("encode canonical-history query failure");
        let decoded: QueryExecutionFail =
            norito::decode_from_bytes(&bytes).expect("decode canonical-history query failure");
        assert_eq!(decoded, failure);

        {
            let json = norito::json::to_json(&failure)
                .expect("encode canonical-history query failure JSON");
            let decoded: QueryExecutionFail =
                norito::json::from_str(&json).expect("decode canonical-history query failure JSON");
            assert_eq!(decoded, failure);
        }
    }

    #[test]
    fn settlement_receipt_absence_preserves_exact_owner_and_reference() {
        let account = crate::account::AccountId::new(
            iroha_crypto::KeyPair::from_seed(vec![0x72; 32], iroha_crypto::Algorithm::Ed25519)
                .public_key()
                .clone(),
        );
        let id = crate::isi::SettlementId::new(account, "missing-receipt".parse().unwrap());
        let failure = QueryExecutionFail::Find(FindError::SettlementReceipt(id));
        let frame = norito::encode_canonical(&failure).unwrap();
        assert_eq!(
            norito::decode_canonical::<QueryExecutionFail>(&frame).unwrap(),
            failure
        );
        let json = norito::json::to_json(&failure).unwrap();
        assert_eq!(
            norito::json::from_str::<QueryExecutionFail>(&json).unwrap(),
            failure
        );
    }
}

#[cfg(test)]
mod additional_frame_owner_identity_tests {
    //! Typed frame contracts observed with the original codec.

    #[test]
    fn captured_additional_frame_owner_identities() {
        crate::frame_owner_identity_tests::assert_bidirectional::<
            crate::query::error::model::QueryExecutionFail,
        >("iroha_data_model::query::error::model::QueryExecutionFail");
    }
}
