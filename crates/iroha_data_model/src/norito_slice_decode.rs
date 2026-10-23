//! Canonical slice decoders for data-model fields in packed sequences and options.
//!
//! The shared decoder reconstructs a bounded payload, verifies its canonical
//! representation and reports consumed bytes. Fields need no frame identity.
use norito::core::{DecodeFromSlice, Error, decode_field_canonical};
fn decode_via_canonical<T>(bytes: &[u8]) -> Result<(T, usize), Error>
where
    T: for<'de> norito::DeserializePayload<'de> + norito::SerializePayload,
{
    decode_field_canonical::<T>(bytes)
}

// Helper macro to implement `DecodeFromSlice` for many local types.
macro_rules! impl_canonical_slice_decode {
    ($($ty:path),+ $(,)?) => {
        $(
            impl<'a> DecodeFromSlice<'a> for $ty {
                fn decode_from_slice(bytes: &'a [u8]) -> Result<(Self, usize), Error> {
                    decode_via_canonical(bytes)
                }
            }
        )+
    };
}
// Core ID and value types
impl_canonical_slice_decode! {
    crate::ipfs::IpfsPath,
    crate::sorafs_uri::SorafsUri,
    crate::asset::id::AssetId,
    crate::asset::id::AssetDefinitionId,
    crate::asset::alias::AssetDefinitionAlias,
    crate::nft::NftId,
    crate::rwa::RwaId,
    crate::trigger::TriggerId,
    crate::role::RoleId,
    crate::parameter::CustomParameterId,
    crate::sorafs::capacity::ProviderId,
}
// State and canonical keys derive DecodeFromSlice on their own types.
// Transaction-related
// Transaction-related (derive already supplies DecodeFromSlice for these)
// Block-related
impl_canonical_slice_decode! {
    crate::block::header::BlockHeader,
    crate::block::header::BlockSignature,
    crate::block::payload::BlockResult,
    crate::smart_contract::manifest::ContractManifest,
    crate::smart_contract::manifest::AccessSetHints,
}
// Proof-related
impl_canonical_slice_decode! {
    crate::proof::ProofId,
    crate::proof::ProofRecord,
    crate::nexus::LanePrivacyProof,
    crate::nexus::LanePrivacyWitness,
    crate::nexus::LanePrivacyMerkleWitness,
    // Also cover event payloads that may appear in option/sequence contexts
    crate::events::data::proof::ProofVerified,
    crate::events::data::proof::ProofRejected,
    crate::runtime::RuntimeUpgradeId,
}
// Kaigi components referenced by query/data-model responses
impl_canonical_slice_decode! {
    crate::kaigi::KaigiParticipantCommitment,
    crate::kaigi::KaigiParticipantNullifier,
    crate::kaigi::KaigiRelayHop,
    crate::kaigi::KaigiRelayManifest,
    crate::kaigi::KaigiRelayRegistration,
}
// Query parameter and DSL types; keep only those not covered by derives
impl_canonical_slice_decode! {
    crate::query::parameters::ForwardCursor,
    crate::query::parameters::Pagination,
    crate::query::parameters::Sorting,
    crate::query::parameters::SortOrder,
    crate::query::parameters::FetchSize,
    crate::parameter::Parameters,
    crate::query::proof::FindProofRecordById,
    crate::query::AnyQueryBox,
    crate::query::QueryResponse,
}
// Events and statuses
impl_canonical_slice_decode! {
    crate::events::pipeline::BlockStatus,
    crate::events::pipeline::TransactionStatus,
    crate::events::trigger_completed::TriggerCompletedOutcomeType,
}
// Transaction-related decoders required by versioned types and proofs
impl_canonical_slice_decode! {
    crate::transaction::error::TransactionRejectionReason,
    crate::ValidationFail,
}
// Additional model and crypto types referenced by query responses and versioned wrappers
impl_canonical_slice_decode! {
    // Core model objects (use public re-exports)
    crate::domain::Domain,
    crate::account::Account,
    crate::asset::definition::AssetDefinition,
    crate::asset::definition::AssetConfidentialPolicy,
    crate::asset::definition::ConfidentialPolicyTransition,
    crate::asset::definition::ConfidentialPolicyMode,
    crate::confidential::ConfidentialFeatureDigest,
    crate::asset::value::Asset,
    crate::nft::Nft,
    crate::rwa::Rwa,
    crate::permission::Permission,
    crate::parameter::system::Parameter,
    // Triggers and actions
    crate::trigger::model::Trigger,
    crate::trigger::action::Action,
    crate::trigger::data::DataTriggerStep,
    // Transactions, blocks and query outputs
    crate::transaction::signed::TransactionResult,
    crate::query::CommittedTransaction,
    crate::query::QueryOutputBatchBox,
    // Taikai metadata and envelopes
    crate::taikai::TaikaiEventId,
    crate::taikai::TaikaiStreamId,
    crate::taikai::TaikaiRenditionId,
    crate::taikai::TaikaiTrackKind,
    crate::taikai::TaikaiAudioLayout,
    crate::taikai::TaikaiCodec,
    crate::taikai::TaikaiResolution,
    crate::taikai::TaikaiTrackMetadata,
    crate::taikai::TaikaiCarPointer,
    crate::taikai::TaikaiIngestPointer,
    crate::taikai::TaikaiInstrumentation,
    crate::taikai::TaikaiSegmentEnvelopeV1,
    crate::taikai::TaikaiTimeIndexKey,
    crate::taikai::TaikaiCidIndexKey,
    crate::taikai::TaikaiEnvelopeIndexes,
    // SoraDNS resolver attestation data
    crate::soradns::GatewayHostSet,
    crate::soradns::HttpTransportV1,
    crate::soradns::TlsTransportV1,
    crate::soradns::QuicTransportV1,
    crate::soradns::OdohRelayV1,
    crate::soradns::SoranetBridgeConfigV1,
    crate::soradns::PaddingPolicyV1,
    crate::soradns::TlsProvisioningProfile,
    crate::soradns::ResolverTransportBundle,
    crate::soradns::ResolverTlsBundle,
    crate::soradns::RotationPolicyV1,
    crate::soradns::DirectoryDraftSubmittedEventV1,
    crate::soradns::DirectoryPolicyUpdatedEventV1,
    crate::soradns::DirectoryPublishedEventV1,
    crate::soradns::DirectoryReleaseSignerEventV1,
    crate::soradns::DirectoryRevokedEventV1,
    crate::soradns::DirectoryRotationPolicyV1,
    crate::soradns::DirectoryUnrevokedEventV1,
    crate::soradns::PendingDirectoryDraftV1,
    crate::soradns::ResolverAttestationDocumentV1,
    crate::soradns::ResolverDirectoryEventV1,
    crate::soradns::ResolverDirectoryRecordV1,
    crate::soradns::ResolverRevocationRecordV1,
    crate::soradns::RadRevokeReason,
}
// Canonical governance types share the same decoder in every build.

impl_canonical_slice_decode! {
    crate::governance::types::ProposalId,
    crate::governance::types::AtWindow,
}
// ISI Governance enums used in instruction params

impl_canonical_slice_decode! {
    crate::isi::governance::VotingMode,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[derive(Debug, PartialEq, norito::SerializePayload, norito::DeserializePayload)]
    struct PayloadOnlyField(Vec<u16>);

    impl_canonical_slice_decode! { PayloadOnlyField }

    #[test]
    fn slice_decoder_checks_payload_only_fields_in_every_advertised_layout() {
        let value = PayloadOnlyField(vec![7, 11, 13]);
        for flags in (0..=norito::core::supported_header_flags())
            .filter(|flags| norito::core::validate_header_flags(*flags).is_ok())
        {
            let _requested = norito::core::DecodeFlagsGuard::enter(flags);
            let (payload, actual) = norito::codec::encode_with_header_flags(&value);
            let _actual = norito::core::DecodeFlagsGuard::enter(actual);
            let (decoded, used) = PayloadOnlyField::decode_from_slice(&payload).unwrap();
            assert_eq!(decoded, value);
            assert_eq!(used, payload.len());
            for len in 0..payload.len() {
                assert!(PayloadOnlyField::decode_from_slice(&payload[..len]).is_err());
            }
            let mut trailing = payload;
            trailing.push(0);
            assert!(PayloadOnlyField::decode_from_slice(&trailing).is_err());
        }
    }
}
