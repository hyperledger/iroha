//! ZK-related instructions.
//!
//! This module defines instructions for submitting proofs for verification
//! against on-chain verifying keys.
use super::*;
use crate::asset::definition::ConfidentialPolicyMode;
use iroha_crypto::Hash;
isi! {
    /// Verify a zero-knowledge proof against a verifying key.
    ///
    /// This instruction records verification result in WSV. Backends and
    /// cryptographic verification are provided by `iroha_core` under feature
    /// flags; this data model type acts as a transport envelope.
    #[norito_schema(name = "iroha_data_model::isi::zk::VerifyProof")]
    pub struct VerifyProof {
        /// Proof attachment containing the proof and a VK registry reference.
        pub attachment: crate::proof::ProofAttachment,
    }
}
impl crate::seal::Instruction for VerifyProof {}
impl VerifyProof {
    /// Construct a new `VerifyProof` instruction from a proof attachment.
    pub fn new(attachment: crate::proof::ProofAttachment) -> Self {
        Self { attachment }
    }
}
isi! {
    /// Prune proof registry entries according to the on-chain retention policy.
    ///
    /// When `backend` is `None`, all backends are considered; otherwise only
    /// the matching backend is pruned. Retention limits (cap/grace/batch) come
    /// from the `zk` configuration, keeping pruning deterministic.
    #[derive (crate :: DeriveJsonSerialize , crate :: DeriveJsonDeserialize)]
    #[norito_schema(name = "iroha_data_model::isi::zk::PruneProofs")]
    pub struct PruneProofs {
        /// Optional backend label to restrict pruning scope (e.g., `halo2/ipa`).
        pub backend: Option<String>,
    }
}
impl crate::seal::Instruction for PruneProofs {}
impl PruneProofs {
    /// Construct a new prune request.
    pub fn new(backend: Option<String>) -> Self {
        Self { backend }
    }
}
// --- ZK Assets ---
isi! {
    /// Register a ZK-capable asset definition with policy and verifying keys.
    #[derive (crate :: DeriveJsonSerialize , crate :: DeriveJsonDeserialize)]
    #[norito_schema(name = "iroha_data_model::isi::zk::RegisterZkAsset")]
    #[norito(deny_unknown_fields)]
    pub struct RegisterZkAsset {
        /// Asset definition id.
        pub asset: AssetDefinitionId,
        /// Verifying key for confidential redemption proofs.
        pub vk_unshield: Option<crate::proof::VerifyingKeyId>,
    }
}
impl crate::seal::Instruction for RegisterZkAsset {}
impl RegisterZkAsset {
    /// Construct a new `RegisterZkAsset` instruction.
    pub fn new(
        asset: AssetDefinitionId,
        vk_unshield: Option<crate::proof::VerifyingKeyId>,
    ) -> Self {
        Self { asset, vk_unshield }
    }
}
isi! {
    /// Schedule a confidential policy transition for an asset definition.
    #[derive (crate :: DeriveJsonSerialize , crate :: DeriveJsonDeserialize)]
    #[norito_schema(name = "iroha_data_model::isi::zk::ScheduleConfidentialPolicyTransition")]
    pub struct ScheduleConfidentialPolicyTransition {
        /// Asset definition id.
        pub asset: AssetDefinitionId,
        /// Policy mode that becomes active at `effective_height`.
        pub new_mode: ConfidentialPolicyMode,
        /// Block height at which the transition must be applied.
        pub effective_height: u64,
        /// Deterministic identifier for the transition (governance audit/replay).
        pub transition_id: Hash,
        /// Optional conversion window length (in blocks) prior to finalizing the transition.
        pub conversion_window: Option<u64>,
    }
}
impl crate::seal::Instruction for ScheduleConfidentialPolicyTransition {}
impl ScheduleConfidentialPolicyTransition {
    /// Construct a new `ScheduleConfidentialPolicyTransition` instruction.
    pub fn new(
        asset: AssetDefinitionId,
        new_mode: ConfidentialPolicyMode,
        effective_height: u64,
        transition_id: Hash,
        conversion_window: Option<u64>,
    ) -> Self {
        Self {
            asset,
            new_mode,
            effective_height,
            transition_id,
            conversion_window,
        }
    }
}
isi! {
    /// Cancel a pending confidential policy transition for an asset definition.
    #[derive (crate :: DeriveJsonSerialize , crate :: DeriveJsonDeserialize)]
    #[norito_schema(name = "iroha_data_model::isi::zk::CancelConfidentialPolicyTransition")]
    pub struct CancelConfidentialPolicyTransition {
        /// Asset definition id.
        pub asset: AssetDefinitionId,
        /// Identifier of the transition to cancel.
        pub transition_id: Hash,
    }
}
impl crate::seal::Instruction for CancelConfidentialPolicyTransition {}
impl CancelConfidentialPolicyTransition {
    /// Construct a new `CancelConfidentialPolicyTransition` instruction.
    pub fn new(asset: AssetDefinitionId, transition_id: Hash) -> Self {
        Self {
            asset,
            transition_id,
        }
    }
}
// --- ZK Voting ---
/// Minimum number of options admitted by the first-release election ABI.
pub const MIN_ELECTION_OPTIONS_V1: u32 = 2;
/// Maximum number of options admitted by the first-release election ABI.
///
/// This matches the V1 bounded-list capacity used by Kotodama and the IVM ABI.
pub const MAX_ELECTION_OPTIONS_V1: u32 = 64;
/// A malformed first-release election shape.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum ElectionShapeV1Error {
    /// An election declared fewer than two options.
    #[error("election options {actual} are below the minimum of {minimum}")]
    TooFewOptions {
        /// Minimum admitted option count.
        minimum: usize,
        /// Declared option count.
        actual: usize,
    },
    /// An election exceeded the first-release option cap.
    #[error("election options {actual} exceed the V1 maximum of {maximum}")]
    TooManyOptions {
        /// Maximum admitted option count.
        maximum: usize,
        /// Declared option count.
        actual: usize,
    },
    /// The stored or submitted tally did not contain one counter per option.
    #[error("election tally length {actual} does not match option count {expected}")]
    TallyLengthMismatch {
        /// Declared option count after V1 validation.
        expected: usize,
        /// Number of counters in the tally.
        actual: usize,
    },
}
/// Validate a first-release election option count and return its allocation length.
///
/// # Errors
///
/// Returns [`ElectionShapeV1Error`] when the option count is outside
/// [`MIN_ELECTION_OPTIONS_V1`] through [`MAX_ELECTION_OPTIONS_V1`].
pub fn validate_election_options_v1(options: u32) -> Result<usize, ElectionShapeV1Error> {
    let options = options as usize;
    if options < MIN_ELECTION_OPTIONS_V1 as usize {
        return Err(ElectionShapeV1Error::TooFewOptions {
            minimum: MIN_ELECTION_OPTIONS_V1 as usize,
            actual: options,
        });
    }
    if options > MAX_ELECTION_OPTIONS_V1 as usize {
        return Err(ElectionShapeV1Error::TooManyOptions {
            maximum: MAX_ELECTION_OPTIONS_V1 as usize,
            actual: options,
        });
    }
    Ok(options)
}
/// Validate that a tally contains exactly one counter per valid V1 election option.
///
/// # Errors
///
/// Returns [`ElectionShapeV1Error`] when the option count is invalid or the
/// tally length differs from the validated option count.
pub fn validate_election_tally_v1(
    options: u32,
    tally_len: usize,
) -> Result<usize, ElectionShapeV1Error> {
    let expected = validate_election_options_v1(options)?;
    if tally_len != expected {
        return Err(ElectionShapeV1Error::TallyLengthMismatch {
            expected,
            actual: tally_len,
        });
    }
    Ok(expected)
}
isi! {
    /// Create an anonymous election.
    #[derive (crate :: DeriveJsonSerialize , crate :: DeriveJsonDeserialize)]
    #[norito_schema(name = "iroha_data_model::isi::zk::CreateElection")]
    pub struct CreateElection {
        /// Unique canonical V1 governance selector.
        ///
        /// Admission accepts 1-128 RFC 3986 unreserved ASCII bytes and rejects
        /// a leading dot; see [`crate::governance::is_valid_governance_selector_v1`].
        pub election_id: String,
        /// Number of options (K), from 2 through 64 in V1.
        pub options: u32,
        /// Merkle root of eligible voters.
        #[norito (json = "crate::json_helpers::fixed_bytes")]
        pub eligible_root: [u8; 32],
        /// Start timestamp (ms since epoch).
        pub start_ts: u64,
        /// End timestamp (ms since epoch).
        pub end_ts: u64,
        /// Verifying key for ballot proofs.
        pub vk_ballot: crate::proof::VerifyingKeyId,
        /// Verifying key for tally proofs.
        pub vk_tally: crate::proof::VerifyingKeyId,
        /// Domain separation tag for ballot nullifiers.
        pub domain_tag: String,
    }
}
impl crate::seal::Instruction for CreateElection {}
isi! {
    /// Submit a private ballot for an election.
    #[derive (crate :: DeriveJsonSerialize , crate :: DeriveJsonDeserialize)]
    #[norito_schema(name = "iroha_data_model::isi::zk::SubmitBallot")]
    pub struct SubmitBallot {
        /// Canonical V1 election selector.
        pub election_id: String,
        /// Encrypted ballot payload (opaque bytes).
        pub ciphertext: Vec<u8>,
        /// ZK proof of eligibility and well-formed vote.
        pub ballot_proof: crate::proof::ProofAttachment,
        /// Unique ballot nullifier to prevent double-voting.
        #[norito (json = "crate::json_helpers::fixed_bytes")]
        pub nullifier: [u8; 32],
    }
}
impl crate::seal::Instruction for SubmitBallot {}
isi! {
    /// Finalize an election by verifying the tally proof and recording the result.
    #[derive (crate :: DeriveJsonSerialize , crate :: DeriveJsonDeserialize)]
    #[norito_schema(name = "iroha_data_model::isi::zk::FinalizeElection")]
    pub struct FinalizeElection {
        /// Canonical V1 election selector.
        pub election_id: String,
        /// Exact public conviction weight per option in the frozen asset's smallest units.
        pub tally: Vec<u128>,
        /// ZK proof that `tally` is consistent with submitted ballots.
        pub tally_proof: crate::proof::ProofAttachment,
    }
}
impl crate::seal::Instruction for FinalizeElection {}
fn zk_decode_flags() -> u8 {
    norito::core::effective_decode_flags().unwrap_or_else(norito::core::default_encode_flags)
}

impl<'a> norito::core::DecodeFromSlice<'a> for VerifyProof {
    fn decode_from_slice(bytes: &'a [u8]) -> Result<(Self, usize), norito::core::Error> {
        let flags = zk_decode_flags();
        let mut offset = 0usize;
        let attachment = super::decode_aos_slice_field::<crate::proof::ProofAttachment>(
            super::read_aos_field(bytes, &mut offset, flags)?,
            flags,
        )?;
        if offset != bytes.len() {
            return Err(norito::core::Error::LengthMismatch);
        }
        norito::core::note_payload_access(bytes, offset);
        Ok((Self { attachment }, offset))
    }
}
impl_aos_decode_from_slice!(PruneProofs {
    backend: Option<String>,
});
impl_aos_decode_from_slice!(RegisterZkAsset {
    asset: AssetDefinitionId,
    vk_unshield: Option<crate::proof::VerifyingKeyId>,
});
impl_aos_decode_from_slice!(ScheduleConfidentialPolicyTransition {
    asset: AssetDefinitionId,
    new_mode: ConfidentialPolicyMode,
    effective_height: u64,
    transition_id: Hash,
    conversion_window: Option<u64>,
});
impl_aos_decode_from_slice!(CancelConfidentialPolicyTransition {
    asset: AssetDefinitionId,
    transition_id: Hash,
});
impl_aos_decode_from_slice!(CreateElection {
    election_id: String,
    options: u32,
    eligible_root: [u8; 32],
    start_ts: u64,
    end_ts: u64,
    vk_ballot: crate::proof::VerifyingKeyId,
    vk_tally: crate::proof::VerifyingKeyId,
    domain_tag: String,
});
impl_aos_decode_from_slice!(SubmitBallot {
    election_id: String,
    ciphertext: Vec<u8>,
    ballot_proof: crate::proof::ProofAttachment,
    nullifier: [u8; 32],
});
impl_aos_decode_from_slice!(FinalizeElection {
    election_id: String,
    tally: Vec<u128>,
    tally_proof: crate::proof::ProofAttachment,
});
#[cfg(test)]
mod tests {
    #![allow(clippy::too_many_lines)]
    use super::*;
    use crate::isi::test_support::{assert_registry_decodes, assert_slice_roundtrip};
    use std::str::FromStr as _;
    #[test]
    fn election_shape_v1_enforces_option_and_tally_boundaries() {
        assert_eq!(
            validate_election_options_v1(0),
            Err(ElectionShapeV1Error::TooFewOptions {
                minimum: MIN_ELECTION_OPTIONS_V1 as usize,
                actual: 0,
            })
        );
        assert_eq!(
            validate_election_options_v1(1),
            Err(ElectionShapeV1Error::TooFewOptions {
                minimum: MIN_ELECTION_OPTIONS_V1 as usize,
                actual: 1,
            })
        );
        assert_eq!(validate_election_options_v1(MIN_ELECTION_OPTIONS_V1), Ok(2));
        assert_eq!(
            validate_election_options_v1(MAX_ELECTION_OPTIONS_V1),
            Ok(MAX_ELECTION_OPTIONS_V1 as usize)
        );
        assert_eq!(
            validate_election_options_v1(MAX_ELECTION_OPTIONS_V1 + 1),
            Err(ElectionShapeV1Error::TooManyOptions {
                maximum: MAX_ELECTION_OPTIONS_V1 as usize,
                actual: MAX_ELECTION_OPTIONS_V1 as usize + 1,
            })
        );
        assert_eq!(
            validate_election_tally_v1(1, 1),
            Err(ElectionShapeV1Error::TooFewOptions {
                minimum: MIN_ELECTION_OPTIONS_V1 as usize,
                actual: 1,
            })
        );
        assert_eq!(
            validate_election_tally_v1(MIN_ELECTION_OPTIONS_V1, 2),
            Ok(2)
        );
        assert_eq!(
            validate_election_tally_v1(MIN_ELECTION_OPTIONS_V1, 1),
            Err(ElectionShapeV1Error::TallyLengthMismatch {
                expected: MIN_ELECTION_OPTIONS_V1 as usize,
                actual: 1,
            })
        );
        assert_eq!(
            validate_election_tally_v1(MAX_ELECTION_OPTIONS_V1, 64),
            Ok(64)
        );
        assert_eq!(
            validate_election_tally_v1(MAX_ELECTION_OPTIONS_V1, 0),
            Err(ElectionShapeV1Error::TallyLengthMismatch {
                expected: MAX_ELECTION_OPTIONS_V1 as usize,
                actual: 0,
            })
        );
        assert_eq!(
            validate_election_tally_v1(MAX_ELECTION_OPTIONS_V1, 65),
            Err(ElectionShapeV1Error::TallyLengthMismatch {
                expected: MAX_ELECTION_OPTIONS_V1 as usize,
                actual: MAX_ELECTION_OPTIONS_V1 as usize + 1,
            })
        );
    }
    use crate::proof::{ProofAttachment, ProofBox, VerifyingKeyId};
    use iroha_model_base::domain::DomainId;
    use iroha_model_base::name::Name;
    fn asset_definition_id() -> AssetDefinitionId {
        AssetDefinitionId::derive_from_components(
            DomainId::try_new("wonderland", "universal").expect("domain"),
            Name::from_str("xor").expect("asset name"),
        )
    }
    fn backend() -> iroha_schema::Ident {
        "halo2/ipa".into()
    }
    fn verifying_key(name: &str) -> VerifyingKeyId {
        VerifyingKeyId::new(backend(), name)
    }
    fn proof_attachment() -> ProofAttachment {
        let backend = backend();
        ProofAttachment::new_ref(
            backend.clone(),
            ProofBox::new(backend.clone(), vec![1, 2, 3, 4]),
            VerifyingKeyId::new(backend, "vk_test"),
        )
    }
    #[test]
    #[allow(clippy::too_many_lines)]
    fn zk_decode_from_slice_roundtrips() {
        let asset = asset_definition_id();
        let proof = proof_attachment();
        assert_slice_roundtrip(VerifyProof::new(proof.clone()));
        assert_slice_roundtrip(PruneProofs::new(Some("halo2/ipa".to_owned())));
        assert_slice_roundtrip(RegisterZkAsset::new(
            asset.clone(),
            Some(verifying_key("unshield")),
        ));
        assert_slice_roundtrip(ScheduleConfidentialPolicyTransition::new(
            asset.clone(),
            ConfidentialPolicyMode::Convertible,
            42,
            Hash::new("policy-transition"),
            Some(7),
        ));
        assert_slice_roundtrip(CancelConfidentialPolicyTransition::new(
            asset.clone(),
            Hash::new("policy-transition"),
        ));
        assert_slice_roundtrip(CreateElection {
            election_id: "election-1".to_owned(),
            options: 3,
            eligible_root: [0x21; 32],
            start_ts: 1_700_000_000,
            end_ts: 1_700_086_400,
            vk_ballot: verifying_key("ballot"),
            vk_tally: verifying_key("tally"),
            domain_tag: "iroha-election-v1".to_owned(),
        });
        assert_slice_roundtrip(SubmitBallot {
            election_id: "election-1".to_owned(),
            ciphertext: vec![0x31, 0x32],
            ballot_proof: proof.clone(),
            nullifier: [0x33; 32],
        });
        assert_slice_roundtrip(FinalizeElection {
            election_id: "election-1".to_owned(),
            tally: vec![1, u128::from(u64::MAX) + 1, 3],
            tally_proof: proof,
        });
    }
    #[test]
    fn zk_default_registry_decodes_only_stable_ids() {
        let registry = crate::isi::registry::default();
        let asset = asset_definition_id();
        assert_registry_decodes(
            &registry,
            "iroha.instruction.v1::zk::VerifyProof",
            VerifyProof::new(proof_attachment()),
        );
        assert_registry_decodes(
            &registry,
            "iroha.instruction.v1::zk::PruneProofs",
            PruneProofs::new(None),
        );
        assert_registry_decodes(
            &registry,
            "iroha.instruction.v1::zk::RegisterZkAsset",
            RegisterZkAsset::new(asset.clone(), None),
        );
        assert_registry_decodes(
            &registry,
            "zk::ScheduleConfidentialPolicyTransition",
            ScheduleConfidentialPolicyTransition::new(
                asset.clone(),
                ConfidentialPolicyMode::ShieldedOnly,
                99,
                Hash::new("policy-transition-stable"),
                None,
            ),
        );
        assert_registry_decodes(
            &registry,
            "zk::CancelConfidentialPolicyTransition",
            CancelConfidentialPolicyTransition::new(
                asset.clone(),
                Hash::new("policy-transition-stable"),
            ),
        );
    }
    #[test]
    fn register_zk_asset_rejects_retired_third_wire_field() {
        use norito::{codec::Encode as _, core::DecodeFromSlice as _};
        let registration =
            RegisterZkAsset::new(asset_definition_id(), Some(verifying_key("unshield")));
        let mut retired_payload = registration.encode();
        retired_payload.push(0);
        assert!(
            RegisterZkAsset::decode_from_slice(&retired_payload).is_err(),
            "the retired optional shield field must not be accepted as trailing bytes"
        );
        let mut retired_json =
            norito::json::to_value(&registration).expect("encode registration JSON");
        retired_json
            .as_object_mut()
            .expect("registration JSON object")
            .insert("vk_shield".to_owned(), norito::json::Value::Null);
        assert!(
            norito::json::from_value::<RegisterZkAsset>(retired_json).is_err(),
            "the retired shield role must not be accepted as a JSON field"
        );
    }
}
