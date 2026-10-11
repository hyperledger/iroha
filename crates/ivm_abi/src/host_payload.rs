//! Canonical request and response records for state-reading and VRF syscalls.
//!
//! These records live in the shared ABI crate so the compiler, standalone VM, and ledger host all
//! use one nominal Norito schema at every protocol boundary.
use iroha_data_model::NetworkId;
use norito::core::DecodeLimits;
use norito::{Decode, Encode};
/// Maximum canonical request frame accepted by either V1 VRF verification syscall.
pub const MAX_VRF_VERIFY_PAYLOAD_BYTES_V1: usize = 64 * 1024;
/// Maximum number of verification items accepted by one V1 VRF batch.
pub const MAX_VRF_VERIFY_BATCH_ITEMS_V1: usize = 16;
/// Resource budget for decoding one attacker-controlled V1 VRF request frame.
///
/// Byte-vector fields may consume the complete frame budget, while cumulative elements stay bounded
/// by the same 64 KiB wire contract. The eightfold native-allocation allowance covers nested field
/// accounting, owned byte vectors, and the outer batch vector without weakening the hard bound.
/// Sixteen nested length-delimited scopes exceed the depth required by either the single or batch
/// nominal schema.
pub const VRF_VERIFY_DECODE_LIMITS_V1: DecodeLimits = DecodeLimits::new(
    MAX_VRF_VERIFY_PAYLOAD_BYTES_V1,
    MAX_VRF_VERIFY_PAYLOAD_BYTES_V1,
    MAX_VRF_VERIFY_PAYLOAD_BYTES_V1,
    MAX_VRF_VERIFY_PAYLOAD_BYTES_V1 * 8,
    16,
);
/// Request for recent commitment roots associated with an asset definition.
#[derive(Clone, Debug, PartialEq, Eq, Encode, Decode)]
#[norito(deny_unknown_fields)]
#[derive(norito::NoritoSchema)]
#[norito_schema(
    name = "ivm_abi::host_payload::RootsGetRequest",
    frame = "iroha.ivm.v1.RootsGetRequest"
)]
pub struct RootsGetRequest {
    /// Canonical asset-definition identifier.
    pub asset_id: String,
    /// Maximum number of historical roots to return.
    pub max: u32,
}
/// Recent commitment roots returned by the ledger host.
#[derive(Clone, Debug, PartialEq, Eq, Encode, Decode)]
#[norito(deny_unknown_fields)]
#[derive(norito::NoritoSchema)]
#[norito_schema(
    name = "ivm_abi::host_payload::RootsGetResponse",
    frame = "iroha.ivm.v1.RootsGetResponse"
)]
pub struct RootsGetResponse {
    /// Latest commitment root.
    pub latest: [u8; 32],
    /// Historical roots in canonical host order.
    pub roots: Vec<[u8; 32]>,
    /// Height associated with `latest`.
    pub height: u32,
}
/// Request for the finalized tally of one private election.
#[derive(Clone, Debug, PartialEq, Eq, Encode, Decode)]
#[norito(deny_unknown_fields)]
#[derive(norito::NoritoSchema)]
#[norito_schema(
    name = "ivm_abi::host_payload::VoteGetTallyRequest",
    frame = "iroha.ivm.v1.VoteGetTallyRequest"
)]
pub struct VoteGetTallyRequest {
    /// Canonical governance selector V1 identifying the election.
    pub election_id: String,
}
impl VoteGetTallyRequest {
    /// Return whether the request carries a canonical governance selector V1.
    #[must_use]
    pub fn is_valid_v1(&self) -> bool {
        iroha_data_model::governance::is_valid_governance_selector_v1(&self.election_id)
    }
}
/// Finalized election tally returned by the ledger host.
#[derive(Clone, Debug, PartialEq, Eq, Encode, Decode)]
#[norito(deny_unknown_fields)]
#[derive(norito::NoritoSchema)]
#[norito_schema(
    name = "ivm_abi::host_payload::VoteGetTallyResponse",
    frame = "iroha.ivm.v1.VoteGetTallyResponse"
)]
pub struct VoteGetTallyResponse {
    /// Whether the election has been finalized.
    pub finalized: bool,
    /// Exact smallest-unit conviction weights in canonical candidate order.
    pub tally: Vec<u128>,
}
/// Single VRF verification request.
#[derive(Clone, Debug, PartialEq, Eq, Encode, Decode)]
#[norito(deny_unknown_fields)]
#[derive(norito::NoritoSchema)]
#[norito_schema(
    name = "ivm_abi::host_payload::VrfVerifyRequest",
    frame = "iroha.ivm.v1.VrfVerifyRequest"
)]
pub struct VrfVerifyRequest {
    /// Variant: 1 = proof in G2; 2 = proof in G1.
    pub variant: u8,
    /// Public-key bytes.
    pub pk: Vec<u8>,
    /// Proof/signature bytes.
    pub proof: Vec<u8>,
    /// Exact genesis-derived network identity.
    pub network_id: NetworkId,
    /// Input message bytes.
    pub input: Vec<u8>,
}
/// Batch verification request whose outputs preserve item order.
///
/// Runtime admission requires `1..=MAX_VRF_VERIFY_BATCH_ITEMS_V1` items and a complete canonical
/// frame no larger than [`MAX_VRF_VERIFY_PAYLOAD_BYTES_V1`].
#[derive(Clone, Debug, PartialEq, Eq, Encode, Decode)]
#[norito(deny_unknown_fields)]
#[derive(norito::NoritoSchema)]
#[norito_schema(
    name = "ivm_abi::host_payload::VrfVerifyBatchRequest",
    frame = "iroha.ivm.v1.VrfVerifyBatchRequest"
)]
pub struct VrfVerifyBatchRequest {
    /// Items to verify in order.
    pub items: Vec<VrfVerifyRequest>,
}
#[cfg(test)]
mod tests {
    use super::{VoteGetTallyRequest, VoteGetTallyResponse};
    #[test]
    fn vote_tally_response_roundtrips_weight_above_u64_max() {
        let response = VoteGetTallyResponse {
            finalized: true,
            tally: vec![u128::from(u64::MAX) + 1, 0],
        };
        let encoded = norito::encode_canonical(&response).expect("encode V1 response");
        let decoded: VoteGetTallyResponse =
            norito::decode_canonical(&encoded).expect("decode exact V1 response");
        assert_eq!(decoded, response);
    }
    #[test]
    fn vote_tally_request_uses_canonical_governance_selector_v1() {
        for election_id in ["election-1", "A9_selector~with.dots"] {
            assert!(
                VoteGetTallyRequest {
                    election_id: election_id.to_owned(),
                }
                .is_valid_v1()
            );
        }
        for election_id in ["", ".hidden", "election/alias", "election\nalias"] {
            assert!(
                !VoteGetTallyRequest {
                    election_id: election_id.to_owned(),
                }
                .is_valid_v1()
            );
        }
        assert!(
            VoteGetTallyRequest {
                election_id: "a".repeat(128),
            }
            .is_valid_v1()
        );
        assert!(
            !VoteGetTallyRequest {
                election_id: "a".repeat(129),
            }
            .is_valid_v1()
        );
    }
}

#[cfg(test)]
mod captured_frame_identity_tests {
    #[test]
    fn observed_declared_identities() {
        crate::captured_identity_tests::assert_bidirectional::<super::RootsGetRequest>(
            "ivm_abi::host_payload::RootsGetRequest",
        );
        crate::captured_identity_tests::assert_bidirectional::<super::RootsGetResponse>(
            "ivm_abi::host_payload::RootsGetResponse",
        );
        crate::captured_identity_tests::assert_bidirectional::<super::VoteGetTallyRequest>(
            "ivm_abi::host_payload::VoteGetTallyRequest",
        );
        crate::captured_identity_tests::assert_bidirectional::<super::VoteGetTallyResponse>(
            "ivm_abi::host_payload::VoteGetTallyResponse",
        );
        crate::captured_identity_tests::assert_bidirectional::<super::VrfVerifyRequest>(
            "ivm_abi::host_payload::VrfVerifyRequest",
        );
        crate::captured_identity_tests::assert_bidirectional::<super::VrfVerifyBatchRequest>(
            "ivm_abi::host_payload::VrfVerifyBatchRequest",
        );
    }
}
