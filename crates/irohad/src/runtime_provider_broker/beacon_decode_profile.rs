// Schema-derived cumulative codec work for the complete first-release beacon graph.
//
// This is a decoder quota, not physical allocation custody. The operation's
// original retained session graph, verifier and shared control continue to be
// charged independently to its original allocation pool. No quota can supply
// a missing graph owner or relax the enclosing/default/absolute decode limits.

#[derive(Clone, Copy, Debug)]
struct GlobalBeaconDecodeProfileV1 {
    allocation_wire_passes: usize,
    allocation_intrinsic_bytes: usize,
}

const fn maximum_global_beacon_decode_profile_v1() -> GlobalBeaconDecodeProfileV1 {
    use iroha_data_model::{
        consensus::{
            GlobalThresholdBeaconDkgDealerCommitmentV1, GlobalThresholdBeaconDkgEncryptedShareV1,
            GlobalThresholdBeaconDkgRecipientKeyV1, GlobalThresholdBeaconDkgShareAcceptanceV1,
            GlobalThresholdBeaconPublicShareV1,
        },
    };
    use iroha_model_base::peer::PeerId;
    use std::mem::size_of;

    // The protocol fixes these counts; malformed larger graphs still face the
    // same absolute decoder ceilings before complete semantic validation.
    let n = iroha_crypto::threshold_bls::THRESHOLD_BLS_MAX_COMMITTEE_SIZE_V1 as usize;
    let threshold = (n - 1) / 3 + 1;
    let edges = n * n;
    // A V1 length prefix is at most eight bytes for every field in this schema.
    // The canonical compact layout is smaller; no alternate layout is accepted.
    let field = 8;
    let sequence_count = 8;
    let g2 = iroha_crypto::threshold_bls::THRESHOLD_BLS_PUBLIC_KEY_BYTES;
    // A coefficient is a generic [u8;96] sequence element, so its canonical
    // payload has one framed byte per coordinate (unlike an inline row array).
    let coefficient = g2 * (field + 1);
    let coefficients = sequence_count + threshold * (field + coefficient);
    let proof = (field + g2) + (field + 32);
    // The exact frozen consensus roster uses BlsNormal's 48-byte public key.
    // Compact public-key storage also includes its one-byte algorithm tag.
    let compact_key = sequence_count + (1 + 48) * (field + 1);
    let peer = field + compact_key;
    let public_share = (field + 2) + (field + 32) + (field + g2);
    // Validator generation: network, generation number and the exact ordered BLS roster.
    let generation = (field + 32) + (field + 8) + field + sequence_count + n * (field + peer);
    // Twelve positional session fields: three u16, four identities and five u64.
    let dkg_session = 3 * (field + 2) + 4 * (field + 32) + 5 * (field + 8);
    let installed_beacon = 2 * (field + 32);
    let readiness =
        (field + 2) + 3 * (field + 32) + 4 * (field + 8) + (field + 4) + (field + installed_beacon);
    let pulse = 4 * (field + 32) + (field + 8);
    let anchor = (field + 8) + (field + 32);

    // The complete large-byte path is request -> key session -> transcript ->
    // row sequence -> row -> byte field. Five prefix readers each charge the
    // disjoint field spans at their level. Six concrete canonical field levels
    // (including the root) can request an aligned source copy. Raw byte leaves
    // charge their count and owned backing, at most twice their disjoint wire
    // bytes; signatures/compact keys fit within those same two leaf passes.
    // Coefficient/proof/peer and generation/readiness children below that path
    // are bounded separately by the exact maximum committee geometry above.
    let charged_field_levels = 5;
    let aligned_field_levels = 6;
    let byte_leaf_passes = 2;
    let nested = dkg_session
        + generation
        + readiness
        + pulse
        + anchor
        + n * (coefficients + proof + compact_key + peer + public_share + peer);
    let sequence_elements = 5 * n + 2 * edges + n * threshold;
    let typed_rows = n
        * (size_of::<GlobalThresholdBeaconDkgRecipientKeyV1>()
            + size_of::<GlobalThresholdBeaconDkgDealerCommitmentV1>()
            + size_of::<GlobalThresholdBeaconPublicShareV1>()
            + size_of::<u16>()
            + size_of::<PeerId>())
        + edges
            * (size_of::<GlobalThresholdBeaconDkgEncryptedShareV1>()
                + size_of::<GlobalThresholdBeaconDkgShareAcceptanceV1>())
        + n * threshold * size_of::<[u8; 96]>();
    let span_backing = sequence_elements * size_of::<norito::core::SequenceSpan>();
    GlobalBeaconDecodeProfileV1 {
        allocation_wire_passes: charged_field_levels + aligned_field_levels + byte_leaf_passes,
        // Nested fields can charge their prefix and their realignment copy.
        // Each planned element also retains its original nominal metadata unit.
        allocation_intrinsic_bytes: 2 * nested + typed_rows + span_backing + sequence_elements,
    }
}

const GLOBAL_BEACON_DECODE_PROFILE_V1: GlobalBeaconDecodeProfileV1 =
    maximum_global_beacon_decode_profile_v1();
const GLOBAL_BEACON_DECODE_POLICY_V1: DecodeResourcePolicyV1 = DecodeResourcePolicyV1 {
    allocation_wire_passes: GLOBAL_BEACON_DECODE_PROFILE_V1.allocation_wire_passes,
    allocation_headroom_bytes: GLOBAL_BEACON_DECODE_PROFILE_V1.allocation_intrinsic_bytes,
    // Keep every existing absolute, composed, cumulative and process-pool cap.
    ..STANDARD_DECODE_POLICY_V1
};
