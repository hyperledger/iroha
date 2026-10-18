//! Canonical full-credential proof envelope and cross-subproof binding.
//!
//! `X5S1` is the sole first-release credential container. It carries exactly two ordered,
//! length-delimited proof records: one main aggregate proof and one dedicated `X5C1` compact-CA
//! proof. Public statement material is repeated in the fixed header so decode cannot silently pair
//! a proof with another statement, root, or root-SPKI channel. The cryptographic verifier must
//! still derive and compare that material from its trusted statement. The required public nonce
//! is a separate proof instance and scopes every dynamic MAIN, CA and Joint hash.
use super::credential_joint::JointOriginalOpeningsV1;
#[cfg(test)]
use super::profile::ZK_X509_MAXIMUM_ENCODED_X5S1_BYTES_V1;
pub use super::proof_instance::ZkX509ProofInstanceV1;
use super::{
    accumulator_stark::{
        ZK_X509_CA_ACCUMULATOR_MAX_PROOF_BYTES_V1,
        ZK_X509_CA_ACCUMULATOR_ROOT_SPKI_BASE_CHANNEL_V1, ZkX509CaAccumulatorStarkPublicV1,
    },
    merkle::hash_frame_v1,
    profile::{ZK_X509_MAX_PROOF_BYTES_V1, ZK_X509_PROOF_VERSION_V1},
};
use crate::privacy_engines::transparent_stark::GoldilocksFieldV1 as F;
use iroha_data_model::privacy::{IrohaZkX509StarkP256StatementV1, PrivacyStatementV1};
use thiserror::Error;
const CREDENTIAL_MAGIC_V1: [u8; 4] = *b"X5S1";
const MAIN_AGGREGATE_MAGIC_V1: [u8; 4] = *b"X5M1";
const CA_SUBPROOF_MAGIC_V1: [u8; 4] = *b"X5C1";
const SUBPROOF_COUNT_V1: u16 = 2;
const MAIN_SUBPROOF_KIND_V1: u16 = 1;
const CA_SUBPROOF_KIND_V1: u16 = 2;
const SUBPROOF_INSTANCE_V1: u16 = 0;
const CONSENSUS_CONTEXT_DIGEST_DOMAIN_V1: &[u8] = b"iroha.zk-x509.credential-consensus-context.v1";
const PROOF_INSTANCE_BYTES_V1: usize = 32;
const PUBLIC_HEADER_BYTES_V1: usize = 4 + 2 + 2 + 32 + 32 + 32 + 4;
const JOINT_OPENING_BYTES_V1: usize = 132 * 32;
const _: () = assert!(JOINT_OPENING_BYTES_V1 == JointOriginalOpeningsV1::ENCODED_BYTES);
const FIXED_HEADER_BYTES_V1: usize = PUBLIC_HEADER_BYTES_V1 + JOINT_OPENING_BYTES_V1;
const SUBPROOF_HEADER_BYTES_V1: usize = 2 + 2 + 4;
/// Exact outer bytes added around the two already-encoded inner proofs.
///
/// This is the sole source of truth for the consensus profile's combined
/// proof-size arithmetic. It includes the fixed public header and both
/// ordered `(kind, instance, length)` records, but no inner proof byte.
pub(crate) const ZK_X509_CREDENTIAL_ENVELOPE_FRAMING_BYTES_V1: usize =
    FIXED_HEADER_BYTES_V1 + 2 * SUBPROOF_HEADER_BYTES_V1;
/// Exact hard ceiling for the main aggregate section inside `X5S1`.
///
/// The full credential ceiling is partitioned rather than shared dynamically: a caller cannot steal
/// the compact-CA verifier's budget for an oversized main proof, or vice versa.
pub(crate) const ZK_X509_MAIN_AGGREGATE_MAX_PROOF_BYTES_V1: usize = ZK_X509_MAX_PROOF_BYTES_V1
    as usize
    - ZK_X509_CREDENTIAL_ENVELOPE_FRAMING_BYTES_V1
    - ZK_X509_CA_ACCUMULATOR_MAX_PROOF_BYTES_V1;
const MINIMUM_ENCODED_BYTES_V1: usize = ZK_X509_CREDENTIAL_ENVELOPE_FRAMING_BYTES_V1 + 2 * 4;
const _: () = assert!(
    ZK_X509_CREDENTIAL_ENVELOPE_FRAMING_BYTES_V1
        + ZK_X509_MAIN_AGGREGATE_MAX_PROOF_BYTES_V1
        + ZK_X509_CA_ACCUMULATOR_MAX_PROOF_BYTES_V1
        == ZK_X509_MAX_PROOF_BYTES_V1 as usize
);
/// Compute the exact encoded outer-envelope length without allocation.
#[cfg(any(test, feature = "privacy-release-evidence"))]
pub(crate) const fn zk_x509_credential_envelope_encoded_len_v1(
    main_aggregate_bytes: usize,
    ca_subproof_bytes: usize,
) -> Option<usize> {
    match ZK_X509_CREDENTIAL_ENVELOPE_FRAMING_BYTES_V1.checked_add(main_aggregate_bytes) {
        Some(bytes) => bytes.checked_add(ca_subproof_bytes),
        None => None,
    }
}
/// Fixed verifier-derived public material repeated in the `X5S1` header.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[doc(hidden)]
pub struct ZkX509CredentialPublicBindingV1 {
    /// Canonical digest of the complete typed statement and committed genesis.
    pub(crate) consensus_context_digest: [u8; 32],
    /// Governed compact-CA root as exact bytes.
    pub(crate) governed_ca_root: [u8; 32],
    /// Canonical root-SPKI byte channel.
    pub(crate) root_spki_channel: u32,
}
impl ZkX509CredentialPublicBindingV1 {
    /// Derive all header material from verifier-owned consensus context.
    pub(crate) fn from_consensus_context_v1(
        statement: &IrohaZkX509StarkP256StatementV1,
        genesis_hash: [u8; 32],
    ) -> Result<Self, ZkX509CredentialProofErrorV1> {
        if genesis_hash == [0; 32] {
            return Err(ZkX509CredentialProofErrorV1::InvalidStatement);
        }
        let statement_digest = PrivacyStatementV1::IrohaZkX509StarkP256V1(statement.clone())
            .digest()
            .map_err(|_| ZkX509CredentialProofErrorV1::InvalidStatement)?
            .into_bytes();
        let consensus_context_digest = hash_frame_v1(
            CONSENSUS_CONTEXT_DIGEST_DOMAIN_V1,
            &[&statement_digest, &genesis_hash],
        )
        .map_err(|_| ZkX509CredentialProofErrorV1::InvalidStatement)?;
        let disclosed = u32::try_from(statement.disclosed_attributes.len())
            .map_err(|_| ZkX509CredentialProofErrorV1::InvalidStatement)?;
        let root_spki_channel = disclosed
            .checked_mul(2)
            .and_then(|channels| {
                ZK_X509_CA_ACCUMULATOR_ROOT_SPKI_BASE_CHANNEL_V1.checked_add(channels)
            })
            .ok_or(ZkX509CredentialProofErrorV1::InvalidStatement)?;
        Ok(Self {
            consensus_context_digest,
            governed_ca_root: *statement.ca_membership_root.as_bytes(),
            root_spki_channel,
        })
    }
    /// Convert the byte-level public binding to the compact-CA field input.
    pub(crate) fn ca_public_v1(self) -> ZkX509CaAccumulatorStarkPublicV1 {
        ZkX509CaAccumulatorStarkPublicV1 {
            governed_root: self.governed_ca_root.map(|byte| F(u64::from(byte))),
            root_spki_channel: F(u64::from(self.root_spki_channel)),
        }
    }
}
/// Borrowed exact contents of a canonical `X5S1` envelope.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[doc(hidden)]
pub struct ZkX509CredentialEnvelopeV1<'a> {
    /// Public nonce used by all three verifier-fixed proof-instance domains.
    pub proof_instance: ZkX509ProofInstanceV1,
    /// Canonical ordered MAIN24 and CA108 original-polynomial DEEP openings.
    pub(crate) joint_openings: JointOriginalOpeningsV1,
    /// Header binding checked against the verifier-owned statement.
    pub public: ZkX509CredentialPublicBindingV1,
    /// Exact main aggregate proof bytes.
    pub main_aggregate: &'a [u8],
    /// Exact compact-CA `X5C1` proof bytes.
    pub ca_subproof: &'a [u8],
}
/// Canonical credential envelope or cross-subproof verification failure.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Error)]
#[doc(hidden)]
pub enum ZkX509CredentialProofErrorV1 {
    /// The verifier-owned public statement cannot define the fixed profile.
    #[error("zk-X509 credential statement is invalid")]
    InvalidStatement,
    /// The exact `X5S1` framing, order, count, or inner proof identity is invalid.
    #[error("zk-X509 credential proof envelope is malformed")]
    MalformedEnvelope,
    /// The combined proof or an individual section exceeds its byte ceiling.
    #[error("zk-X509 credential proof exceeds its byte ceiling")]
    ProofTooLarge,
    /// Header material does not equal the verifier-derived statement binding.
    #[error("zk-X509 credential proof public binding is invalid")]
    PublicBindingMismatch,
    /// The main aggregate proof did not verify.
    #[error("zk-X509 main aggregate proof is invalid")]
    MainProof,
    /// The compact-CA proof did not verify.
    #[error("zk-X509 compact-CA subproof is invalid")]
    CaProof,
    /// Paired MAIN/CA roots, transcript state or original openings do not match.
    #[error("zk-X509 credential joint original-oracle binding does not match")]
    CrossSubproofMismatch,
}
#[cfg(any(test, feature = "privacy-release-evidence"))]
fn append_u16_v1(output: &mut Vec<u8>, value: u16) {
    output.extend_from_slice(&value.to_be_bytes());
}
#[cfg(any(test, feature = "privacy-release-evidence"))]
fn append_u32_v1(output: &mut Vec<u8>, value: u32) {
    output.extend_from_slice(&value.to_be_bytes());
}
fn read_u16_v1(encoded: &[u8], cursor: &mut usize) -> Result<u16, ZkX509CredentialProofErrorV1> {
    let end = cursor
        .checked_add(2)
        .ok_or(ZkX509CredentialProofErrorV1::MalformedEnvelope)?;
    let bytes = encoded
        .get(*cursor..end)
        .ok_or(ZkX509CredentialProofErrorV1::MalformedEnvelope)?;
    *cursor = end;
    Ok(u16::from_be_bytes(bytes.try_into().map_err(|_| {
        ZkX509CredentialProofErrorV1::MalformedEnvelope
    })?))
}
fn read_u32_v1(encoded: &[u8], cursor: &mut usize) -> Result<u32, ZkX509CredentialProofErrorV1> {
    let end = cursor
        .checked_add(4)
        .ok_or(ZkX509CredentialProofErrorV1::MalformedEnvelope)?;
    let bytes = encoded
        .get(*cursor..end)
        .ok_or(ZkX509CredentialProofErrorV1::MalformedEnvelope)?;
    *cursor = end;
    Ok(u32::from_be_bytes(bytes.try_into().map_err(|_| {
        ZkX509CredentialProofErrorV1::MalformedEnvelope
    })?))
}
fn read_array_v1<const N: usize>(
    encoded: &[u8],
    cursor: &mut usize,
) -> Result<[u8; N], ZkX509CredentialProofErrorV1> {
    let end = cursor
        .checked_add(N)
        .ok_or(ZkX509CredentialProofErrorV1::MalformedEnvelope)?;
    let value = encoded
        .get(*cursor..end)
        .ok_or(ZkX509CredentialProofErrorV1::MalformedEnvelope)?
        .try_into()
        .map_err(|_| ZkX509CredentialProofErrorV1::MalformedEnvelope)?;
    *cursor = end;
    Ok(value)
}
fn read_subproof_v1<'a>(
    encoded: &'a [u8],
    cursor: &mut usize,
    expected_kind: u16,
    expected_magic: [u8; 4],
    maximum_length: usize,
) -> Result<&'a [u8], ZkX509CredentialProofErrorV1> {
    if read_u16_v1(encoded, cursor)? != expected_kind
        || read_u16_v1(encoded, cursor)? != SUBPROOF_INSTANCE_V1
    {
        return Err(ZkX509CredentialProofErrorV1::MalformedEnvelope);
    }
    let length = usize::try_from(read_u32_v1(encoded, cursor)?)
        .map_err(|_| ZkX509CredentialProofErrorV1::MalformedEnvelope)?;
    if length > maximum_length {
        return Err(ZkX509CredentialProofErrorV1::ProofTooLarge);
    }
    if length < expected_magic.len() {
        return Err(ZkX509CredentialProofErrorV1::MalformedEnvelope);
    }
    let end = cursor
        .checked_add(length)
        .ok_or(ZkX509CredentialProofErrorV1::MalformedEnvelope)?;
    let proof = encoded
        .get(*cursor..end)
        .ok_or(ZkX509CredentialProofErrorV1::MalformedEnvelope)?;
    if proof.get(..expected_magic.len()) != Some(expected_magic.as_slice()) {
        return Err(ZkX509CredentialProofErrorV1::MalformedEnvelope);
    }
    *cursor = end;
    Ok(proof)
}
/// Encode exactly one main aggregate followed by exactly one `X5C1` proof.
#[cfg(any(test, feature = "privacy-release-evidence"))]
#[doc(hidden)]
pub fn encode_zk_x509_credential_envelope_v1(
    proof_instance: ZkX509ProofInstanceV1,
    public: ZkX509CredentialPublicBindingV1,
    main_aggregate: &[u8],
    ca_subproof: &[u8],
    joint_openings: &[u8],
) -> Result<Vec<u8>, ZkX509CredentialProofErrorV1> {
    JointOriginalOpeningsV1::decode_v1(joint_openings)
        .map_err(|_| ZkX509CredentialProofErrorV1::MalformedEnvelope)?;
    if main_aggregate.get(..4) != Some(MAIN_AGGREGATE_MAGIC_V1.as_slice())
        || ca_subproof.get(..4) != Some(CA_SUBPROOF_MAGIC_V1.as_slice())
    {
        return Err(ZkX509CredentialProofErrorV1::MalformedEnvelope);
    }
    if main_aggregate.len() > ZK_X509_MAIN_AGGREGATE_MAX_PROOF_BYTES_V1
        || ca_subproof.len() > ZK_X509_CA_ACCUMULATOR_MAX_PROOF_BYTES_V1
    {
        return Err(ZkX509CredentialProofErrorV1::ProofTooLarge);
    }
    let main_length = u32::try_from(main_aggregate.len())
        .map_err(|_| ZkX509CredentialProofErrorV1::ProofTooLarge)?;
    let ca_length = u32::try_from(ca_subproof.len())
        .map_err(|_| ZkX509CredentialProofErrorV1::ProofTooLarge)?;
    let encoded_length =
        zk_x509_credential_envelope_encoded_len_v1(main_aggregate.len(), ca_subproof.len())
            .ok_or(ZkX509CredentialProofErrorV1::ProofTooLarge)?;
    if encoded_length > ZK_X509_MAX_PROOF_BYTES_V1 as usize {
        return Err(ZkX509CredentialProofErrorV1::ProofTooLarge);
    }
    let mut encoded = Vec::new();
    encoded
        .try_reserve_exact(encoded_length)
        .map_err(|_| ZkX509CredentialProofErrorV1::ProofTooLarge)?;
    encoded.extend_from_slice(&CREDENTIAL_MAGIC_V1);
    append_u16_v1(&mut encoded, ZK_X509_PROOF_VERSION_V1);
    append_u16_v1(&mut encoded, SUBPROOF_COUNT_V1);
    encoded.extend_from_slice(&proof_instance.nonce_v1());
    encoded.extend_from_slice(&public.consensus_context_digest);
    encoded.extend_from_slice(&public.governed_ca_root);
    append_u32_v1(&mut encoded, public.root_spki_channel);
    encoded.extend_from_slice(joint_openings);
    append_u16_v1(&mut encoded, MAIN_SUBPROOF_KIND_V1);
    append_u16_v1(&mut encoded, SUBPROOF_INSTANCE_V1);
    append_u32_v1(&mut encoded, main_length);
    encoded.extend_from_slice(main_aggregate);
    append_u16_v1(&mut encoded, CA_SUBPROOF_KIND_V1);
    append_u16_v1(&mut encoded, SUBPROOF_INSTANCE_V1);
    append_u32_v1(&mut encoded, ca_length);
    encoded.extend_from_slice(ca_subproof);
    if encoded.len() != encoded_length {
        return Err(ZkX509CredentialProofErrorV1::MalformedEnvelope);
    }
    Ok(encoded)
}
/// Decode the sole exact, bounded `X5S1` credential container.
#[doc(hidden)]
pub fn decode_zk_x509_credential_envelope_v1(
    encoded: &[u8],
) -> Result<ZkX509CredentialEnvelopeV1<'_>, ZkX509CredentialProofErrorV1> {
    if encoded.len() > ZK_X509_MAX_PROOF_BYTES_V1 as usize {
        return Err(ZkX509CredentialProofErrorV1::ProofTooLarge);
    }
    if encoded.len() < MINIMUM_ENCODED_BYTES_V1
        || encoded.get(..4) != Some(CREDENTIAL_MAGIC_V1.as_slice())
    {
        return Err(ZkX509CredentialProofErrorV1::MalformedEnvelope);
    }
    let mut cursor = 4;
    if read_u16_v1(encoded, &mut cursor)? != ZK_X509_PROOF_VERSION_V1
        || read_u16_v1(encoded, &mut cursor)? != SUBPROOF_COUNT_V1
    {
        return Err(ZkX509CredentialProofErrorV1::MalformedEnvelope);
    }
    let proof_instance = ZkX509ProofInstanceV1::new_v1(read_array_v1::<PROOF_INSTANCE_BYTES_V1>(
        encoded,
        &mut cursor,
    )?);
    let public = ZkX509CredentialPublicBindingV1 {
        consensus_context_digest: read_array_v1(encoded, &mut cursor)?,
        governed_ca_root: read_array_v1(encoded, &mut cursor)?,
        root_spki_channel: read_u32_v1(encoded, &mut cursor)?,
    };
    let joint_bytes =
        read_array_v1::<{ JointOriginalOpeningsV1::ENCODED_BYTES }>(encoded, &mut cursor)?;
    let joint_openings = JointOriginalOpeningsV1::decode_v1(&joint_bytes)
        .map_err(|_| ZkX509CredentialProofErrorV1::MalformedEnvelope)?;
    let main_aggregate = read_subproof_v1(
        encoded,
        &mut cursor,
        MAIN_SUBPROOF_KIND_V1,
        MAIN_AGGREGATE_MAGIC_V1,
        ZK_X509_MAIN_AGGREGATE_MAX_PROOF_BYTES_V1,
    )?;
    let ca_subproof = read_subproof_v1(
        encoded,
        &mut cursor,
        CA_SUBPROOF_KIND_V1,
        CA_SUBPROOF_MAGIC_V1,
        ZK_X509_CA_ACCUMULATOR_MAX_PROOF_BYTES_V1,
    )?;
    if cursor != encoded.len() {
        return Err(ZkX509CredentialProofErrorV1::MalformedEnvelope);
    }
    Ok(ZkX509CredentialEnvelopeV1 {
        proof_instance,
        joint_openings,
        public,
        main_aggregate,
        ca_subproof,
    })
}
#[cfg(test)]
mod tests {
    fn proof_instance_fixture_v1() -> super::ZkX509ProofInstanceV1 {
        super::ZkX509ProofInstanceV1::new_v1(core::array::from_fn(|i| i as u8))
    }
    fn joint_openings_fixture_v1() -> [u8; super::JointOriginalOpeningsV1::ENCODED_BYTES] {
        [0; super::JointOriginalOpeningsV1::ENCODED_BYTES]
    }
    use super::*;
    use crate::privacy_engines::zk_x509::profile::{
        ZK_X509_CA_FRAME_BYTES_V1, ZK_X509_CA_PRE_DEEP_MAXIMUM_BYTES_V1,
        ZK_X509_DEEP_OPENING_BYTES_V1, ZK_X509_MAIN_FRAME_BYTES_V1,
        ZK_X509_MAIN_PRE_DEEP_MAXIMUM_BYTES_V1, ZK_X509_MAX_PROOF_BYTES_V1,
    };
    fn public(seed: u8) -> ZkX509CredentialPublicBindingV1 {
        ZkX509CredentialPublicBindingV1 {
            consensus_context_digest: [seed; 32],
            governed_ca_root: [seed.wrapping_add(1); 32],
            root_spki_channel: 38,
        }
    }
    fn proof_fixture() -> (ZkX509CredentialPublicBindingV1, Vec<u8>) {
        let public = public(7);
        let encoded = encode_zk_x509_credential_envelope_v1(
            proof_instance_fixture_v1(),
            public,
            b"X5M1main-proof",
            b"X5C1ca-proof",
            &joint_openings_fixture_v1(),
        )
        .unwrap();
        (public, encoded)
    }
    #[test]
    fn canonical_envelope_round_trips_and_binds_exactly_two_proofs() {
        let (public, encoded) = proof_fixture();
        let decoded = decode_zk_x509_credential_envelope_v1(&encoded).expect("canonical envelope");
        assert_eq!(decoded.proof_instance, proof_instance_fixture_v1());
        assert_eq!(&encoded[8..40], &proof_instance_fixture_v1().nonce_v1());
        assert_eq!(decoded.public, public);
        assert_eq!(decoded.main_aggregate, b"X5M1main-proof");
        assert_eq!(decoded.ca_subproof, b"X5C1ca-proof");
        assert_eq!(
            decoded.joint_openings,
            JointOriginalOpeningsV1::decode_v1(&joint_openings_fixture_v1()).unwrap()
        );
    }
    #[test]
    fn every_truncation_and_any_trailing_suffix_is_rejected() {
        let (_, encoded) = proof_fixture();
        for length in 0..encoded.len() {
            assert!(
                decode_zk_x509_credential_envelope_v1(&encoded[..length]).is_err(),
                "truncation at {length} accepted"
            );
        }
        let mut trailing = encoded;
        trailing.push(0);
        assert_eq!(
            decode_zk_x509_credential_envelope_v1(&trailing),
            Err(ZkX509CredentialProofErrorV1::MalformedEnvelope)
        );
    }
    #[test]
    fn malformed_duplicate_reordered_and_excess_subproofs_are_rejected() {
        let (_, encoded) = proof_fixture();
        for offset in [
            0_usize,
            4,
            6,
            FIXED_HEADER_BYTES_V1,
            FIXED_HEADER_BYTES_V1 + 2,
        ] {
            let mut changed = encoded.clone();
            changed[offset] ^= 1;
            assert!(
                decode_zk_x509_credential_envelope_v1(&changed).is_err(),
                "header mutation at {offset} accepted"
            );
        }
        let main_length = b"X5M1main-proof".len();
        let second_kind = FIXED_HEADER_BYTES_V1 + SUBPROOF_HEADER_BYTES_V1 + main_length;
        let mut nonzero_ca_instance = encoded.clone();
        nonzero_ca_instance[second_kind + 2..second_kind + 4].copy_from_slice(&1_u16.to_be_bytes());
        assert_eq!(
            decode_zk_x509_credential_envelope_v1(&nonzero_ca_instance),
            Err(ZkX509CredentialProofErrorV1::MalformedEnvelope)
        );
        let mut duplicate_main = encoded.clone();
        duplicate_main[second_kind..second_kind + 2]
            .copy_from_slice(&MAIN_SUBPROOF_KIND_V1.to_be_bytes());
        assert!(decode_zk_x509_credential_envelope_v1(&duplicate_main).is_err());
        let mut duplicate_ca = encoded.clone();
        duplicate_ca[FIXED_HEADER_BYTES_V1..FIXED_HEADER_BYTES_V1 + 2]
            .copy_from_slice(&CA_SUBPROOF_KIND_V1.to_be_bytes());
        assert!(decode_zk_x509_credential_envelope_v1(&duplicate_ca).is_err());
        let main_record = &encoded[FIXED_HEADER_BYTES_V1..second_kind];
        let ca_record = &encoded[second_kind..];
        let mut swapped = encoded[..FIXED_HEADER_BYTES_V1].to_vec();
        swapped.extend_from_slice(ca_record);
        swapped.extend_from_slice(main_record);
        assert_eq!(
            decode_zk_x509_credential_envelope_v1(&swapped),
            Err(ZkX509CredentialProofErrorV1::MalformedEnvelope)
        );
        let mut excess = encoded;
        excess[6..8].copy_from_slice(&3_u16.to_be_bytes());
        assert!(decode_zk_x509_credential_envelope_v1(&excess).is_err());
    }
    #[test]
    fn every_public_header_byte_changes_the_verifier_owned_context() {
        let (public, encoded) = proof_fixture();
        for offset in (8 + PROOF_INSTANCE_BYTES_V1)..PUBLIC_HEADER_BYTES_V1 {
            let mut changed = encoded.clone();
            changed[offset] ^= 1;
            assert_ne!(
                decode_zk_x509_credential_envelope_v1(&changed)
                    .unwrap()
                    .public,
                public,
                "public byte {offset}"
            );
        }
    }

    #[test]
    fn every_nonce_byte_changes_only_the_proof_instance_in_the_envelope() {
        let (public, encoded) = proof_fixture();
        let original = decode_zk_x509_credential_envelope_v1(&encoded).unwrap();
        for byte in 0..PROOF_INSTANCE_BYTES_V1 {
            let mut changed = encoded.clone();
            changed[8 + byte] ^= 1;
            let decoded = decode_zk_x509_credential_envelope_v1(&changed).unwrap();
            let mut expected_nonce = proof_instance_fixture_v1().nonce_v1();
            expected_nonce[byte] ^= 1;
            assert_eq!(decoded.proof_instance.nonce_v1(), expected_nonce);
            assert_ne!(decoded.proof_instance, original.proof_instance);
            assert_eq!(decoded.public, public);
            assert_eq!(decoded.joint_openings, original.joint_openings);
            assert_eq!(decoded.main_aggregate, original.main_aggregate);
            assert_eq!(decoded.ca_subproof, original.ca_subproof);
        }
        // This is a framing control. Full verification must use the decoded
        // instance and reject mutated nonces through the original scoped roots.
    }

    #[test]
    fn all_nonce_values_are_canonical_but_missing_or_extra_nonce_bytes_are_rejected() {
        let (public, encoded) = proof_fixture();
        for nonce in [[0; 32], [255; 32], core::array::from_fn(|i| i as u8)] {
            let proof_instance = ZkX509ProofInstanceV1::new_v1(nonce);
            let encoded = encode_zk_x509_credential_envelope_v1(
                proof_instance,
                public,
                b"X5M1main-proof",
                b"X5C1ca-proof",
                &joint_openings_fixture_v1(),
            )
            .unwrap();
            let decoded = decode_zk_x509_credential_envelope_v1(&encoded).unwrap();
            assert_eq!(decoded.proof_instance, proof_instance);
            assert_eq!(decoded.public, public);
            assert_eq!(
                encode_zk_x509_credential_envelope_v1(
                    decoded.proof_instance,
                    decoded.public,
                    decoded.main_aggregate,
                    decoded.ca_subproof,
                    &joint_openings_fixture_v1(),
                )
                .unwrap(),
                encoded
            );
        }
        let mut missing = encoded.clone();
        missing.drain(8..8 + PROOF_INSTANCE_BYTES_V1);
        assert_eq!(
            decode_zk_x509_credential_envelope_v1(&missing),
            Err(ZkX509CredentialProofErrorV1::MalformedEnvelope)
        );
        for byte in 0..PROOF_INSTANCE_BYTES_V1 {
            let mut short = encoded.clone();
            short.remove(8 + byte);
            assert!(decode_zk_x509_credential_envelope_v1(&short).is_err());
        }
        let mut extra = encoded[..8].to_vec();
        extra.extend_from_slice(&[0; 32]);
        extra.extend_from_slice(&encoded[8..]);
        assert!(decode_zk_x509_credential_envelope_v1(&extra).is_err());
    }

    #[test]
    fn consensus_context_derivation_binds_statement_profile_intent_and_genesis() {
        let (statement, _) = crate::privacy_engines::zk_x509::projection_air::tests::fixture();
        let genesis = [0x91; 32];
        let canonical =
            ZkX509CredentialPublicBindingV1::from_consensus_context_v1(&statement, genesis)
                .expect("canonical consensus context");
        let mut changed_intent = statement.clone();
        changed_intent.context.transaction_intent_digest =
            iroha_data_model::privacy::PrivacyTransactionIntentDigestV1::new([0xA1; 32]);
        assert_ne!(
            ZkX509CredentialPublicBindingV1::from_consensus_context_v1(&changed_intent, genesis)
                .expect("changed transaction intent"),
            canonical
        );
        let mut changed_profile = statement.clone();
        changed_profile.context.parameter_digest =
            iroha_data_model::privacy::PrivacyParameterDigestV1::new([0xA2; 32]);
        assert_ne!(
            ZkX509CredentialPublicBindingV1::from_consensus_context_v1(&changed_profile, genesis)
                .expect("changed parameter digest"),
            canonical
        );
        let mut changed_manifest = statement.clone();
        changed_manifest.context.engine_manifest_digest =
            iroha_data_model::privacy::PrivacyEngineManifestDigestV1::new([0xA3; 32]);
        assert_ne!(
            ZkX509CredentialPublicBindingV1::from_consensus_context_v1(&changed_manifest, genesis)
                .expect("changed engine manifest digest"),
            canonical
        );
        assert_ne!(
            ZkX509CredentialPublicBindingV1::from_consensus_context_v1(&statement, [0x92; 32],)
                .expect("changed committed genesis"),
            canonical
        );
        assert_eq!(
            ZkX509CredentialPublicBindingV1::from_consensus_context_v1(&statement, [0; 32]),
            Err(ZkX509CredentialProofErrorV1::InvalidStatement)
        );
    }
    #[test]
    fn encoder_rejects_wrong_inner_identity_and_global_resource_overflow() {
        let public = public(1);
        assert_eq!(
            encode_zk_x509_credential_envelope_v1(
                proof_instance_fixture_v1(),
                public,
                b"X5S1main",
                b"X5C1ca",
                &joint_openings_fixture_v1()
            ),
            Err(ZkX509CredentialProofErrorV1::MalformedEnvelope)
        );
        assert_eq!(
            encode_zk_x509_credential_envelope_v1(
                proof_instance_fixture_v1(),
                public,
                b"X5M1main",
                b"X5C2ca",
                &joint_openings_fixture_v1()
            ),
            Err(ZkX509CredentialProofErrorV1::MalformedEnvelope)
        );
        let mut oversized = vec![0_u8; ZK_X509_MAX_PROOF_BYTES_V1 as usize];
        oversized[..4].copy_from_slice(b"X5C1");
        assert_eq!(
            encode_zk_x509_credential_envelope_v1(
                proof_instance_fixture_v1(),
                public,
                b"X5M1",
                &oversized,
                &joint_openings_fixture_v1()
            ),
            Err(ZkX509CredentialProofErrorV1::ProofTooLarge)
        );
    }
    #[test]
    fn section_specific_resource_caps_are_enforced_before_payload_slicing() {
        let (public, encoded) = proof_fixture();
        let main_length_offset = FIXED_HEADER_BYTES_V1 + 4;
        for declared in [0_u32, 1, 2, 3] {
            let mut too_short = encoded.clone();
            too_short[main_length_offset..main_length_offset + 4]
                .copy_from_slice(&declared.to_be_bytes());
            assert_eq!(
                decode_zk_x509_credential_envelope_v1(&too_short),
                Err(ZkX509CredentialProofErrorV1::MalformedEnvelope)
            );
        }
        let mut declared_oversized_main = encoded.clone();
        declared_oversized_main[main_length_offset..main_length_offset + 4].copy_from_slice(
            &u32::try_from(ZK_X509_MAIN_AGGREGATE_MAX_PROOF_BYTES_V1 + 1)
                .expect("main cap fits u32")
                .to_be_bytes(),
        );
        assert_eq!(
            decode_zk_x509_credential_envelope_v1(&declared_oversized_main),
            Err(ZkX509CredentialProofErrorV1::ProofTooLarge)
        );
        let ca_length_offset =
            FIXED_HEADER_BYTES_V1 + SUBPROOF_HEADER_BYTES_V1 + b"X5M1main-proof".len() + 4;
        for declared in [0_u32, 1, 2, 3] {
            let mut too_short = encoded.clone();
            too_short[ca_length_offset..ca_length_offset + 4]
                .copy_from_slice(&declared.to_be_bytes());
            assert_eq!(
                decode_zk_x509_credential_envelope_v1(&too_short),
                Err(ZkX509CredentialProofErrorV1::MalformedEnvelope)
            );
        }
        let mut declared_oversized_ca = encoded;
        declared_oversized_ca[ca_length_offset..ca_length_offset + 4].copy_from_slice(
            &u32::try_from(ZK_X509_CA_ACCUMULATOR_MAX_PROOF_BYTES_V1 + 1)
                .expect("CA cap fits u32")
                .to_be_bytes(),
        );
        assert_eq!(
            decode_zk_x509_credential_envelope_v1(&declared_oversized_ca),
            Err(ZkX509CredentialProofErrorV1::ProofTooLarge)
        );
        let mut oversized_main = vec![0; ZK_X509_MAIN_AGGREGATE_MAX_PROOF_BYTES_V1 + 1];
        oversized_main[..4].copy_from_slice(&MAIN_AGGREGATE_MAGIC_V1);
        assert_eq!(
            encode_zk_x509_credential_envelope_v1(
                proof_instance_fixture_v1(),
                public,
                &oversized_main,
                b"X5C1",
                &joint_openings_fixture_v1()
            ),
            Err(ZkX509CredentialProofErrorV1::ProofTooLarge)
        );
        let mut oversized_ca = vec![0; ZK_X509_CA_ACCUMULATOR_MAX_PROOF_BYTES_V1 + 1];
        oversized_ca[..4].copy_from_slice(&CA_SUBPROOF_MAGIC_V1);
        assert_eq!(
            encode_zk_x509_credential_envelope_v1(
                proof_instance_fixture_v1(),
                public,
                b"X5M1",
                &oversized_ca,
                &joint_openings_fixture_v1()
            ),
            Err(ZkX509CredentialProofErrorV1::ProofTooLarge)
        );
    }
    #[test]
    fn exact_maximum_envelope_includes_the_single_authoritative_outer_frame() {
        assert_eq!(ZK_X509_CREDENTIAL_ENVELOPE_FRAMING_BYTES_V1, 4_348);
        assert_eq!(ZK_X509_MAXIMUM_ENCODED_X5S1_BYTES_V1, 9_412_944);
        assert_eq!(ZK_X509_MAIN_AGGREGATE_MAX_PROOF_BYTES_V1, 7_934_010);
        assert_eq!(
            ZK_X509_MAX_PROOF_BYTES_V1 - ZK_X509_MAXIMUM_ENCODED_X5S1_BYTES_V1,
            24_240
        );
        let maximum_inner = ZK_X509_MAIN_PRE_DEEP_MAXIMUM_BYTES_V1
            + ZK_X509_CA_PRE_DEEP_MAXIMUM_BYTES_V1
            + ZK_X509_DEEP_OPENING_BYTES_V1
            + ZK_X509_CA_FRAME_BYTES_V1
            + ZK_X509_MAIN_FRAME_BYTES_V1;
        assert_eq!(
            maximum_inner as usize + ZK_X509_CREDENTIAL_ENVELOPE_FRAMING_BYTES_V1,
            ZK_X509_MAXIMUM_ENCODED_X5S1_BYTES_V1 as usize
        );
        assert_eq!(
            zk_x509_credential_envelope_encoded_len_v1(
                maximum_inner as usize - ZK_X509_CA_ACCUMULATOR_MAX_PROOF_BYTES_V1,
                ZK_X509_CA_ACCUMULATOR_MAX_PROOF_BYTES_V1,
            ),
            Some(ZK_X509_MAXIMUM_ENCODED_X5S1_BYTES_V1 as usize)
        );
        const { assert!(ZK_X509_MAXIMUM_ENCODED_X5S1_BYTES_V1 < ZK_X509_MAX_PROOF_BYTES_V1) };
        let main_bytes = ZK_X509_MAIN_AGGREGATE_MAX_PROOF_BYTES_V1;
        assert!(
            maximum_inner as usize - ZK_X509_CA_ACCUMULATOR_MAX_PROOF_BYTES_V1 <= main_bytes,
            "the complete MAIN opening schedule fits its reserved envelope allowance"
        );
        let mut main = vec![0_u8; main_bytes];
        let mut ca = vec![0_u8; ZK_X509_CA_ACCUMULATOR_MAX_PROOF_BYTES_V1];
        main[..4].copy_from_slice(&MAIN_AGGREGATE_MAGIC_V1);
        ca[..4].copy_from_slice(&CA_SUBPROOF_MAGIC_V1);
        let encoded = encode_zk_x509_credential_envelope_v1(
            proof_instance_fixture_v1(),
            public(3),
            &main,
            &ca,
            &joint_openings_fixture_v1(),
        )
        .expect("exact maximum outer envelope");
        assert_eq!(encoded.len(), ZK_X509_MAX_PROOF_BYTES_V1 as usize);
        drop(encoded);
        main.push(0);
        assert_eq!(
            encode_zk_x509_credential_envelope_v1(
                proof_instance_fixture_v1(),
                public(3),
                &main,
                &ca,
                &joint_openings_fixture_v1()
            ),
            Err(ZkX509CredentialProofErrorV1::ProofTooLarge)
        );
    }
    #[test]
    fn joint_original_openings_roundtrip_and_reject_every_noncanonical_coordinate() {
        use crate::privacy_engines::transparent_stark::GoldilocksFp4V1 as E;
        let values = JointOriginalOpeningsV1 {
            main: core::array::from_fn(|i| E::canonical([1 + i as u64, 2, 3, 4]).unwrap()),
            ca: core::array::from_fn(|i| E::canonical([100 + i as u64, 5, 6, 7]).unwrap()),
        };
        let bytes = values.encode_v1().unwrap();
        let encoded = encode_zk_x509_credential_envelope_v1(
            proof_instance_fixture_v1(),
            public(9),
            b"X5M1",
            b"X5C1",
            &bytes,
        )
        .unwrap();
        assert_eq!(
            decode_zk_x509_credential_envelope_v1(&encoded)
                .unwrap()
                .joint_openings,
            values
        );
        for word in 0..132 * 4 {
            let mut changed = encoded.clone();
            let start = PUBLIC_HEADER_BYTES_V1 + word * 8;
            changed[start..start + 8].fill(255);
            assert_eq!(
                decode_zk_x509_credential_envelope_v1(&changed),
                Err(ZkX509CredentialProofErrorV1::MalformedEnvelope)
            );
        }
        for length in [0, 1, bytes.len() - 1, bytes.len() + 1] {
            assert_eq!(
                encode_zk_x509_credential_envelope_v1(
                    proof_instance_fixture_v1(),
                    public(9),
                    b"X5M1",
                    b"X5C1",
                    &vec![0; length]
                ),
                Err(ZkX509CredentialProofErrorV1::MalformedEnvelope)
            );
        }
    }

    #[test]
    fn credential_rejects_layout_without_mandatory_joint_openings() {
        let (_, mut encoded) = proof_fixture();
        encoded.drain(PUBLIC_HEADER_BYTES_V1..FIXED_HEADER_BYTES_V1);
        assert_eq!(
            decode_zk_x509_credential_envelope_v1(&encoded),
            Err(ZkX509CredentialProofErrorV1::MalformedEnvelope)
        );
    }
}
