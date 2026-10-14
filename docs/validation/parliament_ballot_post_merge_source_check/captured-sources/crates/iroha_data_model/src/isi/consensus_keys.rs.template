//! Consensus key lifecycle instructions.
use super::*;
/// Register a consensus/committee key with lifecycle metadata.
#[derive(
    Debug,
    Clone,
    PartialEq,
    Eq,
    PartialOrd,
    Ord,
    getset::Getters,
    Decode,
    Encode,
    IntoSchema,
    crate :: DeriveJsonSerialize,
    crate :: DeriveJsonDeserialize,
)]
#[getset(get = "pub")]
#[derive(norito::NoritoSchema)]
#[norito_schema(name = "iroha_data_model::isi::consensus_keys::RegisterConsensusKey")]
pub struct RegisterConsensusKey {
    /// Identifier of the key being registered.
    pub id: crate::consensus::ConsensusKeyId,
    /// Key record to register.
    pub record: crate::consensus::ConsensusKeyRecord,
}
/// Rotate an existing consensus key by registering a successor and marking the old one retiring.
#[derive(
    Debug,
    Clone,
    PartialEq,
    Eq,
    PartialOrd,
    Ord,
    getset::Getters,
    Decode,
    Encode,
    IntoSchema,
    crate :: DeriveJsonSerialize,
    crate :: DeriveJsonDeserialize,
)]
#[getset(get = "pub")]
#[derive(norito::NoritoSchema)]
#[norito_schema(name = "iroha_data_model::isi::consensus_keys::RotateConsensusKey")]
pub struct RotateConsensusKey {
    /// Identifier of the key being rotated out.
    pub id: crate::consensus::ConsensusKeyId,
    /// Replacement key record (must target the same role).
    pub record: crate::consensus::ConsensusKeyRecord,
}
/// Disable an existing consensus key.
#[derive(
    Debug,
    Clone,
    PartialEq,
    Eq,
    PartialOrd,
    Ord,
    getset::Getters,
    Decode,
    Encode,
    IntoSchema,
    crate :: DeriveJsonSerialize,
    crate :: DeriveJsonDeserialize,
)]
#[getset(get = "pub")]
#[derive(norito::NoritoSchema)]
#[norito_schema(name = "iroha_data_model::isi::consensus_keys::DisableConsensusKey")]
pub struct DisableConsensusKey {
    /// Identifier of the key being disabled.
    pub id: crate::consensus::ConsensusKeyId,
}

/// Exact threshold-key lifecycle action authorized by the block-height validator roster.
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
#[norito(tag = "action", content = "value", rename_all = "snake_case")]
#[derive(norito::NoritoSchema)]
#[norito_schema(name = "iroha_data_model::isi::consensus_keys::ThresholdKeyLifecycleActionV1")]
pub enum ThresholdKeyLifecycleActionV1 {
    /// Finalize the exact frozen committee's pending global-beacon transcript.
    ///
    /// A pending key stays inactive until the all-seat-ready committee boundary
    /// is certified. The first bootstrap transcript activates at the next height
    /// only when it matches the unchanged authenticated genesis authority.
    FinalizeGlobalBeaconKey,
    /// Install a finalized Parliament TLE key session for next-height activation.
    ///
    /// Unlike the global beacon, the TLE session persists the same exact
    /// certificate roster as its release-share seat roster.
    InstallParliamentTleKey,
    /// Retire the exact active Parliament TLE key at the next height.
    ///
    /// Retirement authority is the certificate's effective-height roster and
    /// the expected active session remains an exact compare-and-set guard.
    RetireParliamentTleKey,
}

/// One exact-roster validator signature over a threshold-key lifecycle action.
#[derive(
    Debug,
    Clone,
    PartialEq,
    Eq,
    PartialOrd,
    Ord,
    getset::Getters,
    Decode,
    Encode,
    IntoSchema,
    crate :: DeriveJsonSerialize,
    crate :: DeriveJsonDeserialize,
)]
#[getset(get = "pub")]
#[derive(norito::NoritoSchema)]
#[norito_schema(name = "iroha_data_model::isi::consensus_keys::ThresholdKeyLifecycleSignatureV1")]
pub struct ThresholdKeyLifecycleSignatureV1 {
    /// Zero-based seat in the exact ordered authorization roster at block `H`.
    pub signer_index: u16,
    /// Signature over the canonical certificate preimage.
    pub signature: iroha_crypto::Signature,
}

/// Exact-roster quorum certificate for one threshold-key lifecycle action.
#[derive(
    Debug,
    Clone,
    PartialEq,
    Eq,
    PartialOrd,
    Ord,
    getset::Getters,
    Decode,
    Encode,
    IntoSchema,
    crate :: DeriveJsonSerialize,
    crate :: DeriveJsonDeserialize,
)]
#[getset(get = "pub")]
#[derive(norito::NoritoSchema)]
#[norito_schema(name = "iroha_data_model::isi::consensus_keys::ThresholdKeyLifecycleCertificateV1")]
pub struct ThresholdKeyLifecycleCertificateV1 {
    /// Fixed certificate layout version.
    pub version: u16,
    /// Exact lifecycle action.
    pub action: ThresholdKeyLifecycleActionV1,
    /// Exact active session against which this action is authorized.
    ///
    /// `None` is valid only for the first install in this key family. This is
    /// a committee-certified compare-and-set guard, not a registrar hint.
    pub expected_active_session_id: Option<[u8; 32]>,
    /// Block height `H` at which authorization is verified and the action executes.
    ///
    /// Pending beacon finalization does not activate the key. Bootstrap and TLE
    /// lifecycle activation or retirement take effect at `H + 1`.
    pub effective_height: u64,
    /// Exact genesis-derived network identity.
    pub network_id: crate::NetworkId,
    /// Hash of the exact ordered validator roster authorizing this action at `H`.
    ///
    /// For global-beacon finalization, `public_state` commits the exact frozen
    /// future roster, without changing the current authorization roster.
    pub roster_hash: [u8; 32],
    /// Exact authorization-roster committee size at `H`.
    pub committee_size: u16,
    /// Exact `2f + 1` threshold of the authorization roster at `H`.
    pub quorum: u16,
    /// Exact threshold-key session identifier.
    pub session_id: [u8; 32],
    /// Exact finalized DKG transcript commitment.
    pub transcript_hash: [u8; 32],
    /// Canonical Core public-state bytes for install actions; empty for retirement.
    ///
    /// The certificate preimage commits the exact byte length and hash, so an
    /// install target cannot be changed after the roster signs it.
    pub public_state: Vec<u8>,
    /// Strictly ordered unique exact-roster signatures.
    pub signatures: Vec<ThresholdKeyLifecycleSignatureV1>,
}

super::isi! {
    /// Apply one effective-height-roster-certified threshold-key lifecycle action.
    #[derive (crate :: DeriveJsonSerialize , crate :: DeriveJsonDeserialize)]
    #[norito_schema(name = "iroha_data_model::isi::consensus_keys::ApplyThresholdKeyLifecycleCertificateV1")]
    pub struct ApplyThresholdKeyLifecycleCertificateV1 {
        /// Full proof-carrying exact-roster lifecycle certificate.
        pub certificate: ThresholdKeyLifecycleCertificateV1,
    }
}

impl crate::seal::Instruction for ApplyThresholdKeyLifecycleCertificateV1 {}
impl crate::seal::Instruction for RegisterConsensusKey {}
impl crate::seal::Instruction for RotateConsensusKey {}
impl crate::seal::Instruction for DisableConsensusKey {}
fn consensus_key_decode_flags() -> u8 {
    norito::core::effective_decode_flags().unwrap_or_else(norito::core::default_encode_flags)
}
macro_rules! impl_decode_key_record_instruction {
    ($ty:ident) => {
        impl<'a> norito::core::DecodeFromSlice<'a> for $ty {
            fn decode_from_slice(bytes: &'a [u8]) -> Result<(Self, usize), norito::core::Error> {
                let flags = consensus_key_decode_flags();
                let mut offset = 0usize;
                let id = super::decode_aos_canonical_field::<crate::consensus::ConsensusKeyId>(
                    super::read_aos_field(bytes, &mut offset, flags)?,
                    flags,
                )?;
                let record = super::decode_aos_canonical_field::<
                    crate::consensus::ConsensusKeyRecord,
                >(super::read_aos_field(bytes, &mut offset, flags)?, flags)?;
                if offset != bytes.len() {
                    return Err(norito::core::Error::LengthMismatch);
                }
                norito::core::note_payload_access(bytes, offset);
                Ok((Self { id, record }, offset))
            }
        }
    };
}
impl_decode_key_record_instruction!(RegisterConsensusKey);
impl_decode_key_record_instruction!(RotateConsensusKey);
impl<'a> norito::core::DecodeFromSlice<'a> for DisableConsensusKey {
    fn decode_from_slice(bytes: &'a [u8]) -> Result<(Self, usize), norito::core::Error> {
        let flags = consensus_key_decode_flags();
        let mut offset = 0usize;
        let id = super::decode_aos_canonical_field::<crate::consensus::ConsensusKeyId>(
            super::read_aos_field(bytes, &mut offset, flags)?,
            flags,
        )?;
        if offset != bytes.len() {
            return Err(norito::core::Error::LengthMismatch);
        }
        norito::core::note_payload_access(bytes, offset);
        Ok((Self { id }, offset))
    }
}
impl<'a> norito::core::DecodeFromSlice<'a> for ApplyThresholdKeyLifecycleCertificateV1 {
    fn decode_from_slice(bytes: &'a [u8]) -> Result<(Self, usize), norito::core::Error> {
        let flags = consensus_key_decode_flags();
        let mut offset = 0usize;
        let certificate = super::decode_aos_canonical_field::<ThresholdKeyLifecycleCertificateV1>(
            super::read_aos_field(bytes, &mut offset, flags)?,
            flags,
        )?;
        if offset != bytes.len() {
            return Err(norito::core::Error::LengthMismatch);
        }
        norito::core::note_payload_access(bytes, offset);
        Ok((Self { certificate }, offset))
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    use crate::consensus::{
        ConsensusKeyId, ConsensusKeyRecord, ConsensusKeyRole, ConsensusKeyStatus,
    };
    use crate::isi::test_support::{assert_registry_decodes, assert_slice_roundtrip};
    use iroha_crypto::{Algorithm, Hash, HashOf, KeyPair, PublicKey, Signature};
    fn public_key(seed: u8) -> PublicKey {
        let key_pair = KeyPair::try_from_seed(vec![seed; 32], Algorithm::Ed25519)
            .expect("derive checked consensus-key fixture keypair");
        key_pair.public_key().clone()
    }
    fn key_id(name: &str) -> ConsensusKeyId {
        ConsensusKeyId::new(ConsensusKeyRole::Validator, name)
    }
    fn record(name: &str, seed: u8) -> ConsensusKeyRecord {
        ConsensusKeyRecord {
            id: key_id(name),
            public_key: public_key(seed),
            pop: Some(vec![0x01, 0x02]),
            activation_height: 10,
            expiry_height: Some(100),
            replaces: None,
            status: ConsensusKeyStatus::Pending,
        }
    }
    fn threshold_key_lifecycle_instruction() -> ApplyThresholdKeyLifecycleCertificateV1 {
        let signer = KeyPair::random();
        ApplyThresholdKeyLifecycleCertificateV1 {
            certificate: ThresholdKeyLifecycleCertificateV1 {
                version: 1,
                action: ThresholdKeyLifecycleActionV1::RetireParliamentTleKey,
                expected_active_session_id: Some([0x63; 32]),
                effective_height: 19,
                network_id: crate::NetworkId::from_genesis_hash(
                    HashOf::<crate::block::BlockHeader>::from_untyped_unchecked(Hash::prehashed(
                        [0x61; Hash::LENGTH],
                    )),
                ),
                roster_hash: [0x62; 32],
                committee_size: 4,
                quorum: 3,
                session_id: [0x63; 32],
                transcript_hash: [0x64; 32],
                public_state: Vec::new(),
                signatures: vec![ThresholdKeyLifecycleSignatureV1 {
                    signer_index: 0,
                    signature: Signature::try_new(signer.private_key(), b"codec fixture")
                        .expect("sign codec fixture"),
                }],
            },
        }
    }
    #[test]
    fn consensus_key_decode_from_slice_roundtrips() {
        assert_slice_roundtrip(RegisterConsensusKey {
            id: key_id("validator_a"),
            record: record("validator_a", 0x71),
        });
        assert_slice_roundtrip(RotateConsensusKey {
            id: key_id("validator_a"),
            record: ConsensusKeyRecord {
                replaces: Some(key_id("validator_a")),
                ..record("validator_b", 0x72)
            },
        });
        assert_slice_roundtrip(DisableConsensusKey {
            id: key_id("validator_a"),
        });
        assert_slice_roundtrip(threshold_key_lifecycle_instruction());
    }
    #[test]
    fn consensus_key_registry_decodes_stable_ids() {
        let registry = crate::isi::InstructionRegistry::new()
            .register_with_id_slice::<RegisterConsensusKey>("consensus::RegisterConsensusKey")
            .register_with_id_slice::<RotateConsensusKey>("consensus::RotateConsensusKey")
            .register_with_id_slice::<DisableConsensusKey>("consensus::DisableConsensusKey")
            .register_with_id_slice::<ApplyThresholdKeyLifecycleCertificateV1>(
                "iroha.consensus.threshold-key-lifecycle.apply.v1",
            );
        assert_registry_decodes(
            &registry,
            "consensus::RegisterConsensusKey",
            RegisterConsensusKey {
                id: key_id("validator_a"),
                record: record("validator_a", 0x73),
            },
        );
        assert_registry_decodes(
            &registry,
            "iroha.consensus.threshold-key-lifecycle.apply.v1",
            threshold_key_lifecycle_instruction(),
        );
        assert_registry_decodes(
            &registry,
            "consensus::RotateConsensusKey",
            RotateConsensusKey {
                id: key_id("validator_a"),
                record: ConsensusKeyRecord {
                    replaces: Some(key_id("validator_a")),
                    ..record("validator_c", 0x74)
                },
            },
        );
        assert_registry_decodes(
            &registry,
            "consensus::DisableConsensusKey",
            DisableConsensusKey {
                id: key_id("validator_a"),
            },
        );
    }
}

#[cfg(test)]
mod captured_consensus_keys_ordinary_schema_tests;
