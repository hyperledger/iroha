//! Fail-closed first-release ZK-ACE authorization engine.
//!
//! The low-level proof wire is the dedicated masked execution-trace STARK in `zk_ace_stark`. Its
//! AIR proves twelve public outputs: six independently initialized, independently constanted
//! Poseidon-x7 Goldilocks lanes for the identity commitment and six separately domain-bound lanes
//! for the replay nullifier. It commits an independent full-space zero-knowledge mask before
//! batching challenges, links the AIR at one quartic-extension DEEP point, runs Fp4 FRI, and carries
//! no caller-selected backend, verifier key, parameter record, or legacy generic envelope.
//!
//! Every STARK commitment, Fiat--Shamir challenge, FRI phase, and query index uses the shared typed
//! opaque SHA3-384 digest. The final binary-FRI geometry has an 8x LDE, Fp4 challenges, and 136
//! distinct queries selected without replacement. Production remains fail-closed until an
//! independent qROM Fiat--Shamir reduction and implementation review are registered.
#[cfg(test)]
use super::prover_randomness::TRY_CRYPTO_PROVER_RANDOMNESS_POLICY_V1;
use super::zk_ace_stark::{
    AIR_PUBLIC_TRANSCRIPT_SCHEMA_V1, COMPILED_STARK_PROFILE_DESCRIPTOR_V1, MAX_PROOF_BYTES,
    ZkAceAirRelationInputsV1, ZkAceStarkError, prove_zk_ace_stark_v1_with_rng,
    verify_zk_ace_stark_v1,
};
#[cfg(test)]
use iroha_data_model::zk::ZK_ACE_PQ_AUTHORIZATION_V1_CIRCUIT_ID;
use iroha_data_model::{
    NetworkId,
    privacy::{
        GoldilocksDigest384V1, PrivacyConsensusLimitsV1, PrivacyStatementV1,
        PrivacyZkAceIdentityCommitmentV1, PrivacyZkAceReplayNullifierV1,
    },
    zk::{
        ZK_ACE_PQ_AUTHORIZATION_V1_ACTION_TRANSFER, ZK_ACE_PQ_AUTHORIZATION_V1_DOMAIN_TAG,
        ZkAcePrivacyPublicInputsV1, derive_zk_ace_identity_commitment,
        derive_zk_ace_privacy_authorization_digest, derive_zk_ace_replay_nullifier,
        derive_zk_ace_transfer_digest,
    },
};
use rand::TryCryptoRng;
/// Fallible cryptographic RNG contract accepted by the native prover.
pub use rand::TryCryptoRng as ZkAceTryCryptoRngV1;
/// Fallible RNG core contract re-exported for deterministic/adversarial tests
/// without forcing transaction-builder crates to depend on `rand`.
pub use rand::TryRngCore as ZkAceTryRngCoreV1;
#[cfg(test)]
use sha2::{Digest as _, Sha256};
use thiserror::Error;
use zeroize::Zeroize;
/// Secret witness shape retained for the fail-closed native ZK-ACE engine.
///
/// It intentionally implements neither `Debug`, `Clone`, `Copy`, nor any
/// serialization trait. The engine owns the three secrets and overwrites them
/// when the witness leaves scope on every success and error path.
pub struct ZkAcePrivacyWitnessV1 {
    pub(super) identity_root: [u8; 32],
    pub(super) identity_blinding: [u8; 32],
    pub(super) replay_secret: [u8; 32],
}
impl ZkAcePrivacyWitnessV1 {
    /// Validate and take ownership of one native witness.
    ///
    /// # Errors
    ///
    /// Rejects any all-zero secret component before proof work or entropy use.
    pub fn try_new(
        identity_root: [u8; 32],
        identity_blinding: [u8; 32],
        replay_secret: [u8; 32],
    ) -> Result<Self, ZkAcePrivacyWitnessValidationErrorV1> {
        let witness = Self {
            identity_root,
            identity_blinding,
            replay_secret,
        };
        witness.validate()?;
        Ok(witness)
    }
    fn validate(&self) -> Result<(), ZkAcePrivacyWitnessValidationErrorV1> {
        if self.identity_root == [0; 32] {
            return Err(ZkAcePrivacyWitnessValidationErrorV1::ZeroIdentityRoot);
        }
        if self.identity_blinding == [0; 32] {
            return Err(ZkAcePrivacyWitnessValidationErrorV1::ZeroIdentityBlinding);
        }
        if self.replay_secret == [0; 32] {
            return Err(ZkAcePrivacyWitnessValidationErrorV1::ZeroReplaySecret);
        }
        Ok(())
    }
    /// Derive the six-lane public identity commitment under its fixed domain.
    #[must_use]
    pub fn identity_commitment_v1(&self) -> PrivacyZkAceIdentityCommitmentV1 {
        derive_zk_ace_identity_commitment(
            &self.identity_root,
            &self.identity_blinding,
            ZK_ACE_PQ_AUTHORIZATION_V1_DOMAIN_TAG,
        )
    }
    /// Derive the typed replay nullifier without exposing the replay secret.
    #[must_use]
    pub fn replay_nullifier_v1(
        &self,
        authorization_digest: &GoldilocksDigest384V1,
        network_id: &NetworkId,
    ) -> PrivacyZkAceReplayNullifierV1 {
        derive_zk_ace_replay_nullifier(
            &self.replay_secret,
            authorization_digest,
            network_id,
            ZK_ACE_PQ_AUTHORIZATION_V1_ACTION_TRANSFER,
            ZK_ACE_PQ_AUTHORIZATION_V1_DOMAIN_TAG,
        )
    }
}
impl Drop for ZkAcePrivacyWitnessV1 {
    fn drop(&mut self) {
        self.zeroize();
    }
}
impl Zeroize for ZkAcePrivacyWitnessV1 {
    fn zeroize(&mut self) {
        self.identity_root.zeroize();
        self.identity_blinding.zeroize();
        self.replay_secret.zeroize();
    }
}
/// Rejected native witness shape.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Error)]
pub enum ZkAcePrivacyWitnessValidationErrorV1 {
    /// The external identity root is the all-zero sentinel.
    #[error("ZK-ACE identity root witness must be non-zero")]
    ZeroIdentityRoot,
    /// The identity blinding is the all-zero sentinel.
    #[error("ZK-ACE identity blinding witness must be non-zero")]
    ZeroIdentityBlinding,
    /// The replay secret is the all-zero sentinel.
    #[error("ZK-ACE replay secret witness must be non-zero")]
    ZeroReplaySecret,
}
/// Transcript family frozen into the dedicated proof implementation.
pub const ZK_ACE_PRIVACY_TRANSCRIPT_LABEL_V1: &str = "iroha:privacy:zk-ace:transparent-stark:v1";
/// Whether the sole first-release ZK-ACE engine is production-qualified.
pub const ZK_ACE_FULL_ENGINE_AVAILABLE_V1: bool = false;
// TODO: Enable the production boundary only after the final qROM Fiat--Shamir
// reduction, SHA3-384 outer-hash and constrained Poseidon collision/multi-target accounting, and independent
// implementation review are registered against this exact profile digest.
/// Outstanding release evidence required before ZK-ACE can be activated.
pub const ZK_ACE_QROM_CERTIFICATION_BLOCKER_V1: &[u8] = b"independent-qrom-fiat-shamir-reduction+sha3-384-outer-and-constrained-poseidon-collision-and-multi-target-accounting+implementation-review-not-yet-registered";
/// Source and relation description frozen into the compiled profile.
pub const ZK_ACE_SOURCE_PROFILE_V1: &[u8] = b"iroha-native-rust:zk-ace:typed-statement+trusted-genesis:type-name-independent-ordered-length-framed-public-transcript:private-witness:masked-poseidon-x7-execution-trace:outer-sha3-384-opaque48-v1:identity-lanes6-independent:replay-lanes6-independent:typed-catalog+protocol+profile+tree-role+phase+level+index+counter-byte-frames:fp4-deep-ali:independent-pre-batching-fri-mask:binary-fp4-fri:blowup8:queries136:classical-rom128:qrom-certification-pending:producer=preflight+rand0.9-trycrypto-fixed64-reservoir-zeroize-poison-error-or-unwind+self-verify:v1";
/// Exact native proof wire description frozen into the compiled profile.
pub const ZK_ACE_PROOF_WIRE_V1: &[u8] =
    b"ZKA1:fixed-shape:scalars-big-endian:outer-digest48-opaque-bytes:2131222:strict-exact:no-lengths:no-generic-envelope";
/// Exact low-level AIR relation schema frozen into the compiled profile.
pub const ZK_ACE_AIR_RELATION_SCHEMA_V1: &[u8] = AIR_PUBLIC_TRANSCRIPT_SCHEMA_V1;
/// Exact typed authorization projection frozen into the compiled profile.
pub const ZK_ACE_AUTHORIZATION_PROJECTION_V1: &[u8] = b"norito:zk-ace-pq-authorization-statement-v1:replay-nullifier-zero|transaction-intent-bound|trusted-genesis-bound";
/// Canonical six-lane parameter-asset digest consumed through `fastpq_prover`.
///
/// The SHA3-256 value authenticates all six generated initial states and round
/// constants together with the shared MDS matrix.
pub const ZK_ACE_DIGEST384_PARAMETER_SHA3_256_V1: &str =
    "84c5055b47cc7289835e0a5f31d4563849244ffddbf51f5d67b1db95222ce3e6";
/// Exact independent-lane Poseidon profile used by the native hash and AIR.
pub const ZK_ACE_POSEIDON_PROFILE_V1: &[u8] = b"poseidon-x7-goldilocks-digest384:lanes6-independent:width3:rate2:capacity1:full8:partial57:parameter-generator=shake256-rejection-sampling-u64le-below-goldilocks-v1:parameters-sha3-256=84c5055b47cc7289835e0a5f31d4563849244ffddbf51f5d67b1db95222ce3e6";
/// Native and consensus proof byte ceiling.
pub const ZK_ACE_PRIVACY_MAX_PROOF_BYTES_V1: u32 = MAX_PROOF_BYTES as u32;
/// Frozen SHA-256 self-authentication digest of every verifier-profile field below.
///
/// SHA-256 is retained here only as a non-STARK artifact checksum. It is never
/// used by a Merkle tree, Fiat--Shamir transcript, challenge, FRI phase, or
/// query sampler.
pub const ZK_ACE_COMPILED_PROFILE_DIGEST_V1: [u8; 32] = [
    0xb3, 0xee, 0xcf, 0x3d, 0x57, 0x82, 0x6f, 0xbc, 0x6f, 0xa0, 0xdc, 0x68, 0x11, 0x63, 0x17, 0x71,
    0x62, 0x97, 0x71, 0xee, 0x1f, 0x30, 0xe7, 0x97, 0x57, 0xd9, 0x30, 0x09, 0xf9, 0xe1, 0xeb, 0x4d,
];
/// Return the frozen digest of the exact verifier profile.
#[must_use]
pub const fn zk_ace_compiled_profile_digest_v1() -> [u8; 32] {
    ZK_ACE_COMPILED_PROFILE_DIGEST_V1
}
/// Return the complete human-auditable compiled algebraic profile.
#[must_use]
pub const fn zk_ace_stark_profile_descriptor_v1() -> &'static [u8] {
    COMPILED_STARK_PROFILE_DESCRIPTOR_V1
}
#[cfg(test)]
fn recompute_zk_ace_compiled_profile_digest_v1() -> [u8; 32] {
    let mut hasher = Sha256::new();
    hash_field(&mut hasher, b"iroha.privacy.zk-ace.compiled-profile.v1");
    hash_field(&mut hasher, ZK_ACE_SOURCE_PROFILE_V1);
    hash_field(&mut hasher, TRY_CRYPTO_PROVER_RANDOMNESS_POLICY_V1);
    hash_field(&mut hasher, ZK_ACE_PROOF_WIRE_V1);
    hash_field(&mut hasher, ZK_ACE_AIR_RELATION_SCHEMA_V1);
    hash_field(&mut hasher, ZK_ACE_AUTHORIZATION_PROJECTION_V1);
    hash_field(
        &mut hasher,
        ZK_ACE_DIGEST384_PARAMETER_SHA3_256_V1.as_bytes(),
    );
    hash_field(&mut hasher, ZK_ACE_POSEIDON_PROFILE_V1);
    hash_field(&mut hasher, ZK_ACE_QROM_CERTIFICATION_BLOCKER_V1);
    hash_field(
        &mut hasher,
        ZK_ACE_PQ_AUTHORIZATION_V1_CIRCUIT_ID.as_bytes(),
    );
    hash_field(&mut hasher, ZK_ACE_PRIVACY_TRANSCRIPT_LABEL_V1.as_bytes());
    hash_field(&mut hasher, zk_ace_stark_profile_descriptor_v1());
    hash_field(
        &mut hasher,
        &ZK_ACE_PRIVACY_MAX_PROOF_BYTES_V1.to_be_bytes(),
    );
    hasher.finalize().into()
}
#[cfg(test)]
fn hash_field(hasher: &mut Sha256, field: &[u8]) {
    hasher.update(
        u64::try_from(field.len())
            .expect("fixed profile field length fits u64")
            .to_be_bytes(),
    );
    hasher.update(field);
}
fn project_air_relation_inputs_v1(
    public_inputs: &ZkAcePrivacyPublicInputsV1,
    authorization_digest: GoldilocksDigest384V1,
) -> Result<ZkAceAirRelationInputsV1, ZkAceNativeErrorV1> {
    let statement = &public_inputs.statement;
    let transfer_digest = derive_zk_ace_transfer_digest(
        &statement.source,
        &statement.destination,
        &statement.asset_definition_id,
        statement.amount,
        &statement.context.network_id,
        ZK_ACE_PQ_AUTHORIZATION_V1_ACTION_TRANSFER,
        statement.policy_digest.as_bytes(),
    )
    .map_err(|_| ZkAceNativeErrorV1::PublicInputsEncoding)?;
    Ok(ZkAceAirRelationInputsV1::transparent_transfer(
        statement.identity_commitment.into_bytes(),
        transfer_digest.to_le_bytes(),
        authorization_digest.to_le_bytes(),
        statement.context.network_id,
        statement.replay_nullifier.into_bytes(),
        statement.policy_digest.into_bytes(),
        statement.source.clone(),
        statement.destination.clone(),
        statement.asset_definition_id.clone(),
        statement.amount,
    ))
}
fn validate_privacy_witness_relation(
    public_inputs: &ZkAcePrivacyPublicInputsV1,
    witness: &ZkAcePrivacyWitnessV1,
    authorization_digest: &GoldilocksDigest384V1,
) -> Result<(), ZkAceNativeErrorV1> {
    let statement = &public_inputs.statement;
    if witness.identity_commitment_v1() != statement.identity_commitment
        || witness.replay_nullifier_v1(authorization_digest, &statement.context.network_id)
            != statement.replay_nullifier
    {
        return Err(ZkAceNativeErrorV1::WitnessRelationMismatch);
    }
    Ok(())
}
/// Fail closed at the production ZK-ACE proving boundary.
///
/// # Errors
///
/// Returns [`ZkAceNativeErrorV1::EngineUnavailable`] before validation or
/// entropy use while qROM qualification remains incomplete.
pub fn prove_zk_ace_privacy_v1_with_rng<R: TryCryptoRng + ?Sized>(
    public_inputs: &ZkAcePrivacyPublicInputsV1,
    witness: &ZkAcePrivacyWitnessV1,
    randomness: &mut R,
) -> Result<Vec<u8>, ZkAceNativeErrorV1> {
    if !ZK_ACE_FULL_ENGINE_AVAILABLE_V1 {
        return Err(ZkAceNativeErrorV1::EngineUnavailable);
    }
    validate_privacy_public_inputs(public_inputs)?;
    witness
        .validate()
        .map_err(ZkAceNativeErrorV1::InvalidWitness)?;
    let authorization_digest = derive_zk_ace_privacy_authorization_digest(public_inputs)
        .map_err(|_| ZkAceNativeErrorV1::PublicInputsEncoding)?;
    validate_privacy_witness_relation(public_inputs, witness, &authorization_digest)?;
    let relation_inputs = project_air_relation_inputs_v1(public_inputs, authorization_digest)?;
    prove_zk_ace_stark_v1_with_rng(&relation_inputs, witness, randomness).map_err(|error| {
        match error {
            ZkAceStarkError::WitnessRelation => ZkAceNativeErrorV1::WitnessRelationMismatch,
            ZkAceStarkError::RandomnessUnavailable => ZkAceNativeErrorV1::RandomnessUnavailable,
            ZkAceStarkError::RandomnessUnhealthy => ZkAceNativeErrorV1::UnhealthyRandomness,
            error => ZkAceNativeErrorV1::Prover {
                reason: error.to_string(),
            },
        }
    })
}
/// Fail closed before requesting operating-system entropy.
///
/// # Errors
///
/// Returns the same fail-closed result as
/// [`prove_zk_ace_privacy_v1_with_rng`].
pub fn prove_zk_ace_privacy_v1(
    public_inputs: &ZkAcePrivacyPublicInputsV1,
    witness: &ZkAcePrivacyWitnessV1,
) -> Result<Vec<u8>, ZkAceNativeErrorV1> {
    prove_zk_ace_privacy_v1_with_rng(public_inputs, witness, &mut rand::rngs::OsRng)
}
/// Fail closed at the production ZK-ACE verification boundary.
///
/// # Errors
///
/// Returns [`ZkAceNativeErrorV1::EngineUnavailable`] before proof parsing
/// while qROM qualification remains incomplete.
pub fn verify_zk_ace_privacy_v1(
    public_inputs: &ZkAcePrivacyPublicInputsV1,
    proof: &[u8],
    caller_max_proof_bytes: u32,
) -> Result<(), ZkAceNativeErrorV1> {
    if !ZK_ACE_FULL_ENGINE_AVAILABLE_V1 {
        return Err(ZkAceNativeErrorV1::EngineUnavailable);
    }
    validate_privacy_public_inputs(public_inputs)?;
    let effective_cap = caller_max_proof_bytes.min(ZK_ACE_PRIVACY_MAX_PROOF_BYTES_V1);
    let proof_len = u32::try_from(proof.len()).map_err(|_| ZkAceNativeErrorV1::ProofTooLarge {
        bytes: u64::try_from(proof.len()).unwrap_or(u64::MAX),
        max: effective_cap,
    })?;
    if proof_len == 0 {
        return Err(ZkAceNativeErrorV1::EmptyProof);
    }
    if proof_len > effective_cap {
        return Err(ZkAceNativeErrorV1::ProofTooLarge {
            bytes: u64::from(proof_len),
            max: effective_cap,
        });
    }
    let authorization_digest = derive_zk_ace_privacy_authorization_digest(public_inputs)
        .map_err(|_| ZkAceNativeErrorV1::PublicInputsEncoding)?;
    let relation_inputs = project_air_relation_inputs_v1(public_inputs, authorization_digest)?;
    verify_zk_ace_stark_v1(&relation_inputs, proof)
        .map_err(|_| ZkAceNativeErrorV1::VerificationFailed)
}
fn validate_privacy_public_inputs(
    public_inputs: &ZkAcePrivacyPublicInputsV1,
) -> Result<(), ZkAceNativeErrorV1> {
    if public_inputs.version != 1 {
        return Err(ZkAceNativeErrorV1::PublicInputVersionMismatch {
            actual: public_inputs.version,
        });
    }
    if public_inputs.genesis_hash == [0; 32] {
        return Err(ZkAceNativeErrorV1::ZeroGenesisHash);
    }
    PrivacyStatementV1::ZkAcePqAuthorizationV1(public_inputs.statement.clone())
        .validate(&PrivacyConsensusLimitsV1::taira_default())
        .map_err(|_| ZkAceNativeErrorV1::InvalidStatement)
}
/// Native ZK-ACE construction or verification failure.
#[derive(Debug, PartialEq, Eq, Error)]
pub enum ZkAceNativeErrorV1 {
    /// The qROM reduction and independent review have not been registered.
    #[error("ZK-ACE native engine is unavailable pending qROM certification")]
    EngineUnavailable,
    /// The public-input wrapper is not the exact first-release schema.
    #[error("ZK-ACE public-input version must be 1, got {actual}")]
    PublicInputVersionMismatch {
        /// Rejected version.
        actual: u16,
    },
    /// Trusted genesis binding is absent.
    #[error("ZK-ACE trusted genesis hash must be non-zero")]
    ZeroGenesisHash,
    /// The typed privacy statement failed its closed validation rules.
    #[error("ZK-ACE typed privacy statement is invalid")]
    InvalidStatement,
    /// A secret component used the all-zero sentinel.
    #[error("ZK-ACE private witness is invalid: {0}")]
    InvalidWitness(ZkAcePrivacyWitnessValidationErrorV1),
    /// A structurally valid witness does not open the public commitment or
    /// derive the public replay nullifier.
    #[error("ZK-ACE private witness does not satisfy the public commitment/nullifier relation")]
    WitnessRelationMismatch,
    /// Canonical public-input projection failed.
    #[error("ZK-ACE public inputs could not be encoded canonically")]
    PublicInputsEncoding,
    /// The proof payload is empty.
    #[error("ZK-ACE proof must not be empty")]
    EmptyProof,
    /// The proof payload exceeds the effective native or caller ceiling.
    #[error("ZK-ACE proof is too large: {bytes} bytes exceeds {max}")]
    ProofTooLarge {
        /// Observed proof length.
        bytes: u64,
        /// Effective proof ceiling.
        max: u32,
    },
    /// The injected or operating-system cryptographic source failed.
    #[error("ZK-ACE prover randomness is unavailable")]
    RandomnessUnavailable,
    /// The cryptographic source emitted a catastrophic repeated pattern.
    #[error("ZK-ACE prover randomness failed its health check")]
    UnhealthyRandomness,
    /// Native construction or its mandatory self-check failed.
    #[error("ZK-ACE prover failed: {reason}")]
    Prover {
        /// Fail-closed diagnostic.
        reason: String,
    },
    /// The dedicated native verifier rejected the proof.
    #[error("ZK-ACE native transparent STARK verification failed")]
    VerificationFailed,
}
#[cfg(test)]
mod tests {
    use super::*;
    use iroha_crypto::{Algorithm, KeyPair};
    use iroha_data_model::{
        NetworkId,
        account::AccountId,
        asset::AssetDefinitionId,
        privacy::{
            PrivacyEngineManifestDigestV1, PrivacyParameterDigestV1, PrivacyParameterIdV1,
            PrivacyPolicyDigestV1, PrivacyPolicyIdV1, PrivacyStatementContextV1,
            PrivacyStatementSchemaDigestV1, PrivacyTransactionIntentDigestV1,
            PrivacyVerifierDigestV1, ZkAcePqAuthorizationStatementV1,
        },
        zk::{
            ZK_ACE_PQ_AUTHORIZATION_V1_ACTION_TRANSFER, ZK_ACE_PQ_AUTHORIZATION_V1_DOMAIN_TAG,
            derive_zk_ace_identity_commitment, derive_zk_ace_privacy_authorization_digest,
            derive_zk_ace_replay_nullifier,
        },
    };
    use iroha_model_base::domain::DomainId;
    use iroha_model_base::name::Name;
    use rand::{TryCryptoRng, TryRngCore};
    use std::str::FromStr as _;
    #[derive(Debug)]
    struct InjectedEntropyError;
    impl core::fmt::Display for InjectedEntropyError {
        fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
            formatter.write_str("injected ZK-ACE entropy failure")
        }
    }
    struct PanicEntropyRng;
    impl TryRngCore for PanicEntropyRng {
        type Error = InjectedEntropyError;
        fn try_next_u32(&mut self) -> Result<u32, Self::Error> {
            panic!("deterministically invalid ZK-ACE input reached entropy")
        }
        fn try_next_u64(&mut self) -> Result<u64, Self::Error> {
            panic!("deterministically invalid ZK-ACE input reached entropy")
        }
        fn try_fill_bytes(&mut self, _destination: &mut [u8]) -> Result<(), Self::Error> {
            panic!("deterministically invalid ZK-ACE input reached entropy")
        }
    }
    impl TryCryptoRng for PanicEntropyRng {}
    fn account(seed: u8) -> AccountId {
        let key_pair = KeyPair::try_from_seed(vec![seed; 32], Algorithm::Ed25519)
            .expect("derive test account");
        AccountId::new(key_pair.public_key().clone())
    }
    fn asset() -> AssetDefinitionId {
        AssetDefinitionId::derive_from_components(
            DomainId::try_new("privacy", "universal").expect("test domain"),
            Name::from_str("zkace").expect("test asset"),
        )
    }
    fn public_inputs_and_witness() -> (ZkAcePrivacyPublicInputsV1, ZkAcePrivacyWitnessV1) {
        let witness = ZkAcePrivacyWitnessV1 {
            identity_root: [0x11; 32],
            identity_blinding: [0x22; 32],
            replay_secret: [0x33; 32],
        };
        let network_id = NetworkId::from_genesis_hash(iroha_crypto::HashOf::<
            iroha_data_model::block::BlockHeader,
        >::from_untyped_unchecked(
            iroha_crypto::Hash::prehashed([0x48; 32])
        ));
        let identity_commitment = derive_zk_ace_identity_commitment(
            &witness.identity_root,
            &witness.identity_blinding,
            ZK_ACE_PQ_AUTHORIZATION_V1_DOMAIN_TAG,
        );
        let statement = ZkAcePqAuthorizationStatementV1 {
            context: PrivacyStatementContextV1 {
                network_id,
                action_index: 0,
                transaction_intent_digest: PrivacyTransactionIntentDigestV1::new([0x40; 32]),
                parameter_id: PrivacyParameterIdV1::new([0x41; 32]),
                parameter_digest: PrivacyParameterDigestV1::new([0x42; 32]),
                verifier_digest: PrivacyVerifierDigestV1::new([0x43; 32]),
                statement_schema_digest: PrivacyStatementSchemaDigestV1::new([0x44; 32]),
                engine_manifest_digest: PrivacyEngineManifestDigestV1::new([0x45; 32]),
            },
            identity_commitment,
            policy_id: PrivacyPolicyIdV1::new([0x46; 32]),
            policy_digest: PrivacyPolicyDigestV1::new([0x47; 32]),
            source: account(1),
            destination: account(2),
            asset_definition_id: asset(),
            public_balance_scope: iroha_data_model::asset::AssetBalanceScope::Global,
            amount: 19,
            authorization_epoch: 7,
            replay_nullifier: iroha_data_model::privacy::PrivacyZkAceReplayNullifierV1::default(),
        };
        let mut public_inputs = ZkAcePrivacyPublicInputsV1::new(statement, [0x48; 32]);
        let authorization_digest = derive_zk_ace_privacy_authorization_digest(&public_inputs)
            .expect("typed authorization digest");
        let replay_nullifier = derive_zk_ace_replay_nullifier(
            &witness.replay_secret,
            &authorization_digest,
            &network_id,
            ZK_ACE_PQ_AUTHORIZATION_V1_ACTION_TRANSFER,
            ZK_ACE_PQ_AUTHORIZATION_V1_DOMAIN_TAG,
        );
        public_inputs.statement.replay_nullifier = replay_nullifier;
        (public_inputs, witness)
    }
    #[test]
    fn compiled_profile_digest_matches_every_exact_native_parameter() {
        assert_eq!(
            fastpq_isi::GOLDILOCKS_DIGEST384_PARAMETER_SHA3_256_V1,
            [
                0x84, 0xc5, 0x05, 0x5b, 0x47, 0xcc, 0x72, 0x89, 0x83, 0x5e, 0x0a, 0x5f, 0x31, 0xd4,
                0x56, 0x38, 0x49, 0x24, 0x4f, 0xfd, 0xdb, 0xf5, 0x1f, 0x5d, 0x67, 0xb1, 0xdb, 0x95,
                0x22, 0x2c, 0xe3, 0xe6,
            ]
        );
        assert_eq!(
            ZK_ACE_DIGEST384_PARAMETER_SHA3_256_V1,
            "84c5055b47cc7289835e0a5f31d4563849244ffddbf51f5d67b1db95222ce3e6"
        );
        assert!(
            core::str::from_utf8(ZK_ACE_POSEIDON_PROFILE_V1)
                .expect("profile is UTF-8")
                .ends_with(ZK_ACE_DIGEST384_PARAMETER_SHA3_256_V1)
        );
        const { assert!(!ZK_ACE_FULL_ENGINE_AVAILABLE_V1) };
        let stark_profile = core::str::from_utf8(zk_ace_stark_profile_descriptor_v1())
            .expect("STARK profile is UTF-8");
        assert!(stark_profile.contains("blowup=8"));
        assert!(stark_profile.contains("queries=136"));
        assert!(stark_profile.contains("outer-digest48-opaque-bytes"));
        assert!(stark_profile.contains("classical-rom-bcs-work-normalized-bits128"));
        assert!(stark_profile.contains("qrom-qualification=unavailable"));
        assert!(stark_profile.contains("activation=unavailable"));
        assert_eq!(
            recompute_zk_ace_compiled_profile_digest_v1(),
            ZK_ACE_COMPILED_PROFILE_DIGEST_V1
        );
    }
    #[test]
    fn authorization_projection_breaks_only_replay_cycle() {
        let (public_inputs, _) = public_inputs_and_witness();
        let expected = derive_zk_ace_privacy_authorization_digest(&public_inputs)
            .expect("authorization projection");
        let mut changed = public_inputs.clone();
        let mut replay_bytes = changed.statement.replay_nullifier.into_bytes();
        replay_bytes[0] ^= 1;
        changed.statement.replay_nullifier =
            PrivacyZkAceReplayNullifierV1::from_le_bytes(replay_bytes)
                .expect("low-byte mutation remains canonical");
        assert_eq!(
            derive_zk_ace_privacy_authorization_digest(&changed).expect("normalized nullifier"),
            expected
        );
        changed = public_inputs.clone();
        changed.statement.context.transaction_intent_digest.0[0] ^= 1;
        assert_ne!(
            derive_zk_ace_privacy_authorization_digest(&changed).expect("intent binding"),
            expected
        );
        changed = public_inputs;
        changed.genesis_hash[0] ^= 1;
        assert_ne!(
            derive_zk_ace_privacy_authorization_digest(&changed).expect("genesis binding"),
            expected
        );
    }
    #[test]
    fn production_entrypoints_fail_before_validation_entropy_or_proof_work() {
        let (public_inputs, witness) = public_inputs_and_witness();
        let mut invalid_public = public_inputs.clone();
        invalid_public.version ^= 1;
        assert_eq!(
            prove_zk_ace_privacy_v1_with_rng(&invalid_public, &witness, &mut PanicEntropyRng,),
            Err(ZkAceNativeErrorV1::EngineUnavailable)
        );
        assert_eq!(
            prove_zk_ace_privacy_v1_with_rng(&public_inputs, &witness, &mut PanicEntropyRng),
            Err(ZkAceNativeErrorV1::EngineUnavailable)
        );
        assert_eq!(
            verify_zk_ace_privacy_v1(&invalid_public, &[], ZK_ACE_PRIVACY_MAX_PROOF_BYTES_V1,),
            Err(ZkAceNativeErrorV1::EngineUnavailable)
        );
        assert_eq!(
            verify_zk_ace_privacy_v1(&public_inputs, &[], ZK_ACE_PRIVACY_MAX_PROOF_BYTES_V1,),
            Err(ZkAceNativeErrorV1::EngineUnavailable)
        );
        assert_eq!(
            verify_zk_ace_privacy_v1(&public_inputs, &[1], ZK_ACE_PRIVACY_MAX_PROOF_BYTES_V1),
            Err(ZkAceNativeErrorV1::EngineUnavailable)
        );
    }
}
