//! Canonical governed verification for final Kaigi authorization and usage.
//!
//! Unit tests and production execute the same verifier. Every authorization
//! binds the complete ledger context and uses one explicitly governed key.
use super::{Error, privacy_error};
pub(super) mod authorization_v1;
#[cfg(test)]
pub(super) mod proof_fixture_v1;
use crate::{state::StateTransaction, zk, zk_guardrails::guardrails_from_config};
use iroha_config::parameters::actual::VerifyingKeyRef;
use iroha_crypto::Hash;
use iroha_data_model::{
    kaigi::{
        KaigiParticipantCommitment, KaigiParticipantNullifier, KaigiRecord,
        scalar::KaigiAuthorizationScalarV1,
    },
    proof::{ProofBox, VerifyingKeyId},
    zk::{BackendTag, OpenVerifyEnvelope},
};
use iroha_schema::Ident;
use kaigi_zk::authorization_v1::{KAIGI_AUTHORIZATION_CIRCUIT_ID_V1, KaigiAuthorizationContextV1};
use mv::storage::StorageReadOnly;
use std::str::FromStr;

/// Instruction artifacts checked against authenticated call state.
#[derive(Debug)]
pub struct PrivacyArtifacts<'a> {
    /// Participant or host commitment.
    pub commitment: Option<&'a KaigiParticipantCommitment>,
    /// Exact action nullifier.
    pub nullifier: Option<&'a KaigiParticipantNullifier>,
    /// Roster root used by the proof.
    pub roster_root: Option<&'a Hash>,
    /// Canonical Norito `OpenVerifyEnvelope`.
    pub proof: Option<&'a [u8]>,
}

/// Reject all privacy artifacts for explicitly transparent sessions.
pub fn ensure_transparent_payload(artifacts: &PrivacyArtifacts<'_>) -> Result<(), Error> {
    if artifacts.commitment.is_some()
        || artifacts.nullifier.is_some()
        || artifacts.roster_root.is_some()
        || artifacts.proof.is_some()
    {
        return Err(privacy_error(
            "privacy artifacts are not accepted by transparent Kaigi sessions",
        ));
    }
    Ok(())
}

/// Verify a complete final authorization with the exact ledger-owned context.
pub fn verify_authorization(
    state: &mut StateTransaction<'_, '_>,
    artifacts: &PrivacyArtifacts<'_>,
    context: &KaigiAuthorizationContextV1,
    expected_commitment: Option<&KaigiAuthorizationScalarV1>,
) -> Result<(), Error> {
    let commitment = artifacts
        .commitment
        .ok_or_else(|| privacy_error("privacy mode requires commitment"))?;
    let nullifier = artifacts
        .nullifier
        .ok_or_else(|| privacy_error("privacy mode requires nullifier"))?;
    if expected_commitment.is_some_and(|expected| expected != &commitment.commitment) {
        return Err(privacy_error(
            "stored commitment differs from authorization",
        ));
    }
    let root = artifacts
        .roster_root
        .ok_or_else(|| privacy_error("privacy mode requires roster root"))?;
    if root.as_ref() != &context.pre_roster_root {
        return Err(privacy_error(
            "roster root differs from authenticated call state",
        ));
    }
    let proof = artifacts
        .proof
        .ok_or_else(|| privacy_error("privacy mode requires proof"))?;
    if proof.is_empty() {
        return Err(privacy_error("privacy proof payload must be non-empty"));
    }
    let configured = state.zk.kaigi_authorization_vk.clone();
    validate_configured_verifier(
        state,
        proof.len(),
        configured.as_ref(),
        "kaigi authorization",
    )?;
    let envelope = decode_privacy_proof_envelope(proof)?;
    if envelope.circuit_id != KAIGI_AUTHORIZATION_CIRCUIT_ID_V1 {
        return Err(privacy_error(
            "Kaigi authorization requires the full canonical V1 circuit ID",
        ));
    }
    let configured_backend = configured
        .as_ref()
        .ok_or_else(|| privacy_error("verifier not configured"))?;
    let columns = zk::native_pipa_r::public_instances(&configured_backend.backend, &envelope)
        .map_err(|error| {
            privacy_error(format!(
                "failed to decode Kaigi authorization instances: {error}"
            ))
        })?;
    authorization_v1::verify_public_inputs_v1(
        &columns,
        context,
        commitment.commitment.as_bytes(),
        nullifier.digest.as_bytes(),
    )?;
    verify_with_config(
        state,
        proof,
        configured,
        "kaigi authorization",
        zk::ProofRelation::KaigiAuthorization,
    )
}

/// Check the final usage relation against the stored host and ledger segment.
#[allow(clippy::too_many_arguments)]
pub fn verify_usage_commitment(
    state: &mut StateTransaction<'_, '_>,
    record: &KaigiRecord,
    duration_ms: u64,
    billed_gas: u64,
    proof: Option<&[u8]>,
    commitment: &KaigiAuthorizationScalarV1,
) -> Result<(), Error> {
    use crate::state::StateReadOnly as _;
    use ff::PrimeField as _;
    use iroha_data_model::kaigi::authorization::KaigiAuthorizationIdentitiesV1;
    use kaigi_zk::Scalar as Fp;
    use kaigi_zk::usage_v1::{
        KAIGI_USAGE_CIRCUIT_ID_V1, KAIGI_USAGE_INSTANCE_ROWS_V1, KaigiUsageContextV1,
        KaigiUsageOutputsV1, KaigiUsagePublicInputsV1,
    };
    let host = record
        .host_commitment
        .as_ref()
        .ok_or_else(|| privacy_error("private usage requires its original host commitment"))?;
    let network = *state.network_id();
    let identities =
        KaigiAuthorizationIdentitiesV1::new(network, &record.id, &record.host, &record.host)
            .map_err(|error| {
                privacy_error(format!("cannot bind canonical usage identities: {error}"))
            })?;
    let context = KaigiUsageContextV1 {
        network_id: *network.as_bytes(),
        call_id: identities.call_id.words(),
        host_id: identities.host_id.words(),
        pre_roster_root: record.roster_root().into(),
        segment_index: record.segments_recorded,
        duration_ms,
        billed_gas,
    };
    context
        .validate()
        .map_err(|error| privacy_error(format!("invalid Kaigi usage context: {error}")))?;
    let proof = proof.ok_or_else(|| privacy_error("privacy mode requires usage proof"))?;
    if proof.is_empty() {
        return Err(privacy_error("privacy proof payload must be non-empty"));
    }
    let configured = state.zk.kaigi_usage_vk.clone();
    validate_configured_verifier(state, proof.len(), configured.as_ref(), "kaigi usage")?;
    let envelope = decode_privacy_proof_envelope(proof)?;
    if envelope.circuit_id != KAIGI_USAGE_CIRCUIT_ID_V1 {
        return Err(privacy_error(
            "Kaigi usage requires the full canonical V1 circuit ID",
        ));
    }
    let configured_backend = configured
        .as_ref()
        .ok_or_else(|| privacy_error("verifier not configured"))?;
    let columns = zk::native_pipa_r::public_instances(&configured_backend.backend, &envelope)
        .map_err(|error| {
            privacy_error(format!("failed to decode Kaigi usage instances: {error}"))
        })?;
    let [column] = columns.as_slice() else {
        return Err(privacy_error("Kaigi usage requires one instance column"));
    };
    if column.len() != KAIGI_USAGE_INSTANCE_ROWS_V1 {
        return Err(privacy_error(
            "Kaigi usage requires exactly 25 instance rows",
        ));
    }
    let host_commitment = Option::<Fp>::from(Fp::from_repr(host.commitment.to_le_bytes()))
        .ok_or_else(|| privacy_error("host commitment is not a canonical Pasta scalar"))?;
    let usage_commitment = Option::<Fp>::from(Fp::from_repr(commitment.to_le_bytes()))
        .ok_or_else(|| privacy_error("usage commitment is not a canonical Pasta scalar"))?;
    let expected = KaigiUsagePublicInputsV1 {
        context,
        outputs: KaigiUsageOutputsV1 {
            host_commitment,
            usage_commitment,
        },
    }
    .instance();
    if column.as_slice() != expected {
        return Err(privacy_error(
            "Kaigi usage differs from authenticated call, host, root, segment or billed tuple",
        ));
    }
    verify_with_config(
        state,
        proof,
        configured,
        "kaigi usage",
        zk::ProofRelation::KaigiUsage,
    )
}
fn validate_configured_verifier(
    state_transaction: &StateTransaction<'_, '_>,
    proof_len: usize,
    vk_cfg: Option<&VerifyingKeyRef>,
    purpose: &str,
) -> Result<(), Error> {
    let Some(vk_cfg) = vk_cfg else {
        return Err(privacy_error(format!("{purpose} verifier not configured")));
    };
    let vk_id = VerifyingKeyId::new(vk_cfg.backend.clone(), vk_cfg.name.clone());
    let Some(record) = state_transaction.world.verifying_keys.get(&vk_id) else {
        return Err(privacy_error(format!("{purpose} verifier not registered")));
    };
    if !record.is_active_at(state_transaction.block_height()) {
        return Err(privacy_error(format!("{purpose} verifier is not active")));
    }
    if record.gas_schedule_id.is_none() {
        return Err(privacy_error(format!(
            "{purpose} verifier missing gas schedule reference"
        )));
    }
    enforce_verifier_proof_size(record.max_proof_bytes, proof_len, purpose)
}
#[allow(clippy::needless_pass_by_value)]
fn verify_with_config(
    state_transaction: &mut StateTransaction<'_, '_>,
    proof_bytes: &[u8],
    vk_cfg: Option<VerifyingKeyRef>,
    purpose: &str,
    required_relation: zk::ProofRelation,
) -> Result<(), Error> {
    let Some(vk_cfg) = vk_cfg.as_ref() else {
        return Err(privacy_error(format!("{purpose} verifier not configured")));
    };
    let backend_tag = vk_cfg.backend.clone();
    let circuit_name = vk_cfg.name.clone();
    let vk_id = VerifyingKeyId::new(backend_tag.clone(), circuit_name.clone());
    let Some(record) = state_transaction.world.verifying_keys.get(&vk_id) else {
        return Err(privacy_error(format!("{purpose} verifier not registered")));
    };
    if !record.is_active_at(state_transaction.block_height()) {
        return Err(privacy_error(format!("{purpose} verifier is not active")));
    }
    if record.gas_schedule_id.is_none() {
        return Err(privacy_error(format!(
            "{purpose} verifier missing gas schedule reference"
        )));
    }
    enforce_verifier_proof_size(record.max_proof_bytes, proof_bytes.len(), purpose)?;
    let record_backend = record.backend;
    let record_circuit_id = record.circuit_id.clone();
    let record_commitment = record.commitment;
    let record_key = record.key.clone();
    let envelope = decode_privacy_proof_envelope(proof_bytes)?;
    validate_privacy_proof_envelope_metadata(
        &envelope,
        backend_tag.as_str(),
        record_backend,
        &record_circuit_id,
        record_commitment,
    )?;
    state_transaction.register_confidential_proof(proof_bytes.len())?;
    let backend_ident = Ident::from_str(backend_tag.as_str())
        .map_err(|_| privacy_error("invalid verifier backend identifier"))?;
    let proof_box = ProofBox::new(backend_ident, proof_bytes.to_vec());
    let key = record_key
        .as_ref()
        .ok_or_else(|| privacy_error(format!("{purpose} verifier has no key material")))?;
    #[cfg(feature = "telemetry")]
    let started = std::time::Instant::now();
    let result = zk::verify_for_relation(
        required_relation,
        &proof_box,
        key,
        guardrails_from_config(&state_transaction.zk),
    );
    #[cfg(feature = "telemetry")]
    {
        let status = if result.is_ok() {
            iroha_data_model::proof::ProofStatus::Verified
        } else {
            iroha_data_model::proof::ProofStatus::Rejected
        };
        let latency_ms = u64::try_from(started.elapsed().as_millis()).unwrap_or(u64::MAX);
        state_transaction.telemetry.record_zk_verify(
            backend_tag.as_str(),
            status,
            proof_bytes.len(),
            latency_ms,
        );
    }
    result
        .map_err(|error| privacy_error(format!("{purpose} proof verification failed: {error}")))?;
    Ok(())
}
fn enforce_verifier_proof_size(
    max_proof_bytes: u32,
    proof_len: usize,
    purpose: &str,
) -> Result<(), Error> {
    let max_proof_bytes = usize::try_from(max_proof_bytes).unwrap_or(usize::MAX);
    if max_proof_bytes == 0 {
        return Err(privacy_error(format!(
            "{purpose} verifier missing a governed max_proof_bytes limit"
        )));
    }
    if proof_len > max_proof_bytes {
        return Err(privacy_error(format!(
            "{purpose} proof exceeds verifier max_proof_bytes"
        )));
    }
    Ok(())
}
fn decode_privacy_proof_envelope(proof_bytes: &[u8]) -> Result<OpenVerifyEnvelope, Error> {
    norito::decode_canonical(proof_bytes).map_err(|err| {
        privacy_error(format!(
            "failed to decode canonical privacy proof envelope: {err}"
        ))
    })
}
fn validate_privacy_proof_envelope_metadata(
    envelope: &OpenVerifyEnvelope,
    configured_backend: &str,
    record_backend: BackendTag,
    record_circuit_id: &str,
    record_commitment: [u8; Hash::LENGTH],
) -> Result<(), Error> {
    let Some(expected_backend) = zk::verifier_backend_registry_tag_v1(configured_backend) else {
        return Err(privacy_error(
            "privacy proof verifier backend is not admitted by the native verifier registry",
        ));
    };
    if expected_backend != record_backend {
        return Err(privacy_error("privacy verifier backend tag mismatch"));
    }
    if record_backend != envelope.backend {
        return Err(privacy_error("privacy proof backend mismatch"));
    }
    if record_circuit_id != envelope.circuit_id.as_str() {
        return Err(privacy_error("privacy proof circuit mismatch"));
    }
    if !envelope.aux.is_empty() {
        return Err(privacy_error(
            "privacy proof envelope auxiliary bytes must be empty",
        ));
    }
    if envelope.vk_hash == [0u8; Hash::LENGTH] {
        return Err(privacy_error(
            "privacy proof verifier-key hash must be non-zero",
        ));
    }
    if envelope.vk_hash != record_commitment {
        return Err(privacy_error("privacy proof verifier commitment mismatch"));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn verifier_proof_size_enforces_governed_cap() {
        assert!(enforce_verifier_proof_size(8, 8, "kaigi usage").is_ok());
        let err = enforce_verifier_proof_size(8, 9, "kaigi usage")
            .expect_err("proof larger than verifier cap must reject");
        assert!(format!("{err:?}").contains("max_proof_bytes"));
        let err = enforce_verifier_proof_size(0, 1, "kaigi usage")
            .expect_err("zero verifier cap must fail closed");
        assert!(format!("{err:?}").contains("missing a governed max_proof_bytes limit"));
    }
    #[test]
    fn privacy_proof_envelope_metadata_rejects_zero_verifier_hash() {
        let commitment = Hash::new(b"kaigi-privacy-verifier-key");
        let commitment: [u8; Hash::LENGTH] = commitment.into();
        let mut envelope = OpenVerifyEnvelope {
            backend: BackendTag::NativePipaRPasta,
            circuit_id: KAIGI_AUTHORIZATION_CIRCUIT_ID_V1.to_owned(),
            vk_hash: commitment,
            public_inputs: Vec::new(),
            proof_bytes: Vec::new(),
            aux: Vec::new(),
        };
        assert!(
            validate_privacy_proof_envelope_metadata(
                &envelope,
                "pipa-r/pasta/kaigi-authorization-v1",
                BackendTag::NativePipaRPasta,
                KAIGI_AUTHORIZATION_CIRCUIT_ID_V1,
                commitment,
            )
            .is_ok()
        );
        let err = validate_privacy_proof_envelope_metadata(
            &envelope,
            "halo2/ipa:production-ready",
            BackendTag::NativePipaRPasta,
            KAIGI_AUTHORIZATION_CIRCUIT_ID_V1,
            commitment,
        )
        .expect_err("readiness-claim verifier backend must reject");
        let Error::InvalidParameter(
            iroha_data_model::isi::error::InvalidParameterError::SmartContract(message),
        ) = err
        else {
            panic!("unexpected readiness-claim backend rejection: {err:?}");
        };
        assert!(
            message.contains("native verifier registry"),
            "unexpected error: {message}"
        );
        let err = validate_privacy_proof_envelope_metadata(
            &envelope,
            "stark/fri/poseidon-x7-goldilocks-6x64-v1",
            BackendTag::NativePipaRPasta,
            KAIGI_AUTHORIZATION_CIRCUIT_ID_V1,
            commitment,
        )
        .expect_err("configured backend tag drift must reject");
        let Error::InvalidParameter(
            iroha_data_model::isi::error::InvalidParameterError::SmartContract(message),
        ) = err
        else {
            panic!("unexpected backend tag mismatch rejection: {err:?}");
        };
        assert!(
            message.contains("backend tag mismatch"),
            "unexpected error: {message}"
        );
        envelope.vk_hash = [0u8; Hash::LENGTH];
        let err = validate_privacy_proof_envelope_metadata(
            &envelope,
            "pipa-r/pasta/kaigi-authorization-v1",
            BackendTag::NativePipaRPasta,
            KAIGI_AUTHORIZATION_CIRCUIT_ID_V1,
            commitment,
        )
        .expect_err("zero verifier-key hash must reject");
        let Error::InvalidParameter(
            iroha_data_model::isi::error::InvalidParameterError::SmartContract(message),
        ) = err
        else {
            panic!("unexpected zero-hash rejection: {err:?}");
        };
        assert!(message.contains("non-zero"), "unexpected error: {message}");
    }
    #[test]
    fn privacy_proof_admission_rejects_alternate_norito_layout() {
        let envelope = OpenVerifyEnvelope {
            backend: BackendTag::NativePipaRPasta,
            circuit_id: KAIGI_AUTHORIZATION_CIRCUIT_ID_V1.to_owned(),
            vk_hash: [0xA5; Hash::LENGTH],
            public_inputs: vec![0x11; 32],
            proof_bytes: vec![0x22; 64],
            aux: Vec::new(),
        };
        let canonical =
            norito::encode_canonical(&envelope).expect("encode canonical privacy envelope");
        assert_eq!(
            decode_privacy_proof_envelope(&canonical)
                .expect("canonical privacy envelope must decode"),
            envelope
        );
        let alternate_flags =
            norito::core::default_encode_flags() ^ norito::core::header_flags::COMPACT_LEN;
        let alternate = {
            let _guard = norito::core::DecodeFlagsGuard::enter(alternate_flags);
            norito::to_bytes(&envelope).expect("encode alternate-layout privacy envelope")
        };
        assert_ne!(alternate, canonical);
        let err = decode_privacy_proof_envelope(&alternate)
            .expect_err("alternate-layout privacy envelope must reject");
        let Error::InvalidParameter(
            iroha_data_model::isi::error::InvalidParameterError::SmartContract(message),
        ) = err
        else {
            panic!("unexpected alternate-layout rejection: {err:?}");
        };
        assert!(
            message.contains("canonical privacy proof envelope"),
            "unexpected error: {message}"
        );
    }
}
