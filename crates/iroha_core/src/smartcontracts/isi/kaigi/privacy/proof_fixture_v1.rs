//! Real authorization proofs and governed keys for Kaigi execution tests.

use super::*;
use crate::state::StateReadOnly;
use ff::PrimeField as _;
use iroha_data_model::{
    confidential::ConfidentialStatus, prelude::AccountId, proof::VerifyingKeyRecord,
};
use kaigi_zk::authorization_v1::{
    KAIGI_AUTHORIZATION_PUBLIC_INPUTS_SCHEMA_V1, KaigiAuthorizationActionV1,
    KaigiAuthorizationWitnessV1, compute_authorization_v1,
};
use kaigi_zk::{Scalar as Fp, native::NativeRelationV1};

/// Exact artifacts from the final circuit, with a real proof.
pub(crate) struct AuthorizationFixtureV1 {
    /// Canonical private opening commitment.
    pub commitment: KaigiParticipantCommitment,
    /// Canonical action nullifier.
    pub nullifier: KaigiParticipantNullifier,
    /// Authenticated pre-state root.
    pub root: Hash,
    /// Canonical outer envelope.
    pub proof: Vec<u8>,
}

/// Generate a final proof for this ledger context and install its governed key.
pub(crate) fn authorization_fixture_v1(
    state: &mut StateTransaction<'_, '_>,
    record: &KaigiRecord,
    subject: &AccountId,
    sequence: u64,
    action: KaigiAuthorizationActionV1,
    secret: u64,
) -> AuthorizationFixtureV1 {
    let key = zk::native_pipa_r::kaigi_verifying_key(NativeRelationV1::Authorization).unwrap();
    let hash = zk::hash_vk(&key);
    let mut vk = VerifyingKeyRecord::new(
        1,
        KAIGI_AUTHORIZATION_CIRCUIT_ID_V1,
        BackendTag::NativePipaRPasta,
        "vesta",
        Hash::new(KAIGI_AUTHORIZATION_PUBLIC_INPUTS_SCHEMA_V1).into(),
        hash,
    );
    vk.status = ConfidentialStatus::Active;
    vk.max_proof_bytes = 64 * 1024;
    vk.gas_schedule_id = Some("kaigi-authorization-v1-tests".into());
    vk.vk_len = key.bytes.len().try_into().unwrap();
    vk.key = Some(key.clone());
    let id = VerifyingKeyId::new(zk::ZK_BACKEND_NATIVE_PIPA_R, "kaigi-authorization-v1-tests");
    state.world.verifying_keys.insert(id, vk);
    state.zk.kaigi_authorization_vk = Some(VerifyingKeyRef {
        backend: zk::ZK_BACKEND_NATIVE_PIPA_R.into(),
        name: "kaigi-authorization-v1-tests".into(),
    });
    let context = authorization_v1::context_from_ledger_v1(
        *state.network_id(),
        &record.id,
        &record.host,
        subject,
        sequence,
        action,
        &record.roster_root(),
    )
    .unwrap();
    let mut secret = Fp::from(secret).to_repr();
    let witness = KaigiAuthorizationWitnessV1::take_blinding(&mut secret).unwrap();
    assert_eq!(secret, [0; 32]);
    let outputs = compute_authorization_v1(&context, &witness).unwrap();
    let envelope = zk::native_pipa_r::prove_kaigi_authorization(context, witness).unwrap();
    AuthorizationFixtureV1 {
        commitment: KaigiParticipantCommitment {
            commitment: KaigiAuthorizationScalarV1::from_le_bytes(outputs.commitment.to_repr())
                .unwrap(),
        },
        nullifier: KaigiParticipantNullifier {
            digest: KaigiAuthorizationScalarV1::from_le_bytes(outputs.nullifier.to_repr()).unwrap(),
        },
        root: record.roster_root(),
        proof: norito::encode_canonical(&envelope).unwrap(),
    }
}
