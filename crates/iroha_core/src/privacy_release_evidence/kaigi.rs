//! Pure real final Kaigi proof fixtures for explicit four-validator release tests.
//!
//! This nonshipping module builds public governed-key instructions and canonical proof bytes.
//! It never reads or mutates StateTransaction, executes an instruction, installs a verifier,
//! or grants authority. Callers must obtain the complete record and NetworkId from the real
//! network and submit every resulting instruction with the correct account signature.
//! Fixed private fixture blindings are unsuitable for production; no witness bytes are exported.
//! TODO: Run and qualify the real four-validator lifecycle against the exact candidate daemon.

use crate::zk::hash_vk;
use ff::PrimeField as _;
use iroha_config::parameters::actual::VerifyingKeyRef;
use iroha_core_zk::{ZK_BACKEND_NATIVE_PIPA_R, native_pipa_r};
use iroha_crypto::Hash;
use iroha_data_model::{
    NetworkId,
    account::AccountId,
    confidential::ConfidentialStatus,
    isi::{
        CreateKaigi, EndKaigi, JoinKaigi, LeaveKaigi, RecordKaigiUsage,
        verifying_keys::RegisterVerifyingKey,
    },
    kaigi::{
        KaigiId, KaigiParticipantCommitment, KaigiParticipantNullifier, KaigiRecord, NewKaigi,
        authorization::KaigiAuthorizationIdentitiesV1, scalar::KaigiAuthorizationScalarV1,
    },
    proof::{VerifyingKeyBox, VerifyingKeyId, VerifyingKeyRecord},
    zk::BackendTag,
};
/// Exact circuit-owned action enum used only to select a real fixture witness relation.
pub use kaigi_zk::authorization_v1::KaigiAuthorizationActionV1;
use kaigi_zk::native::NativeRelationV1;
use kaigi_zk::{
    authorization_v1::{
        KAIGI_AUTHORIZATION_INSTANCE_ROWS_V1, KaigiAuthorizationContextV1,
        KaigiAuthorizationPublicInputsV1, KaigiAuthorizationWitnessV1, compute_authorization_v1,
    },
    usage_v1::{
        KAIGI_USAGE_INSTANCE_ROWS_V1, KaigiUsageContextV1, KaigiUsagePublicInputsV1,
        compute_usage_v1,
    },
};
use std::sync::OnceLock;

const HOST_BLINDING: [u8; 32] = [0x17; 32];
const PARTICIPANT_BLINDING: [u8; 32] = [0x21; 32];
const AUTHORIZATION_VK_NAME: &str = "kaigi_authorization_current";
const USAGE_VK_NAME: &str = "kaigi_usage_current";

struct GovernedKey {
    carrier: VerifyingKeyBox,
    circuit_id: &'static str,
    schema: &'static [u8],
    name: &'static str,
}
impl GovernedKey {
    fn new(kind: NativeRelationV1, name: &'static str) -> Self {
        Self {
            carrier: native_pipa_r::kaigi_verifying_key(kind).expect("compiled native key"),
            circuit_id: kind.circuit_id(),
            schema: native_pipa_r::public_schema(kind.into()),
            name,
        }
    }
    fn id(&self) -> VerifyingKeyId {
        VerifyingKeyId::new(ZK_BACKEND_NATIVE_PIPA_R, self.name)
    }
    fn record(&self) -> VerifyingKeyRecord {
        let mut record = VerifyingKeyRecord::new(
            1,
            self.circuit_id,
            BackendTag::NativePipaRPasta,
            "vesta",
            Hash::new(self.schema).into(),
            hash_vk(&self.carrier),
        );
        record.vk_len = self.carrier.bytes.len().try_into().expect("key length");
        record.status = ConfidentialStatus::Active;
        record.max_proof_bytes = 64 * 1024;
        record.gas_schedule_id = Some(self.name.into());
        record.key = Some(self.carrier.clone());
        record
    }
}
fn authorization_key() -> &'static GovernedKey {
    static KEY: OnceLock<GovernedKey> = OnceLock::new();
    KEY.get_or_init(|| GovernedKey::new(NativeRelationV1::Authorization, AUTHORIZATION_VK_NAME))
}
fn usage_key() -> &'static GovernedKey {
    static KEY: OnceLock<GovernedKey> = OnceLock::new();
    KEY.get_or_init(|| GovernedKey::new(NativeRelationV1::Usage, USAGE_VK_NAME))
}
fn witness(mut bytes: [u8; 32]) -> KaigiAuthorizationWitnessV1 {
    let witness = KaigiAuthorizationWitnessV1::take_blinding(&mut bytes)
        .expect("canonical nonzero fixture blinding");
    assert_eq!(bytes, [0; 32], "witness takes and erases source bytes");
    witness
}

/// Complete public authorization carrier produced by the final circuit.
#[derive(Clone)]
pub struct KaigiReleaseAuthorizationV1 {
    /// Canonical commitment to the fixture participation opening.
    pub commitment: KaigiParticipantCommitment,
    /// Action-separated canonical nullifier.
    pub nullifier: KaigiParticipantNullifier,
    /// Exact pre-action roster root supplied by the caller.
    pub root: Hash,
    /// Canonical real OpenVerifyEnvelope proof bytes.
    pub proof: Vec<u8>,
}
impl KaigiReleaseAuthorizationV1 {
    /// Build signed-host creation input; this does not submit it.
    #[must_use]
    pub fn create(&self, call: NewKaigi) -> CreateKaigi {
        CreateKaigi {
            call,
            commitment: Some(self.commitment.clone()),
            nullifier: Some(self.nullifier.clone()),
            roster_root: Some(self.root),
            proof: Some(self.proof.clone()),
        }
    }
    /// Build signed-participant join input; this does not submit it.
    #[must_use]
    pub fn join(&self, call_id: &KaigiId, participant: &AccountId) -> JoinKaigi {
        JoinKaigi {
            call_id: call_id.clone(),
            participant: participant.clone(),
            commitment: Some(self.commitment.clone()),
            nullifier: Some(self.nullifier.clone()),
            roster_root: Some(self.root),
            proof: Some(self.proof.clone()),
        }
    }
    /// Build signed-participant leave input; this does not submit it.
    #[must_use]
    pub fn leave(&self, call_id: &KaigiId, participant: &AccountId) -> LeaveKaigi {
        LeaveKaigi {
            call_id: call_id.clone(),
            participant: participant.clone(),
            commitment: Some(self.commitment.clone()),
            nullifier: Some(self.nullifier.clone()),
            roster_root: Some(self.root),
            proof: Some(self.proof.clone()),
        }
    }
    /// Build signed-host termination input; this does not submit it.
    #[must_use]
    pub fn end(&self, call_id: &KaigiId) -> EndKaigi {
        EndKaigi {
            call_id: call_id.clone(),
            ended_at_ms: None,
            commitment: Some(self.commitment.clone()),
            nullifier: Some(self.nullifier.clone()),
            roster_root: Some(self.root),
            proof: Some(self.proof.clone()),
        }
    }
}

/// Ordinary configuration references for the two governed final verifier records.
#[must_use]
pub fn kaigi_release_verifier_references_v1() -> [VerifyingKeyRef; 2] {
    [
        VerifyingKeyRef {
            backend: ZK_BACKEND_NATIVE_PIPA_R.into(),
            name: AUTHORIZATION_VK_NAME.into(),
        },
        VerifyingKeyRef {
            backend: ZK_BACKEND_NATIVE_PIPA_R.into(),
            name: USAGE_VK_NAME.into(),
        },
    ]
}

/// Build real governed-key registration instructions without installing either record.
/// The network must grant and exercise normal verifier-governance permission.
#[must_use]
pub fn kaigi_release_verifier_registrations_v1() -> [RegisterVerifyingKey; 2] {
    [authorization_key(), usage_key()].map(|key| RegisterVerifyingKey {
        id: key.id(),
        record: key.record(),
    })
}

/// Prove one final authorization against explicit full network and record context.
/// Fixed fixture blindings are chosen by host versus participant action; no state is trusted implicitly.
#[must_use]
pub fn build_kaigi_release_authorization_v1(
    network: NetworkId,
    record: &KaigiRecord,
    subject: &AccountId,
    sequence: u64,
    action: KaigiAuthorizationActionV1,
) -> KaigiReleaseAuthorizationV1 {
    let blinding = match action {
        KaigiAuthorizationActionV1::HostCreate | KaigiAuthorizationActionV1::HostEnd => {
            HOST_BLINDING
        }
        KaigiAuthorizationActionV1::Join | KaigiAuthorizationActionV1::Leave => {
            PARTICIPANT_BLINDING
        }
    };
    let identity = KaigiAuthorizationIdentitiesV1::new(network, &record.id, &record.host, subject)
        .expect("full canonical identity");
    let context = KaigiAuthorizationContextV1 {
        network_id: *network.as_bytes(),
        call_id: identity.call_id.words(),
        host_id: identity.host_id.words(),
        subject_id: identity.subject_id.words(),
        participation_sequence: sequence,
        action,
        pre_roster_root: record.roster_root().into(),
    };
    let witness = witness(blinding);
    let outputs =
        compute_authorization_v1(&context, &witness).expect("final authorization outputs");
    let instance = KaigiAuthorizationPublicInputsV1 { context, outputs }.instance();
    assert_eq!(instance.len(), KAIGI_AUTHORIZATION_INSTANCE_ROWS_V1);
    KaigiReleaseAuthorizationV1 {
        commitment: KaigiParticipantCommitment {
            commitment: KaigiAuthorizationScalarV1::from_le_bytes(outputs.commitment.to_repr())
                .unwrap(),
        },
        nullifier: KaigiParticipantNullifier {
            digest: KaigiAuthorizationScalarV1::from_le_bytes(outputs.nullifier.to_repr()).unwrap(),
        },
        root: record.roster_root(),
        proof: norito::encode_canonical(
            &native_pipa_r::prove_kaigi_authorization(context, witness).unwrap(),
        )
        .unwrap(),
    }
}

/// Prove the next fixed-duration usage segment against the complete caller-supplied host context.
#[must_use]
pub fn build_kaigi_release_usage_v1(network: NetworkId, record: &KaigiRecord) -> RecordKaigiUsage {
    let identity =
        KaigiAuthorizationIdentitiesV1::new(network, &record.id, &record.host, &record.host)
            .unwrap();
    let context = KaigiUsageContextV1 {
        network_id: *network.as_bytes(),
        call_id: identity.call_id.words(),
        host_id: identity.host_id.words(),
        pre_roster_root: record.roster_root().into(),
        segment_index: record.segments_recorded,
        duration_ms: 1_200,
        billed_gas: 345,
    };
    let witness = witness(HOST_BLINDING);
    let outputs = compute_usage_v1(&context, &witness).unwrap();
    assert_eq!(
        outputs.host_commitment.to_repr(),
        record
            .host_commitment
            .as_ref()
            .unwrap()
            .commitment
            .to_le_bytes()
    );
    let instance = KaigiUsagePublicInputsV1 { context, outputs }.instance();
    assert_eq!(instance.len(), KAIGI_USAGE_INSTANCE_ROWS_V1);
    RecordKaigiUsage {
        call_id: record.id.clone(),
        duration_ms: context.duration_ms,
        billed_gas: context.billed_gas,
        usage_commitment: Some(
            KaigiAuthorizationScalarV1::from_le_bytes(outputs.usage_commitment.to_repr()).unwrap(),
        ),
        proof: Some(
            norito::encode_canonical(&native_pipa_r::prove_kaigi_usage(context, witness).unwrap())
                .unwrap(),
        ),
    }
}

#[cfg(test)]
mod tests;
