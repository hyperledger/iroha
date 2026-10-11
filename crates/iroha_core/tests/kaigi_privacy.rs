//! Integration coverage for final Kaigi authorization and usage instruction execution.
#![allow(clippy::all, clippy::pedantic, clippy::nursery, clippy::restriction)]
#![cfg(feature = "zk-tests")]

use core::num::NonZeroU64;
use ff::PrimeField as _;
use iroha_config::parameters::actual::VerifyingKeyRef;
use iroha_core::{
    kura::Kura,
    query::store::LiveQueryStore,
    smartcontracts::Execute,
    state::{State, StateReadOnly, StateTransaction, WorldReadOnly},
};
use iroha_core_zk::hash_vk;
use iroha_core_zk::{ZK_BACKEND_NATIVE_PIPA_R, native_pipa_r};
use iroha_crypto::Hash;
use iroha_data_model::{
    block::BlockHeader,
    confidential::ConfidentialStatus,
    isi::{CreateKaigi, EndKaigi, JoinKaigi, LeaveKaigi, RecordKaigiUsage},
    kaigi::{
        KaigiId, KaigiParticipantCommitment, KaigiParticipantNullifier, KaigiPrivacyMode,
        KaigiRecord, KaigiStatus, NewKaigi, authorization::KaigiAuthorizationIdentitiesV1,
        kaigi_metadata_key, scalar::KaigiAuthorizationScalarV1,
    },
    prelude::*,
    proof::{VerifyingKeyBox, VerifyingKeyId, VerifyingKeyRecord},
    zk::{BackendTag, OpenVerifyEnvelope},
};
use iroha_model_base::domain::DomainId;
use iroha_model_base::name::Name;
use iroha_primitives::json::Json;
use iroha_test_samples::{ALICE_ID, gen_account_in};
use kaigi_zk::{Scalar, native::NativeRelationV1};
use kaigi_zk::{
    authorization_v1::{
        KAIGI_AUTHORIZATION_INSTANCE_ROWS_V1, KaigiAuthorizationActionV1,
        KaigiAuthorizationContextV1, KaigiAuthorizationPublicInputsV1, KaigiAuthorizationWitnessV1,
        compute_authorization_v1,
    },
    usage_v1::{
        KAIGI_USAGE_INSTANCE_ROWS_V1, KaigiUsageContextV1, KaigiUsagePublicInputsV1,
        compute_usage_v1,
    },
};
use std::{str::FromStr, sync::OnceLock, time::Duration};
#[path = "common/world_fixture.rs"]
mod test_world;

// Deterministic private fixture bytes only. Production generates secret nonzero full-field blinding.
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
    fn reference(&self) -> VerifyingKeyRef {
        VerifyingKeyRef {
            backend: ZK_BACKEND_NATIVE_PIPA_R.into(),
            name: self.name.into(),
        }
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
#[derive(Clone)]
struct AuthorizationArtifacts {
    commitment: KaigiParticipantCommitment,
    nullifier: KaigiParticipantNullifier,
    root: Hash,
    proof: Vec<u8>,
}
impl AuthorizationArtifacts {
    fn create(&self, call: NewKaigi) -> CreateKaigi {
        CreateKaigi {
            call,
            commitment: Some(self.commitment.clone()),
            nullifier: Some(self.nullifier.clone()),
            roster_root: Some(self.root),
            proof: Some(self.proof.clone()),
        }
    }
    fn join(&self, call_id: &KaigiId, participant: &AccountId) -> JoinKaigi {
        JoinKaigi {
            call_id: call_id.clone(),
            participant: participant.clone(),
            commitment: Some(self.commitment.clone()),
            nullifier: Some(self.nullifier.clone()),
            roster_root: Some(self.root),
            proof: Some(self.proof.clone()),
        }
    }
    fn leave(&self, call_id: &KaigiId, participant: &AccountId) -> LeaveKaigi {
        LeaveKaigi {
            call_id: call_id.clone(),
            participant: participant.clone(),
            commitment: Some(self.commitment.clone()),
            nullifier: Some(self.nullifier.clone()),
            roster_root: Some(self.root),
            proof: Some(self.proof.clone()),
        }
    }
    fn end(&self, call_id: &KaigiId) -> EndKaigi {
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
fn authorization_artifacts(
    tx: &StateTransaction<'_, '_>,
    record: &KaigiRecord,
    subject: &AccountId,
    sequence: u64,
    action: KaigiAuthorizationActionV1,
    blinding: [u8; 32],
) -> AuthorizationArtifacts {
    let network = *tx.network_id();
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
    AuthorizationArtifacts {
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
fn usage_instruction(tx: &StateTransaction<'_, '_>, record: &KaigiRecord) -> RecordKaigiUsage {
    let network = *tx.network_id();
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
fn new_state() -> State {
    let mut state = State::new_for_testing(
        test_world::world_with_test_accounts(),
        Kura::blank_kura_for_testing(),
        LiveQueryStore::start_test(),
    );
    state
        .edit_zk_for_testing(|zk| zk.pipa_r.enabled = true)
        .expect("fixture ZK settings install");
    state
        .edit_zk_for_testing(|zk| zk.verify_timeout = Duration::ZERO)
        .expect("fixture ZK settings install");
    state
        .edit_zk_for_testing(|zk| zk.kaigi_authorization_vk = Some(authorization_key().reference()))
        .expect("fixture ZK settings install");
    state
}
fn register_key(tx: &mut StateTransaction<'_, '_>, key: &GovernedKey) {
    iroha_data_model::isi::verifying_keys::RegisterVerifyingKey {
        id: key.id(),
        record: key.record(),
    }
    .execute(&ALICE_ID, tx)
    .expect("register governed final V1 verifier");
}
fn seed(tx: &mut StateTransaction<'_, '_>, label: &str) -> (NewKaigi, AccountId, AccountId) {
    let manage_vk = iroha_data_model::permission::Permission::new(
        "CanManageVerifyingKeys".parse().unwrap(),
        Json::new(()),
    );
    Grant::account_permission(manage_vk, ALICE_ID.clone())
        .execute(&ALICE_ID, tx)
        .expect("grant verifier governance");
    register_key(tx, authorization_key());
    let domain = DomainId::try_new("kaigi", "universal").unwrap();
    let (host, _) = gen_account_in("kaigi");
    let (participant, _) = gen_account_in("kaigi");
    Register::domain(Domain::new(domain.clone()))
        .execute(&ALICE_ID, tx)
        .unwrap();
    for account in [&host, &participant] {
        Register::account(Account::new(account.clone()))
            .execute(&ALICE_ID, tx)
            .unwrap();
    }
    let mut call = NewKaigi::with_defaults(
        KaigiId::new(domain, Name::from_str(label).unwrap()),
        host.clone(),
    );
    call.privacy_mode = KaigiPrivacyMode::ZkRosterV1;
    (call, host, participant)
}
fn read_record(tx: &StateTransaction<'_, '_>, call: &KaigiId) -> KaigiRecord {
    tx.world
        .domain(&call.domain_id)
        .unwrap()
        .metadata()
        .get(&kaigi_metadata_key(&call.call_name).unwrap())
        .unwrap()
        .clone()
        .try_into_any_norito()
        .expect("canonical record retained in domain metadata")
}
fn create_private(tx: &mut StateTransaction<'_, '_>, call: &NewKaigi) -> AuthorizationArtifacts {
    let initial = KaigiRecord::from_new(call, 0);
    let proof = authorization_artifacts(
        tx,
        &initial,
        call.host(),
        0,
        KaigiAuthorizationActionV1::HostCreate,
        HOST_BLINDING,
    );
    proof
        .create(call.clone())
        .execute(call.host(), tx)
        .expect("host-authorized private creation");
    proof
}
fn mutate_open_verify_envelope(
    proof: &[u8],
    mutate: impl FnOnce(&mut OpenVerifyEnvelope),
) -> Vec<u8> {
    let mut envelope: OpenVerifyEnvelope =
        norito::decode_canonical(proof).expect("decode canonical OpenVerifyEnvelope fixture");
    mutate(&mut envelope);
    norito::encode_canonical(&envelope).expect("serialize mutated OpenVerifyEnvelope")
}
// Mutate one exact scalar in the authenticated instance carrier, retaining the
// original proof. Every context/output row must remain bound at admission.
fn mutate_instance_row(proof: &[u8], row: usize, expected_rows: usize) -> Vec<u8> {
    mutate_open_verify_envelope(proof, |envelope| {
        let mut native: iroha_data_model::zk::NativePipaRProofV1 =
            norito::decode_canonical(&envelope.proof_bytes).unwrap();
        assert_eq!(native.public_inputs.len(), expected_rows);
        assert!(row < expected_rows);
        let value = Option::<Scalar>::from(Scalar::from_repr(native.public_inputs[row])).unwrap();
        native.public_inputs[row] = (value + Scalar::from(1)).to_repr();
        envelope.proof_bytes = norito::encode_canonical(&native).unwrap();
    })
}

#[test]
fn kaigi_private_create_join_leave_rejoin_and_end_use_real_ledger_bound_proofs() {
    use KaigiAuthorizationActionV1::{HostEnd, Join, Leave};
    let state = new_state();
    let mut block = state.block(BlockHeader::new(
        NonZeroU64::new(1).unwrap(),
        None,
        None,
        0,
        0,
    ));
    let mut tx = block.transaction();
    let (call, host, participant) = seed(&mut tx, "privacy");
    let created = create_private(&mut tx, &call);
    let initial = read_record(&tx, call.id());
    assert_eq!(initial.host_commitment.as_ref(), Some(&created.commitment));
    assert!(initial.roster_commitments.is_empty());
    assert_eq!(initial.nullifier_log.len(), 1);
    let joined =
        authorization_artifacts(&tx, &initial, &participant, 1, Join, PARTICIPANT_BLINDING);
    assert!(
        joined
            .join(call.id(), &participant)
            .execute(&host, &mut tx)
            .is_err(),
        "host cannot impersonate participant"
    );
    joined
        .join(call.id(), &participant)
        .execute(&participant, &mut tx)
        .expect("join sequence one");
    assert!(
        joined
            .join(call.id(), &participant)
            .execute(&participant, &mut tx)
            .is_err(),
        "active participation replay"
    );
    let active = read_record(&tx, call.id());
    assert_eq!(active.roster_commitments, vec![joined.commitment.clone()]);
    assert_eq!(active.nullifier_log.len(), 2);
    assert!(
        active.participants.is_empty(),
        "public participant list stays empty in private mode"
    );
    assert_ne!(active.roster_root(), initial.roster_root());
    assert_eq!(active.private_participation.entries()[0].sequence(), 1);
    let left = authorization_artifacts(&tx, &active, &participant, 1, Leave, PARTICIPANT_BLINDING);
    assert_eq!(
        left.commitment, joined.commitment,
        "same participation opening across actions"
    );
    assert_ne!(
        left.nullifier, joined.nullifier,
        "action-separated deterministic nullifiers"
    );
    assert!(
        joined
            .leave(call.id(), &participant)
            .execute(&participant, &mut tx)
            .is_err(),
        "join proof is not leave authorization"
    );
    left.leave(call.id(), &participant)
        .execute(&participant, &mut tx)
        .expect("on-chain leave");
    assert!(
        left.leave(call.id(), &participant)
            .execute(&participant, &mut tx)
            .is_err(),
        "leave replay"
    );
    let departed = read_record(&tx, call.id());
    assert!(departed.roster_commitments.is_empty());
    assert_eq!(departed.roster_root(), initial.roster_root());
    assert_eq!(departed.nullifier_log.len(), 3);
    assert_eq!(departed.private_participation.entries()[0].sequence(), 2);
    assert_eq!(
        departed.private_participation.entries()[0].active_commitment(),
        None
    );
    assert!(
        joined
            .join(call.id(), &participant)
            .execute(&participant, &mut tx)
            .is_err(),
        "departed sequence cannot be replayed"
    );
    let rejoined =
        authorization_artifacts(&tx, &departed, &participant, 2, Join, PARTICIPANT_BLINDING);
    assert_ne!(rejoined.commitment, joined.commitment);
    assert_ne!(rejoined.nullifier, joined.nullifier);
    rejoined
        .join(call.id(), &participant)
        .execute(&participant, &mut tx)
        .expect("ledger-owned sequence two rejoin");
    let reactivated = read_record(&tx, call.id());
    let ended = authorization_artifacts(&tx, &reactivated, &host, 0, HostEnd, HOST_BLINDING);
    assert_eq!(ended.commitment, created.commitment);
    assert!(
        ended.end(call.id()).execute(&participant, &mut tx).is_err(),
        "only signed host can end"
    );
    assert!(
        created.end(call.id()).execute(&host, &mut tx).is_err(),
        "create proof cannot authorize end"
    );
    ended
        .end(call.id())
        .execute(&host, &mut tx)
        .expect("host proof ends call");
    assert!(
        ended.end(call.id()).execute(&host, &mut tx).is_err(),
        "terminal replay"
    );
    assert!(
        rejoined
            .join(call.id(), &participant)
            .execute(&participant, &mut tx)
            .is_err(),
        "ended call cannot reopen"
    );
    assert!(
        created
            .create(call.clone())
            .execute(&host, &mut tx)
            .is_err(),
        "permanent call ID cannot be recreated"
    );
    let final_record = read_record(&tx, call.id());
    assert_eq!(final_record.status, KaigiStatus::Ended);
    assert_eq!(final_record.nullifier_log.len(), 5);
    assert_eq!(
        final_record.private_participation.entries()[0].original_account(),
        &participant
    );
    tx.apply();
    block.commit_world_overlay_for_testing().unwrap();
    let view = state.view();
    let stored = view
        .world
        .domain(&call.id().domain_id)
        .unwrap()
        .metadata()
        .get(&kaigi_metadata_key(&call.id().call_name).unwrap())
        .unwrap()
        .clone();
    let committed: KaigiRecord = stored.try_into_any_norito().unwrap();
    assert_eq!(
        committed, final_record,
        "canonical record survives block commit"
    );
}

#[test]
fn kaigi_authorization_rejects_metadata_root_cap_and_admission_tampering() {
    let state = new_state();
    let mut block = state.block(BlockHeader::new(
        NonZeroU64::new(1).unwrap(),
        None,
        None,
        0,
        0,
    ));
    let mut tx = block.transaction();
    let (call, host, participant) = seed(&mut tx, "admission");
    let empty_create = CreateKaigi {
        call: call.clone(),
        commitment: None,
        nullifier: None,
        roster_root: None,
        proof: None,
    };
    assert!(
        empty_create.execute(&host, &mut tx).is_err(),
        "private host creation requires full proof quartet"
    );
    create_private(&mut tx, &call);
    let initial = read_record(&tx, call.id());
    let joined = authorization_artifacts(
        &tx,
        &initial,
        &participant,
        1,
        KaigiAuthorizationActionV1::Join,
        PARTICIPANT_BLINDING,
    );
    for (name, proof) in [
        (
            "auxiliary bytes",
            mutate_open_verify_envelope(&joined.proof, |p| p.aux = b"ignored-hint".to_vec()),
        ),
        (
            "zero verifier hash",
            mutate_open_verify_envelope(&joined.proof, |p| p.vk_hash = [0; 32]),
        ),
        (
            "wrong verifier hash",
            mutate_open_verify_envelope(&joined.proof, |p| p.vk_hash = [0x31; 32]),
        ),
        (
            "short circuit ID",
            mutate_open_verify_envelope(&joined.proof, |p| {
                p.circuit_id = "halo2/pasta/kaigi-authorization-v1".into()
            }),
        ),
        (
            "wrong schema",
            mutate_open_verify_envelope(&joined.proof, |p| p.public_inputs.push(0)),
        ),
    ] {
        let mut instruction = joined.join(call.id(), &participant);
        instruction.proof = Some(proof);
        assert!(
            instruction.execute(&participant, &mut tx).is_err(),
            "must reject {name}"
        );
        assert_eq!(
            read_record(&tx, call.id()),
            initial,
            "{name} did not mutate state"
        );
    }
    for row in 0..KAIGI_AUTHORIZATION_INSTANCE_ROWS_V1 {
        let mut instruction = joined.join(call.id(), &participant);
        instruction.proof = Some(mutate_instance_row(
            &joined.proof,
            row,
            KAIGI_AUTHORIZATION_INSTANCE_ROWS_V1,
        ));
        assert!(
            instruction.execute(&participant, &mut tx).is_err(),
            "authorization row {row} must be bound"
        );
        assert_eq!(read_record(&tx, call.id()), initial);
    }
    let mut wrong_root = joined.join(call.id(), &participant);
    wrong_root.roster_root = Some(Hash::new("different pre-state root"));
    let error = wrong_root
        .execute(&participant, &mut tx)
        .expect_err("wrong roster root");
    assert!(format!("{error:?}").contains("roster root differs"));
    for mask in 0u8..15 {
        let mut instruction = joined.join(call.id(), &participant);
        if mask & 1 == 0 {
            instruction.commitment = None;
        }
        if mask & 2 == 0 {
            instruction.nullifier = None;
        }
        if mask & 4 == 0 {
            instruction.roster_root = None;
        }
        if mask & 8 == 0 {
            instruction.proof = None;
        }
        assert!(
            instruction.execute(&participant, &mut tx).is_err(),
            "partial quartet {mask}"
        );
    }
    let key = authorization_key();
    for (name, record) in [
        ("missing cap", {
            let mut r = key.record();
            r.max_proof_bytes = 0;
            r
        }),
        ("exceeded cap", {
            let mut r = key.record();
            r.max_proof_bytes = (joined.proof.len() - 1).try_into().unwrap();
            r
        }),
        ("missing gas schedule", {
            let mut r = key.record();
            r.gas_schedule_id = None;
            r
        }),
        ("inactive verifier", {
            let mut r = key.record();
            r.status = ConfidentialStatus::Proposed;
            r
        }),
    ] {
        tx.world
            .verifying_keys_mut_for_testing()
            .insert(key.id(), record);
        assert!(
            joined
                .join(call.id(), &participant)
                .execute(&participant, &mut tx)
                .is_err(),
            "reject {name}"
        );
        assert_eq!(read_record(&tx, call.id()), initial);
    }
    tx.world
        .verifying_keys_mut_for_testing()
        .insert(key.id(), key.record());
    tx.zk.kaigi_authorization_vk = None;
    assert!(
        joined
            .join(call.id(), &participant)
            .execute(&participant, &mut tx)
            .is_err(),
        "missing configured authority"
    );
    tx.zk.kaigi_authorization_vk = Some(key.reference());
    let mut exact_cap = key.record();
    exact_cap.max_proof_bytes = joined.proof.len().try_into().unwrap();
    tx.world
        .verifying_keys_mut_for_testing()
        .insert(key.id(), exact_cap);
    joined
        .join(call.id(), &participant)
        .execute(&participant, &mut tx)
        .expect("canonical governed proof at exact cap");
}

#[test]
fn usage_summary_emitted_only_for_exact_host_context_and_fresh_segment() {
    let mut state = new_state();
    state
        .edit_zk_for_testing(|zk| zk.kaigi_usage_vk = Some(usage_key().reference()))
        .expect("fixture ZK settings install");
    let mut block = state.block(BlockHeader::new(
        NonZeroU64::new(1).unwrap(),
        None,
        None,
        0,
        0,
    ));
    let mut tx = block.transaction();
    let (call, host, participant) = seed(&mut tx, "usage");
    register_key(&mut tx, usage_key());
    create_private(&mut tx, &call);
    let initial = read_record(&tx, call.id());
    let usage = usage_instruction(&tx, &initial);
    assert!(
        usage.clone().execute(&participant, &mut tx).is_err(),
        "usage must be signed by host"
    );
    let mut altered = usage.clone();
    altered.duration_ms += 1;
    assert!(
        altered.execute(&host, &mut tx).is_err(),
        "proof binds duration"
    );
    let mut altered = usage.clone();
    altered.billed_gas += 1;
    assert!(
        altered.execute(&host, &mut tx).is_err(),
        "proof binds billed gas"
    );
    assert_eq!(
        read_record(&tx, call.id()),
        initial,
        "failed usage does not alter counters"
    );
    for row in 0..KAIGI_USAGE_INSTANCE_ROWS_V1 {
        let mut altered = usage.clone();
        altered.proof = Some(mutate_instance_row(
            usage.proof.as_ref().unwrap(),
            row,
            KAIGI_USAGE_INSTANCE_ROWS_V1,
        ));
        assert!(
            altered.execute(&host, &mut tx).is_err(),
            "usage row {row} must be bound"
        );
        assert_eq!(read_record(&tx, call.id()), initial);
    }
    tx.world.take_external_events();
    usage
        .clone()
        .execute(&host, &mut tx)
        .expect("final 25-row host usage proof");
    let events = tx.world.take_external_events();
    let summary = events
        .iter()
        .find_map(|event| {
            if let EventBox::Data(ev) = event {
                if let DataEvent::Domain(DomainEvent::KaigiUsageSummary(summary)) = ev.as_ref() {
                    return Some(summary.clone());
                }
            }
            None
        })
        .expect("usage summary event emitted");
    assert_eq!(summary.call, *call.id());
    assert_eq!(summary.total_duration_ms, usage.duration_ms);
    assert_eq!(summary.total_billed_gas, usage.billed_gas);
    assert_eq!(summary.segments_recorded, 1);
    let accepted = read_record(&tx, call.id());
    assert_eq!(
        accepted.usage_commitments,
        vec![usage.usage_commitment.unwrap()]
    );
    assert!(
        usage.execute(&host, &mut tx).is_err(),
        "usage replay cannot bill a second segment"
    );
    assert_eq!(read_record(&tx, call.id()), accepted);
}
