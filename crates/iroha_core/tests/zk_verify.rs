#![doc = "ZK attachment pre-verify wiring tests (dedup and basic sanity)."]
#![cfg(feature = "zk-tests")]
//! ZK attachment pre-verify wiring tests (dedup and basic sanity).
#![cfg(feature = "zk-preverify")]
#[path = "common/zk_components.rs"]
mod zk_components;
use iroha_core::{
    executor::Executor,
    kura::Kura,
    query::store::LiveQueryStore,
    smartcontracts::Execute as _,
    state::{State, WorldReadOnly},
};
use iroha_core_zk::test_utils::{FixtureEnvelope, native_confidential_fixture_envelope};
use iroha_data_model::{
    ValidationFail,
    confidential::ConfidentialStatus,
    isi::error::{InstructionExecutionError, InvalidParameterError},
    prelude::*,
    transaction::signed_attachments::SignedAttachmentErrorV1,
    zk::BackendTag,
};
use iroha_test_samples::ALICE_ID;
use mv::storage::StorageReadOnly;
use nonzero_ext::nonzero;
use zk_components::execute_isi_component;

#[path = "common/root_scope_fixture.rs"]
mod root_scope_fixture;
/// Seed the canonical verifying key of [`NATIVE_CIRCUIT_ID`] and return its registry id
/// and commitment.
///
/// A key enters the registry through the governed lifecycle, which a component fixture does
/// not run. The fixture applies the grant and the registration themselves, as the registry
/// tests of the crate do; the caps under test are charged by `VerifyProof`, which the
/// calling test submits through the executor.
fn seed_production_verifying_key(
    stx: &mut iroha_core::state::StateTransaction<'_, '_>,
) -> (iroha_data_model::proof::VerifyingKeyId, [u8; 32]) {
    let permission = iroha_data_model::permission::Permission::new(
        "CanManageVerifyingKeys".parse().expect("permission name"),
        iroha_primitives::json::Json::new(()),
    );
    Grant::account_permission(permission, ALICE_ID.clone())
        .execute(&ALICE_ID, stx)
        .expect("grant verifying-key management");
    let id = iroha_data_model::proof::VerifyingKeyId::new("pipa-r/pasta", "vk_main");
    let record = iroha_core_zk::confidential_v2::confidential_transfer_v2_vk_record("core", 1)
        .expect("canonical verifying key of the production circuit");
    let commitment = record.commitment;
    iroha_data_model::isi::verifying_keys::RegisterVerifyingKey {
        id: id.clone(),
        record,
    }
    .execute(&ALICE_ID, stx)
    .expect("register the production verifying key");
    (id, commitment)
}
/// A proof of [`NATIVE_CIRCUIT_ID`] whose envelope the registry admits (the canonical
/// public-input schema of the circuit, the commitment of its registered key) and whose
/// payload is `seed` repeated: the backend runs and records the proof as rejected.
fn production_circuit_proof(
    vk_commitment: [u8; 32],
    seed: u8,
) -> iroha_data_model::proof::ProofBox {
    let fixture = iroha_core_zk::test_utils::native_framing_fixture_envelope(
        NATIVE_CIRCUIT_ID,
        vk_commitment,
    );
    let mut envelope: iroha_data_model::zk::OpenVerifyEnvelope =
        norito::decode_canonical(&fixture.proof_bytes).expect("decode native envelope");
    let mut body: iroha_data_model::zk::NativePipaRProofV1 =
        norito::decode_canonical(&envelope.proof_bytes).expect("decode native proof body");
    body.proof.fill(seed);
    envelope.proof_bytes = norito::encode_canonical(&body).expect("encode native proof body");
    iroha_data_model::proof::ProofBox::new(
        "pipa-r/pasta".into(),
        norito::encode_canonical(&envelope).expect("encode native envelope"),
    )
}
#[path = "common/native_genesis.rs"]
mod native_genesis;
#[path = "common/world_fixture.rs"]
mod test_world;
use native_genesis::certified_state;
const NATIVE_CIRCUIT_ID: &str = iroha_core_zk::confidential_v2::CONFIDENTIAL_TRANSFER_V2_CIRCUIT_ID;
fn bound_native_fixture() -> FixtureEnvelope {
    native_confidential_fixture_envelope()
}
const UNSUPPORTED_PROTOCOL_ATTACHMENT_BACKENDS: &[&str] = &[
    "halo2/ipa/orchard",
    "stark/fri/miden",
    "anonymous-pgc",
    "verange",
    "zk-ams",
    "zk-x509",
    "sis-hints-anoncred-pq-v0",
    "sis-with-hints",
    "pq-masp-stark-fri",
];
const PRODUCTION_CLAIM_ATTACHMENT_BACKENDS: &[&str] = &[
    "halo2/ipa:production-ready",
    "halo2/ipa:claimed-production",
    "halo2/ipa:mainnet-ready",
    "halo2/ipa:release-ready",
    "halo2/ipa:certified-mainnet",
    "halo2/ipa:third-party-audited",
    "stark/fri/audit-signoff",
    "stark/fri/externally-audited",
    "stark/fri/boi-audited",
    "stark/fri/external-security-review",
    "stark/fri/security-review-passed",
    "stark/fri/S.e.c.u.r.i.t.yReviewPassed",
    "stark/fri/s.e.c.u.r.i.t.y-review-passed",
    "stark/fri/s-e-c-u-r-i-t-y-a-u-d-i-t-e-d",
    "stark/fri/a-u-d-i-t-c-l-a-i-m",
];
fn build_vk_record(
    _name: &str,
    vk_box: iroha_data_model::proof::VerifyingKeyBox,
    schema_hash: [u8; 32],
) -> iroha_data_model::proof::VerifyingKeyRecord {
    let commitment = iroha_core_zk::hash_vk(&vk_box);
    let mut record = iroha_data_model::proof::VerifyingKeyRecord::new_with_owner(
        1,
        NATIVE_CIRCUIT_ID,
        None,
        "core",
        BackendTag::NativePipaRPasta,
        "vesta",
        schema_hash,
        commitment,
    );
    record.vk_len = vk_box.bytes.len() as u32;
    record.status = ConfidentialStatus::Active;
    record.key = Some(vk_box);
    record.gas_schedule_id = Some("native_pipa_r_default".into());
    record
}
fn try_signed_empty_tx_with_attachments(
    network_id: NetworkId,
    attachments: Vec<iroha_data_model::proof::ProofAttachment>,
) -> Result<SignedTransaction, SignedAttachmentErrorV1> {
    TransactionBuilder::new(
        network_id,
        ALICE_ID.clone(),
        iroha_data_model::transaction::FeePaymentIntent::authority(Vec::new(), None),
    )
    .with_executable(Executable::Instructions(
        Vec::<InstructionBox>::new().into(),
    ))
    .with_proof_attachments(attachments)
    .map(|builder| builder.sign(iroha_test_samples::ALICE_KEYPAIR.private_key()))
}
fn signed_empty_tx_with_attachments(
    network_id: NetworkId,
    attachments: Vec<iroha_data_model::proof::ProofAttachment>,
) -> SignedTransaction {
    try_signed_empty_tx_with_attachments(network_id, attachments).expect("valid proof carriers")
}
fn bounded_proof_attachments(
    attachments: Vec<iroha_data_model::proof::ProofAttachment>,
) -> Vec<iroha_data_model::proof::ProofAttachment> {
    attachments
}
fn grant_vk_management(
    _exec: &Executor,
    stx: &mut iroha_core::state::StateTransaction<'_, '_>,
    authority: &AccountId,
) {
    let permission = iroha_data_model::permission::Permission::new(
        "CanManageVerifyingKeys".parse().expect("permission name"),
        iroha_primitives::json::Json::new(()),
    );
    let grant: InstructionBox = Grant::account_permission(permission, authority.clone()).into();
    execute_isi_component(stx, authority, grant).expect("grant vk management");
}
#[test]
fn duplicate_proof_in_same_block_is_rejected() {
    // Minimal node state and block context
    let world = test_world::world_with_test_accounts();
    let state = certified_state(world);
    let header = iroha_data_model::block::BlockHeader::new(
        nonzero!(2_u64),
        state.view().latest_block_hash(),
        None,
        1,
        0,
    );
    let mut block = state.block(header);
    // Build a transaction with proofs carrying a single inline attachment and no instructions
    let authority = ALICE_ID.clone();
    let private_key = iroha_test_samples::ALICE_KEYPAIR.private_key().clone();
    let fixture = bound_native_fixture();
    let vk_id = iroha_data_model::proof::VerifyingKeyId::new("pipa-r/pasta", "vk_preverify");
    let vk_box = fixture
        .vk_box("pipa-r/pasta")
        .expect("fixture verifying key");
    let vk_record = build_vk_record("vk_preverify", vk_box, fixture.schema_hash);
    let exec = Executor::default();
    {
        let mut reg_stx = block.transaction();
        let reg_vk: InstructionBox = iroha_data_model::isi::verifying_keys::RegisterVerifyingKey {
            id: vk_id.clone(),
            record: vk_record,
        }
        .into();
        grant_vk_management(&exec, &mut reg_stx, &authority);
        execute_isi_component(&mut reg_stx, &authority, reg_vk).expect("register vk");
        reg_stx.apply();
    }
    let attachments =
        bounded_proof_attachments(vec![iroha_data_model::proof::ProofAttachment::new_ref(
            "pipa-r/pasta".into(),
            fixture.proof_box("pipa-r/pasta"),
            vk_id,
        )]);
    let tx1: SignedTransaction = TransactionBuilder::new(
        *state.network_id_ref(),
        authority.clone(),
        iroha_data_model::transaction::FeePaymentIntent::authority(Vec::new(), None),
    )
    .with_executable(Executable::Instructions(
        Vec::<InstructionBox>::new().into(),
    ))
    .with_proof_attachments(attachments.clone())
    .expect("valid proof carriers")
    .sign(&private_key);
    let mut stx1 = block.transaction();
    Executor::preverify_attachments(&mut stx1, &tx1).expect("first tx should pass pre-verify");
    drop(stx1);
    // Second identical transaction in the same block should hit dedup
    let tx2: SignedTransaction = TransactionBuilder::new(
        *state.network_id_ref(),
        authority.clone(),
        iroha_data_model::transaction::FeePaymentIntent::authority(Vec::new(), None),
    )
    .with_executable(Executable::Instructions(
        Vec::<InstructionBox>::new().into(),
    ))
    .with_proof_attachments(attachments)
    .expect("valid proof carriers")
    .sign(&private_key);
    let mut stx2 = block.transaction();
    let err = Executor::preverify_attachments(&mut stx2, &tx2)
        .expect_err("duplicate proof should be rejected");
    match err {
        ValidationFail::NotPermitted(msg) => {
            assert!(msg.contains("duplicate proof"));
        }
        other => panic!("unexpected error: {other:?}"),
    }
}
#[test]
fn verifyproof_isi_records_proof() {
    let world = test_world::world_with_test_accounts();
    let kura = Kura::blank_kura_for_testing();
    let query_handle = LiveQueryStore::start_test();
    let state = State::new_for_testing(world, kura, query_handle);
    let header = iroha_data_model::block::BlockHeader::new(nonzero!(1_u64), None, None, 0, 0);
    let mut block = state.block(header);
    let mut stx = block.transaction();
    let exec = Executor::default();
    // Register a verifying key record
    let vk_id = iroha_data_model::proof::VerifyingKeyId::new("pipa-r/pasta", "vk_main");
    let fixture = bound_native_fixture();
    let vk_box = fixture
        .vk_box("pipa-r/pasta")
        .expect("fixture verifying key");
    let vk_rec = build_vk_record("vk_main", vk_box, fixture.schema_hash);
    let reg_vk: InstructionBox = iroha_data_model::isi::verifying_keys::RegisterVerifyingKey {
        id: vk_id.clone(),
        record: vk_rec,
    }
    .into();
    grant_vk_management(&exec, &mut stx, &ALICE_ID.clone());
    execute_isi_component(&mut stx, &ALICE_ID.clone(), reg_vk).expect("register vk");
    // Verify a proof using VK reference
    let proof_box = fixture.proof_box("pipa-r/pasta");
    let attachment = iroha_data_model::proof::ProofAttachment::new_ref(
        "pipa-r/pasta".into(),
        proof_box.clone(),
        vk_id.clone(),
    );
    let verify: InstructionBox = iroha_data_model::isi::zk::VerifyProof::new(attachment).into();
    execute_isi_component(&mut stx, &ALICE_ID.clone(), verify).expect("verify proof");
    // Apply transaction and ensure a proof record exists
    let pid = iroha_data_model::proof::ProofId {
        backend: "pipa-r/pasta".into(),
        proof_hash: iroha_core_zk::hash_proof(&proof_box),
    };
    assert!(stx.world.proofs().get(&pid).is_some());
}
#[test]
fn verifyproof_rejects_when_exceeding_size_cap() {
    let world = test_world::world_with_test_accounts();
    let kura = Kura::blank_kura_for_testing();
    let query_handle = LiveQueryStore::start_test();
    let mut state = State::new_for_testing(world, kura, query_handle);
    let mut zk_cfg = state.installed_zk().clone();
    zk_cfg.max_proof_size_bytes = 3;
    state
        .set_zk(zk_cfg)
        .expect("empty state accepts verifier test configuration");
    // Instruction execution requires committed root authority: the first height commits the
    // Global root scope and the fixture executes at the second height.
    root_scope_fixture::commit_global_root_scope(&state);
    let header = iroha_data_model::block::BlockHeader::new(nonzero!(2_u64), None, None, 0, 0);
    let mut block = state.block(header);
    let mut stx = block.transaction();
    let _exec = Executor::default();
    let (vk_id, vk_commitment) = seed_production_verifying_key(&mut stx);
    // A correctly framed native envelope is far above the three-byte cap.
    let fixture = iroha_core_zk::test_utils::native_framing_fixture_envelope(
        NATIVE_CIRCUIT_ID,
        vk_commitment,
    );
    let proof = fixture.proof_box("pipa-r/pasta");
    assert!(proof.bytes.len() > 3, "the fixture proof exceeds the cap");
    let attachment =
        iroha_data_model::proof::ProofAttachment::new_ref("pipa-r/pasta".into(), proof, vk_id);
    let verify: InstructionBox = iroha_data_model::isi::zk::VerifyProof::new(attachment).into();
    let err = execute_isi_component(&mut stx, &ALICE_ID.clone(), verify)
        .expect_err("proof should exceed size cap");
    assert!(
        matches!(
            &err,
            ValidationFail::InstructionFailed(InstructionExecutionError::InvalidParameter(
                InvalidParameterError::SmartContract(msg)
            )) if msg.contains("max_proof_size_bytes")
        ),
        "unexpected error: {err:?}"
    );
    assert_eq!(
        stx.world.proofs().iter().count(),
        0,
        "a proof above the size cap leaves no record"
    );
}
#[test]
fn verifyproof_rejects_when_block_cap_hit() {
    let world = test_world::world_with_test_accounts();
    let kura = Kura::blank_kura_for_testing();
    let query_handle = LiveQueryStore::start_test();
    let mut state = State::new_for_testing(world, kura, query_handle);
    let mut zk_cfg = state.installed_zk().clone();
    zk_cfg.max_confidential_ops_per_block = 1;
    zk_cfg.max_verify_calls_per_block = 1;
    zk_cfg.max_verify_calls_per_tx = 2;
    zk_cfg.max_proof_bytes_block = 10_000_000;
    zk_cfg.max_proof_size_bytes = 1_000_000;
    state
        .set_zk(zk_cfg)
        .expect("empty state accepts verifier test configuration");
    // Instruction execution requires committed root authority: the first height commits the
    // Global root scope and the fixture executes at the second height.
    root_scope_fixture::commit_global_root_scope(&state);
    let header = iroha_data_model::block::BlockHeader::new(nonzero!(2_u64), None, None, 0, 0);
    let mut block = state.block(header);
    let mut stx = block.transaction();
    let _exec = Executor::default();
    let (vk_id, vk_commitment) = seed_production_verifying_key(&mut stx);
    // The cap counts verification calls, whatever the backend decides: the first proof is
    // admitted, verified and recorded as rejected, and it uses the one call of the block.
    let first = production_circuit_proof(vk_commitment, 0x11);
    let first_id = iroha_data_model::proof::ProofId {
        backend: "pipa-r/pasta".into(),
        proof_hash: iroha_core_zk::hash_proof(&first),
    };
    let attachment = iroha_data_model::proof::ProofAttachment::new_ref(
        "pipa-r/pasta".into(),
        first,
        vk_id.clone(),
    );
    let verify: InstructionBox = iroha_data_model::isi::zk::VerifyProof::new(attachment).into();
    execute_isi_component(&mut stx, &ALICE_ID.clone(), verify)
        .expect("first verify should succeed");
    assert_eq!(
        stx.world
            .proofs()
            .get(&first_id)
            .expect("the first call records its proof")
            .status,
        iroha_data_model::proof::ProofStatus::Rejected,
        "the placeholder payload is not a valid proof"
    );
    let second = production_circuit_proof(vk_commitment, 0x22);
    let second_id = iroha_data_model::proof::ProofId {
        backend: "pipa-r/pasta".into(),
        proof_hash: iroha_core_zk::hash_proof(&second),
    };
    let attachment2 =
        iroha_data_model::proof::ProofAttachment::new_ref("pipa-r/pasta".into(), second, vk_id);
    let verify2: InstructionBox = iroha_data_model::isi::zk::VerifyProof::new(attachment2).into();
    let err = execute_isi_component(&mut stx, &ALICE_ID.clone(), verify2)
        .expect_err("second verify should hit block cap");
    assert!(
        matches!(
            &err,
            ValidationFail::InstructionFailed(InstructionExecutionError::InvalidParameter(
                InvalidParameterError::SmartContract(msg)
            )) if msg.contains("per block exceeded")
        ),
        "unexpected error: {err:?}"
    );
    assert!(
        stx.world.proofs().get(&second_id).is_none(),
        "the call above the block cap leaves no record"
    );
}
#[test]
fn preverify_rejects_missing_vk_reference() {
    let world = test_world::world_with_test_accounts();
    let state = certified_state(world);
    let header = iroha_data_model::block::BlockHeader::new(
        nonzero!(2_u64),
        state.view().latest_block_hash(),
        None,
        1,
        0,
    );
    let mut block = state.block(header);

    // Build tx with attachment referencing a non-existent VK id
    let authority = ALICE_ID.clone();
    let private_key = iroha_test_samples::ALICE_KEYPAIR.private_key().clone();
    let vk_id = iroha_data_model::proof::VerifyingKeyId::new("pipa-r/pasta", "vk_missing");
    let fixture = bound_native_fixture();
    let attachments =
        bounded_proof_attachments(vec![iroha_data_model::proof::ProofAttachment::new_ref(
            "pipa-r/pasta".into(),
            fixture.proof_box("pipa-r/pasta"),
            vk_id,
        )]);
    let tx: SignedTransaction = TransactionBuilder::new(
        *state.network_id_ref(),
        authority.clone(),
        iroha_data_model::transaction::FeePaymentIntent::authority(Vec::new(), None),
    )
    .with_executable(Executable::Instructions(
        Vec::<InstructionBox>::new().into(),
    ))
    .with_proof_attachments(attachments)
    .expect("valid proof carriers")
    .sign(&private_key);
    let mut stx = block.transaction();
    let err = Executor::preverify_attachments(&mut stx, &tx)
        .expect_err("missing vk_ref should be rejected");
    assert!(matches!(err, ValidationFail::NotPermitted(msg) if msg.contains("verifying key")));
}
#[test]
fn signed_carrier_rejects_proof_backend_mismatch_before_lookup() {
    let world = test_world::world_with_test_accounts();
    let state = certified_state(world);

    let attachment = iroha_data_model::proof::ProofAttachment::new_ref(
        "pipa-r/pasta".into(),
        iroha_data_model::proof::ProofBox::new("stark/fri".into(), vec![1, 2, 3]),
        iroha_data_model::proof::VerifyingKeyId::new("pipa-r/pasta", "vk_mismatch"),
    );
    let error = try_signed_empty_tx_with_attachments(
        *state.network_id_ref(),
        bounded_proof_attachments(vec![attachment]),
    )
    .expect_err("malformed carrier must fail before signing and registry lookup");
    assert!(matches!(
        error,
        SignedAttachmentErrorV1::MalformedProofCarrier { index: 0, reason }
            if reason == "proof.backend must match attachment backend"
    ));
}

#[test]
fn signed_carrier_rejects_vk_ref_backend_mismatch_before_lookup() {
    let world = test_world::world_with_test_accounts();
    let state = certified_state(world);

    let fixture = bound_native_fixture();
    let attachment = iroha_data_model::proof::ProofAttachment::new_ref(
        "pipa-r/pasta".into(),
        fixture.proof_box("pipa-r/pasta"),
        iroha_data_model::proof::VerifyingKeyId::new("stark/fri", "vk_mismatch"),
    );
    let error = try_signed_empty_tx_with_attachments(
        *state.network_id_ref(),
        bounded_proof_attachments(vec![attachment]),
    )
    .expect_err("malformed carrier must fail before signing and registry lookup");
    assert!(matches!(
        error,
        SignedAttachmentErrorV1::MalformedProofCarrier { index: 0, reason }
            if reason == "vk_ref.backend must match attachment backend"
    ));
}

#[test]
fn preverify_rejects_protocol_names_as_backend_labels_before_lookup() {
    for (idx, backend) in UNSUPPORTED_PROTOCOL_ATTACHMENT_BACKENDS
        .iter()
        .copied()
        .enumerate()
    {
        let world = test_world::world_with_test_accounts();
        let state = certified_state(world);
        let header = iroha_data_model::block::BlockHeader::new(
            nonzero!(2_u64),
            state.view().latest_block_hash(),
            None,
            1,
            0,
        );
        let mut block = state.block(header);

        let attachment = iroha_data_model::proof::ProofAttachment::new_ref(
            backend.into(),
            iroha_data_model::proof::ProofBox::new(backend.into(), vec![idx as u8, 2, 3]),
            iroha_data_model::proof::VerifyingKeyId::new(
                backend,
                format!("vk_unsupported_protocol_attachment_{idx}"),
            ),
        );
        let tx = signed_empty_tx_with_attachments(
            *state.network_id_ref(),
            bounded_proof_attachments(vec![attachment]),
        );
        let mut stx = block.transaction();
        let err = Executor::preverify_attachments(&mut stx, &tx)
            .expect_err("protocol name must fail as a generic backend before registry lookup");
        assert!(
            matches!(&err, ValidationFail::NotPermitted(msg) if msg.contains("unsupported proof backends")),
            "unexpected preverify error for {backend}: {err:?}"
        );
    }
}
#[test]
fn preverify_rejects_production_claim_backend_labels_before_lookup() {
    for (idx, backend) in PRODUCTION_CLAIM_ATTACHMENT_BACKENDS
        .iter()
        .copied()
        .enumerate()
    {
        let world = test_world::world_with_test_accounts();
        let state = certified_state(world);
        let header = iroha_data_model::block::BlockHeader::new(
            nonzero!(2_u64),
            state.view().latest_block_hash(),
            None,
            1,
            0,
        );
        let mut block = state.block(header);

        let attachment = iroha_data_model::proof::ProofAttachment::new_ref(
            backend.into(),
            iroha_data_model::proof::ProofBox::new(backend.into(), vec![idx as u8, 2, 3]),
            iroha_data_model::proof::VerifyingKeyId::new(
                backend,
                format!("vk_production_claim_attachment_{idx}"),
            ),
        );
        let carrier = try_signed_empty_tx_with_attachments(
            *state.network_id_ref(),
            bounded_proof_attachments(vec![attachment]),
        );
        if !iroha_data_model::proof::verifying_key_id_field_is_portable(backend) {
            // Nonportable labels never acquire a signed carrier. The typed
            // construction refusal is earlier than any registry/preverify read.
            assert!(
                matches!(
                    &carrier,
                    Err(SignedAttachmentErrorV1::MalformedProofCarrier { index: 0, reason })
                        if reason == "vk_ref must use portable registry syntax"
                ),
                "unexpected carrier result for {backend}: {carrier:?}"
            );
            continue;
        }
        let tx = carrier.expect("portable production-claim label is a structural carrier");
        let mut stx = block.transaction();
        let err = Executor::preverify_attachments(&mut stx, &tx)
            .expect_err("production-claim attachment backend must fail before registry lookup");
        assert!(
            matches!(&err, ValidationFail::NotPermitted(msg) if msg.contains("readiness-claim proof backends")),
            "unexpected preverify error for {backend}: {err:?}"
        );
    }
}

#[test]
fn preverify_rejects_commitment_only_missing_vk_reference() {
    let world = test_world::world_with_test_accounts();
    let state = certified_state(world);
    let header = iroha_data_model::block::BlockHeader::new(
        nonzero!(2_u64),
        state.view().latest_block_hash(),
        None,
        1,
        0,
    );
    let mut block = state.block(header);

    let fixture = bound_native_fixture();
    let mut attachment = iroha_data_model::proof::ProofAttachment::new_ref(
        "pipa-r/pasta".into(),
        fixture.proof_box("pipa-r/pasta"),
        iroha_data_model::proof::VerifyingKeyId::new("pipa-r/pasta", "missing_but_committed"),
    );
    attachment.vk_commitment = Some([0xAB; 32]);
    let tx = signed_empty_tx_with_attachments(
        *state.network_id_ref(),
        bounded_proof_attachments(vec![attachment]),
    );
    let mut stx = block.transaction();
    let err = Executor::preverify_attachments(&mut stx, &tx)
        .expect_err("vk_commitment must not bypass the registry reference requirement");
    assert!(
        matches!(err, ValidationFail::NotPermitted(msg) if msg.contains("verifying key inactive"))
    );
}
#[test]
fn preverify_rejects_inactive_registered_vk_even_with_matching_commitment() {
    let world = test_world::world_with_test_accounts();
    let state = certified_state(world);
    let header = iroha_data_model::block::BlockHeader::new(
        nonzero!(2_u64),
        state.view().latest_block_hash(),
        None,
        1,
        0,
    );
    let mut block = state.block(header);
    let exec = Executor::default();
    let authority = ALICE_ID.clone();
    let vk_id = iroha_data_model::proof::VerifyingKeyId::new("pipa-r/pasta", "vk_proposed");
    let fixture = bound_native_fixture();
    let vk_box = fixture
        .vk_box("pipa-r/pasta")
        .expect("fixture verifying key");
    let mut vk_record = build_vk_record("vk_proposed", vk_box, fixture.schema_hash);
    vk_record.status = ConfidentialStatus::Proposed;
    let expected_commitment = vk_record.commitment;
    {
        let mut reg_stx = block.transaction();
        let reg_vk: InstructionBox = iroha_data_model::isi::verifying_keys::RegisterVerifyingKey {
            id: vk_id.clone(),
            record: vk_record,
        }
        .into();
        grant_vk_management(&exec, &mut reg_stx, &authority);
        execute_isi_component(&mut reg_stx, &authority, reg_vk).expect("register proposed vk");
        reg_stx.apply();
    }
    let mut attachment = iroha_data_model::proof::ProofAttachment::new_ref(
        "pipa-r/pasta".into(),
        fixture.proof_box("pipa-r/pasta"),
        vk_id,
    );
    attachment.vk_commitment = Some(expected_commitment);
    let tx = signed_empty_tx_with_attachments(
        *state.network_id_ref(),
        bounded_proof_attachments(vec![attachment]),
    );
    let mut stx = block.transaction();
    let err = Executor::preverify_attachments(&mut stx, &tx)
        .expect_err("inactive registered vk must not preverify");
    assert!(
        matches!(err, ValidationFail::NotPermitted(msg) if msg.contains("verifying key inactive"))
    );
}
#[test]
fn verifyproof_requires_registered_verifying_key() {
    let world = test_world::world_with_test_accounts();
    let kura = Kura::blank_kura_for_testing();
    let query_handle = LiveQueryStore::start_test();
    let state = State::new_for_testing(world, kura, query_handle);
    let header = iroha_data_model::block::BlockHeader::new(nonzero!(1_u64), None, None, 0, 0);
    let mut block = state.block(header);
    let mut stx = block.transaction();

    let fixture = bound_native_fixture();
    let attachment = iroha_data_model::proof::ProofAttachment::new_ref(
        "pipa-r/pasta".into(),
        fixture.proof_box("pipa-r/pasta"),
        iroha_data_model::proof::VerifyingKeyId::new("pipa-r/pasta", "missing_vk"),
    );
    let verify: InstructionBox = iroha_data_model::isi::zk::VerifyProof::new(attachment).into();
    let err = execute_isi_component(&mut stx, &ALICE_ID.clone(), verify)
        .expect_err("verifyproof should require a registered verifying key");
    assert!(
        format!("{err:?}").contains(
            "proof must reference a registered verifying key reference; inline verifying keys are not supported"
        )
    );
}
#[test]
fn verifyproof_rejects_proof_backend_mismatch_before_lookup() {
    let world = test_world::world_with_test_accounts();
    let kura = Kura::blank_kura_for_testing();
    let query_handle = LiveQueryStore::start_test();
    let state = State::new_for_testing(world, kura, query_handle);
    let header = iroha_data_model::block::BlockHeader::new(nonzero!(1_u64), None, None, 0, 0);
    let mut block = state.block(header);
    let mut stx = block.transaction();

    let attachment = iroha_data_model::proof::ProofAttachment::new_ref(
        "pipa-r/pasta".into(),
        iroha_data_model::proof::ProofBox::new("stark/fri".into(), vec![1, 2, 3]),
        iroha_data_model::proof::VerifyingKeyId::new("pipa-r/pasta", "vk_not_consulted"),
    );
    let verify: InstructionBox = iroha_data_model::isi::zk::VerifyProof::new(attachment).into();
    let err = execute_isi_component(&mut stx, &ALICE_ID.clone(), verify)
        .expect_err("proof backend mismatch must fail before registry lookup");
    assert!(format!("{err:?}").contains("proof backend mismatch"));
}
#[test]
fn verifyproof_rejects_vk_ref_backend_mismatch_before_lookup() {
    let world = test_world::world_with_test_accounts();
    let kura = Kura::blank_kura_for_testing();
    let query_handle = LiveQueryStore::start_test();
    let state = State::new_for_testing(world, kura, query_handle);
    let header = iroha_data_model::block::BlockHeader::new(nonzero!(1_u64), None, None, 0, 0);
    let mut block = state.block(header);
    let mut stx = block.transaction();

    let fixture = bound_native_fixture();
    let attachment = iroha_data_model::proof::ProofAttachment::new_ref(
        "pipa-r/pasta".into(),
        fixture.proof_box("pipa-r/pasta"),
        iroha_data_model::proof::VerifyingKeyId::new("stark/fri", "vk_not_consulted"),
    );
    let verify: InstructionBox = iroha_data_model::isi::zk::VerifyProof::new(attachment).into();
    let err = execute_isi_component(&mut stx, &ALICE_ID.clone(), verify)
        .expect_err("vk_ref backend mismatch must fail before registry lookup");
    assert!(format!("{err:?}").contains("verifying key backend mismatch"));
}
#[test]
fn verifyproof_rejects_unsupported_backend_before_lookup() {
    let world = test_world::world_with_test_accounts();
    let kura = Kura::blank_kura_for_testing();
    let query_handle = LiveQueryStore::start_test();
    let state = State::new_for_testing(world, kura, query_handle);
    let header = iroha_data_model::block::BlockHeader::new(nonzero!(1_u64), None, None, 0, 0);
    let mut block = state.block(header);
    let mut stx = block.transaction();

    let attachment = iroha_data_model::proof::ProofAttachment::new_ref(
        "halo2/unknown-native-v1".into(),
        iroha_data_model::proof::ProofBox::new("halo2/unknown-native-v1".into(), vec![1, 2, 3]),
        iroha_data_model::proof::VerifyingKeyId::new("halo2/unknown-native-v1", "vk_missing"),
    );
    let verify: InstructionBox = iroha_data_model::isi::zk::VerifyProof::new(attachment).into();
    let err = execute_isi_component(&mut stx, &ALICE_ID.clone(), verify)
        .expect_err("unsupported proof backend must fail before registry lookup");
    assert!(format!("{err:?}").contains("unsupported proof backends"));
}
#[test]
fn verifyproof_rejects_inactive_registered_verifying_key() {
    let world = test_world::world_with_test_accounts();
    let kura = Kura::blank_kura_for_testing();
    let query_handle = LiveQueryStore::start_test();
    let state = State::new_for_testing(world, kura, query_handle);
    let header = iroha_data_model::block::BlockHeader::new(nonzero!(1_u64), None, None, 0, 0);
    let mut block = state.block(header);
    let mut stx = block.transaction();
    let exec = Executor::default();
    let vk_id = iroha_data_model::proof::VerifyingKeyId::new("pipa-r/pasta", "vk_inactive");
    let fixture = bound_native_fixture();
    let vk_box = fixture
        .vk_box("pipa-r/pasta")
        .expect("fixture verifying key");
    let mut vk_rec = build_vk_record("vk_inactive", vk_box, fixture.schema_hash);
    vk_rec.status = ConfidentialStatus::Proposed;
    let reg_vk: InstructionBox = iroha_data_model::isi::verifying_keys::RegisterVerifyingKey {
        id: vk_id.clone(),
        record: vk_rec,
    }
    .into();
    grant_vk_management(&exec, &mut stx, &ALICE_ID.clone());
    execute_isi_component(&mut stx, &ALICE_ID.clone(), reg_vk).expect("register inactive vk");
    let attachment = iroha_data_model::proof::ProofAttachment::new_ref(
        "pipa-r/pasta".into(),
        fixture.proof_box("pipa-r/pasta"),
        vk_id,
    );
    let verify: InstructionBox = iroha_data_model::isi::zk::VerifyProof::new(attachment).into();
    let err = execute_isi_component(&mut stx, &ALICE_ID.clone(), verify)
        .expect_err("verifyproof must reject inactive verifying keys");
    assert!(format!("{err:?}").contains("verifying key is not active"));
}

#[test]
fn verifyproof_enforces_verifying_key_activation_window() {
    for (name, activation_height, withdraw_height) in [
        ("vk_before_activation", Some(2), None),
        ("vk_at_withdrawal", None, Some(1)),
    ] {
        let world = test_world::world_with_test_accounts();
        let kura = Kura::blank_kura_for_testing();
        let query_handle = LiveQueryStore::start_test();
        let state = State::new_for_testing(world, kura, query_handle);
        let header = iroha_data_model::block::BlockHeader::new(nonzero!(1_u64), None, None, 0, 0);
        let mut block = state.block(header);
        let mut stx = block.transaction();
        let exec = Executor::default();
        let vk_id = iroha_data_model::proof::VerifyingKeyId::new("pipa-r/pasta", name);
        let fixture = bound_native_fixture();
        let vk_box = fixture
            .vk_box("pipa-r/pasta")
            .expect("fixture verifying key");
        let mut vk_rec = build_vk_record(name, vk_box, fixture.schema_hash);
        vk_rec.activation_height = activation_height;
        vk_rec.withdraw_height = withdraw_height;
        let reg_vk: InstructionBox = iroha_data_model::isi::verifying_keys::RegisterVerifyingKey {
            id: vk_id.clone(),
            record: vk_rec,
        }
        .into();
        grant_vk_management(&exec, &mut stx, &ALICE_ID.clone());
        execute_isi_component(&mut stx, &ALICE_ID.clone(), reg_vk)
            .expect("register height-bounded vk");

        let attachment = iroha_data_model::proof::ProofAttachment::new_ref(
            "pipa-r/pasta".into(),
            fixture.proof_box("pipa-r/pasta"),
            vk_id,
        );
        let verify: InstructionBox = iroha_data_model::isi::zk::VerifyProof::new(attachment).into();
        let err = execute_isi_component(&mut stx, &ALICE_ID.clone(), verify)
            .expect_err("proof verification must honor the key activation window");
        assert!(
            format!("{err:?}").contains("verifying key is not active"),
            "unexpected error for {name}: {err:?}"
        );
    }
}

#[test]
fn verifyproof_rejects_envelope_vk_hash_mismatch() {
    let world = test_world::world_with_test_accounts();
    let kura = Kura::blank_kura_for_testing();
    let query_handle = LiveQueryStore::start_test();
    let state = State::new_for_testing(world, kura, query_handle);
    let header = iroha_data_model::block::BlockHeader::new(nonzero!(1_u64), None, None, 0, 0);
    let mut block = state.block(header);
    let mut stx = block.transaction();
    let exec = Executor::default();
    let vk_id = iroha_data_model::proof::VerifyingKeyId::new("pipa-r/pasta", "vk_tamper_hash");
    let fixture = bound_native_fixture();
    let vk_box = fixture
        .vk_box("pipa-r/pasta")
        .expect("fixture verifying key");
    let vk_rec = build_vk_record("vk_tamper_hash", vk_box, fixture.schema_hash);
    let reg_vk: InstructionBox = iroha_data_model::isi::verifying_keys::RegisterVerifyingKey {
        id: vk_id.clone(),
        record: vk_rec,
    }
    .into();
    grant_vk_management(&exec, &mut stx, &ALICE_ID.clone());
    execute_isi_component(&mut stx, &ALICE_ID.clone(), reg_vk).expect("register vk");
    let mut proof_box = fixture.proof_box("pipa-r/pasta");
    let mut envelope: iroha_data_model::zk::OpenVerifyEnvelope =
        norito::decode_from_bytes(&proof_box.bytes).expect("decode OpenVerifyEnvelope");
    envelope.vk_hash[0] ^= 0x80;
    proof_box.bytes = norito::to_bytes(&envelope).expect("encode tampered OpenVerifyEnvelope");
    let attachment =
        iroha_data_model::proof::ProofAttachment::new_ref("pipa-r/pasta".into(), proof_box, vk_id);
    let verify: InstructionBox = iroha_data_model::isi::zk::VerifyProof::new(attachment).into();
    let err = execute_isi_component(&mut stx, &ALICE_ID.clone(), verify)
        .expect_err("tampered envelope vk_hash must not verify");
    assert!(format!("{err:?}").contains("verifying key commitment mismatch"));
}
#[test]
fn verifyproof_rejects_duplicate_proof_record() {
    let world = test_world::world_with_test_accounts();
    let kura = Kura::blank_kura_for_testing();
    let query_handle = LiveQueryStore::start_test();
    let state = State::new_for_testing(world, kura, query_handle);
    let header = iroha_data_model::block::BlockHeader::new(nonzero!(1_u64), None, None, 0, 0);
    let mut block = state.block(header);
    let mut stx = block.transaction();
    let exec = Executor::default();
    let vk_id = iroha_data_model::proof::VerifyingKeyId::new("pipa-r/pasta", "vk_duplicate");
    let fixture = bound_native_fixture();
    let vk_box = fixture
        .vk_box("pipa-r/pasta")
        .expect("fixture verifying key");
    let vk_rec = build_vk_record("vk_duplicate", vk_box, fixture.schema_hash);
    let reg_vk: InstructionBox = iroha_data_model::isi::verifying_keys::RegisterVerifyingKey {
        id: vk_id.clone(),
        record: vk_rec,
    }
    .into();
    grant_vk_management(&exec, &mut stx, &ALICE_ID.clone());
    execute_isi_component(&mut stx, &ALICE_ID.clone(), reg_vk).expect("register vk");
    let attachment = iroha_data_model::proof::ProofAttachment::new_ref(
        "pipa-r/pasta".into(),
        fixture.proof_box("pipa-r/pasta"),
        vk_id,
    );
    let first: InstructionBox =
        iroha_data_model::isi::zk::VerifyProof::new(attachment.clone()).into();
    execute_isi_component(&mut stx, &ALICE_ID.clone(), first)
        .expect("first proof verify records proof");
    let duplicate: InstructionBox = iroha_data_model::isi::zk::VerifyProof::new(attachment).into();
    let err = execute_isi_component(&mut stx, &ALICE_ID.clone(), duplicate)
        .expect_err("duplicate proof record must be rejected");
    assert!(format!("{err:?}").contains("Repetition"));
}
#[test]
fn signed_carrier_rejects_empty_proof_before_preverify() {
    let world = test_world::world_with_test_accounts();
    let state = certified_state(world);
    let header = iroha_data_model::block::BlockHeader::new(
        nonzero!(2_u64),
        state.view().latest_block_hash(),
        None,
        1,
        0,
    );
    let mut block = state.block(header);
    let exec = Executor::default();
    let authority = ALICE_ID.clone();
    let vk_id = iroha_data_model::proof::VerifyingKeyId::new("pipa-r/pasta", "vk_empty_proof");
    let fixture = bound_native_fixture();
    let vk_box = fixture
        .vk_box("pipa-r/pasta")
        .expect("fixture verifying key");
    let vk_record = build_vk_record("vk_empty_proof", vk_box, fixture.schema_hash);
    {
        let mut reg_stx = block.transaction();
        let reg_vk: InstructionBox = iroha_data_model::isi::verifying_keys::RegisterVerifyingKey {
            id: vk_id.clone(),
            record: vk_record,
        }
        .into();
        grant_vk_management(&exec, &mut reg_stx, &authority);
        execute_isi_component(&mut reg_stx, &authority, reg_vk).expect("register vk");
        reg_stx.apply();
    }
    let attachments =
        bounded_proof_attachments(vec![iroha_data_model::proof::ProofAttachment::new_ref(
            "pipa-r/pasta".into(),
            iroha_data_model::proof::ProofBox::new("pipa-r/pasta".into(), vec![]),
            vk_id,
        )]);
    let error = try_signed_empty_tx_with_attachments(*state.network_id_ref(), attachments)
        .expect_err("empty proof must be refused before signing and preverification");
    assert!(matches!(
        error,
        SignedAttachmentErrorV1::MalformedProofCarrier { index: 0, reason }
            if reason == "proof.bytes must be non-empty"
    ));
}

#[test]
fn preverify_rejects_proof_too_big() {
    let world = test_world::world_with_test_accounts();
    let state = certified_state(world);
    let header = iroha_data_model::block::BlockHeader::new(
        nonzero!(2_u64),
        state.view().latest_block_hash(),
        None,
        1,
        0,
    );
    let mut block = state.block(header);
    let exec = Executor::default();
    let authority = ALICE_ID.clone();
    let private_key = iroha_test_samples::ALICE_KEYPAIR.private_key().clone();
    // Build a proof larger than the current preverify cap (1 MiB)
    let big = vec![0u8; 1_200_000];
    let vk_id = iroha_data_model::proof::VerifyingKeyId::new("pipa-r/pasta", "vk_big_proof");
    let fixture = bound_native_fixture();
    let vk_box = fixture
        .vk_box("pipa-r/pasta")
        .expect("fixture verifying key");
    let vk_record = build_vk_record("vk_big_proof", vk_box, fixture.schema_hash);
    {
        let mut reg_stx = block.transaction();
        let reg_vk: InstructionBox = iroha_data_model::isi::verifying_keys::RegisterVerifyingKey {
            id: vk_id.clone(),
            record: vk_record,
        }
        .into();
        grant_vk_management(&exec, &mut reg_stx, &authority);
        execute_isi_component(&mut reg_stx, &authority, reg_vk).expect("register vk");
        reg_stx.apply();
    }
    let attachments =
        bounded_proof_attachments(vec![iroha_data_model::proof::ProofAttachment::new_ref(
            "pipa-r/pasta".into(),
            iroha_data_model::proof::ProofBox::new("pipa-r/pasta".into(), big),
            vk_id,
        )]);
    let tx: SignedTransaction = TransactionBuilder::new(
        *state.network_id_ref(),
        authority.clone(),
        iroha_data_model::transaction::FeePaymentIntent::authority(Vec::new(), None),
    )
    .with_executable(Executable::Instructions(
        Vec::<InstructionBox>::new().into(),
    ))
    .with_proof_attachments(attachments)
    .expect("valid proof carriers")
    .sign(&private_key);
    let mut stx = block.transaction();
    let err = Executor::preverify_attachments(&mut stx, &tx)
        .expect_err("oversized proof should be rejected");
    assert!(matches!(err, ValidationFail::NotPermitted(msg) if msg.contains("proof too big")));
}
#[test]
fn verifyproof_records_rejected_malformed_native_envelope() {
    let world = test_world::world_with_test_accounts();
    let kura = Kura::blank_kura_for_testing();
    let query_handle = LiveQueryStore::start_test();
    let state = State::new_for_testing(world, kura, query_handle);
    let header = iroha_data_model::block::BlockHeader::new(nonzero!(1_u64), None, None, 0, 0);
    let mut block = state.block(header);
    let mut stx = block.transaction();
    let exec = Executor::default();
    let vk_id = iroha_data_model::proof::VerifyingKeyId::new("pipa-r/pasta", "vk_bad_proof");
    let fixture = bound_native_fixture();
    let vk_box = fixture
        .vk_box("pipa-r/pasta")
        .expect("fixture verifying key");
    let vk_record = build_vk_record("vk_bad_proof", vk_box, fixture.schema_hash);
    let reg_vk: InstructionBox = iroha_data_model::isi::verifying_keys::RegisterVerifyingKey {
        id: vk_id.clone(),
        record: vk_record,
    }
    .into();
    grant_vk_management(&exec, &mut stx, &ALICE_ID.clone());
    execute_isi_component(&mut stx, &ALICE_ID.clone(), reg_vk).expect("register vk");
    let mut proof_box = fixture.proof_box("pipa-r/pasta");
    let mut envelope: iroha_data_model::zk::OpenVerifyEnvelope =
        norito::decode_from_bytes(&proof_box.bytes).expect("decode OpenVerifyEnvelope");
    envelope.proof_bytes[0] ^= 0x01;
    proof_box.bytes = norito::to_bytes(&envelope).expect("encode tampered OpenVerifyEnvelope");
    // Registered VK reference and malformed proof on a supported backend should record rejection.
    let attachment =
        iroha_data_model::proof::ProofAttachment::new_ref("pipa-r/pasta".into(), proof_box, vk_id);
    let verify: InstructionBox =
        iroha_data_model::isi::zk::VerifyProof::new(attachment.clone()).into();
    execute_isi_component(&mut stx, &ALICE_ID.clone(), verify)
        .expect("verify should record even if rejected");
    let pid = iroha_data_model::proof::ProofId {
        backend: attachment.backend,
        proof_hash: iroha_core_zk::hash_proof(&attachment.proof),
    };
    let rec = stx.world.proofs().get(&pid).expect("proof record exists");
    assert!(matches!(
        rec.status,
        iroha_data_model::proof::ProofStatus::Rejected
    ));
}
