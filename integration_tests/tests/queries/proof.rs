#![allow(clippy::all, clippy::pedantic, clippy::nursery, clippy::restriction)]
//! Integration tests for proof queries.
//! The mixed native PIPA-R/STARK network scenario requires the `zk-stark` feature and daemon.
#[cfg(feature = "zk-stark")]
use eyre::Result;
#[cfg(feature = "zk-stark")]
use integration_tests::sandbox;
#[cfg(feature = "zk-stark")]
use iroha::data_model::{
    confidential::ConfidentialStatus,
    prelude::*,
    proof::{VerifyingKeyBox, VerifyingKeyId, VerifyingKeyRecord},
    query::proof::prelude::{
        FindProofRecords, FindProofRecordsByBackend, FindProofRecordsByStatus,
    },
    zk::BackendTag,
};
use iroha::data_model::{isi::verifying_keys, proof::ProofAttachment};
#[cfg(feature = "zk-stark")]
use iroha_core_zk::hash_vk;
#[path = "../proof_fixtures.rs"]
mod proof_fixtures;
use iroha_data_model::zk::OpenVerifyEnvelope;
#[cfg(feature = "zk-stark")]
use iroha_test_network::NetworkBuilder;
#[cfg(feature = "zk-stark")]
use iroha_test_samples::SAMPLE_GENESIS_ACCOUNT_ID;
use proof_fixtures::confidential_attachment;
#[cfg(feature = "zk-stark")]
use proof_fixtures::rejected_confidential_attachment;
#[cfg(feature = "zk-stark")]
use std::{thread::sleep, time::Duration};
#[cfg(feature = "zk-stark")]
fn active_vk_record(
    circuit_id: &str,
    backend: BackendTag,
    curve: &str,
    vk_box: VerifyingKeyBox,
    public_inputs_schema_hash: [u8; 32],
    max_proof_bytes: usize,
    gas_schedule_id: &str,
) -> VerifyingKeyRecord {
    let mut record = VerifyingKeyRecord::new(
        1,
        circuit_id,
        backend,
        curve,
        public_inputs_schema_hash,
        hash_vk(&vk_box),
    );
    record.vk_len =
        u32::try_from(vk_box.bytes.len()).expect("verifying key length should fit in u32");
    record.max_proof_bytes =
        u32::try_from(max_proof_bytes).expect("proof length should fit in u32");
    record.gas_schedule_id = Some(gas_schedule_id.to_owned());
    record.key = Some(vk_box);
    record.status = ConfidentialStatus::Active;
    record
}
fn native_attachment_and_registration(
    statement: &str,
    vk_name: &str,
) -> (ProofAttachment, verifying_keys::RegisterVerifyingKey) {
    confidential_attachment(statement, vk_name)
}
#[cfg(feature = "zk-stark")]
fn rejected_stark_attachment_and_registration(
    label: &str,
) -> (ProofAttachment, verifying_keys::RegisterVerifyingKey) {
    use iroha_core_zk::stark::{
        STARK_FRI_CONSENSUS_MIN_BLOWUP_LOG2, STARK_FRI_CONSENSUS_MIN_N_LOG2,
        STARK_FRI_CONSENSUS_MIN_QUERIES, StarkFriVerifyingKeyV1, StarkVerifyEnvelopeV1,
    };
    use iroha_data_model::zk::StarkFriOpenProofV1;
    let backend = iroha_core_zk::ZK_BACKEND_STARK_FRI_V1;
    let circuit_id = format!("{backend}:query-binding");
    let schema = b"integration:query-binding:v1";
    let vk_payload = StarkFriVerifyingKeyV1 {
        version: 1,
        circuit_id: circuit_id.clone(),
        n_log2: STARK_FRI_CONSENSUS_MIN_N_LOG2,
        blowup_log2: STARK_FRI_CONSENSUS_MIN_BLOWUP_LOG2,
        fold_arity: 2,
        queries: STARK_FRI_CONSENSUS_MIN_QUERIES,
        merkle_arity: 2,
    };
    let vk_box = VerifyingKeyBox::new(
        backend.into(),
        norito::encode_canonical(&vk_payload).expect("canonical STARK verifying key"),
    );
    let mut proof_box = iroha_core_zk::prove_stark_fri_open_verify_envelope(
        backend,
        &circuit_id,
        &vk_box,
        schema,
        vec![vec![[0x11; 32]], vec![[0x22; 32]]],
    )
    .expect("genuine Binding AIR proof at current consensus floors");
    assert!(
        iroha_core_zk::verify_backend(backend, &proof_box, Some(&vk_box))
            .expect("valid proof verification must be admitted")
    );
    let mut outer: OpenVerifyEnvelope = norito::decode_canonical(&proof_box.bytes).unwrap();
    let mut open: StarkFriOpenProofV1 = norito::decode_canonical(&outer.proof_bytes).unwrap();
    let mut inner: StarkVerifyEnvelopeV1 = norito::decode_canonical(&open.envelope_bytes).unwrap();
    // Change an authenticated FRI query coordinate, preserving every Norito
    // frame, the registered key, public statement, schema and vector extent.
    inner.proof.queries[0][0].j ^= 1;
    open.envelope_bytes = norito::encode_canonical(&inner).unwrap();
    outer.proof_bytes = norito::encode_canonical(&open).unwrap();
    proof_box.bytes = norito::encode_canonical(&outer).unwrap();
    assert!(
        !iroha_core_zk::verify_backend(backend, &proof_box, Some(&vk_box))
            .expect("corrupted proof verification must be admitted")
    );
    let vk_id = VerifyingKeyId::new(backend, label);
    let record = active_vk_record(
        &circuit_id,
        BackendTag::Stark,
        "goldilocks",
        vk_box,
        iroha_crypto::Hash::new(schema).into(),
        proof_box.bytes.len(),
        "stark_default",
    );
    let attachment = ProofAttachment::new_ref(backend.into(), proof_box, vk_id.clone());
    (
        attachment,
        verifying_keys::RegisterVerifyingKey { id: vk_id, record },
    )
}
#[cfg(feature = "zk-stark")]
#[test]
fn rejected_stark_fixture_retains_canonical_key_and_proof_framing() {
    let (attachment, registration) = rejected_stark_attachment_and_registration("query_control_vk");
    let envelope: OpenVerifyEnvelope = norito::decode_canonical(&attachment.proof.bytes).unwrap();
    assert_eq!(envelope.circuit_id, registration.record.circuit_id);
    assert_eq!(envelope.vk_hash, registration.record.commitment);
    let schema_hash: [u8; 32] = iroha_crypto::Hash::new(&envelope.public_inputs).into();
    assert_eq!(schema_hash, registration.record.public_inputs_schema_hash);
    assert_eq!(attachment.vk_ref, registration.id);
    assert!(registration.record.key.is_some());
}

#[cfg(feature = "zk-stark")]
fn proof_query_network_builder(
    registrations: impl IntoIterator<Item = verifying_keys::RegisterVerifyingKey>,
) -> NetworkBuilder {
    let mut builder = NetworkBuilder::new()
        .with_peers(4)
        .with_genesis_instruction(Grant::account_permission(
            Permission::new("CanManageVerifyingKeys".into(), Json::new(())),
            SAMPLE_GENESIS_ACCOUNT_ID.clone(),
        ));
    for registration in registrations {
        builder = builder.with_genesis_instruction(registration);
    }
    builder
}
fn native_attachment(statement: &str) -> ProofAttachment {
    native_attachment_and_registration(
        statement,
        &format!("confidential_{}", statement.replace(['/', ':'], "_")),
    )
    .0
}
#[test]
#[cfg(feature = "zk-stark")]
fn proof_query_scenarios() -> Result<()> {
    let (find_attachment, find_vk) = native_attachment_and_registration("query-find", "query_vk");
    let (backend_attachment, _) = native_attachment_and_registration("query-backend", "query_vk");
    let (verified_attachment, _) = native_attachment_and_registration("query-status", "query_vk");
    let rejected_attachment = rejected_confidential_attachment("query-rejected", "query_vk");
    let (stark_backend_attachment, stark_backend_vk) =
        rejected_stark_attachment_and_registration("query_stark_vk");
    let Some((network, rt)) = sandbox::start_network_blocking_or_skip(
        proof_query_network_builder([find_vk, stark_backend_vk]),
        stringify!(proof_query_scenarios),
    )?
    else {
        return Ok(());
    };
    let client = network.client();
    // find_proof_records_lists_after_verify
    {
        client.submit(
            iroha::data_model::isi::zk::VerifyProof::new(find_attachment),
            iroha_data_model::transaction::FeePaymentIntent::authority(Vec::new(), None),
        )?;
        rt.block_on(async { network.ensure_blocks(1).await })?;
        let recs = retry_all_proof_records(&client)?;
        assert!(
            !recs.is_empty(),
            "expected at least one proof record after VerifyProof"
        );
    }
    // find_proof_records_by_backend_filters
    {
        client.submit_all(
            [iroha::data_model::isi::zk::VerifyProof::new(
                backend_attachment,
            )],
            iroha_data_model::transaction::FeePaymentIntent::authority(Vec::new(), None),
        )?;
        client.submit_all(
            [iroha::data_model::isi::zk::VerifyProof::new(
                stark_backend_attachment,
            )],
            iroha_data_model::transaction::FeePaymentIntent::authority(Vec::new(), None),
        )?;
        rt.block_on(async { network.ensure_blocks(1).await })?;
        let native = retry_records_by_backend(&client, "pipa-r/pasta")?;
        let stark = retry_records_by_backend(&client, "stark/fri/poseidon-x7-goldilocks-6x64-v1")?;
        let native_backends = proof_record_backends(&native);
        let stark_backends = proof_record_backends(&stark);
        assert!(
            !native.is_empty(),
            "expected at least one pipa-r/pasta proof record"
        );
        assert!(
            native
                .iter()
                .all(|record| record.id.backend.as_str() == "pipa-r/pasta"),
            "backend query should only return pipa-r/pasta proof records, got {native_backends:?}"
        );
        assert!(
            !stark.is_empty(),
            "expected at least one stark/fri/poseidon-x7-goldilocks-6x64-v1 proof record"
        );
        assert!(
            stark
                .iter()
                .all(|record| record.id.backend.as_str()
                    == "stark/fri/poseidon-x7-goldilocks-6x64-v1"),
            "backend query should only return stark/fri/poseidon-x7-goldilocks-6x64-v1 proof records, got {stark_backends:?}"
        );
        let nonexistent = client
            .client()
            .query(FindProofRecordsByBackend::new("nonexistent".into()))
            .execute_all()?;
        assert!(
            nonexistent.is_empty(),
            "nonexistent backend should be empty"
        );
    }
    // find_proof_records_by_status_filters
    {
        client.submit_all(
            [iroha::data_model::isi::zk::VerifyProof::new(
                verified_attachment,
            )],
            iroha_data_model::transaction::FeePaymentIntent::authority(Vec::new(), None),
        )?;
        client.submit_all(
            [iroha::data_model::isi::zk::VerifyProof::new(
                rejected_attachment,
            )],
            iroha_data_model::transaction::FeePaymentIntent::authority(Vec::new(), None),
        )?;
        rt.block_on(async { network.ensure_blocks(1).await })?;
        let verified =
            retry_records_by_status(&client, iroha::data_model::proof::ProofStatus::Verified)?;
        let rejected =
            retry_records_by_status(&client, iroha::data_model::proof::ProofStatus::Rejected)?;
        assert!(
            !verified.is_empty(),
            "expected at least one verified proof record"
        );
        assert!(
            !rejected.is_empty(),
            "expected at least one rejected proof record"
        );
    }
    Ok(())
}
#[cfg(feature = "zk-stark")]
fn retry_records_by_status(
    client: &iroha::blocking::Client,
    status: iroha::data_model::proof::ProofStatus,
) -> Result<Vec<iroha::data_model::proof::ProofRecord>> {
    retry_proof_records(|| {
        Ok(client
            .client()
            .query(FindProofRecordsByStatus::new(status))
            .execute_all()?)
    })
}
#[cfg(feature = "zk-stark")]
fn retry_all_proof_records(
    client: &iroha::blocking::Client,
) -> Result<Vec<iroha::data_model::proof::ProofRecord>> {
    retry_proof_records(|| Ok(client.client().query(FindProofRecords).execute_all()?))
}
#[cfg(feature = "zk-stark")]
fn retry_records_by_backend(
    client: &iroha::blocking::Client,
    backend: &str,
) -> Result<Vec<iroha::data_model::proof::ProofRecord>> {
    retry_proof_records(|| {
        Ok(client
            .client()
            .query(FindProofRecordsByBackend::new(backend.into()))
            .execute_all()?)
    })
}
#[cfg(feature = "zk-stark")]
fn retry_proof_records(
    mut query: impl FnMut() -> Result<Vec<iroha::data_model::proof::ProofRecord>>,
) -> Result<Vec<iroha::data_model::proof::ProofRecord>> {
    const RETRIES: usize = 5;
    const DELAY: Duration = Duration::from_millis(200);
    for attempt in 0..RETRIES {
        match query() {
            Ok(records) if !records.is_empty() => return Ok(records),
            Ok(records) if attempt + 1 < RETRIES => {
                let _ = records;
                sleep(DELAY);
                // Continue retrying if empty.
            }
            Ok(records) => return Ok(records),
            Err(_) if attempt + 1 < RETRIES => {
                sleep(DELAY);
                // Retry on transient errors.
            }
            Err(err) => return Err(err.into()),
        }
    }
    unreachable!()
}
#[cfg(feature = "zk-stark")]
fn proof_record_backends(records: &[iroha::data_model::proof::ProofRecord]) -> Vec<String> {
    records
        .iter()
        .map(|record| record.id.backend.to_string())
        .collect()
}
#[test]
fn native_attachment_statement_changes_proof_hash() {
    use iroha_core_zk::confidential_v2::CONFIDENTIAL_UNSHIELD_V2_PUBLIC_INPUT_ORDER_V1;

    let a = native_attachment("statement-a");
    let b = native_attachment("statement-b");
    let inputs = |attachment: &ProofAttachment| {
        let envelope: OpenVerifyEnvelope =
            norito::decode_canonical(&attachment.proof.bytes).expect("canonical proof envelope");
        assert_eq!(
            envelope.backend,
            iroha_data_model::zk::BackendTag::NativePipaRPasta
        );
        let carrier: iroha_data_model::zk::NativePipaRProofV1 =
            norito::decode_canonical(&envelope.proof_bytes)
                .expect("canonical native PIPA-R carrier");
        assert!(!carrier.proof.is_empty());
        assert_eq!(
            carrier.public_inputs.len(),
            CONFIDENTIAL_UNSHIELD_V2_PUBLIC_INPUT_ORDER_V1.len()
        );
        carrier.public_inputs
    };
    let inputs_a = inputs(&a);
    let inputs_b = inputs(&b);
    for (column, name) in CONFIDENTIAL_UNSHIELD_V2_PUBLIC_INPUT_ORDER_V1
        .iter()
        .enumerate()
    {
        // The statement selects rho, binding the input commitment, nullifier
        // and tree root. The absent second input, asset, amount and network stay fixed.
        if matches!(*name, "input_commitment_0" | "nullifier_0" | "root") {
            assert_ne!(
                inputs_a[column], inputs_b[column],
                "{name} must bind the note opening"
            );
        } else {
            assert_eq!(inputs_a[column], inputs_b[column], "{name} must stay fixed");
        }
    }
    let hash_a = iroha_core_zk::hash_proof(&a.proof);
    let hash_b = iroha_core_zk::hash_proof(&b.proof);
    assert_ne!(
        hash_a, hash_b,
        "bound public statement should change proof hash"
    );
}

#[test]
fn native_attachment_circuit_changes_proof_hash() {
    let (attachment, registration) =
        confidential_attachment("circuit-identity", "circuit_identity_vk");
    let mut envelope: OpenVerifyEnvelope =
        norito::decode_canonical(&attachment.proof.bytes).expect("canonical confidential envelope");
    envelope.circuit_id =
        iroha_core_zk::confidential_v2::CONFIDENTIAL_TRANSFER_V2_CIRCUIT_ID.into();
    let relabelled = iroha::data_model::proof::ProofBox::new(
        attachment.proof.backend.clone(),
        norito::encode_canonical(&envelope).expect("canonical relabelled envelope"),
    );
    assert_ne!(
        iroha_core_zk::hash_proof(&attachment.proof),
        iroha_core_zk::hash_proof(&relabelled),
        "circuit identity must participate in the proof hash"
    );
    assert!(
        !iroha_core_zk::verify_backend(
            &relabelled.backend,
            &relabelled,
            registration.record.key.as_ref(),
        )
        .expect("relabelled proof verification must be admitted"),
        "changing the circuit identity must not make the confidential proof valid for another relation"
    );
}
