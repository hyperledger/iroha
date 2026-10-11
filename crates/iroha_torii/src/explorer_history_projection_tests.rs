// Real native history fixtures preserve inspectable payloads in the sole first-release wire.
use crate::explorer_history::{
    HistoryInstructionRow, HistoryTransactionDetail, HistoryTransactionRow,
};
use iroha_data_model::isi;

fn row(tx: SignedTransaction, height: u64, result: TransactionResult) -> HistoryTransactionRow {
    let hash = tx.hash_as_entrypoint();
    let header = BlockHeader::new(
        std::num::NonZeroU64::new(height).unwrap(),
        None,
        None,
        1_700_000_000_000,
        0,
    );
    let mut builder = BlockBuilder::new(header);
    builder.push_transaction(tx);
    let mut block = builder.build_with_signature(0, ALICE_KEYPAIR.private_key());
    crate::test_utils::attach_fixture_execution_outputs(
        &mut block,
        vec![
            iroha_data_model::block::execution_output::ExecutionOutputV1::Network(
                iroha_data_model::block::execution_output::NetworkExecutionOutputV1 {
                    input_index: 0,
                    result,
                    completions: vec![],
                },
            ),
        ],
    );
    let pool = iroha_allocation::AllocationBudget::new(
        iroha_data_model::block::SharedSignedBlock::allocation_layout().size(),
    );
    HistoryTransactionRow {
        block: iroha_data_model::block::SharedSignedBlock::try_new(block, &pool).unwrap(),
        entrypoint_index: 0,
        entrypoint_hash: hash,
    }
}
fn builder() -> TransactionBuilder {
    TransactionBuilder::new(
        test_network_id(),
        ALICE_ID.clone(),
        iroha_data_model::transaction::FeePaymentIntent::authority(Vec::new(), None),
    )
}
#[test]
fn transaction_summary_reflects_status() {
    let row = row(
        builder().sign(ALICE_KEYPAIR.private_key()),
        5,
        TransactionResult::new(Ok(DataTriggerSequence::default())),
    );
    let value = json::to_value(&row).unwrap();
    assert_eq!(value.get("block").and_then(Value::as_u64), Some(5));
    assert_eq!(
        value.get("authority").and_then(Value::as_str),
        Some(ALICE_ID.to_string().as_str())
    );
    assert_eq!(
        value.get("status").and_then(Value::as_str),
        Some("Committed")
    );
}
#[test]
fn transaction_detail_preserves_native_rejection_metadata_and_lifetime() {
    let mut metadata = Metadata::default();
    metadata.insert(
        "purpose".parse().unwrap(),
        json::Value::String("test".into()),
    );
    let mut builder = builder().with_metadata(metadata);
    builder.set_creation_time(StdDuration::from_millis(1_700_000_000));
    builder
        .set_ttl(StdDuration::from_secs(30))
        .set_nonce(NonZeroU32::new(7).unwrap());
    let rejection = TransactionRejectionReason::Validation(ValidationFail::TooComplex);
    let row = row(
        builder.sign(ALICE_KEYPAIR.private_key()),
        12,
        TransactionResult::new(Err(rejection.clone())),
    );
    let value = json::to_value(&HistoryTransactionDetail(row)).unwrap();
    assert_eq!(
        value.get("status").and_then(Value::as_str),
        Some("Rejected")
    );
    assert_eq!(value.get("nonce").and_then(Value::as_u64), Some(7));
    assert_eq!(
        value
            .get("time_to_live")
            .unwrap()
            .get("ms")
            .and_then(Value::as_u64),
        Some(30_000)
    );
    assert_eq!(
        value
            .get("metadata")
            .unwrap()
            .get("purpose")
            .and_then(Value::as_str),
        Some("test")
    );
    let reason = value.get("rejection_reason").unwrap();
    let decoded: TransactionRejectionReason =
        json::from_value(reason.get("reason").unwrap().clone()).unwrap();
    assert_eq!(decoded, rejection);
    let message = reason.get("message").unwrap().as_str().unwrap();
    assert!(message.contains("Validation failed"));
    assert!(message.contains("Operation is too complex"));
    assert!(reason.get("encoded").is_none());
    assert!(reason.get("json").is_none());
}
#[test]
fn transaction_detail_preserves_nested_repetition_reason() {
    let rejection = TransactionRejectionReason::Validation(ValidationFail::InstructionFailed(
        isi::error::InstructionExecutionError::Repetition(isi::error::RepetitionError {
            instruction: isi::InstructionType::Register,
            id: iroha_data_model::IdBox::DomainId(DomainId::try_new("acme", "universal").unwrap()),
        }),
    ));
    let row = row(
        builder().sign(ALICE_KEYPAIR.private_key()),
        21,
        TransactionResult::new(Err(rejection)),
    );
    let value = json::to_value(&HistoryTransactionDetail(row)).unwrap();
    let message = value
        .get("rejection_reason")
        .unwrap()
        .get("message")
        .unwrap()
        .as_str()
        .unwrap();
    assert!(message.contains("Validation failed: Instruction execution failed"));
    assert!(message.contains("acme"));
}
#[test]
fn transaction_detail_preserves_contract_call_arguments() {
    let address =
        ContractAddress::derive(&test_network_id(), &ALICE_ID, 1, DataSpaceId::UNIVERSAL).unwrap();
    let arguments = vec![0x4b, 0x4f, 0x54, 0x4f];
    let tx = builder()
        .with_executable(Executable::ContractCall(ContractInvocation {
            contract_address: address.clone(),
            expected_code_hash: iroha_crypto::Hash::prehashed([0; 32]),
            entrypoint: "contribute".to_owned(),
            arguments: Some(
                iroha_data_model::transaction::executable::ContractArgumentRecord::try_new(
                    arguments.clone(),
                )
                .unwrap(),
            ),
        }))
        .sign(ALICE_KEYPAIR.private_key());
    let row = row(
        tx,
        9,
        TransactionResult::new(Ok(DataTriggerSequence::default())),
    );
    let value = json::to_value(&HistoryTransactionDetail(row)).unwrap();
    assert_eq!(
        value.get("executable").and_then(Value::as_str),
        Some("ContractCall")
    );
    let decoded: ContractInvocation =
        json::from_value(value.get("executable_payload").unwrap().clone()).unwrap();
    assert_eq!(decoded.contract_address, address);
    assert_eq!(decoded.arguments.unwrap().as_bytes(), arguments);
}
fn instruction_value(instruction: InstructionBox) -> Value {
    let tx = builder()
        .with_instructions([instruction])
        .sign(ALICE_KEYPAIR.private_key());
    let row = HistoryInstructionRow {
        transaction: row(
            tx,
            7,
            TransactionResult::new(Ok(DataTriggerSequence::default())),
        ),
        instruction_index: 0,
    };
    json::to_value(&row).unwrap()
}
fn decoded_instruction(value: &Value) -> InstructionBox {
    let frame = value.get("box").unwrap();
    assert!(frame.get("encoded").is_none());
    assert!(frame.get("json").is_none());
    assert!(frame.get("wire_id").unwrap().as_str().is_some());
    let instruction: InstructionBox =
        json::from_value(frame.get("instruction").unwrap().clone()).unwrap();
    let framed = norito::encode_canonical(&instruction).unwrap();
    assert_eq!(
        frame.get("framed_sha256").and_then(Value::as_str),
        Some(hex::encode(Sha256::digest(framed)).as_str())
    );
    instruction
}
#[test]
fn instruction_native_frame_preserves_unmapped_instruction_and_wire_kind() {
    let instruction: InstructionBox = iroha_data_model::isi::AddSignatory::new(
        ALICE_ID.clone(),
        ALICE_KEYPAIR.public_key().clone(),
    )
    .into();
    let value = instruction_value(instruction.clone());
    assert_eq!(
        value.get("kind").and_then(Value::as_str),
        Some("AddSignatory")
    );
    assert_eq!(decoded_instruction(&value), instruction);
    assert_eq!(value.get("index").and_then(Value::as_u64), Some(0));
}
#[test]
fn instruction_native_frame_preserves_registered_payload_and_digest() {
    let instruction: InstructionBox = Register::domain(iroha_data_model::domain::Domain::new(
        DomainId::try_new("payload", "universal").unwrap(),
    ))
    .into();
    let value = instruction_value(instruction.clone());
    assert_eq!(value.get("kind").and_then(Value::as_str), Some("Register"));
    assert_eq!(decoded_instruction(&value), instruction);
}
#[test]
fn instruction_native_frame_preserves_custom_json_body() {
    let mut args = Map::new();
    args.insert("foo".to_owned(), Value::from(1_u64));
    let mut root = Map::new();
    root.insert("kind".to_owned(), Value::String("Demo".to_owned()));
    root.insert("args".to_owned(), Value::Object(args));
    let instruction: InstructionBox =
        CustomInstruction::new(iroha_primitives::json::Json::new(Value::Object(root))).into();
    assert_eq!(
        decoded_instruction(&instruction_value(instruction.clone())),
        instruction
    );
}
#[test]
fn instruction_native_frame_preserves_exact_typed_governance_proposal() {
    use iroha_data_model::sccp::governance::{
        SccpFreezeLightClientActionV1, SccpGovernanceActionV1, SccpGovernanceBaseRevisionV1,
        SccpGovernanceProposalV1, SccpGovernanceSubjectV1,
    };
    let network = iroha_data_model::bridge::SccpNetworkV1::TonMainnet;
    let instruction: InstructionBox =
        iroha_data_model::isi::governance::ProposeSccpRouteGovernance {
            proposal: SccpGovernanceProposalV1 {
                network_id: test_network_id(),
                base_revisions: vec![SccpGovernanceBaseRevisionV1 {
                    subject: SccpGovernanceSubjectV1::LightClient(network),
                    revision: 3,
                }],
                actions: vec![SccpGovernanceActionV1::FreezeLightClient(
                    SccpFreezeLightClientActionV1 { network },
                )],
            },
        }
        .into();
    assert_eq!(
        decoded_instruction(&instruction_value(instruction.clone())),
        instruction
    );
}
