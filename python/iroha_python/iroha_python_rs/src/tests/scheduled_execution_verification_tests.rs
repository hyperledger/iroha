//! Real Core scheduled invocations and Commit-QC proof authentication.
//! Compiled fixed-argument contract callbacks have separate Core execution tests.

use super::*;
use iroha_core::{
    state::World,
    sumeragi::{
        finality::{build_checkpoint, build_proof},
        test_chain::{CertifiedTestChain, TestChainConfig},
    },
};
use iroha_data_model::{
    Registrable,
    isi::{Log, Unregister},
    trigger::action::TimeTriggerRetryPolicy,
};
use iroha_version::codec::EncodeVersioned;

struct Fixture {
    chain: CertifiedTestChain,
    original: SignedTransaction,
    checkpoint: SumeragiFinalityCheckpoint,
    proofs: Vec<SumeragiFinalityProof>,
}

impl Fixture {
    fn new(reject: bool) -> Self {
        let key = KeyPair::from_seed(vec![0x51; 32], Algorithm::Ed25519);
        let authority = AccountId::new(key.public_key().clone());
        let world = World::with([], [Account::new(authority.clone()).build(&authority)], []);
        let mut chain = CertifiedTestChain::start(TestChainConfig::new(world, 1_000)).unwrap();
        chain.commit_at(1_001, vec![]);
        let checkpoint = build_checkpoint(&chain.state().view(), 2).unwrap();
        let body: InstructionBox = if reject {
            Unregister::domain(
                iroha_model_base::domain::DomainId::try_new("absent_scheduled", "universal")
                    .unwrap(),
            )
            .into()
        } else {
            Log::new(
                iroha_data_model::Level::INFO,
                "actual scheduled execution".into(),
            )
            .into()
        };
        let action = TriggerAction::new(
            vec![body],
            Repeats::Exactly(1),
            authority,
            TimeEventFilter::new(ExecutionTime::Schedule(
                TimeSchedule::starting_at(Duration::from_millis(1_002))
                    .with_period(Duration::from_millis(5)),
            )),
        )
        .unwrap()
        .with_retry_policy(TimeTriggerRetryPolicy {
            max_retries: NonZeroU32::new(1).unwrap(),
            retry_after_ms: NonZeroU64::new(5).unwrap(),
        })
        .unwrap();
        let original = chain.sign(
            &key,
            [Register::trigger(Trigger::new("fixture".parse().unwrap(), action)).into()],
            1_001,
        );
        assert_eq!(chain.commit_at(1_002, vec![original.clone()]), vec![true]);
        chain.commit_at(1_003, vec![]);
        if reject {
            chain.commit_at(1_007, vec![]);
            chain.commit_at(1_008, vec![]);
        }
        let last = if reject { 6 } else { 4 };
        let proofs = (2..=last)
            .map(|height| build_proof(&chain.state().view(), height).unwrap())
            .collect();
        Self {
            chain,
            original,
            checkpoint,
            proofs,
        }
    }

    fn verify(
        &self,
        original: &[u8],
        id: &str,
        proofs: &[SumeragiFinalityProof],
    ) -> PyResult<json::Value> {
        let (projection, _) = authenticate(
            original,
            id,
            &json::to_json(&proofs.to_vec()).unwrap(),
            self.chain.network_id(),
            self.checkpoint.chain_id(),
            &self.checkpoint.encode_canonical().unwrap(),
        )?;
        json::from_json(&projection).map_err(refusal)
    }

    fn result(&self) -> json::Value {
        self.verify(&self.original.encode_versioned(), "fixture", &self.proofs)
            .unwrap()
    }
}

#[test]
fn genuine_scheduled_output_binds_original_activation_authority_and_internal_route() {
    let fixture = Fixture::new(false);
    // Actual Network results omit root instructions; an empty callback sequence
    // must not make the authenticated signed registration disappear.
    let registration = decode_framed_signed_block(&fixture.proofs[1].block_wire).unwrap();
    let selected = original_trigger(&fixture.original, &"fixture".parse().unwrap()).unwrap();
    let input_index = registration
        .network_entrypoints()
        .position(|input| input.hash() == fixture.original.hash_as_entrypoint())
        .unwrap();
    let (_, output) = registration
        .network_output_at(u32::try_from(input_index).unwrap())
        .unwrap();
    assert!(output.result.0.as_ref().unwrap().is_empty());
    assert_eq!(
        check_lifecycle(
            &registration,
            fixture.original.hash_as_entrypoint(),
            &selected
        )
        .unwrap(),
        1
    );
    let result = fixture.result();
    assert_eq!(result["proof_kind"].as_str(), Some("scheduled-time-v1"));
    assert_eq!(result["terminal"].as_str(), Some("applied"));
    assert_eq!(result["registered_at_height"].as_u64(), Some(3));
    assert_eq!(result["registered_at_ms"].as_u64(), Some(1_002));
    assert_eq!(
        result["authority"],
        json::to_value(fixture.original.authority()).unwrap()
    );
    assert_eq!(
        result["execution_route"],
        norito::json!({
            "kind": "internal", "root_scope": "Global", "dataspace_id": 0, "lane_id": null,
        })
    );
    assert!(result.get("transaction_hash").is_none());
    let rows = result["outcomes"].as_array().unwrap();
    assert_eq!(rows.len(), 1);
    assert_eq!(rows[0]["block_height"].as_u64(), Some(4));
    assert_eq!(rows[0]["result_ok"].as_bool(), Some(true));
    assert_eq!(rows[0]["output"]["kind"].as_str(), Some("time"));
}

#[test]
fn genuine_retry_chain_is_complete_and_exhausts_only_its_native_budget() {
    let fixture = Fixture::new(true);
    let result = fixture.result();
    assert_eq!(result["terminal"].as_str(), Some("exhausted"));
    let rows = result["outcomes"].as_array().unwrap();
    assert_eq!(rows.len(), 2);
    assert_eq!(rows[0]["block_height"].as_u64(), Some(4));
    assert_eq!(rows[1]["block_height"].as_u64(), Some(6));
    assert!(
        rows.iter()
            .all(|row| row["result_ok"].as_bool() == Some(false))
    );
    assert_ne!(
        rows[0]["execution_call_hash"],
        rows[1]["execution_call_hash"]
    );
    let pending = fixture
        .verify(
            &fixture.original.encode_versioned(),
            "fixture",
            &fixture.proofs[..2],
        )
        .unwrap();
    assert_eq!(pending["terminal"].as_str(), Some("pending"));
    assert!(pending["outcomes"].as_array().unwrap().is_empty());
}

#[test]
fn scheduled_proof_rejects_foreign_original_id_mutation_replay_and_missing_prefix() {
    let fixture = Fixture::new(true);
    let bytes = fixture.original.encode_versioned();
    assert!(fixture.verify(&bytes, "foreign", &fixture.proofs).is_err());
    let mut altered = bytes.clone();
    altered[0] ^= 1;
    assert!(
        fixture
            .verify(&altered, "fixture", &fixture.proofs)
            .is_err()
    );
    let mut extra = bytes.clone();
    extra.push(0);
    assert!(fixture.verify(&extra, "fixture", &fixture.proofs).is_err());
    let mut gap = fixture.proofs.clone();
    gap.remove(2);
    assert!(fixture.verify(&bytes, "fixture", &gap).is_err());
    let mut duplicate = fixture.proofs.clone();
    duplicate.insert(3, duplicate[2].clone());
    assert!(fixture.verify(&bytes, "fixture", &duplicate).is_err());
    let mut substituted = fixture.proofs.clone();
    let last = substituted.last_mut().unwrap();
    let index = last.block_wire.len() / 2;
    last.block_wire[index] ^= 1;
    assert!(fixture.verify(&bytes, "fixture", &substituted).is_err());
    let late = build_checkpoint(&fixture.chain.state().view(), 4).unwrap();
    assert!(
        authenticate(
            &bytes,
            "fixture",
            &json::to_json(&fixture.proofs[2..].to_vec()).unwrap(),
            fixture.chain.network_id(),
            late.chain_id(),
            &late.encode_canonical().unwrap(),
        )
        .is_err(),
        "a later trusted tip cannot replace original activation and retry history"
    );
}

#[test]
fn genuine_prefix_rejects_same_block_reincarnation_metadata_and_repeat_mutations() {
    for change in ["reincarnation", "metadata", "repeats"] {
        let source = Fixture::new(false);
        let trigger = original_trigger(&source.original, &"fixture".parse().unwrap()).unwrap();
        let key = KeyPair::from_seed(vec![0x51; 32], Algorithm::Ed25519);
        let authority = AccountId::new(key.public_key().clone());
        let world = World::with([], [Account::new(authority.clone()).build(&authority)], []);
        let mut chain = CertifiedTestChain::start(TestChainConfig::new(world, 1_000)).unwrap();
        chain.commit_at(1_001, vec![]);
        let checkpoint = build_checkpoint(&chain.state().view(), 2).unwrap();
        let original = chain.sign(&key, [Register::trigger(trigger.clone()).into()], 1_002);
        let edits: Vec<InstructionBox> = match change {
            "reincarnation" => vec![
                Unregister::trigger(trigger.id().clone()).into(),
                Register::trigger(trigger).into(),
            ],
            "metadata" => vec![
                iroha_data_model::isi::SetKeyValue::trigger(
                    trigger.id().clone(),
                    "operator_note".parse().unwrap(),
                    Json::from(1_u32),
                )
                .into(),
            ],
            "repeats" => vec![
                iroha_data_model::isi::Mint::trigger_repetitions(1, trigger.id().clone()).into(),
            ],
            _ => unreachable!(),
        };
        // Both apply at exactly the same height/time. Reincarnation therefore
        // retains the same persistent action hash but is a different lifetime.
        let changed = chain.sign(&key, edits, 1_003);
        assert_eq!(
            chain.commit_at(1_002, vec![original.clone(), changed]),
            vec![true, true]
        );
        chain.commit_at(1_003, vec![]);
        let proofs: Vec<_> = (2..=4)
            .map(|height| build_proof(&chain.state().view(), height).unwrap())
            .collect();
        let fixture = Fixture {
            chain,
            original,
            checkpoint,
            proofs,
        };
        let error = fixture
            .verify(
                &fixture.original.encode_versioned(),
                "fixture",
                &fixture.proofs,
            )
            .unwrap_err();
        assert!(
            error.to_string().contains("lifecycle changed"),
            "{change}: {error}"
        );
    }
}

#[test]
fn registration_height_checkpoint_can_anchor_the_complete_activation_prefix() {
    let fixture = Fixture::new(false);
    let checkpoint = build_checkpoint(&fixture.chain.state().view(), 3).unwrap();
    assert!(
        authenticate(
            &fixture.original.encode_versioned(),
            "fixture",
            &json::to_json(&fixture.proofs[1..].to_vec()).unwrap(),
            fixture.chain.network_id(),
            checkpoint.chain_id(),
            &checkpoint.encode_canonical().unwrap(),
        )
        .is_ok()
    );
}

#[test]
fn native_batch_roots_and_callback_zero_have_distinct_registration_ownership() {
    let fixture = Fixture::new(false);
    let selected = original_trigger(&fixture.original, &"fixture".parse().unwrap()).unwrap();
    let registration: InstructionBox = Register::trigger(selected.clone()).into();
    let batch =
        Executable::Batch(vec![ExecutableBatchItem::Instruction(registration.clone())].into());
    assert_eq!(
        check_network_root_lifecycle(&batch, true, &selected).unwrap(),
        1
    );
    let error =
        check_lifecycle_instructions(std::iter::once(&registration), false, &selected).unwrap_err();
    assert!(
        error
            .to_string()
            .contains("unrelated or nested registration")
    );
    assert!(check_network_root_lifecycle(&batch, false, &selected).is_err());
}

#[test]
fn opaque_roots_and_nested_native_execution_cannot_hide_lifecycle_changes() {
    let fixture = Fixture::new(false);
    let selected = original_trigger(&fixture.original, &"fixture".parse().unwrap()).unwrap();
    let opaque = Executable::Ivm(IvmBytecode::from_compiled(vec![]));
    assert!(
        check_network_root_lifecycle(&opaque, true, &selected)
            .unwrap_err()
            .to_string()
            .contains("native-effect trace")
    );
    let call = iroha_data_model::transaction::executable::ContractInvocation {
        contract_address: iroha_data_model::smart_contract::ContractAddress::derive(
            &fixture.chain.network_id(),
            fixture.original.authority(),
            83,
            iroha_model_base::topology::DataSpaceId::UNIVERSAL,
        )
        .unwrap(),
        expected_code_hash: Hash::new("opaque-lifecycle-contract"),
        entrypoint: "apply".into(),
        arguments: None,
    };
    let batch = Executable::Batch(
        vec![
            ExecutableBatchItem::Instruction(Register::trigger(selected.clone()).into()),
            ExecutableBatchItem::ContractCall(call.clone()),
        ]
        .into(),
    );
    assert!(
        check_network_root_lifecycle(&batch, true, &selected)
            .unwrap_err()
            .to_string()
            .contains("ContractCall batch items")
    );
    assert!(
        check_network_root_lifecycle(&Executable::ContractCall(call), true, &selected).is_err()
    );
    let nested: InstructionBox =
        ExecuteTrigger::new("unrelated_nested_trigger".parse().unwrap()).into();
    assert!(
        check_lifecycle_instructions(std::iter::once(&nested), false, &selected)
            .unwrap_err()
            .to_string()
            .contains("opaque instructions")
    );
    let retire_owner: InstructionBox =
        Unregister::account(fixture.original.authority().clone()).into();
    assert!(
        !lifecycle_transparent_instruction(&retire_owner),
        "account retirement may remove dependent triggers"
    );
    let retire_domain: InstructionBox = Unregister::domain(
        iroha_model_base::domain::DomainId::try_new("fixture", "universal").unwrap(),
    )
    .into();
    assert!(
        !lifecycle_transparent_instruction(&retire_domain),
        "domain retirement may remove dependent triggers"
    );
}
