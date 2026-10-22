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
        // Error assertions must also work when this module runs in isolation.
        pyo3::Python::initialize();
        let key = KeyPair::from_seed(vec![0x51; 32], Algorithm::Ed25519);
        let authority = AccountId::new(key.public_key().clone());
        let world = World::with([], [Account::new(authority.clone()).build(&authority)], []);
        let mut chain = CertifiedTestChain::start(TestChainConfig::new(world, 1_000)).unwrap();
        chain.commit_at(1_001, vec![]);
        let checkpoint = build_checkpoint(&chain.state().view(), 2).unwrap();
        let registration_ms = chain.committed(2).block_time_ms().checked_add(1).unwrap();
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
                TimeSchedule::starting_at(Duration::from_millis(registration_ms))
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
            registration_ms - 1,
        );
        assert_eq!(chain.commit_at(registration_ms, vec![original.clone()]), vec![true]);
        assert_eq!(chain.committed(3).block_time_ms(), registration_ms);
        let first_ms = registration_ms.checked_add(1).unwrap();
        chain.commit_at(first_ms, vec![]);
        assert_eq!(chain.committed(4).block_time_ms(), first_ms);
        if reject {
            chain.commit_at(first_ms + 4, vec![]);
            chain.commit_at(first_ms + 5, vec![]);
            assert_eq!(chain.committed(6).block_time_ms(), first_ms + 5);
        }
        let last = if reject { 6 } else { 4 };
        let proofs: Vec<_> = (2..=last)
            .map(|height| build_proof(&chain.state().view(), height).unwrap())
            .collect();
        let actual = proofs.iter().flat_map(|proof| {
            let block = decode_framed_signed_block(&proof.block_wire).unwrap();
            block.execution_outputs().iter().filter_map(|output| {
                let ExecutionOutputV1::Time(row) = output else { return None; };
                assert_eq!(row.result.is_ok(), !reject, "actual callback disposition");
                Some(block.header().height().get())
            }).collect::<Vec<_>>()
        }).collect::<Vec<_>>();
        assert_eq!(actual, if reject { vec![4, 6] } else { vec![4] },
            "fixture must execute the selected schedule, not merely observe an idle prefix");
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
    assert_eq!(result["registered_at_ms"].as_u64(),
        Some(fixture.chain.committed(3).block_time_ms()));
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


impl Fixture {
    /// Genuine certified Core execution with a bounded output policy in genesis.
    /// The same oversized body succeeds or fails after its large Log instruction.
    fn bounded_output(reject: bool) -> Self {
        Self::bounded_output_sequence(reject, false)
    }

    fn bounded_output_sequence(reject: bool, mixed: bool) -> Self {
        pyo3::Python::initialize();
        assert!(!mixed || reject);
        use iroha_data_model::parameter::{BlockParameter, ExecutionOutputPolicyV1, Parameter};
        let key = KeyPair::from_seed(vec![0x51; 32], Algorithm::Ed25519);
        let authority = AccountId::new(key.public_key().clone());
        let world = World::with([], [Account::new(authority.clone()).build(&authority)], []);
        let mut config = TestChainConfig::new(world, 1_000);
        let mut output_policy = ExecutionOutputPolicyV1::bootstrap();
        output_policy.max_output_bytes = 4_096;
        output_policy.max_pipeline_triggers = 0;
        output_policy.max_time_invocations = 1;
        output_policy.validate().unwrap();
        config.genesis_parameters.extend([
            Parameter::Block(BlockParameter::ExecutionOutput(output_policy)),
            Parameter::Block(BlockParameter::MaxTimeTriggerInvocations(NonZeroU32::MIN)),
        ]);
        let mut chain = CertifiedTestChain::start(config).unwrap();
        chain.commit_at(1_001, vec![]);
        let checkpoint = build_checkpoint(&chain.state().view(), 2).unwrap();
        let registration_ms = chain.committed(2).block_time_ms().checked_add(1).unwrap();
        let mut body: Vec<InstructionBox> = vec![
            Log::new(iroha_data_model::Level::INFO, "x".repeat(16_384)).into(),
        ];
        if reject {
            body.push(Unregister::trigger("absent_bounded_scheduled".parse().unwrap()).into());
        }
        let action = TriggerAction::new(
            body,
            Repeats::Exactly(1),
            authority,
            TimeEventFilter::new(ExecutionTime::Schedule(
                TimeSchedule::starting_at(Duration::from_millis(registration_ms))
                    .with_period(Duration::from_millis(5)),
            )),
        ).unwrap().with_retry_policy(TimeTriggerRetryPolicy {
            max_retries: NonZeroU32::new(1).unwrap(),
            retry_after_ms: NonZeroU64::new(5).unwrap(),
        }).unwrap();
        let original = chain.sign(
            &key,
            [Register::trigger(Trigger::new("fixture".parse().unwrap(), action)).into()],
            registration_ms - 1,
        );
        assert_eq!(chain.commit_at(registration_ms, vec![original.clone()]), vec![true]);
        assert_eq!(chain.committed(3).block_time_ms(), registration_ms);
        let first_ms = registration_ms.checked_add(1).unwrap();
        chain.commit_at(first_ms, vec![]);
        assert_eq!(chain.committed(4).block_time_ms(), first_ms);
        let last = if mixed {
            // The selected action is unchanged. Make its final Unregister succeed
            // for one attempt by adding an unrelated, far-future trigger.
            let temporary = TriggerAction::new(
                vec![InstructionBox::from(Log::new(iroha_data_model::Level::INFO, "unused".into()))],
                Repeats::Exactly(1),
                original.authority().clone(),
                TimeEventFilter::new(ExecutionTime::Schedule(
                    TimeSchedule::starting_at(Duration::from_millis(registration_ms + 1_000_000)),
                )),
            ).unwrap();
            let install = chain.sign(&key, [Register::trigger(Trigger::new(
                "absent_bounded_scheduled".parse().unwrap(), temporary,
            )).into()], first_ms);
            assert_eq!(chain.commit_at(first_ms + 4, vec![install]), vec![true]);
            chain.commit_at(first_ms + 5, vec![]);
            assert_eq!(chain.committed(6).block_time_ms(), first_ms + 5);
            // The healthy callback's unregister rolled back with its large output.
            // This independent Network removal must therefore still succeed.
            let remove = chain.sign(&key, [Unregister::trigger(
                "absent_bounded_scheduled".parse().unwrap(),
            ).into()], first_ms + 5);
            assert_eq!(chain.commit_at(first_ms + 6, vec![remove]), vec![true]);
            assert_eq!(chain.committed(7).block_time_ms(), first_ms + 6);
            7
        } else {
            for time in [first_ms + 4, first_ms + 5, first_ms + 9, first_ms + 10] {
                chain.commit_at(time, vec![]);
            }
            assert_eq!(chain.committed(6).block_time_ms(), first_ms + 5);
            assert_eq!(chain.committed(8).block_time_ms(), first_ms + 10);
            8
        };
        let proofs = (2..=last)
            .map(|height| build_proof(&chain.state().view(), height).unwrap()).collect();
        Self { chain, original, checkpoint, proofs }
    }
}

#[test]
fn certified_output_rollback_preserves_prior_retry_state_until_exact_exhaustion() {
    let fixture = Fixture::bounded_output_sequence(true, true);
    let original = fixture.original.encode_versioned();
    let after_overflow = fixture.verify(&original, "fixture", &fixture.proofs[..5]).unwrap();
    assert_eq!(after_overflow["terminal"].as_str(), Some("retrying"));
    let earlier = after_overflow["outcomes"].as_array().unwrap();
    assert_eq!(earlier.len(), 2);
    assert_eq!(earlier[0]["disposition"].as_str(), Some("rejected"));
    assert_eq!(earlier[1]["disposition"].as_str(), Some("output_limit"));
    let result = fixture.result();
    assert_eq!(result["terminal"].as_str(), Some("exhausted"));
    let rows = result["outcomes"].as_array().unwrap();
    assert_eq!(rows.len(), 3);
    assert_eq!(rows[2]["disposition"].as_str(), Some("rejected"));
    let mut native_hashes = Vec::new();
    let mut heights = Vec::new();
    for proof in &fixture.proofs {
        let block = decode_framed_signed_block(&proof.block_wire).unwrap();
        for output in block.execution_outputs() {
            if let ExecutionOutputV1::Time(row) = output {
                native_hashes.push(row.invocation.trigger.action_hash);
                heights.push(block.header().height().get());
            }
        }
    }
    assert_eq!(heights, vec![4, 6, 7]);
    assert_ne!(native_hashes[0], native_hashes[1], "real failure advances native retry tuple");
    assert_eq!(native_hashes[1], native_hashes[2], "capacity rollback must preserve the prior retry tuple");
}

#[test]
fn certified_healthy_output_rollbacks_do_not_consume_retry_budget_or_change_action() {
    let fixture = Fixture::bounded_output(false);
    let result = fixture.result();
    assert_eq!(result["terminal"].as_str(), Some("pending"));
    let rows = result["outcomes"].as_array().unwrap();
    assert_eq!(rows.len(), 3, "capacity rollbacks may outnumber the failure retry budget");
    let mut actual_hash = None;
    for proof in &fixture.proofs {
        let block = decode_framed_signed_block(&proof.block_wire).unwrap();
        for output in block.execution_outputs() {
            if let ExecutionOutputV1::Time(row) = output {
                assert!(output.is_output_limit_rejection());
                assert!(!output.is_internal_rejection_diagnostic_omitted());
                assert_eq!(scheduled_disposition(output).unwrap(), "output_limit");
                if let Some(previous) = actual_hash {
                    assert_eq!(row.invocation.trigger.action_hash, previous,
                        "native retry state must remain unchanged after healthy output rollback");
                }
                actual_hash = Some(row.invocation.trigger.action_hash);
            }
        }
    }
    for row in rows {
        assert_eq!(row["result_ok"].as_bool(), Some(false));
        assert_eq!(row["disposition"].as_str(), Some("output_limit"));
    }
}

#[test]
fn certified_omitted_real_rejections_still_consume_the_exact_retry_budget() {
    let fixture = Fixture::bounded_output(true);
    let result = fixture.result();
    assert_eq!(result["terminal"].as_str(), Some("exhausted"));
    let rows = result["outcomes"].as_array().unwrap();
    assert_eq!(rows.len(), 2);
    for proof in &fixture.proofs {
        let block = decode_framed_signed_block(&proof.block_wire).unwrap();
        for output in block.execution_outputs() {
            if let ExecutionOutputV1::Time(_) = output {
                assert!(!output.is_output_limit_rejection());
                assert!(output.is_internal_rejection_diagnostic_omitted());
                assert_eq!(scheduled_disposition(output).unwrap(), "rejected");
            }
        }
    }
    for row in rows {
        assert_eq!(row["result_ok"].as_bool(), Some(false));
        assert_eq!(row["disposition"].as_str(), Some("rejected"));
    }
}

#[test]
fn time_disposition_uses_the_typed_root_and_complete_terminal_not_error_text() {
    use iroha_data_model::block::execution_output::TriggerFailureRootV1;
    let fixture = Fixture::bounded_output(false);
    let block = decode_framed_signed_block(&fixture.proofs[2].block_wire).unwrap();
    let actual = block.execution_outputs().iter()
        .find(|output| matches!(output, ExecutionOutputV1::Time(_))).unwrap();
    assert_eq!(scheduled_disposition(actual).unwrap(), "output_limit");
    for mutation in ["root", "completion", "absent"] {
        let mut changed = actual.clone();
        let ExecutionOutputV1::Time(row) = &mut changed else { unreachable!() };
        match mutation {
            "root" => row.failure_root = Some(TriggerFailureRootV1::OmittedAfterRejection),
            "completion" => row.completions.clear(),
            "absent" => row.failure_root = None,
            _ => unreachable!(),
        }
        assert!(scheduled_disposition(&changed).is_err(), "accepted altered {mutation}");
    }
}
