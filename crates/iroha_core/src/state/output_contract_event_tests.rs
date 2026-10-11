//! Actual Network and Pipeline output ownership for compiled native contract emissions.

use super::*;
use iroha_data_model::{
    events::pipeline::{BlockEventFilter, BlockStatus},
    smart_contract::{ContractAddress, ContractArtifactId},
    transaction::executable::ContractInvocation,
};
use iroha_model_base::topology::DataSpaceId;

fn install(state: &State, source: &str) -> (ContractAddress, Hash) {
    let (code, manifest) = kotodama_lang::compiler::Compiler::new()
        .compile_source_with_manifest(source)
        .expect("compile native event fixture");
    let hash = manifest.code_hash.expect("authenticated artifact hash");
    let address = ContractAddress::derive(&state.network_id, &ALICE_ID, 51, DataSpaceId::UNIVERSAL)
        .expect("derive fixture contract");
    let binding =
        crate::smartcontracts::code::ContractSubjectBinding::new_direct(&address, ALICE_ID.clone())
            .with_active_code_hash(hash);
    let (mut setup, _recording) = output_fixture_setup(state);
    let mut tx = setup.transaction_for_callback_testing();
    Register::account(Account::new(binding.subject.clone()))
        .execute(&ALICE_ID, &mut tx)
        .unwrap();
    let artifact = ContractArtifactId::new(DataSpaceId::UNIVERSAL, hash);
    tx.world.contract_code.insert(artifact, code);
    tx.world.contract_manifests.insert(artifact, manifest);
    tx.world.contract_instances.insert(address.clone(), hash);
    tx.world
        .contract_subject_addresses
        .insert(binding.subject.clone(), address.clone());
    tx.world
        .contract_subject_bindings
        .insert(address.clone(), binding);
    tx.apply();
    setup.commit_world_overlay_for_testing().unwrap();
    (address, hash)
}

fn invocation(address: &ContractAddress, hash: Hash, name: &str) -> ContractInvocation {
    ContractInvocation {
        contract_address: address.clone(),
        expected_code_hash: hash,
        entrypoint: name.to_owned(),
        arguments: None,
    }
}

const SOURCE: &str = r#"
seiyaku EmissionOutput {
    error enum Failure { Rejected = 1 }
  event Accepted { bool flag; }
  kotoage fn publish() authorize(anyone) { emit Accepted { flag: true }; }
  kotoage fn reject() authorize(anyone) { emit Accepted { flag: false }; require(false, Failure::Rejected); }
}
"#;

#[test]
fn actual_network_output_retains_native_emissions_and_rejection_discards_them() {
    for (selector, success) in [("publish", true), ("reject", false)] {
        let state = fixture(65_536, None);
        let (address, hash) = install(&state, SOURCE);
        let mut builder = TransactionBuilder::new(
            state.network_id,
            ALICE_ID.clone(),
            FeePaymentIntent::authority(vec![], std::num::NonZeroU64::new(1_000_000)),
        );
        builder.set_creation_time(output_fixture_input_time(&state));
        let input = TransactionEntrypoint::External(
            builder
                .with_executable(Executable::ContractCall(invocation(
                    &address, hash, selector,
                )))
                .sign(ALICE_KEYPAIR.private_key()),
        );
        let source = carrier(&state, vec![input]);
        let (mut block, _recording) = recorded_network_block(&state, &source);
        execute(&mut block, &source).expect("complete actual signed contract invocation");
        let result = &network_row(&block, 0).result;
        assert_eq!(result.is_ok(), success, "{result:?}");
        assert_eq!(result.contract_events().len(), usize::from(success));
        if success {
            let events = result.contract_events();
            assert!(events.admitted_to(&block.execution_budget()));
            assert_eq!(events.as_slice()[0].contract, address);
            assert_eq!(events.as_slice()[0].code_hash, hash);
            assert_eq!(events.as_slice()[0].caller, *ALICE_ID);
            assert_eq!(events.as_slice()[0].definition.name.as_ref(), "Accepted");
            let rendered = ivm::value_record::render_entrypoint_return_record(
                &events.as_slice()[0].definition.payload_type,
                &events.as_slice()[0].payload,
            )
            .unwrap();
            assert_eq!(rendered["flag"].as_bool(), Some(true));
            let clone = events.clone();
            assert!(
                iroha_data_model::smart_contract::event::ContractEmissionsV1::ptr_eq(
                    events, &clone
                )
            );
        }
    }
}

#[test]
fn actual_network_output_limit_contains_no_native_emissions() {
    let state = fixture(4096, None);
    let contract_source = format!(
        "seiyaku LargeEmission {{ event Written {{ string text; }} kotoage fn publish() authorize(anyone) {{ emit Written {{ text: \"{}\" }}; }} }}",
        "x".repeat(8192)
    );
    let (address, hash) = install(&state, &contract_source);
    let mut builder = TransactionBuilder::new(
        state.network_id,
        ALICE_ID.clone(),
        FeePaymentIntent::authority(vec![], std::num::NonZeroU64::new(1_000_000)),
    );
    builder.set_creation_time(output_fixture_input_time(&state));
    let input = TransactionEntrypoint::External(
        builder
            .with_executable(Executable::ContractCall(invocation(
                &address, hash, "publish",
            )))
            .sign(ALICE_KEYPAIR.private_key()),
    );
    let source = carrier(&state, vec![input]);
    let (mut block, _recording) = recorded_network_block(&state, &source);
    execute(&mut block, &source).expect("healthy emission overflow has a terminal output");
    assert!(
        retained(&block).rows[0].is_output_limit_rejection(),
        "{:?}",
        retained(&block).rows[0]
    );
    assert!(network_row(&block, 0).result.contract_events().is_empty());
}

#[test]
fn actual_pipeline_output_owns_its_emissions_separately_from_network() {
    for (selector, success) in [("publish", true), ("reject", false)] {
        let state = fixture(65_536, None);
        let (address, hash) = install(&state, SOURCE);
        {
            let mut parameters = state.world.parameters.block();
            let mut policy = parameters.get().block().execution_output();
            policy.max_pipeline_triggers = 1;
            parameters
                .get_mut()
                .set_parameter(Parameter::Block(BlockParameter::ExecutionOutput(policy)));
            parameters.commit();
        }
        {
            let (mut setup, _recording) = output_fixture_setup(&state);
            let mut tx = setup.transaction_for_callback_testing();
            let trigger = Trigger::new(
                "native_emitter".parse().unwrap(),
                Action::new(
                    Executable::ContractCall(invocation(&address, hash, selector)),
                    Repeats::Exactly(1),
                    ALICE_ID.clone(),
                    BlockEventFilter::new().for_status(BlockStatus::Approved),
                )
                .unwrap(),
            );
            Register::trigger(trigger)
                .execute(&ALICE_ID, &mut tx)
                .unwrap();
            tx.apply();
            setup.commit_world_overlay_for_testing().unwrap();
        }
        let source = carrier(
            &state,
            vec![input(
                &state,
                vec![Log::new(Level::DEBUG, "root".into()).into()],
                FeePaymentIntent::authority(vec![], None),
                false,
            )],
        );
        let (mut block, _recording) = recorded_network_block(&state, &source);
        block.reserve_ordinary_execution_outputs(&source).unwrap();
        block
            .produce_ordinary_execution_outputs(&source, |producer| {
                producer.execute_network_sources(None)?;
                producer.execute_pipeline_outputs()?;
                producer.execute_scheduled_time_outputs()
            })
            .unwrap();
        let rows = &retained(&block).rows;
        assert_eq!(rows.len(), 2);
        assert!(rows[0].result().contract_events().is_empty());
        assert!(matches!(rows[1], ExecutionOutputV1::Pipeline(_)));
        assert_eq!(rows[1].result().is_ok(), success, "{:?}", rows[1]);
        assert_eq!(
            rows[1].result().contract_events().len(),
            usize::from(success)
        );
    }
}
