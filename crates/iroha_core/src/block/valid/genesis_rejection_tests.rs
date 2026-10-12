//! Actual rejected genesis execution retains its cause without publishing output or state.

use super::*;
use crate::{
    governance::manifest::LaneManifestRegistry,
    kura::Kura,
    query::store::LiveQueryStore,
    state::{State, World, WorldReadOnly},
    sumeragi::{
        network_topology::Topology,
        test_chain::{TestChainConfig, fixture_validators, signed_genesis_fixture},
    },
};
use iroha_data_model::{
    Identifiable, Registrable,
    account::Account,
    isi::{Register, error::InstructionExecutionError},
    prelude::Domain,
};
use iroha_model_base::domain::DomainId;
use std::{error::Error as _, sync::Arc};

#[test]
fn rejected_genesis_outputs_fail_before_schedule_finalization() {
    iroha_genesis::init_instruction_registry();
    let config = TestChainConfig::new(World::new(), 1_000);
    let account = AccountId::new(config.genesis_key.public_key().clone());
    let duplicate = DomainId::try_new("duplicate", "universal").unwrap();
    let validators = fixture_validators();
    assert_eq!(validators.len(), 4);
    let mut source = signed_genesis_fixture(
        &config.chain_id,
        &config.genesis_key,
        &validators,
        vec![
            Register::domain(Domain::new(duplicate.clone())).into(),
            Register::domain(Domain::new(duplicate.clone())).into(),
        ],
        1_000,
        iroha_data_model::block::consensus::ConsensusMode::Permissioned,
        None,
    )
    .unwrap();
    let original_wire = source.encode_wire().unwrap();
    let expected_index = source
        .external_transactions()
        .position(|transaction| {
            let iroha_data_model::transaction::Executable::Instructions(instructions) =
                transaction.instructions()
            else {
                return false;
            };
            instructions.iter().any(|instruction| {
                matches!(
                    instruction.as_any().downcast_ref::<iroha_data_model::isi::RegisterBox>(),
                    Some(iroha_data_model::isi::RegisterBox::Domain(register))
                        if register.object().id() == &duplicate
                )
            })
        })
        .expect("the original duplicate registration has a network input");
    let kura = Kura::blank_kura_for_testing();
    let state = State::new_with_chain_and_network_id_for_testing(
        World::with(
            [Domain::new(iroha_genesis::GENESIS_DOMAIN_ID.clone()).build(&account)],
            [Account::new(account.clone()).build(&account)],
            [],
        ),
        Arc::clone(&kura),
        LiveQueryStore::start_test(),
        config.chain_id,
        NetworkId::from_genesis_hash(source.hash()),
    );
    let nexus = state.nexus_snapshot();
    state.install_lane_manifests_for_testing(&Arc::new(
        LaneManifestRegistry::empty().rebind(&nexus.lane_catalog, &nexus.governance),
    ));
    let authenticated = authenticate_genesis_block_intents(&source, &account).unwrap();
    let (mut overlay, recorder) = state
        .block_with_recorded_pristine_carrier_stage(&source, |_| Ok::<_, String>(()), |error| error)
        .unwrap();
    let error = overlay
        .execute_and_seal_ordinary_outputs::<String>(
            &mut source,
            Some(&authenticated),
            |_, _, _| panic!("rejected genesis must not enter the schedule finalizer"),
        )
        .unwrap_err();
    let crate::state::ExecutionOutputSealError::RejectedGenesis(rejection) = error else {
        panic!("expected the actual retained output rejection: {error:?}");
    };
    assert_eq!(rejection.output_index, expected_index);
    assert!(matches!(
        rejection.reason.as_ref(),
        TransactionRejectionReason::Validation(
            iroha_data_model::ValidationFail::InstructionFailed(
                InstructionExecutionError::Repetition(_)
            )
        )
    ));
    assert_eq!(
        rejection
            .source()
            .unwrap()
            .downcast_ref::<TransactionRejectionReason>(),
        Some(rejection.reason.as_ref()),
    );
    assert!(
        !source.has_results(),
        "failed output storage remains unattached"
    );
    assert_eq!(source.encode_wire().unwrap(), original_wire);
    assert!(
        overlay.world.domain(&duplicate).is_err(),
        "rejected batch rolled back"
    );
    assert!(
        matches!(
            overlay.commit().unwrap_err(),
            crate::state::storage_transactions::TransactionsBlockError::ExecutionOutputCapacity,
        ),
        "poisoned owner cannot publish"
    );
    drop(recorder);

    let topology = Topology::new(validators.iter().map(|(peer, _)| peer.clone()));
    let (rejected, error) = {
        let selected_genesis = source.clone();
        let selected_scope = crate::sumeragi::epoch::authenticated_genesis(&selected_genesis)
            .expect("signed fixture root scope")
            .into_parts()
            .1;
        ValidBlock::validate_signed_genesis(
            selected_genesis,
            &topology,
            &account,
            &TimeSource::new_system(),
            &state,
            iroha_data_model::block::consensus::ConsensusMode::Permissioned,
            selected_scope,
        )
    }
    .unpack(|_| {})
    .err()
    .expect("the original invalid genesis must remain rejected");
    let BlockValidationError::InvalidGenesis(InvalidGenesisError::RejectedOutput(actual)) =
        error.as_ref()
    else {
        panic!("native validator erased the retained cause: {error:?}");
    };
    assert_eq!(actual, &rejection);
    assert_eq!(rejected.encode_wire().unwrap(), original_wire);
    let startup = crate::sumeragi::startup::apply_genesis(
        &state,
        source,
        &account,
        iroha_data_model::block::consensus::ConsensusMode::Permissioned,
        None,
    )
    .unwrap_err();
    let crate::sumeragi::startup::StartupError::InvalidGenesis(error) = &startup else {
        panic!("startup erased the native validation error: {startup:?}");
    };
    assert!(
        matches!(error.as_ref(), BlockValidationError::InvalidGenesis(
        InvalidGenesisError::RejectedOutput(actual)
    ) if actual == &rejection)
    );
    assert!(startup.source().unwrap().is::<Box<BlockValidationError>>());
    assert_eq!(state.view().height(), 0, "genesis was not published");
    assert!(state.world_view().domain(&duplicate).is_err());
    assert_eq!(kura.blocks_count(), 0);
    assert_eq!(kura.pipeline_sidecar_queue_len_for_testing(), 0);
}
