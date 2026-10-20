//! Signed private genesis cannot acquire the global AMX coordinator's authority.

use super::*;
use crate::sumeragi::test_chain::{CertifiedTestChain, TestChainConfig, TestChainError};
use iroha_data_model::{
    isi::sumeragi_amx::{BeginAmxV1, RegisterAmxDataspaceV1},
    sumeragi_amx::{AmxLegV1, AmxTransactionV1},
    sumeragi_finality::{authenticated_genesis, test_fixtures::NativeFinalityFixture},
};

fn coordinator_instructions(
    genesis_time_ms: u64,
    original_cadence_ms: u64,
) -> (Vec<InstructionBox>, [u8; 32]) {
    let mut instructions = [21, 22]
        .into_iter()
        .map(|id| {
            let participant = NativeFinalityFixture::start(&format!("root-scope-amx-{id}"));
            RegisterAmxDataspaceV1 {
                dataspace: DataSpaceId::new(id),
                instance: participant.verifier().instance().0,
                anchor: norito::encode_canonical(
                    &authenticated_genesis(participant.genesis())
                        .map(|genesis| genesis.into_parts().0)
                        .unwrap(),
                )
                .unwrap(),
            }
            .into()
        })
        .collect::<Vec<InstructionBox>>();
    let transaction = AmxTransactionV1 {
        legs: [21, 22]
            .into_iter()
            .map(|id| AmxLegV1 {
                dataspace: DataSpaceId::new(id),
                payload: vec![7],
            })
            .collect(),
        deadline: 8,
        expires_at_ms: genesis_time_ms
            .checked_add(
                iroha_data_model::sumeragi_amx::amx_max_time_window_ms(original_cadence_ms)
                    .unwrap(),
            )
            .unwrap(),
        nonce: [13; 32],
    };
    let tx = transaction.id().unwrap();
    instructions.push(BeginAmxV1 { transaction }.into());
    (instructions, tx)
}

#[test]
fn signed_private_genesis_cannot_install_global_amx_coordinator() {
    let (instructions, _) = coordinator_instructions(1_000, 100);
    let parent = chain(4, 200);
    let parent = NetworkId::from_genesis_hash(parent.genesis.hash());
    let result = DataspaceChain::with_genesis_instructions(
        parent,
        DataSpaceId::new((1_u64 << 40) + 91),
        instructions,
    );
    let Err(failure) = result else {
        panic!("signed private genesis installed the global AMX coordinator");
    };
    // Inspect the retained typed reason: the outer Display intentionally reports
    // the validation category while its source keeps the original refusal.
    let TestChainError::OriginalGenesisExecution(error) = &failure.error else {
        panic!(
            "private AMX refused for a different startup reason: {}",
            failure.error
        );
    };
    let crate::block::BlockValidationError::InvalidGenesis(
        crate::block::InvalidGenesisError::RejectedOutput(rejection),
    ) = error.as_ref()
    else {
        panic!("private AMX did not retain its original rejected output: {error:?}");
    };
    assert_eq!(rejection.output_index, 0);
    assert!(
        matches!(rejection.reason.as_ref(),
            iroha_data_model::transaction::error::TransactionRejectionReason::Validation(
                iroha_data_model::ValidationFail::NotPermitted(message))
            if message == "AMX coordinator requires the authenticated global root"
        ),
        "unexpected original private AMX refusal: {:?}",
        rejection.reason
    );
    let view = failure.state.view();
    assert_eq!(view.height(), 0);
    assert_eq!(failure.state.kura().blocks_count(), 0);
    assert!(view.world().sumeragi_amx().dataspaces.is_empty());
    assert!(view.world().sumeragi_amx().transactions.is_empty());
}

#[test]
fn signed_global_genesis_keeps_original_amx_coordinator_authority() {
    let mut config = TestChainConfig::new(World::new(), 1_000);
    let (mut instructions, tx) = coordinator_instructions(
        config.genesis_time_ms,
        config.genesis_block_cadence_ms.get(),
    );
    // Signed global genesis installs coordinator authority. Relayable Begin records need
    // a non-genesis quorum-certified carrier, as required by the native AMX proof reader.
    let begin = instructions
        .pop()
        .expect("the final instruction begins the AMX");
    config.genesis_instructions = instructions;
    let genesis_key = config.genesis_key.clone();
    let mut chain = CertifiedTestChain::start(config).unwrap();
    let view = chain.state().view();
    assert_eq!(view.height(), 1);
    assert_eq!(chain.kura().blocks_count(), 1);
    assert_eq!(view.world().sumeragi_amx().dataspaces.len(), 2);
    assert!(view.world().sumeragi_amx().transaction(&tx).is_none());
    drop(view);
    let begin = chain.sign(&genesis_key, [begin], 1_099);
    assert_eq!(chain.commit_at(1_100, vec![begin]), [true]);
    let view = chain.state().view();
    assert_eq!(view.height(), 2);
    assert_eq!(chain.kura().blocks_count(), 2);
    assert_eq!(view.world().sumeragi_amx().dataspaces.len(), 2);
    let amx = view.world().sumeragi_amx();
    let entry = amx
        .transaction(&tx)
        .expect("certified Begin retains the transaction");
    assert_eq!(entry.begun_at, 2);
}
