//! Structural fixtures for canonical output ownership; these grant no execution authority.
use super::{BlockHeader, SignedBlock, execution_output::*, output_budget::ExecutionOutputLimits};
use crate::{
    events::time::{TimeEvent, TimeInterval},
    transaction::signed::{ExecutionStep, TransactionResult, TransactionResultInner},
    trigger::{DataTriggerStep, TriggerId},
};
use iroha_crypto::Hash;

pub fn limits() -> ExecutionOutputLimits {
    ExecutionOutputLimits {
        max_outputs: 1024,
        max_output_bytes: 16 * 1024 * 1024,
        max_total_output_bytes: 128 * 1024 * 1024,
        max_executed_wire_bytes: super::consensus::MAX_EXECUTED_BLOCK_WIRE_BYTES,
    }
}
pub fn network(index: u32, result: impl Into<TransactionResult>) -> ExecutionOutputV1 {
    ExecutionOutputV1::Network(NetworkExecutionOutputV1 {
        input_index: index,
        result: result.into(),
        completions: vec![],
    })
}
pub fn time(
    header: &BlockHeader,
    index: u32,
    id: TriggerId,
    instructions: ExecutionStep,
) -> ExecutionOutputV1 {
    ExecutionOutputV1::Time(TimeExecutionOutputV1 {
        invocation: TimeInvocationV1 {
            schedule_index: index,
            event: TimeEvent {
                interval: TimeInterval {
                    since_ms: header.creation_time_ms.saturating_sub(1),
                    length_ms: 1,
                },
            },
            trigger: TriggerUseV1 {
                trigger_id: id.clone(),
                registered_at_height: header.height().get() - 1,
                action_hash: Hash::new(b"test-only exact persistent action"),
            },
        },
        result: TransactionResult::new(Ok(vec![DataTriggerStep { id, instructions }])),
        failure_root: None,
        completions: vec![],
    })
}
pub fn install_network(
    block: &mut SignedBlock,
    results: Vec<TransactionResultInner>,
) -> Result<(), super::SetExecutionOutputsError> {
    let outputs = results
        .into_iter()
        .enumerate()
        .map(|(index, result)| network(u32::try_from(index).unwrap(), result))
        .collect();
    block.set_execution_outputs(
        outputs,
        0,
        std::collections::BTreeMap::default(),
        vec![],
        crate::nexus::AxtPolicySnapshot::default(),
        std::collections::BTreeSet::default(),
        &limits(),
    )
}

#[cfg(feature = "transparent_api")]
pub fn proposal(count: usize) -> SignedBlock {
    use crate::{
        Level,
        account::AccountId,
        isi::Log,
        transaction::{FeePaymentIntent, TransactionBuilder},
    };
    use iroha_crypto::{Algorithm, HashOf, KeyPair};
    let key = KeyPair::try_from_seed(vec![0x57; 32], Algorithm::Ed25519).unwrap();
    let authority = AccountId::new(key.public_key().clone());
    let header = BlockHeader::new(
        std::num::NonZeroU64::new(2).unwrap(),
        Some(HashOf::from_untyped_unchecked(Hash::new(
            b"output fixture parent",
        ))),
        None,
        1_000,
        0,
    );
    let network_id = crate::NetworkId::from_genesis_hash(HashOf::from_untyped_unchecked(
        Hash::new(b"output fixture genesis"),
    ));
    let mut builder = super::builder::BlockBuilder::new(header);
    for index in 0..count {
        let mut tx = TransactionBuilder::new(
            network_id,
            authority.clone(),
            FeePaymentIntent::authority(vec![], None),
        );
        tx.set_creation_time(std::time::Duration::from_millis(900));
        builder.push_transaction(
            tx.with_instructions([Log::new(Level::INFO, format!("output {index}"))])
                .sign(key.private_key()),
        );
    }
    builder.build_with_signature(0, key.private_key())
}

pub fn install(
    block: &mut SignedBlock,
    outputs: Vec<ExecutionOutputV1>,
    fragments: u64,
) -> Result<(), super::SetExecutionOutputsError> {
    block.set_execution_outputs(
        outputs,
        fragments,
        std::collections::BTreeMap::default(),
        vec![],
        crate::nexus::AxtPolicySnapshot::default(),
        std::collections::BTreeSet::default(),
        &limits(),
    )
}

pub fn simple_time(block: &SignedBlock, schedule_index: u32) -> ExecutionOutputV1 {
    time(
        &block.header(),
        schedule_index,
        "output_timer".parse().unwrap(),
        ExecutionStep(Vec::new().into()),
    )
}

pub fn committed(block: &SignedBlock, input_index: u32) -> crate::query::CommittedTransaction {
    use iroha_crypto::HashOf;
    let entrypoint = block
        .network_entrypoint_at(input_index as usize)
        .unwrap()
        .clone();
    let (output_index, _) = block.network_output_at(input_index).unwrap();
    let output = block.execution_outputs()[output_index as usize].clone();
    crate::query::CommittedTransaction {
        block_hash: block.hash(),
        entrypoint_hash: entrypoint.hash(),
        entrypoint_proof: block.network_input_proof(input_index).unwrap(),
        entrypoint,
        output_hash: HashOf::new(&output),
        output_proof: block.output_proof(output_index).unwrap(),
        output,
    }
}
