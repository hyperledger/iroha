//! Structural output fixtures for storage/query tests, without execution or finality authority.

use iroha_crypto::HashOf;
use iroha_data_model::{
    block::{
        SignedBlock,
        execution_output::{ExecutionOutputV1, NetworkExecutionOutputV1},
        output_budget::ExecutionOutputLimits,
    },
    transaction::{TransactionEntrypoint, signed::TransactionResultInner},
};

/// Explicit finite policy for structural fixtures; never a runtime admission default.
pub(crate) fn structural_output_limits() -> ExecutionOutputLimits {
    ExecutionOutputLimits {
        max_outputs: 1024,
        max_output_bytes: 64 * 1024 * 1024,
        max_total_output_bytes: 128 * 1024 * 1024,
        max_executed_wire_bytes: 256 * 1024 * 1024,
    }
}

/// Build Network rows only after checking every fixture's immutable source join.
/// Internal invocation fixtures must construct their own typed invocation rows.
pub(crate) fn structural_network_outputs(
    block: &SignedBlock,
    sources: &[HashOf<TransactionEntrypoint>],
    results: Vec<TransactionResultInner>,
) -> Vec<ExecutionOutputV1> {
    assert_eq!(
        sources.len(),
        results.len(),
        "every Network fixture source needs one result"
    );
    assert!(
        block.network_input_hashes().eq(sources.iter().copied()),
        "Network fixture sources must match immutable inputs"
    );
    results
        .into_iter()
        .enumerate()
        .map(|(index, result)| {
            ExecutionOutputV1::Network(NetworkExecutionOutputV1 {
                input_index: u32::try_from(index).expect("bounded structural Network fixture"),
                result: result.into(),
                completions: Vec::new(),
            })
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use iroha_data_model::{
        block::{BlockHeader, builder::BlockBuilder},
        transaction::{FeePaymentIntent, TransactionBuilder},
    };
    use iroha_test_samples::{ALICE_ID, ALICE_KEYPAIR};

    #[test]
    fn structural_network_join_rejects_missing_or_substituted_sources() {
        let header = BlockHeader::new(std::num::NonZeroU64::MIN, None, None, 1, 0);
        let network = iroha_data_model::NetworkId::from_genesis_hash(header.hash());
        let tx = TransactionBuilder::new(
            network,
            ALICE_ID.clone(),
            FeePaymentIntent::authority(Vec::new(), None),
        )
        .sign(ALICE_KEYPAIR.private_key());
        let mut builder = BlockBuilder::new(header);
        builder.push_transaction(tx);
        let mut block = builder.build_with_signature(0, ALICE_KEYPAIR.private_key());
        let inputs: Vec<_> = block.network_input_hashes().collect();
        assert!(
            std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| structural_network_outputs(
                &block,
                &inputs,
                Vec::new()
            )))
            .is_err()
        );
        let mut wrong = inputs.clone();
        wrong[0] =
            HashOf::from_untyped_unchecked(iroha_crypto::Hash::new(b"foreign Network source"));
        assert!(
            std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| structural_network_outputs(
                &block,
                &wrong,
                vec![Ok(Vec::new())]
            )))
            .is_err()
        );
        let outputs = structural_network_outputs(&block, &inputs, vec![Ok(Vec::new())]);
        block
            .set_execution_outputs(
                outputs,
                0,
                std::collections::BTreeMap::default(),
                Vec::new(),
                iroha_data_model::nexus::AxtPolicySnapshot::default(),
                std::collections::BTreeSet::default(),
                &structural_output_limits(),
            )
            .unwrap();
        assert!(block.network_output_at(0).unwrap().1.result.is_ok());
        assert!(block.validate_output_merkle_cache().is_ok());
    }
}
