// The sole native genesis execution must reproduce every signed deterministic policy.
impl ValidBlock {
    fn validate_native_genesis_policy(
        block: &SignedBlock,
        state: &StateBlock<'_>,
    ) -> Result<(), BlockValidationError> {
        if !block.header().is_genesis() {
            return Ok(());
        }
        let metadata =
            iroha_data_model::sumeragi_finality::signed_genesis_consensus_metadata(block).map_err(
                |error| match crate::execution_attempt::genesis_read_attempt_error(error, |error| {
                    Self::execution_context_error(error.to_string())
                }) {
                    crate::execution_attempt::ExecutionAttemptError::Rejected(error) => error,
                    crate::execution_attempt::ExecutionAttemptError::Deferred(reason) => {
                        BlockValidationError::ExecutionDeferred(reason)
                    }
                },
            )?;
        let actual_execution = crate::sumeragi::staged_genesis_execution_policy_hash(state)
            .map_err(|error| Self::execution_context_error(error.to_string()))?;
        let actual_nexus = crate::sumeragi::staged_genesis_nexus_amx_context_hash(state);
        Self::require_native_genesis_policy(
            Hash::prehashed(metadata.sumeragi_context.execution_policy_hash),
            actual_execution,
            Hash::prehashed(metadata.sumeragi_context.nexus_amx_context_hash),
            actual_nexus,
        )?;
        // Startup consumes this original execution instead of executing a disposable second
        // genesis. Preserve its exact H1 cadence check before any durable publication.
        let actual_cadence = state
            .world()
            .parameters()
            .sumeragi()
            .block_cadence_ms()
            .get();
        let signed_cadence = metadata.block_cadence_ms.get();
        if actual_cadence != signed_cadence {
            return Err(Self::execution_context_error(format!(
                "staged genesis cadence {actual_cadence} ms differs from authenticated signed cadence {signed_cadence} ms"
            )));
        }
        Ok(())
    }

    fn require_native_genesis_policy(
        expected_execution: Hash,
        actual_execution: Hash,
        expected_nexus: Hash,
        actual_nexus: Hash,
    ) -> Result<(), BlockValidationError> {
        if expected_execution != actual_execution || expected_nexus != actual_nexus {
            return Err(BlockValidationError::GenesisPolicyMismatch {
                expected_execution,
                actual_execution,
                expected_nexus,
                actual_nexus,
            });
        }
        Ok(())
    }
}

#[cfg(test)]
mod native_genesis_policy_tests {
    use super::*;

    #[test]
    fn signed_genesis_requires_both_exact_policy_commitments() {
        let execution = Hash::new(b"original execution policy");
        let nexus = Hash::new(b"original Nexus policy");
        assert!(
            ValidBlock::require_native_genesis_policy(execution, execution, nexus, nexus).is_ok()
        );
        let foreign = Hash::new(b"substituted policy");
        for (actual_execution, actual_nexus) in
            [(foreign, nexus), (execution, foreign), (foreign, foreign)]
        {
            let error = ValidBlock::require_native_genesis_policy(
                execution,
                actual_execution,
                nexus,
                actual_nexus,
            )
            .unwrap_err();
            assert!(
                matches!(error, BlockValidationError::GenesisPolicyMismatch {
                expected_execution, actual_execution: retained_execution,
                expected_nexus, actual_nexus: retained_nexus,
            } if expected_execution == execution && expected_nexus == nexus
                && retained_execution == actual_execution && retained_nexus == actual_nexus)
            );
        }
    }
    #[test]
    fn native_final_genesis_policy_requires_exact_executed_cadence_before_publication() {
        use crate::{
            state::{World, WorldReadOnly as _},
            sumeragi::{
                network_topology::Topology,
                test_chain::{CertifiedTestChain, TestChainConfig},
            },
        };
        use iroha_primitives::time::TimeSource;

        let config = TestChainConfig::new(World::new(), 1_000);
        let authority = AccountId::new(config.genesis_key.public_key().clone());
        let prepared =
            CertifiedTestChain::prepare(config).expect("original signed genesis fixture");
        let genesis = prepared.genesis.block();
        let metadata =
            iroha_data_model::sumeragi_finality::signed_genesis_consensus_metadata(genesis)
                .expect("original signed consensus metadata");
        let topology = Topology::new(
            prepared
                .validator_keys
                .iter()
                .map(|key| PeerId::new(key.public_key().clone())),
        );
        let (_valid, mut staged) = ValidBlock::validate_signed_genesis(
            genesis.clone(),
            &topology,
            &authority,
            &TimeSource::new_system(),
            &prepared.state,
            iroha_data_model::parameter::system::ConsensusMode::Permissioned,
        )
        .unpack(|_| {})
        .unwrap_or_else(|(_, error)| panic!("original native genesis: {error}"));
        assert_eq!(prepared.state.committed_height(), 0);
        assert_eq!(prepared.kura.exact_durable_blocks_count().unwrap(), 0);
        ValidBlock::validate_native_genesis_policy(genesis, &staged)
            .expect("the actual original staged state matches its signed metadata");

        let original_cadence = staged.world().parameters().sumeragi().block_cadence_ms();
        assert_eq!(original_cadence, metadata.block_cadence_ms);
        let changed =
            std::num::NonZeroU64::new(original_cadence.get().checked_add(1).unwrap()).unwrap();
        staged.world.parameters.get_mut().sumeragi.block_cadence_ms = changed;
        let error = ValidBlock::validate_native_genesis_policy(genesis, &staged)
            .expect_err("signed metadata cannot bless a different final executed H1 cadence");
        let expected = format!(
            "staged genesis cadence {} ms differs from authenticated signed cadence {} ms",
            changed.get(),
            original_cadence.get()
        );
        assert!(
            matches!(error, BlockValidationError::ExecutionContextInvalid(ref reason) if reason == &expected),
            "{error}"
        );
        assert_eq!(prepared.state.committed_height(), 0);
        assert_eq!(prepared.kura.exact_durable_blocks_count().unwrap(), 0);
        staged.world.parameters.get_mut().sumeragi.block_cadence_ms = original_cadence;
        ValidBlock::validate_native_genesis_policy(genesis, &staged)
            .expect("restoring the exact original staged cadence restores acceptance");
    }
}
