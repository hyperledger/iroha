/// Provider governance intake retains Core's bonded-citizen and enactment boundaries.
mod sorafs_provider_governance_admission {
    use super::*;
    use iroha_data_model::{
        governance::types::{ProposalKind, SorafsProviderGovernanceProposal},
        isi::{
            error::InstructionExecutionError,
            governance::ProposeSorafsProviderGovernance,
            sorafs::{EstablishSorafsProviderOwnerV1, SorafsProviderGovernanceActionV1},
        },
        sorafs::capacity::ProviderId,
    };

    #[test]
    fn initial_executor_provider_governance_requires_current_citizenship_bond() {
        let authority = ALICE_ID.clone();
        let provider = ProviderId::new([0xA9; 32]);
        let action = SorafsProviderGovernanceActionV1::Establish(EstablishSorafsProviderOwnerV1 {
            provider_id: provider,
            owner: BOB_ID.clone(),
        });
        let instruction: InstructionBox = ProposeSorafsProviderGovernance {
            action: action.clone(),
        }
        .into();
        assert!(initial_native_instruction_is_explicitly_admitted(
            &instruction
        ));
        let mut state = state_after_genesis(World::with(
            [],
            [
                Account::new(authority.clone()).build(&authority),
                Account::new(BOB_ID.clone()).build(&BOB_ID),
            ],
            [],
        ));
        state.gov.citizenship_bond_amount = Quantity::from(10_u32);
        let mut block = state.block(BlockHeader::new(nonzero!(2_u64), None, None, 1, 0));
        let mut transaction = block.transaction();

        for bond in [None, Some(9_u32)] {
            if let Some(amount) = bond {
                transaction.world.citizens.insert(
                    authority.clone(),
                    crate::state::CitizenshipRecord::new(
                        authority.clone(),
                        Quantity::from(amount),
                        1,
                    ),
                );
            }
            let error = crate::executor::Executor::Initial
                .execute_instruction(&mut transaction, &authority, instruction.clone())
                .expect_err("missing or insufficient citizenship bond must fail closed");
            assert!(
                matches!(error, ValidationFail::InstructionFailed(InstructionExecutionError::InvariantViolation(ref message))
                    if message.as_ref() == "not permitted: a bonded citizen is required to propose SoraFS provider governance"),
                "expected the native citizenship rejection, got {error:?}"
            );
            assert!(
                transaction
                    .world
                    .governance_proposals
                    .iter()
                    .next()
                    .is_none()
            );
            assert!(transaction.world.provider_owners.get(&provider).is_none());
        }

        transaction.world.citizens.insert(
            authority.clone(),
            crate::state::CitizenshipRecord::new(authority.clone(), Quantity::from(10_u32), 1),
        );
        crate::executor::Executor::Initial
            .execute_instruction(&mut transaction, &authority, instruction.clone())
            .expect("an exactly bonded citizen may submit a provider proposal");
        let kind = ProposalKind::SorafsProviderGovernance(SorafsProviderGovernanceProposal {
            action: Box::new(action),
        });
        let proposal_id = kind.fingerprint();
        let proposal = transaction
            .world
            .governance_proposals
            .get(&proposal_id)
            .expect("canonical provider proposal");
        assert_eq!(proposal.kind, kind);
        assert_eq!(proposal.proposer, authority);
        assert_eq!(proposal.created_height, 2);
        assert_eq!(
            proposal.status,
            crate::state::GovernanceProposalStatus::Proposed
        );
        assert!(
            transaction.world.provider_owners.get(&provider).is_none(),
            "proposal intake must not enact provider ownership"
        );
        assert!(
            transaction
                .world
                .governance_referenda
                .iter()
                .next()
                .is_none(),
            "provider governance must not create a standalone referendum bypass"
        );
        let before = proposal.encode();
        crate::executor::Executor::Initial
            .execute_instruction(&mut transaction, &authority, instruction.clone())
            .expect("exact proposal replay is idempotent");
        assert_eq!(transaction.world.governance_proposals.iter().count(), 1);
        assert_eq!(
            transaction
                .world
                .governance_proposals
                .get(&proposal_id)
                .expect("replayed proposal")
                .encode(),
            before
        );

        transaction.apply();
        block
            .commit_world_overlay_for_testing()
            .expect("retain original proposal for changed-policy replay");
        state.gov.citizenship_bond_amount = Quantity::from(11_u32);
        let mut block = state.block(BlockHeader::new(nonzero!(2_u64), None, None, 1, 0));
        let mut transaction = block.transaction();
        let error = crate::executor::Executor::Initial
            .execute_instruction(&mut transaction, &authority, instruction)
            .expect_err("replay must recheck the current bond requirement");
        assert!(matches!(error, ValidationFail::InstructionFailed(
            InstructionExecutionError::InvariantViolation(ref message))
            if message.as_ref() == "not permitted: a bonded citizen is required to propose SoraFS provider governance"));
        assert_eq!(
            transaction
                .world
                .governance_proposals
                .get(&proposal_id)
                .expect("unchanged proposal after rejected replay")
                .encode(),
            before
        );
        assert!(transaction.world.provider_owners.get(&provider).is_none());
    }
}
