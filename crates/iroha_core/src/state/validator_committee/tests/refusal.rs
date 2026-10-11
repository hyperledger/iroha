//! Original incumbent and signed frozen-credential-command refusal ownership.

use super::*;
use crate::{
    execution_attempt::ExecutionAttemptError as Attempt, smartcontracts::Execute,
    sumeragi::test_chain::CertifiedTestChain,
};
use iroha_data_model::{isi::SetParameter, prelude::*};
use iroha_model_base::domain::DomainId;

fn original_incumbent() -> (CertifiedTestChain, KeyPair) {
    use crate::sumeragi::test_chain::{CertifiedTestChain, TestChainConfig};
    use iroha_crypto::Algorithm;
    use iroha_data_model::{
        isi::RegisterPublicLaneValidator,
        nexus::PublicLaneMonetaryPlanV1,
        parameter::{Parameter, system::SumeragiNposParameters},
    };
    use iroha_model_base::{peer::PeerId, topology::LaneId};
    let owner_key = KeyPair::from_seed(vec![0xD1; 32], Algorithm::Ed25519);
    let other_key = KeyPair::from_seed(vec![0xD2; 32], Algorithm::Ed25519);
    let owner = AccountId::new(owner_key.public_key().clone());
    let other = AccountId::new(other_key.public_key().clone());
    let mut validators = (0x51..=0x54)
        .map(|seed| KeyPair::from_seed(vec![seed; 32], Algorithm::BlsNormal))
        .collect::<Vec<_>>();
    validators.sort_by_key(|key| PeerId::new(key.public_key().clone()));
    let peer_key = validators[0].clone();
    let peer = PeerId::new(peer_key.public_key().clone());
    let staking = iroha_config::parameters::actual::NexusStaking::default();
    let definition: AssetDefinitionId = staking.stake_asset_id.parse().unwrap();
    let escrow = AccountId::parse_encoded(&staking.stake_escrow_account_id).unwrap();
    let amount = Quantity::from(1_000_u32);
    let source = AssetId::new(definition.clone(), owner.clone());
    let destination = AssetId::new(definition.clone(), escrow.clone());
    let world = World::with_assets(
        [Domain::new(DomainId::try_new("nexus", "universal").unwrap()).build(&owner)],
        [
            Account::new(owner.clone()).build(&owner),
            Account::new(other.clone()).build(&other),
            Account::new(escrow.clone()).build(&escrow),
        ],
        [AssetDefinition::new(
            definition,
            "Staked XOR",
            iroha_primitives::numeric::NumericSpec::fractional(9),
            iroha_data_model::asset::AssetBalancePolicy::Global,
            None,
        )
        .build(&owner)],
        [Asset::new(source.clone(), amount.clone())],
        [],
    );
    let mut config = TestChainConfig::new(world, 1_000);
    config.validator_keys = Some(validators);
    config.consensus_mode = iroha_data_model::parameter::system::SumeragiConsensusMode::Npos;
    config.genesis_parameters.push(Parameter::Custom(
        SumeragiNposParameters::default().into_custom_parameter(),
    ));
    config.genesis_instructions.push(
        RegisterPublicLaneValidator::new(
            LaneId::SINGLE,
            owner.clone(),
            peer.clone(),
            owner.clone(),
            amount.clone(),
            Metadata::default(),
            PublicLaneMonetaryPlanV1::genesis_registration(source, destination, amount),
        )
        .into(),
    );
    let chain = CertifiedTestChain::start(config).unwrap();
    (chain, owner_key)
}

/// Execute the original selecting boundary and both real ceremonies before testing publication.
fn original_preparation() -> (CertifiedTestChain, KeyPair, ValidatorCommitteeOperationV1) {
    use crate::beacon::{
        FinalizedGlobalThresholdBeaconKeySessionRecordV1, GlobalThresholdBeaconPartialSignerV1,
        GlobalThresholdBeaconPulseAggregatorV1, InMemoryGlobalThresholdBeaconPartialSignerV1,
        ValidatedGlobalThresholdBeaconSessionV1,
    };
    use crate::sumeragi::test_chain::{Signers, TestChainConfig};
    use iroha_data_model::{
        consensus::{GlobalThresholdBeaconChainAnchorV1, GlobalThresholdBeaconPulseContextV1},
        isi::{
            RegisterPublicLaneValidator,
            consensus_keys::{
                ApplyThresholdKeyLifecycleCertificateV1, ThresholdKeyLifecycleActionV1,
                ThresholdKeyLifecycleCertificateV1, ThresholdKeyLifecycleSignatureV1,
            },
        },
        nexus::{PrepareValidatorCommitteeCredentialsV1, PublicLaneMonetaryPlanV1},
        parameter::system::SumeragiParameter,
    };
    use std::num::NonZeroU64;

    const EPOCH: u64 = 16;
    let mut keys = (0x51..=0x54)
        .map(|seed| KeyPair::from_seed(vec![seed; 32], Algorithm::BlsNormal))
        .collect::<Vec<_>>();
    keys.sort_by_key(|key| PeerId::new(key.public_key().clone()));
    let owners = (0xD1..=0xD4)
        .map(|seed| KeyPair::from_seed(vec![seed; 32], Algorithm::Ed25519))
        .collect::<Vec<_>>();
    let accounts = owners
        .iter()
        .map(|key| AccountId::new(key.public_key().clone()))
        .collect::<Vec<_>>();
    let staking = iroha_config::parameters::actual::NexusStaking::default();
    let definition: AssetDefinitionId = staking.stake_asset_id.parse().unwrap();
    let escrow = AccountId::parse_encoded(&staking.stake_escrow_account_id).unwrap();
    let world = World::with_assets(
        [Domain::new(DomainId::try_new("nexus", "universal").unwrap()).build(&accounts[0])],
        accounts
            .iter()
            .map(|account| Account::new(account.clone()).build(account))
            .chain([Account::new(escrow.clone()).build(&escrow)]),
        [AssetDefinition::new(
            definition.clone(),
            "Staked XOR",
            iroha_primitives::numeric::NumericSpec::fractional(9),
            iroha_data_model::asset::AssetBalancePolicy::Global,
            None,
        )
        .build(&accounts[0])],
        accounts.iter().map(|account| {
            Asset::new(
                AssetId::new(definition.clone(), account.clone()),
                Quantity::from(1_000u64),
            )
        }),
        [],
    );
    let mut config = TestChainConfig::new(world, 1_000);
    config.validator_keys = Some(keys.clone());
    config.consensus_mode = iroha_data_model::parameter::system::SumeragiConsensusMode::Npos;
    config.genesis_parameters.extend([
        Parameter::Sumeragi(SumeragiParameter::EpochLengthBlocks(
            NonZeroU64::new(EPOCH).unwrap(),
        )),
        Parameter::Custom(
            SumeragiNposParameters {
                epoch_length_blocks: NonZeroU64::new(EPOCH).unwrap(),
                max_validators: 4,
                evidence_horizon_blocks: EPOCH,
                slashing_delay_blocks: 2,
                ..SumeragiNposParameters::default()
            }
            .into_custom_parameter(),
        ),
    ]);
    for (account, key) in accounts.iter().zip(&keys) {
        let source = AssetId::new(definition.clone(), account.clone());
        let destination = AssetId::new(definition.clone(), escrow.clone());
        config.genesis_instructions.push(
            RegisterPublicLaneValidator::new(
                LaneId::SINGLE,
                account.clone(),
                PeerId::new(key.public_key().clone()),
                account.clone(),
                Quantity::from(1_000u64),
                Metadata::default(),
                PublicLaneMonetaryPlanV1::genesis_registration(
                    source,
                    destination,
                    Quantity::from(1_000u64),
                ),
            )
            .into(),
        );
    }
    let mut chain = CertifiedTestChain::start(config).unwrap();

    struct Beacon {
        session: ValidatedGlobalThresholdBeaconSessionV1,
        signers: Vec<InMemoryGlobalThresholdBeaconPartialSignerV1>,
    }
    fn ceremony(
        chain: &CertifiedTestChain,
        keys: &[KeyPair],
        generation: u64,
        session_id: [u8; 32],
        attempt_id: [u8; 32],
        start: u64,
    ) -> Beacon {
        let roster = keys
            .iter()
            .map(|key| PeerId::new(key.public_key().clone()))
            .collect::<Vec<_>>();
        let (session, signers) = prepared_session_and_signers_fixture_for_keys_v1(
            GlobalThresholdBeaconDkgSessionV1 {
                version: 1,
                network_id: chain.network_id(),
                session_id,
                attempt_id,
                authority_generation: generation,
                roster_hash: crate::beacon::global_threshold_beacon_roster_hash_v1(&roster),
                committee_size: 4,
                threshold: 2,
                start_height: start,
                commitments_end_height: start + 1,
                deliveries_end_height: start + 2,
                acceptances_end_height: start + 3,
            },
            keys,
            &chain.state().ivm_execution_budget(),
        );
        assert!(session.belongs_to(&chain.state().ivm_execution_budget()));
        Beacon { session, signers }
    }
    fn install(chain: &mut CertifiedTestChain, beacon: &Beacon, keys: &[KeyPair], owner: &KeyPair) {
        let height = chain.height() + 1;
        let roster = keys
            .iter()
            .map(|key| PeerId::new(key.public_key().clone()))
            .collect::<Vec<_>>();
        let record = FinalizedGlobalThresholdBeaconKeySessionRecordV1::new(
            beacon.session.record().clone(),
            &chain.state().ivm_execution_budget(),
        )
        .unwrap();
        let mut certificate = ThresholdKeyLifecycleCertificateV1 {
            version: crate::state::THRESHOLD_KEY_LIFECYCLE_CERTIFICATE_VERSION_V1,
            action: ThresholdKeyLifecycleActionV1::FinalizeGlobalBeaconKey,
            expected_active_session_id: chain
                .state()
                .view()
                .world()
                .active_global_beacon_key_session(),
            effective_height: height,
            network_id: chain.network_id(),
            roster_hash: crate::beacon::global_threshold_beacon_roster_hash_v1(&roster),
            committee_size: 4,
            quorum: 3,
            session_id: record.session.session_id,
            transcript_hash: record.session.transcript_hash,
            public_state: norito::encode_canonical(&record).unwrap(),
            signatures: Vec::new(),
        };
        let preimage =
            crate::state::threshold_key_lifecycle_certificate_preimage_v1(&certificate).unwrap();
        certificate.signatures = keys
            .iter()
            .take(3)
            .enumerate()
            .map(|(index, key)| ThresholdKeyLifecycleSignatureV1 {
                signer_index: index as u16,
                signature: iroha_crypto::Signature::try_new(key.private_key(), &preimage).unwrap(),
            })
            .collect();
        crate::state::verify_threshold_key_lifecycle_certificate_v1(
            &certificate,
            &chain.network_id(),
            height,
            &roster,
        )
        .unwrap();
        let signed = chain.sign(
            owner,
            [ApplyThresholdKeyLifecycleCertificateV1 { certificate }.into()],
            height * 1_000,
        );
        assert_eq!(chain.commit_at(height * 1_000, vec![signed]), [true]);
    }
    fn advance(chain: &mut CertifiedTestChain, target: u64, beacon: &Beacon) {
        while chain.height() < target {
            let height = chain.height() + 1;
            let current = chain
                .state()
                .view()
                .world()
                .consensus_schedule()
                .ready(height)
                .unwrap()
                .epoch
                .clone();
            let control = if height + 1 == current.authorization.last_height {
                let parent = chain.committed(chain.height());
                let epoch = crate::sumeragi::schedule::core_epoch(&current).unwrap().id;
                let mut pulse = GlobalThresholdBeaconPulseAggregatorV1::new(
                    beacon.session.clone(),
                    height,
                    GlobalThresholdBeaconChainAnchorV1 {
                        height: chain.height(),
                        block_hash: parent.block_hash(),
                    },
                    GlobalThresholdBeaconPulseContextV1 {
                        instance: chain.instance().0,
                        epoch: epoch.epoch,
                        epoch_context_id: epoch.context.0,
                        parent_consensus_hash: parent.core_hash().0,
                        parent_result: parent.result().0,
                    },
                )
                .unwrap();
                for signer in beacon.signers.iter().take(2) {
                    pulse
                        .accept_partial(
                            signer
                                .sign_partial(pulse.session(), pulse.payload())
                                .unwrap(),
                        )
                        .unwrap();
                }
                crate::sumeragi::epoch_beacon::control::encode(Some(pulse.finalize().unwrap()))
                    .unwrap()
            } else {
                iroha_sumeragi::types::ControlWitness::empty()
            };
            chain.commit_with_control(Some(height * 1_000), Vec::new(), Signers::Quorum, control);
            assert_eq!(chain.height(), height);
        }
    }
    let bootstrap = ceremony(&chain, &keys, 0, [0x71; 32], [0x71; 32], 1);
    advance(&mut chain, 3, &bootstrap);
    install(&mut chain, &bootstrap, &keys, &owners[0]);
    advance(&mut chain, EPOCH, &bootstrap);
    let preparation = chain
        .state()
        .view()
        .world()
        .validator_committee_transitions()
        .get(&2)
        .unwrap()
        .preparation
        .clone();
    assert_eq!(preparation.selection_height, EPOCH);
    assert_eq!(
        preparation.selection_anchor,
        chain.committed(EPOCH - 1).block_hash()
    );
    assert_eq!(
        preparation.generation().validators,
        keys.iter()
            .map(|key| PeerId::new(key.public_key().clone()))
            .collect::<Vec<_>>()
    );
    let target = ceremony(
        &chain,
        &keys,
        1,
        preparation.beacon_session_id().unwrap(),
        preparation.transition_id().unwrap(),
        EPOCH + 1,
    );
    advance(&mut chain, EPOCH + 4, &bootstrap);
    install(&mut chain, &target, &keys, &owners[0]);
    let command =
        ValidatorCommitteeOperationV1::PrepareCredentials(PrepareValidatorCommitteeCredentialsV1 {
            transition_id: preparation.transition_id().unwrap(),
            target_epoch: 2,
            credentials: ValidatorCommitteeCredentialsV1 {
                beacon: InstalledBeaconEpochBindingV1 {
                    session_id: target.session.record().session_id,
                    transcript_hash: target.session.record().transcript_hash,
                },
            },
        });
    assert!(
        chain
            .state()
            .view()
            .world()
            .validator_committee_transitions()
            .get(&2)
            .unwrap()
            .credentials
            .is_none()
    );
    (chain, owners[0].clone(), command)
}

fn no_allocation<T>(read: impl FnOnce() -> T) -> T {
    norito::with_decode_limits_scope(
        norito::DecodeLimits::new(usize::MAX, usize::MAX, usize::MAX, 0, 64),
        read,
    )
}

#[test]
fn original_incumbent_history_refusal_keeps_authority_and_same_source_retry() {
    let (chain, _) = original_incumbent();
    let view = chain.state().view();
    let expected = current_authority(&view).unwrap();
    let error: Attempt<String> = no_allocation(|| current_authority(&view)).unwrap_err();
    let Attempt::Deferred(reason) = error else {
        panic!("original incumbent history refusal was erased: {error:?}");
    };
    assert_eq!(
        reason.reason(),
        ivm::error::ExecutionDeferral::ActiveMemoryCapacity
    );
    assert!(reason.allocation_refusal().is_none());
    assert_eq!(current_authority(&view).unwrap(), expected);
    assert_eq!(view.height(), 1);
}

#[test]
fn original_credentials_command_decode_refusal_has_no_publication_and_retries() {
    let (mut chain, owner_key, command) = original_preparation();
    let before = chain
        .state()
        .view()
        .world()
        .validator_committee_transitions()
        .get(&2)
        .unwrap()
        .clone();
    let original_height = chain.height();
    let time = (original_height + 1) * 1_000;
    let owner = AccountId::new(owner_key.public_key().clone());
    let parameter = command.clone().into_custom_parameter();
    let producer =
        no_allocation(|| ValidatorCommitteeOperationV1::from_custom_parameter(&parameter))
            .unwrap_err();
    assert!(
        matches!(
            producer,
            norito::json::Error::DecodeResource(
                norito::core::DecodeResourceError::TotalAllocationExceeded { .. }
            )
        ),
        "{producer:?}"
    );
    let original = parameter.payload().get().to_owned();
    let instruction = SetParameter::new(Parameter::Custom(parameter.clone()));
    let signed = chain.sign(
        &owner_key,
        [InstructionBox::from(instruction.clone())],
        time,
    );
    let proposal = chain.proposal(Some(time), vec![signed.clone()]);
    {
        let mut block = chain.state().block(proposal.header());
        let mut tx = block.transaction();
        let _error = no_allocation(|| instruction.clone().execute(&owner, &mut tx)).unwrap_err();
        let reason = tx
            .execution_deferral()
            .expect("original command decoder refusal must be retained before a wire verdict");
        assert_eq!(
            reason.reason(),
            ivm::error::ExecutionDeferral::ActiveMemoryCapacity
        );
        assert!(reason.allocation_refusal().is_none());
        assert_eq!(
            tx.world.validator_committee_transitions.get(&2),
            Some(&before)
        );
        tx.apply();
        assert_eq!(
            block.world.validator_committee_transitions.get(&2),
            Some(&before)
        );
    }
    assert_eq!(parameter.payload().get(), &original);
    assert_eq!(chain.height(), original_height);
    assert_eq!(chain.commit_at(time, vec![signed]), [true]);
    let mut expected = before;
    let ValidatorCommitteeOperationV1::PrepareCredentials(prepared) = &command else {
        unreachable!()
    };
    expected.credentials = Some(prepared.credentials);
    assert_eq!(
        chain
            .state()
            .view()
            .world()
            .validator_committee_transitions()
            .get(&2),
        Some(&expected)
    );
}

#[test]
fn original_credentials_authority_refusal_keeps_command_and_same_source_retry() {
    let (mut chain, owner_key, command) = original_preparation();
    let before = chain
        .state()
        .view()
        .world()
        .validator_committee_transitions()
        .get(&2)
        .unwrap()
        .clone();
    let original_height = chain.height();
    let time = (original_height + 1) * 1_000;
    let owner = AccountId::new(owner_key.public_key().clone());
    let signed = chain.sign(
        &owner_key,
        [InstructionBox::from(SetParameter::new(Parameter::Custom(
            command.clone().into_custom_parameter(),
        )))],
        time,
    );
    let proposal = chain.proposal(Some(time), vec![signed.clone()]);
    {
        let mut block = chain.state().block(proposal.header());
        let mut tx = block.transaction();
        let error: Attempt<String> =
            no_allocation(|| tx.apply_validator_committee_operation(&owner, command.clone()))
                .unwrap_err();
        let Attempt::Deferred(reason) = error else {
            panic!("original authority refusal became a completed command failure: {error:?}")
        };
        assert_eq!(
            reason.reason(),
            ivm::error::ExecutionDeferral::ActiveMemoryCapacity
        );
        assert!(reason.allocation_refusal().is_none());
        assert_eq!(
            tx.world.validator_committee_transitions.get(&2),
            Some(&before)
        );
        tx.apply_validator_committee_operation(&owner, command.clone())
            .unwrap();
        let mut expected = before.clone();
        let ValidatorCommitteeOperationV1::PrepareCredentials(prepared) = &command else {
            unreachable!()
        };
        expected.credentials = Some(prepared.credentials);
        assert_eq!(
            tx.world.validator_committee_transitions.get(&2),
            Some(&expected)
        );
        // The observational attempt is discarded; the exact signed input is retried below.
    }
    assert_eq!(chain.height(), original_height);
    assert_eq!(chain.commit_at(time, vec![signed]), [true]);
    let mut expected = before;
    let ValidatorCommitteeOperationV1::PrepareCredentials(prepared) = &command else {
        unreachable!()
    };
    expected.credentials = Some(prepared.credentials);
    assert_eq!(
        chain
            .state()
            .view()
            .world()
            .validator_committee_transitions()
            .get(&2),
        Some(&expected)
    );
}

#[test]
fn malformed_committee_command_is_terminal_and_never_installs_credentials() {
    use iroha_data_model::parameter::custom::CustomParameter;
    let (chain, owner_key) = original_incumbent();
    let owner = AccountId::new(owner_key.public_key().clone());
    let malformed = CustomParameter::new(
        ValidatorCommitteeOperationV1::parameter_id(),
        r#"{"kind":"NotACommitteeOperation","value":{}}"#.parse::<iroha_primitives::json::Json>().unwrap(),
    );
    let instruction = SetParameter::new(Parameter::Custom(malformed));
    let signed = chain.sign(
        &owner_key,
        [InstructionBox::from(instruction.clone())],
        2_000,
    );
    let proposal = chain.proposal(Some(2_000), vec![signed]);
    let mut block = chain.state().block(proposal.header());
    let mut tx = block.transaction();
    let error = instruction.execute(&owner, &mut tx).unwrap_err();
    assert!(
        format!("{error:?}").contains("invalid validator committee command"),
        "{error:?}"
    );
    assert!(tx.execution_deferral().is_none());
    assert!(tx.world.validator_committee_transitions.is_empty());
    drop(tx);
    assert!(block.world.validator_committee_transitions.is_empty());
}

#[test]
fn original_beacon_public_state_decode_refusal_defers_before_installation() {
    use crate::beacon::FinalizedGlobalThresholdBeaconKeySessionRecordV1;
    use iroha_crypto::Signature;
    use iroha_data_model::isi::consensus_keys::{
        ApplyThresholdKeyLifecycleCertificateV1, ThresholdKeyLifecycleActionV1,
        ThresholdKeyLifecycleCertificateV1, ThresholdKeyLifecycleSignatureV1,
    };
    let (mut chain, owner_key) = original_incumbent();
    let owner = AccountId::new(owner_key.public_key().clone());
    let mut keys = (0x51..=0x54)
        .map(|seed| KeyPair::from_seed(vec![seed; 32], Algorithm::BlsNormal))
        .collect::<Vec<_>>();
    keys.sort_by_key(|key| PeerId::new(key.public_key().clone()));
    let roster = keys
        .iter()
        .map(|key| PeerId::new(key.public_key().clone()))
        .collect::<Vec<_>>();
    let fixture = crate::beacon::tests::finalized_key_session_fixture_for_context_v1(
        chain.network_id(),
        [0x77; 32],
        &keys,
    );
    let record = fixture;
    while chain.height() + 1 < record.session.adaptive_dkg.finalized_at_height {
        chain.commit(Vec::new());
    }
    let height = chain.height() + 1;
    let time = height * 1_000;
    let public_state = norito::encode_canonical(&record).unwrap();
    let error = no_allocation(|| {
        norito::decode_canonical::<FinalizedGlobalThresholdBeaconKeySessionRecordV1>(&public_state)
    })
    .unwrap_err();
    assert!(
        matches!(
            error,
            norito::Error::TotalAllocationExceeded { limit: 0, .. }
        ),
        "{error:?}"
    );
    let mut certificate = ThresholdKeyLifecycleCertificateV1 {
        version: crate::state::THRESHOLD_KEY_LIFECYCLE_CERTIFICATE_VERSION_V1,
        action: ThresholdKeyLifecycleActionV1::FinalizeGlobalBeaconKey,
        expected_active_session_id: None,
        effective_height: height,
        network_id: chain.network_id(),
        roster_hash: crate::beacon::global_threshold_beacon_roster_hash_v1(&roster),
        committee_size: 4,
        quorum: 3,
        session_id: record.session.session_id,
        transcript_hash: record.session.transcript_hash,
        public_state: public_state.clone(),
        signatures: Vec::new(),
    };
    let preimage =
        crate::state::threshold_key_lifecycle_certificate_preimage_v1(&certificate).unwrap();
    certificate.signatures = keys
        .iter()
        .take(3)
        .enumerate()
        .map(|(i, key)| ThresholdKeyLifecycleSignatureV1 {
            signer_index: u16::try_from(i).unwrap(),
            signature: Signature::try_new(key.private_key(), &preimage).unwrap(),
        })
        .collect();
    crate::state::verify_threshold_key_lifecycle_certificate_v1(
        &certificate,
        &chain.network_id(),
        height,
        &roster,
    )
    .unwrap();
    let instruction = ApplyThresholdKeyLifecycleCertificateV1 { certificate };
    let signed = chain.sign(
        &owner_key,
        [InstructionBox::from(instruction.clone())],
        time,
    );
    let proposal = chain.proposal(Some(time), vec![signed.clone()]);
    {
        let mut block = chain.state().block(proposal.header());
        let mut tx = block.transaction();
        assert_eq!(
            tx.threshold_key_lifecycle_frozen_roster_v1().unwrap(),
            roster
        );
        let _error = no_allocation(|| instruction.clone().execute(&owner, &mut tx)).unwrap_err();
        let reason = tx.execution_deferral().expect(
            "original public-state decoder refusal cannot become a deterministic lifecycle failure",
        );
        assert_eq!(
            reason.reason(),
            ivm::error::ExecutionDeferral::ActiveMemoryCapacity
        );
        assert!(reason.allocation_refusal().is_none());
        assert!(
            tx.world
                .global_beacon_key_sessions
                .get(&record.session.session_id)
                .is_none()
        );
        tx.apply();
        assert!(
            block
                .world
                .global_beacon_key_sessions
                .get(&record.session.session_id)
                .is_none()
        );
    }
    assert_eq!(instruction.certificate.public_state, public_state);
    assert_eq!(chain.commit_at(time, vec![signed]), [true]);
    let view = chain.state().view();
    let installed = view
        .world()
        .global_beacon_key_sessions()
        .get(&record.session.session_id)
        .unwrap();
    assert_eq!(installed.session.record(), &record.session);
    assert_eq!(installed.activated_at_height, Some(height + 1));
}

#[test]
fn original_tle_public_state_decode_refusal_defers_before_installation() {
    use crate::tle_release::TleKeySessionPublicStateV1;
    use iroha_crypto::Signature;
    use iroha_data_model::isi::consensus_keys::{
        ApplyThresholdKeyLifecycleCertificateV1, ThresholdKeyLifecycleActionV1,
        ThresholdKeyLifecycleCertificateV1, ThresholdKeyLifecycleSignatureV1,
    };
    let (mut chain, owner_key) = original_incumbent();
    let owner = AccountId::new(owner_key.public_key().clone());
    let mut keys = (0x51..=0x54)
        .map(|seed| KeyPair::from_seed(vec![seed; 32], Algorithm::BlsNormal))
        .collect::<Vec<_>>();
    keys.sort_by_key(|key| PeerId::new(key.public_key().clone()));
    let roster = keys
        .iter()
        .map(|key| PeerId::new(key.public_key().clone()))
        .collect::<Vec<_>>();
    let record = crate::tle_release::tests::public_key_session_fixture_for_context_v1(
        *chain.network_id().as_bytes(),
        0x77,
        crate::beacon::global_threshold_beacon_roster_hash_v1(&roster),
    );
    let height = chain.height() + 1;
    let time = height * 1_000;
    let public_state = norito::encode_canonical(&record).unwrap();
    let error =
        no_allocation(|| norito::decode_canonical::<TleKeySessionPublicStateV1>(&public_state))
            .unwrap_err();
    assert!(
        matches!(
            error,
            norito::Error::TotalAllocationExceeded { limit: 0, .. }
        ),
        "{error:?}"
    );
    let mut certificate = ThresholdKeyLifecycleCertificateV1 {
        version: crate::state::THRESHOLD_KEY_LIFECYCLE_CERTIFICATE_VERSION_V1,
        action: ThresholdKeyLifecycleActionV1::InstallParliamentTleKey,
        expected_active_session_id: None,
        effective_height: height,
        network_id: chain.network_id(),
        roster_hash: crate::beacon::global_threshold_beacon_roster_hash_v1(&roster),
        committee_size: 4,
        quorum: 3,
        session_id: *record.key_session_id.as_bytes(),
        transcript_hash: record.transcript_hash,
        public_state: public_state.clone(),
        signatures: Vec::new(),
    };
    let preimage =
        crate::state::threshold_key_lifecycle_certificate_preimage_v1(&certificate).unwrap();
    certificate.signatures = keys
        .iter()
        .take(3)
        .enumerate()
        .map(|(i, key)| ThresholdKeyLifecycleSignatureV1 {
            signer_index: u16::try_from(i).unwrap(),
            signature: Signature::try_new(key.private_key(), &preimage).unwrap(),
        })
        .collect();
    crate::state::verify_threshold_key_lifecycle_certificate_v1(
        &certificate,
        &chain.network_id(),
        height,
        &roster,
    )
    .unwrap();
    let instruction = ApplyThresholdKeyLifecycleCertificateV1 { certificate };
    let signed = chain.sign(
        &owner_key,
        [InstructionBox::from(instruction.clone())],
        time,
    );
    let proposal = chain.proposal(Some(time), vec![signed.clone()]);
    {
        let mut malformed = instruction.clone();
        malformed.certificate.public_state.push(0);
        let preimage =
            crate::state::threshold_key_lifecycle_certificate_preimage_v1(&malformed.certificate)
                .unwrap();
        malformed.certificate.signatures = keys
            .iter()
            .take(3)
            .enumerate()
            .map(|(i, key)| ThresholdKeyLifecycleSignatureV1 {
                signer_index: u16::try_from(i).unwrap(),
                signature: Signature::try_new(key.private_key(), &preimage).unwrap(),
            })
            .collect();
        crate::state::verify_threshold_key_lifecycle_certificate_v1(
            &malformed.certificate,
            &chain.network_id(),
            height,
            &roster,
        )
        .unwrap();
        let mut block = chain.state().block(proposal.header());
        let mut tx = block.transaction();
        let error = malformed.execute(&owner, &mut tx).unwrap_err();
        assert!(
            format!("{error:?}").contains("Parliament TLE public key session is not canonical"),
            "{error:?}"
        );
        assert!(tx.execution_deferral().is_none());
        assert!(
            tx.world
                .tle_key_sessions
                .get(&record.key_session_id)
                .is_none()
        );
    }
    {
        let mut block = chain.state().block(proposal.header());
        let mut tx = block.transaction();
        assert_eq!(
            tx.threshold_key_lifecycle_frozen_roster_v1().unwrap(),
            roster
        );
        let _error = no_allocation(|| instruction.clone().execute(&owner, &mut tx)).unwrap_err();
        let reason = tx.execution_deferral().expect(
            "original public-state decoder refusal cannot become a deterministic lifecycle failure",
        );
        assert_eq!(
            reason.reason(),
            ivm::error::ExecutionDeferral::ActiveMemoryCapacity
        );
        assert!(reason.allocation_refusal().is_none());
        assert!(
            tx.world
                .tle_key_sessions
                .get(&record.key_session_id)
                .is_none()
        );
        tx.apply();
        assert!(
            block
                .world
                .tle_key_sessions
                .get(&record.key_session_id)
                .is_none()
        );
    }
    assert_eq!(instruction.certificate.public_state, public_state);
    assert_eq!(chain.commit_at(time, vec![signed]), [true]);
    let view = chain.state().view();
    let installed = view
        .world()
        .tle_key_sessions()
        .get(&record.key_session_id)
        .unwrap();
    assert_eq!(installed, &record);
    assert_eq!(
        view.world().active_tle_key_session(),
        Some(record.key_session_id)
    );
}

#[test]
fn original_staking_authority_refusal_keeps_exit_overlay_and_same_signed_retry() {
    use iroha_data_model::isi::ExitPublicLaneValidator;
    use iroha_model_base::topology::LaneId;
    let (mut chain, owner_key) = original_incumbent();
    let owner = AccountId::new(owner_key.public_key().clone());
    let key = (LaneId::SINGLE, owner.clone());
    let original = chain
        .state()
        .view()
        .world()
        .public_lane_validators()
        .get(&key)
        .unwrap()
        .clone();
    let expected_exit = {
        let view = chain.state().view();
        let (_, incumbent) = current_authority(&view).unwrap();
        assert!(2 < incumbent.last_height);
        let length = view
            .world()
            .sumeragi_npos_parameters()
            .expect("original policy decoder completes")
            .unwrap()
            .epoch_length_blocks()
            .get();
        incumbent
            .last_height
            .checked_add(length)
            .unwrap()
            .checked_add(1)
            .unwrap()
    };
    assert!(original.deactivation_height.is_none());
    let instruction = ExitPublicLaneValidator {
        lane_id: LaneId::SINGLE,
        validator: owner.clone(),
        release_at_ms: 2_001,
    };
    let signed = chain.sign(
        &owner_key,
        [InstructionBox::from(instruction.clone())],
        2_000,
    );
    let proposal = chain.proposal(Some(2_000), vec![signed.clone()]);
    assert_eq!(proposal.header().creation_time().as_millis(), 2_001);
    let limits = norito::DecodeLimits::new(2_048, usize::MAX, usize::MAX, usize::MAX, 64);
    {
        let mut block = chain.state().block(proposal.header());
        let overlay_before = block
            .world
            .public_lane_validators
            .get(&key)
            .unwrap()
            .clone();
        let mut tx = block.transaction();
        let error = norito::with_decode_limits_scope(limits, || {
            assert!(
                tx.world
                    .sumeragi_npos_parameters()
                    .expect("original policy decoder completes")
                    .is_some(),
                "preceding signed policy must remain readable at this genuine history boundary"
            );
            let authority = current_authority(&tx).unwrap_err();
            assert!(matches!(authority, Attempt::Deferred(_)), "{authority:?}");
            instruction.clone().execute(&owner, &mut tx)
        })
        .unwrap_err();
        assert!(
            tx.execution_deferral().is_some(),
            "original authority owner was dropped by staking scheduling: {error:?}"
        );
        assert_eq!(
            tx.world.public_lane_validators.get(&key),
            Some(&overlay_before)
        );
        tx.apply();
        assert_eq!(
            block.world.public_lane_validators.get(&key),
            Some(&overlay_before)
        );
    }
    assert_eq!(chain.height(), 1);
    assert_eq!(
        chain
            .state()
            .view()
            .world()
            .public_lane_validators()
            .get(&key),
        Some(&original)
    );
    assert_eq!(chain.commit_at(2_000, vec![signed]), [true]);
    let view = chain.state().view();
    let current = view.world().public_lane_validators().get(&key).unwrap();
    assert_eq!(
        current.status,
        iroha_data_model::nexus::PublicLaneValidatorStatus::Exiting(2_001)
    );
    assert_eq!(current.election_exit_height, Some(expected_exit));
    // The exit request cannot release the original Global voting/slashing tenure.
    // Only a certified boundary may close that separate obligation.
    assert_eq!(current.deactivation_height, original.deactivation_height);
    assert_eq!(current.self_stake, original.self_stake);
}

#[test]
fn original_npos_parameter_refusal_does_not_become_missing_staking_policy() {
    use iroha_data_model::{
        nexus::{
            PublicLanePreparationOperationV1, PublicLanePreparationRequestV1,
            PublicLanePrepareClaimV1,
        },
        parameter::system::SumeragiNposParameters,
    };
    let (chain, owner_key) = original_incumbent();
    let view = chain.state().view();
    let owner = AccountId::new(owner_key.public_key().clone());
    let request = PublicLanePreparationRequestV1 {
        lane_id: iroha_model_base::topology::LaneId::SINGLE,
        valid_for_blocks: 1,
        operation: PublicLanePreparationOperationV1::ClaimRewards(PublicLanePrepareClaimV1 {
            recipient: owner,
        }),
    };
    let custom = view
        .world()
        .parameters()
        .custom()
        .get(&SumeragiNposParameters::parameter_id())
        .unwrap();
    let original_bytes = custom.payload().get().to_owned();
    let expected = crate::smartcontracts::isi::staking::preparation::prepare_public_lane_plan(
        &view,
        request.clone(),
    )
    .unwrap_err();
    assert!(matches!(expected, Attempt::Rejected(_)), "{expected:?}");
    let producer =
        no_allocation(|| norito::json::from_str::<SumeragiNposParameters>(&original_bytes))
            .unwrap_err();
    assert!(
        matches!(
            producer,
            norito::json::Error::DecodeResource(
                norito::core::DecodeResourceError::TotalAllocationExceeded { .. }
            )
        ),
        "{producer:?}"
    );
    let error = no_allocation(|| {
        crate::smartcontracts::isi::staking::preparation::prepare_public_lane_plan(
            &view,
            request.clone(),
        )
    })
    .unwrap_err();
    assert!(
        matches!(error, Attempt::Deferred(_)),
        "the original signed NPoS read refusal was flattened: {error:?}"
    );
    assert_eq!(custom.payload().get(), &original_bytes);
    let retry =
        crate::smartcontracts::isi::staking::preparation::prepare_public_lane_plan(&view, request)
            .unwrap_err();
    assert_eq!(retry, expected);
}

#[test]
fn original_npos_exit_policy_refusal_keeps_stake_and_same_signed_retry() {
    use iroha_data_model::{
        isi::ExitPublicLaneValidator, parameter::system::SumeragiNposParameters,
    };
    use iroha_model_base::topology::LaneId;
    let (mut chain, owner_key) = original_incumbent();
    let owner = AccountId::new(owner_key.public_key().clone());
    let key = (LaneId::SINGLE, owner.clone());
    let instruction = ExitPublicLaneValidator {
        lane_id: LaneId::SINGLE,
        validator: owner.clone(),
        release_at_ms: 2_001,
    };
    let signed = chain.sign(
        &owner_key,
        [InstructionBox::from(instruction.clone())],
        2_000,
    );
    let proposal = chain.proposal(Some(2_000), vec![signed.clone()]);
    let original = chain
        .state()
        .view()
        .world()
        .public_lane_validators()
        .get(&key)
        .unwrap()
        .clone();
    let parameter = chain
        .state()
        .view()
        .world()
        .parameters()
        .custom()
        .get(&SumeragiNposParameters::parameter_id())
        .unwrap()
        .clone();
    let producer =
        no_allocation(|| SumeragiNposParameters::from_custom_parameter(&parameter)).unwrap_err();
    assert!(
        matches!(
            producer,
            norito::json::Error::DecodeResource(
                norito::core::DecodeResourceError::TotalAllocationExceeded { .. }
            )
        ),
        "{producer:?}"
    );
    {
        let mut block = chain.state().block(proposal.header());
        // Block-start activation is separate from this refused transaction.
        let overlay_before = block
            .world
            .public_lane_validators
            .get(&key)
            .unwrap()
            .clone();
        let mut tx = block.transaction();
        let error = no_allocation(|| instruction.clone().execute(&owner, &mut tx)).unwrap_err();
        let refusal = tx
            .execution_deferral()
            .unwrap_or_else(|| panic!("policy refusal became a wire rejection: {error:?}"));
        assert_eq!(
            refusal.reason(),
            ivm::error::ExecutionDeferral::ActiveMemoryCapacity
        );
        assert!(refusal.allocation_refusal().is_none());
        assert_eq!(
            tx.world.public_lane_validators.get(&key),
            Some(&overlay_before)
        );
        assert_eq!(
            tx.world
                .parameters
                .get()
                .custom()
                .get(&SumeragiNposParameters::parameter_id()),
            Some(&parameter)
        );
        assert_eq!(tx.last_tx_gas_used, 0);
        tx.apply();
        assert_eq!(
            block.world.public_lane_validators.get(&key),
            Some(&overlay_before)
        );
    }
    assert_eq!(chain.height(), 1);
    assert_eq!(
        chain
            .state()
            .view()
            .world()
            .public_lane_validators()
            .get(&key),
        Some(&original)
    );
    assert_eq!(chain.commit_at(2_000, vec![signed]), [true]);
    let view = chain.state().view();
    let after = view.world().public_lane_validators().get(&key).unwrap();
    assert_eq!(after.total_stake, original.total_stake);
    assert_eq!(after.self_stake, original.self_stake);
    assert_eq!(
        after.status,
        iroha_data_model::nexus::PublicLaneValidatorStatus::Exiting(2_001)
    );
}

#[test]
fn original_npos_reserve_validation_refuses_without_changing_current_or_undo() {
    let (mut chain, _) = original_incumbent();
    chain.commit(Vec::new());
    let state = chain.state();
    let before = norito::json::to_json(&state.world).unwrap();
    fn assert_custody(world: &impl WorldReadOnly) {
        // Both validators read the original signed policy before deriving the reserve ledger.
        // Their monomorphic API is exercised below at each exact Cell generation.
        assert!(world.sumeragi_npos_parameters().unwrap().is_some());
    }
    let current = state.world.view();
    assert_custody(&current);
    crate::state::validate_public_lane_stake_reserves(&current).unwrap();
    for error in [
        no_allocation(|| crate::state::validate_public_lane_stake_reserves(&current)).unwrap_err(),
    ] {
        assert!(matches!(error, Attempt::Deferred(_)), "{error:?}");
    }
    drop(current);
    {
        let previous = state.world.block_and_revert();
        assert_custody(&previous);
        crate::state::validate_public_lane_stake_reserves(&previous).unwrap();
        for error in
            [
                no_allocation(|| crate::state::validate_public_lane_stake_reserves(&previous))
                    .unwrap_err(),
            ]
        {
            assert!(matches!(error, Attempt::Deferred(_)), "{error:?}");
        }
        crate::state::validate_public_lane_stake_reserves(&previous).unwrap();
    }
    assert_eq!(norito::json::to_json(&state.world).unwrap(), before);
    let current = state.world.view();
    crate::state::validate_public_lane_stake_reserves(&current).unwrap();
}

#[cfg(feature = "telemetry")]
#[test]
fn late_original_npos_activation_read_refusal_rolls_back_and_same_signed_retry() {
    use iroha_data_model::{
        isi::ActivatePublicLaneValidator, parameter::system::SumeragiNposParameters,
    };
    use iroha_model_base::topology::LaneId;
    let (mut chain, owner_key) = original_incumbent();
    let owner = AccountId::new(owner_key.public_key().clone());
    let key = (LaneId::SINGLE, owner.clone());
    let original = chain
        .state()
        .view()
        .world()
        .public_lane_validators()
        .get(&key)
        .unwrap()
        .clone();
    let instruction = ActivatePublicLaneValidator {
        lane_id: LaneId::SINGLE,
        validator: owner.clone(),
    };
    let signed = chain.sign(
        &owner_key,
        [InstructionBox::from(instruction.clone())],
        2_000,
    );
    let proposal = chain.proposal(Some(2_000), vec![signed.clone()]);
    let parameter = chain
        .state()
        .view()
        .world()
        .parameters()
        .custom()
        .get(&SumeragiNposParameters::parameter_id())
        .unwrap()
        .clone();
    let original_bytes = parameter.payload().get().to_owned();
    let ceiling = 8 * 1024 * 1024;
    let limits =
        |allocation| norito::DecodeLimits::new(usize::MAX, usize::MAX, usize::MAX, allocation, 64);
    let used = || {
        let norito::Error::TotalAllocationExceeded { attempted, limit } =
            norito::core::reserve_decode_allocation(ceiling + 1).unwrap_err()
        else {
            panic!("non-charging original allocation probe");
        };
        assert_eq!(limit, u64::try_from(ceiling).unwrap());
        usize::try_from(attempted).unwrap() - ceiling - 1
    };
    let policy_bytes = norito::with_decode_limits_scope(limits(ceiling), || {
        assert!(
            SumeragiNposParameters::from_custom_parameter(&parameter)
                .unwrap()
                .is_some()
        );
        used()
    });
    let full_bytes = {
        let mut block = chain.state().block(proposal.header());
        let mut tx = block.transaction();
        norito::with_decode_limits_scope(limits(ceiling), || {
            instruction.clone().execute(&owner, &mut tx).unwrap();
            used()
        })
    };
    assert!(policy_bytes > 0);
    assert!(
        full_bytes >= 2 * policy_bytes,
        "activation makes earlier original policy reads"
    );
    let earlier_bytes = full_bytes - policy_bytes;
    // The same original policy fits independently; this scope refuses only after
    // the completed activation-prefix reads have consumed its cumulative budget.
    norito::with_decode_limits_scope(limits(earlier_bytes), || {
        assert!(
            SumeragiNposParameters::from_custom_parameter(&parameter)
                .unwrap()
                .is_some()
        );
    });
    {
        let mut block = chain.state().block(proposal.header());
        let before = block
            .world
            .public_lane_validators
            .get(&key)
            .unwrap()
            .clone();
        let mut tx = block.transaction();
        let error = norito::with_decode_limits_scope(limits(earlier_bytes), || {
            instruction.clone().execute(&owner, &mut tx)
        })
        .unwrap_err();
        let refusal = tx
            .execution_deferral()
            .unwrap_or_else(|| panic!("late policy refusal lost: {error:?}"));
        assert_eq!(
            refusal.reason(),
            ivm::error::ExecutionDeferral::ActiveMemoryCapacity
        );
        assert!(refusal.allocation_refusal().is_none());
        assert_eq!(tx.world.public_lane_validators.get(&key), Some(&before));
        assert_eq!(tx.last_tx_gas_used, 0);
        tx.apply();
        assert_eq!(block.world.public_lane_validators.get(&key), Some(&before));
    }
    assert_eq!(chain.height(), 1);
    assert_eq!(
        chain
            .state()
            .view()
            .world()
            .public_lane_validators()
            .get(&key),
        Some(&original)
    );
    assert_eq!(parameter.payload().get(), &original_bytes);
    assert_eq!(chain.commit_at(2_000, vec![signed]), [true]);
    assert_eq!(
        chain
            .state()
            .view()
            .world()
            .public_lane_validators()
            .get(&key)
            .unwrap()
            .status,
        iroha_data_model::nexus::PublicLaneValidatorStatus::Active
    );
}
