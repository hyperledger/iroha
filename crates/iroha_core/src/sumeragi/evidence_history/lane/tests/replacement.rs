//! Deterministic real detector-to-custody qualification through certified replacement and exit.
//!
//! This is a native component test. It injects signed conflicting votes only into the sans-IO
//! Kernel and never exposes a real-node fault switch or an evidence submission endpoint.

use super::*;
use std::collections::BTreeMap;

use crate::{
    beacon::{
        FinalizedGlobalThresholdBeaconKeySessionRecordV1, GlobalThresholdBeaconPartialSignerV1,
        GlobalThresholdBeaconPulseAggregatorV1, InMemoryGlobalThresholdBeaconPartialSignerV1,
        ValidatedGlobalThresholdBeaconSessionV1, prepared_session_and_signers_fixture_for_keys_v1,
        prove_global_threshold_beacon_seat_readiness_v1,
    },
    smartcontracts::isi::staking::preparation::prepare_public_lane_plan,
    sumeragi::test_chain::{Signers, TestChainConfig},
};
use iroha_crypto::{Hash, SignatureOf};
use iroha_data_model::sumeragi::epoch::{InstalledBeaconEpochBindingV1, ValidatorEpochDecisionV1};
use iroha_data_model::{
    account::{Account, AccountId},
    asset::AssetId,
    block::consensus::{EvidencePenaltyStatus, EvidenceScope, NexusFeeSettlementV1},
    consensus::{
        GlobalThresholdBeaconChainAnchorV1, GlobalThresholdBeaconDkgSessionV1,
        GlobalThresholdBeaconPulseContextV1, NposPenaltyAction,
    },
    isi::{
        FinalizePublicLaneUnbond, Grant, InstructionBox, Log, Mint,
        PublicLaneCandidateAuthorization, Register, RegisterPublicLaneCandidate,
        RegisterPublicLaneValidator, SetParameter,
        consensus_keys::{
            ApplyThresholdKeyLifecycleCertificateV1, ThresholdKeyLifecycleActionV1,
            ThresholdKeyLifecycleCertificateV1, ThresholdKeyLifecycleSignatureV1,
        },
    },
    nexus::{
        AdmitValidatorCommitteeSeatV1, FeeDebitSource, PrepareValidatorCommitteeCredentialsV1,
        PublicLaneMonetaryPlanV1, PublicLaneMonetaryPreconditionV1,
        PublicLaneMonetaryRegistrationV1, PublicLaneMonetaryScopeV1,
        PublicLanePreparationOperationV1, PublicLanePreparationRequestV1,
        PublicLanePrepareUnbondV1, PublicLanePreparedPlanV1, ValidatorCommitteeCredentialsV1,
        ValidatorCommitteeOperationV1, ValidatorCommitteeSeatReadinessV1,
    },
    parameter::{
        Parameter,
        system::{SumeragiNposParameters, SumeragiParameter},
    },
    sumeragi_lanes::SumeragiLanePolicy,
    transaction::{FeeChargeKind, FeePaymentIntent, SignedTransaction, TransactionBuilder},
};
use iroha_model_base::peer::PeerId;
use iroha_primitives::numeric::Quantity;

const EPOCH: u64 = 64;
const TARGET_FIRST: u64 = 2 * EPOCH + 1;

pub(super) fn policy() -> SumeragiNposParameters {
    SumeragiNposParameters {
        epoch_length_blocks: std::num::NonZeroU64::new(EPOCH).unwrap(),
        max_validators: 4,
        evidence_horizon_blocks: 128,
        slashing_delay_blocks: 2,
        ..SumeragiNposParameters::default()
    }
}

fn replacement_keys() -> Vec<KeyPair> {
    let mut keys = super::keys()
        .into_iter()
        .enumerate()
        .filter_map(|(index, key)| (index != 2).then_some(key))
        .collect::<Vec<_>>();
    keys.push(KeyPair::from_seed(vec![0xED; 32], Algorithm::BlsNormal));
    keys.sort_by_key(|key| PeerId::new(key.public_key().clone()));
    keys
}

fn operator(index: usize) -> KeyPair {
    KeyPair::from_seed(
        vec![0x70 + u8::try_from(index).unwrap(); 32],
        Algorithm::Ed25519,
    )
}

fn administrator() -> KeyPair {
    KeyPair::from_seed(vec![0xCE; 32], Algorithm::Ed25519)
}

pub(super) fn fund_signed_genesis(config: &mut TestChainConfig) {
    super::fund_original_validator_in_signed_genesis(config);
    assert_eq!(
        config.genesis_key.public_key(),
        administrator().public_key()
    );
    config
        .genesis_parameters
        .push(Parameter::Sumeragi(SumeragiParameter::EpochLengthBlocks(
            std::num::NonZeroU64::new(EPOCH).unwrap(),
        )));
    // The signed genesis grants the administrator exactly the permission needed
    // by its later committed lane/committee policy updates.
    config.genesis_instructions.push(
        Grant::account_permission(
            iroha_executor_data_model::permission::parameter::CanSetParameters,
            AccountId::new(administrator().public_key().clone()),
        )
        .into(),
    );
    let xor = policy().xor_asset_definition_id;
    for index in 0..4 {
        let account = AccountId::new(operator(index).public_key().clone());
        config.genesis_instructions.extend([
            Register::account(Account::new(account.clone())).into(),
            Mint::asset_quantity(20_000_u64, AssetId::new(xor.clone(), account)).into(),
        ]);
    }
    // Explicit signed-genesis funding pays every successful progress/control operation.
    // All original offender principal and its separate liquid balance stay unchanged.
    config.genesis_instructions.push(
        Mint::asset_quantity(
            1_000_000_u64,
            AssetId::new(xor, AccountId::new(administrator().public_key().clone())),
        )
        .into(),
    );
}

#[test]
fn real_detector_penalty_survives_certified_replacement_and_complete_xor_withdrawal() {
    crate::sumeragi::threads::sumeragi_thread_builder("slashed-replacement-withdrawal")
        .spawn(|| super::funded_original_lane_slashing_scenario(true))
        .unwrap()
        .join()
        .unwrap();
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct Money {
    balances: BTreeMap<AssetId, Quantity>,
    stake: BTreeMap<AssetId, Quantity>,
    rewards: BTreeMap<AssetId, Quantity>,
    supply: Quantity,
}

fn money(chain: &CertifiedTestChain) -> Money {
    let view = chain.state().view();
    let world = view.world();
    let xor = policy().xor_asset_definition_id;
    Money {
        balances: world
            .assets()
            .iter()
            .filter(|(id, value)| id.definition() == &xor && !value.as_ref().is_zero())
            .map(|(id, value)| (id.clone(), value.as_ref().clone()))
            .collect(),
        stake: world
            .public_lane_stake_reserves()
            .iter()
            .filter(|(id, _)| id.definition() == &xor)
            .map(|(id, value)| (id.clone(), value.clone()))
            .collect(),
        rewards: world
            .assets()
            .iter()
            .filter(|(id, _)| id.definition() == &xor)
            .filter_map(|(id, _)| {
                let reserved =
                    crate::validation_fee_rewards::reserved_fee_custody(world, id).unwrap();
                (!reserved.is_zero()).then(|| (id.clone(), reserved))
            })
            .collect(),
        supply: world
            .asset_definition(&xor)
            .unwrap()
            .total_quantity()
            .clone(),
    }
}

fn add(values: &mut BTreeMap<AssetId, Quantity>, asset: &AssetId, amount: &Quantity) {
    let value = values.get(asset).cloned().unwrap_or_else(Quantity::zero);
    values.insert(asset.clone(), value.checked_add(amount).unwrap());
}

fn subtract(values: &mut BTreeMap<AssetId, Quantity>, asset: &AssetId, amount: &Quantity) {
    let value = values.get(asset).unwrap().checked_sub(amount).unwrap();
    if value.is_zero() {
        values.remove(asset);
    } else {
        values.insert(asset.clone(), value);
    }
}

fn paid(
    chain: &CertifiedTestChain,
    payer: &KeyPair,
    instruction: InstructionBox,
) -> SignedTransaction {
    let at = chain.committed(chain.height()).block_time_ms();
    let account = AccountId::new(payer.public_key().clone());
    let mut builder = TransactionBuilder::new(
        chain.network_id(),
        account.clone(),
        FeePaymentIntent::authority(Vec::new(), None),
    )
    .with_instructions([instruction]);
    builder.set_creation_time(Duration::from_millis(at));
    let draft = builder.clone().sign(payer.private_key());
    let view = chain.state().view();
    let quote = crate::executor::quote_nexus_fee_admission_draft(
        view.world(),
        view.nexus(),
        view.pipeline(),
        &view.zk().gas,
        draft.payload(),
        at,
        crate::smartcontracts::isi::sccp::hold::committed_time_ms(&view)
            .expect("original committed fixture time"),
        chain.height() + 1,
        Some(iroha_model_base::topology::DataSpaceId::UNIVERSAL),
    )
    .expect("real liquid XOR funds the exact signed fee quote");
    assert_eq!(
        quote.quote.debit_source,
        FeeDebitSource::Account(account.clone())
    );
    assert_eq!(
        quote
            .quote
            .authority_charge_assets
            .get(&FeeChargeKind::Nexus),
        Some(&AssetId::new(policy().xor_asset_definition_id, account))
    );
    builder
        .with_fee_payment_intent(quote.recommended_intent)
        .sign(payer.private_key())
}

/// Assert all real XOR balances, both reserve families and supply across one actual transaction.
fn commit_checked(
    chain: &mut CertifiedTestChain,
    signed: SignedTransaction,
    rejected: Option<&str>,
    principal: Option<(&PublicLaneMonetaryPlanV1, bool)>,
    control: ControlWitness,
) {
    let mut expected = money(chain);
    let results = chain.commit_with_control(None, vec![signed.clone()], Signers::Quorum, control);
    assert_eq!(
        results,
        [rejected.is_none()],
        "{:?}",
        chain.committed(chain.height()).block().network_output_at(0)
    );
    let committed = chain.committed(chain.height());
    let output = &committed.block().network_output_at(0).unwrap().1.result;
    if let Some(reason) = rejected {
        assert!(format!("{:?}", output.as_ref().unwrap_err()).contains(reason));
        assert!(
            principal.is_none(),
            "rejected business work cannot release principal"
        );
    }
    let receipt = output
        .nexus_fee_receipt()
        .expect("executed funded work has its real fee receipt");
    let authority = signed.authority();
    let fee_asset = AssetId::new(policy().xor_asset_definition_id, authority.clone());
    assert_eq!(
        receipt.source_id,
        *Hash::from(signed.hash_as_entrypoint()).as_ref()
    );
    assert_eq!(receipt.block_height, chain.height());
    assert_eq!(receipt.fee_asset_id, *fee_asset.definition());
    assert_eq!(
        receipt.debit_source,
        FeeDebitSource::Account(authority.clone())
    );
    assert_eq!(receipt.settlement, NexusFeeSettlementV1::Burn);
    assert!(!receipt.fee_amount.is_zero());
    let view = chain.state().view();
    let bytes = norito::canonical_frame_len(signed.payload()).unwrap();
    assert_eq!(receipt.schedule.tx_bytes_len, bytes as u64);
    assert_eq!(receipt.schedule.instruction_count, 1);
    assert_eq!(
        receipt.fee_amount,
        crate::executor::compute_nexus_fee_amount(
            &view.nexus().fees,
            bytes,
            1,
            receipt.schedule.gas_used
        )
        .unwrap()
    );
    let bound = signed
        .fee_payment_intent()
        .charge_limits()
        .iter()
        .find(|limit| limit.kind == FeeChargeKind::Nexus)
        .unwrap();
    assert_eq!(bound.asset_definition_id, *fee_asset.definition());
    assert!(receipt.fee_amount <= bound.max_amount);
    drop(view);
    // Charge the already liquid account before applying any returned principal.
    subtract(&mut expected.balances, &fee_asset, &receipt.fee_amount);
    expected.supply = expected.supply.checked_sub(&receipt.fee_amount).unwrap();
    if let Some((plan, enters_custody)) = principal {
        subtract(&mut expected.balances, &plan.source_asset, &plan.amount);
        add(
            &mut expected.balances,
            &plan.destination_asset,
            &plan.amount,
        );
        if enters_custody {
            add(&mut expected.stake, &plan.destination_asset, &plan.amount);
        } else {
            subtract(&mut expected.stake, &plan.source_asset, &plan.amount);
        }
    }
    assert_eq!(
        money(chain),
        expected,
        "only the signed principal and actual finalized fee may move"
    );
    assert_eq!(
        chain
            .committed_body(chain.height())
            .unwrap()
            .unwrap()
            .1
            .signers
            .count_ones(),
        3
    );
}

struct Beacon {
    session: ValidatedGlobalThresholdBeaconSessionV1,
    signers: Vec<InMemoryGlobalThresholdBeaconPartialSignerV1>,
}

fn make_beacon(
    chain: &CertifiedTestChain,
    keys: &[KeyPair],
    generation: u64,
    session_id: [u8; 32],
    attempt_id: [u8; 32],
    start: u64,
) -> Beacon {
    let peers = keys
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
            roster_hash: crate::beacon::global_threshold_beacon_roster_hash_v1(&peers),
            committee_size: 4,
            threshold: 2,
            start_height: start,
            commitments_end_height: start + 1,
            deliveries_end_height: start + 2,
            acceptances_end_height: start + 3,
        },
        keys,
        &chain.execution_budget(),
    );
    assert!(session.belongs_to(&chain.execution_budget()));
    Beacon { session, signers }
}

fn install_beacon(chain: &mut CertifiedTestChain, beacon: &Beacon, keys: &[KeyPair]) {
    let view = chain.state().view();
    let context = &view
        .world()
        .consensus_schedule()
        .ready(chain.height() + 1)
        .unwrap()
        .epoch;
    let roster = context
        .committee
        .iter()
        .map(|seat| seat.validator.clone())
        .collect::<Vec<_>>();
    assert_eq!(
        roster,
        keys.iter()
            .map(|key| PeerId::new(key.public_key().clone()))
            .collect::<Vec<_>>()
    );
    let expected_active_session_id = view.world().active_global_beacon_key_session();
    drop(view);
    let record = FinalizedGlobalThresholdBeaconKeySessionRecordV1::new(
        beacon.session.record().clone(),
        &chain.execution_budget(),
    )
    .unwrap();
    let committee_size = u16::try_from(roster.len()).unwrap();
    assert_eq!(committee_size, 4);
    let quorum = committee_size - (committee_size - 1) / 3;
    let mut certificate = ThresholdKeyLifecycleCertificateV1 {
        version: crate::state::THRESHOLD_KEY_LIFECYCLE_CERTIFICATE_VERSION_V1,
        action: ThresholdKeyLifecycleActionV1::FinalizeGlobalBeaconKey,
        expected_active_session_id,
        effective_height: chain.height() + 1,
        network_id: chain.network_id(),
        roster_hash: crate::beacon::global_threshold_beacon_roster_hash_v1(&roster),
        committee_size,
        quorum,
        session_id: record.session.session_id,
        transcript_hash: record.session.transcript_hash,
        public_state: norito::encode_canonical(&record).unwrap(),
        signatures: Vec::new(),
    };
    let bytes =
        crate::state::threshold_key_lifecycle_certificate_preimage_v1(&certificate).unwrap();
    certificate.signatures = keys
        .iter()
        .take(usize::from(quorum))
        .enumerate()
        .map(|(index, key)| ThresholdKeyLifecycleSignatureV1 {
            signer_index: index as u16,
            signature: iroha_crypto::Signature::try_new(key.private_key(), &bytes).unwrap(),
        })
        .collect();
    let signed = paid(
        chain,
        &administrator(),
        ApplyThresholdKeyLifecycleCertificateV1 { certificate }.into(),
    );
    commit_checked(chain, signed, None, None, ControlWitness::empty());
}

fn advance(chain: &mut CertifiedTestChain, target: u64, beacon: &Beacon) {
    while chain.height() < target {
        let height = chain.height() + 1;
        let view = chain.state().view();
        let current = view
            .world()
            .consensus_schedule()
            .ready(height)
            .unwrap()
            .epoch
            .clone();
        let boundary_pulse = height + 1 == current.authorization.last_height;
        drop(view);
        let control = if boundary_pulse {
            let parent = chain.committed(chain.height());
            let epoch = crate::sumeragi::schedule::core_epoch(&current).unwrap().id;
            let mut aggregate = GlobalThresholdBeaconPulseAggregatorV1::new(
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
                aggregate
                    .accept_partial(
                        signer
                            .sign_partial(aggregate.session(), aggregate.payload())
                            .unwrap(),
                    )
                    .unwrap();
            }
            crate::sumeragi::epoch_beacon::control::encode(Some(aggregate.finalize().unwrap()))
                .unwrap()
        } else {
            ControlWitness::empty()
        };
        let signed = paid(
            chain,
            &administrator(),
            Log::new(
                iroha_logger::Level::INFO,
                format!("funded exact replacement progress {height}"),
            )
            .into(),
        );
        commit_checked(chain, signed, None, None, control);
    }
}

pub(super) fn finish_after_real_detector_penalty(
    chain: &mut CertifiedTestChain,
    replay: &mut CertifiedTestChain,
    offender: &KeyPair,
    request_id: Hash,
    release_at_ms: u64,
    evidence_key: &Hash,
    expected_evidence: &crate::state::RetainedEvidenceRecord,
) {
    let validator = AccountId::new(offender.public_key().clone());
    let stake_key = (LaneId::SINGLE, validator.clone());
    let share_key = (LaneId::SINGLE, validator.clone(), validator.clone());
    let EvidencePenaltyStatus::Applied {
        height: applied_height,
    } = expected_evidence.penalty_status
    else {
        panic!("the original detector report already produced its delayed finalized penalty")
    };
    let applied = chain.committed(applied_height);
    let applied_identity = (applied.block_hash(), applied.core_hash(), applied.result());
    let applied_effects = applied.block().npos_consensus_effects().unwrap().clone();
    assert!(
        applied_effects
            .penalty_actions
            .iter()
            .any(|action| matches!(action,
                NposPenaltyAction::ConsensusSlash(slash)
                if &slash.evidence_key == evidence_key && slash.validator == validator
                    && slash.amount == Quantity::from(1_000_u64)
            ))
    );
    assert!(
        applied_effects
            .penalty_actions
            .iter()
            .any(|action| matches!(action,
                NposPenaltyAction::MarkConsensusEvidenceApplied(marker)
                if &marker.evidence_key == evidence_key && marker.height == applied_height
            ))
    );
    drop(applied);
    let old_keys = super::keys();
    let target_keys = replacement_keys();
    let new_key = target_keys
        .iter()
        .find(|key| {
            !old_keys
                .iter()
                .any(|old| old.public_key() == key.public_key())
        })
        .unwrap();
    chain.provision_candidate_custody(new_key).unwrap();
    let source = chain
        .state()
        .view()
        .world()
        .public_lane_stake_custody()
        .get(&stake_key)
        .unwrap()
        .0
        .clone();
    let destination = AssetId::with_scope(
        source.definition().clone(),
        validator.clone(),
        *source.scope(),
    );
    assert!(
        chain.height() < EPOCH - 20,
        "all real setup fits before frozen selection"
    );
    let id = Hash::new(b"funded slash replacement original bootstrap").into();
    let bootstrap = make_beacon(chain, &old_keys, 0, id, id, 1);
    install_beacon(chain, &bootstrap, &old_keys);

    for (index, key) in target_keys.iter().enumerate() {
        let owner = operator(index);
        let account = AccountId::new(owner.public_key().clone());
        let plan = PublicLaneMonetaryPlanV1 {
            network_scope: PublicLaneMonetaryScopeV1::Network(chain.network_id()),
            valid_until_height: EPOCH - 1,
            source_asset: AssetId::new(source.definition().clone(), account.clone()),
            destination_asset: source.clone(),
            amount: Quantity::from(1_000_u64),
            precondition: PublicLaneMonetaryPreconditionV1::Registration(
                PublicLaneMonetaryRegistrationV1 {
                    activation_height: TARGET_FIRST,
                },
            ),
        };
        let registration = RegisterPublicLaneValidator {
            lane_id: LaneId::SINGLE,
            validator: account.clone(),
            peer_id: PeerId::new(key.public_key().clone()),
            stake_account: account,
            initial_stake: plan.amount.clone(),
            metadata: iroha_model_base::metadata::Metadata::default(),
            monetary_plan: plan.clone(),
        };
        let authorization = PublicLaneCandidateAuthorization::new(
            chain.network_id(),
            registration.clone(),
            TARGET_FIRST,
        );
        let candidate = RegisterPublicLaneCandidate {
            registration,
            activation_height: TARGET_FIRST,
            proof_of_possession: iroha_crypto::bls_normal_pop_prove(key.private_key()).unwrap(),
            peer_signature: SignatureOf::new(key.private_key(), &authorization),
        };
        let signed = paid(chain, &owner, candidate.into());
        commit_checked(
            chain,
            signed,
            None,
            Some((&plan, true)),
            ControlWitness::empty(),
        );
    }
    // Close the separately authenticated fixed lane through committed policy. Physical
    // routing catalogs and retained historical custody remain intact until their real fences.
    let view = chain.state().view();
    let raw = view
        .world()
        .parameters()
        .custom()
        .get(&SumeragiLanePolicy::parameter_id())
        .unwrap();
    let mut lanes = SumeragiLanePolicy::from_custom_parameter(raw)
        .unwrap()
        .unwrap();
    assert_eq!(lanes.fixed.len(), 1);
    lanes.fixed.clear();
    drop(view);
    let update: InstructionBox =
        SetParameter::new(Parameter::Custom(lanes.into_custom_parameter())).into();
    let denied = paid(chain, &operator(0), update.clone());
    commit_checked(
        chain,
        denied,
        Some("CanSetParameters"),
        None,
        ControlWitness::empty(),
    );
    let signed = paid(chain, &administrator(), update);
    commit_checked(chain, signed, None, None, ControlWitness::empty());
    let EvidenceScope::Lane(scope) = expected_evidence.attribution.scope else {
        panic!("the original report belongs to the authenticated fixed lane")
    };
    let view = chain.state().view();
    let closing_lane = view
        .world()
        .sumeragi_lanes()
        .lanes
        .iter()
        .find(|row| row.incarnation == scope.incarnation)
        .expect("the committed close policy retains the lane through its retirement fence");
    let retirement = closing_lane
        .retirement_height()
        .expect("the committed policy update closed the original lane");
    assert!(
        retirement < EPOCH,
        "real retirement completes before frozen selection"
    );
    assert!(retirement > chain.height());
    drop(view);
    advance(chain, retirement, &bootstrap);
    let view = chain.state().view();
    let old_lane = view
        .world()
        .sumeragi_lanes()
        .custody
        .iter()
        .find(|row| {
            row.lane == scope.lane
                && row.incarnation == scope.incarnation
                && row.instance == expected_evidence.attribution.instance
                && row.created_at == scope.created_at
        })
        .expect("the original report retains its exact retired lane custody");
    old_lane.validate().unwrap();
    assert_eq!(old_lane.retired_at, Some(retirement));
    assert!(
        view.world()
            .sumeragi_lanes()
            .lanes
            .iter()
            .all(|row| row.incarnation != scope.incarnation)
    );
    assert!(
        old_lane
            .admits_at(expected_evidence.recorded_at_height)
            .unwrap()
    );
    let admission_deadline = old_lane.admission_deadline().unwrap().unwrap();
    assert!(admission_deadline > TARGET_FIRST);
    assert_eq!(
        view.world().consensus_evidence().get(evidence_key),
        Some(expected_evidence)
    );
    drop(view);

    advance(chain, EPOCH, &bootstrap);
    let preparation = chain
        .state()
        .view()
        .world()
        .validator_committee_transitions()
        .get(&2)
        .unwrap()
        .preparation
        .clone();
    assert_eq!(preparation.first_height, TARGET_FIRST);
    assert_eq!(preparation.authority_generation, 1);
    assert_eq!(
        preparation
            .committee
            .iter()
            .map(|seat| seat.validator.clone())
            .collect::<Vec<_>>(),
        target_keys
            .iter()
            .map(|key| PeerId::new(key.public_key().clone()))
            .collect::<Vec<_>>()
    );
    assert!(
        !preparation
            .committee
            .iter()
            .any(|seat| seat.validator.public_key() == old_keys[2].public_key())
    );
    // The frozen elected BLS committee is the target generation. No separate candidate-key
    // publication can alter it; readiness still needs the actual finalized beacon shares.
    let start = chain.height() + 1;
    let prepared = make_beacon(
        chain,
        &target_keys,
        1,
        preparation.beacon_session_id().unwrap(),
        preparation.transition_id().unwrap(),
        start,
    );
    advance(chain, start + 3, &bootstrap);
    install_beacon(chain, &prepared, &old_keys);
    let credentials = ValidatorCommitteeCredentialsV1 {
        beacon: InstalledBeaconEpochBindingV1 {
            session_id: prepared.session.record().session_id,
            transcript_hash: prepared.session.record().transcript_hash,
        },
    };
    let signed = paid(
        chain,
        &operator(0),
        SetParameter::new(Parameter::Custom(
            ValidatorCommitteeOperationV1::PrepareCredentials(
                PrepareValidatorCommitteeCredentialsV1 {
                    transition_id: preparation.transition_id().unwrap(),
                    target_epoch: 2,
                    credentials,
                },
            )
            .into_custom_parameter(),
        ))
        .into(),
    );
    commit_checked(chain, signed, None, None, ControlWitness::empty());
    let transition = chain
        .state()
        .view()
        .world()
        .validator_committee_transitions()
        .get(&2)
        .unwrap()
        .clone();
    let generation = transition.preparation.generation();
    for (index, key) in target_keys.iter().enumerate() {
        let context = transition.readiness_context(index as u32).unwrap();
        let peer = PeerId::new(key.public_key().clone());
        let mut rebound = context.clone();
        rebound.transition_id[0] ^= 1;
        assert!(
            chain
                .check_prepared_seat_binding(&peer, &generation, &rebound)
                .is_err()
        );
        let old_offender = PeerId::new(old_keys[2].public_key().clone());
        assert!(
            chain
                .check_prepared_seat_binding(&old_offender, &generation, &context)
                .is_err()
        );
        chain
            .check_prepared_seat_binding(&peer, &generation, &context)
            .unwrap();
        let readiness = ValidatorCommitteeSeatReadinessV1 {
            validator_index: index as u32,
            beacon: prove_global_threshold_beacon_seat_readiness_v1(
                &prepared.signers[index],
                &prepared.session,
                &generation,
                &context,
            )
            .unwrap(),
        };
        let signed = paid(
            chain,
            &operator(index),
            SetParameter::new(Parameter::Custom(
                ValidatorCommitteeOperationV1::AdmitSeat(AdmitValidatorCommitteeSeatV1 {
                    transition_id: preparation.transition_id().unwrap(),
                    target_epoch: 2,
                    readiness,
                })
                .into_custom_parameter(),
            ))
            .into(),
        );
        commit_checked(chain, signed, None, None, ControlWitness::empty());
        assert_eq!(
            chain
                .committed(chain.height())
                .commitment()
                .schedule
                .current
                .authorization
                .authority_generation,
            0
        );
    }
    advance(chain, TARGET_FIRST - 1, &bootstrap);
    let view = chain.state().view();
    let outcome = view
        .world()
        .validator_committee_transitions()
        .get(&2)
        .unwrap()
        .outcome
        .as_ref()
        .unwrap();
    assert_eq!(outcome.decision, ValidatorEpochDecisionV1::Activate);
    assert_eq!(outcome.authority_generation, 1);
    assert_eq!(
        view.world()
            .validator_committee_transitions()
            .get(&2)
            .unwrap()
            .readiness
            .len(),
        4
    );
    drop(view);
    advance(chain, TARGET_FIRST, &prepared);
    assert_eq!(
        chain
            .committed(TARGET_FIRST)
            .commitment()
            .schedule
            .current
            .authorization
            .authority_generation,
        1
    );
    assert_eq!(
        chain
            .committed(TARGET_FIRST - 1)
            .commitment()
            .schedule
            .current
            .authorization
            .authority_generation,
        0
    );
    let view = chain.state().view();
    let registration = view
        .world()
        .public_lane_validators()
        .get(&stake_key)
        .unwrap();
    assert!(
        !crate::state::validator_committee::peer_has_committee_obligation(
            view.world(),
            chain
                .committed(TARGET_FIRST)
                .commitment()
                .schedule
                .current
                .committee
                .iter()
                .map(|seat| &seat.validator),
            &registration.peer_id
        )
    );
    let pending = view
        .world()
        .public_lane_stake_shares()
        .get(&share_key)
        .unwrap()
        .pending_unbonds
        .get(&request_id)
        .unwrap();
    assert_eq!(pending.amount, Quantity::from(9_000_u64));
    assert!(pending.slashable_through_height >= TARGET_FIRST - 1);
    let liability_release = pending.liability_release_height;
    assert!(
        liability_release
            >= TARGET_FIRST - 1 + policy().evidence_horizon_blocks + policy().slashing_delay_blocks
    );
    drop(view);
    // The terminal record is a replay fence through the exact old-lane admission deadline.
    // Its authenticated historical penalty remains immutable after live-table pruning.
    assert!(admission_deadline + policy().slashing_delay_blocks < liability_release);
    advance(chain, admission_deadline, &prepared);
    assert_eq!(
        chain
            .state()
            .view()
            .world()
            .consensus_evidence()
            .get(evidence_key),
        Some(expected_evidence)
    );
    advance(chain, admission_deadline + 1, &prepared);
    assert!(
        chain
            .state()
            .view()
            .world()
            .consensus_evidence()
            .get(evidence_key)
            .is_none()
    );
    // Let the actual lane retirement fence close first; global liability must still
    // reject the signed post-slash plan until its independently retained block height.
    loop {
        let view = chain.state().view();
        let registration = view
            .world()
            .public_lane_validators()
            .get(&stake_key)
            .unwrap();
        let retained = crate::sumeragi::lanes::custody::retains_registration(
            view.world(),
            registration,
            chain.height() + 1,
        )
        .unwrap();
        drop(view);
        if !retained {
            break;
        }
        assert!(
            chain.height() + 2 < liability_release,
            "lane retirement precedes this global liability control"
        );
        advance(chain, chain.height() + 1, &prepared);
    }
    assert!(chain.height() + 1 < liability_release);
    let view = chain.state().view();
    let early = prepare_public_lane_plan(
        &view,
        PublicLanePreparationRequestV1 {
            lane_id: LaneId::SINGLE,
            valid_for_blocks: 1,
            operation: PublicLanePreparationOperationV1::FinalizeUnbond(
                PublicLanePrepareUnbondV1 {
                    validator: validator.clone(),
                    staker: validator.clone(),
                    request_id,
                },
            ),
        },
    )
    .unwrap();
    let PublicLanePreparedPlanV1::Monetary(early_plan) = early.plan else {
        panic!("exact early remaining plan")
    };
    assert_eq!(early_plan.amount, Quantity::from(9_000_u64));
    drop(view);
    let early = paid(
        chain,
        offender,
        FinalizePublicLaneUnbond {
            lane_id: LaneId::SINGLE,
            validator: validator.clone(),
            staker: validator.clone(),
            request_id,
            monetary_plan: early_plan,
        }
        .into(),
    );
    commit_checked(
        chain,
        early,
        Some(&format!(
            "unbond request remains slashable through the pre-transaction effects at block height {liability_release}"
        )),
        None,
        ControlWitness::empty(),
    );
    // Both the global evidence horizon and original fixed-lane horizon must expire.
    advance(chain, liability_release - 1, &prepared);
    let view = chain.state().view();
    let registration = view
        .world()
        .public_lane_validators()
        .get(&stake_key)
        .unwrap();
    assert!(
        !crate::sumeragi::lanes::custody::retains_registration(
            view.world(),
            registration,
            liability_release
        )
        .unwrap()
    );
    assert!(chain.committed(chain.height()).block_time_ms() >= release_at_ms);
    let prepared_plan = prepare_public_lane_plan(
        &view,
        PublicLanePreparationRequestV1 {
            lane_id: LaneId::SINGLE,
            valid_for_blocks: 4,
            operation: PublicLanePreparationOperationV1::FinalizeUnbond(
                PublicLanePrepareUnbondV1 {
                    validator: validator.clone(),
                    staker: validator.clone(),
                    request_id,
                },
            ),
        },
    )
    .unwrap();
    let PublicLanePreparedPlanV1::Monetary(plan) = prepared_plan.plan else {
        panic!("exact remaining principal plan")
    };
    assert_eq!(plan.amount, Quantity::from(9_000_u64));
    assert_eq!(plan.source_asset, source);
    assert_eq!(plan.destination_asset, destination);
    drop(view);
    let instruction = FinalizePublicLaneUnbond {
        lane_id: LaneId::SINGLE,
        validator: validator.clone(),
        staker: validator.clone(),
        request_id,
        monetary_plan: plan.clone(),
    };
    let signed = paid(chain, offender, instruction.clone().into());
    commit_checked(
        chain,
        signed.clone(),
        None,
        Some((&plan, false)),
        ControlWitness::empty(),
    );
    assert_eq!(chain.height(), liability_release);
    let fresh_replay = paid(chain, offender, instruction.into());
    assert_ne!(fresh_replay.hash(), signed.hash());
    commit_checked(
        chain,
        fresh_replay,
        Some("validator has no retained positive stake custody"),
        None,
        ControlWitness::empty(),
    );
    let view = chain.state().view();
    assert!(
        view.world()
            .public_lane_stake_custody()
            .get(&stake_key)
            .is_none()
    );
    assert!(
        view.world()
            .public_lane_stake_shares()
            .get(&share_key)
            .is_none_or(|share| share.bonded.is_zero() && share.pending_unbonds.is_empty())
    );
    assert!(
        view.world()
            .consensus_evidence()
            .get(evidence_key)
            .is_none()
    );
    drop(view);
    let applied = chain.committed(applied_height);
    assert_eq!(
        (applied.block_hash(), applied.core_hash(), applied.result()),
        applied_identity
    );
    assert_eq!(
        applied.block().npos_consensus_effects(),
        Some(&applied_effects)
    );
    drop(applied);
    let expected = money(chain);
    for _ in 0..2 {
        replay.replay_from(chain).unwrap();
        assert_eq!(money(replay), expected);
        assert!(
            replay
                .state()
                .view()
                .world()
                .consensus_evidence()
                .get(evidence_key)
                .is_none()
        );
        let replayed_penalty = replay.committed(applied_height);
        assert_eq!(
            (
                replayed_penalty.block_hash(),
                replayed_penalty.core_hash(),
                replayed_penalty.result()
            ),
            applied_identity
        );
        assert_eq!(
            replayed_penalty.block().npos_consensus_effects(),
            Some(&applied_effects)
        );
        assert!(
            replay
                .state()
                .view()
                .world()
                .public_lane_stake_custody()
                .get(&stake_key)
                .is_none()
        );
    }
}
