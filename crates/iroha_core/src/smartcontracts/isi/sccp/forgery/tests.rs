//! Native signed-certificate controls and separate bounded predicate DATA controls.
//! No test supplies a successful verifier, fabricated execution tip, or recorded-evidence grant.

use iroha_data_model::sccp::generation::SccpGenerationEndV1;

use super::*;
use crate::{
    smartcontracts::isi::sccp::{
        read::native::finality,
        test_support::{blank_state, retained_generation_fixture, sample_generation_at},
    },
    state::World,
    sumeragi::{
        crypto::BlsCrypto,
        test_chain::{CertifiedTestChain, TestChainConfig},
    },
};
use iroha_allocation::AllocationRefusal;
use iroha_crypto::{
    Algorithm, KeyPair,
    bls::consensus::{aggregate, sign},
};
use iroha_data_model::{
    isi::sccp::InitializeSccpV1,
    parameter::{Parameter, SumeragiParameter, system::SumeragiNposParameters},
    sccp::{native::SccpAnchorWitnessV1, params::SccpParametersV1},
    sumeragi_finality::certified_result::SccpFinalityHeaderFieldsV1,
};
use std::{num::NonZeroU64, sync::atomic::AtomicBool, time::Duration};

fn control(stop: &AtomicBool) -> SccpNativeReadControl<'_> {
    SccpNativeReadControl {
        deadline: Instant::now() + Duration::from_secs(60),
        stop,
    }
}

pub(crate) fn keys() -> Vec<KeyPair> {
    let mut keys = (0x91..=0x94)
        .map(|seed| KeyPair::try_from_seed(vec![seed; 32], Algorithm::BlsNormal).unwrap())
        .collect::<Vec<_>>();
    keys.sort_by_key(raw_key);
    keys
}

fn raw_key(key: &KeyPair) -> [u8; 48] {
    key.public_key()
        .try_to_bytes()
        .unwrap()
        .1
        .try_into()
        .unwrap()
}

// Real signed NPoS genesis, InitializeSccp, StateExecutor output seal and exact-q QC.
// The owned keys intentionally permit adversarial signed certificates in these tests.
/// Genuine initialized native chain with every G1 member funded and registered.
pub(crate) fn active_chain() -> (CertifiedTestChain, Vec<KeyPair>) {
    configured_chain(4)
}

/// Genuine genesis registrations, captured by the same generation finalizer as its QC.
/// No retained committee field or opaque tip is changed after authenticated execution.
pub(crate) fn active_member_chain() -> (CertifiedTestChain, Vec<KeyPair>) {
    configured_chain(4)
}

/// Bind output limits and an optional real forgery-event callback in the signed genesis.
/// Return the exact retained ordinary genesis signer separately from the BLS committee.
/// Existing member helpers retain their unchanged default parameters and actions.
pub(crate) fn active_member_chain_with_output_policy(
    policy: iroha_data_model::parameter::ExecutionOutputPolicyV1,
    callback_bytes: Option<usize>,
) -> (CertifiedTestChain, Vec<KeyPair>, KeyPair) {
    configured_chain_with_output(4, Some((policy, callback_bytes)), None, None)
}

/// Supply the selector capacity in the original signed genesis, never the retained parent.
pub(crate) fn active_member_chain_with_max_transactions(
    max_transactions: NonZeroU64,
) -> (CertifiedTestChain, Vec<KeyPair>) {
    let (chain, keys, _) = configured_chain_with_output(4, None, Some(max_transactions), None);
    (chain, keys)
}

/// Genuine signed genesis with an explicit immutable delay and ordinary transaction signer.
pub(crate) fn active_member_chain_with_penalty_delay(
    delay: u64,
) -> (CertifiedTestChain, Vec<KeyPair>, KeyPair) {
    configured_chain_with_output(4, None, None, Some(delay))
}

fn configured_chain(register_members: usize) -> (CertifiedTestChain, Vec<KeyPair>) {
    let (chain, keys, _) = configured_chain_with_output(register_members, None, None, None);
    (chain, keys)
}

fn configured_chain_with_output(
    register_members: usize,
    output: Option<(
        iroha_data_model::parameter::ExecutionOutputPolicyV1,
        Option<usize>,
    )>,
    max_transactions: Option<NonZeroU64>,
    penalty_delay: Option<u64>,
) -> (CertifiedTestChain, Vec<KeyPair>, KeyPair) {
    let keys = keys();
    let mut config = TestChainConfig::new(World::new(), 1_000);
    config.validator_keys = Some(keys.clone());
    config.consensus_mode = iroha_data_model::parameter::system::SumeragiConsensusMode::Npos;
    config.genesis_block_cadence_ms = NonZeroU64::new(1_000).unwrap();
    let mut npos = SumeragiNposParameters {
        epoch_length_blocks: NonZeroU64::new(3_600).unwrap(),
        max_validators: 4,
        ..SumeragiNposParameters::default()
    };
    if let Some(delay) = penalty_delay {
        assert_ne!(delay, 0);
        npos.slashing_delay_blocks = delay;
    }
    config.genesis_parameters.extend([
        Parameter::Sumeragi(SumeragiParameter::EpochLengthBlocks(
            npos.epoch_length_blocks,
        )),
        Parameter::Custom(npos.into_custom_parameter()),
    ]);
    let mut nexus = iroha_config::parameters::actual::Nexus::default();
    nexus.staking.unbonding_delay = Duration::from_secs(21 * 86_400);
    nexus.staking.max_slash_bps = 1;
    if register_members != 0 {
        register_genesis_members(&mut config, &keys[..register_members], &nexus.staking);
    }
    config.nexus = Some(nexus);
    if let Some(maximum) = max_transactions {
        config.genesis_parameters.push(Parameter::Block(
            iroha_data_model::parameter::BlockParameter::MaxTransactions(maximum),
        ));
    }
    if let Some((policy, callback_bytes)) = output {
        use iroha_data_model::{
            account::AccountId,
            events::data::prelude::{DataEventFilter, SccpEventFilter},
            isi::{Grant, Log, Register, SetKeyValue},
            parameter::BlockParameter,
            prelude::{InstructionBox, Level},
            sccp::events::SccpEventSet,
            trigger::{
                Trigger,
                action::{Action, Repeats},
            },
        };
        policy.validate().expect("genuine genesis output policy");
        assert_eq!(policy.max_pipeline_triggers, 0);
        assert_eq!(policy.max_time_invocations, 1);
        config.genesis_parameters.extend([
            Parameter::Block(BlockParameter::ExecutionOutput(policy)),
            Parameter::Block(BlockParameter::MaxTimeTriggerInvocations(
                std::num::NonZeroU32::MIN,
            )),
        ]);
        if let Some(bytes) = callback_bytes {
            let owner = AccountId::new(config.genesis_key.public_key().clone());
            // The SCCP event filter is global. Grant its exact capability in the
            // genuine signed genesis before registering the callback action.
            config.genesis_instructions.push(
                Grant::account_permission(
                    iroha_executor_data_model::permission::trigger::CanRegisterGlobalDataTrigger {
                        authority: owner.clone(),
                    },
                    owner.clone(),
                )
                .into(),
            );
            config.genesis_instructions.push(
                Register::trigger(Trigger::new(
                    "forgery_output_callback".parse().unwrap(),
                    Action::new(
                        vec![
                            InstructionBox::from(SetKeyValue::account(
                                owner.clone(),
                                "forgery_callback_write".parse().unwrap(),
                                iroha_primitives::json::Json::new(7),
                            )),
                            Log::new(Level::DEBUG, "x".repeat(bytes)).into(),
                        ],
                        Repeats::Exactly(1),
                        owner,
                        DataEventFilter::Sccp(
                            SccpEventFilter::new()
                                .for_events(SccpEventSet::ForgeryEvidenceRecorded),
                        ),
                    )
                    .unwrap(),
                ))
                .into(),
            );
        }
    }
    config.genesis_instructions.push(
        InitializeSccpV1 {
            parameters: SccpParametersV1::taira_default(),
            reset_nonce: [0x5a; 32],
        }
        .into(),
    );
    let ordinary_signer = config.genesis_key.clone();
    let mut chain = CertifiedTestChain::start(config).expect("original active NPoS genesis");
    assert_eq!(
        chain.genesis_account(),
        &iroha_data_model::account::AccountId::new(ordinary_signer.public_key().clone()),
        "retain the actual signed-genesis ordinary account custody"
    );
    chain.commit_at(2_000, Vec::new());
    {
        let view = chain.state().view();
        assert_eq!(
            store::committee_generations::get(view.world(), &1)
                .unwrap()
                .keys,
            keys.iter().map(raw_key).collect::<Vec<_>>()
        );
    }
    if register_members != 0 {
        let view = chain.state().view();
        let generation = store::committee_generations::get(view.world(), &1).unwrap();
        assert_eq!(
            generation.members.iter().filter(|m| m.is_some()).count(),
            register_members,
            "actual genesis G6 capture"
        );
        for (member, key) in generation.members.iter().take(register_members).zip(&keys) {
            let member = member.as_ref().unwrap();
            assert_eq!(
                member.validator,
                iroha_data_model::account::AccountId::new(key.public_key().clone())
            );
            assert_eq!(member.activation_height, 1);
        }
    }
    (chain, keys, ordinary_signer)
}

pub(crate) fn register_genesis_members(
    config: &mut TestChainConfig,
    keys: &[KeyPair],
    staking: &iroha_config::parameters::actual::NexusStaking,
) {
    use iroha_data_model::{
        Registrable,
        account::{Account, AccountId},
        asset::{Asset, AssetBalancePolicy, AssetDefinition, AssetDefinitionId, AssetId},
        domain::Domain,
        isi::RegisterPublicLaneValidator,
        nexus::PublicLaneMonetaryPlanV1,
    };
    use iroha_model_base::{domain::DomainId, peer::PeerId, topology::LaneId};
    use iroha_primitives::numeric::{NumericSpec, Quantity};
    let owner = AccountId::new(config.genesis_key.public_key().clone());
    let definition: AssetDefinitionId = staking.stake_asset_id.parse().unwrap();
    let escrow = AccountId::parse_encoded(&staking.stake_escrow_account_id).unwrap();
    let amount = Quantity::from(1_000_u32);
    let validators = keys
        .iter()
        .map(|key| AccountId::new(key.public_key().clone()))
        .collect::<Vec<_>>();
    config.world = World::with_assets(
        [Domain::new(DomainId::try_new("nexus", "universal").unwrap()).build(&owner)],
        validators
            .iter()
            .chain(std::iter::once(&escrow))
            .map(|id| Account::new(id.clone()).build(&owner)),
        [AssetDefinition::new(
            definition.clone(),
            "Network XOR",
            NumericSpec::fractional(9),
            AssetBalancePolicy::Global,
            None,
        )
        .build(&owner)],
        validators
            .iter()
            .map(|id| Asset::new(AssetId::new(definition.clone(), id.clone()), amount.clone())),
        [],
    );
    for (validator, key) in validators.into_iter().zip(keys) {
        let source = AssetId::new(definition.clone(), validator.clone());
        let target = AssetId::new(definition.clone(), escrow.clone());
        config.genesis_instructions.push(
            RegisterPublicLaneValidator {
                lane_id: LaneId::SINGLE,
                validator: validator.clone(),
                peer_id: PeerId::new(key.public_key().clone()),
                stake_account: validator,
                initial_stake: amount.clone(),
                metadata: iroha_model_base::metadata::Metadata::default(),
                monetary_plan: PublicLaneMonetaryPlanV1::genesis_registration(
                    source,
                    target,
                    amount.clone(),
                ),
            }
            .into(),
        );
    }
}

/// Read the original committed certificate through the actual native producer.
pub(crate) fn original(chain: &CertifiedTestChain) -> SubmitSccpForgeryEvidenceV1 {
    let stop = AtomicBool::new(false);
    let budget = AllocationBudget::new(128 << 20);
    let view = chain.state().view();
    let answer = finality(&view, None, &budget, control(&stop)).unwrap();
    SubmitSccpForgeryEvidenceV1 {
        qc: answer.data().qc,
        header: answer.data().header,
        aggregate_signature: answer.data().aggregate_signature,
        anchor: None,
    }
}

/// Mutate fixed X DATA before explicitly resigning it with fixture keys.
pub(crate) fn change_header(
    evidence: &mut SubmitSccpForgeryEvidenceV1,
    change: impl FnOnce(&mut SccpFinalityHeaderFieldsV1),
) {
    let mut fields = SccpFinalityHeaderV1::parse(&evidence.header)
        .unwrap()
        .fields();
    change(&mut fields);
    evidence.header = *SccpFinalityHeaderV1::from_fields(&fields)
        .unwrap()
        .as_bytes();
}

/// Recompute the exact native aggregate over the selected fixture quorum.
pub(crate) fn resign(
    evidence: &mut SubmitSccpForgeryEvidenceV1,
    keys: &[KeyPair],
    instance: Hash32,
) {
    let qc = QcFixedV1::parse(&evidence.qc).unwrap();
    let x = SccpFinalityHeaderV1::parse(&evidence.header).unwrap();
    let digest = ConsensusDigest::from_preimage(&commit_preimage(
        &instance.0,
        &qc,
        x.height(),
        &outer_result(&x, &qc.result_body).0,
    ))
    .unwrap();
    let shares = keys
        .iter()
        .enumerate()
        .filter(|(index, _)| qc.signers & (1_u32 << index) != 0)
        .map(|(_, key)| sign(key.private_key(), &digest).unwrap())
        .collect::<Vec<_>>();
    evidence.aggregate_signature = aggregate(shares).unwrap();
}

/// Produce a genuine exact-quorum signature on an adversarial future-height claim.
pub(crate) fn future(chain: &CertifiedTestChain, keys: &[KeyPair]) -> SubmitSccpForgeryEvidenceV1 {
    let mut evidence = original(chain);
    change_header(&mut evidence, |fields| fields.height = chain.height() + 1);
    resign(&mut evidence, keys, chain.instance());
    evidence
}

#[test]
fn genuine_certificate_and_other_exact_quorum_are_never_evidence() {
    let (chain, keys) = active_chain();
    let mut evidence = original(&chain);
    let stop = AtomicBool::new(false);
    let budget = AllocationBudget::new(128 << 20);
    let view = chain.state().view();
    for signers in [0b0111, 0b1011, 0b1101, 0b1110] {
        let mut qc = QcFixedV1::parse(&evidence.qc).unwrap();
        qc.signers = signers;
        evidence.qc = qc.encode();
        resign(&mut evidence, &keys, chain.instance());
        assert!(matches!(
            verify_committed(&view, &evidence, 3_000, &budget, control(&stop)),
            Err(ForgeryVerificationError::NotEvidence)
        ));
        assert_eq!(budget.reserved_bytes(), 0);
    }
}

#[test]
fn signed_future_candidate_borrows_original_generation_and_refunds_pairing() {
    let (chain, keys) = active_chain();
    let evidence = future(&chain, &keys);
    let stop = AtomicBool::new(false);
    let budget = AllocationBudget::new(128 << 20);
    let view = chain.state().view();
    let checked = verify_committed(&view, &evidence, 3_000, &budget, control(&stop)).unwrap();
    assert_eq!(checked.rule(), SccpForgeryRuleV1::E2);
    assert!(std::ptr::eq(checked.evidence(), &raw const evidence));
    let retained = store::committee_generations::get(view.world(), &1).unwrap();
    assert!(std::ptr::eq(checked.generation(), retained));
    assert_eq!(
        checked.parent().iroha_hash(),
        view.native_execution_tip().unwrap().iroha_hash()
    );
    assert_eq!(checked.execution_height(), chain.height() + 1);
    assert_eq!(checked.instance(), chain.instance());
    assert_eq!(
        checked.instance(),
        SumeragiRootScope::Global
            .instance_id(
                &BlsCrypto::new(),
                *view.network_id(),
                view.chain_id().as_str()
            )
            .unwrap()
    );
    assert_eq!(
        checked.liability_clock(),
        iroha_data_model::sccp::generation::next_liability_clock_v1(
            *store::liability_clock::get(view.world()),
            checked.parent().creation_time_ms(),
            3_000,
            SccpParametersV1::taira_default().committee_heartbeat_ms
        )
    );
    let x = SccpFinalityHeaderV1::parse(&evidence.header).unwrap();
    assert_eq!(
        *checked.result(),
        outer_result(&x, &checked.qc().result_body).0
    );
    assert_eq!(
        checked.evidence_id(),
        forgery_evidence_id(1, checked.message(), checked.qc().signers)
    );
    let signers = checked.signers().collect::<Vec<_>>();
    assert_eq!(signers.len(), 3);
    for (index, key, member) in signers {
        let index = usize::try_from(index).unwrap();
        assert!(std::ptr::eq(key, &raw const retained.keys[index]));
        assert_eq!(member, retained.members[index].as_ref());
        if let Some(member) = member {
            assert!(std::ptr::eq(
                member,
                retained.members[index].as_ref().unwrap()
            ));
        }
    }
    assert_eq!(
        budget.reserved_bytes(),
        0,
        "scratch and funding retire before candidate publication"
    );
}

#[test]
fn local_refusal_and_stop_never_become_protocol_verdicts_or_leak_budget() {
    let (chain, keys) = active_chain();
    let evidence = future(&chain, &keys);
    let stop = AtomicBool::new(false);
    let view = chain.state().view();
    let layout = ConsensusAggregateScratch::<()>::backing_layout();
    let bytes = layout.size();
    // A finite limit below the exact demand can never be satisfied: no release wait.
    let budget = AllocationBudget::new(bytes - 1);
    assert!(matches!(
        verify_committed(&view, &evidence, 3_000, &budget, control(&stop)),
        Err(ForgeryVerificationError::Allocation(AllocationRefusal::ExceedsLimit {
            requested_bytes,
            limit_bytes,
        })) if requested_bytes == bytes && limit_bytes == bytes - 1
    ));
    assert_eq!(budget.reserved_bytes(), 0);
    // Capacity held by another owner of the same pool is a typed retryable refusal.
    budget.set_limit_bytes(bytes);
    let occupied = budget.try_reserve_bytes(1).unwrap();
    assert!(matches!(
        verify_committed(&view, &evidence, 3_000, &budget, control(&stop)),
        Err(ForgeryVerificationError::Allocation(AllocationRefusal::Capacity {
            requested_bytes,
            reserved_bytes: 1,
            limit_bytes,
            ..
        })) if requested_bytes == bytes && limit_bytes == bytes
    ));
    assert_eq!(budget.reserved_bytes(), 1);
    drop(occupied);
    assert_eq!(budget.reserved_bytes(), 0);
    assert_eq!(
        crate::test_allocations::allocations_during(|| {
            assert!(verify_committed(&view, &evidence, 3_000, &budget, control(&stop)).is_ok());
        }),
        1,
        "exact pairing charge construction requires only its one backing allocation"
    );
    assert_eq!(budget.reserved_bytes(), 0);
    let (failure, observed) = crate::test_allocations::refuse_one_layout_during(layout, || {
        verify_committed(&view, &evidence, 3_000, &budget, control(&stop))
    });
    assert!(observed, "actual forgery pairing allocator was refused");
    assert!(
        matches!(&failure, Err(ForgeryVerificationError::PhysicalAllocation(original))
            if original.vec_reserve_error().is_some_and(|(_, actual)| actual == layout)),
        "HC941 forgery pairing allocator refusal must remain local with its original cause"
    );
    let Err(ForgeryVerificationError::PhysicalAllocation(original)) = failure else {
        unreachable!("asserted original pairing cause")
    };
    let deferred = crate::execution_attempt::ExecutionDeferred::from(original);
    assert!(deferred.allocation_refusal().is_none());
    assert_eq!(
        deferred.reason(),
        ivm::error::ExecutionDeferral::AllocationUnavailable
    );
    assert!(
        deferred
            .allocator_refusal()
            .unwrap()
            .vec_reserve_error()
            .is_some()
    );
    assert_eq!(budget.reserved_bytes(), 0);
    assert!(verify_committed(&view, &evidence, 3_000, &budget, control(&stop)).is_ok());
    stop.store(true, Ordering::Release);
    assert!(matches!(
        verify_committed(&view, &evidence, 3_000, &budget, control(&stop)),
        Err(ForgeryVerificationError::Cancelled)
    ));
    stop.store(false, Ordering::Release);
    assert!(matches!(
        verify_committed(
            &view,
            &evidence,
            3_000,
            &budget,
            SccpNativeReadControl {
                deadline: Instant::now(),
                stop: &stop
            }
        ),
        Err(ForgeryVerificationError::Deadline)
    ));
    assert_eq!(budget.reserved_bytes(), 0);
}

#[test]
fn exact_quorum_spare_bits_and_invalid_signature_are_rejected_before_mismatch() {
    let (chain, keys) = active_chain();
    let original = future(&chain, &keys);
    let stop = AtomicBool::new(false);
    let budget = AllocationBudget::new(128 << 20);
    let view = chain.state().view();
    for signers in [0, 0b0011, 0b1111, 0b1_0111, 1_u32 << 31] {
        let mut evidence = original.clone();
        let mut qc = QcFixedV1::parse(&evidence.qc).unwrap();
        qc.signers = signers;
        evidence.qc = qc.encode();
        if signers == 0b0011 || signers == 0b1111 {
            resign(&mut evidence, &keys, chain.instance());
        }
        assert!(matches!(
            verify_committed(&view, &evidence, 3_000, &budget, control(&stop)),
            Err(ForgeryVerificationError::BadSignature)
        ));
        assert_eq!(budget.reserved_bytes(), 0);
    }
    for signature in [
        [0; 96],
        [0xff; 96],
        iroha_sccp::v1::committee::IDENTITY_SIGNATURE,
    ] {
        let mut evidence = original.clone();
        evidence.aggregate_signature = signature;
        assert!(matches!(
            verify_committed(&view, &evidence, 3_000, &budget, control(&stop)),
            Err(ForgeryVerificationError::BadSignature)
        ));
        assert_eq!(budget.reserved_bytes(), 0);
    }
}

#[test]
fn every_native_commit_field_and_raw_result_are_signed_but_epoch_is_not_reinterpreted() {
    let (chain, keys) = active_chain();
    let original = future(&chain, &keys);
    let stop = AtomicBool::new(false);
    let budget = AllocationBudget::new(128 << 20);
    let view = chain.state().view();
    for field in 0..7 {
        let mut evidence = original.clone();
        let mut qc = QcFixedV1::parse(&evidence.qc).unwrap();
        match field {
            0 => qc.epoch ^= 1,
            1 => qc.epoch_context[0] ^= 1,
            2 => qc.view ^= 1,
            3 => qc.block_hash[0] ^= 1,
            4 => qc.result_body[0] ^= 1,
            5 => change_header(&mut evidence, |x| x.timestamp_ms += 1),
            6 => change_header(&mut evidence, |x| x.height += 1),
            _ => unreachable!(),
        }
        evidence.qc = qc.encode();
        assert!(
            matches!(
                verify_committed(&view, &evidence, 3_000, &budget, control(&stop)),
                Err(ForgeryVerificationError::BadSignature)
            ),
            "signed field {field}"
        );
    }
    let mut wrong_instance = original.clone();
    resign(&mut wrong_instance, &keys, Hash32([0x77; 32]));
    assert!(matches!(
        verify_committed(&view, &wrong_instance, 3_000, &budget, control(&stop)),
        Err(ForgeryVerificationError::BadSignature)
    ));
    let mut signed_unverified_epoch = original;
    let mut qc = QcFixedV1::parse(&signed_unverified_epoch.qc).unwrap();
    qc.epoch = u64::MAX;
    qc.epoch_context = [0x55; 32];
    signed_unverified_epoch.qc = qc.encode();
    resign(&mut signed_unverified_epoch, &keys, chain.instance());
    let candidate = verify_committed(
        &view,
        &signed_unverified_epoch,
        3_000,
        &budget,
        control(&stop),
    )
    .unwrap();
    assert_eq!(
        (candidate.qc().epoch, candidate.qc().epoch_context),
        (u64::MAX, [0x55; 32])
    );
    assert_eq!(candidate.generation().generation, 1);
    assert_eq!(candidate.rule(), SccpForgeryRuleV1::E2);
    assert_eq!(budget.reserved_bytes(), 0);
}

#[test]
fn claim_generation_and_root_failures_precede_pairing() {
    let (chain, keys) = active_chain();
    let original = future(&chain, &keys);
    let stop = AtomicBool::new(false);
    let no_pairing = AllocationBudget::new(0);
    let view = chain.state().view();
    let mut cases = Vec::new();
    let mut malformed = original.clone();
    malformed.header[0] ^= 1;
    cases.push(malformed);
    let mut foreign = original.clone();
    change_header(&mut foreign, |x| x.network_id[0] ^= 1);
    cases.push(foreign);
    let mut wrong_root = original.clone();
    change_header(&mut wrong_root, |x| x.committee_root[0] ^= 1);
    cases.push(wrong_root);
    let mut inactive = original.clone();
    inactive.header = *SccpFinalityHeaderV1::inactive(*view.network_id().as_bytes(), 3, 3_000)
        .unwrap()
        .as_bytes();
    cases.push(inactive);
    for evidence in cases {
        assert!(matches!(
            verify_committed(&view, &evidence, 3_000, &no_pairing, control(&stop)),
            Err(ForgeryVerificationError::NotEvidence)
        ));
    }
    let mut unknown = original;
    change_header(&mut unknown, |x| x.generation = 2);
    assert!(matches!(
        verify_committed(&view, &unknown, 3_000, &no_pairing, control(&stop)),
        Err(ForgeryVerificationError::EvidenceUnknownGeneration)
    ));
    let empty = blank_state();
    assert!(matches!(
        verify_committed(&empty.view(), &unknown, 3_000, &no_pairing, control(&stop)),
        Err(ForgeryVerificationError::NotEvidence)
    ));
    assert_eq!(no_pairing.reserved_bytes(), 0);
}

#[test]
fn genuine_heartbeat_tenure_precedes_future_and_needs_no_anchor() {
    let (mut chain, keys) = active_chain();
    let mut evidence = original(&chain);
    let started = store::committee_generations::get(chain.state().view().world(), &1)
        .unwrap()
        .start_timestamp_ms;
    chain.commit_at(
        started + SccpParametersV1::taira_default().committee_heartbeat_ms,
        Vec::new(),
    );
    let view = chain.state().view();
    change_header(&mut evidence, |x| x.height = chain.height() + 1);
    resign(&mut evidence, &keys, chain.instance());
    evidence.anchor = Some(SccpAnchorWitnessV1 {
        core_hash: [0; 32],
        result: [0; 32],
        path: [[0; 32]; 12],
    });
    let stop = AtomicBool::new(false);
    let budget = AllocationBudget::new(128 << 20);
    let candidate = verify_committed(
        &view,
        &evidence,
        chain
            .state()
            .view()
            .native_execution_tip()
            .unwrap()
            .creation_time_ms(),
        &budget,
        control(&stop),
    )
    .unwrap();
    assert_eq!(candidate.rule(), SccpForgeryRuleV1::E1);
    assert_eq!(candidate.generation().generation, 1);
    assert!(candidate.generation().end.is_some());
}

#[test]
fn signed_e3_e4_use_original_parent_and_open_anchors_despite_offered_witness() {
    let (mut chain, keys) = active_chain();
    let original = original(&chain);
    let stop = AtomicBool::new(false);
    let budget = AllocationBudget::new(128 << 20);
    // First parent-direct, then the same original height in the open chunk.
    for pass in 0..2 {
        if pass == 1 {
            chain.commit_at(3_000, Vec::new());
        }
        let view = chain.state().view();
        for rule in [SccpForgeryRuleV1::E3, SccpForgeryRuleV1::E4] {
            let mut evidence = original.clone();
            let mut qc = QcFixedV1::parse(&evidence.qc).unwrap();
            if rule == SccpForgeryRuleV1::E3 {
                qc.block_hash[0] ^= 1;
            }
            qc.result_body[0] ^= 1;
            evidence.qc = qc.encode();
            resign(&mut evidence, &keys, chain.instance());
            evidence.anchor = Some(SccpAnchorWitnessV1 {
                core_hash: qc.block_hash,
                result: outer_result(
                    &SccpFinalityHeaderV1::parse(&evidence.header).unwrap(),
                    &qc.result_body,
                )
                .0,
                path: [[0; 32]; 12],
            });
            let candidate = verify_committed(&view, &evidence, 4_000, &budget, control(&stop))
                .expect("SC18 original parent/open anchor must prevail over offered witness");
            assert_eq!(candidate.rule(), rule);
        }
    }
    assert_eq!(budget.reserved_bytes(), 0);
}

#[test]
fn genuine_native_certificate_uses_core_anchor_instead_of_outer_block_hash() {
    let (chain, _) = active_chain();
    let evidence = original(&chain);
    let view = chain.state().view();
    let parent = view.native_execution_tip().unwrap();
    let qc = QcFixedV1::parse(&evidence.qc).unwrap();
    assert_eq!(qc.block_hash, parent.core_hash().0);
    assert_ne!(parent.iroha_hash().as_ref(), &parent.core_hash().0);
    let budget = AllocationBudget::new(128 << 20);
    let stop = AtomicBool::new(false);
    assert!(
        matches!(
            verify_committed(&view, &evidence, 4_000, &budget, control(&stop)),
            Err(ForgeryVerificationError::NotEvidence)
        ),
        "SC18 genuine native certificate cannot become E3 through outer block hash substitution"
    );
    assert_eq!(budget.reserved_bytes(), 0);
}

#[test]
fn signed_body_digest_only_forgery_is_e4_against_original_anchor() {
    let (chain, keys) = active_chain();
    let original = original(&chain);
    let mut evidence = original.clone();
    let mut qc = QcFixedV1::parse(&evidence.qc).unwrap();
    qc.result_body[0] ^= 1;
    evidence.qc = qc.encode();
    resign(&mut evidence, &keys, chain.instance());
    assert_eq!(evidence.header, original.header, "only D_body changes");
    assert_eq!(
        qc.block_hash,
        QcFixedV1::parse(&original.qc).unwrap().block_hash
    );
    let budget = AllocationBudget::new(128 << 20);
    let stop = AtomicBool::new(false);
    let view = chain.state().view();
    {
        let result = verify_committed(&view, &evidence, 4_000, &budget, control(&stop));
        assert!(
            result
                .as_ref()
                .is_ok_and(|candidate| candidate.rule() == SccpForgeryRuleV1::E4),
            "SC13 signed D_body mismatch must remain punishable E4 evidence"
        );
        let candidate = result.unwrap();
        assert_eq!(candidate.rule(), SccpForgeryRuleV1::E4);
    }
    assert_eq!(budget.reserved_bytes(), 0);
}

#[test]
fn absent_and_authenticated_dataspace_sources_cannot_supply_global_identity() {
    assert!(matches!(
        original_source(&blank_state().view()),
        Err(ForgeryVerificationError::Unavailable(_))
    ));
    crate::state::native_capture_fixture::with_native_capture_dataspace_source(
        |state, _block, _guard, _source, _hash| {
            assert!(matches!(
                original_source(&state.view()),
                Err(ForgeryVerificationError::UnsupportedScope)
            ));
        },
    );
}

// DATA controls of the private pure predicate only: these cannot produce an opaque
// candidate and do not stand in for original State/generation or native BLS authority.
#[test]
fn mismatch_priority_and_completed_anchor_errors_are_exact() {
    let mut rec = sample_generation_at(1, 2);
    rec.end = Some(SccpGenerationEndV1 {
        end_height: 4,
        end_timestamp_ms: 9_000,
        next_committee_root: [1; 32],
        successor_validity_ms: 1,
    });
    let qc = QcFixedV1 {
        epoch: 0,
        epoch_context: [0; 32],
        view: 0,
        block_hash: [1; 32],
        result_body: [2; 32],
        signers: 7,
    };
    let no_anchor = || panic!("E1/E2 may not consult an anchor");
    assert_eq!(
        first_mismatch(
            &retained_generation_fixture(&rec),
            4,
            5,
            &qc,
            [3; 32],
            no_anchor
        )
        .unwrap(),
        SccpForgeryRuleV1::E1
    );
    assert_eq!(
        first_mismatch(
            &retained_generation_fixture(&rec),
            4,
            1,
            &qc,
            [3; 32],
            no_anchor
        )
        .unwrap(),
        SccpForgeryRuleV1::E1
    );
    assert_eq!(
        first_mismatch(
            &retained_generation_fixture(&rec),
            4,
            4,
            &qc,
            [3; 32],
            no_anchor
        )
        .unwrap(),
        SccpForgeryRuleV1::E2
    );
    let anchor = SccpAnchorV1 {
        core_hash: [1; 32],
        result: [3; 32],
    };
    assert_eq!(
        first_mismatch(
            &retained_generation_fixture(&rec),
            4,
            3,
            &qc,
            [4; 32],
            || Ok(anchor)
        )
        .unwrap(),
        SccpForgeryRuleV1::E4
    );
    assert!(matches!(
        first_mismatch(
            &retained_generation_fixture(&rec),
            4,
            3,
            &qc,
            [3; 32],
            || Ok(anchor)
        ),
        Err(ForgeryVerificationError::NotEvidence)
    ));
    assert!(matches!(
        anchor_error(SccpAnchorLookupError::InvalidHeight),
        ForgeryVerificationError::Unavailable(_)
    ));
    assert!(matches!(
        anchor_error(SccpAnchorLookupError::WitnessRequired),
        ForgeryVerificationError::WitnessRequired
    ));
    assert!(matches!(
        anchor_error(SccpAnchorLookupError::BadWitness),
        ForgeryVerificationError::BadWitness
    ));
    assert!(matches!(
        anchor_error(SccpAnchorLookupError::EvidenceExpired),
        ForgeryVerificationError::EvidenceExpired
    ));
}

#[test]
fn generation_lookup_and_inclusive_liability_use_captured_values_only() {
    use crate::smartcontracts::isi::sccp::test_support::header;
    use iroha_data_model::sumeragi_finality::certified_result::FLAG_ACTIVE;
    let state = blank_state();
    let mut block = state.block(header(4));
    let mut stx = block.transaction();
    let mut rec = sample_generation_at(1, 1);
    let x = SccpFinalityHeaderV1::from_fields(&SccpFinalityHeaderFieldsV1 {
        network_id: [3; 32],
        height: 2,
        flags: FLAG_ACTIVE,
        generation: 1,
        committee_root: rec.committee_root,
        ..SccpFinalityHeaderFieldsV1::default()
    })
    .unwrap();
    assert!(matches!(
        generation_for_claim(Current(&*stx.world), &x, 1, 0),
        Err(ForgeryVerificationError::EvidenceExpired)
    ));
    assert!(matches!(
        generation_for_claim(Current(&*stx.world), &x, 0, 0),
        Err(ForgeryVerificationError::EvidenceUnknownGeneration)
    ));
    crate::smartcontracts::isi::sccp::test_support::install_generation(&mut stx, 1, rec.clone())
        .unwrap();
    let last = rec.liable_until_lc + rec.progress_cap_ms;
    assert!(generation_for_claim(Current(&*stx.world), &x, 2, last).is_ok());
    assert!(
        matches!(
            generation_for_claim(Current(&*stx.world), &x, 2, last + 1),
            Err(ForgeryVerificationError::EvidenceExpired)
        ),
        "SC14 expired captured generation must fail E0 before signature verification"
    );
    assert!(
        generation_for_claim(Current(&*stx.world), &x, 1, u64::MAX).is_ok(),
        "current generation remains liable"
    );
    let mut wrong_root = x.fields();
    wrong_root.committee_root[0] ^= 1;
    assert!(
        matches!(
            generation_for_claim(
                Current(&*stx.world),
                &SccpFinalityHeaderV1::from_fields(&wrong_root).unwrap(),
                2,
                u64::MAX
            ),
            Err(ForgeryVerificationError::NotEvidence)
        ),
        "root mismatch precedes E0"
    );
    rec.end = Some(SccpGenerationEndV1 {
        end_height: 2,
        end_timestamp_ms: 8_000,
        next_committee_root: rec.committee_root,
        successor_validity_ms: rec.validity_ms,
    });
    rec.dest_cleared_lc = Some(rec.liable_until_lc + 5);
    let last = rec.dest_cleared_lc.unwrap() + rec.grace_ms;
    crate::smartcontracts::isi::sccp::test_support::install_generation(&mut stx, 1, rec.clone())
        .unwrap();
    assert!(generation_for_claim(Current(&*stx.world), &x, 2, last).is_ok());
    assert!(matches!(
        generation_for_claim(Current(&*stx.world), &x, 2, last + 1),
        Err(ForgeryVerificationError::EvidenceExpired)
    ));
    // A later parameter change is not an authority to shorten the captured record's terms.
    store::parameters::set(&mut stx, None);
    assert!(generation_for_claim(Current(&*stx.world), &x, 2, last).is_ok());
}

#[test]
fn completed_chunk_uses_retained_root_and_preserves_witness_refusals() {
    use iroha_sccp::v1::evidence::{anchor_leaf, anchor_path_root};
    let rec = sample_generation_at(1, 1);
    let anchor = SccpAnchorV1 {
        core_hash: [1; 32],
        result: [3; 32],
    };
    let path = [[4; 32]; 12];
    let root =
        anchor_path_root(&anchor_leaf(2, &anchor.core_hash, &anchor.result), 1, &path).unwrap();
    let qc = QcFixedV1 {
        epoch: 0,
        epoch_context: [0; 32],
        view: 0,
        block_hash: [1; 32],
        result_body: [2; 32],
        signers: 7,
    };
    let lookup = |root, witness| {
        lookup_anchor(
            4097,
            SccpAnchorV1 {
                core_hash: [5; 32],
                result: [6; 32],
            },
            &[],
            2,
            root,
            witness,
        )
        .map_err(anchor_error)
    };
    assert_eq!(
        first_mismatch(
            &retained_generation_fixture(&rec),
            4098,
            2,
            &qc,
            [9; 32],
            || lookup(Some(&root), Some((&anchor, &path)))
        )
        .unwrap(),
        SccpForgeryRuleV1::E4
    );
    assert!(matches!(
        first_mismatch(
            &retained_generation_fixture(&rec),
            4098,
            2,
            &qc,
            [9; 32],
            || lookup(None, Some((&anchor, &path)))
        ),
        Err(ForgeryVerificationError::EvidenceExpired)
    ));
    assert!(matches!(
        first_mismatch(
            &retained_generation_fixture(&rec),
            4098,
            2,
            &qc,
            [9; 32],
            || lookup(Some(&root), None)
        ),
        Err(ForgeryVerificationError::WitnessRequired)
    ));
    let mut wrong_path = path;
    wrong_path[0][0] ^= 1;
    assert!(matches!(
        first_mismatch(
            &retained_generation_fixture(&rec),
            4098,
            2,
            &qc,
            [9; 32],
            || lookup(Some(&root), Some((&anchor, &wrong_path)))
        ),
        Err(ForgeryVerificationError::BadWitness)
    ));
}

#[test]
fn pairing_kernel_handles_maximum_committee_and_rejects_noncanonical_signer_keys() {
    use iroha_data_model::sumeragi_finality::certified_result::{FLAG_ACTIVE, committee_root};
    let stop = AtomicBool::new(false);
    let budget = AllocationBudget::new(128 << 20);
    // Pure cryptographic relation DATA; verify_signature cannot manufacture a source-bound candidate.
    for count in [4_usize, 7, 31] {
        let mut pairs = (1..=count)
            .map(|seed| {
                KeyPair::try_from_seed(vec![u8::try_from(seed).unwrap(); 32], Algorithm::BlsNormal)
                    .unwrap()
            })
            .collect::<Vec<_>>();
        pairs.sort_by_key(raw_key);
        let mut rec = sample_generation_at(1, 1);
        rec.keys = pairs.iter().map(raw_key).collect();
        rec.members = vec![None; count];
        rec.committee_root = committee_root(&rec.keys).unwrap();
        let header = SccpFinalityHeaderV1::from_fields(&SccpFinalityHeaderFieldsV1 {
            network_id: [3; 32],
            height: 2,
            flags: FLAG_ACTIVE,
            generation: 1,
            committee_root: rec.committee_root,
            ..SccpFinalityHeaderFieldsV1::default()
        })
        .unwrap();
        let quorum = count - (count - 1) / 3;
        let qc = QcFixedV1 {
            epoch: 0,
            epoch_context: [4; 32],
            view: 0,
            block_hash: [5; 32],
            result_body: [6; 32],
            signers: (1_u32 << quorum) - 1,
        };
        let mut submission = SubmitSccpForgeryEvidenceV1 {
            qc: qc.encode(),
            header: *header.as_bytes(),
            aggregate_signature: [0; 96],
            anchor: None,
        };
        let instance = Hash32([8; 32]);
        resign(&mut submission, &pairs, instance);
        verify_signature(
            &retained_generation_fixture(&rec),
            instance,
            &header,
            &qc,
            &submission.aggregate_signature,
            &budget,
            VerificationControl::Read(control(&stop)),
        )
        .unwrap();
        for invalid in [[0; 48], [0xff; 48], iroha_sccp::v1::committee::IDENTITY_KEY] {
            let mut bad = rec.clone();
            bad.keys[0] = invalid;
            assert!(matches!(
                verify_signature(
                    &retained_generation_fixture(&bad),
                    instance,
                    &header,
                    &qc,
                    &submission.aggregate_signature,
                    &budget,
                    VerificationControl::Read(control(&stop))
                ),
                Err(ForgeryVerificationError::BadSignature)
            ));
        }
        assert_eq!(budget.reserved_bytes(), 0);
    }
}

#[test]
fn candidate_from_lagging_committed_view_requires_new_parent_recheck() {
    let (mut chain, _) = active_chain();
    let state = std::sync::Arc::clone(chain.state());
    let lagging = state.view();
    chain.commit_at(3_000, Vec::new());
    let evidence = original(&chain);
    let stop = AtomicBool::new(false);
    let budget = AllocationBudget::new(128 << 20);
    let old = verify_committed(&lagging, &evidence, 3_000, &budget, control(&stop)).unwrap();
    assert_eq!(old.rule(), SccpForgeryRuleV1::E2);
    assert_eq!(old.parent().height(), 2);
    let current = state.view();
    assert!(matches!(
        verify_committed(&current, &evidence, 4_000, &budget, control(&stop)),
        Err(ForgeryVerificationError::NotEvidence)
    ));
    assert_eq!(budget.reserved_bytes(), 0);
}

#[test]
fn cheap_precheck_requires_actual_pairing_and_preserves_exact_original_observation() {
    let (chain, keys) = active_member_chain();
    let mut evidence = future(&chain, &keys);
    let view = chain.state().view();
    let budget = AllocationBudget::new(128 << 20);
    let checked = verify_prechecked(
        &prepare_committed(&view, &evidence, 3_000).unwrap(),
        &budget,
    )
    .unwrap();
    assert_eq!(checked.parent(), view.native_execution_tip().unwrap());
    assert_eq!(checked.rule(), SccpForgeryRuleV1::E2);
    assert_eq!(checked.signers().filter(|(_, _, m)| m.is_some()).count(), 3);
    evidence.aggregate_signature[0] ^= 1;
    let precheck = prepare_committed(&view, &evidence, 3_000)
        .expect("cheap stage grants no signature authority");
    assert!(matches!(
        verify_prechecked(&precheck, &budget),
        Err(ForgeryVerificationError::BadSignature)
    ));
    assert_eq!(budget.reserved_bytes(), 0);
}

#[test]
fn cheap_precheck_rejects_genuine_claim_before_original_pairing_pool() {
    let (chain, _) = active_chain();
    let evidence = original(&chain);
    let view = chain.state().view();
    assert!(matches!(
        prepare_committed(&view, &evidence, 3_000),
        Err(ForgeryVerificationError::NotEvidence)
    ));
}

#[test]
fn proposal_recheck_requires_same_original_parent_and_preserves_local_refusal() {
    let (chain, keys) = active_member_chain();
    let evidence = future(&chain, &keys);
    let view = chain.state().view();
    let budget = AllocationBudget::new(128 << 20);
    let current = chain.committed(chain.height());
    verify_for_proposal(&view, current.block(), &evidence, 3_000, &budget).unwrap();
    let original = original(&chain);
    assert!(
        verify_for_proposal(&view, current.block(), &original, 3_000, &budget)
            .unwrap_err()
            .is_protocol_rejection()
    );
    let earlier = chain.committed(1);
    let wrong = verify_for_proposal(&view, earlier.block(), &evidence, 3_000, &budget).unwrap_err();
    assert!(!wrong.is_protocol_rejection());
    assert!(wrong.into_local_refusal().is_ok());
    let bytes = ConsensusAggregateScratch::<()>::backing_bytes();
    let scarce = AllocationBudget::new(bytes);
    let occupied = scarce.try_reserve_bytes(bytes).unwrap();
    let refusal =
        verify_for_proposal(&view, current.block(), &evidence, 3_000, &scarce).unwrap_err();
    assert!(!refusal.is_protocol_rejection());
    let ForgeryLocalRefusal::Storage(crate::state::StateStorageAdmissionError::SccpEvidence(
        crate::state::EvidencePreparationError::Admission(refused),
    )) = refusal.into_local_refusal().unwrap()
    else {
        panic!("original pairing refusal, not protocol rejection")
    };
    assert!(matches!(refused, AllocationRefusal::Capacity { .. }));
    drop(occupied);
}
