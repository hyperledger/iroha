//! Genuine executed native Check readback, original ownership and current-cut refusals.

use super::*;
use crate::{
    state::World,
    sumeragi::test_chain::{CertifiedTestChain, Signers, TestChainConfig},
};
use iroha_crypto::{Algorithm, Hash, HashOf, KeyPair};
use iroha_data_model::{
    isi::{InstructionBox, Log, musubi::AdvanceMusubiPinOutboxV1},
    transaction::TransactionEntrypoint,
};
use std::time::Duration;

struct Fixture {
    chain: CertifiedTestChain,
    key: KeyPair,
}

impl Fixture {
    fn genesis() -> Self {
        let key = KeyPair::from_seed(vec![0x91; 32], Algorithm::Ed25519);
        let mut configuration = TestChainConfig::new(World::new(), 1_000);
        configuration.genesis_key = key.clone();
        Self {
            chain: CertifiedTestChain::start(configuration).unwrap(),
            key,
        }
    }
    fn new() -> Self {
        let mut fixture = Self::genesis();
        fixture.log();
        fixture
    }
    fn log(&mut self) {
        let signed = self.sign(
            Log::new(
                iroha_logger::Level::INFO,
                "native readback source".to_owned(),
            )
            .into(),
        );
        assert!(self.chain.commit(vec![signed])[0]);
    }
    fn authority(&self) -> AccountId {
        AccountId::new(self.key.public_key().clone())
    }
    fn sign(&self, instruction: InstructionBox) -> SignedTransaction {
        self.chain.sign(
            &self.key,
            [instruction],
            self.chain.committed(self.chain.height()).block_time_ms() + 1,
        )
    }
    fn row(&self) -> Option<MusubiPinOutboxHighWaterV1> {
        self.chain
            .state()
            .view()
            .world
            .musubi_pin_outbox_high_waters()
            .get(&self.authority())
            .cloned()
    }
    fn expected(&self) -> MusubiPinOutboxCheckExpectedV1 {
        let floor = self.chain.committed(self.chain.height());
        let row = self.row();
        MusubiPinOutboxCheckExpectedV1 {
            chain_id: self.chain.state().chain_id_ref().clone(),
            network_id: self.chain.network_id(),
            pin_authority: self.authority(),
            session_id: [0x71; 32],
            inventory_digest: row.as_ref().map_or([0x72; 32], |row| row.inventory_digest),
            floor: MusubiPinOutboxCheckFloorV1 {
                height: floor.height(),
                block_hash: *floor.block_hash().as_ref(),
                context_id: floor.id(),
            },
            expected: row.map_or(
                MusubiPinOutboxCheckExpectationV1::Absent,
                MusubiPinOutboxCheckExpectationV1::Present,
            ),
        }
    }
    fn prepare(&self) -> PreparedMusubiPinOutboxCheckV1 {
        begin_musubi_pin_outbox_check_v1(
            Arc::clone(self.chain.state()),
            self.expected(),
            Instant::now() + Duration::from_secs(60),
        )
        .unwrap()
    }
    fn pending(&self) -> PendingMusubiPinOutboxCheckV1 {
        let prepared = self.prepare();
        let signed = self.sign(prepared.instruction().clone().into());
        prepared.bind_signed_transaction(signed).unwrap()
    }
    fn applied(&mut self) -> PendingMusubiPinOutboxCheckV1 {
        let pending = self.pending();
        assert!(
            self.chain
                .commit(vec![pending.signed_transaction().clone()])[0]
        );
        pending
    }
    fn advance(&mut self, digest: [u8; 32]) {
        let row = self.row();
        let instruction = AdvanceMusubiPinOutboxV1 {
            network_id: self.chain.network_id(),
            pin_authority: self.authority(),
            session_id: [0x71; 32],
            expected_revision: row.as_ref().map_or(0, |row| row.revision),
            expected_inventory_digest: row.as_ref().map_or([0; 32], |row| row.inventory_digest),
            inventory_digest: digest,
        };
        let signed = self.sign(instruction.into());
        assert!(self.chain.commit(vec![signed])[0]);
    }
}

fn exact(pending: &PendingMusubiPinOutboxCheckV1) -> Vec<u8> {
    norito::encode_canonical(&TransactionEntrypoint::External(
        pending.signed_transaction().clone(),
    ))
    .unwrap()
}

#[test]
fn native_readback_proves_authority_wide_absence_and_complete_present_row() {
    let mut f = Fixture::new();
    for present in [false, true] {
        if present {
            f.advance([0x72; 32]);
        }
        let expected = f.row();
        let pending = f.applied();
        let bytes = exact(&pending);
        let tip = f.chain.committed(f.chain.height());
        let readback = pending
            .verify_finalized()
            .unwrap()
            .consume_current(f.chain.state())
            .unwrap();
        assert_eq!(readback.high_water(), expected.as_ref());
        assert_eq!(readback.canonical_external(), bytes);
        assert_eq!(readback.check_block_hash(), *tip.block_hash().as_ref());
        assert_eq!(readback.applied_floor().context_id, tip.id());
        assert_eq!(readback.applied_floor().height, f.chain.height());
        assert_eq!(readback.instruction().pin_authority, f.authority());
        assert_eq!(f.row(), expected, "Check does not mutate the high-water");
    }
    let mut false_absence = f.expected();
    false_absence.expected = MusubiPinOutboxCheckExpectationV1::Absent;
    false_absence.session_id = [0x81; 32];
    false_absence.inventory_digest = [0x82; 32];
    assert!(matches!(begin_musubi_pin_outbox_check_v1(
        Arc::clone(f.chain.state()),
        false_absence,
        Instant::now() + Duration::from_secs(60)
    )
    .err(), Some(crate::execution_attempt::ExecutionAttemptError::Rejected(actual_rejection)) if actual_rejection == (
        Error::CurrentState
    )));
    let mut changed_row = f.expected();
    let MusubiPinOutboxCheckExpectationV1::Present(row) = &mut changed_row.expected else {
        unreachable!()
    };
    row.transaction_hash = [0x83; 32];
    assert!(matches!(begin_musubi_pin_outbox_check_v1(
        Arc::clone(f.chain.state()),
        changed_row,
        Instant::now() + Duration::from_secs(60)
    )
    .err(), Some(crate::execution_attempt::ExecutionAttemptError::Rejected(actual_rejection)) if actual_rejection == (
        Error::CurrentState
    )));
}

#[test]
fn early_read_retains_original_paid_check_until_same_transaction_is_applied() {
    let mut f = Fixture::new();
    let pending = f.pending();
    let deadline = pending.deadline();
    let original = exact(&pending);
    let failure = pending.verify_finalized().err().unwrap();
    assert_eq!(failure.rejection(), Some(Error::NotApplied));
    let pending = failure.into_pending();
    assert_eq!(pending.deadline(), deadline);
    assert_eq!(exact(&pending), original);
    assert!(f.chain.commit(vec![pending.signed_transaction().clone()])[0]);
    let readback = pending
        .verify_finalized()
        .unwrap()
        .consume_current(f.chain.state())
        .unwrap();
    assert_eq!(readback.canonical_external(), original);
    assert!(readback.high_water().is_none());
}

#[test]
fn native_source_and_quota_refusals_retain_original_bytes_deadline_and_challenge() {
    let mut f = Fixture::new();
    let pending = f.applied();
    let original = exact(&pending);
    let deadline = pending.deadline();
    let zero = norito::DecodeLimits::new(usize::MAX, usize::MAX, usize::MAX, 0, 128);
    let failure = norito::with_decode_limits_scope(zero, || pending.verify_finalized())
        .err()
        .unwrap();
    assert!(matches!(
        failure.error(),
        crate::execution_attempt::ExecutionAttemptError::Deferred(_)
    ));
    let pending = failure.into_pending();
    assert_eq!(exact(&pending), original);
    assert_eq!(pending.deadline(), deadline);
    let source_height = f.chain.height();
    let original_qc = f
        .chain
        .committed(source_height)
        .block()
        .commit_certificate()
        .unwrap()
        .commit_qc()
        .to_vec();
    f.chain
        .corrupt_local_quorum_for_test(source_height, Signers::BelowQuorum);
    let failure = pending.verify_finalized().err().unwrap();
    assert_eq!(failure.rejection(), Some(Error::Finality));
    let pending = failure.into_pending();
    // Restore exactly the original stored QC; do not manufacture a replacement certificate.
    f.chain
        .kura()
        .corrupt_commit_certificate_for_testing(
            core::num::NonZeroUsize::new(usize::try_from(source_height).unwrap()).unwrap(),
            Some(original_qc),
        )
        .unwrap();
    assert_eq!(exact(&pending), original);
    assert_eq!(pending.deadline(), deadline);
    let verified = pending.verify_finalized().unwrap();
    let failure =
        norito::with_decode_limits_scope(zero, || verified.consume_current(f.chain.state()))
            .err()
            .unwrap();
    assert!(matches!(
        failure.error(),
        crate::execution_attempt::ExecutionAttemptError::Deferred(_)
    ));
    let pending = failure.into_pending();
    assert_eq!(pending.deadline(), deadline);
    assert_eq!(exact(&pending), original);
    assert_eq!(
        pending
            .verify_finalized()
            .unwrap()
            .consume_current(f.chain.state())
            .unwrap()
            .canonical_external(),
        original
    );
}

#[test]
fn current_row_and_publication_changes_require_fresh_native_verification() {
    let mut f = Fixture::new();
    let pending = f.applied();
    let original = exact(&pending);
    let deadline = pending.deadline();
    let verified = pending.verify_finalized().unwrap();
    f.log();
    let failure = verified.consume_current(f.chain.state()).err().unwrap();
    assert_eq!(failure.rejection(), Some(Error::CurrentState));
    let pending = failure.into_pending();
    assert_eq!(pending.deadline(), deadline);
    assert_eq!(exact(&pending), original);
    let verified = pending.verify_finalized().unwrap();
    f.advance([0x72; 32]);
    let failure = verified.consume_current(f.chain.state()).err().unwrap();
    assert_eq!(failure.rejection(), Some(Error::CurrentState));
    let failure = failure.into_pending().verify_finalized().err().unwrap();
    assert_eq!(
        failure.rejection(),
        Some(Error::CurrentState),
        "fresh proof cannot reinterpret the original Absent expectation"
    );
    let pending = f.applied();
    f.advance([0x73; 32]);
    assert_eq!(
        pending.verify_finalized().err().unwrap().rejection(),
        Some(Error::CurrentState),
        "complete original Present row remains fixed"
    );
}

#[test]
fn equal_byte_foreign_views_and_recipient_states_never_supply_original_authority() {
    let mut f = Fixture::new();
    let pending = f.applied();
    let view = f.chain.state().view();
    let foreign_view = f.chain.state().view();
    let mut original_bound = Some(pending.bound);
    let mut proof = PreparedCheckExecutionV1::new(
        &view,
        NativeCustodyCheckPurposeV1::MusubiPinOutbox,
        &mut original_bound,
        &pending.prepared.round,
    )
    .unwrap();
    let foreign = SignerCertifiedWalkV1::new(&foreign_view).unwrap();
    let receipt = foreign
        .walk(proof.floor_height(), proof.applied_height())
        .next()
        .unwrap()
        .unwrap();
    assert!(
        matches!(proof.consume(&receipt), Err(crate::execution_attempt::ExecutionAttemptError::Rejected(actual_rejection)) if actual_rejection == (
            NativeCheckErrorV1::Finality
        ))
    );
    drop(receipt);
    drop(foreign);
    drop(foreign_view);
    drop(view);
    let pending = f.applied();
    let original = exact(&pending);
    let mut other = Fixture::genesis();
    other.chain.replay_from(&f.chain).unwrap();
    assert_eq!(
        other.chain.committed(other.chain.height()).id(),
        f.chain.committed(f.chain.height()).id()
    );
    let verified = pending.verify_finalized().unwrap();
    let zero = norito::DecodeLimits::new(usize::MAX, usize::MAX, usize::MAX, 0, 128);
    let failure =
        norito::with_decode_limits_scope(zero, || verified.consume_current(other.chain.state()))
            .err()
            .unwrap();
    assert_eq!(
        failure.rejection(),
        Some(Error::CurrentState),
        "recipient identity precedes history/decoder admission"
    );
    let pending = failure.into_pending();
    assert_eq!(exact(&pending), original);
    let same_owner = Arc::clone(f.chain.state());
    assert_eq!(
        pending
            .verify_finalized()
            .unwrap()
            .consume_current(&same_owner)
            .unwrap()
            .canonical_external(),
        original
    );
}

#[test]
fn exact_binding_and_original_deadline_cannot_be_replaced() {
    let mut f = Fixture::new();
    let prepared = f.prepare();
    let mut changed = prepared.instruction().clone();
    changed.challenge[0] ^= 1;
    let changed = f.sign(changed.into());
    assert_eq!(
        prepared
            .bind_signed_transaction(changed)
            .err()
            .and_then(|failure| failure.rejection()),
        Some(Error::Transaction)
    );
    let pending = f.applied();
    let original = exact(&pending);
    let mut pending = pending;
    pending.prepared.round.expire_for_test();
    let expired = pending.deadline();
    for _ in 0..2 {
        let failure = pending.verify_finalized().err().unwrap();
        assert_eq!(failure.rejection(), Some(Error::Expired));
        pending = failure.into_pending();
        assert_eq!(pending.deadline(), expired);
        assert_eq!(exact(&pending), original);
    }
}

#[test]
fn original_floor_and_global_network_chain_are_independently_required() {
    let mut f = Fixture::genesis();
    let expected = f.expected();
    assert!(matches!(begin_musubi_pin_outbox_check_v1(
        Arc::clone(f.chain.state()),
        f.expected(),
        Instant::now() + Duration::from_secs(60)
    )
    .err(), Some(crate::execution_attempt::ExecutionAttemptError::Rejected(actual_rejection)) if actual_rejection == (
        Error::Finality
    )));
    f.log();
    let prepared = begin_musubi_pin_outbox_check_v1(
        Arc::clone(f.chain.state()),
        expected,
        Instant::now() + Duration::from_secs(60),
    )
    .unwrap();
    assert_eq!(
        prepared.instruction().floor.height,
        1,
        "genuine H2 now authenticates original genesis execution"
    );
    for field in 0..4 {
        let mut expected = f.expected();
        match field {
            0 => expected.chain_id = ChainId::from("another-chain"),
            1 => {
                expected.network_id = NetworkId::from_genesis_hash(HashOf::from_untyped_unchecked(
                    Hash::new(b"another network"),
                ))
            }
            2 => expected.floor.block_hash = [0x54; 32],
            3 => expected.floor.context_id = f.chain.committed(1).id(),
            _ => unreachable!(),
        }
        assert!(
            begin_musubi_pin_outbox_check_v1(
                Arc::clone(f.chain.state()),
                expected,
                Instant::now() + Duration::from_secs(60)
            )
            .is_err()
        );
    }
    assert!(matches!(
        begin_musubi_pin_outbox_check_v1(
            Arc::clone(f.chain.state()),
            f.expected(),
            Instant::now()
                .checked_sub(Duration::from_secs(1))
                .expect("fixture clock supports the original expired deadline")
        )
        .err(),
        Some(crate::execution_attempt::ExecutionAttemptError::Rejected(
            Error::Expired
        ))
    ));
}

#[test]
fn completed_proof_retains_exact_original_backing_without_a_second_allocation() {
    let mut f = Fixture::new();
    let pending = f.applied();
    let original = exact(&pending);
    let deadline = pending.deadline();
    let view = f.chain.state().view();
    let mut original_bound = Some(pending.bound);
    let mut proof = PreparedCheckExecutionV1::new(
        &view,
        NativeCustodyCheckPurposeV1::MusubiPinOutbox,
        &mut original_bound,
        &pending.prepared.round,
    )
    .unwrap();
    let reader = SignerCertifiedWalkV1::new(&view).unwrap();
    for receipt in reader.walk(proof.floor_height(), proof.applied_height()) {
        proof.consume(&receipt.unwrap()).unwrap();
    }
    let zero = norito::DecodeLimits::new(usize::MAX, usize::MAX, usize::MAX, 0, 128);
    let cut = match norito::with_decode_limits_scope(zero, || proof.finish()) {
        Ok(success) => success,
        Err(error) => {
            panic!("metadata-only finish must not allocate a second canonical frame: {error:?}")
        }
    };
    assert_ne!(cut.check_block_hash(), [0; 32]);
    drop(reader);
    drop(view);
    let pending = PendingMusubiPinOutboxCheckV1 {
        prepared: pending.prepared,
        bound: original_bound
            .take()
            .expect("finish retained original slot"),
    };
    assert_eq!(pending.deadline(), deadline);
    assert_eq!(exact(&pending), original);
    assert_eq!(
        pending
            .verify_finalized()
            .unwrap()
            .consume_current(f.chain.state())
            .unwrap()
            .canonical_external(),
        original
    );
}

fn private_fixture() -> (CertifiedTestChain, KeyPair) {
    use iroha_data_model::{
        Registrable,
        account::Account,
        asset::{
            Asset, AssetBalancePolicy, AssetBalanceScope, AssetDefinition, AssetDefinitionId,
            AssetId,
        },
        block::consensus::PrivateRootFeePolicy,
        domain::Domain,
        nexus::{DataSpaceCatalog, DataSpaceMetadata, LaneCatalog, LaneConfig, LaneVisibility},
        parameter::Parameter,
    };
    use iroha_model_base::topology::DataSpaceId;

    let ds = DataSpaceId::new(u64::MAX - 15);
    let key = KeyPair::from_seed(vec![0xcc; 32], Algorithm::Ed25519);
    let owner = AccountId::new(key.public_key().clone());
    let domain =
        iroha_model_base::domain::DomainId::parse_fully_qualified("app.private-pin-test").unwrap();
    let asset = AssetDefinitionId::derive_from_components(domain.clone(), "gas".parse().unwrap());
    let mut definition = AssetDefinition::numeric(
        asset.clone(),
        "Private gas",
        AssetBalancePolicy::DataspaceRestricted,
        Some(domain.clone()),
    )
    .build(&owner);
    definition.total_quantity = 1_000_000_u32.into();
    let world = World::with_assets(
        [Domain::new(domain).build(&owner)],
        [Account::new(owner.clone()).build(&owner)],
        [definition],
        [Asset::new(
            AssetId::with_scope(asset.clone(), owner, AssetBalanceScope::Dataspace(ds)),
            1_000_000_u32,
        )],
        [],
    );
    let mut configuration = TestChainConfig::new(world, 1_000);
    configuration.genesis_parameters.push(Parameter::Custom(
        PrivateRootFeePolicy {
            asset_definition_id: asset.clone(),
            base_fee: 1_u32.into(),
            per_byte_fee: 0_u32.into(),
            per_instruction_fee: 1_u32.into(),
            per_gas_unit_fee: 1_u32.into(),
        }
        .into_custom_parameter()
        .unwrap(),
    ));
    configuration.root_scope = SumeragiRootScope::Dataspace {
        parent_network_id: iroha_data_model::NetworkId::from_genesis_hash(
            HashOf::from_untyped_unchecked(Hash::new(b"independent public parent")),
        ),
        dataspace_id: ds,
    };
    let mut nexus = iroha_config::parameters::actual::Nexus::default();
    nexus.fees.fee_asset_id = asset.to_string();
    nexus.lane_catalog = LaneCatalog::new(
        std::num::NonZeroU32::new(1).unwrap(),
        vec![LaneConfig {
            dataspace_id: ds,
            visibility: LaneVisibility::Restricted,
            ..LaneConfig::default()
        }],
    )
    .unwrap();
    nexus.configured_lane_catalog = nexus.lane_catalog.clone();
    nexus.lane_config =
        iroha_config::parameters::actual::LaneConfig::from_catalog(&nexus.lane_catalog);
    nexus.dataspace_catalog = DataSpaceCatalog::new(vec![DataSpaceMetadata {
        id: ds,
        alias: "private-pin-test".into(),
        description: None,
        fault_tolerance: 1,
    }])
    .unwrap();
    nexus.configured_dataspace_catalog = nexus.dataspace_catalog.clone();
    nexus.routing_policy.default_dataspace = ds;
    configuration.nexus = Some(nexus);
    (CertifiedTestChain::start(configuration).unwrap(), key)
}

#[test]
fn genuine_private_root_with_native_floor_and_equal_chain_label_is_refused() {
    let (chain, key) = private_fixture();
    let mut private = Fixture { chain, key };
    private.log();
    let global = Fixture::new();
    assert_eq!(
        private.chain.state().chain_id_ref(),
        global.chain.state().chain_id_ref()
    );
    let view = private.chain.state().view();
    let reader = crate::sumeragi::certified_chain::CertifiedChain::new_with_source_admission(
        &view,
        |_, _| Ok(()),
    )
    .unwrap();
    let receipt = reader
        .certified_from_execution(
            std::num::NonZeroUsize::new(
                usize::try_from(private.chain.height()).expect("fixture value fits usize"),
            )
            .unwrap(),
            |_, _| Ok(()),
        )
        .unwrap();
    assert_ne!(
        receipt.header().unwrap().instance,
        SumeragiRootScope::Global
            .instance_id(
                &BlsCrypto::new(),
                private.chain.network_id(),
                private.chain.state().chain_id_ref().as_str()
            )
            .unwrap()
    );
    assert!(matches!(begin_musubi_pin_outbox_check_v1(
        Arc::clone(private.chain.state()),
        private.expected(),
        Instant::now() + Duration::from_secs(60)
    )
    .err(), Some(crate::execution_attempt::ExecutionAttemptError::Rejected(actual_rejection)) if actual_rejection == (
        Error::Finality
    )));
}

mod binding_custody;

#[test]
fn original_state_verification_refusal_retains_exact_frame_and_signed_graph() {
    use crate::execution_attempt::ExecutionAttemptError;
    use iroha_allocation::AllocationRefusal;
    // Views can reclaim old published State generations from this same pool. Keep those
    // real EBR owners alive so only this Check's admissions change the exact counters below.
    let _retirement_pin = crossbeam_epoch::pin();
    let mut fixture = Fixture::new();
    let pending = fixture.applied();
    let budget = fixture.chain.state().ivm_execution_budget();
    let retained = budget.reserved_bytes();
    let deadline = pending.deadline();
    let challenge = pending.prepared.instruction.challenge;
    let frame = pending.bound.canonical_external().as_ptr();
    let signed = match pending.signed_transaction().instructions() {
        iroha_data_model::transaction::Executable::Instructions(instructions) => {
            instructions.as_ptr()
        }
        _ => panic!("native instruction owner"),
    };
    let held = budget
        .try_reserve_bytes(budget.limit_bytes() - retained)
        .unwrap();
    let failure = pending.verify_finalized().err().unwrap();
    assert!(
        matches!(failure.error(), ExecutionAttemptError::Deferred(original)
        if matches!(original.allocation_refusal(), Some(AllocationRefusal::Capacity { .. })))
    );
    assert!(failure.is_retryable());
    assert_eq!(failure.deadline(), deadline);
    drop(held);
    assert_eq!(budget.reserved_bytes(), retained);
    let pending = failure.into_pending();
    assert!(Arc::ptr_eq(&pending.prepared.state, fixture.chain.state()));
    assert_eq!(pending.prepared.instruction.challenge, challenge);
    assert_eq!(pending.bound.canonical_external().as_ptr(), frame);
    match pending.signed_transaction().instructions() {
        iroha_data_model::transaction::Executable::Instructions(instructions) => {
            assert_eq!(instructions.as_ptr(), signed)
        }
        _ => panic!("same native instruction owner"),
    }
    let readback = pending
        .verify_finalized()
        .unwrap()
        .consume_current(fixture.chain.state())
        .unwrap();
    assert_eq!(
        readback.canonical_external().as_ptr(),
        frame,
        "successful discharge takes exactly the originally borrowed frame"
    );
    assert_eq!(budget.reserved_bytes(), retained);
    let frame_len = readback.canonical_external().len();
    drop(readback);
    assert_eq!(budget.reserved_bytes(), retained - frame_len);
}
