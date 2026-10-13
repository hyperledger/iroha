//! Genuine paid native Check/Advance and ordinary Queue component controls.
//!
//! The archive bytes used for this component are deliberately not source authority. These tests
//! invoke the private Check/Advance owner directly, and separately prove the public path refuses
//! that foreign archive before effects. They do not claim successful pin/three-provider publication.

use super::*;
use iroha_config::parameters::actual::{Nexus, Queue as QueueConfig};
use iroha_core::{
    executor::quote_nexus_fee_admission_draft,
    state::World,
    sumeragi::test_chain::{CertifiedTestChain, TestChainConfig},
};
use iroha_crypto::Algorithm;
use iroha_data_model::{
    Registrable,
    account::{Account, AccountId},
    asset::{AssetBalancePolicy, AssetDefinition, AssetId},
    isi::{Log, Mint, Register},
    transaction::{
        FeeChargeKind, FeeChargeLimit, FeePaymentIntent, SignedTransaction, TransactionBuilder,
    },
};
use iroha_model_base::topology::DataSpaceId;
use iroha_primitives::{numeric::Quantity, time::TimeSource};
use std::{
    collections::BTreeMap,
    time::{Duration, SystemTime, UNIX_EPOCH},
};

fn now() -> u64 {
    u64::try_from(
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_millis(),
    )
    .unwrap()
}
struct Clock;
impl MusubiPublicationServiceClockV1 for Clock {
    fn current_time_ms(
        &mut self,
    ) -> std::result::Result<u64, iroha_musubi_service::MusubiPublicationServiceBackendErrorV1>
    {
        Ok(now())
    }
}
struct Fixture {
    coordinator: NativeMusubiPinCoordinatorV1,
    chain: CertifiedTestChain,
    context: MusubiPublicationPrivateServiceContextV1,
    key: KeyPair,
    asset: iroha_data_model::asset::AssetDefinitionId,
    sink: AccountId,
    original: Operation,
    root: tempfile::TempDir,
}
impl Fixture {
    fn new() -> Self {
        let key = KeyPair::from_seed(vec![0xA6; 32], Algorithm::Ed25519);
        let owner = AccountId::new(key.public_key().clone());
        let sink = AccountId::new(
            KeyPair::from_seed(vec![0xA7; 32], Algorithm::Ed25519)
                .public_key()
                .clone(),
        );
        let world = World::with(
            [],
            [
                Account::new(owner.clone()).build(&owner),
                Account::new(sink.clone()).build(&sink),
            ],
            [],
        );
        // Global fee admission binds the canonical XOR identity of this signed root.
        let asset = iroha_data_model::asset::AssetDefinitionId::parse_address_literal(
            &iroha_config::parameters::defaults::nexus::fees::fee_asset_id(),
        )
        .expect("canonical global XOR fee asset");
        let mut configuration = TestChainConfig::new(world, now().saturating_sub(10_000));
        let mut nexus = Nexus::default();
        nexus.fees.base_fee = Quantity::from(1u32);
        nexus.fees.per_instruction_fee = Quantity::from(1u32);
        nexus.fees.per_byte_fee = Quantity::zero();
        nexus.fees.per_gas_unit_fee = Quantity::zero();
        nexus.fees.fee_asset_id = asset.to_string();
        nexus.fees.fee_sink_account_id = sink.to_string();
        configuration.nexus = Some(nexus);
        configuration.genesis_instructions = vec![
            Register::asset_definition(AssetDefinition::numeric(
                asset.clone(),
                "Native pin fees",
                AssetBalancePolicy::Global,
                None,
            ))
            .into(),
            Mint::asset_quantity(
                Quantity::from(100u32),
                AssetId::of(asset.clone(), owner.clone()),
            )
            .into(),
        ];
        let mut chain = CertifiedTestChain::start(configuration).unwrap();
        let log = quoted(
            &chain,
            &key,
            Log::new(iroha_logger::Level::INFO, "native pin component".to_owned()).into(),
        );
        assert_eq!(chain.commit(vec![log]), [true]);
        assert_eq!(chain.height(), 2);
        let root = tempfile::tempdir().unwrap();
        let (events, _) = tokio::sync::broadcast::channel(16);
        let queue = Arc::new(Queue::from_config(QueueConfig::default(), events));
        let node = sorafs_node::NodeHandle::new(
            sorafs_node::config::StorageConfig::builder()
                .data_dir(root.path().join("storage"))
                .build(),
        );
        let context = MusubiPublicationPrivateServiceContextV1::new(
            chain.network_id(),
            Arc::clone(chain.state()),
            queue,
            node,
        );
        let mut coordinator = NativeMusubiPinCoordinatorV1::initialize(
            &context,
            &root.path().join("pins"),
            [0xA8; 32],
            policy(&key),
            key.clone(),
        )
        .unwrap();
        let mut source = super::super::finality::tests::reader_fixture().query;
        // Only retained component bytes. The public advance test verifies this fails native
        // source authentication; no current archive or pin success is synthesized here.
        source.network_id = chain.network_id();
        coordinator
            .prepare_operation(
                [0xA9; 32],
                [0x51; 32],
                &source,
                NativePinAuthorizationV1 {
                    deadline_unix_ms: now() + 600_000,
                    max_check_rounds: 4,
                    per_transaction: FeePaymentIntent::authority(
                        vec![FeeChargeLimit::new(
                            FeeChargeKind::Nexus,
                            asset.clone(),
                            Quantity::from(2u32),
                        )],
                        None,
                    ),
                    max_total_fees: BTreeMap::from([(asset.clone(), Quantity::from(20u32))]),
                },
            )
            .unwrap();
        let original = coordinator.store.operation([0xA9; 32]).unwrap();
        Self {
            coordinator,
            chain,
            context,
            key,
            asset,
            sink,
            original,
            root,
        }
    }
    fn balance(&self, account: &AccountId) -> Quantity {
        self.chain
            .state()
            .view()
            .world
            .assets()
            .get(&AssetId::of(self.asset.clone(), account.clone()))
            .map_or_else(Quantity::zero, |balance| balance.as_ref().clone())
    }
    fn commit_only_queued(&mut self) -> Vec<u8> {
        let queued = self
            .context
            .queue()
            .all_transactions(&self.chain.state().view())
            .collect::<Vec<_>>();
        assert_eq!(queued.len(), 1, "one ordinary queued original");
        let iroha_data_model::transaction::TransactionEntrypoint::External(signed) =
            queued.into_iter().next().unwrap().into_entrypoint()
        else {
            panic!("the original pin queue fixture authors an external input");
        };
        let wire = signed.encode_wire_v1().unwrap();
        assert_eq!(self.chain.commit(vec![signed]), [true]);
        assert_eq!(
            self.chain
                .committed(self.chain.height())
                .block()
                .network_entrypoint_count(),
            1
        );
        wire
    }
}
fn policy(key: &KeyPair) -> MusubiPublicationPaidPinPolicy {
    MusubiPublicationPaidPinPolicy {
        storage_class: StorageClass::Hot,
        retention_horizon_secs: 30 * 24 * 60 * 60,
        transaction_authority: AccountId::new(key.public_key().clone()),
    }
}
fn quoted(
    chain: &CertifiedTestChain,
    key: &KeyPair,
    instruction: InstructionBox,
) -> SignedTransaction {
    let builder = TransactionBuilder::new_with_time_source(
        chain.network_id(),
        AccountId::new(key.public_key().clone()),
        &TimeSource::new_fixed(Duration::from_millis(now())),
        FeePaymentIntent::authority(vec![], None),
    )
    .with_instructions([instruction]);
    let view = chain.state().view();
    let quote = quote_nexus_fee_admission_draft(
        view.world(),
        view.nexus(),
        view.pipeline(),
        &view.zk().gas,
        builder.payload(),
        view.authenticated_query_ledger_time_ms().unwrap(),
        iroha_core::smartcontracts::isi::sccp::hold::committed_time_ms(&view)
            .expect("original native quote time"),
        chain.height() + 1,
        Some(DataSpaceId::UNIVERSAL),
    )
    .unwrap();
    builder
        .with_fee_payment_intent(quote.recommended_intent)
        .sign(key.private_key())
}

fn retain_codec_only_pin(f: &mut Fixture, operation: &Operation) -> Vec<u8> {
    use sorafs_manifest::{DagCodecId, ManifestBuilder, PinPolicy, ProfileId};
    let source = operation.source().unwrap();
    let archive = &source.registration.commitment;
    let selected_at = now();
    // This exact signed pin is local custody only: its foreign archive never becomes a native
    // pin. The real paid Advance below anchors the authority's complete local inventory hash.
    let manifest = ManifestBuilder::new()
        .root_cid(archive.root_cid.as_bytes().to_vec())
        .dag_codec(DagCodecId(sorafs_manifest::MANIFEST_DAG_CODEC))
        .chunking_from_registry(ProfileId(archive.chunker.profile_id))
        .chunk_digest_sha3_256(*archive.chunk_plan_digest.as_bytes())
        .por_root(*archive.por_root.as_bytes())
        .content_length(archive.content_length)
        .car_digest(*archive.car_digest.as_bytes())
        .car_size(archive.car_size)
        .pin_policy(PinPolicy {
            min_replicas: 3,
            storage_class: sorafs_manifest::StorageClass::Hot,
            retention_epoch: selected_at.div_ceil(1_000)
                + iroha_data_model::transaction::DEFAULT_TRANSACTION_TIME_TO_LIVE.as_secs()
                + policy(&f.key).retention_horizon_secs,
        })
        .build()
        .unwrap();
    let instruction: InstructionBox =
        RegisterPinManifest::new(manifest.encode().unwrap(), None, None).into();
    let mut request = f
        .coordinator
        .request(operation, SlotKind::Pin, &instruction)
        .unwrap();
    request.pin_selected_at_unix_ms = Some(selected_at);
    let payload = TransactionBuilder::new_with_time_source(
        f.chain.network_id(),
        AccountId::new(f.key.public_key().clone()),
        &TimeSource::new_fixed(Duration::from_millis(selected_at)),
        FeePaymentIntent::authority(Vec::new(), None),
    )
    .with_instructions([instruction])
    .into_payload()
    .unwrap();
    let mut slot = f.coordinator.store.create_slot(operation, request).unwrap();
    f.coordinator
        .store
        .admit_payload(operation, &slot, &payload)
        .unwrap();
    slot.retain_payload(&payload).unwrap();
    slot.sign_original(&f.key, &mut Clock, Instant::now() + Duration::from_secs(30))
        .unwrap();
    let exact_wire = slot.signed().unwrap().encode_wire_v1().unwrap();
    drop(slot);
    exact_wire
}

#[test]
fn actual_native_high_water_refuses_lost_signed_inventory_and_missing_operation_on_reopen() {
    let mut f = Fixture::new();
    let operation = f.coordinator.store.operation(f.original.id).unwrap();
    let exact_wire = retain_codec_only_pin(&mut f, &operation);
    let operation = f.coordinator.store.operation(f.original.id).unwrap();
    assert!(
        f.coordinator
            .begin_round(operation, now(), Instant::now() + Duration::from_secs(30))
            .unwrap_err()
            .to_string()
            .contains("absence cannot replace retained signed inventory")
    );
    assert!(f.coordinator.round.is_none());
    let inventory = f.coordinator.store.inventory(None).unwrap();
    assert_eq!(inventory.signed_pins, 1);
    let advance = quoted(
        &f.chain,
        &f.key,
        AdvanceMusubiPinOutboxV1 {
            network_id: f.chain.network_id(),
            pin_authority: AccountId::new(f.key.public_key().clone()),
            session_id: [0xA8; 32],
            expected_revision: 0,
            expected_inventory_digest: [0; 32],
            inventory_digest: inventory.digest,
        }
        .into(),
    );
    assert_eq!(f.chain.commit(vec![advance]), [true]);
    let owner = AccountId::new(f.key.public_key().clone());
    let row = f
        .chain
        .state()
        .view()
        .world
        .musubi_pin_outbox_high_waters()
        .get(&owner)
        .unwrap()
        .clone();
    assert_eq!(row.inventory_digest, inventory.digest);
    let path = f.root.path().join("pins");
    drop(f.coordinator);
    let reopened = NativeMusubiPinCoordinatorV1::open(
        &f.context,
        &path,
        [0xA8; 32],
        policy(&f.key),
        f.key.clone(),
    )
    .unwrap();
    let slot = reopened
        .store
        .open_slot(&f.original, SlotKind::Pin)
        .unwrap()
        .unwrap();
    assert_eq!(slot.signed().unwrap().encode_wire_v1().unwrap(), exact_wire);
    drop(slot);
    drop(reopened);
    // Explicit offline-loss specimen. No process reinitializes the missing signed history.
    let operation_path = path.join(format!("op-{}", hex::encode(f.original.id)));
    std::fs::remove_dir_all(operation_path.join("pin")).unwrap();
    let mut reopened = NativeMusubiPinCoordinatorV1::open(
        &f.context,
        &path,
        [0xA8; 32],
        policy(&f.key),
        f.key.clone(),
    )
    .unwrap();
    assert_eq!(reopened.store.inventory(None).unwrap().signed_pins, 0);
    let operation = reopened.store.operation(f.original.id).unwrap();
    assert!(
        reopened
            .begin_round(operation, now(), Instant::now() + Duration::from_secs(30))
            .unwrap_err()
            .to_string()
            .contains("complete retained predecessor")
    );
    assert!(reopened.round.is_none());
    assert_eq!(
        f.context
            .queue()
            .all_transactions(&f.chain.state().view())
            .count(),
        0
    );
    drop(reopened);
    std::fs::remove_dir_all(&operation_path).unwrap();
    let mut reopened =
        NativeMusubiPinCoordinatorV1::open(&f.context, &path, [0xA8; 32], policy(&f.key), f.key)
            .unwrap();
    assert!(reopened.recover(f.original.id).is_err());
    assert!(!operation_path.exists());
}

#[test]
fn native_predecessor_allows_only_the_exact_one_pending_signed_inventory() {
    let mut f = Fixture::new();
    let predecessor = f.coordinator.store.inventory(None).unwrap().digest;
    let advance = quoted(
        &f.chain,
        &f.key,
        AdvanceMusubiPinOutboxV1 {
            network_id: f.chain.network_id(),
            pin_authority: AccountId::new(f.key.public_key().clone()),
            session_id: [0xA8; 32],
            expected_revision: 0,
            expected_inventory_digest: [0; 32],
            inventory_digest: predecessor,
        }
        .into(),
    );
    assert_eq!(f.chain.commit(vec![advance]), [true]);
    let operation = f.coordinator.store.operation(f.original.id).unwrap();
    let original_wire = retain_codec_only_pin(&mut f, &operation);
    let operation = f.coordinator.store.operation(f.original.id).unwrap();
    f.coordinator
        .begin_round(operation, now(), Instant::now() + Duration::from_secs(30))
        .unwrap();
    let round = f.coordinator.round.take().unwrap();
    assert!(matches!(round.goal, Goal::Advance));
    assert!(round.slot.as_ref().unwrap().payload().unwrap().is_none());
    assert!(round.slot.as_ref().unwrap().signed().is_none());
    drop(round);
    f.coordinator
        .prepare_operation(
            [0xBA; 32],
            [0x52; 32],
            &f.original.source().unwrap(),
            f.original.authorization.clone(),
        )
        .unwrap();
    let extra = f.coordinator.store.operation([0xBA; 32]).unwrap();
    retain_codec_only_pin(&mut f, &extra);
    let operation = f.coordinator.store.operation(f.original.id).unwrap();
    assert!(
        f.coordinator
            .begin_round(operation, now(), Instant::now() + Duration::from_secs(30))
            .unwrap_err()
            .to_string()
            .contains("complete retained predecessor")
    );
    assert!(f.coordinator.round.is_none());
    let slot = f
        .coordinator
        .store
        .open_slot(&f.original, SlotKind::Pin)
        .unwrap()
        .unwrap();
    assert_eq!(
        slot.signed().unwrap().encode_wire_v1().unwrap(),
        original_wire
    );
    assert!(!slot.exposed().unwrap());
    assert_eq!(
        f.context
            .queue()
            .all_transactions(&f.chain.state().view())
            .count(),
        0
    );
}

#[test]
fn actual_paid_check_queue_original_and_initial_advance_preserve_exact_custody_on_reopen() {
    let mut f = Fixture::new();
    let owner = AccountId::new(f.key.public_key().clone());
    let before = f.balance(&owner);
    let sink_before = f.balance(&f.sink);
    let original = f.coordinator.store.operation(f.original.id).unwrap();
    f.coordinator
        .begin_round(original, now(), Instant::now() + Duration::from_secs(60))
        .unwrap();
    assert!(f.coordinator.contains_operation(f.original.id).unwrap());
    assert!(f.coordinator.contains_operation([0xB0; 32]).is_err());
    let mut round = f.coordinator.round.take().unwrap();
    let deadline = round.deadline;
    assert!(
        f.coordinator
            .drive_round(&mut round, &mut Clock, deadline)
            .unwrap()
            .is_none()
    );
    let signed = round
        .pending
        .as_ref()
        .unwrap()
        .signed_transaction()
        .encode_wire_v1()
        .unwrap();
    let slot = f
        .coordinator
        .store
        .open_slot(&f.original, SlotKind::Check(1))
        .unwrap()
        .unwrap();
    assert!(slot.exposed().unwrap());
    assert_eq!(slot.signed().unwrap().encode_wire_v1().unwrap(), signed);
    assert!(!slot.record_exposure().unwrap());
    drop(slot);
    assert_eq!(f.commit_only_queued(), signed);
    let deadline = round.deadline;
    let readback = f
        .coordinator
        .drive_round(&mut round, &mut Clock, deadline)
        .unwrap()
        .unwrap();
    assert!(readback.high_water().is_none());
    assert_eq!(readback.applied_floor().height, 3);
    assert_eq!(
        f.balance(&owner),
        before.checked_sub(&Quantity::from(2u32)).unwrap()
    );
    assert_eq!(
        f.balance(&f.sink),
        sink_before.checked_add(&Quantity::from(2u32)).unwrap()
    );
    let expected = f.coordinator.store.inventory(None).unwrap().digest;
    assert!(matches!(
        f.coordinator
            .perform_goal(
                &f.original,
                Goal::Initialize,
                &readback,
                &mut Clock,
                deadline
            )
            .unwrap(),
        NativeMusubiPinProgressV1::Pending(NativeMusubiPinPhaseV1::Initialize)
    ));
    let wire = f.commit_only_queued();
    let view = f.chain.state().view();
    let row = view
        .world
        .musubi_pin_outbox_high_waters()
        .get(&owner)
        .unwrap();
    assert_eq!(row.revision, 1);
    assert_eq!(row.inventory_digest, expected);
    assert_eq!(row.session_id, [0xA8; 32]);
    drop(view);
    assert_eq!(
        f.balance(&owner),
        before.checked_sub(&Quantity::from(4u32)).unwrap()
    );
    let slot = f
        .coordinator
        .store
        .open_slot(&f.original, SlotKind::Initialize)
        .unwrap()
        .unwrap();
    assert_eq!(slot.signed().unwrap().encode_wire_v1().unwrap(), wire);
    drop(slot);
    drop(f.coordinator);
    let reopened = NativeMusubiPinCoordinatorV1::open(
        &f.context,
        &f.root.path().join("pins"),
        [0xA8; 32],
        policy(&f.key),
        f.key,
    )
    .unwrap();
    assert_eq!(reopened.store.inventory(None).unwrap().digest, expected);
    let slot = reopened
        .store
        .open_slot(&f.original, SlotKind::Initialize)
        .unwrap()
        .unwrap();
    assert_eq!(slot.signed().unwrap().encode_wire_v1().unwrap(), wire);
    assert!(
        !slot.record_exposure().unwrap(),
        "reopen cannot obtain another dispatch"
    );
}

#[test]
fn public_foreign_source_and_retirement_refuse_before_quote_or_queue_and_recovery_is_read_only() {
    let mut f = Fixture::new();
    let before = f.balance(&AccountId::new(f.key.public_key().clone()));
    assert!(f.coordinator.contains_operation(f.original.id).unwrap());
    assert!(!f.coordinator.contains_operation([0xB0; 32]).unwrap());
    assert!(f.coordinator.contains_operation([0; 32]).is_err());
    assert!(
        f.coordinator
            .advance(
                f.original.id,
                &mut Clock,
                Instant::now() + Duration::from_secs(60)
            )
            .is_err()
    );
    assert!(f.coordinator.round.is_none());
    assert!(
        f.coordinator
            .store
            .open_slot(&f.original, SlotKind::Check(1))
            .unwrap()
            .is_none()
    );
    assert_eq!(f.context.queue().queued_len(), 0);
    assert!(matches!(
        f.coordinator.recover(f.original.id).unwrap(),
        NativeMusubiPinProgressV1::Pending(NativeMusubiPinPhaseV1::RetainedPin)
    ));
    // Exercise a refused ordinary handoff with an exact old original, not a fabricated
    // successful execution or a live Check capability. The permanent marker survives refusal.
    let instruction: InstructionBox = AdvanceMusubiPinOutboxV1 {
        network_id: f.chain.network_id(),
        pin_authority: AccountId::new(f.key.public_key().clone()),
        session_id: [0xA8; 32],
        expected_revision: 0,
        expected_inventory_digest: [0; 32],
        inventory_digest: f.coordinator.store.inventory(None).unwrap().digest,
    }
    .into();
    let request = f
        .coordinator
        .request(&f.original, SlotKind::Initialize, &instruction)
        .unwrap();
    let mut slot = f
        .coordinator
        .store
        .create_slot(&f.original, request)
        .unwrap();
    let created = now() - 120_000;
    let payload = TransactionBuilder::new_with_time_source(
        f.chain.network_id(),
        AccountId::new(f.key.public_key().clone()),
        &TimeSource::new_fixed(Duration::from_millis(created)),
        f.original.authorization.per_transaction.clone(),
    )
    .with_instructions([instruction])
    .into_payload()
    .unwrap();
    f.coordinator
        .store
        .admit_payload(&f.original, &slot, &payload)
        .unwrap();
    slot.retain_payload(&payload).unwrap();
    slot.sign_original(
        &f.key,
        &mut authorization::FixedClock(created + 1),
        Instant::now() + Duration::from_secs(60),
    )
    .unwrap();
    let original_wire = slot.signed().unwrap().encode_wire_v1().unwrap();
    assert!(slot.record_exposure().unwrap());
    assert!(
        f.coordinator
            .dispatch(
                slot,
                &f.original.authorization,
                &mut Clock,
                Instant::now() + Duration::from_secs(60)
            )
            .is_err(),
        "expired original is refused by ordinary admission/Queue"
    );
    assert_eq!(f.context.queue().queued_len(), 0);
    let slot = f
        .coordinator
        .store
        .open_slot(&f.original, SlotKind::Initialize)
        .unwrap()
        .unwrap();
    assert_eq!(
        slot.signed().unwrap().encode_wire_v1().unwrap(),
        original_wire
    );
    assert!(
        !slot.record_exposure().unwrap(),
        "failed ordinary handoff cannot resend"
    );
    drop(slot);
    f.coordinator.cancel_operation(f.original.id).unwrap();
    assert!(
        f.coordinator
            .advance(
                f.original.id,
                &mut Clock,
                Instant::now() + Duration::from_secs(60)
            )
            .is_err()
    );
    assert_eq!(f.context.queue().queued_len(), 0);
    assert_eq!(
        f.balance(&AccountId::new(f.key.public_key().clone())),
        before
    );
}

#[test]
fn cancellation_after_queue_exposure_preserves_paid_original_and_never_restarts_on_reopen() {
    let mut f = Fixture::new();
    let owner = AccountId::new(f.key.public_key().clone());
    let before = f.balance(&owner);
    let operation = f.coordinator.store.operation(f.original.id).unwrap();
    f.coordinator
        .begin_round(operation, now(), Instant::now() + Duration::from_secs(60))
        .unwrap();
    let mut round = f.coordinator.round.take().unwrap();
    let deadline = round.deadline;
    assert!(
        f.coordinator
            .drive_round(&mut round, &mut Clock, deadline)
            .unwrap()
            .is_none()
    );
    let original_wire = round
        .pending
        .as_ref()
        .unwrap()
        .signed_transaction()
        .encode_wire_v1()
        .unwrap();
    f.coordinator.round = Some(round);
    f.coordinator.cancel_operation(f.original.id).unwrap();
    assert!(f.coordinator.round.is_none());
    assert!(f.coordinator.contains_operation(f.original.id).unwrap());
    assert_eq!(
        f.context.queue().queued_len(),
        1,
        "cancellation cannot retract an exposed native transaction"
    );
    assert_eq!(f.commit_only_queued(), original_wire);
    assert_eq!(
        f.balance(&owner),
        before.checked_sub(&Quantity::from(2u32)).unwrap()
    );
    assert!(
        f.chain
            .state()
            .view()
            .world
            .musubi_pin_outbox_high_waters()
            .get(&owner)
            .is_none()
    );
    drop(f.coordinator);
    let mut reopened = NativeMusubiPinCoordinatorV1::open(
        &f.context,
        &f.root.path().join("pins"),
        [0xA8; 32],
        policy(&f.key),
        f.key,
    )
    .unwrap();
    assert!(
        reopened
            .advance(
                f.original.id,
                &mut Clock,
                Instant::now() + Duration::from_secs(60)
            )
            .is_err()
    );
    assert!(matches!(
        reopened.recover(f.original.id).unwrap(),
        NativeMusubiPinProgressV1::Pending(NativeMusubiPinPhaseV1::RetainedPin)
    ));
    let slot = reopened
        .store
        .open_slot(&f.original, SlotKind::Check(1))
        .unwrap()
        .unwrap();
    assert_eq!(
        slot.signed().unwrap().encode_wire_v1().unwrap(),
        original_wire
    );
    assert!(!slot.record_exposure().unwrap());
    drop(slot);
    assert!(
        reopened
            .store
            .open_slot(&f.original, SlotKind::Check(2))
            .unwrap()
            .is_none()
    );
    let source = f.original.source().unwrap();
    let mut changed = f.original.authorization.clone();
    changed.deadline_unix_ms += 1;
    assert!(
        reopened
            .prepare_operation(f.original.id, f.original.context_digest, &source, changed)
            .is_err(),
        "reopen does not authorize a new expiry"
    );
}

/// Scripted durable-clock observations test refusal only; they never establish finality.
struct BoundaryClock {
    observations: std::collections::VecDeque<u64>,
}
impl BoundaryClock {
    fn new(values: impl IntoIterator<Item = u64>) -> Self {
        Self {
            observations: values.into_iter().collect(),
        }
    }
}
impl MusubiPublicationServiceClockV1 for BoundaryClock {
    fn current_time_ms(
        &mut self,
    ) -> std::result::Result<u64, iroha_musubi_service::MusubiPublicationServiceBackendErrorV1>
    {
        Ok(self
            .observations
            .pop_front()
            .expect("only the selected boundary observations"))
    }
}

#[test]
fn actual_native_check_expiry_after_payload_preparation_preserves_unsigned_original() {
    struct DelayedClock {
        end: Instant,
        value: u64,
        called: bool,
    }
    impl MusubiPublicationServiceClockV1 for DelayedClock {
        fn current_time_ms(
            &mut self,
        ) -> std::result::Result<u64, iroha_musubi_service::MusubiPublicationServiceBackendErrorV1>
        {
            self.called = true;
            std::thread::sleep(
                self.end.saturating_duration_since(Instant::now()) + Duration::from_millis(1),
            );
            Ok(self.value)
        }
    }

    let mut f = Fixture::new();
    let owner = AccountId::new(f.key.public_key().clone());
    let before = f.balance(&owner);
    let original = f.coordinator.store.operation(f.original.id).unwrap();
    f.coordinator
        .begin_round(original, now(), Instant::now() + Duration::from_secs(60))
        .unwrap();
    let mut round = f.coordinator.round.take().unwrap();
    let deadline = round.deadline;
    // The first sample permits the real native quote, original aggregate admission and payload
    // publication. The second sample is the exact original UTC boundary at the signing leaf.
    let mut clock = BoundaryClock::new([now(), f.original.authorization.deadline_unix_ms]);
    let error = match f.coordinator.drive_round(&mut round, &mut clock, deadline) {
        Err(error) => error,
        Ok(_) => panic!("elapsed original cannot authorize signing"),
    };
    assert!(error.to_string().contains("authorization has expired"));
    assert!(clock.observations.is_empty());
    let slot = round.slot.as_ref().unwrap();
    let payload = slot::encode_frame(&slot.payload().unwrap().unwrap()).unwrap();
    assert!(slot.signed().is_none());
    assert!(!slot.exposed().unwrap());
    assert_eq!(f.context.queue().queued_len(), 0);
    assert_eq!(f.balance(&owner), before);

    // Even a live UTC sample cannot extend the original monotonic boundary while the durable
    // clock is being read. This is a refusal test over the actual original authorization.
    let end = Instant::now() + Duration::from_millis(100);
    let mut delayed = DelayedClock {
        end,
        value: now(),
        called: false,
    };
    assert!(
        f.original
            .authorization
            .check_effect_boundary(&mut delayed, end)
            .is_err()
    );
    assert!(delayed.called);
    assert!(round.slot.as_ref().unwrap().signed().is_none());
    drop(round);
    let reopened = f
        .coordinator
        .store
        .open_slot(&f.original, SlotKind::Check(1))
        .unwrap()
        .unwrap();
    assert_eq!(
        slot::encode_frame(&reopened.payload().unwrap().unwrap()).unwrap(),
        payload
    );
    assert!(reopened.signed().is_none());
    assert!(!reopened.exposed().unwrap());
}

#[test]
fn actual_native_check_finality_cannot_authorize_advance_signature_after_original_expiry() {
    let mut f = Fixture::new();
    let owner = AccountId::new(f.key.public_key().clone());
    let before = f.balance(&owner);
    let original = f.coordinator.store.operation(f.original.id).unwrap();
    f.coordinator
        .begin_round(original, now(), Instant::now() + Duration::from_secs(60))
        .unwrap();
    let mut round = f.coordinator.round.take().unwrap();
    let deadline = round.deadline;
    assert!(
        f.coordinator
            .drive_round(&mut round, &mut Clock, deadline)
            .unwrap()
            .is_none()
    );
    f.commit_only_queued();
    let readback = f
        .coordinator
        .drive_round(&mut round, &mut Clock, deadline)
        .unwrap()
        .unwrap();
    assert!(readback.high_water().is_none());
    assert_eq!(readback.applied_floor().height, 3);
    let mut clock = BoundaryClock::new([now(), f.original.authorization.deadline_unix_ms]);
    let result = f.coordinator.perform_goal(
        &f.original,
        Goal::Initialize,
        &readback,
        &mut clock,
        deadline,
    );
    let error = match result {
        Err(error) => error,
        Ok(_) => panic!("elapsed original cannot authorize signing"),
    };
    assert!(error.to_string().contains("authorization has expired"));
    assert!(clock.observations.is_empty());
    let retained = f.coordinator.retained.as_ref().unwrap();
    let payload = slot::encode_frame(&retained.payload().unwrap().unwrap()).unwrap();
    assert!(retained.signed().is_none());
    assert!(!retained.exposed().unwrap());
    assert_eq!(
        f.balance(&owner),
        before.checked_sub(&Quantity::from(2u32)).unwrap()
    );
    assert!(
        f.chain
            .state()
            .view()
            .world
            .musubi_pin_outbox_high_waters()
            .get(&owner)
            .is_none()
    );
    f.coordinator.reconcile_retained().unwrap();
    let reopened = f
        .coordinator
        .store
        .open_slot(&f.original, SlotKind::Initialize)
        .unwrap()
        .unwrap();
    assert_eq!(
        slot::encode_frame(&reopened.payload().unwrap().unwrap()).unwrap(),
        payload
    );
    assert!(reopened.signed().is_none());
    assert!(!reopened.exposed().unwrap());
}

#[test]
fn actual_native_check_expiry_after_marker_or_admission_never_replays_queue_handoff() {
    // Boundary four follows the durable marker and exact slot validation. Boundary five
    // follows actual AcceptedTransaction admission. Neither can renew the original UTC.
    for boundary in [4, 5] {
        let mut f = Fixture::new();
        let owner = AccountId::new(f.key.public_key().clone());
        let before = f.balance(&owner);
        let original = f.coordinator.store.operation(f.original.id).unwrap();
        f.coordinator
            .begin_round(original, now(), Instant::now() + Duration::from_secs(60))
            .unwrap();
        let mut round = f.coordinator.round.take().unwrap();
        let deadline = round.deadline;
        let mut values = vec![now(); boundary - 1];
        values.push(f.original.authorization.deadline_unix_ms);
        let mut clock = BoundaryClock::new(values);
        let error = match f.coordinator.drive_round(&mut round, &mut clock, deadline) {
            Err(error) => error,
            Ok(_) => panic!("elapsed original cannot authorize Queue handoff"),
        };
        assert!(error.to_string().contains("authorization has expired"));
        assert!(clock.observations.is_empty());
        assert!(round.slot.is_none());
        let wire = round
            .pending
            .as_ref()
            .unwrap()
            .signed_transaction()
            .encode_wire_v1()
            .unwrap();
        assert_eq!(f.context.queue().queued_len(), 0);
        assert_eq!(f.balance(&owner), before);
        let slot = f
            .coordinator
            .store
            .open_slot(&f.original, SlotKind::Check(1))
            .unwrap()
            .unwrap();
        assert_eq!(slot.signed().unwrap().encode_wire_v1().unwrap(), wire);
        assert!(
            !slot.record_exposure().unwrap(),
            "elapsed handoff marker is permanent"
        );
        drop(slot);
        drop(round);
        drop(f.coordinator);
        let reopened = NativeMusubiPinCoordinatorV1::open(
            &f.context,
            &f.root.path().join("pins"),
            [0xA8; 32],
            policy(&f.key),
            f.key,
        )
        .unwrap();
        let slot = reopened
            .store
            .open_slot(&f.original, SlotKind::Check(1))
            .unwrap()
            .unwrap();
        assert_eq!(slot.signed().unwrap().encode_wire_v1().unwrap(), wire);
        assert!(!slot.record_exposure().unwrap());
        assert_eq!(f.context.queue().queued_len(), 0);
    }
}

#[test]
fn original_operation_binds_complete_caller_context_across_reopen_without_queue_effects() {
    let mut f = Fixture::new();
    let id = f.original.id;
    let source = f.original.source().unwrap();
    let original = f.coordinator.original_operation(id).unwrap().unwrap();
    assert_eq!(original.context_digest, f.original.context_digest);
    assert_eq!(original.source, source);
    assert_eq!(original.authorization, f.original.authorization);
    assert!(
        f.coordinator
            .prepare_operation(id, [0x99; 32], &source, f.original.authorization.clone())
            .is_err()
    );
    assert_eq!(f.context.queue().queued_len(), 0);
    assert_eq!(
        f.coordinator
            .original_operation(id)
            .unwrap()
            .unwrap()
            .context_digest,
        original.context_digest
    );
    drop(f.coordinator);
    let coordinator = NativeMusubiPinCoordinatorV1::open(
        &f.context,
        &f.root.path().join("pins"),
        [0xA8; 32],
        policy(&f.key),
        f.key.clone(),
    );
    let coordinator = coordinator.expect("reopen exact original native operation");
    assert_eq!(
        coordinator
            .original_operation(id)
            .unwrap()
            .unwrap()
            .authorization,
        original.authorization
    );
    assert!(
        coordinator
            .original_operation([0x98; 32])
            .unwrap()
            .is_none()
    );
    assert_eq!(f.context.queue().queued_len(), 0);
}

#[test]
fn caller_context_inspection_preserves_the_actual_held_native_check_round() {
    let mut f = Fixture::new();
    let operation = f.coordinator.store.operation(f.original.id).unwrap();
    f.coordinator
        .begin_round(operation, now(), Instant::now() + Duration::from_secs(30))
        .unwrap();
    let before = f.coordinator.round.as_ref().unwrap().deadline;
    let original = f
        .coordinator
        .original_operation(f.original.id)
        .unwrap()
        .unwrap();
    assert_eq!(original.context_digest, f.original.context_digest);
    assert_eq!(original.authorization, f.original.authorization);
    assert_eq!(f.coordinator.round.as_ref().unwrap().deadline, before);
    assert!(f.coordinator.original_operation([0x98; 32]).is_err());
    assert!(matches!(
        f.coordinator.observe_operation(f.original.id).unwrap(),
        NativeMusubiPinProgressV1::Pending(NativeMusubiPinPhaseV1::RetainedPin)
    ));
    assert_eq!(f.context.queue().queued_len(), 0);
    assert!(
        f.coordinator
            .round
            .as_ref()
            .unwrap()
            .slot
            .as_ref()
            .unwrap()
            .signed()
            .is_none()
    );
    let selected = f
        .root
        .path()
        .join("pins")
        .join(format!("op-{}", hex::encode(f.original.id)))
        .join("check-01");
    std::fs::remove_file(selected.join("preparation.json")).unwrap();
    assert!(f.coordinator.original_operation(f.original.id).is_err());
    assert!(f.coordinator.observe_operation(f.original.id).is_err());
    assert_eq!(f.context.queue().queued_len(), 0);
    assert_eq!(f.coordinator.round.as_ref().unwrap().deadline, before);
}
