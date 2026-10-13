//! Daemon consumption of genuine one-use native Checks under exact State ownership.

use super::*;
use iroha_core::query::musubi_pin_outbox::{
    MusubiPinOutboxCheckErrorV1, VerifiedMusubiPinOutboxCheckV1,
};
use iroha_core::{
    query::musubi_pin_outbox::PendingMusubiPinOutboxCheckV1,
    state::World,
    sumeragi::test_chain::{CertifiedTestChain, TestChainConfig},
};
use iroha_crypto::{Algorithm, KeyPair};
use iroha_data_model::{
    NetworkId, account::AccountId, musubi::MusubiPinOutboxHighWaterV1,
    transaction::TransactionEntrypoint,
};
use iroha_data_model::{
    Registrable,
    account::Account,
    asset::AssetDefinition,
    domain::Domain,
    musubi::{MusubiPinOutboxCheckExpectationV1, MusubiPinOutboxCheckFloorV1},
};
use std::time::Duration;

const SESSION: [u8; 32] = [0x81; 32];
const INVENTORY: [u8; 32] = [0x82; 32];

struct Fixture {
    chain: CertifiedTestChain,
    key: KeyPair,
}
impl Fixture {
    fn new() -> Self {
        let key = KeyPair::from_seed(vec![0xa1; 32], Algorithm::Ed25519);
        let owner = AccountId::new(key.public_key().clone());
        let world = World::with(
            std::iter::empty::<Domain>(),
            [Account::new(owner.clone()).build(&owner)],
            std::iter::empty::<AssetDefinition>(),
        );
        let mut chain = CertifiedTestChain::start(TestChainConfig::new(world, 1_000)).unwrap();
        // A genuine successor authenticates genesis execution before any fresh Check read.
        let tick = chain.sign(
            &key,
            [iroha_data_model::isi::Log::new(
                iroha_logger::Level::INFO,
                "daemon pin-outbox Check floor".to_owned(),
            )
            .into()],
            chain.committed(chain.height()).block_time_ms() + 1,
        );
        assert_eq!(chain.commit(vec![tick]), [true]);
        Self { chain, key }
    }
    fn authority(&self) -> AccountId {
        AccountId::new(self.key.public_key().clone())
    }
    fn reader(&self) -> Arc<State> {
        Arc::clone(self.chain.state())
    }
    fn row(&self) -> Option<MusubiPinOutboxHighWaterV1> {
        self.chain
            .state()
            .query_view()
            .world()
            .musubi_pin_outbox_high_waters()
            .get(&self.authority())
            .cloned()
    }
    fn expected(
        &self,
        expected: MusubiPinOutboxCheckExpectationV1,
    ) -> MusubiPinOutboxCheckExpectedV1 {
        let tip = self.chain.committed(self.chain.height());
        MusubiPinOutboxCheckExpectedV1 {
            chain_id: self.chain.state().chain_id_ref().clone(),
            network_id: self.chain.network_id(),
            pin_authority: self.authority(),
            session_id: SESSION,
            inventory_digest: INVENTORY,
            floor: MusubiPinOutboxCheckFloorV1 {
                height: tip.height(),
                block_hash: *tip.block_hash().as_ref(),
                context_id: tip.id(),
            },
            expected,
        }
    }
    fn advance(&mut self, inventory: [u8; 32]) {
        let (revision, prior) = self
            .row()
            .map_or((0, [0; 32]), |row| (row.revision, row.inventory_digest));
        let instruction = AdvanceMusubiPinOutboxV1 {
            network_id: self.chain.network_id(),
            pin_authority: self.authority(),
            session_id: SESSION,
            expected_revision: revision,
            expected_inventory_digest: prior,
            inventory_digest: inventory,
        };
        let signed = self.chain.sign(
            &self.key,
            [instruction.into()],
            self.chain.committed(self.chain.height()).block_time_ms() + 1,
        );
        assert_eq!(self.chain.commit(vec![signed]), [true]);
    }
    fn pending(
        &self,
        reader: &Arc<State>,
        expectation: MusubiPinOutboxCheckExpectationV1,
    ) -> PendingMusubiPinOutboxCheckV1 {
        let prepared = begin_musubi_pin_outbox_check_v1(
            Arc::clone(reader),
            self.expected(expectation),
            Instant::now() + Duration::from_secs(60),
        )
        .unwrap();
        let signed = self.chain.sign(
            &self.key,
            [prepared.instruction().clone().into()],
            self.chain.committed(self.chain.height()).block_time_ms() + 1,
        );
        prepared.bind_signed_transaction(signed).unwrap()
    }
    fn verified(
        &mut self,
        reader: &Arc<State>,
        expectation: MusubiPinOutboxCheckExpectationV1,
    ) -> VerifiedMusubiPinOutboxCheckV1 {
        let pending = self.pending(reader, expectation);
        let signed = pending.signed_transaction().clone();
        assert_eq!(self.chain.commit(vec![signed]), [true]);
        pending
            .verify_finalized()
            .unwrap_or_else(|failure| panic!("native Check verification: {:?}", failure.error()))
    }
}

#[test]
fn daemon_fresh_check_reads_absence_and_complete_present_row_from_original_state() {
    let mut fixture = Fixture::new();
    let reader = fixture.reader();
    let absent = fixture.verified(&reader, MusubiPinOutboxCheckExpectationV1::Absent);
    let readback = absent
        .consume_current(&reader)
        .unwrap_or_else(|failure| panic!("absent Check consumption: {:?}", failure.error()));
    assert!(readback.high_water().is_none());
    assert!(fixture.row().is_none());

    fixture.advance(INVENTORY);
    let row = fixture.row().unwrap();
    let verified = fixture.verified(
        &reader,
        MusubiPinOutboxCheckExpectationV1::Present(row.clone()),
    );
    // A second reader retains the same original State allocation, not a reconstructed snapshot.
    let same_owner = fixture.reader();
    let readback = verified
        .consume_current(&same_owner)
        .unwrap_or_else(|failure| panic!("present Check consumption: {:?}", failure.error()));
    assert_eq!(readback.high_water(), Some(&row));
    assert_eq!(fixture.row(), Some(row));
}

#[test]
fn daemon_fresh_check_rejects_foreign_same_network_state_before_decode_or_history() {
    let mut fixture = Fixture::new();
    let other = Fixture::new();
    assert_eq!(fixture.chain.network_id(), other.chain.network_id());
    assert!(!Arc::ptr_eq(fixture.chain.state(), other.chain.state()));
    let reader = fixture.reader();
    let pending = fixture.pending(&reader, MusubiPinOutboxCheckExpectationV1::Absent);
    let original = pending.signed_transaction().clone();
    let deadline = pending.deadline();
    assert_eq!(fixture.chain.commit(vec![original.clone()]), [true]);
    let verified = pending
        .verify_finalized()
        .unwrap_or_else(|failure| panic!("native Check verification: {:?}", failure.error()));
    let foreign = other.reader();
    let limits = norito::DecodeLimits::new(usize::MAX, usize::MAX, usize::MAX, 0, 128);
    let failure = norito::with_decode_limits_scope(limits, || {
        verified.consume_current(&foreign).err().unwrap()
    });
    assert_eq!(
        failure.rejection(),
        Some(MusubiPinOutboxCheckErrorV1::CurrentState)
    );
    let pending = failure.into_pending();
    assert_eq!(pending.signed_transaction(), &original);
    assert_eq!(pending.deadline(), deadline);
    let verified = pending
        .verify_finalized()
        .unwrap_or_else(|failure| panic!("original Check retry: {:?}", failure.error()));
    let readback = verified
        .consume_current(&reader)
        .unwrap_or_else(|failure| panic!("original State consumption: {:?}", failure.error()));
    assert!(readback.high_water().is_none());
    assert_eq!(
        readback.canonical_external(),
        norito::encode_canonical(&TransactionEntrypoint::External(original)).unwrap()
    );
}

#[test]
fn daemon_fresh_check_retains_unapplied_signed_transaction_for_same_attempt_retry() {
    let mut fixture = Fixture::new();
    let reader = fixture.reader();
    let pending = fixture.pending(&reader, MusubiPinOutboxCheckExpectationV1::Absent);
    let original = pending.signed_transaction().clone();
    let deadline = pending.deadline();
    let failure = pending.verify_finalized().err().unwrap();
    assert_eq!(
        failure.rejection(),
        Some(MusubiPinOutboxCheckErrorV1::NotApplied)
    );
    let pending = failure.into_pending();
    assert_eq!(pending.signed_transaction(), &original);
    assert_eq!(pending.deadline(), deadline);
    assert_eq!(fixture.chain.commit(vec![original.clone()]), [true]);
    let verified = pending
        .verify_finalized()
        .unwrap_or_else(|failure| panic!("original Check reconciliation: {:?}", failure.error()));
    let readback = verified
        .consume_current(&reader)
        .unwrap_or_else(|failure| panic!("reconciled Check consumption: {:?}", failure.error()));
    assert!(readback.high_water().is_none());
    assert_eq!(
        readback.canonical_external(),
        norito::encode_canonical(&TransactionEntrypoint::External(original)).unwrap()
    );
}

#[test]
fn daemon_fresh_check_rejects_later_native_inventory_change() {
    let mut fixture = Fixture::new();
    fixture.advance(INVENTORY);
    let row = fixture.row().unwrap();
    let reader = fixture.reader();
    let verified = fixture.verified(&reader, MusubiPinOutboxCheckExpectationV1::Present(row));
    fixture.advance([0x83; 32]);
    assert_eq!(
        verified
            .consume_current(&reader)
            .err()
            .and_then(|failure| failure.rejection()),
        Some(MusubiPinOutboxCheckErrorV1::CurrentState)
    );
    assert_eq!(fixture.row().unwrap().inventory_digest, [0x83; 32]);
}

#[test]
fn daemon_fresh_check_keeps_independent_network_and_original_deadline() {
    let fixture = Fixture::new();
    let reader = fixture.reader();
    assert!(matches!(
        begin_musubi_pin_outbox_check_v1(
            Arc::clone(&reader),
            fixture.expected(MusubiPinOutboxCheckExpectationV1::Absent),
            Instant::now().checked_sub(Duration::from_secs(1)).unwrap(),
        )
        .err(),
        Some(
            iroha_core::execution_attempt::ExecutionAttemptError::Rejected(
                MusubiPinOutboxCheckErrorV1::Expired
            )
        )
    ));
    let mut wrong = fixture.expected(MusubiPinOutboxCheckExpectationV1::Absent);
    wrong.network_id = NetworkId::from_genesis_hash(iroha_crypto::HashOf::from_untyped_unchecked(
        iroha_crypto::Hash::new(b"different independent network"),
    ));
    assert!(matches!(
        begin_musubi_pin_outbox_check_v1(
            Arc::clone(&reader),
            wrong,
            Instant::now() + Duration::from_secs(60)
        )
        .err(),
        Some(
            iroha_core::execution_attempt::ExecutionAttemptError::Rejected(
                MusubiPinOutboxCheckErrorV1::CurrentState
            )
        )
    ));
}

#[test]
fn fresh_check_requires_every_field_of_the_actual_successful_high_water() {
    let mut fixture = Fixture::new();
    fixture.advance(INVENTORY);
    let row = fixture.row().unwrap();
    assert_eq!(row.recorded_at_height, fixture.chain.height());
    for case in 0..8 {
        let mut changed = row.clone();
        match case {
            0 => changed.version = 2,
            1 => {
                changed.network_id =
                    NetworkId::from_genesis_hash(iroha_crypto::HashOf::from_untyped_unchecked(
                        iroha_crypto::Hash::new(b"foreign row"),
                    ))
            }
            2 => {
                changed.pin_authority = AccountId::new(
                    KeyPair::from_seed(vec![0x92; 32], Algorithm::Ed25519)
                        .public_key()
                        .clone(),
                )
            }
            3 => changed.session_id = [0x93; 32],
            4 => changed.revision += 1,
            5 => changed.inventory_digest = [0x94; 32],
            6 => changed.recorded_at_height += 1,
            7 => changed.transaction_hash = [0x95; 32],
            _ => unreachable!(),
        }
        assert!(
            begin_musubi_pin_outbox_check_v1(
                fixture.reader(),
                fixture.expected(MusubiPinOutboxCheckExpectationV1::Present(changed)),
                Instant::now() + Duration::from_secs(60)
            )
            .is_err(),
            "changed row field {case}"
        );
        assert_eq!(fixture.row(), Some(row.clone()));
    }
    let failed = fixture.chain.sign(
        &fixture.key,
        [AdvanceMusubiPinOutboxV1 {
            network_id: fixture.chain.network_id(),
            pin_authority: fixture.authority(),
            session_id: SESSION,
            expected_revision: 0,
            expected_inventory_digest: [0; 32],
            inventory_digest: [0x96; 32],
        }
        .into()],
        fixture
            .chain
            .committed(fixture.chain.height())
            .block_time_ms()
            + 1,
    );
    let failed_hash = *failed.hash().as_ref();
    assert_eq!(fixture.chain.commit(vec![failed]), [false]);
    assert_eq!(fixture.row(), Some(row.clone()));
    assert_ne!(row.transaction_hash, failed_hash);
    let reader = fixture.reader();
    let verified = fixture.verified(
        &reader,
        MusubiPinOutboxCheckExpectationV1::Present(row.clone()),
    );
    let read = verified
        .consume_current(&reader)
        .unwrap_or_else(|failure| panic!("native read failed: {:?}", failure.error()));
    assert_eq!(read.high_water(), Some(&row));
}

#[test]
fn local_coherence_refuses_state_ahead_and_kura_ahead_without_minting_a_check() {
    let fixture = Fixture::new();
    require_coherent_native_tip(fixture.chain.state()).unwrap();
    let tip = fixture.chain.committed(fixture.chain.height());
    let header = iroha_data_model::block::BlockHeader::new(
        std::num::NonZeroU64::new(fixture.chain.height() + 1).unwrap(),
        Some(tip.block_hash()),
        None,
        tip.block_time_ms() + 1,
        0,
    );
    fixture
        .chain
        .state()
        .block(header)
        .commit_empty_block_for_testing()
        .unwrap();
    assert!(
        require_coherent_native_tip(fixture.chain.state())
            .unwrap_err()
            .to_string()
            .contains("State/Kura height differs")
    );

    let fixture = Fixture::new();
    let mut other = Fixture::new();
    assert_eq!(
        fixture.chain.committed(2).block_hash(),
        other.chain.committed(2).block_hash()
    );
    other.advance(INVENTORY);
    let block = other.chain.committed(other.chain.height()).block().clone();
    fixture.chain.kura().store_block(block).unwrap();
    assert!(
        require_coherent_native_tip(fixture.chain.state())
            .unwrap_err()
            .to_string()
            .contains("State/Kura height differs")
    );
    assert!(fixture.row().is_none());
}
