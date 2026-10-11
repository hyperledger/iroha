//! Deterministic mutations at the sole parser's native-file observation boundaries.
//! The scoped test hook restores its actual private file on ordinary return or unwind.

use super::*;
use crate::managed::{
    native_operation::test_support::UnavailablePeers,
    stream_token_custody::renewal_tests::{Fixture, wait_until},
};
use std::{
    cell::RefCell,
    path::{Path, PathBuf},
    rc::Rc,
    time::Duration,
};

#[derive(Clone, Copy, PartialEq, Eq)]
pub(super) enum Point {
    AnchorDecoded,
    ContainerNamesValidated,
    HistoriesVerified,
    WalletInspected,
}
enum MutationAction {
    Write(Vec<u8>),
    Remove,
}
struct Mutation {
    point: Point,
    root: PathBuf,
    directory: Arc<PrivateDirectory>,
    name: String,
    original: Option<zeroize::Zeroizing<Vec<u8>>>,
    action: MutationAction,
    fired: bool,
    applied: bool,
}
thread_local! {
    static MUTATION: RefCell<Option<Rc<RefCell<Mutation>>>> = const { RefCell::new(None) };
}
struct ScopedMutation(Rc<RefCell<Mutation>>);
impl ScopedMutation {
    fn arm(
        point: Point,
        root: &Path,
        directory: Arc<PrivateDirectory>,
        name: &str,
        replacement: Vec<u8>,
    ) -> Self {
        let original = read_optional(&directory, name, MAX_BODY_BYTES)
            .unwrap()
            .map(zeroize::Zeroizing::new);
        let value = Rc::new(RefCell::new(Mutation {
            point,
            root: root.to_owned(),
            directory,
            name: name.to_owned(),
            original,
            action: MutationAction::Write(replacement),
            fired: false,
            applied: false,
        }));
        MUTATION.with(|slot| {
            assert!(
                slot.borrow().is_none(),
                "one scoped mutation per parser test"
            );
            *slot.borrow_mut() = Some(Rc::clone(&value));
        });
        Self(value)
    }
    fn arm_remove(point: Point, root: &Path, directory: Arc<PrivateDirectory>, name: &str) -> Self {
        let mutation = Self::arm(point, root, directory, name, Vec::new());
        {
            let mut value = mutation.0.borrow_mut();
            assert!(
                value.original.is_some(),
                "remove only an actual original test source"
            );
            value.action = MutationAction::Remove;
        }
        mutation
    }
    fn fired(&self) -> bool {
        self.0.borrow().fired
    }
    fn applied(&self) -> bool {
        self.0.borrow().applied
    }
}
impl Drop for ScopedMutation {
    fn drop(&mut self) {
        MUTATION.with(|slot| {
            slot.borrow_mut().take();
        });
        let value = self.0.borrow();
        if value.fired {
            if let Some(original) = &value.original {
                value
                    .directory
                    .write_atomic(&value.name, original, PublishMode::Replace)
                    .expect("restore exact original parser input");
            } else {
                std::fs::remove_file(value.directory.path().join(&value.name))
                    .expect("remove only test-created parser input");
            }
        }
    }
}
pub(super) fn hit(point: Point, root: &Path) -> Result<()> {
    MUTATION.with(|slot| {
        let selected = slot.borrow().as_ref().map(Rc::clone);
        if let Some(selected) = selected {
            let mut value = selected.borrow_mut();
            if value.point == point && value.root == root && !value.fired {
                // Mark ownership before the write so unwind cleanup covers a published prefix.
                value.fired = true;
                match &value.action {
                    MutationAction::Write(bytes) => value.directory.write_atomic(
                        &value.name,
                        bytes,
                        if value.original.is_some() {
                            PublishMode::Replace
                        } else {
                            PublishMode::CreateNew
                        },
                    )?,
                    MutationAction::Remove => {
                        std::fs::remove_file(value.directory.path().join(&value.name))?;
                    }
                }
                value.applied = true;
            }
        }
        Ok(())
    })
}
struct MissingRecord {
    directory: Arc<PrivateDirectory>,
    name: String,
    bytes: zeroize::Zeroizing<Vec<u8>>,
}
impl MissingRecord {
    fn remove(directory: Arc<PrivateDirectory>, name: &str) -> Self {
        let bytes = directory.read(name, MAX_SELECTION_BYTES).unwrap();
        std::fs::remove_file(directory.path().join(name)).unwrap();
        Self {
            directory,
            name: name.to_owned(),
            bytes,
        }
    }
}
impl Drop for MissingRecord {
    fn drop(&mut self) {
        self.directory
            .write_atomic(&self.name, &self.bytes, PublishMode::CreateNew)
            .expect("restore original external selection reference");
    }
}

fn pending(fixture: &Fixture) -> BodyHistory {
    wait_until(
        fixture.initial.issued_at_unix_ms + 10_000,
        Duration::from_secs(20),
    );
    let (checkpoint, current) = fixture.current();
    let terms = Terms::new(now_ms().unwrap() + 60_000, &fixture.options).unwrap();
    let unsigned = fixture
        .owner
        .select_renewal_unsigned(
            2,
            &fixture.policy,
            &current,
            &checkpoint,
            &terms,
            fixture.options.deadline,
        )
        .unwrap();
    BodyHistory::initialize(
        &fixture.owner,
        CustodyPurpose::Renewal(2),
        unsigned,
        &terms.fees,
        &SigningTurn::Explicit(&terms),
        fixture.options.deadline,
    )
    .unwrap()
}
fn open(fixture: &Fixture) -> Result<BodyHistory> {
    BodyHistory::open(&fixture.owner, CustodyPurpose::Renewal(2))?
        .ok_or_else(|| invalid("test history absent"))
}
fn publish_unsigned(history: &BodyHistory) {
    let pending = history.anchor.pending.as_ref().unwrap();
    let bytes = encode(pending, MAX_BODY_BYTES).unwrap();
    let container = history.root.ensure_child("bodies").unwrap();
    private_parent(&container)
        .unwrap()
        .publish_private_child(
            body_name(pending.ordinal).unwrap(),
            &[("reserved.nrt", bytes.as_slice())],
        )
        .unwrap();
}
fn refuses(
    fixture: &Fixture,
    history: &BodyHistory,
    point: Point,
    directory: Arc<PrivateDirectory>,
    name: &str,
    bytes: Vec<u8>,
) {
    let mutation = ScopedMutation::arm(point, history.root.path(), directory, name, bytes);
    let result = open(fixture);
    assert!(mutation.fired());
    assert!(
        mutation.applied(),
        "test mutation must successfully publish"
    );
    assert!(result.is_err(), "parser must refuse changed {name}");
    drop(mutation);
    assert!(open(fixture).is_ok());
}

#[test]
fn decoded_original_anchor_and_reference_cannot_bind_later_replacement_bytes() {
    let _guard = crate::managed::native_test_guard();
    // This separate native fixture isolates parser races from the unchanged original 4s test.
    let fixture = Fixture::enrolled(20_000);
    let peers = UnavailablePeers::start(&fixture.prepared);
    let history = pending(&fixture);
    let mut selection = history.selection.clone();
    selection.profile[0] ^= 1;
    let mut anchor = history.anchor.clone();
    anchor.outer[0] ^= 1;
    let authority = Arc::new(fixture.owner.authority.directory.retain().unwrap());
    let name = reference_name(CustodyPurpose::Renewal(2)).unwrap();
    let mut reference: Reference = read(&authority, &name, MAX_SELECTION_BYTES).unwrap();
    reference.outer[0] ^= 1;
    for (directory, name, bytes) in [
        (
            Arc::clone(&history.root),
            "original.nrt".to_owned(),
            encode(&selection, MAX_SELECTION_BYTES).unwrap(),
        ),
        (
            Arc::clone(&history.root),
            "anchor.nrt".to_owned(),
            encode(&anchor, MAX_BODY_BYTES).unwrap(),
        ),
        (
            Arc::clone(&authority),
            name.clone(),
            encode(&reference, MAX_SELECTION_BYTES).unwrap(),
        ),
    ] {
        refuses(
            &fixture,
            &history,
            Point::AnchorDecoded,
            directory,
            &name,
            bytes,
        );
    }
    // Initial atomic root publication may legitimately precede its reference. The parser
    // must preserve that observed absence rather than return it after a reference appears.
    let missing = MissingRecord::remove(Arc::clone(&authority), &name);
    assert!(!open(&fixture).unwrap().reference_present);
    refuses(
        &fixture,
        &history,
        Point::AnchorDecoded,
        Arc::clone(&authority),
        &name,
        missing.bytes.to_vec(),
    );
    drop(missing);
    assert!(open(&fixture).unwrap().reference_present);
    assert_eq!(fixture.native.chain.height(), 4);
    assert!(peers.requests.lock().unwrap().is_empty());
}

#[test]
fn parsed_container_inventory_cannot_bind_a_later_unexpected_name() {
    let _guard = crate::managed::native_test_guard();
    let fixture = Fixture::enrolled(20_000);
    let peers = UnavailablePeers::start(&fixture.prepared);
    let history = pending(&fixture);
    // With no parsed body or container, a late new allowed root name must still refuse.
    refuses(
        &fixture,
        &history,
        Point::HistoriesVerified,
        Arc::clone(&history.root),
        "bodies",
        b"not a directory".to_vec(),
    );
    let container = Arc::new(history.root.ensure_child("bodies").unwrap());
    for with_body in [false, true] {
        if with_body {
            publish_unsigned(&history);
        }
        refuses(
            &fixture,
            &history,
            Point::ContainerNamesValidated,
            Arc::clone(&container),
            "unexpected.nrt",
            b"unexpected".to_vec(),
        );
    }
    assert_eq!(fixture.native.chain.height(), 4);
    assert!(peers.requests.lock().unwrap().is_empty());
}

#[test]
fn unsigned_body_records_and_absences_are_rechecked_before_parser_return() {
    let _guard = crate::managed::native_test_guard();
    let fixture = Fixture::enrolled(20_000);
    let peers = UnavailablePeers::start(&fixture.prepared);
    let history = pending(&fixture);
    publish_unsigned(&history);
    let history = history.reopen(&fixture.owner).unwrap();
    assert_eq!(history.bodies.len(), 1);
    assert!(history.bodies[0].original.is_none());
    assert!(history.bodies[0].activation.is_none());
    let mut reservation = history.bodies[0].reservation.clone();
    reservation.outer[0] ^= 1;
    for (name, bytes) in [
        (
            "reserved.nrt",
            encode(&reservation, MAX_BODY_BYTES).unwrap(),
        ),
        ("original.nrt", b"not an original".to_vec()),
    ] {
        refuses(
            &fixture,
            &history,
            Point::HistoriesVerified,
            Arc::clone(&history.bodies[0].directory),
            name,
            bytes,
        );
    }
    assert!(
        history.bodies[0]
            .directory
            .entries(1)
            .unwrap()
            .iter()
            .all(|name| name == "reserved.nrt")
    );
    assert_eq!(fixture.native.chain.height(), 4);
    assert!(peers.requests.lock().unwrap().is_empty());
}

#[test]
fn wallet_callback_cannot_reuse_an_earlier_epoch_or_claim_source_image() {
    use crate::managed::{
        native_operation::authorization::Epoch,
        stream_token_custody::bootstrap_test_support::NativeEnrollmentReads,
    };

    let _guard = crate::managed::native_test_guard();
    // Follow the same genuine H4 predecessor and original finite intervals as closed64.
    // Only the unsigned local body/retired wallet and issuer census are exercised here.
    let fixture = Fixture::enrolled_with_renewal_validity(4_000, 8_000);
    wait_until(
        fixture.initial.issued_at_unix_ms + 2_000,
        Duration::from_secs(4),
    );
    let (checkpoint, current) = fixture.current();
    let terms = Terms::new(now_ms().unwrap() + 2_000, &fixture.options).unwrap();
    let unsigned = fixture
        .owner
        .select_renewal_unsigned(
            2,
            &fixture.policy,
            &current,
            &checkpoint,
            &terms,
            fixture.options.deadline,
        )
        .unwrap();
    let history = fixture.owner.bootstrap_native_body(
        &fixture.native,
        &current,
        CustodyPurpose::Renewal(2),
        unsigned,
        now_ms().unwrap() + 2_000,
        &fixture.options,
    );
    let (directory, original, scope) = history.dispatch().unwrap();
    journal::explicit(
        directory,
        original,
        now_ms().unwrap() + 3_000,
        &fixture.options,
        &fixture.owner.wallet().unwrap(),
        scope,
    )
    .unwrap();
    let old = history.retained_selected(&fixture.owner).unwrap();
    wait_until(
        history.bodies[0]
            .reservation
            .unsigned
            .statement
            .expires_at_unix_ms,
        Duration::from_secs(10),
    );
    let (checkpoint, current) = fixture.current();
    let mut turn = fixture.renewal_turn();
    let history = open(&fixture).unwrap();
    let authorization = turn
        .authorize_retained(&fixture.owner, &history, fixture.options.deadline)
        .unwrap();
    let terms = Terms::new(now_ms().unwrap() + 2_000, &fixture.options).unwrap();
    let unsigned = fixture
        .owner
        .select_renewal_unsigned(
            2,
            &fixture.policy,
            &current,
            &checkpoint,
            &terms,
            fixture.options.deadline,
        )
        .unwrap();
    let history = history
        .reserve_successor(
            &fixture.owner,
            unsigned,
            &current,
            authorization,
            fixture.options.deadline,
        )
        .unwrap()
        .finish_pending_with_reads(
            &fixture.owner,
            &current,
            &SigningTurn::Generated(authorization),
            fixture.options.deadline,
            &NativeEnrollmentReads(&fixture.native),
        )
        .unwrap();
    assert_eq!(history.bodies.len(), 2);
    assert_eq!(
        history
            .current_history()
            .unwrap()
            .cumulative_reserved_count(),
        1
    );
    let wallet = old.directory().path().join("transaction");
    assert_eq!(
        old.request(fixture.options.deadline)
            .unwrap()
            .inspect(&fixture.owner.wallet().unwrap(), &wallet)
            .unwrap()
            .phase(),
        iroha_wallet::operations::NativePreparationPhase::Retired
    );
    let epochs = Arc::new(history.root.open_child("epochs").unwrap());
    let mut foreign: Epoch = attempts::read_record(&epochs, "0001.nrt").unwrap().unwrap();
    foreign.parent_intent[0] ^= 1;
    let epoch_bytes = epochs.read("0001.nrt", attempts::MAX_RECORD_BYTES).unwrap();
    let claim_bytes = epochs
        .read("0001-replacement.nrt", attempts::MAX_RECORD_BYTES)
        .unwrap();
    let before = epochs
        .entries(crate::managed::native_operation::authorization::MAX_EPOCHS * 2)
        .unwrap();
    // The hook runs only after the actual canonical wallet inspector has returned its
    // original retired request. The next body's original issuer census must read the file
    // or namespace again; its earlier decoded DTO/optional claim cannot authorize it.
    for (name, bytes) in [
        (
            "0001.nrt",
            encode(&foreign, attempts::MAX_RECORD_BYTES).unwrap(),
        ),
        (
            "0001-replacement.nrt",
            b"invalid actual replacement claim".to_vec(),
        ),
        ("unexpected.nrt", b"foreign issuer material".to_vec()),
    ] {
        let mutation = ScopedMutation::arm(
            Point::WalletInspected,
            history.root.path(),
            Arc::clone(&epochs),
            name,
            bytes,
        );
        let result = open(&fixture);
        assert!(mutation.fired() && mutation.applied());
        assert!(result.is_err(), "wallet callback changed {name}");
        drop(mutation);
        assert!(open(&fixture).is_ok());
        assert_eq!(
            epochs.read("0001.nrt", attempts::MAX_RECORD_BYTES).unwrap(),
            epoch_bytes
        );
        assert_eq!(
            epochs
                .read("0001-replacement.nrt", attempts::MAX_RECORD_BYTES)
                .unwrap(),
            claim_bytes
        );
        assert_eq!(
            epochs
                .entries(crate::managed::native_operation::authorization::MAX_EPOCHS * 2)
                .unwrap(),
            before
        );
        assert!(!wallet.join("payload.json").exists());
        assert!(!wallet.join("operation.json").exists());
        assert!(!wallet.join("submission.json").exists());
    }
    let mutation = ScopedMutation::arm_remove(
        Point::WalletInspected,
        history.root.path(),
        Arc::clone(&epochs),
        "0001.nrt",
    );
    let result = open(&fixture);
    assert!(mutation.fired() && mutation.applied());
    assert!(
        result.is_err(),
        "wallet callback removed the original epoch"
    );
    assert!(!epochs.path().join("0001.nrt").exists());
    drop(mutation);
    assert!(open(&fixture).is_ok());
    assert_eq!(
        epochs.read("0001.nrt", attempts::MAX_RECORD_BYTES).unwrap(),
        epoch_bytes
    );
    assert_eq!(
        epochs
            .entries(crate::managed::native_operation::authorization::MAX_EPOCHS * 2)
            .unwrap(),
        before
    );
    assert!(!wallet.join("payload.json").exists());
    assert!(!wallet.join("operation.json").exists());
    assert!(!wallet.join("submission.json").exists());
    assert_eq!(fixture.native.chain.height(), 4);
}
