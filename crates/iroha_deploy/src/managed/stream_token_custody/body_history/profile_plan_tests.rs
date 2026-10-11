//! One per-call original plan preserves full profile fences and actual attester refusal.

use super::*;
use crate::managed::{
    native_operation::test_support::UnavailablePeers,
    service_authority::profile_validation_test_support::count,
    stream_token_custody::{
        bootstrap_test_support::NativeEnrollmentReads,
        renewal_tests::{Fixture, wait_until},
    },
};
use std::{cell::Cell, time::Duration};

fn pending(fixture: &Fixture) -> (BodyHistory, VerifiedStreamTokenCustodyStateV1, Terms) {
    wait_until(
        fixture.initial.issued_at_unix_ms + 2_000,
        Duration::from_secs(4),
    );
    let (checkpoint, current) = fixture.current();
    // This is the existing explicit requested-deadline pattern. The generated policy and
    // selected body validity are unchanged; no fixture clock is advanced or rewritten.
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
    let (selection, validations) = count(|| {
        Selection::new(
            &fixture.owner,
            CustodyPurpose::Renewal(2),
            &unsigned,
            &terms.fees,
        )
    });
    let selection = selection.unwrap();
    assert_eq!(validations, 1);
    let history = BodyHistory::initialize(
        &fixture.owner,
        CustodyPurpose::Renewal(2),
        unsigned,
        &terms.fees,
        &SigningTurn::Explicit(&terms),
        fixture.options.deadline,
    )
    .unwrap();
    assert_eq!(
        history.selection.digest().unwrap(),
        selection.digest().unwrap()
    );
    assert!(history.original().unwrap().is_none());
    assert!(history.has_pending());
    (history, current, terms)
}

#[test]
fn unsigned_body_reads_share_one_plan_and_recheck_complete_profile_on_every_call() {
    let _guard = crate::managed::native_test_guard();
    let fixture = Fixture::enrolled(4_000);
    let peers = UnavailablePeers::start(&fixture.prepared);
    let (history, current, _) = pending(&fixture);
    let expected = history.selection.digest().unwrap();
    let (read, validations) = count(|| history.read_current(&fixture.owner));
    let read = read.unwrap();
    assert_eq!(
        validations, 2,
        "one entry and one post-inspection full-image fence"
    );
    assert_eq!(read.selection.digest().unwrap(), expected);
    assert!(Arc::ptr_eq(&history.root, &read.root));
    drop(read);
    let (read, validations) =
        count(|| BodyHistory::open(&fixture.owner, CustodyPurpose::Renewal(2)));
    assert_eq!(read.unwrap().unwrap().selection.digest().unwrap(), expected);
    assert_eq!(validations, 2);

    let (checked, validations) = count(|| -> Result<()> {
        let plan = history.verify_fresh_predecessor(&fixture.owner, &current)?;
        let unsigned = &history.anchor.pending.as_ref().unwrap().unsigned;
        unsigned.validate(&fixture.owner, CustodyPurpose::Renewal(2), || Ok(&plan))?;
        let mut changed = unsigned.clone();
        changed.statement.expires_at_unix_ms -= 1;
        assert!(
            changed
                .validate(&fixture.owner, CustodyPurpose::Renewal(2), || Ok(&plan))
                .is_err()
        );
        Ok(())
    });
    checked.unwrap();
    assert_eq!(validations, 1);

    let generation =
        PrivateDirectory::open_exact(fixture.prepared.context.client_config.parent().unwrap())
            .unwrap();
    let original = generation.read("peer3.toml", 1024 * 1024).unwrap();
    let mut changed = original.clone();
    changed.extend_from_slice(b"\n# same semantic configuration, different original bytes\n");
    generation
        .write_atomic("peer3.toml", &changed, PublishMode::Replace)
        .unwrap();
    for result in [
        history.read_current(&fixture.owner).map(Some),
        BodyHistory::open(&fixture.owner, CustodyPurpose::Renewal(2)),
    ] {
        assert!(
            matches!(result, Err(crate::managed::Error::Invalid(message))
            if message == "retained service profile input custody differs")
        );
    }
    assert!(
        history
            .verify_fresh_predecessor(&fixture.owner, &current)
            .is_err()
    );
    generation
        .write_atomic("peer3.toml", &original, PublishMode::Replace)
        .unwrap();
    assert_eq!(
        history
            .read_current(&fixture.owner)
            .unwrap()
            .selection
            .digest()
            .unwrap(),
        expected
    );

    // The selected provider's plan cannot freeze or omit another closed original namespace.
    let providers = generation
        .open_child("runtime")
        .unwrap()
        .open_child("stream-token-authorities")
        .unwrap()
        .open_child("providers")
        .unwrap();
    let other = providers.open_child("2").unwrap();
    other
        .write_atomic("unexpected.key", b"not a key", PublishMode::CreateNew)
        .unwrap();
    assert!(history.read_current(&fixture.owner).is_err());
    assert!(BodyHistory::open(&fixture.owner, CustodyPurpose::Renewal(2)).is_err());
    std::fs::remove_file(other.path().join("unexpected.key")).unwrap();
    assert_eq!(
        history
            .read_current(&fixture.owner)
            .unwrap()
            .selection
            .digest()
            .unwrap(),
        expected
    );
    assert!(
        history
            .root
            .entries(4)
            .unwrap()
            .iter()
            .all(|name| name != "bodies")
    );
    assert_eq!(fixture.native.chain.height(), 4);
    assert!(peers.requests.lock().unwrap().is_empty());
}

struct ChangeProfileDuringHistorical<'a> {
    native: NativeEnrollmentReads<'a>,
    generation: &'a PrivateDirectory,
    changed: &'a [u8],
    called: Cell<bool>,
}
impl EnrollmentReads for ChangeProfileDuringHistorical<'_> {
    fn historical(
        &self,
        owner: &ManagedStreamTokenCustody,
        policy: &SignerCustodyPolicyV1,
        checkpoint: &FinalityVerifier,
        deadline: Instant,
    ) -> Result<VerifiedStreamTokenCustodyStateV1> {
        let current = self
            .native
            .historical(owner, policy, checkpoint, deadline)?;
        assert!(!self.called.replace(true));
        self.generation
            .write_atomic("peer3.toml", self.changed, PublishMode::Replace)?;
        Ok(current)
    }
}

#[test]
fn changed_profile_during_actual_historical_read_refuses_attester_and_original_publication() {
    let _guard = crate::managed::native_test_guard();
    let fixture = Fixture::enrolled(4_000);
    let peers = UnavailablePeers::start(&fixture.prepared);
    let (history, current, terms) = pending(&fixture);
    let unsigned = encode(
        &history.anchor.pending.as_ref().unwrap().unsigned,
        MAX_BODY_BYTES,
    )
    .unwrap();
    let root = Arc::clone(&history.root);
    let generation =
        PrivateDirectory::open_exact(fixture.prepared.context.client_config.parent().unwrap())
            .unwrap();
    let original = generation.read("peer3.toml", 1024 * 1024).unwrap();
    let mut changed = original.clone();
    changed.extend_from_slice(b"\n# changed during an actual native proof callback\n");
    let reads = ChangeProfileDuringHistorical {
        native: NativeEnrollmentReads(&fixture.native),
        generation: &generation,
        changed: &changed,
        called: Cell::new(false),
    };
    let error = match history.finish_pending_with_reads(
        &fixture.owner,
        &current,
        &SigningTurn::Explicit(&terms),
        fixture.options.deadline,
        &reads,
    ) {
        Ok(_) => panic!("profile substitution must refuse at the actual attester boundary"),
        Err(error) => error,
    };
    assert!(reads.called.get());
    assert!(
        error
            .to_string()
            .contains("invalid original custody-attester profile")
    );
    let body = root
        .open_child("bodies")
        .unwrap()
        .open_child("0001")
        .unwrap();
    assert_eq!(
        body.entries(2).unwrap(),
        vec![std::ffi::OsString::from("reserved.nrt")]
    );
    let anchor: Anchor = read(&root, "anchor.nrt", MAX_BODY_BYTES).unwrap();
    assert_eq!(anchor.active, Some(1));
    assert!(anchor.pending.is_none());
    assert!(anchor.completed.is_none());
    generation
        .write_atomic("peer3.toml", &original, PublishMode::Replace)
        .unwrap();
    let restored = BodyHistory::open(&fixture.owner, CustodyPurpose::Renewal(2))
        .unwrap()
        .unwrap();
    assert!(restored.original().unwrap().is_none());
    let completed = restored
        .finish_pending_with_reads(
            &fixture.owner,
            &current,
            &SigningTurn::Explicit(&terms),
            fixture.options.deadline,
            &NativeEnrollmentReads(&fixture.native),
        )
        .unwrap();
    assert!(completed.original().unwrap().is_some());
    assert_eq!(
        completed.anchor.completed,
        Some(completed.original().unwrap().unwrap().digest().unwrap())
    );
    assert_eq!(
        encode(&completed.bodies[0].reservation.unsigned, MAX_BODY_BYTES).unwrap(),
        unsigned
    );
    assert!(!body.path().join("dispatch.nrt").exists());
    assert!(!body.path().join("attempts").exists());
    assert_eq!(fixture.native.chain.height(), 4);
    assert!(peers.requests.lock().unwrap().is_empty());
}
