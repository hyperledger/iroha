//! Explicit private-worker DATA validates durable ordering, never platform/runtime admission.
use super::*;

const CONFIGURATION: [u8; 32] = [31; 32];
const INCARNATION: [u8; 32] = [41; 32];
const EXCHANGE: [u8; 32] = [42; 32];

pub(crate) fn response(packet: &VerifierExchangeV1, outcome: &str) -> Vec<u8> {
    let bytes = &packet.frame()[4..];
    let request: norito::json::Value = norito::json::from_slice(bytes).unwrap();
    let value = norito::json!({
        "schema": ("iroha.kagemusha.wallet-e1-verifier.v1"), "version": (1_u16),
        "exchange_id": (request.get("exchange_id").unwrap().clone()),
        "request_sha256": (hex::encode(Sha256::digest(bytes))),
        "journal_incarnation": (request.get("journal_incarnation").unwrap().clone()),
        "config_sha256": (hex::encode(CONFIGURATION)),
        "outcome": (outcome), "evidence_base64": (norito::json::Value::Null),
        "refusal_code": (norito::json::Value::Null),
    });
    let bytes = norito::json::to_vec(&value).unwrap();
    let mut frame = (bytes.len() as u32).to_le_bytes().to_vec();
    frame.extend(bytes);
    frame
}

pub(crate) fn prepare(
    journal: &mut EnrollmentJournalV1,
    attempt: &mut EnrollmentAttemptV1,
    dispatch: &PreKeyDispatchV1,
) {
    journal
        .select_worker_preparation(attempt, dispatch, CONFIGURATION, INCARNATION)
        .unwrap();
    let packet = journal
        .worker_preparation_exchange(attempt, CONFIGURATION, EXCHANGE)
        .unwrap();
    journal
        .retain_worker_prepared(
            attempt,
            CONFIGURATION,
            EXCHANGE,
            &response(&packet, "prepared"),
        )
        .unwrap();
}

#[test]
fn no_permit_or_account_verification_precedes_durable_worker_preparation() {
    let (_temp, _parent, mut journal) = super::super::tests::initialized();
    let (dispatch, mut attempt, signer) =
        super::super::permit_tests::unprepared_fixture(&mut journal);
    let permit = super::super::permit_tests::signed(
        &dispatch,
        super::super::permit_tests::body(&dispatch, &attempt),
        &signer,
    );
    assert_eq!(
        journal.retain_permit(&attempt, &dispatch, permit.clone()),
        Err(Conflict)
    );
    let request = super::super::permit_tests::account_request(&dispatch, &attempt);
    assert!(matches!(
        journal.select_verification(&mut attempt, request.clone(), CONFIGURATION, 2_000),
        Err(Conflict)
    ));
    journal
        .select_worker_preparation(&mut attempt, &dispatch, CONFIGURATION, INCARNATION)
        .unwrap();
    assert_eq!(
        journal.retain_permit(&attempt, &dispatch, permit.clone()),
        Err(Conflict)
    );
    assert!(matches!(
        journal.select_verification(&mut attempt, request.clone(), CONFIGURATION, 2_000),
        Err(Conflict)
    ));
    let packet = journal
        .worker_preparation_exchange(&attempt, CONFIGURATION, EXCHANGE)
        .unwrap();
    for outcome in [
        "unavailable",
        "outcome_unknown",
        "rejected",
        "evidence",
        "journal",
    ] {
        assert!(
            journal
                .retain_worker_prepared(
                    &mut attempt,
                    CONFIGURATION,
                    EXCHANGE,
                    &response(&packet, outcome)
                )
                .is_err()
        );
        assert!(
            attempt
                .record
                .worker_preparation
                .as_ref()
                .unwrap()
                .ready
                .is_none()
        );
    }
    journal
        .retain_worker_prepared(
            &mut attempt,
            CONFIGURATION,
            EXCHANGE,
            &response(&packet, "prepared"),
        )
        .unwrap();
    journal.retain_permit(&attempt, &dispatch, permit).unwrap();
    journal
        .select_verification(&mut attempt, request, CONFIGURATION, 2_000)
        .unwrap();
}

#[test]
fn selected_incarnation_and_preparation_survive_restart_and_lost_acknowledgment() {
    let (temp, _parent, mut journal) = super::super::tests::initialized();
    let (dispatch, mut attempt, _) = super::super::permit_tests::unprepared_fixture(&mut journal);
    let original = journal
        .select_worker_preparation(&mut attempt, &dispatch, CONFIGURATION, INCARNATION)
        .unwrap()
        .original()
        .to_vec();
    let packet = journal
        .worker_preparation_exchange(&attempt, CONFIGURATION, EXCHANGE)
        .unwrap();
    let reply = response(&packet, "prepared");
    // Worker committed its preparation, then the parent lost the pipe before retaining it.
    drop(journal);
    let mut journal =
        EnrollmentJournalV1::open(&temp.path().join("issuer"), b"approved scope DATA").unwrap();
    let mut attempt = journal.read(&attempt.selection().key).unwrap().unwrap();
    assert_eq!(
        journal
            .select_worker_preparation(&mut attempt, &dispatch, CONFIGURATION, INCARNATION)
            .unwrap()
            .original(),
        original
    );
    assert!(matches!(
        journal.select_worker_preparation(&mut attempt, &dispatch, CONFIGURATION, [99; 32]),
        Err(Conflict)
    ));
    assert!(matches!(
        journal.select_worker_preparation(&mut attempt, &dispatch, [99; 32], INCARNATION),
        Err(Conflict)
    ));
    assert!(
        journal
            .retain_worker_prepared(&mut attempt, CONFIGURATION, [99; 32], &reply)
            .is_err()
    );
    journal
        .retain_worker_prepared(&mut attempt, CONFIGURATION, EXCHANGE, &reply)
        .unwrap();
    let retained = attempt
        .record
        .worker_preparation
        .as_ref()
        .unwrap()
        .ready
        .clone()
        .unwrap();
    let next = journal
        .worker_preparation_exchange(&attempt, CONFIGURATION, [43; 32])
        .unwrap();
    journal
        .retain_worker_prepared(
            &mut attempt,
            CONFIGURATION,
            [43; 32],
            &response(&next, "prepared"),
        )
        .unwrap();
    assert!(
        attempt
            .record
            .worker_preparation
            .as_ref()
            .unwrap()
            .ready
            .as_ref()
            == Some(&retained)
    );
    assert_eq!(
        journal
            .require_worker_prepared(&attempt, CONFIGURATION)
            .unwrap()
            .original(),
        original
    );
}

#[test]
fn changed_original_or_preparation_acknowledgment_cannot_admit_an_attempt() {
    let (_temp, _parent, mut journal) = super::super::tests::initialized();
    let (dispatch, mut attempt, _) = super::super::permit_tests::fixture(&mut journal);
    for field in 0..4 {
        let mut record = attempt.record.clone();
        let selected = record.worker_preparation.as_mut().unwrap();
        match field {
            0 => selected.original.push(b' '),
            1 => selected.incarnation[0] ^= 1,
            2 => selected.ready.as_mut().unwrap().exchange[0] ^= 1,
            _ => selected.ready.as_mut().unwrap().response.push(b' '),
        }
        let bytes = encode(&record).unwrap();
        journal
            .directory
            .write_atomic(
                &filename(&attempt.selection().key).unwrap(),
                &bytes,
                PublishMode::Replace,
            )
            .unwrap();
        let changed = journal.read(&attempt.selection().key).unwrap().unwrap();
        assert!(
            journal
                .require_worker_prepared(&changed, CONFIGURATION)
                .is_err()
        );
        journal
            .directory
            .write_atomic(
                &filename(&attempt.selection().key).unwrap(),
                &attempt.original,
                PublishMode::Replace,
            )
            .unwrap();
    }
    let mut foreign = dispatch;
    foreign.request_id[0] ^= 1;
    assert!(matches!(
        journal.select_worker_preparation(&mut attempt, &foreign, CONFIGURATION, INCARNATION),
        Err(Conflict)
    ));
}

#[test]
fn selected_account_verification_cannot_reprepare_worker_after_restart() {
    use iroha_core_zk::kagemusha_wallet_enrollment_v1::issuer_worker::ActionV1;

    let (temp, _parent, mut journal) = super::super::tests::initialized();
    let (dispatch, mut attempt, signer) = super::super::permit_tests::fixture(&mut journal);
    let packet = journal
        .worker_preparation_exchange(&attempt, CONFIGURATION, EXCHANGE)
        .unwrap();
    let prepared = response(&packet, "prepared");
    let permit = super::super::permit_tests::signed(
        &dispatch,
        super::super::permit_tests::body(&dispatch, &attempt),
        &signer,
    );
    journal.retain_permit(&attempt, &dispatch, permit).unwrap();
    let request = super::super::permit_tests::account_request(&dispatch, &attempt);
    journal
        .select_verification(&mut attempt, request, CONFIGURATION, 2_000)
        .unwrap();
    let key = attempt.selection().key;
    drop(journal);
    let mut journal =
        EnrollmentJournalV1::open(&temp.path().join("issuer"), b"approved scope DATA").unwrap();
    let mut attempt = journal.read(&key).unwrap().unwrap();
    let original = attempt.original.clone();
    // A lost worker record may have been claimed before the interruption. Only recovery of
    // that original may be attempted; sending Prepare again could recreate it as unclaimed.
    assert!(matches!(
        journal.select_worker_preparation(&mut attempt, &dispatch, CONFIGURATION, INCARNATION),
        Err(Conflict)
    ));
    assert!(matches!(
        journal.worker_preparation_exchange(&attempt, CONFIGURATION, EXCHANGE),
        Err(Conflict)
    ));
    assert_eq!(
        journal.retain_worker_prepared(&mut attempt, CONFIGURATION, EXCHANGE, &prepared),
        Err(Conflict)
    );
    journal
        .worker_exchange(&attempt, CONFIGURATION, ActionV1::Recover, EXCHANGE, 2_001)
        .unwrap();
    assert_eq!(attempt.original, original);
    assert_eq!(journal.read(&key).unwrap().unwrap().original, original);
}
