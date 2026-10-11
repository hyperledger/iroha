//! `Advance` tests: the G1 capsule interface, expected heads, the released chain and its
//! byte-identical retries, request validation, operation-identity rules, competing operations,
//! pending signing, capacity and the ballast.

use std::sync::Mutex;

use iroha_data_model::kagemusha::{
    KagemushaDeviceSignatureV1, KagemushaWalletCompletionRecordV1, KagemushaWalletEffectV1,
    KagemushaWalletLifecycleV1, KagemushaWalletReceiptSignerV1, KagemushaWalletRecoveryCapsuleV1,
    KagemushaWalletStatementV1, KagemushaWalletTerminalReasonV1,
    kagemusha_wallet_provider_contract_v1,
};

use super::*;
use crate::kagemusha_wallet_advance_v1::*;
use crate::kagemusha_wallet_advance_v1::{
    KAGEMUSHA_WALLET_BALLAST_NAME_V1, KagemushaWalletAnchorPolicyV1, KagemushaWalletCopyV1,
    KagemushaWalletDestructiveConfirmationV1, KagemushaWalletProviderOptionsV1,
    KagemushaWalletSimFaultV1, KagemushaWalletSimStepV1, kagemusha_wallet_capsules_dir_v1,
    kagemusha_wallet_completion_dir_v1, kagemusha_wallet_completion_name_v1,
    kagemusha_wallet_markers_dir_v1,
    test_support::{
        BOOT_A, DeviceV1, SimProviderV1, TEST_BALLAST_BYTES, TestOwnerV1, WalletFixtureV1,
        advance_request, bootstrap_capsule, bootstrap_capsule_variant, bootstrapped_device,
        capsule_for, commitment, enrolled_device, field_value, next_capsule, next_capsule_variant,
        released, stand_in_map_openings, wallet_fixture,
    },
};

const ANDROID: KagemushaWalletAnchorPolicyV1 = KagemushaWalletAnchorPolicyV1::NotRequired;
type OutcomeV1 = KagemushaWalletAdvanceOutcomeV1<KagemushaWalletCompletionRecordV1>;

/// Growth-class `Retiring` capsule following `previous`.
fn retiring_capsule(
    f: &WalletFixtureV1,
    previous: &KagemushaWalletRecoveryCapsuleV1,
) -> KagemushaWalletRecoveryCapsuleV1 {
    let statement = KagemushaWalletStatementV1 {
        lifecycle: KagemushaWalletLifecycleV1::Retiring,
        sequence: previous.body().statement.sequence + 1,
        predecessor: previous.body().statement.successor,
        successor: commitment(0x31),
        lineage_pending_outgoing_root: field_value(0x39),
        effect: KagemushaWalletEffectV1::Retiring,
        ..previous.body().statement
    };
    capsule_for(f, statement, previous.custody_digest(), 0x33)
}

fn current(
    provider: &mut SimProviderV1,
    slot: &KagemushaWalletSlotIdV1,
) -> KagemushaWalletMarkerRecordV1 {
    provider
        .status(slot)
        .expect("status")
        .marker()
        .expect("marker")
        .clone()
}

/// Bytes in use on the device, so a capacity of exactly this leaves no free space.
fn in_use(device: &DeviceV1) -> u64 {
    let probe = device.fs.fork();
    probe.set_capacity(Some(u64::MAX / 4));
    u64::MAX / 4 - probe.available_bytes().expect("free")
}

fn visible(device: &DeviceV1, dir: &KagemushaWalletCustodyDirV1) -> Vec<String> {
    device.fs.visible_names(dir)
}

/// An owner whose receipt body or assembly fails.
struct FailingOwnerV1 {
    body: bool,
}

impl
    KagemushaWalletTransitionOwnerV1<
        KagemushaWalletRecoveryCapsuleV1,
        KagemushaWalletCompletionRecordV1,
    > for FailingOwnerV1
{
    fn receipt_body(
        &self,
        capsule: &KagemushaWalletRecoveryCapsuleV1,
        capsule_digest: &[u8; 32],
    ) -> Result<Vec<u8>, KagemushaWalletProviderErrorV1> {
        if self.body {
            return Err(KagemushaWalletProviderErrorV1::Invalid {
                field: "owner.body",
            });
        }
        TestOwnerV1.receipt_body(capsule, capsule_digest)
    }

    fn require_completion(
        &self,
        capsule: &KagemushaWalletRecoveryCapsuleV1,
        record: &KagemushaWalletCompletionRecordV1,
    ) -> Result<(), KagemushaWalletProviderErrorV1> {
        record
            .require_capsule(capsule)
            .map_err(|_| KagemushaWalletProviderErrorV1::Invalid {
                field: "completion.capsule",
            })
    }

    fn assemble(
        &self,
        _capsule: &KagemushaWalletRecoveryCapsuleV1,
        _capsule_digest: &[u8; 32],
        _signature: &KagemushaDeviceSignatureV1,
    ) -> Result<KagemushaWalletCompletionRecordV1, KagemushaWalletProviderErrorV1> {
        Err(KagemushaWalletProviderErrorV1::Invalid {
            field: "owner.assemble",
        })
    }
}

#[test]
fn wallet_advance_v1_advance_g1_capsule_interface() {
    let f = wallet_fixture(0x70);
    let bootstrap = bootstrap_capsule(&f);
    let next = next_capsule(&f, &bootstrap);
    let retiring = retiring_capsule(&f, &bootstrap);
    assert_eq!(
        <KagemushaWalletRecoveryCapsuleV1 as KagemushaWalletAdvanceCapsuleV1>::marker_binding(
            &f.enrollment
        ),
        f.scheme_id()
    );
    for capsule in [&bootstrap, &next, &retiring] {
        assert_eq!(
            KagemushaWalletAdvanceCapsuleV1::operation_id(capsule),
            capsule.body().operation_id
        );
        assert_eq!(
            KagemushaWalletAdvanceCapsuleV1::head_marker_state(capsule),
            Ok(capsule.head_marker_state())
        );
        assert_eq!(
            capsule.bound_proof_digest(),
            Ok(capsule.proof_digest().expect("proof digest"))
        );
        assert_eq!(
            capsule.predecessor_commitment(),
            capsule.body().statement.predecessor
        );
    }
    assert!(bootstrap.predecessor_commitment().is_zero());
    assert_eq!(
        bootstrap.bootstrap_enrollment_marker(),
        Some(f.enrollment.marker_digest().expect("digest"))
    );
    assert_eq!(next.bootstrap_enrollment_marker(), None);
    assert_eq!(
        bootstrap.capacity_class(),
        KagemushaWalletCapacityClassV1::Growth
    );
    assert_eq!(
        retiring.capacity_class(),
        KagemushaWalletCapacityClassV1::Growth
    );
    assert_eq!(
        next.capacity_class(),
        KagemushaWalletCapacityClassV1::Cleanup
    );
    let mut invalid = bootstrap.body().clone();
    invalid.wallet_id = [0; 32];
    assert!(
        invalid.freeze().is_err(),
        "invalid body has no head marker state"
    );
}

#[test]
fn wallet_advance_v1_advance_expected_head_of_each_phase() {
    let f = wallet_fixture(0x71);
    let enrollment = f.enrollment_record(BOOT_A);
    let capsule = bootstrap_capsule(&f);
    let selected = enrollment
        .select(capsule.head_marker_state(), BOOT_A)
        .expect("select");
    let released = selected.release([0xc7; 32], BOOT_A).expect("release");
    let terminal = released
        .terminate(KagemushaWalletTerminalReasonV1::CustodyDeleted, BOOT_A)
        .expect("terminal");
    assert_eq!(
        KagemushaWalletExpectedHeadV1::of(&enrollment),
        Some(KagemushaWalletExpectedHeadV1::Enrollment {
            marker_digest: *enrollment.marker_digest()
        })
    );
    assert_eq!(KagemushaWalletExpectedHeadV1::of(&selected), None);
    assert_eq!(
        KagemushaWalletExpectedHeadV1::of(&released),
        Some(KagemushaWalletExpectedHeadV1::Released {
            sequence: 0,
            head: capsule.body().statement.successor,
            capsule_digest: capsule.custody_digest(),
        })
    );
    assert_eq!(KagemushaWalletExpectedHeadV1::of(&terminal), None);
    assert_eq!(
        head_commitment(&released),
        Some(capsule.body().statement.successor)
    );
    assert_eq!(head_commitment(&enrollment), None);
}

#[test]
fn wallet_advance_v1_advance_releases_a_chain_with_identical_retries() {
    let (device, f, slot) = enrolled_device(ANDROID, 0x72);
    let mut provider = device.open();
    let enrollment = current(&mut provider, &slot);
    let bootstrap = bootstrap_capsule(&f);
    let request = advance_request(&enrollment, &bootstrap);
    let first = provider
        .advance(&slot, &TestOwnerV1, &request)
        .expect("bootstrap");
    let KagemushaWalletAdvanceOutcomeV1::Released { retained, resumed } = &first else {
        panic!("released");
    };
    assert!(!resumed);
    assert_eq!(retained.operation_id, bootstrap.body().operation_id);
    assert_eq!(retained.selected_generation, 1);
    assert_eq!(
        retained.frame,
        retained.record.to_canonical_bytes().expect("frame")
    );
    // The released receipt must verify through the independent model consumer, which
    // recomputes its canonical 338-byte body and 32-byte Poseidon signing message.
    let signer = KagemushaWalletReceiptSignerV1 {
        scheme_id: f.scheme_id(),
        wallet_id: f.wallet_id(),
        provider_contract: kagemusha_wallet_provider_contract_v1(),
        payment_key: f.payment_key,
    };
    retained
        .record
        .receipt
        .verify(&signer, &bootstrap.body().statement, &request.proof_digest)
        .expect("receipt verifies from the frozen capsule");
    let mut changed_proof = request.proof_digest;
    changed_proof[0] ^= 1;
    assert!(
        retained
            .record
            .receipt
            .verify(&signer, &bootstrap.body().statement, &changed_proof)
            .is_err(),
        "the receipt binds the exact frozen proof"
    );
    // Every retry, in this process and after a restart, returns the same bytes.
    let retry = provider
        .advance(&slot, &TestOwnerV1, &request)
        .expect("retry");
    assert_eq!(
        retry,
        KagemushaWalletAdvanceOutcomeV1::Released {
            retained: retained.clone(),
            resumed: true
        }
    );
    drop(provider);
    device.fs.restart();
    let mut provider = device.open();
    assert_eq!(
        provider.advance(&slot, &TestOwnerV1, &request),
        Ok(retry.clone())
    );
    let head = current(&mut provider, &slot);
    assert_eq!(head.generation(), 2);
    assert_eq!(head.completion_digest(), Some(retained.completion_digest));
    assert_eq!(
        visible(&device, &kagemusha_wallet_markers_dir_v1(&slot)).len(),
        1
    );
    // The next head, then lookups of both operations.
    let next = next_capsule(&f, &bootstrap);
    let second = released(
        provider
            .advance(&slot, &TestOwnerV1, &advance_request(&head, &next))
            .expect("next"),
    );
    assert_eq!(second.selected_generation, 3);
    assert_eq!(
        provider.lookup(&slot, &bootstrap.body().operation_id),
        Ok(KagemushaWalletLookupV1::Retained(retained.clone()))
    );
    assert_eq!(
        provider.lookup(&slot, &next.body().operation_id),
        Ok(KagemushaWalletLookupV1::Retained(Box::new(second.clone())))
    );
    assert_eq!(
        provider.lookup(&slot, &[0x55; 32]),
        Ok(KagemushaWalletLookupV1::Unknown)
    );
    // Retrying the older operation returns its retained result.
    assert_eq!(provider.advance(&slot, &TestOwnerV1, &request), Ok(retry));
    assert!(device.platform.with(|state| state.violations.is_empty()));
    assert_eq!(device.platform.with(|state| state.sign_calls), 2);
}

#[test]
fn wallet_advance_v1_advance_validates_requests_without_writing() {
    let (device, f, slot, bootstrap) = bootstrapped_device(ANDROID, 0x73);
    let mut provider = device.open();
    let head = current(&mut provider, &slot);
    let next = next_capsule(&f, &bootstrap);
    let good = advance_request(&head, &next);
    let markers = kagemusha_wallet_markers_dir_v1(&slot);
    let capsules = kagemusha_wallet_capsules_dir_v1(&slot);
    let before = (visible(&device, &markers), visible(&device, &capsules));
    let not_performed = |reason| Ok(KagemushaWalletAdvanceOutcomeV1::NotPerformed(reason));
    let invalid = |field| not_performed(KagemushaWalletNotPerformedV1::Invalid { field });
    let mut stale = good.clone();
    stale.expected = KagemushaWalletExpectedHeadV1::Enrollment {
        marker_digest: *f.enrollment_record(BOOT_A).marker_digest(),
    };
    assert_eq!(
        provider.advance(&slot, &TestOwnerV1, &stale),
        not_performed(KagemushaWalletNotPerformedV1::StaleHead)
    );
    let mut wrong_head = good.clone();
    wrong_head.new_head = commitment(0x01);
    assert_eq!(
        provider.advance(&slot, &TestOwnerV1, &wrong_head),
        invalid("new_head")
    );
    let mut wrong_proof = good.clone();
    wrong_proof.proof_digest = [0x02; 32];
    assert_eq!(
        provider.advance(&slot, &TestOwnerV1, &wrong_proof),
        invalid("proof_digest")
    );
    let mut wrong_op = good.clone();
    wrong_op.operation_id = [0x03; 32];
    assert_eq!(
        provider.advance(&slot, &TestOwnerV1, &wrong_op),
        invalid("operation_id")
    );
    // A capsule of a later sequence, or a second Bootstrap, does not link to this head.
    let skipping = advance_request(&head, &next_capsule(&f, &next));
    assert_eq!(
        provider.advance(&slot, &TestOwnerV1, &skipping),
        invalid("capsule.predecessor")
    );
    // A second Bootstrap reuses the Bootstrap operation identity with other inputs.
    let mut second_bootstrap = advance_request(&head, &bootstrap_capsule_variant(&f, 1));
    second_bootstrap.expected = good.expected;
    let Ok(KagemushaWalletLookupV1::Retained(bootstrap_result)) =
        provider.lookup(&slot, &bootstrap.body().operation_id)
    else {
        panic!("bootstrap retained");
    };
    assert_eq!(
        provider.advance(&slot, &TestOwnerV1, &second_bootstrap),
        Err(KagemushaWalletProviderErrorV1::OperationIdConflict {
            retained: bootstrap_result.status()
        })
    );
    let mut undecodable = good.capsule.body().clone();
    undecodable.wallet_id = [0; 32];
    assert!(
        undecodable.freeze().is_err(),
        "malformed body cannot reach Advance"
    );
    let mut overflow = good.clone();
    overflow.growth_bytes = u64::MAX;
    assert_eq!(
        provider.advance(&slot, &TestOwnerV1, &overflow),
        Err(KagemushaWalletProviderErrorV1::Invalid {
            field: "growth_bytes"
        })
    );
    assert_eq!(
        (visible(&device, &markers), visible(&device, &capsules)),
        before
    );
    released(provider.advance(&slot, &TestOwnerV1, &good).expect("good"));
    assert_eq!(device.platform.with(|state| state.sign_calls), 2);
}

#[test]
fn wallet_advance_v1_advance_operation_identity_rules() {
    let (base, f, slot, bootstrap) = bootstrapped_device(ANDROID, 0x74);
    let next = next_capsule(&f, &bootstrap);
    // A staging attempt discarded by reconcile frees the operation identity.
    let device = base.fork();
    let mut provider = device.open();
    let head = current(&mut provider, &slot);
    let request = advance_request(&head, &next);
    let probe = base.fork();
    let mut probe_provider = probe.open();
    current(&mut probe_provider, &slot);
    let start = probe.fs.steps();
    released(
        probe_provider
            .advance(&slot, &TestOwnerV1, &request)
            .expect("probe"),
    );
    let trace = probe.fs.trace_since(start);
    let selected_rename = trace
        .iter()
        .enumerate()
        .filter(|(_, step)| **step == KagemushaWalletSimStepV1::RenameNoReplace)
        .nth(2)
        .map(|(index, _)| u64::try_from(index).expect("index"))
        .expect("Selected marker rename");
    let start = device.fs.steps();
    device.fs.inject(
        start + selected_rename,
        KagemushaWalletSimFaultV1::CrashBefore,
    );
    assert_eq!(
        provider.advance(&slot, &TestOwnerV1, &request),
        Ok(KagemushaWalletAdvanceOutcomeV1::Pending {
            operation_id: request.operation_id
        })
    );
    drop(provider);
    device.fs.restart();
    let mut provider = device.open();
    assert_eq!(
        provider.lookup(&slot, &next.body().operation_id),
        Ok(KagemushaWalletLookupV1::Unknown),
        "staging without its marker selects nothing"
    );
    let first = provider
        .advance(&slot, &TestOwnerV1, &request)
        .expect("fresh");
    assert!(matches!(
        first,
        KagemushaWalletAdvanceOutcomeV1::Released { resumed: false, .. }
    ));
    // Changed inputs under a used identity conflict; the retained operation is untouched.
    let mut changed = request.clone();
    let mut body = changed.capsule.body().clone();
    body.map_openings = stand_in_map_openings(9);
    changed.capsule = body.freeze().unwrap().seal([0; 32]).unwrap();
    let retained = released(first.clone());
    assert_eq!(
        provider.advance(&slot, &TestOwnerV1, &changed),
        Err(KagemushaWalletProviderErrorV1::OperationIdConflict {
            retained: retained.status()
        })
    );
    assert_eq!(
        provider.advance(&slot, &TestOwnerV1, &request),
        Ok(KagemushaWalletAdvanceOutcomeV1::Released {
            retained: Box::new(retained.clone()),
            resumed: true
        })
    );
    // An older identity with corrupt copies everywhere is delivery-data loss.
    let dir = kagemusha_wallet_completion_dir_v1(&slot);
    for copy in KagemushaWalletCopyV1::BOTH {
        device.fs.place_unsynced(
            &dir,
            kagemusha_wallet_completion_name_v1(&bootstrap.body().operation_id, copy).as_str(),
            b"corrupt",
        );
    }
    let enrollment = f.enrollment_record(BOOT_A);
    assert_eq!(
        provider.advance(
            &slot,
            &TestOwnerV1,
            &advance_request(&enrollment, &bootstrap)
        ),
        Ok(KagemushaWalletAdvanceOutcomeV1::DeliveryDataLoss {
            operation_id: bootstrap.body().operation_id
        })
    );
}

#[test]
fn wallet_advance_v1_advance_competing_operations_release_one_successor() {
    let (device, f, slot, bootstrap) = bootstrapped_device(ANDROID, 0x75);
    let mut provider = device.open();
    let head = current(&mut provider, &slot);
    let requests = [
        advance_request(&head, &next_capsule(&f, &bootstrap)),
        advance_request(&head, &next_capsule_variant(&f, &bootstrap, 1)),
    ];
    let provider = Mutex::new(provider);
    let outcomes: Vec<Result<OutcomeV1, KagemushaWalletProviderErrorV1>> =
        std::thread::scope(|scope| {
            let handles: Vec<_> = requests
                .iter()
                .map(|request| {
                    let provider = &provider;
                    scope.spawn(move || {
                        provider
                            .lock()
                            .expect("provider")
                            .advance(&slot, &TestOwnerV1, request)
                    })
                })
                .collect();
            handles
                .into_iter()
                .map(|handle| handle.join().expect("thread"))
                .collect()
        });
    let released_count = outcomes
        .iter()
        .filter(|outcome| {
            matches!(
                outcome,
                Ok(KagemushaWalletAdvanceOutcomeV1::Released { .. })
            )
        })
        .count();
    let stale_count = outcomes
        .iter()
        .filter(|outcome| {
            **outcome
                == Ok(KagemushaWalletAdvanceOutcomeV1::NotPerformed(
                    KagemushaWalletNotPerformedV1::StaleHead,
                ))
        })
        .count();
    assert_eq!((released_count, stale_count), (1, 1), "{outcomes:?}");
}

#[test]
fn wallet_advance_v1_advance_pending_signing_resumes_the_same_operation() {
    let (device, f, slot, bootstrap) = bootstrapped_device(ANDROID, 0x76);
    let mut provider = device.open();
    let head = current(&mut provider, &slot);
    let next = next_capsule(&f, &bootstrap);
    let request = advance_request(&head, &next);
    device.platform.with(|state| state.sign_unavailable = true);
    let pending = Ok(KagemushaWalletAdvanceOutcomeV1::Pending {
        operation_id: next.body().operation_id,
    });
    assert_eq!(provider.advance(&slot, &TestOwnerV1, &request), pending);
    assert_eq!(provider.advance(&slot, &TestOwnerV1, &request), pending);
    assert_eq!(
        provider.lookup(&slot, &next.body().operation_id),
        Ok(KagemushaWalletLookupV1::SelectedUnsigned {
            capsule_digest: next.custody_digest()
        })
    );
    // While selected, a competing operation is stale and changed inputs conflict.
    let competitor = advance_request(&head, &next_capsule_variant(&f, &bootstrap, 1));
    assert_eq!(
        provider.advance(&slot, &TestOwnerV1, &competitor),
        Ok(KagemushaWalletAdvanceOutcomeV1::NotPerformed(
            KagemushaWalletNotPerformedV1::StaleHead
        ))
    );
    let mut changed = request.clone();
    let mut body = changed.capsule.body().clone();
    body.map_openings = stand_in_map_openings(8);
    changed.capsule = body.freeze().unwrap().seal([0; 32]).unwrap();
    assert_eq!(
        provider.advance(&slot, &TestOwnerV1, &changed),
        Err(KagemushaWalletProviderErrorV1::OperationIdConflict {
            retained: KagemushaWalletRetainedStatusV1::Selected {
                capsule_digest: next.custody_digest()
            }
        })
    );
    assert_eq!(
        provider.pending_reason(&slot),
        Some(KagemushaWalletProviderErrorV1::Unavailable(
            KagemushaWalletUnavailableV1::KeyUnusable
        ))
    );
    // Owner failures after selection leave the performed operation pending, never an error
    // (regression: they used to be returned as errors).
    device.platform.with(|state| state.sign_unavailable = false);
    assert!(matches!(
        provider.reconcile(&slot, &FailingOwnerV1 { body: true }),
        Ok(KagemushaWalletSlotStatusV1::Pending(_))
    ));
    assert_eq!(
        provider.pending_reason(&slot),
        Some(KagemushaWalletProviderErrorV1::Invalid {
            field: "owner.body"
        })
    );
    assert_eq!(
        provider.advance(&slot, &FailingOwnerV1 { body: false }, &request),
        pending
    );
    assert_eq!(
        provider.pending_reason(&slot),
        Some(KagemushaWalletProviderErrorV1::Invalid {
            field: "owner.assemble"
        })
    );
    assert!(matches!(
        provider.status(&slot),
        Ok(KagemushaWalletSlotStatusV1::Pending(_))
    ));
    let resumed = provider
        .advance(&slot, &TestOwnerV1, &request)
        .expect("resumed");
    assert!(matches!(
        resumed,
        KagemushaWalletAdvanceOutcomeV1::Released { resumed: true, .. }
    ));
    assert_eq!(provider.pending_reason(&slot), None, "cleared on release");
    assert!(device.platform.with(|state| state.violations.is_empty()));
}

/// Index of the `nth` (zero-based) step of `kind` in a fault-free run of `request`.
fn step_of(
    base: &DeviceV1,
    slot: &KagemushaWalletSlotIdV1,
    request: &KagemushaWalletAdvanceRequestV1<KagemushaWalletRecoveryCapsuleV1>,
    kind: KagemushaWalletSimStepV1,
    nth: usize,
) -> u64 {
    let probe = base.fork();
    let mut provider = probe.open();
    let start = probe.fs.steps();
    released(
        provider
            .advance(slot, &TestOwnerV1, request)
            .expect("probe"),
    );
    let trace = probe.fs.trace_since(start);
    let index = trace
        .iter()
        .enumerate()
        .filter(|(_, step)| **step == kind)
        .nth(nth)
        .map(|(index, _)| index)
        .expect("step");
    u64::try_from(index).expect("index")
}

#[test]
fn wallet_advance_v1_advance_owner_refusal_happens_before_staging() {
    // Regression: the receipt body is asked in A2, so a capsule the owner cannot certify is
    // never selected (it used to be selected and then fail at every later reconcile).
    let (device, f, slot, bootstrap) = bootstrapped_device(ANDROID, 0x7b);
    let mut provider = device.open();
    let head = current(&mut provider, &slot);
    let request = advance_request(&head, &next_capsule(&f, &bootstrap));
    let dirs = [
        kagemusha_wallet_markers_dir_v1(&slot),
        kagemusha_wallet_capsules_dir_v1(&slot),
        kagemusha_wallet_completion_dir_v1(&slot),
    ];
    let before: Vec<_> = dirs.iter().map(|dir| visible(&device, dir)).collect();
    let signed = device.platform.with(|state| state.sign_calls);
    assert_eq!(
        provider.advance(&slot, &FailingOwnerV1 { body: true }, &request),
        Ok(KagemushaWalletAdvanceOutcomeV1::NotPerformed(
            KagemushaWalletNotPerformedV1::Invalid {
                field: "receipt_body"
            }
        ))
    );
    let after: Vec<_> = dirs.iter().map(|dir| visible(&device, dir)).collect();
    assert_eq!(after, before, "nothing staged or selected");
    assert_eq!(device.platform.with(|state| state.sign_calls), signed);
    released(
        provider
            .advance(&slot, &TestOwnerV1, &request)
            .expect("advance"),
    );
}

#[test]
fn wallet_advance_v1_advance_refuses_a_capsule_of_another_wallet_before_staging() {
    // Regression: a capsule (and so a completion record) bound to another wallet used to be
    // selected, then signed, written, discarded and signed again on every reconcile.
    let (device, f, slot, bootstrap) = bootstrapped_device(ANDROID, 0x7c);
    let mut provider = device.open();
    let head = current(&mut provider, &slot);
    let other = wallet_fixture(0x7d);
    let foreign = next_capsule(&other, &bootstrap);
    assert_ne!(foreign.body().wallet_id, f.wallet_id());
    let request = advance_request(&head, &foreign);
    let capsules = visible(&device, &kagemusha_wallet_capsules_dir_v1(&slot));
    let signed = device.platform.with(|state| state.sign_calls);
    assert_eq!(
        provider.advance(&slot, &TestOwnerV1, &request),
        Ok(KagemushaWalletAdvanceOutcomeV1::NotPerformed(
            KagemushaWalletNotPerformedV1::Invalid {
                field: "capsule.marker"
            }
        ))
    );
    assert_eq!(
        visible(&device, &kagemusha_wallet_capsules_dir_v1(&slot)),
        capsules
    );
    assert_eq!(device.platform.with(|state| state.sign_calls), signed);
    assert_eq!(current(&mut provider, &slot), head);
    // The capsule interface refuses it directly as well.
    let selected = head
        .select(foreign.head_marker_state(), BOOT_A)
        .expect("select");
    assert_eq!(
        KagemushaWalletAdvanceCapsuleV1::require_marker(&foreign, selected.marker()),
        Err(KagemushaWalletProviderErrorV1::Invalid {
            field: "capsule.marker"
        })
    );
    let own = next_capsule(&f, &bootstrap);
    let selected = head
        .select(own.head_marker_state(), BOOT_A)
        .expect("select");
    assert_eq!(
        KagemushaWalletAdvanceCapsuleV1::require_marker(&own, selected.marker()),
        Ok(())
    );
}

#[test]
fn wallet_advance_v1_advance_retries_older_operations_while_one_is_pending() {
    // Regression: while a later head waits for its receipt, a retry of an earlier released
    // operation returns its retained bytes (it used to be StaleHead: "not performed").
    let (device, f, slot, bootstrap) = bootstrapped_device(ANDROID, 0x7e);
    let mut provider = device.open();
    let enrollment = f.enrollment_record(BOOT_A);
    let bootstrap_request = advance_request(&enrollment, &bootstrap);
    let first = released(
        provider
            .advance(&slot, &TestOwnerV1, &bootstrap_request)
            .expect("retained"),
    );
    let head = current(&mut provider, &slot);
    let next = next_capsule(&f, &bootstrap);
    let request = advance_request(&head, &next);
    device.platform.with(|state| state.sign_unavailable = true);
    assert_eq!(
        provider.advance(&slot, &TestOwnerV1, &request),
        Ok(KagemushaWalletAdvanceOutcomeV1::Pending {
            operation_id: next.body().operation_id
        })
    );
    assert_eq!(
        provider.advance(&slot, &TestOwnerV1, &bootstrap_request),
        Ok(KagemushaWalletAdvanceOutcomeV1::Released {
            retained: Box::new(first.clone()),
            resumed: true
        })
    );
    // Changed inputs under the older identity still conflict.
    let mut changed = bootstrap_request.clone();
    changed.capsule = bootstrap_capsule_variant(&f, 1);
    assert_eq!(
        provider.advance(&slot, &TestOwnerV1, &changed),
        Err(KagemushaWalletProviderErrorV1::OperationIdConflict {
            retained: first.status()
        })
    );
    // An operation the slot knows nothing about is stale.
    let unknown = advance_request(&head, &next_capsule_variant(&f, &bootstrap, 1));
    assert_eq!(
        provider.advance(&slot, &TestOwnerV1, &unknown),
        Ok(KagemushaWalletAdvanceOutcomeV1::NotPerformed(
            KagemushaWalletNotPerformedV1::StaleHead
        ))
    );
    // A pruned older operation is archived, not stale.
    let tombstone = provider
        .prune_completion(&slot, &bootstrap.body().operation_id, 7)
        .expect("prune");
    assert_eq!(
        provider.advance(&slot, &TestOwnerV1, &bootstrap_request),
        Ok(KagemushaWalletAdvanceOutcomeV1::Archived(Box::new(
            tombstone
        )))
    );
    device.platform.with(|state| state.sign_unavailable = false);
    released(
        provider
            .advance(&slot, &TestOwnerV1, &request)
            .expect("finished"),
    );
}

#[test]
fn wallet_advance_v1_advance_older_delivery_loss_while_pending() {
    let (device, f, slot, bootstrap) = bootstrapped_device(ANDROID, 0x7f);
    let mut provider = device.open();
    let enrollment = f.enrollment_record(BOOT_A);
    let bootstrap_request = advance_request(&enrollment, &bootstrap);
    let head = current(&mut provider, &slot);
    let next = next_capsule(&f, &bootstrap);
    device.platform.with(|state| state.sign_unavailable = true);
    assert!(matches!(
        provider.advance(&slot, &TestOwnerV1, &advance_request(&head, &next)),
        Ok(KagemushaWalletAdvanceOutcomeV1::Pending { .. })
    ));
    let dir = kagemusha_wallet_completion_dir_v1(&slot);
    for copy in KagemushaWalletCopyV1::BOTH {
        device.fs.place_unsynced(
            &dir,
            kagemusha_wallet_completion_name_v1(&bootstrap.body().operation_id, copy).as_str(),
            b"corrupt",
        );
    }
    assert_eq!(
        provider.advance(&slot, &TestOwnerV1, &bootstrap_request),
        Ok(KagemushaWalletAdvanceOutcomeV1::DeliveryDataLoss {
            operation_id: bootstrap.body().operation_id
        })
    );
}

#[test]
fn wallet_advance_v1_advance_failures_after_selection_are_pending() {
    // Regression: once the Selected marker is durable, a failure other than custody loss is
    // `Pending` with its reason, never an error.
    let (base, f, slot, bootstrap) = bootstrapped_device(ANDROID, 0x80);
    let head = current(&mut base.open(), &slot);
    let request = advance_request(&head, &next_capsule(&f, &bootstrap));
    let pending = Ok(KagemushaWalletAdvanceOutcomeV1::Pending {
        operation_id: request.operation_id,
    });
    // Renames: two capsule copies, the Selected marker, then the two record copies.
    let record_rename = step_of(
        &base,
        &slot,
        &request,
        KagemushaWalletSimStepV1::RenameNoReplace,
        3,
    );
    // A filesystem refusing the record's create-new rename after selection.
    let device = base.fork();
    let mut provider = device.open();
    device.fs.inject(
        device.fs.steps() + record_rename,
        KagemushaWalletSimFaultV1::ErrorKind(std::io::ErrorKind::Unsupported),
    );
    assert_eq!(provider.advance(&slot, &TestOwnerV1, &request), pending);
    assert_eq!(
        provider.pending_reason(&slot),
        Some(KagemushaWalletProviderErrorV1::NoReplaceUnsupported)
    );
    released(
        provider
            .advance(&slot, &TestOwnerV1, &request)
            .expect("finished"),
    );
    // An owner that cannot assemble the output after signing.
    let device = base.fork();
    let mut provider = device.open();
    assert_eq!(
        provider.advance(&slot, &FailingOwnerV1 { body: false }, &request),
        pending
    );
    assert!(matches!(
        provider.status(&slot),
        Ok(KagemushaWalletSlotStatusV1::Pending(_))
    ));
    // A foreign entry appearing in `markers/` after selection (while the output is assembled):
    // the record's persistence refuses it, and the performed operation is pending.
    let device = base.fork();
    let mut provider = device.open();
    let placing = PlacingOwnerV1 {
        fs: device.fs.clone(),
        dir: kagemusha_wallet_markers_dir_v1(&slot),
    };
    assert_eq!(provider.advance(&slot, &placing, &request), pending);
    assert_eq!(
        provider.pending_reason(&slot),
        Some(KagemushaWalletProviderErrorV1::UnexpectedEntry { dir: "markers" })
    );
    // The next reconcile stops on the foreign entry before deciding anything.
    assert_eq!(
        provider.advance(&slot, &TestOwnerV1, &request),
        Err(KagemushaWalletProviderErrorV1::UnexpectedEntry { dir: "markers" })
    );
    assert!(device.platform.with(|state| state.violations.is_empty()));
}

/// An owner that places a foreign file in `dir` while it assembles the output.
struct PlacingOwnerV1 {
    fs: crate::kagemusha_wallet_advance_v1::KagemushaWalletSimFsV1,
    dir: KagemushaWalletCustodyDirV1,
}

impl
    KagemushaWalletTransitionOwnerV1<
        KagemushaWalletRecoveryCapsuleV1,
        KagemushaWalletCompletionRecordV1,
    > for PlacingOwnerV1
{
    fn receipt_body(
        &self,
        capsule: &KagemushaWalletRecoveryCapsuleV1,
        capsule_digest: &[u8; 32],
    ) -> Result<Vec<u8>, KagemushaWalletProviderErrorV1> {
        TestOwnerV1.receipt_body(capsule, capsule_digest)
    }

    fn require_completion(
        &self,
        capsule: &KagemushaWalletRecoveryCapsuleV1,
        record: &KagemushaWalletCompletionRecordV1,
    ) -> Result<(), KagemushaWalletProviderErrorV1> {
        record
            .require_capsule(capsule)
            .map_err(|_| KagemushaWalletProviderErrorV1::Invalid {
                field: "completion.capsule",
            })
    }

    fn assemble(
        &self,
        capsule: &KagemushaWalletRecoveryCapsuleV1,
        capsule_digest: &[u8; 32],
        signature: &KagemushaDeviceSignatureV1,
    ) -> Result<KagemushaWalletCompletionRecordV1, KagemushaWalletProviderErrorV1> {
        self.fs.place_unsynced(&self.dir, "notes", b"x");
        TestOwnerV1.assemble(capsule, capsule_digest, signature)
    }
}

#[test]
fn wallet_advance_v1_advance_capacity_wait_at_selection_discards_staging() {
    // Regression: `CapacityWait` from the Selected marker's write used to leave both capsule
    // copies on disk until the next reconcile.
    let (base, f, slot) = enrolled_device(ANDROID, 0x81);
    let enrollment = current(&mut base.open(), &slot);
    let request = advance_request(&enrollment, &bootstrap_capsule(&f));
    // The Selected marker's data write follows the two capsule renames.
    let second_rename = step_of(
        &base,
        &slot,
        &request,
        KagemushaWalletSimStepV1::RenameNoReplace,
        1,
    );
    let probe = base.fork();
    let mut probe_provider = probe.open();
    let start = probe.fs.steps();
    released(
        probe_provider
            .advance(&slot, &TestOwnerV1, &request)
            .expect("probe"),
    );
    let trace = probe.fs.trace_since(start);
    let marker_write = trace
        .iter()
        .enumerate()
        .skip(usize::try_from(second_rename).expect("index"))
        .find(|(_, step)| **step == KagemushaWalletSimStepV1::Write)
        .map(|(index, _)| u64::try_from(index).expect("index"))
        .expect("marker write");
    let device = base.fork();
    let mut provider = device.open();
    device.fs.inject(
        device.fs.steps() + marker_write,
        KagemushaWalletSimFaultV1::ErrorKind(std::io::ErrorKind::StorageFull),
    );
    assert_eq!(
        provider.advance(&slot, &TestOwnerV1, &request),
        Ok(KagemushaWalletAdvanceOutcomeV1::NotPerformed(
            KagemushaWalletNotPerformedV1::CapacityWait
        ))
    );
    assert!(
        visible(&device, &kagemusha_wallet_capsules_dir_v1(&slot)).is_empty(),
        "staged copies discarded at once"
    );
    assert_eq!(
        visible(&device, &kagemusha_wallet_markers_dir_v1(&slot)).len(),
        1
    );
    released(
        provider
            .advance(&slot, &TestOwnerV1, &request)
            .expect("retry"),
    );
}

#[test]
fn wallet_advance_v1_advance_refuses_unenrolled_and_terminal_slots() {
    let (device, f, slot, bootstrap) = bootstrapped_device(ANDROID, 0x77);
    let mut provider = device.open();
    let head = current(&mut provider, &slot);
    let request = advance_request(&head, &next_capsule(&f, &bootstrap));
    let unknown = KagemushaWalletSlotIdV1([0x77; 32]);
    crate::kagemusha_wallet_advance_v1::kagemusha_wallet_prepare_slot_dirs_v1(
        provider.store(),
        &unknown,
    )
    .expect("slot");
    assert_eq!(
        provider.advance(&unknown, &TestOwnerV1, &request),
        Err(KagemushaWalletProviderErrorV1::Invalid {
            field: "slot.not_enrolled"
        })
    );
    assert_eq!(
        provider.lookup(&unknown, &request.operation_id),
        Ok(KagemushaWalletLookupV1::Unknown)
    );
    let status = provider.status(&slot).expect("status");
    let confirmation =
        KagemushaWalletDestructiveConfirmationV1::for_status(slot, &status).expect("confirm");
    provider
        .delete_custody(&slot, &confirmation)
        .expect("delete");
    assert_eq!(
        provider.advance(&slot, &TestOwnerV1, &request),
        Err(KagemushaWalletProviderErrorV1::Terminal)
    );
}

#[test]
fn wallet_advance_v1_advance_capacity_and_ballast() {
    let (base, f, slot) = enrolled_device(ANDROID, 0x78);
    let root = KagemushaWalletCustodyDirV1::root();
    let ballast = KAGEMUSHA_WALLET_BALLAST_NAME_V1.to_owned();
    assert!(
        visible(&base, &root).contains(&ballast),
        "E2 writes the ballast"
    );
    let enrollment = {
        let mut provider = base.open();
        current(&mut provider, &slot)
    };
    let bootstrap = bootstrap_capsule(&f);
    let request = advance_request(&enrollment, &bootstrap);
    // Growth without room beyond an intact ballast waits, writing nothing.
    let device = base.fork();
    let mut provider = device.open();
    provider
        .status(&slot)
        .expect("verified while there is room");
    device.fs.set_capacity(Some(0));
    assert_eq!(
        provider.advance(&slot, &TestOwnerV1, &request),
        Ok(KagemushaWalletAdvanceOutcomeV1::NotPerformed(
            KagemushaWalletNotPerformedV1::CapacityWait
        ))
    );
    assert!(visible(&device, &kagemusha_wallet_capsules_dir_v1(&slot)).is_empty());
    assert!(
        visible(&device, &root).contains(&ballast),
        "growth never draws the ballast"
    );
    // A full reconcile on a full disk draws the ballast for its fresh-inode rewrite.
    device.fs.set_capacity(Some(in_use(&device)));
    provider.poison(&slot);
    assert!(matches!(
        provider.status(&slot),
        Ok(KagemushaWalletSlotStatusV1::Enrollment(_))
    ));
    assert!(!visible(&device, &root).contains(&ballast));
    device.fs.set_capacity(None);
    released(
        provider
            .advance(&slot, &TestOwnerV1, &request)
            .expect("bootstrap"),
    );
    // Cleanup with a full disk draws the ballast and completes. The ballast must cover the
    // worst-case footprint, so this provider uses a larger one.
    drop(provider);
    let mut provider = SimProviderV1::open(
        device.fs.clone(),
        device.platform.clone(),
        super::super::test_support::SCHEME,
        KagemushaWalletProviderOptionsV1 {
            ballast_bytes: 32 * 1024,
        },
    )
    .expect("open");
    provider.remove_ballast().expect("remove");
    assert_eq!(provider.write_ballast(), Ok(true));
    let head = current(&mut provider, &slot);
    let archive = advance_request(&head, &next_capsule(&f, &bootstrap));
    device.fs.set_capacity(Some(in_use(&device)));
    let archived = released(
        provider
            .advance(&slot, &TestOwnerV1, &archive)
            .expect("archive"),
    );
    assert_eq!(archived.operation_id, archive.operation_id);
    assert!(
        !visible(&device, &root).contains(&ballast),
        "drawn, and no room to regrow"
    );
    // Without the ballast and without room, the next growth operation waits.
    let head = current(&mut provider, &slot);
    let retiring = advance_request(&head, &retiring_capsule(&f, &archive.capsule));
    assert_eq!(
        provider.advance(&slot, &TestOwnerV1, &retiring),
        Ok(KagemushaWalletAdvanceOutcomeV1::NotPerformed(
            KagemushaWalletNotPerformedV1::CapacityWait
        ))
    );
    // Once space returns the ballast regrows first, then the operation runs.
    device.fs.set_capacity(None);
    released(
        provider
            .advance(&slot, &TestOwnerV1, &retiring)
            .expect("retiring"),
    );
    assert!(visible(&device, &root).contains(&ballast));
}

#[test]
fn wallet_advance_v1_advance_post_selection_full_disk_uses_the_ballast() {
    let (base, f, slot, bootstrap) = bootstrapped_device(ANDROID, 0x79);
    let head = current(&mut base.open(), &slot);
    let request = advance_request(&head, &next_capsule(&f, &bootstrap));
    let probe = base.fork();
    let mut probe_provider = probe.open();
    let start = probe.fs.steps();
    released(
        probe_provider
            .advance(&slot, &TestOwnerV1, &request)
            .expect("probe"),
    );
    let trace = probe.fs.trace_since(start);
    // The completion record's first data write comes after the third rename.
    let third_rename = trace
        .iter()
        .enumerate()
        .filter(|(_, step)| **step == KagemushaWalletSimStepV1::RenameNoReplace)
        .nth(2)
        .map(|(index, _)| index)
        .expect("rename");
    let write = trace
        .iter()
        .enumerate()
        .skip(third_rename)
        .find(|(_, step)| **step == KagemushaWalletSimStepV1::Write)
        .map(|(index, _)| u64::try_from(index).expect("index"))
        .expect("write");
    let device = base.fork();
    let mut provider = device.open();
    let ballast_inode = device.fs.inode_of(
        &KagemushaWalletCustodyDirV1::root(),
        KAGEMUSHA_WALLET_BALLAST_NAME_V1,
    );
    device.fs.inject(
        device.fs.steps() + write,
        KagemushaWalletSimFaultV1::ErrorKind(std::io::ErrorKind::StorageFull),
    );
    released(
        provider
            .advance(&slot, &TestOwnerV1, &request)
            .expect("advance"),
    );
    let regrown = device.fs.inode_of(
        &KagemushaWalletCustodyDirV1::root(),
        KAGEMUSHA_WALLET_BALLAST_NAME_V1,
    );
    assert!(
        regrown.is_some() && regrown != ballast_inode,
        "drawn, then regrown"
    );
    assert_eq!(
        device
            .fs
            .visible_file(
                &KagemushaWalletCustodyDirV1::root(),
                KAGEMUSHA_WALLET_BALLAST_NAME_V1
            )
            .map(|bytes| bytes.len()),
        Some(usize::try_from(TEST_BALLAST_BYTES).expect("size"))
    );
}

#[test]
fn wallet_advance_v1_advance_ballast_helpers() {
    let (device, _f, _slot) = enrolled_device(ANDROID, 0x7a);
    let provider = device.open();
    assert_eq!(provider.ballast_present(), Ok(true));
    assert_eq!(
        provider.write_ballast(),
        Ok(true),
        "an existing ballast stands"
    );
    provider.remove_ballast().expect("remove");
    assert_eq!(provider.ballast_present(), Ok(false));
    provider.regrow_ballast();
    assert_eq!(provider.ballast_present(), Ok(true));
    provider.remove_ballast().expect("remove");
    device.fs.set_capacity(Some(0));
    assert_eq!(provider.write_ballast(), Ok(false));
    provider.regrow_ballast();
    assert_eq!(provider.ballast_present(), Ok(false));
    device.fs.set_capacity(None);
    // `with_ballast` retries once after drawing the ballast, only when allowed.
    provider.write_ballast().expect("ballast");
    let mut calls = 0;
    let result = provider.with_ballast(false, || {
        calls += 1;
        Err::<(), _>(KagemushaWalletProviderErrorV1::NoSpace)
    });
    assert_eq!(
        (result, calls),
        (Err(KagemushaWalletProviderErrorV1::NoSpace), 1)
    );
    assert_eq!(provider.ballast_present(), Ok(true));
    let mut calls = 0;
    let result = provider.with_ballast(true, || {
        calls += 1;
        if calls == 1 {
            Err(KagemushaWalletProviderErrorV1::NoSpace)
        } else {
            Ok(calls)
        }
    });
    assert_eq!(result, Ok(2));
    assert_eq!(provider.ballast_present(), Ok(false));
    let result = provider.with_ballast(true, || {
        Err::<(), _>(KagemushaWalletProviderErrorV1::NoSpace)
    });
    assert_eq!(
        result,
        Err(KagemushaWalletProviderErrorV1::NoSpace),
        "nothing left to draw"
    );
    // Reserve: growth needs the ballast; cleanup may draw it.
    assert_eq!(
        provider.reserve_capacity(KagemushaWalletCapacityClassV1::Growth, 100, 0),
        Ok(true),
        "the ballast is regrown first"
    );
    device.fs.set_capacity(Some(0));
    assert_eq!(
        provider.reserve_capacity(KagemushaWalletCapacityClassV1::Cleanup, 100, 0),
        Ok(true)
    );
    assert_eq!(provider.ballast_present(), Ok(false), "drawn for cleanup");
    assert_eq!(
        provider.reserve_capacity(KagemushaWalletCapacityClassV1::Cleanup, 100, 0),
        Ok(false),
        "no ballast left: cleanup waits too"
    );
    assert_eq!(
        provider.reserve_capacity(KagemushaWalletCapacityClassV1::Growth, 100, 0),
        Ok(false)
    );
}

/// Probe completion refusal without changing body assembly or signing behavior.
struct RejectCompletionOwner(bool);
impl
    KagemushaWalletTransitionOwnerV1<
        KagemushaWalletRecoveryCapsuleV1,
        KagemushaWalletCompletionRecordV1,
    > for RejectCompletionOwner
{
    fn receipt_body(
        &self,
        capsule: &KagemushaWalletRecoveryCapsuleV1,
        digest: &[u8; 32],
    ) -> Result<Vec<u8>, KagemushaWalletProviderErrorV1> {
        if self.0 {
            return Err(KagemushaWalletProviderErrorV1::Invalid {
                field: "receipt.stall.probe",
            });
        }
        TestOwnerV1.receipt_body(capsule, digest)
    }
    fn assemble(
        &self,
        capsule: &KagemushaWalletRecoveryCapsuleV1,
        digest: &[u8; 32],
        signature: &KagemushaDeviceSignatureV1,
    ) -> Result<KagemushaWalletCompletionRecordV1, KagemushaWalletProviderErrorV1> {
        TestOwnerV1.assemble(capsule, digest, signature)
    }
    fn require_completion(
        &self,
        _: &KagemushaWalletRecoveryCapsuleV1,
        _: &KagemushaWalletCompletionRecordV1,
    ) -> Result<(), KagemushaWalletProviderErrorV1> {
        Err(KagemushaWalletProviderErrorV1::Invalid {
            field: "completion.join.probe",
        })
    }
}

#[test]
fn wallet_advance_v1_completion_join_is_required_after_staging_and_before_existing_adoption() {
    let (device, f, slot) = enrolled_device(ANDROID, 0x82);
    let mut provider = device.open();
    let head = current(&mut provider, &slot);
    let request = advance_request(&head, &bootstrap_capsule(&f));
    assert!(
        provider
            .advance(&slot, &RejectCompletionOwner(false), &request)
            .is_err()
    );
    let signed = device.platform.with(|state| state.sign_calls);
    assert_eq!(signed, 1);
    let mut reopened = device.open();
    assert!(matches!(
        reopened.status(&slot),
        Ok(KagemushaWalletSlotStatusV1::Pending(_))
    ));
    assert!(
        reopened
            .reconcile(&slot, &RejectCompletionOwner(false))
            .is_err()
    );
    assert_eq!(
        device.platform.with(|state| state.sign_calls),
        signed,
        "existing completion refusal never signs again"
    );
    let mut recovered = device.open();
    assert!(matches!(
        recovered.reconcile(&slot, &TestOwnerV1),
        Ok(KagemushaWalletSlotStatusV1::Released(_))
    ));
    assert_eq!(device.platform.with(|state| state.sign_calls), signed);
}

#[test]
fn wallet_advance_v1_retained_retry_requires_completion_join_with_released_or_pending_head() {
    for pending in [false, true] {
        let (device, f, slot) = enrolled_device(ANDROID, 0x83);
        let mut provider = device.open();
        let head = current(&mut provider, &slot);
        let bootstrap = bootstrap_capsule(&f);
        let request = advance_request(&head, &bootstrap);
        assert!(matches!(
            provider.advance(&slot, &TestOwnerV1, &request),
            Ok(KagemushaWalletAdvanceOutcomeV1::Released { .. })
        ));
        if pending {
            let head = current(&mut provider, &slot);
            let next = advance_request(&head, &next_capsule(&f, &bootstrap));
            assert!(matches!(
                provider.advance(&slot, &FailingOwnerV1 { body: false }, &next),
                Ok(KagemushaWalletAdvanceOutcomeV1::Pending { .. })
            ));
        }
        let signed = device.platform.with(|state| state.sign_calls);
        assert!(
            provider
                .advance(&slot, &RejectCompletionOwner(true), &request)
                .is_err()
        );
        assert_eq!(device.platform.with(|state| state.sign_calls), signed);
    }
}
