//! Both delivery-evidence forms through actual installed Archive proofs and retained replay.
//!
//! This helper runs only inside the genuine full-catalog native exchange case.
//! TODO: Compile and execute the extended same-network campaign on the current candidate.

use super::*;

/// Commit and fold the exact delivery evidence, then reopen the same payer custody.
/// Retry must return the identical Archive package without another signature or debit.
pub(super) fn exercise(
    mut wallet: Wallet,
    device: &HostDevice,
    sources: &Sources,
    fixture: &Fixture,
    frames: &[Vec<u8>; 4],
    credited: &[u8],
) -> (Wallet, Vec<u8>) {
    let evidence: KagemushaWalletCreditedV1 = decode(credited);
    let (credit_id, branch) = match &evidence.evidence {
        KagemushaWalletCreditedEvidenceV1::Receive { package } => {
            let KagemushaWalletEffectV1::Receive { credit_id, .. } = package.statement.effect
            else {
                panic!("Receive acknowledgement must name a received credit")
            };
            (credit_id, "ArchiveReceive")
        }
        KagemushaWalletCreditedEvidenceV1::Status { status } => {
            (status.opening.credit_id, "ArchiveStatus")
        }
    };
    let before = wallet.snapshot().unwrap();
    let original = complete(wallet.accept_credited(credited).unwrap());
    let package: KagemushaWalletPackageV1 = decode(&original);
    let credential = KagemushaWalletCredentialV1::decode_canonical(
        &frames[0],
        &fixture.config.scheme.scheme_id(),
    )
    .unwrap();
    package.verify(&credential).unwrap();
    assert!(matches!(
        package.statement.effect,
        KagemushaWalletEffectV1::ArchiveSent { credit_id: actual, .. } if actual == credit_id
    ));
    sources
        .installed
        .verifier()
        .verify_package_proofs(&package, None, MemoryBudget::DEFAULT)
        .unwrap();
    let committed = wallet.snapshot().unwrap();
    assert_eq!(committed.sequence, before.sequence.checked_add(1).unwrap());
    assert_eq!(package.statement.sequence, committed.sequence);
    assert_eq!(committed.owned_balance, before.owned_balance);
    assert_eq!(committed.known_burned_total, before.known_burned_total);
    assert!(committed.fold_backlog > 0);

    let signatures = device.platform.with(|state| state.sign_calls);
    assert_eq!(
        complete(wallet.accept_credited(credited).unwrap()),
        original
    );
    assert_eq!(wallet.snapshot().unwrap(), committed);
    fold(&mut wallet);
    let folded = wallet.snapshot().unwrap();
    assert_eq!(folded.sequence, committed.sequence);
    assert_eq!(folded.owned_balance, committed.owned_balance);
    assert_eq!(folded.known_burned_total, committed.known_burned_total);
    assert_eq!(folded.verified_fold.unwrap().sequence, committed.sequence);
    assert_eq!(device.platform.with(|state| state.sign_calls), signatures);

    drop(wallet);
    let mut wallet = sources.open(device, fixture, frames);
    assert_eq!(wallet.snapshot().unwrap(), folded);
    assert_eq!(
        complete(wallet.accept_credited(credited).unwrap()),
        original
    );
    assert_eq!(wallet.snapshot().unwrap(), folded);
    assert_eq!(device.platform.with(|state| state.sign_calls), signatures);
    eprintln!(
        "NATIVE_EXCHANGE_ARCHIVE branch={branch} exact_replay_after_restart=true current_head_folded=true monetary_value_unchanged=true"
    );
    (wallet, original)
}
