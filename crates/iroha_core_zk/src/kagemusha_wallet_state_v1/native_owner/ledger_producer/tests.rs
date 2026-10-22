//! Direct Unload finality on genuine native BLS certificates and Merkle membership, with
//! explicit mock archive and manifest custody. Fixture execution rows are synthetic: these
//! tests cover outcome custody and claim binding, not a World Unload or a payout.
use super::super::ledger_outcome::tests::{
    advance, boundary, bytes, certify, genesis, ledger_wallet, original, other_quorum, rejected,
    restart, signed_action, successor_epoch_block,
};
use super::*;
use crate::kagemusha_wallet_state_v1::tests::{Wallet, fixture};
use iroha_crypto::{Algorithm, KeyPair};
use iroha_data_model::sumeragi_finality::test_fixtures::NativeFinalityFixture;

struct Claim {
    original: Vec<u8>,
    digest: [u8; 32],
    scheme: [u8; 32],
}

fn claim() -> Claim {
    let claim: KagemushaWalletUnloadClaimV1 = fixture("KagemushaWalletUnloadClaimV1");
    let original = claim.to_canonical_bytes().unwrap();
    Claim {
        digest: *iroha_crypto::Hash::new(&original).as_ref(),
        scheme: claim.credential.body.scheme_id,
        original,
    }
}

// A relayer that is not the claim's paid account signs the envelope.
fn relayer() -> KeyPair {
    KeyPair::from_seed(vec![79; 32], Algorithm::Ed25519)
}

fn envelope(native: &NativeFinalityFixture, claim: &Claim, offset: u64) -> SignedTransaction {
    signed_action(
        native,
        &relayer(),
        claim.scheme,
        KagemushaWalletLedgerActionV1::Unload(claim.original.clone()),
        offset,
    )
}

fn outcome(w: &mut Wallet, claim: &Claim, signed: &SignedTransaction) -> LedgerAttemptOutcomeV1 {
    let (_, manifest) = w.sync_manifest().unwrap();
    w.unload_outcome(&manifest, &claim.digest, signed).unwrap()
}

fn ingest(
    w: &mut Wallet,
    native: &NativeFinalityFixture,
    claim: &Claim,
    signed: &SignedTransaction,
    offered: &[u8],
) -> Result<LedgerAttemptIngestV1, Error> {
    let (root, manifest) = w.sync_manifest().unwrap();
    w.ingest_unload_original(
        root,
        manifest,
        &genesis(native),
        claim.digest,
        signed,
        offered,
    )
}

fn confirmed(height: u64, commit_hash: [u8; 32]) -> LedgerAttemptOutcomeV1 {
    LedgerAttemptOutcomeV1::Confirmed(LedgerCommitV1 {
        height,
        commit_hash,
    })
}

#[test]
fn one_original_confirms_a_relayed_unload_with_one_publication_and_survives_restart() {
    let mut native = NativeFinalityFixture::start("unload-direct-finality");
    let claim = claim();
    let signed = envelope(&native, &claim, 0);
    let block = certify(&mut native, std::slice::from_ref(&signed), vec![Ok(vec![])]);
    let offered = bytes(&original(&block, 0));
    let mut w = ledger_wallet(&native);
    let entrypoint = *signed.hash_as_entrypoint().as_ref();
    let before = w.custody.publication_calls;
    // A read never verifies or writes, and it returns the natively derived route selector.
    assert_eq!(
        outcome(&mut w, &claim, &signed),
        LedgerAttemptOutcomeV1::Awaiting { entrypoint }
    );
    assert_eq!(w.custody.publication_calls, before);
    let LedgerAttemptIngestV1::Outcome(LedgerAttemptOutcomeV1::Confirmed(commit)) =
        ingest(&mut w, &native, &claim, &signed, &offered).unwrap()
    else {
        panic!("an applied certified Unload confirms");
    };
    assert_eq!(commit.height, 2);
    assert_eq!(w.custody.publication_calls, before + 1);
    let retained = w.manifest().unwrap().0;
    assert_eq!(
        outcome(&mut w, &claim, &signed),
        confirmed(2, commit.commit_hash)
    );
    // An exact retry and another honest quorum's original are idempotent and write nothing.
    for again in [offered.clone(), bytes(&other_quorum(&original(&block, 0)))] {
        assert_eq!(
            ingest(&mut w, &native, &claim, &signed, &again).unwrap(),
            LedgerAttemptIngestV1::Outcome(confirmed(2, commit.commit_hash))
        );
    }
    assert_eq!(
        (w.custody.publication_calls, w.manifest().unwrap().0),
        (before + 1, retained)
    );
    let mut w = restart(w);
    assert_eq!(
        outcome(&mut w, &claim, &signed),
        confirmed(2, commit.commit_hash)
    );
    // The same envelope can never be reread under another claim.
    let (_, manifest) = w.sync_manifest().unwrap();
    assert!(matches!(
        w.unload_outcome(&manifest, &[93; 32], &signed),
        Err(Error::OperationConflict)
    ));
}

#[test]
fn confirmation_work_is_independent_of_the_inclusion_height() {
    let mut counts = Vec::new();
    for filler in [0, 38] {
        let mut native = NativeFinalityFixture::start("unload-height-independence");
        advance(&mut native, filler);
        let claim = claim();
        let signed = envelope(&native, &claim, 0);
        let block = certify(&mut native, std::slice::from_ref(&signed), vec![Ok(vec![])]);
        assert_eq!(block.height(), 2 + filler as u64);
        let offered = bytes(&original(&block, 0));
        let mut w = ledger_wallet(&native);
        let reads = w.archive.reads.load(std::sync::atomic::Ordering::SeqCst);
        let publications = w.custody.publication_calls;
        assert!(matches!(
            ingest(&mut w, &native, &claim, &signed, &offered).unwrap(),
            LedgerAttemptIngestV1::Outcome(LedgerAttemptOutcomeV1::Confirmed(_))
        ));
        counts.push((
            w.archive.reads.load(std::sync::atomic::Ordering::SeqCst) - reads,
            w.custody.publication_calls - publications,
        ));
    }
    assert_eq!(counts[0], counts[1]);
    assert_eq!(counts[0].1, 1);
}

#[test]
fn rejected_envelope_is_retained_alone_and_a_new_envelope_over_the_same_claim_confirms() {
    let mut native = NativeFinalityFixture::start("unload-rejected-envelope");
    let claim = claim();
    let first = envelope(&native, &claim, 0);
    let refused = certify(&mut native, std::slice::from_ref(&first), vec![rejected()]);
    let second = envelope(&native, &claim, 0);
    assert_ne!(first.hash_as_entrypoint(), second.hash_as_entrypoint());
    let applied = certify(&mut native, std::slice::from_ref(&second), vec![Ok(vec![])]);
    let mut w = ledger_wallet(&native);
    let (_, before) = w.sync_manifest().unwrap();
    let LedgerAttemptIngestV1::Outcome(LedgerAttemptOutcomeV1::Rejected(rejection)) = ingest(
        &mut w,
        &native,
        &claim,
        &first,
        &bytes(&original(&refused, 0)),
    )
    .unwrap() else {
        panic!("a certified rejection closes its own envelope");
    };
    assert_eq!(rejection.height, 2);
    // The rejection has no reader but the outcome query: claims and every other selected
    // index are unchanged, so it cannot restore value, release or retarget the claim.
    let (_, after) = w.sync_manifest().unwrap();
    assert_eq!(after.claims, before.claims);
    assert_eq!(after.credits, before.credits);
    assert_eq!(after.outgoing, before.outgoing);
    assert_eq!(after.indexed, before.indexed);
    assert_eq!(
        outcome(&mut w, &claim, &second),
        LedgerAttemptOutcomeV1::Awaiting {
            entrypoint: *second.hash_as_entrypoint().as_ref()
        }
    );
    let LedgerAttemptIngestV1::Outcome(LedgerAttemptOutcomeV1::Confirmed(commit)) = ingest(
        &mut w,
        &native,
        &claim,
        &second,
        &bytes(&original(&applied, 0)),
    )
    .unwrap() else {
        panic!("the new envelope's applied execution confirms the same claim");
    };
    assert_eq!(commit.height, 3);
    assert_eq!(
        outcome(&mut w, &claim, &first),
        LedgerAttemptOutcomeV1::Rejected(rejection)
    );
}

#[test]
fn conflicting_or_foreign_originals_are_errors_that_write_nothing() {
    let mut native = NativeFinalityFixture::start("unload-conflict");
    let claim = claim();
    let signed = envelope(&native, &claim, 0);
    let other = envelope(&native, &claim, 1);
    let first = certify(
        &mut native,
        &[signed.clone(), other.clone()],
        vec![rejected(), Ok(vec![])],
    );
    // The fixture never executes: the same entrypoint certified again with the opposite
    // result stands for a consensus fault.
    let conflicting = certify(&mut native, std::slice::from_ref(&signed), vec![Ok(vec![])]);
    let mut w = ledger_wallet(&native);
    // Another envelope's original is an error before any outcome exists.
    assert!(matches!(
        ingest(
            &mut w,
            &native,
            &claim,
            &signed,
            &bytes(&original(&first, 1))
        ),
        Err(Error::Proof(_))
    ));
    assert!(matches!(
        outcome(&mut w, &claim, &signed),
        LedgerAttemptOutcomeV1::Awaiting { .. }
    ));
    assert!(matches!(
        ingest(
            &mut w,
            &native,
            &claim,
            &signed,
            &bytes(&original(&first, 0))
        )
        .unwrap(),
        LedgerAttemptIngestV1::Outcome(LedgerAttemptOutcomeV1::Rejected(_))
    ));
    let retained = w.manifest().unwrap().0;
    let publications = w.custody.publication_calls;
    assert!(matches!(
        ingest(
            &mut w,
            &native,
            &claim,
            &signed,
            &bytes(&original(&conflicting, 0))
        ),
        Err(Error::Proof("conflicting authenticated ledger outcome"))
    ));
    assert!(matches!(
        ingest(&mut w, &native, &claim, &signed, &[0; 7]),
        Err(Error::Invalid(_))
    ));
    assert_eq!(
        (w.custody.publication_calls, w.manifest().unwrap().0),
        (publications, retained)
    );
    assert!(matches!(
        outcome(&mut w, &claim, &signed),
        LedgerAttemptOutcomeV1::Rejected(_)
    ));
}

#[test]
fn unselected_epoch_writes_nothing_and_the_same_original_confirms_after_synchronization() {
    let claim = claim();
    // The envelope sits in H4, the first block of epoch one; a fresh wallet selects epoch zero.
    let (native, chain, block, made) =
        successor_epoch_block(|fixture| (vec![envelope(fixture, &claim, 0)], vec![Ok(vec![])]));
    let signed = made[0].clone();
    assert_eq!(block.height(), 4);
    let offered = bytes(&original(&block, 0));
    let mut w = ledger_wallet(&native);
    let publications = w.custody.publication_calls;
    assert_eq!(
        ingest(&mut w, &native, &claim, &signed, &offered).unwrap(),
        LedgerAttemptIngestV1::EpochRequired { target_height: 4 }
    );
    assert_eq!(w.custody.publication_calls, publications);
    assert!(matches!(
        outcome(&mut w, &claim, &signed),
        LedgerAttemptOutcomeV1::Awaiting { .. }
    ));
    w.ingest_epoch_original(&genesis(&native), 0, &boundary(&native, &chain[2]))
        .unwrap();
    assert!(matches!(
        ingest(&mut w, &native, &claim, &signed, &offered).unwrap(),
        LedgerAttemptIngestV1::Outcome(LedgerAttemptOutcomeV1::Confirmed(LedgerCommitV1 {
            height: 4,
            ..
        }))
    ));
}

#[test]
fn uncertain_publication_reconciles_from_custody_on_exact_retry() {
    for after in [false, true] {
        let mut native = NativeFinalityFixture::start("unload-uncertain-publication");
        let claim = claim();
        let signed = envelope(&native, &claim, 0);
        let block = certify(&mut native, std::slice::from_ref(&signed), vec![Ok(vec![])]);
        let offered = bytes(&original(&block, 0));
        let mut w = ledger_wallet(&native);
        w.custody.fail_publication = Some(after);
        assert!(ingest(&mut w, &native, &claim, &signed, &offered).is_err());
        let mut w = restart(w);
        assert_eq!(
            matches!(
                outcome(&mut w, &claim, &signed),
                LedgerAttemptOutcomeV1::Confirmed(_)
            ),
            after
        );
        assert!(matches!(
            ingest(&mut w, &native, &claim, &signed, &offered).unwrap(),
            LedgerAttemptIngestV1::Outcome(LedgerAttemptOutcomeV1::Confirmed(_))
        ));
        assert!(matches!(
            outcome(&mut w, &claim, &signed),
            LedgerAttemptOutcomeV1::Confirmed(_)
        ));
    }
}

#[test]
fn signed_unload_binds_the_exact_claim_scheme_and_network_for_any_submitter() {
    let native = NativeFinalityFixture::start("unload-intake");
    let claim = claim();
    let relayed = envelope(&native, &claim, 0);
    let network = native.network_id();
    let wire = relayed.encode_wire_v1().unwrap();
    assert_eq!(
        signed_unload(&wire, &network, &claim.scheme, &claim.original).unwrap(),
        relayed
    );
    // The submitter only relays: its account is not the claim's paid account.
    let decoded: KagemushaWalletUnloadClaimV1 = fixture("KagemushaWalletUnloadClaimV1");
    assert_ne!(
        decoded.account,
        iroha_data_model::account::AccountId::new(relayer().public_key().clone())
    );
    let mut changed = claim.original.clone();
    changed.push(0);
    let foreign = iroha_data_model::NetworkId::from_genesis_hash(
        iroha_crypto::HashOf::from_untyped_unchecked(iroha_crypto::Hash::new(
            b"foreign Unload network",
        )),
    );
    let other_scheme = signed_action(
        &native,
        &relayer(),
        [92; 32],
        KagemushaWalletLedgerActionV1::Unload(claim.original.clone()),
        0,
    )
    .encode_wire_v1()
    .unwrap();
    let mut trailing = wire.clone();
    trailing.push(0);
    for (bytes, network, original) in [
        (&wire, &network, changed.as_slice()),
        (&wire, &foreign, claim.original.as_slice()),
        (&other_scheme, &network, claim.original.as_slice()),
        (&trailing, &network, claim.original.as_slice()),
        (
            &vec![0; LEDGER_INSTRUCTION_MAX_BYTES_V1 + 1],
            &network,
            claim.original.as_slice(),
        ),
    ] {
        assert!(matches!(
            signed_unload(bytes, network, &claim.scheme, original),
            Err(Error::Invalid(_))
        ));
    }
    let limits = norito::DecodeLimits::new(usize::MAX, 0, usize::MAX, usize::MAX, 64);
    let refused = norito::with_decode_limits_scope(limits, || {
        signed_unload(&wire, &network, &claim.scheme, &claim.original)
    });
    assert!(matches!(refused, Err(Error::DecodeResource(ref cause))
        if cause.kind() == norito::core::DecodeLocalRefusalKind::EnclosingLimit));
}

#[test]
fn unload_outcome_row_fits_one_index_leaf() {
    let mut native = NativeFinalityFixture::start("unload-outcome-row");
    let claim = claim();
    let signed = envelope(&native, &claim, 0);
    let block = certify(&mut native, std::slice::from_ref(&signed), vec![Ok(vec![])]);
    let mut w = ledger_wallet(&native);
    let offered = bytes(&original(&block, 0));
    ingest(&mut w, &native, &claim, &signed, &offered).unwrap();
    let (_, manifest) = w.sync_manifest().unwrap();
    let row = manifest
        .ledger_unload_outcomes
        .get(&mut w.archive, signed.hash_as_entrypoint().as_ref())
        .unwrap()
        .unwrap();
    assert!(row.len() <= crate::kagemusha_wallet_state_v1::index::INDEX_VALUE_LIMIT);
    let decoded: UnloadOutcome = archive::decode(&row).unwrap();
    assert_eq!(decoded.original_digest, claim.digest);
}

/// Host diagnostic, not a device SLA: Native's whole work to confirm an Unload included at
/// height 40 is one original's verification and one publication (compare HEAD's per-block walk).
#[test]
#[ignore = "host timing diagnostic; run explicitly with --ignored --nocapture"]
fn direct_confirmation_host_timing() {
    use std::time::{Duration, Instant};
    let mut native = NativeFinalityFixture::start("unload-direct-confirmation-timing");
    advance(&mut native, 38);
    let claim = claim();
    let signed = envelope(&native, &claim, 0);
    let block = certify(&mut native, std::slice::from_ref(&signed), vec![Ok(vec![])]);
    let offered = bytes(&original(&block, 0));
    let mut total = Duration::ZERO;
    for sample in 0..6 {
        let mut w = ledger_wallet(&native);
        let start = Instant::now();
        assert!(matches!(
            ingest(&mut w, &native, &claim, &signed, &offered).unwrap(),
            LedgerAttemptIngestV1::Outcome(LedgerAttemptOutcomeV1::Confirmed(_))
        ));
        if sample != 0 {
            total += start.elapsed();
        }
    }
    eprintln!(
        "DIRECT_CONFIRMATION samples=5 height={} original_bytes={} mean_ms={:.3}",
        block.height(),
        offered.len(),
        total.as_secs_f64() * 200.0,
    );
}
