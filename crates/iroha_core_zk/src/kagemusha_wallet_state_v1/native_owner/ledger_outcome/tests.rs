//! Genuine native BLS certificates and Merkle membership with explicit mock archive and
//! manifest custody. Fixture execution rows are synthetic: these tests cover direct-finality
//! outcome custody, not World execution or monetary qualification.
use super::*;
use crate::kagemusha_wallet_state_v1::tests::{Wallet, fixture, synthetic_payout_wallet};
use iroha_crypto::{Algorithm, KeyPair};
use iroha_data_model::{
    account::AccountId,
    block::{BlockSignatures, SignedBlock, builder::BlockBuilder},
    isi::kagemusha_wallet::{KagemushaWalletLedgerActionV1, KagemushaWalletLedgerV1},
    sumeragi_finality::{
        CertifiedTransactionInclusionV1, SumeragiCommitCertificateV1, SumeragiCommitVerifierV1,
        SumeragiFinalityProof, VerifiedSumeragiBlock, test_fixtures::NativeFinalityFixture,
    },
    transaction::{
        FeePaymentIntent, TransactionBuilder, TransactionResultInner,
        error::{TransactionLimitError, TransactionRejectionReason},
    },
};
use iroha_sumeragi::{
    message::Qc,
    types::{AggregateSignature, Bitmap},
};
use std::time::Duration;

/// One explicitly synthetic rejection; the fixture certifies results it never executes.
pub(in crate::kagemusha_wallet_state_v1::native_owner) fn rejected() -> TransactionResultInner {
    Err(TransactionRejectionReason::LimitCheck(
        TransactionLimitError {
            reason: "synthetic rejection".into(),
        },
    ))
}

/// Sign one ledger action as `key` on `native`'s network, created `offset` milliseconds before
/// the fixture's next proposal.
pub(in crate::kagemusha_wallet_state_v1::native_owner) fn signed_action(
    native: &NativeFinalityFixture,
    key: &KeyPair,
    scheme: [u8; 32],
    action: KagemushaWalletLedgerActionV1,
    offset: u64,
) -> SignedTransaction {
    let mut builder = TransactionBuilder::new(
        native.network_id(),
        AccountId::new(key.public_key().clone()),
        FeePaymentIntent::authority(vec![], None),
    );
    builder.set_creation_time(Duration::from_millis(
        native.next_header().creation_time_ms - 1 - offset,
    ));
    builder
        .with_instructions([KagemushaWalletLedgerV1::new(scheme, action)])
        .sign(key.private_key())
}

/// The fixture's next block of exactly these signed inputs and synthetic results.
pub(in crate::kagemusha_wallet_state_v1::native_owner) fn block(
    native: &NativeFinalityFixture,
    transactions: &[SignedTransaction],
    results: Vec<TransactionResultInner>,
) -> SignedBlock {
    let mut builder = BlockBuilder::new(native.next_header());
    for transaction in transactions {
        builder.push_transaction(transaction.clone());
    }
    let mut block = builder.build(BlockSignatures::default());
    NativeFinalityFixture::install_network_results(&mut block, results);
    block
}

/// Certify the fixture's next block of exactly these signed inputs and synthetic results.
pub(in crate::kagemusha_wallet_state_v1::native_owner) fn certify(
    native: &mut NativeFinalityFixture,
    transactions: &[SignedTransaction],
    results: Vec<TransactionResultInner>,
) -> VerifiedSumeragiBlock {
    let block = block(native, transactions, results);
    let proof = native.certify(block);
    native.verifier().verify_retained_decision(&proof).unwrap()
}

/// The short NPoS boundary chain (H3 selects epoch one) whose first epoch-one block, H4, holds
/// exactly the inputs and synthetic results `make` builds against the fixture at H3. Returns
/// the fixture, the chain, the verified H4 and those inputs.
pub(in crate::kagemusha_wallet_state_v1::native_owner) fn successor_epoch_block(
    make: impl FnOnce(&NativeFinalityFixture) -> (Vec<SignedTransaction>, Vec<TransactionResultInner>),
) -> (
    NativeFinalityFixture,
    Vec<SumeragiFinalityProof>,
    VerifiedSumeragiBlock,
    Vec<SignedTransaction>,
) {
    let mut made = Vec::new();
    let (native, chain) =
        NativeFinalityFixture::short_npos_boundary_chain_with_successor_block(4, |fixture, _| {
            let (transactions, results) = make(fixture);
            let built = block(fixture, &transactions, results);
            made = transactions;
            built
        });
    let h4 = native
        .verifier()
        .verify_retained_decision(&chain[3])
        .unwrap();
    (native, chain, h4, made)
}

/// Certify `count` ordinary blocks, so a later attempt sits far above genesis.
pub(in crate::kagemusha_wallet_state_v1::native_owner) fn advance(
    native: &mut NativeFinalityFixture,
    count: usize,
) {
    for _ in 0..count {
        let block = native.block_with_submitted_work(native.next_header());
        native.certify(block);
    }
}

/// The exact original Torii serves for one Network input of a certified block.
pub(in crate::kagemusha_wallet_state_v1::native_owner) fn original(
    block: &VerifiedSumeragiBlock,
    input_index: u32,
) -> KagemushaWalletLedgerFinalityV1 {
    let signed = block.block();
    let entrypoint = signed
        .network_entrypoint_at(input_index as usize)
        .unwrap()
        .clone();
    let (output_index, _) = signed.network_output_at(input_index).unwrap();
    KagemushaWalletLedgerFinalityV1 {
        version: 1,
        entrypoint_hash: entrypoint.hash(),
        certificate: SumeragiCommitCertificateV1::from_verified(block).unwrap(),
        inclusion: CertifiedTransactionInclusionV1 {
            entry_proof: signed.network_input_proof(input_index).unwrap(),
            output: signed.execution_outputs()[output_index as usize].clone(),
            output_proof: signed.output_proof(output_index).unwrap(),
        },
    }
}

pub(in crate::kagemusha_wallet_state_v1::native_owner) fn bytes(
    original: &KagemushaWalletLedgerFinalityV1,
) -> Vec<u8> {
    original.to_canonical_bytes().unwrap()
}

/// The independently installed signed genesis of `native`, with no later decision.
pub(in crate::kagemusha_wallet_state_v1::native_owner) fn genesis(
    native: &NativeFinalityFixture,
) -> SumeragiFinalityVerifier {
    SumeragiFinalityVerifier::new(
        native.genesis(),
        native.chain_id(),
        native.genesis_proof().committee.clone(),
    )
    .unwrap()
}

/// Verify an original with a reader built from `native`'s genesis alone, outside any wallet.
pub(in crate::kagemusha_wallet_state_v1::native_owner) fn verified(
    native: &NativeFinalityFixture,
    original: &KagemushaWalletLedgerFinalityV1,
    signed: &SignedTransaction,
) -> VerifiedKagemushaLedgerOutcomeV1 {
    let reader = SumeragiCommitVerifierV1::new(&genesis(native)).unwrap();
    original.verify(&reader, native.chain_id(), signed).unwrap()
}

/// A released synthetic wallet whose ledger scope is `native`'s signed genesis.
pub(in crate::kagemusha_wallet_state_v1::native_owner) fn ledger_wallet(
    native: &NativeFinalityFixture,
) -> Wallet {
    let mut scheme: KagemushaWalletSchemeV1 = fixture("KagemushaWalletSchemeV1");
    scheme.network_id = *native.network_id().as_bytes();
    synthetic_payout_wallet(scheme, native.chain_id().to_owned())
}

pub(in crate::kagemusha_wallet_state_v1::native_owner) fn restart(wallet: Wallet) -> Wallet {
    Coordinator::new(
        wallet.custody,
        wallet.archive,
        wallet.proofs,
        wallet.scheme_id,
        wallet.wallet_id,
    )
    .unwrap()
}

/// Re-sign the original's `CommitQC` with another exact quorum of the fixture's public seeds.
/// An honest peer may hold this different certificate for the very same block.
pub(in crate::kagemusha_wallet_state_v1::native_owner) fn other_quorum(
    original: &KagemushaWalletLedgerFinalityV1,
) -> KagemushaWalletLedgerFinalityV1 {
    let mut keys: Vec<_> = (1..=4_u8)
        .map(|seed| KeyPair::from_seed(vec![seed; 32], Algorithm::BlsNormal))
        .collect();
    keys.sort_by_key(|key| key.public_key().try_to_bytes().unwrap().1.to_vec());
    let mut qc: Qc = norito::decode_canonical(&original.certificate.commit_qc).unwrap();
    let subset = [0_u32, 1, 3];
    assert_ne!(
        qc.signers,
        Bitmap::from_indices(keys.len(), subset).unwrap()
    );
    qc.signers = Bitmap::from_indices(keys.len(), subset).unwrap();
    let shares: Vec<_> = subset
        .iter()
        .map(|index| {
            iroha_crypto::bls::consensus::sign_preimage(
                keys[*index as usize].private_key(),
                &qc.preimage(),
            )
            .unwrap()
        })
        .collect();
    qc.agg_sig = AggregateSignature(iroha_crypto::bls::consensus::aggregate(&shares).unwrap());
    let mut other = original.clone();
    other.certificate.commit_qc = norito::encode_canonical(&qc).unwrap();
    other
}

/// One epoch boundary certificate of the fixture's chain, as the ledger epoch route serves it.
pub(in crate::kagemusha_wallet_state_v1::native_owner) fn boundary(
    native: &NativeFinalityFixture,
    proof: &SumeragiFinalityProof,
) -> Vec<u8> {
    SumeragiCommitCertificateV1::from_verified(
        &native.verifier().verify_retained_decision(proof).unwrap(),
    )
    .unwrap()
    .to_canonical_bytes()
    .unwrap()
}

fn scheme() -> [u8; 32] {
    [5; 32]
}

fn attempt(native: &NativeFinalityFixture, key: &KeyPair, offset: u64) -> SignedTransaction {
    signed_action(
        native,
        key,
        scheme(),
        KagemushaWalletLedgerActionV1::Unload(vec![9; 64]),
        offset,
    )
}

#[test]
fn selected_epoch_verifies_applied_and_rejected_originals_without_any_write() {
    let mut native = NativeFinalityFixture::start("ledger-outcome-verify");
    let key = KeyPair::from_seed(vec![61; 32], Algorithm::Ed25519);
    let applied = attempt(&native, &key, 0);
    let refused = attempt(&native, &key, 1);
    let block = certify(
        &mut native,
        &[applied.clone(), refused.clone()],
        vec![Ok(vec![]), rejected()],
    );
    let genesis = genesis(&native);
    let mut w = ledger_wallet(&native);
    let (root, manifest) = w.sync_manifest().unwrap();
    let publications = w.custody.publication_calls;
    for (index, signed, accepted) in [(0, &applied, true), (1, &refused, false)] {
        let OfferedOutcome::Verified(outcome) = w
            .verify_ledger_original(
                &manifest,
                &genesis,
                signed,
                &bytes(&original(&block, index)),
            )
            .unwrap()
        else {
            panic!("the genesis epoch is selected");
        };
        assert_eq!(outcome.accepted(), accepted);
        assert_eq!(outcome.height(), 2);
        assert_eq!(outcome.entrypoint(), entrypoint(signed).unwrap());
        assert_eq!(outcome.entrypoint(), *signed.hash().as_ref());
        assert_ne!(outcome.commit_hash(), [0; 32]);
    }
    // Another attempt's original, a forged quorum, a foreign genesis, an oversized or
    // noncanonical frame are errors, never outcomes; nothing is written for any of them.
    let mut forged = original(&block, 0);
    let mut qc: Qc = norito::decode_canonical(&forged.certificate.commit_qc).unwrap();
    qc.agg_sig.0[0] ^= 1;
    forged.certificate.commit_qc = norito::encode_canonical(&qc).unwrap();
    let mut trailing = bytes(&original(&block, 0));
    trailing.push(0);
    for (signed, offered) in [
        (&applied, bytes(&original(&block, 1))),
        (&applied, bytes(&forged)),
        (&applied, trailing),
        (
            &applied,
            vec![0; KAGEMUSHA_WALLET_LEDGER_FINALITY_MAX_BYTES_V1 + 1],
        ),
        (&applied, Vec::new()),
    ] {
        assert!(matches!(
            w.verify_ledger_original(&manifest, &genesis, signed, &offered),
            Err(Error::Proof(_) | Error::Invalid(_))
        ));
    }
    let foreign = NativeFinalityFixture::start("ledger-outcome-foreign");
    assert!(
        w.verify_ledger_original(
            &manifest,
            &self::genesis(&foreign),
            &applied,
            &bytes(&original(&block, 0))
        )
        .is_err()
    );
    assert_eq!(w.custody.publication_calls, publications);
    assert_eq!(w.manifest().unwrap().0, root);
}

#[test]
fn unselected_epoch_is_data_until_the_boundary_is_selected() {
    let key = KeyPair::from_seed(vec![62; 32], Algorithm::Ed25519);
    // The attempt sits in H4, the first block of epoch one; a fresh wallet selects epoch zero.
    let (native, chain, block, made) =
        successor_epoch_block(|fixture| (vec![attempt(fixture, &key, 0)], vec![Ok(vec![])]));
    let signed = made[0].clone();
    assert_eq!(block.height(), 4);
    let offered = bytes(&original(&block, 0));
    let genesis = genesis(&native);
    let mut w = ledger_wallet(&native);
    let (root, manifest) = w.sync_manifest().unwrap();
    let publications = w.custody.publication_calls;
    assert!(matches!(
        w.verify_ledger_original(&manifest, &genesis, &signed, &offered)
            .unwrap(),
        OfferedOutcome::EpochRequired(4)
    ));
    assert_eq!(
        (w.custody.publication_calls, w.manifest().unwrap().0),
        (publications, root)
    );
    // The same original is never trusted to carry its own epoch: only the selected
    // boundary, verified by the incumbent quorum, installs epoch one.
    w.ingest_epoch_original(&genesis, 0, &boundary(&native, &chain[2]))
        .unwrap();
    let (_, manifest) = w.sync_manifest().unwrap();
    let OfferedOutcome::Verified(outcome) = w
        .verify_ledger_original(&manifest, &genesis, &signed, &offered)
        .unwrap()
    else {
        panic!("epoch one is selected");
    };
    assert_eq!((outcome.height(), outcome.accepted()), (4, true));
}

#[test]
fn retained_original_rechecks_every_custody_binding_without_bls() {
    let mut native = NativeFinalityFixture::start("ledger-outcome-custody");
    let key = KeyPair::from_seed(vec![63; 32], Algorithm::Ed25519);
    let first = attempt(&native, &key, 0);
    let second = attempt(&native, &key, 1);
    let block = certify(
        &mut native,
        &[first.clone(), second.clone()],
        vec![Ok(vec![]), rejected()],
    );
    let mut w = ledger_wallet(&native);
    let offered = bytes(&original(&block, 0));
    let outcome = w
        .write_ledger_original(&verified(&native, &original(&block, 0), &first), &offered)
        .unwrap();
    let key = entrypoint(&first).unwrap();
    w.retained_ledger_original(&outcome, &key).unwrap();
    assert!(
        archive::encode(&outcome).unwrap().len()
            < crate::kagemusha_wallet_state_v1::index::INDEX_VALUE_LIMIT / 2
    );
    for binding in 0..7 {
        assert!(matches!(
            w.retained_ledger_original(&outcome.tampered(binding), &key),
            Err(Error::WitnessLost(_))
        ));
    }
    assert!(matches!(
        w.retained_ledger_original(&outcome, &entrypoint(&second).unwrap()),
        Err(Error::WitnessLost(_))
    ));
    // A retained original whose leaves no longer join one row is lost custody.
    let mut unjoined = original(&block, 0);
    unjoined.inclusion.entry_proof = original(&block, 1).inclusion.entry_proof;
    let unjoined = bytes(&unjoined);
    let address = w
        .archive
        .write_object(&unjoined, KAGEMUSHA_WALLET_LEDGER_FINALITY_MAX_BYTES_V1)
        .unwrap();
    let moved = LedgerOutcome {
        finality: address,
        ..outcome
    };
    assert!(matches!(
        w.retained_ledger_original(&moved, &key),
        Err(Error::WitnessLost(_))
    ));
    // A missing original never means absence.
    w.archive
        .remove(ArchiveKey::Object(outcome.finality))
        .unwrap();
    assert!(matches!(
        w.retained_ledger_original(&outcome, &key),
        Err(Error::WitnessLost(_))
    ));
}

#[test]
fn reconcile_keeps_the_first_original_and_refuses_a_conflicting_outcome() {
    let mut native = NativeFinalityFixture::start("ledger-outcome-reconcile");
    let key = KeyPair::from_seed(vec![64; 32], Algorithm::Ed25519);
    let signed = attempt(&native, &key, 0);
    let first = certify(&mut native, std::slice::from_ref(&signed), vec![rejected()]);
    // The fixture never executes: the same entrypoint certified again with the opposite
    // result stands for a consensus fault that Native must refuse, not record.
    let conflicting = certify(&mut native, std::slice::from_ref(&signed), vec![Ok(vec![])]);
    let genesis = genesis(&native);
    let mut w = ledger_wallet(&native);
    let (root, manifest) = w.sync_manifest().unwrap();
    let exact = bytes(&original(&first, 0));
    let retained = w
        .write_ledger_original(&verified(&native, &original(&first, 0), &signed), &exact)
        .unwrap();
    let publications = w.custody.publication_calls;
    let reads = w.archive.reads.load(std::sync::atomic::Ordering::SeqCst);
    // The exact retained original is idempotent without decoding or verifying it.
    assert_eq!(
        w.reconcile_ledger_original(&manifest, &genesis, &retained, &signed, &exact)
            .unwrap(),
        LedgerAttemptOutcomeV1::Rejected(retained.commit())
    );
    assert_eq!(
        w.archive.reads.load(std::sync::atomic::Ordering::SeqCst),
        reads
    );
    // Another honest quorum certificate over the same block verifies to the same outcome.
    let other = bytes(&other_quorum(&original(&first, 0)));
    assert_ne!(other, exact);
    assert_eq!(
        w.reconcile_ledger_original(&manifest, &genesis, &retained, &signed, &other)
            .unwrap(),
        LedgerAttemptOutcomeV1::Rejected(retained.commit())
    );
    assert!(matches!(
        w.reconcile_ledger_original(
            &manifest,
            &genesis,
            &retained,
            &signed,
            &bytes(&original(&conflicting, 0))
        ),
        Err(Error::Proof("conflicting authenticated ledger outcome"))
    ));
    w.retained_ledger_original(&retained, &entrypoint(&signed).unwrap())
        .unwrap();
    assert_eq!(
        (w.custody.publication_calls, w.manifest().unwrap().0),
        (publications, root)
    );
}

#[test]
fn retained_wire_recomputes_its_entrypoint_and_lost_bytes_are_custody_loss() {
    let native = NativeFinalityFixture::start("ledger-outcome-wire");
    let key = KeyPair::from_seed(vec![65; 32], Algorithm::Ed25519);
    let signed = attempt(&native, &key, 0);
    let wire = signed.encode_wire_v1().unwrap();
    assert_eq!(
        retained_entrypoint(&wire).unwrap(),
        *signed.hash_as_entrypoint().as_ref()
    );
    assert_eq!(signed_original(&wire).unwrap(), signed);
    let mut trailing = wire.clone();
    trailing.push(0);
    for lost in [Vec::new(), vec![0], trailing] {
        assert!(matches!(
            retained_entrypoint(&lost),
            Err(Error::WitnessLost(_))
        ));
        assert!(matches!(signed_original(&lost), Err(Error::Invalid(_))));
    }
    let limits = norito::DecodeLimits::new(usize::MAX, 0, usize::MAX, usize::MAX, 64);
    let refused = norito::with_decode_limits_scope(limits, || signed_original(&wire));
    assert!(matches!(refused, Err(Error::DecodeResource(ref cause))
        if cause.kind() == norito::core::DecodeLocalRefusalKind::EnclosingLimit));
    assert_eq!(signed_original(&wire).unwrap(), signed);
}
