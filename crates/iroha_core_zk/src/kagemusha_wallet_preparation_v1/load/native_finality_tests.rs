//! The actual pre-derivation Load gate with genuine exact-quorum BLS certificates.
//!
//! Fixture events are synthetic execution results, authenticated by real native BLS.
//! These component tests do not grant an installed artifact capability or exercise
//! Advance signing, durable balance publication, Selected resume, or monetary proofs.
//! TODO: run the full-catalog public prepare/commit test with signer unavailability,
//! exact Selected-capsule restart and byte-identical completed retry. Selected resume
//! uses that previously authorized capsule; it does not reauthenticate new Load input.

use iroha_crypto::{HashOf, MerkleTree};
use iroha_data_model::{
    events::{
        EventBox,
        data::{DataEvent, kagemusha::KagemushaLoadCommittedV1},
    },
    sumeragi_finality::{
        SumeragiCommitCertificateV1, SumeragiFinalityVerifier, test_fixtures::NativeFinalityFixture,
    },
};
use iroha_sumeragi::message::Qc;

use super::*;

#[path = "native_finality_tests/selected_epoch.rs"]
mod selected_epoch;

fn authenticate_originals(
    native: &SumeragiFinalityVerifier,
    receipt: &[u8],
    finality: &[u8],
) -> Result<
    (
        KagemushaWalletLoadReceiptV1,
        [KagemushaWalletRetainedInputV1; 2],
    ),
    Error,
> {
    super::authenticate_originals(
        &mut SumeragiCommitVerifierV1::new(native).unwrap(),
        receipt,
        finality,
    )
}

struct NativeLoad {
    native: SumeragiFinalityVerifier,
    receipt: KagemushaWalletLoadReceiptV1,
    evidence: KagemushaWalletLoadFinalityV1,
    events: MerkleTree<EventBox>,
}

impl NativeLoad {
    fn new(chain: &str) -> Self {
        let mut fixture = NativeFinalityFixture::start_with_explicit_parameters(chain);
        // Select the independent signed-genesis authority before certifying H2.
        let native = fixture.verifier();
        let receipt = KagemushaWalletLoadReceiptV1 {
            version: 1,
            scheme_id: [1; 32],
            asset_digest: [2; 32],
            wallet_id: [3; 32],
            request_id: [4; 32],
            ordinal: 0,
            amount: 101,
            online_charge: 7,
            charge_quote: [5; 32],
            transaction_hash: [6; 32],
            block_height: 2,
            payer_account_digest: [7; 32],
        };
        let unrelated = KagemushaWalletLoadReceiptV1 {
            request_id: [8; 32],
            ..receipt
        };
        let events = [unrelated, receipt].map(|value| {
            EventBox::Data(
                DataEvent::KagemushaLoadCommitted(
                    KagemushaLoadCommittedV1::from_receipt(&value).unwrap(),
                )
                .into(),
            )
        });
        let tree: MerkleTree<EventBox> = events.iter().map(HashOf::new).collect();
        let block = fixture.block_with_submitted_work(fixture.next_header());
        let original = fixture.certify_with_events(block, &events);
        let certified = fixture.verifier();
        let verified = certified.verify_retained_decision(&original).unwrap();
        let evidence = KagemushaWalletLoadFinalityV1 {
            version: 1,
            receipt_digest: receipt.receipt_digest().unwrap(),
            certificate: SumeragiCommitCertificateV1::from_verified(&verified).unwrap(),
            event_proof: tree.get_proof(1).unwrap(),
        };
        Self {
            native,
            receipt,
            evidence,
            events: tree,
        }
    }

    fn check(
        &self,
        receipt: &KagemushaWalletLoadReceiptV1,
        evidence: &KagemushaWalletLoadFinalityV1,
    ) -> Result<
        (
            KagemushaWalletLoadReceiptV1,
            [KagemushaWalletRetainedInputV1; 2],
        ),
        Error,
    > {
        let receipt_bytes = receipt.to_canonical_bytes().unwrap();
        let evidence_bytes = evidence.to_canonical_bytes().unwrap();
        // Mutations in the cryptographic cases are still canonical model objects.
        assert_eq!(
            KagemushaWalletLoadReceiptV1::decode_canonical(&receipt_bytes).unwrap(),
            *receipt
        );
        assert_eq!(
            KagemushaWalletLoadFinalityV1::decode_canonical(&evidence_bytes).unwrap(),
            *evidence
        );
        authenticate_originals(&self.native, &receipt_bytes, &evidence_bytes)
    }
}

#[test]
fn native_load_gate_preserves_exact_authenticated_originals() {
    let source = NativeLoad::new("wallet-load-gate-originals");
    let (receipt, retained) = source.check(&source.receipt, &source.evidence).unwrap();
    assert_eq!(receipt, source.receipt);
    assert_eq!(
        retained,
        [
            KagemushaWalletRetainedInputV1 {
                role: KagemushaWalletRetainedInputRoleV1::LoadReceipt,
                bytes: source.receipt.to_canonical_bytes().unwrap(),
            },
            KagemushaWalletRetainedInputV1 {
                role: KagemushaWalletRetainedInputRoleV1::LoadFinality,
                bytes: source.evidence.to_canonical_bytes().unwrap(),
            },
        ]
    );
    // Rechecking exact originals grants the same data, not a second credit or a
    // Selected capability; those state/custody owners are outside this gate.
    assert_eq!(
        source.check(&source.receipt, &source.evidence).unwrap(),
        (receipt, retained)
    );
}

#[test]
fn native_load_gate_rejects_receipt_changes_even_with_rebound_envelope_digest() {
    let source = NativeLoad::new("wallet-load-gate-receipt");
    source.check(&source.receipt, &source.evidence).unwrap();
    let mut changed = [source.receipt; 11];
    changed[0].scheme_id[0] ^= 1;
    changed[1].asset_digest[0] ^= 1;
    changed[2].wallet_id[0] ^= 1;
    changed[3].request_id[0] ^= 1;
    changed[4].ordinal += 1;
    changed[5].amount += 1;
    changed[6].online_charge += 1;
    changed[7].charge_quote[0] ^= 1;
    changed[8].transaction_hash[0] ^= 1;
    changed[9].block_height += 1;
    changed[10].payer_account_digest[0] ^= 1;
    for receipt in changed {
        let mut evidence = source.evidence.clone();
        evidence.receipt_digest = receipt.receipt_digest().unwrap();
        assert_eq!(source.check(&receipt, &evidence), Err(Error::Proof));
    }
}

#[test]
fn native_load_gate_rejects_canonical_qc_with_another_valid_bls_signature() {
    let source = NativeLoad::new("wallet-load-gate-qc");
    let other = NativeLoad::new("wallet-load-gate-other-qc");
    source.check(&source.receipt, &source.evidence).unwrap();
    other.check(&other.receipt, &other.evidence).unwrap();
    let original: Qc = norito::decode_canonical(&source.evidence.certificate.commit_qc).unwrap();
    let foreign: Qc = norito::decode_canonical(&other.evidence.certificate.commit_qc).unwrap();
    let mut forged = original.clone();
    assert_ne!(original.agg_sig, foreign.agg_sig);
    // Preserve the exact message, quorum and canonical point encoding; only the
    // aggregate changes to a genuine signature for a different signed message.
    forged.agg_sig = foreign.agg_sig;
    let mut evidence = source.evidence.clone();
    evidence.certificate.commit_qc = norito::encode_canonical(&forged).unwrap();
    assert_eq!(
        norito::decode_canonical::<Qc>(&evidence.certificate.commit_qc).unwrap(),
        forged
    );
    assert_eq!(source.check(&source.receipt, &evidence), Err(Error::Proof));
}

#[test]
fn native_load_gate_rejects_substituted_event_and_foreign_certificate() {
    let source = NativeLoad::new("wallet-load-gate-event");
    source.check(&source.receipt, &source.evidence).unwrap();
    let mut wrong_event = source.evidence.clone();
    wrong_event.event_proof = source.events.get_proof(0).unwrap();
    assert_ne!(wrong_event.event_proof, source.evidence.event_proof);
    assert_eq!(
        source.check(&source.receipt, &wrong_event),
        Err(Error::Proof)
    );
    let foreign = NativeLoad::new("wallet-load-gate-foreign-event");
    let mut substituted = source.evidence.clone();
    substituted.certificate = foreign.evidence.certificate;
    assert_eq!(
        source.check(&source.receipt, &substituted),
        Err(Error::Proof)
    );
}

#[test]
fn native_load_gate_rejects_noncanonical_originals_and_a_foreign_root() {
    let source = NativeLoad::new("wallet-load-gate-bytes");
    let receipt = source.receipt.to_canonical_bytes().unwrap();
    let evidence = source.evidence.to_canonical_bytes().unwrap();
    let mut trailing_receipt = receipt.clone();
    trailing_receipt.push(0);
    assert_eq!(
        authenticate_originals(&source.native, &trailing_receipt, &evidence),
        Err(Error::Authority)
    );
    let mut trailing_evidence = evidence.clone();
    trailing_evidence.push(0);
    assert_eq!(
        authenticate_originals(&source.native, &receipt, &trailing_evidence),
        Err(Error::Authority)
    );
    let foreign = NativeFinalityFixture::start_with_explicit_parameters("foreign-load-root");
    assert_eq!(
        authenticate_originals(&foreign.verifier(), &receipt, &evidence),
        Err(Error::Proof)
    );
    // A canonically encoded but mismatched retained receipt/finality pair is
    // refused by exact-original binding before a receipt is returned to derive.
    let mut changed = source.receipt;
    changed.amount += 1;
    assert_eq!(
        source.check(&changed, &source.evidence),
        Err(Error::Authority)
    );
    source.check(&source.receipt, &source.evidence).unwrap();
}
