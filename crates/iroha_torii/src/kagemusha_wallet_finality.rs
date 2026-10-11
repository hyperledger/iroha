//! Bounded certificate DATA reads for native wallet finality verification.
//! The phone's authenticated epoch owner, never this transport, grants finality.

use std::{num::NonZeroU64, time::Instant};

use iroha_allocation::{AllocationBudget, AllocationReservation, ChargedBuffer};
use iroha_core::{
    kagemusha_wallet_v1::CommittedLoadReceipts, state::StateView, sumeragi::finality,
};
use iroha_crypto::HashOf;
use iroha_data_model::{
    account::AccountId,
    events::EventBox,
    isi::kagemusha_wallet::KagemushaWalletLoadReceiptV1,
    kagemusha::{
        KAGEMUSHA_WALLET_LOAD_FINALITY_MAX_BYTES_V1, KagemushaWalletLoadFinalityV1,
        kagemusha_wallet_account_digest_v1,
    },
    sumeragi::epoch::MAX_VALIDATORS,
    sumeragi_finality::{
        ExecutionResultCommitment, MAX_COMMIT_CERTIFICATE_BYTES_V1, MAX_RESULT_PREIMAGE_BYTES,
        SumeragiCommitCertificateV1,
    },
};
use iroha_model_base::peer::PeerId;

type Result<T> = std::result::Result<T, &'static str>;

// The result decoder charges both reconstructed Ready epochs and the optional retained
// validation contexts to its inherited cumulative Norito scope. The validation workspace
// also briefly encodes one already validated epoch (at most 31 keys/PoPs and fixed fields,
// bounded by the existing result-frame allowance) and projects one validator generation.
// That projection owns 31 PeerIds and their compact 48-byte BLS keys plus algorithm byte;
// validation bounds the roster/key shapes before making the projection. These two buffers
// are not decoder allocations and need their own original-pool allowance.
const VALIDATION_SCRATCH_BYTES: usize =
    MAX_RESULT_PREIMAGE_BYTES + MAX_VALIDATORS * (size_of::<PeerId>() + 49);
// KagemushaLoadEventPathV1::proof uses try_reserve_exact for at most 32 optional hashes.
// Its validation proof is dropped before the returned evidence proof is constructed.
const EVENT_PROOF_BYTES: usize = 32 * size_of::<Option<HashOf<EventBox>>>();

fn reserve_event_proof(budget: &AllocationBudget) -> Result<AllocationReservation> {
    budget
        .try_reserve_bytes(EVENT_PROOF_BYTES)
        .map_err(|_| "event proof allocation unavailable")
}

fn require_payer(payer: &AccountId, receipt: &KagemushaWalletLoadReceiptV1) -> Result<()> {
    receipt
        .validate()
        .map_err(|_| "invalid committed receipt")?;
    if receipt.payer_account_digest
        != kagemusha_wallet_account_digest_v1(payer).map_err(|_| "invalid payer identity")?
    {
        return Err("committed receipt belongs to another payer");
    }
    Ok(())
}

fn require_selected_data(
    certificate: &SumeragiCommitCertificateV1,
    height: u64,
    boundary: bool,
) -> Result<()> {
    if certificate
        .height()
        .map_err(|_| "certificate header differs")?
        != height
    {
        return Err("certificate height differs from selected original");
    }
    let result = ExecutionResultCommitment::decode(&certificate.result_preimage)
        .map_err(|_| "certificate result shape differs")?;
    if result.height != height || (boundary && result.schedule.boundary.is_none()) {
        return Err("certificate is not the selected boundary or receipt");
    }
    Ok(())
}

// Only a validation result may leave this lexical owner; no decoded graph or encoded Vec
// can escape after its original pool reservation is refunded.
fn certificate_decode(
    certificate: &SumeragiCommitCertificateV1,
    budget: &AllocationBudget,
    decode: impl FnOnce() -> Result<()>,
) -> Result<()> {
    certificate
        .validate_shape()
        .map_err(|_| "certificate decode shape differs")?;
    let extent = certificate
        .consensus_header
        .len()
        .checked_add(certificate.commit_qc.len())
        .and_then(|bytes| bytes.checked_add(certificate.result_preimage.len()))
        .filter(|bytes| *bytes <= MAX_COMMIT_CERTIFICATE_BYTES_V1)
        .ok_or("certificate decode extent differs")?;
    let limits = norito::canonical_decode_limits(extent);
    let bytes = limits
        .max_total_allocated_bytes()
        .checked_add(VALIDATION_SCRATCH_BYTES)
        .ok_or("certificate decode allocation overflows")?;
    let _charge = budget
        .try_reserve_bytes(bytes)
        .map_err(|_| "certificate decode allocation unavailable")?;
    norito::with_decode_limits_scope(limits, decode)
}

fn selected_certificate(
    view: &StateView<'_>,
    receipt_height: u64,
    boundary: Option<u64>,
    budget: &AllocationBudget,
    deadline: Instant,
) -> Result<finality::NativeCommitCertificateDataV1> {
    let height = boundary.unwrap_or(receipt_height);
    if height < 2
        || boundary.is_some_and(|height| height >= receipt_height)
        || Instant::now() >= deadline
    {
        return Err("certificate selection deadline or height differs");
    }
    let original = finality::read_commit_certificate(
        view,
        NonZeroU64::new(height).ok_or("zero certificate height")?,
        budget,
        deadline,
    )
    .map_err(|_| "committed native certificate unavailable")?;
    certificate_decode(original.certificate(), budget, || {
        require_selected_data(original.certificate(), height, boundary.is_some())
    })?;
    if Instant::now() >= deadline {
        return Err("native certificate read deadline expired");
    }
    Ok(original)
}

fn response_frame<T: norito::core::NoritoSerialize>(
    value: &T,
    maximum: usize,
    budget: &AllocationBudget,
    deadline: Instant,
) -> Result<ChargedBuffer<u8>> {
    if Instant::now() >= deadline {
        return Err("native certificate response deadline expired");
    }
    // Count, acquire exact original-pool capacity, and serialize directly into that owner.
    // There is no geometrically grown temporary Vec or post-encoding custody transfer.
    let output = crate::native_projection_response::encode_canonical(
        value,
        maximum,
        budget,
        crate::native_projection_response::capacity,
    )
    .map_err(|_| "certificate response encoding or allocation unavailable")?;
    if Instant::now() >= deadline {
        return Err("native certificate response deadline expired");
    }
    Ok(output)
}

/// Read exactly one named boundary as DATA; no source-supplied successor is followed.
pub(super) fn epoch(
    view: &StateView<'_>,
    payer: &AccountId,
    receipt: &KagemushaWalletLoadReceiptV1,
    boundary: u64,
    budget: &AllocationBudget,
    deadline: Instant,
) -> Result<ChargedBuffer<u8>> {
    require_payer(payer, receipt)?;
    let original =
        selected_certificate(view, receipt.block_height, Some(boundary), budget, deadline)?;
    // selected_certificate already checked the canonical header and complete result.
    // Preserve the epoch codec's remaining inner-QC canonical check before streaming DATA.
    certificate_decode(original.certificate(), budget, || {
        norito::decode_canonical_with_limits::<iroha_sumeragi::message::Qc>(
            &original.certificate().commit_qc,
            norito::canonical_decode_limits(original.certificate().commit_qc.len()),
        )
        .map_err(|_| "native epoch certificate QC differs")?;
        Ok(())
    })?;
    response_frame(
        original.certificate(),
        MAX_COMMIT_CERTIFICATE_BYTES_V1,
        budget,
        deadline,
    )
}

/// Return only the receipt certificate and counted event path as untrusted DATA.
/// The phone must authenticate its retained epoch and BLS certificate before Advance.
pub(super) fn evidence(
    view: &StateView<'_>,
    source: &CommittedLoadReceipts<'_, '_>,
    payer: &AccountId,
    receipt: &KagemushaWalletLoadReceiptV1,
    budget: &AllocationBudget,
    deadline: Instant,
) -> Result<ChargedBuffer<u8>> {
    require_payer(payer, receipt)?;
    let original = selected_certificate(view, receipt.block_height, None, budget, deadline)?;
    let receipt_digest = receipt.receipt_digest().map_err(|_| "invalid receipt")?;
    // Prepay even event_path_for's temporary validation proof, then retain the same
    // allowance until the final evidence proof has been destroyed after serialization.
    let _event_charge = reserve_event_proof(budget)?;
    let event = source
        .event_path_for(
            payer,
            &receipt.scheme_id,
            &receipt.wallet_id,
            &receipt.request_id,
        )
        .map_err(|_| "committed Load event unavailable")?;
    let event_proof = event
        .proof()
        .map_err(|_| "committed event path unavailable")?;
    let (certificate, _certificate_charge) = original.into_parts();
    // These constructors establish the codec's version, canonical receipt digest,
    // bounded certificate and <=32-sibling invariants; response_frame enforces its cap.
    // Calling to_canonical_bytes/validate here would allocate an extra unowned frame.
    let evidence = KagemushaWalletLoadFinalityV1 {
        version: 1,
        receipt_digest,
        certificate,
        event_proof,
    };
    // The evidence graph drops before its certificate/proof reservations; the output keeps
    // its own exact charge through the HTTP body's last byte.
    response_frame(
        &evidence,
        KAGEMUSHA_WALLET_LOAD_FINALITY_MAX_BYTES_V1,
        budget,
        deadline,
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use iroha_core::{
        state::{StateReadOnly as _, World},
        sumeragi::test_chain::{CertifiedTestChain, TestChainConfig},
    };
    use iroha_crypto::{Algorithm, KeyPair};
    use iroha_data_model::{
        block::decode_framed_signed_block,
        sumeragi_finality::{SumeragiCommitVerifierV1, SumeragiFinalityVerifier},
    };
    use std::{num::NonZeroUsize, time::Duration};

    fn receipt_at(payer: &AccountId, height: u64) -> KagemushaWalletLoadReceiptV1 {
        KagemushaWalletLoadReceiptV1 {
            version: 1,
            scheme_id: [1; 32],
            asset_digest: [2; 32],
            wallet_id: [3; 32],
            request_id: [4; 32],
            ordinal: 1,
            amount: 7,
            online_charge: 0,
            charge_quote: [0; 32],
            transaction_hash: [5; 32],
            block_height: height,
            payer_account_digest: kagemusha_wallet_account_digest_v1(payer).unwrap(),
        }
    }

    fn verifier(view: &StateView<'_>) -> SumeragiCommitVerifierV1 {
        let genesis = finality::build_proof(view, 1).unwrap();
        let signed = decode_framed_signed_block(&genesis.block_wire).unwrap();
        let native =
            SumeragiFinalityVerifier::new(&signed, view.chain_id().as_str(), genesis.committee)
                .unwrap();
        SumeragiCommitVerifierV1::new(&native).unwrap()
    }

    #[test]
    fn receipt_source_reads_one_exact_frame_without_genesis_or_history_replay() {
        let mut chain =
            CertifiedTestChain::start(TestChainConfig::new(World::default(), 1_000)).unwrap();
        chain.commit(Vec::new());
        chain.commit(Vec::new());
        let view = chain.state().view();
        let mut phone = verifier(&view);
        for height in [1, 2] {
            chain
                .kura()
                .corrupt_native_frame_for_test(NonZeroUsize::new(height).unwrap());
        }
        let budget = AllocationBudget::new(128 << 20);
        let deadline = Instant::now() + Duration::from_secs(30);
        let original = selected_certificate(&view, 3, None, &budget, deadline).unwrap();
        assert_eq!(phone.verify(original.certificate()).unwrap().height(), 3);
        assert!(
            certificate_decode(original.certificate(), &AllocationBudget::new(0), || Ok(()))
                .is_err()
        );
        let mut tampered = original.certificate().clone();
        *tampered.commit_qc.last_mut().unwrap() ^= 1;
        // Shape-matched transport DATA is not an authority capability.
        require_selected_data(&tampered, 3, false).unwrap();
        assert!(phone.verify(&tampered).is_err());
        drop(original);
        assert_eq!(budget.reserved_bytes(), 0);
        for (height, boundary, until) in [
            (1, None, deadline),
            (3, Some(3), deadline),
            (3, Some(4), deadline),
            (3, None, Instant::now()),
        ] {
            assert!(selected_certificate(&view, height, boundary, &budget, until).is_err());
        }
        assert!(selected_certificate(&view, 3, None, &AllocationBudget::new(0), deadline).is_err());
    }

    #[test]
    fn epoch_source_requires_exact_boundary_before_receipt_without_following_successors() {
        let mut chain = CertifiedTestChain::npos_boundary_fixture();
        chain.commit(Vec::new());
        let view = chain.state().view();
        let mut phone = verifier(&view);
        chain
            .kura()
            .corrupt_native_frame_for_test(NonZeroUsize::new(1).unwrap());
        let budget = AllocationBudget::new(128 << 20);
        let deadline = Instant::now() + Duration::from_secs(30);
        // H11 is not present: selecting H10 must not read its advertised successor.
        let original = selected_certificate(&view, 11, Some(10), &budget, deadline).unwrap();
        assert_eq!(phone.verify(original.certificate()).unwrap().height(), 10);
        let payer = AccountId::new(
            KeyPair::from_seed(vec![0x61; 32], Algorithm::Ed25519)
                .public_key()
                .clone(),
        );
        let response = epoch(
            &view,
            &payer,
            &receipt_at(&payer, 11),
            10,
            &budget,
            deadline,
        )
        .unwrap();
        assert_eq!(
            response.as_slice(),
            original.certificate().to_canonical_bytes().unwrap(),
        );
        let decoded = SumeragiCommitCertificateV1::decode_canonical(response.as_slice()).unwrap();
        assert_eq!(&decoded, original.certificate());
        assert_eq!(phone.verify(&decoded).unwrap().height(), 10);
        assert!(require_selected_data(original.certificate(), 9, true).is_err());
        assert!(selected_certificate(&view, 11, Some(2), &budget, deadline).is_err());
        drop(response);
        drop(original);
        assert_eq!(budget.reserved_bytes(), 0);
    }

    #[test]
    fn response_custody_is_retained_and_all_bounds_refuse() {
        let value = [1_u8, 2];
        let expected = norito::encode_canonical(&value).unwrap();
        let length = expected.len();
        let budget = AllocationBudget::new(length);
        let deadline = Instant::now() + Duration::from_secs(30);
        assert!(response_frame(&value, 0, &budget, deadline).is_err());
        assert!(response_frame(&value, length - 1, &budget, deadline).is_err());
        assert!(response_frame(&value, length, &budget, Instant::now()).is_err());
        assert!(response_frame(&value, length, &AllocationBudget::new(0), deadline).is_err());
        assert!(
            response_frame(&value, length, &AllocationBudget::new(length - 1), deadline).is_err()
        );
        assert_eq!(budget.reserved_bytes(), 0);
        let response = response_frame(&value, length, &budget, deadline).unwrap();
        assert_eq!(response.as_slice(), expected);
        assert_eq!(budget.reserved_bytes(), length);
        assert!(response_frame(&value, length, &budget, deadline).is_err());
        drop(response);
        assert_eq!(budget.reserved_bytes(), 0);
    }

    #[test]
    fn certificate_decode_prepays_and_refunds_the_complete_lexical_allowance() {
        // The closure is intentionally independent of cryptographic fixture work: it observes
        // the pool at the actual admission seam and proves refusal precedes any decode work.
        let certificate = SumeragiCommitCertificateV1 {
            consensus_header: vec![1],
            commit_qc: vec![2],
            result_preimage: vec![3],
        };
        let bytes = norito::canonical_decode_limits(3).max_total_allocated_bytes()
            + VALIDATION_SCRATCH_BYTES;
        let small = AllocationBudget::new(bytes - 1);
        let called = std::cell::Cell::new(false);
        assert!(
            certificate_decode(&certificate, &small, || {
                called.set(true);
                Ok(())
            })
            .is_err()
        );
        assert!(!called.get());
        assert_eq!(small.reserved_bytes(), 0);
        let budget = AllocationBudget::new(bytes);
        for reject in [false, true] {
            let observed = certificate_decode(&certificate, &budget, || {
                assert_eq!(budget.reserved_bytes(), bytes);
                if reject {
                    Err("injected decoder refusal")
                } else {
                    Ok(())
                }
            });
            assert_eq!(observed.is_err(), reject);
            assert_eq!(budget.reserved_bytes(), 0);
        }
        let missing = SumeragiCommitCertificateV1 {
            consensus_header: Vec::new(),
            ..certificate
        };
        assert!(
            certificate_decode(&missing, &budget, || {
                called.set(true);
                Ok(())
            })
            .is_err()
        );
        assert!(!called.get());
        assert_eq!(budget.reserved_bytes(), 0);
    }

    #[test]
    fn event_proof_reservation_and_receipt_frame_have_separate_live_charges() {
        let payer = AccountId::new(
            KeyPair::from_seed(vec![0x63; 32], Algorithm::Ed25519)
                .public_key()
                .clone(),
        );
        // This is codec DATA parity, not a finality/receipt-inclusion claim. The epoch test
        // above separately compares a real certified boundary's complete canonical frame.
        let evidence = KagemushaWalletLoadFinalityV1 {
            version: 1,
            receipt_digest: receipt_at(&payer, 2).receipt_digest().unwrap(),
            certificate: SumeragiCommitCertificateV1 {
                consensus_header: vec![1],
                commit_qc: vec![2],
                result_preimage: vec![3],
            },
            event_proof: iroha_crypto::MerkleProof::from_audit_path(0, vec![None; 32]),
        };
        let expected = evidence.to_canonical_bytes().unwrap();
        let length = expected.len();
        let small = AllocationBudget::new(EVENT_PROOF_BYTES - 1);
        assert!(reserve_event_proof(&small).is_err());
        assert_eq!(small.reserved_bytes(), 0);
        let budget = AllocationBudget::new(EVENT_PROOF_BYTES + length);
        let proof_charge = reserve_event_proof(&budget).unwrap();
        assert_eq!(budget.reserved_bytes(), EVENT_PROOF_BYTES);
        let deadline = Instant::now() + Duration::from_secs(30);
        let output = response_frame(
            &evidence,
            KAGEMUSHA_WALLET_LOAD_FINALITY_MAX_BYTES_V1,
            &budget,
            deadline,
        )
        .unwrap();
        assert_eq!(output.as_slice(), expected);
        assert_eq!(budget.reserved_bytes(), EVENT_PROOF_BYTES + length);
        drop(evidence);
        drop(proof_charge);
        assert_eq!(budget.reserved_bytes(), length);
        drop(output);
        assert_eq!(budget.reserved_bytes(), 0);
    }

    #[test]
    fn receipt_selection_requires_exact_payer_and_valid_non_genesis_load() {
        let payer = AccountId::new(
            KeyPair::from_seed(vec![0x61; 32], Algorithm::Ed25519)
                .public_key()
                .clone(),
        );
        let other = AccountId::new(
            KeyPair::from_seed(vec![0x62; 32], Algorithm::Ed25519)
                .public_key()
                .clone(),
        );
        let receipt = receipt_at(&payer, 2);
        require_payer(&payer, &receipt).unwrap();
        assert!(require_payer(&other, &receipt).is_err());
        for changed in [
            KagemushaWalletLoadReceiptV1 {
                block_height: 1,
                ..receipt
            },
            KagemushaWalletLoadReceiptV1 {
                amount: 0,
                ..receipt
            },
        ] {
            assert!(require_payer(&payer, &changed).is_err());
        }
    }
}
