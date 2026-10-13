//! Current authenticated wallet heads and immutable, descending receipt pages.
use super::*;
use crate::{
    account::AccountId,
    validation_fee::{
        RetailFeeReceiptHeadV1, retail_fee_receipt_chain_hash_v1,
        retail_fee_receipt_head_state_key_v1,
    },
};

/// Maximum immutable receipts in a private history page.
pub const MAX_RETAIL_FEE_RECEIPT_PAGE_COUNT_V1: usize = 100;
/// Maximum canonical receipt history page bytes.
pub const MAX_RETAIL_FEE_RECEIPT_PAGE_BYTES_V1: usize = 1024 * 1024;

/// Canonical execution-witness-compatible leaf for an authenticated current head.
///
/// # Errors
///
/// Returns an error if the head cannot be canonically encoded or its state key
/// cannot be represented.
pub fn retail_fee_head_leaf_hash_v1(head: &RetailFeeReceiptHeadV1) -> Result<Hash, String> {
    let key = retail_fee_receipt_head_state_key_v1(&head.wallet_id)?;
    let mut bytes = vec![0];
    bytes.extend_from_slice(Hash::new(key.as_ref().as_bytes()).as_ref());
    bytes.extend_from_slice(
        Hash::new(norito::encode_canonical(head).map_err(|e| e.to_string())?).as_ref(),
    );
    Ok(Hash::new(bytes))
}
/// Canonical sparse key path of the original wallet identity.
///
/// # Errors
///
/// Returns an error if the wallet receipt-head state key cannot be represented.
pub fn retail_fee_head_path_v1(wallet: &AccountId) -> Result<[u8; 32], String> {
    Ok(Hash::new(
        retail_fee_receipt_head_state_key_v1(wallet)?
            .as_ref()
            .as_bytes(),
    )
    .into())
}
/// Canonical binary node hash, shared by compressed storage and proof verification.
pub fn retail_fee_head_node_hash_v1(left: Hash, right: Hash) -> Hash {
    fee_ordinary_smt_node_hash(left, right)
}

/// Independently retained position in one wallet's immutable receipt hash chain.
#[derive(
    Debug,
    Clone,
    PartialEq,
    Eq,
    Encode,
    Decode,
    IntoSchema,
    crate::DeriveJsonSerialize,
    crate::DeriveJsonDeserialize,
    norito::NoritoSchema,
)]
#[norito_schema(name = "iroha_data_model::fee_evidence::RetailFeeReceiptCursorV1")]
pub struct RetailFeeReceiptCursorV1 {
    /// Original wallet identity, unchanged through account recovery.
    pub wallet_id: AccountId,
    /// Next descending receipt sequence; zero means the beginning is reached.
    pub next_sequence: u64,
    /// Hash of that exact next receipt; absent exactly at sequence zero.
    pub next_receipt_hash: Option<[u8; 32]>,
}
/// Current wallet head authenticated under one independently pinned finality checkpoint.
#[derive(
    Debug,
    Clone,
    PartialEq,
    Eq,
    Encode,
    Decode,
    IntoSchema,
    crate::DeriveJsonSerialize,
    crate::DeriveJsonDeserialize,
    norito::NoritoSchema,
)]
#[norito_schema(name = "iroha_data_model::fee_evidence::RetailFeeCurrentHeadProofV1")]
pub struct RetailFeeCurrentHeadProofV1 {
    /// Native D8 inclusion under the checkpoint's ordinary-write root.
    pub snapshot_witness: FeeEvidenceWitnessProofV1,
    /// Exact current cumulative wallet cursor, including recovered account identity.
    pub head: RetailFeeReceiptHeadV1,
    /// Exactly 256 sparse siblings, leaf to root; unrelated wallets stay private.
    pub head_siblings: Vec<Hash>,
}
impl RetailFeeCurrentHeadProofV1 {
    /// Verify against independent native finality and obtain the first history cursor.
    ///
    /// # Errors
    ///
    /// Returns an error for an invalid snapshot, identity or checkpoint mismatch,
    /// incoherent cursor, invalid sparse proof, or canonical encoding failure.
    pub fn verify(
        &self,
        ordinary_root: Hash,
        wallet: &AccountId,
        requested_account: &AccountId,
        height: u64,
    ) -> Result<RetailFeeReceiptCursorV1, String> {
        let snapshot = self.snapshot_witness.commitment()?;
        if snapshot.evaluated_height != height
            || !self.snapshot_witness.verify(ordinary_root)
            || self.head_siblings.len() != 256
            || &self.head.wallet_id != wallet
            || &self.head.current_account_id != requested_account
            || self.head.updated_at_height > height
            || self.head.updated_at_height == 0
            || (self.head.sequence == 0) != self.head.last_receipt_hash.is_none()
        {
            return Err(
                "current wallet head is not bound to the requested identity and checkpoint".into(),
            );
        }
        let path = retail_fee_head_path_v1(wallet)?;
        let mut current = retail_fee_head_leaf_hash_v1(&self.head)?;
        for (level, sibling) in self.head_siblings.iter().copied().enumerate() {
            let index = 255 - level;
            current = if path[index / 8] & (1 << (index % 8)) != 0 {
                retail_fee_head_node_hash_v1(sibling, current)
            } else {
                retail_fee_head_node_hash_v1(current, sibling)
            };
        }
        if current != snapshot.account_heads_root {
            return Err("current wallet head proof differs from finalized cumulative root; retry checkpoint".into());
        }
        Ok(RetailFeeReceiptCursorV1 {
            wallet_id: wallet.clone(),
            next_sequence: self.head.sequence,
            next_receipt_hash: self.head.last_receipt_hash,
        })
    }
}
/// A bounded private descending page; no new head or finality is needed between pages.
#[derive(
    Debug,
    Clone,
    PartialEq,
    Eq,
    Encode,
    Decode,
    IntoSchema,
    crate::DeriveJsonSerialize,
    crate::DeriveJsonDeserialize,
    norito::NoritoSchema,
)]
#[norito_schema(name = "iroha_data_model::fee_evidence::RetailFeeReceiptPageV1")]
pub struct RetailFeeReceiptPageV1 {
    /// Exact immutable wallet receipts in descending sequence order.
    pub receipts: Vec<RetailFeeReceiptV1>,
}
impl RetailFeeReceiptPageV1 {
    /// Verify every receipt against a cursor derived from a verified head or page.
    /// Never trust a cursor supplied solely by an unverified history response.
    ///
    /// # Errors
    ///
    /// Returns an error for an empty, oversized or incoherent page, canonical
    /// encoding failure, or a wallet, sequence, hash-chain or amount-conservation
    /// mismatch.
    pub fn verify(
        &self,
        cursor: &RetailFeeReceiptCursorV1,
    ) -> Result<RetailFeeReceiptCursorV1, String> {
        if (cursor.next_sequence == 0) != cursor.next_receipt_hash.is_none()
            || self.receipts.len() > MAX_RETAIL_FEE_RECEIPT_PAGE_COUNT_V1
            || norito::to_bytes(self).map_err(|e| e.to_string())?.len()
                > MAX_RETAIL_FEE_RECEIPT_PAGE_BYTES_V1
            || (cursor.next_sequence > 0 && self.receipts.is_empty())
        {
            return Err(
                "receipt page is empty, oversized, or has an incoherent trusted cursor".into(),
            );
        }
        let mut next = cursor.clone();
        for receipt in &self.receipts {
            let expected_sequence = next.next_sequence;
            if receipt.wallet_id != next.wallet_id
                || receipt.sequence != expected_sequence
                || receipt.sequence == 0
                || Some(retail_fee_receipt_chain_hash_v1(receipt)?) != next.next_receipt_hash
                || receipt.collected_minor.checked_add(receipt.waived_minor)
                    != Some(receipt.scheduled_minor)
                || (receipt.sequence == 1) != receipt.previous_receipt_hash.is_none()
            {
                return Err(
                    "receipt page breaks the wallet's authenticated descending chain".into(),
                );
            }
            next.next_sequence -= 1;
            next.next_receipt_hash = receipt.previous_receipt_hash;
        }
        Ok(next)
    }
}

/// Maximum finalized blocks in one native fee accounting window.
pub(super) const MAX_FEE_EVIDENCE_WINDOW_BLOCKS_V1: usize =
    crate::sumeragi::finality::NATIVE_FINALITY_MAX_BLOCK_COUNT;

/// Authenticate a complete contiguous window forward from the anchor's opening checkpoint.
///
/// Returns each block's authenticated ordinary-write root in window order.
pub(super) fn verify_finality_window(
    blocks: &[FeeEvidenceFinalizedBlockV1],
    anchor: &FeeEvidenceTrustAnchorV1,
) -> Result<Vec<Hash>, String> {
    use crate::sumeragi_finality::SumeragiFinalityVerifier;
    let proofs = blocks
        .iter()
        .map(|block| &block.finality)
        .collect::<Vec<_>>();
    let opening_height = anchor.opening_height();
    if opening_height == 0
        || anchor.closing_height <= opening_height
        || proofs.len() > MAX_FEE_EVIDENCE_WINDOW_BLOCKS_V1
        || u64::try_from(proofs.len()).ok()
            != anchor
                .closing_height
                .checked_sub(opening_height)
                .and_then(|span| span.checked_add(1))
    {
        return Err("native finality window is incomplete or unbounded".into());
    }
    let checkpoint = &anchor.opening_checkpoint;
    let mut verifier = SumeragiFinalityVerifier::from_trusted_checkpoint(
        checkpoint,
        &anchor.network_id,
        checkpoint.chain_id(),
    )
    .map_err(|e| format!("native finality checkpoint: {e}"))?;
    let mut roots = Vec::with_capacity(proofs.len());
    let mut closing_hash = None;
    for (index, proof) in proofs.into_iter().enumerate() {
        let decision = if index == 0 {
            verifier.verify_same_decision(checkpoint.tip(), proof)
        } else {
            verifier.verify(proof)
        }
        .map_err(|e| format!("native finality certificate: {e}"))?;
        if decision.height() != opening_height + index as u64
            || decision.header() != proof.block_header
        {
            return Err("native finality network or height mismatch".into());
        }
        roots.push(decision.execution().ordinary_writes_root);
        closing_hash = Some(proof.block_header.hash());
    }
    if closing_hash != Some(anchor.closing_block_hash) {
        return Err("native finality checkpoints differ from independent trust".into());
    }
    Ok(roots)
}

#[cfg(test)]
mod tests {
    use super::*;
    #[cfg(feature = "transparent_api")]
    #[test]
    fn native_fee_window_authenticates_forward_from_checkpoint_and_rejects_substitution() {
        use crate::sumeragi_finality::tests::Fixture;
        let f = Fixture::new();
        let mut verifier = f.verifier();
        verifier.verify(&f.first).unwrap();
        let checkpoint = verifier.export_checkpoint(&f.first).unwrap();
        let block = |finality: crate::sumeragi_finality::SumeragiFinalityProof| {
            FeeEvidenceFinalizedBlockV1 {
                finality,
                evidence: FeeEvidenceBlockProofV1 {
                    snapshot_witness: FeeEvidenceWitnessProofV1 {
                        key: Vec::new(),
                        value: Vec::new(),
                        siblings: Vec::new(),
                    },
                    records: Vec::new(),
                },
                policy_witness: crate::validation_fee::ValidationFeePolicyWitnessProofV1 {
                    key: Vec::new(),
                    value: Vec::new(),
                    siblings: Vec::new(),
                },
                registry: None,
            }
        };
        let anchor = FeeEvidenceTrustAnchorV1 {
            network_id: f.network,
            opening_checkpoint: checkpoint.clone(),
            closing_height: 2,
            closing_block_hash: f.second.block_header.hash(),
        };
        let blocks = vec![block(f.first.clone()), block(f.second.clone())];
        let roots = verify_finality_window(&blocks, &anchor).unwrap();
        assert_eq!(roots.len(), 2);
        assert_eq!(
            roots[1],
            f.second
                .decode_checked(crate::sumeragi_finality::CertifiedResultScope::TairaGlobal)
                .unwrap()
                .execution()
                .ordinary_writes_root
        );
        // A shorter window, a substituted closing pin, reordering and tampering fail.
        assert!(verify_finality_window(&blocks[..1], &anchor).is_err());
        let mut wrong_closing = anchor.clone();
        wrong_closing.closing_block_hash = f.first.block_header.hash();
        assert!(verify_finality_window(&blocks, &wrong_closing).is_err());
        let reordered = vec![block(f.second.clone()), block(f.first.clone())];
        assert!(verify_finality_window(&reordered, &anchor).is_err());
        let mut tampered = f.second.clone();
        let last = tampered.block_wire.len() - 1;
        tampered.block_wire[last] ^= 1;
        assert!(
            verify_finality_window(&[block(f.first.clone()), block(tampered)], &anchor).is_err()
        );
        let foreign = FeeEvidenceTrustAnchorV1 {
            network_id: crate::NetworkId::from_genesis_hash(HashOf::from_untyped_unchecked(
                Hash::new(b"foreign native fee network"),
            )),
            ..anchor
        };
        assert!(verify_finality_window(&blocks, &foreign).is_err());
    }
    #[test]
    fn native_fee_private_pages_verify_descending_history_recovery_and_saved_cursors() {
        let record = super::super::tests::receipt(12, "p");
        let FeeEvidencePayloadV1::RetailReceipt(mut first) = record.payload else {
            unreachable!()
        };
        first.sequence = 1;
        first.previous_receipt_hash = None;
        let mut second = first.clone();
        second.sequence = 2;
        second.recorded_at_height = 900_000;
        second.account_id = AccountId::new(
            iroha_crypto::KeyPair::from_seed(vec![91; 32], iroha_crypto::Algorithm::Ed25519)
                .public_key()
                .clone(),
        );
        second.previous_receipt_hash = Some(retail_fee_receipt_chain_hash_v1(&first).unwrap());
        let closing = RetailFeeReceiptCursorV1 {
            wallet_id: first.wallet_id.clone(),
            next_sequence: 2,
            next_receipt_hash: Some(retail_fee_receipt_chain_hash_v1(&second).unwrap()),
        };
        let page = RetailFeeReceiptPageV1 {
            receipts: vec![second.clone()],
        };
        let next = page.verify(&closing).unwrap();
        assert_eq!(next.next_sequence, 1);
        assert_eq!(next.next_receipt_hash, second.previous_receipt_hash);
        let last = RetailFeeReceiptPageV1 {
            receipts: vec![first.clone()],
        }
        .verify(&next)
        .unwrap();
        assert_eq!(last.next_sequence, 0);
        assert_eq!(last.next_receipt_hash, None);
        assert!(
            RetailFeeReceiptPageV1 {
                receipts: vec![first.clone()]
            }
            .verify(&closing)
            .is_err(),
            "omitted recent receipt"
        );
        assert!(
            RetailFeeReceiptPageV1 {
                receipts: vec![second.clone(), second.clone()]
            }
            .verify(&closing)
            .is_err(),
            "replayed receipt"
        );
        let mut corrupt = second;
        corrupt.collected_minor += 1;
        assert!(
            RetailFeeReceiptPageV1 {
                receipts: vec![corrupt]
            }
            .verify(&closing)
            .is_err()
        );
        assert!(
            RetailFeeReceiptPageV1 { receipts: vec![] }
                .verify(&closing)
                .is_err(),
            "empty page cannot claim completeness"
        );
        assert!(
            RetailFeeReceiptPageV1 {
                receipts: vec![first; 101]
            }
            .verify(&next)
            .is_err(),
            "bounded page"
        );
    }
}
