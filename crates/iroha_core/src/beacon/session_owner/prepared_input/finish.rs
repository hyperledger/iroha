//! Single move from completely decoded destinations into the canonical retained graph.

use super::*;
use common::*;
use rows::{Acceptance, Dealer, Edge, Peer, Recipient, Row};
use sequence::Rows;

/// Actual final graph charges, admitted with their backing before decoding.
/// On an impossible unwind while transferring custody, retaining credit is safer
/// than reporting free capacity while an incompletely assembled graph may live.
pub(super) struct Ledger {
    charges: Option<ChargedBuffer<AllocationCharge>>,
}
impl Ledger {
    pub(super) fn new(
        entries: usize,
        budget: &AllocationBudget,
    ) -> Result<Self, SessionGraphError> {
        Ok(Self {
            charges: Some(buffer(entries, budget)?),
        })
    }
    fn retain(&mut self, charge: AllocationCharge) {
        if let Err(charge) = self
            .charges
            .as_mut()
            .expect("prepared graph ledger")
            .try_push(charge)
        {
            std::mem::forget(charge);
            panic!("prepared graph ledger cardinality changed");
        }
    }
    #[allow(unsafe_code)]
    pub(super) fn vector<T>(&mut self, values: ChargedBuffer<T>) -> Vec<T> {
        // SAFETY: the same allocation moves into its canonical field. Its charge
        // moves into the preallocated ledger, without growth or a mutable escape.
        let (values, charge) = unsafe { values.into_allocation_parts() };
        self.retain(charge);
        values
    }
    #[allow(unsafe_code)]
    fn signature(&mut self, destination: PreparedSignatureDecode) -> Signature {
        let signature = match destination.finish() {
            Ok(signature) => signature,
            Err(incomplete) => {
                drop(incomplete);
                panic!("signature extraction preceded complete frame validation");
            }
        };
        // SAFETY: complete immutable bytes and original charge move once into
        // the same canonical graph/ledger, which never permits independent escape.
        let (signature, charge) = unsafe { signature.into_allocation_parts() };
        self.retain(charge);
        signature
    }
    #[allow(unsafe_code)]
    fn peer(&mut self, destination: Peer) -> PeerId {
        let key = match destination.key.finish() {
            Ok(key) => key,
            Err(incomplete) => {
                drop(incomplete);
                panic!("key extraction preceded complete frame validation");
            }
        };
        // SAFETY: no copy, resize, revalidation or ownership split occurs before
        // the canonical PeerId and original charge join this retained graph.
        let (key, charge) = unsafe { key.into_allocation_parts() };
        self.retain(charge);
        PeerId::new(key)
    }
    #[allow(unsafe_code)]
    pub(super) fn finish<T>(mut self, payload: T, budget: &AllocationBudget) -> RetainedPayload<T> {
        let ledger = self.charges.take().expect("prepared graph ledger");
        if ledger.as_slice().len() != ledger.capacity() {
            drop(payload);
            drop(ledger);
            panic!("prepared graph ledger was not completely transferred");
        }
        // SAFETY: every retained canonical Vec/key/signature field has moved
        // through the exact original charge transfer above. All temporary bank
        // storage remains independently charged and is retired separately.
        match unsafe { RetainedPayload::try_new(payload, ledger, budget) } {
            Ok(owner) => owner,
            Err((payload, ledger, _error)) => {
                drop(payload);
                drop(ledger);
                panic!("prepared graph original pool changed");
            }
        }
    }
}
impl Drop for Ledger {
    fn drop(&mut self) {
        if std::thread::panicking() {
            if let Some(charges) = self.charges.take() {
                std::mem::forget(charges);
            }
        }
    }
}

pub(super) trait FinishRow: Row {
    fn finish(self, ledger: &mut Ledger) -> Self::Wire;
}
impl FinishRow for Recipient {
    fn finish(self, ledger: &mut Ledger) -> Self::Wire {
        GlobalThresholdBeaconDkgRecipientKeyV1 {
            recipient_index: self.recipient_index,
            validator: ledger.peer(self.validator),
            x25519_public_key: self.x25519_public_key,
            mlkem768_public_key: ledger.vector(self.mlkem768_public_key.bytes),
            signature: ledger.signature(self.signature),
        }
    }
}
impl FinishRow for Dealer {
    fn finish(self, ledger: &mut Ledger) -> Self::Wire {
        GlobalThresholdBeaconDkgDealerCommitmentV1 {
            dealer_index: self.dealer_index,
            coefficient_commitments: ledger.vector(self.coefficient_commitments.values),
            constant_term_proof: self.constant_term_proof,
            signature: ledger.signature(self.signature),
        }
    }
}
impl FinishRow for Edge {
    fn finish(self, ledger: &mut Ledger) -> Self::Wire {
        GlobalThresholdBeaconDkgEncryptedShareV1 {
            dealer_index: self.dealer_index,
            recipient_index: self.recipient_index,
            dealer_commitment_hash: self.dealer_commitment_hash,
            recipient_key_hash: self.recipient_key_hash,
            delivery_height: self.delivery_height,
            ephemeral_x25519_public_key: self.ephemeral_x25519_public_key,
            mlkem768_ciphertext: ledger.vector(self.mlkem768_ciphertext.bytes),
            encrypted_share: ledger.vector(self.encrypted_share.bytes),
            signature: ledger.signature(self.signature),
        }
    }
}
impl FinishRow for Acceptance {
    fn finish(self, ledger: &mut Ledger) -> Self::Wire {
        GlobalThresholdBeaconDkgShareAcceptanceV1 {
            dealer_index: self.dealer_index,
            recipient_index: self.recipient_index,
            dealer_commitment_hash: self.dealer_commitment_hash,
            encrypted_share_hash: self.encrypted_share_hash,
            accepted_height: self.accepted_height,
            signature: ledger.signature(self.signature),
        }
    }
}
impl<D: FinishRow> Rows<D> {
    /// Called only after the enclosing complete frame and every row are ready.
    pub(super) fn finish(mut self, ledger: &mut Ledger) -> Vec<D::Wire> {
        assert!(
            self.ready(),
            "row transfer precedes complete canonical input"
        );
        assert!(
            self.canonical.as_slice().is_empty(),
            "row backing was already consumed"
        );
        for row in self.destinations.drain_all() {
            self.canonical.push_reserved(row.finish(ledger));
        }
        ledger.vector(self.canonical)
    }
}
