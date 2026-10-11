//! Exact Archive custody conversion; incoming verdicts remain circuit obligations.
//!
//! The historical payer credential is retained independently of its current renewal.
//! Core removal paths come from the released capsule; the fold supplies its actual
//! adjusted-map path and total-verifier proposals. No conversion admits a proof.
//! TODO: exercise this boundary through the complete installed Archive/Ω catalog.

use iroha_kagemusha_proof::{
    a_relation::native::archive as native,
    admin_sigma::ArchiveWitness,
    q_sigma::native::IncomingMode,
    tree::{IndexedLeaf, IndexedRemove},
};

use super::*;

#[path = "archive/evidence.rs"]
mod evidence;
#[path = "archive/prepare.rs"]
mod prepare;
#[path = "archive/retained.rs"]
mod retained;
pub(crate) use prepare::ArchiveStepV1;

/// Decoder, opening and correction proposals for the exact retained evidence form.
/// Every proposal is constrained by the mandatory Archive source owners.
pub enum ArchiveIncomingWitnessV1 {
    /// Total incoming Receive sigma mode, also bound by Q0.
    Receive(Box<IncomingMode>),
    /// Total Status decoder, proof opening and both accumulator modes/corrections.
    Status(Box<native::StatusWitness>),
}

/// Actual adjusted-state path and untrusted result proposals for background folding.
pub struct ArchiveFoldWitnessV1 {
    /// Ordered relink/clear path against the predecessor's adjusted pending root.
    pub adjusted_pending: KagemushaWalletIndexedRemoveV1,
    /// Exact evidence variant's total decoder/proof proposals.
    pub incoming: ArchiveIncomingWitnessV1,
    /// Proofs, Evidence and Signatures proposals; these never confer validity.
    pub results: [bool; 3],
}

fn decode<T>(original: &[u8]) -> Result<T, Error>
where
    T: norito::NoritoSerialize,
    for<'de> T: norito::NoritoDeserialize<'de>,
{
    if original.is_empty() || original.len() > KAGEMUSHA_WALLET_MESSAGE_MAX_BYTES_V1 {
        return Err(Error::Authority);
    }
    norito::decode_canonical_with_limits(original, norito::canonical_decode_limits(original.len()))
        .map_err(|_| Error::Authority)
}

fn removal_original(openings: &[Vec<u8>]) -> Result<KagemushaWalletIndexedRemoveV1, Error> {
    let [predecessor, leaf] = openings else {
        return Err(Error::Authority);
    };
    let (Some(predecessor), predecessor_opening) = authority(
        KagemushaWalletIndexedOpeningV1::from_transcript(predecessor),
    )?
    else {
        return Err(Error::Authority);
    };
    let (Some(leaf), leaf_opening) =
        authority(KagemushaWalletIndexedOpeningV1::from_transcript(leaf))?
    else {
        return Err(Error::Authority);
    };
    Ok(KagemushaWalletIndexedRemoveV1 {
        predecessor,
        predecessor_opening,
        leaf,
        leaf_opening,
    })
}

fn removal(
    original: &KagemushaWalletIndexedRemoveV1,
    root: &[u8; 32],
    pending: &KagemushaWalletPendingOutgoingLeafV1,
) -> Result<(IndexedRemove<Fp>, [u8; 32]), Error> {
    if original.leaf.value != authority(pending.leaf_value())? {
        return Err(Error::Authority);
    }
    let after = authority(original.verify(root, &pending.credit_id))?;
    let leaf = |v: &KagemushaWalletIndexedLeafV1| -> Result<IndexedLeaf<Fp>, Error> {
        let [key, value, next_key] = fields(vec![v.key, v.value, v.next_key])?;
        Ok(IndexedLeaf {
            key,
            value,
            next_key,
        })
    };
    Ok((
        IndexedRemove {
            predecessor: leaf(&original.predecessor)?,
            predecessor_slot: original.predecessor_opening.slot,
            predecessor_siblings: fields(original.predecessor_opening.siblings.to_vec())?,
            leaf: leaf(&original.leaf)?,
            slot: original.leaf_opening.slot,
            leaf_siblings: fields(original.leaf_opening.siblings.to_vec())?,
        },
        after,
    ))
}

/// Verified original field projection; Q proofs remain mandatory independent inputs.
pub(crate) struct ArchiveFoldFieldsV1 {
    pub(crate) state: ArchiveWitness,
    pub(crate) removals: [IndexedRemove<Fp>; 2],
    pub(crate) own: [Vec<u8>; 3],
    pub(crate) sigma: Vec<u8>,
    pub(crate) retained: native::RetainedPayment,
    pub(crate) evidence: native::Evidence,
    pub(crate) results: [bool; 3],
    pub(crate) predecessor: native::PredecessorInput,
}
impl ArchiveFoldFieldsV1 {
    pub(crate) fn with_q(self, q: [native::QInput; 3]) -> native::Inputs {
        native::Inputs {
            state: self.state,
            removals: self.removals,
            own: self.own,
            sigma: self.sigma,
            retained: self.retained,
            evidence: self.evidence,
            results: self.results,
            predecessor: self.predecessor,
            q,
        }
    }
}

impl PreparationV1<'_> {
    /// Convert exact retained Payment/Credited originals into either native Archive form.
    /// The current owner signs this Archive; its historical payer credential is read
    /// from durable custody and may have an earlier renewal digest. Incoming proof,
    /// signature and membership verdicts remain soft circuit obligations, including
    /// every corrected-claim no-op. All ten A/nine W owners remain mandatory.
    ///
    /// # Errors
    /// Changed source/receipt/credential, missing or duplicate originals, noncanonical
    /// frames, wrong evidence proposal variant, or an invalid core/adjusted removal.
    #[allow(clippy::too_many_arguments)]
    pub fn archive_native_inputs(
        &self,
        owner: &AuthenticatedCredentialV1,
        step: &ReleasedStep,
        predecessor: &FoldedStateV1,
        public: &KagemushaWalletLineagePublicV1,
        witness: ArchiveFoldWitnessV1,
        q: [native::QInput; 3],
        budget: MemoryBudget,
    ) -> Result<native::Inputs, Error> {
        self.archive_fold_fields(owner, step, predecessor, public, witness, budget)
            .map(|fields| fields.with_q(q))
    }

    /// Reconstruct the exact native source before its independent Q proofs exist.
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn archive_fold_fields(
        &self,
        owner: &AuthenticatedCredentialV1,
        step: &ReleasedStep,
        predecessor: &FoldedStateV1,
        public: &KagemushaWalletLineagePublicV1,
        witness: ArchiveFoldWitnessV1,
        budget: MemoryBudget,
    ) -> Result<ArchiveFoldFieldsV1, Error> {
        let capsule = &step.frozen.capsule;
        let KagemushaWalletEffectV1::ArchiveSent {
            credit_id,
            credited,
        } = capsule.statement.effect
        else {
            return Err(Error::Authority);
        };
        if capsule.kind != KagemushaWalletOperationKindV1::ArchiveSent {
            return Err(Error::Authority);
        }
        let (successor, statement, receipt) =
            self.transition_fields(owner, step, predecessor, public, budget)?;
        let retained = retained::originals(
            self.installed.verifier().scheme(),
            &owner.credential,
            &capsule.retained_inputs,
        )?;
        if retained.pending.credit_id != credit_id {
            return Err(Error::Authority);
        }
        let (core, core_after) = removal(
            &removal_original(&capsule.map_openings)?,
            &predecessor.source_state.core.pending_outgoing_root,
            &retained.pending,
        )?;
        if core_after != capsule.successor_state.core.pending_outgoing_root {
            return Err(Error::Authority);
        }
        let (adjusted, _) = removal(
            &witness.adjusted_pending,
            &predecessor.lineage.public.pending_outgoing_root,
            &retained.pending,
        )?;
        let evidence = evidence::original(
            retained_original(
                &capsule.retained_inputs,
                KagemushaWalletRetainedInputRoleV1::Credited,
            )?,
            &retained.request,
            &retained.payment_digest,
            &credited,
            witness.incoming,
        )?;
        Ok(ArchiveFoldFieldsV1 {
            state: ArchiveWitness {
                predecessor: predecessor.witness,
                successor,
                statement,
            },
            removals: [core, adjusted],
            own: [
                owner.credential_tape.clone(),
                owner.certificate_tape.clone(),
                receipt,
            ],
            sigma: capsule.step_proof.bytes.clone(),
            retained: retained.native,
            evidence,
            results: witness.results,
            predecessor: native::PredecessorInput {
                proof: predecessor.proof.clone(),
                pallas: predecessor.pallas,
                vesta: predecessor.vesta,
            },
        })
    }
}

#[cfg(test)]
#[path = "archive/tests.rs"]
mod tests;
