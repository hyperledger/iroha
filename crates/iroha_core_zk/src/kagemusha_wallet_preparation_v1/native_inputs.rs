//! Retained Bootstrap, Load and consuming originals for the installed native producers.
//!
//! These conversions do not authenticate a Q/A/W catalog or admit a wallet. Supplied
//! Q originals remain untrusted until the native plan verifies them; operation owners
//! then bind every signed tape and map to the same context before terminal admission.
//!
//! TODO: exercise these entry points through the installed wallet producer once its
//! complete authenticated catalog is available. The local path-conversion tests and
//! native producer proof tests establish separate component boundaries only.

use iroha_kagemusha_proof::{
    a_relation::native::{bootstrap, consuming, load},
    tree::IndexedInsert,
};

use super::*;

pub(super) fn no_map_openings(openings: &[Vec<u8>]) -> Result<(), Error> {
    if openings.is_empty() {
        Ok(())
    } else {
        Err(Error::Authority)
    }
}

pub(super) fn retained_insertion(
    openings: &[Vec<u8>],
) -> Result<KagemushaWalletIndexedInsertV1, Error> {
    let [low_original, empty_original] = openings else {
        return Err(Error::Authority);
    };
    let (Some(low), low_opening) = authority(KagemushaWalletIndexedOpeningV1::from_transcript(
        low_original,
    ))?
    else {
        return Err(Error::Authority);
    };
    let (None, slot_opening) = authority(KagemushaWalletIndexedOpeningV1::from_transcript(
        empty_original,
    ))?
    else {
        return Err(Error::Authority);
    };
    Ok(KagemushaWalletIndexedInsertV1 {
        low,
        low_opening,
        slot_opening,
    })
}

/// Decode only the retained paths for the statement's exact recovery-map effect.
/// Unload retains the low-leaf opening followed by the intermediate empty-slot
/// opening; Retiring has no recovery path and preserves the root.
fn consuming_recovery(
    effect: &KagemushaWalletEffectV1,
    openings: &[Vec<u8>],
    predecessor_root: &[u8; 32],
    successor_root: &[u8; 32],
) -> Result<Option<IndexedInsert<Fp>>, Error> {
    match effect {
        KagemushaWalletEffectV1::Unload {
            nullifier,
            redeem_ordinal,
            amount,
            online_charge,
            ..
        } => {
            let witness = retained_insertion(openings)?;
            let leaf = KagemushaWalletRedeemLeafV1 {
                ordinal: *redeem_ordinal,
                nullifier: *nullifier,
                amount: *amount,
                online_charge: *online_charge,
            };
            if authority(witness.verify(
                predecessor_root,
                &leaf.key(),
                &authority(leaf.leaf_value())?,
            ))? != *successor_root
            {
                return Err(Error::Authority);
            }
            super::monetary::insertion(&witness).map(Some)
        }
        KagemushaWalletEffectV1::Retiring => {
            no_map_openings(openings)?;
            if predecessor_root != successor_root {
                return Err(Error::Authority);
            }
            Ok(None)
        }
        _ => Err(Error::Authority),
    }
}

fn load_recovery(
    effect: &KagemushaWalletEffectV1,
    openings: &[Vec<u8>],
    predecessor_root: &[u8; 32],
    successor_root: &[u8; 32],
) -> Result<IndexedInsert<Fp>, Error> {
    let KagemushaWalletEffectV1::Load {
        receipt_digest,
        load_ordinal,
        amount,
        ..
    } = effect
    else {
        return Err(Error::Authority);
    };
    let leaf = KagemushaWalletLoadLeafV1 {
        ordinal: *load_ordinal,
        receipt_digest: *receipt_digest,
        amount: *amount,
    };
    let insertion = retained_insertion(openings)?;
    if authority(insertion.verify(
        predecessor_root,
        &leaf.key(),
        &authority(leaf.leaf_value())?,
    ))? != *successor_root
    {
        return Err(Error::Authority);
    }
    super::monetary::insertion(&insertion)
}

/// Verified original field projection; the signature Q proof remains a mandatory
/// independent input. A proves the Bootstrap transition directly (lean lineage),
/// so no sigma original is a native input.
pub struct BootstrapFoldFieldsV1 {
    pub(crate) state: BootstrapWitness,
    pub(crate) objects: [Vec<u8>; 3],
}
impl BootstrapFoldFieldsV1 {
    pub(crate) fn with_q(self, q: [bootstrap::QInput; 1]) -> bootstrap::Inputs {
        bootstrap::Inputs {
            state: self.state,
            objects: self.objects,
            q,
        }
    }
}

/// Verified original field projection; Q proofs remain mandatory independent inputs.
pub struct LoadFoldFieldsV1 {
    pub(crate) state: LoadWitness,
    pub(crate) receipt: [u8; 282],
    pub(crate) objects: [Vec<u8>; 1],
    /// Native source of the payment key for the own-receipt leaf; not a circuit object.
    pub(crate) credential: Vec<u8>,
    pub(crate) insertion: IndexedInsert<Fp>,
    pub(crate) predecessor: load::PredecessorInput,
}
impl LoadFoldFieldsV1 {
    pub(crate) fn with_q(self, q: [load::QInput; 1]) -> load::Inputs {
        load::Inputs {
            state: self.state,
            receipt: self.receipt,
            objects: self.objects,
            insertion: self.insertion,
            predecessor: self.predecessor,
            q,
        }
    }
}

/// Verified original field projection; Q proofs remain mandatory independent inputs.
pub struct ConsumingFoldFieldsV1 {
    pub(crate) state: ConsumingWitness,
    pub(crate) objects: [Vec<u8>; 1],
    /// Native source of the payment key for the own-receipt leaf; not a circuit object.
    pub(crate) credential: Vec<u8>,
    pub(crate) recovery: Option<IndexedInsert<Fp>>,
    pub(crate) predecessor: consuming::PredecessorInput,
}
impl ConsumingFoldFieldsV1 {
    pub(crate) fn with_q(self, q: [consuming::QInput; 1]) -> consuming::Inputs {
        consuming::Inputs {
            state: self.state,
            objects: self.objects,
            recovery: self.recovery,
            predecessor: self.predecessor,
            q,
        }
    }
}

impl PreparationV1<'_> {
    /// Reconstruct Load's native source before its independent Q proof exists.
    /// Retained ordinary receipt/finality and the capsule's authenticated insertion
    /// bind the source; both predecessor claims remain unchanged. The installed
    /// native plan must still verify the receipt-bound Advance and every A owner.
    /// This method grants no funding or catalog authority by itself.
    ///
    /// # Errors
    /// Changed receipt, anchor, source state, finality originals or recovery root;
    /// missing/reordered paths, occupied insertion slot, or another operation. Local
    /// decoder refusals retain their original cause and permit an unchanged retry.
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn load_fold_fields(
        &self,
        owner: &AuthenticatedCredentialV1,
        step: &ReleasedStep,
        predecessor: &FoldedStateV1,
        public: &KagemushaWalletLineagePublicV1,
        budget: MemoryBudget,
    ) -> Result<LoadFoldFieldsV1, wallet_state::Error> {
        let capsule = &step.frozen.capsule;
        let fields = self.load_fields(owner, step, predecessor, public, budget)?;
        let insertion = super::dispatch::proof(load_recovery(
            &capsule.body().statement.effect,
            &capsule.body().map_openings,
            &predecessor.source_state.core.load_redeem_recovery_root,
            &capsule
                .body()
                .successor_state
                .core
                .load_redeem_recovery_root,
        ))?;
        Ok(LoadFoldFieldsV1 {
            state: fields.state,
            receipt: fields.receipt,
            objects: fields.objects,
            credential: fields.credential,
            insertion,
            predecessor: load::PredecessorInput {
                proof: predecessor.proof.clone(),
                pallas: predecessor.pallas,
                vesta: predecessor.vesta,
            },
        })
    }

    /// Reconstruct Bootstrap's authenticated released source before its Q proof exists,
    /// without selecting any proving artifact. The installed native
    /// `bootstrap::Plan::prepare` and unsplit terminal A must still verify the
    /// subsequently attached Q proof and bind all three original signed tapes.
    ///
    /// # Errors
    /// Rejects another operation, extraneous map witnesses, invalid retained
    /// evidence, or a changed credential, state or installation.
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn bootstrap_fold_fields(
        &self,
        owner: &AuthenticatedCredentialV1,
        step: &ReleasedStep,
        public: &KagemushaWalletLineagePublicV1,
        budget: MemoryBudget,
    ) -> Result<BootstrapFoldFieldsV1, Error> {
        no_map_openings(&step.frozen.capsule.body().map_openings)?;
        let fields = self.bootstrap_fields(owner, step, public, budget)?;
        Ok(BootstrapFoldFieldsV1 {
            state: fields.state,
            objects: fields.objects,
        })
    }

    /// Reconstruct Unload or Retiring's source before its independent Q proof exists,
    /// from the exact released source and fully verified predecessor. The recovery
    /// path is decoded from the capsule, never supplied separately. The installed
    /// native `consuming::Plan::prepare` and complete A/W chain remain mandatory
    /// before accepting any result; this method grants no open authority.
    ///
    /// # Errors
    /// Rejects another operation, changed source/lineage/credential, wrong path
    /// count or order, a nonempty insertion slot, or either changed recovery root.
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn consuming_fold_fields(
        &self,
        owner: &AuthenticatedCredentialV1,
        step: &ReleasedStep,
        predecessor: &FoldedStateV1,
        public: &KagemushaWalletLineagePublicV1,
        budget: MemoryBudget,
    ) -> Result<ConsumingFoldFieldsV1, Error> {
        let capsule = &step.frozen.capsule;
        let fields = self.consuming_fields(
            capsule.body().kind,
            owner,
            step,
            predecessor,
            public,
            budget,
        )?;
        let recovery = consuming_recovery(
            &capsule.body().statement.effect,
            &capsule.body().map_openings,
            &predecessor.source_state.core.load_redeem_recovery_root,
            &capsule
                .body()
                .successor_state
                .core
                .load_redeem_recovery_root,
        )?;
        Ok(ConsumingFoldFieldsV1 {
            state: fields.state,
            objects: fields.objects,
            credential: fields.credential,
            recovery,
            predecessor: consuming::PredecessorInput {
                proof: predecessor.proof.clone(),
                pallas: predecessor.pallas,
                vesta: predecessor.vesta,
            },
        })
    }
}

#[cfg(test)]
#[path = "native_inputs/tests.rs"]
mod tests;
