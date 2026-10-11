//! Local Load/Archive sigma preparation from the released head, without a fold.
//!
//! The lineage-shaped private witness in these non-consuming sigma relations
//! carries committed core values. It is never an Omega, a FoldedState or source
//! of monetary authority. Background A owners independently open the actual
//! predecessor Omega and derive all adjusted values, including Archive no-op.

use iroha_kagemusha_proof::admin_sigma::ArchiveWitness;

use super::*;

pub(super) fn local_state(
    credential: &KagemushaWalletCredentialV1,
    state: &KagemushaWalletStateV1,
    relation_id: [u8; 32],
    omega_key_digest: [u8; 32],
) -> Result<StateWitness, Error> {
    authority(state.validate_for_credential(credential))?;
    let c = &state.core;
    // Reuse the canonical field encoder, not a second packing convention. This
    // temporary public-shaped value is private sigma input; no proof or claims
    // are attached, and it is never returned as lineage evidence.
    let projection = KagemushaWalletLineagePublicV1 {
        version: KAGEMUSHA_WALLET_VERSION_V1,
        scheme_id: c.scheme_id,
        relation_id,
        head: authority(state.commitment())?,
        wallet_id: c.wallet_id,
        credential_digest: c.credential_digest,
        payment_key: credential.body.payment_key,
        lifecycle: c.lifecycle,
        policy_epoch: c.policy_epoch,
        enabled_controls: c.enabled_controls,
        burned_total: c.burned_total,
        pending_outgoing_root: c.pending_outgoing_root,
        credit_digest_root: KagemushaWalletIndexedTreeV1::new().root(),
    };
    Ok(StateWitness {
        core: fields(authority(state.core_field_items())?)?,
        rest: fields(authority(state.rest_field_items())?)?,
        lineage: lineage_public_fields(&projection, omega_key_digest)?,
    })
}

impl PreparationV1<'_> {
    fn unfolded_transition(
        &self,
        owner: &AuthenticatedCredentialV1,
        source: &ReleasedStep,
        state: &KagemushaWalletStateV1,
        statement: &KagemushaWalletStatementV1,
        budget: MemoryBudget,
    ) -> Result<(StateWitness, StateWitness, [Fp; 26]), Error> {
        if !matches!(
            statement.effect.kind(),
            KagemushaWalletOperationKindV1::Load | KagemushaWalletOperationKindV1::ArchiveSent
        ) {
            return Err(Error::Authority);
        }
        // The existing source check verifies exact durable completion, its
        // receipt and sigma. It requires an Omega only when the *source's own*
        // operation consumed one, never a fold of this current source head.
        self.receipt_tape(owner, source, budget)?;
        let capsule = &source.frozen.capsule;
        authority(statement.validate_successor_of(&capsule.statement))?;
        let statement_fields = self.statement_fields(owner, statement)?;
        let relation = self.installed.verifier().scheme().relation_id;
        let before = local_state(
            &owner.credential,
            &capsule.successor_state,
            relation,
            self.omega_key_digest,
        )?;
        let after = local_state(&owner.credential, state, relation, self.omega_key_digest)?;
        if statement.successor != authority(state.commitment())?
            || statement.lifecycle != state.core.lifecycle
            || statement.sequence != state.core.sequence
            || statement.next_load != state.core.next_load
            || statement.enabled_controls != capsule.successor_state.core.enabled_controls
        {
            return Err(Error::Authority);
        }
        Ok((before, after, statement_fields))
    }

    /// Prepare Load's exact local sigma witness before Advance from a released
    /// head, including an unfolded head. The private core projection carries no
    /// adjusted-value authority; finalized receipt and recovery-map owners are
    /// still mandatory when folding this step.
    ///
    /// # Errors
    /// Wrong operation, source proof/receipt/credential, discontinuous statement,
    /// or noncanonical successor binding.
    pub fn load_sigma_fields(
        &self,
        owner: &AuthenticatedCredentialV1,
        source: &ReleasedStep,
        state: &KagemushaWalletStateV1,
        statement: &KagemushaWalletStatementV1,
        budget: MemoryBudget,
    ) -> Result<LoadWitness, Error> {
        if statement.effect.kind() != KagemushaWalletOperationKindV1::Load {
            return Err(Error::Authority);
        }
        let (predecessor, successor, statement) =
            self.unfolded_transition(owner, source, state, statement, budget)?;
        Ok(LoadWitness {
            predecessor,
            successor,
            statement,
        })
    }

    /// Prepare Archive's local sigma witness before Advance from a released
    /// head. Both Credited variants use the same fixed sigma class. Native
    /// Advance authenticates the core removal; A owns evidence verification and
    /// the separate adjusted removal or no-op. No Payment deletion is authorized.
    ///
    /// # Errors
    /// Wrong operation, source proof/receipt/credential, discontinuous statement,
    /// or noncanonical successor binding.
    pub fn archive_sigma_fields(
        &self,
        owner: &AuthenticatedCredentialV1,
        source: &ReleasedStep,
        state: &KagemushaWalletStateV1,
        statement: &KagemushaWalletStatementV1,
        budget: MemoryBudget,
    ) -> Result<ArchiveWitness, Error> {
        if statement.effect.kind() != KagemushaWalletOperationKindV1::ArchiveSent {
            return Err(Error::Authority);
        }
        let (predecessor, successor, statement) =
            self.unfolded_transition(owner, source, state, statement, budget)?;
        Ok(ArchiveWitness {
            predecessor,
            successor,
            statement,
        })
    }
}

#[cfg(test)]
#[path = "unfolded/tests.rs"]
mod tests;
