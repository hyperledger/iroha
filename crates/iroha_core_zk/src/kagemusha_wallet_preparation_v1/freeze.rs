//! Native capsule construction from opaque prepared steps and exact installed proofs.
//!
//! These adapters derive the output and operation identity, preserve the original fold
//! witnesses, and run the installed complete verifier before returning a frozen transition.
//! They do not sign, publish, Advance, or confer an installed producer capability.

use crate::kagemusha_wallet_state_v1::FrozenTransition;
use iroha_kagemusha_proof::tree::IndexedInsert;

use super::*;

type Retained = KagemushaWalletRetainedInputV1;

struct CapsuleFields<'a> {
    manifest: [u8; 32],
    source: [u8; 32],
    state: &'a KagemushaWalletStateV1,
    statement: &'a KagemushaWalletStatementV1,
    predecessor: Option<&'a FoldedStateV1>,
    payment: [u8; 32],
    openings: Vec<Vec<u8>>,
    retained: Vec<Retained>,
}

fn map_openings(maps: &[IndexedInsert<Fp>]) -> Vec<Vec<u8>> {
    maps.iter()
        .flat_map(|map| {
            let leaf = KagemushaWalletIndexedLeafV1 {
                key: map.leaf.key.to_repr(),
                value: map.leaf.value.to_repr(),
                next_key: map.leaf.next_key.to_repr(),
            };
            let low = KagemushaWalletIndexedOpeningV1 {
                slot: map.leaf_slot,
                siblings: map.leaf_siblings.map(|v| v.to_repr()),
            };
            let empty = KagemushaWalletIndexedOpeningV1 {
                slot: map.slot,
                siblings: map.slot_siblings.map(|v| v.to_repr()),
            };
            [low.leaf_transcript(&leaf), empty.empty_transcript()]
        })
        .collect()
}

// Pure assembly is private and is never an acceptance path. Every public adapter
// must pass the installed verifier before this capsule leaves PreparationV1.
fn assemble(
    credential: KagemushaWalletCredentialV1,
    input: CapsuleFields<'_>,
    proof: KagemushaWalletStepProofV1,
) -> Result<FrozenTransition, Error> {
    let kind = input.statement.effect.kind();
    if kind.consumes_lineage() != input.predecessor.is_some() {
        return Err(Error::Authority);
    }
    if let Some(predecessor) = input.predecessor {
        if predecessor.manifest_digest != input.manifest
            || predecessor.source_capsule_digest != input.source
            || predecessor.source_statement.successor != input.statement.predecessor
            || predecessor.credential != credential
        {
            return Err(Error::Authority);
        }
    }
    let lineage = input
        .predecessor
        .map_or(KagemushaWalletLineageSlotV1::None, |p| {
            KagemushaWalletLineageSlotV1::Present {
                lineage: p.lineage.clone(),
            }
        });
    let proof_digest = authority(kagemusha_wallet_proof_digest_v1(
        kind,
        lineage.lineage(),
        &proof,
    ))?;
    let output = authority(KagemushaWalletOutputDescriptorV1::for_transition(
        input.statement,
        &proof_digest,
        &input.payment,
    ))?;
    let wallet_id = credential.body.wallet_id;
    let frozen = FrozenTransition {
        credential,
        capsule: KagemushaWalletRecoveryCapsuleV1 {
            version: KAGEMUSHA_WALLET_VERSION_V1,
            scheme_id: input.statement.scheme_id,
            wallet_id,
            operation_id: authority(input.statement.operation_id(&wallet_id))?,
            kind,
            predecessor_capsule_digest: input.source,
            successor_state: *input.state,
            statement: *input.statement,
            predecessor_lineage: lineage,
            step_proof: proof,
            payment_digest: input.payment,
            map_openings: input.openings,
            retained_inputs: input.retained,
            output,
        },
    };
    frozen.validate().map_err(|_| Error::Authority)?;
    Ok(frozen)
}

impl PreparationV1<'_> {
    fn freeze(
        &self,
        owner: &AuthenticatedCredentialV1,
        input: CapsuleFields<'_>,
        proof: KagemushaWalletStepProofV1,
        budget: MemoryBudget,
    ) -> Result<FrozenTransition, Error> {
        self.credential_owner(owner)?;
        if input.manifest != self.installed.verifier().manifest_digest() {
            return Err(Error::Authority);
        }
        self.statement_fields(owner, input.statement)?;
        let frozen = assemble(owner.credential, input, proof)?;
        self.installed
            .verifier()
            .verify_capsule_proofs_cancellable(
                &frozen.capsule,
                &frozen.credential,
                budget,
                self.cancellation,
            )?;
        Ok(frozen)
    }

    pub(crate) fn freeze_bootstrap(
        &self,
        owner: &AuthenticatedCredentialV1,
        step: &BootstrapStepV1,
        proof: KagemushaWalletStepProofV1,
        budget: MemoryBudget,
    ) -> Result<FrozenTransition, Error> {
        self.freeze(
            owner,
            CapsuleFields {
                manifest: step.manifest,
                source: [0; 32],
                state: &step.state,
                statement: &step.statement,
                predecessor: None,
                payment: [0; 32],
                openings: Vec::new(),
                retained: Vec::new(),
            },
            proof,
            budget,
        )
    }

    /// Freeze a prepared Send or Receive with its actual installed sigma proof.
    /// Supply the exact opaque predecessor fold for Send and no fold for Receive.
    /// The recorded Request selects Receive's blacklist verifier, including after renewal.
    ///
    /// # Errors
    /// Foreign installation/owner/fold, invalid proof, altered source, or invalid capsule.
    pub(crate) fn freeze_monetary(
        &self,
        owner: &AuthenticatedCredentialV1,
        step: &MonetaryStepV1,
        predecessor: Option<&FoldedStateV1>,
        proof: KagemushaWalletStepProofV1,
        budget: MemoryBudget,
    ) -> Result<FrozenTransition, Error> {
        let payment = step.retained_payment_digest()?;
        self.freeze(
            owner,
            CapsuleFields {
                manifest: step.manifest_digest(),
                source: step.source_capsule_digest(),
                state: step.state(),
                statement: step.statement(),
                predecessor,
                payment,
                openings: map_openings(step.map_witnesses()),
                retained: step.capsule_inputs()?,
            },
            proof,
            budget,
        )
    }

    /// Freeze exact finalized Load originals and insertion openings with installed sigma.
    /// This local capsule contains no Omega and grants no permission to spend before folding.
    ///
    /// # Errors
    /// Foreign installation/owner, invalid proof, inconsistent prepared state or capsule.
    pub fn freeze_load(
        &self,
        owner: &AuthenticatedCredentialV1,
        step: &LoadStepV1,
        proof: KagemushaWalletStepProofV1,
        budget: MemoryBudget,
    ) -> Result<FrozenTransition, Error> {
        let (retained, openings) = step.originals();
        self.freeze(
            owner,
            CapsuleFields {
                manifest: step.manifest_digest(),
                source: step.source_capsule_digest(),
                state: step.state(),
                statement: step.statement(),
                predecessor: None,
                payment: [0; 32],
                openings: openings.to_vec(),
                retained: retained.to_vec(),
            },
            proof,
            budget,
        )
    }

    pub(crate) fn freeze_archive(
        &self,
        owner: &AuthenticatedCredentialV1,
        step: &ArchiveStepV1,
        proof: KagemushaWalletStepProofV1,
        budget: MemoryBudget,
    ) -> Result<FrozenTransition, Error> {
        let (retained, openings) = step.originals();
        self.freeze(
            owner,
            CapsuleFields {
                manifest: step.manifest_digest(),
                source: step.source_capsule_digest(),
                state: step.state(),
                statement: step.statement(),
                predecessor: None,
                payment: [0; 32],
                openings: openings.to_vec(),
                retained: retained.to_vec(),
            },
            proof,
            budget,
        )
    }

    /// Freeze a signed Refresh, retaining its exact update, certificates and quota/map witness.
    /// Credential renewal uses the authenticated successor credential passed as owner.
    ///
    /// # Errors
    /// Foreign installation/owner, invalid proof, wrong renewal owner or invalid capsule.
    pub fn freeze_refresh(
        &self,
        owner: &AuthenticatedCredentialV1,
        step: &RefreshStepV1,
        proof: KagemushaWalletStepProofV1,
        budget: MemoryBudget,
    ) -> Result<FrozenTransition, Error> {
        let (retained, openings) = step.originals();
        self.freeze(
            owner,
            CapsuleFields {
                manifest: step.manifest_digest(),
                source: step.source_capsule_digest(),
                state: step.state(),
                statement: step.statement(),
                predecessor: None,
                payment: [0; 32],
                openings: openings.to_vec(),
                retained: retained.to_vec(),
            },
            proof,
            budget,
        )
    }

    /// Freeze Unload or Retiring with the exact verified fold and actual installed sigma.
    /// Optional Unload charge originals remain in the durable preparation/payout custody;
    /// Lambda does not authenticate them and they are not added as capsule inputs.
    ///
    /// # Errors
    /// Foreign installation/owner/fold, invalid proof, changed source or invalid capsule.
    pub fn freeze_consuming(
        &self,
        owner: &AuthenticatedCredentialV1,
        step: &ConsumingStepV1,
        predecessor: &FoldedStateV1,
        proof: KagemushaWalletStepProofV1,
        budget: MemoryBudget,
    ) -> Result<FrozenTransition, Error> {
        self.freeze(
            owner,
            CapsuleFields {
                manifest: step.manifest_digest(),
                source: step.source_capsule_digest(),
                state: step.state(),
                statement: step.statement(),
                predecessor: Some(predecessor),
                payment: [0; 32],
                openings: step.map_openings().to_vec(),
                retained: vec![],
            },
            proof,
            budget,
        )
    }
}

#[cfg(test)]
mod tests;
