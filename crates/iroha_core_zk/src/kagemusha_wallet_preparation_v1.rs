//! Canonical G1 conversion for the genuine installed native proof producers.
//!
//! The installed signed verifier inventory selects the scheme and Omega key. Exact
//! credential/certificate originals are issuer-authenticated before conversion, retained
//! completions are checked against their source capsule, and predecessor Omega transport
//! is fully verified, including both native accumulator decisions. The resulting objects
//! are witnesses for the existing sigma/Q/A/W relations; conversion does not authorize
//! Advance, confer source-marker authority, implement NativeProofs or enable wallet open.
//! A complete authenticated producer catalog and the custody/operation intake owner remain
//! mandatory. These helpers never generate artifact keys or select a profile from a witness.

use ff::PrimeField;
use iroha_data_model::{
    isi::kagemusha_wallet::KagemushaWalletLoadReceiptV1, kagemusha::kagemusha_wallet_v1::*,
};
use iroha_kagemusha_proof::admin_sigma::{
    BootstrapWitness, ConsumingWitness, LoadWitness, StateWitness,
};
use iroha_pasta::{Fp, msm::MemoryBudget};
use iroha_plonk_recursion::ACCUMULATOR_BYTES;

use crate::{
    kagemusha_wallet_artifacts_v1::InstalledVerifierPackV1,
    kagemusha_wallet_proofs_v1::{Error, lineage_public_fields},
    kagemusha_wallet_state_v1::ReleasedStep,
};

#[path = "kagemusha_wallet_preparation_v1/incoming_statement.rs"]
mod incoming_statement;

#[path = "kagemusha_wallet_preparation_v1/monetary.rs"]
mod monetary;
pub use monetary::{MonetaryStepV1, ReceiveFoldMapsV1, ReceiveMapsV1, SendControlsV1, SendMapsV1};
pub(crate) use monetary::{ReceiveFoldFieldsV1, SendFoldFieldsV1};

#[path = "kagemusha_wallet_preparation_v1/native_inputs.rs"]
mod native_inputs;
pub(crate) use native_inputs::{BootstrapFoldFieldsV1, ConsumingFoldFieldsV1, LoadFoldFieldsV1};

#[path = "kagemusha_wallet_preparation_v1/refresh.rs"]
mod refresh;
pub(crate) use refresh::RefreshFoldFieldsV1;
pub use refresh::{RefreshOriginalsV1, RefreshOwnersV1, RefreshStepV1};

#[path = "kagemusha_wallet_preparation_v1/archive.rs"]
mod archive;
pub(crate) use archive::{ArchiveFoldFieldsV1, ArchiveStepV1};
pub use archive::{ArchiveFoldWitnessV1, ArchiveIncomingWitnessV1};

#[path = "kagemusha_wallet_preparation_v1/bootstrap.rs"]
mod bootstrap;
pub(crate) use bootstrap::BootstrapStepV1;

#[path = "kagemusha_wallet_preparation_v1/load.rs"]
mod load;
pub use load::{LoadOriginalsV1, LoadStepV1};

#[path = "kagemusha_wallet_preparation_v1/consuming.rs"]
mod consuming;
pub use consuming::{ConsumingActionV1, ConsumingStepV1, UnloadChargeOriginalsV1};

#[path = "kagemusha_wallet_preparation_v1/unfolded.rs"]
mod unfolded;

#[path = "kagemusha_wallet_preparation_v1/admin_proving.rs"]
mod admin_proving;

#[path = "kagemusha_wallet_preparation_v1/freeze.rs"]
mod freeze;

#[path = "kagemusha_wallet_preparation_v1/dispatch.rs"]
mod dispatch;
pub use dispatch::NativeAdvanceCheckV1;
pub(crate) use dispatch::PreparedOperationV1;

#[path = "kagemusha_wallet_preparation_v1/choices.rs"]
mod choices;
pub(crate) use choices::NativeChoicesV1;

#[cfg(test)]
#[path = "kagemusha_wallet_preparation_v1/tests.rs"]
mod tests;

fn authority<T>(value: Result<T, KagemushaWalletValidationErrorV1>) -> Result<T, Error> {
    value.map_err(|_| Error::Authority)
}

fn fields<const N: usize>(original: Vec<[u8; 32]>) -> Result<[Fp; N], Error> {
    if original.len() != N {
        return Err(Error::Authority);
    }
    original
        .into_iter()
        .map(|word| Option::<Fp>::from(Fp::from_repr(word)).ok_or(Error::Authority))
        .collect::<Result<Vec<_>, _>>()?
        .try_into()
        .map_err(|_| Error::Authority)
}

fn signed_tape(body: Vec<u8>, signature: &KagemushaDeviceSignatureV1) -> Vec<u8> {
    let mut tape = body;
    tape.extend_from_slice(signature.as_raw_bytes());
    tape
}

fn retained_original(
    inputs: &[KagemushaWalletRetainedInputV1],
    role: KagemushaWalletRetainedInputRoleV1,
) -> Result<&[u8], Error> {
    let mut selected = inputs.iter().filter(|input| input.role == role);
    let first = selected.next().ok_or(Error::Authority)?;
    if first.bytes.is_empty() || selected.next().is_some() {
        return Err(Error::Authority);
    }
    Ok(&first.bytes)
}

// Shape and exact-original conversion only. Native authenticates direct BLS
// finality before Advance; A authenticates the resulting receipt-bound signature.
fn retained_load_source(
    inputs: &[KagemushaWalletRetainedInputV1],
    digest: [u8; 32],
) -> Result<(KagemushaWalletLoadReceiptV1, KagemushaWalletLoadFinalityV1), Error> {
    let ordinary = authority(KagemushaWalletLoadReceiptV1::decode_canonical(
        retained_original(inputs, KagemushaWalletRetainedInputRoleV1::LoadReceipt)?,
    ))?;
    let original = authority(KagemushaWalletLoadFinalityV1::decode_canonical(
        retained_original(inputs, KagemushaWalletRetainedInputRoleV1::LoadFinality)?,
    ))?;
    if authority(ordinary.receipt_digest())? != digest || original.receipt_digest != digest {
        return Err(Error::Authority);
    }
    Ok((ordinary, original))
}

/// Immutable conversion context selected by the authenticated installation owner.
pub struct PreparationV1<'a> {
    installed: &'a InstalledVerifierPackV1,
    cancellation: Option<&'a iroha_pasta::CancellationToken>,
    omega_key_digest: [u8; 32],
    omega_proof_bytes: usize,
}

/// Issuer-authenticated exact current credential and Enrollment-role certificate originals.
/// Private construction prevents substituting another signed object after authentication.
pub struct AuthenticatedCredentialV1 {
    manifest_digest: [u8; 32],
    credential: KagemushaWalletCredentialV1,
    certificate: KagemushaWalletSignerCertificateV1,
    credential_original: Vec<u8>,
    certificate_original: Vec<u8>,
    credential_tape: Vec<u8>,
    certificate_tape: Vec<u8>,
}

impl AuthenticatedCredentialV1 {
    /// Exact credential, authenticated under the installed scheme.
    #[must_use]
    pub const fn credential(&self) -> &KagemushaWalletCredentialV1 {
        &self.credential
    }
    /// Original canonical G1 frames for custody retention and exact reinstallation.
    #[must_use]
    pub fn originals(&self) -> (&[u8], &[u8]) {
        (&self.credential_original, &self.certificate_original)
    }
    /// Signed-body transcript followed by the original canonical raw P-256 signature.
    #[must_use]
    pub fn tapes(&self) -> (&[u8], &[u8]) {
        (&self.credential_tape, &self.certificate_tape)
    }
}

/// Canonical original transport from a fully verified source-bound predecessor fold.
/// This is proof evidence, not independent Selected/Released custody-marker authority.
pub struct FoldedStateV1 {
    manifest_digest: [u8; 32],
    source_capsule_digest: [u8; 32],
    source_statement: KagemushaWalletStatementV1,
    source_state: KagemushaWalletStateV1,
    credential: KagemushaWalletCredentialV1,
    lineage: KagemushaWalletLineageV1,
    witness: StateWitness,
    proof: Vec<u8>,
    pallas: [u8; ACCUMULATOR_BYTES],
    vesta: [u8; ACCUMULATOR_BYTES],
}

impl FoldedStateV1 {
    /// Exact native state opening; all operation effects still belong to the real circuit.
    #[must_use]
    pub const fn witness(&self) -> &StateWitness {
        &self.witness
    }
    /// Unmodified unframed Omega proof and both canonical native accumulator originals.
    #[must_use]
    pub fn transport(&self) -> (&[u8], &[u8; ACCUMULATOR_BYTES], &[u8; ACCUMULATOR_BYTES]) {
        (&self.proof, &self.pallas, &self.vesta)
    }
    /// Exact admitted predecessor lineage object.
    #[must_use]
    pub const fn lineage(&self) -> &KagemushaWalletLineageV1 {
        &self.lineage
    }
    /// Exact source statement already bound to this fold's retained capsule/completion.
    #[must_use]
    pub const fn source_statement(&self) -> &KagemushaWalletStatementV1 {
        &self.source_statement
    }
    /// Exact source state opening already bound to this fold's head.
    #[must_use]
    pub const fn source_state(&self) -> &KagemushaWalletStateV1 {
        &self.source_state
    }
    /// Source capsule identity for the mandatory successor/source-marker check.
    #[must_use]
    pub const fn source_capsule_digest(&self) -> [u8; 32] {
        self.source_capsule_digest
    }
}

/// Typed post-Advance Bootstrap inputs for the existing sigma/Q/A/W producer chain.
/// Q proofs and all installed proving material remain separate mandatory inputs.
pub(crate) struct BootstrapFieldsV1 {
    /// Original state/public/statement fields in the compiled sigma's exact order.
    pub(crate) state: BootstrapWitness,
    /// Actual original sigma bytes from the selected capsule.
    pub(crate) sigma: Vec<u8>,
    /// Enrollment certificate, current credential, own retained receipt.
    pub(crate) objects: [Vec<u8>; 3],
}

/// Typed post-Advance Load fields; map insertion/Q ownership remain in the native relation.
pub(crate) struct LoadFieldsV1 {
    /// Exact compiled Load witness.
    pub(crate) state: LoadWitness,
    /// Actual original sigma bytes from the selected capsule.
    pub(crate) sigma: Vec<u8>,
    /// Exact canonical ordinary receipt transcript committed by ledger execution.
    pub(crate) receipt: [u8; 282],
    /// Own Advance receipt, Enrollment certificate and current credential.
    pub(crate) objects: [Vec<u8>; 3],
}

/// Typed post-Advance Unload/Retiring fields for their actual consuming sigma relation.
pub(crate) struct ConsumingFieldsV1 {
    /// Exact compiled consuming witness; its operation is fixed by the calling producer.
    pub(crate) state: ConsumingWitness,
    /// Actual original sigma bytes from the selected capsule.
    pub(crate) sigma: Vec<u8>,
    /// Current credential, Enrollment certificate, own retained receipt.
    pub(crate) objects: [Vec<u8>; 3],
}

impl<'a> PreparationV1<'a> {
    /// Derive identities and exact layout from immutable authenticated installation originals.
    /// No caller supplies an Omega key digest, scheme id or length.
    /// # Errors
    /// Rejects inconsistent originals; this constructor grants no producer/open capability.
    pub fn new(installed: &'a InstalledVerifierPackV1) -> Result<Self, Error> {
        let scheme = installed.verifier().scheme();
        let manifest = authority(KagemushaWalletArtifactManifestV1::decode_canonical(
            &installed.originals().manifest,
            scheme,
        ))?;
        if manifest.manifest_digest() != installed.verifier().manifest_digest() {
            return Err(Error::Authority);
        }
        let allowlist = authority(KagemushaWalletVerifyingKeyAllowlistV1::decode_canonical(
            &installed.originals().allowlist,
            &manifest.body,
        ))?;
        // G1 records the total Omega transport length, including both 544-byte claims.
        let transport_bytes =
            usize::try_from(allowlist.lineage_proof_bytes).map_err(|_| Error::Inventory)?;
        let omega_proof_bytes = transport_bytes
            .checked_sub(2 * ACCUMULATOR_BYTES)
            .filter(|length| *length != 0)
            .ok_or(Error::Inventory)?;
        Ok(Self {
            installed,
            cancellation: None,
            omega_key_digest: allowlist.lineage_verifying_key_digest,
            omega_proof_bytes,
        })
    }

    /// Bind background preparation to the same operation signal as its native proofs.
    /// Cancellation supplies no proof verdict or authority to change monetary state.
    pub(crate) fn with_cancellation(
        mut self,
        cancellation: &'a iroha_pasta::CancellationToken,
    ) -> Self {
        self.cancellation = Some(cancellation);
        self
    }

    /// Authenticate exact canonical credential and issuer certificate before creating tapes.
    /// Native slot/account/payment-key enrollment intake must independently bind this owner.
    /// # Errors
    /// Another installed scheme, noncanonical frame, issuer role/key or invalid signature.
    pub fn authenticate_credential(
        &self,
        credential_original: &[u8],
        certificate_original: &[u8],
    ) -> Result<AuthenticatedCredentialV1, Error> {
        let scheme = self.installed.verifier().scheme();
        let credential = authority(KagemushaWalletCredentialV1::decode_canonical(
            credential_original,
            &scheme.scheme_id(),
        ))?;
        let certificate = authority(KagemushaWalletSignerCertificateV1::decode_canonical(
            certificate_original,
            scheme,
        ))?;
        authority(credential.verify(scheme, &certificate))?;
        Ok(AuthenticatedCredentialV1 {
            manifest_digest: self.installed.verifier().manifest_digest(),
            credential_tape: signed_tape(credential.body.transcript(), &credential.signature),
            certificate_tape: signed_tape(certificate.body.transcript(), &certificate.signature),
            credential,
            certificate,
            credential_original: credential_original.to_vec(),
            certificate_original: certificate_original.to_vec(),
        })
    }

    fn credential_owner(&self, owner: &AuthenticatedCredentialV1) -> Result<(), Error> {
        if owner.manifest_digest != self.installed.verifier().manifest_digest() {
            return Err(Error::Authority);
        }
        authority(
            owner
                .credential
                .verify(self.installed.verifier().scheme(), &owner.certificate),
        )
    }

    /// Convert canonical state/statement arrays without reduction or integer aliasing.
    /// This supplies witness values only; the actual circuit constrains monetary effects.
    /// # Errors
    /// State/credential/public bindings or a canonical field encoding differ.
    pub fn state_fields(
        &self,
        owner: &AuthenticatedCredentialV1,
        state: &KagemushaWalletStateV1,
        public: &KagemushaWalletLineagePublicV1,
    ) -> Result<StateWitness, Error> {
        self.credential_owner(owner)?;
        authority(state.validate_for_credential(&owner.credential))?;
        authority(public.validate())?;
        let scheme = self.installed.verifier().scheme();
        if public.scheme_id != scheme.scheme_id()
            || public.relation_id != scheme.relation_id
            || public.head != authority(state.commitment())?
            || public.wallet_id != state.core.wallet_id
            || public.credential_digest != state.core.credential_digest
            || public.payment_key != owner.credential.body.payment_key
            || public.lifecycle != state.core.lifecycle
            || public.policy_epoch != state.core.policy_epoch
            || public.enabled_controls != state.core.enabled_controls
        {
            return Err(Error::Authority);
        }
        Ok(StateWitness {
            core: fields(authority(state.core_field_items())?)?,
            rest: fields(authority(state.rest_field_items())?)?,
            lineage: lineage_public_fields(public, self.omega_key_digest)?,
        })
    }

    /// Exact current G1 statement preimage used by the actual sigma and A context.
    /// # Errors
    /// Statement, installed scheme or current credential differ.
    pub fn statement_fields(
        &self,
        owner: &AuthenticatedCredentialV1,
        statement: &KagemushaWalletStatementV1,
    ) -> Result<[Fp; 26], Error> {
        self.credential_owner(owner)?;
        authority(statement.validate_for_scheme(self.installed.verifier().scheme()))?;
        authority(statement.validate_for_credential(&owner.credential))?;
        fields(authority(statement.field_items())?)
    }

    fn successor_fields(
        &self,
        owner: &AuthenticatedCredentialV1,
        state: &KagemushaWalletStateV1,
        statement: &KagemushaWalletStatementV1,
        public: &KagemushaWalletLineagePublicV1,
    ) -> Result<(StateWitness, [Fp; 26]), Error> {
        let opening = self.state_fields(owner, state, public)?;
        let fields = self.statement_fields(owner, statement)?;
        if statement.successor != authority(state.commitment())?
            || statement.lifecycle != state.core.lifecycle
            || statement.sequence != state.core.sequence
            || statement.next_load != state.core.next_load
        {
            return Err(Error::Authority);
        }
        Ok((opening, fields))
    }

    /// Prepare the genuine Bootstrap sigma witness before a receipt or completion exists.
    /// The actual enrolled slot/challenge owner and installed sigma prover remain mandatory.
    /// # Errors
    /// Another fixed operation, state/statement/public binding or credential authentication.
    pub fn bootstrap_sigma_fields(
        &self,
        owner: &AuthenticatedCredentialV1,
        state: &KagemushaWalletStateV1,
        statement: &KagemushaWalletStatementV1,
        public: &KagemushaWalletLineagePublicV1,
    ) -> Result<BootstrapWitness, Error> {
        if statement.effect.kind() != KagemushaWalletOperationKindV1::Bootstrap {
            return Err(Error::Authority);
        }
        let (state, statement) = self.successor_fields(owner, state, statement, public)?;
        Ok(BootstrapWitness {
            core: state.core,
            rest: state.rest,
            lineage: state.lineage,
            statement,
        })
    }

    fn sigma_transition_fields(
        &self,
        owner: &AuthenticatedCredentialV1,
        predecessor: &FoldedStateV1,
        state: &KagemushaWalletStateV1,
        statement: &KagemushaWalletStatementV1,
        public: &KagemushaWalletLineagePublicV1,
    ) -> Result<(StateWitness, [Fp; 26]), Error> {
        if predecessor.manifest_digest != self.installed.verifier().manifest_digest()
            || predecessor.credential != owner.credential
        {
            return Err(Error::Authority);
        }
        authority(statement.validate_successor_of(&predecessor.source_statement))?;
        if statement.effect.kind().consumes_lineage() {
            authority(statement.validate_against_lineage(&predecessor.lineage.public))?;
        }
        self.successor_fields(owner, state, statement, public)
    }

    // Only the native derivation owner may supply these successor fields.
    fn consuming_sigma_fields(
        &self,
        kind: KagemushaWalletOperationKindV1,
        owner: &AuthenticatedCredentialV1,
        predecessor: &FoldedStateV1,
        state: &KagemushaWalletStateV1,
        statement: &KagemushaWalletStatementV1,
        public: &KagemushaWalletLineagePublicV1,
    ) -> Result<ConsumingWitness, Error> {
        if !matches!(
            kind,
            KagemushaWalletOperationKindV1::Unload | KagemushaWalletOperationKindV1::Retiring
        ) || statement.effect.kind() != kind
        {
            return Err(Error::Authority);
        }
        let (successor, statement) =
            self.sigma_transition_fields(owner, predecessor, state, statement, public)?;
        Ok(ConsumingWitness {
            predecessor: predecessor.witness,
            successor,
            statement,
        })
    }

    /// Reconstruct the signed receipt tape from the exact retained completion, then verify
    /// its original signature and actual source capsule sigma/Omega proofs in full.
    /// # Errors
    /// Another credential, missing/changed original completion or native verification failure.
    pub fn receipt_tape(
        &self,
        owner: &AuthenticatedCredentialV1,
        step: &ReleasedStep,
        budget: MemoryBudget,
    ) -> Result<Vec<u8>, Error> {
        self.credential_owner(owner)?;
        step.frozen.validate().map_err(|_| Error::Authority)?;
        let capsule = &step.frozen.capsule;
        let retained = &step.retained;
        if step.frozen.credential != owner.credential
            || retained.selected_generation == 0
            || retained.operation_id != capsule.operation_id
            || retained.capsule_digest != authority(capsule.capsule_digest())?
            || retained.frame != authority(retained.record.to_canonical_bytes())?
            || retained.completion_digest != authority(retained.record.completion_digest())?
        {
            return Err(Error::Authority);
        }
        authority(retained.record.verify(&owner.credential, capsule))?;
        self.installed
            .verifier()
            .verify_capsule_proofs_cancellable(
                capsule,
                &owner.credential,
                budget,
                self.cancellation,
            )?;
        let signer = authority(KagemushaWalletReceiptSignerV1::from_credential(
            &owner.credential,
        ))?;
        let proof_digest = authority(capsule.proof_digest())?;
        let receipt = &retained.record.receipt;
        authority(receipt.verify(&signer, &capsule.statement, &proof_digest))?;
        let body = authority(receipt.body(&signer, &capsule.statement, &proof_digest))?;
        Ok(signed_tape(body.transcript(), &receipt.signature))
    }

    /// Fully verify an actual predecessor fold and bind every source state/receipt original.
    /// The coordinator still supplies Selected/Released marker provenance and durable lifetime.
    /// # Errors
    /// Source completion/fold differs or original Omega/P/V full native verification fails.
    pub fn folded_state(
        &self,
        owner: &AuthenticatedCredentialV1,
        step: &ReleasedStep,
        fold: &KagemushaWalletFoldRecordV1,
        budget: MemoryBudget,
    ) -> Result<FoldedStateV1, Error> {
        self.receipt_tape(owner, step, budget)?;
        authority(fold.validate())?;
        let capsule = &step.frozen.capsule;
        if fold.scheme_id != capsule.scheme_id
            || fold.wallet_id != capsule.wallet_id
            || fold.sequence != capsule.statement.sequence
            || fold.head != capsule.statement.successor
            || fold.capsule_digest != authority(capsule.capsule_digest())?
        {
            return Err(Error::Authority);
        }
        let witness = self.state_fields(owner, &capsule.successor_state, &fold.lineage.public)?;
        self.installed.verifier().verify_lineage_cancellable(
            &fold.lineage,
            budget,
            self.cancellation,
        )?;
        let expected_length = self
            .omega_proof_bytes
            .checked_add(2 * ACCUMULATOR_BYTES)
            .ok_or(Error::Inventory)?;
        if fold.lineage.proof.len() != expected_length {
            return Err(Error::Proof);
        }
        let (proof, claims) = fold.lineage.proof.split_at(self.omega_proof_bytes);
        let (pallas, vesta) = claims.split_at(ACCUMULATOR_BYTES);
        Ok(FoldedStateV1 {
            manifest_digest: self.installed.verifier().manifest_digest(),
            source_capsule_digest: fold.capsule_digest,
            source_statement: capsule.statement.clone(),
            source_state: capsule.successor_state,
            credential: owner.credential,
            lineage: fold.lineage.clone(),
            witness,
            proof: proof.to_vec(),
            pallas: pallas.try_into().map_err(|_| Error::Proof)?,
            vesta: vesta.try_into().map_err(|_| Error::Proof)?,
        })
    }

    fn transition_fields(
        &self,
        owner: &AuthenticatedCredentialV1,
        step: &ReleasedStep,
        predecessor: &FoldedStateV1,
        public: &KagemushaWalletLineagePublicV1,
        budget: MemoryBudget,
    ) -> Result<(StateWitness, [Fp; 26], Vec<u8>), Error> {
        let receipt = self.receipt_tape(owner, step, budget)?;
        let capsule = &step.frozen.capsule;
        if predecessor.manifest_digest != self.installed.verifier().manifest_digest()
            || predecessor.source_capsule_digest != capsule.predecessor_capsule_digest
            || predecessor.credential != owner.credential
        {
            return Err(Error::Authority);
        }
        authority(
            capsule
                .statement
                .validate_successor_of(&predecessor.source_statement),
        )?;
        if capsule.kind.consumes_lineage()
            && capsule.predecessor_lineage() != Some(&predecessor.lineage)
        {
            return Err(Error::Authority);
        }
        Ok((
            self.state_fields(owner, &capsule.successor_state, public)?,
            self.statement_fields(owner, &capsule.statement)?,
            receipt,
        ))
    }

    /// Prepare actual Bootstrap fields/tapes from its retained post-Advance source.
    /// # Errors
    /// Not Bootstrap, another enrollment/credential/state or invalid retained proof/receipt.
    pub(crate) fn bootstrap_fields(
        &self,
        owner: &AuthenticatedCredentialV1,
        step: &ReleasedStep,
        public: &KagemushaWalletLineagePublicV1,
        budget: MemoryBudget,
    ) -> Result<BootstrapFieldsV1, Error> {
        let capsule = &step.frozen.capsule;
        if capsule.kind != KagemushaWalletOperationKindV1::Bootstrap {
            return Err(Error::Authority);
        }
        let receipt = self.receipt_tape(owner, step, budget)?;
        let state = self.state_fields(owner, &capsule.successor_state, public)?;
        Ok(BootstrapFieldsV1 {
            state: BootstrapWitness {
                core: state.core,
                rest: state.rest,
                lineage: state.lineage,
                statement: self.statement_fields(owner, &capsule.statement)?,
            },
            sigma: capsule.step_proof.bytes.clone(),
            objects: [
                owner.certificate_tape.clone(),
                owner.credential_tape.clone(),
                receipt,
            ],
        })
    }

    /// Convert retained ordinary receipt originals and own signed fields. Native
    /// verified BLS finality before Advance; the producer verifies the receipt-bound
    /// Advance signature and every state transition in the four Load stages.
    /// # Errors
    /// Another operation, missing/ambiguous original, noncanonical fields, changed
    /// receipt terms or source digest.
    pub(crate) fn load_fields(
        &self,
        owner: &AuthenticatedCredentialV1,
        step: &ReleasedStep,
        predecessor: &FoldedStateV1,
        public: &KagemushaWalletLineagePublicV1,
        budget: MemoryBudget,
    ) -> Result<LoadFieldsV1, Error> {
        let capsule = &step.frozen.capsule;
        let KagemushaWalletEffectV1::Load {
            receipt_digest: digest,
            load_ordinal,
            amount,
            online_charge,
        } = capsule.statement.effect
        else {
            return Err(Error::Authority);
        };
        if capsule.kind != KagemushaWalletOperationKindV1::Load {
            return Err(Error::Authority);
        }
        let (ordinary, _) = retained_load_source(&capsule.retained_inputs, digest)?;
        let previous = &predecessor.source_state.core;
        if ordinary.scheme_id != self.installed.verifier().scheme().scheme_id()
            || ordinary.asset_digest != previous.asset_digest
            || ordinary.wallet_id != previous.wallet_id
            || ordinary.ordinal != previous.next_load
            || ordinary.ordinal != load_ordinal
            || ordinary.amount != amount
            || ordinary.online_charge != online_charge
        {
            return Err(Error::Authority);
        }
        let (successor, statement, receipt) =
            self.transition_fields(owner, step, predecessor, public, budget)?;
        Ok(LoadFieldsV1 {
            state: LoadWitness {
                predecessor: predecessor.witness,
                successor,
                statement,
            },
            sigma: capsule.step_proof.bytes.clone(),
            receipt: authority(ordinary.transcript())?,
            objects: [
                receipt,
                owner.certificate_tape.clone(),
                owner.credential_tape.clone(),
            ],
        })
    }

    /// Convert exact Unload or Retiring inputs, preserving the same hard carried Omega.
    /// # Errors
    /// Wrong fixed operation, source/credential/lineage changes or invalid retained evidence.
    pub(crate) fn consuming_fields(
        &self,
        kind: KagemushaWalletOperationKindV1,
        owner: &AuthenticatedCredentialV1,
        step: &ReleasedStep,
        predecessor: &FoldedStateV1,
        public: &KagemushaWalletLineagePublicV1,
        budget: MemoryBudget,
    ) -> Result<ConsumingFieldsV1, Error> {
        if !matches!(
            kind,
            KagemushaWalletOperationKindV1::Unload | KagemushaWalletOperationKindV1::Retiring
        ) || step.frozen.capsule.kind != kind
        {
            return Err(Error::Authority);
        }
        let (successor, statement, receipt) =
            self.transition_fields(owner, step, predecessor, public, budget)?;
        Ok(ConsumingFieldsV1 {
            state: ConsumingWitness {
                predecessor: predecessor.witness,
                successor,
                statement,
            },
            sigma: step.frozen.capsule.step_proof.bytes.clone(),
            objects: [
                owner.credential_tape.clone(),
                owner.certificate_tape.clone(),
                receipt,
            ],
        })
    }
}
