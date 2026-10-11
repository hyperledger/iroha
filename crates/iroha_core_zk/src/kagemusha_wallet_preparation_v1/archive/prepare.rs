//! Private Archive derivation from authenticated local Send custody and exact Credited bytes.

use super::*;

/// Opaque local Archive proposal; incoming evidence remains a soft fold obligation.
pub(crate) struct ArchiveStepV1 {
    pub(super) manifest: [u8; 32],
    pub(super) source: [u8; 32],
    pub(super) witness: ArchiveWitness,
    pub(super) state: KagemushaWalletStateV1,
    pub(super) statement: KagemushaWalletStatementV1,
    pub(super) retained: Vec<KagemushaWalletRetainedInputV1>,
    pub(super) openings: [Vec<u8>; 2],
}
impl ArchiveStepV1 {
    pub(crate) fn witness(&self) -> &ArchiveWitness {
        &self.witness
    }
    pub(crate) fn state(&self) -> &KagemushaWalletStateV1 {
        &self.state
    }
    pub(crate) fn statement(&self) -> &KagemushaWalletStatementV1 {
        &self.statement
    }
    pub(crate) fn manifest_digest(&self) -> [u8; 32] {
        self.manifest
    }
    pub(crate) fn source_capsule_digest(&self) -> [u8; 32] {
        self.source
    }
    pub(crate) fn originals(&self) -> (&[KagemushaWalletRetainedInputV1], &[Vec<u8>; 2]) {
        (&self.retained, &self.openings)
    }
}

pub(super) fn derive(
    credential: &KagemushaWalletCredentialV1,
    before: &KagemushaWalletStateV1,
    pending: &KagemushaWalletPendingOutgoingLeafV1,
    credited: [u8; 32],
    removal: &KagemushaWalletIndexedRemoveV1,
    nonce: [u8; 32],
    relation: [u8; 32],
) -> Result<(KagemushaWalletStateV1, KagemushaWalletStatementV1), Error> {
    authority(before.validate_for_credential(credential))?;
    if nonce == [0; 32]
        || nonce == before.core.state_nonce
        || !bool::from(Fp::from_repr(nonce).is_some())
    {
        return Err(Error::Authority);
    }
    let (_, pending_root) = super::removal(removal, &before.core.pending_outgoing_root, pending)?;
    let mut state = *before;
    state.core.sequence = state.core.sequence.checked_add(1).ok_or(Error::Authority)?;
    state.core.pending_outgoing_root = pending_root;
    state.core.state_nonce = nonce;
    authority(state.validate_for_credential(credential))?;
    let statement = KagemushaWalletStatementV1 {
        version: 1,
        scheme_id: state.core.scheme_id,
        relation_id: relation,
        credential_digest: state.core.credential_digest,
        asset_digest: state.core.asset_digest,
        lifecycle: state.core.lifecycle,
        sequence: state.core.sequence,
        next_load: state.core.next_load,
        enabled_controls: before.core.enabled_controls,
        lineage_burned_total: 0,
        lineage_pending_outgoing_root: [0; 32],
        predecessor: authority(before.commitment())?,
        successor: authority(state.commitment())?,
        effect: KagemushaWalletEffectV1::ArchiveSent {
            credit_id: pending.credit_id,
            credited,
        },
    };
    Ok((state, statement))
}

impl PreparationV1<'_> {
    pub(crate) fn prepare_archive(
        &self,
        owner: &AuthenticatedCredentialV1,
        source: &ReleasedStep,
        intent: &crate::kagemusha_wallet_state_v1::ArchiveIntentV1,
        removal: &KagemushaWalletIndexedRemoveV1,
        nonce: [u8; 32],
        budget: MemoryBudget,
    ) -> Result<ArchiveStepV1, Error> {
        let scheme = self.installed.verifier().scheme();
        let request: KagemushaWalletRequestV1 = decode(&intent.request)?;
        let payment = authority(KagemushaWalletPaymentV1::decode_canonical(
            &intent.payment,
            &scheme.scheme_id(),
        ))?;
        let credited: KagemushaWalletCreditedV1 = decode(&intent.credited)?;
        authority(credited.verify_for(scheme, &request, &payment))?;
        match &credited.evidence {
            KagemushaWalletCreditedEvidenceV1::Receive { package } => self
                .installed
                .verifier()
                .verify_package_proofs_cancellable(
                    package,
                    Some(&request.body),
                    budget,
                    self.cancellation,
                )?,
            KagemushaWalletCreditedEvidenceV1::Status { status } => self
                .installed
                .verifier()
                .verify_lineage_cancellable(&status.lineage, budget, self.cancellation)?,
        }
        self.restore_archive(owner, source, intent, removal, nonce, budget)
    }

    // Reconstruct selected own state; incoming no-op predicates are evaluated by Archive A.
    pub(crate) fn restore_archive(
        &self,
        owner: &AuthenticatedCredentialV1,
        source: &ReleasedStep,
        intent: &crate::kagemusha_wallet_state_v1::ArchiveIntentV1,
        removal: &KagemushaWalletIndexedRemoveV1,
        nonce: [u8; 32],
        budget: MemoryBudget,
    ) -> Result<ArchiveStepV1, Error> {
        use KagemushaWalletRetainedInputRoleV1 as R;
        self.credential_owner(owner)?;
        self.receipt_tape(owner, source, budget)?;
        let retained = [
            (R::Request, &intent.request),
            (R::Payment, &intent.payment),
            (R::Credential, &intent.credential),
            (R::CertificateSet, &intent.certificates),
            (R::Credited, &intent.credited),
        ]
        .map(|(role, bytes)| KagemushaWalletRetainedInputV1 {
            role,
            bytes: bytes.clone(),
        })
        .to_vec();
        let held = retained::originals(
            self.installed.verifier().scheme(),
            &owner.credential,
            &retained,
        )?;
        let digest =
            evidence::credited_digest(&intent.credited, &held.request, &held.payment_digest)?;
        let (state, statement) = derive(
            &owner.credential,
            &source.frozen.capsule.successor_state,
            &held.pending,
            digest,
            removal,
            nonce,
            self.installed.verifier().scheme().relation_id,
        )?;
        let witness = self.archive_sigma_fields(owner, source, &state, &statement, budget)?;
        Ok(ArchiveStepV1 {
            manifest: owner.manifest_digest,
            source: authority(source.frozen.capsule.capsule_digest())?,
            witness,
            state,
            statement,
            retained,
            openings: [
                removal
                    .predecessor_opening
                    .leaf_transcript(&removal.predecessor),
                removal.leaf_opening.leaf_transcript(&removal.leaf),
            ],
        })
    }
}
