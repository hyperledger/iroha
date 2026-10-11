//! Opaque generation-zero Bootstrap derivation from admitted enrollment custody.

use super::*;

pub(crate) struct BootstrapStepV1 {
    pub(crate) state: KagemushaWalletStateV1,
    pub(crate) statement: KagemushaWalletStatementV1,
    pub(crate) witness: BootstrapWitness,
    pub(crate) manifest: [u8; 32],
}

impl PreparationV1<'_> {
    pub(crate) fn prepare_bootstrap(
        &self,
        owner: &AuthenticatedCredentialV1,
        enrollment_marker: [u8; 32],
        nonce: [u8; 32],
    ) -> Result<BootstrapStepV1, Error> {
        self.credential_owner(owner)?;
        if enrollment_marker == [0; 32]
            || nonce == [0; 32]
            || !bool::from(Fp::from_repr(nonce).is_some())
        {
            return Err(Error::Authority);
        }
        let scheme = self.installed.verifier().scheme();
        let state = authority(KagemushaWalletStateV1::bootstrap(&owner.credential, nonce))?;
        let statement = KagemushaWalletStatementV1 {
            version: 1,
            scheme_id: scheme.scheme_id(),
            relation_id: scheme.relation_id,
            credential_digest: owner.credential.credential_digest(),
            asset_digest: state.core.asset_digest,
            lifecycle: state.core.lifecycle,
            sequence: 0,
            next_load: 0,
            enabled_controls: state.core.enabled_controls,
            lineage_burned_total: 0,
            lineage_pending_outgoing_root: [0; 32],
            predecessor: KagemushaWalletStateCommitmentV1 { value: [0; 32] },
            successor: authority(state.commitment())?,
            effect: KagemushaWalletEffectV1::Bootstrap {
                enrollment_id: owner.credential.body.enrollment_id,
                enrollment_marker,
            },
        };
        let projection = unfolded::local_state(
            &owner.credential,
            &state,
            scheme.relation_id,
            self.omega_key_digest,
        )?;
        Ok(BootstrapStepV1 {
            state,
            statement,
            witness: BootstrapWitness {
                core: projection.core,
                rest: projection.rest,
                lineage: projection.lineage,
                statement: self.statement_fields(owner, &statement)?,
            },
            manifest: owner.manifest_digest,
        })
    }
}
