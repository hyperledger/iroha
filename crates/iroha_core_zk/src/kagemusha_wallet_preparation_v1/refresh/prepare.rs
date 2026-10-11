//! Pre-Advance Refresh derivation from exact signed originals and a released head.

use super::*;

/// Exact original policy custody supplied before a Refresh has an Advance receipt.
/// The same decoder authenticates these bytes again when the released step folds.
#[derive(Clone, Copy)]
pub struct RefreshOriginalsV1<'a> {
    /// Update kind selected by the requested operation.
    pub kind: KagemushaWalletPolicyUpdateKindV1,
    /// Complete original canonical signed update frame.
    pub update: &'a [u8],
    /// Complete original canonical direct-root certificate set.
    pub certificates: &'a [u8],
    /// Blacklist-history low and empty insertion openings, absent for other kinds.
    pub openings: &'a [Vec<u8>],
    /// Original canonical 64-slot predecessor usage frame, exactly for QuotaShare.
    pub quota: Option<&'a [u8]>,
}

/// Authenticated Refresh inputs with the exact derived local sigma witness.
/// This is preparation only: Native still owns head locking and irreversible Advance.
pub struct RefreshStepV1 {
    manifest_digest: [u8; 32],
    source_capsule_digest: [u8; 32],
    witness: RefreshWitness,
    state: KagemushaWalletStateV1,
    statement: KagemushaWalletStatementV1,
    retained: Vec<KagemushaWalletRetainedInputV1>,
    openings: Vec<Vec<u8>>,
}

impl RefreshStepV1 {
    /// Exact fixed-class witness; no folded or adjusted-value authority is conveyed.
    #[must_use]
    pub const fn witness(&self) -> &RefreshWitness {
        &self.witness
    }
    /// Fully derived successor state for the proposed local Advance.
    #[must_use]
    pub const fn state(&self) -> &KagemushaWalletStateV1 {
        &self.state
    }
    /// Exact statement that must be proved and signed by Advance.
    #[must_use]
    pub const fn statement(&self) -> &KagemushaWalletStatementV1 {
        &self.statement
    }
    /// Original frames and map openings to retain without reconstruction in the capsule.
    #[must_use]
    pub fn originals(&self) -> (&[KagemushaWalletRetainedInputV1], &[Vec<u8>]) {
        (&self.retained, &self.openings)
    }
    /// Authenticated installation to recheck before proving and release.
    #[must_use]
    pub const fn manifest_digest(&self) -> [u8; 32] {
        self.manifest_digest
    }
    /// Exact current released head to recheck under Native's commit lock.
    #[must_use]
    pub const fn source_capsule_digest(&self) -> [u8; 32] {
        self.source_capsule_digest
    }
}

/// Derive both state openings and the statement; callers cannot supply effects.
pub(super) fn transition(
    current: &KagemushaWalletCredentialV1,
    successor: &KagemushaWalletCredentialV1,
    source: &KagemushaWalletStateV1,
    update: &DecodedRefresh,
    nonce: [u8; 32],
    relation: [u8; 32],
    omega_key: [u8; 32],
) -> Result<
    (
        KagemushaWalletStateV1,
        KagemushaWalletStatementV1,
        RefreshWitness,
    ),
    Error,
> {
    let mut state = KagemushaWalletStateV1 {
        version: source.version,
        core: update.core,
        rest: update.rest,
    };
    state.core.sequence = source
        .core
        .sequence
        .checked_add(1)
        .ok_or(Error::Authority)?;
    state.core.state_nonce = nonce;
    authority(state.validate_for_credential(successor))?;
    let statement = KagemushaWalletStatementV1 {
        version: KAGEMUSHA_WALLET_VERSION_V1,
        scheme_id: source.core.scheme_id,
        relation_id: relation,
        credential_digest: state.core.credential_digest,
        asset_digest: source.core.asset_digest,
        lifecycle: state.core.lifecycle,
        sequence: state.core.sequence,
        next_load: state.core.next_load,
        enabled_controls: source.core.enabled_controls,
        lineage_burned_total: 0,
        lineage_pending_outgoing_root: [0; 32],
        predecessor: authority(source.commitment())?,
        successor: authority(state.commitment())?,
        effect: update.effect,
    };
    let witness = RefreshWitness {
        predecessor: unfolded::local_state(current, source, relation, omega_key)?,
        successor: unfolded::local_state(successor, &state, relation, omega_key)?,
        statement: fields(authority(statement.field_items())?)?,
        update: update.projection,
    };
    Ok((state, statement, witness))
}

impl PreparationV1<'_> {
    /// Prepare any Refresh kind from a verified released head, including one
    /// awaiting its background fold. Signed originals determine the effect,
    /// state and private sigma projection; no successor capsule or Omega is invented.
    ///
    /// # Errors
    /// Foreign installation/owner, invalid source proof/receipt, stale or wrongly
    /// signed update, invalid renewal, malformed custody, map/usage mismatch or overflow.
    pub fn prepare_refresh(
        &self,
        owners: RefreshOwnersV1<'_>,
        source: &ReleasedStep,
        originals: RefreshOriginalsV1<'_>,
        successor_nonce: [u8; 32],
        budget: MemoryBudget,
    ) -> Result<RefreshStepV1, Error> {
        self.credential_owner(owners.current)?;
        self.credential_owner(owners.successor)?;
        self.receipt_tape(owners.current, source, budget)?;
        let capsule = &source.frozen.capsule;
        let scheme = self.installed.verifier().scheme();
        let update = decode_originals(
            scheme,
            &owners.current.credential,
            &owners.successor.credential,
            &capsule.successor_state,
            originals,
        )?;
        let (state, statement, witness) = transition(
            &owners.current.credential,
            &owners.successor.credential,
            &capsule.successor_state,
            &update,
            successor_nonce,
            scheme.relation_id,
            self.omega_key_digest,
        )?;
        self.statement_fields(owners.successor, &statement)?;
        authority(statement.validate_successor_of(&capsule.statement))?;
        // Blacklists retain one explicit complete-original archive reference under
        // their fixed update kind. Native publishes and authenticates that full
        // original through the actual coordinator ObjectStore before proving.
        let retained_update = if originals.kind == KagemushaWalletPolicyUpdateKindV1::Blacklist {
            crate::kagemusha_wallet_state_v1::BlacklistOriginalReferenceV1::for_original(
                &scheme.scheme_id(),
                originals.update,
            )
            .and_then(|source| source.to_canonical_bytes())
            .map_err(|_| Error::Authority)?
        } else {
            originals.update.to_vec()
        };
        let mut retained = vec![
            KagemushaWalletRetainedInputV1 {
                role: KagemushaWalletRetainedInputRoleV1::PolicyUpdate,
                bytes: retained_update,
            },
            KagemushaWalletRetainedInputV1 {
                role: KagemushaWalletRetainedInputRoleV1::CertificateSet,
                bytes: originals.certificates.to_vec(),
            },
        ];
        if let Some(quota) = originals.quota {
            retained.push(KagemushaWalletRetainedInputV1 {
                role: KagemushaWalletRetainedInputRoleV1::QuotaRefreshWitness,
                bytes: quota.to_vec(),
            });
        }
        Ok(RefreshStepV1 {
            manifest_digest: owners.current.manifest_digest,
            source_capsule_digest: authority(capsule.capsule_digest())?,
            witness,
            state,
            statement,
            retained,
            openings: originals.openings.to_vec(),
        })
    }
}
