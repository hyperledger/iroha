//! Native Unload/Retiring derivation from the exact authenticated folded head.
//!
//! The caller chooses an amount, not a successor, nullifier or lineage verdict.
//! Native custody supplies the nonce and recovery insertion and rechecks the
//! source at commit. Charge originals belong to retained payout custody, not
//! Lambda's capsule inputs: the ledger authenticates that separate signed quote.

use super::*;

/// Exact signed charge material retained until the Unload's finalized payout.
#[derive(Clone, Copy)]
pub struct UnloadChargeOriginalsV1<'a> {
    /// Canonical RegulatoryPolicy-signed quote with exact Unload terms.
    pub quote: &'a [u8],
    /// Canonical issuer-authenticated certificate set containing its signer.
    pub certificate_set: &'a [u8],
}

/// Requested consuming operation with actual native-owned map witnesses.
#[derive(Clone, Copy)]
pub enum ConsumingActionV1<'a> {
    /// Debit the chosen positive face amount, retaining its recovery claim.
    Unload {
        /// Offline face amount; the ledger withholds any authenticated charge.
        amount: u128,
        /// Low-leaf and intermediate empty-slot openings from native custody.
        insertion: &'a KagemushaWalletIndexedInsertV1,
        /// Omitted for the default zero charge.
        charge: Option<UnloadChargeOriginalsV1<'a>>,
    },
    /// Irreversibly enter Retiring while preserving value and recovery maps.
    Retiring,
}

/// Fully derived consuming sigma input, with exact originals and source identity.
/// This grants no Advance or wallet admission capability.
pub struct ConsumingStepV1 {
    manifest_digest: [u8; 32],
    source_capsule_digest: [u8; 32],
    witness: ConsumingWitness,
    state: KagemushaWalletStateV1,
    statement: KagemushaWalletStatementV1,
    projection: KagemushaWalletLineagePublicV1,
    charge: Option<(Vec<u8>, Vec<u8>)>,
    openings: Vec<Vec<u8>>,
}

impl ConsumingStepV1 {
    /// Exact fixed Unload/Retiring witness, never an alternative relation.
    pub const fn witness(&self) -> &ConsumingWitness {
        &self.witness
    }
    /// Derived successor, synchronizing burned value and pending root from Omega.
    pub const fn state(&self) -> &KagemushaWalletStateV1 {
        &self.state
    }
    /// Exact statement for sigma, Advance and retained payout/retirement.
    pub const fn statement(&self) -> &KagemushaWalletStatementV1 {
        &self.statement
    }
    /// Private sigma projection of the successor; no proof or fold authority.
    pub const fn successor_projection(&self) -> &KagemushaWalletLineagePublicV1 {
        &self.projection
    }
    /// Exact optional quote and certificate-set bytes for durable payout custody.
    /// These are not added to the Unload capsule's retained Lambda roles.
    pub fn charge_originals(&self) -> Option<(&[u8], &[u8])> {
        self.charge
            .as_ref()
            .map(|(quote, certificates)| (quote.as_slice(), certificates.as_slice()))
    }
    /// Unload's two insertion openings, or no openings for Retiring.
    pub fn map_openings(&self) -> &[Vec<u8>] {
        &self.openings
    }
    /// Installation identity to recheck before proving and commit.
    pub const fn manifest_digest(&self) -> [u8; 32] {
        self.manifest_digest
    }
    /// Exact source capsule to recheck under Native's exclusive head lock.
    pub const fn source_capsule_digest(&self) -> [u8; 32] {
        self.source_capsule_digest
    }
}

fn charge_terms(
    scheme: &KagemushaWalletSchemeV1,
    state: &KagemushaWalletStateV1,
    amount: u128,
    original: Option<UnloadChargeOriginalsV1<'_>>,
) -> Result<(u128, [u8; 32]), Error> {
    let Some(original) = original else {
        return Ok((0, [0; 32]));
    };
    let quote = authority(KagemushaWalletChargeQuoteV1::decode_canonical(
        original.quote,
        &scheme.scheme_id(),
    ))?;
    if original.certificate_set.is_empty()
        || original.certificate_set.len() > KAGEMUSHA_WALLET_MESSAGE_MAX_BYTES_V1
    {
        return Err(Error::Authority);
    }
    let certificates: KagemushaWalletCertificateSetV1 = norito::decode_canonical_with_limits(
        original.certificate_set,
        norito::canonical_decode_limits(original.certificate_set.len()),
    )
    .map_err(|_| Error::Authority)?;
    authority(certificates.verify(scheme))?;
    let signer = authority(certificates.certificate(
        &quote.body.signer_certificate,
        KagemushaWalletSignerRoleV1::RegulatoryPolicy,
    ))?;
    authority(quote.verify(scheme, signer))?;
    authority(quote.require_terms(
        KagemushaWalletChargeKindV1::Unload,
        &state.core.wallet_id,
        state.core.next_redeem,
        amount,
        quote.body.online_charge,
    ))?;
    if quote.body.asset_digest != state.core.asset_digest {
        return Err(Error::Authority);
    }
    Ok((quote.body.online_charge, quote.charge_quote_digest()))
}

struct Derived {
    state: KagemushaWalletStateV1,
    statement: KagemushaWalletStatementV1,
    projection: KagemushaWalletLineagePublicV1,
    charge: Option<(Vec<u8>, Vec<u8>)>,
    openings: Vec<Vec<u8>>,
}

fn checked_unload_terms(
    scheme: &KagemushaWalletSchemeV1,
    before: &KagemushaWalletStateV1,
    lineage: &KagemushaWalletLineagePublicV1,
    amount: u128,
    charge: Option<UnloadChargeOriginalsV1<'_>>,
) -> Result<(u128, [u8; 32]), Error> {
    authority(before.check_unload(amount, lineage))?;
    charge_terms(scheme, before, amount, charge)
}

// This arithmetic helper admits no source proof. The public owner accepts only
// an opaque FoldedStateV1 whose exact original Omega and both claims verified.
fn derive(
    scheme: &KagemushaWalletSchemeV1,
    credential: &KagemushaWalletCredentialV1,
    before: &KagemushaWalletStateV1,
    lineage: &KagemushaWalletLineagePublicV1,
    action: ConsumingActionV1<'_>,
    nonce: [u8; 32],
) -> Result<Derived, Error> {
    authority(before.validate_for_credential(credential))?;
    authority(before.spendable_with(lineage))?;
    let mut state = before.clone();
    state.core.sequence = before
        .core
        .sequence
        .checked_add(1)
        .ok_or(Error::Authority)?;
    state.core.state_nonce = nonce;
    state.core.burned_total = lineage.burned_total;
    state.core.pending_outgoing_root = lineage.pending_outgoing_root;
    let (effect, charge, openings) = match action {
        ConsumingActionV1::Unload {
            amount,
            insertion,
            charge,
        } => {
            let (online_charge, charge_quote) =
                checked_unload_terms(scheme, before, lineage, amount, charge)?;
            let ordinal = before.core.next_redeem;
            let nullifier = kagemusha_wallet_unload_nullifier_v1(
                &before.core.scheme_id,
                &before.core.wallet_id,
                ordinal,
            );
            let leaf = KagemushaWalletRedeemLeafV1 {
                ordinal,
                nullifier,
                amount,
                online_charge,
            };
            state.core.load_redeem_recovery_root = authority(insertion.verify(
                &before.core.load_redeem_recovery_root,
                &leaf.key(),
                &authority(leaf.leaf_value())?,
            ))?;
            state.core.balance = before
                .core
                .balance
                .checked_sub(amount)
                .ok_or(Error::Authority)?;
            state.core.next_redeem = ordinal.checked_add(1).ok_or(Error::Authority)?;
            (
                KagemushaWalletEffectV1::Unload {
                    nullifier,
                    redeem_ordinal: ordinal,
                    amount,
                    online_charge,
                    charge_quote,
                },
                charge.map(|original| (original.quote.to_vec(), original.certificate_set.to_vec())),
                vec![
                    insertion.low_opening.leaf_transcript(&insertion.low),
                    insertion.slot_opening.empty_transcript(),
                ],
            )
        }
        ConsumingActionV1::Retiring => {
            if before.core.lifecycle != KagemushaWalletLifecycleV1::Active {
                return Err(Error::Authority);
            }
            state.core.lifecycle = KagemushaWalletLifecycleV1::Retiring;
            (KagemushaWalletEffectV1::Retiring, None, vec![])
        }
    };
    authority(state.validate_for_credential(credential))?;
    let statement = KagemushaWalletStatementV1 {
        version: KAGEMUSHA_WALLET_VERSION_V1,
        scheme_id: before.core.scheme_id,
        relation_id: scheme.relation_id,
        credential_digest: state.core.credential_digest,
        asset_digest: before.core.asset_digest,
        lifecycle: state.core.lifecycle,
        sequence: state.core.sequence,
        next_load: state.core.next_load,
        enabled_controls: before.core.enabled_controls,
        lineage_burned_total: lineage.burned_total,
        lineage_pending_outgoing_root: lineage.pending_outgoing_root,
        predecessor: authority(before.commitment())?,
        successor: authority(state.commitment())?,
        effect,
    };
    authority(statement.validate_for_scheme(scheme))?;
    authority(statement.validate_for_credential(credential))?;
    authority(statement.validate_against_lineage(lineage))?;
    let mut projection = *lineage;
    projection.head = statement.successor;
    projection.lifecycle = state.core.lifecycle;
    Ok(Derived {
        state,
        statement,
        projection,
        charge,
        openings,
    })
}

impl PreparationV1<'_> {
    // Reuse the genuine Unload amount/quote predicates without a recovery insertion,
    // successor nonce, proving, signing or durable state change.
    pub(crate) fn review_unload_terms(
        &self,
        owner: &AuthenticatedCredentialV1,
        predecessor: &FoldedStateV1,
        amount: u128,
        charge: Option<UnloadChargeOriginalsV1<'_>>,
    ) -> Result<(u128, [u8; 32]), Error> {
        self.credential_owner(owner)?;
        if predecessor.manifest_digest != self.installed.verifier().manifest_digest()
            || predecessor.credential != owner.credential
        {
            return Err(Error::Authority);
        }
        self.state_fields(
            owner,
            &predecessor.source_state,
            &predecessor.lineage.public,
        )?;
        authority(
            predecessor
                .source_state
                .validate_for_credential(&owner.credential),
        )?;
        checked_unload_terms(
            self.installed.verifier().scheme(),
            &predecessor.source_state,
            &predecessor.lineage.public,
            amount,
            charge,
        )
    }

    /// Derive Unload or Retiring from the exact authenticated folded source.
    /// Native supplies its own nonce and map paths, persists these originals,
    /// then rechecks the source under its exclusive commit lock before Advance.
    /// The foreign caller cannot provide state, nullifiers or lineage fields.
    ///
    /// # Errors
    /// Foreign installation/credential, invalid or mismatched signed charge,
    /// insufficient adjusted balance, zero amount, replay/nonempty recovery
    /// slot, malformed path, overflow, noncanonical nonce or repeated retirement.
    pub fn prepare_consuming(
        &self,
        owner: &AuthenticatedCredentialV1,
        predecessor: &FoldedStateV1,
        action: ConsumingActionV1<'_>,
        successor_nonce: [u8; 32],
    ) -> Result<ConsumingStepV1, Error> {
        self.credential_owner(owner)?;
        if predecessor.manifest_digest != self.installed.verifier().manifest_digest()
            || predecessor.credential != owner.credential
        {
            return Err(Error::Authority);
        }
        // Exact source identity/policy fields are checked by the same projection
        // owner used when the fully verified fold was originally constructed.
        self.state_fields(
            owner,
            &predecessor.source_state,
            &predecessor.lineage.public,
        )?;
        let derived = derive(
            self.installed.verifier().scheme(),
            &owner.credential,
            &predecessor.source_state,
            &predecessor.lineage.public,
            action,
            successor_nonce,
        )?;
        let witness = self.consuming_sigma_fields(
            derived.statement.effect.kind(),
            owner,
            predecessor,
            &derived.state,
            &derived.statement,
            &derived.projection,
        )?;
        Ok(ConsumingStepV1 {
            manifest_digest: owner.manifest_digest,
            source_capsule_digest: predecessor.source_capsule_digest,
            witness,
            state: derived.state,
            statement: derived.statement,
            projection: derived.projection,
            charge: derived.charge,
            openings: derived.openings,
        })
    }
}

#[cfg(test)]
#[path = "consuming/tests.rs"]
mod tests;
