//! Exact retained Refresh originals with distinct current and successor credentials.
//!
//! A renewal's released capsule names the successor credential. Its C4 owner still
//! authenticates the predecessor credential, while the update owner proves immutable
//! identity and exact renewal continuity. This path does not relax other operations.

use ff::Field;
use iroha_kagemusha_proof::{
    a_relation::native::refresh as native,
    admin_sigma::{RefreshKind, RefreshUpdateWitness, RefreshWitness},
    tree::IndexedInsert,
};

use super::{
    native_inputs::{no_map_openings, retained_insertion},
    *,
};
use KagemushaWalletSignerRoleV1 as Role;

#[path = "refresh/prepare.rs"]
mod prepare;
pub use prepare::{RefreshOriginalsV1, RefreshStepV1};

/// Independently issuer-authenticated credentials on both sides of a Refresh.
/// They must be identical except for an exact Credential renewal. The current
/// owner supplies C4's original tapes; the successor owns the released capsule.
#[derive(Clone, Copy)]
pub struct RefreshOwnersV1<'a> {
    /// Credential authenticated by the actual predecessor fold.
    pub current: &'a AuthenticatedCredentialV1,
    /// Credential bound to the released successor; the same owner for other kinds.
    pub successor: &'a AuthenticatedCredentialV1,
}

struct DecodedRefresh {
    core: KagemushaWalletStateCoreV1,
    rest: KagemushaWalletStateRestV1,
    effect: KagemushaWalletEffectV1,
    projection: RefreshUpdateWitness,
    objects: [Vec<u8>; 2],
    blacklist: Option<IndexedInsert<Fp>>,
    quota: Option<native::QuotaInput>,
}

fn word(bytes: [u8; 32]) -> Result<Fp, Error> {
    Option::<Fp>::from(Fp::from_repr(bytes)).ok_or(Error::Authority)
}

fn limbs(bytes: &[u8; 32]) -> [Fp; 2] {
    core::array::from_fn(|i| {
        let mut limb = [0; 16];
        limb.copy_from_slice(&bytes[i * 16..(i + 1) * 16]);
        Fp::from_u128(u128::from_le_bytes(limb))
    })
}

fn projection(kind: RefreshKind, digest: [u8; 32]) -> Result<RefreshUpdateWitness, Error> {
    Ok(RefreshUpdateWitness {
        kind,
        digest: word(digest)?,
        scheme: [Fp::ZERO; 2],
        asset: [Fp::ZERO; 2],
        wallet: [Fp::ZERO; 2],
        counter: Fp::ZERO,
        issued_at_ms: Fp::ZERO,
        expires_at_ms: Fp::ZERO,
        root: Fp::ZERO,
        controls: Fp::ZERO,
        fee_schedule: Fp::ZERO,
    })
}

fn certificates(
    original: &[u8],
    scheme: &KagemushaWalletSchemeV1,
) -> Result<KagemushaWalletCertificateSetV1, Error> {
    if original.is_empty() || original.len() > KAGEMUSHA_WALLET_MESSAGE_MAX_BYTES_V1 {
        return Err(Error::Authority);
    }
    let set: KagemushaWalletCertificateSetV1 = norito::decode_canonical_with_limits(
        original,
        norito::canonical_decode_limits(original.len()),
    )
    .map_err(|_| Error::Authority)?;
    authority(set.verify(scheme))?;
    Ok(set)
}

fn finish(
    changed: &KagemushaWalletPolicyRefreshV1,
    projection: &RefreshUpdateWitness,
    certificate: &KagemushaWalletSignerCertificateV1,
    tape: Vec<u8>,
    blacklist: Option<IndexedInsert<Fp>>,
) -> DecodedRefresh {
    DecodedRefresh {
        core: changed.core,
        rest: changed.rest,
        effect: changed.effect,
        projection: *projection,
        objects: [
            signed_tape(certificate.body.transcript(), &certificate.signature),
            tape,
        ],
        blacklist,
        quota: None,
    }
}

struct UpdateSource<'a> {
    scheme: &'a KagemushaWalletSchemeV1,
    current: &'a KagemushaWalletCredentialV1,
    successor: &'a KagemushaWalletCredentialV1,
    state: &'a KagemushaWalletStateV1,
    original: &'a [u8],
    certificates: &'a KagemushaWalletCertificateSetV1,
    openings: &'a [Vec<u8>],
}

fn credential_update(source: &UpdateSource<'_>) -> Result<DecodedRefresh, Error> {
    let scheme = source.scheme;
    let scheme_id = scheme.scheme_id();
    let original = source.original;
    let set = source.certificates;
    let current = source.current;
    let successor = source.successor;
    let update = authority(KagemushaWalletCredentialV1::decode_canonical(
        original, &scheme_id,
    ))?;
    if update != *successor {
        return Err(Error::Authority);
    }
    let certificate =
        authority(set.certificate(&update.body.issuer_certificate, Role::Enrollment))?;
    authority(update.verify(scheme, certificate))?;
    let changed = authority(source.state.refresh_policy(
        KagemushaWalletPolicyUpdateV1::Credential {
            previous: current,
            replacement: &update,
        },
    ))?;
    let mut values = projection(RefreshKind::Credential, update.credential_digest())?;
    values.issued_at_ms = Fp::from(update.body.issued_at_ms);
    values.expires_at_ms = Fp::from(update.body.lease_expires_at_ms);
    Ok(finish(
        &changed,
        &values,
        certificate,
        signed_tape(update.body.transcript(), &update.signature),
        None,
    ))
}

fn scheme_policy_update(source: &UpdateSource<'_>) -> Result<DecodedRefresh, Error> {
    let scheme = source.scheme;
    let scheme_id = scheme.scheme_id();
    let original = source.original;
    let set = source.certificates;
    let update = authority(KagemushaWalletSchemePolicyV1::decode_canonical(
        original, &scheme_id,
    ))?;
    let certificate =
        authority(set.certificate(&update.body.signer_certificate, Role::RegulatoryPolicy))?;
    authority(update.verify(scheme, certificate))?;
    let changed = authority(
        source
            .state
            .refresh_policy(KagemushaWalletPolicyUpdateV1::SchemePolicy { policy: &update }),
    )?;
    let mut values = projection(RefreshKind::SchemePolicy, update.scheme_policy_digest())?;
    values.scheme = limbs(&update.body.scheme_id);
    values.asset = limbs(&update.body.asset_digest);
    values.counter = Fp::from(update.body.policy_epoch);
    values.controls = Fp::from(u64::from(update.body.enabled_controls));
    values.fee_schedule = word(update.body.fee_schedule)?;
    Ok(finish(
        &changed,
        &values,
        certificate,
        signed_tape(update.body.transcript(), &update.signature),
        None,
    ))
}

fn blacklist_update(source: &UpdateSource<'_>) -> Result<DecodedRefresh, Error> {
    let scheme = source.scheme;
    let scheme_id = scheme.scheme_id();
    let original = source.original;
    let set = source.certificates;
    let update = authority(KagemushaWalletBlacklistV1::decode_canonical(
        original, &scheme_id,
    ))?;
    let certificate =
        authority(set.certificate(&update.body.signer_certificate, Role::RegulatoryPolicy))?;
    authority(update.verify(scheme, certificate))?;
    let history = retained_insertion(source.openings)?;
    let changed = authority(source.state.refresh_policy(
        KagemushaWalletPolicyUpdateV1::Blacklist {
            list: &update,
            history: &history,
        },
    ))?;
    let mut values = projection(RefreshKind::Blacklist, update.blacklist_digest())?;
    values.scheme = limbs(&update.body.scheme_id);
    values.counter = Fp::from(update.body.list_version);
    values.issued_at_ms = Fp::from(update.body.issued_at_ms);
    values.root = word(update.body.entries_root)?;
    Ok(finish(
        &changed,
        &values,
        certificate,
        signed_tape(update.body.transcript(), &update.signature),
        Some(super::monetary::insertion(&history)?),
    ))
}

fn time_anchor_update(source: &UpdateSource<'_>) -> Result<DecodedRefresh, Error> {
    let scheme = source.scheme;
    let scheme_id = scheme.scheme_id();
    let original = source.original;
    let set = source.certificates;
    let update = authority(KagemushaWalletTimeAnchorV1::decode_canonical(
        original, &scheme_id,
    ))?;
    let certificate =
        authority(set.certificate(&update.body.signer_certificate, Role::TimeAnchor))?;
    authority(update.verify(scheme, certificate))?;
    let changed = authority(
        source
            .state
            .refresh_policy(KagemushaWalletPolicyUpdateV1::TimeAnchor { anchor: &update }),
    )?;
    let mut values = projection(RefreshKind::TimeAnchor, update.time_anchor_digest())?;
    values.scheme = limbs(&update.body.scheme_id);
    values.wallet = limbs(&update.body.wallet_id);
    values.issued_at_ms = Fp::from(update.body.issuer_time_ms);
    Ok(finish(
        &changed,
        &values,
        certificate,
        signed_tape(update.body.transcript(), &update.signature),
        None,
    ))
}

fn quota_update(
    source: &UpdateSource<'_>,
    retained: &KagemushaWalletQuotaRefreshWitnessV1,
) -> Result<DecodedRefresh, Error> {
    let update = authority(KagemushaWalletQuotaShareV1::decode_canonical(
        source.original,
        &source.scheme.scheme_id(),
    ))?;
    let certificate = authority(
        source
            .certificates
            .certificate(&update.body.signer_certificate, Role::RegulatoryPolicy),
    )?;
    authority(update.verify(source.scheme, certificate))?;
    let usage = authority(retained.usage())?;
    // The model authenticates the complete retained array against the actual
    // predecessor root before deriving every successor slot and policy effect.
    let changed = authority(source.state.refresh_policy(
        KagemushaWalletPolicyUpdateV1::QuotaShare {
            share: &update,
            usage: &usage,
        },
    ))?;
    let rebuilt = changed.quota_usage.as_ref().ok_or(Error::Authority)?;
    let mut values = projection(RefreshKind::QuotaShare, update.quota_share_digest())?;
    values.scheme = limbs(&update.body.scheme_id);
    values.asset = limbs(&update.body.asset_digest);
    values.wallet = limbs(&update.body.wallet_id);
    values.counter = Fp::from(update.body.share_id);
    values.issued_at_ms = Fp::from(update.body.issued_at_ms);
    values.expires_at_ms = Fp::from(update.body.expires_at_ms);
    values.root = word(update.body.windows_root)?;
    let mut quota = native::QuotaInput {
        old: [[Fp::ZERO; 4]; 64],
        windows: [[Fp::ZERO; 4]; 64],
        used: [Fp::ZERO; 64],
        issued: values.issued_at_ms,
        window_count: Fp::from(u64::from(update.body.window_count)),
    };
    for (row, slot) in quota.old.iter_mut().zip(usage.slots()) {
        if let Some(leaf) = slot {
            *row = [
                Fp::from(u64::from(leaf.window_kind.tag())),
                Fp::from(leaf.window_start_ms),
                Fp::from(leaf.window_end_ms),
                Fp::from_u128(leaf.used),
            ];
        }
    }
    for (row, window) in quota.windows.iter_mut().zip(&update.windows) {
        *row = [
            Fp::from(u64::from(window.kind.tag())),
            Fp::from(window.start_ms),
            Fp::from(window.end_ms),
            Fp::from_u128(window.limit),
        ];
    }
    for (used, slot) in quota.used.iter_mut().zip(rebuilt.slots()) {
        *used = slot
            .as_ref()
            .map_or(Fp::ZERO, |leaf| Fp::from_u128(leaf.used));
    }
    let mut decoded = finish(
        &changed,
        &values,
        certificate,
        signed_tape(update.body.transcript(), &update.signature),
        None,
    );
    decoded.quota = Some(quota);
    Ok(decoded)
}

/// Authenticate the statement-selected original update and derive every permitted
/// policy effect from the actual predecessor. No caller supplies update projections.
fn decode_update(
    scheme: &KagemushaWalletSchemeV1,
    current: &KagemushaWalletCredentialV1,
    successor: &KagemushaWalletCredentialV1,
    source: &KagemushaWalletStateV1,
    capsule: &KagemushaWalletRecoveryCapsuleV1,
    original_update: &[u8],
) -> Result<DecodedRefresh, Error> {
    let KagemushaWalletEffectV1::RefreshPolicy { update_kind, .. } = capsule.statement.effect
    else {
        return Err(Error::Authority);
    };
    if capsule.kind != KagemushaWalletOperationKindV1::RefreshPolicy {
        return Err(Error::Authority);
    }
    // The capsule decoder owns duplicate/operation-specific quota-role checks.
    let _ = authority(capsule.quota_refresh_witness())?;
    let update = retained_original(
        &capsule.retained_inputs,
        KagemushaWalletRetainedInputRoleV1::PolicyUpdate,
    )?;
    crate::kagemusha_wallet_state_v1::verify_policy_update_original(
        update_kind,
        &scheme.scheme_id(),
        update,
        original_update,
    )
    .map_err(|_| Error::Authority)?;
    let certificates = retained_original(
        &capsule.retained_inputs,
        KagemushaWalletRetainedInputRoleV1::CertificateSet,
    )?;
    let quota = capsule
        .retained_inputs
        .iter()
        .find(|original| original.role == KagemushaWalletRetainedInputRoleV1::QuotaRefreshWitness);
    let decoded = decode_originals(
        scheme,
        current,
        successor,
        source,
        RefreshOriginalsV1 {
            kind: update_kind,
            update: original_update,
            certificates,
            openings: &capsule.map_openings,
            quota: quota.map(|original| original.bytes.as_slice()),
        },
    )?;
    if decoded.effect != capsule.statement.effect {
        return Err(Error::Authority);
    }
    Ok(decoded)
}

fn decode_originals(
    scheme: &KagemushaWalletSchemeV1,
    current: &KagemushaWalletCredentialV1,
    successor: &KagemushaWalletCredentialV1,
    source: &KagemushaWalletStateV1,
    originals: RefreshOriginalsV1<'_>,
) -> Result<DecodedRefresh, Error> {
    use KagemushaWalletPolicyUpdateKindV1 as Kind;
    authority(source.validate_for_credential(current))?;
    if originals.kind != Kind::Credential && current != successor {
        return Err(Error::Authority);
    }
    if originals.kind != Kind::Blacklist {
        no_map_openings(originals.openings)?;
    }
    let quota = match (originals.kind == Kind::QuotaShare, originals.quota) {
        (true, Some(original)) => Some(authority(
            KagemushaWalletQuotaRefreshWitnessV1::decode_canonical(original),
        )?),
        (false, None) => None,
        _ => return Err(Error::Authority),
    };
    let set = certificates(originals.certificates, scheme)?;
    let source = UpdateSource {
        scheme,
        current,
        successor,
        state: source,
        original: originals.update,
        certificates: &set,
        openings: originals.openings,
    };
    match originals.kind {
        Kind::Credential => credential_update(&source),
        Kind::SchemePolicy => scheme_policy_update(&source),
        Kind::Blacklist => blacklist_update(&source),
        Kind::TimeAnchor => time_anchor_update(&source),
        Kind::QuotaShare => quota_update(&source, quota.as_ref().ok_or(Error::Authority)?),
    }
}

fn exact_successor(
    source: &KagemushaWalletStateV1,
    successor: &KagemushaWalletStateV1,
    update: &DecodedRefresh,
) -> Result<(), Error> {
    let mut core = update.core;
    core.sequence = source
        .core
        .sequence
        .checked_add(1)
        .ok_or(Error::Authority)?;
    core.state_nonce = successor.core.state_nonce;
    let expected = KagemushaWalletStateV1 {
        version: source.version,
        core,
        rest: update.rest,
    };
    authority(expected.validate())?;
    if expected != *successor {
        return Err(Error::Authority);
    }
    Ok(())
}

/// Verified original field projection; Q proofs remain mandatory independent inputs.
pub(crate) struct RefreshFoldFieldsV1 {
    pub(crate) state: RefreshWitness,
    pub(crate) sigma: Vec<u8>,
    pub(crate) objects: [Vec<u8>; 5],
    pub(crate) blacklist: Option<IndexedInsert<Fp>>,
    pub(crate) quota: Option<native::QuotaInput>,
    pub(crate) predecessor: native::PredecessorInput,
}
impl RefreshFoldFieldsV1 {
    pub(crate) fn with_q(self, q: [native::QInput; 3]) -> native::Inputs {
        native::Inputs {
            state: self.state,
            sigma: self.sigma,
            objects: self.objects,
            blacklist: self.blacklist,
            quota: self.quota,
            predecessor: self.predecessor,
            q,
        }
    }
}

impl PreparationV1<'_> {
    /// Prepare every Refresh kind from its exact retained original custody.
    /// Native resolves the complete original through its coordinator/archive
    /// capability before calling this pure proof converter. Storage errors keep
    /// their original retry/loss classification outside this proof-only boundary.
    /// Credential renewal uses distinct owners; the other kinds require identical
    /// owners. Quota usage is rebuilt only from its retained authenticated predecessor array.
    /// Original Q proofs remain untrusted until the fixed native plan and all mandatory
    /// A/W owners verify them. This conversion grants no artifact or wallet-open authority.
    ///
    /// # Errors
    /// Changed source/owner/effect, missing or duplicate original,
    /// bad issuer role/signature, invalid renewal, changed unrelated state or history path.
    pub fn refresh_native_inputs(
        &self,
        owners: RefreshOwnersV1<'_>,
        step: &ReleasedStep,
        predecessor: &FoldedStateV1,
        public: &KagemushaWalletLineagePublicV1,
        original_update: &[u8],
        q: [native::QInput; 3],
        budget: MemoryBudget,
    ) -> Result<native::Inputs, Error> {
        self.refresh_fold_fields(owners, step, predecessor, public, original_update, budget)
            .map(|fields| fields.with_q(q))
    }

    /// Reconstruct the exact native source before its independent Q proofs exist.
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn refresh_fold_fields(
        &self,
        owners: RefreshOwnersV1<'_>,
        step: &ReleasedStep,
        predecessor: &FoldedStateV1,
        public: &KagemushaWalletLineagePublicV1,
        original_update: &[u8],
        budget: MemoryBudget,
    ) -> Result<RefreshFoldFieldsV1, Error> {
        self.credential_owner(owners.current)?;
        self.credential_owner(owners.successor)?;
        let capsule = &step.frozen.capsule;
        if predecessor.manifest_digest != self.installed.verifier().manifest_digest()
            || predecessor.source_capsule_digest != capsule.predecessor_capsule_digest
            || predecessor.credential != owners.current.credential
        {
            return Err(Error::Authority);
        }
        authority(
            capsule
                .statement
                .validate_successor_of(&predecessor.source_statement),
        )?;
        let decoded = decode_update(
            self.installed.verifier().scheme(),
            &owners.current.credential,
            &owners.successor.credential,
            &predecessor.source_state,
            capsule,
            original_update,
        )?;
        exact_successor(
            &predecessor.source_state,
            &capsule.successor_state,
            &decoded,
        )?;
        // A renewal preserves payment-key identity; its successor credential is the
        // one selected and signed by Advance. C4 below retains the predecessor owner.
        let receipt = self.receipt_tape(owners.successor, step, budget)?;
        let (successor, statement) = self.successor_fields(
            owners.successor,
            &capsule.successor_state,
            &capsule.statement,
            public,
        )?;
        let [certificate, update] = decoded.objects;
        Ok(RefreshFoldFieldsV1 {
            state: RefreshWitness {
                predecessor: predecessor.witness,
                successor,
                statement,
                update: decoded.projection,
            },
            sigma: capsule.step_proof.bytes.clone(),
            objects: [
                certificate,
                update,
                receipt,
                owners.current.certificate_tape.clone(),
                owners.current.credential_tape.clone(),
            ],
            blacklist: decoded.blacklist,
            quota: decoded.quota,
            predecessor: native::PredecessorInput {
                proof: predecessor.proof.clone(),
                pallas: predecessor.pallas,
                vesta: predecessor.vesta,
            },
        })
    }
}

#[cfg(test)]
#[path = "refresh/tests.rs"]
mod tests;
