//! Exact Q-source qualification under a source-qualified sigma catalog.

#[path = "q/session.rs"]
mod session;
pub use session::QQualificationProgressV1;
#[cfg(test)]
pub(crate) use session::{
    assert_builtin_signature_reuse_controls, assert_signature_reuse_controls,
};

use iroha_kagemusha_proof::{
    a_relation::native::artifact::{ArtifactError, KeyArtifact},
    a_relation::{
        archive::authorization::ArchiveAuthorizationObjects, own::OwnPolicy,
        receive::ReceiveStagePlan, refresh::RefreshStagePlan,
    },
    q_sigma::{
        QSigmaPlan, SigmaClass,
        native::{QSigmaError, QSigmaProver, QSigmaProverView, QSigmaSource},
    },
    q_signature::{
        QSignaturePlan, SignatureKey, SignatureSlot,
        native::{QSignatureError, QSignatureProver, QSignatureProverView},
    },
};
use iroha_plonk::{
    frontend::Error as LayoutError, keys::pk::artifact::ReadConfig, pcs::ipa::PinnedParams,
};
use iroha_plonk_gadgets::p256::{VerifyMode, native::Affine};
use iroha_plonk_recursion::verifier::VerifierPlan;

use super::recipe::InstalledSourceSealV1;
use super::*;

/// A Q original did not match its authenticated source, scope or bounded input.
#[derive(Debug, thiserror::Error)]
pub enum QQualificationErrorV1 {
    /// Another installation, missing inventory entry or bounded read failure.
    #[error(transparent)]
    Original(#[from] Error),
    /// The fixed source plan could not be reconstructed.
    #[error("invalid compiled Q source plan")]
    Source,
    /// Exact sigma-Q source import failed.
    #[error(transparent)]
    Sigma(#[from] QSigmaError),
    /// Exact signature-Q source import failed.
    #[error(transparent)]
    Signature(#[from] QSignatureError),
    /// Imported descriptor and complete key identity differ.
    #[error(transparent)]
    Metadata(#[from] ArtifactError),
}

/// Unauthenticated Q source metadata shared by offline construction and intake.
/// A descriptor/key match is not source qualification or a wallet capability.
#[derive(Clone, Debug)]
pub struct QProgramRecipeV1 {
    sigma: Option<QSigmaPlan>,
    signatures: Vec<QSignaturePlan>,
    keys: Vec<KeyArtifact<Ep>>,
}
impl QProgramRecipeV1 {
    /// Assemble exact ordered Q metadata; original source qualification is separate.
    /// A route that verifies no sigma (its A proves the own step directly and it
    /// consumes no incoming sigma) has no sigma source, so its Q leaves are the
    /// signature sources alone.
    /// # Errors
    /// Missing/extra Q source or a different declared public schema.
    pub fn from_metadata(
        sigma: Option<QSigmaPlan>,
        signatures: Vec<QSignaturePlan>,
        keys: Vec<KeyArtifact<Ep>>,
    ) -> Result<Self, QQualificationErrorV1> {
        let offset = usize::from(sigma.is_some());
        if signatures.is_empty() || signatures.len() > 2 || keys.len() != signatures.len() + offset
        {
            return Err(QQualificationErrorV1::Source);
        }
        if let Some(sigma) = &sigma {
            let d = keys[0].binding().descriptor();
            if d.instance_lengths
                .iter()
                .map(|n| *n as usize)
                .collect::<Vec<_>>()
                != sigma.instance_lengths()
                || d.instance_types.as_deref() != Some(&QSigmaPlan::instance_types())
            {
                return Err(QQualificationErrorV1::Source);
            }
        }
        for (key, signature) in keys[offset..].iter().zip(&signatures) {
            let d = key.binding().descriptor();
            if d.instance_lengths
                != [u32::try_from(signature.instance_length())
                    .map_err(|_| QQualificationErrorV1::Source)?]
                || d.instance_types.as_deref() != Some(&QSignaturePlan::instance_types())
            {
                return Err(QQualificationErrorV1::Source);
            }
        }
        Ok(Self {
            sigma,
            signatures,
            keys,
        })
    }
    /// Ordered own/incoming sigma source recipe; absent when the route verifies no sigma.
    pub const fn sigma(&self) -> Option<&QSigmaPlan> {
        self.sigma.as_ref()
    }
    /// Index of the first signature Q: one after `Q_sigma`, or zero without it.
    pub const fn signature_offset(&self) -> usize {
        if self.sigma.is_some() { 1 } else { 0 }
    }
    /// Exact signature policies, after any `Q_sigma`.
    pub fn signatures(&self) -> &[QSignaturePlan] {
        &self.signatures
    }
    /// Candidate exact Q verifiers, in Q0, Q1, ... order.
    pub fn keys(&self) -> &[KeyArtifact<Ep>] {
        &self.keys
    }
}

/// One program's source-qualified Q metadata, without any retained proving key.
/// A/W/context/terminal qualification is still required for this same program.
#[derive(Clone, Debug)]
pub struct QualifiedQProgramV1 {
    program: u32,
    installation: ([u8; 32], [u8; 32]),
    recipe: QProgramRecipeV1,
    seals: Box<[InstalledSourceSealV1<Ep>]>,
}
impl QualifiedQProgramV1 {
    /// Exact authenticated installation and program index.
    pub const fn identity(&self) -> (([u8; 32], [u8; 32]), u32) {
        (self.installation, self.program)
    }
    /// Complete ordered own/incoming sigma classes from the qualified sigma keys;
    /// absent when the route verifies no sigma.
    pub const fn sigma(&self) -> Option<&QSigmaPlan> {
        self.recipe.sigma()
    }
    /// Index of the first signature Q.
    pub const fn signature_offset(&self) -> usize {
        self.recipe.signature_offset()
    }
    /// Exact signature-slot policies, corresponding to Q1 and subsequent leaves.
    pub fn signatures(&self) -> &[QSignaturePlan] {
        self.recipe.signatures()
    }
    /// Exact imported keys in Q0, Q1, ... order, with no PK backreferences.
    pub fn keys(&self) -> &[KeyArtifact<Ep>] {
        self.recipe.keys()
    }
    /// Bind the selected member before the wallet revalidates its originals.
    /// No source file is opened and no public source graph is cloned here.
    pub(super) fn borrow_cancellable<'a>(
        &'a self,
        stage: usize,
        expected_member: u32,
        params: &'a PinnedParams<Ep>,
        cancellation: Option<&iroha_pasta::CancellationToken>,
    ) -> Result<ImportedQV1<'a>, QQualificationErrorV1> {
        let seal = self.seals.get(stage).ok_or(Error::Inventory)?;
        let key = self.keys().get(stage).ok_or(Error::Inventory)?;
        let view = seal.bind(expected_member, key, cancellation)?;
        let offset = self.signature_offset();
        Ok(match self.sigma() {
            Some(sigma) if stage < offset => ImportedQV1::Sigma(
                QSigmaProverView::from_source_bound(params, view, sigma, Some(2))?,
            ),
            _ => {
                let plan = self
                    .signatures()
                    .get(stage.checked_sub(offset).ok_or(Error::Inventory)?)
                    .ok_or(Error::Inventory)?;
                ImportedQV1::Signature(QSignatureProverView::from_source_bound(plan, params, view)?)
            }
        })
    }
    pub(super) const fn recipe(&self) -> &QProgramRecipeV1 {
        &self.recipe
    }
}

fn signature_plans(
    variant: Variant,
    policy: OwnPolicy,
    root: Affine,
) -> Result<Vec<QSignaturePlan>, LayoutError> {
    let hard = |variables: usize, fixed: bool| {
        let mut slots = vec![
            SignatureSlot {
                mode: VerifyMode::Hard,
                key: SignatureKey::Variable
            };
            variables
        ];
        if fixed {
            slots.push(SignatureSlot {
                mode: VerifyMode::Hard,
                key: SignatureKey::Fixed(root),
            });
        }
        QSignaturePlan::new(slots)
    };
    match variant {
        Variant::Bootstrap => Ok(vec![hard(2, true)?]),
        // Lean lineage: the own receipt is the only signature leaf; the credential
        // and certificate are carried by continuity.
        Variant::Load | Variant::Send | Variant::Unload | Variant::Retiring => {
            Ok(vec![hard(1, false)?])
        }
        // Lean lineage: one merged leaf, the own receipt hard and every incoming slot soft.
        Variant::Receive | Variant::ReceiveRenewed => {
            Ok(vec![ReceiveStagePlan::signature_schema_for(
                variant, policy,
            )?])
        }
        // Lean lineage: one merged leaf, the own receipt hard and the incoming receipt soft.
        Variant::ArchiveReceive | Variant::ArchiveStatus => {
            Ok(vec![ArchiveAuthorizationObjects::signature_schema()?])
        }
        Variant::RefreshCredential
        | Variant::RefreshSchemePolicy
        | Variant::RefreshTimeAnchor
        | Variant::RefreshQuotaShare => Ok(RefreshStagePlan::signature_schemas(policy)?.to_vec()),
    }
}

fn sigma_class(
    selectors: &[u8],
    sigmas: &[KeyArtifact<Eq>; 11],
    parameters: &impl Fn(u32) -> Result<PinnedParams<Eq>, QQualificationErrorV1>,
) -> Result<(SigmaClass, VerifyingKey<Eq>), QQualificationErrorV1> {
    let first = selectors
        .first()
        .and_then(|selector| sigmas.get(usize::from(*selector)))
        .ok_or(QQualificationErrorV1::Source)?;
    let k = u32::from(first.binding().descriptor().k);
    let params = parameters(k)?;
    if params.k() != k {
        return Err(QQualificationErrorV1::Source);
    }
    let verifier = VerifierPlan::new(first.binding().clone(), params)
        .map_err(|_| QQualificationErrorV1::Source)?;
    let mut entries = Vec::with_capacity(selectors.len());
    for selector in selectors {
        let key = sigmas
            .get(usize::from(*selector))
            .ok_or(QQualificationErrorV1::Source)?;
        if key.binding() != first.binding() {
            return Err(QQualificationErrorV1::Source);
        }
        let digest = key
            .key()
            .kagemusha_digest(key.binding())
            .map_err(|_| QQualificationErrorV1::Source)?;
        entries.push((*selector, digest));
    }
    Ok((
        SigmaClass::new(verifier, entries).map_err(|_| QQualificationErrorV1::Source)?,
        first.key().clone(),
    ))
}

/// Reconstruct the fixed Q sources from raw exact metadata and compiled scope.
/// This offline recipe grants no authenticated installation or proving capability.
/// # Errors
/// A foreign, repeated, unordered or incompatible selector class, wrong incoming
/// arity, invalid scope, or an incompatible source descriptor is rejected.
pub fn q_source_recipe(
    scope: SourceScopeV1,
    variant: Variant,
    own_class: &[u8],
    incoming_class: &[u8],
    sigmas: &[KeyArtifact<Eq>; 11],
) -> Result<(Option<QSigmaSource>, Vec<QSignaturePlan>), QQualificationErrorV1> {
    q_source_recipe_with_parameters(scope, variant, own_class, incoming_class, sigmas, &|k| {
        PinnedParams::derive(k).map_err(|_| QQualificationErrorV1::Source)
    })
}

pub(super) fn q_source_recipe_with_parameters(
    scope: SourceScopeV1,
    variant: Variant,
    own_class: &[u8],
    incoming_class: &[u8],
    sigmas: &[KeyArtifact<Eq>; 11],
    parameters: &impl Fn(u32) -> Result<PinnedParams<Eq>, QQualificationErrorV1>,
) -> Result<(Option<QSigmaSource>, Vec<QSignaturePlan>), QQualificationErrorV1> {
    selectors(own_class, false)?;
    selectors(incoming_class, true)?;
    let allowed: Vec<_> = compiled_routes()
        .into_iter()
        .filter(|route| route.variant == variant)
        .collect();
    if own_class
        .iter()
        .any(|selector| !allowed.iter().any(|r| r.own == *selector))
        || incoming_class
            .iter()
            .any(|selector| !allowed.iter().any(|r| r.incoming == Some(*selector)))
        || incoming_class.is_empty() != allowed.iter().all(|r| r.incoming.is_none())
    {
        return Err(QQualificationErrorV1::Source);
    }
    let signatures = signature_plans(variant, scope.own()?, scope.root())
        .map_err(|_| QQualificationErrorV1::Source)?;
    if iroha_kagemusha_proof::a_relation::schedule::proves_own_step_inline(variant) {
        // A proves the own step directly: the own class names the payment-path
        // sigma only, and no Q verifies it. A route that consumes an incoming
        // sigma keeps an incoming-only Q_sigma for it.
        if incoming_class.is_empty() {
            return Ok((None, signatures));
        }
        let (incoming, incoming_key) = sigma_class(incoming_class, sigmas, parameters)?;
        let vesta = parameters(16)?;
        if vesta.k() != 16 {
            return Err(QQualificationErrorV1::Source);
        }
        let sigma = QSigmaPlan::incoming_only(incoming, &vesta)
            .map_err(|_| QQualificationErrorV1::Source)?;
        return Ok((
            Some(QSigmaSource::incoming_only(sigma, incoming_key)?),
            signatures,
        ));
    }
    let (own, own_key) = sigma_class(own_class, sigmas, parameters)?;
    let incoming = if incoming_class.is_empty() {
        None
    } else {
        Some(sigma_class(incoming_class, sigmas, parameters)?)
    };
    let (incoming, incoming_key) = match incoming {
        Some((class, key)) => (Some(class), Some(key)),
        None => (None, None),
    };
    let vesta = parameters(16)?;
    if vesta.k() != 16 {
        return Err(QQualificationErrorV1::Source);
    }
    let sigma =
        QSigmaPlan::new(own, incoming, &vesta).map_err(|_| QQualificationErrorV1::Source)?;
    Ok((
        Some(QSigmaSource::new(sigma, own_key, incoming_key)?),
        signatures,
    ))
}

// The installation-bound qualifier alone can turn this raw recipe into a grant.
pub(super) fn source(
    record: &OperationV1,
    scheme: &KagemushaWalletSchemeV1,
    sigmas: &[KeyArtifact<Eq>; 11],
    parameters: &impl Fn(u32) -> Result<PinnedParams<Eq>, QQualificationErrorV1>,
) -> Result<(Option<QSigmaSource>, Vec<QSignaturePlan>), QQualificationErrorV1> {
    let result = q_source_recipe_with_parameters(
        SourceScopeV1::from_scheme(scheme)?,
        variant(record.variant)?,
        &record.own_class,
        &record.incoming_class,
        sigmas,
        parameters,
    )?;
    if record.q.len() != result.1.len() + usize::from(result.0.is_some()) {
        return Err(Error::Inventory.into());
    }
    Ok(result)
}

/// One borrowed, already qualified Q source after current original custody checks.
pub enum ImportedQV1<'a> {
    /// Q0 with its exact own/incoming source and selected serialized profile.
    Sigma(QSigmaProverView<'a>),
    /// Q1 or later with its installed hard/soft signature policy.
    Signature(QSignatureProverView<'a>),
}
impl ImportedQV1<'_> {
    /// Exact borrowed descriptor, including its current row bound.
    pub fn binding(&self) -> &DescriptorBinding {
        match self {
            Self::Sigma(p) => p.binding(),
            Self::Signature(p) => p.binding(),
        }
    }
}

// Temporary standalone owners exist only during complete typed qualification.
enum StrictImportedQ {
    Sigma(Box<QSigmaProver>),
    Signature(Box<QSignatureProver>),
}
impl StrictImportedQ {
    fn into_metadata(self) -> iroha_plonk::keys::SourceBoundVerifyingKeyV2<Ep> {
        match self {
            Self::Sigma(p) => (*p).into_metadata(),
            Self::Signature(p) => (*p).into_metadata(),
        }
    }
}

fn import_with_admission(
    index: usize,
    source: Option<&QSigmaSource>,
    signatures: &[QSignaturePlan],
    bytes: &OriginalBytesV1,
    pallas: &PinnedParams<Ep>,
    config: ReadConfig,
    member: Option<iroha_plonk::keys::BuiltinSourceMemberV1>,
    cancellation: Option<&iroha_pasta::CancellationToken>,
) -> Result<StrictImportedQ, QQualificationErrorV1> {
    iroha_pasta::CancellationToken::checkpoint(cancellation).map_err(|_| Error::Cancelled)?;
    let offset = usize::from(source.is_some());
    Ok(if let Some(source) = source.filter(|_| index < offset) {
        StrictImportedQ::Sigma(Box::new(match member {
            Some(member) => {
                QSigmaProver::from_builtin_original_artifact_serialized_foreign_cancellable(
                    source,
                    pallas.clone(),
                    &bytes.descriptor,
                    &bytes.verifying_key,
                    &bytes.proving_key,
                    config,
                    2,
                    member,
                    cancellation,
                )?
            }
            None => QSigmaProver::from_original_artifact_serialized_foreign_cancellable(
                source,
                pallas.clone(),
                &bytes.descriptor,
                &bytes.verifying_key,
                &bytes.proving_key,
                config,
                2,
                cancellation,
            )?,
        }))
    } else {
        let plan = signatures
            .get(index.checked_sub(offset).ok_or(Error::Inventory)?)
            .ok_or(Error::Inventory)?
            .clone();
        StrictImportedQ::Signature(Box::new(match member {
            Some(member) => QSignatureProver::from_builtin_original_artifact_cancellable(
                plan,
                pallas.clone(),
                &bytes.descriptor,
                &bytes.verifying_key,
                &bytes.proving_key,
                config,
                member,
                cancellation,
            )?,
            None => QSignatureProver::from_original_artifact_cancellable(
                plan,
                pallas.clone(),
                &bytes.descriptor,
                &bytes.verifying_key,
                &bytes.proving_key,
                config,
                cancellation,
            )?,
        }))
    })
}

impl AuthenticatedProducerInventoryV1 {
    /// Strictly reconstruct and import one program's Q originals from the same
    /// installed scheme/root and already-qualified eleven sigma sources.
    /// Only metadata survives each import. No context, A/W or wallet grant follows.
    /// # Errors
    /// Another installation, mixed descriptor class, changed selector/root/slot plan,
    /// missing original, bounded read failure, or any exact source import refusal.
    pub fn qualify_q_program(
        &self,
        installed: &InstalledVerifierPackV1,
        sigmas: &QualifiedSigmasV1,
        program: u32,
        originals: &mut dyn OriginalSourceV1,
        config: ReadConfig,
    ) -> Result<QualifiedQProgramV1, QQualificationErrorV1> {
        self.qualify_q_program_with_admission(
            installed,
            sigmas,
            program,
            originals,
            config,
            super::builtin::Admission::Strict,
        )
    }

    pub(super) fn qualify_q_program_with_admission(
        &self,
        installed: &InstalledVerifierPackV1,
        sigmas: &QualifiedSigmasV1,
        program: u32,
        originals: &mut dyn OriginalSourceV1,
        config: ReadConfig,
        admission: super::builtin::Admission<'_>,
    ) -> Result<QualifiedQProgramV1, QQualificationErrorV1> {
        let scheme = installed.verifier().scheme();
        let identity = (scheme.scheme_id(), installed.verifier().manifest_digest());
        if identity != self.installation() || identity != sigmas.installation() {
            return Err(Error::Authority.into());
        }
        let record = self
            .inventory
            .operations
            .get(usize::try_from(program).map_err(|_| Error::Inventory)?)
            .ok_or(Error::Inventory)?;
        let (source, signatures) = source(record, scheme, sigmas.metadata(), &|k| {
            Ok(installed.verifier().vesta_parameters(k)?.as_ref().clone())
        })?;
        let pallas = installed.verifier().pallas_parameters().as_ref().clone();
        let mut keys = Vec::with_capacity(record.q.len());
        let mut seals = Vec::with_capacity(record.q.len());
        for (index, original) in record.q.iter().copied().enumerate() {
            let bytes = self.read_original(original, originals, config.maximum_bytes)?;
            let metadata = import_with_admission(
                index,
                source.as_ref(),
                &signatures,
                &bytes,
                &pallas,
                config,
                admission.member(&[
                    2,
                    program,
                    u32::try_from(index).map_err(|_| Error::Inventory)?,
                ])?,
                None,
            )?
            .into_metadata();
            let (binding, key, seal) = metadata.into_parts();
            drop(bytes);
            keys.push(KeyArtifact::new(binding, key)?);
            seals.push(InstalledSourceSealV1::new(original, seal));
        }
        Ok(QualifiedQProgramV1 {
            program,
            installation: identity,
            recipe: QProgramRecipeV1::from_metadata(
                source.as_ref().map(|source| source.plan().clone()),
                signatures,
                keys,
            )?,
            seals: seals.into_boxed_slice(),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn signature_recipes_cover_every_compiled_q_slot_and_fixed_root() {
        use iroha_kagemusha_proof::a_relation::schedule::proves_own_step_inline;
        let root = Affine::GENERATOR;
        let policy = OwnPolicy::new([1, 2], root).unwrap();
        for variant in Variant::ALL {
            let plans = signature_plans(variant, policy, root).unwrap();
            let expected = OperationSchedule::for_variant(variant)
                .q_partitions()
                .iter()
                .flatten()
                .count();
            // A `Q_sigma` exists iff the route verifies an own sigma (Refresh) or
            // consumes an incoming one (Receive and `ArchiveReceive`).
            let incoming = matches!(
                variant,
                Variant::Receive | Variant::ReceiveRenewed | Variant::ArchiveReceive
            );
            let sigma = usize::from(!proves_own_step_inline(variant) || incoming);
            assert_eq!(plans.len() + sigma, expected, "{variant:?}");
            // Merged leaves keep the own receipt hard in slot 0 and every incoming
            // slot soft; every other leaf is entirely hard.
            let merged = incoming || variant == Variant::ArchiveStatus;
            for plan in &plans {
                for (index, slot) in plan.slots().iter().enumerate() {
                    if let SignatureKey::Fixed(point) = slot.key {
                        assert_eq!(point, root);
                    }
                    assert_eq!(
                        slot.mode,
                        if merged && index > 0 {
                            VerifyMode::Soft
                        } else {
                            VerifyMode::Hard
                        },
                        "{variant:?}"
                    );
                }
            }
            let changed = signature_plans(
                variant,
                OwnPolicy::new([1, 2], root.neg()).unwrap(),
                root.neg(),
            )
            .unwrap();
            // Only a fixed certificate root depends on the policy. Credentials and
            // certificates are checked only at Bootstrap, renewal (the renewed quoted
            // pair) and Refresh; every other route carries them by continuity.
            let fixed = plans
                .iter()
                .flat_map(QSignaturePlan::slots)
                .any(|slot| matches!(slot.key, SignatureKey::Fixed(_)));
            assert_eq!(
                fixed,
                matches!(
                    variant,
                    Variant::Bootstrap
                        | Variant::ReceiveRenewed
                        | Variant::RefreshCredential
                        | Variant::RefreshSchemePolicy
                        | Variant::RefreshQuotaShare
                        | Variant::RefreshTimeAnchor
                ),
                "{variant:?}"
            );
            assert_eq!(
                plans
                    .iter()
                    .zip(changed.iter())
                    .any(|(a, b)| a.slots() != b.slots()),
                fixed,
                "{variant:?}"
            );
        }
        for variant in [
            Variant::Load,
            Variant::Send,
            Variant::Unload,
            Variant::Retiring,
        ] {
            let lean = signature_plans(variant, policy, root).unwrap();
            assert_eq!(
                lean.iter().map(|x| x.slots().len()).collect::<Vec<_>>(),
                [1],
                "{variant:?}"
            );
        }
        for (variant, slots) in [
            (Variant::Receive, 3),
            (Variant::ReceiveRenewed, 5),
            (Variant::ArchiveReceive, 2),
            (Variant::ArchiveStatus, 2),
        ] {
            let merged = signature_plans(variant, policy, root).unwrap();
            assert_eq!(
                merged.iter().map(|x| x.slots().len()).collect::<Vec<_>>(),
                [slots],
                "{variant:?}"
            );
        }
    }
}
