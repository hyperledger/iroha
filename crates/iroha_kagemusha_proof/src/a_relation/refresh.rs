//! Fixed policy-update owners over exact original objects and recursive context.
//!
//! Every kind authenticates both the update and the current credential under
//! direct, purpose-scoped root certificates. State effects, blacklist insertion
//! and the fixed64 quota rebuild consume those same context-bound object fields.
//! The shared tag7 sigma class proves all five state-effect branches under one
//! fixed key. TODO: compose and qualify complete genuine Q/A/W chains before
//! admitting any Refresh terminal key or wallet producer.

use ff::Field;
use iroha_pasta::{Ep, Fp};
use iroha_plonk::frontend::{Error, Region, Value};
use iroha_plonk_gadgets::{GlueChip, UintChip, Word, bytes::tape::BytesChip, p256::VerifyMode};
use iroha_plonk_recursion::{obligation::ledger::Variant, verifier::VerifierChip};

use super::{
    SigmaBindingCells, SignatureQCells,
    context::{ContextInputs, ContextObjectCells, ContextObjectSpec, ContextPlan},
    own::{CurrentAuthorization, OwnPolicy, authenticate_current},
    schedule::OperationTask,
};
use crate::{
    operation_relation::{
        map_effects::{InsertCells, MapEffectsChip, MapState, MapTransition},
        objects::{
            ObjectKind, SignedObjectCells,
            credential::{CredentialAuthorization, CredentialCells},
            issuer::{self, IssuerAuthorization},
            policy::PolicyCells,
            receipt::{self, ReceiptContext},
        },
        quota_refresh::{self, QuotaRebuildCells, QuotaRoot},
        refresh::{self, RefreshUpdate},
    },
    q_signature::{QSignaturePlan, SignatureKey, SignatureSlot},
};

fn update_kind(variant: Variant) -> Result<ObjectKind, Error> {
    match variant {
        Variant::RefreshCredential => Ok(ObjectKind::Credential),
        Variant::RefreshSchemePolicy => Ok(ObjectKind::SchemePolicy),
        Variant::RefreshBlacklist => Ok(ObjectKind::Blacklist),
        Variant::RefreshQuotaShare => Ok(ObjectKind::QuotaShare),
        Variant::RefreshTimeAnchor => Ok(ObjectKind::TimeAnchor),
        _ => Err(Error::Synthesis),
    }
}
fn kinds(variant: Variant) -> Result<[ObjectKind; 5], Error> {
    Ok([
        ObjectKind::Certificate,
        update_kind(variant)?,
        ObjectKind::Receipt,
        ObjectKind::Certificate,
        ObjectKind::Credential,
    ])
}

/// Typed private quota-array commitments shared by every required root/merge owner.
///
/// Array digests use the internal-word context domain with tags7/8/9 and exact
/// counts256/256/64. The context commits these three digests and issue/count as
/// tag6 with five words. Each root opens every array it reads; the merge owner
/// opens all arrays and proves all578-word semantics. Every owner is mandatory.
#[derive(Clone, Debug)]
pub struct QuotaCommitmentCells {
    /// Tag7 digest of all64 old usage leaves, in slot/field order.
    pub previous_usage: Word<Fp>,
    /// Tag8 digest of all64 replacement windows, in slot/field order.
    pub windows: Word<Fp>,
    /// Tag9 digest of all64 successor usage amounts, in slot order.
    pub successor_usage: Word<Fp>,
    /// Signed share issue time, also opened by every quota owner.
    pub issued: Word<Fp>,
    /// Signed share window count, also opened by every quota owner.
    pub window_count: Word<Fp>,
}
impl QuotaCommitmentCells {
    fn words(&self) -> [Word<Fp>; 5] {
        [
            self.previous_usage.clone(),
            self.windows.clone(),
            self.successor_usage.clone(),
            self.issued.clone(),
            self.window_count.clone(),
        ]
    }
}

/// Update certificate, signed update, own receipt, current certificate/credential.
#[derive(Clone, Debug)]
pub struct RefreshObjects {
    variant: Variant,
    objects: Option<[SignedObjectCells; 5]>,
    context: Vec<ContextObjectCells>,
    quota_commitment: Option<QuotaCommitmentCells>,
}
impl RefreshObjects {
    /// Exact object capacities selected only by the circuit-fixed operation kind.
    /// # Errors
    /// Non-refresh variant or impossible fixed size conversion.
    pub fn context_specs(variant: Variant) -> Result<Vec<ContextObjectSpec>, Error> {
        let mut specs = kinds(variant)?
            .into_iter()
            .enumerate()
            .map(|(i, kind)| {
                Ok(ContextObjectSpec {
                    tag: u32::try_from(i + 1).map_err(|_| Error::BoundsFailure)?,
                    capacity: u32::try_from(kind.body_len() + 64)
                        .map_err(|_| Error::BoundsFailure)?,
                })
            })
            .collect::<Result<Vec<_>, Error>>()?;
        if variant == Variant::RefreshQuotaShare {
            specs.push(ContextObjectSpec {
                tag: 6,
                capacity: 160,
            });
        }
        Ok(specs)
    }
    /// Decode each hard own object and retain its original body and signature tape.
    /// # Errors
    /// Wrong fixed kind/length or malformed own object/layout failure.
    pub fn decode(
        chip: &mut VerifierChip<Ep>,
        bytes: &mut BytesChip<Fp>,
        region: &mut Region<'_, Fp>,
        variant: Variant,
        sources: [&[Value<u8>]; 5],
    ) -> Result<Self, Error> {
        let mut objects = Vec::new();
        let mut context = Vec::new();
        for ((kind, source), spec) in kinds(variant)?
            .into_iter()
            .zip(sources)
            .zip(Self::context_specs(variant)?)
        {
            let run = bytes.run(
                region,
                source,
                &kind.primary_segments(),
                &kind.secondary_segments(),
            )?;
            let lanes = chip.operation_lanes()?;
            let object = SignedObjectCells::from_run(
                &mut UintChip::new(lanes.glue, lanes.range),
                lanes.hash,
                region,
                kind,
                &run,
            )?;
            context.push(ContextObjectCells::from_exact_run(
                chip,
                region,
                spec,
                object.digest(),
                &run,
            )?);
            objects.push(object);
        }
        Ok(Self {
            variant,
            objects: Some(objects.try_into().map_err(|_| Error::Synthesis)?),
            context,
            quota_commitment: None,
        })
    }
    /// Whether this stage exclusively owns one or more quota tree roots.
    /// Such stages can retain object proposals; all other stages need originals.
    pub fn quota_root_only(context: &ContextPlan, stage: usize) -> bool {
        context.operation().frame().variant() == Variant::RefreshQuotaShare
            && context.operation_tasks(stage).is_some_and(|tasks| {
                !tasks.is_empty()
                    && tasks.iter().all(|task| {
                        matches!(
                            task,
                            OperationTask::RefreshQuotaPreviousRoot
                                | OperationTask::RefreshQuotaWindowRoot
                                | OperationTask::RefreshQuotaUsageRoot
                        )
                    })
            })
    }

    /// Retain exact context proposals solely for a mandatory quota root owner.
    ///
    /// The auxiliary tuple is recomputed and copy-bound here; each consumed
    /// private array is opened by its root owner. The complete context plan
    /// requires signed-original and merge owners before terminal admission.
    /// This object deliberately cannot supply signed fields or authorization.
    /// # Errors
    /// Non-root stage, incomplete or wrong context schema, mismatched auxiliary
    /// commitment, or layout failure.
    pub fn quota_root_claims(
        chip: &mut VerifierChip<Ep>,
        region: &mut Region<'_, Fp>,
        context: &ContextPlan,
        stage: usize,
        values: &[[Value<Fp>; 3]],
        commitment: &QuotaCommitmentCells,
    ) -> Result<Self, Error> {
        if !Self::quota_root_only(context, stage) {
            return Err(Error::Synthesis);
        }
        let claims = context.assign_quota_object_claims(chip, region, values)?;
        let auxiliary = ContextObjectCells::from_internal_words(
            chip,
            region,
            ContextObjectSpec {
                tag: 6,
                capacity: 160,
            },
            &commitment.words(),
        )?;
        for (actual, expected) in auxiliary
            .commitment_words()
            .iter()
            .zip(claims[5].commitment_words())
        {
            GlueChip::assert_equal(region, actual, &expected)?;
        }
        Ok(Self {
            variant: Variant::RefreshQuotaShare,
            objects: None,
            context: claims,
            quota_commitment: Some(commitment.clone()),
        })
    }

    fn originals(&self) -> Result<&[SignedObjectCells; 5], Error> {
        self.objects.as_ref().ok_or(Error::Synthesis)
    }

    /// Add the proposed exact quota-witness commitment to a quota context.
    ///
    /// The auxiliary object commits three typed array hashes and issue/count.
    /// Every root owner opens the arrays it consumes; the mandatory merge owner
    /// opens all arrays before terminal admission. Signature stages retain the
    /// same five-word proposal without assigning the private arrays.
    /// # Errors
    /// Wrong variant, repeated commitment or context construction failure.
    pub fn with_quota_commitment(
        mut self,
        chip: &mut VerifierChip<Ep>,
        region: &mut Region<'_, Fp>,
        commitment: &QuotaCommitmentCells,
    ) -> Result<Self, Error> {
        if self.variant != Variant::RefreshQuotaShare || self.quota_commitment.is_some() {
            return Err(Error::Synthesis);
        }
        self.context.push(ContextObjectCells::from_internal_words(
            chip,
            region,
            ContextObjectSpec {
                tag: 6,
                capacity: 160,
            },
            &commitment.words(),
        )?);
        self.quota_commitment = Some(commitment.clone());
        Ok(self)
    }

    /// Same-tape signed originals plus the required typed quota proposal, if any.
    pub fn context(&self) -> &[ContextObjectCells] {
        &self.context
    }

    fn bind_quota_witness(
        &self,
        chip: &mut VerifierChip<Ep>,
        region: &mut Region<'_, Fp>,
        witness: &QuotaRebuildCells,
        task: OperationTask,
    ) -> Result<(), Error> {
        let proposed = self.quota_commitment.as_ref().ok_or(Error::Synthesis)?;
        let (old, windows, used) = match task {
            OperationTask::RefreshQuotaMerge => (true, true, true),
            OperationTask::RefreshQuotaPreviousRoot => (true, false, false),
            OperationTask::RefreshQuotaWindowRoot => (false, true, false),
            OperationTask::RefreshQuotaUsageRoot => (false, true, true),
            _ => return Err(Error::Synthesis),
        };
        let mut bind = |tag, words: Vec<Word<Fp>>, expected: &Word<Fp>| {
            let object = ContextObjectCells::from_internal_words(
                chip,
                region,
                ContextObjectSpec {
                    tag,
                    capacity: u32::try_from(words.len() * 32).map_err(|_| Error::BoundsFailure)?,
                },
                &words,
            )?;
            GlueChip::assert_equal(region, object.authenticated_digest(), expected)
        };
        if old {
            bind(
                7,
                witness.old.iter().flatten().cloned().collect(),
                &proposed.previous_usage,
            )?;
        }
        if windows {
            bind(
                8,
                witness.windows.iter().flatten().cloned().collect(),
                &proposed.windows,
            )?;
        }
        if used {
            bind(9, witness.used.to_vec(), &proposed.successor_usage)?;
        }
        GlueChip::assert_equal(region, &witness.issued, &proposed.issued)?;
        GlueChip::assert_equal(region, &witness.window_count, &proposed.window_count)
    }

    fn bind_context(
        &self,
        region: &mut Region<'_, Fp>,
        input: &ContextInputs<'_>,
    ) -> Result<(), Error> {
        if input.own_statement.variant() != self.variant
            || input.objects.len() != Self::context_specs(self.variant)?.len()
            || self.context.len() != input.objects.len()
            || (self.variant == Variant::RefreshQuotaShare) != self.quota_commitment.is_some()
        {
            return Err(Error::Synthesis);
        }
        for (actual, expected) in self.context.iter().zip(input.objects) {
            for (actual, expected) in actual
                .commitment_words()
                .iter()
                .zip(expected.commitment_words())
            {
                GlueChip::assert_equal(region, actual, &expected)?;
            }
        }
        Ok(())
    }

    fn effects(
        &self,
        chip: &mut VerifierChip<Ep>,
        region: &mut Region<'_, Fp>,
        transition: &MapTransition<'_>,
    ) -> Result<(), Error> {
        let lanes = chip.operation_lanes()?;
        let mut uint = UintChip::new(lanes.glue, lanes.range);
        if self.variant == Variant::RefreshCredential {
            let old = CredentialCells::check(&mut uint, region, &self.originals()?[4])?;
            let new = CredentialCells::check(&mut uint, region, &self.originals()?[1])?;
            let valid = new.replacement_of(&mut uint, region, &old)?;
            GlueChip::assert_constant(region, valid.word(), Fp::ONE)?;
            let valid = new.bind_current(
                &mut uint,
                region,
                transition.successor.state,
                transition.successor.lineage,
            )?;
            GlueChip::assert_constant(region, valid.word(), Fp::ONE)?;
            refresh::constrain(
                &mut uint,
                region,
                transition,
                RefreshUpdate::Credential {
                    digest: self.originals()?[1].digest(),
                    issued: self.originals()?[1].word(25)?,
                    lease: self.originals()?[1].word(27)?,
                },
            )
        } else {
            let update = PolicyCells::check(&mut uint, region, &self.originals()?[1])?;
            GlueChip::assert_constant(region, update.valid().word(), Fp::ONE)?;
            refresh::constrain(&mut uint, region, transition, update.refresh_update()?)
        }
    }

    fn authenticate_update(
        &self,
        chip: &mut VerifierChip<Ep>,
        region: &mut Region<'_, Fp>,
        policy: OwnPolicy,
        input: &ContextInputs<'_>,
        sigma: &SigmaBindingCells,
        signatures: &SignatureQCells,
    ) -> Result<(), Error> {
        let slots = signatures.slots();
        require_slots(&RefreshStagePlan::signature_schemas(policy)?[0], signatures)?;
        let predecessor = input.predecessor.ok_or(Error::Synthesis)?;
        let scope = policy.scope(chip, region, predecessor.state)?;
        let mut uint = chip.uint();
        let auth = IssuerAuthorization {
            certificate: &self.originals()?[0],
            certificate_proof: &slots[2],
            object_proof: &slots[1],
            root_key: slots[2].key(),
            scheme: &scope.scheme,
        };
        let valid = issuer::authenticate(&mut uint, region, &self.originals()?[1], &auth)?;
        GlueChip::assert_constant(region, valid.word(), Fp::ONE)?;
        if self.variant == Variant::RefreshCredential {
            for (actual, expected) in self.originals()?[1]
                .identifier(6)?
                .iter()
                .zip(&scope.provider)
            {
                GlueChip::assert_equal(region, actual, expected)?;
            }
        }
        GlueChip::assert_equal(
            region,
            self.originals()?[1].digest(),
            &input.own_statement.fields()[18],
        )?;
        let payment_key = core::array::from_fn(|i| predecessor.public.fields()[9 + i].clone());
        let valid = self.originals()?[2].bind_signature(region, &slots[0], &payment_key)?;
        GlueChip::assert_constant(region, valid.word(), Fp::ONE)?;
        let wallet = core::array::from_fn(|i| predecessor.public.fields()[6 + i].clone());
        let zero = uint.glue().constant(region, Fp::ZERO)?;
        let lanes = chip.operation_lanes()?;
        let valid = receipt::bind(
            &mut UintChip::new(lanes.glue, lanes.range),
            lanes.hash,
            region,
            &self.originals()?[2],
            &ReceiptContext {
                wallet: &wallet,
                provider: &scope.provider,
                statement: input.own_statement,
                proof_digest: sigma.step_digest()?,
                payment_digest: &zero,
            },
        )?;
        GlueChip::assert_constant(region, valid.word(), Fp::ONE)
    }

    fn authenticate_current(
        &self,
        chip: &mut VerifierChip<Ep>,
        region: &mut Region<'_, Fp>,
        policy: OwnPolicy,
        input: &ContextInputs<'_>,
        signatures: &SignatureQCells,
    ) -> Result<(), Error> {
        require_slots(&RefreshStagePlan::signature_schemas(policy)?[1], signatures)?;
        let slots = signatures.slots();
        let predecessor = input.predecessor.ok_or(Error::Synthesis)?;
        let current = MapState {
            state: predecessor.state,
            lineage: predecessor.public,
        };
        if self.variant != Variant::RefreshCredential {
            return authenticate_current(
                chip,
                region,
                policy,
                CurrentAuthorization {
                    credential: &self.originals()?[4],
                    certificate: &self.originals()?[3],
                    credential_proof: &slots[0],
                    certificate_proof: &slots[1],
                    current,
                    statement: input.own_statement,
                },
            );
        }
        // A renewal statement names the successor credential. C4 still verifies
        // the predecessor's exact current credential; Effects separately proves
        // replacement continuity and binds the new credential to the successor.
        let scope = policy.scope(chip, region, current.state)?;
        let mut uint = chip.uint();
        current
            .state
            .bind_lineage(&mut uint, region, current.lineage)?;
        let credential = CredentialCells::check(&mut uint, region, &self.originals()?[4])?;
        let valid = credential.authenticate(
            &mut uint,
            region,
            &CredentialAuthorization {
                certificate: &self.originals()?[3],
                certificate_proof: &slots[1],
                credential_proof: &slots[0],
                root_key: slots[1].key(),
                scheme: &scope.scheme,
                provider: &scope.provider,
            },
        )?;
        GlueChip::assert_constant(region, valid.word(), Fp::ONE)?;
        let valid = credential.bind_current(&mut uint, region, current.state, current.lineage)?;
        GlueChip::assert_constant(region, valid.word(), Fp::ONE)
    }
}
fn require_slots(schema: &QSignaturePlan, signatures: &SignatureQCells) -> Result<(), Error> {
    if schema.slots().len() != signatures.slots().len()
        || schema
            .slots()
            .iter()
            .zip(signatures.slots())
            .any(|(expected, actual)| {
                expected.mode != actual.mode() || expected.key != actual.key_policy()
            })
    {
        return Err(Error::Synthesis);
    }
    Ok(())
}

/// Inputs present only at their mandatory fixed operation owner.
#[derive(Clone, Copy, Default)]
pub struct RefreshStageWitness<'a> {
    /// Q-bound exact own sigma tape, mandatory at update/receipt authorization.
    pub sigma: Option<&'a SigmaBindingCells>,
    /// Hard Q1 update/receipt/certificate or hard Q2 current credential/certificate.
    pub signatures: Option<&'a SignatureQCells>,
    /// Mandatory new-version history insertion for the Blacklist map owner.
    pub blacklist: Option<&'a InsertCells>,
    /// All578 original words, mandatory at each quota root/merge owner.
    pub quota: Option<&'a QuotaRebuildCells>,
}

/// Mandatory fixed owners and signature schemas for all five policy updates.
#[derive(Clone, Debug)]
pub struct RefreshStagePlan {
    context: ContextPlan,
    policy: OwnPolicy,
}
impl RefreshStagePlan {
    /// Hard Q1 [receipt,update,certificate] and Q2 [current credential,certificate].
    /// # Errors
    /// Invalid fixed scheme-root key.
    pub fn signature_schemas(policy: OwnPolicy) -> Result<[QSignaturePlan; 2], Error> {
        [2, 1]
            .map(|variables| {
                let mut slots = vec![
                    SignatureSlot {
                        mode: VerifyMode::Hard,
                        key: SignatureKey::Variable
                    };
                    variables
                ];
                slots.push(SignatureSlot {
                    mode: VerifyMode::Hard,
                    key: SignatureKey::Fixed(policy.root),
                });
                QSignaturePlan::new(slots)
            })
            .into_iter()
            .collect::<Result<Vec<_>, _>>()?
            .try_into()
            .map_err(|_| Error::Synthesis)
    }
    /// Reject missing/duplicated owners, foreign object shapes and misplaced hard Q leaves.
    /// # Errors
    /// Wrong variant, schema, signature columns or operation-task placement.
    pub fn new(context: ContextPlan, policy: OwnPolicy) -> Result<Self, Error> {
        let variant = context.operation().frame().variant();
        if context.operation().q_count() != 3
            || context.object_specs() != RefreshObjects::context_specs(variant)?
        {
            return Err(Error::Synthesis);
        }
        let schemas = Self::signature_schemas(policy)?;
        for (index, schema) in schemas.iter().enumerate() {
            let d = context
                .operation()
                .q(index + 1)
                .ok_or(Error::Synthesis)?
                .verifier()
                .binding()
                .descriptor();
            if d.instance_lengths
                != [u32::try_from(schema.instance_length()).map_err(|_| Error::BoundsFailure)?]
                || d.instance_types.as_deref() != Some(&QSignaturePlan::instance_types())
            {
                return Err(Error::Synthesis);
            }
        }
        let groups = (0..context.stage_count())
            .map(|i| context.operation_tasks(i).unwrap_or_default().to_vec())
            .collect::<Vec<_>>();
        OperationTask::validate(variant, &groups)?;
        for (stage, tasks) in groups.iter().enumerate() {
            // The two different Q exports cannot share a single witness slot.
            if tasks.contains(&OperationTask::RefreshUpdateAuthorization)
                && tasks.contains(&OperationTask::RefreshCurrentAuthorization)
            {
                return Err(Error::Synthesis);
            }
            for (task, q) in [
                (OperationTask::RefreshUpdateAuthorization, 1),
                (OperationTask::RefreshCurrentAuthorization, 2),
            ] {
                if tasks.contains(&task)
                    && !context
                        .q_partition(stage)
                        .ok_or(Error::Synthesis)?
                        .contains(&q)
                {
                    return Err(Error::Synthesis);
                }
            }
        }
        Ok(Self { context, policy })
    }
    /// Exact schema committed across all A/W continuations.
    pub const fn context(&self) -> &ContextPlan {
        &self.context
    }
    /// Execute every fixed stage owner using the same context-bound objects and state.
    /// # Errors
    /// Missing/extraneous witness, different operation/context, or failed constraints.
    pub fn constrain_stage(
        &self,
        chip: &mut VerifierChip<Ep>,
        region: &mut Region<'_, Fp>,
        stage: usize,
        objects: &RefreshObjects,
        input: &ContextInputs<'_>,
        witness: RefreshStageWitness<'_>,
    ) -> Result<(), Error> {
        let tasks = self
            .context
            .operation_tasks(stage)
            .ok_or(Error::Synthesis)?;
        let update = tasks.contains(&OperationTask::RefreshUpdateAuthorization);
        let current = tasks.contains(&OperationTask::RefreshCurrentAuthorization);
        let quota_owner = tasks.iter().any(|task| {
            matches!(
                task,
                OperationTask::RefreshQuotaMerge
                    | OperationTask::RefreshQuotaPreviousRoot
                    | OperationTask::RefreshQuotaWindowRoot
                    | OperationTask::RefreshQuotaUsageRoot
            )
        });
        if input.own_statement.variant() != self.context.operation().frame().variant()
            || update != witness.sigma.is_some()
            || (update || current) != witness.signatures.is_some()
            || tasks.contains(&OperationTask::RefreshBlacklist) != witness.blacklist.is_some()
            || quota_owner != witness.quota.is_some()
            || (objects.objects.is_none() && !RefreshObjects::quota_root_only(&self.context, stage))
        {
            return Err(Error::Synthesis);
        }
        objects.bind_context(region, input)?;
        let before = input.predecessor.ok_or(Error::Synthesis)?;
        let transition = MapTransition {
            statement: input.own_statement,
            predecessor: MapState {
                state: before.state,
                lineage: before.public,
            },
            successor: MapState {
                state: input.successor.state,
                lineage: input.successor.public,
            },
        };
        if let Some(sigma) = witness.sigma {
            for (actual, expected) in sigma
                .hard_statement()?
                .fields()
                .iter()
                .zip(input.own_statement.fields())
            {
                GlueChip::assert_equal(region, actual, expected)?;
            }
            GlueChip::assert_constant(
                region,
                sigma.key_index(),
                Fp::from(u64::from(
                    super::schedule::sigma_selector(7, 0).ok_or(Error::Synthesis)?,
                )),
            )?;
            super::bind_sigma(
                chip,
                region,
                &self.context.operation().sigma,
                input.q_instances.first().ok_or(Error::Synthesis)?,
                core::slice::from_ref(sigma),
            )?;
        }
        if let Some(signature) = witness.signatures {
            let q = if update { 1 } else { 2 };
            signature.bind_context(
                region,
                self.context.operation(),
                q,
                input.q_instances.get(q).ok_or(Error::Synthesis)?,
            )?;
        }
        for task in tasks {
            match task {
                OperationTask::RefreshEffects => objects.effects(chip, region, &transition)?,
                OperationTask::RefreshUpdateAuthorization => objects.authenticate_update(
                    chip,
                    region,
                    self.policy,
                    input,
                    witness.sigma.ok_or(Error::Synthesis)?,
                    witness.signatures.ok_or(Error::Synthesis)?,
                )?,
                OperationTask::RefreshCurrentAuthorization => objects.authenticate_current(
                    chip,
                    region,
                    self.policy,
                    input,
                    witness.signatures.ok_or(Error::Synthesis)?,
                )?,
                OperationTask::RefreshBlacklist => {
                    let lanes = chip.operation_lanes()?;
                    MapEffectsChip::new(lanes.glue, lanes.range, lanes.hash).refresh_blacklist(
                        region,
                        &transition,
                        witness.blacklist.ok_or(Error::Synthesis)?,
                    )?;
                }
                OperationTask::RefreshQuotaMerge => {
                    let quota = witness.quota.ok_or(Error::Synthesis)?;
                    objects.bind_quota_witness(chip, region, quota, *task)?;
                    GlueChip::assert_equal(
                        region,
                        &quota.issued,
                        objects.originals()?[1].word(5)?,
                    )?;
                    GlueChip::assert_equal(
                        region,
                        &quota.window_count,
                        objects.originals()?[1].word(8)?,
                    )?;
                    let lanes = chip.operation_lanes()?;
                    quota_refresh::constrain_semantics(
                        &mut UintChip::new(lanes.glue, lanes.range),
                        region,
                        &transition,
                        quota,
                    )?;
                }
                OperationTask::RefreshQuotaPreviousRoot
                | OperationTask::RefreshQuotaWindowRoot
                | OperationTask::RefreshQuotaUsageRoot => {
                    let root = match task {
                        OperationTask::RefreshQuotaPreviousRoot => QuotaRoot::PreviousUsage,
                        OperationTask::RefreshQuotaWindowRoot => QuotaRoot::ReplacementWindows,
                        OperationTask::RefreshQuotaUsageRoot => QuotaRoot::ReplacementUsage,
                        _ => return Err(Error::Synthesis),
                    };
                    let quota = witness.quota.ok_or(Error::Synthesis)?;
                    objects.bind_quota_witness(chip, region, quota, *task)?;
                    quota_refresh::constrain_root(
                        chip.operation_lanes()?.hash,
                        region,
                        &transition,
                        quota,
                        root,
                    )?;
                }
                _ => return Err(Error::Synthesis),
            }
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests;
