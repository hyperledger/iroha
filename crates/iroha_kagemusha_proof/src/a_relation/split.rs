//! Fixed A → W continuation schedules, with no native lineage acceptance entry point.

use super::{
    AOutputCells, BoundSigmaCells, IncomingVestaCells, LineagePublicCells, PredecessorCells,
    ProofMessageCells, SelectedPallasCells, SigmaBindingCells, VerifiedQCells, VestaClaimCells,
    bind_sigma,
    context::{ContextInputs, ContextPlan},
    lineage_digest,
    proof::{IncomingProofBinding, omega_instances},
};
use crate::{
    omega::{OmegaCircuit, OmegaConfig, OmegaPlan, OmegaWitness},
    operation_relation::incoming_statement::StatementView,
};
use ff::Field;
use iroha_pasta::{Ep, Eq, Fp, Fq};
use iroha_plonk::{
    DescriptorBinding, ProvingKey, VerifyingKey,
    cs::ConstraintSystem,
    frontend::{Circuit, Error, Layouter, Region, SimpleFloorPlanner},
    keys::{KeygenConfigV2, keygen_pk_v2},
    pcs::ipa::PinnedParams,
};
use iroha_plonk_gadgets::{GlueChip, Word, ecc::NonIdentityPoint};
use iroha_plonk_recursion::{
    accumulation_circuit::{FoldInputCells, FoldPlan, FoldSource},
    codec::ScalarCells,
    obligation::ModeCells,
    verifier::{VerificationMode, VerifierChip, VerifierPlan},
};

/// An internal context wrapper. Its admitted keys must be A-stage keys generated
/// for this exact context schema; there is no transported-lineage constructor.
#[derive(Clone, Debug)]
pub struct WCircuit {
    inner: OmegaCircuit,
    schema: Vec<Fp>,
    stage: usize,
}
impl WCircuit {
    /// Build the W-only wrapper with its circuit-fixed preceding A key allowlist.
    ///
    /// # Errors
    /// Terminal stage, wrong A descriptor/schema, allowlist or proof dimensions.
    pub fn new(
        context: &ContextPlan,
        stage: usize,
        binding: DescriptorBinding,
        params: PinnedParams<Eq>,
        allowlist: Vec<Fq>,
        witness: OmegaWitness,
    ) -> Result<Self, Error> {
        if stage >= context.stage_count() - 1 {
            return Err(Error::Synthesis);
        }
        let plan = OmegaPlan::new(binding, params, allowlist)?;
        Ok(Self {
            inner: OmegaCircuit::new(plan, witness)?,
            schema: context.schema().to_vec(),
            stage,
        })
    }
}
impl Circuit<Fq> for WCircuit {
    type Config = OmegaConfig;
    type FloorPlanner = SimpleFloorPlanner;
    type Params = ();
    fn without_witnesses(&self) -> Self {
        Self {
            inner: self.inner.without_witnesses(),
            schema: self.schema.clone(),
            stage: self.stage,
        }
    }
    fn configure(meta: &mut ConstraintSystem<Fq>) -> Self::Config {
        OmegaCircuit::configure(meta)
    }
    fn synthesize(&self, config: Self::Config, layouter: impl Layouter<Fq>) -> Result<(), Error> {
        self.inner.synthesize(config, layouter)
    }
}
/// A W identity from W-specific key generation or authenticated artifact import. The continuation
/// uses this circuit-fixed complete key, never a supplied proof's witness key.
#[derive(Clone, Debug)]
pub struct WKey {
    key: VerifyingKey<Ep>,
    verifier: VerifierPlan<Ep>,
    schema: Vec<Fp>,
    stage: usize,
}
impl WKey {
    /// Generate an internal W key and retain its typed verifier identity.
    /// The proving key is returned for local artifact/prover orchestration.
    ///
    /// # Errors
    /// Synthesis, key generation, wrong k or descriptor/profile failures.
    pub fn keygen(
        circuit: &WCircuit,
        params: &PinnedParams<Ep>,
    ) -> Result<(Self, ProvingKey<Ep>), Error> {
        params.require_k(16).map_err(|_| Error::Synthesis)?;
        let mut config = KeygenConfigV2::pipa_r(OmegaPlan::instance_types().to_vec());
        config.compress_selectors = false;
        let key = keygen_pk_v2(params, circuit, &config).map_err(|_| Error::Synthesis)?;
        if key.binding().descriptor().k != 16 {
            return Err(Error::Synthesis);
        }
        let verifier = VerifierPlan::new(key.binding().clone(), params.clone())
            .map_err(|_| Error::Synthesis)?;
        Ok((
            Self {
                key: key.vk().clone(),
                verifier,
                schema: circuit.schema.clone(),
                stage: circuit.stage,
            },
            key,
        ))
    }
    /// Import a W key already authenticated by the native artifact owner.
    ///
    /// The context, stage and descriptor are installation metadata. They must
    /// never be selected from a foreign proof. Import does not generate a key,
    /// infer another profile or admit an internal W as the final Omega key.
    ///
    /// # Errors
    /// Terminal/out-of-order stage, another descriptor, wrong public schema,
    /// non-k16 parameters or an unsupported PIPA-R verifier profile.
    pub fn from_artifact(
        context: &ContextPlan,
        stage: usize,
        binding: DescriptorBinding,
        params: PinnedParams<Ep>,
        key: VerifyingKey<Ep>,
    ) -> Result<Self, Error> {
        let descriptor = binding.descriptor();
        if stage >= context.stage_count().saturating_sub(1)
            || descriptor.k != 16
            || descriptor.instance_lengths != [1, 2, 16]
            || descriptor.instance_types.as_deref() != Some(&OmegaPlan::instance_types())
            || key.descriptor_digest() != binding.digest()
        {
            return Err(Error::Synthesis);
        }
        params.require_k(16).map_err(|_| Error::Synthesis)?;
        let verifier = VerifierPlan::new(binding, params).map_err(|_| Error::Synthesis)?;
        Ok(Self {
            key,
            verifier,
            schema: context.schema().to_vec(),
            stage,
        })
    }

    /// The fixed internal program, with Omega's three typed public columns.
    pub const fn verifier(&self) -> &VerifierPlan<Ep> {
        &self.verifier
    }
    /// The complete pinned W verifying key; this is not a final Omega key.
    pub const fn verifying_key(&self) -> &VerifyingKey<Ep> {
        &self.key
    }
}
/// Fixed split schedule retaining every context, predecessor, incoming and Q claim.
#[derive(Clone, Debug)]
pub struct SplitPlan {
    context: ContextPlan,
    wrap: WKey,
    stage: usize,
    stage_fold: FoldPlan<Ep>,
}
impl SplitPlan {
    /// Pin the immediately preceding W key and this stage's fixed Pallas schedule.
    ///
    /// # Errors
    /// Wrong context identity, missing full-k parameters or invalid schedule.
    pub fn new(
        context: ContextPlan,
        stage: usize,
        wrap: WKey,
        params: &PinnedParams<Ep>,
    ) -> Result<Self, Error> {
        if context.schema() != wrap.schema
            || stage == 0
            || stage >= context.stage_count()
            || wrap.stage.checked_add(1) != Some(stage)
        {
            return Err(Error::Synthesis);
        }
        let mut sources = vec![FoldSource::Fixed(16); 2];
        if context.predecessor_stage() == Some(stage) {
            sources.extend([FoldSource::Fixed(16); 2]);
        }
        if stage + 1 == context.stage_count() && context.operation().frame().has_incoming() {
            sources.extend([FoldSource::Incoming(16); 2]);
        }
        sources.extend(vec![
            FoldSource::Fixed(16);
            context
                .q_partition(stage)
                .ok_or(Error::Synthesis)?
                .len()
        ]);
        let stage_fold = FoldPlan::with_sources(params, sources).map_err(|_| Error::Synthesis)?;
        Ok(Self {
            context,
            wrap,
            stage,
            stage_fold,
        })
    }
    /// Exact A stage, starting at zero; this plan always resumes a previous W.
    pub const fn stage(&self) -> usize {
        self.stage
    }
    /// The immutable schedule determines whether this stage emits a lineage.
    pub fn is_terminal(&self) -> bool {
        self.stage + 1 == self.context.stage_count()
    }
    /// Fixed complete operation and context schema.
    pub const fn context(&self) -> &ContextPlan {
        &self.context
    }
    /// Pin W after its preceding A key is generated; no witness-selected key.
    pub const fn wrap(&self) -> &WKey {
        &self.wrap
    }
}
/// An internal stage's checked context digest, carried P claim and Vesta part.
#[derive(Clone, Debug)]
pub struct ContinuationCells {
    digest: Word<Fp>,
    pallas: FoldInputCells<Ep>,
    part: VestaClaimCells,
}
impl ContinuationCells {
    /// The internal context digest, using `kgwlink1` rather than `kgwomg_1`.
    pub const fn digest(&self) -> &Word<Fp> {
        &self.digest
    }
    /// Current carried Pallas claim committed by the digest and retained next.
    pub const fn pallas(&self) -> &FoldInputCells<Ep> {
        &self.pallas
    }
    /// Exact uniform69 internal A frame with explicit absent-slot fillers.
    ///
    /// # Errors
    /// Layout failure or invalid pinned trivial encoding.
    pub fn words(
        &self,
        chip: &mut VerifierChip<Ep>,
        region: &mut Region<'_, Fp>,
    ) -> Result<Vec<Word<Fp>>, Error> {
        let mut words = vec![
            self.digest.clone(),
            chip.uint()
                .glue()
                .constant(region, Fp::from(u64::from(self.part.source_k())))?,
        ];
        words.extend(self.part.words());
        let trivial = VestaClaimCells::trivial(chip, region)?;
        words.extend(trivial.words());
        words.extend(trivial.words());
        for value in [Fp::ZERO, Fp::ONE, Fp::ZERO] {
            words.push(chip.uint().glue().constant(region, value)?);
        }
        for value in trivial.coordinates() {
            words.extend([value.lo().word().clone(), value.hi().word().clone()]);
        }
        Ok(words)
    }
}
pub(super) fn bind_statements(
    region: &mut Region<'_, Fp>,
    inputs: &ContextInputs<'_>,
    bindings: &[SigmaBindingCells],
) -> Result<(), Error> {
    let statements = std::iter::once(inputs.own_statement.fields())
        .chain(inputs.incoming_statement.map(StatementView::fields));
    if bindings.len() != 1 + usize::from(inputs.incoming_statement.is_some()) {
        return Err(Error::Synthesis);
    }
    for (statement, binding) in statements.zip(bindings) {
        for (a, b) in statement.iter().zip(binding.statement().fields()) {
            GlueChip::assert_equal(region, a, b)?;
        }
    }
    Ok(())
}
/// Close A1 using its exact hard Q partition and optional hard predecessor pair.
/// A single opening is forwarded; multiple claims require the fixed hard fold.
/// With zero Q slots, the context V part is authenticated by mandatory Q
/// verification in fixed later stages; W alone is not final acceptance.
/// This free function avoids
/// any circular dependency on the not-yet-generated W key.
///
/// # Errors
/// Missing/reordered obligations, wrong statements, bad fold or layout failure.
#[allow(clippy::too_many_arguments)]
pub fn close_first(
    chip: &mut VerifierChip<Ep>,
    region: &mut Region<'_, Fp>,
    context: &ContextPlan,
    inputs: &ContextInputs<'_>,
    predecessor: Option<&PredecessorCells>,
    q: &[VerifiedQCells],
    sigma: &[SigmaBindingCells],
    fold: Option<&ProofMessageCells>,
    params: &PinnedParams<Ep>,
) -> Result<ContinuationCells, Error> {
    if predecessor.is_some() != context.predecessor_in_first() {
        return Err(Error::Synthesis);
    }
    context.bind_q_partition(region, inputs, q, 0)?;
    bind_statements(region, inputs, sigma)?;
    let sigma = bind_sigma(
        chip,
        region,
        &context.operation().sigma,
        &inputs.q_instances[0],
        sigma,
    )?;
    let mut claims = Vec::new();
    if let Some(pred) = predecessor {
        let expected = inputs.predecessor.as_ref().ok_or(Error::Synthesis)?;
        bind_predecessor(
            region,
            expected.public.fields(),
            expected.pallas,
            expected.vesta,
            inputs.successor.public.omega_key_digest(),
            pred,
        )?;
        claims.extend([pred.pallas.clone(), pred.opening.clone()]);
    }
    claims.extend(q.iter().map(|q| q.opening.clone()));
    let pallas = if claims.len() == 1 {
        if fold.is_some() {
            return Err(Error::Synthesis);
        }
        claims[0].clone()
    } else {
        let plan = FoldPlan::with_sources(params, vec![FoldSource::Fixed(16); claims.len()])
            .map_err(|_| Error::Synthesis)?;
        let proof = fold.ok_or(Error::Synthesis)?;
        let output = chip.verify_fold(
            region,
            &plan,
            &claims,
            proof.messages(),
            proof.length(),
            VerificationMode::Hard,
        )?;
        FoldInputCells::from_claim(chip, region, &output.claim)?
    };
    let immutable = context.digest(chip, region, inputs)?;
    let digest = context.stage_digest(chip, region, 0, &immutable, &pallas)?;
    Ok(ContinuationCells {
        digest,
        pallas,
        part: sigma.part,
    })
}
#[derive(Clone, Debug)]
struct BoundLineage {
    public: [Word<Fp>; 18],
    pallas: FoldInputCells<Ep>,
    vesta: VestaClaimCells,
}
#[derive(Clone, Debug)]
struct BoundIncoming {
    lineage_valid: iroha_plonk_gadgets::Bit<Fp>,
    lineage: BoundLineage,
    proof: IncomingProofBinding,
    modes: [ModeCells<Fp>; 3],
    pallas_corrections: [NonIdentityPoint<Fp>; 2],
    vesta_correction: [ScalarCells<Ep>; 2],
}
/// Hard-authenticated context, its separate P obligations and full-k V carry.
#[derive(Clone, Debug)]
pub struct ResumedContextCells {
    schema: Vec<Fp>,
    stage: usize,
    immutable: Word<Fp>,
    pallas: FoldInputCells<Ep>,
    opening: FoldInputCells<Ep>,
    vesta: VestaClaimCells,
    q_instances: Vec<Vec<Vec<ScalarCells<Ep>>>>,
    successor: [Word<Fp>; 18],
    predecessor: Option<BoundLineage>,
    incoming: Option<BoundIncoming>,
    receive_results: Option<super::results::ReceiveResultClaims>,
    /// Incoming sigma verdict/modes rebound to the exact authenticated Q data.
    pub sigma: BoundSigmaCells,
}
impl ResumedContextCells {
    /// Select Receive's original incoming claims from the authenticated stage context.
    ///
    /// The fixed Proofs owner must precede this terminal stage. The admitted
    /// prior A keys establish that owner equated this exact opening to the
    /// actual total verifier output; W authenticates its unchanged context.
    /// No opening or verdict argument can replace the retained export here.
    /// Corrected points and modes are the original committed cells, and the
    /// selected P/opening and V remain separate final fold obligations.
    /// # Errors
    /// Wrong stage/schema, absent complete Receive result/export, or layout failure.
    pub fn select_receive_incoming(
        &self,
        chip: &mut VerifierChip<Ep>,
        region: &mut Region<'_, Fp>,
        plan: &SplitPlan,
    ) -> Result<(SelectedPallasCells, IncomingVestaCells), Error> {
        use super::{IncomingOmegaCells, results::ReceiveResultTag};
        if !plan.is_terminal() || self.stage != plan.stage || self.schema != plan.context.schema() {
            return Err(Error::Synthesis);
        }
        let result_plan = plan.context.receive_results().ok_or(Error::Synthesis)?;
        if usize::try_from(result_plan.owner(ReceiveResultTag::Proofs))
            .map_err(|_| Error::BoundsFailure)?
            >= self.stage
        {
            return Err(Error::Synthesis);
        }
        let results = self.receive_results.as_ref().ok_or(Error::Synthesis)?;
        let expected = self.incoming.as_ref().ok_or(Error::Synthesis)?;
        GlueChip::assert_equal(region, &expected.lineage.public[17], &self.successor[17])?;
        let origin = IncomingOmegaCells {
            carried_key: self.successor[17].clone(),
            lineage_valid: expected.lineage_valid.clone(),
            public: expected.lineage.public.clone(),
            vesta: expected.lineage.vesta.clone(),
            proof: expected.proof.clone(),
            valid: results.values(result_plan)?[ReceiveResultTag::Proofs as usize - 1].clone(),
            pallas: expected.lineage.pallas.clone(),
            opening: results.opening()?.clone(),
        };
        let selected = super::select_incoming(
            chip,
            region,
            &origin,
            &[expected.modes[0].clone(), expected.modes[1].clone()],
            &expected.pallas_corrections,
        )?;
        Ok((
            selected,
            IncomingVestaCells {
                claim: expected.lineage.vesta.clone(),
                mode: expected.modes[2].clone(),
                corrected: expected.vesta_correction.clone(),
            },
        ))
    }

    /// W's V accumulator becomes the next A stage's full-k16 part.
    pub const fn vesta_part(&self) -> &VestaClaimCells {
        &self.vesta
    }
}
/// The terminal A stage's result and exact frame data retained by its fold.
/// Construction is private: callers cannot replace the folded P claim or the
/// authenticated predecessor/incoming frame after closure.
#[derive(Clone, Debug)]
pub struct FinalHalfCells {
    pallas: FoldInputCells<Ep>,
    part: VestaClaimCells,
    successor: [Word<Fp>; 18],
    predecessor: Option<VestaClaimCells>,
    incoming: Option<IncomingVestaCells>,
    frame: super::AFramePlan,
}
impl FinalHalfCells {
    /// The exact checked Pallas fold output, retained for the lineage digest.
    pub const fn pallas(&self) -> &FoldInputCells<Ep> {
        &self.pallas
    }
    /// Bind the successor and emit the final uniform69 frame under `kgwomg_1`.
    ///
    /// # Errors
    /// Wrong successor fields, slot shape or layout failure.
    pub fn words(
        &self,
        chip: &mut VerifierChip<Ep>,
        region: &mut Region<'_, Fp>,
        public: &LineagePublicCells,
    ) -> Result<Vec<Word<Fp>>, Error> {
        for (actual, expected) in public.fields().iter().zip(&self.successor) {
            GlueChip::assert_equal(region, actual, expected)?;
        }
        let digest = lineage_digest(chip, region, public, &self.pallas)?;
        AOutputCells {
            digest,
            sigma_part: self.part.clone(),
            predecessor: self.predecessor.clone(),
            incoming: self.incoming.clone(),
        }
        .words_with_source(chip, region, self.frame, 16)
    }
}
/// Hard-verify the pinned W key against a freshly recomputed complete context.
/// All after-split operation inputs must be these very context cells.
///
/// # Errors
/// Schema/key/shape mismatch, wrong statements, proof failure or layout error.
#[allow(clippy::too_many_arguments)]
pub fn resume_context(
    chip: &mut VerifierChip<Ep>,
    region: &mut Region<'_, Fp>,
    plan: &SplitPlan,
    inputs: &ContextInputs<'_>,
    pallas: &FoldInputCells<Ep>,
    vesta: &VestaClaimCells,
    proof: &ProofMessageCells,
    sigma: &[SigmaBindingCells],
) -> Result<ResumedContextCells, Error> {
    let immutable = plan.context.digest(chip, region, inputs)?;
    let previous = plan.stage.checked_sub(1).ok_or(Error::Synthesis)?;
    let digest = plan
        .context
        .stage_digest(chip, region, previous, &immutable, pallas)?;
    let instances = omega_instances(chip, region, &digest, vesta)?;
    let key = chip.constant_key(region, &plan.wrap.verifier, &plan.wrap.key)?;
    let output = chip.verify(
        region,
        &plan.wrap.verifier,
        &key,
        &instances,
        proof.messages(),
        proof.length(),
        VerificationMode::Hard,
    )?;
    bind_statements(region, inputs, sigma)?;
    let sigma = bind_sigma(
        chip,
        region,
        &plan.context.operation().sigma,
        &inputs.q_instances[0],
        sigma,
    )?;
    if let Some(mode) = &sigma.incoming_mode {
        let expected = inputs.modes.last().ok_or(Error::Synthesis)?;
        bind_mode(region, mode, expected)?;
    }
    Ok(ResumedContextCells {
        schema: plan.context.schema().to_vec(),
        stage: plan.stage,
        immutable,
        pallas: pallas.clone(),
        opening: FoldInputCells::from_claim(chip, region, &output.claim)?,
        vesta: vesta.clone(),
        q_instances: inputs.q_instances.to_vec(),
        successor: inputs.successor.public.fields().clone(),
        predecessor: inputs.predecessor.map(|p| BoundLineage {
            public: p.public.fields().clone(),
            pallas: p.pallas.clone(),
            vesta: p.vesta.clone(),
        }),
        incoming: inputs
            .incoming
            .map(|p| {
                Ok::<_, Error>(BoundIncoming {
                    lineage_valid: p.public.valid().clone(),
                    lineage: BoundLineage {
                        public: p.public.fields().clone(),
                        pallas: p.pallas.clone(),
                        vesta: p.vesta.clone(),
                    },
                    proof: plan.context.incoming_proof_binding(inputs)?,
                    modes: core::array::from_fn(|i| inputs.modes[i].clone()),
                    pallas_corrections: core::array::from_fn(|i| {
                        inputs.pallas_corrections[i].clone()
                    }),
                    vesta_correction: inputs.vesta_corrections[0].clone(),
                })
            })
            .transpose()?,
        sigma,
        receive_results: inputs.receive_results.cloned(),
    })
}
/// Opaque stage result selected only by the immutable schedule.
#[derive(Clone, Debug)]
pub enum StageOutput {
    /// Internal A context, which must be wrapped by its stage-specific W.
    Continue(Box<ContinuationCells>),
    /// Final operation frame, whose key alone may enter the final Omega catalog.
    Final(Box<FinalHalfCells>),
}
impl StageOutput {
    /// Emit a final lineage frame; intermediate stages cannot use this API.
    ///
    /// # Errors
    /// Wrong stage class, substituted successor or layout failure.
    pub fn words(
        &self,
        chip: &mut VerifierChip<Ep>,
        region: &mut Region<'_, Fp>,
        public: &LineagePublicCells,
    ) -> Result<Vec<Word<Fp>>, Error> {
        match self {
            Self::Final(value) => value.words(chip, region, public),
            Self::Continue(_) => Err(Error::Synthesis),
        }
    }
    /// Access an intermediate context; a final stage cannot become another W.
    ///
    /// # Errors
    /// This is the terminal stage.
    pub fn continuation(&self) -> Result<&ContinuationCells, Error> {
        match self {
            Self::Continue(value) => Ok(value),
            Self::Final(_) => Err(Error::Synthesis),
        }
    }
}
/// Close this fixed stage with `contextP/O_W`, its assigned predecessor pair,
/// terminal incoming claims and assigned Q openings, exactly once in that order.
///
/// # Errors
/// Wrong presence, missing/duplicate/reordered Q, bad hard fold or layout error.
#[allow(clippy::too_many_arguments)]
pub fn close_stage(
    chip: &mut VerifierChip<Ep>,
    region: &mut Region<'_, Fp>,
    plan: &SplitPlan,
    resumed: &ResumedContextCells,
    predecessor: Option<&PredecessorCells>,
    incoming: Option<&SelectedPallasCells>,
    incoming_vesta: Option<&IncomingVestaCells>,
    q: &[VerifiedQCells],
    fold: &ProofMessageCells,
) -> Result<StageOutput, Error> {
    let operation = plan.context.operation();
    if resumed.schema != plan.context.schema()
        || resumed.stage != plan.stage
        || incoming_vesta.is_some() != (plan.is_terminal() && operation.frame().has_incoming())
        || predecessor.is_some() != (plan.context.predecessor_stage() == Some(plan.stage))
        || incoming.is_some() != (plan.is_terminal() && operation.frame().has_incoming())
        || q.len()
            != plan
                .context
                .q_partition(plan.stage)
                .ok_or(Error::Synthesis)?
                .len()
    {
        return Err(Error::Synthesis);
    }
    for (index, value) in plan
        .context
        .q_partition(plan.stage)
        .ok_or(Error::Synthesis)?
        .iter()
        .copied()
        .zip(q)
    {
        if value.index != index || value.instances.len() != resumed.q_instances[index].len() {
            return Err(Error::Synthesis);
        }
        let fixed = operation.q(index).ok_or(Error::Synthesis)?;
        GlueChip::assert_constant(
            region,
            &value.key_digest,
            fixed
                .key
                .kagemusha_digest(fixed.verifier().binding())
                .map_err(|_| Error::Synthesis)?,
        )?;
        for (a, b) in value.instances.iter().zip(&resumed.q_instances[index]) {
            if a.len() != b.len() {
                return Err(Error::Synthesis);
            }
            for (a, b) in a.iter().zip(b) {
                GlueChip::assert_equal(region, a.lo().word(), b.lo().word())?;
                GlueChip::assert_equal(region, a.hi().word(), b.hi().word())?;
            }
        }
    }
    match (&resumed.predecessor, predecessor) {
        (Some(expected), Some(pred)) => {
            bind_predecessor(
                region,
                &expected.public,
                &expected.pallas,
                &expected.vesta,
                &resumed.successor[17],
                pred,
            )?;
        }
        (Some(expected), None) if plan.context.predecessor_stage() != Some(plan.stage) => {
            GlueChip::assert_equal(region, &expected.public[17], &resumed.successor[17])?;
        }
        (None, None) => {}
        _ => return Err(Error::Synthesis),
    }
    match (&resumed.incoming, incoming, incoming_vesta) {
        (Some(expected), Some(selected), Some(vesta)) => {
            GlueChip::assert_equal(region, &selected.origin.carried_key, &resumed.successor[17])?;
            GlueChip::assert_equal(
                region,
                expected.lineage_valid.word(),
                selected.origin.lineage_valid.word(),
            )?;
            for (a, b) in expected.lineage.public.iter().zip(&selected.origin.public) {
                GlueChip::assert_equal(region, a, b)?;
            }
            bind_claim(region, &expected.lineage.pallas, &selected.origin.pallas)?;
            for actual in [&selected.origin.vesta, &vesta.claim] {
                for (a, b) in expected.lineage.vesta.words().iter().zip(actual.words()) {
                    GlueChip::assert_equal(region, a, &b)?;
                }
            }
            match (&expected.proof, &selected.origin.proof) {
                (IncomingProofBinding::Messages(a), IncomingProofBinding::Messages(b)) => {
                    bind_proof(region, a, b)?;
                }
                (
                    IncomingProofBinding::ReceiveActive(a),
                    IncomingProofBinding::ReceiveActive(b),
                ) => {
                    for (a, b) in a.iter().zip(b) {
                        GlueChip::assert_equal(region, a, b)?;
                    }
                }
                _ => return Err(Error::Synthesis),
            }
            if let Some(results) = &resumed.receive_results {
                bind_claim(region, results.opening()?, &selected.origin.opening)?;
            }
            for i in 0..2 {
                bind_mode(region, &expected.modes[i], &selected.modes[i])?;
                GlueChip::assert_equal(
                    region,
                    expected.pallas_corrections[i].x(),
                    selected.corrected[i].x(),
                )?;
                GlueChip::assert_equal(
                    region,
                    expected.pallas_corrections[i].y(),
                    selected.corrected[i].y(),
                )?;
            }
            bind_mode(region, &expected.modes[2], &vesta.mode)?;
            for (a, b) in expected.vesta_correction.iter().zip(&vesta.corrected) {
                GlueChip::assert_equal(region, a.lo().word(), b.lo().word())?;
                GlueChip::assert_equal(region, a.hi().word(), b.hi().word())?;
            }
        }
        (_, None, None) if !plan.is_terminal() => {}
        (None, None, None) => {}
        _ => return Err(Error::Synthesis),
    }
    let mut claims = vec![resumed.pallas.clone(), resumed.opening.clone()];
    if let Some(pred) = predecessor {
        claims.extend([pred.pallas.clone(), pred.opening.clone()]);
    }
    if let Some(incoming) = incoming {
        claims.extend([incoming.pallas.clone(), incoming.opening.clone()]);
    }
    claims.extend(q.iter().map(|q| q.opening.clone()));
    let result = chip.verify_fold(
        region,
        &plan.stage_fold,
        &claims,
        fold.messages(),
        fold.length(),
        VerificationMode::Hard,
    )?;
    let pallas = FoldInputCells::from_claim(chip, region, &result.claim)?;
    if plan.is_terminal() {
        Ok(StageOutput::Final(Box::new(FinalHalfCells {
            pallas,
            part: resumed.vesta.clone(),
            successor: resumed.successor.clone(),
            predecessor: resumed.predecessor.as_ref().map(|p| p.vesta.clone()),
            incoming: incoming_vesta.cloned(),
            frame: operation.frame(),
        })))
    } else {
        let digest =
            plan.context
                .stage_digest(chip, region, plan.stage, &resumed.immutable, &pallas)?;
        Ok(StageOutput::Continue(Box::new(ContinuationCells {
            digest,
            pallas,
            part: resumed.vesta.clone(),
        })))
    }
}

fn bind_predecessor(
    region: &mut Region<'_, Fp>,
    public: &[Word<Fp>; 18],
    pallas: &FoldInputCells<Ep>,
    vesta: &VestaClaimCells,
    successor_key: &Word<Fp>,
    actual: &PredecessorCells,
) -> Result<(), Error> {
    GlueChip::assert_equal(region, &actual.public[17], successor_key)?;
    for (a, b) in public.iter().zip(&actual.public) {
        GlueChip::assert_equal(region, a, b)?;
    }
    bind_claim(region, pallas, &actual.pallas)?;
    for (a, b) in vesta.words().iter().zip(actual.vesta.words()) {
        GlueChip::assert_equal(region, a, &b)?;
    }
    Ok(())
}

pub(super) fn bind_claim(
    region: &mut Region<'_, Fp>,
    a: &FoldInputCells<Ep>,
    b: &FoldInputCells<Ep>,
) -> Result<(), Error> {
    GlueChip::assert_equal(region, a.source_k(), b.source_k())?;
    GlueChip::assert_equal(region, a.g().x(), b.g().x())?;
    GlueChip::assert_equal(region, a.g().y(), b.g().y())?;
    for (a, b) in a.challenges().iter().zip(b.challenges()) {
        GlueChip::assert_equal(region, a.lo().word(), b.lo().word())?;
        GlueChip::assert_equal(region, a.hi().word(), b.hi().word())?;
    }
    Ok(())
}

pub(super) fn bind_mode(
    region: &mut Region<'_, Fp>,
    a: &ModeCells<Fp>,
    b: &ModeCells<Fp>,
) -> Result<(), Error> {
    for (a, b) in [a.accept(), a.trivial(), a.corrected()].into_iter().zip([
        b.accept(),
        b.trivial(),
        b.corrected(),
    ]) {
        GlueChip::assert_equal(region, a.word(), b.word())?;
    }
    Ok(())
}
pub(super) fn bind_proof(
    region: &mut Region<'_, Fp>,
    a: &ProofMessageCells,
    b: &ProofMessageCells,
) -> Result<(), Error> {
    if a.messages().len() != b.messages().len() {
        return Err(Error::Synthesis);
    }
    GlueChip::assert_equal(region, a.length().word(), b.length().word())?;
    for (a, b) in a.messages().iter().zip(b.messages()) {
        GlueChip::assert_equal(region, a.lo().word(), b.lo().word())?;
        GlueChip::assert_equal(region, a.hi().word(), b.hi().word())?;
        GlueChip::assert_equal(region, a.top().word(), b.top().word())?;
    }
    Ok(())
}
