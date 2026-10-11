//! Exact Archive nonproof witness proposals without Q originals or proving keys.

use super::super::{Plan, RetainedPayment};
use super::*;
use crate::{
    a_relation::archive::evidence::{EvidencePredicateInputs, evidence_predicate},
    admin_sigma::ArchiveWitness,
    q_signature::SignatureWitness,
};
use ff::Field;
use iroha_plonk::check::{CheckMode, check_circuit};
use std::sync::Mutex;

/// Original Archive sources before Q production and obligation-mode selection.
/// These values propose witnesses; the actual A owners independently bind them.
#[derive(Clone)]
pub struct PredicateInputs {
    /// Exact before/after state and tag5 statement.
    pub state: ArchiveWitness,
    /// Current Credential, certificate and own Receipt originals.
    pub own: [Vec<u8>; 3],
    /// Exact retained Send Payment and its four signed objects.
    pub retained: RetainedPayment,
    /// Original evidence, including total Status decoder proposals.
    pub evidence: Evidence,
    /// Original incoming Receipt signature for the single soft Q2 slot.
    pub signature: SignatureWitness,
    /// Fully source-verified predecessor Pallas claim.
    pub predecessor_pallas: AccumulatorT<Ep>,
    /// Fully source-verified predecessor Vesta claim.
    pub predecessor_vesta: AccumulatorT<Eq>,
    /// Exact installed incoming Receive selector; absent for Status.
    pub incoming_selector: Option<u8>,
}
#[derive(Clone, Copy)]
enum Group {
    Evidence,
    Signature,
}
#[derive(Clone)]
struct Proposal {
    plan: Plan,
    input: PredicateInputs,
    group: Group,
    observed: Arc<Mutex<Option<bool>>>,
}
#[derive(Clone, Debug)]
struct ProposalConfig {
    verifier: VerifierConfig<Ep>,
    bytes: BytesConfig,
}
impl Circuit<Fp> for Proposal {
    type Config = ProposalConfig;
    type FloorPlanner = SimpleFloorPlanner;
    type Params = ();
    fn without_witnesses(&self) -> Self {
        self.clone()
    }
    fn configure(meta: &mut ConstraintSystem<Fp>) -> ProposalConfig {
        let verifier = VerifierConfig::configure_serialized_foreign_tagged(meta, 4)
            .expect("fixed native proposal buses");
        let a = meta.advice_column();
        let b = meta.advice_column();
        ProposalConfig {
            verifier,
            bytes: BytesConfig::configure(meta, a, b),
        }
    }
    fn synthesize(
        &self,
        config: ProposalConfig,
        mut layouter: impl Layouter<Fp>,
    ) -> Result<(), Error> {
        let mut chip = VerifierChip::new(config.verifier);
        let mut bytes = BytesChip::new(config.bytes);
        chip.load_tables(&mut layouter)?;
        bytes.load_table(&mut layouter)?;
        let cells = Cells { known: true };
        let source = &self.input;
        let plan = self.plan.context();
        let variant = plan.operation().frame().variant();
        layouter.assign_region(
            || "native Archive predicate proposal",
            |mut region| {
                cells.state(&mut chip, &mut region, &source.state.predecessor)?;
                cells.state(&mut chip, &mut region, &source.state.successor)?;
                let fields = cells.words(&mut chip, &mut region, &source.state.statement)?;
                let statement = StatementCells::constrain_with_verifier(
                    &mut chip,
                    &mut region,
                    variant,
                    &fields,
                )?;
                let incoming_statement =
                    if let Evidence::Receive { statement, .. } = &source.evidence {
                        let fields = cells.words(&mut chip, &mut region, statement)?;
                        let lanes = chip.operation_lanes()?;
                        Some(IncomingStatementCells::constrain(
                            &mut UintChip::new(lanes.glue, lanes.range),
                            lanes.hash,
                            &mut region,
                            Variant::Receive,
                            &fields,
                        )?)
                    } else {
                        None
                    };
                let commitments = self
                    .plan
                    .original_commitments_from_parts(
                        &source.own,
                        &source.retained,
                        &source.evidence,
                        [false; 3],
                    )
                    .map_err(|_| Error::Synthesis)?;
                let context = plan.assign_archive_object_claims(
                    &mut chip,
                    &mut region,
                    &commitments
                        .iter()
                        .map(|v| v.map(Value::known))
                        .collect::<Vec<_>>(),
                )?;
                let status_public = if let Evidence::Status { witness, .. } = &source.evidence {
                    let fields = cells.words(&mut chip, &mut region, &witness.public)?;
                    let valid = chip
                        .uint()
                        .glue()
                        .boolean(&mut region, Value::known(witness.public_valid))?;
                    Some(IncomingLineageCells::constrain(
                        &mut chip.uint(),
                        &mut region,
                        &fields,
                        &valid,
                    )?)
                } else {
                    None
                };
                // Exact native signature instances only. No Q proof/capability is fabricated.
                let schema = self
                    .plan
                    .stage()
                    .signature_schema(2)
                    .ok_or(Error::Synthesis)?;
                let signature = schema
                    .native_instances(std::slice::from_ref(&source.signature))
                    .map_err(|_| Error::Synthesis)?;
                let signature = signature
                    .iter()
                    .map(|column| {
                        column
                            .iter()
                            .map(|v| cells.scalar(&mut chip, &mut region, *v))
                            .collect()
                    })
                    .collect::<Result<Vec<Vec<_>>, _>>()?;
                // The real installed incoming selector is bound directly to the
                // held Request by the shared predicate, without a synthetic Q0 frame.
                let incoming_selector = source
                    .incoming_selector
                    .map(|selector| {
                        cells.scalar(&mut chip, &mut region, Fq::from(u64::from(selector)))
                    })
                    .transpose()?;
                let (receipt, credited) = match &source.evidence {
                    Evidence::Receive {
                        receipt, credited, ..
                    }
                    | Evidence::Status {
                        receipt, credited, ..
                    } => (receipt, credited),
                };
                let raw = [
                    &source.retained.signed[0],
                    &source.retained.signed[3],
                    receipt,
                ]
                .map(|v| cells.bytes(v));
                let objects = ArchiveIncomingObjects::decode(
                    &mut chip,
                    &mut bytes,
                    &mut region,
                    raw.each_ref().map(Vec::as_slice),
                )?;
                objects.bind_original_context(&mut region, plan, &statement, &context)?;
                let valid = match self.group {
                    Group::Signature => objects.signature_projection(
                        &mut chip,
                        &mut region,
                        plan.operation(),
                        schema,
                        &signature,
                    )?,
                    Group::Evidence => {
                        let credited = cells.bytes(credited);
                        let (status, opening, fields) = if let Evidence::Status {
                            status: original,
                            credit_opening,
                            statement,
                            ..
                        } = &source.evidence
                        {
                            (
                                Some(cells.bytes(original)),
                                Some(cells.bytes(credit_opening)),
                                Some(cells.words(&mut chip, &mut region, statement)?),
                            )
                        } else {
                            (None, None, None)
                        };
                        let evidence = if variant == Variant::ArchiveReceive {
                            ArchiveEvidenceSource::Receive {
                                credited: &credited,
                            }
                        } else {
                            ArchiveEvidenceSource::Status {
                                credited: &credited,
                                statement: fields.as_ref().ok_or(Error::Synthesis)?,
                                status: status.as_ref().ok_or(Error::Synthesis)?,
                                opening: opening.as_ref().ok_or(Error::Synthesis)?,
                            }
                        };
                        evidence_predicate(
                            &mut chip,
                            &mut bytes,
                            &mut region,
                            plan,
                            EvidencePredicateInputs {
                                own_statement: &statement,
                                incoming_statement: incoming_statement.as_ref(),
                                incoming_public: status_public.as_ref(),
                                objects: &context,
                                incoming_selector: incoming_selector.as_ref(),
                            },
                            self.plan.policy(),
                            &objects,
                            evidence,
                        )?
                    }
                };
                let _ = valid.word().value().map(|v| {
                    if let Ok(mut out) = self.observed.lock() {
                        *out = Some(v == Fp::ONE);
                    }
                });
                Ok(())
            },
        )
    }
}
impl Plan {
    /// Derive exact Evidence and Signatures proposals, in that order, through
    /// their existing circuit predicates using two bounded k16 assignments.
    /// Actual Q/A/W/Omega proofs and all deferred decisions remain mandatory.
    /// # Errors
    /// Wrong variant/selector/source shape, substituted hard original, malformed
    /// retained identity, or failed bounded predicate assignment.
    pub fn propose_nonproof(
        &self,
        input: PredicateInputs,
    ) -> Result<[bool; 2], super::super::Error> {
        let receive = matches!(&input.evidence, Evidence::Receive { .. });
        if receive != (self.context().operation().frame().variant() == Variant::ArchiveReceive)
            || receive != input.incoming_selector.is_some()
        {
            return Err(super::super::Error::Input);
        }
        super::super::check_retained_sizes(input.retained.omega.len(), input.retained.sigma.len())?;
        let mut results = Vec::with_capacity(2);
        let mut input = Some(input);
        for group in [Group::Evidence, Group::Signature] {
            let observed = Arc::new(Mutex::new(None));
            // Preserve owned witness intake and move its buffers into the last assignment.
            let input = if matches!(group, Group::Signature) {
                input.take().ok_or(super::super::Error::Input)?
            } else {
                input.as_ref().ok_or(super::super::Error::Input)?.clone()
            };
            let circuit = Proposal {
                plan: self.clone(),
                input,
                group,
                observed: observed.clone(),
            };
            let report = check_circuit(&circuit, 16, &[], CheckMode::Strict)
                .map_err(|_| super::super::Error::Input)?;
            if !report.is_satisfied() {
                return Err(super::super::Error::Input);
            }
            results.push(
                observed
                    .lock()
                    .map_err(|_| super::super::Error::Input)?
                    .ok_or(super::super::Error::Input)?,
            );
        }
        results.try_into().map_err(|_| super::super::Error::Input)
    }
}
