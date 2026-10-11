//! Bounded native evaluation of the same nonproof predicates proved by Receive A.
//! This creates no Q proof, checkpoint, source grant or acceptance capability.

use super::super::Plan;
use super::*;
use crate::{
    a_relation::receive::{authorization::ReceiveSignaturePredicateInputs, maps},
    operation_relation::map_effects::{MapState, MapTransition},
    q_signature::SignatureWitness,
};
use ff::Field;
use iroha_plonk::check::{CheckMode, check_circuit};
use iroha_plonk_gadgets::GlueChip;
use std::sync::Mutex;

/// Original nonproof Receive witnesses, before Q or any operation-wide mode is chosen.
/// Fields are proposals only; the fixed actual A owners still bind every original.
#[derive(Clone)]
pub struct PredicateInputs {
    /// Exact source state before this Receive.
    pub before: crate::admin_sigma::StateWitness,
    /// Proposed successor public values; result-dependent roots are bound by actual A.
    pub after: crate::admin_sigma::StateWitness,
    /// Exact own statement from the retained capsule.
    pub statement: [Fp; 26],
    /// Actual consumed-credit path retained before Advance.
    pub consumed: crate::tree::IndexedInsert<Fp>,
    /// Source-selected history opening in the same native fixed path representation.
    pub blacklist: crate::tree::IndexedInsert<Fp>,
    /// Exact Send statement26 from the incoming original package.
    pub incoming_statement: [Fp; 26],
    /// The same eleven original byte tapes later consumed by native Inputs.
    pub objects: [Vec<u8>; 11],
    /// Exact soft signature witnesses for the original incoming Q2 slots.
    pub signatures: Vec<SignatureWitness>,
    /// Fully source-verified predecessor Pallas claim, not an incoming verdict.
    pub predecessor_pallas: AccumulatorT<Ep>,
    /// Fully source-verified predecessor Vesta claim.
    pub predecessor_vesta: AccumulatorT<Eq>,
    /// Compiled own selector, bound again to the Request by the Blacklist owner.
    pub own_selector: u8,
    /// Compiled incoming selector, bound again to decoded lineage by Objects.
    pub incoming_selector: u8,
}

#[derive(Clone, Copy)]
enum Group {
    Objects,
    Signatures,
    Maps,
}
#[derive(Clone)]
struct Proposal {
    plan: Plan,
    input: PredicateInputs,
    group: Group,
    observed: Arc<Mutex<Option<[bool; 2]>>>,
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
        let input = &self.input;
        let plan = self.plan.context();
        layouter.assign_region(
            || "native Receive predicate proposal",
            |mut region| {
                let (old, pred_public) = cells.state(&mut chip, &mut region, &input.before)?;
                let (new, next_public) = cells.state(&mut chip, &mut region, &input.after)?;
                let fields = cells.words(&mut chip, &mut region, &input.statement)?;
                let statement = StatementCells::constrain_with_verifier(
                    &mut chip,
                    &mut region,
                    plan.operation().frame().variant(),
                    &fields,
                )?;
                let values = input.objects.each_ref().map(|raw| cells.bytes(raw));
                let valid = match self.group {
                    Group::Objects => {
                        let fields =
                            cells.words(&mut chip, &mut region, &input.incoming_statement)?;
                        let lanes = chip.operation_lanes()?;
                        let incoming_statement = IncomingStatementCells::constrain(
                            &mut UintChip::new(lanes.glue, lanes.range),
                            lanes.hash,
                            &mut region,
                            Variant::Send,
                            &fields,
                        )?;
                        let transport_plan = IncomingTransportPlan::new(plan.operation())?;
                        let raw = cells.active(
                            &mut chip,
                            &mut bytes,
                            &mut region,
                            &input.objects[4],
                            plan.object_specs()[4].capacity as usize,
                            &transport_plan.active_segments()?,
                        )?;
                        let transport = transport_plan.decode_active(
                            &mut chip,
                            &mut region,
                            &raw,
                            next_public.omega_key_digest(),
                        )?;
                        let sigma_length = plan
                            .operation()
                            .sigma
                            .class(1)
                            .ok_or(Error::Synthesis)?
                            .verifier()
                            .proof_length();
                        let sigma_raw = cells.active(
                            &mut chip,
                            &mut bytes,
                            &mut region,
                            &input.objects[5],
                            plan.object_specs()[5].capacity as usize,
                            &SigmaBindingCells::incoming_segments(sigma_length)?,
                        )?;
                        let index = chip
                            .uint()
                            .glue()
                            .constant(&mut region, Fp::from(u64::from(input.incoming_selector)))?;
                        let sigma = SigmaBindingCells::from_incoming_active(
                            &mut chip,
                            &mut region,
                            &incoming_statement,
                            index,
                            &sigma_raw,
                            sigma_length,
                        )?;
                        // Same exact framed original digest as the mandatory ProofDigest owner.
                        let mut framed =
                            super::super::frame(&input.objects[4]).map_err(|_| Error::Synthesis)?;
                        framed.extend(
                            super::super::frame(&input.objects[5]).map_err(|_| Error::Synthesis)?,
                        );
                        let digest = iroha_plonk_gadgets::bytes::p_bytes_native::<Fp>(
                            u64::from_le_bytes(*b"kgwprf_1"),
                            &framed,
                        );
                        let digest = chip.uint().glue().constant(&mut region, digest)?;
                        let objects = ReceiveObjects::decode(
                            &mut chip,
                            &mut bytes,
                            &mut region,
                            self.plan.policy,
                            ReceiveObjectSources {
                                request: &values[0],
                                payer: &values[1],
                                receipt: &values[2],
                                payment: &values[3],
                            },
                            ReceiveObjectInputs {
                                own: &statement,
                                receiver: &pred_public,
                                incoming: &transport,
                                sigma: &sigma,
                                consuming_digest: &digest,
                            },
                        )?;
                        [
                            objects.native_predicate().clone(),
                            chip.uint()
                                .glue()
                                .boolean(&mut region, Value::known(true))?,
                        ]
                    }
                    Group::Signatures | Group::Maps => {
                        let objects = ReceiveSignedObjects::decode(
                            &mut chip,
                            &mut bytes,
                            &mut region,
                            [&values[0], &values[1], &values[2]],
                        )?;
                        if matches!(self.group, Group::Signatures) {
                            let authorization = ReceiveAuthorizationObjects::decode(
                                &mut chip,
                                &mut bytes,
                                &mut region,
                                plan.operation().frame().variant(),
                                ReceiveAuthorizationSources {
                                    current: &values[6],
                                    certificate: &values[7],
                                    receipt: &values[8],
                                    quoted: [&values[9], &values[10]],
                                },
                            )?;
                            let schemas =
                                crate::a_relation::receive::ReceiveStagePlan::signature_schemas(
                                    plan.operation().frame().variant(),
                                    self.plan.policy,
                                )?;
                            // Genuine native ECDSA exports for the exact installed Q2
                            // schema. No Q0 column, proof or proposed verdict is present.
                            let q2 = schemas[1]
                                .native_instances(&input.signatures)
                                .map_err(|_| Error::Synthesis)?;
                            let q2 = q2
                                .iter()
                                .map(|column| {
                                    column
                                        .iter()
                                        .map(|value| {
                                            cells.q_instance(
                                                &mut chip,
                                                &mut region,
                                                *value,
                                                InstanceType::Bounded,
                                            )
                                        })
                                        .collect::<Result<Vec<_>, _>>()
                                })
                                .collect::<Result<Vec<_>, _>>()?;
                            let signatures = ReceiveSignatureQProjection::from_original_instances(
                                &mut chip,
                                &mut region,
                                plan.operation(),
                                &schemas[1],
                                &q2,
                            )?;
                            [
                                authorization.signature_predicate(
                                    &mut chip,
                                    &mut region,
                                    ReceiveSignaturePredicateInputs {
                                        policy: self.plan.policy,
                                        own_statement: &statement,
                                        predecessor: MapState {
                                            state: &old,
                                            lineage: &pred_public,
                                        },
                                        objects: &objects,
                                        slots: signatures.slots(),
                                    },
                                )?,
                                chip.uint()
                                    .glue()
                                    .boolean(&mut region, Value::known(true))?,
                            ]
                        } else {
                            let consumed =
                                cells.insertion(&mut chip.uint(), &mut region, &input.consumed)?;
                            let history =
                                cells.insertion(&mut chip.uint(), &mut region, &input.blacklist)?;
                            let nonmembership = maps::nonmembership_predicate(
                                &mut chip,
                                &mut region,
                                &MapTransition {
                                    statement: &statement,
                                    predecessor: MapState {
                                        state: &old,
                                        lineage: &pred_public,
                                    },
                                    successor: MapState {
                                        state: &new,
                                        lineage: &next_public,
                                    },
                                },
                                &consumed.low,
                            )?;
                            let (blacklist, selector) = objects.blacklist_predicate(
                                &mut chip,
                                &mut region,
                                &old,
                                &pred_public,
                                &history.low,
                            )?;
                            let actual = chip
                                .uint()
                                .glue()
                                .constant(&mut region, Fp::from(u64::from(input.own_selector)))?;
                            GlueChip::assert_equal(&mut region, &actual, &selector)?;
                            [nonmembership, blacklist]
                        }
                    }
                };
                let _ = valid[0]
                    .word()
                    .value()
                    .zip(valid[1].word().value())
                    .map(|(a, b)| {
                        if let Ok(mut output) = self.observed.lock() {
                            *output = Some([a == Fp::ONE, b == Fp::ONE]);
                        }
                    });
                Ok(())
            },
        )
    }
}

impl Plan {
    /// Derive the Objects, Signatures, Nonmembership and Blacklist witness bits
    /// using those exact circuit predicates, in three bounded k16 assignments.
    /// This performs no key generation and produces no proof or acceptance grant.
    /// Actual Q/A/W/Omega verification and every accumulator decide remain mandatory.
    /// # Errors
    /// Wrong source shape, malformed own input, substituted hard binding, invalid
    /// authenticated path, resource bound or failed native predicate assignment.
    pub fn propose_nonproof(
        &self,
        input: PredicateInputs,
    ) -> Result<[bool; 4], super::super::Error> {
        let mut values = Vec::with_capacity(4);
        let mut input = Some(input);
        for group in [Group::Objects, Group::Signatures, Group::Maps] {
            let observed = Arc::new(Mutex::new(None));
            // The last assignment consumes the caller's original buffers; earlier groups
            // keep the same bounded per-assignment copies and constraint order.
            let input = if matches!(group, Group::Maps) {
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
            let bits = observed
                .lock()
                .map_err(|_| super::super::Error::Input)?
                .ok_or(super::super::Error::Input)?;
            values.push(bits[0]);
            if matches!(group, Group::Maps) {
                values.push(bits[1]);
            }
        }
        values.try_into().map_err(|_| super::super::Error::Input)
    }
}
