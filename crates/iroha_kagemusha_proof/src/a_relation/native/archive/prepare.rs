//! Hard original proof checks and exact Archive context proposals.
//!
//! These checks authenticate predecessor and Q proofs, but incoming result bits,
//! decoded fields and object semantics still require every compiled A owner.

use ff::Field;
use ff::PrimeField;
use iroha_pasta::msm::MemoryBudget;
use iroha_plonk_gadgets::bytes::p_bytes_native;
use std::sync::Arc;

use super::*;
use crate::{
    a_relation::{archive::results::ArchiveResultTag, native::support},
    operation_relation::objects::ObjectKind,
};

/// Verified hard originals with exact source proposals for the compiled Archive owners.
/// No method on this type certifies the incoming evidence or authorizes a wallet commit.
#[derive(Clone, Debug)]
pub struct Prepared {
    plan: Plan,
    input: Inputs,
    commitments: Vec<[Fp; 3]>,
    predecessor: (AccumulatorT<Ep>, AccumulatorT<Eq>),
    predecessor_opening: FoldInput<Ep>,
    q_openings: [FoldInput<Ep>; 3],
    part: FoldInput<Eq>,
    selected_status: Option<([FoldInput<Ep>; 2], FoldInput<Eq>)>,
}
impl Prepared {
    // Private source-shape factory for strict original-key import only. The
    // syntax-only dummy claims are never decided, exposed or passed to prepare;
    // the caller must synthesize the returned source with known=false.
    pub(super) fn unknown_source(plan: &Plan) -> Result<Arc<Self>, Error> {
        use crate::{admin_sigma::StateWitness, tree::IndexedLeaf};
        use group::prime::PrimeCurveAffine;

        let p = AccumulatorT::<Ep>::new(EpAffine::generator(), [Fq::ONE; 16])
            .map_err(|_| Error::Artifact)?;
        let v = AccumulatorT::<Eq>::new(EqAffine::generator(), [Fp::ONE; 16])
            .map_err(|_| Error::Artifact)?;
        let operation = plan.context().operation();
        let specs = plan.context().object_specs();
        let state = StateWitness {
            core: [Fp::ZERO; 33],
            rest: [Fp::ZERO; 8],
            lineage: [Fp::ZERO; 18],
        };
        let path = IndexedRemove {
            predecessor: IndexedLeaf::default(),
            predecessor_slot: 0,
            predecessor_siblings: [Fp::ZERO; 32],
            leaf: IndexedLeaf::default(),
            slot: 1,
            leaf_siblings: [Fp::ZERO; 32],
        };
        let mut qs = Vec::with_capacity(3);
        let mut openings = Vec::with_capacity(3);
        for index in 0..3 {
            let fixed = operation.q(index).ok_or(Error::Artifact)?.verifier();
            qs.push(QInput {
                proof: vec![0; fixed.proof_length()],
                instances: fixed
                    .binding()
                    .descriptor()
                    .instance_lengths
                    .iter()
                    .map(|length| {
                        usize::try_from(*length)
                            .map(|length| vec![Fq::ZERO; length])
                            .map_err(|_| Error::Artifact)
                    })
                    .collect::<Result<_, _>>()?,
            });
            openings.push(
                FoldInput::from_opening(
                    *p.g(),
                    &vec![Fq::ONE; fixed.binding().descriptor().k as usize],
                )
                .map_err(|_| Error::Artifact)?,
            );
        }
        let evidence = match operation.frame().variant() {
            Variant::ArchiveReceive => Evidence::Receive {
                statement: [Fp::ZERO; 26],
                receipt: vec![0; specs[12].capacity as usize],
                sigma: vec![],
                credited: vec![0; specs[15].capacity as usize],
                mode: IncomingMode::Trivial,
            },
            Variant::ArchiveStatus => Evidence::Status {
                statement: [Fp::ZERO; 26],
                receipt: vec![0; specs[12].capacity as usize],
                omega: vec![],
                credited: vec![0; specs[15].capacity as usize],
                status: vec![0; specs[16].capacity as usize],
                credit_opening: vec![0; specs[17].capacity as usize],
                witness: Box::new(StatusWitness {
                    public: [Fp::ZERO; 18],
                    public_valid: false,
                    pallas: p.clone(),
                    vesta: v.clone(),
                    opening: p.as_input(),
                    modes: [IncomingMode::Trivial; 3],
                    pallas_corrections: [*p.g(); 2],
                    vesta_correction: *v.g(),
                }),
            },
            _ => return Err(Error::Artifact),
        };
        let input = Inputs {
            state: ArchiveWitness {
                predecessor: state,
                successor: state,
                statement: [Fp::ZERO; 26],
            },
            removals: [path; 2],
            own: core::array::from_fn(|i| vec![0; specs[i].capacity as usize]),
            sigma: vec![
                0;
                operation
                    .sigma
                    .class(0)
                    .ok_or(Error::Artifact)?
                    .verifier()
                    .proof_length()
            ],
            retained: RetainedPayment {
                signed: core::array::from_fn(|i| vec![0; specs[i + 3].capacity as usize]),
                payment: vec![0; specs[7].capacity as usize],
                statement: [Fp::ZERO; 26],
                omega: vec![0; 320],
                sigma: vec![],
            },
            evidence,
            results: [false; 3],
            q: qs.try_into().map_err(|_| Error::Artifact)?,
            predecessor: PredecessorInput {
                proof: vec![0; operation.omega().ok_or(Error::Artifact)?.proof_length()],
                pallas: p.to_bytes(),
                vesta: v.to_bytes(),
            },
        };
        let part = FoldInput::from_opening(
            *v.g(),
            &vec![Fp::ONE; operation.sigma.part_source_k() as usize],
        )
        .map_err(|_| Error::Artifact)?;
        Ok(Arc::new(Self {
            plan: plan.clone(),
            input,
            commitments: vec![[Fp::ZERO; 3]; specs.len()],
            predecessor_opening: p.as_input(),
            predecessor: (p, v),
            q_openings: openings.try_into().map_err(|_| Error::Artifact)?,
            part,
            selected_status: None,
        }))
    }

    pub(super) fn first(
        self: &Arc<Self>,
        salt: Fp,
        config: &iroha_plonk_recursion::FoldConfig,
    ) -> Result<super::circuit::Stage, Error> {
        let (fold, pallas) = iroha_plonk_recursion::create_fold(
            &self.plan.pallas,
            &[
                self.predecessor.0.as_input(),
                self.predecessor_opening.clone(),
            ],
            salt.to_repr(),
            config,
        )
        .map_err(|error| {
            if error.is_cancelled() {
                Error::Cancelled
            } else {
                Error::Proof
            }
        })?;
        pallas
            .decide_cancellable(
                &self.plan.pallas,
                config.kernel_budget,
                config.cancellation.as_ref(),
            )
            .map_err(|error| {
                if error.is_cancelled() {
                    Error::Cancelled
                } else {
                    Error::Proof
                }
            })?;
        Ok(super::circuit::Stage {
            source: Arc::clone(self),
            continuation: None,
            pallas: pallas.clone(),
            fold: fold.to_bytes().to_vec(),
            known: true,
        })
    }

    /// Construct the actual A1 source and public frame for artifact tooling.
    /// The shared allocation retains original bytes once across all stage circuits.
    /// # Errors
    /// Failed two-input hard predecessor fold or public-frame conversion.
    pub fn first_circuit(
        self: &Arc<Self>,
        salt: Fp,
        config: &iroha_plonk_recursion::FoldConfig,
    ) -> Result<(StageCircuit, Vec<Fp>), Error> {
        let inner = self.first(salt, config)?;
        let public = inner.public()?;
        Ok((StageCircuit { inner }, public))
    }

    /// Fixed installed operation metadata.
    pub const fn plan(&self) -> &Plan {
        &self.plan
    }
    /// Exact retained originals and untrusted incoming proposals.
    pub const fn inputs(&self) -> &Inputs {
        &self.input
    }
    /// Same ordered object commitments that every owner must rederive.
    pub fn commitments(&self) -> &[[Fp; 3]] {
        &self.commitments
    }
    /// Full deciding hard predecessor claims, in Pallas/Vesta order.
    pub const fn predecessor_claims(&self) -> &(AccumulatorT<Ep>, AccumulatorT<Eq>) {
        &self.predecessor
    }
    /// Actual hard predecessor verifier opening.
    pub const fn predecessor_opening(&self) -> &FoldInput<Ep> {
        &self.predecessor_opening
    }
    /// Actual openings of Q0, Q1 and Q2; none may be dropped or deduplicated.
    pub const fn q_openings(&self) -> &[FoldInput<Ep>; 3] {
        &self.q_openings
    }
    /// Exact deciding source part exported by Q0.
    pub const fn part(&self) -> &FoldInput<Eq> {
        &self.part
    }
    /// Selected deciding Status obligations; circuits must authenticate the modes.
    pub const fn selected_status(&self) -> Option<&([FoldInput<Ep>; 2], FoldInput<Eq>)> {
        self.selected_status.as_ref()
    }
}

impl Plan {
    /// Verify all hard proofs and deciding obligations while preserving soft originals.
    /// The complete A/W producer must still bind every result and source commitment.
    /// # Errors
    /// Wrong original shape, continuity key, hard proof or selected obligation.
    pub fn prepare(&self, input: Inputs, budget: MemoryBudget) -> Result<Prepared, Error> {
        self.prepare_cancellable(input, budget, None)
    }
    /// Execute the same native check with an explicit operation signal.
    /// # Errors
    /// As the ordinary entry point, or cancellation without a partial verdict.
    pub fn prepare_cancellable(
        &self,
        input: Inputs,
        budget: MemoryBudget,
        cancellation: Option<&iroha_pasta::CancellationToken>,
    ) -> Result<Prepared, Error> {
        iroha_pasta::CancellationToken::checkpoint(cancellation).map_err(|_| Error::Cancelled)?;
        self.validate_original_shapes(&input)?;
        let program = self.context().operation();
        let omega = program.omega().ok_or(Error::Artifact)?;
        support::check_hard_own_tapes(
            input.own.each_ref().map(Vec::as_slice),
            &input.q[1].instances,
            core::array::from_fn(|i| input.state.predecessor.lineage[9 + i]),
            [self.policy.root.x, self.policy.root.y],
        )?;
        support::check_own_sigma_tape(
            &input.q[0].instances,
            program.sigma.chunk_range(0).ok_or(Error::Artifact)?,
            &input.state.statement,
            &input.sigma,
        )?;
        let pallas =
            AccumulatorT::<Ep>::from_bytes(&input.predecessor.pallas).map_err(|_| Error::Input)?;
        let vesta =
            AccumulatorT::<Eq>::from_bytes(&input.predecessor.vesta).map_err(|_| Error::Input)?;
        if pallas.as_input().source_k() != 16 || vesta.as_input().source_k() != 16 {
            return Err(Error::Input);
        }
        pallas
            .decide_cancellable(&self.pallas, budget, cancellation)
            .map_err(|error| {
                if error.is_cancelled() {
                    Error::Cancelled
                } else {
                    Error::Proof
                }
            })?;
        vesta
            .decide_cancellable(&self.vesta, budget, cancellation)
            .map_err(|error| {
                if error.is_cancelled() {
                    Error::Cancelled
                } else {
                    Error::Proof
                }
            })?;
        let key = self
            .predecessor_key
            .kagemusha_digest(omega.binding())
            .map_err(|_| Error::Artifact)?;
        if input.state.predecessor.lineage[17] != key || input.state.successor.lineage[17] != key {
            return Err(Error::Input);
        }
        let public = support::omega_instances(
            support::terminal_digest(&input.state.predecessor.lineage, &pallas.as_input())?,
            &vesta,
        )?;
        iroha_plonk::verifier::verify_full_cancellable(
            &self.pallas,
            omega.binding(),
            &self.predecessor_key,
            &public,
            &input.predecessor.proof,
            budget,
            cancellation,
        )
        .map_err(|error| {
            if error.is_cancelled() {
                Error::Cancelled
            } else {
                Error::Proof
            }
        })?;
        let predecessor_opening = support::opening_pallas_cancellable(
            &self.pallas,
            omega.binding(),
            &self.predecessor_key,
            &public,
            &input.predecessor.proof,
            budget,
            cancellation,
        )?;
        let mut q_openings = Vec::with_capacity(3);
        for (index, source) in input.q.iter().enumerate() {
            let fixed = program.q(index).ok_or(Error::Artifact)?;
            iroha_plonk::verifier::verify_full_cancellable(
                fixed.verifier().params(),
                fixed.verifier().binding(),
                &fixed.key,
                &source.instances,
                &source.proof,
                budget,
                cancellation,
            )
            .map_err(|error| {
                if error.is_cancelled() {
                    Error::Cancelled
                } else {
                    Error::Proof
                }
            })?;
            q_openings.push(support::opening_pallas_cancellable(
                fixed.verifier().params(),
                fixed.verifier().binding(),
                &fixed.key,
                &source.instances,
                &source.proof,
                budget,
                cancellation,
            )?);
        }
        let part = support::q_sigma_part(&input.q[0].instances, &program.sigma)?;
        part.decide_cancellable(&self.vesta, budget, cancellation)
            .map_err(|error| {
                if error.is_cancelled() {
                    Error::Cancelled
                } else {
                    Error::Proof
                }
            })?;
        let selected_status = if let Evidence::Status { witness, .. } = &input.evidence {
            if witness.pallas.as_input().source_k() != 16
                || witness.vesta.as_input().source_k() != 16
                || witness.opening.source_k() != 16
            {
                return Err(Error::Input);
            }
            Some((
                [
                    support::select_pallas_cancellable(
                        &self.pallas,
                        &witness.pallas.as_input(),
                        witness.modes[0],
                        witness.pallas_corrections[0],
                        budget,
                        cancellation,
                    )?,
                    support::select_pallas_cancellable(
                        &self.pallas,
                        &witness.opening,
                        witness.modes[1],
                        witness.pallas_corrections[1],
                        budget,
                        cancellation,
                    )?,
                ],
                support::select_vesta_cancellable(
                    &self.vesta,
                    &witness.vesta.as_input(),
                    witness.modes[2],
                    witness.vesta_correction,
                    budget,
                    cancellation,
                )?,
            ))
        } else {
            None
        };
        let commitments = self.original_commitments(&input)?;
        Ok(Prepared {
            plan: self.clone(),
            input,
            commitments,
            predecessor: (pallas, vesta),
            predecessor_opening,
            q_openings: q_openings.try_into().map_err(|_| Error::Input)?,
            part,
            selected_status,
        })
    }

    /// Compute all exact original-source commitments and the typed result proposal.
    /// This is deterministic witness preparation, not authentication of any soft bit.
    /// # Errors
    /// Wrong original shape, hard joint bound or noncanonical proposed Status opening.
    pub fn original_commitments(&self, input: &Inputs) -> Result<Vec<[Fp; 3]>, Error> {
        self.validate_original_shapes(input)?;
        self.original_commitments_from_parts(
            &input.own,
            &input.retained,
            &input.evidence,
            input.results,
        )
    }

    // The same original tape commitments are needed before Q exists. This helper
    // produces no Q or source-verification capability, and every actual A owner
    // rebinds its named original tape after Q production.
    pub(super) fn original_commitments_from_parts(
        &self,
        own: &[Vec<u8>; 3],
        retained: &RetainedPayment,
        evidence: &Evidence,
        result_bits: [bool; 3],
    ) -> Result<Vec<[Fp; 3]>, Error> {
        let specs = self.context().object_specs();
        let mut out = Vec::with_capacity(specs.len());
        for (kind, raw) in [
            ObjectKind::Credential,
            ObjectKind::Certificate,
            ObjectKind::Receipt,
        ]
        .into_iter()
        .zip(own)
        .chain(
            [
                ObjectKind::Request,
                ObjectKind::Credential,
                ObjectKind::Receipt,
                ObjectKind::Credential,
            ]
            .into_iter()
            .zip(&retained.signed),
        ) {
            out.push(support::exact_context(
                specs[out.len()],
                support::object_digest(kind, raw)?,
                raw,
            )?);
        }
        let digest =
            |domain: [u8; 8], bytes: &[u8]| p_bytes_native(u64::from_le_bytes(domain), bytes);
        out.push(support::exact_context(
            specs[7],
            digest(*b"kgwpay_1", &retained.payment),
            &retained.payment,
        )?);
        out.push(support::internal_context(specs[8], &retained.statement)?);
        let mut proof_tape = support::frame(&retained.omega)?;
        proof_tape.extend(support::frame(&retained.sigma)?);
        let proof_digest = digest(*b"kgwprf_1", &proof_tape);
        for (slot, raw) in [(9, &retained.omega), (10, &retained.sigma)] {
            out.push(support::active_context(specs[slot], proof_digest, raw)?);
        }
        out.push(support::internal_context(
            specs[11],
            &retained.statement[17..24],
        )?);
        let (statement, receipt, raw, credited, raw_digest) = match evidence {
            Evidence::Receive {
                statement,
                receipt,
                sigma,
                credited,
                ..
            } => (
                statement,
                receipt,
                sigma,
                credited,
                digest(*b"kgwstep1", &support::frame(sigma)?),
            ),
            Evidence::Status {
                statement,
                receipt,
                omega,
                credited,
                ..
            } => (
                statement,
                receipt,
                omega,
                credited,
                digest(*b"kgwlin_1", omega),
            ),
        };
        out.push(support::exact_context(
            specs[12],
            support::object_digest(ObjectKind::Receipt, receipt)?,
            receipt,
        )?);
        out.push(support::active_context(specs[13], raw_digest, raw)?);
        out.push(support::internal_context(specs[14], statement)?);
        out.push(support::exact_context(
            specs[15],
            digest(*b"kgwcrdd1", credited),
            credited,
        )?);
        if let Evidence::Status {
            status,
            credit_opening,
            ..
        } = evidence
        {
            out.push(support::exact_context(
                specs[16],
                digest(*b"kgwcsts1", status),
                status,
            )?);
            out.push(support::exact_context(
                specs[17],
                digest(*b"kgwcopn1", credit_opening),
                credit_opening,
            )?);
        }
        let mut results = vec![
            Fp::ONE,
            Fp::from(if matches!(evidence, Evidence::Receive { .. }) {
                1
            } else {
                2
            }),
        ];
        for tag in ArchiveResultTag::ALL {
            results.extend([
                Fp::from(tag as u64),
                Fp::from(u64::from(self.stage.results().owner(tag))),
            ]);
        }
        results.extend(result_bits.map(|v| Fp::from(u64::from(v))));
        if let Evidence::Status { witness, .. } = evidence {
            support::push_pallas(&mut results, &witness.opening)?;
        }
        out.push(support::internal_context(
            *specs.last().ok_or(Error::Artifact)?,
            &results,
        )?);
        Ok(out)
    }
}
