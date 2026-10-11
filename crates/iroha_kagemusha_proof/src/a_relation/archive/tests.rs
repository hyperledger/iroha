//! Archive schema/dispatch metadata tests; no fixture key is admitted.

mod current_omega_soft;
mod hard_predecessor;
#[path = "../../../tests/common/proof_fixtures/omega_hard_fixture.rs"]
mod omega_fixture;
mod real_sources;
mod stage_context;

use super::*;
use crate::{
    a_relation::{AProofPlan, QProofPlan, own::OwnPolicy},
    q_sigma::{QSigmaPlan, SigmaClass},
    q_signature::QSignaturePlan,
};
use iroha_pasta::{Ep, Eq, Fp, Fq, PastaField};
use iroha_plonk::{
    cs::{ConstraintSystem, InstanceType},
    frontend::{Circuit, Layouter, SimpleFloorPlanner},
    keys::{KeygenConfigV2, keygen_vk_with_binding_v2},
    pcs::ipa::PinnedParams,
};
use iroha_plonk_gadgets::p256::native::Affine;
use iroha_plonk_recursion::verifier::VerifierPlan;
use stage::ArchiveStagePlan;
use std::marker::PhantomData;

#[test]
fn complete_archive_schema_covers_both_full_credited_envelope_domains() {
    for variant in Variant::ALL {
        let result = ArchiveStagePlan::full_context_specs(variant);
        let capacity = match variant {
            Variant::ArchiveReceive => MAX_RECEIVE_SIGMA_RAW_BYTES,
            Variant::ArchiveStatus => MAX_STATUS_OMEGA_RAW_BYTES,
            _ => {
                assert!(result.is_err());
                continue;
            }
        };
        let specs = result.unwrap();
        assert_eq!(specs[9].capacity, 8_597);
        assert_eq!(specs[10].capacity, 8_277);
        assert_eq!(specs[13].capacity, u32::try_from(capacity).unwrap());
        assert_eq!(
            specs,
            ArchiveStagePlan::context_specs(variant, 8_597, 8_277, capacity).unwrap()
        );
        assert!(specs[13].capacity > 3_456);
        assert_eq!(
            specs.len(),
            if variant == Variant::ArchiveReceive {
                17
            } else {
                19
            }
        );
    }
    assert_eq!(MAX_RECEIVE_SIGMA_RAW_BYTES + 679, 10_000);
    assert_eq!(MAX_STATUS_OMEGA_RAW_BYTES - 320 + 2_188, 10_000);
}

#[test]
fn archive_envelope_capacities_match_regenerated_g1_bounds() {
    let fixture: norito::json::Value = norito::json::from_str(include_str!(
        "../../../../../fixtures/kagemusha/wallet_v1_vectors.json"
    ))
    .unwrap();
    let bounds = &fixture["bounds"];
    let number = |name: &str| usize::try_from(bounds[name].as_u64().unwrap()).unwrap();
    let message = number("message_max_bytes");
    assert_eq!(
        MAX_RECEIVE_SIGMA_RAW_BYTES,
        number("credited_receive_proof_budget_bytes")
    );
    assert_eq!(
        MAX_RECEIVE_SIGMA_RAW_BYTES + number("credited_receive_fixed_bytes"),
        message
    );
    assert_eq!(
        MAX_STATUS_OMEGA_RAW_BYTES - 320 + number("credited_status_fixed_bytes"),
        message
    );
    assert_eq!(
        MAX_STATUS_OMEGA_RAW_BYTES - 320,
        number("lineage_proof_cap_bytes")
    );
    let specs = ArchiveStagePlan::full_context_specs(Variant::ArchiveStatus).unwrap();
    assert_eq!(
        usize::try_from(specs[10].capacity).unwrap(),
        number("payment_proof_budget_bytes")
    );
    assert_eq!(
        usize::try_from(specs[9].capacity).unwrap(),
        number("payment_proof_budget_bytes") + 320
    );
}

// This constructor-only fixture declares exact instance columns. Its keys and
// nonexistent proofs never authenticate operation execution or wallet artifacts.
#[derive(Clone)]
struct Metadata<F>(Vec<usize>, PhantomData<F>);
impl<F: PastaField> Circuit<F> for Metadata<F> {
    type Config = ();
    type Params = Vec<usize>;
    type FloorPlanner = SimpleFloorPlanner;
    fn params(&self) -> Self::Params {
        self.0.clone()
    }
    fn without_witnesses(&self) -> Self {
        self.clone()
    }
    fn configure(meta: &mut ConstraintSystem<F>) {
        Self::configure_with_params(meta, vec![1]);
    }
    fn configure_with_params(meta: &mut ConstraintSystem<F>, lengths: Vec<usize>) {
        for n in lengths {
            meta.instance_column(n);
        }
    }
    fn synthesize(&self, (): (), _: impl Layouter<F>) -> Result<(), Error> {
        Ok(())
    }
}

fn tasks() -> Vec<Vec<OperationTask>> {
    use OperationTask::*;
    vec![
        vec![ArchiveRetainedPayment, ArchiveProofs, ArchiveOwnProof],
        vec![ArchiveAuthorization],
        vec![ArchiveSignatures],
        vec![ArchiveEvidence],
        vec![
            ArchiveEffects,
            ArchiveRetainedProofs,
            ArchiveCorePending,
            ArchiveLineagePending,
        ],
    ]
}
pub(super) fn operation(
    variant: Variant,
) -> (AProofPlan, OwnPolicy, iroha_plonk::VerifyingKey<Ep>) {
    let policy = OwnPolicy::new([31, 32], Affine::GENERATOR).unwrap();
    let p = PinnedParams::<Ep>::derive(16).unwrap();
    let v = PinnedParams::<Eq>::derive(16).unwrap();
    let leaf_params = PinnedParams::<Eq>::derive(12).unwrap();
    let (binding, key) = keygen_vk_with_binding_v2(
        &leaf_params,
        &Metadata::<Fp>(vec![1], PhantomData),
        &KeygenConfigV2::pipa_r(vec![InstanceType::Bounded]),
    )
    .unwrap();
    let digest = key.kagemusha_digest(&binding).unwrap();
    let leaf = VerifierPlan::new(binding, leaf_params).unwrap();
    let own = SigmaClass::new(leaf, vec![(12, digest)]).unwrap();
    let incoming = (variant == Variant::ArchiveReceive).then(|| {
        // Distinct selector indices require distinct authenticated key digests.
        // A different constructor-only domain supplies that distinction without
        // weakening the production selector/digest bijection.
        let params = PinnedParams::<Eq>::derive(14).unwrap();
        let (binding, key) = keygen_vk_with_binding_v2(
            &params,
            &Metadata::<Fp>(vec![1], PhantomData),
            &KeygenConfigV2::pipa_r(vec![InstanceType::Bounded]),
        )
        .unwrap();
        let digest = key.kagemusha_digest(&binding).unwrap();
        SigmaClass::new(
            VerifierPlan::new(binding, params).unwrap(),
            vec![(10, digest)],
        )
        .unwrap()
    });
    let sigma = QSigmaPlan::new(own, incoming, &v).unwrap();
    let schemas = authorization::ArchiveAuthorizationObjects::signature_schemas(policy).unwrap();
    let mut q = Vec::new();
    for (lengths, types) in std::iter::once((
        sigma.instance_lengths().to_vec(),
        QSigmaPlan::instance_types().to_vec(),
    ))
    .chain(schemas.iter().map(|s| {
        (
            vec![s.instance_length()],
            QSignaturePlan::instance_types().to_vec(),
        )
    })) {
        let (binding, key) = keygen_vk_with_binding_v2(
            &p,
            &Metadata::<Fq>(lengths, PhantomData),
            &KeygenConfigV2::pipa_r(types),
        )
        .unwrap();
        q.push(QProofPlan::new(VerifierPlan::new(binding, p.clone()).unwrap(), key).unwrap());
    }
    let (binding, omega_key) = keygen_vk_with_binding_v2(
        &p,
        &Metadata::<Fq>(vec![1, 2, 16], PhantomData),
        &KeygenConfigV2::pipa_r(vec![
            InstanceType::Bounded,
            InstanceType::Field,
            InstanceType::Bounded,
        ]),
    )
    .unwrap();
    let omega = VerifierPlan::new(binding, p.clone()).unwrap();
    (
        AProofPlan::new(variant, sigma, q, Some(omega), &p).unwrap(),
        policy,
        omega_key,
    )
}

#[test]
fn archive_stage_schema_requires_all_original_categories_results_and_q_owners() {
    use OperationTask::*;

    for variant in [Variant::ArchiveReceive, Variant::ArchiveStatus] {
        let (operation, policy, _) = operation(variant);
        let full = ArchiveStagePlan::full(operation.clone(), policy).unwrap();
        assert_eq!(full.context().stage_count(), 10);
        assert_eq!(full.context().predecessor_stage(), Some(0));
        assert_eq!(
            full.context().object_specs(),
            ArchiveStagePlan::full_context_specs(variant).unwrap()
        );
        for (stage, (tasks, q)) in [
            (vec![ArchiveOwnProof, ArchiveCorePending], None),
            (vec![ArchiveRetainedProofs], None),
            (vec![ArchiveSignatures], Some(2)),
            (vec![ArchiveAuthorization], Some(1)),
            (vec![ArchiveLineagePending], None),
            (vec![ArchiveProofs], None),
            (vec![], Some(0)),
            (vec![ArchiveEvidence], None),
            (vec![ArchiveRetainedPayment], None),
            (vec![ArchiveEffects], None),
        ]
        .into_iter()
        .enumerate()
        {
            assert_eq!(
                full.context().operation_tasks(stage),
                Some(tasks.as_slice())
            );
            assert_eq!(
                full.context().q_partition(stage),
                Some(q.into_iter().collect::<Vec<_>>().as_slice())
            );
        }
        let specs = ArchiveStagePlan::context_specs(variant, 5120, 3456, 5120).unwrap();
        let partition = vec![vec![0], vec![1], vec![2], vec![], vec![]];
        let make = |operation, partition, specs, groups| {
            ContextPlan::with_schedule(operation, partition, Some(0), specs)
                .and_then(|p| p.with_operation_tasks(groups))
                .and_then(|p| ArchiveStagePlan::new(p, policy))
        };
        let plan = make(operation.clone(), partition.clone(), specs.clone(), tasks()).unwrap();
        assert_eq!(plan.context().stage_count(), 5);
        assert_eq!(
            plan.context().object_specs().len(),
            if variant == Variant::ArchiveReceive {
                17
            } else {
                19
            }
        );
        assert_eq!(plan.results().spec(), *specs.last().unwrap());
        assert!(plan.signature_schema(0).is_none());
        assert!(plan.signature_schema(3).is_none());
        assert_eq!(plan.signature_schema(1).unwrap().slots().len(), 3);
        assert_eq!(plan.signature_schema(2).unwrap().slots().len(), 1);
        for i in 0..specs.len() {
            if [9, 10, 13].contains(&i) {
                continue;
            }
            let mut changed = specs.clone();
            changed[i].capacity += 1;
            assert!(
                make(operation.clone(), partition.clone(), changed, tasks()).is_err(),
                "capacity{i}"
            );
        }
        for index in 0..specs.len() {
            let mut changed = specs.clone();
            changed.remove(index);
            assert!(
                make(operation.clone(), partition.clone(), changed, tasks()).is_err(),
                "missing source{index}"
            );
        }
        for task in OperationTask::required(variant) {
            for duplicate in [false, true] {
                let mut changed = tasks();
                if duplicate {
                    changed[4].push(*task);
                    changed[4].sort_unstable();
                } else {
                    for group in &mut changed {
                        group.retain(|t| t != task);
                    }
                }
                assert!(
                    make(operation.clone(), partition.clone(), specs.clone(), changed).is_err(),
                    "task{task:?} duplicate{duplicate}"
                );
            }
        }
        for changed in [
            vec![vec![0], vec![2], vec![1], vec![], vec![]],
            vec![vec![0], vec![1], vec![], vec![2], vec![]],
            vec![vec![0], vec![1], vec![2], vec![], vec![2]],
        ] {
            assert!(make(operation.clone(), changed, specs.clone(), tasks()).is_err());
        }
        let p = PinnedParams::<Ep>::derive(16).unwrap();
        let wrong = AProofPlan::new(
            variant,
            operation.sigma.clone(),
            vec![
                operation.q(0).unwrap().clone(),
                operation.q(2).unwrap().clone(),
                operation.q(1).unwrap().clone(),
            ],
            operation.omega().cloned(),
            &p,
        )
        .unwrap();
        assert!(make(wrong, partition, specs, tasks()).is_err());
    }
    for variant in Variant::ALL {
        assert_eq!(
            ArchiveStagePlan::context_specs(variant, 1, 1, 1).is_ok(),
            matches!(variant, Variant::ArchiveReceive | Variant::ArchiveStatus)
        );
    }
    for sizes in [[0, 1, 1], [1, 0, 1], [1, 1, 0], [1, 1, usize::MAX]] {
        assert!(
            ArchiveStagePlan::context_specs(Variant::ArchiveStatus, sizes[0], sizes[1], sizes[2])
                .is_err()
        );
    }
}

#[test]
fn native_archive_intake_preserves_full_soft_originals_without_certifying_them() {
    use crate::q_sigma::native::IncomingMode;
    use crate::{
        a_relation::native::archive as native,
        admin_sigma::{ArchiveWitness, StateWitness},
        tree::{IndexedLeaf, IndexedRemove},
    };
    use ff::Field;
    use iroha_pasta::msm::MemoryBudget;
    use iroha_plonk_recursion::AccumulatorT;
    for variant in [Variant::ArchiveReceive, Variant::ArchiveStatus] {
        let (operation, policy, key) = operation(variant);
        let p = PinnedParams::<Ep>::derive(16).unwrap();
        let v = PinnedParams::<Eq>::derive(16).unwrap();
        let own_length = operation.sigma.class(0).unwrap().verifier().proof_length();
        let plan = native::Plan::new(operation.clone(), policy, key.clone(), p.clone(), v.clone())
            .unwrap();
        assert_eq!(plan.context().stage_count(), native::A_STAGE_COUNT);
        assert_eq!(plan.stage().context().schema(), plan.context().schema());
        assert_eq!(plan.predecessor_key().to_bytes(), key.to_bytes());
        plan.pallas().require_k(16).unwrap();
        plan.vesta().require_k(16).unwrap();
        assert!(
            native::Plan::new(
                operation,
                policy,
                key,
                PinnedParams::derive(12).unwrap(),
                v.clone()
            )
            .is_err()
        );
        let specs = plan.context().object_specs();
        let pallas = AccumulatorT::trivial(&p, MemoryBudget::DEFAULT).unwrap();
        let vesta = AccumulatorT::trivial(&v, MemoryBudget::DEFAULT).unwrap();
        let receive = native::Evidence::Receive {
            statement: [Fp::ZERO; 26],
            receipt: vec![0; specs[12].capacity as usize],
            sigma: vec![0x37; MAX_RECEIVE_SIGMA_RAW_BYTES],
            credited: vec![0; specs[15].capacity as usize],
            mode: IncomingMode::Trivial,
        };
        let status = native::Evidence::Status {
            statement: [Fp::ZERO; 26],
            receipt: vec![0; specs[12].capacity as usize],
            omega: vec![0x51; MAX_STATUS_OMEGA_RAW_BYTES],
            credited: vec![0; specs[15].capacity as usize],
            status: vec![0; 162],
            credit_opening: vec![0; 1125],
            witness: Box::new(native::StatusWitness {
                public: [Fp::ZERO; 18],
                public_valid: false,
                pallas: pallas.clone(),
                vesta: vesta.clone(),
                opening: pallas.as_input(),
                modes: [IncomingMode::Trivial; 3],
                pallas_corrections: [*pallas.g(); 2],
                vesta_correction: *vesta.g(),
            }),
        };
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
        // Deliberately invalid metadata-only objects: shape preparation must not
        // certify a predicate or turn this fixture into a hard proof source.
        let mut input = native::Inputs {
            state: ArchiveWitness {
                predecessor: state,
                successor: state,
                statement: [Fp::ZERO; 26],
            },
            removals: [path; 2],
            own: core::array::from_fn(|i| vec![0; specs[i].capacity as usize]),
            sigma: vec![0; own_length],
            retained: native::RetainedPayment {
                signed: core::array::from_fn(|i| vec![0; specs[i + 3].capacity as usize]),
                payment: vec![0; specs[7].capacity as usize],
                statement: [Fp::ZERO; 26],
                omega: vec![0; 320],
                sigma: vec![0; 8277],
            },
            evidence: if variant == Variant::ArchiveReceive {
                receive.clone()
            } else {
                status.clone()
            },
            results: [false; 3],
            q: core::array::from_fn(|_| native::QInput {
                proof: vec![],
                instances: vec![],
            }),
            predecessor: native::PredecessorInput {
                proof: vec![],
                pallas: pallas.to_bytes(),
                vesta: vesta.to_bytes(),
            },
        };
        assert_eq!(plan.validate_original_shapes(&input), Ok(()));
        let commitments = plan.original_commitments(&input).unwrap();
        assert_eq!(commitments.len(), specs.len());
        assert_eq!(commitments[13][1], Fp::from(u64::from(specs[13].capacity)));
        assert!(plan.prepare(input.clone(), MemoryBudget::DEFAULT).is_err());
        let mut changed = input.clone();
        let raw = match &mut changed.evidence {
            native::Evidence::Receive { sigma, .. } => sigma,
            native::Evidence::Status { omega, .. } => omega,
        };
        *raw.last_mut().unwrap() ^= 1;
        let different = plan.original_commitments(&changed).unwrap();
        assert_ne!(
            different[13], commitments[13],
            "full original tail is bound"
        );
        for slot in (0..commitments.len()).filter(|slot| *slot != 13) {
            assert_eq!(different[slot], commitments[slot]);
        }
        let raw = match &mut changed.evidence {
            native::Evidence::Receive { sigma, .. } => sigma,
            native::Evidence::Status { omega, .. } => omega,
        };
        raw.push(0);
        assert_eq!(
            plan.validate_original_shapes(&changed),
            Err(native::Error::Input)
        );
        match &mut changed.evidence {
            native::Evidence::Receive { sigma, .. } => sigma.clear(),
            native::Evidence::Status { omega, .. } => omega.clear(),
        }
        assert_eq!(
            plan.validate_original_shapes(&changed),
            Ok(()),
            "empty original remains a total soft input"
        );
        assert_eq!(
            plan.original_commitments(&changed).unwrap()[13][1],
            Fp::ZERO
        );
        changed = input.clone();
        changed.retained.omega.push(0);
        assert_eq!(
            plan.validate_original_shapes(&changed),
            Err(native::Error::Input)
        );
        for slot in 0..3 {
            changed = input.clone();
            changed.own[slot].pop();
            assert!(plan.validate_original_shapes(&changed).is_err());
        }
        for slot in 0..4 {
            changed = input.clone();
            changed.retained.signed[slot].push(0);
            assert!(plan.validate_original_shapes(&changed).is_err());
        }
        changed = input.clone();
        changed.sigma.pop();
        assert!(plan.validate_original_shapes(&changed).is_err());
        changed = input.clone();
        changed.retained.payment.pop();
        assert!(plan.validate_original_shapes(&changed).is_err());
        for result in 0..3 {
            changed = input.clone();
            changed.results[result] = true;
            assert_ne!(
                plan.original_commitments(&changed).unwrap().last(),
                commitments.last()
            );
        }
        if let native::Evidence::Status { witness, .. } = &mut input.evidence {
            witness.opening = iroha_plonk_recursion::FoldInput::from_opening(
                *pallas.g(),
                &[iroha_pasta::Fq::ONE; 12],
            )
            .unwrap();
            assert!(plan.original_commitments(&input).is_err());
        }
        input.evidence = if variant == Variant::ArchiveReceive {
            status
        } else {
            receive
        };
        assert!(plan.validate_original_shapes(&input).is_err());
    }
}

// Unknown source layout/import evidence only. The constructor metadata keys
// below contain no operation proofs and cannot stand in for real Q workloads.
fn native_source_import_sweep(
    variant: Variant,
    real_q: bool,
    import: bool,
    captured_predecessor: bool,
) {
    native_source_import_sweep_with_incoming_k(variant, real_q, import, captured_predecessor, 12);
}

fn native_source_import_sweep_with_incoming_k(
    variant: Variant,
    real_q: bool,
    import: bool,
    captured_predecessor: bool,
    incoming_k: u32,
) {
    use crate::a_relation::{
        native::{archive as native, artifact::KeyArtifact},
        split::{WCircuit, WKey},
    };
    use ff::Field;
    use iroha_pasta::msm::MemoryBudget;
    use iroha_plonk::{
        Protocol,
        frontend::synthesize,
        keys::{keygen_pk_v2, pk::artifact::ReadConfig},
    };
    assert!(!captured_predecessor || real_q);
    assert!(incoming_k == 12 || captured_predecessor);
    let (operation, policy, predecessor) = if captured_predecessor {
        let (binding, key) = real_sources::read_captured_metadata();
        real_sources::captured_operation(variant, binding, key, incoming_k)
    } else if real_q {
        real_sources::operation(variant)
    } else {
        operation(variant)
    };
    let p = PinnedParams::<Ep>::derive(16).unwrap();
    let v = PinnedParams::<Eq>::derive(16).unwrap();
    let plan = native::Plan::new(operation, policy, predecessor, p.clone(), v.clone()).unwrap();
    let expected_buses = native::INTERNAL_RANGE_BUSES;
    assert_eq!(
        plan.source_circuit(0, None).unwrap().params(),
        expected_buses
    );
    assert!(plan.source_circuit(1, None).is_err());
    assert!(plan.source_circuit(native::A_STAGE_COUNT, None).is_err());
    let mut a_config = KeygenConfigV2::pipa_r(vec![InstanceType::Bounded]);
    a_config.compress_selectors = false;
    let mut w_config = KeygenConfigV2::pipa_r(crate::omega::OmegaPlan::instance_types().to_vec());
    w_config.compress_selectors = false;
    let mut a = Vec::new();
    let mut w = Vec::new();
    let mut wrappers = Vec::new();
    let wrapper_source = |stage: usize, a: &KeyArtifact<Eq>| {
        let length = Protocol::new(a.binding().descriptor())
            .unwrap()
            .proof_length();
        WCircuit::new(
            plan.context(),
            stage,
            a.binding().clone(),
            v.clone(),
            vec![a.key().kagemusha_digest(a.binding()).unwrap()],
            crate::omega::OmegaWitness {
                key: a.key().clone(),
                instances: vec![Fp::ZERO; 69],
                proof: vec![0; length],
                length: u32::try_from(length).unwrap(),
                fold: [0; 1120],
            },
        )
        .unwrap()
        .without_witnesses()
    };
    for stage in 0..native::A_STAGE_COUNT {
        let circuit = plan
            .source_circuit(stage, wrappers.last().cloned())
            .unwrap();
        assert_eq!(
            circuit.params(),
            if stage + 1 == native::A_STAGE_COUNT {
                3
            } else {
                expected_buses
            }
        );
        let layout = synthesize(&circuit, 16, None).unwrap_or_else(|error| {
            if let Ok(diagnostic) = synthesize(&circuit, 17, None) {
                let rows = diagnostic.tables.advice_assigned().iter().map(|column| {
                    column.iter().rposition(|assigned| *assigned).map_or(0, |i| i + 1)
                }).collect::<Vec<_>>();
                eprintln!("ARCHIVE_OVERFLOW_DIAGNOSTIC variant={variant:?} stage={stage} rows={rows:?} k17_diagnostic_only=true hard_k16_failed=true");
            }
            panic!("Archive {variant:?} stage{stage} exceeds hard k16: {error:?}");
        });
        let repeated = synthesize(&circuit.without_witnesses(), 16, None).unwrap();
        assert_eq!(layout.tables.fixed(), repeated.tables.fixed());
        assert_eq!(layout.tables.permutation(), repeated.tables.permutation());
        assert_eq!(
            layout.tables.advice_assigned(),
            repeated.tables.advice_assigned()
        );
        let max_rows = layout
            .tables
            .advice_assigned()
            .iter()
            .map(|column| {
                column
                    .iter()
                    .rposition(|assigned| *assigned)
                    .map_or(0, |i| i + 1)
            })
            .max()
            .unwrap();
        eprintln!(
            "ARCHIVE_UNKNOWN_SOURCE variant={variant:?} stage={stage} max_rows={max_rows} real_Q_source={real_q} incoming_sigma_k={incoming_k} captured_predecessor={captured_predecessor} real_workload_qualification=false"
        );
        drop((layout, repeated));
        let (binding, key) = keygen_vk_with_binding_v2(&v, &circuit, &a_config).unwrap();
        let artifact = KeyArtifact::new(binding, key).unwrap();
        if stage < native::W_STAGE_COUNT {
            let source = wrapper_source(stage, &artifact);
            let (binding, key) = keygen_vk_with_binding_v2(&p, &source, &w_config).unwrap();
            wrappers.push(
                WKey::from_artifact(
                    plan.context(),
                    stage,
                    binding.clone(),
                    p.clone(),
                    key.clone(),
                )
                .unwrap(),
            );
            w.push(KeyArtifact::new(binding, key).unwrap());
        }
        a.push(artifact);
    }
    assert!(plan.source_circuit(0, Some(wrappers[0].clone())).is_err());
    assert!(plan.source_circuit(2, Some(wrappers[0].clone())).is_err());
    if !import {
        return;
    }
    let prover = native::Prover::from_artifacts(
        plan.clone(),
        a.clone().try_into().unwrap(),
        w.try_into().unwrap(),
    )
    .unwrap();
    assert_eq!(
        prover.checkpoint_layouts().unwrap().len(),
        native::A_STAGE_COUNT + native::W_STAGE_COUNT
    );
    for stage in 0..native::A_STAGE_COUNT {
        let source = plan
            .source_circuit(stage, stage.checked_sub(1).map(|i| wrappers[i].clone()))
            .unwrap();
        let pk = keygen_pk_v2(&v, &source, &a_config).unwrap();
        assert_eq!(pk.vk().to_bytes(), a[stage].key().to_bytes());
        let original = pk.artifact_bytes_v2().unwrap();
        drop(pk);
        let read = ReadConfig {
            maximum_bytes: original.len(),
            maximum_rows: 1 << 16,
            coset_cache: iroha_plonk::keys::CosetCachePolicy::OnDemand,
            msm_budget: MemoryBudget::DEFAULT,
        };
        assert!(
            prover
                .import_a(stage, &original[..original.len() - 1], read)
                .is_err()
        );
        assert!(
            prover
                .import_a((stage + 1) % native::A_STAGE_COUNT, &original, read)
                .is_err()
        );
        let imported_seal = prover.import_a(stage, &original, read).unwrap();
        let imported = prover.bind_a(stage, &imported_seal, None).unwrap();
        assert_eq!(
            imported.verifying_key().to_bytes(),
            a[stage].key().to_bytes()
        );
        eprintln!(
            "ARCHIVE_SOURCE_IMPORT variant={variant:?} A={stage} original_bytes={} real_Q_source={real_q} incoming_sigma_k={incoming_k} captured_predecessor={captured_predecessor}",
            original.len()
        );
        drop((imported, original));
        if stage < native::W_STAGE_COUNT {
            let pk = keygen_pk_v2(&p, &wrapper_source(stage, &a[stage]), &w_config).unwrap();
            let original = pk.artifact_bytes_v2().unwrap();
            drop(pk);
            let read = ReadConfig {
                maximum_bytes: original.len(),
                ..read
            };
            assert!(
                prover
                    .import_w(stage, &original[..original.len() - 1], read)
                    .is_err()
            );
            assert!(
                prover
                    .import_w((stage + 1) % native::W_STAGE_COUNT, &original, read)
                    .is_err()
            );
            let imported_seal = prover.import_w(stage, &original, read).unwrap();
            let imported = prover.bind_w(stage, &imported_seal, None).unwrap();
            assert_eq!(
                imported.verifying_key().to_bytes(),
                wrappers[stage].verifying_key().to_bytes()
            );
            eprintln!(
                "ARCHIVE_SOURCE_IMPORT variant={variant:?} W={stage} original_bytes={} real_Q_source={real_q} incoming_sigma_k={incoming_k} captured_predecessor={captured_predecessor}",
                original.len()
            );
        }
    }
}

#[test]
#[ignore = "sequential full source key/import sweep; constructor-only Q metadata, not real proof qualification"]
fn native_archive_receive_unknown_sources_import_every_owner() {
    native_source_import_sweep(Variant::ArchiveReceive, false, true, false);
}

#[test]
#[ignore = "sequential full source key/import sweep; constructor-only Q metadata, not real proof qualification"]
fn native_archive_status_unknown_sources_import_every_owner() {
    native_source_import_sweep(Variant::ArchiveStatus, false, true, false);
}

#[test]
#[ignore = "actual Q source layout preflight; constructor predecessor, no operation proofs"]
fn native_archive_real_q_status_sources_fit() {
    native_source_import_sweep(Variant::ArchiveStatus, true, false, false);
}

#[test]
#[ignore = "actual Q source layout preflight; constructor predecessor, no operation proofs"]
fn native_archive_real_q_receive_sources_fit() {
    native_source_import_sweep(Variant::ArchiveReceive, true, false, false);
}

#[test]
#[ignore = "actual Q source original-key import sweep; constructor predecessor, no operation proofs"]
fn native_archive_real_q_status_sources_import_every_owner() {
    native_source_import_sweep(Variant::ArchiveStatus, true, true, false);
}

#[test]
#[ignore = "actual Q source original-key import sweep; constructor predecessor, no operation proofs"]
fn native_archive_real_q_receive_sources_import_every_owner() {
    native_source_import_sweep(Variant::ArchiveReceive, true, true, false);
}

#[test]
#[ignore = "actual Q and captured genuine Bootstrap Omega source capacity; requires named capture, not operation proofs"]
fn native_archive_captured_omega_status_sources_fit() {
    native_source_import_sweep(Variant::ArchiveStatus, true, false, true);
}

#[test]
#[ignore = "actual Q and captured genuine Bootstrap Omega source capacity; requires named capture, not operation proofs"]
fn native_archive_captured_omega_receive_sources_fit() {
    native_source_import_sweep(Variant::ArchiveReceive, true, false, true);
}

#[test]
#[ignore = "actual Q and captured genuine Bootstrap Omega original-key import sweep; no Archive operation proofs"]
fn native_archive_captured_omega_status_sources_import_every_owner() {
    native_source_import_sweep(Variant::ArchiveStatus, true, true, true);
}

#[test]
#[ignore = "actual Q and captured genuine Bootstrap Omega original-key import sweep; no Archive operation proofs"]
fn native_archive_captured_omega_receive_sources_import_every_owner() {
    native_source_import_sweep(Variant::ArchiveReceive, true, true, true);
}

#[test]
#[ignore = "actual k14 incoming sigma/Q and captured Bootstrap Omega source capacity; no artifact admission"]
fn native_archive_captured_omega_k14_receive_sources_fit() {
    native_source_import_sweep_with_incoming_k(Variant::ArchiveReceive, true, false, true, 14);
}

#[test]
#[ignore = "actual k14 incoming sigma/Q and captured Bootstrap Omega original imports; no Archive proofs"]
fn native_archive_captured_omega_k14_receive_sources_import_every_owner() {
    native_source_import_sweep_with_incoming_k(Variant::ArchiveReceive, true, true, true, 14);
}

// These proposed words deliberately have no byte preimages. The assignment
// helper must retain them exactly without claiming any owner's authentication.
#[derive(Clone)]
struct ProposedSources {
    plan: ContextPlan,
    values: Vec<[Fp; 3]>,
    known: bool,
}
impl Circuit<Fp> for ProposedSources {
    type Config = (
        iroha_plonk_recursion::verifier::VerifierConfig<Ep>,
        iroha_plonk::cs::Column<iroha_plonk::cs::Instance>,
    );
    type Params = usize;
    type FloorPlanner = SimpleFloorPlanner;
    fn params(&self) -> usize {
        self.plan.object_specs().len() * 3
    }
    fn without_witnesses(&self) -> Self {
        Self {
            known: false,
            ..self.clone()
        }
    }
    fn configure(meta: &mut ConstraintSystem<Fp>) -> Self::Config {
        Self::configure_with_params(meta, 17 * 3)
    }
    fn configure_with_params(meta: &mut ConstraintSystem<Fp>, count: usize) -> Self::Config {
        let verifier =
            iroha_plonk_recursion::verifier::VerifierConfig::configure_serialized_foreign_tagged(
                meta, 4,
            )
            .unwrap();
        let public = meta.instance_column(count);
        meta.enable_equality(public);
        (verifier, public)
    }
    fn synthesize(
        &self,
        (config, public): Self::Config,
        mut layouter: impl Layouter<Fp>,
    ) -> Result<(), Error> {
        let mut chip = iroha_plonk_recursion::verifier::VerifierChip::new(config);
        chip.load_tables(&mut layouter)?;
        let outputs = layouter.assign_region(
            || "proposed Archive source commitments",
            |mut region| {
                let values = self
                    .values
                    .iter()
                    .map(|row| {
                        row.map(|word| {
                            if self.known {
                                iroha_plonk::frontend::Value::known(word)
                            } else {
                                iroha_plonk::frontend::Value::unknown()
                            }
                        })
                    })
                    .collect::<Vec<_>>();
                Ok(self
                    .plan
                    .assign_archive_object_claims(&mut chip, &mut region, &values)?
                    .iter()
                    .flat_map(crate::a_relation::context::ContextObjectCells::commitment_words)
                    .collect::<Vec<_>>())
            },
        )?;
        for (row, word) in outputs.iter().enumerate() {
            layouter.constrain_instance(word.cell(), public, row)?;
        }
        Ok(())
    }
}
impl ProposedSources {
    fn public(&self) -> Vec<Vec<Fp>> {
        vec![self.values.iter().flatten().copied().collect()]
    }
    fn accepts(&self, public: &[Vec<Fp>]) -> bool {
        iroha_plonk::check::check_circuit(self, 16, public, iroha_plonk::check::CheckMode::Strict)
            .is_ok_and(|result| result.is_satisfied())
    }
}

#[test]
fn archive_source_proposals_require_complete_schema_and_uint32_without_certifying_owners() {
    use ff::Field;
    use iroha_plonk::frontend::synthesize;
    for variant in [Variant::ArchiveReceive, Variant::ArchiveStatus] {
        let (operation, _, _) = operation(variant);
        let specs = ArchiveStagePlan::context_specs(variant, 8597, 3456, 3456).unwrap();
        let partition = vec![vec![0], vec![1], vec![2], vec![], vec![]];
        let unowned = ContextPlan::with_schedule(
            operation.clone(),
            partition.clone(),
            Some(0),
            specs.clone(),
        )
        .unwrap();
        let plan = unowned.clone().with_operation_tasks(tasks()).unwrap();
        let values = specs
            .iter()
            .enumerate()
            .map(|(i, spec)| {
                [
                    Fp::from(u64::try_from(i + 101).unwrap()),
                    Fp::from(u64::from(spec.capacity)),
                    Fp::from(u64::try_from(i + 201).unwrap()),
                ]
            })
            .collect::<Vec<_>>();
        let honest = ProposedSources {
            plan,
            values,
            known: true,
        };
        assert!(honest.accepts(&honest.public()));
        let known = synthesize(&honest, 16, Some(&honest.public())).unwrap();
        let unknown = synthesize(&honest.without_witnesses(), 16, None).unwrap();
        assert_eq!(known.tables.fixed(), unknown.tables.fixed());
        assert_eq!(known.tables.permutation(), unknown.tables.permutation());
        assert_eq!(
            known.tables.advice_assigned(),
            unknown.tables.advice_assigned()
        );
        for field in 0..3 {
            let mut public = honest.public();
            public[0][field] += Fp::ONE;
            assert!(
                !honest.accepts(&public),
                "proposal field{field} was not copy-bound"
            );
        }
        let mut wrong = honest.clone();
        wrong.values[0][1] = Fp::from(1u64 << 32);
        assert!(!wrong.accepts(&wrong.public()), "oversized UInt32 length");
        // Capacity is a schema property. This proposal alone must not certify
        // provenance or reject a representable arbitrary length before its owner.
        wrong.values[0][1] = Fp::from(u64::from(u32::MAX));
        assert!(wrong.accepts(&wrong.public()));
        let mut missing = honest.clone();
        missing.values.pop();
        assert!(synthesize(&missing, 16, None).is_err());
        let mut unowned_case = honest.clone();
        unowned_case.plan = unowned;
        assert!(
            synthesize(&unowned_case, 16, None).is_err(),
            "missing fixed operation owners"
        );
        let mut changed = specs;
        changed[0].capacity += 1;
        let wrong_schema = ContextPlan::with_schedule(operation, partition, Some(0), changed)
            .unwrap()
            .with_operation_tasks(tasks())
            .unwrap();
        let mut wrong = honest;
        wrong.plan = wrong_schema;
        assert!(synthesize(&wrong, 16, None).is_err(), "wrong source schema");
    }
}
