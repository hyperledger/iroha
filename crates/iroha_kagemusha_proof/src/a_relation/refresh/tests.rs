//! Fixed task/descriptor rejection tests; metadata keys never authorize lineage.

use super::*;
use crate::{
    a_relation::{AProofPlan, QProofPlan},
    q_sigma::{QSigmaPlan, SigmaClass},
};
use ff::PrimeField;
use iroha_pasta::{Eq, Fq, PastaCurve, PastaField};
use iroha_plonk::{
    cs::{Column, ConstraintSystem, Instance, InstanceType},
    frontend::{Circuit, Layouter, SimpleFloorPlanner},
    keys::{KeygenConfigV2, keygen_vk_with_binding_v2},
    pcs::ipa::PinnedParams,
};
use iroha_plonk_gadgets::p256::native::Affine;
use iroha_plonk_recursion::verifier::VerifierPlan;
use std::marker::PhantomData;

// These empty programs supply only declared descriptor shapes to rejection
// tests. They are never used for proofs, operation execution or key admission.
#[derive(Clone)]
struct Metadata<F: PastaField> {
    lengths: Vec<usize>,
    marker: PhantomData<F>,
}
impl<F: PastaField> Circuit<F> for Metadata<F> {
    type Config = Vec<Column<Instance>>;
    type Params = Vec<usize>;
    type FloorPlanner = SimpleFloorPlanner;
    fn params(&self) -> Self::Params {
        self.lengths.clone()
    }
    fn without_witnesses(&self) -> Self {
        self.clone()
    }
    fn configure(_: &mut ConstraintSystem<F>) -> Self::Config {
        Vec::new()
    }
    fn configure_with_params(
        meta: &mut ConstraintSystem<F>,
        lengths: Self::Params,
    ) -> Self::Config {
        lengths
            .into_iter()
            .map(|n| meta.instance_column(n))
            .collect()
    }
    fn synthesize(&self, _: Self::Config, _: impl Layouter<F>) -> Result<(), Error> {
        Ok(())
    }
}

fn program<C: PastaCurve>(
    params: &PinnedParams<C>,
    lengths: Vec<usize>,
    types: Vec<InstanceType>,
) -> (VerifierPlan<C>, iroha_plonk::VerifyingKey<C>) {
    let (binding, key) = keygen_vk_with_binding_v2(
        params,
        &Metadata {
            lengths,
            marker: PhantomData,
        },
        &KeygenConfigV2::pipa_r(types),
    )
    .unwrap();
    (VerifierPlan::new(binding, params.clone()).unwrap(), key)
}

fn operation(variant: Variant, schemas: &[QSignaturePlan; 2]) -> AProofPlan {
    let p = PinnedParams::<Ep>::derive(16).unwrap();
    let v = PinnedParams::<Eq>::derive(16).unwrap();
    let (leaf, _) = program(
        &PinnedParams::<Eq>::derive(12).unwrap(),
        vec![1],
        vec![InstanceType::Bounded],
    );
    let sigma = QSigmaPlan::new(
        SigmaClass::new(leaf, vec![(14, Fq::from(19))]).unwrap(),
        None,
        &v,
    )
    .unwrap();
    let (q, key) = program(
        &p,
        sigma.instance_lengths().to_vec(),
        QSigmaPlan::instance_types().to_vec(),
    );
    let mut leaves = vec![QProofPlan::new(q, key).unwrap()];
    for schema in schemas {
        let (program, key) = program(
            &p,
            vec![schema.instance_length()],
            QSignaturePlan::instance_types().to_vec(),
        );
        leaves.push(QProofPlan::new(program, key).unwrap());
    }
    let (omega, _) = program(
        &p,
        vec![1, 2, 16],
        vec![
            InstanceType::Bounded,
            InstanceType::Field,
            InstanceType::Bounded,
        ],
    );
    AProofPlan::new(variant, sigma, leaves, Some(omega), &p).unwrap()
}

const VARIANTS: [Variant; 5] = [
    Variant::RefreshCredential,
    Variant::RefreshSchemePolicy,
    Variant::RefreshBlacklist,
    Variant::RefreshQuotaShare,
    Variant::RefreshTimeAnchor,
];
fn tasks(variant: Variant) -> Vec<Vec<OperationTask>> {
    let mut out = vec![
        vec![OperationTask::RefreshEffects],
        vec![OperationTask::RefreshUpdateAuthorization],
        vec![OperationTask::RefreshCurrentAuthorization],
    ];
    if variant == Variant::RefreshBlacklist {
        out.push(vec![OperationTask::RefreshBlacklist]);
    }
    if variant == Variant::RefreshQuotaShare {
        out.extend(
            [
                OperationTask::RefreshQuotaPreviousRoot,
                OperationTask::RefreshQuotaWindowRoot,
                OperationTask::RefreshQuotaUsageRoot,
                OperationTask::RefreshQuotaMerge,
            ]
            .map(|task| vec![task]),
        );
    }
    out
}

#[test]
fn every_refresh_kind_pins_its_exact_original_shape_and_all_five_signature_slots() {
    let policy = OwnPolicy::new([3, 4], Affine::GENERATOR).unwrap();
    let schemas = RefreshStagePlan::signature_schemas(policy).unwrap();
    assert_eq!(schemas[0].slots().len(), 3);
    assert_eq!(schemas[1].slots().len(), 2);
    for schema in &schemas {
        let (certificate, variables) = schema.slots().split_last().unwrap();
        assert_eq!(certificate.key, SignatureKey::Fixed(Affine::GENERATOR));
        assert!(variables.iter().all(|s| s.key == SignatureKey::Variable));
        assert!(schema.slots().iter().all(|s| s.mode == VerifyMode::Hard));
    }
    for (variant, update) in VARIANTS.into_iter().zip([
        ObjectKind::Credential,
        ObjectKind::SchemePolicy,
        ObjectKind::Blacklist,
        ObjectKind::QuotaShare,
        ObjectKind::TimeAnchor,
    ]) {
        assert_eq!(update_kind(variant).unwrap(), update);
        let specs = RefreshObjects::context_specs(variant).unwrap();
        if variant == Variant::RefreshQuotaShare {
            assert_eq!(specs.len(), 6);
            assert_eq!(
                specs[5],
                ContextObjectSpec {
                    tag: 6,
                    capacity: 160
                }
            );
        } else {
            assert_eq!(specs.len(), 5);
        }
        for (i, (spec, kind)) in specs.iter().zip(kinds(variant).unwrap()).enumerate() {
            assert_eq!(spec.tag, u32::try_from(i + 1).unwrap());
            assert_eq!(
                usize::try_from(spec.capacity).unwrap(),
                kind.body_len() + 64
            );
        }
    }
    for variant in [
        Variant::Bootstrap,
        Variant::Load,
        Variant::Send,
        Variant::Receive,
        Variant::ArchiveStatus,
        Variant::Unload,
        Variant::Retiring,
    ] {
        assert!(RefreshObjects::context_specs(variant).is_err());
    }
}

#[test]
fn refresh_task_schemas_cannot_omit_duplicate_or_relabel_authentication_or_maps() {
    let policy = OwnPolicy::new([3, 4], Affine::GENERATOR).unwrap();
    let schemas = RefreshStagePlan::signature_schemas(policy).unwrap();
    for variant in VARIANTS {
        let operation = operation(variant, &schemas);
        let tasks = tasks(variant);
        let mut partition = vec![vec![0], vec![1], vec![2]];
        partition.resize_with(tasks.len(), Vec::new);
        let specs = RefreshObjects::context_specs(variant).unwrap();
        let context = |groups, partition, specs| {
            ContextPlan::with_schedule(operation.clone(), partition, Some(0), specs)
                .and_then(|c| c.with_operation_tasks(groups))
        };
        let plan = RefreshStagePlan::new(
            context(tasks.clone(), partition.clone(), specs.clone()).unwrap(),
            policy,
        )
        .unwrap();
        assert_eq!(plan.context().stage_count(), tasks.len());
        for i in 0..tasks.len() {
            let mut missing = tasks.clone();
            missing[i].clear();
            assert!(context(missing, partition.clone(), specs.clone()).is_err());
            let mut repeated = tasks.clone();
            repeated[i].push(tasks[i][0]);
            assert!(context(repeated, partition.clone(), specs.clone()).is_err());
        }
        let mut wrong = partition.clone();
        wrong.swap(1, 2);
        assert!(
            RefreshStagePlan::new(
                context(tasks.clone(), wrong, specs.clone()).unwrap(),
                policy
            )
            .is_err()
        );
        for mutation in 0..3 {
            let mut wrong = specs.clone();
            match mutation {
                0 => wrong[1].capacity += 1,
                1 => wrong[3].tag = 99,
                _ => wrong.swap(0, 4),
            }
            assert!(
                RefreshStagePlan::new(
                    context(tasks.clone(), partition.clone(), wrong).unwrap(),
                    policy
                )
                .is_err()
            );
        }
        if variant == Variant::RefreshQuotaShare {
            for change in 0..3 {
                let mut wrong = specs.clone();
                match change {
                    0 => {
                        wrong.pop();
                    }
                    1 => wrong[5].capacity = 32,
                    _ => wrong[5].tag = 7,
                }
                assert!(
                    context(tasks.clone(), partition.clone(), wrong)
                        .and_then(|c| RefreshStagePlan::new(c, policy))
                        .is_err()
                );
            }
        }
        let mut substituted = tasks.clone();
        substituted[0] = vec![OperationTask::LoadRecovery];
        assert!(context(substituted, partition, specs).is_err());
    }
}

#[derive(Clone)]
struct Originals {
    variant: Variant,
    sources: [Vec<u8>; 5],
    known: bool,
}
#[derive(Clone, Debug)]
struct OriginalConfig {
    verifier: iroha_plonk_recursion::verifier::VerifierConfig<Ep>,
    bytes: iroha_plonk_gadgets::bytes::tape::BytesConfig,
    public: Column<Instance>,
}
impl Circuit<Fp> for Originals {
    type Config = OriginalConfig;
    type Params = ();
    type FloorPlanner = SimpleFloorPlanner;
    fn without_witnesses(&self) -> Self {
        Self {
            known: false,
            ..self.clone()
        }
    }
    fn configure(meta: &mut ConstraintSystem<Fp>) -> Self::Config {
        let verifier =
            iroha_plonk_recursion::verifier::VerifierConfig::configure_serialized_foreign_tagged(
                meta, 3,
            )
            .unwrap();
        let a = meta.advice_column();
        let b = meta.advice_column();
        let bytes = iroha_plonk_gadgets::bytes::tape::BytesConfig::configure(meta, a, b);
        let public = meta.instance_column(15);
        meta.enable_equality(public);
        Self::Config {
            verifier,
            bytes,
            public,
        }
    }
    fn synthesize(
        &self,
        config: Self::Config,
        mut layouter: impl Layouter<Fp>,
    ) -> Result<(), Error> {
        let mut chip = VerifierChip::new(config.verifier);
        let mut bytes = BytesChip::new(config.bytes);
        chip.load_tables(&mut layouter)?;
        bytes.load_table(&mut layouter)?;
        let output = layouter.assign_region(
            || "exact Refresh original context",
            |mut region| {
                let sources = self.sources.each_ref().map(|s| {
                    s.iter()
                        .map(|b| {
                            if self.known {
                                Value::known(*b)
                            } else {
                                Value::unknown()
                            }
                        })
                        .collect::<Vec<_>>()
                });
                let objects = RefreshObjects::decode(
                    &mut chip,
                    &mut bytes,
                    &mut region,
                    self.variant,
                    sources.each_ref().map(Vec::as_slice),
                )?;
                Ok(objects
                    .context()
                    .iter()
                    .flat_map(ContextObjectCells::commitment_words)
                    .collect::<Vec<_>>())
            },
        )?;
        for (i, word) in output.iter().enumerate() {
            layouter.constrain_instance(word.cell(), config.public, i)?;
        }
        Ok(())
    }
}
fn decode_hex(s: &str) -> Vec<u8> {
    s.as_bytes()
        .chunks_exact(2)
        .map(|pair| u8::from_str_radix(std::str::from_utf8(pair).unwrap(), 16).unwrap())
        .collect()
}
fn originals(variant: Variant) -> Originals {
    let json: norito::json::Value = norito::json::from_str(include_str!(
        "../../../../../fixtures/kagemusha/wallet_v1_vectors.json"
    ))
    .unwrap();
    let rows = json["signatures"].as_array().unwrap();
    Originals {
        variant,
        known: true,
        sources: kinds(variant).unwrap().map(|kind| {
            let domain = kind.signing_domain().to_le_bytes();
            let row = rows
                .iter()
                .find(|row| row["domain"].as_str().unwrap().as_bytes() == domain)
                .unwrap();
            let mut raw = decode_hex(row["transcript_hex"].as_str().unwrap());
            raw.extend(decode_hex(row["signature_hex"].as_str().unwrap()));
            raw
        }),
    }
}
fn original_public(source: &Originals) -> Vec<Fp> {
    use iroha_pasta::poseidon::hash_with_domain;
    use iroha_plonk_gadgets::bytes::{le_value, p_bytes_native};
    let mut output = Vec::new();
    for ((raw, kind), spec) in source
        .sources
        .iter()
        .zip(kinds(source.variant).unwrap())
        .zip(RefreshObjects::context_specs(source.variant).unwrap())
    {
        let body = kind.body_len();
        let mut words = vec![p_bytes_native(kind.signing_domain(), &raw[..body])];
        for offset in [16, 0, 48, 32] {
            words.push(Fp::from_u128(u128::from_be_bytes(
                raw[body + offset..body + offset + 16].try_into().unwrap(),
            )));
        }
        let digest = hash_with_domain(kind.object_domain(), &words);
        let mut framed = spec.capacity.to_le_bytes().to_vec();
        framed.extend(raw);
        let mut tape = vec![
            Fp::from(u64::from(spec.tag)),
            Fp::from(u64::from(spec.capacity)),
        ];
        tape.extend(
            framed
                .chunks(31)
                .map(|chunk| le_value::<Fp>(chunk).unwrap()),
        );
        output.extend([
            digest,
            Fp::from(u64::from(spec.capacity)),
            hash_with_domain(u64::from_le_bytes(*b"kgwctap1"), &tape),
        ]);
    }
    output
}
#[test]
fn signed_refresh_originals_and_context_keep_every_body_signature_and_fixed_shape() {
    use iroha_plonk::{
        check::{CheckMode, check_circuit},
        frontend::synthesize,
    };
    for variant in VARIANTS {
        let source = originals(variant);
        let public = vec![original_public(&source)];
        assert!(
            check_circuit(&source, 16, &public, CheckMode::Strict)
                .unwrap()
                .is_satisfied(),
            "{variant:?}"
        );
        let known = synthesize(&source, 16, Some(&public)).unwrap();
        let unknown = synthesize(&source.without_witnesses(), 16, None).unwrap();
        assert_eq!(known.tables.fixed(), unknown.tables.fixed());
        assert_eq!(known.tables.permutation(), unknown.tables.permutation());
        assert_eq!(
            known.tables.advice_assigned(),
            unknown.tables.advice_assigned()
        );
        for index in 0..5 {
            let mut bad = source.clone();
            let end = bad.sources[index].len();
            bad.sources[index][end - 1] ^= 1;
            assert!(
                !check_circuit(&bad, 16, &public, CheckMode::Strict)
                    .unwrap()
                    .is_satisfied(),
                "{variant:?} source{index}"
            );
        }
        let mut short = source.clone();
        short.sources[1].pop();
        assert!(synthesize(&short, 16, Some(&public)).is_err());
    }
}

#[path = "quota_tests.rs"]
mod quota;

#[path = "quota_proposals.rs"]
mod quota_proposals;
