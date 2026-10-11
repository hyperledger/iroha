//! Genuine retained-metadata capacity regression; outputs are unqualified engineering originals.

use super::*;
use crate::a_relation::{native::artifact::KeyArtifact, schedule::compiled::OperationSchedule};
use iroha_pasta::PastaCurve;
use iroha_plonk::{DescriptorBinding, ProvingKey, keys::CosetCachePolicy};
use sha2::{Digest, Sha256};
use std::{fs, io::Read, path::Path};

fn hex(bytes: &[u8]) -> String {
    use std::fmt::Write;
    let mut out = String::new();
    for byte in bytes {
        write!(out, "{byte:02x}").unwrap();
    }
    out
}
fn bounded(path: &Path, cap: usize) -> Vec<u8> {
    let before = fs::symlink_metadata(path).unwrap();
    assert!(before.is_file() && before.len() > 0 && before.len() <= cap as u64);
    let bytes = fs::read(path).unwrap();
    assert_eq!(bytes.len() as u64, before.len());
    bytes
}
fn metadata<C: PastaCurve>(root: &Path, name: &[u8]) -> KeyArtifact<C> {
    // Prefixes locate independently content-addressed public D/V; this is not PK admission.
    let mut reader = fs::File::open(root.join(hex(name))).unwrap();
    let mut header = [0; 44];
    reader.read_exact(&mut header).unwrap();
    assert_eq!(&header[..8], b"PIPAPK01");
    let length = u32::from_le_bytes(header[40..].try_into().unwrap()) as usize;
    assert!(length <= 1 << 18);
    let mut vk = vec![0; length];
    reader.read_exact(&mut vk).unwrap();
    assert_eq!(bounded(&root.join(hex(&Sha256::digest(&vk))), length), vk);
    let mut matching = None;
    for entry in fs::read_dir(root).unwrap() {
        let entry = entry.unwrap();
        if entry.metadata().unwrap().len() > 1 << 20 {
            continue;
        }
        let bytes = bounded(&entry.path(), 1 << 20);
        if let Ok(binding) = DescriptorBinding::decode_v2(&bytes) {
            assert_eq!(
                entry.file_name().to_str().unwrap(),
                hex(&Sha256::digest(&bytes))
            );
            if binding.digest() == &header[8..40] {
                assert!(matching.replace(binding).is_none());
            }
        }
    }
    let binding = matching.unwrap();
    let key = VerifyingKey::read(&vk, &binding).unwrap();
    KeyArtifact::new(binding, key).unwrap()
}
fn source(root: &Path, names: &[u8]) -> Plan {
    assert_eq!(names.len(), 20 * 32);
    let key = |i| &names[i * 32..(i + 1) * 32];
    let sigma: [KeyArtifact<Eq>; 16] = core::array::from_fn(|i| metadata(root, key(i)));
    let policy = bounded(&root.parent().unwrap().join("source-policy.norito"), 4_096);
    let (provider, root_x, root_y): ([u128; 2], [u64; 4], [u64; 4]) =
        norito::decode_canonical_with_limits(
            &policy,
            norito::canonical_decode_limits(policy.len()),
        )
        .unwrap();
    let policy = OwnPolicy::new(
        provider,
        Affine {
            x: root_x,
            y: root_y,
        },
    )
    .unwrap();
    let pallas = PinnedParams::<Ep>::derive(16).unwrap();
    let vesta = PinnedParams::<Eq>::derive(16).unwrap();
    let class = |indices: &[usize]| {
        let first = &sigma[indices[0]];
        let params = PinnedParams::derive(u32::from(first.binding().descriptor().k)).unwrap();
        let entries = indices
            .iter()
            .map(|&i| {
                assert_eq!(first.binding(), sigma[i].binding());
                (
                    u8::try_from(i).unwrap(),
                    sigma[i].key().kagemusha_digest(sigma[i].binding()).unwrap(),
                )
            })
            .collect();
        SigmaClass::new(
            VerifierPlan::new(first.binding().clone(), params).unwrap(),
            entries,
        )
        .unwrap()
    };
    let sigma = QSigmaPlan::new(class(&[10]), Some(class(&[2, 6])), &vesta).unwrap();
    let q_proofs = (16..19)
        .map(|i| {
            let key: KeyArtifact<Ep> = metadata(root, key(i));
            QProofPlan::new(
                VerifierPlan::new(key.binding().clone(), pallas.clone()).unwrap(),
                key.key().clone(),
            )
            .unwrap()
        })
        .collect();
    let omega: KeyArtifact<Ep> = metadata(root, key(19));
    let predecessor = VerifierPlan::new(omega.binding().clone(), pallas.clone()).unwrap();
    let operation = AProofPlan::new(
        Variant::ReceiveRenewed,
        sigma,
        q_proofs,
        Some(predecessor),
        &pallas,
    )
    .unwrap();
    Plan::new(operation, policy, omega.key().clone(), pallas, vesta).unwrap()
}
fn rows(circuit: &StageCircuit, k: u32) -> (usize, usize) {
    let layout = synthesize(circuit, k, None).unwrap();
    let total = layout
        .tables
        .regions()
        .iter()
        .flat_map(|region| region.extents.values())
        .map(|(_, last)| last + 1)
        .max()
        .unwrap();
    let advice = layout
        .tables
        .advice_assigned()
        .iter()
        .filter_map(|column| column.iter().rposition(|assigned| *assigned))
        .map(|last| last + 1)
        .max()
        .unwrap();
    (total, advice)
}
fn publish<C: PastaCurve>(root: &Path, key: &ProvingKey<C>) {
    for bytes in [
        key.binding().encoded().to_vec(),
        key.vk().to_bytes().to_vec(),
        key.artifact_bytes_v2().unwrap(),
    ] {
        let path = root.join(hex(&Sha256::digest(&bytes)));
        if path.exists() {
            assert_eq!(bounded(&path, bytes.len()), bytes);
        } else {
            fs::write(path, bytes).unwrap();
        }
    }
}

#[test]
#[ignore = "explicit exact retained metadata; actual ten-A/nine-W k16 source generation"]
fn genuine_renewed_schedule_fits_every_stage_and_retains_old_overflow() {
    let input = std::env::var("KAGEMUSHA_CAPACITY_INPUT").unwrap();
    let original = std::env::var("KAGEMUSHA_DIAGNOSTIC_ORIGINALS").unwrap();
    let output = std::env::var("KAGEMUSHA_CAPACITY_OUTPUT").unwrap();
    let output = Path::new(&output);
    fs::create_dir(output).unwrap();
    let plan = source(Path::new(&original), &bounded(Path::new(&input), 640));
    let renewed = OperationSchedule::for_variant(Variant::ReceiveRenewed);
    for replacement in [
        None,
        Some(crate::a_relation::schedule::OperationTask::ReceiveConsumedEffects),
    ] {
        let mut tasks = renewed.tasks().to_vec();
        assert_eq!(
            tasks[7].pop(),
            Some(crate::a_relation::schedule::OperationTask::ReceiveCreditEffects)
        );
        if let Some(task) = replacement {
            tasks[7].push(task);
        }
        let context = ContextPlan::with_schedule(
            plan.context().operation().clone(),
            renewed.q_partitions().to_vec(),
            Some(0),
            plan.context().object_specs().to_vec(),
        )
        .unwrap();
        assert!(
            context.with_operation_tasks(tasks).is_err(),
            "moved credit owner is mandatory in exact context"
        );
    }
    // Retain the exact former semantic partition only in this regression. It is
    // never an installed or selectable production schedule.
    let ordinary = OperationSchedule::for_variant(Variant::Receive);
    let baseline = ContextPlan::with_schedule(
        plan.context().operation().clone(),
        ordinary.q_partitions().to_vec(),
        Some(0),
        plan.context().object_specs().to_vec(),
    )
    .unwrap()
    .with_operation_tasks(ordinary.tasks().to_vec())
    .unwrap();
    let mut old = plan.clone();
    old.stage = ReceiveStagePlan::new(baseline, plan.policy).unwrap();
    let circuit = old.source_circuit(0, None).unwrap();
    assert!(matches!(
        synthesize(&circuit, 16, None),
        Err(CircuitError::RowOutOfRange { .. })
    ));
    eprintln!(
        "CAPACITY prior_renewed_A0 diagnostic_k17_rows_total_and_advice={:?} not_admitted=true",
        rows(&circuit, 17)
    );
    drop((old, circuit));
    let mut aconfig = KeygenConfigV2::pipa_r(vec![InstanceType::Bounded]);
    aconfig.compress_selectors = false;
    aconfig.coset_cache = CosetCachePolicy::OnDemand;
    let mut wconfig = KeygenConfigV2::pipa_r(crate::omega::OmegaPlan::instance_types().to_vec());
    wconfig.coset_cache = CosetCachePolicy::OnDemand;
    let mut previous = None;
    for stage in 0..plan.context().stage_count() {
        let circuit = plan.source_circuit(stage, previous.take()).unwrap();
        eprintln!(
            "CAPACITY renewed_A{stage} k16_rows_total_and_advice={:?}",
            rows(&circuit, 16)
        );
        let key = keygen_pk_v2(&plan.vesta, &circuit, &aconfig).unwrap();
        publish(output, &key);
        if stage + 1 < plan.context().stage_count() {
            let wrapper = plan.wrapper_source(stage, key.binding(), key.vk()).unwrap();
            drop(key);
            let key = keygen_pk_v2(&plan.pallas, &wrapper, &wconfig).unwrap();
            publish(output, &key);
            previous = Some(
                WKey::from_artifact(
                    plan.context(),
                    stage,
                    key.binding().clone(),
                    plan.pallas.clone(),
                    key.vk().clone(),
                )
                .unwrap(),
            );
        }
    }
}
