//! Required physical readback refusal and synthetic accounting regressions.

use super::*;
use crate::vector::metal_owner::HealthLease;
use sha2::{Digest, Sha256};

fn child(test: &str) -> bool {
    const KEY: &str = "IVM_METAL_MERKLE_READBACK_CONTROL";
    if std::env::var(KEY).as_deref() == Ok(test) {
        return true;
    }
    let path = module_path!().split_once("::").unwrap().1;
    let name = format!("{path}::{test}");
    let output = std::process::Command::new(std::env::current_exe().unwrap())
        .args(["--exact", &name, "--nocapture"])
        .env(KEY, test)
        .output()
        .expect("isolated physical Merkle control");
    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);
    print!("{stdout}{stderr}");
    assert!(output.status.success(), "physical Merkle control failed");
    assert!(stdout.contains("1 passed; 0 failed; 0 ignored"));
    false
}

fn configure() -> usize {
    crate::set_acceleration_config(crate::AccelerationConfig {
        enable_metal: true,
        enable_cuda: false,
        ..Default::default()
    });
    let slots = metal_runtime::device_slots().expect("complete physical Metal inventory");
    assert!(slots > 0, "physical Metal device required");
    slots
}

fn sample() -> ([u8; 96], [[u8; 64]; 3], [[u8; 32]; 3], [u8; 32]) {
    let data = std::array::from_fn(|index| (index as u8).wrapping_mul(31));
    let blocks = std::array::from_fn(|index| {
        let mut block = [0; 64];
        block[..32].copy_from_slice(&data[index * 32..(index + 1) * 32]);
        block[32] = 0x80;
        block[56..].copy_from_slice(&256u64.to_be_bytes());
        block
    });
    let leaves =
        std::array::from_fn(|index| Sha256::digest(&data[index * 32..(index + 1) * 32]).into());
    let tree = iroha_crypto::MerkleTree::<[u8; 32]>::from_byte_chunks(&data, 32).unwrap();
    let root = *tree.root().unwrap().as_ref();
    (data, blocks, leaves, root)
}

fn counts(health: &HealthLease, synthetic: bool) -> [u64; 2] {
    [MetalKernel::Sha256Leaves, MetalKernel::Sha256Pairs].map(|kernel| {
        if synthetic {
            health.synthetic_completions(kernel as usize)
        } else {
            health.completions(kernel as usize)
        }
    })
}

#[test]
fn required_metal_merkle_readback_rechecks_original_owner_after_completion() {
    if !child("required_metal_merkle_readback_rechecks_original_owner_after_completion") {
        return;
    }
    let slots = configure();
    let (data, blocks, expected_leaves, expected_root) = sample();
    let original_blocks = blocks;
    let original_leaves = expected_leaves;
    for slot in 0..slots {
        // Quarantine last: neither restoring file policy nor discovery may revive it.
        for mode in ["optout", "cap", "quarantine"] {
            let (health, leaves, root, tree, completed) =
                metal_runtime::with_device_for_qualification(slot, || {
                    let health = metal_runtime::current_health().unwrap();
                    let before = counts(&health, false);
                    let leaves = leaves_attempt(&blocks).expect("actual native leaf readback");
                    let root = reduce_attempt(&expected_leaves, true)
                        .expect("actual native canonical reduction readback");
                    let tree = tree_attempt(&data, 32)
                        .expect("actual complete tree destination before publication");
                    assert_eq!(leaves.value.as_slice(), expected_leaves.as_slice());
                    assert_eq!(root.value, expected_root);
                    assert_eq!(tree.value.root(), expected_root);
                    let completed = counts(&health, false);
                    assert_eq!(completed, [before[0] + 2, before[1] + 2]);
                    (health, leaves, root, tree, completed)
                })
                .expect("every physical owner must execute");
            assert!(metal_runtime::current_health().is_none());
            let enabled = crate::acceleration_config();
            match mode {
                "optout" => crate::set_acceleration_config(crate::AccelerationConfig {
                    enable_metal: false,
                    ..enabled
                }),
                "cap" => crate::set_acceleration_config(crate::AccelerationConfig {
                    max_gpus: Some(0),
                    ..enabled
                }),
                "quarantine" => health.quarantine(false),
                _ => unreachable!(),
            }
            assert!(leaves.publish().is_none(), "{mode}: discard staged leaves");
            assert!(root.publish().is_none(), "{mode}: discard staged root");
            assert!(
                tree.publish().is_none(),
                "{mode}: discard complete staged tree"
            );
            assert_eq!(counts(&health, false), completed, "no publication credit");
            assert_eq!(blocks, original_blocks);
            assert_eq!(expected_leaves, original_leaves);
            assert_eq!(
                (crate::byte_merkle_tree::ByteMerkleTree::root_from_bytes_accel(&data, 32))
                    .expect("expected successful fixture result"),
                expected_root,
                "original-input fallback remains canonical"
            );
            crate::set_acceleration_config(enabled);
            if mode == "quarantine" {
                assert!(!health.usable());
            }
            println!(
                "IVM_METAL_MERKLE_READBACK device={} refusal={mode} completed_leaves=2 completed_pair_levels=2",
                health.identity()
            );
        }
    }
}

#[test]
fn required_metal_merkle_calibration_uses_real_adapters_without_production_credit() {
    if !child("required_metal_merkle_calibration_uses_real_adapters_without_production_credit") {
        return;
    }
    let slots = configure();
    let (data, blocks, expected_leaves, expected_root) = sample();
    for slot in 0..slots {
        metal_runtime::with_device_for_qualification(slot, || {
            let health = metal_runtime::current_health().unwrap();
            let production = counts(&health, false);
            let synthetic = counts(&health, true);
            let started = std::time::Instant::now();
            let (leaves, root) = crate::vector::metal_receipts::with_synthetic(|| {
                let leaves = chunk_leaves(&data, 32).unwrap();
                let root = metal_merkle_root(&leaves).unwrap();
                (leaves, root)
            });
            assert_eq!(leaves.as_slice(), expected_leaves.as_slice());
            assert_eq!(root, expected_root);
            assert!(started.elapsed().as_nanos() > 0);
            assert_eq!(counts(&health, false), production);
            assert_eq!(counts(&health, true), [synthetic[0] + 1, synthetic[1] + 2]);
            assert_eq!(metal_sha256_leaves(&blocks).unwrap().as_slice(), expected_leaves.as_slice());
            assert_eq!(metal_merkle_root(&expected_leaves), Some(expected_root));
            assert_eq!(counts(&health, false), [production[0] + 1, production[1] + 2]);
            assert_eq!(counts(&health, true), [synthetic[0] + 1, synthetic[1] + 2]);
            println!(
                "IVM_METAL_MERKLE_COST_RECEIPT device={} production_leaves=1 production_pair_levels=2 synthetic_leaves=1 synthetic_pair_levels=2",
                health.identity()
            );
        })
        .expect("every physical owner must execute");
    }
}

#[test]
fn required_metal_rehash_rechecks_original_owner_after_destination_lock() {
    if !child("required_metal_rehash_rechecks_original_owner_after_destination_lock") {
        return;
    }
    let slots = configure();
    let (data, _, expected_leaves, expected_root) = sample();
    let context = Sha256Context::production();
    let baseline = Sha256Baseline::capture(context).expect("original CPU fallback identity");
    for slot in 0..slots {
        for mode in ["optout", "cap", "quarantine"] {
            let tree = crate::ByteMerkleTree::new(3, 32).unwrap();
            let original = tree.root();
            let (health, staged, completed) =
                metal_runtime::with_device_for_qualification(slot, || {
                    let health = metal_runtime::current_health().unwrap();
                    let before = counts(&health, false);
                    let staged = rehash_attempt(&tree, &data, baseline, context)
                        .expect("real fixed-leaf native readback");
                    assert_eq!(staged.digests.as_slice(), expected_leaves.as_slice());
                    assert_eq!(
                        tree.root(),
                        original,
                        "readback does not mutate retained destination"
                    );
                    let completed = counts(&health, false);
                    assert_eq!(completed, [before[0] + 1, before[1]]);
                    (health, staged, completed)
                })
                .expect("every original physical owner must execute");
            assert!(metal_runtime::current_health().is_none());
            let enabled = crate::acceleration_config();
            assert!(
                !staged.install_after_lock(|| {
                    match mode {
                        "optout" => crate::set_acceleration_config(crate::AccelerationConfig {
                            enable_metal: false,
                            ..enabled
                        }),
                        "cap" => crate::set_acceleration_config(crate::AccelerationConfig {
                            max_gpus: Some(0),
                            ..enabled
                        }),
                        "quarantine" => health.quarantine(false),
                        _ => unreachable!(),
                    }
                }),
                "{mode}: locked destination must reject late owner refusal"
            );
            assert_eq!(tree.root(), original, "{mode}: no leaf or node may change");
            assert_eq!(counts(&health, false), completed, "no installation receipt");
            tree.recompute_all_leaves_parallel(&data);
            assert_eq!(
                tree.root(),
                expected_root,
                "complete original-input fallback"
            );
            assert_eq!(counts(&health, false), completed);
            crate::set_acceleration_config(enabled);
            if mode == "quarantine" {
                assert!(
                    !health.usable(),
                    "restoring policy must not restore physical health"
                );
            }
            println!(
                "IVM_METAL_REHASH_INSTALL_RECEIPT device={} refusal={mode} completed_leaves=1 retained_unchanged=true",
                health.identity()
            );
        }
    }
}
